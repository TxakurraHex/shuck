use super::{DissectError, DissectResult, undissected_layer};
use crate::model::{Field, Layer};

fn port_name(port: u16) -> Option<&'static str> {
    match port {
        20 => Some("FTP-data"),
        21 => Some("FTP"),
        22 => Some("SSH"),
        23 => Some("Telnet"),
        25 => Some("SMTP"),
        53 => Some("DNS"),
        80 => Some("HTTP"),
        110 => Some("POP3"),
        143 => Some("IMAP"),
        443 => Some("HTTPS"),
        465 => Some("SMTPS"),
        587 => Some("SMTP submission"),
        853 => Some("DNS-over-TLS"),
        993 => Some("IMAPS"),
        995 => Some("POP3S"),
        3306 => Some("MySQL"),
        5432 => Some("PostgreSQL"),
        6379 => Some("Redis"),
        6443 => Some("Kubernetes API"),
        8080 => Some("HTTP-alt"),
        8443 => Some("HTTPS-alt"),
        _ => None,
    }
}

fn fmt_port(port: u16) -> String {
    match port_name(port) {
        Some(name) => format!("{port} ({name})"),
        None => port.to_string(),
    }
}

/// Decode the 8 TCP flag bits in byte 13 into a compact label like "[SYN, ACK]".
/// Per RFC 9293 the byte is, MSB→LSB:  CWR ECE URG ACK PSH RST SYN FIN.
fn fmt_flags(flags: u8) -> String {
    let mut names = Vec::new();
    if flags & 0x80 != 0 {
        names.push("CWR");
    }
    if flags & 0x40 != 0 {
        names.push("ECE");
    }
    if flags & 0x20 != 0 {
        names.push("URG");
    }
    if flags & 0x10 != 0 {
        names.push("ACK");
    }
    if flags & 0x08 != 0 {
        names.push("PSH");
    }
    if flags & 0x04 != 0 {
        names.push("RST");
    }
    if flags & 0x02 != 0 {
        names.push("SYN");
    }
    if flags & 0x01 != 0 {
        names.push("FIN");
    }
    if names.is_empty() {
        "[]".into()
    } else {
        format!("[{}]", names.join(", "))
    }
}

/// Dissect a TCP segment. RFC 9293.
///
/// Header layout:
///   [0..2]   Source Port
///   [2..4]   Destination Port
///   [4..8]   Sequence Number
///   [8..12]  Acknowledgment Number
///   [12]     Data Offset (high nibble) | Reserved (low nibble, 4 bits)
///   [13]     Flags (CWR ECE URG ACK PSH RST SYN FIN)
///   [14..16] Window Size
///   [16..18] Checksum
///   [18..20] Urgent Pointer
///   [20..]   Options (if Data Offset > 5), then payload
pub fn dissect(bytes: &[u8], base: usize) -> DissectResult {
    if bytes.len() < 20 {
        return Err(DissectError::Truncated {
            need: 20,
            at: base,
            have: bytes.len(),
        });
    }

    let src_port = u16::from_be_bytes([bytes[0], bytes[1]]);
    let dst_port = u16::from_be_bytes([bytes[2], bytes[3]]);
    let seq = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    let ack = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);

    let doff_reserved = bytes[12];
    let data_offset = doff_reserved >> 4;
    let header_len = (data_offset as usize) * 4;
    let reserved = doff_reserved & 0x0f;

    let flag_byte = bytes[13];
    let window = u16::from_be_bytes([bytes[14], bytes[15]]);
    let checksum = u16::from_be_bytes([bytes[16], bytes[17]]);
    let urgent = u16::from_be_bytes([bytes[18], bytes[19]]);

    if data_offset < 5 {
        return Err(DissectError::Malformed(format!(
            "invalid Data Offset {data_offset} (must be >= 5)"
        )));
    }
    if bytes.len() < header_len {
        return Err(DissectError::Truncated {
            need: header_len,
            at: base,
            have: bytes.len(),
        });
    }

    let mut fields = vec![
        Field {
            name: "Source Port".into(),
            value: fmt_port(src_port),
            offset: base,
            length: 2,
        },
        Field {
            name: "Destination Port".into(),
            value: fmt_port(dst_port),
            offset: base + 2,
            length: 2,
        },
        Field {
            name: "Sequence Number".into(),
            value: seq.to_string(),
            offset: base + 4,
            length: 4,
        },
        Field {
            name: "Ack Number".into(),
            value: ack.to_string(),
            offset: base + 8,
            length: 4,
        },
        Field {
            name: "Data Offset".into(),
            value: format!("{data_offset} ({header_len} bytes)"),
            offset: base + 12,
            length: 1,
        },
        Field {
            name: "Reserved".into(),
            value: format!("0b{reserved:04b}"),
            offset: base + 12,
            length: 1,
        },
        Field {
            name: "Flags".into(),
            value: format!("0x{flag_byte:02x} {}", fmt_flags(flag_byte)),
            offset: base + 13,
            length: 1,
        },
        Field {
            name: "Window Size".into(),
            value: window.to_string(),
            offset: base + 14,
            length: 2,
        },
        Field {
            name: "Checksum".into(),
            value: format!("0x{checksum:04x}"),
            offset: base + 16,
            length: 2,
        },
        Field {
            name: "Urgent Pointer".into(),
            value: urgent.to_string(),
            offset: base + 18,
            length: 2,
        },
    ];

    // Options walk: Only present when the header is bigger than 20 bytes.
    // Each emitted Field gets its own offset/length so the hex pane lights
    // up only the option you've selected - including single-byte NOPs.
    if header_len > 20 {
        let opts = &bytes[20..header_len];
        let opt_fields = walk_options(opts, base + 20);
        fields.extend(opt_fields);
    }

    let payload_len = bytes.len().saturating_sub(header_len);
    let summary = format!(
        "{src_port} -> {dst_port}, {} seq={seq}, ack={ack}, win={window}, len={payload_len}",
        fmt_flags(flag_byte)
    );

    let children = if payload_len > 0 {
        let payload_base = base + header_len;
        vec![undissected_layer(
            "Application Data (not yet dissected)",
            format!("{payload_len} bytes of payload at offset {payload_base}"),
            payload_base,
            payload_len,
        )]
    } else {
        vec![]
    };

    Ok(Layer {
        name: "TCP".into(),
        summary,
        fields,
        children,
    })
}

/// Walk a TCP options blob, emitting one Field per option.
/// TLV grammar:
///   kind 0 (EOL)   → 1 byte,  terminates the option list
///   kind 1 (NOP)   → 1 byte,  just padding so the next option aligns
///   kind 2         → kind byte, length byte (includes those two bytes), data
fn walk_options(bytes: &[u8], base: usize) -> Vec<Field> {
    let mut fields = Vec::new();
    let mut i: usize = 0;
    while i < bytes.len() {
        let kind = bytes[i];
        match kind {
            0 => {
                fields.push(Field {
                    name: "Option".into(),
                    value: "End of Options (EOL)".into(),
                    offset: base + i,
                    length: 1,
                });
                break;
            }
            1 => {
                fields.push(Field {
                    name: "Option".into(),
                    value: "NOP".into(),
                    offset: base + i,
                    length: 1,
                });
                break;
            }
            _ => {
                if i + 1 >= bytes.len() {
                    fields.push(Field {
                        name: "Option (truncated)".into(),
                        value: format!("kind={kind}"),
                        offset: base + i,
                        length: 1,
                    });
                    break;
                }
                let len = bytes[i + 1] as usize;
                if len < 2 || i + len > bytes.len() {
                    fields.push(Field {
                        name: "Option (malformed)".into(),
                        value: format!("kind={kind} len={len}"),
                        offset: base + i,
                        length: 2,
                    });
                    break;
                }
                let data = &bytes[i + 2..i + len];
                let value = decode_option(kind, data);
                fields.push(Field {
                    name: "Option".into(),
                    value: format!("{} ({value})", option_name(kind)),
                    offset: base + i,
                    length: len,
                });
                i += len;
            }
        }
    }
    fields
}

fn option_name(kind: u8) -> &'static str {
    match kind {
        2 => "MSS",
        3 => "Window Scale",
        4 => "SACK Permitted",
        5 => "SACK",
        8 => "Timestamp",
        28 => "User Timestamp",
        29 => "TCP Authentication",
        34 => "TFO Cookie",
        _ => "Unknown",
    }
}

fn decode_option(kind: u8, data: &[u8]) -> String {
    match kind {
        2 if data.len() == 2 => {
            let mss = u16::from_be_bytes([data[0], data[1]]);
            format!("mss={mss}")
        }
        3 if data.len() == 1 => format!("shift={}", data[0]),
        4 if data.is_empty() => "permitted".to_string(),
        5 => {
            // SACK option carries 1-4 blocks of {left edge, right edge}, 8 bytes each.
            let mut parts = Vec::new();
            for block in data.chunks(8) {
                if block.len() == 8 {
                    let left = u32::from_be_bytes([block[0], block[1], block[2], block[3]]);
                    let right = u32::from_be_bytes([block[4], block[5], block[6], block[7]]);
                    parts.push(format!("{left}-{right}"));
                }
            }
            parts.join(", ")
        }
        8 if data.len() == 8 => {
            let tsval = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
            let tsecr = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
            format!("tsval={tsval} tsecr={tsecr}")
        }
        _ => format!("{} bytes", data.len()),
    }
}
