use super::{DissectError, DissectResult};
use crate::model::{Field, Layer};
use std::net::{Ipv4Addr, Ipv6Addr};

fn type_name(t: u16) -> &'static str {
    match t {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        12 => "PTR",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        33 => "SRV",
        35 => "NAPTR",
        41 => "OPT",
        43 => "DS",
        46 => "RRSIG",
        47 => "NSEC",
        48 => "DNSKEY",
        50 => "NSEC3",
        64 => "SVCB",
        65 => "HTTPS",
        257 => "CAA",
        _ => "Unknown",
    }
}

fn class_name(c: u16) -> &'static str {
    match c {
        1 => "IN",
        3 => "CH",
        4 => "HS",
        254 => "NONE",
        255 => "ANY",
        _ => "Unknown",
    }
}

fn opcode_name(op: u8) -> &'static str {
    match op {
        0 => "QUERY",
        1 => "IQUERY",
        2 => "STATUS",
        4 => "NOTIFY",
        5 => "UPDATE",
        _ => "Unknown",
    }
}

fn rcode_name(r: u8) -> &'static str {
    match r {
        0 => "NOERROR",
        1 => "FORMERR",
        2 => "SERVFAIL",
        3 => "NXDOMAIN",
        4 => "NOTIMPL",
        5 => "REFUSED",
        6 => "YXDOMAIN",
        7 => "YXRRSET",
        8 => "NXRRSET",
        9 => "NOTAUTH",
        10 => "NOTZONE",
        _ => "Unknown",
    }
}

/// Read a DNS-encoded name starting at `start` within the full `msg`.
/// Returns `(resolved_name, bytes_consumed_at_start)`. The second value is
/// the number of bytes physically present at the starting position - it
/// does *not* count bytes read through pointer deref.
///
/// Compression rule:
///   - 0b00xxxxxx: label length byte (0-63 bytes of label follow)
///   - 0b11xxxxxx: pointer — low 6 bits + next byte = 14-bit absolute
///                 offset from the start of the DNS message
///   - 0b01 / 0b10: reserved, treated as malformed here

fn read_name(msg: &[u8], start: usize) -> Result<(String, usize), DissectError> {
    let mut name = String::new();
    let mut pos = start;
    let mut consumed: Option<usize> = None;
    let mut hops = 0usize;

    loop {
        if pos >= msg.len() {
            return Err(DissectError::Truncated {
                need: pos + 1,
                at: start,
                have: msg.len(),
            });
        }
        let b = msg[pos];

        if b == 0 {
            // Null terminator. If no ptr found yet, bytes at `start` are
            // entire label seq + null.
            if consumed.is_none() {
                consumed = Some(pos + 1 - start);
            }
            break;
        }

        match b & 0xC0 {
            0x00 => {
                // Standard length-prefixed label.
                let label_len = b as usize;
                if label_len > 63 {
                    return Err(DissectError::Malformed(format!(
                        "DNS label too long: {label_len} bytes"
                    )));
                }
                if pos + 1 + label_len > msg.len() {
                    return Err(DissectError::Truncated {
                        need: pos + 1 + label_len,
                        at: start,
                        have: msg.len(),
                    });
                }
                if !name.is_empty() {
                    name.push('.');
                }
                for &c in &msg[pos + 1..pos + 1 + label_len] {
                    // Labels are theoretically arbitrary bytes, ASCII in practice.
                    // (Lossy display is ok here)
                    name.push(c as char);
                }
                pos += 1 + label_len;
            }
            0xC0 => {
                // Compression ptr. After following, no further bytes are at the original
                // position, record consumed_at_start here.
                if pos + 1 >= msg.len() {
                    return Err(DissectError::Truncated {
                        need: pos + 2,
                        at: start,
                        have: msg.len(),
                    });
                }
                let offset = ((((b as u16) & 0x3F) << 8) | msg[pos + 1] as u16) as usize;
                if offset >= msg.len() {
                    return Err(DissectError::Malformed(format!(
                        "DNS pointer offset {offset} out of bounds (msg len {})",
                        msg.len()
                    )));
                }
                if consumed.is_none() {
                    consumed = Some(pos + 2 - start);
                }
                hops += 1;
                if hops > 100 {
                    return Err(DissectError::Malformed(
                        "DNS name pointer chain exceeds 100 hops".into(),
                    ));
                }
                pos = offset;
            }
            _ => {
                return Err(DissectError::Malformed(format!(
                    "invalid DNS label prefix 0x{b:02x}"
                )));
            }
        }
    }

    if name.is_empty() {
        name.push('.'); // root domain
    }
    Ok((name, consumed.unwrap_or(0)))
}

/// Cheap sanity check used by the UDP dispatcher before calling `dissect`.
/// Verifies the header fits and that the section counts couldn't fit even
/// if every record were the minimum size. Rejects obvious mismatches.
pub fn looks_like_dns(bytes: &[u8]) -> bool {
    if bytes.len() < 12 {
        return false;
    }
    let qd = u16::from_be_bytes([bytes[4], bytes[5]]) as usize;
    let an = u16::from_be_bytes([bytes[6], bytes[7]]) as usize;
    let ns = u16::from_be_bytes([bytes[8], bytes[9]]) as usize;
    let ar = u16::from_be_bytes([bytes[10], bytes[11]]) as usize;
    // Min question = 5B (1 root + 2 type + 2 class).
    // Min RR is 11B (1 root + 2 type + 2 class + 4 ttl + 2 read len).
    let min = 12 + qd * 5 + (an + ns + ar) * 11;
    bytes.len() >= min
}

//
// RDATA decoders.
//

fn rdata_fields(
    rtype: u16,
    msg: &[u8],
    rdata_off: usize,
    rdlength: usize,
    base: usize,
) -> Vec<Field> {
    let Some(rdata) = msg.get(rdata_off..rdata_off + rdlength) else {
        return vec![raw_rdata_field(base, rdata_off, rdlength)];
    };

    match rtype {
        1 if rdata.len() == 4 => vec![Field {
            name: "Address".into(),
            value: Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]).to_string(),
            offset: base + rdata_off,
            length: 4,
        }],

        28 if rdata.len() == 16 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(rdata);
            vec![Field {
                name: "Address".into(),
                value: Ipv6Addr::from(octets).to_string(),
                offset: base + rdata_off,
                length: 16,
            }]
        }

        2 | 5 | 12 => {
            // NS / CNAME / PTR - RDATA is a single name (may use compression).
            let label = match rtype {
                2 => "Name Server",
                5 => "CNAME",
                _ => "Pointer",
            };
            match read_name(msg, rdata_off) {
                Ok((n, _)) => vec![Field {
                    name: label.into(),
                    value: n,
                    offset: base + rdata_off,
                    length: rdlength,
                }],
                Err(_) => vec![raw_rdata_field(base, rdata_off, rdlength)],
            }
        }

        15 if rdata.len() >= 3 => {
            // MX: 2-byte pref, then a name.
            let pref = u16::from_be_bytes([rdata[0], rdata[1]]);
            let exch = read_name(msg, rdata_off + 2)
                .map(|(n, _)| n)
                .unwrap_or_else(|_| "(error)".into());
            vec![
                Field {
                    name: "Preference".into(),
                    value: pref.to_string(),
                    offset: base + rdata_off,
                    length: 2,
                },
                Field {
                    name: "Exchange".into(),
                    value: exch,
                    offset: base + rdata_off + 2,
                    length: rdlength - 2,
                },
            ]
        }

        16 => {
            // TXT - 1+ length-prefixed character strings.
            let mut parts = Vec::new();
            let mut i = 0;
            while i < rdata.len() {
                let len = rdata[i] as usize;
                if i + 1 + len > rdata.len() {
                    break;
                }
                let s: String = rdata[i + 1..i + 1 + len]
                    .iter()
                    .map(|&c| c as char)
                    .collect();
                parts.push(format!("\"{s}\""));
                i += 1 + len;
            }
            vec![Field {
                name: "Text".into(),
                value: parts.join(" "),
                offset: base + rdata_off,
                length: rdlength,
            }]
        }

        6 => {
            // SOA - mname, rname, then 5x u32 timers.
            let Ok((mname, mname_len)) = read_name(msg, rdata_off) else {
                return vec![raw_rdata_field(base, rdata_off, rdlength)];
            };
            let Ok((rname, rname_len)) = read_name(msg, rdata_off + mname_len) else {
                return vec![raw_rdata_field(base, rdata_off, rdlength)];
            };
            let tail_off = rdata_off + mname_len + rname_len;
            if tail_off + 20 > rdata_off + rdlength {
                return vec![raw_rdata_field(base, rdata_off, rdlength)];
            }
            let u32_at = |off: usize| {
                u32::from_be_bytes([msg[off], msg[off + 1], msg[off + 2], msg[off + 3]])
            };
            vec![
                Field {
                    name: "Primary NS".into(),
                    value: mname,
                    offset: base + rdata_off,
                    length: mname_len,
                },
                Field {
                    name: "Responsible Mailbox".into(),
                    value: rname,
                    offset: base + rdata_off + mname_len,
                    length: rname_len,
                },
                Field {
                    name: "Serial".into(),
                    value: u32_at(tail_off).to_string(),
                    offset: base + tail_off,
                    length: 4,
                },
                Field {
                    name: "Refresh".into(),
                    value: format!("{}s", u32_at(tail_off + 4)),
                    offset: base + tail_off + 4,
                    length: 4,
                },
                Field {
                    name: "Retry".into(),
                    value: format!("{}s", u32_at(tail_off + 8)),
                    offset: base + tail_off + 8,
                    length: 4,
                },
                Field {
                    name: "Expire".into(),
                    value: format!("{}s", u32_at(tail_off + 12)),
                    offset: base + tail_off + 12,
                    length: 4,
                },
                Field {
                    name: "Minimum TTL".into(),
                    value: format!("{}s", u32_at(tail_off + 16)),
                    offset: base + tail_off + 16,
                    length: 4,
                },
            ]
        }

        33 if rdata.len() >= 7 => {
            // SRV - priority, weight, port, target name.
            let priority = u16::from_be_bytes([rdata[0], rdata[1]]);
            let weight = u16::from_be_bytes([rdata[2], rdata[3]]);
            let port = u16::from_be_bytes([rdata[4], rdata[5]]);
            let target = read_name(msg, rdata_off + 6)
                .map(|(n, _)| n)
                .unwrap_or_else(|_| "(error)".into());
            vec![
                Field {
                    name: "Priority".into(),
                    value: priority.to_string(),
                    offset: base + rdata_off,
                    length: 2,
                },
                Field {
                    name: "Weight".into(),
                    value: weight.to_string(),
                    offset: base + rdata_off + 2,
                    length: 2,
                },
                Field {
                    name: "Port".into(),
                    value: port.to_string(),
                    offset: base + rdata_off + 4,
                    length: 2,
                },
                Field {
                    name: "Target".into(),
                    value: target,
                    offset: base + rdata_off + 6,
                    length: rdlength - 6,
                },
            ]
        }

        _ => vec![raw_rdata_field(base, rdata_off, rdlength)],
    }
}

fn raw_rdata_field(base: usize, rdata_off: usize, rdlength: usize) -> Field {
    Field {
        name: "RDATA".into(),
        value: format!("{rdlength} bytes"),
        offset: base + rdata_off,
        length: rdlength,
    }
}

fn rdata_summary(rtype: u16, msg: &[u8], rdata_off: usize, rdlength: usize) -> Option<String> {
    let rdata = msg.get(rdata_off..rdata_off + rdlength)?;
    match rtype {
        1 if rdata.len() == 4 => {
            Some(Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]).to_string())
        }
        28 if rdata.len() == 16 => {
            let mut octects = [0u8; 16];
            octects.copy_from_slice(rdata);
            Some(Ipv6Addr::from(octects).to_string())
        }
        2 | 5 | 12 => read_name(msg, rdata_off).ok().map(|(n, _)| n),
        15 if rdata.len() >= 3 => {
            let pref = u16::from_be_bytes([rdata[0], rdata[1]]);
            let exch = read_name(msg, rdata_off + 2).ok().map(|(n, _)| n)?;
            Some(format!("{pref} {exch}"))
        }
        _ => None,
    }
}

//
// RR walker
//

struct RrParsed {
    layer: Layer,
    next: usize,
}

fn read_rr(
    msg: &[u8],
    cursor: usize,
    base: usize,
    section: &str,
    index: u16,
) -> Result<RrParsed, DissectError> {
    let rr_start = cursor;
    let (name, name_len) = read_name(msg, cursor)?;
    let pos = cursor + name_len;

    if pos + 10 > msg.len() {
        return Err(DissectError::Truncated {
            need: pos + 10,
            at: base + rr_start,
            have: msg.len(),
        });
    }

    let rtype = u16::from_be_bytes([msg[pos], msg[pos + 1]]);
    let rclass = u16::from_be_bytes([msg[pos + 2], msg[pos + 3]]);
    let ttl = u32::from_be_bytes([msg[pos + 4], msg[pos + 5], msg[pos + 6], msg[pos + 7]]);
    let rdlength = u16::from_be_bytes([msg[pos + 8], msg[pos + 9]]) as usize;

    let rdata_off = pos + 10;
    if rdata_off + rdlength > msg.len() {
        return Err(DissectError::Truncated {
            need: rdata_off + rdlength,
            at: base + rr_start,
            have: msg.len(),
        });
    }

    let mut fields = vec![
        Field {
            name: "Name".into(),
            value: name.clone(),
            offset: base + rr_start,
            length: name_len,
        },
        Field {
            name: "Type".into(),
            value: format!("{rtype} ({})", type_name(rtype)),
            offset: base + pos,
            length: 2,
        },
        Field {
            name: "Class".into(),
            value: format!("{rclass} ({})", class_name(rclass)),
            offset: base + pos + 2,
            length: 2,
        },
        Field {
            name: "TTL".into(),
            value: format!("{ttl}s"),
            offset: base + pos + 4,
            length: 4,
        },
        Field {
            name: "RDLENGTH".into(),
            value: rdlength.to_string(),
            offset: base + pos + 8,
            length: 2,
        },
    ];
    fields.extend(rdata_fields(rtype, msg, rdata_off, rdlength, base));

    let summary = match rdata_summary(rtype, msg, rdata_off, rdlength) {
        Some(s) => format!("{} {} -> {} ({}s)", type_name(rtype), name, s, ttl),
        None => format!("{} {} ({}s)", type_name(rtype), name, ttl),
    };

    Ok(RrParsed {
        layer: Layer {
            name: format!("{section} #{index}"),
            summary,
            fields,
            children: vec![],
        },
        next: rdata_off + rdlength,
    })
}

//
// TLD - Top-Level Dissector (haha)
//
pub fn dissect(bytes: &[u8], base: usize) -> DissectResult {
    if bytes.len() < 12 {
        return Err(DissectError::Truncated {
            need: 12,
            at: base,
            have: bytes.len(),
        });
    }

    let id = u16::from_be_bytes([bytes[0], bytes[1]]);
    let flags = u16::from_be_bytes([bytes[2], bytes[3]]);
    let qr = (flags >> 15) & 1;
    let opcode = ((flags >> 11) & 0x0F) as u8;
    let aa = (flags >> 10) & 1;
    let tc = (flags >> 9) & 1;
    let rd = (flags >> 8) & 1;
    let ra = (flags >> 7) & 1;
    let z = (flags >> 6) & 1;
    let ad = (flags >> 5) & 1;
    let cd = (flags >> 4) & 1;
    let rcode = (flags & 0x0F) as u8;

    let qdcount = u16::from_be_bytes([bytes[4], bytes[5]]);
    let ancount = u16::from_be_bytes([bytes[6], bytes[7]]);
    let nscount = u16::from_be_bytes([bytes[8], bytes[9]]);
    let arcount = u16::from_be_bytes([bytes[10], bytes[11]]);

    let fields = vec![
        Field {
            name: "Transaction ID".into(),
            value: format!("0x{id:04x}"),
            offset: base,
            length: 2,
        },
        Field {
            name: "QR".into(),
            value: if qr == 0 {
                "0 (query)".into()
            } else {
                "1 (response)".into()
            },
            offset: base + 2,
            length: 1,
        },
        Field {
            name: "Opcode".into(),
            value: format!("{opcode} ({})", opcode_name(opcode)),
            offset: base + 2,
            length: 1,
        },
        Field {
            name: "Flags".into(),
            value: format!("AA={aa} TC={tc} RD={rd} RA={ra} Z= {z} AD={ad} CD={cd}"),
            offset: base + 2,
            length: 2,
        },
        Field {
            name: "RCODE".into(),
            value: format!("{rcode} ({})", rcode_name(rcode)),
            offset: base + 3,
            length: 1,
        },
        Field {
            name: "QDCOUNT".into(),
            value: qdcount.to_string(),
            offset: base + 4,
            length: 2,
        },
        Field {
            name: "ANCOUNT".into(),
            value: ancount.to_string(),
            offset: base + 6,
            length: 2,
        },
        Field {
            name: "NSCOUNT".into(),
            value: nscount.to_string(),
            offset: base + 8,
            length: 2,
        },
        Field {
            name: "ARCOUNT".into(),
            value: arcount.to_string(),
            offset: base + 10,
            length: 2,
        },
    ];

    let mut children = Vec::new();
    let mut cursor = 12;

    // Questions.
    for i in 0..qdcount {
        let q_start = cursor;
        let (qname, name_len) = read_name(bytes, cursor)?;
        cursor += name_len;
        if cursor + 4 > bytes.len() {
            return Err(DissectError::Truncated {
                need: cursor + 4,
                at: base + q_start,
                have: bytes.len(),
            });
        }
        let qtype = u16::from_be_bytes([bytes[cursor], bytes[cursor + 1]]);
        let qclass = u16::from_be_bytes([bytes[cursor + 2], bytes[cursor + 3]]);

        let q_fields = vec![
            Field {
                name: "Name".into(),
                value: qname.clone(),
                offset: base + q_start,
                length: name_len,
            },
            Field {
                name: "Type".into(),
                value: format!("{qtype} ({})", type_name(qtype)),
                offset: base + cursor,
                length: 2,
            },
            Field {
                name: "Class".into(),
                value: format!("{qclass} ({})", class_name(qclass)),
                offset: base + cursor + 2,
                length: 2,
            },
        ];
        cursor += 4;

        children.push(Layer {
            name: format!("Question #{}", i + 1),
            summary: format!("{} {} {}", type_name(qtype), qname, class_name(qclass)),
            fields: q_fields,
            children: vec![],
        });
    }

    // Answer / Authority / Additional sections share the same RR shape.
    for (section, count) in [
        ("Answer", ancount),
        ("Authority", nscount),
        ("Additional", arcount),
    ] {
        for j in 0..count {
            let rr = read_rr(bytes, cursor, base, section, j + 1)?;
            cursor = rr.next;
            children.push(rr.layer);
        }
    }

    // Top-level one-liner.
    let summary = if qr == 0 {
        // Query - use the first question if present.
        let qsum = children
            .iter()
            .find(|l| l.name.starts_with("Question"))
            .map(|l| l.summary.clone())
            .unwrap_or_default();
        format!("Standard query 0x{id:04x} {qsum}")
    } else {
        format!(
            "Standard response 0x{id:04x} {} ({} ans, {} auth, {} addl)",
            rcode_name(rcode),
            ancount,
            nscount,
            arcount
        )
    };

    Ok(Layer {
        name: "DNS".into(),
        summary,
        fields,
        children,
    })
}
