use super::{DissectError, DissectResult, undissected_layer};
use crate::model::{Field, Layer};

fn port_name(port: u16) -> Option<&'static str> {
    match port {
        53 => Some("DNS"),
        67 => Some("DHCP server"),
        68 => Some("DHCP client"),
        69 => Some("TFTP"),
        123 => Some("NTP"),
        137 => Some("NetBIOS-NS"),
        138 => Some("NetBIOS-DGM"),
        161 => Some("SNMP"),
        162 => Some("SNMP trap"),
        500 => Some("IKE"),
        514 => Some("syslog"),
        1194 => Some("OpenVPN"),
        1190 => Some("SSDP"),
        4500 => Some("IPsec NAT-T"),
        5353 => Some("mDNS"),
        5355 => Some("LLMNR"),
        _ => None,
    }
}

fn fmt_port(port: u16) -> String {
    match port_name(port) {
        Some(name) => format!("{port} ({name})"),
        None => port.to_string(),
    }
}

pub fn dissect(bytes: &[u8], base: usize) -> DissectResult {
    if bytes.len() < 8 {
        return Err(DissectError::Truncated {
            need: 8,
            at: base,
            have: bytes.len(),
        });
    }

    let src_port = u16::from_be_bytes([bytes[0], bytes[1]]);
    let dst_port = u16::from_be_bytes([bytes[2], bytes[3]]);
    let length = u16::from_be_bytes([bytes[4], bytes[5]]);
    let checksum = u16::from_be_bytes([bytes[6], bytes[7]]);

    let fields = vec![
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
            name: "Length".into(),
            value: format!("{length} (header + data)"),
            offset: base + 4,
            length: 2,
        },
        Field {
            name: "Checksum".into(),
            value: format!("0x{checksum:04x}"),
            offset: base + 6,
            length: 2,
        },
    ];

    let payload_len = bytes.len().saturating_sub(8);
    let summary = format!("{src_port} -> {dst_port}, len={payload_len}");

    let children = if payload_len > 0 {
        let payload_base = base + 8;
        vec![undissected_layer(
            "Application data (not yet dissected)",
            format!("{payload_len} bytes of payload at offset {payload_base}"),
            payload_base,
            payload_len,
        )]
    } else {
        vec![]
    };

    Ok(Layer {
        name: "UDP".into(),
        summary,
        fields,
        children,
    })
}
