use super::{DissectError, DissectResult, undissected_layer};
use crate::model::{Field, Layer};
use std::net::Ipv4Addr;

/// IANI-assigned IP protocol IDs. Not an exhaustive list, but contains any we'd be likely to see
/// on a normal host.
pub fn protocol_name(p: u8) -> &'static str {
    match p {
        1 => "ICMP",
        2 => "IGMP",
        6 => "TCP",
        17 => "UDP",
        47 => "GRE",
        50 => "ESP",
        51 => "AH",
        89 => "OSPF",
        132 => "SCTP",
        _ => "Unknown",
    }
}

pub fn dissect(bytes: &[u8], base: usize) -> DissectResult {
    if bytes.len() < 20 {
        return Err(DissectError::Truncated {
            need: 20,
            at: base,
            have: bytes.len(),
        });
    }

    let version_ihl = bytes[0];
    let version = version_ihl >> 4;
    // Internet Header Length - Length of the internet header in 32 bit words, pointing to
    // beginning of the data.
    let ihl = version_ihl & 0x0f;
    let header_len = (ihl as usize) * 4; // convert to bytes for offsetting

    if version != 4 {
        return Err(DissectError::Malformed(format!(
            "expected IPv4 (version 4), got version {version}",
        )));
    }
    if ihl < 5 {
        return Err(DissectError::Malformed(format!(
            "invalid IHL {ihl} (must be >= 5)",
        )));
    }
    if bytes.len() < header_len {
        return Err(DissectError::Truncated {
            need: header_len,
            at: base,
            have: bytes.len(),
        });
    }

    // Type of Service - Indicate desired QoS
    let tos = bytes[1];
    // Bits 0-2: Precedence (Differentiated Services Code Path)
    //      111 - Network Control
    //      110 - Internetwork Control
    //      101 - CRITIC/ECP
    //      100 - Flash Override
    //      011 - Flash
    //      010 - Immediate
    //      001 - Priority
    //      000 - Routine
    let dscp = tos >> 2;
    // Bit 3: 0 for normal delay, 1 for low delay
    // Bit 4: 0 for normal throughput, 1 for high throughput
    // Bit 5: 0 for normal reliability, 1 for high reliability
    // Bits 6-7: Explicit Congestion Notification - Used by routers to signal network congestion
    // Added in RFC 2168
    //      00 - Not-ECT: Not ECN-Capable transport
    //      10 or 01 - ECN-Capable Transport
    //      11 - Congestion Experienced (marked by router)
    let ecn = tos & 0x03;

    let total_length = u16::from_be_bytes([bytes[2], bytes[3]]);
    let identification = u16::from_be_bytes([bytes[4], bytes[5]]);

    let flags_frag = u16::from_be_bytes([bytes[6], bytes[7]]);
    let flag_bits = (flags_frag >> 13) as u8;
    let reserved = (flag_bits >> 2) & 1;
    let df = (flag_bits >> 1) & 1; // 0 = May fragment, 1 = Don't fragment
    let mf = flag_bits & 1; // 0 = Last fragment, 1 = More fragments
    let fragment_offset = flags_frag & 0x1fff; // Where this fragment belongs in the datagram

    let ttl = bytes[8];
    let protocol = bytes[9];
    let checksum = u16::from_be_bytes([bytes[10], bytes[11]]);

    let src = Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]);
    let dst = Ipv4Addr::new(bytes[16], bytes[17], bytes[18], bytes[19]);

    let mut fields = vec![
        Field {
            name: "Version".into(),
            value: version.to_string(),
            offset: base,
            length: 1,
        },
        Field {
            name: "Header Length (IHL)".into(),
            value: format!("{ihl} ({header_len} bytes)"),
            offset: base,
            length: 2,
        },
        Field {
            name: "DSCP".into(),
            value: format!("0x{dscp:02x}"),
            offset: base + 1,
            length: 1,
        },
        Field {
            name: "ECN".into(),
            value: format!("0b{ecn:02b}"),
            offset: base + 1,
            length: 1,
        },
        Field {
            name: "Total Length".into(),
            value: total_length.to_string(),
            offset: base + 2,
            length: 2,
        },
        Field {
            name: "Identification".into(),
            value: format!("0x{identification:04x} ({identification})"),
            offset: base + 4,
            length: 2,
        },
        Field {
            name: "Flags".into(),
            value: format!("Res={reserved} DF={df} MF={mf}"),
            offset: base + 6,
            length: 1,
        },
        Field {
            name: "Fragment Offset".into(),
            value: format!("{fragment_offset} (x8 bytes)"),
            offset: base + 6,
            length: 2,
        },
        Field {
            name: "TTL".into(),
            value: ttl.to_string(),
            offset: base + 8,
            length: 1,
        },
        Field {
            name: "Protocol".into(),
            value: format!("{protocol} ({})", protocol_name(protocol)),
            offset: base + 9,
            length: 1,
        },
        Field {
            name: "Header Checksum".into(),
            value: format!("0x{checksum:04x}"),
            offset: base + 10,
            length: 2,
        },
        Field {
            name: "Source Address".into(),
            value: src.to_string(),
            offset: base + 12,
            length: 4,
        },
        Field {
            name: "Destination Address".into(),
            value: dst.to_string(),
            offset: base + 16,
            length: 4,
        },
    ];

    // IPv4 options when IHL > 5 - Surfaced as a single blob for now.
    // TODO: Walk the options to expand them
    if header_len > 20 {
        let opts_len = header_len - 20;
        fields.push(Field {
            name: "Options".into(),
            value: format!("{opts_len} bytes"),
            offset: base + 20,
            length: opts_len,
        });
    }

    let summary = format!("{src} -> {dst}, {}, ttl={ttl}", protocol_name(protocol));

    // Payload - keyed off protocol field
    // TODO: Implement further tcp/udp dissection
    let payload_off = header_len;
    let children = if bytes.len() > payload_off {
        let payload_len = bytes.len() - payload_off;
        let payload_base = base + payload_off;
        vec![undissected_layer(
            format!("{} (not yet dissected)", protocol_name(protocol)),
            format!("{payload_len} bytes of payload at offset {payload_base}"),
            payload_base,
            payload_len,
        )]
    } else {
        vec![]
    };

    Ok(Layer {
        name: "IPv4".into(),
        summary,
        fields,
        children,
    })
}
