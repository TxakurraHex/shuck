use super::{DissectError, DissectResult};
use crate::model::{Field, Layer};
use std::net::Ipv4Addr;

fn fmt_mac(bytes: &[u8]) -> String {
    debug_assert_eq!(bytes.len(), 6);
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
    )
}

fn hw_type_name(t: u16) -> &'static str {
    match t {
        1 => "Ethernet",
        6 => "IEEE 802",
        _ => "Unknown",
    }
}

fn op_name(op: u16) -> &'static str {
    match op {
        1 => "Request",
        2 => "Reply",
        3 => "RARP Request",
        4 => "RARP Reply",
        _ => "Unknown",
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

    // Hardware address space (Ethernet is 0x000001)
    let htype = u16::from_be_bytes([bytes[0], bytes[1]]);
    // Protocol address space (0x0800 is IPv4)
    let ptype = u16::from_be_bytes([bytes[2], bytes[3]]);
    // Length of htype
    let hlen = bytes[4];
    // Length of ptype
    let plen = bytes[5];
    // OpCode
    let oper = u16::from_be_bytes([bytes[6], bytes[7]]);

    let addrs_start = 0;
    let total_needed = addrs_start + 2 * (hlen as usize + plen as usize);
    if bytes.len() < total_needed {
        return Err(DissectError::Truncated {
            need: total_needed,
            at: base,
            have: bytes.len(),
        });
    }

    // src HW addr offset
    let sha_off = addrs_start;
    // src protocol address offset
    let spa_off = sha_off + hlen as usize;
    // dest hardware address offset
    let tha_off = spa_off + plen as usize;
    // dest protocol address offset
    let tpa_off = tha_off + hlen as usize;

    let mut fields = vec![
        Field {
            name: "Hardware Type".into(),
            value: format!("{htype} ({})", hw_type_name(htype)),
            offset: base,
            length: 2,
        },
        Field {
            name: "Protocol Type".into(),
            value: format!("0x{ptype:04x}"),
            offset: base + 2,
            length: 2,
        },
        Field {
            name: "Hardware Size".into(),
            value: hlen.to_string(),
            offset: base + 4,
            length: 1,
        },
        Field {
            name: "Protocol Size".into(),
            value: plen.to_string(),
            offset: base + 5,
            length: 1,
        },
        Field {
            name: "Operation".into(),
            value: format!("{oper} ({})", op_name(oper)),
            offset: base + 6,
            length: 2,
        },
    ];

    let is_eth_ipv4 = htype == 1 && ptype == 0x0800 && hlen == 6 && plen == 4;

    if is_eth_ipv4 {
        let sha = &bytes[sha_off..sha_off + 6];
        let spa = Ipv4Addr::new(
            bytes[spa_off],
            bytes[spa_off + 1],
            bytes[spa_off + 2],
            bytes[spa_off + 3],
        );
        let tha = &bytes[tha_off..tha_off + 6];
        let tpa = Ipv4Addr::new(
            bytes[tpa_off],
            bytes[tpa_off + 1],
            bytes[tpa_off + 2],
            bytes[tpa_off + 3],
        );

        fields.push(Field {
            name: "Sender Hardware Address".into(),
            value: fmt_mac(sha),
            offset: base + sha_off,
            length: 6,
        });
        fields.push(Field {
            name: "Sender Protocol Address".into(),
            value: spa.to_string(),
            offset: base + spa_off,
            length: 4,
        });
        fields.push(Field {
            name: "Target Hardware Address".into(),
            value: fmt_mac(tha),
            offset: base + tha_off,
            length: 6,
        });
        fields.push(Field {
            name: "Target Protocol Address".into(),
            value: tpa.to_string(),
            offset: base + tpa_off,
            length: 4,
        });

        let summary = match oper {
            1 => format!("Who has {tpa}? Tell {spa}"),
            2 => format!("{spa} is at {}", fmt_mac(sha)),
            _ => format!("{} {spa} → {tpa}", op_name(oper)),
        };
        return Ok(Layer {
            name: "ARP".into(),
            summary,
            fields,
            children: vec![],
        });
    }

    // Non-Ethernet/IPv4 ARP: just surface address slots as length-tagged blobs.
    fields.push(Field {
        name: "Sender Hardware Address".into(),
        value: format!("{hlen} bytes"),
        offset: base + sha_off,
        length: hlen as usize,
    });
    fields.push(Field {
        name: "Sender Protocol Address".into(),
        value: format!("{plen} bytes"),
        offset: base + spa_off,
        length: plen as usize,
    });
    fields.push(Field {
        name: "Target Hardware Address".into(),
        value: format!("{hlen} bytes"),
        offset: base + tha_off,
        length: hlen as usize,
    });
    fields.push(Field {
        name: "Target Protocol Address".into(),
        value: format!("{plen} bytes"),
        offset: base + tpa_off,
        length: plen as usize,
    });

    Ok(Layer {
        name: "ARP".into(),
        summary: format!("{} (htype={htype}, ptype=0x{ptype:04x})", op_name(oper)),
        fields,
        children: vec![],
    })
}
