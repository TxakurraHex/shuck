use super::{DissectError, DissectResult, ethertype, take};
use crate::model::{Field, Layer};

/// Format a 6-byte MAC as aa:bb:cc:dd:ee:ff
fn fmt_mac(bytes: &[u8]) -> String {
    debug_assert_eq!(bytes.len(), 6);
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
    )
}

/// Dissect an Ethernet II frame. Handles a single 802.1Q VLAN tag inline.
///
/// Layout (no VLAN):
///   [0..6]    destination MAC
///   [6..12]   source MAC
///   [12..14]  EtherType
///   [14..]    payload
///
/// Layout (with one VLAN tag, EtherType = 0x8100):
///   [12..14]  TPID = 0x8100
///   [14..16]  TCI = (PCP + DEI + VID)
///   [16..18]  inner EtherType
///   [18..]    payload
pub fn dissect(bytes: &[u8], base: usize) -> DissectResult {
    if bytes.len() < 14 {
        return Err(DissectError::Truncated {
            need: 14,
            at: base,
            have: bytes.len(),
        });
    }

    let dst = take(bytes, 0, 6)?;
    let src = take(bytes, 6, 6)?;
    let mut ethertype = u16::from_be_bytes([bytes[12], bytes[13]]);

    let mut fields = vec![
        Field {
            name: "Destination MAC".into(),
            value: fmt_mac(dst),
            offset: base,
            length: 6,
        },
        Field {
            name: "Source MAC".into(),
            value: fmt_mac(src),
            offset: base + 6,
            length: 6,
        },
        Field {
            name: "EtherType".into(),
            value: format!("0x{:04x} ({})", ethertype, ethertype::name(ethertype)),
            offset: base + 12,
            length: 2,
        },
    ];

    let mut payload_start: usize = 14;

    // 802.1Q VLAN tag. Assumes no stacked tags (TODO: Implement stacked tags)
    if ethertype == ethertype::VLAN {
        if bytes.len() < 18 {
            return Err(DissectError::Truncated {
                need: 18,
                at: base,
                have: bytes.len(),
            });
        }
        let tci = u16::from_be_bytes([bytes[14], bytes[15]]);
        let pcp = (tci >> 13) & 0x07;
        let dei = (tci >> 12) & 0x01;
        let vid = tci & 0x0fff;
        let inner = u16::from_be_bytes([bytes[16], bytes[17]]);

        fields.push(Field {
            name: "VLAN TCI".into(),
            value: format!("PCP={pcp} DEI={dei} VID={vid}"),
            offset: base + 14,
            length: 2,
        });
        fields.push(Field {
            name: "Inner EtherType".into(),
            value: format!("0x{:04x} ({})", inner, ethertype::name(inner)),
            offset: base + 16,
            length: 2,
        });

        ethertype = inner;
        payload_start = 18;
    }

    let summary = format!(
        "{} -> {}, {}",
        fmt_mac(src),
        fmt_mac(dst),
        ethertype::name(ethertype),
    );

    // TODO: Replace stub with ipv4::dissect / arp::dissect
    let children = if bytes.len() > payload_start {
        vec![Layer {
            name: format!("{} (not yet dissected)", ethertype::name(ethertype)),
            summary: format!(
                "{} bytes of payload at offset {}",
                bytes.len() - payload_start,
                base + payload_start
            ),
            fields: vec![Field {
                name: "Payload".into(),
                value: format!("{} bytes", bytes.len() - payload_start),
                offset: base + payload_start,
                length: bytes.len() - payload_start,
            }],
            children: vec![],
        }]
    } else {
        vec![]
    };

    Ok(Layer {
        name: "Ethernet II".into(),
        summary,
        fields,
        children,
    })
}
