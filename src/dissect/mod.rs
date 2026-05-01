use crate::model::{Frame, Layer, LinkType};

#[derive(Debug, thiserror::Error)]
pub enum DissectError {
    #[error("truncated: need {need} bytes at offset {at}, have {have}")]
    Truncated { need: usize, at: usize, have: usize },
    #[error("malformed: {0}")]
    Malformed(String),
}

pub type DissectResult = Result<Layer, DissectError>;

pub mod ethernet;

pub mod ethertype {
    pub const IPV4: u16 = 0x0800;
    pub const ARP: u16 = 0x0806;
    pub const VLAN: u16 = 0x8100;
    pub const IPV6: u16 = 0x86dd;

    pub fn name(et: u16) -> &'static str {
        match et {
            IPV4 => "IPv4",
            ARP => "ARP",
            VLAN => "802.1Q VLAN",
            IPV6 => "IPv6",
            _ => "Unknown",
        }
    }
}

/// Safely slice `len` bytes starting at `at`, or return Truncated.
pub fn take(bytes: &[u8], at: usize, len: usize) -> Result<&[u8], DissectError> {
    bytes.get(at..at + len).ok_or(DissectError::Truncated {
        need: len,
        at,
        have: bytes.len(),
    })
}

pub fn dissect_frame(frame: &Frame) -> Vec<Layer> {
    let result = match frame.link_type {
        LinkType::Ethernet => ethernet::dissect(&frame.raw, 0),
        LinkType::Loopback => Err(DissectError::Malformed(
            "BSD loopback dissection not implemented yet".into(),
        )),
        LinkType::Raw => Err(DissectError::Malformed(
            "Raw IP dissection not implemented yet".into(),
        )),
        LinkType::Other(n) => Err(DissectError::Malformed(format!(
            "unsupported link type {n}"
        ))),
    };

    match result {
        Ok(layer) => vec![layer],
        Err(e) => vec![Layer {
            name: "Undissected".into(),
            summary: e.to_string(),
            fields: vec![],
            children: vec![],
        }],
    }
}
