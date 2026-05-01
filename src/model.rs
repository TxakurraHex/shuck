use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkType {
    Ethernet, // DLT 1
    Loopback, // DLT 0 (BSD null/loopback, used by macOS lo0)
    Raw,      // DLT 101 (raw IP)
    Other(u32),
}

impl LinkType {
    pub fn from_u32(v: u32) -> Self {
        match v {
            0 => Self::Loopback,
            1 => Self::Ethernet,
            101 => Self::Raw,
            other => Self::Other(other),
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Ethernet => "Ethernet",
            Self::Loopback => "Loopback",
            Self::Raw => "Raw IP",
            Self::Other(_) => "Other",
        }
    }
}

#[derive(Debug)]
pub struct Frame {
    pub number: u32,
    pub timestamp: Duration, // from pcap
    pub link_type: LinkType,
    pub raw: Vec<u8>,
    pub layers: Vec<Layer>,
}

#[derive(Debug, Clone)]
pub struct Layer {
    pub name: String,
    pub summary: String,
    pub fields: Vec<Field>,
    pub children: Vec<Layer>,
}

#[derive(Debug, Clone)]
pub struct Field {
    pub name: String,
    pub value: String,
    pub offset: usize, // absolute offset into Frame.raw
    pub length: usize,
}
