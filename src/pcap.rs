use crate::dissect;
use crate::model::{Frame, LinkType};
use anyhow::{Context, Result, anyhow};
use pcap_file::{
    pcap::PcapReader,
    pcapng::{Block, PcapNgReader},
};
use std::{fs::File, io::Read, path::Path, time::Duration};

// pcap classic magic numbers (4 byte ID in file header)
const PCAP_MAGIC_US_LE: [u8; 4] = [0xd4, 0xc3, 0xb2, 0xa1]; // microseconds, little endian
const PCAP_MAGIC_US_BE: [u8; 4] = [0xa1, 0xb2, 0xc3, 0xd4]; // microseconds, big endian
const PCAP_MAGIC_NS_LE: [u8; 4] = [0x4d, 0x3c, 0xb2, 0xa1]; // ns, little endian
const PCAP_MAGIC_NS_BE: [u8; 4] = [0xa1, 0xb2, 0x3c, 0x4d]; // ns, big endian

// pcapng starts with a Section Header Block with block type is 0x0a0d0d0a.
const PCAPNG_MAGIC: [u8; 4] = [0x0a, 0x0d, 0x0d, 0x0a];

pub fn load(path: &Path) -> Result<Vec<Frame>> {
    let mut file = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;

    if bytes.len() < 4 {
        return Err(anyhow!("file too short to be a capture"));
    }

    let magic: [u8; 4] = bytes[0..4].try_into()?;
    match magic {
        PCAP_MAGIC_US_LE | PCAP_MAGIC_US_BE | PCAP_MAGIC_NS_LE | PCAP_MAGIC_NS_BE => {
            load_pcap(&bytes)
        }
        PCAPNG_MAGIC => load_pcapng(&bytes),
        _ => Err(anyhow!(
            "unrecognized magic: {:02x?}; not a pcap or pcapng file",
            magic
        )),
    }
}

fn load_pcap(bytes: &[u8]) -> Result<Vec<Frame>> {
    let mut reader = PcapReader::new(bytes).context("parsing pcap header")?;
    let link_type = LinkType::from_u32(reader.header().datalink.into());

    let mut frames = Vec::new();
    let mut number: u32 = 1;
    while let Some(pkt) = reader.next_packet() {
        let pkt = pkt.context("reading pcap packet")?;
        let mut frame = Frame {
            number,
            timestamp: pkt.timestamp,
            link_type,
            raw: pkt.data.into_owned(),
            layers: Vec::new(),
        };
        frame.layers = dissect::dissect_frame(&frame);
        frames.push(frame);
        number += 1;
    }
    Ok(frames)
}

fn load_pcapng(bytes: &[u8]) -> Result<Vec<Frame>> {
    let mut reader = PcapNgReader::new(bytes).context("parsing pcapng header")?;

    // Pcapng link types are per-interface: each Interface Description Block
    // declares a link type, and Enhanced Packet Blocks reference it by index.
    // We walk blocks in order and build up the interface table as we go.
    let mut interfaces: Vec<LinkType> = Vec::new();
    let mut frames = Vec::new();
    let mut number: u32 = 1;

    while let Some(block) = reader.next_block() {
        let block = block.context("reading pcapng block")?;
        match block {
            Block::InterfaceDescription(idb) => {
                interfaces.push(LinkType::from_u32(idb.linktype.into()));
            }
            Block::EnhancedPacket(ep) => {
                let link_type = interfaces
                    .get(ep.interface_id as usize)
                    .copied()
                    .unwrap_or(LinkType::Other(0));
                let mut frame = Frame {
                    number,
                    timestamp: ep.timestamp,
                    link_type,
                    raw: ep.data.into_owned(),
                    layers: Vec::new(),
                };
                frame.layers = dissect::dissect_frame(&frame);
                frames.push(frame);
                number += 1;
            }
            Block::SimplePacket(sp) => {
                // SPB has no interface_id; spec says implicitly interface 0.
                let link_type = interfaces.first().copied().unwrap_or(LinkType::Other(0));
                let mut frame = Frame {
                    number,
                    timestamp: Duration::ZERO,
                    link_type,
                    raw: sp.data.into_owned(),
                    layers: Vec::new(),
                };
                frame.layers = dissect::dissect_frame(&frame);
                frames.push(frame);
                number += 1;
            }
            // Ignoring SHB, name resolution, statistics, custom blocks for now
            _ => {}
        }
    }
    Ok(frames)
}
