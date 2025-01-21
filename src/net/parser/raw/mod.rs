mod ethertypes;
mod protocols;
mod utils;

use std::net::IpAddr;

use log::{debug, trace, warn};

#[derive(Debug)]
pub struct RawProtocolHeader {
    pub src_ip: Option<IpAddr>,
    pub dst_ip: Option<IpAddr>,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub length: u16,
    pub payload: Option<Vec<u8>>,
    pub raw_packet: Option<Vec<u8>>,
    pub ethertype: Option<u16>,
    pub flags: Option<u8>,
    pub version: Option<u8>,
    pub next_header: Option<u8>,
    pub sequence: Option<u32>,
    pub spi: Option<u32>,

    // IGMP specific fields
    pub qrv: Option<u8>,  // Querier's Robustness Variable
    pub qqic: Option<u8>, // Querier's Query Interval Code

    pub ttl: Option<u8>, // Time To Live

    // Add IPX specific fields
    pub src_network: Option<u32>,
    pub dst_network: Option<u32>,

    pub checksum: Option<u16>, // IP checksum
}

impl RawProtocolHeader {
    pub fn new(
        src_ip: Option<IpAddr>,
        dst_ip: Option<IpAddr>,
        src_port: u16,
        dst_port: u16,
        protocol: u8,
        length: u16,
        payload: Option<Vec<u8>>,
    ) -> Self {
        Self {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
            length,
            payload,
            raw_packet: None,
            ethertype: None,
            flags: None,
            version: None,
            next_header: None,
            sequence: None,
            spi: None,
            ttl: None,
            qrv: None,
            qqic: None,
            src_network: None,
            dst_network: None,
            checksum: None,
        }
    }

    pub fn with_raw_packet(mut self, packet: Vec<u8>) -> Self {
        self.raw_packet = Some(packet);
        self
    }

    pub fn with_next_header(mut self, next_header: u8) -> Self {
        self.next_header = Some(next_header);
        self
    }

    pub fn with_sequence(mut self, sequence: u32) -> Self {
        self.sequence = Some(sequence);
        self
    }

    pub fn with_spi(mut self, spi: u32) -> Self {
        self.spi = Some(spi);
        self
    }

    pub fn with_ethertype(mut self, ethertype: u16) -> Self {
        self.ethertype = Some(ethertype);
        self
    }

    pub fn with_flags(mut self, flags: u8) -> Self {
        self.flags = Some(flags);
        self
    }

    pub fn with_version(mut self, version: u8) -> Self {
        self.version = Some(version);
        self
    }

    pub fn with_qrv(mut self, qrv: u8) -> Self {
        self.qrv = Some(qrv);
        self
    }

    pub fn with_qqic(mut self, qqic: u8) -> Self {
        self.qqic = Some(qqic);
        self
    }

    pub fn with_ttl(mut self, ttl: u8) -> Self {
        self.ttl = Some(ttl);
        self
    }

    pub fn with_src_network(mut self, network: u32) -> Self {
        self.src_network = Some(network);
        self
    }

    pub fn with_dst_network(mut self, network: u32) -> Self {
        self.dst_network = Some(network);
        self
    }

    pub fn with_checksum(mut self, checksum: u16) -> Self {
        self.checksum = Some(checksum);
        self
    }

    pub fn from_ethertype(payload: &[u8], ethertype: u16) -> Option<Self> {
        trace!(
            "Attempting to parse raw protocol from EtherType: 0x{:04x}",
            ethertype
        );

        // Try ethertypes module first
        if let Some(header) = ethertypes::parse_ethertype(payload, ethertype) {
            debug!("Successfully parsed using ethertypes module");
            return Some(header);
        }

        // Fallback to protocol-based parsing
        Self::from_raw_packet(payload, ethertype as u8)
    }

    pub fn from_raw_packet(payload: &[u8], protocol_hint: u8) -> Option<Self> {
        trace!(
            "Attempting raw packet parsing with protocol hint: {}",
            protocol_hint
        );

        // Try known protocols first
        if let Some(header) = protocols::parse_protocol(payload, protocol_hint) {
            debug!("Successfully parsed using protocol module");
            return Some(header);
        }

        // Fallback to generic packet analysis
        if payload.len() < 4 {
            warn!("Payload too short for generic analysis");
            debug!("Payload: {:?}", payload);
            return None;
        }

        // Look for common protocol patterns
        let possible_header = match protocol_hint {
            0xb9 => {
                // Netflix VPN pattern
                debug!("Detected possible Netflix VPN traffic");
                Some(Self::new(
                    None,
                    None,
                    ((payload[0] as u16) << 8) | payload[1] as u16,
                    ((payload[2] as u16) << 8) | payload[3] as u16,
                    protocol_hint,
                    payload.len() as u16,
                    Some(payload[4..].to_vec()),
                ))
            }
            0x36 => {
                // Custom VPN pattern
                debug!("Detected possible custom VPN traffic");
                Some(Self::new(
                    None,
                    None,
                    payload[0] as u16,
                    payload[1] as u16,
                    protocol_hint,
                    payload.len() as u16,
                    Some(payload[2..].to_vec()),
                ))
            }
            _ => {
                trace!("Using generic packet analysis");
                Some(Self::new(
                    None,
                    None,
                    if payload.len() >= 2 {
                        ((payload[0] as u16) << 8) | payload[1] as u16
                    } else {
                        0
                    },
                    if payload.len() >= 4 {
                        ((payload[2] as u16) << 8) | payload[3] as u16
                    } else {
                        0
                    },
                    protocol_hint,
                    payload.len() as u16,
                    Some(payload.to_vec()),
                ))
            }
        };

        if possible_header.is_some() {
            debug!("Created raw protocol header through generic analysis");
        }

        possible_header
    }
}
