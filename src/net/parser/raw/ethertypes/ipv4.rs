use log::{debug, trace};
use super::{EtherTypeParser, dump_packet_details};
use super::super::RawProtocolHeader;

pub struct IPv4Parser;

impl EtherTypeParser for IPv4Parser {
    fn parse_packet(&self, packet: &[u8]) -> Option<RawProtocolHeader> {
        if packet.len() < 20 {  // Minimum IPv4 header length
            trace!("Packet too short for IPv4");
            return None;
        }

        // Verify this is an IPv4 packet
        let version = packet[0] >> 4;
        if version != 4 {
            trace!("Not an IPv4 packet (version = {})", version);
            return None;
        }

        let header_length = (packet[0] & 0x0F) * 4;
        let total_length = u16::from_be_bytes([packet[2], packet[3]]);
        let protocol = packet[9];
        let src_ip = std::net::Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
        let dst_ip = std::net::Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);

        debug!("IPv4 packet: protocol={}, length={}", protocol, total_length);
        dump_packet_details(packet, "IPv4");

        let payload = if packet.len() > header_length as usize {
            Some(packet[header_length as usize..].to_vec())
        } else {
            None
        };

        Some(RawProtocolHeader::new(
            Some(std::net::IpAddr::V4(src_ip)),
            Some(std::net::IpAddr::V4(dst_ip)),
            0,  // Ports will be parsed by protocol handlers
            0,
            protocol,
            total_length,
            payload,
        ).with_version(version)
         .with_flags(packet[6] >> 5)  // IP flags
         .with_ttl(packet[8])
         .with_checksum(u16::from_be_bytes([packet[10], packet[11]]))
        )
    }

    fn can_parse(&self, ethertype: u16) -> bool {
        // Standard IPv4 EtherType is 0x0800, but we also check for these unusual values
        // that we've seen in the dumps
        matches!(ethertype, 0x0800 | 0x1715 | 0x4a7d)
    }

    fn protocol_name(&self) -> &'static str {
        "IPv4"
    }
} 