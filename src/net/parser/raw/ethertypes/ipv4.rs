use log::{debug, trace};
use super::{EtherTypeParser, dump_packet_details};
use super::super::RawProtocolHeader;
use std::net::{IpAddr, Ipv4Addr};

pub struct IPv4Parser;

impl EtherTypeParser for IPv4Parser {
    fn parse_packet(&self, packet: &[u8]) -> Option<RawProtocolHeader> {
        // Ensure minimum IPv4 header length (20 bytes)
        if packet.len() < 20 {
            trace!("Packet too short for IPv4 header: {} bytes", packet.len());
            return None;
        }

        // Extract version and header length from first byte
        let version = packet[0] >> 4;
        let header_length = (packet[0] & 0x0F) * 4; // IHL is in 4-byte units

        // Validate IPv4 version
        if version != 4 {
            trace!("Invalid IPv4 version: {}", version);
            return None;
        }

        // Validate header length
        if header_length < 20 || header_length as usize > packet.len() {
            trace!("Invalid IPv4 header length: {}", header_length);
            return None;
        }

        // Extract total length from bytes 2-3
        let total_length = u16::from_be_bytes([packet[2], packet[3]]) as usize;
        
        // Validate total length
        if total_length < header_length as usize || total_length > packet.len() {
            trace!("Invalid IPv4 total length: {}", total_length);
            return None;
        }

        // Extract source and destination IP addresses (bytes 12-15 and 16-19)
        let src_ip = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
        let dst_ip = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
        
        // Get protocol number (byte 9)
        let protocol = packet[9];

        // Calculate payload start and length
        let payload_start = header_length as usize;
        let payload_length = total_length - payload_start;
        
        // Extract payload
        let payload = if payload_length > 0 && payload_start + payload_length <= packet.len() {
            packet[payload_start..payload_start + payload_length].to_vec()
        } else {
            Vec::new()
        };

        let mut header = RawProtocolHeader::new(
            Some(IpAddr::V4(src_ip)),
            Some(IpAddr::V4(dst_ip)),
            0,  // src_port (will be set later if UDP)
            0,  // dst_port (will be set later if UDP)
            protocol,
            total_length,
            payload,
        )
        .with_version(version)
        .with_flags(packet[6] >> 5)
        .with_ttl(packet[8])
        .with_checksum(u16::from_be_bytes([packet[10], packet[11]]));

        // Handle UDP ports (protocol 17) which includes OpenVPN
        if protocol == 17 && header_length as usize + 4 <= packet.len() {
            let udp_data = &packet[header_length as usize..];
            if udp_data.len() >= 4 {
                let src_port = u16::from_be_bytes([udp_data[0], udp_data[1]]);
                let dst_port = u16::from_be_bytes([udp_data[2], udp_data[3]]);
                
                header = header.with_src_port(src_port).with_dst_port(dst_port);
                
                trace!("UDP ports extracted: {}:{} -> {}:{}", 
                    src_ip, src_port, dst_ip, dst_port);
            }
        }

        Some(header)
    }

    fn can_parse(&self, ethertype: u16) -> bool {
        // Standard IPv4 EtherType is 0x0800. Also include additional ethertype values that have been seen in dumps.
        matches!(ethertype, 0x0800 | 0x1715 | 0x4a7d)
    }

    fn protocol_name(&self) -> &'static str {
        "IPv4"
    }
} 