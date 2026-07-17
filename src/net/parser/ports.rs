use crate::error::ParseError;

use crate::net::parser::raw::RawProtocolHeader;
use log::debug;
use pnet::packet::{tcp::TcpPacket, udp::UdpPacket};

/// Best-effort port extraction for a protocol fluere has no dedicated arm for:
/// try TCP, then UDP, then the raw protocol-agnostic parser, else `(0, 0)`.
fn parse_unknown_protocol_ports(unknown_protocol: u8, payload: &[u8]) -> (u16, u16) {
    debug!("Attempting to parse unknown protocol: {}", unknown_protocol);

    if let Some(tcp) = TcpPacket::new(payload) {
        debug!("Successfully parsed as TCP packet");
        return (tcp.get_source(), tcp.get_destination());
    }

    if let Some(udp) = UdpPacket::new(payload) {
        debug!("Successfully parsed as UDP packet");
        return (udp.get_source(), udp.get_destination());
    }

    debug!("Attempting to parse using RawProtocolHeader");
    match RawProtocolHeader::from_raw_packet(payload, unknown_protocol) {
        Some(header) => (header.src_port, header.dst_port),
        None => {
            debug!(
                "Failed to parse protocol {}, returning default ports",
                unknown_protocol
            );
            (0, 0)
        }
    }
}

pub fn parse_ports(protocol: u8, payload: &[u8]) -> Result<(u16, u16), ParseError> {
    match protocol {
        0 | 1 | 2 | 4 | 47 | 50 | 51 | 58 => Ok((0, 0)), // no L4 ports (Hop-by-Hop/ICMP/IGMP/IPv4-encap/GRE/ESP/AH/ICMPv6)
        6 => match TcpPacket::new(payload) {
            Some(tcp) => Ok((tcp.get_source(), tcp.get_destination())),
            None => Err(ParseError::InvalidPacket),
        },
        17 => match UdpPacket::new(payload) {
            Some(udp) => Ok((udp.get_source(), udp.get_destination())),
            None => Err(ParseError::InvalidPacket),
        },
        // DNS typically runs on UDP port 53
        53 => match UdpPacket::new(payload) {
            Some(udp) => Ok((udp.get_source(), udp.get_destination())),
            None => Ok((53, 53)), // Default DNS ports if packet parsing fails
        },
        unknown_protocol => Ok(parse_unknown_protocol_ports(unknown_protocol, payload)),
    }
}
