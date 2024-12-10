use crate::net::NetError;

use log::debug;
use pnet::packet::{tcp::TcpPacket, udp::UdpPacket};

pub fn parse_ports(protocol: u8, payload: &[u8]) -> Result<(u16, u16), NetError> {
    match protocol {
        0 => Ok((0, 0)), // IPv6 Hop-by-Hop Option
        1 => Ok((0, 0)), // ICMP
        2 => Ok((0, 0)), // IGMP
        4 => Ok((0, 0)), // IPv4 encapsulation
        6 => match TcpPacket::new(payload) {
            Some(tcp) => Ok((tcp.get_source(), tcp.get_destination())),
            None => Err(NetError::InvalidPacket),
        },
        17 => match UdpPacket::new(payload) {
            Some(udp) => Ok((udp.get_source(), udp.get_destination())),
            None => Err(NetError::InvalidPacket),
        },
        47 => Ok((0, 0)), // GRE
        50 => Ok((0, 0)), // ESP
        51 => Ok((0, 0)), // AH
        58 => Ok((0, 0)), // ICMPv6
        // DNS typically runs on UDP port 53
        53 => match UdpPacket::new(payload) {
            Some(udp) => Ok((udp.get_source(), udp.get_destination())),
            None => Ok((53, 53)), // Default DNS ports if packet parsing fails
        },
        _ => {
            debug!("Unknown protocol: {}, returning default ports", protocol);
            Ok((0, 0)) // Return default ports instead of error for unknown protocols
        }
    }
}
