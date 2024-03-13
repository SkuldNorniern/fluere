use crate::net::NetError;

use log::debug;
use pnet::packet::{tcp::TcpPacket, udp::UdpPacket};

pub fn parse_ports(protocol: u8, payload: &[u8]) -> Result<(u16, u16), NetError> {
    match protocol {
        58 => Ok((0, 0)),
        17 => match UdpPacket::new(payload) {
            Some(udp) => Ok((udp.get_source(), udp.get_destination())),
            None => Err(NetError::InvalidPacket),
        },
        6 => match TcpPacket::new(payload) {
            Some(tcp) => Ok((tcp.get_source(), tcp.get_destination())),
            None => Err(NetError::InvalidPacket),
        },
        2 => Ok((0, 0)),
        1 => Ok((0, 0)),
        0 => Ok((0, 0)),
        _ => {
            debug!("Unknown protocol: {}", protocol);
            Err(NetError::UnknownProtocol(protocol))
        }
    }
}
