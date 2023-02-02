use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;

use crate::net::errors::NetError;

pub fn parse_ports(protocol: u8, payload: &[u8]) -> Result<(u16, u16), NetError> {
    match protocol {
        58 => return Ok((0, 0)),
        17 => {
            let udp = UdpPacket::new(payload).unwrap();

            return Ok((udp.get_source(), udp.get_destination()));
        }
        6 => {
            let tcp = TcpPacket::new(payload).unwrap();

            return Ok((tcp.get_source(), tcp.get_destination()));
        }
        1 => return Ok((0, 0)),
        _ => {}
    }

    Err(NetError::UnknownProtocol {
        protocol: protocol.to_string(),
    })
}
