use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;

use crate::net::errors::NetError;

pub fn parse_ports(protocol: u8, payload: &[u8]) -> Result<(u16, u16), NetError> {
    match protocol {
        58 => Ok((0, 0)),
        17 => {
            let udp = UdpPacket::new(payload).unwrap();

            Ok((udp.get_source(), udp.get_destination()))
        }
        6 => {
            let tcp = TcpPacket::new(payload).unwrap();

            Ok((tcp.get_source(), tcp.get_destination()))
        }
        2 => Ok((0, 0)),
        1 => Ok((0, 0)),
        0 => Ok((0, 0)),
        _ => {
            println!("Unknown protocol: {}", protocol);
            Err(NetError::UnknownProtocol {
                protocol: protocol.to_string(),
            })
        }
    }

    //Err(NetError::UnknownProtocol {
    //    protocol: protocol.to_string(),
    //})
}
