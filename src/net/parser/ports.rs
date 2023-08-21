use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;

use crate::net::errors::NetError;

// Function to parse UDP ports
fn parse_udp_ports(payload: &[u8]) -> Result<(u16, u16), NetError> {
    let udp = UdpPacket::new(payload).unwrap();
    Ok((udp.get_source(), udp.get_destination()))
}

// Function to parse TCP ports
fn parse_tcp_ports(payload: &[u8]) -> Result<(u16, u16), NetError> {
    let tcp = TcpPacket::new(payload).unwrap();
    Ok((tcp.get_source(), tcp.get_destination()))
}

// Function to parse ICMP ports
fn parse_icmp_ports() -> Result<(u16, u16), NetError> {
    Ok((0, 0))
}

pub fn parse_ports(protocol: u8, payload: &[u8]) -> Result<(u16, u16), NetError> {
    match protocol {
        58 => parse_icmp_ports(),
        17 => parse_udp_ports(payload),
        6 => parse_tcp_ports(payload),
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
}
    //Err(NetError::UnknownProtocol {
    //    protocol: protocol.to_string(),
    //})
}
