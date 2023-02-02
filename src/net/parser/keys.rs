use pcap;

use pnet::packet::ethernet::EtherTypes::Ipv4;
use pnet::packet::ethernet::EtherTypes::Ipv6;
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::Packet;

use crate::net::errors::NetError;
use crate::net::parser::{parse_ports, protocol_to_number};
use crate::net::types::{Key, MacAddress};

use std::net::IpAddr;

pub fn parse_keys(packet: pcap::Packet) -> Result<(Key, Key), NetError> {
    let ethernet_packet = EthernetPacket::new(packet.data).unwrap();

    let src_mac = MacAddress::new(ethernet_packet.get_source().into());
    let dst_mac = MacAddress::new(ethernet_packet.get_destination().into());
    let (src_ip, dst_ip, src_port, dst_port, protocol) = match ethernet_packet.get_ethertype() {
        Ipv4 => {
            let i = Ipv4Packet::new(ethernet_packet.payload().clone()).unwrap();
            if i.payload().is_empty() {
                return Err(NetError::EmptyPacket);
            }

            let ipv4 = ipv4_keys(i);
            match ipv4 {
                Ok(_) => {}
                Err(e) => return Err(e),
            }

            ipv4.unwrap()
        }
        Ipv6 => {
            let i = Ipv6Packet::new(ethernet_packet.payload().clone()).unwrap();
            if i.payload().is_empty() {
                return Err(NetError::EmptyPacket);
            }

            let ipv6 = ipv6_keys(i);
            match ipv6 {
                Ok(_) => {}
                Err(e) => return Err(e),
            }

            ipv6.unwrap()
        }
        _ => {
            return Err(NetError::UnknownProtocol {
                protocol: ethernet_packet.get_ethertype().to_string(),
            })
        }
    };

    let key_value = Key {
        src_ip,
        src_port,
        dst_ip,
        dst_port,
        protocol,
        src_mac,
        dst_mac,
    };
    let key_reverse_value = Key {
        src_ip: dst_ip,
        src_port: dst_port,
        dst_ip: src_ip,
        dst_port: src_port,
        protocol,
        src_mac: dst_mac,
        dst_mac: src_mac,
    };

    Ok((key_value, key_reverse_value))
}

fn ipv4_keys(packet: Ipv4Packet) -> Result<(IpAddr, IpAddr, u16, u16, u8), NetError> {
    let src_ip = packet.get_source();
    let dst_ip = packet.get_destination();
    let protocol = protocol_to_number(packet.get_next_level_protocol());
    let parsed_ports = parse_ports(protocol, packet.payload());
    match parsed_ports {
        Ok(_) => {}
        Err(e) => return Err(e),
    }
    let (src_port, dst_port) = parsed_ports.unwrap();

    Ok((
        std::net::IpAddr::V4(src_ip),
        std::net::IpAddr::V4(dst_ip),
        src_port,
        dst_port,
        protocol,
    ))
}

fn ipv6_keys(packet: Ipv6Packet) -> Result<(IpAddr, IpAddr, u16, u16, u8), NetError> {
    let src_ip = packet.get_source();
    let dst_ip = packet.get_destination();
    let protocol = protocol_to_number(packet.get_next_header());
    let parsed_ports = parse_ports(protocol, packet.payload());
    match parsed_ports {
        Ok(_) => {}
        Err(e) => return Err(e),
    }
    let (src_port, dst_port) = parsed_ports.unwrap();

    Ok((
        std::net::IpAddr::V6(src_ip),
        std::net::IpAddr::V6(dst_ip),
        src_port,
        dst_port,
        protocol,
    ))
}
