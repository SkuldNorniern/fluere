use pcap;

use pnet::packet::arp::ArpPacket;
use pnet::packet::ethernet::EtherTypes;
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;

use crate::net::errors::NetError;
use crate::net::parser::{parse_ports, protocol_to_number};
use crate::net::types::{Key, MacAddress};

use std::net::IpAddr;

const VXLAN_HEADER: [u8; 8] = [0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64, 0x00];

fn decapsulate_vxlan(payload: &[u8]) -> Option<Vec<u8>> {
    if payload.starts_with(&VXLAN_HEADER) {
        //println!("Decapsulating VXLAN");
        Some(payload[VXLAN_HEADER.len()..].to_vec())
    } else {
        None
    }
}

// Moved to keys_parser.rs

fn arp_keys(packet: ArpPacket) -> Result<(IpAddr, IpAddr, u16, u16, u8), NetError> {
    let src_ip = packet.get_sender_proto_addr();
    let dst_ip = packet.get_target_proto_addr();
    let src_port = 0;
    let dst_port = 0;
    let protocol = 4;

    Ok((
        std::net::IpAddr::V4(src_ip),
        std::net::IpAddr::V4(dst_ip),
        src_port,
        dst_port,
        protocol,
    ))
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
