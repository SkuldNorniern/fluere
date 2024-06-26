use pcap;

use pnet::packet::arp::ArpPacket;
use pnet::packet::ethernet::EtherTypes;
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::udp::UdpPacket;

use pnet::packet::Packet;

use log::trace;

use crate::net::parser::parse_ports;
use crate::net::types::{Key, MacAddress};
use crate::net::NetError;

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

pub fn parse_keys(packet: pcap::Packet) -> Result<(Key, Key), NetError> {
    if packet.is_empty() {
        return Err(NetError::EmptyPacket);
    }
    let ethernet_packet_raw = EthernetPacket::new(packet.data);
    let ethernet_packet_unpack = match ethernet_packet_raw {
        None => return Err(NetError::EmptyPacket),
        Some(e) => e,
    };

    let is_udp: bool = match ethernet_packet_unpack.get_ethertype() {
        EtherTypes::Ipv6 => {
            let i = Ipv6Packet::new(ethernet_packet_unpack.payload()).unwrap();
            if i.payload().is_empty() {
                return Err(NetError::EmptyPacket);
            }
            let is_udp = UdpPacket::new(i.payload()).is_some();

            is_udp
        }
        EtherTypes::Ipv4 => {
            let i = Ipv4Packet::new(ethernet_packet_unpack.payload()).unwrap();
            if i.payload().is_empty() {
                return Err(NetError::EmptyPacket);
            }

            let is_udp = UdpPacket::new(i.payload()).is_some();

            is_udp
        }
        _ => false,
    };
    let mut decapsulated_data: Option<Vec<u8>> = None;

    if is_udp {
        let udp_payload = match ethernet_packet_unpack.get_ethertype() {
            EtherTypes::Ipv6 => {
                let i = Ipv6Packet::new(ethernet_packet_unpack.payload()).unwrap();
                if i.payload().is_empty() {
                    return Err(NetError::EmptyPacket);
                }

                UdpPacket::new(i.payload()).unwrap().payload().to_vec()
            }
            EtherTypes::Ipv4 => {
                let i = Ipv4Packet::new(ethernet_packet_unpack.payload()).unwrap();
                if i.payload().is_empty() {
                    return Err(NetError::EmptyPacket);
                }

                UdpPacket::new(i.payload()).unwrap().payload().to_vec()
            }
            _ => Vec::new(),
        };
        if udp_payload.is_empty() {
            return Err(NetError::EmptyPacket);
        }
        //UdpPacket::new(ethernet_packet_unpack.payload()).unwrap().payload().to_vec();
        //println!("UDP payload: {:?}", udp_payload);
        decapsulated_data = decapsulate_vxlan(&udp_payload);
    }

    let ethernet_packet_decapsulated = if let Some(data) = &decapsulated_data {
        match EthernetPacket::new(data) {
            None => return Err(NetError::EmptyPacket),
            Some(e) => e,
        }
    } else {
        ethernet_packet_unpack
    };

    let ethernet_packet = ethernet_packet_decapsulated;

    let src_mac = MacAddress::new(ethernet_packet.get_source().into());
    let dst_mac = MacAddress::new(ethernet_packet.get_destination().into());
    //println!("ether type {:?}",ethernet_packet.get_ethertype());
    let (src_ip, dst_ip, src_port, dst_port, protocol) = match ethernet_packet.get_ethertype() {
        EtherTypes::Ipv6 => {
            let i = Ipv6Packet::new(ethernet_packet.payload()).unwrap();
            if i.payload().is_empty() {
                return Err(NetError::EmptyPacket);
            }

            trace!("IPv6 packet detected");

            ipv6_keys(i)?
        }
        EtherTypes::Ipv4 => {
            let i = Ipv4Packet::new(ethernet_packet.payload()).unwrap();
            if i.payload().is_empty() {
                return Err(NetError::EmptyPacket);
            }

            trace!("IPv4 packet detected");

            ipv4_keys(i)?
        }
        EtherTypes::Arp => {
            let i = ArpPacket::new(ethernet_packet.payload()).unwrap();
            //if i.payload().is_empty() {
            //    return Err(NetError::EmptyPacket);
            //}

            trace!("ARP packet detected");

            arp_keys(i)?
        }
        _ => {
            return Err(NetError::UnknownEtherType(
                ethernet_packet.get_ethertype().to_string(),
            ))
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
    let protocol = packet.get_next_level_protocol().0;
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
    let protocol = packet.get_next_header().0;
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
