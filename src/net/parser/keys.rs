use std::net::IpAddr;

use crate::net::parser::parse_ports;
use crate::net::types::{Key, MacAddress};
use crate::net::NetError;

use pcap;

use pnet::packet::arp::ArpPacket;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::gre::GrePacket;
use pnet::packet::icmp::IcmpPacket;
use pnet::packet::icmpv6::Icmpv6Packet;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::dns::DnsPacket;
use pnet::packet::vlan::VlanPacket;
use pnet::packet::Packet;

use log::trace;





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
    trace!("Parsing keys");
    if packet.is_empty() {
        return Err(NetError::EmptyPacket);
    }
    trace!("Parsing ethernet packet");
    let ethernet_packet_raw = EthernetPacket::new(packet.data);
    let ethernet_packet_unpack = match ethernet_packet_raw {
        None => return Err(NetError::EmptyPacket),
        Some(e) => e,
    };
    trace!("Parsed ethernet packet");

    let is_udp: bool = match ethernet_packet_unpack.get_ethertype() {
        EtherTypes::Ipv6 => {
            let i = Ipv6Packet::new(ethernet_packet_unpack.payload());
            if i.is_none() {
                return Err(NetError::EmptyPacket);
            }
            let is_udp = UdpPacket::new(i.unwrap().payload()).is_some();

            is_udp
        }
        EtherTypes::Ipv4 => {
            let i = Ipv4Packet::new(ethernet_packet_unpack.payload());
            if i.is_none() {
                return Err(NetError::EmptyPacket);
            }

            let is_udp = UdpPacket::new(i.unwrap().payload()).is_some();

            is_udp
        }
        EtherTypes::Arp => {
            let i = ArpPacket::new(ethernet_packet_unpack.payload());
            if i.is_none() {
                return Err(NetError::EmptyPacket);
            }

            let is_udp = UdpPacket::new(i.unwrap().payload()).is_some();

            is_udp
        }

        _ => false,
    };
    trace!("Parsed if is UDP payload");
    trace!("is_udp: {:?}", is_udp);
    let mut decapsulated_data: Option<Vec<u8>> = None;

    if is_udp {
        let udp_payload = match ethernet_packet_unpack.get_ethertype() {
            EtherTypes::Ipv6 => {
                let i = Ipv6Packet::new(ethernet_packet_unpack.payload());
                if i.is_none() {
                    return Err(NetError::EmptyPacket);
                }

                UdpPacket::new(i.unwrap().payload()).unwrap().payload().to_vec()
            }
            EtherTypes::Ipv4 => {
                let i = Ipv4Packet::new(ethernet_packet_unpack.payload());
                if i.is_none() {
                    return Err(NetError::EmptyPacket);
                }

                UdpPacket::new(i.unwrap().payload()).unwrap().payload().to_vec()
            }
            EtherTypes::Arp => {
                let i = ArpPacket::new(ethernet_packet_unpack.payload());
                if i.is_none() {
                    return Err(NetError::EmptyPacket);
                }

                UdpPacket::new(i.unwrap().payload()).unwrap().payload().to_vec()
            }
            _ => Vec::new(),
        };
        trace!("Parsed UDP payload");
        if udp_payload.is_empty() {
            return Err(NetError::EmptyPacket);
        }
        trace!("Parsed UDP payload");
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
    trace!("ether type {:?}",ethernet_packet.get_ethertype());
    let (src_ip, dst_ip, src_port, dst_port, protocol) = match ethernet_packet.get_ethertype() {
        EtherTypes::Ipv6 => {
            let i = Ipv6Packet::new(ethernet_packet.payload());
            if i.is_none() {
                return Err(NetError::EmptyPacket);
            }

            trace!("IPv6 packet detected");

            ipv6_keys(i.unwrap())?
        }
        EtherTypes::Ipv4 => {
            let i = Ipv4Packet::new(ethernet_packet.payload());
            if i.is_none() {
                return Err(NetError::EmptyPacket);
            }

            trace!("IPv4 packet detected");

            ipv4_keys(i.unwrap())?
        }
        EtherTypes::Arp => {
            let i = ArpPacket::new(ethernet_packet.payload());
            if i.is_none() {
               return Err(NetError::EmptyPacket);
            }

            trace!("ARP packet detected");

            arp_keys(i.unwrap())?
        }
        EtherTypes::Vlan => {
            let i = VlanPacket::new(ethernet_packet.payload());
            if i.is_none() {
                return Err(NetError::EmptyPacket);
            }
            trace!("VLAN packet detected");
            vlan_keys(i.unwrap())?
        }
        EtherTypes::Rarp => {
            let i = ArpPacket::new(ethernet_packet.payload());
            if i.is_none() {
                return Err(NetError::EmptyPacket);
            }
            trace!("RARP packet detected");
            arp_keys(i.unwrap())?
        }
        _ => {
            //Check Every possible key parsing method
            let parse_test_ipv4 = ipv4_keys(Ipv4Packet::new(ethernet_packet.payload()).unwrap());
            let parse_test_ipv6 = ipv6_keys(Ipv6Packet::new(ethernet_packet.payload()).unwrap());
            let parse_test_arp = arp_keys(ArpPacket::new(ethernet_packet.payload()).unwrap());
            let parse_test_vlan = vlan_keys(VlanPacket::new(ethernet_packet.payload()).unwrap());
            // let parse_test_gre = gre_keys(GrePacket::new(ethernet_packet.payload()).unwrap());
            // let parse_test_icmpv6 = icmpv6_keys(Icmpv6Packet::new(ethernet_packet.payload()).unwrap());
            //let parse_test_tcp = tcp_keys(TcpPacket::new(ethernet_packet.payload()).unwrap());
            //let parse_test_udp = udp_keys(UdpPacket::new(ethernet_packet.payload()).unwrap());
            // let parse_test_dns = dns_keys(DnsPacket::new(ethernet_packet.payload()).unwrap());

            trace!("parse_test_ipv4: {:?}", parse_test_ipv4);
            trace!("parse_test_ipv6: {:?}", parse_test_ipv6);
            trace!("parse_test_arp: {:?}", parse_test_arp);
            trace!("parse_test_vlan: {:?}", parse_test_vlan);


            return Err(NetError::UnknownEtherType(
                ethernet_packet.get_ethertype().to_string(),
            ))

        }
    };
    trace!("Parsed keys");
    trace!("src_ip: {:?}", src_ip);
    trace!("dst_ip: {:?}", dst_ip);
    trace!("src_port: {:?}", src_port);
    trace!("dst_port: {:?}", dst_port);
    trace!("protocol: {:?}", protocol);
    trace!("src_mac: {:?}", src_mac);
    trace!("dst_mac: {:?}", dst_mac);
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
    let (src_port, dst_port) = parse_ports(protocol, packet.payload())?;

    // Handle GRE specially
    if protocol == 47 {
        if let Some(gre) = GrePacket::new(packet.payload()) {
            // For GRE, we might want to parse the inner protocol
            let inner_protocol = gre.get_protocol_type();
            return Ok((
                std::net::IpAddr::V4(src_ip),
                std::net::IpAddr::V4(dst_ip),
                inner_protocol, // Use inner protocol as "port"
                0,
                protocol,
            ));
        }
    }

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
    let (src_port, dst_port) = parse_ports(protocol, packet.payload())?;

    // Handle ICMPv6 specially
    if protocol == 58 {
        if let Some(icmpv6) = Icmpv6Packet::new(packet.payload()) {
            return Ok((
                std::net::IpAddr::V6(src_ip),
                std::net::IpAddr::V6(dst_ip),
                icmpv6.get_icmpv6_type().0 as u16, // Use ICMPv6 type as "port"
                icmpv6.get_icmpv6_code().0 as u16, // Use ICMPv6 code as "port"
                protocol,
            ));
        }
    }

    Ok((
        std::net::IpAddr::V6(src_ip),
        std::net::IpAddr::V6(dst_ip),
        src_port,
        dst_port,
        protocol,
    ))
}

fn vlan_keys(packet: VlanPacket) -> Result<(IpAddr, IpAddr, u16, u16, u8), NetError> {
    trace!("Parsing VLAN packet");
    let inner_packet = EthernetPacket::new(packet.payload()).ok_or(NetError::InvalidPacket)?;
    match inner_packet.get_ethertype() {
        EtherTypes::Ipv4 => {
            let ipv4_packet = Ipv4Packet::new(inner_packet.payload()).ok_or(NetError::InvalidPacket)?;
            ipv4_keys(ipv4_packet)
        }
        EtherTypes::Ipv6 => {
            let ipv6_packet = Ipv6Packet::new(inner_packet.payload()).ok_or(NetError::InvalidPacket)?;
            ipv6_keys(ipv6_packet)
        }
        _ => Err(NetError::UnknownEtherType(inner_packet.get_ethertype().to_string())),
    }
}
