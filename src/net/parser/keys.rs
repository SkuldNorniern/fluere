use std::net::{IpAddr, Ipv4Addr};

use crate::error::ParseError;
use crate::net::parser::parse_ports;
use crate::net::types::{Key, MacAddress};

use pcap;

use pnet::packet::Packet;
use pnet::packet::arp::ArpPacket;
use pnet::packet::ethernet::{EtherType, EtherTypes, EthernetPacket};
use pnet::packet::gre::GrePacket;
use pnet::packet::icmpv6::Icmpv6Packet;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::udp::UdpPacket;
use pnet::packet::vlan::VlanPacket;

use log::trace;

use super::raw::RawProtocolHeader;

const VXLAN_HEADER: [u8; 8] = [0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64, 0x00];

fn decapsulate_vxlan(payload: &[u8]) -> Option<Vec<u8>> {
    if payload.starts_with(&VXLAN_HEADER) {
        //println!("Decapsulating VXLAN");
        Some(payload[VXLAN_HEADER.len()..].to_vec())
    } else {
        None
    }
}

/// For ethertypes that carry an IP/ARP header, extract the UDP payload beneath
/// it (if any). Returns `Err` if the ethertype implies an L3 header that fails
/// to parse; returns `Ok(None)` for ethertypes with no UDP-bearing L3 (or L3
/// that isn't UDP), matching the prior two-pass is_udp/udp_payload behavior.
fn extract_udp_payload(
    ethertype: EtherType,
    payload: &[u8],
) -> Result<Option<Vec<u8>>, ParseError> {
    let inner_payload: Vec<u8> = match ethertype {
        EtherTypes::Ipv6 => Ipv6Packet::new(payload)
            .ok_or(ParseError::EmptyPacket)?
            .payload()
            .to_vec(),
        EtherTypes::Ipv4 => Ipv4Packet::new(payload)
            .ok_or(ParseError::EmptyPacket)?
            .payload()
            .to_vec(),
        EtherTypes::Arp => ArpPacket::new(payload)
            .ok_or(ParseError::EmptyPacket)?
            .payload()
            .to_vec(),
        _ => return Ok(None),
    };
    Ok(UdpPacket::new(&inner_payload).map(|udp| udp.payload().to_vec()))
}

/// If the frame carries a VXLAN-encapsulated inner Ethernet frame, return its
/// raw bytes; otherwise `Ok(None)`.
fn maybe_vxlan_payload(
    ethertype: EtherType,
    payload: &[u8],
) -> Result<Option<Vec<u8>>, ParseError> {
    let Some(udp_payload) = extract_udp_payload(ethertype, payload)? else {
        return Ok(None);
    };
    trace!("Parsed UDP payload");
    if udp_payload.is_empty() {
        return Err(ParseError::EmptyPacket);
    }
    Ok(decapsulate_vxlan(&udp_payload))
}

/// Dispatch to the correct per-ethertype key extractor.
fn dispatch_keys(
    ethertype: EtherType,
    l3_payload: &[u8],
) -> Result<(IpAddr, IpAddr, u16, u16, u8), ParseError> {
    match ethertype {
        EtherTypes::Ipv6 => {
            ipv6_keys(Ipv6Packet::new(l3_payload).ok_or(ParseError::EmptyPacket)?)
        }
        EtherTypes::Ipv4 => {
            ipv4_keys(Ipv4Packet::new(l3_payload).ok_or(ParseError::EmptyPacket)?)
        }
        EtherTypes::Arp | EtherTypes::Rarp => {
            arp_keys(ArpPacket::new(l3_payload).ok_or(ParseError::EmptyPacket)?)
        }
        EtherTypes::Vlan => {
            vlan_keys(VlanPacket::new(l3_payload).ok_or(ParseError::EmptyPacket)?)
        }
        other => fallback_keys(other, l3_payload),
    }
}

pub fn parse_keys(packet: pcap::Packet) -> Result<(Key, Key), ParseError> {
    trace!("Parsing keys");
    if packet.is_empty() {
        return Err(ParseError::EmptyPacket);
    }
    trace!("Parsing ethernet packet");
    let ethernet_packet = EthernetPacket::new(packet.data).ok_or(ParseError::InvalidPacket)?;
    trace!("Parsed ethernet packet");

    let decapsulated_data =
        maybe_vxlan_payload(ethernet_packet.get_ethertype(), ethernet_packet.payload())?;

    let ethernet_packet = match &decapsulated_data {
        Some(data) => EthernetPacket::new(data).ok_or(ParseError::EmptyPacket)?,
        None => ethernet_packet,
    };

    let src_mac = MacAddress::new(ethernet_packet.get_source().into());
    let dst_mac = MacAddress::new(ethernet_packet.get_destination().into());
    trace!("ether type {:?}", ethernet_packet.get_ethertype());
    let (src_ip, dst_ip, src_port, dst_port, protocol) =
        dispatch_keys(ethernet_packet.get_ethertype(), ethernet_packet.payload())?;
    trace!(
        "Parsed keys: src_ip={:?} dst_ip={:?} src_port={:?} dst_port={:?} protocol={:?} src_mac={:?} dst_mac={:?}",
        src_ip, dst_ip, src_port, dst_port, protocol, src_mac, dst_mac
    );
    Ok(build_key_pair(
        src_ip, dst_ip, src_port, dst_port, protocol, src_mac, dst_mac,
    ))
}

/// Build the forward and reverse `Key` for a flow from its extracted fields.
#[allow(clippy::too_many_arguments)]
fn build_key_pair(
    src_ip: IpAddr,
    dst_ip: IpAddr,
    src_port: u16,
    dst_port: u16,
    protocol: u8,
    src_mac: MacAddress,
    dst_mac: MacAddress,
) -> (Key, Key) {
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
    (key_value, key_reverse_value)
}

/// Fallback for ethertypes with no dedicated arm: try each standard parser in
/// turn, then fall back to the raw protocol-agnostic parser.
fn fallback_keys(
    ethertype: EtherType,
    payload: &[u8],
) -> Result<(IpAddr, IpAddr, u16, u16, u8), ParseError> {
    let parse_test_ipv4 = Ipv4Packet::new(payload)
        .ok_or(ParseError::InvalidPacket)
        .and_then(ipv4_keys);
    let parse_test_ipv6 = Ipv6Packet::new(payload)
        .ok_or(ParseError::InvalidPacket)
        .and_then(ipv6_keys);
    let parse_test_arp = ArpPacket::new(payload)
        .ok_or(ParseError::InvalidPacket)
        .and_then(arp_keys);
    let parse_test_vlan = VlanPacket::new(payload)
        .ok_or(ParseError::InvalidPacket)
        .and_then(vlan_keys);

    // If all standard parsers fail, try raw parser as fallback
    let parse_test_raw = RawProtocolHeader::from_raw_packet(payload, ethertype.0 as u8)
        .map(|raw_header| {
            (
                raw_header
                    .src_ip
                    .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
                raw_header
                    .dst_ip
                    .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
                raw_header.src_port,
                raw_header.dst_port,
                raw_header.protocol,
            )
        })
        .ok_or(ParseError::InvalidPacket);

    trace!("parse_test_ipv4: {:?}", parse_test_ipv4);
    trace!("parse_test_ipv6: {:?}", parse_test_ipv6);
    trace!("parse_test_arp: {:?}", parse_test_arp);
    trace!("parse_test_vlan: {:?}", parse_test_vlan);
    trace!("parse_test_raw: {:?}", parse_test_raw);

    // Try to use the first successful parse result, including raw parser
    parse_test_ipv4
        .or(parse_test_ipv6)
        .or(parse_test_arp)
        .or(parse_test_vlan)
        .or(parse_test_raw)
        .or(Err(ParseError::UnknownEtherType(ethertype.to_string())))
}

fn arp_keys(packet: ArpPacket) -> Result<(IpAddr, IpAddr, u16, u16, u8), ParseError> {
    let sender_ip = packet.get_sender_proto_addr();
    let target_ip = packet.get_target_proto_addr();
    let src_port = 0;
    let dst_port = 0;
    let protocol = 4;

    Ok((
        IpAddr::V4(sender_ip),
        IpAddr::V4(target_ip),
        src_port,
        dst_port,
        protocol,
    ))
}

fn ipv4_keys(packet: Ipv4Packet) -> Result<(IpAddr, IpAddr, u16, u16, u8), ParseError> {
    let src_ip = packet.get_source();
    let dst_ip = packet.get_destination();
    let protocol = packet.get_next_level_protocol().0;
    let (src_port, dst_port) = parse_ports(protocol, packet.payload())?;

    // Handle GRE specially
    if protocol == 47
        && let Some(gre) = GrePacket::new(packet.payload()) {
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

    Ok((
        std::net::IpAddr::V4(src_ip),
        std::net::IpAddr::V4(dst_ip),
        src_port,
        dst_port,
        protocol,
    ))
}

fn ipv6_keys(packet: Ipv6Packet) -> Result<(IpAddr, IpAddr, u16, u16, u8), ParseError> {
    let src_ip = packet.get_source();
    let dst_ip = packet.get_destination();
    let protocol = packet.get_next_header().0;
    let (src_port, dst_port) = parse_ports(protocol, packet.payload())?;

    // Handle ICMPv6 specially
    if protocol == 58
        && let Some(icmpv6) = Icmpv6Packet::new(packet.payload()) {
            return Ok((
                std::net::IpAddr::V6(src_ip),
                std::net::IpAddr::V6(dst_ip),
                icmpv6.get_icmpv6_type().0 as u16, // Use ICMPv6 type as "port"
                icmpv6.get_icmpv6_code().0 as u16, // Use ICMPv6 code as "port"
                protocol,
            ));
        }

    Ok((
        std::net::IpAddr::V6(src_ip),
        std::net::IpAddr::V6(dst_ip),
        src_port,
        dst_port,
        protocol,
    ))
}

fn vlan_keys(packet: VlanPacket) -> Result<(IpAddr, IpAddr, u16, u16, u8), ParseError> {
    trace!("Parsing VLAN packet");
    let inner_packet = EthernetPacket::new(packet.payload()).ok_or(ParseError::InvalidPacket)?;
    match inner_packet.get_ethertype() {
        EtherTypes::Ipv4 => {
            let ipv4_packet =
                Ipv4Packet::new(inner_packet.payload()).ok_or(ParseError::InvalidPacket)?;
            ipv4_keys(ipv4_packet)
        }
        EtherTypes::Ipv6 => {
            let ipv6_packet =
                Ipv6Packet::new(inner_packet.payload()).ok_or(ParseError::InvalidPacket)?;
            ipv6_keys(ipv6_packet)
        }
        _ => Err(ParseError::UnknownEtherType(
            inner_packet.get_ethertype().to_string(),
        )),
    }
}
