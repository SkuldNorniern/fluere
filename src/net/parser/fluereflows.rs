use pcap;

use crate::error::ParseError;
use crate::net::parser::raw::RawProtocolHeader;
use crate::net::parser::{dscp_to_tos, parse_flags, parse_microseconds, parse_ports};

use fluereflow::FluereRecord;
use log::trace;
use pnet::packet::{
    Packet, PacketSize,
    arp::ArpPacket,
    ethernet::{EtherTypes, EthernetPacket},
    ip::IpNextHeaderProtocols,
    ipv4::Ipv4Packet,
    ipv6::Ipv6Packet,
    udp::UdpPacket,
};

const VXLAN_HEADER: [u8; 8] = [0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64, 0x00];

fn decapsulate_vxlan(payload: &[u8]) -> Option<Vec<u8>> {
    if payload.starts_with(&VXLAN_HEADER) {
        //println!("Decapsulating VXLAN");
        Some(payload[VXLAN_HEADER.len()..].to_vec())
    } else {
        None
    }
}

/// Extract the UDP payload beneath an IPv6/IPv4 L3 header (if any). Returns
/// `Err(InvalidPacket)` if the ethertype implies an L3 header that fails to
/// parse; `Ok(None)` for ethertypes with no UDP-bearing L3 (or L3 that isn't
/// UDP), matching the prior two-pass is_udp/udp_payload behavior (where a
/// failed `UdpPacket::new` meant `is_udp == false`, not an error).
fn extract_udp_payload(
    ethertype: pnet::packet::ethernet::EtherType,
    payload: &[u8],
) -> Result<Option<Vec<u8>>, ParseError> {
    let inner_payload: Vec<u8> = match ethertype {
        EtherTypes::Ipv6 => Ipv6Packet::new(payload)
            .ok_or(ParseError::InvalidPacket)?
            .payload()
            .to_vec(),
        EtherTypes::Ipv4 => Ipv4Packet::new(payload)
            .ok_or(ParseError::InvalidPacket)?
            .payload()
            .to_vec(),
        _ => return Ok(None),
    };
    Ok(UdpPacket::new(&inner_payload).map(|udp| {
        trace!("UDP payload length: {}", udp.payload().len());
        udp.payload().to_vec()
    }))
}

/// If the frame carries a VXLAN-encapsulated inner Ethernet frame, return its
/// raw bytes; otherwise `Ok(None)`.
fn maybe_vxlan_payload(
    ethertype: pnet::packet::ethernet::EtherType,
    payload: &[u8],
) -> Result<Option<Vec<u8>>, ParseError> {
    let Some(udp_payload) = extract_udp_payload(ethertype, payload)? else {
        return Ok(None);
    };
    Ok(decapsulate_vxlan(&udp_payload))
}

/// Dispatch to the correct per-ethertype record extractor.
fn dispatch_fluereflow(
    ethernet_packet: &EthernetPacket,
    time: u64,
) -> Result<(usize, [u8; 9], FluereRecord), ParseError> {
    match ethernet_packet.get_ethertype() {
        EtherTypes::Ipv4 => {
            let i = Ipv4Packet::new(ethernet_packet.payload()).ok_or_else(|| {
                trace!("Failed to parse IPv4 packet");
                ParseError::InvalidPacket
            })?;
            ipv4_packet(time, i)
        }
        EtherTypes::Ipv6 => {
            let i = Ipv6Packet::new(ethernet_packet.payload()).ok_or_else(|| {
                trace!("Failed to parse IPv6 packet");
                ParseError::InvalidPacket
            })?;
            ipv6_packet(time, i)
        }
        EtherTypes::Arp => {
            let i = ArpPacket::new(ethernet_packet.payload()).ok_or_else(|| {
                trace!("Failed to parse ARP packet");
                ParseError::InvalidPacket
            })?;
            arp_packet(time, i)
        }
        ethertype => fallback_fluereflow(ethernet_packet, ethertype, time),
    }
}

/// Fallback for ethertypes with no dedicated arm: try the raw protocol-agnostic
/// parser via ethertype.
fn fallback_fluereflow(
    ethernet_packet: &EthernetPacket,
    ethertype: pnet::packet::ethernet::EtherType,
    time: u64,
) -> Result<(usize, [u8; 9], FluereRecord), ParseError> {
    trace!("Attempting fallback parsing for EtherType: {}", ethertype);
    let Some(raw_header) = RawProtocolHeader::from_ethertype(ethernet_packet.packet(), ethertype.0)
    else {
        trace!("Unknown EtherType: {}", ethertype);
        return Err(ParseError::UnknownEtherType(ethertype.to_string()));
    };

    let flags = raw_header.flags.map_or([0; 9], |f| parse_flags(f, &[]));
    Ok((
        raw_header.length as usize,
        flags,
        FluereRecord::new(
            raw_header
                .src_ip
                .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)),
            raw_header
                .dst_ip
                .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)),
            0,
            0,
            time,
            time,
            raw_header.src_port,
            raw_header.dst_port,
            raw_header.length as u32,
            raw_header.length as u32,
            raw_header.ttl.unwrap_or(0),
            raw_header.ttl.unwrap_or(0),
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            raw_header.protocol,
            0,
        ),
    ))
}

pub fn parse_fluereflow(packet: pcap::Packet) -> Result<(usize, [u8; 9], FluereRecord), ParseError> {
    trace!("Parsing packet");
    if packet.is_empty() {
        return Err(ParseError::EmptyPacket);
    }

    let ethernet_packet_unpack =
        EthernetPacket::new(packet.data).ok_or(ParseError::EmptyPacket)?;

    let decapsulated_data = maybe_vxlan_payload(
        ethernet_packet_unpack.get_ethertype(),
        ethernet_packet_unpack.payload(),
    )?;

    let ethernet_packet = match &decapsulated_data {
        Some(data) => match EthernetPacket::new(data) {
            None => ethernet_packet_unpack, // Fall back to original packet if decapsulation fails
            Some(e) => e,
        },
        None => ethernet_packet_unpack,
    };

    let time = parse_microseconds(
        packet.header.ts.tv_sec as u64,
        packet.header.ts.tv_usec as u64,
    );

    dispatch_fluereflow(&ethernet_packet, time)
}

fn arp_packet(time: u64, packet: ArpPacket) -> Result<(usize, [u8; 9], FluereRecord), ParseError> {
    let src_ip = packet.get_sender_proto_addr();
    let dst_ip = packet.get_target_proto_addr();

    // ports parsing
    let src_port = 0;
    let dst_port = 0;
    // TCP flags Fin Syn Rst Psh Ack Urg Ece Cwr Ns
    let flags = parse_flags(4, packet.payload());

    //	Autonomous system number of the source and destination, either origin or peer
    let doctets = packet.packet_size();

    Ok((
        doctets,
        flags,
        FluereRecord::new(
            std::net::IpAddr::V4(src_ip),
            std::net::IpAddr::V4(dst_ip),
            0,
            0,
            time,
            time,
            src_port,
            dst_port,
            packet.packet_size() as u32,
            packet.packet_size() as u32,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            4,
            0,
        ),
    ))
}

fn ipv4_packet(time: u64, packet: Ipv4Packet) -> Result<(usize, [u8; 9], FluereRecord), ParseError> {
    let protocol = packet.get_next_level_protocol().0;
    let src_ip = packet.get_source();
    let dst_ip = packet.get_destination();

    // Special handling for DNS over UDP
    if packet.get_next_level_protocol() == IpNextHeaderProtocols::Udp
        && let Some(udp) = UdpPacket::new(packet.payload())
            && (udp.get_destination() == 53 || udp.get_source() == 53) {
                return Ok((
                    packet.packet_size(),
                    [0; 9], // DNS doesn't use TCP flags
                    FluereRecord::new(
                        std::net::IpAddr::V4(src_ip),
                        std::net::IpAddr::V4(dst_ip),
                        0,
                        0,
                        time,
                        time,
                        udp.get_source(),
                        udp.get_destination(),
                        udp.packet_size() as u32,
                        udp.packet_size() as u32,
                        packet.get_ttl(),
                        packet.get_ttl(),
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        17, // UDP
                        0,  // No TOS for DNS
                    ),
                ));
            }

    // Continue with normal packet processing...
    let (src_port, dst_port) = parse_ports(protocol, packet.payload()).unwrap_or((0, 0));

    // TCP flags
    let flags = parse_flags(protocol, packet.payload());

    let doctets = packet.packet_size();
    let tos_convert_result = dscp_to_tos(packet.get_dscp());
    let tos = tos_convert_result.unwrap_or(0);

    Ok((
        doctets,
        flags,
        FluereRecord::new(
            std::net::IpAddr::V4(src_ip),
            std::net::IpAddr::V4(dst_ip),
            0,
            0,
            time,
            time,
            src_port,
            dst_port,
            packet.get_total_length() as u32,
            packet.get_total_length() as u32,
            packet.get_ttl(),
            packet.get_ttl(),
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            protocol,
            tos,
        ),
    ))
}

fn ipv6_packet(time: u64, packet: Ipv6Packet) -> Result<(usize, [u8; 9], FluereRecord), ParseError> {
    let protocol = packet.get_next_header().0;
    let src_ip = packet.get_source();
    let dst_ip = packet.get_destination();

    // ports parsing
    let (src_port, dst_port) = parse_ports(protocol, packet.payload())?;
    // TCP flags Fin Syn Rst Psh Ack Urg Ece Cwr Ns
    let flags = parse_flags(protocol, packet.payload());

    //	Autonomous system number of the source and destination, either origin or peer
    let doctets = packet.packet_size();
    //first six bits in the 8-bit Traffic Class field
    let dscp = packet.get_traffic_class() >> 2;
    let tos_convert_result = dscp_to_tos(dscp);
    let tos = tos_convert_result.unwrap_or_default();

    Ok((
        doctets,
        flags,
        FluereRecord::new(
            std::net::IpAddr::V6(src_ip),
            std::net::IpAddr::V6(dst_ip),
            0,
            0,
            time,
            time,
            src_port,
            dst_port,
            packet.get_payload_length() as u32,
            packet.get_payload_length() as u32,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            protocol,
            tos,
        ),
    ))
}
