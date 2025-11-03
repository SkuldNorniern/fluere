use pcap;

use crate::net::NetError;
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

pub fn parse_fluereflow(packet: pcap::Packet) -> Result<(usize, [u8; 9], FluereRecord), NetError> {
    trace!("Parsing packet");
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
            let i = match Ipv6Packet::new(ethernet_packet_unpack.payload()) {
                Some(packet) => packet,
                None => return Err(NetError::InvalidPacket),
            };
            UdpPacket::new(i.payload()).is_some()
        }
        EtherTypes::Ipv4 => {
            let i = match Ipv4Packet::new(ethernet_packet_unpack.payload()) {
                Some(packet) => packet,
                None => return Err(NetError::InvalidPacket),
            };
            UdpPacket::new(i.payload()).is_some()
        }
        _ => false,
    };

    let mut decapsulated_data: Option<Vec<u8>> = None;

    if is_udp {
        let udp_payload = match ethernet_packet_unpack.get_ethertype() {
            EtherTypes::Ipv6 => {
                let i = match Ipv6Packet::new(ethernet_packet_unpack.payload()) {
                    Some(packet) => packet,
                    None => return Err(NetError::InvalidPacket),
                };

                match UdpPacket::new(i.payload()) {
                    Some(udp) => {
                        trace!("UDP payload length: {}", udp.payload().len());
                        udp.payload().to_vec()
                    }
                    None => return Err(NetError::InvalidPacket),
                }
            }
            EtherTypes::Ipv4 => {
                let i = match Ipv4Packet::new(ethernet_packet_unpack.payload()) {
                    Some(packet) => packet,
                    None => return Err(NetError::InvalidPacket),
                };

                match UdpPacket::new(i.payload()) {
                    Some(udp) => {
                        trace!("UDP payload length: {}", udp.payload().len());
                        udp.payload().to_vec()
                    }
                    None => return Err(NetError::InvalidPacket),
                }
            }
            _ => Vec::new(),
        };

        // Only check if UDP payload is empty when we expect it to have content
        if udp_payload.is_empty() && is_udp {
            trace!("Empty UDP payload detected");
        }

        decapsulated_data = decapsulate_vxlan(&udp_payload);
    }

    let ethernet_packet = if let Some(data) = &decapsulated_data {
        match EthernetPacket::new(data) {
            None => ethernet_packet_unpack, // Fall back to original packet if decapsulation fails
            Some(e) => e,
        }
    } else {
        ethernet_packet_unpack
    };

    let time = parse_microseconds(
        packet.header.ts.tv_sec as u64,
        packet.header.ts.tv_usec as u64,
    );

    let record_result = match ethernet_packet.get_ethertype() {
        EtherTypes::Ipv4 => {
            let i = match Ipv4Packet::new(ethernet_packet.payload()) {
                Some(packet) => packet,
                None => {
                    trace!("Failed to parse IPv4 packet");
                    return Err(NetError::InvalidPacket);
                }
            };
            ipv4_packet(time, i)
        }
        EtherTypes::Ipv6 => {
            let i = match Ipv6Packet::new(ethernet_packet.payload()) {
                Some(packet) => packet,
                None => {
                    trace!("Failed to parse IPv6 packet");
                    return Err(NetError::InvalidPacket);
                }
            };
            ipv6_packet(time, i)
        }
        EtherTypes::Arp => {
            let i = match ArpPacket::new(ethernet_packet.payload()) {
                Some(packet) => packet,
                None => {
                    trace!("Failed to parse ARP packet");
                    return Err(NetError::InvalidPacket);
                }
            };
            arp_packet(time, i)
        }
        ethertype => {
            trace!("Attempting fallback parsing for EtherType: {}", ethertype);
            if let Some(raw_header) =
                RawProtocolHeader::from_ethertype(ethernet_packet.packet(), ethertype.0)
            {
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
            } else {
                trace!("Unknown EtherType: {}", ethertype);
                Err(NetError::UnknownEtherType(ethertype.to_string()))
            }
        }
    }?;

    Ok(record_result)
}

fn arp_packet(time: u64, packet: ArpPacket) -> Result<(usize, [u8; 9], FluereRecord), NetError> {
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

fn ipv4_packet(time: u64, packet: Ipv4Packet) -> Result<(usize, [u8; 9], FluereRecord), NetError> {
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

fn ipv6_packet(time: u64, packet: Ipv6Packet) -> Result<(usize, [u8; 9], FluereRecord), NetError> {
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
