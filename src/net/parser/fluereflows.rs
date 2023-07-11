use pcap;

use fluereflow::FluereRecord;
use pnet::packet::ethernet::EtherTypes;
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::Packet;
use pnet::packet::PacketSize;

use crate::net::errors::NetError;
use crate::net::parser::{
    dscp_to_tos, parse_flags, parse_microseconds, parse_ports, protocol_to_number,
};

pub fn parse_fluereflow(packet: pcap::Packet) -> Result<(usize, [u8; 9], FluereRecord), NetError> {
    if packet.is_empty() {
        return Err(NetError::EmptyPacket);
    }

    let ethernet_packet_raw = EthernetPacket::new(packet.data);
    let ethernet_packet = match ethernet_packet_raw {
        None => return Err(NetError::EmptyPacket),
        Some(e) => e,
    };

    let time = parse_microseconds(
        packet.header.ts.tv_sec as u64,
        packet.header.ts.tv_usec as u64,
    );
    let record_result = match ethernet_packet.get_ethertype() {
        EtherTypes::Ipv4 => {
            let i = Ipv4Packet::new(ethernet_packet.payload()).unwrap();
            if i.payload().is_empty() {
                return Err(NetError::EmptyPacket);
            }

            ipv4_packet(time, i)
        }
        EtherTypes::Ipv6 => {
            let i = Ipv6Packet::new(ethernet_packet.payload()).unwrap();
            if i.payload().is_empty() {
                return Err(NetError::EmptyPacket);
            }

            ipv6_packet(time, i)
        }
        _ => {
            return Err(NetError::UnknownProtocol {
                protocol: ethernet_packet.get_ethertype().to_string(),
            })
        }
    };

    match record_result {
        Ok(_) => {}
        Err(e) => return Err(e),
    }
    let (doctets, raw_flags, record) = record_result.unwrap();
    Ok((doctets, raw_flags, record))
}

fn ipv4_packet(time: u64, packet: Ipv4Packet) -> Result<(usize, [u8; 9], FluereRecord), NetError> {
    let protocol = protocol_to_number(packet.get_next_level_protocol());
    let src_ip = packet.get_source();
    let dst_ip = packet.get_destination();

    // ports parsing
    let parsed_ports = parse_ports(protocol, packet.payload());
    match parsed_ports {
        Ok(_) => {}
        Err(e) => return Err(e),
    }
    let (src_port, dst_port) = parsed_ports.unwrap();
    // TCP flags Fin Syn Rst Psh Ack Urg Ece Cwr Ns
    let flags = parse_flags(protocol, packet.payload());

    //	Autonomous system number of the source and destination, either origin or peer
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
    let protocol = protocol_to_number(packet.get_next_header());
    let src_ip = packet.get_source();
    let dst_ip = packet.get_destination();

    // ports parsing
    let parsed_ports = parse_ports(protocol, packet.payload());
    match parsed_ports {
        Ok(_) => {}
        Err(e) => return Err(e),
    }
    let (src_port, dst_port) = parsed_ports.unwrap();
    // TCP flags Fin Syn Rst Psh Ack Urg Ece Cwr Ns
    let flags = parse_flags(protocol, packet.payload());

    //	Autonomous system number of the source and destination, either origin or peer
    let doctets = packet.packet_size();
    //first six bits in the 8-bit Traffic Class field
    let dscp = packet.get_traffic_class() >> 2;
    let tos_convert_result = dscp_to_tos(dscp);
    let tos = tos_convert_result.unwrap_or(0);

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
