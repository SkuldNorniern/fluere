use pcap;

use pnet::packet::ethernet::EtherTypes::Ipv4;
use pnet::packet::ethernet::EthernetPacket;

use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::Packet;

use crate::net::errors::NetError;
use crate::net::parser::{
    dscp_to_tos, parse_etherprotocol, parse_flags, parse_ipv4, parse_ports, protocol_to_number,
};
use crate::net::types::{FluereRecord, Key, MacAddress};

pub fn fluereflow_convert(
    packet: pcap::Packet,
) -> Result<
    (
        Key,
        Key,
        u32,
        (u32, u32, u32, u32, u32, u32, u32, u32, u32),
        FluereRecord,
    ),
    NetError,
> {
    let e = EthernetPacket::new(packet.data).unwrap();
    //println!("Ethernet packet: {:?}", e.get_ethertype());
    match e.get_ethertype() {
        Ipv4 => {}
        _ => {
            return Err(NetError::UnknownProtocol {
                protocol: e.get_ethertype().to_string(),
            })
        }
    }
    let i = Ipv4Packet::new(e.payload()).unwrap();
    if i.payload().is_empty() {
        return Err(NetError::EmptyPacket);
    }
    let protocol = protocol_to_number(i.get_next_level_protocol());

    let (_packet_data, _frame) = parse_etherprotocol(packet.data).unwrap();

    let (_frame_data, _ipv4) = parse_ipv4(_packet_data).unwrap();

    let src_ip = i.get_source();
    let dst_ip = i.get_destination();

    // ports parsing
    let parsed_ports = parse_ports(protocol, i.payload());
    match parsed_ports {
        Ok(_) => {}
        Err(e) => return Err(e),
    }
    let (src_port, dst_port) = parsed_ports.unwrap();
    // TCP flags Fin Syn Rst Psh Ack Urg Ece Cwr Ns
    let flags = parse_flags(protocol, i.payload());

    //	Autonomous system number of the source and destination, either origin or peer
    let doctets = i.get_total_length() as u32;
    let src_mac = MacAddress::new(e.get_source().into());
    let dst_mac = MacAddress::new(e.get_destination().into());

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
    let tos_convert_result = dscp_to_tos(i.get_dscp());
    let tos = match tos_convert_result {
        Ok(_) => tos_convert_result.unwrap(),
        Err(_) => 0,
    };
    Ok((
        key_value,
        key_reverse_value,
        doctets,
        flags,
        FluereRecord::new(
            i.get_source(),
            i.get_destination(),
            0,
            0,
            packet.header.ts.tv_sec as u32,
            packet.header.ts.tv_sec as u32,
            src_port,
            dst_port,
            i.get_total_length() as u32,
            i.get_total_length() as u32,
            i.get_ttl(),
            i.get_ttl(),
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
