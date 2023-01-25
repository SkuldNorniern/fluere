use pcap;

use pnet::packet::ethernet::EthernetPacket;

use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;

use crate::net::errors::NetError;
use crate::net::parser::{dscp_to_tos, parse_etherprotocol, parse_ipv4, protocol_to_number};
use crate::net::types::{FluereRecord, Key, MacAddress};

use std::net::Ipv4Addr;

pub fn fluereflow_convert(
    packet: pcap::Packet,
) -> Result<(Key, Key,u32, (u32, u32, u32, u32, u32, u32, u32, u32, u32), FluereRecord), NetError> {
    let e = EthernetPacket::new(packet.data).unwrap();
    let i = Ipv4Packet::new(e.payload()).unwrap();
    let protocol = protocol_to_number(i.get_next_level_protocol());

    let (_packet_data, _frame) = parse_etherprotocol(packet.data).unwrap();

    let (_frame_data, _ipv4) = parse_ipv4(_packet_data).unwrap();
    if i.payload().is_empty() {
        return Err(NetError::EmptyPacket);
    }

    let src_ip = i.get_source();
    let dst_ip = i.get_destination();

    let (src_port, dst_port) = match protocol {
        17 => {
            let udp = UdpPacket::new(i.payload()).unwrap();

            (udp.get_source(), udp.get_destination())
        }
        6 => {
            let tcp = TcpPacket::new(i.payload()).unwrap();

            (tcp.get_source(), tcp.get_destination())
        }
        0 => (0, 0),
        _ => {
            return Err(NetError::UnknownProtocol {
                protocol: protocol.to_string(),
            })
        } //panic!("Unknown protocol {:?}", i),
    };
    // TCP flags Fin Syn Rst Psh Ack Urg Ece Cwr Ns
    let flags = match protocol {
        6 => {
            let tcp = TcpPacket::new(i.payload()).unwrap();
            let tcp_flags = tcp.get_flags();

            (
                match tcp_flags & 0x01 {
                    0 => 0,
                    _ => 1,
                },
                match tcp_flags & 0x02 {
                    0 => 0,
                    _ => 1,
                },
                match tcp_flags & 0x04 {
                    0 => 0,
                    _ => 1,
                },
                match tcp_flags & 0x08 {
                    0 => 0,
                    _ => 1,
                },
                match tcp_flags & 0x10 {
                    0 => 0,
                    _ => 1,
                },
                match tcp_flags & 0x20 {
                    0 => 0,
                    _ => 1,
                },
                match tcp_flags & 0x40 {
                    0 => 0,
                    _ => 1,
                },
                match tcp_flags & 0x80 {
                    0 => 0,
                    _ => 1,
                },
                match tcp_flags & 0x100 {
                    0 => 0,
                    _ => 1,
                },
            )
        }
        _ => (0, 0, 0, 0, 0, 0, 0, 0, 0),
    };

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
        dst_ip,
        dst_port,
        src_ip,
        src_port,
        protocol,
        dst_mac,
        src_mac,
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
            protocol,
            tos,
        ),
    ))
}
