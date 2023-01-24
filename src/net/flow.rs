use pcap;

use pnet::packet::ethernet::EthernetPacket;

use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;

use crate::net::errors::NetError;
use crate::net::parser::{dscp_to_tos, parse_etherprotocol, parse_ipv4, protocol_to_number};
use crate::net::types::{Key, V5Record};

use std::net::Ipv4Addr;

pub fn flow_convert(packet: pcap::Packet) -> Result<(Key, V5Record), NetError> {
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
    // TCP flags
    let (fin, syn, rst, psh, ack, urg, flags) = match protocol {
        6 => {
            let tcp = TcpPacket::new(i.payload()).unwrap();
            let tcp_flags = tcp.get_flags();

            (
                tcp_flags & 0x01,
                tcp_flags & 0x02,
                tcp_flags & 0x04,
                tcp_flags & 0x08,
                tcp_flags & 0x10,
                tcp_flags & 0x20,
                tcp_flags,
            )
        }
        _ => (0, 0, 0, 0, 0, 0, 0),
    };

    //	Autonomous system number of the source and destination, either origin or peer
    let src_as: u16 = 0;
    let dst_as: u16 = 0;
    //Source address prefix mask bits
    let src_mask = 0;
    let _doctets = i.get_total_length() as u32;
    //Destination address prefix mask bits
    let dst_mask = 0;
    let key_value = Key {
        src_ip,
        src_port,
        dst_ip,
        dst_port,
        protocol,
    };
    let _key_reverse_value = Key {
        dst_ip,
        dst_port,
        src_ip,
        src_port,
        protocol,
    };
    Ok((
        key_value,
        V5Record::new(
            i.get_source(),
            i.get_destination(),
            Ipv4Addr::new(0, 0, 0, 0),
            0,
            0,
            0,
            0,
            packet.header.ts.tv_sec as u32,
            packet.header.ts.tv_sec as u32,
            src_port,
            dst_port,
            0,
            fin as u8,
            syn as u8,
            rst as u8,
            psh as u8,
            ack as u8,
            urg as u8,
            flags,
            protocol,
            dscp_to_tos(i.get_dscp()),
            src_as,
            dst_as,
            src_mask,
            dst_mask,
            0,
        ),
    ))
}
