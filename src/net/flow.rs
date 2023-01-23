use pcap;

use pnet::packet::ethernet::EthernetPacket;

use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;

use crate::net::errors::NetError;
use crate::net::parser::dscp_to_tos;
use crate::net::parser::parse_etherprotocol;
use crate::net::parser::parse_ipv4;
use crate::net::types::{Key, V5Record};

use std::net::Ipv4Addr;

pub fn flow_convert(packet: pcap::Packet) -> Result<(Key, V5Record), NetError> {
    let e = EthernetPacket::new(packet.data).unwrap();
    let i = Ipv4Packet::new(e.payload()).unwrap();

    //let p : =
    let (_packet_data, _frame) = parse_etherprotocol(packet.data).unwrap();
    let (_frame_data, _ipv4) = parse_ipv4(_packet_data).unwrap();
    if i.payload().is_empty() {
        return Err(NetError::EmptyPacket);
    }

    let src_ip = i.get_source();
    let dst_ip = i.get_destination();
    let src_port = match i.get_next_level_protocol() {
        pnet::packet::ip::IpNextHeaderProtocol(17) => {
            UdpPacket::new(i.payload()).unwrap().get_source()
        }
        pnet::packet::ip::IpNextHeaderProtocol(6) => {
            TcpPacket::new(i.payload()).unwrap().get_source()
        }
        _ => {
            return Err(NetError::UnknownProtocol {
                protocol: i.get_next_level_protocol().to_string(),
            })
        }
        //panic!("Unknown protocol {:?}", i),
    };
    let dst_port = match i.get_next_level_protocol() {
        pnet::packet::ip::IpNextHeaderProtocol(17) => {
            UdpPacket::new(i.payload()).unwrap().get_destination()
        }
        pnet::packet::ip::IpNextHeaderProtocol(6) => {
            TcpPacket::new(i.payload()).unwrap().get_destination()
        }
        _ => {
            return Err(NetError::UnknownProtocol {
                protocol: i.get_next_level_protocol().to_string(),
            })
        } //panic!("Unknown protocol {:?}", i),
    };
    let mut fin = 0;
    let mut syn = 0;
    let mut rst = 0;
    let mut psh = 0;
    let mut ack = 0;
    let mut urg = 0;
    let mut flags = 0;
    if i.get_next_level_protocol() == pnet::packet::ip::IpNextHeaderProtocol(6) {
        let tcp = TcpPacket::new(i.payload()).unwrap();
        let tcp_flags = tcp.get_flags();
        fin = tcp_flags & 0x01;
        syn = tcp_flags & 0x02;
        rst = tcp_flags & 0x04;
        psh = tcp_flags & 0x08;
        ack = tcp_flags & 0x10;
        urg = tcp_flags & 0x20;
        flags = tcp_flags;
    } else {
        fin = 0;
        syn = 0;
        rst = 0;
        psh = 0;
        ack = 0;
        urg = 0;
        flags = 0;
    }

    //	Autonomous system number of the source, either origin or peer
    let src_as: u16 = 0;
    //	Autonomous system number of the destination, either origin or peer
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
        protocol: i.get_next_level_protocol(),
    };
    let key_reverse_value = Key {
        dst_ip,
        dst_port,
        src_ip,
        src_port,
        protocol: i.get_next_level_protocol(),
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
            i.get_next_level_protocol(),
            dscp_to_tos(i.get_dscp()),
            src_as,
            dst_as,
            src_mask,
            dst_mask,
            0,
        ),
    ))
}
