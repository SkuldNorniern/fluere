extern crate chrono;

use chrono::Local;
use pcap::Capture;
use pnet::packet::ethernet::EthernetPacket;

use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;

use super::interface::get_interface;

use crate::net;
use crate::net::parser::parse_etherprotocol;
use crate::net::parser::parse_ipv4;
use crate::net::types::V5NetflowPacket;
use crate::net::parser::dscp_to_tos;

use std::collections::HashMap;

use std::time::Instant;

fn handle_ipv4(d: &[u8]) {
    let i = Ipv4Packet::new(d).unwrap();

    match i.get_next_level_protocol() {
        _Udp => handle_udp(i.payload()),
        _Tcp => handle_tcp(i.payload()),
        _ => panic!("Unknown protocol {:?}", i),
    }
}

fn handle_udp(d: &[u8]) {
    //println!("raw_udp: {:?}", d);
    let u = UdpPacket::new(d).unwrap();
    let _src_port = u.get_source();
    let _dst_port = u.get_destination();
    println!("udp: {:?}", u);
    //handle_netflow(u.payload());
}
fn handle_tcp(d: &[u8]) {
    let u = TcpPacket::new(d).unwrap();
    let _src_port = u.get_source();
    let _dst_port = u.get_destination();
    println!("tcp: {:?}", u);
    //handle_netflow(u.payload());
}
fn handle_netflow(d: &[u8]) {
    let n = V5NetflowPacket::new(d);
    let netflow = serde_json::to_string(&n).unwrap();
    println!("{}", netflow);
    println!("received flow");
}

pub fn packet_capture(interface_name: &str) {
    let interface = get_interface(interface_name);
    let mut cap = Capture::from_device(interface)
        .unwrap()
        .timeout(0)
        .buffer_size(10000000)
        .open()
        .unwrap();

    let _date = Local::now();
    let start = Instant::now();
    let _records: Vec<net::types::netflowv5::V5Record> = Vec::new();
    let mut active_flow: HashMap<
        (std::net::Ipv4Addr, u16, std::net::Ipv4Addr, u16),
        net::types::netflowv5::V5Record,
    > = HashMap::new();

    while let Ok(packet) = cap.next_packet() {
        //println!("received packet");
        //println!("time: {}",packet.header.ts.tv_sec);
        let e = EthernetPacket::new(packet.data).unwrap();
        let i = Ipv4Packet::new(e.payload()).unwrap();
        //let p : =
        let (_packet_data, _frame) = parse_etherprotocol(packet.data).unwrap();
        let (_frame_data, _ipv4) = parse_ipv4(_packet_data).unwrap();
        if i.payload().is_empty() {
            continue;
        }
        //println!("frame: {:?}", frame);

        //println!("ipv4: {:?}", ipv4);
        /*match ipv4.protocol {
            crate::net::types::ipv4::IPProtocol::UDP => handle_udp(i.payload()),
            crate::net::types::ipv4::IPProtocol::TCP => handle_tcp(i.payload()),
            _ => panic!("Unknown protocol {:?}", i),
        }*/
        let src_ip = i.get_source();
        let dst_ip = i.get_destination();
        let src_port = match i.get_next_level_protocol() {
            pnet::packet::ip::IpNextHeaderProtocol(17) => {
                UdpPacket::new(i.payload()).unwrap().get_source()
            }
            pnet::packet::ip::IpNextHeaderProtocol(6) => {
                TcpPacket::new(i.payload()).unwrap().get_source()
            }
            _ => continue,//panic!("Unknown protocol {:?}", i),
        };
        let dst_port = match i.get_next_level_protocol() {
            pnet::packet::ip::IpNextHeaderProtocol(17) => {
                UdpPacket::new(i.payload()).unwrap().get_destination()
            }
            pnet::packet::ip::IpNextHeaderProtocol(6) => {
                TcpPacket::new(i.payload()).unwrap().get_destination()
            }
            _ => continue,//panic!("Unknown protocol {:?}", i),
        };
        //Total number of Layer 3 bytes in the packets of the flow
        //let d_octets:u32 =
        //	Autonomous system number of the source, either origin or peer
        let src_as: u16 = 0;
        //	Autonomous system number of the destination, either origin or peer
        let dst_as: u16 = 0;
        //Source address prefix mask bits
        let src_mask = 0;
        //Destination address prefix mask bits
        let dst_mask = 0;
        let key = (src_ip, src_port, dst_ip, dst_port);
        //pushing packet in to active_flows if it is not present

        active_flow
            .entry(key)
            .or_insert(net::types::netflowv5::V5Record::new(
                i.get_source(),
                i.get_destination(),
                [0,0,0,0].into(),
                0,
                0,
                1,
                0,
                packet.header.ts.tv_sec as u32,
                packet.header.ts.tv_sec as u32,
                src_port,
                dst_port,
                0,
                i.get_flags(),
                i.get_next_level_protocol(),
                dscp_to_tos(i.get_dscp()),
                src_as,
                dst_as,
                src_mask,
                dst_mask,
                0,
            ));
        println!("active flows: {:?}", active_flow.len());
        /*let flow = active_flows.get(&key);

        if flow.is_some() {
            println!("Packet is in the established flow direction");
        } else {
            // check for the reverse direction flow
            let reverse_key = (dst_ip, dst_port, src_ip, src_port);
            let flow = active_flows.get(&reverse_key);
            if flow.is_some() {
                println!("Packet is in the reverse flow direction");
            } else {
                println!("Packet is in a new flow direction");
            }
        }*/
        //records.push(net::types::netflowv5::V5Record::new());
        //println!("packet: {:?}", i);
        //println!("packet: {:?}", packet);
    }
    let duration = start.elapsed();
    println!("Captured in {:?}", duration);
}
