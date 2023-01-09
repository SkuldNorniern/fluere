extern crate chrono;

use chrono::Local;
use pcap::Capture;
use pnet::packet::Packet;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::udp::UdpPacket;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::ethernet::EthernetPacket;

use crate::net::types::V5NetflowPacket;


use std::time::Instant;

fn handle_ipv4(d: &[u8]) {
    let i = Ipv4Packet::new(d).unwrap();

    match i.get_next_level_protocol() {
        Udp => handle_udp(i.payload()),
        Tcp=> handle_tcp(i.payload()),
        _ => panic!("Unknown protocol {:?}",i),
    }
}

fn handle_udp(d: &[u8]) {
    let u = UdpPacket::new(d).unwrap();

    let dst_port = u.get_destination();
    handle_netflow(u.payload());
}
fn handle_tcp(d: &[u8]) {
    let u = TcpPacket::new(d).unwrap();

    let dst_port = u.get_destination();
    handle_netflow(u.payload());
}
fn handle_netflow(d: &[u8]) {
    let n = V5NetflowPacket::new(d);
    let netflow = serde_json::to_string(&n).unwrap();
    println!("{}", netflow);
    println!("received flow"); 
}

pub fn netflow_fileparse(file_name: &str, output_dir: &str) {
    let mut cap = Capture::from_file(file_name)
        .unwrap();

    let date = Local::now();
    let file_dir = "./output";
    let start = Instant::now();
    while let Ok(packet) = cap.next_packet() {
        //println!("received packet");
        let e = EthernetPacket::new(packet.data).unwrap();
        match e.get_ethertype() {
            Ipv4 => handle_ipv4(e.payload()),
            _ => panic!("Unknown ethertype"),
        }
        //println!("packet: {:?}", packet);
        
    }
    let duration = start.elapsed();
    println!("Captured in {:?}", duration);
}
