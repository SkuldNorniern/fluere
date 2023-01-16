extern crate chrono;
extern crate csv;

use chrono::Local;
use pcap::Capture;
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ip::IpNextHeaderProtocol;
use pnet::packet::ipv4::Ipv4Packet;

use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;


use super::interface::get_interface;

use crate::net;
use crate::net::parser::dscp_to_tos;
use crate::net::parser::parse_etherprotocol;
use crate::net::parser::parse_ipv4;

use std::collections::HashMap;
use std::fs;
use std::net::Ipv4Addr;
use std::time::Instant;

/*fn check_timeout() {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32;

    let expired_flows: Vec<FlowKey> = self
        .active_flows
        .iter()
        .filter(|(_, flow)| now - flow.last_seen > FLOW_TIMEOUT)
        .map(|(key, _)| key.clone())
        .collect();

    for key in expired_flows {
        self.active_flows.remove(&key);
    }
}*/
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct Key {
    src_ip: std::net::Ipv4Addr,
    src_port: u16,
    dst_ip: std::net::Ipv4Addr,
    dst_port: u16,
    protocol: IpNextHeaderProtocol,
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

pub fn packet_capture(csv_file: &str, interface_name: &str, duration: i32, flow_timeout: u32) {
    let interface = get_interface(interface_name);
    let mut cap = Capture::from_device(interface)
        .unwrap()
        .timeout(duration)
        .buffer_size(10000000)
        .open()
        .unwrap();

    let date = Local::now();
    let file_dir = "./output";
    fs::create_dir_all(file_dir.clone());
    let start = Instant::now();
    let file_path = format!(
        "{}/{}_{}.csv",
        file_dir,
        csv_file,
        date.format("%Y-%m-%d_%H-%M-%S")
    );
    let file = fs::File::create(file_path).unwrap();
    let mut wtr = csv::Writer::from_writer(file);

    let mut records: Vec<net::types::netflowv5::V5Record> = Vec::new();
    let mut active_flow: HashMap<Key, net::types::netflowv5::V5Record> = HashMap::new();

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
            _ => continue, //panic!("Unknown protocol {:?}", i),
        };
        let dst_port = match i.get_next_level_protocol() {
            pnet::packet::ip::IpNextHeaderProtocol(17) => {
                UdpPacket::new(i.payload()).unwrap().get_destination()
            }
            pnet::packet::ip::IpNextHeaderProtocol(6) => {
                TcpPacket::new(i.payload()).unwrap().get_destination()
            }
            _ => continue, //panic!("Unknown protocol {:?}", i),
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
            println!("tcp_flags: {:?}", tcp_flags);
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
        let doctets = i.get_total_length() as u32;
        //Destination address prefix mask bits
        let dst_mask = 0;
        let key_value = Key {
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            protocol: i.get_next_level_protocol(),
        };
        //pushing packet in to active_flows if it is not present

        active_flow
            .entry(key_value)
            .or_insert(net::types::netflowv5::V5Record::new(
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
            ));
        let cur_dpkt = active_flow.get_mut(&key_value).unwrap().get_d_pkts();
        let cur_octets = active_flow.get_mut(&key_value).unwrap().get_d_octets();
        //println!("active flows: {:?}", active_flow.len());
        //println!("current inputed flow{:?}", active_flow.get(&key_value).unwrap());
        active_flow
            .get_mut(&key_value)
            .unwrap()
            .set_d_pkts(cur_dpkt + 1);
        active_flow
            .get_mut(&key_value)
            .unwrap()
            .set_d_octets(cur_octets + doctets);
        active_flow
            .get_mut(&key_value)
            .unwrap()
            .set_last(packet.header.ts.tv_sec as u32);
        //println!("after first: {:?}", active_flow.get(&key_value).unwrap().get_first());
        //println!("after last: {:?}", active_flow.get(&key_value).unwrap().get_last());
        //println!("packet_ts0: {:?}",packet.header.ts.tv_sec as u32);
        let keys: Vec<Key> = active_flow.keys().cloned().collect();
        //println!("keys: {:?}", keys);
        //println!("flags : {:?},{:?},{:?},{:?},{:?},{:?},{:?} ",fin,syn,rst,psh,ack,urg,flags);
        for key in keys {
            let flow = active_flow.get(&key).unwrap();
            if (flow.get_last() < (packet.header.ts.tv_sec as u32 - flow_timeout)) || fin == 1 {
                println!("flow expired: {:?}", flow);
                records.push(*flow);
                active_flow.remove(&key);
            }
        }
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
        //println!("received packet");
    }
    println!("Captured in {:?}", start.elapsed());
    // Write the header row
    wtr.write_record([
        "src_ip", "dst_ip", "nexthop", "input", "output", "dPkts", "dOctets", "First", "Last",
        "src_port", "dst_port", "pad1", "fin", "syn", "rst", "psh", "ack", "urg", "flags", "prot",
        "tos", "src_as", "dst_as", "src_mask", "dst_mask", "pad2",
    ])
    .unwrap();
    for flow in records.iter() {
        wtr.write_record([
            &flow.get_source().to_string(),
            &flow.get_destination().to_string(),
            &flow.get_next_hop().to_string(),
            &flow.get_input().to_string(),
            &flow.get_output().to_string(),
            &flow.get_d_pkts().to_string(),
            &flow.get_d_octets().to_string(),
            &flow.get_first().to_string(),
            &flow.get_last().to_string(),
            &flow.get_src_port().to_string(),
            &flow.get_dst_port().to_string(),
            &flow.get_pad1().to_string(),
            &flow.get_fin().to_string(),
            &flow.get_syn().to_string(),
            &flow.get_rst().to_string(),
            &flow.get_psh().to_string(),
            &flow.get_ack().to_string(),
            &flow.get_urg().to_string(),
            &flow.get_flags().to_string(),
            &flow.get_prot().to_string(),
            &flow.get_tos().to_string(),
            &flow.get_src_as().to_string(),
            &flow.get_dst_as().to_string(),
            &flow.get_src_mask().to_string(),
            &flow.get_dst_mask().to_string(),
            &flow.get_pad2().to_string(),
        ])
        .unwrap();
    }

    //println!("records {:?}", records);
}
