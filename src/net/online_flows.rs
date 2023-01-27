extern crate csv;

use pcap::Capture;

use tokio::task;

use super::interface::get_interface;

use crate::net::flow::flow_convert;
use crate::net::types::{Key, V5Record};
use crate::utils::{cur_time_file, v5_exporter};

use std::collections::HashMap;
use std::fs;
use std::time::{Duration, Instant};

pub async fn packet_capture(
    csv_file: &str,
    interface_name: &str,
    duration: u64,
    interval: u64,
    flow_timeout: u32,
    verbose: u8,
) {
    let interface = get_interface(interface_name);
    let mut cap = Capture::from_device(interface)
        .unwrap()
        .promisc(true)
        //.immediate_mode(true)
        .open()
        .unwrap();

    let file_dir = "./output";
    match fs::create_dir_all(<&str>::clone(&file_dir)) {
        Ok(_) => println!("Created directory: {}", file_dir),
        Err(error) => panic!("Problem creating directory: {:?}", error),
    };

    let start = Instant::now();
    let mut last_export = Instant::now();
    let file_path = cur_time_file(csv_file, file_dir).await;
    let mut file = fs::File::create(file_path).unwrap();
    //let mut wtr = csv::Writer::from_writer(file);

    let mut records: Vec<V5Record> = Vec::new();
    let mut active_flow: HashMap<Key, V5Record> = HashMap::new();

    while let Ok(packet) = cap.next_packet() {
        if verbose >= 3 {
            println!("received packet");
        }
        //println!("received packet");
        //println!("time: {}",packet.header.ts.tv_sec);
        /*let e = EthernetPacket::new(packet.data).unwrap();
        let i = Ipv4Packet::new(e.payload()).unwrap();


        //let p : =
        let (_packet_data, _frame) = parse_etherprotocol(packet.data).unwrap();
        let (_frame_data, _ipv4) = parse_ipv4(_packet_data).unwrap();
        if i.payload().is_empty() {
            continue;
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
        };*/
        /*
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
        let doctets = i.get_total_length() as u32;
        //Destination address prefix mask bits
        let dst_mask = 0;
        */
        /*let key_value = Key {
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            protocol: i.get_next_level_protocol(),
        };*/
        let convert_result = flow_convert(packet.clone());
        match convert_result {
            Ok(_) => (),
            Err(_) => continue,
        };
        let (key_value, reverse_key, flowdata) = convert_result.unwrap();
        let mut is_reverse = false;
        //pushing packet in to active_flows if it is not present
        if active_flow.get(&key_value).is_none() {
            if active_flow.get(&reverse_key).is_none() {
                active_flow.insert(key_value, flowdata);
                if verbose >= 2 {
                    println!("flow established");
                }
            } else {
                is_reverse = true;
            }
        }

        let doctets = flowdata.get_d_octets();
        let fin = flowdata.get_fin();

        //println!("active flows: {:?}", active_flow.len());
        //println!("current inputed flow{:?}", active_flow.get(&key_value).unwrap());
        if is_reverse {
            let cur_dpkt = active_flow.get(&reverse_key).unwrap().get_d_pkts();
            let cur_octets = active_flow.get(&reverse_key).unwrap().get_d_octets();
            active_flow
                .get_mut(&reverse_key)
                .unwrap()
                .set_d_pkts(cur_dpkt + 1);
            active_flow
                .get_mut(&reverse_key)
                .unwrap()
                .set_d_octets(cur_octets + doctets);
            active_flow
                .get_mut(&reverse_key)
                .unwrap()
                .set_last(packet.header.ts.tv_sec as u32);
        } else {
            let cur_dpkt = active_flow.get(&key_value).unwrap().get_d_pkts();
            let cur_octets = active_flow.get(&key_value).unwrap().get_d_octets();
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
        }

        let keys: Vec<Key> = active_flow.keys().cloned().collect();
        //println!("keys: {:?}", keys);
        //println!("flags : {:?},{:?},{:?},{:?},{:?},{:?},{:?} ",fin,syn,rst,psh,ack,urg,flags);
        for key in keys {
            let flow = active_flow.get(&key).unwrap();
            if (flow.get_last() < (packet.header.ts.tv_sec as u32 - flow_timeout)) || fin == 1 {
                if verbose >= 2 {
                    println!("flow expired");
                }
                records.push(*flow);
                active_flow.remove(&key);
            }
        }
        // Export flows if the interval has been reached
        if last_export.elapsed() >= Duration::from_millis(interval) {
            let cloned_records = records.clone();
            let tasks = task::spawn(async {
                v5_exporter(cloned_records, file).await;
            });
            let file_path = cur_time_file(csv_file, file_dir).await;
            file = fs::File::create(file_path.clone()).unwrap();

            let result = tasks.await;
            if verbose >= 1 {
                println!("Export {} result: {:?}", file_path, result);
            }
            //println!("records {:?}", records);
            records.clear();
            last_export = Instant::now();
        }
        // Check if the duration has been reached
        if start.elapsed() >= Duration::from_millis(duration) {
            break;
        }
    }
    if verbose >= 1 {
        println!("Captured in {:?}", start.elapsed());
    }
    let tasks = task::spawn(async {
        v5_exporter(records, file).await;
    });

    let result = tasks.await;
    if verbose >= 1 {
        println!("Exporting task excutation result: {:?}", result);
    }
    //println!("records {:?}", records);
}
