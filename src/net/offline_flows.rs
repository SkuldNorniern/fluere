extern crate chrono;
extern crate csv;

use chrono::Local;
use pcap::Capture;
use pnet::packet::ethernet::EthernetPacket;

use pnet::packet::ipv4::Ipv4Packet;

use pnet::packet::Packet;
use tokio::task;

use crate::net::flow::flow_convert;
use crate::net::types::{Key, V5Record};
use crate::utils::exporter;

use std::collections::HashMap;
use std::fs;

use std::time::Instant;

pub async fn netflow_fileparse(csv_file: &str, file_name: &str, flow_timeout: u32) {
    let mut cap = Capture::from_file(file_name).unwrap();

    let date = Local::now();
    let file_dir = "./output";
    match fs::create_dir_all(<&str>::clone(&file_dir)) {
        Ok(_) => println!("Created directory: {}", file_dir),
        Err(error) => panic!("Problem creating directory: {:?}", error),
    };

    let start = Instant::now();
    let file_path = format!(
        "{}/{}_{}.csv",
        file_dir,
        csv_file,
        date.format("%Y-%m-%d_%H-%M-%S")
    );
    let file = fs::File::create(file_path).unwrap();
    //let mut wtr = csv::Writer::from_writer(file);

    let mut records: Vec<V5Record> = Vec::new();
    let mut active_flow: HashMap<Key, V5Record> = HashMap::new();

    while let Ok(packet) = cap.next_packet() {
        
        let e = EthernetPacket::new(packet.data).unwrap();
        let _i = Ipv4Packet::new(e.payload()).unwrap();

        let convert_result = flow_convert(packet.clone());
        match convert_result {
            Ok(_) => (),
            Err(_) => continue,
        };
        let (key_value,reverse_key, flowdata) = convert_result.unwrap();
        let mut is_reverse = false;
        //pushing packet in to active_flows if it is not present 
        if active_flow.get(&key_value).is_none() {
            if active_flow.get(&reverse_key).is_none() {
                active_flow.insert(key_value, flowdata);
                println!("flow established");
            }
            else {
                is_reverse = true;
            }
            //active_flow.entry(key_value).or_insert(flowdata);
            println!("flow established");
        }
        

        let doctets = flowdata.get_d_octets();
        let fin = flowdata.get_fin();
        let cur_dpkt = active_flow.get(&key_value).unwrap().get_d_pkts();
        let cur_octets = active_flow.get(&key_value).unwrap().get_d_octets();
        //println!("active flows: {:?}", active_flow.len());
        //println!("current inputed flow{:?}", active_flow.get(&key_value).unwrap());
        if is_reverse {
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
        }
        else {
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
        for key in keys {
            let flow = active_flow.get(&key).unwrap();
            if (flow.get_last() < (packet.header.ts.tv_sec as u32 - flow_timeout)) || fin == 1 {
                //println!("flow expired");
                records.push(*flow);
                active_flow.remove(&key);
            }
        }
    }
    println!("Captured in {:?}", start.elapsed());

    let tasks = task::spawn(async {
        exporter(records, file).await;
    });
    
    let result = tasks.await;
    println!("result: {:?}", result);
}
