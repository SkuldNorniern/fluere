extern crate csv;

use pcap::Capture;

use tokio::task;

use crate::net::fluereflow::fluereflow_convert;
use crate::net::parser::parse_keys;
use crate::net::types::{FluereRecord, Key,TcpFlags};
use crate::utils::{cur_time_file, fluere_exporter};

use std::collections::HashMap;
use std::fs;
use std::time::Instant;

pub async fn fluereflow_fileparse(
    csv_file: &str,
    file_name: &str,
    _flow_timeout: u32,
    verbose: u8,
) {
    let mut cap = Capture::from_file(file_name).unwrap();

    let file_dir = "./output";
    match fs::create_dir_all(<&str>::clone(&file_dir)) {
        Ok(_) => {
            if verbose >= 1 {
                println!("Created directory: {}", file_dir)
            }
        }
        Err(error) => panic!("Problem creating directory: {:?}", error),
    };

    let start = Instant::now();
    let file_path = cur_time_file(csv_file, file_dir, ".csv").await;
    let file = fs::File::create(file_path.clone()).unwrap();

    //let mut wtr = csv::Writer::from_writer(file);

    let mut records: Vec<FluereRecord> = Vec::new();
    let mut active_flow: HashMap<Key, FluereRecord> = HashMap::new();

    while let Ok(packet) = cap.next_packet() {
        let parsed_keys = parse_keys(packet.clone());
        match parsed_keys {
            Ok(_) => (),
            Err(_) => continue,
        };
        let (key_value, reverse_key) = parsed_keys.unwrap();
        let flow_convert_result = fluereflow_convert(packet.clone());
        match flow_convert_result {
            Ok(_) => (),
            Err(_) => continue,
        };
        let (doctets, raw_flags, flowdata) = flow_convert_result.unwrap();
        let flags = TcpFlags::new(raw_flags);
        //pushing packet in to active_flows if it is not present
        let is_reverse = match active_flow.get(&key_value) {
            None => match active_flow.get(&reverse_key) {
                None => {
                    active_flow.insert(key_value, flowdata);
                    if verbose >= 2 {
                        println!("flow established");
                    }

                    false
                }
                Some(_) => true,
            },
            Some(_) => false,
        };

        let pkt = flowdata.get_min_pkt();
        let ttl = flowdata.get_min_ttl();
        //println!("active flows: {:?}", active_flow.len());
        //println!("current inputed flow{:?}", active_flow.get(&key_value).unwrap());
        if is_reverse {
            let flow = active_flow.get_mut(&reverse_key).unwrap();

            flow.set_d_pkts(flow.get_d_pkts() + 1);
            flow.set_in_pkts(flow.get_in_pkts() + 1);
            flow.set_in_bytes(flow.get_in_bytes() + doctets);
            flow.set_d_octets(flow.get_d_octets() + doctets);
            flow.set_max_pkt(flow.get_max_pkt().max(pkt));
            flow.set_min_pkt(flow.get_min_pkt().min(pkt));
            flow.set_max_ttl(flow.get_max_ttl().max(ttl));
            flow.set_min_ttl(flow.get_min_ttl().min(ttl));
            flow.set_fin_cnt(flow.get_fin_cnt() + flags.fin as u32);
            flow.set_syn_cnt(flow.get_syn_cnt() + flags.syn as u32);
            flow.set_rst_cnt(flow.get_rst_cnt() + flags.rst as u32);
            flow.set_psh_cnt(flow.get_psh_cnt() + flags.psh as u32);
            flow.set_ack_cnt(flow.get_ack_cnt() + flags.ack as u32);
            flow.set_urg_cnt(flow.get_urg_cnt() + flags.urg as u32);
            flow.set_ece_cnt(flow.get_ece_cnt() + flags.ece as u32);
            flow.set_cwr_cnt(flow.get_cwr_cnt() + flags.cwr as u32);
            flow.set_ns_cnt(flow.get_ns_cnt() + flags.ns as u32);
            flow.set_last(packet.header.ts.tv_sec as u32);

            if verbose >= 2 {
                println!("reverse flow updated");
            }

            if  flags.fin == 1 || flags.rst == 1 {
                if verbose >= 2 {
                    println!("flow finished");
                }
                records.push(*active_flow.get(&reverse_key).unwrap());
                active_flow.remove(&reverse_key);
            }
        } else {
            let flow = active_flow.get_mut(&key_value).unwrap();

            flow.set_d_pkts(flow.get_d_pkts() + 1);
            flow.set_out_pkts(flow.get_in_pkts() + 1);
            flow.set_out_bytes(flow.get_in_bytes() + doctets);
            flow.set_d_octets(flow.get_d_octets() + doctets);
            flow.set_max_pkt(flow.get_max_pkt().max(pkt));
            flow.set_min_pkt(flow.get_min_pkt().min(pkt));
            flow.set_max_ttl(flow.get_max_ttl().max(ttl));
            flow.set_min_ttl(flow.get_min_ttl().min(ttl));
            flow.set_fin_cnt(flow.get_fin_cnt() + flags.fin as u32);
            flow.set_syn_cnt(flow.get_syn_cnt() + flags.syn as u32);
            flow.set_rst_cnt(flow.get_rst_cnt() + flags.rst as u32);
            flow.set_psh_cnt(flow.get_psh_cnt() + flags.psh as u32);
            flow.set_ack_cnt(flow.get_ack_cnt() + flags.ack as u32);
            flow.set_urg_cnt(flow.get_urg_cnt() + flags.urg as u32);
            flow.set_ece_cnt(flow.get_ece_cnt() + flags.ece as u32);
            flow.set_cwr_cnt(flow.get_cwr_cnt() + flags.cwr as u32);
            flow.set_ns_cnt(flow.get_ns_cnt() + flags.ns as u32);
            flow.set_last(packet.header.ts.tv_sec as u32);

            if flags.fin == 1 || flags.rst == 1 {
                if verbose >= 2 {
                    println!("flow finished");
                }
                records.push(*active_flow.get(&key_value).unwrap());
                active_flow.remove(&key_value);
            }
        }
        /*for (key, flow) in active_flow.clone().iter(){
            //let flow = active_flow.get(&key).unwrap();
            if flow.get_last() < (packet.header.ts.tv_sec as u32 - flow_timeout)
            {
                //println!("flow expired");
                records.push(*flow);
                active_flow.remove(key);
            }
        }*/
    }
    if verbose >= 1 {
        println!("Captured in {:?}", start.elapsed());
    }
    println!("Active flow {:?}", active_flow.len());
    println!("Ended flow {:?}", records.len());
    for (_key, flow) in active_flow.clone().iter() {
        records.push(*flow);
    }
    let tasks = task::spawn(async {
        fluere_exporter(records, file).await;
    });

    let result = tasks.await;
    if verbose >= 1 {
        println!("Export {} result: {:?}", file_path, result);
    }
    //println!("records {:?}", records);
}
