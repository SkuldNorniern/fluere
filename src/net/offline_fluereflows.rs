extern crate csv;

use fluereflow::FluereRecord;
use pcap::Capture;
use tokio::task;

use crate::{
    net::{
        parser::{parse_fluereflow, parse_keys, parse_microseconds}, 
        flows::update_flow,
        types::{Key, TcpFlags},
    },
    types::{Args,UDFlowKey},
    utils::{cur_time_file, fluere_exporter},
};

use std::{
    collections::HashMap,
    fs,
    time::Instant,
};

pub async fn fluereflow_fileparse(arg: Args) {
    let csv_file = arg.files.csv.unwrap();
    let file_name = arg.files.file.unwrap();
    let use_mac = arg.parameters.use_mac.unwrap();
    let _flow_timeout = arg.parameters.timeout.unwrap();
    let verbose = arg.verbose.unwrap();

    let mut cap = Capture::from_file(file_name).unwrap();

    let file_dir = "./output";
    match fs::create_dir_all(<&str>::clone(&file_dir)) {
        Ok(_) => {
            if verbose >= 1 {
                println!("Created directory: {}", file_dir)
            }
        }
        Err(error) => return Err(()),
    };

    let start = Instant::now();
    let file_path = cur_time_file(csv_file.as_str(), file_dir, ".csv").await;
    let file = fs::File::create(file_path.clone()).unwrap();

    //let mut wtr = csv::Writer::from_writer(file);

    let mut records: Vec<FluereRecord> = Vec::new();
    let mut active_flow: HashMap<Key, FluereRecord> = HashMap::new();

    while let Ok(packet) = cap.next_packet() {
        let (mut key_value, mut reverse_key) = match parse_keys(packet.clone()) {
            Ok(keys) => keys,
            Err(_) => continue,
        };
        if !use_mac {
            key_value.mac_defaultate();
            reverse_key.mac_defaultate();
        }
        let (doctets, raw_flags, flowdata) = match parse_fluereflow(packet.clone()) {
            Ok(result) => result,
            Err(_) => continue,
        };
        let flags = TcpFlags::new(raw_flags);
        //pushing packet in to active_flows if it is not present
        let is_reverse = match active_flow.get(&key_value) {
            None => match active_flow.get(&reverse_key) {
                None => {
                    // if the protocol is TCP, check if is a syn packet
                    if flowdata.get_prot() == 6 {
                        if flags.syn > 0 {
                            active_flow.insert(key_value, flowdata);
                            if verbose >= 2 {
                                println!("flow established");
                            }
                        } else {
                            continue;
                        }
                    } else {
                        active_flow.insert(key_value, flowdata);
                        if verbose >= 2 {
                            println!("flow established");
                        }
                    }

                    false
                }
                Some(_) => true,
            },
            Some(_) => false,
        };
        let time = parse_microseconds(
            packet.header.ts.tv_sec as u64,
            packet.header.ts.tv_usec as u64,
        );
        let pkt = flowdata.get_min_pkt();
        let ttl = flowdata.get_min_ttl();
        //println!("active flows: {:?}", active_flow.len());
        //println!("current inputed flow{:?}", active_flow.get(&key_value).unwrap());
        let flow_key = if is_reverse { &reverse_key } else { &key_value };
        if let Some(flow) = active_flow.get_mut(flow_key) {
            let update_key = UDFlowKey {
                doctets,
                pkt,
                ttl,
                flags,
                time,
            };
            update_flow(flow, is_reverse, update_key);

            if verbose >= 2 {
                println!("{} flow updated", if is_reverse { "reverse" } else { "forward" });
            }

            if flags.fin == 1 || flags.rst == 1 {
                if verbose >= 2 {
                    println!("flow finished");
                }
                records.push(*flow);
                active_flow.remove(flow_key);
            }   
        }
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
