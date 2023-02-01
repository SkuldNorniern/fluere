extern crate csv;

use pcap::Capture;

use tokio::task;
use tokio::time::sleep;

use super::interface::get_interface;

use crate::net::fluereflow::fluereflow_convert;
use crate::net::types::{FluereRecord, Key};
use crate::utils::{cur_time_file, fluere_exporter};

use std::collections::HashMap;
use std::fs;
use std::time::{Duration, Instant};

pub async fn packet_capture(
    csv_file: &str,
    interface_name: &str,
    duration: u64,
    interval: u64,
    flow_timeout: u32,
    sleep_windows: u64,
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
        Ok(_) => {
            if verbose >= 1 {
                println!("Created directory: {}", file_dir)
            }
        }
        Err(error) => panic!("Problem creating directory: {:?}", error),
    };

    let start = Instant::now();
    let mut last_export = Instant::now();
    let file_path = cur_time_file(csv_file, file_dir, ".csv").await;
    let mut file = fs::File::create(file_path.clone()).unwrap();

    //let mut wtr = csv::Writer::from_writer(file);

    let mut records: Vec<FluereRecord> = Vec::new();
    let mut active_flow: HashMap<Key, FluereRecord> = HashMap::new();
    let mut packet_count = 0;

    while let Ok(packet) = cap.next_packet() {
        if verbose >= 3 {
            println!("received packet");
        }

        let convert_result = fluereflow_convert(packet.clone());
        match convert_result {
            Ok(_) => (),
            Err(_) => continue,
        };
        let (key_value, reverse_key, doctets, flags, flowdata) = convert_result.unwrap();
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

        let (fin, syn, rst, psh, ack, urg, ece, cwr, ns) = flags;
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
            flow.set_fin_cnt(flow.get_fin_cnt() + fin);
            flow.set_syn_cnt(flow.get_syn_cnt() + syn);
            flow.set_rst_cnt(flow.get_rst_cnt() + rst);
            flow.set_psh_cnt(flow.get_psh_cnt() + psh);
            flow.set_ack_cnt(flow.get_ack_cnt() + ack);
            flow.set_urg_cnt(flow.get_urg_cnt() + urg);
            flow.set_ece_cnt(flow.get_ece_cnt() + ece);
            flow.set_cwr_cnt(flow.get_cwr_cnt() + cwr);
            flow.set_ns_cnt(flow.get_ns_cnt() + ns);
            flow.set_last(packet.header.ts.tv_sec as u32);

            if verbose >= 3 {
                println!("reverse flow updated");
            }

            if fin == 1 || rst == 1 {
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
            flow.set_fin_cnt(flow.get_fin_cnt() + fin);
            flow.set_syn_cnt(flow.get_syn_cnt() + syn);
            flow.set_rst_cnt(flow.get_rst_cnt() + rst);
            flow.set_psh_cnt(flow.get_psh_cnt() + psh);
            flow.set_ack_cnt(flow.get_ack_cnt() + ack);
            flow.set_urg_cnt(flow.get_urg_cnt() + urg);
            flow.set_ece_cnt(flow.get_ece_cnt() + ece);
            flow.set_cwr_cnt(flow.get_cwr_cnt() + cwr);
            flow.set_ns_cnt(flow.get_ns_cnt() + ns);
            flow.set_last(packet.header.ts.tv_sec as u32);

            if verbose >= 3 {
                println!("foward flow updated");
            }

            if fin == 1 || rst == 1 {
                if verbose >= 2 {
                    println!("flow finished");
                }
                records.push(*active_flow.get(&key_value).unwrap());
                active_flow.remove(&key_value);
            }
        }

        packet_count += 1;
        // slow down the loop for windows to avoid random shutdown
        if packet_count % 10 == 0 && cfg!(target_os = "windows") {
            if verbose >= 3 {
                println!("Slow down the loop for windows");
            }
            sleep(Duration::from_millis(sleep_windows)).await;
        }

        // Export flows if the interval has been reached
        if last_export.elapsed() >= Duration::from_millis(interval) {
            let mut expired_flows = vec![];
            for (key, flow) in active_flow.iter() {
                if flow.get_last() < (packet.header.ts.tv_sec as u32 - flow_timeout / 1000) {
                    if verbose >= 2 {
                        println!("flow expired");
                    }
                    records.push(*flow);
                    expired_flows.push(*key);
                }
            }
            active_flow.retain(|key, _| !expired_flows.contains(key));
            let cloned_records = records.clone();
            let tasks = task::spawn(async {
                fluere_exporter(cloned_records, file).await;
            });

            let result = tasks.await;
            if verbose >= 1 {
                println!("Export {} result: {:?}", file_path, result);
            }
            let file_path = cur_time_file(csv_file, file_dir, ".csv").await;
            file = fs::File::create(file_path.clone()).unwrap();
            records.clear();
            last_export = Instant::now();
        }

        // Check if the duration has been reached
        if start.elapsed() >= Duration::from_millis(duration) && duration != 0 {
            let mut expired_flows = vec![];
            for (key, flow) in active_flow.iter() {
                if flow.get_last() < (packet.header.ts.tv_sec as u32 - flow_timeout / 1000) {
                    if verbose >= 2 {
                        println!("flow expired");
                    }
                    records.push(*flow);
                    expired_flows.push(*key);
                }
            }
            active_flow.retain(|key, _| !expired_flows.contains(key));
            break;
        }
    }
    if verbose >= 1 {
        println!("Captured in {:?}", start.elapsed());
    }
    for (_key, flow) in active_flow.iter() {
        records.push(*flow);
    }
    let tasks = task::spawn(async {
        fluere_exporter(records, file).await;
    });

    let result = tasks.await;
    if verbose >= 1 {
        println!("Exporting task excutation result: {:?}", result);
    }
    //println!("records {:?}", records);
}
