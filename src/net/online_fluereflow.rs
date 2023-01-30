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
    let file_path = cur_time_file(csv_file, file_dir).await;
    let mut file = fs::File::create(file_path.clone()).unwrap();
    let mut is_reverse = false;
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
        if active_flow.get(&key_value).is_none() {
            if active_flow.get(&reverse_key).is_none() {
                active_flow.insert(key_value, flowdata);
                is_reverse = false;
                if verbose >= 2 {
                    println!("flow established");
                }
            } else {
                is_reverse = true;
            }
        } else {
            is_reverse = false;
        }

        let (fin, syn, rst, psh, ack, urg, ece, cwr, ns) = flags;
        let pkt = flowdata.get_min_pkt();
        let ttl = flowdata.get_min_ttl();
        //println!("active flows: {:?}", active_flow.len());
        //println!("current inputed flow{:?}", active_flow.get(&key_value).unwrap());
        if is_reverse {
            let cur_dpkt = active_flow.get(&reverse_key).unwrap().get_d_pkts();
            let cur_inpkt = active_flow.get(&reverse_key).unwrap().get_in_pkts();
            let cur_octets = active_flow.get(&reverse_key).unwrap().get_d_octets();
            let min_pkt = active_flow.get(&reverse_key).unwrap().get_min_pkt();
            let max_pkt = active_flow.get(&reverse_key).unwrap().get_max_pkt();
            let min_ttl = active_flow.get(&reverse_key).unwrap().get_min_ttl();
            let max_ttl = active_flow.get(&reverse_key).unwrap().get_max_ttl();
            let cur_fin = active_flow.get(&reverse_key).unwrap().get_fin_cnt();
            let cur_syn = active_flow.get(&reverse_key).unwrap().get_syn_cnt();
            let cur_rst = active_flow.get(&reverse_key).unwrap().get_rst_cnt();
            let cur_psh = active_flow.get(&reverse_key).unwrap().get_psh_cnt();
            let cur_ack = active_flow.get(&reverse_key).unwrap().get_ack_cnt();
            let cur_urg = active_flow.get(&reverse_key).unwrap().get_urg_cnt();
            let cur_ece = active_flow.get(&reverse_key).unwrap().get_ece_cnt();
            let cur_cwr = active_flow.get(&reverse_key).unwrap().get_cwr_cnt();
            let cur_ns = active_flow.get(&reverse_key).unwrap().get_ns_cnt();
            let cur_inbytes = active_flow.get(&reverse_key).unwrap().get_in_bytes();

            active_flow
                .get_mut(&reverse_key)
                .unwrap()
                .set_d_pkts(cur_dpkt + 1);
            active_flow
                .get_mut(&reverse_key)
                .unwrap()
                .set_in_pkts(cur_inpkt + 1);
            active_flow
                .get_mut(&reverse_key)
                .unwrap()
                .set_d_octets(cur_octets + doctets);
            active_flow
                .get_mut(&reverse_key)
                .unwrap()
                .set_max_ttl(if max_ttl < ttl { ttl } else { max_ttl });
            active_flow
                .get_mut(&reverse_key)
                .unwrap()
                .set_min_ttl(if min_ttl > ttl { ttl } else { min_ttl });
            active_flow
                .get_mut(&reverse_key)
                .unwrap()
                .set_max_pkt(if max_pkt < pkt { pkt } else { max_pkt });
            active_flow
                .get_mut(&reverse_key)
                .unwrap()
                .set_min_pkt(if min_pkt > pkt { pkt } else { min_pkt });
            active_flow
                .get_mut(&reverse_key)
                .unwrap()
                .set_fin_cnt(cur_fin + fin);
            active_flow
                .get_mut(&reverse_key)
                .unwrap()
                .set_syn_cnt(cur_syn + syn);
            active_flow
                .get_mut(&reverse_key)
                .unwrap()
                .set_rst_cnt(cur_rst + rst);
            active_flow
                .get_mut(&reverse_key)
                .unwrap()
                .set_psh_cnt(cur_psh + psh);
            active_flow
                .get_mut(&reverse_key)
                .unwrap()
                .set_ack_cnt(cur_ack + ack);
            active_flow
                .get_mut(&reverse_key)
                .unwrap()
                .set_urg_cnt(cur_urg + urg);
            active_flow
                .get_mut(&reverse_key)
                .unwrap()
                .set_ece_cnt(cur_ece + ece);
            active_flow
                .get_mut(&reverse_key)
                .unwrap()
                .set_cwr_cnt(cur_cwr + cwr);
            active_flow
                .get_mut(&reverse_key)
                .unwrap()
                .set_ns_cnt(cur_ns + ns);
            active_flow
                .get_mut(&reverse_key)
                .unwrap()
                .set_in_bytes(cur_inbytes + doctets);
            active_flow
                .get_mut(&reverse_key)
                .unwrap()
                .set_last(packet.header.ts.tv_sec as u32);

            if fin == 1 || rst == 1 {
                if verbose >= 2 {
                    println!("flow finished");
                }
                records.push(*active_flow.get(&reverse_key).unwrap());
                active_flow.remove(&reverse_key);
            }
        } else {
            let cur_dpkt = active_flow.get(&key_value).unwrap().get_d_pkts();
            let cur_outpkt = active_flow.get(&key_value).unwrap().get_out_pkts();
            let cur_octets = active_flow.get(&key_value).unwrap().get_d_octets();
            let min_pkt = active_flow.get(&key_value).unwrap().get_min_pkt();
            let max_pkt = active_flow.get(&key_value).unwrap().get_max_pkt();
            let min_ttl = active_flow.get(&key_value).unwrap().get_min_ttl();
            let max_ttl = active_flow.get(&key_value).unwrap().get_max_ttl();
            let cur_fin = active_flow.get(&key_value).unwrap().get_fin_cnt();
            let cur_syn = active_flow.get(&key_value).unwrap().get_syn_cnt();
            let cur_rst = active_flow.get(&key_value).unwrap().get_rst_cnt();
            let cur_psh = active_flow.get(&key_value).unwrap().get_psh_cnt();
            let cur_ack = active_flow.get(&key_value).unwrap().get_ack_cnt();
            let cur_urg = active_flow.get(&key_value).unwrap().get_urg_cnt();
            let cur_ece = active_flow.get(&key_value).unwrap().get_ece_cnt();
            let cur_cwr = active_flow.get(&key_value).unwrap().get_cwr_cnt();
            let cur_ns = active_flow.get(&key_value).unwrap().get_ns_cnt();
            let cur_outbytes = active_flow.get(&key_value).unwrap().get_out_bytes();

            active_flow
                .get_mut(&key_value)
                .unwrap()
                .set_d_pkts(cur_dpkt + 1);
            active_flow
                .get_mut(&key_value)
                .unwrap()
                .set_out_pkts(cur_outpkt + 1);
            active_flow
                .get_mut(&key_value)
                .unwrap()
                .set_d_octets(cur_octets + doctets);
            active_flow
                .get_mut(&key_value)
                .unwrap()
                .set_max_ttl(if max_ttl < ttl { ttl } else { max_ttl });
            active_flow
                .get_mut(&key_value)
                .unwrap()
                .set_min_ttl(if min_ttl > ttl { ttl } else { min_ttl });
            active_flow
                .get_mut(&key_value)
                .unwrap()
                .set_max_pkt(if max_pkt < pkt { pkt } else { max_pkt });
            active_flow
                .get_mut(&key_value)
                .unwrap()
                .set_min_pkt(if min_pkt > pkt { pkt } else { min_pkt });
            active_flow
                .get_mut(&key_value)
                .unwrap()
                .set_fin_cnt(cur_fin + fin);
            active_flow
                .get_mut(&key_value)
                .unwrap()
                .set_syn_cnt(cur_syn + syn);
            active_flow
                .get_mut(&key_value)
                .unwrap()
                .set_rst_cnt(cur_rst + rst);
            active_flow
                .get_mut(&key_value)
                .unwrap()
                .set_psh_cnt(cur_psh + psh);
            active_flow
                .get_mut(&key_value)
                .unwrap()
                .set_ack_cnt(cur_ack + ack);
            active_flow
                .get_mut(&key_value)
                .unwrap()
                .set_urg_cnt(cur_urg + urg);
            active_flow
                .get_mut(&key_value)
                .unwrap()
                .set_ece_cnt(cur_ece + ece);
            active_flow
                .get_mut(&key_value)
                .unwrap()
                .set_cwr_cnt(cur_cwr + cwr);
            active_flow
                .get_mut(&key_value)
                .unwrap()
                .set_ns_cnt(cur_ns + ns);
            active_flow
                .get_mut(&key_value)
                .unwrap()
                .set_out_bytes(cur_outbytes + doctets);
            active_flow
                .get_mut(&key_value)
                .unwrap()
                .set_last(packet.header.ts.tv_sec as u32);

            if fin == 1 || rst == 1 {
                if verbose >= 2 {
                    println!("flow finished");
                }
                records.push(*active_flow.get(&key_value).unwrap());
                active_flow.remove(&key_value);
            }
        }

        //println!("keys: {:?}", keys);
        //println!("flags : {:?},{:?},{:?},{:?},{:?},{:?},{:?} ",fin,syn,rst,psh,ack,urg,flags);

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
            for (key, flow) in active_flow.clone().iter() {
                //let flow = active_flow.get(&key).unwrap();
                if flow.get_last() < (packet.header.ts.tv_sec as u32 - flow_timeout / 1000) {
                    if verbose >= 2 {
                        println!("flow expired");
                    }
                    records.push(*flow);
                    active_flow.remove(key);
                }
            }
            let cloned_records = records.clone();
            let tasks = task::spawn(async {
                fluere_exporter(cloned_records, file).await;
            });
            
            let result = tasks.await;
            if verbose >= 1 {
                println!("Export {} result: {:?}", file_path, result);
            }
            let file_path = cur_time_file(csv_file, file_dir).await;
            file = fs::File::create(file_path.clone()).unwrap();
            //println!("records {:?}", records);
            records.clear();
            last_export = Instant::now();
        }

        // Check if the duration has been reached
        if start.elapsed() >= Duration::from_millis(duration) && duration != 0 {
            for (key, flow) in active_flow.clone().iter() {
                //let flow = active_flow.get(&key).unwrap();
                if flow.get_last() < (packet.header.ts.tv_sec as u32 - flow_timeout) {
                    if verbose >= 2 {
                        println!("flow expired");
                    }
                    records.push(*flow);
                    active_flow.remove(key);
                }
            }
            break;
        }
    }
    if verbose >= 1 {
        println!("Captured in {:?}", start.elapsed());
    }
    for (_key, flow) in active_flow.clone().iter() {
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
