use std::{collections::HashMap, fs, time::Instant, path::Path};

use crate::{
    net::{
        flows::update_flow,
        parser::{parse_fluereflow, parse_keys, parse_microseconds},
        types::{Key, TcpFlags},
    },
    types::{Args, UDFlowKey},
    utils::fluere_exporter,
    FluereError, NetError,
};

use fluereflow::FluereRecord;
use log::{debug, info, trace};
use pcap::Capture;
use tokio::task;

pub async fn fluereflow_fileparse(arg: Args) -> Result<(), FluereError> {
    let csv_file = arg.files.csv.unwrap();
    let file_name = arg.files.file.unwrap();
    let use_mac = arg.parameters.use_mac.unwrap();
    let flow_timeout = arg.parameters.timeout.unwrap();

    let mut cap = Capture::from_file(file_name.clone()).map_err(NetError::from)?;

    let file_dir = "./output";
    match fs::create_dir_all(<&str>::clone(&file_dir)) {
        Ok(_) => {
            debug!("Created directory: {}", file_dir)
        }
        Err(error) => panic!("Problem creating directory: {:?}", error),
    };

    let start = Instant::now();
    // let file_path = cur_time_file(csv_file.as_str(), file_dir, ".csv");
    let file_noext = format!(
        "{}_converted.csv",
        Path::new(&file_name)
            .file_stem()
            .and_then(|stem| stem.to_str())
            .unwrap_or("output")
    );
    let output_file_path = format!("{}/{}", file_dir, file_noext);
    let file = fs::File::create(output_file_path.clone()).unwrap();

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
            Err(e) => {
                debug!("{}", e);
                continue;
            }
        };
        let flags = TcpFlags::new(raw_flags);
        //pushing packet in to active_flows if it is not present
        let is_reverse = match active_flow.get(&key_value) {
            None => match active_flow.get(&reverse_key) {
                None => {
                    // if the protocol is TCP, check if is a syn packet
                    if flowdata.prot == 6 {
                        if flags.syn > 0 {
                            active_flow.insert(key_value, flowdata);

                            trace!("flow established");
                        } else {
                            continue;
                        }
                    } else {
                        active_flow.insert(key_value, flowdata);

                        trace!("flow established");
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
        let pkt = flowdata.min_pkt;
        let ttl = flowdata.min_ttl;
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

            trace!(
                "{} flow updated",
                if is_reverse { "reverse" } else { "forward" }
            );

            if flags.fin == 1 || flags.rst == 1 {
                trace!("flow finished");
                trace!("flow data: {:?}", flow);
                records.push(*flow);
                active_flow.remove(flow_key);
            }
        }

        // Before processing a new packet, check for and handle expired flows
        let mut expired_flows = Vec::new();
        for (key, flow) in active_flow.iter() {
            if flow_timeout > 0 && time > (flow.last + (flow_timeout * 1000)) {
                // Assuming flow.last is in microseconds
                trace!("flow expired");
                trace!("flow data: {:?}", flow);
                records.push(*flow);
                expired_flows.push(*key);
            }
        }

        // Remove expired flows from the active flows map
        // active_flow.retain(|key, _| !expired_flows.contains(key));
        for key in expired_flows {
            active_flow.remove(&key);
        }
    }
    info!("Converted in {:?}", start.elapsed());
    let ac_flow_cnt = active_flow.len();
    let ended_flow_cnt = records.len();

    for (_key, flow) in active_flow.clone().iter() {
        records.push(*flow);
    }
    let tasks = task::spawn(async {
        fluere_exporter(records, file);
    });

    let result = tasks.await;
    info!("Export {} result: {:?}", output_file_path, result);

    info!("Active flow {:?}", ac_flow_cnt);
    info!("Ended flow {:?}", ended_flow_cnt);
    Ok(())
}
