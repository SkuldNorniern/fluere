use std::{
    collections::{BTreeMap, HashMap},
    fs,
    path::Path,
    time::Instant,
};

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
use indicatif::ProgressBar;
use log::{debug, info, trace};
use pcap::Capture;
use tokio::task;

pub async fn fluereflow_fileparse(arg: Args) -> Result<(), FluereError> {
    let _csv_file = arg.files.csv.unwrap();
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
    let file_noext = format!(
        "{}_converted.csv",
        Path::new(&file_name)
            .file_stem()
            .and_then(|stem| stem.to_str())
            .unwrap_or("output")
    );
    let output_file_path = format!("{}/{}", file_dir, file_noext);
    let file = fs::File::create(output_file_path.clone()).unwrap();

    let mut records: Vec<FluereRecord> = Vec::new();
    let mut active_flow: HashMap<Key, FluereRecord> = HashMap::new();
    let mut flow_expirations: BTreeMap<u64, Vec<Key>> = BTreeMap::new();

    info!("Converting file: {}", file_name);

    let bar = ProgressBar::new_spinner();

    while let Ok(packet) = cap.next_packet() {
        trace!("Parsing packet");

        let (mut key_value, mut reverse_key) = match parse_keys(packet.clone()) {
            Ok(keys) => keys,
            Err(_) => continue,
        };
        trace!("Parsed keys");
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

        // Define `packet_time` before any usage
        let packet_time = parse_microseconds(
            packet.header.ts.tv_sec as u64,
            packet.header.ts.tv_usec as u64,
        );

        let flags = TcpFlags::new(raw_flags);
        // Pushing packet into active_flows if it is not present
        let is_reverse = match active_flow.get(&key_value) {
            None => match active_flow.get(&reverse_key) {
                None => {
                    // If the protocol is TCP, check if it's a SYN packet
                    if flowdata.prot == 6 {
                        if flags.syn > 0 {
                            let expiration_time = packet_time + (flow_timeout * 1_000); // Convert milliseconds to microseconds
                            flow_expirations
                                .entry(expiration_time)
                                .or_default()
                                .push(key_value);
                            active_flow.insert(key_value, flowdata);

                            trace!("Flow established");
                        } else {
                            continue;
                        }
                    } else {
                        let expiration_time = packet_time + (flow_timeout * 1_000); // Convert milliseconds to microseconds
                        flow_expirations
                            .entry(expiration_time)
                            .or_default()
                            .push(key_value);
                        active_flow.insert(key_value, flowdata);

                        trace!("Flow established");
                    }

                    false
                }
                Some(_) => true,
            },
            Some(_) => false,
        };

        let pkt = flowdata.min_pkt;
        let ttl = flowdata.min_ttl;

        let flow_key = if is_reverse { &reverse_key } else { &key_value };
        if let Some(flow) = active_flow.get_mut(flow_key) {
            let update_key = UDFlowKey {
                doctets,
                pkt,
                ttl,
                flags,
                time: packet_time, // Use the correct variable here
            };

            update_flow(flow, is_reverse, update_key);

            trace!(
                "{} flow updated",
                if is_reverse { "reverse" } else { "forward" }
            );

            if flags.fin == 1 || flags.rst == 1 {
                trace!("Flow finished");
                trace!("Flow data: {:?}", flow);
                records.push(*flow);
                active_flow.remove(flow_key);
            }
        }

        // Remove expired flows before processing the next packet
        let current_time = packet_time;
        let expired_times: Vec<u64> = flow_expirations
            .range(..=current_time)
            .map(|(&time, _)| time)
            .collect();

        for expiration_time in expired_times {
            if let Some(keys) = flow_expirations.remove(&expiration_time) {
                for key in keys {
                    if let Some(flow) = active_flow.remove(&key) {
                        records.push(flow);
                    }
                }
            }
        }
    }
    bar.finish();
    info!("Converted in {:?}", start.elapsed());
    let ac_flow_cnt = active_flow.len();
    let ended_flow_cnt = records.len();

    for (_key, flow) in active_flow.clone().iter() {
        records.push(*flow);
    }

    let tasks = task::spawn(async {
        fluere_exporter(records, file).await;
    });

    let result = tasks.await;
    info!("Export {} result: {:?}", output_file_path, result);

    info!("Active flows: {:?}", ac_flow_cnt);
    info!("Ended flows: {:?}", ended_flow_cnt);
    Ok(())
}
