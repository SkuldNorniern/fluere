// This file contains the implementation of the online packet capture functionality.online
// It uses the pcap library to capture packets from a network interface and the fluereflow library to convert the packets into NetFlow data.
// The data is then exported to a CSV file.

use std::{
    collections::{BTreeMap, HashMap},
    fs,
    mem::take,
    time::{Duration, Instant},
};

use crate::{
    net::{
        find_device,
        flows::update_flow,
        parser::{parse_fluereflow, parse_keys, parse_microseconds},
        types::{Key, TcpFlags},
        CaptureDevice,
        NetError,
    },
    types::{Args, UDFlowKey},
    utils::{cur_time_file, fluere_exporter},
    FluereError,
};

use fluere_config::Config;

// FEAT:TASK: set plugin as feature
// | Since the plugin manager uses Lua, for edge cases that require minimal feature,
// | setting the plugin as a feature would be beneficial.
use fluere_plugin::PluginManager;
use fluereflow::FluereRecord;

use log::{debug, info, trace, error};
use tokio::{task, task::JoinHandle};

// This function captures packets from a network interface and converts them into NetFlow data.
// It takes the command line arguments as input, which specify the network interface to capture from and other parameters.
// The function runs indefinitely, capturing packets and exporting the captured data to a CSV file.
pub async fn packet_capture(arg: Args) -> Result<(), FluereError> {
    let csv_file = arg.files.csv.unwrap();
    let use_mac = arg.parameters.use_mac.unwrap();
    let interface_name = arg.interface.expect("interface not found");
    let duration = arg.parameters.duration.unwrap();
    let interval = arg.parameters.interval.unwrap();
    let flow_timeout = arg.parameters.timeout.unwrap();
    let _sleep_windows = arg.parameters.sleep_windows.unwrap();
    let config = Config::new();
    let plugin_manager = PluginManager::new().expect("Failed to create plugin manager");
    let plugin_worker = plugin_manager.start_worker();

    plugin_manager
        .load_plugins(&config)
        .await
        .expect("Failed to load plugins");

    let interface = find_device(&interface_name)?;
    let mut cap_device = CaptureDevice::new(interface.clone()).map_err(NetError::from)?;
    let cap = &mut cap_device.capture;

    let file_dir = "./output";
    fs::create_dir_all(file_dir)
        .unwrap_or_else(|error| panic!("Problem creating directory: {:?}", error));

    let start = Instant::now();
    let mut last_export = Instant::now();
    let mut file_path = cur_time_file(csv_file.as_str(), file_dir, ".csv");
    // FIX:TASK: there is a possibility of a permission error
    // | need to check, if it is a permission error and handle it
    let mut file = fs::File::create(file_path.as_ref()).unwrap();

    //let mut wtr = csv::Writer::from_writer(file);

    let mut records: Vec<FluereRecord> = Vec::new();
    let mut active_flow: HashMap<Key, FluereRecord> = HashMap::new();
    let tasks: Vec<JoinHandle<Result<(), FluereError>>> = vec![];
    let mut export_tasks = vec![];

    // Initialize flow_expirations BTreeMap
    let mut flow_expirations: BTreeMap<u64, Vec<Key>> = BTreeMap::new();

    loop {
        match cap.next_packet() {
            Err(_) => continue,
            Ok(packet) => {
                trace!("received packet");

                let (mut key_value, mut reverse_key) = match parse_keys(packet.clone()) {
                    Ok(keys) => keys,
                    Err(e) => {
                        debug!("Error on parse_keys: {}", e);
                        continue;
                    }
                };
                if !use_mac {
                    key_value.mac_defaultate();
                    reverse_key.mac_defaultate();
                }

                let (doctets, raw_flags, flowdata) = match parse_fluereflow(packet.clone()) {
                    Ok(result) => result,
                    Err(e) => {
                        debug!("Error on parse_fluereflow: {}", e);
                        continue;
                    }
                };

                let flags = TcpFlags::new(raw_flags);
                //pushing packet in to active_flows if it is not present
                let packet_time = parse_microseconds(
                    packet.header.ts.tv_sec as u64,
                    packet.header.ts.tv_usec as u64,
                );

                // When a new flow is established
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
                                    trace!("flow established");
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
                                trace!("flow established");
                            }
                            false
                        }
                        Some(_) => true,
                    },
                    Some(_) => false,
                };

                let flow_key = if is_reverse { &reverse_key } else { &key_value };

                // Update the flow
                if let Some(flow) = active_flow.get_mut(flow_key) {
                    let update_key = UDFlowKey {
                        doctets,
                        pkt: flowdata.min_pkt,
                        ttl: flowdata.min_ttl,
                        flags,
                        time: packet_time,
                    };
                    update_flow(flow, is_reverse, update_key);

                    // Update the expiration time for the flow
                    let new_expiration_time = packet_time + (flow_timeout * 1_000);
                    flow_expirations
                        .entry(new_expiration_time)
                        .or_default()
                        .push(*flow_key);

                    trace!(
                        "{} flow updated",
                        if is_reverse { "reverse" } else { "forward" }
                    );
                    trace!("flow key detail: {:?}", flow_key);

                    // Check if the flow has finished
                    if flags.fin == 1 || flags.rst == 1 {
                        trace!("flow finished");
                        trace!("flow data: {:?}", flow);

                        plugin_manager.process_flow_data(*flow).await.unwrap();
                        records.push(*flow);

                        active_flow.remove(flow_key);

                        // Remove the flow from flow_expirations
                        for (_exp_time, keys) in flow_expirations.iter_mut() {
                            if let Some(pos) = keys.iter().position(|k| k == flow_key) {
                                keys.swap_remove(pos);
                                break;
                            }
                        }
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
                                trace!("flow expired");
                                plugin_manager.process_flow_data(flow).await.unwrap();
                                records.push(flow);
                            }
                        }
                    }
                }

                // Export flows if the interval has been reached
                if last_export.elapsed() >= Duration::from_millis(interval) && interval != 0 {
                    // No need to handle expired flows here, as we now handle them with flow_expirations
                    // Proceed with exporting the current records
                    let records_to_export = take(&mut records);
                    debug!("Calculating timeout done");

                    let file_path_clone = file_path.clone();
                    info!("Export {} Started", file_path_clone);
                    export_tasks.push(task::spawn(async move {
                        let _ = fluere_exporter(records_to_export, file).await;
                        info!("Export {} Finished", file_path_clone);
                    }));

                    info!("running without blocking");
                    file_path = cur_time_file(&csv_file, file_dir, ".csv");
                    file = fs::File::create(file_path.as_ref()).unwrap();
                    last_export = Instant::now();
                }

                // Check if the duration has been reached
                if start.elapsed() >= Duration::from_millis(duration) && duration != 0 {
                    break;
                }
            }
        }
    }

    // After the loop, handle any remaining flows
    // Remove any flows that have not yet expired and process them
    for (_exp_time, keys) in flow_expirations.iter() {
        for key in keys {
            if let Some(flow) = active_flow.remove(key) {
                plugin_manager.process_flow_data(flow).await.unwrap();
                records.push(flow);
            }
        }
    }

    debug!("Captured in {:?}", start.elapsed());
    for (_key, flow) in active_flow.iter() {
        plugin_manager.process_flow_data(*flow).await.unwrap();
        records.push(*flow);
    }
    for task in tasks {
        let _ = task.await;
    }

    let records_to_export = take(&mut records);
    export_tasks.push(task::spawn(async {
        let exporter = fluere_exporter(records_to_export, file).await;
        if exporter.is_err() {
            error!("Export error: {}", exporter.unwrap_err());
        }
    }));
    plugin_manager.await_completion(plugin_worker).await;
    drop(plugin_manager);
    for task in export_tasks {
        let _ = task.await;
    }
    // info!("Exporting task excutation result: {:?}", result);

    Ok(())
}
