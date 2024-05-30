// This file contains the implementation of the online packet capture functionality.online
// It uses the pcap library to capture packets from a network interface and the fluereflow library to convert the packets into NetFlow data.
// The data is then exported to a CSV file.

use std::{
    collections::HashMap,
    fs,
    time::{Duration, Instant},
};

use crate::{
    net::{
        find_device,
        flows::update_flow,
        parser::{parse_fluereflow, parse_keys, parse_microseconds},
        types::{Key, TcpFlags},
        CaptureDevice,
    },
    types::{Args, UDFlowKey},
    utils::{cur_time_file, fluere_exporter},
    FluereError, NetError,
};

use fluere_config::Config;

// FEAT:TASK: set plugin as feature
// | Since the plugin manager uses Lua, for edge cases that require minimal feature,
// | setting the plugin as a feature would be beneficial.
use fluere_plugin::PluginManager;
use fluereflow::FluereRecord;

use tokio::task;

use log::{debug, info, trace};

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

    let interface = find_device(interface_name.as_str())?;
    let mut cap_device = CaptureDevice::new(interface.clone()).map_err(NetError::from)?;
    let cap = &mut cap_device.capture;

    let file_dir = "./output";
    match fs::create_dir_all(<&str>::clone(&file_dir)) {
        Ok(_) => {
            trace!("Created directory: {}", file_dir)
        }
        Err(error) => panic!("Problem creating directory: {:?}", error),
    };

    let start = Instant::now();
    let mut last_export = Instant::now();
    let mut file_path = cur_time_file(csv_file.as_str(), file_dir, ".csv");
    // FIX:TASK: there is a possibility of a permission error
    // | need to check, if it is a permission error and handle it
    let mut file = fs::File::create(file_path.as_ref()).unwrap();

    //let mut wtr = csv::Writer::from_writer(file);

    let mut records: Vec<FluereRecord> = Vec::new();
    let mut active_flow: HashMap<Key, FluereRecord> = HashMap::new();
    let mut tasks = vec![];
    let mut export_tasks = vec![];
    // let mut packet_count = 0;
    // let export_rt =
    loop {
        match cap.next_packet() {
            Err(_) => {
                continue;
            }
            Ok(packet) => {
                trace!("received packet");
                // trace!("packet: {:?}", );

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
                /*let is_reverse = if active_flow.contains_key(&key_value) {
                false
                } else if active_flow.contains_key(&reverse_key) {
                true
                } else {
                if flowdata.get_prot() != 6  && flags.syn > 0  {
                active_flow.insert(key_value, flowdata);
                if verbose >= 2 {
                println!("flow established");
                }
                } else {
                continue;
                }
                false
                };*/

                let time = parse_microseconds(
                    packet.header.ts.tv_sec as u64,
                    packet.header.ts.tv_usec as u64,
                );
                //println!("time: {:?}", time);
                let pkt = flowdata.min_pkt;
                let ttl = flowdata.min_ttl;
                // trace!(
                // "current inputed flow{:?}",
                // active_flow.get(&key_value).unwrap()
                // );
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
                    trace!("flow key detail: {:?}", flow_key);

                    // Check if the flow has finished
                    if flags.fin == 1 || flags.rst == 1 {
                        trace!("flow finished");
                        trace!("flow data: {:?}", flow);

                        plugin_manager.process_flow_data(*flow).await.unwrap();

                        records.push(*flow);

                        active_flow.remove(flow_key);
                    }
                }

                // Export flows if the interval has been reached
                if last_export.elapsed() >= Duration::from_millis(interval) && interval != 0 {
                    let mut expired_flows = vec![];
                    let mut expired_flow_data = vec![];
                    // packet_count = 0;
                    debug!("Calculating timeout start");
                    for (key, flow) in active_flow.iter() {
                        if flow_timeout > 0 && flow.last < (time - (flow_timeout * 1000)) {
                            trace!("flow expired");
                            trace!("flow data: {:?}", flow);

                            // plugin_manager.process_flow_data(*flow).await.unwrap();
                            records.push(*flow);
                            expired_flows.push(*key);
                            expired_flow_data.push(*flow);
                        }
                    }

                    // Send the expired flows to the plugins
                    debug!(
                        "Sending {} expired flows to plugins start",
                        expired_flows.len()
                    );

                    let cloned_plugin_manager = plugin_manager.clone();
                    tasks.push(task::spawn(async move {
                        for flow in &expired_flow_data {
                            cloned_plugin_manager
                                .process_flow_data(*flow)
                                .await
                                .unwrap();
                        }
                        debug!(
                            "Sending {} expired flows to plugins done",
                            expired_flow_data.len()
                        );
                    }));

                    active_flow.retain(|key, _| !expired_flows.contains(key));
                    let cloned_records = records.clone();
                    records.clear();
                    debug!("Calculating timeout done");

                    let file_path_clone = file_path.clone();
                    //let file = fs::File::create(file_path_clone).unwrap();
                    info!("Export {} Started", file_path_clone);
                    export_tasks.push(task::spawn(async move {
                        fluere_exporter(cloned_records, file).await;
                        info!("Export {} Finished", file_path_clone);
                    }));

                    // let result = tasks.await;
                    info!("running without blockng");
                    file_path = cur_time_file(csv_file.as_str(), file_dir, ".csv");
                    file = fs::File::create(file_path.as_ref()).unwrap();
                    last_export = Instant::now();
                }

                // Check if the duration has been reached
                if start.elapsed() >= Duration::from_millis(duration) && duration != 0 {
                    let mut expired_flows = vec![];
                    for (key, flow) in active_flow.iter() {
                        if flow.last < (time - (flow_timeout * 1000)) {
                            trace!("flow expired");
                            plugin_manager.process_flow_data(*flow).await.unwrap();
                            records.push(*flow);
                            expired_flows.push(*key);
                        }
                    }
                    active_flow.retain(|key, _| !expired_flows.contains(key));
                    break;
                }
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

    let cloned_records = records.clone();
    export_tasks.push(task::spawn(async {
        fluere_exporter(cloned_records, file).await;
    }));
    plugin_manager.await_completion(plugin_worker).await;
    drop(plugin_manager);
    for task in export_tasks {
        let _ = task.await;
    }
    // info!("Exporting task excutation result: {:?}", result);

    Ok(())
}
