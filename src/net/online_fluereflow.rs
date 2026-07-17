// This file contains the implementation of the online packet capture functionality.online
// It uses the pcap library to capture packets from a network interface and the fluereflow library to convert the packets into NetFlow data.
// The data is then exported to a CSV file.

use std::{
    fs,
    mem::take,
    time::{Duration, Instant},
};

use crate::{
    FluereError,
    error::OptionExt,
    net::{
        CaptureDevice, find_device,
        flow_engine::FlowEngine,
        parser::{parse_fluereflow, parse_keys, parse_microseconds},
        types::TcpFlags,
    },
    types::Args,
    utils::{cur_time_file, fluere_exporter},
};

use fluere_config::Config;

// FEAT:TASK: set plugin as feature
// | Since the plugin manager uses Lua, for edge cases that require minimal feature,
// | setting the plugin as a feature would be beneficial.
use fluere_plugin::PluginManager;
use fluereflow::FluereRecord;

use log::{debug, error, info, trace};
use tokio::{task, task::JoinHandle};

// This function captures packets from a network interface and converts them into NetFlow data.
// It takes the command line arguments as input, which specify the network interface to capture from and other parameters.
// The function runs indefinitely, capturing packets and exporting the captured data to a CSV file.
pub async fn packet_capture(arg: Args) -> Result<(), FluereError> {
    let csv_file = arg
        .files
        .csv
        .required("this should be defaulted to `output` on construction")?;
    //let enable_ipv6
    let use_mac = arg
        .parameters
        .use_mac
        .required("this should be defaulted to `false` on construction")?;
    let interface_name = arg.interface.required("interface should be provided")?;
    let duration = arg
        .parameters
        .duration
        .required("this should be defaulted to `0(infinite)` on construction")?;
    let interval = arg
        .parameters
        .interval
        .required("this should be defaulted to `30 minutes` on construction")?;
    let flow_timeout = arg
        .parameters
        .timeout
        .required("this should be defaulted to `10 minutes` on construction")?;
    let _sleep_windows = arg
        .parameters
        .sleep_windows
        .required("this should be defaulted to `false`, and now deprecated")?;
    let config = Config::new();
    let plugin_manager =
        PluginManager::new().map_err(|error| FluereError::Plugin(error.to_string()))?;
    let plugin_worker = plugin_manager.start_worker();

    plugin_manager
        .load_plugins(&config)
        .await
        .map_err(|error| FluereError::Plugin(error.to_string()))?;

    let interface = find_device(&interface_name)?;
    let mut cap_device = CaptureDevice::new(interface.clone())?;
    let cap = &mut cap_device.capture;

    let file_dir = "./output";
    fs::create_dir_all(file_dir)?;

    let start = Instant::now();
    let mut last_export = Instant::now();
    let mut file_path = cur_time_file(csv_file.as_str(), file_dir, ".csv");
    // FIX:TASK: there is a possibility of a permission error
    // | need to check, if it is a permission error and handle it
    let mut file = fs::File::create(file_path.as_ref())?;

    //let mut wtr = csv::Writer::from_writer(file);

    let mut records: Vec<FluereRecord> = Vec::new();
    let mut engine = FlowEngine::new(flow_timeout);
    let tasks: Vec<JoinHandle<Result<(), FluereError>>> = vec![];
    let mut export_tasks = vec![];

    loop {
        match cap.next_packet() {
            Err(e) => {
                trace!("Error capturing packet: {}", e);
                continue;
            }
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

                if let Some(flow) = engine.offer(
                    key_value,
                    reverse_key,
                    flowdata,
                    doctets,
                    flags,
                    packet_time,
                ) {
                    trace!("flow finished");
                    trace!("flow data: {:?}", flow);
                    plugin_manager
                        .process_flow_data(flow)
                        .await
                        .map_err(|error| FluereError::Plugin(error.to_string()))?;
                    records.push(flow);
                }

                for flow in engine.sweep_expired(packet_time) {
                    trace!("flow expired");
                    plugin_manager
                        .process_flow_data(flow)
                        .await
                        .map_err(|error| FluereError::Plugin(error.to_string()))?;
                    records.push(flow);
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
                        let exporter = fluere_exporter(records_to_export, file).await;
                        if let Err(err) = exporter {
                            error!("Export error: {}", err);
                        }
                        info!("Export {} Finished", file_path_clone);
                    }));

                    info!("running without blocking");
                    file_path = cur_time_file(&csv_file, file_dir, ".csv");
                    file = fs::File::create(file_path.as_ref())?;
                    last_export = Instant::now();
                }

                // Check if the duration has been reached
                if start.elapsed() >= Duration::from_millis(duration) && duration != 0 {
                    break;
                }
            }
        }
    }

    debug!("Captured in {:?}", start.elapsed());
    for flow in engine.drain() {
        plugin_manager
            .process_flow_data(flow)
            .await
            .map_err(|error| FluereError::Plugin(error.to_string()))?;
        records.push(flow);
    }
    for task in tasks {
        let _ = task.await;
    }

    let records_to_export = take(&mut records);
    export_tasks.push(task::spawn(async {
        let exporter = fluere_exporter(records_to_export, file).await;
        if let Err(err) = exporter {
            error!("Export error: {}", err);
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
