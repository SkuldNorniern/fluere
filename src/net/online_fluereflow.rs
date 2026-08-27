// This file contains the implementation of the online packet capture functionality.online
// It uses the pcap library to capture packets from a network interface and the fluereflow library to convert the packets into NetFlow data.
// The data is then exported to a CSV file.

use std::{
    borrow::Cow,
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
        observe_packet,
        parser::{PacketObservation, ParserState},
    },
    types::Args,
    utils::{cur_time_file, fluere_exporter},
};

use fluere_config::Config;

// FEAT:TASK: set plugin as feature
// | Since the plugin manager uses Lua, for edge cases that require minimal feature,
// | setting the plugin as a feature would be beneficial.
use crate::net::Flow;
use fluere_plugin::PluginManager;

use log::{debug, error, info, trace};
use tokio::{task, task::JoinHandle};

struct OnlineArgs {
    csv_file: String,
    use_mac: bool,
    snaplen: u64,
    interface_name: String,
    duration: u64,
    interval: u64,
    flow_timeout: u64,
}

fn extract_online_args(arg: Args) -> Result<OnlineArgs, FluereError> {
    let csv_file = arg
        .files
        .csv
        .required("this should be defaulted to `output` on construction")?;
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
    let snaplen = arg
        .parameters
        .snaplen
        .required("this should be defaulted to `65535` on construction")?;
    Ok(OnlineArgs {
        csv_file,
        use_mac,
        snaplen,
        interface_name,
        duration,
        interval,
        flow_timeout,
    })
}

struct ExportSchedule {
    interval: u64,
    last_export: Instant,
}

fn next_packet(cap: &mut pcap::Capture<pcap::Active>) -> Option<pcap::Packet<'_>> {
    match cap.next_packet() {
        Ok(packet) => Some(packet),
        Err(error) => {
            trace!("Error capturing packet: {}", error);
            None
        }
    }
}

fn duration_reached(start: Instant, duration: u64) -> bool {
    start.elapsed() >= Duration::from_millis(duration) && duration != 0
}

async fn process_packet(
    observation: PacketObservation,
    engine: &mut FlowEngine,
    plugin_manager: &PluginManager,
    records: &mut Vec<Flow>,
) -> Result<(), FluereError> {
    for flow in engine.accept(observation).completed {
        trace!("flow finished: {:?}", flow);
        plugin_manager
            .process_flow_data(flow.record, crate::net::identity::for_plugin(&flow))
            .await
            .map_err(|error| FluereError::Plugin(error.to_string()))?;
        records.push(flow);
    }

    Ok(())
}

fn rotate_export(
    records: &mut Vec<Flow>,
    file: fs::File,
    file_path: &str,
    csv_file: &str,
    file_dir: &str,
    export_tasks: &mut Vec<JoinHandle<()>>,
) -> Result<(Cow<'static, str>, fs::File), FluereError> {
    let records_to_export = take(records);
    debug!("Calculating timeout done");

    let file_path_clone = file_path.to_owned();
    info!("Export {} Started", file_path_clone);
    export_tasks.push(task::spawn(async move {
        let exporter = fluere_exporter(records_to_export, file).await;
        if let Err(err) = exporter {
            error!("Export error: {}", err);
        }
        info!("Export {} Finished", file_path_clone);
    }));

    info!("running without blocking");
    let file_path = cur_time_file(csv_file, file_dir, ".csv");
    let file = fs::File::create(file_path.as_ref())?;
    Ok((file_path, file))
}

fn export_if_due(
    records: &mut Vec<Flow>,
    file: fs::File,
    file_path: Cow<'static, str>,
    csv_file: &str,
    file_dir: &str,
    schedule: &mut ExportSchedule,
    export_tasks: &mut Vec<JoinHandle<()>>,
) -> Result<(Cow<'static, str>, fs::File), FluereError> {
    if schedule.last_export.elapsed() >= Duration::from_millis(schedule.interval)
        && schedule.interval != 0
    {
        let export = rotate_export(records, file, &file_path, csv_file, file_dir, export_tasks)?;
        schedule.last_export = Instant::now();
        return Ok(export);
    }
    Ok((file_path, file))
}

async fn drain_engine(
    engine: &mut FlowEngine,
    plugin_manager: &PluginManager,
    records: &mut Vec<Flow>,
) -> Result<(), FluereError> {
    for flow in engine.drain() {
        plugin_manager
            .process_flow_data(flow.record, crate::net::identity::for_plugin(&flow))
            .await
            .map_err(|error| FluereError::Plugin(error.to_string()))?;
        records.push(flow);
    }
    Ok(())
}

async fn await_capture_tasks(tasks: Vec<JoinHandle<Result<(), FluereError>>>) {
    for task in tasks {
        let _ = task.await;
    }
}

fn spawn_final_export(records: &mut Vec<Flow>, file: fs::File) -> JoinHandle<()> {
    let records_to_export = take(records);
    task::spawn(async {
        let exporter = fluere_exporter(records_to_export, file).await;
        if let Err(err) = exporter {
            error!("Export error: {}", err);
        }
    })
}

async fn await_export_tasks(export_tasks: Vec<JoinHandle<()>>) {
    for task in export_tasks {
        let _ = task.await;
    }
}

// This function captures packets from a network interface and converts them into NetFlow data.
// It takes the command line arguments as input, which specify the network interface to capture from and other parameters.
// The function runs indefinitely, capturing packets and exporting the captured data to a CSV file.
pub async fn packet_capture(arg: Args) -> Result<(), FluereError> {
    let OnlineArgs {
        csv_file,
        use_mac,
        snaplen,
        interface_name,
        duration,
        interval,
        flow_timeout,
    } = extract_online_args(arg)?;
    let config = Config::new();
    let (plugin_manager, plugin_worker) = PluginManager::start(&config)
        .await
        .map_err(|error| FluereError::Plugin(error.to_string()))?;

    let interface = find_device(&interface_name)?;
    let mut cap_device = CaptureDevice::new(interface.clone(), snaplen)?;
    let cap = &mut cap_device.capture;
    let linktype = u16::try_from(cap.get_datalink().0).unwrap_or(1);

    let file_dir = "./output";
    fs::create_dir_all(file_dir)?;

    let start = Instant::now();
    let mut export_schedule = ExportSchedule {
        interval,
        last_export: Instant::now(),
    };
    let mut file_path = cur_time_file(csv_file.as_str(), file_dir, ".csv");
    // FIX:TASK: there is a possibility of a permission error
    // | need to check, if it is a permission error and handle it
    let mut file = fs::File::create(file_path.as_ref())?;

    //let mut wtr = csv::Writer::from_writer(file);

    let mut records: Vec<Flow> = Vec::new();
    let mut engine = FlowEngine::new(flow_timeout);
    let tasks: Vec<JoinHandle<Result<(), FluereError>>> = vec![];
    let mut export_tasks = vec![];

    let mut parser_state = ParserState::new();

    loop {
        let Some(packet) = next_packet(cap) else {
            continue;
        };
        trace!("received packet");
        let Some(observation) = observe_packet(packet, use_mac, linktype, &mut parser_state) else {
            continue;
        };
        process_packet(observation, &mut engine, &plugin_manager, &mut records).await?;

        // Export flows if the interval has been reached
        (file_path, file) = export_if_due(
            &mut records,
            file,
            file_path,
            &csv_file,
            file_dir,
            &mut export_schedule,
            &mut export_tasks,
        )?;

        // Check if the duration has been reached
        if duration_reached(start, duration) {
            break;
        }
    }

    debug!("Captured in {:?}", start.elapsed());
    drain_engine(&mut engine, &plugin_manager, &mut records).await?;
    await_capture_tasks(tasks).await;

    export_tasks.push(spawn_final_export(&mut records, file));
    // Consumes the manager: dropping its sender is what lets the worker drain
    // the queue and stop before plugin cleanup runs.
    plugin_manager.shutdown(plugin_worker).await;
    await_export_tasks(export_tasks).await;
    // info!("Exporting task excutation result: {:?}", result);

    Ok(())
}
