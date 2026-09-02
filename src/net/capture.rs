//! Live capture: read packets off an interface, build flows, export them.
//!
//! This is what `fluere capture` runs without `--tui`; the terminal-interface
//! variant lives in [`super::capture_tui`].

use std::{borrow::Cow, fs, mem::take, time::Instant};

use crate::{
    FluereError,
    error::CaptureError,
    net::{
        CaptureDevice, find_device,
        flow_engine::FlowEngine,
        observe_packet,
        parser::{PacketObservation, ParserState},
        source,
        stop::StopSignal,
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

fn process_packet(
    observation: PacketObservation,
    engine: &mut FlowEngine,
    plugin_manager: &PluginManager,
    records: &mut Vec<Flow>,
) -> Result<(), FluereError> {
    for flow in engine.accept(observation).completed {
        trace!("flow finished: {flow:?}");
        crate::net::identity::offer_to_plugins(plugin_manager, &flow)?;
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
    info!("Export {file_path_clone} Started");
    export_tasks.push(task::spawn(async move {
        let exporter = fluere_exporter(records_to_export, file).await;
        if let Err(err) = exporter {
            error!("Export error: {err}");
        }
        info!("Export {file_path_clone} Finished");
    }));

    info!("running without blocking");
    let file_path = cur_time_file(csv_file, file_dir, ".csv");
    let file = crate::utils::output::create(file_path.as_ref())?;
    Ok((file_path, file))
}

fn export_if_due(
    records: &mut Vec<Flow>,
    file: fs::File,
    file_path: Cow<'static, str>,
    csv_file: &str,
    file_dir: &str,
    schedule: &mut crate::net::live::ExportSchedule,
    export_tasks: &mut Vec<JoinHandle<()>>,
) -> Result<(Cow<'static, str>, fs::File), FluereError> {
    if schedule.is_due() {
        let export = rotate_export(records, file, &file_path, csv_file, file_dir, export_tasks)?;
        schedule.mark_exported();
        return Ok(export);
    }
    Ok((file_path, file))
}

fn drain_engine(
    engine: &mut FlowEngine,
    plugin_manager: &PluginManager,
    records: &mut Vec<Flow>,
) -> Result<(), FluereError> {
    for flow in engine.drain() {
        crate::net::identity::offer_to_plugins(plugin_manager, &flow)?;
        records.push(flow);
    }
    Ok(())
}

fn spawn_final_export(records: &mut Vec<Flow>, file: fs::File) -> JoinHandle<()> {
    let records_to_export = take(records);
    task::spawn(async {
        let exporter = fluere_exporter(records_to_export, file).await;
        if let Err(err) = exporter {
            error!("Export error: {err}");
        }
    })
}

/// Capture from an interface and export FluereFlow records.
///
/// Runs until the requested duration elapses or the operator interrupts it,
/// then drains the engine so flows still open are exported rather than lost.
pub async fn run(arg: Args) -> Result<(), FluereError> {
    let crate::net::live::Settings {
        csv_file,
        use_mac,
        snaplen,
        interface_name,
        duration,
        interval,
        flow_timeout,
    } = crate::net::live::Settings::from_args(arg)?;
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
    let mut export_schedule = crate::net::live::ExportSchedule::new(interval);
    let mut file_path = cur_time_file(csv_file.as_str(), file_dir, ".csv");
    // FIX:TASK: there is a possibility of a permission error
    // | need to check, if it is a permission error and handle it
    let mut file = crate::utils::output::create(file_path.as_ref())?;

    //let mut wtr = csv::Writer::from_writer(file);

    let mut records: Vec<Flow> = Vec::new();
    let mut engine = FlowEngine::new(flow_timeout);
    let mut export_tasks = vec![];

    let mut parser_state = ParserState::new();
    let interrupt = StopSignal::listen();

    loop {
        // Both checked before the read, so a quiet interface still stops on
        // time and still answers an interrupt. Checking the duration only
        // after a packet arrived meant `--duration` was ignored for as long as
        // nothing was captured.
        if interrupt.requested() {
            info!("Stopping capture");
            break;
        }
        if crate::net::live::duration_reached(start, duration) {
            break;
        }

        match source::read(cap) {
            source::Read::Packet(packet) => {
                trace!("received packet");
                if let Some(observation) =
                    observe_packet(packet, use_mac, linktype, &mut parser_state)
                {
                    process_packet(observation, &mut engine, &plugin_manager, &mut records)?;
                }
            }
            // Nothing arrived in this window. Not a failure, and not a reason
            // to skip the work below: an export is due on a schedule, not on
            // the next packet, and a quiet interface is exactly when a capture
            // looks stuck.
            source::Read::Timeout => {}
            source::Read::Eof => break,
            source::Read::Fatal(error) => {
                error!("Capture failed: {error}");
                return Err(FluereError::Capture(CaptureError::Pcap(error)));
            }
        }

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
    }

    debug!("Captured in {:?}", start.elapsed());
    drain_engine(&mut engine, &plugin_manager, &mut records)?;

    export_tasks.push(spawn_final_export(&mut records, file));
    // Consumes the manager: dropping its sender is what lets the worker drain
    // the queue and stop before plugin cleanup runs.
    plugin_manager.shutdown(plugin_worker).await;
    crate::net::live::await_export_tasks(export_tasks).await;
    // info!("Exporting task excutation result: {:?}", result);

    Ok(())
}
