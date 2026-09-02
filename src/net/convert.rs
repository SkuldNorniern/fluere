use std::{fs, path::Path, time::Instant};

use crate::{
    FluereError,
    error::{CaptureError, OptionExt},
    net::{
        flow_engine::FlowEngine,
        observe_packet,
        parser::{PacketObservation, ParserState},
        source,
    },
    types::Args,
    utils::fluere_exporter,
};

use crate::net::Flow;
use fluere_config::Config;
use fluere_plugin::PluginManager;
use indicatif::ProgressBar;
use log::{error, info, trace};
use pcap::Capture;

fn process_packet(
    observation: PacketObservation,
    engine: &mut FlowEngine,
    plugin_manager: &PluginManager,
    records: &mut Vec<Flow>,
) -> Result<(), FluereError> {
    for flow in engine.accept(observation).completed {
        trace!("Flow finished: {flow:?}");
        plugin_manager
            .process_flow_data(flow.record, crate::net::identity::for_plugin(&flow))
            .map_err(|error| FluereError::Plugin(error.to_string()))?;
        records.push(flow);
    }

    Ok(())
}

/// Hand the flows still open at the end of the capture to the plugins too, so
/// a plugin sees every flow the conversion produced and not just the ones that
/// happened to close inside the file.
fn drain_engine(
    engine: &mut FlowEngine,
    plugin_manager: &PluginManager,
    records: &mut Vec<Flow>,
) -> Result<(), FluereError> {
    for flow in engine.drain() {
        plugin_manager
            .process_flow_data(flow.record, crate::net::identity::for_plugin(&flow))
            .map_err(|error| FluereError::Plugin(error.to_string()))?;
        records.push(flow);
    }

    Ok(())
}

pub async fn run(arg: Args) -> Result<(), FluereError> {
    let csv_title = arg.files.csv;
    let file_name = arg
        .files
        .file
        .required("pcap file path should be provided")?;
    let use_mac = arg
        .parameters
        .use_mac
        .required("this should be defaulted to `false` on construction")?;
    let flow_timeout = arg
        .parameters
        .timeout
        .required("this should be defaulted to `10 minutes` on construction")?;

    let mut cap = Capture::from_file(file_name.clone())?;
    let linktype = u16::try_from(cap.get_datalink().0).unwrap_or(1);

    let file_dir = "./output";
    fs::create_dir_all(file_dir)?;

    let start = Instant::now();
    // `-c` names the output; without it, derive the name from the capture file.
    let file_noext = csv_title.unwrap_or_else(|| {
        format!(
            "{}_converted",
            Path::new(&file_name)
                .file_stem()
                .and_then(|stem| stem.to_str())
                .unwrap_or("output")
        )
    });
    let output_file_path = format!("{file_dir}/{file_noext}.csv");
    let file = crate::utils::output::create(&output_file_path)?;

    let mut records: Vec<Flow> = Vec::new();
    let mut engine = FlowEngine::new(flow_timeout);

    let config = Config::new();
    let (plugin_manager, plugin_worker) = PluginManager::start(&config)
        .await
        .map_err(|error| FluereError::Plugin(error.to_string()))?;

    info!("Converting file: {file_name}");

    let bar = ProgressBar::new_spinner();
    let mut parser_state = ParserState::new();

    loop {
        // A read failure is not end of file. Treating it as one meant a damaged
        // capture produced partial output and still reported success, which is
        // the worst of both.
        let observation = match source::read(&mut cap) {
            source::Read::Packet(packet) => {
                trace!("Parsing packet");
                observe_packet(packet, use_mac, linktype, &mut parser_state)
            }
            source::Read::Eof => break,
            // A file has no timeouts, but reading one costs nothing either.
            source::Read::Timeout => continue,
            source::Read::Fatal(error) => {
                error!("Reading {file_name} failed: {error}");
                return Err(FluereError::Capture(CaptureError::Pcap(error)));
            }
        };

        if let Some(observation) = observation {
            process_packet(observation, &mut engine, &plugin_manager, &mut records)?;
        }
    }
    bar.finish();
    info!("Converted in {:?}", start.elapsed());
    let ac_flow_cnt = engine.active_count();
    let ended_flow_cnt = records.len();

    drain_engine(&mut engine, &plugin_manager, &mut records)?;

    // Consumes the manager: dropping its sender lets the worker drain the
    // queue and stop before plugin cleanup runs.
    plugin_manager.shutdown(plugin_worker).await;

    // Awaited immediately, so there is nothing to gain from a spawned task -
    // and a failed export has to reach the caller rather than be discarded.
    fluere_exporter(records, file).await?;
    info!("Exported {output_file_path}");

    info!("Active flows: {ac_flow_cnt:?}");
    info!("Ended flows: {ended_flow_cnt:?}");
    Ok(())
}
