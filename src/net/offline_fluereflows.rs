use std::{fs, path::Path, time::Instant};

use crate::{
    FluereError,
    error::OptionExt,
    net::{
        flow_engine::FlowEngine,
        parser::{parse_fluereflow, parse_keys, parse_microseconds},
        types::TcpFlags,
    },
    types::Args,
    utils::fluere_exporter,
};

use fluereflow::FluereRecord;
use indicatif::ProgressBar;
use log::{debug, info, trace};
use pcap::Capture;
use tokio::task;

pub async fn fluereflow_fileparse(arg: Args) -> Result<(), FluereError> {
    let _csv_file = arg
        .files
        .csv
        .required("this should be defaulted to `output` on construction")?;
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

    let file_dir = "./output";
    fs::create_dir_all(file_dir)?;

    let start = Instant::now();
    let file_noext = format!(
        "{}_converted.csv",
        Path::new(&file_name)
            .file_stem()
            .and_then(|stem| stem.to_str())
            .unwrap_or("output")
    );
    let output_file_path = format!("{}/{}", file_dir, file_noext);
    let file = fs::File::create(&output_file_path)?;

    let mut records: Vec<FluereRecord> = Vec::new();
    let mut engine = FlowEngine::new(flow_timeout);

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
        if let Some(flow) = engine.offer(
            key_value,
            reverse_key,
            flowdata,
            doctets,
            flags,
            packet_time,
        ) {
            trace!("Flow finished");
            trace!("Flow data: {:?}", flow);
            records.push(flow);
        }

        records.extend(engine.sweep_expired(packet_time));
    }
    bar.finish();
    info!("Converted in {:?}", start.elapsed());
    let ac_flow_cnt = engine.active_count();
    let ended_flow_cnt = records.len();

    records.extend(engine.drain());

    let tasks = task::spawn(async {
        let _ = fluere_exporter(records, file).await;
    });

    let result = tasks.await;
    info!("Export {} result: {:?}", output_file_path, result);

    info!("Active flows: {:?}", ac_flow_cnt);
    info!("Ended flows: {:?}", ended_flow_cnt);
    Ok(())
}
