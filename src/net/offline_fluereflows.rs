use std::{fs, path::Path, time::Instant};

use crate::{
    FluereError,
    error::OptionExt,
    net::{
        flow_engine::FlowEngine,
        parser::{parse_fluereflow, parse_keys, parse_microseconds},
        types::{Key, TcpFlags},
    },
    types::Args,
    utils::fluere_exporter,
};

use fluereflow::FluereRecord;
use indicatif::ProgressBar;
use log::{debug, info, trace};
use pcap::Capture;

struct ParsedPacket {
    key_value: Key,
    reverse_key: Key,
    flowdata: FluereRecord,
    doctets: usize,
    flags: TcpFlags,
    packet_time: u64,
}

fn parse_packet(packet: pcap::Packet<'_>, use_mac: bool, linktype: u16) -> Option<ParsedPacket> {
    let (mut key_value, mut reverse_key) = match parse_keys(packet.clone(), linktype) {
        Ok(keys) => keys,
        Err(_) => return None,
    };
    trace!("Parsed keys");
    if !use_mac {
        key_value.mac_defaultate();
        reverse_key.mac_defaultate();
    }

    let (doctets, raw_flags, flowdata) = match parse_fluereflow(packet.clone(), linktype) {
        Ok(result) => result,
        Err(error) => {
            debug!("{}", error);
            return None;
        }
    };

    Some(ParsedPacket {
        key_value,
        reverse_key,
        flowdata,
        doctets,
        flags: TcpFlags::new(raw_flags),
        packet_time: parse_microseconds(
            packet.header.ts.tv_sec as u64,
            packet.header.ts.tv_usec as u64,
        ),
    })
}

fn process_packet(packet: ParsedPacket, engine: &mut FlowEngine, records: &mut Vec<FluereRecord>) {
    if let Some(flow) = engine.offer(
        packet.key_value,
        packet.reverse_key,
        packet.flowdata,
        packet.doctets,
        packet.flags,
        packet.packet_time,
    ) {
        trace!("Flow finished");
        trace!("Flow data: {:?}", flow);
        records.push(flow);
    }

    records.extend(engine.sweep_expired(packet.packet_time));
}

pub async fn fluereflow_fileparse(arg: Args) -> Result<(), FluereError> {
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
    let output_file_path = format!("{}/{}.csv", file_dir, file_noext);
    let file = fs::File::create(&output_file_path)?;

    let mut records: Vec<FluereRecord> = Vec::new();
    let mut engine = FlowEngine::new(flow_timeout);

    info!("Converting file: {}", file_name);

    let bar = ProgressBar::new_spinner();

    while let Ok(packet) = cap.next_packet() {
        trace!("Parsing packet");
        let Some(packet) = parse_packet(packet, use_mac, linktype) else {
            continue;
        };
        process_packet(packet, &mut engine, &mut records);
    }
    bar.finish();
    info!("Converted in {:?}", start.elapsed());
    let ac_flow_cnt = engine.active_count();
    let ended_flow_cnt = records.len();

    records.extend(engine.drain());

    // Awaited immediately, so there is nothing to gain from a spawned task -
    // and a failed export has to reach the caller rather than be discarded.
    fluere_exporter(records, file).await?;
    info!("Exported {}", output_file_path);

    info!("Active flows: {:?}", ac_flow_cnt);
    info!("Ended flows: {:?}", ended_flow_cnt);
    Ok(())
}
