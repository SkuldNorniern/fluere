use crate::net::Flow;
use log::{debug, error};
use std::fs::File;

/// Columns, in order. Kept next to the row builder so the two cannot drift.
const COLUMNS: [&str; 37] = [
    "source",
    "destination",
    "src_port",
    "dst_port",
    "prot",
    "packets",
    "frame_octets",
    "fwd_packets",
    "rev_packets",
    "fwd_octets",
    "rev_octets",
    "first",
    "last",
    "duration",
    "fwd_min_pkt",
    "fwd_max_pkt",
    "rev_min_pkt",
    "rev_max_pkt",
    "min_ttl",
    "max_ttl",
    "fin_cnt",
    "syn_cnt",
    "rst_cnt",
    "psh_cnt",
    "ack_cnt",
    "urg_cnt",
    "ece_cnt",
    "cwr_cnt",
    "ns_cnt",
    "dscp",
    "ecn",
    "start_state",
    "end_reason",
    // What separated this flow from another with the same addresses and ports.
    "vlan",
    "encap",
    "tunnel_id",
    "tunnel_endpoints",
];

pub async fn fluere_exporter(records: Vec<Flow>, file: File) -> Result<(), csv::Error> {
    let mut wtr = csv::Writer::from_writer(file);

    debug!("Writing {} records", records.len());
    wtr.write_record(COLUMNS).map_err(|e| {
        error!("Failed to write CSV header: {}", e);
        e
    })?;

    for flow in records.iter() {
        wtr.write_record(row(flow)).map_err(|e| {
            error!("Failed to write CSV record: {}", e);
            e
        })?;
    }

    debug!("Wrote {} records", records.len());
    Ok(())
}

/// One flow as text.
///
/// Totals come from the record's accessors rather than a stored field, so a row
/// cannot report a total that disagrees with its own directions.
fn row(flow: &Flow) -> Vec<String> {
    let record = &flow.record;
    let key = &flow.key;
    let flags = &record.forward.tcp_flags;
    let reverse_flags = &record.reverse.tcp_flags;

    // Flag counters are per direction now; the columns keep reporting the
    // conversation's total so existing consumers still add up.
    let both = |forward: u64, reverse: u64| (forward + reverse).to_string();
    let range = |range: Option<fluereflow::Range<u32>>, take_max: bool| {
        range.map_or_else(String::new, |r| {
            if take_max { r.max } else { r.min }.to_string()
        })
    };

    vec![
        key.src_ip.to_string(),
        key.dst_ip.to_string(),
        key.src_port.to_string(),
        key.dst_port.to_string(),
        key.protocol.to_string(),
        record.packets().to_string(),
        record.frame_octets().to_string(),
        record.forward.packets.to_string(),
        record.reverse.packets.to_string(),
        record.forward.frame_octets.to_string(),
        record.reverse.frame_octets.to_string(),
        record.time.start.nanos().to_string(),
        record.time.end.nanos().to_string(),
        record.time.duration().to_string(),
        range(record.forward.packet_length, false),
        range(record.forward.packet_length, true),
        range(record.reverse.packet_length, false),
        range(record.reverse.packet_length, true),
        record
            .network
            .ttl
            .map_or_else(String::new, |r| r.min.to_string()),
        record
            .network
            .ttl
            .map_or_else(String::new, |r| r.max.to_string()),
        both(flags.fin, reverse_flags.fin),
        both(flags.syn, reverse_flags.syn),
        both(flags.rst, reverse_flags.rst),
        both(flags.psh, reverse_flags.psh),
        both(flags.ack, reverse_flags.ack),
        both(flags.urg, reverse_flags.urg),
        both(flags.ece, reverse_flags.ece),
        both(flags.cwr, reverse_flags.cwr),
        both(flags.ns, reverse_flags.ns),
        record.network.dscp.to_string(),
        record.network.ecn.to_string(),
        format!("{:?}", record.time.start_state).to_lowercase(),
        record
            .time
            .end_reason
            .map_or_else(String::new, |reason| format!("{:?}", reason).to_lowercase()),
        flow.vlan(),
        flow.encapsulation().to_string(),
        flow.tunnel_id(),
        flow.tunnel_endpoints(),
    ]
}
