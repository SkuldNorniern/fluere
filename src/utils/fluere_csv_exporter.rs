use crate::net::Flow;
use log::{debug, error};
use std::fs::File;

/// The endpoint columns, filled in only where the protocol actually has them.
///
/// Protocols without ports used to borrow the port fields: ICMP put its type
/// and code there, IPsec split its SPI across them, GRE reported its inner
/// protocol type. Each now has a column of its own, so a value never means one
/// thing in one row and something else in the next.
#[derive(Default)]
struct Endpoints {
    ports: (String, String),
    icmp_type: String,
    icmp_code: String,
    spi: String,
    gre_protocol: String,
}

impl Endpoints {
    fn of(flow: &Flow) -> Self {
        let mut endpoints = Endpoints::default();

        // Each kind is read from the key's own typed endpoint rather than
        // guessed from the protocol number, so this cannot drift from how the
        // flow was actually keyed.
        if let Some((source, destination)) = flow.key.endpoints.ports() {
            endpoints.ports = (source.to_string(), destination.to_string());
        }
        if let Some(spi) = flow.key.endpoints.security_association() {
            endpoints.spi = format!("0x{:08x}", spi);
        }
        if let Some(protocol) = flow.key.endpoints.gre_protocol() {
            endpoints.gre_protocol = format!("0x{:04x}", protocol);
        }
        // ICMP type and code are a measurement, not an endpoint: they identify
        // the direction, and an echo exchange is one flow.
        if let Some((icmp_type, code)) = flow.record.transport.icmp {
            endpoints.icmp_type = icmp_type.to_string();
            endpoints.icmp_code = code.to_string();
        }

        endpoints
    }
}

/// Columns, in order. Kept next to the row builder so the two cannot drift.
const COLUMNS: [&str; 46] = [
    "source",
    "destination",
    "ip_version",
    "src_port",
    "dst_port",
    "icmp_type",
    "icmp_code",
    "spi",
    "gre_protocol",
    "protocol",
    "prot",
    "ethertype",
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
    "path_count",
    "paths",
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

    // Flush explicitly: relying on the writer's destructor would swallow a
    // failure on the last buffered rows, which is exactly when the caller most
    // needs to hear about it.
    wtr.flush().map_err(|error| {
        error!("Failed to flush CSV output: {}", error);
        csv::Error::from(error)
    })?;

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
    let endpoints = Endpoints::of(flow);
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
        key.source.to_string(),
        key.destination.to_string(),
        key.ip_version().to_string(),
        endpoints.ports.0.clone(),
        endpoints.ports.1.clone(),
        endpoints.icmp_type,
        endpoints.icmp_code,
        endpoints.spi,
        endpoints.gre_protocol,
        flow.protocol_name().to_string(),
        // Empty for traffic with no IP protocol number of its own.
        if flow.is_ip() {
            key.protocol.to_string()
        } else {
            String::new()
        },
        crate::net::identity::ethertype(flow),
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
        record.paths.count().to_string(),
        crate::net::identity::paths(flow),
        crate::net::identity::vlan(flow),
        crate::net::identity::encapsulation(flow).to_string(),
        crate::net::identity::tunnel_id(flow),
        crate::net::identity::tunnel_endpoints(flow),
    ]
}
