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
        let key = &flow.key;
        let mut endpoints = Endpoints::default();

        match key.protocol {
            // ICMP and ICMPv6: the type and code are a measurement, taken from
            // the flow's first packet rather than from the key.
            1 | 58 => {
                if let Some((icmp_type, code)) = flow.record.transport.icmp {
                    endpoints.icmp_type = icmp_type.to_string();
                    endpoints.icmp_code = code.to_string();
                }
            }
            // IPsec: the key holds the two halves of the SPI.
            50 | 51 => {
                let spi = (u32::from(key.src_port) << 16) | u32::from(key.dst_port);
                endpoints.spi = format!("0x{:08x}", spi);
            }
            // GRE whose inner flow could not be decoded reports the protocol it
            // was carrying.
            47 if key.src_port != 0 => {
                endpoints.gre_protocol = format!("0x{:04x}", key.src_port);
            }
            // ARP has no endpoints at all.
            4 => {}
            _ => {
                endpoints.ports = (key.src_port.to_string(), key.dst_port.to_string());
            }
        }

        endpoints
    }
}

/// Columns, in order. Kept next to the row builder so the two cannot drift.
const COLUMNS: [&str; 44] = [
    "source",
    "destination",
    "ip_version",
    // Only ever real transport ports. Anything else a protocol puts in their
    // place has a column of its own below, so no column means two things.
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
        key.src_ip.to_string(),
        key.dst_ip.to_string(),
        if key.src_ip.is_ipv6() { "6" } else { "4" }.to_string(),
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
        flow.ethertype(),
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
