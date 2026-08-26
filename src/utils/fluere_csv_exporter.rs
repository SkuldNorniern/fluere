use crate::net::Flow;
use log::{debug, error, trace};
use std::fs::File;

pub async fn fluere_exporter(records: Vec<Flow>, file: File) -> Result<(), csv::Error> {
    let mut wtr = csv::Writer::from_writer(file);

    debug!("Writing {} records", records.len());
    trace!(" record: {:?}", records);
    wtr.write_record([
        "source",
        "destination",
        "src_port",
        "dst_port",
        "prot",
        "d_pkts",
        "d_octets",
        "in_pkts",
        "out_pkts",
        "in_bytes",
        "out_bytes",
        "first",
        "last",
        "min_pkt",
        "max_pkt",
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
        "tos",
        "mid_stream",
        // What separated this flow from another with the same addresses and
        // ports. Empty when the traffic was untagged and untunnelled.
        "vlan",
        "encap",
        "tunnel_id",
        "tunnel_endpoints",
    ])
    .map_err(|e| {
        error!("Failed to write CSV header: {}", e);
        e
    })?;

    for flow in records.iter() {
        let vlan = flow.vlan();
        let encapsulation = flow.encapsulation();
        let tunnel_id = flow.tunnel_id();
        let tunnel_endpoints = flow.tunnel_endpoints();
        let flow = &flow.record;
        wtr.write_record([
            &flow.source.to_string(),
            &flow.destination.to_string(),
            &flow.src_port.to_string(),
            &flow.dst_port.to_string(),
            &flow.prot.to_string(),
            &flow.d_pkts.to_string(),
            &flow.d_octets.to_string(),
            &flow.in_pkts.to_string(),
            &flow.out_pkts.to_string(),
            &flow.in_bytes.to_string(),
            &flow.out_bytes.to_string(),
            &flow.first.to_string(),
            &flow.last.to_string(),
            &flow.min_pkt.to_string(),
            &flow.max_pkt.to_string(),
            &flow.min_ttl.to_string(),
            &flow.max_ttl.to_string(),
            &flow.fin_cnt.to_string(),
            &flow.syn_cnt.to_string(),
            &flow.rst_cnt.to_string(),
            &flow.psh_cnt.to_string(),
            &flow.ack_cnt.to_string(),
            &flow.urg_cnt.to_string(),
            &flow.ece_cnt.to_string(),
            &flow.cwr_cnt.to_string(),
            &flow.ns_cnt.to_string(),
            &flow.tos.to_string(),
            &u8::from(flow.mid_stream).to_string(),
            &vlan,
            &encapsulation.to_string(),
            &tunnel_id,
            &tunnel_endpoints,
        ])
        .map_err(|e| {
            error!("Failed to write CSV record: {}", e);
            e
        })?;
    }
    debug!("Wrote {} records", records.len());
    Ok(())
}
