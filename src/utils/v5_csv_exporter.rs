use crate::net::V5Record;
use std::fs::File;

pub async fn v5_exporter(records: Vec<V5Record>, file: File) {
    let mut wtr = csv::Writer::from_writer(file);

    wtr.write_record([
        "src_ip", "dst_ip", "nexthop", "input", "output", "dPkts", "dOctets", "First", "Last",
        "src_port", "dst_port", "pad1", "fin", "syn", "rst", "psh", "ack", "urg", "flags", "prot",
        "tos", "src_as", "dst_as", "src_mask", "dst_mask", "pad2",
    ])
    .unwrap();
    for flow in records.iter() {
        wtr.write_record([
            &flow.get_source().to_string(),
            &flow.get_destination().to_string(),
            &flow.get_next_hop().to_string(),
            &flow.get_input().to_string(),
            &flow.get_output().to_string(),
            &flow.get_d_pkts().to_string(),
            &flow.get_d_octets().to_string(),
            &flow.get_first().to_string(),
            &flow.get_last().to_string(),
            &flow.get_src_port().to_string(),
            &flow.get_dst_port().to_string(),
            &flow.get_pad1().to_string(),
            &flow.get_fin().to_string(),
            &flow.get_syn().to_string(),
            &flow.get_rst().to_string(),
            &flow.get_psh().to_string(),
            &flow.get_ack().to_string(),
            &flow.get_urg().to_string(),
            &flow.get_flags().to_string(),
            &flow.get_prot().to_string(),
            &flow.get_tos().to_string(),
            &flow.get_src_as().to_string(),
            &flow.get_dst_as().to_string(),
            &flow.get_src_mask().to_string(),
            &flow.get_dst_mask().to_string(),
            &flow.get_pad2().to_string(),
        ])
        .unwrap();
    }
}
