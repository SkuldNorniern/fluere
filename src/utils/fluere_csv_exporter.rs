use crate::net::FluereRecord;
use std::fs::File;

pub async fn fluere_exporter(records: Vec<FluereRecord>, file: File) {
    let mut wtr = csv::Writer::from_writer(file);

    wtr.write_record([
        "source",
        "destination",
        "d_pkts",
        "d_octets",
        "first",
        "last",
        "src_port",
        "dst_port",
        "min_pkt",
        "max_pkt",
        "min_ttl",
        "max_ttl",
        "in_pkts",
        "out_pkts",
        "fin_cnt",
        "syn_cnt",
        "rst_cnt",
        "psh_cnt",
        "ack_cnt",
        "urg_cnt",
        "ece_cnt",
        "cwr_cnt",
        "ns_cnt",
        "prot",
        "tos",
    ])
    .unwrap();
    for flow in records.iter() {
        wtr.write_record([
            &flow.get_source().to_string(),
            &flow.get_destination().to_string(),
            &flow.get_d_pkts().to_string(),
            &flow.get_d_octets().to_string(),
            &flow.get_first().to_string(),
            &flow.get_last().to_string(),
            &flow.get_src_port().to_string(),
            &flow.get_dst_port().to_string(),
            &flow.get_min_pkt().to_string(),
            &flow.get_max_pkt().to_string(),
            &flow.get_min_ttl().to_string(),
            &flow.get_max_ttl().to_string(),
            &flow.get_in_pkts().to_string(),
            &flow.get_out_pkts().to_string(),
            &flow.get_fin_cnt().to_string(),
            &flow.get_syn_cnt().to_string(),
            &flow.get_rst_cnt().to_string(),
            &flow.get_psh_cnt().to_string(),
            &flow.get_ack_cnt().to_string(),
            &flow.get_urg_cnt().to_string(),
            &flow.get_ece_cnt().to_string(),
            &flow.get_cwr_cnt().to_string(),
            &flow.get_ns_cnt().to_string(),
            &flow.get_prot().to_string(),
            &flow.get_tos().to_string(),
        ])
        .unwrap();
    }
}
