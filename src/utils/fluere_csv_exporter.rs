use fluereflow::FluereRecord;
use std::fs::File;

pub async fn fluere_exporter(records: Vec<FluereRecord>, file: File) {
    let mut wtr = csv::Writer::from_writer(file);

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
    ])
    .unwrap();
    for flow in records.iter() {
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
        ])
        .unwrap();
    }
}
