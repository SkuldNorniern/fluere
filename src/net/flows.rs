use fluereflow::FluereRecord;

use crate::types::UDFlowKey;

/// Updates a flow
/// # Arguments
/// * `flow` - The flow to update
/// * `is_reverse` - Whether the flow is a reverse flow
/// * `update_key` - The update key
///
pub fn update_flow(flow: &mut FluereRecord, is_reverse: bool, update_key: UDFlowKey) {
    let doctets = update_key.doctets;
    let pkt = update_key.pkt;
    let ttl = update_key.ttl;
    let flags = update_key.flags;  
    let time = update_key.time;

    flow.set_d_pkts(flow.get_d_pkts() + 1);
    flow.set_d_octets(flow.get_d_octets() + doctets);
    flow.set_max_pkt(flow.get_max_pkt().max(pkt));
    flow.set_min_pkt(flow.get_min_pkt().min(pkt));
    flow.set_max_ttl(flow.get_max_ttl().max(ttl));
    flow.set_min_ttl(flow.get_min_ttl().min(ttl));
    flow.set_fin_cnt(flow.get_fin_cnt() + flags.fin as u32);
    flow.set_syn_cnt(flow.get_syn_cnt() + flags.syn as u32);
    flow.set_rst_cnt(flow.get_rst_cnt() + flags.rst as u32);
    flow.set_psh_cnt(flow.get_psh_cnt() + flags.psh as u32);
    flow.set_ack_cnt(flow.get_ack_cnt() + flags.ack as u32);
    flow.set_urg_cnt(flow.get_urg_cnt() + flags.urg as u32);
    flow.set_ece_cnt(flow.get_ece_cnt() + flags.ece as u32);
    flow.set_cwr_cnt(flow.get_cwr_cnt() + flags.cwr as u32);
    flow.set_ns_cnt(flow.get_ns_cnt() + flags.ns as u32);
    flow.set_last(time);

    if is_reverse {
        flow.set_in_pkts(flow.get_in_pkts() + 1);
        flow.set_in_bytes(flow.get_in_bytes() + doctets);
    } else {
        flow.set_out_pkts(flow.get_out_pkts() + 1);
        flow.set_out_bytes(flow.get_out_bytes() + doctets);
    }
}


