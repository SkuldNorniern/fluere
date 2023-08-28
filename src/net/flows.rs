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

    flow.d_pkts += 1;
    flow.d_octets += doctets;
    flow.max_pkt = flow.max_pkt.max(pkt);
    flow.min_pkt = flow.min_pkt.min(pkt);
    flow.max_ttl = flow.max_ttl.max(ttl);
    flow.min_ttl = flow.min_ttl.min(ttl);
    flow.fin_cnt += flags.fin as u32;
    flow.syn_cnt += flags.syn as u32;
    flow.rst_cnt += flags.rst as u32;
    flow.psh_cnt += flags.psh as u32;
    flow.ack_cnt += flags.ack as u32;
    flow.urg_cnt += flags.urg as u32;
    flow.ece_cnt += flags.ece as u32;
    flow.cwr_cnt += flags.cwr as u32;
    flow.ns_cnt += flags.ns as u32;
    flow.last = time;

    if is_reverse {
        flow.in_pkts += 1;
        flow.in_bytes += doctets;
    } else {
        flow.out_pkts += 1;
        flow.out_bytes += doctets;
    }
}
