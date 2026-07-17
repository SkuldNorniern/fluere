//! Differential coverage for the production pnet key extractor and paccel.
//!
//! This test uses a local-only pcap corpus to inform a future pnet-to-paccel
//! migration decision; it does not perform that swap or change production code.
//! Machines without any of the corpus files skip the comparison gracefully.

use std::collections::BTreeMap;
use std::path::Path;

use fluere::net::{parser::parse_keys, types::Key};
use paccel::engine::{BuiltinPacketParser, FlowKey, ParseConfig, StopLayer};

const PCAP_CANDIDATES: &[&str] = &[
    "testdata/dns_test.pcap",
    "testdata/SSRF_1.pcap",
    "data/vpn_icq_chat1a.pcap",
    "data/vpn_icq_chat1b.pcap",
    "testdata/2019-11043_1.pcap",
];

#[derive(Default)]
struct Tally {
    total_packets: usize,
    matched: usize,
    known_divergent: usize,
    both_failed: usize,
    only_pnet_ok: usize,
    only_paccel_ok: usize,
    // Breaks down only_pnet_ok by pnet's protocol number, so a large bucket
    // can be visually confirmed as e.g. all-ARP (expected: paccel's
    // flow_key() is None for non-IP layers) rather than hiding TCP/UDP
    // packets paccel failed to parse at all (which would be a real gap).
    only_pnet_ok_by_protocol: BTreeMap<u8, usize>,
    mismatched: Vec<String>,
}

fn is_known_divergent(protocol: u8) -> bool {
    matches!(protocol, 1 | 2 | 4 | 47 | 50 | 51 | 58)
}

fn tuples_match(key: &Key, flow_key: &FlowKey) -> bool {
    key.src_ip == flow_key.src_ip
        && key.dst_ip == flow_key.dst_ip
        && key.src_port == flow_key.src_port
        && key.dst_port == flow_key.dst_port
        && key.protocol == flow_key.protocol
}

fn record_both_keys(
    tally: &mut Tally,
    key: &Key,
    flow_key: &FlowKey,
    file_name: &str,
    packet_index: usize,
) {
    // Fluere assigns protocol-specific pseudo-ports for these protocols (for
    // example, GRE's inner ethertype and ICMPv6 type/code). Paccel instead uses
    // real 0/0 ports or, for decoded tunnels, the innermost real flow. Those
    // semantics are intentionally different and are not parser bugs.
    if key.protocol != flow_key.protocol || is_known_divergent(key.protocol) {
        tally.known_divergent += 1;
    } else if tuples_match(key, flow_key) {
        tally.matched += 1;
    } else {
        tally.mismatched.push(format!(
            "{file_name} packet {packet_index}: pnet=({:?}, {:?}, {}, {}, {}) paccel=({:?}, {:?}, {}, {}, {})",
            key.src_ip,
            key.dst_ip,
            key.src_port,
            key.dst_port,
            key.protocol,
            flow_key.src_ip,
            flow_key.dst_ip,
            flow_key.src_port,
            flow_key.dst_port,
            flow_key.protocol,
        ));
    }
}

fn record_packet(
    tally: &mut Tally,
    pnet_key: Option<Key>,
    paccel_key: Option<FlowKey>,
    file_name: &str,
    packet_index: usize,
) {
    tally.total_packets += 1;
    match (pnet_key, paccel_key) {
        (None, None) => tally.both_failed += 1,
        (Some(key), None) => {
            tally.only_pnet_ok += 1;
            *tally
                .only_pnet_ok_by_protocol
                .entry(key.protocol)
                .or_insert(0) += 1;
        }
        (None, Some(_)) => tally.only_paccel_ok += 1,
        (Some(key), Some(flow_key)) => {
            record_both_keys(tally, &key, &flow_key, file_name, packet_index);
        }
    }
}

fn compare_capture(path: &str, tally: &mut Tally) -> Result<(), String> {
    let mut capture = pcap::Capture::from_file(path)
        .map_err(|error| format!("failed to open confirmed corpus file {path}: {error}"))?;
    let config = ParseConfig {
        stop_after: StopLayer::Transport,
        ..Default::default()
    };
    let mut packet_index = 0;

    while let Ok(packet) = capture.next_packet() {
        packet_index += 1;
        let pnet_key = parse_keys(packet.clone()).ok().map(|(key, _)| key);
        let paccel_key = BuiltinPacketParser::parse_with_config(packet.data, config)
            .ok()
            .and_then(|parsed| parsed.flow_key());
        record_packet(tally, pnet_key, paccel_key, path, packet_index);
    }

    Ok(())
}

#[test]
fn production_pnet_and_paccel_agree_on_plain_flow_tuples() -> Result<(), String> {
    let available: Vec<&str> = PCAP_CANDIDATES
        .iter()
        .copied()
        .filter(|path| Path::new(path).exists())
        .collect();

    if available.is_empty() {
        eprintln!(
            "skipping differential parser test: the pcap corpus is local-only and no candidate files exist"
        );
        return Ok(());
    }

    let mut tally = Tally::default();
    for path in &available {
        compare_capture(path, &mut tally)?;
    }

    let skipped: Vec<&str> = PCAP_CANDIDATES
        .iter()
        .copied()
        .filter(|path| !Path::new(path).exists())
        .collect();
    eprintln!("differential parser corpus used: {}", available.join(", "));
    eprintln!(
        "differential parser corpus skipped (missing): {}",
        skipped.join(", ")
    );
    eprintln!(
        "differential parser tally: total_packets={}, matched={}, known_divergent={}, both_failed={}, only_pnet_ok={}, only_paccel_ok={}, mismatched={}",
        tally.total_packets,
        tally.matched,
        tally.known_divergent,
        tally.both_failed,
        tally.only_pnet_ok,
        tally.only_paccel_ok,
        tally.mismatched.len(),
    );
    eprintln!(
        "only_pnet_ok by pnet protocol number: {:?}",
        tally.only_pnet_ok_by_protocol
    );

    let mismatch_sample = tally
        .mismatched
        .iter()
        .take(10)
        .cloned()
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        tally.mismatched.is_empty(),
        "plain TCP/UDP flow tuple mismatches (first 10):\n{mismatch_sample}"
    );
    assert!(
        tally.matched > 0,
        "expected at least some agreeing plain TCP/UDP flows"
    );

    // TCP (6) and UDP (17) appearing here would mean paccel failed to parse
    // a packet pnet successfully extracted TCP/UDP ports from — a real gap,
    // not the expected ARP/no-IP-layer divergence.
    let unexpected_tcp_udp_only_pnet: usize = [6u8, 17u8]
        .iter()
        .filter_map(|proto| tally.only_pnet_ok_by_protocol.get(proto))
        .sum();
    assert_eq!(
        unexpected_tcp_udp_only_pnet, 0,
        "found TCP/UDP packets pnet parsed but paccel failed entirely on: {:?}",
        tally.only_pnet_ok_by_protocol
    );

    Ok(())
}
