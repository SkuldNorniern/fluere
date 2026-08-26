use std::collections::{BTreeMap, HashMap};

use crate::net::flows::update_flow;
use crate::net::types::{Key, TcpFlags};
use crate::types::UDFlowKey;
use fluereflow::FluereRecord;

pub struct FlowEngine {
    active: HashMap<Key, FluereRecord>,
    expirations: BTreeMap<u64, Vec<Key>>,
    current_expirations: HashMap<Key, u64>,
    flow_timeout: u64,
}

impl FlowEngine {
    pub fn new(flow_timeout: u64) -> Self {
        Self {
            active: HashMap::new(),
            expirations: BTreeMap::new(),
            current_expirations: HashMap::new(),
            flow_timeout,
        }
    }

    pub fn offer(
        &mut self,
        key: Key,
        reverse: Key,
        mut record: FluereRecord,
        doctets: usize,
        flags: TcpFlags,
        packet_time: u64,
    ) -> Option<FluereRecord> {
        let is_reverse = match self.active.get(&key) {
            Some(_) => false,
            None => match self.active.get(&reverse) {
                Some(_) => true,
                None => {
                    record.mid_stream = record.prot == 6 && flags.syn == 0;

                    let expiration = self.expiration_for(packet_time);
                    self.active.insert(key, record);
                    self.push_expiration(key, expiration);
                    false
                }
            },
        };

        let flow_key = if is_reverse { reverse } else { key };
        if let Some(flow) = self.active.get_mut(&flow_key) {
            update_flow(
                flow,
                is_reverse,
                UDFlowKey {
                    doctets,
                    pkt: record.min_pkt,
                    ttl: record.min_ttl,
                    flags,
                    time: packet_time,
                },
            );
        } else {
            return None;
        }

        let expiration = self.expiration_for(packet_time);
        self.push_expiration(flow_key, expiration);

        if flags.is_finished() {
            self.current_expirations.remove(&flow_key);
            self.active.remove(&flow_key)
        } else {
            None
        }
    }

    pub fn sweep_expired(&mut self, current_time: u64) -> Vec<FluereRecord> {
        let expired_times: Vec<u64> = self
            .expirations
            .range(..=current_time)
            .map(|(&expiration, _)| expiration)
            .collect();
        let mut expired = Vec::new();

        for expiration in expired_times {
            if let Some(keys) = self.expirations.remove(&expiration) {
                for key in keys {
                    if self.current_expirations.get(&key) != Some(&expiration) {
                        continue;
                    }

                    self.current_expirations.remove(&key);
                    if let Some(flow) = self.active.remove(&key) {
                        expired.push(flow);
                    }
                }
            }
        }

        expired
    }

    pub fn drain(&mut self) -> Vec<FluereRecord> {
        self.expirations.clear();
        self.current_expirations.clear();
        self.active.drain().map(|(_, flow)| flow).collect()
    }

    pub fn active(&self) -> &HashMap<Key, FluereRecord> {
        &self.active
    }

    pub fn active_count(&self) -> usize {
        self.active.len()
    }

    fn expiration_for(&self, packet_time: u64) -> u64 {
        packet_time + (self.flow_timeout * 1_000)
    }

    fn push_expiration(&mut self, key: Key, expiration: u64) {
        self.expirations.entry(expiration).or_default().push(key);
        self.current_expirations.insert(key, expiration);
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use pcap::{Packet, PacketHeader};

    use super::*;
    use crate::net::parser::{parse_fluereflow, parse_keys};
    use crate::net::types::MacAddress;

    fn keys(protocol: u8) -> (Key, Key) {
        let key = Key {
            src_ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            src_port: 12_345,
            dst_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)),
            dst_port: 443,
            protocol,
            src_mac: MacAddress::new([0; 6]),
            dst_mac: MacAddress::new([1; 6]),
        };
        let reverse = Key {
            src_ip: key.dst_ip,
            src_port: key.dst_port,
            dst_ip: key.src_ip,
            dst_port: key.src_port,
            protocol,
            src_mac: key.dst_mac,
            dst_mac: key.src_mac,
        };
        (key, reverse)
    }

    fn record(protocol: u8, time: u64) -> FluereRecord {
        FluereRecord::new(
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)),
            0,
            0,
            time,
            time,
            12_345,
            443,
            60,
            60,
            64,
            64,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            protocol,
            0,
            false,
        )
    }

    fn flags(syn: u8, fin: u8, rst: u8) -> TcpFlags {
        TcpFlags::new([fin, syn, rst, 0, 0, 0, 0, 0, 0])
    }

    #[test]
    fn opens_new_tcp_flow_without_syn_and_flags_mid_stream() {
        let (key, reverse) = keys(6);
        let mut engine = FlowEngine::new(10);

        assert!(
            engine
                .offer(key, reverse, record(6, 1), 60, flags(0, 0, 0), 1)
                .is_none()
        );
        assert_eq!(engine.active_count(), 1);
        assert!(engine.active().get(&key).unwrap().mid_stream);
    }

    #[test]
    fn new_tcp_flow_with_syn_is_not_mid_stream() {
        let (key, reverse) = keys(6);
        let mut engine = FlowEngine::new(10);

        engine.offer(key, reverse, record(6, 1), 60, flags(1, 0, 0), 1);
        assert!(!engine.active().get(&key).unwrap().mid_stream);
    }

    #[test]
    fn stale_expiration_does_not_evict_touched_flow() {
        let (key, reverse) = keys(17);
        let mut engine = FlowEngine::new(10);

        engine.offer(key, reverse, record(17, 1_000), 60, flags(0, 0, 0), 1_000);
        engine.offer(reverse, key, record(17, 5_000), 70, flags(0, 0, 0), 5_000);

        assert!(engine.sweep_expired(11_000).is_empty());
        assert_eq!(engine.active().get(&key).unwrap().in_pkts, 1);

        let expired = engine.sweep_expired(15_000);
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].d_pkts, 2);
        assert_eq!(engine.active_count(), 0);
    }

    #[test]
    fn finished_flow_is_returned_and_removed() {
        let (key, reverse) = keys(6);
        let mut engine = FlowEngine::new(10);

        engine.offer(key, reverse, record(6, 1), 60, flags(1, 0, 0), 1);
        let finished = engine
            .offer(reverse, key, record(6, 2), 70, flags(0, 1, 0), 2)
            .unwrap();

        assert_eq!(finished.d_pkts, 2);
        assert_eq!(finished.in_pkts, 1);
        assert_eq!(finished.fin_cnt, 1);
        assert_eq!(engine.active_count(), 0);
        assert!(engine.sweep_expired(20_000).is_empty());
    }

    /// Build an Ethernet + IPv4 + TCP frame for one direction of a flow.
    /// The reverse direction swaps MAC addresses, IP addresses and ports so it
    /// hashes to the reverse `Key` rather than opening a second flow.
    fn tcp_frame(forward: bool, tcp_flags: u8) -> Vec<u8> {
        let (src_mac, dst_mac) = ([0xaau8; 6], [0xbbu8; 6]);
        let (src_ip, dst_ip) = ([192u8, 0, 2, 1], [198u8, 51, 100, 2]);
        let (src_port, dst_port) = (12_345u16, 443u16);

        let (src_mac, dst_mac) = if forward {
            (src_mac, dst_mac)
        } else {
            (dst_mac, src_mac)
        };
        let (src_ip, dst_ip) = if forward {
            (src_ip, dst_ip)
        } else {
            (dst_ip, src_ip)
        };
        let (src_port, dst_port) = if forward {
            (src_port, dst_port)
        } else {
            (dst_port, src_port)
        };

        let mut frame = Vec::with_capacity(54);
        frame.extend_from_slice(&dst_mac);
        frame.extend_from_slice(&src_mac);
        frame.extend_from_slice(&0x0800u16.to_be_bytes());

        frame.extend_from_slice(&[0x45, 0x00]);
        frame.extend_from_slice(&40u16.to_be_bytes());
        frame.extend_from_slice(&[0, 1, 0, 0, 64, 6, 0, 0]);
        frame.extend_from_slice(&src_ip);
        frame.extend_from_slice(&dst_ip);

        frame.extend_from_slice(&src_port.to_be_bytes());
        frame.extend_from_slice(&dst_port.to_be_bytes());
        frame.extend_from_slice(&[0; 8]);
        frame.extend_from_slice(&[0x50, tcp_flags, 0x20, 0x00, 0, 0, 0, 0]);
        frame
    }

    /// Feed one captured frame through the real parser into the engine, the
    /// way the capture loops do.
    fn offer_frame(engine: &mut FlowEngine, frame: &[u8], time: u64) -> Option<FluereRecord> {
        let header = PacketHeader {
            ts: libc::timeval {
                tv_sec: 0,
                tv_usec: time as i64,
            },
            caplen: frame.len() as u32,
            len: frame.len() as u32,
        };
        let (key, reverse) = parse_keys(Packet::new(&header, frame), 1).expect("parsable frame");
        let (doctets, raw_flags, record) =
            parse_fluereflow(Packet::new(&header, frame), 1).expect("parsable frame");
        engine.offer(
            key,
            reverse,
            record,
            doctets,
            TcpFlags::new(raw_flags),
            time,
        )
    }

    fn assert_counter_invariants(flow: &FluereRecord) {
        assert_eq!(
            flow.in_pkts + flow.out_pkts,
            flow.d_pkts,
            "directional packet counts must sum to the total"
        );
        assert_eq!(
            flow.in_bytes + flow.out_bytes,
            flow.d_octets,
            "directional byte counts must sum to the total"
        );
        if flow.in_pkts == 0 {
            assert_eq!(
                flow.in_bytes, 0,
                "no reverse packets means no reverse bytes"
            );
        }
        if flow.out_pkts == 0 {
            assert_eq!(
                flow.out_bytes, 0,
                "no forward packets means no forward bytes"
            );
        }
    }

    #[test]
    fn first_packet_is_counted_exactly_once() {
        let frame = tcp_frame(true, 0x02);
        let mut engine = FlowEngine::new(10);

        offer_frame(&mut engine, &frame, 1);
        let flow = *engine.active().values().next().expect("one active flow");

        assert_eq!(flow.d_pkts, 1);
        assert_eq!(flow.d_octets, frame.len());
        assert_eq!((flow.out_pkts, flow.out_bytes), (1, frame.len()));
        assert_eq!((flow.in_pkts, flow.in_bytes), (0, 0));
        assert_counter_invariants(&flow);
    }

    #[test]
    fn bidirectional_totals_match_the_captured_bytes() {
        let forward = tcp_frame(true, 0x02);
        let backward = tcp_frame(false, 0x12);
        let mut engine = FlowEngine::new(10);

        offer_frame(&mut engine, &forward, 1);
        offer_frame(&mut engine, &forward, 2);
        offer_frame(&mut engine, &backward, 3);

        let flow = *engine.active().values().next().expect("one active flow");

        assert_eq!(flow.d_pkts, 3);
        assert_eq!(flow.d_octets, forward.len() * 2 + backward.len());
        assert_eq!((flow.out_pkts, flow.out_bytes), (2, forward.len() * 2));
        assert_eq!((flow.in_pkts, flow.in_bytes), (1, backward.len()));
        assert_counter_invariants(&flow);
    }

    #[test]
    fn drain_returns_and_clears_active_flows() {
        let (key, reverse) = keys(17);
        let mut engine = FlowEngine::new(10);
        engine.offer(key, reverse, record(17, 1), 60, flags(0, 0, 0), 1);

        assert_eq!(engine.drain().len(), 1);
        assert_eq!(engine.active_count(), 0);
        assert!(engine.sweep_expired(20_000).is_empty());
    }
}
