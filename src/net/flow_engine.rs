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
        record: FluereRecord,
        doctets: usize,
        flags: TcpFlags,
        packet_time: u64,
    ) -> Option<FluereRecord> {
        let is_reverse = match self.active.get(&key) {
            Some(_) => false,
            None => match self.active.get(&reverse) {
                Some(_) => true,
                None => {
                    if record.prot == 6 && flags.syn == 0 {
                        return None;
                    }

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

    use super::*;
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
        )
    }

    fn flags(syn: u8, fin: u8, rst: u8) -> TcpFlags {
        TcpFlags::new([fin, syn, rst, 0, 0, 0, 0, 0, 0])
    }

    #[test]
    fn drops_new_tcp_flow_without_syn() {
        let (key, reverse) = keys(6);
        let mut engine = FlowEngine::new(10);

        assert!(
            engine
                .offer(key, reverse, record(6, 1), 60, flags(0, 0, 0), 1)
                .is_none()
        );
        assert_eq!(engine.active_count(), 0);
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
