use std::collections::{BTreeMap, HashMap};

use log::trace;

use crate::net::flows::update_flow;
use crate::net::parser::PacketObservation;
use crate::net::types::{Key, TcpFlags};
use crate::types::UDFlowKey;
use fluereflow::FluereRecord;

/// Why a flow stopped being tracked.
///
/// Not carried on `FluereRecord` yet: that needs a schema change, and the flat
/// record is being replaced. The engine reports it so the reason a flow ended
/// is at least observable today.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowEndReason {
    /// Both directions sent a FIN, so the connection closed normally.
    Fin,
    /// One side reset the connection.
    Rst,
    /// Nothing arrived for the flow within the idle timeout.
    IdleTimeout,
    /// Capture stopped while the flow was still open.
    CaptureEnd,
}

/// Per-flow state the engine keeps but the record does not carry.
#[derive(Debug, Clone, Copy)]
struct FlowState {
    record: FluereRecord,
    /// FIN seen travelling in the direction the flow was opened in.
    forward_fin: bool,
    /// FIN seen travelling the other way.
    reverse_fin: bool,
}

impl FlowState {
    fn new(record: FluereRecord) -> Self {
        FlowState {
            record,
            forward_fin: false,
            reverse_fin: false,
        }
    }

    /// A TCP connection is done once both halves have closed. Anything that is
    /// not TCP never closes this way and leaves on a timeout instead.
    fn both_halves_closed(&self) -> bool {
        self.forward_fin && self.reverse_fin
    }
}

/// What one packet did to the engine.
#[derive(Debug, Default)]
pub struct AcceptOutcome {
    /// Flows finished by this packet: a TCP termination, plus any flow that
    /// idled out at this packet's timestamp.
    pub completed: Vec<FluereRecord>,
    /// Whether this packet opened a flow that was not active before.
    pub opened_flow: bool,
}

pub struct FlowEngine {
    active: HashMap<Key, FlowState>,
    expirations: BTreeMap<u64, Vec<Key>>,
    current_expirations: HashMap<Key, u64>,
    /// Idle timeout in milliseconds, or `None` when the caller asked for no
    /// timeout at all. Flows in a no-timeout engine leave only through TCP
    /// termination or `drain`.
    flow_timeout: Option<u64>,
}

impl FlowEngine {
    /// `flow_timeout` is an idle timeout in milliseconds; zero means flows
    /// never expire on their own, matching what the CLI documents.
    pub fn new(flow_timeout: u64) -> Self {
        Self {
            active: HashMap::new(),
            expirations: BTreeMap::new(),
            current_expirations: HashMap::new(),
            flow_timeout: (flow_timeout > 0).then_some(flow_timeout),
        }
    }

    /// Feed one packet in directly. `accept` is what the capture modes use;
    /// this stays for tests that drive the engine a packet at a time.
    #[cfg(test)]
    pub fn offer(
        &mut self,
        key: Key,
        reverse: Key,
        record: FluereRecord,
        doctets: usize,
        flags: TcpFlags,
        packet_time: u64,
    ) -> Option<FluereRecord> {
        self.offer_with_reason(key, reverse, record, doctets, flags, packet_time)
            .map(|(flow, _)| flow)
    }

    /// As [`offer`](Self::offer), but also reporting why the flow ended.
    fn offer_with_reason(
        &mut self,
        key: Key,
        reverse: Key,
        mut record: FluereRecord,
        doctets: usize,
        flags: TcpFlags,
        packet_time: u64,
    ) -> Option<(FluereRecord, FlowEndReason)> {
        let is_reverse = match self.active.get(&key) {
            Some(_) => false,
            None => match self.active.get(&reverse) {
                Some(_) => true,
                None => {
                    // No SYN on the first packet means the capture started
                    // partway through an existing connection.
                    record.mid_stream = record.prot == 6 && flags.syn == 0;
                    self.active.insert(key, FlowState::new(record));
                    self.schedule_expiration(key, packet_time);
                    false
                }
            },
        };

        let flow_key = if is_reverse { reverse } else { key };
        let state = self.active.get_mut(&flow_key)?;

        update_flow(
            &mut state.record,
            is_reverse,
            UDFlowKey {
                doctets,
                pkt: record.min_pkt,
                ttl: record.min_ttl,
                flags,
                time: packet_time,
            },
        );

        // A half-close only ends this direction. The flow stays open until the
        // other side closes too, so data still flowing the other way keeps
        // belonging to the same connection.
        if flags.fin == 1 {
            if is_reverse {
                state.reverse_fin = true;
            } else {
                state.forward_fin = true;
            }
        }

        let reason = if flags.rst == 1 {
            Some(FlowEndReason::Rst)
        } else if state.both_halves_closed() {
            Some(FlowEndReason::Fin)
        } else {
            None
        };

        self.schedule_expiration(flow_key, packet_time);

        let reason = reason?;
        self.current_expirations.remove(&flow_key);
        self.active
            .remove(&flow_key)
            .map(|state| (state.record, reason))
    }

    /// Feed one observed packet into the engine.
    ///
    /// Every capture mode goes through this, so they all agree on the order of
    /// events for a packet: the flow is updated first, then anything that has
    /// idled out is swept, and both sets of finished flows come back together.
    pub fn accept(&mut self, observation: PacketObservation) -> AcceptOutcome {
        let was_active = self.active.contains_key(&observation.key)
            || self.active.contains_key(&observation.reverse_key);

        let finished = self.offer_with_reason(
            observation.key,
            observation.reverse_key,
            observation.record,
            observation.doctets,
            observation.flags,
            observation.packet_time,
        );
        let expired = self.sweep_expired(observation.packet_time);
        let opened_flow = !was_active && self.active.contains_key(&observation.key);

        let mut completed = Vec::with_capacity(expired.len() + usize::from(finished.is_some()));
        if let Some((flow, reason)) = finished {
            trace!("flow ended: {:?}", reason);
            completed.push(flow);
        }
        completed.extend(expired);

        AcceptOutcome {
            completed,
            opened_flow,
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
                    if let Some(state) = self.active.remove(&key) {
                        trace!("flow ended: {:?}", FlowEndReason::IdleTimeout);
                        expired.push(state.record);
                    }
                }
            }
        }

        expired
    }

    pub fn drain(&mut self) -> Vec<FluereRecord> {
        self.expirations.clear();
        self.current_expirations.clear();
        self.active
            .drain()
            .map(|(_, state)| {
                trace!("flow ended: {:?}", FlowEndReason::CaptureEnd);
                state.record
            })
            .collect()
    }

    /// The flows currently held open. Only the tests inspect this directly;
    /// callers go through `accept`.
    #[cfg(test)]
    pub fn active(&self) -> HashMap<Key, FluereRecord> {
        self.active
            .iter()
            .map(|(key, state)| (*key, state.record))
            .collect()
    }

    pub fn active_count(&self) -> usize {
        self.active.len()
    }

    /// Queue `key` to expire one idle timeout after `packet_time`. Does
    /// nothing when the engine was built without a timeout.
    fn schedule_expiration(&mut self, key: Key, packet_time: u64) {
        let Some(timeout) = self.flow_timeout else {
            return;
        };
        let expiration = packet_time + timeout * 1_000;
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
    fn a_flow_ends_once_both_directions_have_sent_a_fin() {
        let (key, reverse) = keys(6);
        let mut engine = FlowEngine::new(10);

        engine.offer(key, reverse, record(6, 1), 60, flags(1, 0, 0), 1);

        // One FIN closes only that half of the connection.
        assert!(
            engine
                .offer(key, reverse, record(6, 2), 60, flags(0, 1, 0), 2)
                .is_none(),
            "a half-close must not end the flow"
        );
        assert_eq!(engine.active_count(), 1);

        // Data still flowing the other way belongs to the same flow.
        assert!(
            engine
                .offer(reverse, key, record(6, 3), 70, flags(0, 0, 0), 3)
                .is_none()
        );

        let finished = engine
            .offer(reverse, key, record(6, 4), 70, flags(0, 1, 0), 4)
            .expect("the second FIN ends the flow");

        assert_eq!(finished.d_pkts, 4, "every packet stayed in one flow");
        assert_eq!(finished.fin_cnt, 2);
        assert!(!finished.mid_stream);
        assert_eq!(engine.active_count(), 0);
        assert!(engine.sweep_expired(20_000).is_empty());
    }

    #[test]
    fn a_reset_ends_the_flow_immediately() {
        let (key, reverse) = keys(6);
        let mut engine = FlowEngine::new(10);

        engine.offer(key, reverse, record(6, 1), 60, flags(1, 0, 0), 1);
        let finished = engine
            .offer(reverse, key, record(6, 2), 70, flags(0, 0, 1), 2)
            .expect("a RST needs no second half");

        assert_eq!(finished.rst_cnt, 1);
        assert_eq!(engine.active_count(), 0);
    }

    #[test]
    fn a_half_closed_flow_still_leaves_on_the_idle_timeout() {
        let (key, reverse) = keys(6);
        let mut engine = FlowEngine::new(10);

        engine.offer(key, reverse, record(6, 1_000), 60, flags(1, 0, 0), 1_000);
        engine.offer(key, reverse, record(6, 2_000), 60, flags(0, 1, 0), 2_000);
        assert_eq!(engine.active_count(), 1, "still waiting on the other FIN");

        let expired = engine.sweep_expired(30_000);
        assert_eq!(expired.len(), 1, "the idle timeout still applies");
        assert_eq!(engine.active_count(), 0);
    }

    #[test]
    fn a_udp_flow_is_unaffected_by_tcp_close_handling() {
        let (key, reverse) = keys(17);
        let mut engine = FlowEngine::new(10);

        engine.offer(key, reverse, record(17, 1), 60, flags(0, 0, 0), 1);
        engine.offer(reverse, key, record(17, 2), 60, flags(0, 0, 0), 2);

        assert_eq!(engine.active_count(), 1);
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

    /// An Ethernet + IPv4 + UDP frame, for a flow distinct from `tcp_frame`.
    fn udp_frame() -> Vec<u8> {
        let mut frame = vec![0xaa; 6];
        frame.extend_from_slice(&[0xbb; 6]);
        frame.extend_from_slice(&0x0800u16.to_be_bytes());

        frame.extend_from_slice(&[0x45, 0x00]);
        frame.extend_from_slice(&28u16.to_be_bytes());
        frame.extend_from_slice(&[0, 1, 0, 0, 64, 17, 0, 0]);
        frame.extend_from_slice(&[203, 0, 113, 5]);
        frame.extend_from_slice(&[203, 0, 113, 6]);

        frame.extend_from_slice(&53u16.to_be_bytes());
        frame.extend_from_slice(&5353u16.to_be_bytes());
        frame.extend_from_slice(&8u16.to_be_bytes());
        frame.extend_from_slice(&[0, 0]);
        frame
    }

    /// Decode a frame the way the capture loops do.
    fn observe_frame(frame: &[u8], time: u64) -> PacketObservation {
        let header = PacketHeader {
            ts: libc::timeval {
                tv_sec: 0,
                tv_usec: time as i64,
            },
            caplen: frame.len() as u32,
            len: frame.len() as u32,
        };
        crate::net::parser::observe(Packet::new(&header, frame), false, 1).expect("parsable frame")
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
    fn accept_reports_a_newly_opened_flow_once() {
        let frame = tcp_frame(true, 0x02);
        let mut engine = FlowEngine::new(10);

        let first = engine.accept(observe_frame(&frame, 1));
        assert!(first.opened_flow, "the first packet opens the flow");
        assert!(first.completed.is_empty());

        let second = engine.accept(observe_frame(&frame, 2));
        assert!(!second.opened_flow, "a second packet joins the same flow");

        let reverse = engine.accept(observe_frame(&tcp_frame(false, 0x12), 3));
        assert!(
            !reverse.opened_flow,
            "the reverse direction is the same flow, not a new one"
        );
    }

    #[test]
    fn accept_returns_terminated_and_expired_flows_together() {
        let mut engine = FlowEngine::new(10);

        // A UDP flow that will idle out, and a TCP flow that closes properly.
        engine.accept(observe_frame(&udp_frame(), 1_000));
        engine.accept(observe_frame(&tcp_frame(true, 0x02), 2_000));
        let outcome = engine.accept(observe_frame(&tcp_frame(true, 0x01), 3_000));
        assert!(
            outcome.completed.is_empty(),
            "only one half of the TCP connection has closed"
        );

        // Far enough ahead that the UDP flow has idled out, and carrying the
        // FIN that closes the other half of the TCP connection.
        let outcome = engine.accept(observe_frame(&tcp_frame(false, 0x11), 30_000));
        assert_eq!(
            outcome.completed.len(),
            2,
            "the closed connection and the idled-out flow both come back"
        );
        assert_eq!(engine.active_count(), 0);
    }

    #[test]
    fn zero_timeout_means_flows_never_expire() {
        let (key, reverse) = keys(17);
        let mut engine = FlowEngine::new(0);

        engine.offer(key, reverse, record(17, 1), 60, flags(0, 0, 0), 1);

        assert!(engine.sweep_expired(1).is_empty());
        assert!(engine.sweep_expired(u64::MAX).is_empty());
        assert_eq!(engine.active_count(), 1);
        assert_eq!(engine.drain().len(), 1);
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
