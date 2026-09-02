use std::collections::BTreeMap;
#[cfg(test)]
use std::collections::HashMap;

use ahash::AHashMap;

use log::trace;

/// Widest expiry bucket, in nanoseconds. Coarse on purpose: flows falling due
/// within the same second share one queue entry instead of each taking their
/// own. A flow can idle out up to one bucket late, which is immaterial against
/// a timeout measured in minutes. Short timeouts narrow the bucket to match, so
/// the delay is never a large fraction of the timeout itself.
const MAX_BUCKET: u64 = 1_000_000_000;

/// How late a packet may arrive and still be counted on its own flow, in
/// nanoseconds.
///
/// The engine's clock is the latest packet time it has seen, and expiry runs
/// against that time less this allowance. Merged captures and multi-queue
/// interfaces deliver out of order by milliseconds, which this covers.
///
/// The allowance is never more than half the idle timeout, because holding
/// expiry back further than the timeout would mean the timeout no longer says
/// when a flow ends. Skew larger than that can still expire a flow whose next
/// packet has not been delivered yet, and that packet then opens a second flow.
/// Sort a capture by timestamp if it is that badly ordered.
const MAX_LATENESS: u64 = 1_000_000_000;

use crate::net::parser::PacketObservation;
use crate::net::types::Key;
use fluereflow::{Direction, EndReason, Flow, FlowRecord, StartState, TimeResolution};

/// Per-flow state the engine keeps but the record does not carry.
#[derive(Debug, Clone, Copy)]
struct FlowState {
    record: FlowRecord,
    /// FIN seen travelling in the direction the flow was opened in.
    forward_fin: bool,
    /// FIN seen travelling the other way.
    reverse_fin: bool,
    /// The deadline this flow currently has an entry queued for. A queued
    /// entry that disagrees with this is a leftover from an earlier round and
    /// is dropped when the sweep reaches it, so a flow never has more than one
    /// live entry.
    scheduled: u64,
}

impl FlowState {
    fn new(record: FlowRecord, scheduled: u64) -> Self {
        FlowState {
            record,
            forward_fin: false,
            reverse_fin: false,
            scheduled,
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
    pub completed: Vec<Flow>,
    /// Whether this packet opened a flow that was not active before.
    pub opened_flow: bool,
}

/// Whether `endpoint` is one of the two the key already names.
fn names_endpoint(key: &Key, endpoint: (std::net::IpAddr, u16)) -> bool {
    let (source_port, destination_port) = key.ports();

    endpoint == (key.source, source_port) || endpoint == (key.destination, destination_port)
}

/// Open a flow for the first packet seen on it.
///
/// A TCP flow whose first packet has no SYN began before the capture did; other
/// protocols have no handshake to have missed.
fn open_record(observation: &PacketObservation) -> FlowRecord {
    let start_state = if observation.key.protocol == 6 {
        match observation.tcp_flags {
            Some(flags) if flags.syn => StartState::SynObserved,
            _ => StartState::MidStream,
        }
    } else {
        StartState::NotApplicable
    };

    let mut record = FlowRecord::open(
        observation.time(),
        TimeResolution::Microseconds,
        start_state,
    );
    record.network.dscp = observation.dscp;
    record.network.ecn = observation.ecn;
    record
}

pub struct FlowEngine {
    /// Flows currently open.
    ///
    /// Hashed with aHash rather than the standard library's SipHash. A `Key`
    /// is 112 bytes and every packet hashes one, so this is squarely on the hot
    /// path. aHash keeps the seeded, collision-resistant behaviour that matters
    /// when the keys are addresses and ports an attacker chooses.
    active: AHashMap<Key, FlowState>,
    /// Flows due to be checked, bucketed by second. A flow is queued once when
    /// it opens and then only ever re-queued by a sweep, so packets do no
    /// expiration bookkeeping at all and this holds at most one live entry per
    /// active flow.
    due: BTreeMap<u64, Vec<Key>>,
    /// Idle timeout in microseconds, or `None` when the caller asked for no
    /// timeout at all. Flows in a no-timeout engine leave only through TCP
    /// termination or `drain`.
    timeout: Option<u64>,
    /// Width of one bucket in `due`, in microseconds.
    bucket: u64,
    /// The latest packet time seen, which is the engine's clock. Taking the
    /// current packet's time instead would let the clock run backwards.
    watermark: u64,
    /// How late a packet may be delivered and still be counted on its own
    /// flow, in nanoseconds. Expiry is held back by this much.
    lateness: u64,
}

impl FlowEngine {
    /// `flow_timeout` is an idle timeout in milliseconds; zero means flows
    /// never expire on their own, matching what the CLI documents.
    pub fn new(flow_timeout: u64) -> Self {
        // Milliseconds in, nanoseconds inside: the record's timestamps are
        // nanoseconds, so the deadline arithmetic is too.
        let timeout = (flow_timeout > 0).then_some(flow_timeout * 1_000_000);

        Self {
            active: AHashMap::new(),
            due: BTreeMap::new(),
            timeout,
            // Never coarser than the timeout, so the rounding delay stays a
            // small fraction of it however short the timeout is.
            bucket: timeout.unwrap_or(MAX_BUCKET).clamp(1, MAX_BUCKET),
            watermark: 0,
            // A second of skew covers merged captures and multi-queue
            // delivery. Never more than half the timeout, so a short timeout
            // still expires flows roughly when it says it will.
            lateness: timeout.map_or(0, |timeout| MAX_LATENESS.min(timeout / 2)),
        }
    }

    /// Fold one observed packet into its flow, reporting the flow if it ended.
    fn offer_with_reason(
        &mut self,
        observation: PacketObservation,
        opened: &mut bool,
    ) -> Option<(Flow, EndReason)> {
        let key = observation.key;
        let reverse = observation.reverse_key();
        let flags = observation.tcp_flags.unwrap_or_default();
        let at = observation.time().nanos();

        let is_reverse = match self.active.get(&key) {
            Some(_) => false,
            None => match self.active.get(&reverse) {
                Some(_) => true,
                None => {
                    let deadline = self.deadline_from(at);
                    self.active
                        .insert(key, FlowState::new(open_record(&observation), deadline));
                    self.enqueue(key, deadline);
                    *opened = true;
                    false
                }
            },
        };

        let flow_key = if is_reverse { reverse } else { key };
        let state = self.active.get_mut(&flow_key)?;

        let direction = if is_reverse {
            Direction::Reverse
        } else {
            Direction::Forward
        };
        state.record.observe(direction, observation.facts);
        // Only somewhere the key does not already name: ordinary traffic in
        // either direction arrives from one of the flow's own two endpoints.
        if !names_endpoint(&flow_key, observation.arrived_from) {
            state
                .record
                .paths
                .observe(direction, observation.arrived_from);
        }

        // A half-close only ends this direction. The flow stays open until the
        // other side closes too, so data still flowing the other way keeps
        // belonging to the same connection.
        if flags.fin {
            if is_reverse {
                state.reverse_fin = true;
            } else {
                state.forward_fin = true;
            }
        }

        let reason = if flags.rst {
            Some(EndReason::Rst)
        } else if state.both_halves_closed() {
            Some(EndReason::Fin)
        } else {
            None
        };

        // Nothing else to update: the record's own end time is the authoritative
        // deadline, and the sweep reads it directly, so a packet costs no
        // expiry bookkeeping.
        let reason = reason?;
        self.active.remove(&flow_key).map(|mut state| {
            state.record.close(reason);
            (Flow::new(flow_key, state.record), reason)
        })
    }

    /// Feed one observed packet into the engine.
    ///
    /// Every capture mode goes through this, so they all agree on the order of
    /// events for a packet: the flow is updated first, then anything that has
    /// idled out is swept, and both sets of finished flows come back together.
    pub fn accept(&mut self, observation: PacketObservation) -> AcceptOutcome {
        // Expire first. A flow that went idle past its timeout is finished
        // before this packet is looked at, so traffic resuming on the same
        // tuple opens a new flow instead of reviving the old one and reporting
        // a single flow spanning the silence.
        let expired = self.sweep_expired(observation.time().nanos());

        // Recorded where the flow is inserted rather than inferred afterwards
        // from the table. A flow that opens and closes on one packet, a lone
        // RST, is gone again by the time the table is looked at, and used to be
        // reported as never having opened.
        let mut opened_flow = false;
        let finished = self.offer_with_reason(observation, &mut opened_flow);

        // The swept flows are carried on rather than copied into a second
        // vector: a sweep can return thousands of them, and each is a whole
        // record.
        let mut completed = expired;
        if let Some((flow, reason)) = finished {
            trace!("flow ended: {reason:?}");
            completed.push(flow);
        }

        AcceptOutcome {
            completed,
            opened_flow,
        }
    }

    pub fn sweep_expired(&mut self, current_time: u64) -> Vec<Flow> {
        let Some(timeout) = self.timeout else {
            return Vec::new();
        };

        // Out-of-order delivery is normal on merged captures and multi-queue
        // interfaces, and a packet's own timestamp is a poor clock: one packet
        // from far ahead would expire flows whose next packet has simply not
        // been handed over yet, and that flow's later packets would then open a
        // second flow. Expiry runs against the latest time seen, held back by
        // an allowance for how late a packet may be.
        self.watermark = self.watermark.max(current_time);
        let current_time = self.watermark.saturating_sub(self.lateness);

        let current_bucket = current_time / self.bucket;
        let due_buckets: Vec<u64> = self
            .due
            .range(..=current_bucket)
            .map(|(&at, _)| at)
            .collect();
        let mut expired = Vec::new();
        // Collected rather than inserted inline, so re-queued flows are never
        // revisited by the sweep that queued them.
        let mut due_again: Vec<(u64, Key)> = Vec::new();

        for bucket in due_buckets {
            let Some(keys) = self.due.remove(&bucket) else {
                continue;
            };

            for key in keys {
                let Some(state) = self.active.get_mut(&key) else {
                    // The flow already left through a FIN, a RST, or a drain.
                    continue;
                };
                if state.scheduled / self.bucket != bucket {
                    // A leftover entry from before this flow was re-queued.
                    continue;
                }

                let deadline = state.record.time.end.nanos() + timeout;
                if deadline <= current_time {
                    if let Some(mut state) = self.active.remove(&key) {
                        trace!("flow ended: {:?}", EndReason::IdleTimeout);
                        state.record.close(EndReason::IdleTimeout);
                        expired.push(Flow::new(key, state.record));
                    }
                } else {
                    // Touched since it was queued, so it lives on until its
                    // real deadline.
                    state.scheduled = deadline;
                    due_again.push((deadline / self.bucket, key));
                }
            }
        }

        for (bucket, key) in due_again {
            self.due.entry(bucket).or_default().push(key);
        }

        expired
    }

    pub fn drain(&mut self) -> Vec<Flow> {
        self.due.clear();
        self.active
            .drain()
            .map(|(key, mut state)| {
                trace!("flow ended: {:?}", EndReason::CaptureEnd);
                state.record.close(EndReason::CaptureEnd);
                Flow::new(key, state.record)
            })
            .collect()
    }

    /// The flows currently held open. Only the tests inspect this directly;
    /// callers go through `accept`.
    #[cfg(test)]
    pub fn active(&self) -> HashMap<Key, FlowRecord> {
        self.active
            .iter()
            .map(|(key, state)| (*key, state.record))
            .collect()
    }

    pub fn active_count(&self) -> usize {
        self.active.len()
    }

    /// Number of entries queued for expiry. The whole point of the bucketed
    /// design is that this tracks active flows, not packets seen.
    #[cfg(test)]
    fn queued_count(&self) -> usize {
        self.due.values().map(Vec::len).sum()
    }

    /// When a flow last seen at `packet_time` would idle out.
    fn deadline_from(&self, packet_time: u64) -> u64 {
        packet_time + self.timeout.unwrap_or(0)
    }

    /// Queue `key` to be checked once its deadline comes round. Does nothing
    /// when the engine was built without a timeout.
    fn enqueue(&mut self, key: Key, deadline: u64) {
        if self.timeout.is_none() {
            return;
        }
        self.due
            .entry(deadline / self.bucket)
            .or_default()
            .push(key);
    }
}

#[cfg(test)]
mod tests {
    use pcap::{Packet, PacketHeader};

    use super::*;
    use crate::net::scenarios::{ethernet, ipv4, tcp, udp};

    const SYN: u8 = 0x02;
    const FIN: u8 = 0x01;
    const RST: u8 = 0x04;

    const A: [u8; 4] = [192, 0, 2, 1];
    const B: [u8; 4] = [198, 51, 100, 2];

    /// One direction of a TCP conversation.
    fn tcp_frame(forward: bool, flags: u8) -> Vec<u8> {
        let (src, dst) = if forward { (A, B) } else { (B, A) };
        let (sport, dport) = if forward {
            (12_345, 443)
        } else {
            (443, 12_345)
        };
        ethernet(0x0800, &ipv4(6, 64, src, dst, &tcp(sport, dport, flags)))
    }

    /// A UDP flow distinct from the TCP one.
    fn udp_frame() -> Vec<u8> {
        ethernet(
            0x0800,
            &ipv4(
                17,
                64,
                [203, 0, 113, 5],
                [203, 0, 113, 6],
                &udp(53, 5353, &[]),
            ),
        )
    }

    /// Decode a frame the way the capture loops do. `time` is microseconds.
    fn observe_frame(frame: &[u8], time: u64) -> PacketObservation {
        let header = PacketHeader {
            ts: libc::timeval {
                tv_sec: 0,
                tv_usec: time as _,
            },
            caplen: frame.len() as u32,
            len: frame.len() as u32,
        };
        crate::net::parser::observe(
            Packet::new(&header, frame),
            false,
            1,
            &mut crate::net::parser::ParserState::new(),
        )
        .expect("parsable frame")
    }

    /// Feed a frame in at `time` microseconds.
    fn accept_at(engine: &mut FlowEngine, frame: &[u8], time: u64) -> AcceptOutcome {
        engine.accept(observe_frame(frame, time))
    }

    #[test]
    fn a_tcp_flow_without_a_syn_started_before_the_capture() {
        let mut engine = FlowEngine::new(10);
        accept_at(&mut engine, &tcp_frame(true, 0), 1);

        let record = *engine.active().values().next().expect("one flow");
        assert_eq!(record.time.start_state, StartState::MidStream);
    }

    #[test]
    fn a_tcp_flow_with_a_syn_did_not() {
        let mut engine = FlowEngine::new(10);
        accept_at(&mut engine, &tcp_frame(true, SYN), 1);

        let record = *engine.active().values().next().expect("one flow");
        assert_eq!(record.time.start_state, StartState::SynObserved);
    }

    /// UDP has no handshake, so it cannot have missed one.
    #[test]
    fn a_udp_flow_has_no_handshake_to_miss() {
        let mut engine = FlowEngine::new(10);
        accept_at(&mut engine, &udp_frame(), 1);

        let record = *engine.active().values().next().expect("one flow");
        assert_eq!(record.time.start_state, StartState::NotApplicable);
    }

    #[test]
    fn a_flow_ends_once_both_directions_have_sent_a_fin() {
        let mut engine = FlowEngine::new(10);
        accept_at(&mut engine, &tcp_frame(true, SYN), 1);

        assert!(
            accept_at(&mut engine, &tcp_frame(true, FIN), 2)
                .completed
                .is_empty(),
            "a half-close must not end the flow"
        );

        let outcome = accept_at(&mut engine, &tcp_frame(false, FIN), 3);
        assert_eq!(outcome.completed.len(), 1);
        assert_eq!(
            outcome.completed[0].record.time.end_reason,
            Some(EndReason::Fin)
        );
        assert_eq!(engine.active_count(), 0);
    }

    #[test]
    fn a_reset_ends_the_flow_on_its_own() {
        let mut engine = FlowEngine::new(10);
        accept_at(&mut engine, &tcp_frame(true, SYN), 1);

        let outcome = accept_at(&mut engine, &tcp_frame(false, RST), 2);
        assert_eq!(
            outcome.completed[0].record.time.end_reason,
            Some(EndReason::Rst)
        );
    }

    #[test]
    fn a_half_closed_flow_still_leaves_on_the_idle_timeout() {
        let mut engine = FlowEngine::new(10);
        accept_at(&mut engine, &tcp_frame(true, SYN), 1_000);
        accept_at(&mut engine, &tcp_frame(true, FIN), 2_000);
        assert_eq!(engine.active_count(), 1, "still waiting on the other FIN");

        let expired = engine.sweep_expired(30_000_000);
        assert_eq!(expired.len(), 1);
        assert_eq!(
            expired[0].record.time.end_reason,
            Some(EndReason::IdleTimeout)
        );
    }

    #[test]
    fn accept_reports_a_newly_opened_flow_once() {
        let mut engine = FlowEngine::new(10);

        assert!(accept_at(&mut engine, &tcp_frame(true, SYN), 1).opened_flow);
        assert!(!accept_at(&mut engine, &tcp_frame(true, 0), 2).opened_flow);
        assert!(
            !accept_at(&mut engine, &tcp_frame(false, 0), 3).opened_flow,
            "the reverse direction is the same flow"
        );
    }

    /// One packet can finish two flows for two different reasons.
    #[test]
    fn accept_returns_terminated_and_expired_flows_together() {
        let mut engine = FlowEngine::new(10);
        accept_at(&mut engine, &udp_frame(), 1_000);
        accept_at(&mut engine, &tcp_frame(true, SYN), 2_000);
        accept_at(&mut engine, &tcp_frame(true, FIN), 3_000);

        // Past the UDP flow's deadline and past the lateness allowance.
        let outcome = accept_at(&mut engine, &tcp_frame(false, FIN), 17_000);
        assert_eq!(outcome.completed.len(), 2);
        assert_eq!(engine.active_count(), 0);
    }

    /// The point of the bucketed design: bookkeeping tracks flows, not packets.
    #[test]
    fn expiry_bookkeeping_tracks_flows_not_packets() {
        let mut engine = FlowEngine::new(10);
        for packet in 0..1_000u64 {
            accept_at(&mut engine, &udp_frame(), packet);
        }

        assert_eq!(engine.active_count(), 1);
        assert_eq!(
            engine.queued_count(),
            1,
            "a flow keeps one queue entry however many packets it sees"
        );
    }

    #[test]
    fn a_flow_touched_before_its_deadline_is_requeued_not_expired() {
        let mut engine = FlowEngine::new(10);
        accept_at(&mut engine, &udp_frame(), 1_000);
        accept_at(&mut engine, &udp_frame(), 9_000);

        assert!(engine.sweep_expired(12_000_000).is_empty());
        assert_eq!(engine.active_count(), 1);
        assert_eq!(engine.queued_count(), 1, "re-queued exactly once");

        assert_eq!(engine.sweep_expired(24_000_000).len(), 1);
        assert_eq!(engine.active_count(), 0);
    }

    /// A packet from further ahead must not expire a flow whose own next
    /// packet is merely late. Expiring it would split one conversation in two,
    /// because the delayed packet then opens a second flow.
    #[test]
    fn a_flow_is_not_expired_by_another_flow_running_ahead() {
        // 20 ms timeout, so up to 10 ms of skew is tolerated.
        let mut engine = FlowEngine::new(20);
        accept_at(&mut engine, &udp_frame(), 1_000);
        // A different flow, delivered from further along the capture.
        accept_at(&mut engine, &tcp_frame(true, SYN), 30_000);
        // The first flow's own next packet, delivered late.
        let outcome = accept_at(&mut engine, &udp_frame(), 2_000);

        assert!(
            outcome.completed.is_empty(),
            "nothing finished: the UDP flow is still the same conversation"
        );
        assert!(!outcome.opened_flow, "and it did not open a second one");
    }

    /// Skew past the allowance still expires a flow early. This is the
    /// documented limit rather than an accident: holding expiry back further
    /// than the timeout would mean the timeout no longer says when a flow ends.
    #[test]
    fn skew_beyond_the_allowance_still_expires_a_flow() {
        let mut engine = FlowEngine::new(20);
        accept_at(&mut engine, &udp_frame(), 1_000);
        accept_at(&mut engine, &tcp_frame(true, SYN), 500_000);
        let outcome = accept_at(&mut engine, &udp_frame(), 2_000);

        assert!(outcome.opened_flow, "the late packet opened a second flow");
    }

    /// A flow that opens and closes on the same packet still opened.
    #[test]
    fn a_flow_that_opens_and_closes_at_once_is_reported_as_opened() {
        let mut engine = FlowEngine::new(600_000);
        let outcome = accept_at(&mut engine, &tcp_frame(true, RST), 1_000);

        assert!(outcome.opened_flow, "the flow was created");
        assert_eq!(outcome.completed.len(), 1, "and finished immediately");
        assert_eq!(engine.active_count(), 0);
    }

    #[test]
    fn a_closed_flow_leaves_no_entry_behind() {
        let mut engine = FlowEngine::new(10);
        accept_at(&mut engine, &tcp_frame(true, SYN), 1);
        accept_at(&mut engine, &tcp_frame(false, RST), 2);

        assert!(engine.sweep_expired(1_000_000_000).is_empty());
        assert_eq!(engine.queued_count(), 0);
        assert_eq!(engine.active_count(), 0);
    }

    #[test]
    fn zero_timeout_means_flows_never_expire() {
        let mut engine = FlowEngine::new(0);
        accept_at(&mut engine, &udp_frame(), 1);

        assert!(engine.sweep_expired(u64::MAX).is_empty());
        assert_eq!(engine.active_count(), 1);
        assert_eq!(engine.drain().len(), 1);
    }

    #[test]
    fn drain_returns_and_clears_active_flows() {
        let mut engine = FlowEngine::new(10);
        accept_at(&mut engine, &udp_frame(), 1);

        let drained = engine.drain();
        assert_eq!(drained.len(), 1);
        assert_eq!(
            drained[0].record.time.end_reason,
            Some(EndReason::CaptureEnd)
        );
        assert_eq!(engine.active_count(), 0);
    }

    /// The first packet is counted once, by the engine and not the parser.
    #[test]
    fn the_first_packet_is_counted_exactly_once() {
        let frame = tcp_frame(true, SYN);
        let mut engine = FlowEngine::new(10);
        accept_at(&mut engine, &frame, 1);

        let record = *engine.active().values().next().expect("one flow");
        assert_eq!(record.packets(), 1);
        assert_eq!(record.frame_octets(), frame.len() as u64);
        assert_eq!(record.forward.packets, 1);
        assert_eq!(record.reverse.packets, 0);
        assert_eq!(record.reverse.frame_octets, 0);
    }
}
