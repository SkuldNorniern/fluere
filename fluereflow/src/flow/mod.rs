//! FluereFlow: Fluere's own flow record.
//!
//! A flow is what one conversation contributed to a capture: when it happened,
//! what each direction carried, and how much of it the capture actually saw.
//!
//! Two things about the shape are deliberate.
//!
//! **Totals are derived, not stored.** [`FlowRecord::packets`] and
//! [`FlowRecord::frame_octets`] add the two directions up on demand. The
//! previous model stored a total alongside the per-direction counts, which
//! meant they could disagree - and they did, silently double-counting every
//! flow's first packet. A total that cannot be written cannot drift.
//!
//! **Every serialised number has a fixed width.** Counters are `u64` and
//! timestamps are nanoseconds, so a record means the same thing whatever
//! machine wrote it.

mod stats;
mod time;

pub use stats::{CaptureStats, DirectionStats, NetworkStats, Range, TcpFlagCounts, TcpFlags};
pub use time::{EndReason, FlowTime, StartState, TimeResolution, Timestamp};

/// Version of this record shape.
///
/// Bumped whenever a field is added, removed, renamed, or changes meaning, so a
/// consumer can tell which shape it is holding.
pub const SCHEMA_VERSION: u32 = 1;

/// Which direction of a flow a packet travelled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// The direction the flow's first packet took.
    Forward,
    /// The other one.
    Reverse,
}

/// One packet's contribution to a flow.
#[derive(Debug, Clone, Copy)]
pub struct PacketFacts {
    pub time: Timestamp,
    /// Length on the wire.
    pub frame_octets: u32,
    /// Length actually captured, which is smaller when a snaplen truncated it.
    pub captured_octets: u32,
    /// Time to live, or its IPv6 spelling, hop limit. `None` for traffic with
    /// neither.
    pub ttl: Option<u8>,
    /// TCP control bits, `None` for anything that is not TCP.
    pub tcp_flags: Option<TcpFlags>,
}

impl PacketFacts {
    /// Whether the snaplen cut this packet short.
    pub const fn truncated(&self) -> bool {
        self.captured_octets < self.frame_octets
    }
}

/// A single flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlowRecord {
    pub schema: u32,
    pub time: FlowTime,
    pub forward: DirectionStats,
    pub reverse: DirectionStats,
    pub network: NetworkStats,
    pub capture: CaptureStats,
}

impl FlowRecord {
    /// Open a flow. The first packet is not counted here - pass it to
    /// [`observe`](Self::observe) like any other, so it is counted exactly once.
    pub fn open(at: Timestamp, resolution: TimeResolution, start_state: StartState) -> Self {
        FlowRecord {
            schema: SCHEMA_VERSION,
            time: FlowTime::opening(at, resolution, start_state),
            forward: DirectionStats::default(),
            reverse: DirectionStats::default(),
            network: NetworkStats::default(),
            capture: CaptureStats::default(),
        }
    }

    /// Fold one packet into the flow.
    pub fn observe(&mut self, direction: Direction, facts: PacketFacts) {
        let stats = match direction {
            Direction::Forward => &mut self.forward,
            Direction::Reverse => &mut self.reverse,
        };
        stats.observe(facts.frame_octets, facts.tcp_flags.unwrap_or_default());

        self.time.end = facts.time;
        if let Some(ttl) = facts.ttl {
            stats::observe(&mut self.network.ttl, ttl);
        }

        self.capture.captured_octets += u64::from(facts.captured_octets);
        self.capture.truncated |= facts.truncated();
    }

    /// Record why the flow ended.
    pub fn close(&mut self, reason: EndReason) {
        self.time.end_reason = Some(reason);
    }

    /// Packets in both directions.
    pub fn packets(&self) -> u64 {
        self.forward.packets + self.reverse.packets
    }

    /// Wire bytes in both directions.
    pub fn frame_octets(&self) -> u64 {
        self.forward.frame_octets + self.reverse.frame_octets
    }

    /// Whether traffic was seen in both directions.
    pub fn is_bidirectional(&self) -> bool {
        !self.forward.is_empty() && !self.reverse.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(micros: u64) -> Timestamp {
        Timestamp::from_micros(micros)
    }

    fn packet(micros: u64, frame_octets: u32) -> PacketFacts {
        PacketFacts {
            time: at(micros),
            frame_octets,
            captured_octets: frame_octets,
            ttl: Some(64),
            tcp_flags: None,
        }
    }

    fn open() -> FlowRecord {
        FlowRecord::open(
            at(1_000),
            TimeResolution::Microseconds,
            StartState::SynObserved,
        )
    }

    /// The bug this shape exists to prevent: a stored total drifting from the
    /// per-direction counts. Here there is no stored total to drift.
    #[test]
    fn totals_always_agree_with_the_directions() {
        let mut record = open();
        record.observe(Direction::Forward, packet(1_000, 54));
        record.observe(Direction::Reverse, packet(2_000, 100));
        record.observe(Direction::Forward, packet(3_000, 200));

        assert_eq!(record.packets(), 3);
        assert_eq!(
            record.packets(),
            record.forward.packets + record.reverse.packets
        );
        assert_eq!(record.frame_octets(), 354);
        assert_eq!(
            record.frame_octets(),
            record.forward.frame_octets + record.reverse.frame_octets
        );
    }

    #[test]
    fn a_freshly_opened_flow_has_counted_nothing() {
        let record = open();

        assert_eq!(record.packets(), 0);
        assert_eq!(record.frame_octets(), 0);
        assert!(record.forward.is_empty());
        assert!(record.reverse.is_empty());
        assert!(!record.is_bidirectional());
        assert_eq!(record.time.duration(), 0);
    }

    /// A direction that never carried a packet must report no bytes, not bytes
    /// borrowed from the other direction.
    #[test]
    fn an_unused_direction_reports_nothing() {
        let mut record = open();
        record.observe(Direction::Forward, packet(1_000, 54));

        assert_eq!(record.reverse.packets, 0);
        assert_eq!(record.reverse.frame_octets, 0);
        assert_eq!(record.reverse.packet_length, None);
        assert!(!record.is_bidirectional());
    }

    #[test]
    fn the_flow_ends_when_its_last_packet_arrived() {
        let mut record = open();
        record.observe(Direction::Forward, packet(1_000, 54));
        record.observe(Direction::Reverse, packet(9_500, 54));

        assert_eq!(record.time.start, at(1_000));
        assert_eq!(record.time.end, at(9_500));
        assert_eq!(record.time.duration(), 8_500_000);
    }

    #[test]
    fn truncation_is_recorded_without_disturbing_wire_counts() {
        let mut record = open();
        record.observe(
            Direction::Forward,
            PacketFacts {
                captured_octets: 64,
                ..packet(1_000, 1_500)
            },
        );

        assert_eq!(record.frame_octets(), 1_500, "wire length is what counts");
        assert_eq!(record.capture.captured_octets, 64);
        assert!(record.capture.truncated);
    }

    #[test]
    fn an_untruncated_flow_says_so() {
        let mut record = open();
        record.observe(Direction::Forward, packet(1_000, 1_500));

        assert!(!record.capture.truncated);
        assert_eq!(record.capture.captured_octets, 1_500);
    }

    /// IPv6 reports its hop limit under the same name, where the previous model
    /// recorded zero and left the field meaning two different things by address
    /// family.
    #[test]
    fn ttl_spans_both_directions() {
        let mut record = open();
        record.observe(
            Direction::Forward,
            PacketFacts {
                ttl: Some(64),
                ..packet(1_000, 54)
            },
        );
        record.observe(
            Direction::Reverse,
            PacketFacts {
                ttl: Some(52),
                ..packet(2_000, 54)
            },
        );

        assert_eq!(record.network.ttl, Some(Range { min: 52, max: 64 }));
    }

    #[test]
    fn traffic_without_a_ttl_reports_none() {
        let mut record = open();
        record.observe(
            Direction::Forward,
            PacketFacts {
                ttl: None,
                ..packet(1_000, 54)
            },
        );

        assert_eq!(record.network.ttl, None);
    }

    #[test]
    fn closing_records_why() {
        let mut record = open();
        assert_eq!(record.time.end_reason, None, "open flows have no reason");

        record.close(EndReason::Fin);
        assert_eq!(record.time.end_reason, Some(EndReason::Fin));
    }

    #[test]
    fn a_record_carries_its_schema_version() {
        assert_eq!(open().schema, SCHEMA_VERSION);
    }
}
