//! When a flow happened.

/// A point in time, as nanoseconds since the Unix epoch.
///
/// Nanoseconds rather than microseconds because it costs nothing: both fit a
/// `u64`, and `u64` nanoseconds still reaches the year 2554. Widening later
/// would be a breaking change; starting wide is free.
///
/// The precision a capture actually had is recorded separately, in
/// [`TimeResolution`], so a microsecond source is never mistaken for a
/// nanosecond one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct Timestamp {
    nanos: u64,
}

impl Timestamp {
    pub const fn from_nanos(nanos: u64) -> Self {
        Timestamp { nanos }
    }

    pub const fn from_micros(micros: u64) -> Self {
        Timestamp {
            nanos: micros.saturating_mul(1_000),
        }
    }

    pub const fn nanos(self) -> u64 {
        self.nanos
    }

    /// Truncated towards zero, so this is lossy for a nanosecond source.
    pub const fn micros(self) -> u64 {
        self.nanos / 1_000
    }

    /// Nanoseconds elapsed since `earlier`, saturating at zero.
    pub const fn since(self, earlier: Timestamp) -> u64 {
        self.nanos.saturating_sub(earlier.nanos)
    }
}

/// The finest interval a capture source could distinguish.
///
/// libpcap's `timeval` is microseconds; pcapng and some live sources offer
/// nanoseconds. Recording which lets a consumer know whether sub-microsecond
/// differences in [`Timestamp`] mean anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TimeResolution {
    #[default]
    Microseconds,
    Nanoseconds,
}

/// How a flow began.
///
/// Replaces a bare `mid_stream` flag, which could not tell "the capture started
/// partway through a connection" apart from "this protocol has no handshake" -
/// both were `false`, which read as "the handshake was seen".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum StartState {
    /// A TCP handshake was observed from the start.
    SynObserved,
    /// A TCP flow whose opening packets were never captured.
    MidStream,
    /// Not a connection-oriented protocol, so there is no handshake to miss.
    #[default]
    NotApplicable,
}

/// Why a flow stopped being tracked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndReason {
    /// Both directions closed the connection.
    Fin,
    /// One side reset it.
    Rst,
    /// Nothing arrived within the idle timeout.
    IdleTimeout,
    /// A long-running flow exported while it was still active.
    ///
    /// Reserved. Fluere has no active timeout yet, so nothing produces this
    /// today; it is declared so adding one later does not change the shape of
    /// this enum for consumers already matching on it.
    ActiveTimeout,
    /// Capture stopped while the flow was open.
    CaptureEnd,
}

/// When a flow started and stopped, and what those events were.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlowTime {
    pub start: Timestamp,
    pub end: Timestamp,
    pub resolution: TimeResolution,
    pub start_state: StartState,
    /// `None` while the flow is still open.
    pub end_reason: Option<EndReason>,
}

impl FlowTime {
    pub fn opening(at: Timestamp, resolution: TimeResolution, start_state: StartState) -> Self {
        FlowTime {
            start: at,
            end: at,
            resolution,
            start_state,
            end_reason: None,
        }
    }

    /// How long the flow lasted, in nanoseconds.
    pub const fn duration(&self) -> u64 {
        self.end.since(self.start)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn microsecond_sources_convert_without_loss() {
        let stamp = Timestamp::from_micros(1_700_000_000_123_456);
        assert_eq!(stamp.nanos(), 1_700_000_000_123_456_000);
        assert_eq!(stamp.micros(), 1_700_000_000_123_456);
    }

    #[test]
    fn nanoseconds_reach_far_enough_ahead() {
        // u64 nanoseconds from 1970 runs past the year 2500.
        let year_2500 = 16_725_225_600u64 * 1_000_000_000;
        assert!(Timestamp::from_nanos(year_2500).nanos() > 0);
    }

    #[test]
    fn duration_is_the_span_between_first_and_last() {
        let mut time = FlowTime::opening(
            Timestamp::from_micros(1_000),
            TimeResolution::Microseconds,
            StartState::SynObserved,
        );
        assert_eq!(time.duration(), 0);

        time.end = Timestamp::from_micros(3_500);
        assert_eq!(time.duration(), 2_500_000, "2.5 ms in nanoseconds");
    }

    /// Clock jitter must not produce a negative duration.
    #[test]
    fn a_backwards_clock_gives_no_duration() {
        let time = FlowTime {
            start: Timestamp::from_micros(5_000),
            end: Timestamp::from_micros(1_000),
            resolution: TimeResolution::Microseconds,
            start_state: StartState::NotApplicable,
            end_reason: None,
        };
        assert_eq!(time.duration(), 0);
    }

    #[test]
    fn a_flow_with_no_handshake_is_distinguishable_from_a_protocol_without_one() {
        assert_ne!(StartState::MidStream, StartState::NotApplicable);
        assert_ne!(StartState::SynObserved, StartState::NotApplicable);
    }
}
