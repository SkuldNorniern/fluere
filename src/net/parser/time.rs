use chrono::DateTime;

/// Combine the seconds and microseconds of a capture timestamp.
///
/// Saturating rather than wrapping. A capture carries whatever timestamp its
/// writer put there, and a large enough one overflowed here: a panic in a debug
/// build, and a wrapped nonsense time in a release one. `Timestamp` already
/// saturates the microsecond-to-nanosecond step, so this matches it rather than
/// leaving the guard on only one of the two.
#[inline]
pub fn parse_microseconds(sec: u64, usec: u64) -> u64 {
    sec.saturating_mul(1_000_000).saturating_add(usec)
}

/// A wall-clock stamp for display, from seconds since the Unix epoch.
///
/// Only the TUI uses this, to say when it last exported. Flow timestamps are
/// nanoseconds and are exported as numbers, not as formatted text.
#[inline]
pub fn unix_seconds_to_timestamp(seconds: u64) -> String {
    // Out of range means a clock far enough off that the display is the least
    // of the problems, so say so rather than ending the capture over it.
    let Some(time) = DateTime::from_timestamp(seconds as i64, 0) else {
        return "unknown".to_string();
    };

    time.format("%Y-%m-%d_%H-%M-%S UTC").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seconds_and_microseconds_combine() {
        assert_eq!(parse_microseconds(7, 8), 7_000_008);
    }

    /// A crafted capture can name a second far beyond any real clock. That
    /// used to overflow into a small number, putting the flow's start after
    /// its end.
    #[test]
    fn an_impossible_second_saturates_rather_than_wrapping() {
        assert_eq!(parse_microseconds(u64::MAX, 0), u64::MAX);
        assert_eq!(parse_microseconds(u64::MAX, u64::MAX), u64::MAX);
    }

    #[test]
    fn a_stamp_reads_as_utc() {
        assert_eq!(
            unix_seconds_to_timestamp(1_700_000_000),
            "2023-11-14_22-13-20 UTC"
        );
    }

    /// A clock far enough out of range used to end the capture with a panic.
    #[test]
    fn an_impossible_clock_does_not_panic() {
        assert_eq!(unix_seconds_to_timestamp(i64::MAX as u64), "unknown");
    }
}
