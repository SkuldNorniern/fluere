use chrono::DateTime;

#[inline]
pub fn parse_microseconds(sec: u64, usec: u64) -> u64 {
    sec * 1000000 + usec
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
