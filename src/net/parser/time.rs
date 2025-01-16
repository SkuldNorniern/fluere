use chrono::prelude::*;
use chrono::DateTime;

#[inline]
pub fn parse_microseconds(sec: u64, usec: u64) -> u64 {
    sec * 1000000 + usec
}

#[inline]
pub fn microseconds_to_timestamp(usec: u64) -> String {
    let naive = DateTime::from_timestamp(usec as i64, 0)
        .expect("Clockster may have gone backwards")
        .naive_utc();

    #[cfg(not(target_os = "windows"))]
    let datetime = DateTime::<Utc>::from_naive_utc_and_offset(naive, Utc);

    #[cfg(target_os = "windows")]
    let datetime = DateTime::<Utc>::from_utc(naive, Utc);

    datetime.format("%Y-%m-%d_%H-%M-%S UTC").to_string()
}
