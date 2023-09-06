use chrono::prelude::*;

pub fn parse_microseconds(sec: u64, usec: u64) -> u64 {
    sec * 1000000 + usec
}

pub fn microseconds_to_timestamp(usec: u64) -> String {
    let naive = NaiveDateTime::from_timestamp_opt(usec as i64, 0);

    #[cfg(not(target_os = "windows"))]
    let datetime = DateTime::<Utc>::from_naive_utc_and_offset(naive.unwrap(), Utc);

    #[cfg(target_os = "windows")]
    let datetime = DateTime::<Utc>::from_utc(naive.unwrap(), Utc);

    datetime.format("%Y-%m-%d_%H-%M-%S UTC").to_string()
}
