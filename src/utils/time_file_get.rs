use chrono::Local;
use std::borrow::Cow;
use std::path::Path;

/// A name for one export, from the time it was taken.
///
/// The stamp is only precise to the second, so exports rotating faster than
/// that would all name the same file and each would truncate the last. When
/// that happens the name gains a counter - `name_2026-09-10_12-00-00_2.csv` -
/// rather than the stamp growing a sub-second field, so a name looks the same
/// as it always has for every interval that does not collide.
pub fn cur_time_file(name: &str, dir: &str, format: &str) -> Cow<'static, str> {
    let date = Local::now();
    let stem = format!("{}/{}_{}", dir, name, date.format("%Y-%m-%d_%H-%M-%S"));
    let first = format!("{stem}{format}");
    if !Path::new(&first).exists() {
        return Cow::Owned(first);
    }

    // Bounded: past this the clock has moved on, or something else is writing
    // here and a distinct name is no longer this function's problem.
    for attempt in 2..1_000u32 {
        let candidate = format!("{stem}_{attempt}{format}");
        if !Path::new(&candidate).exists() {
            return Cow::Owned(candidate);
        }
    }

    Cow::Owned(first)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two exports in the same second must not name the same file: the second
    /// would truncate the first and its flows would be gone.
    #[test]
    fn a_second_export_within_one_second_gets_its_own_name() {
        let dir = std::env::temp_dir().join(format!("fluere-rotate-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let dir_name = dir.to_str().expect("utf-8 path");

        let first = cur_time_file("flows", dir_name, ".csv");
        std::fs::write(first.as_ref(), b"one").expect("write");
        let second = cur_time_file("flows", dir_name, ".csv");

        assert_ne!(first, second, "the first export must not be overwritten");
        assert!(second.ends_with("_2.csv"));

        std::fs::remove_dir_all(&dir).ok();
    }
}
