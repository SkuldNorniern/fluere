//! What the two live capture modes agree on.
//!
//! `capture` and `capture_tui` run the same capture; they differ only in
//! whether a terminal interface is drawn over it. Everything that is not about
//! drawing lives here, so the two cannot drift apart. They already had: one
//! reported a failed export and the other discarded it, and one named the file
//! it could not create while the other did not.

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use log::error;
use tokio::task::JoinHandle;

use crate::{FluereError, error::OptionExt, types::Args};

/// The settings a live capture runs with, taken from the command line.
pub struct Settings {
    pub csv_file: String,
    pub use_mac: bool,
    pub snaplen: u64,
    pub interface_name: String,
    pub duration: u64,
    pub interval: u64,
    pub flow_timeout: u64,
}

impl Settings {
    /// Every value but the interface has a default the parser applies, so a
    /// missing one is a construction bug rather than something the operator
    /// left out.
    pub fn from_args(arg: Args) -> Result<Self, FluereError> {
        Ok(Settings {
            csv_file: arg
                .files
                .csv
                .required("this should be defaulted to `output` on construction")?,
            use_mac: arg
                .parameters
                .use_mac
                .required("this should be defaulted to `false` on construction")?,
            snaplen: arg
                .parameters
                .snaplen
                .required("this should be defaulted to `65535` on construction")?,
            interface_name: arg.interface.required("interface should be provided")?,
            duration: arg
                .parameters
                .duration
                .required("this should be defaulted to `0(infinite)` on construction")?,
            interval: arg
                .parameters
                .interval
                .required("this should be defaulted to `30 minutes` on construction")?,
            flow_timeout: arg
                .parameters
                .timeout
                .required("this should be defaulted to `10 minutes` on construction")?,
        })
    }
}

/// When the next export falls due.
///
/// Both live modes kept their own type of this name and their own copy of the
/// due check. The terminal mode also needs a wall-clock stamp for the export
/// it last wrote, which is the only reason that field is here rather than
/// local to it.
pub struct ExportSchedule {
    /// Milliseconds between exports. Zero means one file, written when the
    /// capture ends.
    pub interval: u64,
    pub last_export: Instant,
    pub last_export_unix_time: u64,
}

impl ExportSchedule {
    pub fn new(interval: u64) -> Self {
        ExportSchedule {
            interval,
            last_export: Instant::now(),
            last_export_unix_time: unix_time_seconds(),
        }
    }

    /// A zero interval never falls due: the capture writes one file at the end
    /// rather than rotating.
    pub fn is_due(&self) -> bool {
        self.interval != 0 && self.last_export.elapsed() >= Duration::from_millis(self.interval)
    }

    pub fn mark_exported(&mut self) {
        self.last_export = Instant::now();
        self.last_export_unix_time = unix_time_seconds();
    }
}

pub fn unix_time_seconds() -> u64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_secs(),
        Err(error) => {
            error!("System time is before UNIX epoch: {error}");
            0
        }
    }
}

/// How far through the current export interval, as 0.0 to 1.0.
///
/// An interval of zero means exports are not scheduled at all, so there is no
/// progress to show rather than a bar permanently at full.
pub fn export_progress(since_last_export: Duration, interval: u64) -> f64 {
    if interval == 0 {
        return 0.0;
    }

    (since_last_export.as_millis() as f64 / interval as f64).clamp(0.0, 1.0)
}

/// Whether a capture with a set duration has run for it.
///
/// A duration of zero means the capture runs until it is interrupted, so it is
/// never reached.
pub fn duration_reached(start: Instant, duration: u64) -> bool {
    start.elapsed() >= Duration::from_millis(duration) && duration != 0
}

/// Wait for every export to finish, reporting one that did not.
///
/// A panicking task used to be discarded here, so a run whose export died
/// still exited successfully with nothing written.
pub async fn await_export_tasks(export_tasks: Vec<JoinHandle<()>>) {
    for task in export_tasks {
        if let Err(error) = task.await {
            error!("An export did not finish: {error}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_zero_interval_never_falls_due() {
        let mut schedule = ExportSchedule::new(0);
        schedule.last_export = Instant::now() - Duration::from_secs(3600);
        assert!(!schedule.is_due());
    }

    #[test]
    fn an_interval_falls_due_once_it_has_elapsed() {
        let mut schedule = ExportSchedule::new(1_000);
        assert!(!schedule.is_due());
        schedule.last_export = Instant::now() - Duration::from_secs(10);
        assert!(schedule.is_due());
        schedule.mark_exported();
        assert!(!schedule.is_due());
    }

    #[test]
    fn export_progress_runs_from_empty_to_full() {
        assert_eq!(export_progress(Duration::from_millis(0), 1_000), 0.0);
        assert_eq!(export_progress(Duration::from_millis(500), 1_000), 0.5);
        assert_eq!(export_progress(Duration::from_millis(1_000), 1_000), 1.0);
    }

    /// Overdue exports must not run the bar past the end.
    #[test]
    fn export_progress_is_clamped() {
        assert_eq!(export_progress(Duration::from_millis(9_000), 1_000), 1.0);
    }

    /// With no export interval there is nothing to be partway through. The
    /// previous code divided by the interval regardless, which left the bar
    /// pinned at full for a capture that never exports on a timer.
    #[test]
    fn an_unscheduled_export_shows_no_progress() {
        assert_eq!(export_progress(Duration::from_millis(5_000), 0), 0.0);
    }

    #[test]
    fn a_zero_duration_is_never_reached() {
        assert!(!duration_reached(
            Instant::now() - Duration::from_secs(3600),
            0
        ));
    }

    #[test]
    fn a_set_duration_is_reached_once_it_has_elapsed() {
        let long_ago = Instant::now() - Duration::from_secs(10);
        assert!(duration_reached(long_ago, 1_000));
        assert!(!duration_reached(Instant::now(), 1_000));
    }
}
