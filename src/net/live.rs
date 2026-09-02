//! What the two live capture modes agree on.
//!
//! `capture` and `capture_tui` run the same capture; they differ only in
//! whether a terminal interface is drawn over it. Everything that is not about
//! drawing lives here, so the two cannot drift apart. They already had: one
//! reported a failed export and the other discarded it, and one named the file
//! it could not create while the other did not.

use std::time::{Duration, Instant};

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
