//! Noticing that the operator asked the capture to stop.

use log::debug;
use tokio::sync::watch;

/// A flag that turns true when the operator interrupts the process.
///
/// `--duration 0` means "until interrupted", and an interrupt that killed the
/// process where it stood would take the shutdown with it: flows still open
/// would never reach the plugins or the CSV. This lets the capture loop break
/// normally and run the shutdown it already has.
pub struct StopSignal {
    stop: watch::Receiver<bool>,
}

impl StopSignal {
    /// Start listening. Failing to install the handler is not fatal: the
    /// capture still runs, it just cannot be stopped early this way.
    pub fn listen() -> Self {
        let (sender, stop) = watch::channel(false);

        tokio::spawn(async move {
            if let Err(error) = tokio::signal::ctrl_c().await {
                debug!("cannot listen for an interrupt: {error}");
                return;
            }

            debug!("interrupt received, finishing the capture");
            let _ = sender.send(true);

            // Handling the first interrupt takes the usual meaning of the key
            // away, so a shutdown that stalls would leave no way out. A second
            // one leaves immediately, at the cost of whatever had not been
            // written yet.
            if tokio::signal::ctrl_c().await.is_ok() {
                eprintln!("Interrupted again; leaving without finishing the export.");
                std::process::exit(130);
            }
        });

        StopSignal { stop }
    }

    /// Whether the operator has asked to stop.
    pub fn requested(&self) -> bool {
        *self.stop.borrow()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The signal path itself needs a live capture to exercise, but a capture
    /// that has not been interrupted must not think it has been.
    #[tokio::test]
    async fn nothing_is_requested_before_an_interrupt() {
        let signal = StopSignal::listen();
        assert!(!signal.requested());
    }
}
