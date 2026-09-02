// Entry point for Fluere: capture network traffic or convert a pcap file into
// FluereFlow records.

use fluere::{FluereError, cli};
use log::debug;
use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        // Printed rather than returned, so the reader gets the message the
        // error was written to give. Returning it would print the derived
        // `Debug` form instead: `Capture(Pcap(PcapError("...")))` rather than
        // what happened and what to do about it.
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), FluereError> {
    let matches = cli::cli_template().get_matches();

    // `None` means the command did its own work, such as listing devices.
    let Some(invocation) = cli::dispatch(&matches)? else {
        return Ok(());
    };

    fluere::setup_logging(invocation.verbosity)?;
    debug!("Fluere started");

    fluere::execute_mode(invocation.mode, invocation.args).await
}
