// Entry point for Fluere: capture network traffic or convert a pcap file into
// FluereFlow records.

use fluere::{FluereError, cli};
use log::debug;

#[tokio::main]
async fn main() -> Result<(), FluereError> {
    let matches = cli::cli_template().get_matches();

    // `None` means the command did its own work, such as listing devices.
    let Some(invocation) = cli::dispatch(&matches)? else {
        return Ok(());
    };

    fluere::setup_logging(invocation.verbosity)?;
    debug!("Fluere started");

    fluere::execute_mode(invocation.mode, invocation.args).await
}
