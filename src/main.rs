// This is the main entry point of the Fluere application.
// Fluere is a versatile tool designed to capture network packets in pcap format and convert them into NetFlow data.
// It also supports live capture and conversion of NetFlow data.

use fluere::{self, FluereError, Mode};
use log::debug;
use std::process;

#[tokio::main]
async fn main() -> Result<(), FluereError> {
    let args = fluere::cli::cli_template().get_matches();

    if let Some((mode_str, sub_args)) = args.subcommand() {
        // Convert mode string to Mode enum using TryFrom
        let mode = Mode::try_from(mode_str)?;

        // Handle mode-specific arguments
        let Ok((params, verbosity)) = fluere::cli::handle_mode(mode_str, sub_args).await else {
            return Err(FluereError::ConfigError(
                "Failed to handle mode".to_string(),
            ));
        };

        // Setup logging using library function
        fluere::setup_logging(verbosity)?;
        debug!("Fluere started");

        // Execute the selected mode using library function
        fluere::execute_mode(mode, params).await?;

        Ok(())
    } else {
        process::exit(0);
    }
}
