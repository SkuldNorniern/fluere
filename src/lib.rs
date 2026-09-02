pub mod cli;
mod error;
pub mod logger;
pub mod net;
pub mod types;
pub mod utils;

pub use error::{CaptureError, ConfigError, FluereError, ParseError};
use log::{Level, LevelFilter};

/// What a resolved command line asks Fluere to do. Chosen by
/// [`cli::dispatch`], not parsed from a name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Offline,
    Online,
    Live,
    Pcap,
}

impl std::fmt::Display for Mode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Mode::Offline => write!(f, "Offline"),
            Mode::Online => write!(f, "Online"),
            Mode::Live => write!(f, "Live"),
            Mode::Pcap => write!(f, "Pcap"),
        }
    }
}

// Move verbosity level conversion to lib
pub fn get_log_level(verbose: u8) -> LevelFilter {
    match verbose {
        0 => LevelFilter::Error,
        1 => LevelFilter::Warn,
        2 => LevelFilter::Info,
        3 => LevelFilter::Debug,
        4 => LevelFilter::Trace,
        _ => LevelFilter::Info, // Default to Info for unexpected values
    }
}

// Add a new function to handle mode execution
pub async fn execute_mode(mode: Mode, args: types::Args) -> Result<(), FluereError> {
    match mode {
        Mode::Online => net::capture::run(args).await?,
        Mode::Offline => net::convert::run(args).await?,
        Mode::Live => net::capture_tui::run(args).await?,
        Mode::Pcap => net::write_pcap(args).await?,
    }
    Ok(())
}

/// Send diagnostics to stderr, leaving stdout for what a command produces.
///
/// They went to stdout, which is the wrong stream for them: `fluere devices`
/// writes its list there, and anything piping or redirecting a command's
/// output should get that output rather than a running commentary beside it.
pub fn setup_logging(verbose: u8) -> Result<(), FluereError> {
    let logger = logger::Logger::new(
        None,
        Some(Level::Trace),
        Some(logger::Logstdout::StdErr),
        false,
    );
    let filter = get_log_level(verbose);

    log::set_boxed_logger(Box::new(logger))
        .map(|()| log::set_max_level(filter))
        .map_err(|e| ConfigError::Config(format!("Failed to setup logger: {e}")).into())
}
