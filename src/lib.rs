mod error;
pub mod cli;
pub mod logger;
pub mod net;
pub mod types;
pub mod utils;

pub use error::FluereError;
use log::{Level, LevelFilter};

// Move Mode enum and its implementations to lib
#[derive(Debug)]
pub enum Mode {
    Offline,
    Online,
    Live,
    Pcap,
}

impl TryFrom<&str> for Mode {
    type Error = FluereError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        match s {
            "offline" => Ok(Mode::Offline),
            "online" => Ok(Mode::Online),
            "live" => Ok(Mode::Live),
            "pcap" => Ok(Mode::Pcap),
            _ => Err(FluereError::ConfigError(format!("Invalid mode: {}", s))),
        }
    }
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
        Mode::Online => net::online_fluereflow::packet_capture(args).await?,
        Mode::Offline => net::fluereflow_fileparse(args).await?,
        Mode::Live => net::live_fluereflow::packet_capture(args).await?,
        Mode::Pcap => net::pcap_capture(args).await,
    }
    Ok(())
}

// Add a function to setup logging
pub fn setup_logging(verbose: u8) -> Result<(), FluereError> {
    let logger = logger::Logger::new(
        None,
        Some(Level::Trace),
        Some(logger::Logstdout::Stdout),
        false,
    );
    let filter = get_log_level(verbose);
    
    log::set_boxed_logger(Box::new(logger))
        .map(|()| log::set_max_level(filter))
        .map_err(|e| FluereError::ConfigError(format!("Failed to setup logger: {}", e)))
}
