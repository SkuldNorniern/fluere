// This is the main entry point of the Fluere application.
// Fluere is a versatile tool designed to capture network packets in pcap format and convert them into NetFlow data.
// It also supports live capture and conversion of NetFlow data.
// This file contains the main function which parses the command line arguments and calls the appropriate functions based on the arguments.

pub mod cli;
pub mod logger;
pub mod net;
// pub mod plugin;
pub mod types;
pub mod utils;

use std::fs::File;
use std::{fmt::Display, process::exit};

use crate::logger::{Logger, Logstdout};
use crate::net::DeviceError;
// use env_logger;::{init, Logger};

use log::{debug, Level, LevelFilter};

// FEAT:MAYBE: seprate `std` as feature flag for fluere and log crate
// static LOGGER: Logger = Logger {
//     write_to_file: false,
//     file: None,
//     write_to_std: Some(Logstdout::Stdout),
//     severity: Level::Info,
// };

#[derive(Debug)]
enum FluereError {
    InterfaceNotFound,
    DeviceError(DeviceError),
    ArgumentParseError(String),
    ModeNotSupported(String),
    NetworkError(String),
}

impl std::fmt::Display for FluereError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FluereError::InterfaceNotFound => write!(f, "Network interface not found."),
            FluereError::ArgumentParseError(msg) => write!(f, "Argument parsing error: {}", msg),
            FluereError::ModeNotSupported(mode) => write!(f, "Mode not supported: {}", mode),
            FluereError::NetworkError(msg) => write!(f, "Network error: {}", msg),
            FluereError::DeviceError(err) => err.fmt(f),
        }
    }
}

impl std::error::Error for FluereError {}

impl From<DeviceError> for FluereError {
    fn from(err: DeviceError) -> Self {
        FluereError::DeviceError(err)
    }
}

enum Mode {
    Offline,
    Online,
    Live,
    Pcap,
}
impl From<&str> for Mode {
    fn from(s: &str) -> Self {
        match s {
            "offline" => Mode::Offline,
            "online" => Mode::Online,
            "live" => Mode::Live,
            "pcap" => Mode::Pcap,

            // Match occures from the CLI side, which make this unreachable
            _ => unreachable!(),
        }
    }
}
impl Display for Mode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Mode::Offline => write!(f, "Offline"),
            Mode::Online => write!(f, "Online"),
            Mode::Live => write!(f, "Live"),
            Mode::Pcap => write!(f, "Pcap"),
        }
    }
}

fn from_verbose(level: u8) -> LevelFilter {
    match level {
        0 => LevelFilter::Error,
        1 => LevelFilter::Warn,
        2 => LevelFilter::Info,
        3 => LevelFilter::Debug,
        4 => LevelFilter::Trace,
        _ => unreachable!(),
    }
}

// This is the main function of the application.
// It gets the command line arguments, parses them, and calls the appropriate functions based on the arguments.
#[tokio::main]
async fn main() {
    let args = cli::cli_template().get_matches();

    if let Some((mode, sub_args)) = args.subcommand() {
        let mode_type: Mode = Mode::from(mode);
        let parems = cli::handle_mode(mode, sub_args).await;

        let _log_stdout = Logstdout::Stdout;
        let _log_file: Option<File> = None;
        let _log_level = Level::Info;
        let logger = Logger::new(None, Some(Level::Trace), Some(Logstdout::Stdout), false);

        // (Args, u8)
        let filter = from_verbose(parems.1);
        let _ = log::set_boxed_logger(Box::new(logger)).map(|()| log::set_max_level(filter));

        debug!("Fluere started");

        match mode_type {
            Mode::Online => net::online_fluereflow::packet_capture(parems.0).await,
            Mode::Offline => net::fluereflow_fileparse(parems.0).await,
            Mode::Live => net::live_fluereflow::packet_capture(parems.0)
                .await
                .expect("Error on live mode"),
            Mode::Pcap => net::pcap_capture(parems.0).await,
        }
    } else {
        exit(0);
    }
}
