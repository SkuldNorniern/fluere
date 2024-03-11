// This is the main entry point of the Fluere application.
// Fluere is a versatile tool designed to capture network packets in pcap format and convert them into NetFlow data.
// It also supports live capture and conversion of NetFlow data.
// This file contains the main function which parses the command line arguments and calls the appropriate functions based on the arguments.

pub mod cli;
pub mod logger;
pub mod net;
pub mod plugin;
pub mod types;
pub mod utils;

use std::{fmt::Display, process::exit};
use std::fs::File;

use crate::logger::{Logger, Logstdout};
use crate::net::capture::DeviceError;
// use env_logger;::{init, Logger};

use log::{Level, Log, info, warn, error, debug, trace};


// FEAT:MAYBE: seprate `std` as feature flag for fluere and log crate
static LOGGER: Logger = Logger{write_to_file: false, file: None, write_to_std: Some(Logstdout::Stdout), severity: Level::Info};

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

struct Fluere {
    interface: String,
    args: types::Args,
    mode: Mode,
    logger: Logger,
    verbose: Level,
}
impl Fluere {
    fn new(
        interface: String,
        args: types::Args,
        mode: Mode,
        logger: Logger,
        verbose: Level,
    ) -> Fluere {
        Fluere {
            interface,
            args,
            mode,
            logger,
            verbose,
        }
    }
    async fn online_fluereflow(&self, params: types::Args) {
        net::online_fluereflow::packet_capture(params).await;
        info!("Online fluereflow mode completed");
    }
}
// This is the main function of the application.
// It gets the command line arguments, parses them, and calls the appropriate functions based on the arguments.
#[tokio::main]
async fn main() {
    let args = cli::cli_template().get_matches();
    let log_stdout = Logstdout::Stdout;
    let log_file :Option<File> = None;
    let log_level = Level::Info;
    let logger = Logger::new(None,Some(Level::Trace), Some(Logstdout::Stdout),false);
    
    let _ =  log::set_boxed_logger(Box::new(logger))
        .map(|()| log::set_max_level(log::LevelFilter::Info));
        // let mode = match args.subcommand() {
        // Some((mode, _sub_args)) => mode,
        // None => {
            // log::error!("No mode selected. Use --help for more information.");
            // exit(1);
        // }
    // };

   info!("Fluere started"); 
    if let Some((mode, sub_args)) = args.subcommand() {
        match mode {
            "online" | "offline" | "live" | "pcap" => {
                log::debug!("Mode: {}", mode);
                let parems = cli::handle_mode(mode, sub_args).await;

                match mode {
                    "online" => net::online_fluereflow::packet_capture(parems).await,
                    "offline" => net::fluereflow_fileparse(parems).await,
                    "live" => net::live_fluereflow::packet_capture(parems)
                        .await
                        .expect("Error on live mode"),
                    "pcap" => net::pcap_capture(parems).await,
                    _ => unreachable!(),
                }
            }

            // Match occures from the CLI side, which make this unreachable
            _ => unreachable!()
        }
    } else {
        exit(0);
    }
}
