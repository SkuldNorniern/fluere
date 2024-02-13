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

use pnet::datalink;
// use env_logger::{init, Logger};
use log::Level;

use crate::logger::Logger;
use crate::net::list_devices;

use std::fmt::Display;
use std::process::exit;

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
}

// This is the main function of the application.
// It gets the command line arguments, parses them, and calls the appropriate functions based on the arguments.
#[tokio::main]
async fn main() {
    let args = cli::cli_template().get_matches();
    let interfaces = datalink::interfaces(); //let _plugins = scan_plugins("plugins");
                                             //println!("Plugins: {:?}", plugins);
                                             //match generate_config() {
                                             //    Ok(_) => println!("Config file generated"),
                                             //    Err(e) => println!("Error: {e}"),
                                             //}
                                             //let mut interface = "None";
    match args.subcommand() {
        Some(("online", args)) => {
            println!("Online mode");
            utils::get_local_ip();
            if args.get_flag("list") {
                let interfaces = list_devices().unwrap();
                println!("Found {} devices", interfaces.len());
                for (i, interface) in interfaces.iter().enumerate() {
                    println!("[{}]: {}", i, interface.name);
                }
                exit(0);
            }
            let use_mac = args.get_flag("useMACaddress");
            let csv = args.get_one::<String>("csv").expect("default");
            let interface = args
                .get_one::<String>("interface")
                .ok_or("Required Interface")
                .unwrap();

            let timeout = args.get_one::<String>("timeout").unwrap();
            let timeout: u64 = timeout.parse().unwrap();
            let duration = args.get_one::<String>("duration").expect("default");
            let duration: u64 = duration.parse().unwrap();
            let interval = args.get_one::<String>("interval").expect("default");
            let interval: u64 = interval.parse().unwrap();
            let sleep_windows = args.get_one::<String>("sleep_windows").expect("default");
            let sleep_windows: u64 = sleep_windows.parse().unwrap();
            let verbose = args.get_one::<String>("verbose").expect("default");
            let verbose: u8 = verbose.parse().unwrap();

            let args: types::Args = types::Args::new(
                Some(interface.to_string()),
                types::Files::new(Some(csv.to_string()), None, None),
                types::Parameters::new(
                    Some(use_mac),
                    Some(timeout),
                    Some(duration),
                    Some(interval),
                    Some(sleep_windows),
                ),
                Some(verbose),
            );
            if verbose >= 1 {
                println!("Interface {} selected", interface);
            } //net::packet_capture(interface);
            net::online_fluereflow::packet_capture(args).await;
            //net::netflow(_interface);
        }
        Some(("offline", args)) => {
            println!("Offline mode");
            let use_mac = args.get_flag("useMACaddress");
            let file = args.get_one::<String>("file").unwrap();
            let csv = args.get_one::<String>("csv").expect("default");
            let timeout = args.get_one::<String>("timeout").unwrap();
            let timeout: u64 = timeout.parse().unwrap();
            let verbose = args.get_one::<String>("verbose").expect("default");
            let verbose: u8 = verbose.parse().unwrap();

            let args: types::Args = types::Args::new(
                None,
                types::Files::new(Some(csv.to_string()), Some(file.to_string()), None),
                types::Parameters::new(Some(use_mac), Some(timeout), None, None, None),
                Some(verbose),
            );

            net::fluereflow_fileparse(args).await;
            //net::netflow(_file, _csv);
        }
        Some(("live", args)) => {
            println!("Live mode");
            if args.get_flag("list") {
                let interfaces = list_devices().unwrap();
                println!("Found {} devices", interfaces.len());
                for (i, interface) in interfaces.iter().enumerate() {
                    println!("[{}]: {}", i, interface.name);
                }
                exit(0);
            }
            let use_mac = args.get_flag("useMACaddress");
            let csv = args.get_one::<String>("csv").expect("default");
            let interface = args
                .get_one::<String>("interface")
                .ok_or("Required Interface")
                .unwrap();

            let timeout = args.get_one::<String>("timeout").unwrap();
            let timeout: u64 = timeout.parse().unwrap();
            let duration = args.get_one::<String>("duration").expect("default");
            let duration: u64 = duration.parse().unwrap();
            let interval = args.get_one::<String>("interval").expect("default");
            let interval: u64 = interval.parse().unwrap();
            let sleep_windows = args.get_one::<String>("sleep_windows").expect("default");
            let sleep_windows: u64 = sleep_windows.parse().unwrap();
            let verbose = args.get_one::<String>("verbose").expect("default");
            let verbose: u8 = verbose.parse().unwrap();

            let args: types::Args = types::Args::new(
                Some(interface.to_string()),
                types::Files::new(Some(csv.to_string()), None, None),
                types::Parameters::new(
                    Some(use_mac),
                    Some(timeout),
                    Some(duration),
                    Some(interval),
                    Some(sleep_windows),
                ),
                Some(verbose),
            );
            if verbose >= 1 {
                println!("Interface {} selected", interface);
            } //net::packet_capture(interface);
            net::live_fluereflow::packet_capture(args)
                .await
                .expect("Error on live mode");
            //net::netflow(_interface);
        }
        Some(("pcap", args)) => {
            println!("Pcap mode");
            if args.get_flag("list") {
                println!("List of interfaces");
                for (i, interface) in interfaces.iter().enumerate() {
                    println!("[{}]: {}", i, interface.name);
                }

                exit(0);
            }

            let pcap = args
                .get_one::<String>("pcap")
                .ok_or("Required output pcap file name")
                .unwrap();
            let interface = args
                .get_one::<String>("interface")
                .ok_or("Required Interface")
                .unwrap();
            let duration = args.get_one::<String>("duration").expect("default");
            let duration: u64 = duration.parse().unwrap();
            let interval = args.get_one::<String>("interval").expect("default");
            let interval: u64 = interval.parse().unwrap();
            let sleep_windows = args.get_one::<String>("sleep_windows").expect("default");
            let sleep_windows: u64 = sleep_windows.parse().unwrap();
            let verbose = args.get_one::<String>("verbose").expect("default");
            let verbose: u8 = verbose.parse().unwrap();

            let args: types::Args = types::Args::new(
                Some(interface.to_string()),
                types::Files::new(None, None, Some(pcap.to_string())),
                types::Parameters::new(
                    None,
                    None,
                    Some(duration),
                    Some(interval),
                    Some(sleep_windows),
                ),
                Some(verbose),
            );
            if verbose >= 1 {
                println!("Interface {interface} selected");
            }

            net::pcap_capture(args).await;
        }
        _ => {
            println!("No mode selected");
            exit(0);
        }
    }
}
