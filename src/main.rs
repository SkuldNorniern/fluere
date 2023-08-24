// This is the main entry point of the Fluere application.
// Fluere is a versatile tool designed to capture network packets in pcap format and convert them into NetFlow data.
// It also supports live capture and conversion of NetFlow data.
// This file contains the main function which parses the command line arguments and calls the appropriate functions based on the arguments.
pub mod config;
pub mod net;
pub mod plugin;
pub mod types;
pub mod utils;

use clap::{Arg, ArgAction, Command};
use pnet::datalink;

use fluereplugin::PluginManager;

use std::process::exit;

// This function sets up the command line interface for the application using the clap library.
// It defines the available commands and their arguments.
fn cli() -> Command {
    Command::new("fluere")
        .version("0.6.0")
        .author("Skuld Norniern. <skuldnorniern@gmail.com>")
        .about("Netflow Capture Tool")
        .subcommand_required(true)
        .subcommand(
            Command::new("online")
                .about("Capture netflow online")
                .arg(
                    Arg::new("csv")
                        .help("Title of the exported csv file")
                        .short('c')
                        .long("csv")
                        .default_value("output"),
                )
                .arg(
                    Arg::new("list")
                        .help("List of network interfaces")
                        .short('l')
                        .long("list")
                        .action(ArgAction::SetTrue),
                )
                .arg(
                    Arg::new("interface")
                        .help("Select network interface to use [Required]")
                        .short('i')
                        .long("interface")
                        //.required(true),
                )
                .arg(
                    Arg::new("duration")
                        .help("Set capture duration, in milliseconds (0: infinite)")
                        .default_value("0")
                        .short('d')
                        .long("duration"),
                )
                .arg(
                    Arg::new("timeout")
                        .help("Set flow timeout, in milliseconds (0: infinite)")
                        .default_value("600000")
                        .short('t')
                        .long("timeout"),
                )
                .arg(
                    Arg::new("useMACaddress")
                        .help("Set use MAC address on Key value [default: false]")
                        .short('M')
                        .long("useMAC")
                        .action(ArgAction::SetTrue),
                )
                .arg(
                    Arg::new("interval")
                        .help("Set export interval, in milliseconds")
                        .default_value("1800000")
                        .short('I')
                        .long("interval"),
                )
                .arg(
                    Arg::new("sleep_windows")
                        .help("Set inverval of thread pause for (only)MS Windows per n packet (need it for stopping random stop on Windows)")
                        .default_value("10")
                        .short('s')
                        .long("sleep"),
                )
                .arg(
                    Arg::new("verbose")
                        .help("Set verbosity level") 
                        .default_value("1")
                        .short('v')
                        .long("verbose"), // 0: quiet, 1: normal,2: extended, 3: verbose
                ),
        )
        .subcommand(
            Command::new("offline")
                .about("Convet pcap files to netflow")
                .arg(
                    Arg::new("file")
                        .help("Name of the input pcap file [Required]")
                        .short('f')
                        .long("file")
                        .required(true),
                )
                .arg(
                    Arg::new("csv")
                        .help("Title of the exported csv file")
                        .short('c')
                        .long("csv")
                        .default_value("output"),
                )
                .arg(
                    Arg::new("timeout")
                        .help("Set flow timeout, in milliseconds (0: infinite)")
                        .default_value("600000")
                        .short('t')
                        .long("timeout"),
                )
                .arg(
                    Arg::new("useMACaddress")
                        .help("Set use MAC address on Key value [default: false]")
                        .short('M')
                        .long("useMAC")
                        .action(ArgAction::SetTrue),
                )
                .arg(
                    Arg::new("verbose")
                        .help("Set verbosity level")
                        .default_value("1")
                        .short('v')
                        .long("verbose"), // 0: quiet, 1: normal,2: extended, 3: verbose
                ),
        )
        .subcommand(
            Command::new("live")
                .about("Capture netflow online with live TUI feedback")
                .arg(
                    Arg::new("csv")
                        .help("Title of the exported csv file")
                        .short('c')
                        .long("csv")
                        .default_value("output"),
                )
                .arg(
                    Arg::new("list")
                        .help("List of network interfaces")
                        .short('l')
                        .long("list")
                        .action(ArgAction::SetTrue),
                )
                .arg(
                    Arg::new("interface")
                        .help("Select network interface to use [Required]")
                        .short('i')
                        .long("interface")
                        //.required(true),
                )
                .arg(
                    Arg::new("duration")
                        .help("Set capture duration, in milliseconds (0: infinite)")
                        .default_value("0")
                        .short('d')
                        .long("duration"),
                )
                .arg(
                    Arg::new("timeout")
                        .help("Set flow timeout, in milliseconds (0: infinite)")
                        .default_value("600000")
                        .short('t')
                        .long("timeout"),
                )
                .arg(
                    Arg::new("useMACaddress")
                        .help("Set use MAC address on Key value [default: false]")
                        .short('M')
                        .long("useMAC")
                        .action(ArgAction::SetTrue),
                )
                .arg(
                    Arg::new("interval")
                        .help("Set export interval, in milliseconds")
                        .default_value("1800000")
                        .short('I')
                        .long("interval"),
                )
                .arg(
                    Arg::new("sleep_windows")
                        .help("Set inverval of thread pause for (only)MS Windows per n packet (need it for stopping random stop on Windows)")
                        .default_value("10")
                        .short('s')
                        .long("sleep"),
                )
                .arg(
                    Arg::new("verbose")
                        .help("Set verbosity level") 
                        .default_value("1")
                        .short('v')
                        .long("verbose"), // 0: quiet, 1: normal,2: extended, 3: verbose
                ),
        )
        .subcommand(
            Command::new("pcap")
                .about("Collect packet and save to .pcap file")
                .arg(
                    Arg::new("pcap")
                        .help("Name of the output pcap files title [Required]")
                        .short('p')
                        .long("pcap")
                        //.required(true),
                )
                .arg(
                    Arg::new("interface")
                        .help("Select network interface to use [Required]")
                        .short('i')
                        .long("interface")
                        //.required(true),
                )
                .arg(
                    Arg::new("duration")
                        .help("Set capture duration, in milliseconds (0: infinite)")
                        .default_value("0")
                        .short('d')
                        .long("duration"),
                )
                .arg(
                    Arg::new("interval")
                        .help("Set export interval, in milliseconds")
                        .default_value("1800000")
                        .short('I')
                        .long("interval"),
                )
                .arg(
                    Arg::new("sleep_windows")
                        .help("Set inverval of thread pause for (only)MS Windows per n packet (need it for stopping random stop on Windows)")
                        .default_value("10")
                        .short('s')
                        .long("sleep"),
                )
                .arg(
                    Arg::new("list")
                        .help("List of network interfaces")
                        .short('l')
                        .long("list")
                        .action(ArgAction::SetTrue),
                )
                .arg(
                    Arg::new("verbose")
                        .help("Set verbosity level")
                        .default_value("1")
                        .short('v')
                        .long("verbose"), // 0: quiet, 1: normal,2: extended, 3: verbose
                ),
        )
}

// This is the main function of the application.
// It gets the command line arguments, parses them, and calls the appropriate functions based on the arguments.
#[tokio::main]
async fn main() {
    crate::plugin::manager::plugin_setup();
    crate::plugin::manager::plugin_execute();

    let args = cli().get_matches();
    let interfaces = datalink::interfaces();//let _plugins = scan_plugins("plugins");
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
                println!("List of interfaces");
                for iface in interfaces {
                    println!("[{}]: {}", iface.index, iface.name);
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
                println!("List of interfaces");
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
