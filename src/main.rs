pub mod net;
pub mod utils;
pub mod config;

use clap::{Arg, ArgAction, Command};
use net::list_interface_names;
use std::process::exit;

fn cli() -> Command {
    Command::new("fluere")
        .version("0.3.1")
        .author("Skuld Norniern. <skuldnorniern@gmail.com>")
        .about("Netflow Capture Tool")
        .subcommand_required(true)
        .subcommand(
            Command::new("online")
                .about("Capture netflow online")
                .arg(
                    Arg::new("csv")
                        //.about("name of the exported csv file")
                        .short('c')
                        .long("csv"),
                )
                .arg(
                    Arg::new("interface")
                        //.about("Select network interface to use")
                        .short('i')
                        .long("interface"),
                )
                .arg(
                    Arg::new("duration")
                        //.about("Select network interface to use")
                        .default_value("0")
                        .short('d')
                        .long("duration"),
                )
                .arg(
                    Arg::new("timeout")
                        //.about("Select network interface to use")
                        .default_value("600000")
                        .short('t')
                        .long("timeout"),
                )
                .arg(
                    Arg::new("interval")
                        //.about("Select network interface to use")
                        .default_value("1800000")
                        .short('I')
                        .long("interval"),
                )
                .arg(
                    Arg::new("sleep_windows")
                        //.about("Select network interface to use")
                        .default_value("10")
                        .short('s')
                        .long("sleep"),
                )
                .arg(
                    Arg::new("verbose")
                        //.about("List of network interfaces")
                        .default_value("1")
                        .short('v')
                        .long("verbose"), // 0: quiet, 1: normal,2: extended, 3: verbose
                )
                .arg(
                    Arg::new("list")
                        //.about("List of network interfaces")
                        .short('l')
                        .long("list")
                        .action(ArgAction::SetTrue),
                ),
        )
        .subcommand(
            Command::new("offline")
                .about("convet pcap files to netflow")
                .arg(
                    Arg::new("file")
                        //.about("name of the pcap file")
                        .short('f')
                        .long("file"),
                )
                .arg(
                    Arg::new("csv")
                        //.about("name of the exported csv file")
                        .short('c')
                        .long("csv"),
                )
                .arg(
                    Arg::new("timeout")
                        //.about("Select network interface to use")
                        .default_value("600000")
                        .short('t')
                        .long("timeout"),
                )
                .arg(
                    Arg::new("verbose")
                        //.about("List of network interfaces")
                        .default_value("1")
                        .short('v')
                        .long("verbose"), // 0: quiet, 1: normal,2: extended, 3: verbose
                ),
        )
        .subcommand(
            Command::new("pcap")
                .about("collect pcket and save to .pcap file")
                .arg(
                    Arg::new("pcap")
                        //.about("name of the exported csv file")
                        .short('p')
                        .long("pcap"),
                )
                .arg(
                    Arg::new("interface")
                        //.about("Select network interface to use")
                        .short('i')
                        .long("interface"),
                )
                .arg(
                    Arg::new("duration")
                        //.about("Select network interface to use")
                        .default_value("0")
                        .short('d')
                        .long("duration"),
                )
                .arg(
                    Arg::new("interval")
                        //.about("Select network interface to use")
                        .default_value("1800000")
                        .short('I')
                        .long("interval"),
                )
                .arg(
                    Arg::new("sleep_windows")
                        //.about("Select network interface to use")
                        .default_value("10")
                        .short('s')
                        .long("sleep"),
                )
                .arg(
                    Arg::new("list")
                        //.about("List of network interfaces")
                        .short('l')
                        .long("list")
                        .action(ArgAction::SetTrue),
                )
                .arg(
                    Arg::new("verbose")
                        //.about("List of network interfaces")
                        .default_value("1")
                        .short('v')
                        .long("verbose"), // 0: quiet, 1: normal,2: extended, 3: verbose
                ),
        )
}

#[tokio::main]
async fn main() {
    let args = cli().get_matches();
    let _interfaces = net::list_interfaces();
    //let mut interface = "None";
    match args.subcommand() {
        Some(("online", args)) => {
            println!("Online mode");
            if args.get_flag("list") {
                println!("List of interfaces");
                for (i, interface) in _interfaces.iter().enumerate() {
                    println!("[{}]: {}", i, interface.name);
                }

                exit(0);
            }
            let csv = args.get_one::<String>("csv").unwrap();
            let interface = args.get_one::<String>("interface").unwrap();
            let timeout = args.get_one::<String>("timeout").unwrap();
            let timeout: u32 = timeout.parse().unwrap();
            let duration = args.get_one::<String>("duration").expect("default");
            let duration: u64 = duration.parse().unwrap();
            let interval = args.get_one::<String>("interval").expect("default");
            let interval: u64 = interval.parse().unwrap();
            let sleep_windows = args.get_one::<String>("sleep_windows").expect("default");
            let sleep_windows: u64 = sleep_windows.parse().unwrap();
            let verbose = args.get_one::<String>("verbose").expect("default");
            let verbose: u8 = verbose.parse().unwrap();

            if verbose >= 1 {
                println!("Interface {} selected", interface);
            } //net::packet_capture(interface);
            net::online_fluereflow::packet_capture(
                csv,
                interface,
                duration,
                interval,
                timeout,
                sleep_windows,
                verbose,
            )
            .await;
            //net::netflow(_interface);
        }
        Some(("offline", args)) => {
            println!("Offline mode");
            let file = args.get_one::<String>("file").unwrap();
            let csv = args.get_one::<String>("csv").unwrap();
            let timeout = args.get_one::<String>("timeout").unwrap();
            let timeout: u32 = timeout.parse().unwrap();
            let verbose = args.get_one::<String>("verbose").expect("default");
            let verbose: u8 = verbose.parse().unwrap();

            net::fluereflow_fileparse(csv, file, timeout, verbose).await;
            //net::netflow(_file, _csv);
        }
        Some(("pcap", args)) => {
            println!("Pcap mode");
            if args.get_flag("list") {
                println!("List of interfaces");
                for (i, interface) in _interfaces.iter().enumerate() {
                    println!("[{}]: {}", i, interface.name);
                }

                exit(0);
            }

            let pcap = args.get_one::<String>("pcap").unwrap();
            let interface = args.get_one::<String>("interface").unwrap();
            let duration = args.get_one::<String>("duration").expect("default");
            let duration: u64 = duration.parse().unwrap();
            let interval = args.get_one::<String>("interval").expect("default");
            let interval: u64 = interval.parse().unwrap();
            let sleep_windows = args.get_one::<String>("sleep_windows").expect("default");
            let sleep_windows: u64 = sleep_windows.parse().unwrap();
            let verbose = args.get_one::<String>("verbose").expect("default");
            let verbose: u8 = verbose.parse().unwrap();

            if verbose >= 1 {
                println!("Interface {interface} selected");
            }

            net::pcap_capture(pcap, interface, duration, interval, sleep_windows, verbose).await;
        }
        _ => {
            println!("No mode selected");
            exit(0);
        }
    }
}
