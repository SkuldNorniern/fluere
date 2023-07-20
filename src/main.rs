pub mod config;
pub mod net;
pub mod plugin;
pub mod utils;

use clap::{Arg, ArgAction, Command};


use std::process::exit;

fn cli() -> Command {
    Command::new("fluere")
        .version("0.5.1")
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

#[tokio::main]
async fn main() {
    let args = cli().get_matches();
    let interfaces = net::list_interfaces();
    //let _plugins = scan_plugins("plugins");
    //println!("Plugins: {:?}", plugins);
    //match generate_config() {
    //    Ok(_) => println!("Config file generated"),
    //    Err(e) => println!("Error: {e}"),
    //}
    //let mut interface = "None";
    match args.subcommand() {
        Some(("online", args)) => {
            println!("Online mode");
            if args.get_flag("list") {
                println!("List of interfaces");
                for (i, interface) in interfaces.iter().enumerate() {
                    println!("[{}]: {}", i, interface.name);
                }

                exit(0);
            }
            let use_mac = args.get_flag("useMACaddress");
            let csv = args.get_one::<String>("csv").expect("default");
            let interface = args.get_one::<String>("interface").ok_or("Required Interface").unwrap();

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

            if verbose >= 1 {
                println!("Interface {} selected", interface);
            } //net::packet_capture(interface);
            net::online_fluereflow::packet_capture(
                csv,
                use_mac,
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
            let use_mac = args.get_flag("useMACaddress");
            let file = args.get_one::<String>("file").unwrap();
            let csv = args.get_one::<String>("csv").expect("default");
            let timeout = args.get_one::<String>("timeout").unwrap();
            let timeout: u32 = timeout.parse().unwrap();
            let verbose = args.get_one::<String>("verbose").expect("default");
            let verbose: u8 = verbose.parse().unwrap();

            net::fluereflow_fileparse(csv, use_mac, file, timeout, verbose).await;
            //net::netflow(_file, _csv);
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

            let pcap = args.get_one::<String>("pcap").ok_or("Required output pcap file name").unwrap();
            let interface = args.get_one::<String>("interface").ok_or("Required Interface").unwrap();
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
