use std::process::exit;

use crate::types::{Args, Files, Parameters};

use clap::{Arg, ArgAction, ArgMatches, Command};
use pcap::Device;

// This function sets up the command line interface for the application using the clap library.
// It defines the available commands and their arguments.
pub fn cli_template() -> Command {
    Command::new("fluere")
        .version("0.6.2")
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

pub async fn handle_mode(mode: &str, args: &ArgMatches) -> Args {
    let _verbose = args
        .get_one::<String>("verbose")
        .map_or(0, |v| v.parse::<u8>().unwrap_or(0));
    if args.get_flag("list") {
        println!("List of network interfaces");
        println!("--------------------------");
        for (i, device) in Device::list().unwrap().iter().enumerate() {
            println!("[{}] {}", i, device.name);
        }
        exit(0);
    }

    match mode {
        "online" | "live" => parse_online_live_args(args, mode),
        "offline" => parse_offline_args(args),
        "pcap" => parse_pcap_args(args),
        _ => unreachable!(),
    }
}

fn parse_online_live_args(args: &clap::ArgMatches, _mode: &str) -> Args {
    let use_mac = args.get_flag("useMACaddress");
    let csv = args
        .get_one::<String>("csv")
        .expect("CSV file not specified")
        .to_string();
    let interface = args
        .get_one::<String>("interface")
        .expect("Network interface not specified")
        .to_string();
    let timeout = args
        .get_one::<String>("timeout")
        .unwrap()
        .parse::<u64>()
        .unwrap();
    let duration = args
        .get_one::<String>("duration")
        .unwrap()
        .parse::<u64>()
        .unwrap();
    let interval = args
        .get_one::<String>("interval")
        .unwrap()
        .parse::<u64>()
        .unwrap();
    let sleep_windows = args
        .get_one::<String>("sleep_windows")
        .unwrap()
        .parse::<u64>()
        .unwrap();
    let verbose = args
        .get_one::<String>("verbose")
        .unwrap()
        .parse::<u8>()
        .unwrap();

    Args::new(
        Some(interface),
        Files::new(Some(csv), None, None),
        Parameters::new(
            Some(use_mac),
            Some(timeout),
            Some(duration),
            Some(interval),
            Some(sleep_windows),
        ),
        Some(verbose),
    )
}
fn parse_offline_args(args: &clap::ArgMatches) -> Args {
    let use_mac = args.get_flag("useMACaddress");
    let file = args
        .get_one::<String>("file")
        .expect("File not specified")
        .to_string();
    let csv = args.get_one::<String>("csv").unwrap().to_string();
    let timeout = args
        .get_one::<String>("timeout")
        .unwrap()
        .parse::<u64>()
        .unwrap();
    let verbose = args
        .get_one::<String>("verbose")
        .unwrap()
        .parse::<u8>()
        .unwrap();

    Args::new(
        None,
        Files::new(Some(csv), Some(file), None),
        Parameters::new(Some(use_mac), Some(timeout), None, None, None),
        Some(verbose),
    )
}
fn parse_pcap_args(args: &clap::ArgMatches) -> Args {
    let pcap = args
        .get_one::<String>("pcap")
        .expect("Output PCAP file name not specified")
        .to_string();
    let interface = args
        .get_one::<String>("interface")
        .expect("Network interface not specified")
        .to_string();
    let duration = args
        .get_one::<String>("duration")
        .unwrap()
        .parse::<u64>()
        .unwrap();
    let interval = args
        .get_one::<String>("interval")
        .unwrap()
        .parse::<u64>()
        .unwrap();
    let sleep_windows = args
        .get_one::<String>("sleep_windows")
        .unwrap()
        .parse::<u64>()
        .unwrap();
    let verbose = args
        .get_one::<String>("verbose")
        .unwrap()
        .parse::<u8>()
        .unwrap();

    Args::new(
        Some(interface),
        Files::new(None, None, Some(pcap)),
        Parameters::new(
            None,
            None,
            Some(duration),
            Some(interval),
            Some(sleep_windows),
        ),
        Some(verbose),
    )
}
