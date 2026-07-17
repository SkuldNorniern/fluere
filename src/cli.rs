use std::str::FromStr;

use crate::{
    ConfigError,
    types::{Args, Files, Parameters},
};

use clap::{Arg, ArgAction, ArgMatches, Command};
use pcap::Device;

// This function sets up the command line interface for the application using the clap library.
// It defines the available commands and their arguments.
pub fn cli_template() -> Command {
    Command::new("fluere")
        .version("0.7.0")
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
                        .required_unless_present("list")
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
                    Arg::new("use_ipv6")
                        .help("support ipv6 [default: false]")
                        .short('6')
                        .long("ipv6")
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
                        .default_value("2")
                        .short('v')
                        .long("verbose"), // 0: Error, 1: Warning, 2: Info, 3: Debug 4: Trace
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
                    Arg::new("use_ipv6")
                        .help("support ipv6 [default: false]")
                        .short('6')
                        .long("ipv6")
                        .action(ArgAction::SetTrue),
                )
                .arg(
                    Arg::new("verbose")
                        .help("Set verbosity level")
                        .default_value("2")
                        .short('v')
                        .long("verbose"), // 0: Error, 1: Warning, 2: Info, 3: Debug 4: Trace
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
                        .required_unless_present("list")
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
                    Arg::new("use_ipv6")
                        .help("support ipv6 [default: false]")
                        .short('6')
                        .long("ipv6")
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
                        .default_value("2")
                        .short('v')
                        .long("verbose"), // 0: Error, 1: Warning, 2: Info, 3: Debug 4: Trace
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
                        .required_unless_present("list")
                )
                .arg(
                    Arg::new("interface")
                        .help("Select network interface to use [Required]")
                        .short('i')
                        .long("interface")
                        .required_unless_present("list")
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
                        .default_value("2")
                        .short('v')
                        .long("verbose"), // 0: Error, 1: Warn, 2: Info, 3: Debug, 4: Trace
                ),
        )
}

pub async fn handle_mode(mode: &str, args: &ArgMatches) -> Result<Option<(Args, u8)>, ConfigError> {
    let verbose = match args.get_one::<String>("verbose") {
        Some(value) => parse_value("verbose", value)?,
        None => 0,
    };

    if mode != "offline" && args.get_flag("list") {
        println!("List of network interfaces");
        println!("--------------------------");
        let devices = Device::list().map_err(|error| {
            ConfigError::Argument(format!("Failed to list network devices: {}", error))
        })?;
        for (i, device) in devices.iter().enumerate() {
            print!("[{}] {:25}", i, device.name);
            let description = &device.desc;
            if let Some(desc) = description {
                print!(" - {}", desc);
            }
            println!();
        }
        return Ok(None);
    }

    let arg_data = match mode {
        "online" | "live" => parse_online_live_args(args, mode)?,
        "offline" => parse_offline_args(args)?,
        "pcap" => parse_pcap_args(args)?,
        _ => {
            return Err(ConfigError::Argument(format!(
                "Unsupported capture mode: {}",
                mode
            )));
        }
    };

    Ok(Some((arg_data, verbose)))
}

fn required_string(
    args: &ArgMatches,
    name: &str,
    missing_message: &str,
) -> Result<String, ConfigError> {
    args.get_one::<String>(name)
        .cloned()
        .ok_or_else(|| ConfigError::Missing(missing_message.to_string()))
}

fn parse_value<T>(field: &str, value: &str) -> Result<T, ConfigError>
where
    T: FromStr,
{
    value.parse::<T>().map_err(|_| ConfigError::InvalidValue {
        field: field.to_string(),
        value: value.to_string(),
    })
}

fn required_value<T>(args: &ArgMatches, name: &str, missing_message: &str) -> Result<T, ConfigError>
where
    T: FromStr,
{
    let value = args
        .get_one::<String>(name)
        .ok_or_else(|| ConfigError::Missing(missing_message.to_string()))?;
    parse_value(name, value)
}

fn parse_online_live_args(args: &clap::ArgMatches, _mode: &str) -> Result<Args, ConfigError> {
    let use_mac = args.get_flag("useMACaddress");
    let csv = required_string(args, "csv", "CSV file not specified")?;
    let interface = required_string(args, "interface", "Network interface not specified")?;
    let timeout = required_value(args, "timeout", "Timeout argument missing")?;
    let duration = required_value(args, "duration", "Duration argument missing")?;
    let interval = required_value(args, "interval", "Interval argument missing")?;
    let sleep_windows = required_value(args, "sleep_windows", "Sleep windows argument missing")?;

    Ok(Args::new(
        Some(interface),
        Files::new(Some(csv), None, None),
        Parameters::new(
            Some(use_mac),
            Some(timeout),
            Some(duration),
            Some(interval),
            Some(sleep_windows),
        ),
        // Some(verbose),
    ))
}
fn parse_offline_args(args: &clap::ArgMatches) -> Result<Args, ConfigError> {
    let use_mac = args.get_flag("useMACaddress");
    let _use_ipv6 = args.get_flag("use_ipv6");
    let file = required_string(args, "file", "File not specified")?;
    let csv = required_string(args, "csv", "CSV file not specified")?;
    let timeout = required_value(args, "timeout", "Timeout argument missing")?;

    Ok(Args::new(
        None,
        Files::new(Some(csv), Some(file), None),
        Parameters::new(Some(use_mac), Some(timeout), None, None, None),
        // Some(verbose),
    ))
}
fn parse_pcap_args(args: &clap::ArgMatches) -> Result<Args, ConfigError> {
    let pcap = required_string(args, "pcap", "Output PCAP file name not specified")?;
    let interface = required_string(args, "interface", "Network interface not specified")?;
    let duration = required_value(args, "duration", "Duration argument missing")?;
    let interval = required_value(args, "interval", "Interval argument missing")?;
    let sleep_windows = required_value(args, "sleep_windows", "Sleep windows argument missing")?;

    Ok(Args::new(
        Some(interface),
        Files::new(None, None, Some(pcap)),
        Parameters::new(
            None,
            None,
            Some(duration),
            Some(interval),
            Some(sleep_windows),
        ),
        // Some(verbose),
    ))
}
