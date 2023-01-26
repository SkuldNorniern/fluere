pub mod net;
pub mod utils;

use clap::{Arg, ArgAction, Command};
use std::process::exit;

fn cli() -> Command {
    Command::new("fluere")
        .version("0.2.2")
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
                ),
        )
        .subcommand(
            Command::new("pcap")
                .about("collect pcket and save to .pcap file")
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
                    Arg::new("list")
                        //.about("List of network interfaces")
                        .short('l')
                        .long("list")
                        .action(ArgAction::SetTrue),
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
            println!("Interface {} selected", interface);
            //net::packet_capture(interface);
            net::online_fluereflow::packet_capture(csv, interface, duration, interval, timeout)
                .await;
            //net::netflow(_interface);
        }
        Some(("offline", args)) => {
            println!("Offline mode");
            let file = args.get_one::<String>("file").unwrap();
            let csv = args.get_one::<String>("csv").unwrap();
            let timeout = args.get_one::<String>("timeout").unwrap();
            let timeout: u32 = timeout.parse().unwrap();

            net::fluereflow_fileparse(csv, file, timeout).await;
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

            let interface = args.get_one::<String>("interface").unwrap();
            let duration = args.get_one::<String>("duration").expect("default");
            let duration: i32 = duration.parse().unwrap();
            println!("Interface {} selected", interface);

            net::pcap_capture(interface, duration);
        }
        _ => {
            println!("No mode selected");
            exit(0);
        }
    }
}
