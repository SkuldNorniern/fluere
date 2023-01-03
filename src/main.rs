pub mod net;

use clap::{arg,Arg,ArgAction,ArgMatches,Command};
use std::process::exit;

fn cli() -> Command{
    Command::new("fluere")
        .version("1.0")
        .author("Skuld Norniern. <skuldnorniern@gmail.com>")
        .about("Netflow Capture Tool")
        .subcommand_required(true)
        .subcommand(
             Command::new("online")
                .about("Capture netflow online")
                .arg(
                    Arg::new("interface")
                        //.about("Select network interface to use")
                        .short('i')
                        .long("interface")
                )
                .arg(
                    Arg::new("list")
                        //.about("List of network interfaces")
                        .short('l')
                        .long("list")
                        .action(ArgAction::SetTrue),
                )
            
        )
        .subcommand(
            Command::new("offline")
                .about("convet pcap files to netflow")
                .arg(
                    Arg::new("file")
                        //.about("name of the pcap file")
                        .short('f')
                        .long("file")
                )
                .arg(
                    Arg::new("csv")
                        //.about("name of the exported csv file")
                        .short('c')
                        .long("csv")
                )
            )
        .subcommand(
            Command::new("pcap")
                .about("collect pcket and save to .pcap file")
                .arg(
                    Arg::new("interface")
                        //.about("Select network interface to use")
                        .short('i')
                        .long("interface")
                )
                .arg(
                    Arg::new("list")
                        //.about("List of network interfaces")
                        .short('l')
                        .long("list")
                        .action(ArgAction::SetTrue),
                )
            )
        
}

#[tokio::main]
async fn main() {
    let args = cli().get_matches();
    let _interfaces = net::list_interfaces();
    let mut interface = "None";

    match args.subcommand(){
        Some(("online", args)) => {
            println!("Online mode");
            if args.contains_id("interface"){
                println!("Interface {} selected", args.get_one::<String>("interface").unwrap());
                interface = args.get_one::<String>("interface").unwrap()
            }
            if args.contains_id("list"){
                for (i, interface) in _interfaces.iter().enumerate() {
                    println!("[{}]: {}",i ,interface.name);
                }
                //println!("List of interfaces {:?}", _interfaces);
                exit(0);
            }
               //net::netflow(_interface);
        },
        Some(("offline", args)) => {
            println!("Offline mode");
            let _file = args.get_one::<String>("file").unwrap();
            let _csv = args.get_one::<String>("csv").unwrap();
            //net::netflow(_file, _csv);
        },
        Some(("pcap", args)) => {
            println!("Pcap mode");
            if args.contains_id("interface"){
                println!("Interface {} selected", args.get_one::<String>("interface").unwrap());
                interface = args.get_one::<String>("interface").unwrap()
            }
            if args.contains_id("list"){
                for (i, interface) in _interfaces.iter().enumerate() {
                    println!("[{}]: {}",i ,interface.name);
                }
                //println!("List of interfaces {:?}", _interfaces);
                //exit(0);
            }
            
            net::packet_capture(interface);
        },
        _ => {
            println!("No mode selected");
            exit(0);
        }
    }
    /*
    let _interfaces = net::list_interfaces();
    let mut interface = "None";

    //println!("{:?}", _args.;

    if _args.get_one::<bool>("list").unwrap().eq(&true) {
        for (i, interface) in _interfaces.iter().enumerate() {
            println!("[{}]: {}",i ,interface.name);
        }
        exit(0);
        //println!("List of interfaces {:?}", _interfaces);
        //println!("List of network interfaces");
    }

    if _args.contains_id("interface"){
        println!("Interface {} selected", _args.get_one::<String>("interface").unwrap());
        interface = _args.get_one::<String>("interface").unwrap()
    }

    if interface == "None"{
        println!("No interface selected");
        exit(0);
    }
    */
    /*if interface.is_none(){
        let mut flag = 0;
        for iface in _interfaces {
            if iface.is_loopback() || !iface.is_up() || iface.mac.is_none() {
                continue;
            }
            else {
                interface = Some(iface.name.clone()).as_ref();
                flag = 1;
                break;
            }
        }
        if flag == 0 {
            panic!("No valid interfaces")
        }
    }*/

    println!("Interface {:?}", interface);
}
