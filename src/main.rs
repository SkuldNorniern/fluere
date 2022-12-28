pub mod net;

use clap::{command, Arg, ArgAction};
use std::process::exit;

#[tokio::main] 
async fn main() {
    let _args = command!()
        .version("1.0")
        .author("Skuld Norniern. <skuldnorniern@gmail.com>")
        .about("Netflow Capture Tool")
        .arg(
            Arg::new("list")
                //.about("List of network interfaces")
                .short('l')
                .long("list")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("interface")
                //.about("Select network interface to use")
                .short('i')
                .long("interface")
                .action(ArgAction::Append),
        )
        .get_matches();
    
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
