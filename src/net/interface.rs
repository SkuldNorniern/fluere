extern crate pcap;
use pcap::Device;
use pnet::datalink::{self, NetworkInterface};
use std::time::Instant;

pub fn get_interface(device_name: &str) -> Device {
    let start = Instant::now();
    println!("Requested Device : {}", device_name);
    let mut selected_device: Device = Device::lookup().unwrap().unwrap();
    let devices = Device::list();

    // Begin
    match devices {
        Ok(vec_devices) => {
            for device in vec_devices {
                if &*device.name == device_name {
                    selected_device = device.clone();
                    let duration = start.elapsed();
                    println!(
                        "-{} device has been captured! in {:?}",
                        device_name, duration
                    );
                };
            }
        }
        Err(_) => {
            println!("No devices found...");
            std::process::exit(1);
        }
    }

    selected_device
}

pub fn get_default_interface(interfaces: Vec<NetworkInterface>) -> String {
    for interface in interfaces {
        if interface.is_loopback() || !interface.is_up() || interface.mac.is_none() {
            continue;
        } else {
            return interface.name;
        }
    }
    panic!("No valid interfaces")
}

pub fn get_default_interface_name(interfaces: &[NetworkInterface]) -> String {
    interfaces
        .iter()
        .find(|interface| {
            if interface.mac.is_none() || !interface.is_up() || interface.is_loopback() {
                return false;
            }
            true
        })
        .unwrap_or_else(|| panic!("No valid interfaces"))
        .name
        .clone()
}

pub fn list_interfaces() -> Vec<NetworkInterface> {
    datalink::interfaces()
}
pub fn list_interface_names(){
    let interfaces = Device::list();
    /*let mut interface_names: Vec<String> = Vec::new();
    for interface in interfaces {
        interface_names.push(interface.);
    }
    interface_names*/
    for interface in interfaces.unwrap() {
        println!("{:?}", interface);
    }
}
