use pnet::datalink::{self, DataLinkReceiver, NetworkInterface};

pub fn get_default_interface(interfaces: Vec<NetworkInterface>) -> String {
    for interface in interfaces {
        if interface.is_loopback() || !interface.is_up() || interface.mac.is_none() {
            continue;
        }
        else {
            return interface.name
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
