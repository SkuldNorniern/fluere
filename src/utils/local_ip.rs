use if_addrs::get_if_addrs;
use std::io;
use crate::utils::ip_parser::{parse_subnet, is_ip_in_subnet};

pub fn get_local_ip(subnet: Option<(String, u32)>) -> io::Result<String> {
    let interfaces = get_if_addrs()?;
    for interface in interfaces {
        if interface.is_loopback() || !interface.ip().is_ipv4() {
            continue;
        }
        if let Some(subnet) = subnet {
            if is_ip_in_subnet(&interface.ip().to_string(), subnet) {
                return Ok(interface.ip().to_string());
            }
        } else {
            return Ok(interface.ip().to_string());
        }
    }
    Err(io::Error::new(io::ErrorKind::Other, "Failed to retrieve local IP address"))
}

