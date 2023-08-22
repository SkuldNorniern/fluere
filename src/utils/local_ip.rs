use if_addrs::get_if_addrs;
use std::io;

pub fn get_local_ip() -> io::Result<String> {
    let interfaces = get_if_addrs()?;
    for interface in interfaces {
        if interface.is_loopback() || !interface.ip().is_ipv4() {
            continue;
        }
        return Ok(interface.ip().to_string());
    }
    Err(io::Error::new(io::ErrorKind::Other, "Failed to retrieve local IP address"))
}

