use std::net;
use std::io;

pub fn get_local_ip() -> io::Result<String> {
    let socket = net::UdpSocket::bind("0.0.0.0:0")?;
    socket.connect("8.8.8.8:80")?;
    let local_ip = socket.local_addr()?;
    Ok(local_ip.to_string())
}

