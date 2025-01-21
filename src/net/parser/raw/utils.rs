use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub fn bytes_to_ipv4(bytes: &[u8]) -> Option<IpAddr> {
    if bytes.len() >= 4 {
        Some(IpAddr::V4(Ipv4Addr::new(
            bytes[0], bytes[1], bytes[2], bytes[3],
        )))
    } else {
        None
    }
}

pub fn bytes_to_ipv6(bytes: &[u8]) -> Option<IpAddr> {
    if bytes.len() >= 16 {
        let mut segments = [0u16; 8];
        for i in 0..8 {
            segments[i] = ((bytes[i * 2] as u16) << 8) | bytes[i * 2 + 1] as u16;
        }
        Some(IpAddr::V6(Ipv6Addr::from(segments)))
    } else {
        None
    }
}
