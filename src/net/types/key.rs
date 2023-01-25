use std::net::Ipv4Addr;

use crate::net::types::MacAddress;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Key {
    pub src_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_ip: Ipv4Addr,
    pub dst_port: u16,
    pub protocol: u8,
    pub src_mac: MacAddress,
    pub dst_mac: MacAddress,
}
