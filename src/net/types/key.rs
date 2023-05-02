use std::net::IpAddr;

use crate::net::types::MacAddress;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Key {
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
    pub protocol: u8,
    pub src_mac: MacAddress,
    pub dst_mac: MacAddress,
}
impl Key {
    pub fn mac_defaultate(&mut self) {
        self.src_mac = MacAddress::new([0, 0, 0, 0, 0, 0]);
        self.dst_mac = MacAddress::new([0, 0, 0, 0, 0, 0]);
    }
}
