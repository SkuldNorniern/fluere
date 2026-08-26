use std::net::IpAddr;

use crate::net::types::{Encapsulation, MacAddress, VlanTags};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct Key {
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
    pub protocol: u8,
    pub src_mac: MacAddress,
    pub dst_mac: MacAddress,
    /// The VLAN segment this flow arrived on. Untagged frames carry none.
    ///
    /// Part of flow identity because a VLAN is its own broadcast domain, and
    /// separate domains reuse addresses freely.
    pub vlan: VlanTags,
    /// The tunnel this flow arrived inside, when it arrived inside one.
    ///
    /// Part of flow identity because inner addresses alone do not identify a
    /// flow: overlapping private ranges in different tunnels would otherwise
    /// share one record.
    pub encapsulation: Option<Encapsulation>,
}
impl Key {
    pub fn mac_defaultate(&mut self) {
        self.src_mac = MacAddress::new([0, 0, 0, 0, 0, 0]);
        self.dst_mac = MacAddress::new([0, 0, 0, 0, 0, 0]);
    }
}
