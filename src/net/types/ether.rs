use std::convert::TryFrom;
use std::array::TryFromSliceError;
#[derive(Debug, Clone, Copy,PartialEq,Eq)]
pub struct MacAddress(pub [u8; 6]);

impl MacAddress {
    pub fn new(mac: [u8; 6]) -> Self {
        Self(mac)
    }
}
impl From<&[u8]> for MacAddress {
    fn from(mac: &[u8]) -> Self {
        let mut mac_array = [0; 6];
        mac_array.copy_from_slice(mac);
        MacAddress(mac_array)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EtherProtocol {
    IPv4,
    IPv6,
    ARP,
    RARP,
    LLDP,
    Other(u16),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EtherFrame {
    pub source_mac: MacAddress,
    pub dest_mac: MacAddress,
    pub ether_protocol: EtherProtocol,
}
impl From<u16> for EtherProtocol {
    fn from(raw: u16) -> Self {
        match raw {
            0x0800 => Self::IPv4,
            0x86DD => Self::IPv6,
            0x0806 => Self::ARP,
            0x8035 => Self::RARP,
            0x88CC => Self::LLDP,
            other => Self::Other(other),
        }
    }
}
