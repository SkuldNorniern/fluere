#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
    Ipv4,
    Ipv6,
    Arp,
    Rarp,
    Lldp,
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
            0x0800 => Self::Ipv4,
            0x86DD => Self::Ipv6,
            0x0806 => Self::Arp,
            0x8035 => Self::Rarp,
            0x88CC => Self::Lldp,
            other => Self::Other(other),
        }
    }
}
