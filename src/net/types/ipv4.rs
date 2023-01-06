use std::net::Ipv4Addr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IPProtocol {
    ICMP,
    TCP,
    UDP,
    Other(u8),
}

#[derive(Debug)]
pub struct IPv4 {
    pub version: u8,
    pub header_length: u8,
    pub type_of_service: u8,
    pub length: u16,
    pub id: u16,
    pub flags: u8,
    pub fragment_offset: u32,
    pub ttl: u8,
    pub protocol: IPProtocol,
    pub checksum: u16,
    pub source_addr: Ipv4Addr,
    pub dest_addr: Ipv4Addr,
}

impl From<u8> for IPProtocol {
    fn from(raw: u8) -> Self {
        match raw {
            1 => IPProtocol::ICMP,
            6 => IPProtocol::TCP,
            17 => IPProtocol::UDP,
            other => IPProtocol::Other(other),
        }
    }
}
