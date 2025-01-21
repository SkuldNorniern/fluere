use log::debug;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ports {
    pub source: u16,
    pub dest: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Udp {
    pub ports: Ports,
    pub length: u16,
    pub checksum: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tcp {
    pub ports: Ports,
    pub length: u16,
    pub checksum: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Protocol {
    // IANA assigned protocol numbers
    HOPOPT = 0,  // IPv6 Hop-by-Hop Option
    ICMP = 1,    // Internet Control Message Protocol
    IGMP = 2,    // Internet Group Management Protocol
    GGP = 3,     // Gateway-to-Gateway Protocol
    IPV4 = 4,    // IPv4 encapsulation
    TCP = 6,     // Transmission Control Protocol
    UDP = 17,    // User Datagram Protocol
    SFTP = 22,   // SSH File Transfer Protocol
    GRE = 47,    // Generic Routing Encapsulation
    ESP = 50,    // Encapsulating Security Payload
    AH = 51,     // Authentication Header
    DNS = 53,    // Domain Name System
    ICMPV6 = 58, // ICMPv6
    NoNxt = 59,  // No Next Header for IPv6
    EIGRP = 72,  // Enhanced Interior Gateway Routing Protocol
    OSPF = 82,   // Open Shortest Path First
    VRRP = 112,  // Virtual Router Redundancy Protocol
    L2TP = 115,  // Layer Two Tunneling Protocol
    SCTP = 132,  // Stream Control Transmission Protocol
    // Additional protocols from logs
    VXLAN = 187,    // Virtual Extensible LAN
    PIM = 192,      // Protocol Independent Multicast
    MOBILITY = 231, // IP Mobility (Min Encap)
    // Keep Unknown as last
    Unknown = 255,
}

impl Protocol {
    pub fn from_u8(num: u8) -> Self {
        match num {
            0 => Protocol::HOPOPT,
            1 => Protocol::ICMP,
            2 => Protocol::IGMP,
            3 => Protocol::GGP,
            4 => Protocol::IPV4,
            6 => Protocol::TCP,
            17 => Protocol::UDP,
            22 => Protocol::SFTP,
            47 => Protocol::GRE,
            50 => Protocol::ESP,
            51 => Protocol::AH,
            53 => Protocol::DNS,
            58 => Protocol::ICMPV6,
            59 => Protocol::NoNxt,
            72 => Protocol::EIGRP,
            82 => Protocol::OSPF,
            112 => Protocol::VRRP,
            115 => Protocol::L2TP,
            132 => Protocol::SCTP,
            187 => Protocol::VXLAN,
            192 => Protocol::PIM,
            231 => Protocol::MOBILITY,
            _ => {
                debug!("Unknown protocol number: {}", num);
                Protocol::Unknown
            }
        }
    }

    pub fn as_u8(&self) -> u8 {
        *self as u8
    }

    pub fn get_default_ports(&self) -> Option<(u16, u16)> {
        match self {
            Protocol::SFTP => Some((22, 22)),
            Protocol::DNS => Some((53, 53)),
            Protocol::EIGRP => Some((7, 7)),
            Protocol::OSPF => Some((89, 89)),
            Protocol::VRRP => Some((112, 112)),
            Protocol::VXLAN => Some((4789, 4789)),
            Protocol::PIM => Some((0, 0)),
            Protocol::MOBILITY => Some((0, 0)),
            _ => None,
        }
    }
}

impl From<u8> for Protocol {
    fn from(num: u8) -> Self {
        Protocol::from_u8(num)
    }
}
