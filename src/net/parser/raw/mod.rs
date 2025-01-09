mod gre;
mod esp;
mod ah;
mod pim;
mod igmp;
mod arp;
mod utils;
mod vxlan;
mod mpls;
mod isis;
mod bgp;
mod icmp;
mod sctp;
mod ospf;
mod vrrp;
mod l2tp;

pub use self::{
    gre::parse_gre,
    esp::parse_esp,
    ah::parse_ah,
    pim::parse_pim,
    igmp::parse_igmp,
    arp::parse_arp,
    vxlan::parse_vxlan,
    mpls::parse_mpls,
    isis::parse_isis,
    bgp::parse_bgp,
    icmp::parse_icmp,
    sctp::parse_sctp,
    ospf::parse_ospf,
    vrrp::parse_vrrp,
    l2tp::parse_l2tp,
};

use pnet::packet::{
    tcp::TcpPacket,
    udp::UdpPacket,
    ethernet::EtherTypes,
    Packet,
};

use log::trace;
use std::net::IpAddr;

#[derive(Debug)]
pub struct RawProtocolHeader {
    pub src_ip: Option<IpAddr>,
    pub dst_ip: Option<IpAddr>,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub length: u16,
    pub inner_payload: Option<Vec<u8>>,
}

impl RawProtocolHeader {
    pub fn new(
        src_ip: Option<IpAddr>,
        dst_ip: Option<IpAddr>,
        src_port: u16,
        dst_port: u16,
        protocol: u8,
        length: u16,
        inner_payload: Option<Vec<u8>>,
    ) -> Self {
        Self {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
            length,
            inner_payload,
        }
    }

    pub fn from_tcp(packet: &TcpPacket) -> Self {
        Self {
            src_ip: None,
            dst_ip: None,
            src_port: packet.get_source(),
            dst_port: packet.get_destination(),
            protocol: 6, // TCP
            length: packet.packet().len() as u16,
            inner_payload: Some(packet.payload().to_vec()),
        }
    }

    pub fn from_udp(packet: &UdpPacket) -> Self {
        Self {
            src_ip: None,
            dst_ip: None,
            src_port: packet.get_source(),
            dst_port: packet.get_destination(),
            protocol: 17, // UDP
            length: packet.packet().len() as u16,
            inner_payload: Some(packet.payload().to_vec()),
        }
    }

    pub fn from_raw_packet(packet: &[u8], protocol: u8) -> Option<Self> {
        match protocol {
            6 => TcpPacket::new(packet).map(|p| Self::from_tcp(&p)),  // TCP
            17 => UdpPacket::new(packet).map(|p| Self::from_udp(&p)), // UDP
            47 => parse_gre(packet),     // GRE
            50 => parse_esp(packet),     // ESP
            51 => parse_ah(packet),      // AH
            2 => parse_igmp(packet),     // IGMP
            89 => parse_ospf(packet),    // OSPF
            103 => parse_pim(packet),    // PIM
            112 => parse_vrrp(packet),   // VRRP
            115 => parse_l2tp(packet),   // L2TP
            124 => parse_isis(packet),   // IS-IS
            132 => parse_sctp(packet),   // SCTP
            137 => parse_mpls(packet),   // MPLS
            179 => parse_bgp(packet),    // BGP
            _ => None,
        }
    }

    pub fn get_encapsulated_flow(&self) -> Option<Self> {
        if let Some(payload) = &self.inner_payload {
            match self.protocol {
                47 => parse_gre(payload),     // GRE
                50 => parse_esp(payload),     // ESP
                51 => parse_ah(payload),      // AH
                137 => parse_mpls(payload),   // MPLS
                _ => None
            }
        } else {
            None
        }
    }

    // pub fn get_inner_flow(&self) -> Option<Vec<Self>> {
    //     let mut flows = Vec::new();
        
    //     // First check for encapsulated protocols
    //     if let Some(inner) = self.get_encapsulated_flow() {
    //         flows.push(inner);
    //         // Recursively check for more encapsulated flows
    //         if let Some(mut deeper_flows) = inner.get_inner_flow() {
    //             flows.append(&mut deeper_flows);
    //         }
    //     }
        
    //     if flows.is_empty() {
    //         None
    //     } else {
    //         Some(flows)
    //     }
    // }
}
