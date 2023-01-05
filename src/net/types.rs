use std::net::Ipv4Addr;

use pnet::packet::ip::IpNextHeaderProtocol;
use pnet::packet::ipv4::{Ipv4Packet, Ipv4Option};
use pnet::packet::Packet;

#[derive(Debug, Clone)]
pub struct C_Ipv4Packet {
    version: u8,
    header_len: u8,
    dscp: u8,
    ecn: u8,
    total_len: u16,
    identification: u16,
    flags: u8,
    fragment_offset: u16,
    ttl: u8,
    next_level_protocol: IpNextHeaderProtocol,
    checksum: u16,
    source: Ipv4Addr,
    destination: Ipv4Addr,
    options: Vec<Ipv4Option>,
    payload: Vec<u8>,
}

impl C_Ipv4Packet {
    pub fn new(packet_data: Ipv4Packet) -> C_Ipv4Packet  {
        // Parse the packet fields and construct the Ipv4Packet struct
        let version = packet_data.get_version();
        let header_len = packet_data.get_header_length();
        let dscp = packet_data.get_dscp();
        let ecn = packet_data.get_ecn();
        let total_len = packet_data.get_total_length();
        let identification = packet_data.get_identification();
        let flags = packet_data.get_flags();
        let fragment_offset = packet_data.get_fragment_offset();
        let ttl = packet_data.get_ttl();
        let next_level_protocol = packet_data.get_next_level_protocol();
        let checksum = packet_data.get_checksum();
        let source = packet_data.get_source();
        let destination = packet_data.get_destination();
        let options = packet_data.get_options();
        let payload = packet_data.payload().to_vec();
        
        // Return an error if parsing fails
        C_Ipv4Packet {
            version,
            header_len,
            dscp,
            ecn,
            total_len,
            identification,
            flags,
            fragment_offset,
            ttl,
            next_level_protocol,
            checksum,
            source,
            destination,
            options,
            payload,
        }
    }

    pub fn get_version(&self) -> u8 {
        self.version
    }

    pub fn get_header_len(&self) -> u8 {
        self.header_len
    }

    pub fn get_dscp(&self) -> u8 {
        self.dscp
    }

    pub fn get_ecn(&self) -> u8 {
        self.ecn
    }

    pub fn get_total_len(&self) -> u16 {
        self.total_len
    }

    pub fn get_identification(&self) -> u16 {
        self.identification
    }

    pub fn get_flags(&self) -> u8 {
        self.flags
    }

    pub fn get_fragment_offset(&self) -> u16 {
        self.fragment_offset
    }

    pub fn get_ttl(&self) -> u8 {
        self.ttl
    }

    pub fn get_next_level_protocol(&self) -> IpNextHeaderProtocol {
        self.next_level_protocol
    }

    pub fn get_checksum(&self) -> u16 {
        self.checksum
    }

    pub fn get_source(&self) -> Ipv4Addr {
        self.source
    }   

    pub fn get_destination(&self) -> Ipv4Addr {
        self.destination
    }

    pub fn get_options(&self) -> &Vec<Ipv4Option> {
        &self.options
    }   

    pub fn get_payload(&self) -> &[u8] {
        &self.payload
    }   
    
}