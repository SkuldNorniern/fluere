use std::net::Ipv4Addr;
use super::protocols::
use pnet::packet::ip::IpNextHeaderProtocol;
use pnet::packet::ipv4::{Ipv4Option, Ipv4Packet};
use pnet::packet::Packet as PnetPacket;

#[derive(Debug, Clone)]
pub struct Ipv4Packet {
    version: u8,
    header_len: u8,
    dscp: u8,
    ecn: u8,
    total_len: u16,
    id: u16,
    flags: u8,
    fragment_offset: u16,
    ttl: u8,
    protocol: IpNextHeaderProtocol,
    checksum: u16,
    source_ip: Ipv4Addr,
    destination_ip: Ipv4Addr,
    options: Vec<Ipv4Option>,
    payload: Vec<u8>,
}

impl Ipv4Packet {
    pub fn new(packet_data: Ipv4Packet) -> C_Ipv4Packet {
        // Parse the packet fields and construct the Ipv4Packet struct
        let version = packet_data.get_version();
        let header_len = packet_data.get_header_length();
        let dscp = packet_data.get_dscp();
        let ecn = packet_data.get_ecn();
        let total_len = packet_data.get_total_length();
        let id = packet_data.get_identification();
        let flags = packet_data.get_flags();
        let fragment_offset = packet_data.get_fragment_offset();
        let ttl = packet_data.get_ttl();
        let protocol = packet_data.get_next_level_protocol();
        let checksum = packet_data.get_checksum();
        let source_ip = packet_data.get_source();
        let destination_ip = packet_data.get_destination();
        let options = packet_data.get_options();
        let payload = packet_data.payload().to_vec();

        // Return an error if parsing fails
        Ipv4Packet {
            version,
            header_len,
            dscp,
            ecn,
            total_len,
            id,
            flags,
            fragment_offset,
            ttl,
            protocol,
            checksum,
            source_ip,
            destination_ip,
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

    pub fn get_id(&self) -> u16 {
        self.id
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

    pub fn get_protocol(&self) -> IpNextHeaderProtocol {
        self.protocol
    }

    pub fn get_checksum(&self) -> u16 {
        self.checksum
    }

    pub fn get_source_ip(&self) -> Ipv4Addr {
        self.source_ip
    }

    pub fn get_destination_ip(&self) -> Ipv4Addr {
        self.destination_ip
    }

    pub fn get_options(&self) -> &Vec<Ipv4Option> {
        &self.options
    }

    pub fn get_payload(&self) -> &[u8] {
        &self.payload
    }
}
