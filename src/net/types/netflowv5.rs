use pnet::packet::PrimitiveValues;
use pnet_macros::Packet;
use pnet_macros::packet;
use std::net::Ipv4Addr;
use pnet_macros_support::types::*;
use serde::ser::Serialize;
use serde::ser::SerializeStruct;
use serde::Serializer;

#[packet]
pub struct V5Netflow {
    #[construct_with(u16, u16, u32, u32, u32, u32, u8, u8, u16)]
    header: V5Header,
    
    #[length_fn = "v5netflow_records_length"]
    records: Vec<V5record>,
    
    #[payload]
    payload: Vec<u8>
}
fn v5netflow_records_length(p: &V5NetflowPacket) -> usize {
    p.get_header().count as usize * 48
}
impl Serialize for V5Netflow {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer
    {
        let mut struc = serializer.serialize_struct("V5Netflow", 2)?;
        struc.serialize_field("header", &self.header)?;
        struc.serialize_field("records", &self.records)?;
        struc.end()
    }
}
impl Serialize for V5NetflowPacket<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer
    {
        let mut struc = serializer.serialize_struct("V5NetflowPacket", 2)?;
        struc.serialize_field("header", &self.get_header())?;
        struc.serialize_field("records", &self.get_records())?;
        struc.end()
    }
}
/*impl from_packet for V5Netflow {
    type T = (V5Header, Vec<V5record>);
    fn from_packet(p: &V5NetflowPacket) -> (V5Header, Vec<V5record>) {
        (p.get_header(), p.get_records().to_vec())
    }
}*/


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct V5Header{
    version: u16,
    count: u16,
    sys_uptime: u32,
    unix_secs: u32,
    unix_nsecs: u32,
    flow_sequence: u32,
    engine_type: u8,
    engine_id: u8,
    sampling_interval: u16,
}
impl PrimitiveValues for V5Header {
    type T = (u16, u16, u32, u32, u32, u32, u8, u8, u16);
    fn to_primitive_values(&self) -> (u16, u16, u32, u32, u32, u32, u8, u8, u16) {
        (self.version, self.count, self.sys_uptime, self.unix_secs, self.unix_nsecs, self.flow_sequence, self.engine_type, self.engine_id, self.sampling_interval)
    }
}
impl Serialize for V5Header {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer
    {
        let mut struc = serializer.serialize_struct("V5Header", 9)?;
        struc.serialize_field("version", &self.version)?;
        struc.serialize_field("count", &self.count)?;
        struc.serialize_field("sys_uptime", &self.sys_uptime)?;
        struc.serialize_field("unix_secs", &self.unix_secs)?;
        struc.serialize_field("unix_nsecs", &self.unix_nsecs)?;
        struc.serialize_field("flow_sequence", &self.flow_sequence)?;
        struc.serialize_field("engine_type", &self.engine_type)?;
        struc.serialize_field("engine_id", &self.engine_id)?;
        struc.serialize_field("sampling_interval", &self.sampling_interval)?;
        struc.end()
    }
}
impl V5Header{
    pub fn new(version: u16, count: u16, sys_uptime: u32, unix_secs: u32, unix_nsecs: u32, flow_sequence: u32, engine_type: u8, engine_id: u8, sampling_interval: u16) -> V5Header{
        V5Header{
            version,
            count,
            sys_uptime,
            unix_secs,
            unix_nsecs,
            flow_sequence,
            engine_type,
            engine_id,
            sampling_interval,
        }
    }
}

#[derive(Packet, Debug, Clone, PartialEq, Eq)]
pub struct V5record {
    #[construct_with(u8, u8, u8, u8)]
    source: Ipv4Addr,
    
    #[construct_with(u8, u8, u8, u8)]
    destination: Ipv4Addr,
    
    #[construct_with(u8, u8, u8, u8)]
    next_hop: Ipv4Addr,
    
    input: u16be,
    output: u16be,
    d_pkts: u32be,
    d_octets: u32be,
    first: u32be,
    last: u32be,
    src_port: u16be,
    dst_port: u16be,
    pad1: u8,
    tcp_flags: u8,
    prot: u8,
    tos: u8,
    src_as: u16be,
    dst_as: u16be,
    src_mask: u8,
    dst_mask: u8,
    pad2: u16be,

    
    #[length_fn = "record_payload_length"]
    #[payload]
    payload: Vec<u8>
}
fn record_payload_length(_: &V5recordPacket) -> usize {
    0usize
}
impl Serialize for V5record {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer
    {
        let mut struc = serializer.serialize_struct("Record", 18)?;
        struc.serialize_field("source", &self.source)?;
        struc.serialize_field("destination", &self.destination)?;
        struc.serialize_field("next_hop", &self.next_hop)?;
        struc.serialize_field("input", &self.input)?;
        struc.serialize_field("output", &self.output)?;
        struc.serialize_field("d_pkts", &self.d_pkts)?;
        struc.serialize_field("d_octets", &self.d_octets)?;
        // TODO resolved time
        struc.serialize_field("first", &self.first)?;
        struc.serialize_field("last", &self.last)?;
        struc.serialize_field("src_port", &self.src_port)?;
        struc.serialize_field("dst_port", &self.dst_port)?;
        struc.serialize_field("tcp_flags", &self.tcp_flags)?;
        struc.serialize_field("prot", &self.prot)?;
        struc.serialize_field("tos", &self.tos)?;
        struc.serialize_field("src_as", &self.src_as)?;
        struc.serialize_field("dst_as", &self.dst_as)?;
        struc.serialize_field("src_mask", &self.src_mask)?;
        struc.serialize_field("dst_mask", &self.dst_mask)?;
        struc.end()
    }
}