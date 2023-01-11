use std::net::Ipv4Addr;

use pnet::packet::ip::IpNextHeaderProtocol;
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V5Netflow {
    header: V5Header,
    records: Vec<V5Record>,
}
impl V5Netflow {
    pub fn new(header: V5Header, records: Vec<V5Record>) -> V5Netflow {
        V5Netflow { header, records }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct V5Header {
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
impl V5Header {
    pub fn new(
        count: u16,
        sys_uptime: u32,
        unix_secs: u32,
        unix_nsecs: u32,
        flow_sequence: u32,
        engine_type: u8,
        engine_id: u8,
        sampling_interval: u16,
    ) -> V5Header {
        V5Header {
            version: 5,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct V5Record {
    source: Ipv4Addr,
    destination: Ipv4Addr,
    next_hop: Ipv4Addr,

    input: u16,
    output: u16,
    d_pkts: u32,
    d_octets: u32,
    first: u32,
    last: u32,
    src_port: u16,
    dst_port: u16,
    pad1: u8,
    tcp_flags: u8,
    prot: IpNextHeaderProtocol,
    tos: u8,
    src_as: u16,
    dst_as: u16,
    src_mask: u8,
    dst_mask: u8,
    pad2: u16,
}
impl V5Record {
    pub fn new(
        source: Ipv4Addr,
        destination: Ipv4Addr,
        next_hop: Ipv4Addr,
        input: u16,
        output: u16,
        d_pkts: u32,
        d_octets: u32,
        first: u32,
        last: u32,
        src_port: u16,
        dst_port: u16,
        pad1: u8,
        tcp_flags: u8,
        prot: IpNextHeaderProtocol,
        tos: u8,
        src_as: u16,
        dst_as: u16,
        src_mask: u8,
        dst_mask: u8,
        pad2: u16,
    ) -> V5Record {
        V5Record {
            source,
            destination,
            next_hop,
            input,
            output,
            d_pkts,
            d_octets,
            first,
            last,
            src_port,
            dst_port,
            pad1,
            tcp_flags,
            prot,
            tos,
            src_as,
            dst_as,
            src_mask,
            dst_mask,
            pad2,
        }
    }
    pub fn set_d_pkts(&mut self, d_pkts: u32) {
        self.d_pkts = d_pkts;
    }
    pub fn set_d_octets(&mut self, d_octets: u32) {
        self.d_octets = d_octets;
    }
    pub fn set_first(&mut self, first: u32) {
        self.first = first;
    }
    pub fn set_last(&mut self, last: u32) {
        self.last = last;
    }
    pub fn get_source(&self) -> Ipv4Addr {
        self.source
    }
    pub fn get_destination(&self) -> Ipv4Addr {
        self.destination
    }
    pub fn get_next_hop(&self) -> Ipv4Addr {
        self.next_hop
    }
    pub fn get_input(&self) -> u16 {
        self.input
    }
    pub fn get_output(&self) -> u16 {
        self.output
    }
    pub fn get_d_pkts(&self) -> u32 {
        self.d_pkts
    }
    pub fn get_d_octets(&self) -> u32 {
        self.d_octets
    }
    pub fn get_first(&self) -> u32 {
        self.first
    }
    pub fn get_last(&self) -> u32 {
        self.last
    }
    pub fn get_src_port(&self) -> u16 {
        self.src_port
    }
    pub fn get_dst_port(&self) -> u16 {
        self.dst_port
    }
    pub fn get_pad1(&self) -> u8 {
        self.pad1
    }
    pub fn get_tcp_flags(&self) -> u8 {
        self.tcp_flags
    }
    pub fn get_prot(&self) -> IpNextHeaderProtocol {
        self.prot
    }
    pub fn get_tos(&self) -> u8 {
        self.tos
    }
    pub fn get_src_as(&self) -> u16 {
        self.src_as
    }
    pub fn get_dst_as(&self) -> u16 {
        self.dst_as
    }
    pub fn get_src_mask(&self) -> u8 {
        self.src_mask
    }
    pub fn get_dst_mask(&self) -> u8 {
        self.dst_mask
    }
    pub fn get_pad2(&self) -> u16 {
        self.pad2
    }
}
