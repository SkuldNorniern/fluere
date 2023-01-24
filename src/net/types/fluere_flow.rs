use std::net::Ipv4Addr;

#[derive(Debug, Clone, PartialEq , Eq)]
pub struct FluereFlow {
    header: FluereHeader,
    records: Vec<V5Record>,
}
impl FluereFlow {
    pub fn new(header: FluereHeader, records: Vec<FluereRecord>) -> V5Netflow {
        FluereFlow { header, records }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FluereHeader {
    version: u16,
    count: u16,
    sys_uptime: u32,
    unix_secs: u32,
}
impl FluereHeader {
    pub fn new(
        count: u16,
        sys_uptime: u32,
        unix_secs: u32,
        unix_nsecs: u32,
        flow_sequence: u32,
        engine_type: u8,
        engine_id: u8,
        sampling_interval: u16,
    ) -> FluereHeader {
        FluereHeader {
            version: 5,
            count,
            sys_uptime,
            unix_secs,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FluereRecord {
    source: Ipv4Addr,
    destination: Ipv4Addr,
    d_pkts: u32,
    d_octets: u32,
    first: u32,
    last: u32,
    src_port: u16,
    dst_port: u16,
    fin: u8,
    syn: u8,
    rst: u8,
    psh: u8,
    ack: u8,
    urg: u8,
    flags: u16,
    prot: u8,
    tos: u8
}
impl FluereRecord {
    pub fn new(
        source: Ipv4Addr,
        destination: Ipv4Addr,
        d_pkts: u32,
        d_octets: u32,
        first: u32,
        last: u32,
        src_port: u16,
        dst_port: u16,
        fin: u8,
        syn: u8,
        rst: u8,
        psh: u8,
        ack: u8,
        urg: u8,
        flags: u16,
        prot: u8,
        tos: u8,
    ) -> FluereRecord {
        FluereRecord {
            source,
            destination,
            d_pkts,
            d_octets,
            first,
            last,
            src_port,
            dst_port,
            fin,
            syn,
            rst,
            psh,
            ack,
            urg,
            flags,
            prot,
            tos,
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
    pub fn get_fin(&self) -> u8 {
        self.fin
    }
    pub fn get_syn(&self) -> u8 {
        self.syn
    }
    pub fn get_rst(&self) -> u8 {
        self.rst
    }
    pub fn get_psh(&self) -> u8 {
        self.psh
    }
    pub fn get_ack(&self) -> u8 {
        self.ack
    }
    pub fn get_urg(&self) -> u8 {
        self.urg
    }
    pub fn get_flags(&self) -> u16 {
        self.flags
    }
    pub fn get_prot(&self) -> u8 {
        self.prot
    }
    pub fn get_tos(&self) -> u8 {
        self.tos
    }
}
