use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FluereFlow {
    header: FluereHeader,
    records: Vec<FluereRecord>,
}
impl FluereFlow {
    pub fn new(header: FluereHeader, records: Vec<FluereRecord>) -> FluereFlow {
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
    pub fn new(_version: u16, count: u16, sys_uptime: u32, unix_secs: u32) -> FluereHeader {
        FluereHeader {
            version: 1,
            count,
            sys_uptime,
            unix_secs,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FluerePacketInfo {
    source: IpAddr,
    destination: IpAddr,
    src_port: u16,
    dst_port: u16,
    prot: u8,
    tos: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FluerePacketStats {
    d_pkts: u32,
    d_octets: usize,
    first: u64,
    last: u64,
    min_pkt: u32,
    max_pkt: u32,
    in_pkts: u32,
    out_pkts: u32,
    in_bytes: usize,
    out_bytes: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FluerePacketFlags {
    fin_cnt: u32,
    syn_cnt: u32,
    rst_cnt: u32,
    psh_cnt: u32,
    ack_cnt: u32,
    urg_cnt: u32,
    ece_cnt: u32,
    cwr_cnt: u32,
    ns_cnt: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FluerePacketMeta {
    min_ttl: u8,
    max_ttl: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FluereRecord {
    info: FluerePacketInfo,
    stats: FluerePacketStats,
    flags: FluerePacketFlags,
    meta: FluerePacketMeta,
}
impl FluereRecord {
    pub fn new(
        source: IpAddr,
        destination: IpAddr,
        d_pkts: u32,
        d_octets: usize,
        first: u64,
        last: u64,
        src_port: u16,
        dst_port: u16,
        min_pkt: u32,
        max_pkt: u32,
        min_ttl: u8,
        max_ttl: u8,
        in_pkts: u32,
        out_pkts: u32,
        in_bytes: usize,
        out_bytes: usize,
        fin_cnt: u32,
        syn_cnt: u32,
        rst_cnt: u32,
        psh_cnt: u32,
        ack_cnt: u32,
        urg_cnt: u32,
        ece_cnt: u32,
        cwr_cnt: u32,
        ns_cnt: u32,
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
            min_pkt,
            max_pkt,
            min_ttl,
            max_ttl,
            in_pkts,
            out_pkts,
            in_bytes,
            out_bytes,
            fin_cnt,
            syn_cnt,
            rst_cnt,
            psh_cnt,
            ack_cnt,
            urg_cnt,
            ece_cnt,
            cwr_cnt,
            ns_cnt,
            prot,
            tos,
        }
    }
    pub fn set_d_pkts(&mut self, d_pkts: u32) {
        self.d_pkts = d_pkts;
    }
    pub fn set_d_octets(&mut self, d_octets: usize) {
        self.d_octets = d_octets;
    }
    pub fn set_first(&mut self, first: u64) {
        self.first = first;
    }
    pub fn set_last(&mut self, last: u64) {
        self.last = last;
    }
    pub fn set_in_pkts(&mut self, in_pkts: u32) {
        self.in_pkts = in_pkts;
    }
    pub fn set_out_pkts(&mut self, out_pkts: u32) {
        self.out_pkts = out_pkts;
    }
    pub fn set_in_bytes(&mut self, in_bytes: usize) {
        self.in_bytes = in_bytes;
    }
    pub fn set_out_bytes(&mut self, out_bytes: usize) {
        self.out_bytes = out_bytes;
    }
    pub fn set_fin_cnt(&mut self, fin_cnt: u32) {
        self.fin_cnt = fin_cnt;
    }
    pub fn set_syn_cnt(&mut self, syn_cnt: u32) {
        self.syn_cnt = syn_cnt;
    }
    pub fn set_rst_cnt(&mut self, rst_cnt: u32) {
        self.rst_cnt = rst_cnt;
    }
    pub fn set_psh_cnt(&mut self, psh_cnt: u32) {
        self.psh_cnt = psh_cnt;
    }
    pub fn set_ack_cnt(&mut self, ack_cnt: u32) {
        self.ack_cnt = ack_cnt;
    }
    pub fn set_urg_cnt(&mut self, urg_cnt: u32) {
        self.urg_cnt = urg_cnt;
    }
    pub fn set_ece_cnt(&mut self, ece_cnt: u32) {
        self.ece_cnt = ece_cnt;
    }
    pub fn set_cwr_cnt(&mut self, cwr_cnt: u32) {
        self.cwr_cnt = cwr_cnt;
    }
    pub fn set_ns_cnt(&mut self, ns_cnt: u32) {
        self.ns_cnt = ns_cnt;
    }
    pub fn set_min_pkt(&mut self, min_pkt: u32) {
        self.min_pkt = min_pkt;
    }
    pub fn set_max_pkt(&mut self, max_pkt: u32) {
        self.max_pkt = max_pkt;
    }
    pub fn set_min_ttl(&mut self, min_ttl: u8) {
        self.min_ttl = min_ttl;
    }
    pub fn set_max_ttl(&mut self, max_ttl: u8) {
        self.max_ttl = max_ttl;
    }

    pub fn get_source(&self) -> IpAddr {
        self.source
    }
    pub fn get_destination(&self) -> IpAddr {
        self.destination
    }
    pub fn get_d_pkts(&self) -> u32 {
        self.d_pkts
    }
    pub fn get_d_octets(&self) -> usize {
        self.d_octets
    }
    pub fn get_first(&self) -> u64 {
        self.first
    }
    pub fn get_last(&self) -> u64 {
        self.last
    }
    pub fn get_src_port(&self) -> u16 {
        self.src_port
    }
    pub fn get_dst_port(&self) -> u16 {
        self.dst_port
    }
    pub fn get_min_pkt(&self) -> u32 {
        self.min_pkt
    }
    pub fn get_max_pkt(&self) -> u32 {
        self.max_pkt
    }
    pub fn get_min_ttl(&self) -> u8 {
        self.min_ttl
    }
    pub fn get_max_ttl(&self) -> u8 {
        self.max_ttl
    }
    pub fn get_in_pkts(&self) -> u32 {
        self.in_pkts
    }
    pub fn get_out_pkts(&self) -> u32 {
        self.out_pkts
    }
    pub fn get_in_bytes(&self) -> usize {
        self.in_bytes
    }
    pub fn get_out_bytes(&self) -> usize {
        self.out_bytes
    }
    pub fn get_fin_cnt(&self) -> u32 {
        self.fin_cnt
    }
    pub fn get_syn_cnt(&self) -> u32 {
        self.syn_cnt
    }
    pub fn get_rst_cnt(&self) -> u32 {
        self.rst_cnt
    }
    pub fn get_psh_cnt(&self) -> u32 {
        self.psh_cnt
    }
    pub fn get_ack_cnt(&self) -> u32 {
        self.ack_cnt
    }
    pub fn get_urg_cnt(&self) -> u32 {
        self.urg_cnt
    }
    pub fn get_ece_cnt(&self) -> u32 {
        self.ece_cnt
    }
    pub fn get_cwr_cnt(&self) -> u32 {
        self.cwr_cnt
    }
    pub fn get_ns_cnt(&self) -> u32 {
        self.ns_cnt
    }
    pub fn get_prot(&self) -> u8 {
        self.prot
    }
    pub fn get_tos(&self) -> u8 {
        self.tos
    }
}
