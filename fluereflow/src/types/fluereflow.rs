use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FluereFlow {
    pub header: FluereHeader,
    pub records: Vec<FluereRecord>,
}
impl FluereFlow {
    pub fn new(header: FluereHeader, records: Vec<FluereRecord>) -> FluereFlow {
        FluereFlow { header, records }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FluereHeader {
    pub version: u16,
    pub count: u16,
    pub sys_uptime: u32,
    pub unix_secs: u32,
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
pub struct FluereRecord {
    pub source: IpAddr,
    pub destination: IpAddr,
    pub d_pkts: u32,
    pub d_octets: usize,
    pub first: u64,
    pub last: u64,
    pub src_port: u16,
    pub dst_port: u16,
    pub min_pkt: u32,
    pub max_pkt: u32,
    pub min_ttl: u8,
    pub max_ttl: u8,
    pub in_pkts: u32,
    pub out_pkts: u32,
    pub in_bytes: usize,
    pub out_bytes: usize,
    pub fin_cnt: u32,
    pub syn_cnt: u32,
    pub rst_cnt: u32,
    pub psh_cnt: u32,
    pub ack_cnt: u32,
    pub urg_cnt: u32,
    pub ece_cnt: u32,
    pub cwr_cnt: u32,
    pub ns_cnt: u32,
    pub prot: u8,
    pub tos: u8,
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
    pub fn to_vec(&self) -> Vec<String> {
        vec![
            self.source.to_string(),      // Convert IpAddr to String
            self.destination.to_string(), // Convert IpAddr to String
            self.d_pkts.to_string(),
            self.d_octets.to_string(),
            self.first.to_string(),
            self.last.to_string(),
            self.src_port.to_string(),
            self.dst_port.to_string(),
            self.min_pkt.to_string(),
            self.max_pkt.to_string(),
            self.min_ttl.to_string(),
            self.max_ttl.to_string(),
            self.in_pkts.to_string(),
            self.out_pkts.to_string(),
            self.in_bytes.to_string(),
            self.out_bytes.to_string(),
            self.fin_cnt.to_string(),
            self.syn_cnt.to_string(),
            self.rst_cnt.to_string(),
            self.psh_cnt.to_string(),
            self.ack_cnt.to_string(),
            self.urg_cnt.to_string(),
            self.ece_cnt.to_string(),
            self.cwr_cnt.to_string(),
            self.ns_cnt.to_string(),
            self.prot.to_string(),
            self.tos.to_string(),
        ]
    }
}
