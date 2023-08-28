use std::net::IpAddr;
use rlua::{UserData, UserDataMethods};

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

impl UserData for FluereRecord {}

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
    #[allow(dead_code)]
    pub fn add_methods<'lua, M: UserDataMethods<'lua, Self>>(methods: &mut M) {
        methods.add_method("source", |_, this, _: ()| Ok(this.source.to_string()));
        methods.add_method("destination", |_, this, _: ()| Ok(this.destination.to_string()));
        methods.add_method("d_pkts", |_, this, _: ()| Ok(this.d_pkts));
        methods.add_method("d_octets", |_, this, _: ()| Ok(this.d_octets));
        methods.add_method("first", |_, this, _: ()| Ok(this.first));
        methods.add_method("last", |_, this, _: ()| Ok(this.last));
        methods.add_method("src_port", |_, this, _: ()| Ok(this.src_port));
        methods.add_method("dst_port", |_, this, _: ()| Ok(this.dst_port));
        methods.add_method("min_pkt", |_, this, _: ()| Ok(this.min_pkt));
        methods.add_method("max_pkt", |_, this, _: ()| Ok(this.max_pkt));
        methods.add_method("min_ttl", |_, this, _: ()| Ok(this.min_ttl));
        methods.add_method("max_ttl", |_, this, _: ()| Ok(this.max_ttl));
        methods.add_method("in_pkts", |_, this, _: ()| Ok(this.in_pkts));
        methods.add_method("out_pkts", |_, this, _: ()| Ok(this.out_pkts));
        methods.add_method("in_bytes", |_, this, _: ()| Ok(this.in_bytes));
        methods.add_method("out_bytes", |_, this, _: ()| Ok(this.out_bytes));
        methods.add_method("fin_cnt", |_, this, _: ()| Ok(this.fin_cnt));
        methods.add_method("syn_cnt", |_, this, _: ()| Ok(this.syn_cnt));
        methods.add_method("rst_cnt", |_, this, _: ()| Ok(this.rst_cnt));
        methods.add_method("psh_cnt", |_, this, _: ()| Ok(this.psh_cnt));
        methods.add_method("ack_cnt", |_, this, _: ()| Ok(this.ack_cnt));
        methods.add_method("urg_cnt", |_, this, _: ()| Ok(this.urg_cnt));
        methods.add_method("ece_cnt", |_, this, _: ()| Ok(this.ece_cnt));
        methods.add_method("cwr_cnt", |_, this, _: ()| Ok(this.cwr_cnt));
        methods.add_method("ns_cnt", |_, this, _: ()| Ok(this.ns_cnt));
        methods.add_method("prot", |_, this, _: ()| Ok(this.prot));
        methods.add_method("tos", |_, this, _: ()| Ok(this.tos));
    }
    pub fn to_lua_slice<'a>(&self, ctx: &'a rlua::Context<'a>) -> Result<Vec<rlua::Value<'a>>, rlua::Error> {
        Ok(vec![
            rlua::Value::String(ctx.create_string(&self.source.to_string())?), // Convert IpAddr to LuaString
            rlua::Value::String(ctx.create_string(&self.destination.to_string())?), // Convert IpAddr to LuaString           
            rlua::Value::Integer(self.d_pkts as i64),
            rlua::Value::Integer(self.d_octets as i64),
            rlua::Value::Integer(self.first as i64),
            rlua::Value::Integer(self.last as i64),
            rlua::Value::Integer(self.src_port as i64),
            rlua::Value::Integer(self.dst_port as i64),
            rlua::Value::Integer(self.min_pkt as i64),
            rlua::Value::Integer(self.max_pkt as i64),
            rlua::Value::Integer(self.min_ttl as i64),
            rlua::Value::Integer(self.max_ttl as i64),
            rlua::Value::Integer(self.in_pkts as i64),
            rlua::Value::Integer(self.out_pkts as i64),
            rlua::Value::Integer(self.in_bytes as i64),
            rlua::Value::Integer(self.out_bytes as i64),
            rlua::Value::Integer(self.fin_cnt as i64),
            rlua::Value::Integer(self.syn_cnt as i64),
            rlua::Value::Integer(self.rst_cnt as i64),
            rlua::Value::Integer(self.psh_cnt as i64),
            rlua::Value::Integer(self.ack_cnt as i64),
            rlua::Value::Integer(self.urg_cnt as i64),
            rlua::Value::Integer(self.ece_cnt as i64),
            rlua::Value::Integer(self.cwr_cnt as i64),
            rlua::Value::Integer(self.ns_cnt as i64),
            rlua::Value::Integer(self.prot as i64),
            rlua::Value::Integer(self.tos as i64),
        ])
    }
    pub fn to_slice(&self) -> Vec<String> {
        vec![
            self.source.to_string(), // Convert IpAddr to String
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

