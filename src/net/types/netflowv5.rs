use pcap::Packet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct V5header{
    pub version: u16,
    pub count: u16,
    pub sys_uptime: u32,
    pub unix_secs: u32,
    pub unix_nsecs: u32,
    pub flow_sequence: u32,
    pub engine_type: u8,
    pub engine_id: u8,
    pub sampling_interval: u16,
}
impl V5header{
    pub fn new(packe:Packet){
        let packet_header = packet.PacketHeader;
        let packet_data = packet.data;
        
        V5header{
            version: packet_data[0] as u16,
            unix_secs = packet_header.ts,
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct V5record{
    pub src_addr: u32,
    pub dst_addr: u32,
    pub nexthop: u32,
    pub input: u16,
    pub output: u16,
    pub dPkts: u32,
    pub dOctets: u32,
    pub first: u32,
    pub last: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub pad1: u8,
    pub tcp_flags: u8,
    pub prot: u8,
    pub tos: u8,
    pub src_as: u16,
    pub dst_as: u16,
    pub src_mask: u8,
    pub dst_mask: u8,
    pub pad2: u16,

}
