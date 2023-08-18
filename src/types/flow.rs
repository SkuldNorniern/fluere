use crate::net::types::TcpFlags;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct UDFlowKey{
    pub doctets: usize,
    pub pkt: u32,
    pub ttl: u8,
    pub flags: TcpFlags,
    pub time: u64
}
