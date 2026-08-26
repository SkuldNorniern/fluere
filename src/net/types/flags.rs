#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TcpFlags {
    pub fin: u8,
    pub syn: u8,
    pub rst: u8,
    pub psh: u8,
    pub ack: u8,
    pub urg: u8,
    pub ece: u8,
    pub cwr: u8,
    pub ns: u8,
}

impl TcpFlags {
    pub fn new(flags: [u8; 9]) -> TcpFlags {
        TcpFlags {
            fin: flags[0],
            syn: flags[1],
            rst: flags[2],
            psh: flags[3],
            ack: flags[4],
            urg: flags[5],
            ece: flags[6],
            cwr: flags[7],
            ns: flags[8],
        }
    }
}
