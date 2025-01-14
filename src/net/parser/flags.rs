use pnet::packet::tcp::TcpPacket;

// Add constants for flag bits
const TCP_FIN: u8 = 0x01;
const TCP_SYN: u8 = 0x02;
const TCP_RST: u8 = 0x04;
const TCP_PSH: u8 = 0x08;
const TCP_ACK: u8 = 0x10;
const TCP_URG: u8 = 0x20;
const TCP_ECE: u8 = 0x40;
const TCP_CWR: u8 = 0x80;

pub fn parse_flags(protocol: u8, payload: &[u8]) -> [u8; 9] {
    let flags = match protocol {
        6 => {
            match TcpPacket::new(payload) {
                Some(tcp) => {
                    let tcp_flags = tcp.get_flags();
                    [
                        (tcp_flags & TCP_FIN != 0) as u8,
                        (tcp_flags & TCP_SYN != 0) as u8,
                        (tcp_flags & TCP_RST != 0) as u8,
                        (tcp_flags & TCP_PSH != 0) as u8,
                        (tcp_flags & TCP_ACK != 0) as u8,
                        (tcp_flags & TCP_URG != 0) as u8,
                        (tcp_flags & TCP_ECE != 0) as u8,
                        (tcp_flags & TCP_CWR != 0) as u8,
                        0, // Deprecated NS Flag due to Experimental RFC 3530 moved to Historic status
                    ]
                }
                None => [0; 9],
            }
        }
        _ => [0; 9],
    };

    flags
}
