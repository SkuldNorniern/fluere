use pnet::packet::tcp::TcpPacket;

pub fn parse_flags(protocol: u8, payload: &[u8]) -> [u8; 9] {
    let flags = match protocol {
        6 => {
            match TcpPacket::new(payload) {
                Some(tcp) => {
                    let tcp_flags = tcp.get_flags();
                    [
                        (tcp_flags & 0x01 != 0) as u8,
                        (tcp_flags & 0x02 != 0) as u8,
                        (tcp_flags & 0x04 != 0) as u8,
                        (tcp_flags & 0x08 != 0) as u8,
                        (tcp_flags & 0x10 != 0) as u8,
                        (tcp_flags & 0x20 != 0) as u8,
                        (tcp_flags & 0x40 != 0) as u8,
                        (tcp_flags & 0x80 != 0) as u8,
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
