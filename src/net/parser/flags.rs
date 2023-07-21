use pnet::packet::tcp::TcpPacket;

pub fn parse_flags(protocol: u8, payload: &[u8]) -> [u8; 9] {
    let flags = match protocol {
        6 => {
            let tcp = TcpPacket::new(payload).unwrap();
            let tcp_flags = tcp.get_flags();

            [
                match tcp_flags & 0x01 {
                    0 => 0,
                    _ => 1,
                },
                match tcp_flags & 0x02 {
                    0 => 0,
                    _ => 1,
                },
                match tcp_flags & 0x04 {
                    0 => 0,
                    _ => 1,
                },
                match tcp_flags & 0x08 {
                    0 => 0,
                    _ => 1,
                },
                match tcp_flags & 0x10 {
                    0 => 0,
                    _ => 1,
                },
                match tcp_flags & 0x20 {
                    0 => 0,
                    _ => 1,
                },
                match tcp_flags & 0x40 {
                    0 => 0,
                    _ => 1,
                },
                match tcp_flags & 0x80 {
                    0 => 0,
                    _ => 1,
                },
                0, // Deprecated NS Flag due to Experimental RFC 3530 moved to Historic status
            ]
        }
        _ => [0; 9],
    };

    flags
}
