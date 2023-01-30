use pnet::packet::tcp::TcpPacket;

pub fn parse_flags(protocol: u8, payload: &[u8]) -> (u32, u32, u32, u32, u32, u32, u32, u32, u32) {
    let flags = match protocol {
        6 => {
            let tcp = TcpPacket::new(payload).unwrap();
            let tcp_flags = tcp.get_flags();

            (
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
                match tcp_flags & 0x100 {
                    0 => 0,
                    _ => 1,
                },
            )
        }
        _ => (0, 0, 0, 0, 0, 0, 0, 0, 0),
    };

    flags
}
