use crate::net::parser::raw::RawProtocolHeader;

pub fn parse_l2tp(payload: &[u8]) -> Option<RawProtocolHeader> {
    if payload.len() < 6 {
        return None;
    }

    // L2TP Header Format (RFC 2661):
    // 0                   1                   2                   3
    // 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |T|L|x|x|S|x|O|P|x|x|x|x|  Ver  |          Length (opt)         |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |           Tunnel ID           |           Session ID           |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |             Ns (opt)          |             Nr (opt)          |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |      Offset Size (opt)        |    Offset pad... (opt)
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    let flags = payload[0];
    let _version = payload[1] & 0x0F;
    let tunnel_id = ((payload[2] as u16) << 8) | payload[3] as u16;
    let session_id = ((payload[4] as u16) << 8) | payload[5] as u16;

    // Calculate header size based on flags
    let mut header_size = 6;
    if flags & 0x40 != 0 {
        // Length bit set
        header_size += 2;
    }
    if flags & 0x08 != 0 {
        // Sequence bit set
        header_size += 4;
    }
    if flags & 0x02 != 0 {
        // Offset bit set
        header_size += 2;
        if payload.len() > header_size {
            header_size += (((payload[header_size - 2] as u16) << 8)
                | payload[header_size - 1] as u16) as usize;
        }
    }

    Some(RawProtocolHeader::new(
        None,
        None,
        tunnel_id,
        session_id,
        115, // L2TP protocol number
        payload.len() as u16,
        if payload.len() > header_size {
            Some(payload[header_size..].to_vec())
        } else {
            None
        },
    ))
}
