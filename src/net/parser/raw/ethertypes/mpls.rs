use crate::net::parser::raw::RawProtocolHeader;

pub fn parse_mpls(payload: &[u8]) -> Option<RawProtocolHeader> {
    if payload.len() < 4 {
        return None;
    }

    // MPLS Label Stack Entry Format (RFC 3032):
    // 0                   1                   2                   3
    // 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                Label                  | TC  |S|       TTL     |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    let label =
        ((payload[0] as u32) << 12) | ((payload[1] as u32) << 4) | ((payload[2] as u32) >> 4);
    let tc = (payload[2] >> 1) & 0x07;
    let bottom = payload[2] & 0x01 != 0;
    let _ttl = payload[3];

    let mut offset = 4;
    while offset + 4 <= payload.len() && !bottom {
        // Process label stack
        let next_bottom = (payload[offset + 2] & 0x01) != 0;
        if next_bottom {
            break;
        }
        offset += 4;
    }

    Some(RawProtocolHeader::new(
        None,
        None,
        label as u16,
        tc as u16,
        137, // MPLS protocol number
        payload.len() as u16,
        Some(payload[offset..].to_vec()),
    ))
}
