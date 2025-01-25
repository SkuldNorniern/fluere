use crate::net::parser::raw::RawProtocolHeader;

pub fn parse_bgp(payload: &[u8]) -> Option<RawProtocolHeader> {
    if payload.len() < 19 {
        // Minimum BGP header size
        return None;
    }

    // BGP Header Format (RFC 4271):
    // 0                   1                   2                   3
    // 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                                                               |
    // +                                                               +
    // |                                                               |
    // +                                                               +
    // |                           Marker                              |
    // +                                                               +
    // |                                                               |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |          Length               |      Type     |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    let length = ((payload[16] as u16) << 8) | payload[17] as u16;
    let msg_type = payload[18];

    Some(RawProtocolHeader::new(
        None,
        None,
        179, // BGP well-known port
        msg_type as u16,
        179, // BGP protocol number
        length,
        if payload.len() > 19 {
            Some(payload[19..].to_vec())
        } else {
            None
        },
    ))
}
