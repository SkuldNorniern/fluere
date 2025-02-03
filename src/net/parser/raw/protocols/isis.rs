use crate::net::parser::raw::RawProtocolHeader;

pub fn parse_isis(payload: &[u8]) -> Option<RawProtocolHeader> {
    if payload.len() < 8 {
        return None;
    }

    // IS-IS PDU Header Format (ISO/IEC 10589):
    // 0                   1                   2                   3
    // 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |     IRPD      |     Length    |  Version/Prot  |     ID Len   |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |     R     |PDU Type|    Version    |     Reserved              |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    let pdu_length = payload[1] as u16;
    let pdu_type = (payload[4] & 0x1F) as u16;
    let version = payload[5];

    Some(RawProtocolHeader::new(
        None,
        None,
        pdu_type,
        version as u16,
        124, // IS-IS protocol number
        pdu_length,
        if payload.len() > 8 {
            Some(payload[8..].to_vec())
        } else {
            None
        },
    ))
}
