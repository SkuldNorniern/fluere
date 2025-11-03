use crate::net::parser::raw::RawProtocolHeader;

pub fn parse_eigrp(payload: &[u8]) -> Option<RawProtocolHeader> {
    if payload.len() < 20 {
        return None;
    }

    // EIGRP Header Format:
    // 0                   1                   2                   3
    // 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |Ver   |  Opcode |           Checksum            |  Flags        |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                           Sequence                              |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                         Acknowledgment                          |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                    Autonomous System Number                     |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    let _version = payload[0] >> 4;
    let opcode = payload[1];
    let _flags = ((payload[4] as u16) << 8) | payload[5] as u16;
    let as_number = ((payload[16] as u32) << 24)
        | ((payload[17] as u32) << 16)
        | ((payload[18] as u32) << 8)
        | payload[19] as u32;

    Some(RawProtocolHeader::new(
        None,
        None,
        opcode as u16,
        as_number as u16,
        88, // EIGRP protocol number
        payload.len() as u16,
        Some(payload[20..].to_vec()), // TLV data starts after header
    ))
}
