use crate::net::parser::raw::{utils::bytes_to_ipv4, RawProtocolHeader};

pub fn parse_arp(payload: &[u8]) -> Option<RawProtocolHeader> {
    if payload.len() < 28 {
        // Standard ARP packet size for IPv4
        return None;
    }

    // ARP header format:
    // 0                   1                   2                   3
    // 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |        Hardware Type           |         Protocol Type          |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |  HLen  | PLen  |              Operation                        |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                        Sender MAC Address                      |
    // |                          (continued)                          |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                        Sender IP Address                       |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                        Target MAC Address                      |
    // |                          (continued)                          |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                        Target IP Address                       |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    let operation = ((payload[6] as u16) << 8) | payload[7] as u16;
    let src_ip = bytes_to_ipv4(&payload[14..18]);
    let dst_ip = bytes_to_ipv4(&payload[24..28]);

    Some(
        RawProtocolHeader::new(
            src_ip,
            dst_ip,
            operation,
            0,
            0x08, // ARP protocol number (using 8 instead of 806/0x0806)
            payload.len() as u16,
            None,
        )
        .with_ethertype(0x0806),
    )
}
