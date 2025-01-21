use crate::net::parser::raw::protocols::ProtocolParser;
use crate::net::parser::raw::RawProtocolHeader;

pub struct IcmpParser;

impl ProtocolParser for IcmpParser {
    fn protocol_number() -> u8 {
        1 // ICMP protocol number
    }

    fn parse_packet(payload: &[u8], _protocol_number: u8) -> Option<RawProtocolHeader> {
        // ICMP header format:
        // 0                   1                   2                   3
        // 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        // |     Type      |     Code      |          Checksum             |
        // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        // |                             Data                              |
        // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        if payload.len() < 4 {
            return None;
        }

        let icmp_type = payload[0];
        let icmp_code = payload[1];
        // Checksum is at payload[2..4] but we don't validate it here

        Some(
            RawProtocolHeader::new(
                None,
                None,
                icmp_type as u16, // Using type as src_port
                icmp_code as u16, // Using code as dst_port
                Self::protocol_number(),
                payload.len() as u16,
                if payload.len() > 4 {
                    Some(payload[4..].to_vec())
                } else {
                    None
                },
            )
            .with_raw_packet(payload.to_vec())
            .with_flags(icmp_type)
            .with_version(icmp_code),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_icmp_parser() {
        // Echo request (ping) packet
        let payload = &[
            8, // Type: Echo request
            0, // Code: 0
            0x00, 0x00, // Checksum (not validated in this test)
            0x12, 0x34, // Identifier
            0x56, 0x78, // Sequence number
        ];

        let result = IcmpParser::parse_packet(payload, IcmpParser::protocol_number());
        assert!(result.is_some());

        let header = result.unwrap();
        assert_eq!(header.src_port, 8); // Echo request type
        assert_eq!(header.dst_port, 0); // Code 0
        assert_eq!(header.protocol, 1); // ICMP protocol
        assert_eq!(header.length, payload.len() as u16);
    }
}
