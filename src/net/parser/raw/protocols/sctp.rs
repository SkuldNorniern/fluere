use crate::net::parser::raw::protocols::ProtocolParser;
use crate::net::parser::raw::RawProtocolHeader;

pub struct SctpParser;

impl super::ProtocolParser for SctpParser {
    fn protocol_number() -> u8 {
        132 // SCTP protocol number
    }

    fn parse_packet(payload: &[u8], _protocol_number: u8) -> Option<RawProtocolHeader> {
        if payload.len() < 12 {
            return None;
        }

        // SCTP Common Header Format (RFC 9260):
        // 0                   1                   2                   3
        // 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        // |     Source Port Number        |     Destination Port Number     |
        // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        // |                      Verification Tag                           |
        // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        // |                           Checksum                              |
        // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        let src_port = u16::from_be_bytes([payload[0], payload[1]]);
        let dst_port = u16::from_be_bytes([payload[2], payload[3]]);
        let verification_tag = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
        let checksum = u32::from_be_bytes([payload[8], payload[9], payload[10], payload[11]]);

        // Only include payload if there's data after the header
        let inner_payload = if payload.len() > 12 {
            Some(payload[12..].to_vec())
        } else {
            None
        };

        Some(
            RawProtocolHeader::new(
                None,
                None,
                src_port,
                dst_port,
                Self::protocol_number(),
                payload.len() as u16,
                inner_payload,
            )
            .with_raw_packet(payload.to_vec())
            .with_sequence(verification_tag),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sctp_parse_minimal() {
        let payload = [
            0x12, 0x34, // Source port: 4660
            0x56, 0x78, // Destination port: 22136
            0x00, 0x00, 0x00, 0x01, // Verification tag
            0x00, 0x00, 0x00, 0x00, // Checksum
        ];

        let result = SctpParser::parse_packet(&payload, SctpParser::protocol_number());
        assert!(result.is_some());

        let header = result.unwrap();
        assert_eq!(header.src_port, 0x1234);
        assert_eq!(header.dst_port, 0x5678);
        assert_eq!(header.protocol, 132);
        assert_eq!(header.length, payload.len() as u16);
        assert!(header.payload.is_none());
    }

    #[test]
    fn test_sctp_parse_with_data() {
        let payload = vec![
            0x12, 0x34, // Source port: 4660
            0x56, 0x78, // Destination port: 22136
            0x00, 0x00, 0x00, 0x01, // Verification tag
            0x00, 0x00, 0x00, 0x00, // Checksum
            0x00, // DATA chunk type
            0x00, // Flags
            0x00, 0x04, // Length
        ];

        let result = SctpParser::parse_packet(&payload, SctpParser::protocol_number());
        assert!(result.is_some());

        let header = result.unwrap();
        assert_eq!(header.src_port, 0x1234);
        assert_eq!(header.dst_port, 0x5678);
        assert!(header.payload.is_some());
        assert_eq!(header.payload.unwrap(), payload[12..]);
    }

    #[test]
    fn test_sctp_parse_invalid() {
        let payload = [0x00, 0x00];
        let result = SctpParser::parse_packet(&payload, SctpParser::protocol_number());
        assert!(result.is_none());
    }
}
