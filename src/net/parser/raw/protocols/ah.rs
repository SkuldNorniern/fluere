use crate::net::parser::raw::{RawProtocolHeader, protocols::ProtocolParser};

pub struct AhParser;

impl ProtocolParser for AhParser {
    fn protocol_number() -> u8 {
        51 // AH protocol number
    }

    fn parse_packet(payload: &[u8], _protocol_number: u8) -> Option<RawProtocolHeader> {
        // AH header must be at least 12 bytes (3 32-bit words)
        if payload.len() < 12 {
            return None;
        }

        // Authentication Header (AH) Format (RFC 4302):
        // 0                   1                   2                   3
        // 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        // | Next Header   |  Payload Len  |           RESERVED            |
        // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        // |                 Security Parameters Index (SPI)                  |
        // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        // |                    Sequence Number Field                         |
        // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        // |                                                                 |
        // +                Authentication Data (ICV)                        |
        // |                                                                 |
        // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        let next_header = payload[0];
        let payload_len = payload[1];
        let spi = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
        let sequence = u32::from_be_bytes([payload[8], payload[9], payload[10], payload[11]]);

        // Calculate total header length: (Payload Len + 2) * 4 bytes
        // Payload Len represents the length of AH in 32-bit words, minus 2
        let header_len = (payload_len as usize + 2) * 4;

        // Validate total length
        if payload.len() < header_len {
            return None;
        }

        // Extract inner payload if present
        let inner_payload = if payload.len() > header_len {
            Some(payload[header_len..].to_vec())
        } else {
            None
        };

        Some(
            RawProtocolHeader::new(
                None,
                None,
                (spi >> 16) as u16,
                spi as u16,
                Self::protocol_number(),
                payload.len() as u16,
                inner_payload,
            )
            .with_next_header(next_header)
            .with_sequence(sequence)
            .with_spi(spi)
            .with_raw_packet(payload.to_vec()),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ah_parse_minimal() {
        let payload = vec![
            0x06, // Next Header (TCP)
            0x03, // Payload Length (3 32-bit words)
            0x00, 0x00, // Reserved
            0x12, 0x34, 0x56, 0x78, // SPI
            0x00, 0x00, 0x00, 0x01, // Sequence Number
            0xAA, 0xBB, 0xCC, 0xDD, // ICV (Authentication Data)
            0xEE, 0xFF, 0x11, 0x22, // ICV continued
        ];

        let result = AhParser::parse_packet(&payload, AhParser::protocol_number());
        assert!(result.is_some());

        let header = result.unwrap();
        assert_eq!(header.next_header.unwrap(), 0x06); // TCP
        assert_eq!(header.sequence.unwrap(), 1);
        assert_eq!(header.protocol, 51); // AH
        assert!(header.payload.is_none());
    }

    #[test]
    fn test_ah_parse_with_data() {
        let mut payload = vec![
            0x06, // Next Header (TCP)
            0x03, // Payload Length (3 32-bit words)
            0x00, 0x00, // Reserved
            0x12, 0x34, 0x56, 0x78, // SPI
            0x00, 0x00, 0x00, 0x01, // Sequence Number
            0xAA, 0xBB, 0xCC, 0xDD, // ICV
            0xEE, 0xFF, 0x11, 0x22, // ICV continued
        ];
        // Add some data after the AH header
        payload.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]);

        let result = AhParser::parse_packet(&payload, AhParser::protocol_number());
        assert!(result.is_some());

        let header = result.unwrap();
        assert!(header.payload.is_some());
        assert_eq!(header.payload.unwrap(), vec![0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn test_ah_parse_invalid() {
        // Test with insufficient length
        let payload = vec![0x00, 0x00, 0x00];
        let result = AhParser::parse_packet(&payload, AhParser::protocol_number());
        assert!(result.is_none());

        // Test with invalid payload length
        let payload = vec![
            0x06, 0xFF, 0x00, 0x00, // Header with impossible length
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let result = AhParser::parse_packet(&payload, AhParser::protocol_number());
        assert!(result.is_none());
    }
}
