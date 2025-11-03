use crate::net::parser::raw::{RawProtocolHeader, protocols::ProtocolParser};

pub struct EspParser;

impl ProtocolParser for EspParser {
    fn protocol_number() -> u8 {
        50 // ESP protocol number
    }

    fn parse_packet(payload: &[u8], _protocol_number: u8) -> Option<RawProtocolHeader> {
        // ESP header must be at least 8 bytes (SPI + Sequence Number)
        if payload.len() < 8 {
            return None;
        }

        // ESP Packet Format (RFC 4303):
        // 0                   1                   2                   3
        // 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        // |               Security Parameters Index (SPI)                    |
        // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        // |                      Sequence Number                            |
        // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        // |                    IV (optional)                                |
        // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        // |                    Payload Data* (variable)                     |
        // ~                                                                 ~
        // |                                                                 |
        // +               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        // |               |     Padding (0-255 bytes)                       |
        // +-+-+-+-+-+-+-+-+               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        // |                               |  Pad Length   | Next Header     |
        // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        // |         Authentication Data (ICV) (variable)                    |
        // ~                                                                 ~
        // |                                                                 |
        // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        let spi = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
        let sequence = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);

        // Note: Since ESP payload is encrypted, we can't reliably parse the inner payload
        // We only parse the header and treat the rest as encrypted payload
        let inner_payload = if payload.len() > 8 {
            Some(payload[8..].to_vec())
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
    fn test_esp_parse_minimal() {
        let payload = vec![
            0x12, 0x34, 0x56, 0x78, // SPI
            0x00, 0x00, 0x00, 0x01, // Sequence Number
        ];

        let result = EspParser::parse_packet(&payload, EspParser::protocol_number());
        assert!(result.is_some());

        let header = result.unwrap();
        assert_eq!(header.sequence.unwrap(), 1);
        assert_eq!(header.protocol, 50); // ESP
        assert!(header.payload.is_none());
    }

    #[test]
    fn test_esp_parse_with_data() {
        let mut payload = vec![
            0x12, 0x34, 0x56, 0x78, // SPI
            0x00, 0x00, 0x00, 0x01, // Sequence Number
        ];
        // Add some encrypted data
        payload.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]);

        let result = EspParser::parse_packet(&payload, EspParser::protocol_number());
        assert!(result.is_some());

        let header = result.unwrap();
        assert!(header.payload.is_some());
        assert_eq!(header.payload.unwrap(), vec![0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn test_esp_parse_invalid() {
        // Test with insufficient length
        let payload = vec![0x00, 0x00, 0x00];
        let result = EspParser::parse_packet(&payload, EspParser::protocol_number());
        assert!(result.is_none());
    }
}
