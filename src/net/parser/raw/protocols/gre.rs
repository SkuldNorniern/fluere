use crate::net::parser::raw::{protocols::ProtocolParser, RawProtocolHeader};

pub struct GreParser;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum GreVersion {
    Original, // RFC 1701
    Standard, // RFC 2784
    Extended, // RFC 2890
    Pptp,     // Version 1 for PPTP
}

impl GreParser {
    // Original GRE packet header (RFC 1701):
    // 0                   1                   2                   3
    // 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |C|R|K|S|s|Recur|  Flags  | Ver |         Protocol Type         |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |      Checksum (optional)      |       Offset (optional)        |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                         Key (optional)                          |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                   Sequence Number (optional)                    |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                     Routing (optional)                          |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //
    // Standard GRE packet header (RFC 2784):
    // 0                   1                   2                   3
    // 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |C| |K|S| Reserved0       | Ver |         Protocol Type         |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |      Checksum (optional)      |       Reserved1 (Optional)    |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //
    // Extended GRE packet header (RFC 2890):
    // 0                   1                   2                   3
    // 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |C|R|K|S|s|Recur|A| Flags | Ver |         Protocol Type         |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |      Checksum (optional)      |       Reserved1 (Optional)    |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                         Key (optional)                          |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                 Sequence Number (Optional)                      |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //
    // PPTP GRE packet header (RFC 2637):
    // 0                   1                   2                   3
    // 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |C|R|K|S|s|   Ver   |   Protocol Type (0x880B)                  |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |      Payload Length           |       Call ID                  |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                Sequence Number (Optional)                       |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                Acknowledgment Number (Optional)                 |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //
    // Flag Bits:
    // C: Checksum Present (bit 0)
    // R: Routing Present (bit 1)
    // K: Key Present (bit 2)
    // S: Sequence Number Present (bit 3)
    // s: Strict Source Route (bit 4)
    // Recur: Recursion Control (bits 5-7)
    // A: Acknowledgment Present (bit 7, RFC 2890)
    // Ver: Version Number (bits 13-15)

    // Helper function to determine GRE version from flags and version fields
    fn determine_version(flags: u8, version: u8) -> GreVersion {
        match version {
            1 => GreVersion::Pptp, // Version 1 is always PPTP
            0 => {
                if flags & 0x40 != 0 {
                    // Routing Present
                    GreVersion::Original
                } else if flags & 0x20 != 0 || flags & 0x10 != 0 {
                    // Key or Sequence present
                    GreVersion::Extended
                } else if flags & 0x80 != 0 {
                    // Only checksum present
                    GreVersion::Standard
                } else {
                    GreVersion::Original
                }
            }
            _ => GreVersion::Original,
        }
    }

    fn parse_extended(payload: &[u8]) -> Option<(usize, u32, u32)> {
        let mut offset = 4;
        let mut sequence = None;
        let mut key = None;

        // Parse optional fields in order
        if payload[0] & 0x80 != 0 {
            // Checksum present
            if payload.len() < offset + 4 {
                return None;
            }
            offset += 4; // Skip checksum and reserved1
        }

        if payload[0] & 0x20 != 0 {
            // Key present
            if payload.len() < offset + 4 {
                return None;
            }
            key = Some(u32::from_be_bytes([
                payload[offset],
                payload[offset + 1],
                payload[offset + 2],
                payload[offset + 3],
            ]));
            offset += 4;
        }

        if payload[0] & 0x10 != 0 {
            // Sequence present
            if payload.len() < offset + 4 {
                return None;
            }
            sequence = Some(u32::from_be_bytes([
                payload[offset],
                payload[offset + 1],
                payload[offset + 2],
                payload[offset + 3],
            ]));
            offset += 4;
        }

        Some((offset, key.unwrap_or(0), sequence.unwrap_or(0)))
    }

    fn parse_pptp(payload: &[u8]) -> Option<(usize, u32, u32)> {
        if payload.len() < 8 {
            return None;
        }

        let mut offset = 8; // Base PPTP header size
        let mut sequence = None;
        let call_id = u16::from_be_bytes([payload[6], payload[7]]);

        if payload[0] & 0x10 != 0 {
            // Sequence present
            if payload.len() < offset + 4 {
                return None;
            }
            sequence = Some(u32::from_be_bytes([
                payload[offset],
                payload[offset + 1],
                payload[offset + 2],
                payload[offset + 3],
            ]));
            offset += 4;
        }

        if payload[0] & 0x80 != 0 {
            // Acknowledgment present
            if payload.len() < offset + 4 {
                return None;
            }
            offset += 4;
        }

        Some((offset, call_id as u32, sequence.unwrap_or(0)))
    }
}

impl ProtocolParser for GreParser {
    fn protocol_number() -> u8 {
        47
    }

    fn parse_packet(payload: &[u8], _protocol_number: u8) -> Option<RawProtocolHeader> {
        if payload.len() < 4 {
            return None;
        }

        let flags = payload[0];
        let version = payload[1] & 0x07; // Only last 3 bits
        let protocol_type = u16::from_be_bytes([payload[2], payload[3]]);

        let gre_version = Self::determine_version(flags, version);

        // Calculate header size and parse optional fields based on version
        let (header_size, key, sequence) = match gre_version {
            GreVersion::Pptp => Self::parse_pptp(payload)?,
            GreVersion::Extended | GreVersion::Original => Self::parse_extended(payload)?,
            GreVersion::Standard => {
                let mut size = 4;
                if flags & 0x80 != 0 {
                    if payload.len() < size + 4 {
                        return None;
                    }
                    size += 4; // Checksum and Reserved1
                }
                (size, 0, 0)
            }
        };

        // Validate total packet length
        if payload.len() < header_size {
            return None;
        }

        // Extract payload if present
        let inner_payload = if payload.len() > header_size {
            Some(payload[header_size..].to_vec())
        } else {
            None
        };

        Some(
            RawProtocolHeader::new(
                None,
                None,
                protocol_type,
                version as u16,
                Self::protocol_number(),
                payload.len() as u16,
                inner_payload,
            )
            .with_raw_packet(payload.to_vec())
            .with_flags(flags)
            .with_version(version)
            .with_ethertype(protocol_type)
            .with_sequence(sequence)
            .with_spi(key),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gre_parse_minimal_rfc2784() {
        // Standard GRE packet header (RFC 2784)
        let payload = [
            0x00, // No flags
            0x00, // Version 0
            0x08, 0x00, // Protocol Type: IPv4 (0x0800)
        ];

        let result = GreParser::parse_packet(&payload, GreParser::protocol_number());
        assert!(result.is_some());

        let header = result.unwrap();
        assert_eq!(header.ethertype.unwrap(), 0x0800); // Protocol type
        assert_eq!(header.version.unwrap(), 0); // Version
        assert_eq!(header.protocol, 47); // GRE protocol
        assert_eq!(header.flags.unwrap(), 0x00);
        assert!(header.payload.is_none());
    }

    #[test]
    fn test_gre_parse_rfc2784_with_checksum() {
        // Standard GRE with checksum (RFC 2784)
        let payload = [
            0x80, // Checksum present (C bit set)
            0x00, // Version 0
            0x08, 0x00, // Protocol Type: IPv4
            0x12, 0x34, // Checksum
            0x00, 0x00, // Reserved1
            0x01, 0x02, 0x03, 0x04, // Payload
        ];

        let result = GreParser::parse_packet(&payload, GreParser::protocol_number());
        assert!(result.is_some());

        let header = result.unwrap();
        assert_eq!(header.ethertype.unwrap(), 0x0800);
        assert_eq!(header.flags.unwrap(), 0x80);
        assert!(header.payload.is_some());
        assert_eq!(header.payload.as_ref().unwrap(), &[0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn test_gre_parse_rfc2890_extended() {
        // Extended GRE packet header (RFC 2890)
        let payload = [
            0xB0, // Checksum, Key, and Sequence present (C, K, S bits)
            0x00, // Version 0
            0x08, 0x00, // Protocol Type: IPv4
            0x12, 0x34, // Checksum
            0x00, 0x00, // Reserved1
            0xAA, 0xBB, 0xCC, 0xDD, // Key
            0x00, 0x00, 0x00, 0x01, // Sequence
            0x01, 0x02, // Payload
        ];

        let result = GreParser::parse_packet(&payload, GreParser::protocol_number());
        assert!(result.is_some());

        let header = result.unwrap();
        assert_eq!(header.sequence.unwrap(), 1);
        assert_eq!(header.spi.unwrap(), 0xAABBCCDD);
        assert_eq!(header.flags.unwrap(), 0xB0);
        assert!(header.payload.is_some());
    }

    #[test]
    fn test_gre_parse_rfc1701_original() {
        // Original GRE packet header (RFC 1701)
        let payload = [
            0xA0, // Routing and Key present (R and K bits)
            0x00, // Version 0
            0x08, 0x00, // Protocol Type: IPv4
            0x00, 0x00, // Offset
            0x00, 0x00, // Reserved
            0xAA, 0xBB, 0xCC, 0xDD, // Key
            0x01, 0x02, // Routing data
            0x03, 0x04, // Payload
        ];

        let result = GreParser::parse_packet(&payload, GreParser::protocol_number());
        assert!(result.is_some());

        let header = result.unwrap();
        assert_eq!(header.spi.unwrap(), 0xAABBCCDD); // Key value
        assert_eq!(header.flags.unwrap(), 0xA0); // R and K bits set
        assert_eq!(header.ethertype.unwrap(), 0x0800); // IPv4
        assert!(header.payload.is_some());
    }

    #[test]
    fn test_gre_parse_pptp() {
        // PPTP GRE packet header
        let payload = [
            0x30, // Key and Sequence present (K and S bits)
            0x01, // Version 1 (PPTP)
            0x88, 0x0B, // Protocol Type: PPTP (0x880B)
            0x00, 0x00, // Payload Length
            0x00, 0x01, // Call ID
            0x00, 0x00, 0x00, 0x01, // Sequence
            0x01, 0x02, // Payload
        ];

        let result = GreParser::parse_packet(&payload, GreParser::protocol_number());
        assert!(result.is_some());

        let header = result.unwrap();
        assert_eq!(header.version.unwrap(), 1); // PPTP version
        assert_eq!(header.flags.unwrap(), 0x30); // K and S bits
        assert_eq!(header.ethertype.unwrap(), 0x880B); // PPTP protocol
        assert_eq!(header.sequence.unwrap(), 1);
        assert!(header.payload.is_some());
    }

    #[test]
    fn test_gre_parse_invalid() {
        // Test cases for invalid packets
        let tests = vec![
            // Too short packet
            vec![0x00, 0x00],
            // Invalid checksum length
            vec![0x80, 0x00, 0x08, 0x00],
            // Invalid key length
            vec![0x20, 0x00, 0x08, 0x00, 0xAA, 0xBB],
            // Invalid PPTP length
            vec![0x30, 0x01, 0x88, 0x0B],
        ];

        for payload in tests {
            let result = GreParser::parse_packet(&payload, GreParser::protocol_number());
            assert!(result.is_none(), "Expected None for invalid packet");
        }
    }
}
