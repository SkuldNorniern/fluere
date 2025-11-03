use crate::net::parser::raw::protocols::ProtocolParser;
use crate::net::parser::raw::{RawProtocolHeader, utils::bytes_to_ipv4};

// PIM Version
const PIM_VERSION2: u8 = 2;

// PIM Message Types
const HELLO: u8 = 0;
const REGISTER: u8 = 1;
const REGISTER_STOP: u8 = 2;
const JOIN_PRUNE: u8 = 3;
const BOOTSTRAP: u8 = 4;
const ASSERT: u8 = 5;
const GRAFT: u8 = 6;
const GRAFT_ACK: u8 = 7;
const CANDIDATE_RP_ADVERTISEMENT: u8 = 8;
const STATE_REFRESH: u8 = 9;

pub struct PimParser;

impl ProtocolParser for PimParser {
    fn protocol_number() -> u8 {
        103 // PIM protocol number
    }

    fn parse_packet(payload: &[u8], _protocol_number: u8) -> Option<RawProtocolHeader> {
        // PIM Header Format (RFC 4601):
        // 0                   1                   2                   3
        // 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        // |PIM Ver| Type  |   Reserved    |           Checksum              |
        // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        // |                         Message Body                             |
        // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        if payload.len() < 4 {
            return None;
        }

        let version = (payload[0] >> 4) & 0x0F;
        let pim_type = payload[0] & 0x0F;
        let checksum = u16::from_be_bytes([payload[2], payload[3]]);

        // Validate PIM version
        if version != PIM_VERSION2 {
            return None;
        }

        // Create base header - pim_type goes to src_port, version will be set separately
        let mut header = RawProtocolHeader::new(
            None,
            None,
            pim_type as u16, // src_port = message type
            0,               // dst_port = unused
            Self::protocol_number(),
            payload.len() as u16,
            Some(payload[4..].to_vec()),
        );

        // Add version and checksum
        header = header.with_version(version).with_checksum(checksum);
        // Parse specific message types
        match pim_type {
            HELLO => {
                if let Some(()) = Self::parse_hello_message(payload, &mut header) {
                    Some(header)
                } else {
                    None
                }
            }
            JOIN_PRUNE => {
                if let Some(()) = Self::parse_join_prune_message(payload, &mut header) {
                    Some(header)
                } else {
                    None
                }
            }
            _ => Some(header), // Other message types are accepted without specific parsing
        }
    }
}

impl PimParser {
    fn parse_hello_message(payload: &[u8], _header: &mut RawProtocolHeader) -> Option<()> {
        if payload.len() < 4 {
            return None;
        }

        // Parse Hello options
        let mut offset = 4;
        while offset + 4 <= payload.len() {
            let _option_type = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
            let option_length =
                u16::from_be_bytes([payload[offset + 2], payload[offset + 3]]) as usize;

            if offset + 4 + option_length > payload.len() {
                break;
            }

            offset += 4 + option_length;
        }

        Some(())
    }

    fn parse_join_prune_message(payload: &[u8], header: &mut RawProtocolHeader) -> Option<()> {
        if payload.len() < 12 {
            // Minimum length for Join/Prune message
            return None;
        }

        // Extract upstream neighbor address
        header.src_ip = Some(bytes_to_ipv4(&payload[4..8])?);

        let num_groups = payload[8] as usize;
        let _holdtime = u16::from_be_bytes([payload[10], payload[11]]);
        let mut offset = 12;

        // Parse group entries
        for _ in 0..num_groups {
            if offset + 8 > payload.len() {
                return None;
            }

            // Group address
            let _group_addr = bytes_to_ipv4(&payload[offset..offset + 4])?;
            offset += 4;

            // Number of joined and pruned sources
            if offset + 4 > payload.len() {
                return None;
            }
            let num_joins = u16::from_be_bytes([payload[offset], payload[offset + 1]]) as usize;
            let num_prunes =
                u16::from_be_bytes([payload[offset + 2], payload[offset + 3]]) as usize;
            offset += 4;

            // Parse source addresses
            for _ in 0..num_joins + num_prunes {
                if offset + 4 > payload.len() {
                    return None;
                }
                let _source_addr = bytes_to_ipv4(&payload[offset..offset + 4])?;
                offset += 4;
            }
        }

        Some(())
    }

    fn validate_checksum(payload: &[u8]) -> bool {
        if payload.len() < 4 {
            return false;
        }

        let mut sum: u32 = 0;

        // Process each 16-bit word
        for i in (0..payload.len() - 1).step_by(2) {
            let word = ((payload[i] as u32) << 8) | (payload[i + 1] as u32);
            sum = sum.wrapping_add(word);
        }

        // Handle odd length
        if payload.len() % 2 == 1 {
            sum = sum.wrapping_add((payload[payload.len() - 1] as u32) << 8);
        }

        // Add carry bits
        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        // One's complement
        sum = !sum & 0xFFFF;

        sum == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pim_hello_packet() {
        let payload = vec![
            0x20, // Version 2, Type 0 (Hello)
            0x00, // Reserved
            0x00, 0x00, // Checksum
            // Hello Options
            0x00, 0x01, // Option Type
            0x00, 0x02, // Option Length
            0x00, 0x00, // Option Value
        ];

        let result = PimParser::parse_packet(&payload, PimParser::protocol_number());
        assert!(result.is_some());

        let header = result.unwrap();
        assert_eq!(header.version, Some(2));
        assert_eq!(header.src_port, 0); // Hello message type
        assert_eq!(header.protocol, 103); // PIM
    }

    #[test]
    fn test_pim_join_prune() {
        let payload = vec![
            0x23, // Version 2, Type 3 (Join/Prune)
            0x00, // Reserved
            0x00, 0x00, // Checksum
            192, 168, 1, 1,    // Upstream neighbor address
            0x01, // Number of groups
            0x00, // Reserved
            0x00, 0x60, // Holdtime
            // Group entry
            192, 168, 2, 1, // Group address
            0x00, 0x01, // Number of joins
            0x00, 0x00, // Number of prunes
            192, 168, 3, 1, // Source address
        ];

        let result = PimParser::parse_packet(&payload, PimParser::protocol_number());
        assert!(result.is_some());

        let header = result.unwrap();
        assert_eq!(header.version, Some(2));
        assert_eq!(header.src_port, 3); // Join/Prune message type
        assert_eq!(header.protocol, 103); // PIM
    }
}
