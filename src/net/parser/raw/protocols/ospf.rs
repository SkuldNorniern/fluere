use crate::net::parser::raw::protocols::ProtocolParser;
use crate::net::parser::raw::{utils::bytes_to_ipv4, RawProtocolHeader};

// OSPF Message Types
const HELLO: u8 = 1;
const DATABASE_DESCRIPTION: u8 = 2;
const LINK_STATE_REQUEST: u8 = 3;
const LINK_STATE_UPDATE: u8 = 4;
const LINK_STATE_ACK: u8 = 5;

// LSA Types
const ROUTER_LSA: u8 = 1;
const NETWORK_LSA: u8 = 2;
const SUMMARY_LSA_NETWORK: u8 = 3;
const SUMMARY_LSA_ASBR: u8 = 4;
const AS_EXTERNAL_LSA: u8 = 5;
const NSSA_LSA: u8 = 7;
const LINK_LSA: u8 = 8;
const INTRA_AREA_PREFIX_LSA: u8 = 9;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum OspfVersion {
    V1 = 1,
    V2 = 2,
    V3 = 3,
}

pub struct OspfParser;

impl super::ProtocolParser for OspfParser {
    fn protocol_number() -> u8 {
        89 // OSPF protocol number
    }

    fn parse_packet(payload: &[u8], _protocol_number: u8) -> Option<RawProtocolHeader> {
        // OSPF Header Format (RFC 2328):
        // 0                   1                   2                   3
        // 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        // |   Version     |     Type      |         Packet length           |
        // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        // |                          Router ID                              |
        // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        // |                           Area ID                               |
        // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        // |           Checksum            |             AuType             |
        // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        // |                       Authentication                            |
        // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        // |                       Authentication                            |
        // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        if !Self::validate_length(payload, 24) {
            return None;
        }

        let version = payload[0];
        let packet_type = payload[1];
        let packet_length = u16::from_be_bytes([payload[2], payload[3]]);
        let router_id = bytes_to_ipv4(&payload[4..8])?;
        let area_id = bytes_to_ipv4(&payload[8..12])?;
        let checksum = u16::from_be_bytes([payload[12], payload[13]]);
        let auth_type = u16::from_be_bytes([payload[14], payload[15]]);

        // Validate packet length
        if payload.len() < packet_length as usize {
            return None;
        }

        // Extract payload after header
        let inner_payload = if payload.len() > 24 {
            Some(payload[24..].to_vec())
        } else {
            None
        };

        let mut header = RawProtocolHeader::new(
            Some(router_id),
            Some(area_id),
            packet_type as u16,
            auth_type,
            Self::protocol_number(),
            packet_length,
            inner_payload,
        );

        // Add version information
        header = header.with_version(version);

        // Add checksum
        header = header.with_checksum(checksum);

        Some(header)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ospf_hello_packet() {
        let payload = vec![
            2, // Version 2
            1, // Hello Packet
            0, 44, // Packet Length
            192, 168, 1, 1, // Router ID
            0, 0, 0, 0, // Area ID
            0, 0, // Checksum
            0, 0, // Auth Type
            0, 0, 0, 0, // Auth Data
            0, 0, 0, 0, // Auth Data
            // Hello Packet Body
            255, 255, 255, 0, // Network Mask
            10, 0, // Hello Interval
            0, 0, // Options
            1, // Router Priority
            0, 0, 0, 40, // Dead Interval
            0, 0, 0, 0, // DR
            0, 0, 0, 0, // BDR
        ];

        let result = OspfParser::parse_packet(&payload, OspfParser::protocol_number());
        assert!(result.is_some());

        let header = result.unwrap();
        assert_eq!(header.version, Some(2));
        assert_eq!(header.src_port, 1); // Hello packet type
        assert_eq!(header.protocol, 89); // OSPF
        assert!(header.payload.is_some());
    }

    #[test]
    fn test_ospf_invalid_length() {
        let payload = vec![
            2, // Version
            1, // Type
            0, 100, // Invalid length larger than payload
            0, 0, 0, 0,
        ];

        let result = OspfParser::parse_packet(&payload, OspfParser::protocol_number());
        assert!(result.is_none());
    }
}
