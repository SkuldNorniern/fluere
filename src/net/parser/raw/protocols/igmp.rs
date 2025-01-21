use crate::net::parser::raw::protocols::ProtocolParser;
use crate::net::parser::raw::RawProtocolHeader;
use std::net::{IpAddr, Ipv4Addr};

pub struct IgmpParser;

// IGMP message types with their RFC-specified values
const MEMBERSHIP_QUERY: u8 = 0x11; // Query message for all versions
const IGMPV1_MEMBERSHIP_REPORT: u8 = 0x12; // IGMPv1 report message
const IGMPV2_MEMBERSHIP_REPORT: u8 = 0x16; // IGMPv2 report message
const IGMPV3_MEMBERSHIP_REPORT: u8 = 0x22; // IGMPv3 report message
const LEAVE_GROUP: u8 = 0x17; // IGMPv2/v3 leave message

impl IgmpParser {
    // IGMPv2 Message Format (RFC 2236)
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |      Type     | Max Resp Time |           Checksum            |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                         Group Address                           |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //
    // Type (8 bits):
    //   - 0x11: Membership Query
    //   - 0x12: IGMPv1 Membership Report
    //   - 0x16: IGMPv2 Membership Report
    //   - 0x17: Leave Group
    //
    // Max Response Time (8 bits):
    //   - In units of 0.1 seconds
    //   - Used only in Membership Query messages
    //   - Set to 0 in other messages
    //
    // Checksum (16 bits):
    //   - 16-bit one's complement of the one's complement sum
    //
    // Group Address (32 bits):
    //   - Multicast group address being queried/reported
    //   - Set to 0 in General Query messages

    // IGMPv3 Query Message Format (RFC 3376)
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |  Type = 0x11  | Max Resp Code |           Checksum            |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                         Group Address                           |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // | Resv  |S| QRV |     QQIC      |     Number of Sources (N)      |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                       Source Address [1]                         |
    // +-                                                               -+
    // |                       Source Address [2]                         |
    // +-                              .                               -+
    // |                       Source Address [N]                         |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //
    // S Flag (1 bit):
    //   - Suppress Router-Side Processing flag
    //
    // QRV (3 bits):
    //   - Querier's Robustness Variable
    //
    // QQIC (8 bits):
    //   - Querier's Query Interval Code
    //
    // Number of Sources (16 bits):
    //   - Number of source addresses present
    //
    // Source Addresses:
    //   - List of N IPv4 source addresses

    // Destination addresses for different message types:
    // General Query:                 224.0.0.1  (All Systems)
    // Group-Specific Query:          The group being queried
    // IGMPv1/v2/v3 Membership Report: The group being reported
    // Leave Group:                   224.0.0.2  (All Routers)
    // IGMPv3 Membership Report:      224.0.0.22 (IGMPv3-capable multicast routers)

    fn get_destination_addr(igmp_type: u8) -> Option<IpAddr> {
        match igmp_type {
            MEMBERSHIP_QUERY => Some(IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1))), // All Systems
            LEAVE_GROUP => Some(IpAddr::V4(Ipv4Addr::new(224, 0, 0, 2))),      // All Routers
            IGMPV3_MEMBERSHIP_REPORT => Some(IpAddr::V4(Ipv4Addr::new(224, 0, 0, 22))), // IGMPv3 Routers
            _ => None,
        }
    }

    fn parse_v3_query(payload: &[u8]) -> Option<RawProtocolHeader> {
        if payload.len() < 12 {
            return None;
        }

        let max_resp_code = payload[1];
        let group_addr = if payload.len() >= 8 {
            Some(IpAddr::V4(Ipv4Addr::new(
                payload[4], payload[5], payload[6], payload[7],
            )))
        } else {
            None
        };

        let flags = payload[8];
        let qrv = flags & 0x07;
        let qqic = payload[9];
        let num_sources = u16::from_be_bytes([payload[10], payload[11]]);

        let expected_len = 12 + (num_sources as usize * 4);
        if payload.len() < expected_len {
            return None;
        }

        let inner_payload = if num_sources > 0 {
            Some(payload[12..expected_len].to_vec())
        } else {
            None
        };

        Some(
            RawProtocolHeader::new(
                None,
                group_addr,
                MEMBERSHIP_QUERY as u16,
                max_resp_code as u16,
                Self::protocol_number(),
                payload.len() as u16,
                inner_payload,
            )
            .with_raw_packet(payload.to_vec())
            .with_flags(flags)
            .with_version(3)
            .with_qrv(qrv)
            .with_qqic(qqic),
        )
    }
}

impl ProtocolParser for IgmpParser {
    fn protocol_number() -> u8 {
        2
    }

    fn parse_packet(payload: &[u8], _protocol_number: u8) -> Option<RawProtocolHeader> {
        if payload.len() < 8 {
            return None;
        }

        let igmp_type = payload[0];
        let max_resp_time = payload[1];
        let group_addr = if payload.len() >= 8 {
            Some(IpAddr::V4(Ipv4Addr::new(
                payload[4], payload[5], payload[6], payload[7],
            )))
        } else {
            None
        };

        if igmp_type == MEMBERSHIP_QUERY && payload.len() >= 12 {
            return Self::parse_v3_query(payload);
        }

        let version = match igmp_type {
            IGMPV1_MEMBERSHIP_REPORT => 1,
            IGMPV2_MEMBERSHIP_REPORT | LEAVE_GROUP => 2,
            IGMPV3_MEMBERSHIP_REPORT => 3,
            MEMBERSHIP_QUERY => {
                if payload.len() >= 12 {
                    3
                } else {
                    2
                }
            }
            _ => 2,
        };

        let inner_payload = if payload.len() > 8 {
            Some(payload[8..].to_vec())
        } else {
            None
        };

        Some(
            RawProtocolHeader::new(
                None,
                Self::get_destination_addr(igmp_type).or(group_addr),
                igmp_type as u16,
                max_resp_time as u16,
                Self::protocol_number(),
                payload.len() as u16,
                inner_payload,
            )
            .with_raw_packet(payload.to_vec())
            .with_flags(igmp_type)
            .with_version(version),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_igmp_v1_membership_report() {
        let payload = [
            IGMPV1_MEMBERSHIP_REPORT, // Type
            0,                        // Unused
            0x00,
            0x00, // Checksum (not validated)
            239,
            1,
            2,
            3, // Group Address
        ];

        let result = IgmpParser::parse_packet(&payload, IgmpParser::protocol_number());
        assert!(result.is_some());

        let header = result.unwrap();
        assert_eq!(header.version.unwrap(), 1);
        assert_eq!(header.flags.unwrap(), IGMPV1_MEMBERSHIP_REPORT);
        assert!(header.dst_ip.is_some());
    }

    #[test]
    fn test_igmp_v2_membership_query() {
        let payload = [
            MEMBERSHIP_QUERY, // Type
            100,              // Max Response Time (10 seconds)
            0x00,
            0x00, // Checksum (not validated)
            224,
            0,
            0,
            1, // Group Address
        ];

        let result = IgmpParser::parse_packet(&payload, IgmpParser::protocol_number());
        assert!(result.is_some());

        let header = result.unwrap();
        assert_eq!(header.src_port, MEMBERSHIP_QUERY as u16);
        assert_eq!(header.dst_port, 100); // Max Response Time
        assert_eq!(header.version.unwrap(), 2);
        assert_eq!(header.dst_ip.unwrap().to_string(), "224.0.0.1");
    }

    #[test]
    fn test_igmp_v3_group_specific_query() {
        let payload = [
            MEMBERSHIP_QUERY, // Type
            100,              // Max Response Code
            0x00,
            0x00, // Checksum
            239,
            1,
            2,
            3,    // Group Address (specific group)
            0x02, // Resv|S|QRV (QRV=2)
            0x7D, // QQIC
            0x00,
            0x00, // Number of Sources (0)
        ];

        let result = IgmpParser::parse_packet(&payload, IgmpParser::protocol_number());
        assert!(result.is_some());

        let header = result.unwrap();
        assert_eq!(header.version.unwrap(), 3);
        assert_eq!(header.qrv.unwrap(), 2);
        assert_eq!(header.qqic.unwrap(), 0x7D);
        assert!(header.dst_ip.is_some());
    }

    #[test]
    fn test_igmp_v3_source_specific_query() {
        let payload = [
            MEMBERSHIP_QUERY, // Type
            100,              // Max Response Code
            0x00,
            0x00, // Checksum
            239,
            1,
            2,
            3,    // Group Address
            0x02, // Resv|S|QRV (QRV=2)
            0x7D, // QQIC
            0x00,
            0x01, // Number of Sources (1)
            10,
            0,
            0,
            1, // Source Address 1
        ];

        let result = IgmpParser::parse_packet(&payload, IgmpParser::protocol_number());
        assert!(result.is_some());

        let header = result.unwrap();
        assert_eq!(header.version.unwrap(), 3);
        assert_eq!(header.qrv.unwrap(), 2);
        assert!(header.payload.is_some());
        assert_eq!(header.payload.unwrap().len(), 4); // 1 source address
    }

    #[test]
    fn test_igmp_invalid_length() {
        let payload = [
            MEMBERSHIP_QUERY, // Type
            100,              // Max Response Time
            0x00,             // Incomplete packet
        ];

        let result = IgmpParser::parse_packet(&payload, IgmpParser::protocol_number());
        assert!(result.is_none());
    }
}
