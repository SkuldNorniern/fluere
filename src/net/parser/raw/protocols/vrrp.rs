use crate::net::parser::raw::{protocols::ProtocolParser, RawProtocolHeader};
use std::net::{Ipv4Addr, Ipv6Addr};

pub struct VrrpParser;

// VRRP constants
const VRRP_VERSION2: u8 = 2;
const VRRP_VERSION3: u8 = 3;
const VRRP_TYPE_ADVERTISEMENT: u8 = 1;

// Priority values
const VRRP_PRIORITY_DEFAULT: u8 = 100;
const VRRP_PRIORITY_OWNER: u8 = 255;
const VRRP_PRIORITY_MIN: u8 = 1;

impl ProtocolParser for VrrpParser {
    fn protocol_number() -> u8 {
        112 // VRRP protocol number
    }

    fn parse_packet(payload: &[u8], _protocol_number: u8) -> Option<RawProtocolHeader> {
        // VRRP v2/v3 Header Format:
        // 0                   1                   2                   3
        // 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        // |Version| Type  | Virtual Rtr ID|   Priority    |Count IPvX Addr |
        // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        // |(rsvd) |     Max Adver Int     |          Checksum             |
        // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        // |                    IPvX Address (1)                            |
        // |                                                               |
        // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        if payload.len() < 8 {
            return None;
        }

        let version = (payload[0] >> 4) & 0x0F;
        let vrrp_type = payload[0] & 0x0F;
        let virtual_rtr_id = payload[1];
        let priority = payload[2];
        let count_ip_addr = payload[3];
        let max_adver_int = u16::from_be_bytes([payload[4] & 0x0F, payload[5]]);
        let checksum = u16::from_be_bytes([payload[6], payload[7]]);

        // Validate VRRP version and type
        if (version != VRRP_VERSION2 && version != VRRP_VERSION3)
            || vrrp_type != VRRP_TYPE_ADVERTISEMENT
        {
            return None;
        }

        // Validate priority range
        if priority < VRRP_PRIORITY_MIN && priority != 0 {
            return None;
        }

        // Calculate expected packet length based on version and IP address count
        let addr_size = if version == VRRP_VERSION2 { 4 } else { 16 };
        let expected_len = 8 + (count_ip_addr as usize * addr_size);
        if payload.len() < expected_len {
            return None;
        }

        // Parse virtual IP addresses
        let mut virtual_ips = Vec::with_capacity(count_ip_addr as usize);
        let mut offset = 8;

        for _ in 0..count_ip_addr {
            if version == VRRP_VERSION2 {
                if let Some(addr) = parse_ipv4_addr(&payload[offset..offset + 4]) {
                    virtual_ips.extend_from_slice(&addr.octets());
                }
                offset += 4;
            } else {
                if let Some(addr) = parse_ipv6_addr(&payload[offset..offset + 16]) {
                    virtual_ips.extend_from_slice(&addr.octets());
                }
                offset += 16;
            }
        }

        // Create VRRP header with parsed information
        let mut header = RawProtocolHeader::new(
            None,
            None,
            virtual_rtr_id as u16,
            priority as u16,
            Self::protocol_number(),
            expected_len as u16,
            Some(virtual_ips),
        );

        // Add version and advertisement interval
        header = header
            .with_version(version)
            .with_checksum(checksum)
            .with_flags(vrrp_type);

        Some(header)
    }
}

fn parse_ipv4_addr(bytes: &[u8]) -> Option<Ipv4Addr> {
    if bytes.len() >= 4 {
        Some(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]))
    } else {
        None
    }
}

fn parse_ipv6_addr(bytes: &[u8]) -> Option<Ipv6Addr> {
    if bytes.len() >= 16 {
        let mut addr_bytes = [0u8; 16];
        addr_bytes.copy_from_slice(&bytes[..16]);
        Some(Ipv6Addr::from(addr_bytes))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vrrp_v2_parse() {
        let payload = vec![
            0x21,                  // Version 2, Type 1
            0x01,                  // Virtual Router ID
            VRRP_PRIORITY_DEFAULT, // Priority 100
            0x01,                  // Count IP Addresses
            0x00,
            0x01, // Advertisement Interval
            0x00,
            0x00, // Checksum
            192,
            168,
            1,
            1, // Virtual IP Address
        ];

        let result = VrrpParser::parse_packet(&payload, VrrpParser::protocol_number());
        assert!(result.is_some());

        let header = result.unwrap();
        assert_eq!(header.version.unwrap(), VRRP_VERSION2);
        assert_eq!(header.src_port, 1); // Virtual Router ID
        assert_eq!(header.dst_port, VRRP_PRIORITY_DEFAULT as u16);
        assert!(header.payload.is_some());
    }

    #[test]
    fn test_vrrp_v3_parse() {
        let mut payload = vec![
            0x31,                  // Version 3, Type 1
            0x01,                  // Virtual Router ID
            VRRP_PRIORITY_DEFAULT, // Priority 100
            0x01,                  // Count IP Addresses
            0x00,
            0x01, // Advertisement Interval
            0x00,
            0x00, // Checksum
        ];
        // Add IPv6 address
        payload.extend_from_slice(&[0; 16]);

        let result = VrrpParser::parse_packet(&payload, VrrpParser::protocol_number());
        assert!(result.is_some());

        let header = result.unwrap();
        assert_eq!(header.version.unwrap(), VRRP_VERSION3);
        assert_eq!(header.src_port, 1); // Virtual Router ID
        assert!(header.payload.is_some());
    }

    #[test]
    fn test_vrrp_invalid_packets() {
        let test_cases = vec![
            // Too short
            vec![0x21, 0x01],
            // Invalid version
            vec![0x41, 0x01, 0x64, 0x01, 0x00, 0x01, 0x00, 0x00],
            // Invalid type
            vec![0x22, 0x01, 0x64, 0x01, 0x00, 0x01, 0x00, 0x00],
            // Invalid priority
            vec![0x21, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00],
        ];

        for payload in test_cases {
            let result = VrrpParser::parse_packet(&payload, VrrpParser::protocol_number());
            assert!(result.is_none());
        }
    }
}
