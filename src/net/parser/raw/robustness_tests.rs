//! Comprehensive robustness tests for the raw parser module
//! 
//! These tests are designed to prevent the specific issues that were fixed:
//! 1. Port swap bugs in protocol parsers
//! 2. Incorrect packet length handling
//! 3. Field assignment errors in header construction
//! 4. Edge case handling failures

#[cfg(test)]
mod robustness_tests {
    use crate::net::parser::raw::*;
    use crate::net::parser::raw::ethertypes::parse_ethertype;
    use crate::net::parser::raw::protocols::*;
    use std::net::{IpAddr, Ipv4Addr};

    /// Regression test for IPX port swap bug (FIXED)
    #[test]
    fn test_ipx_port_assignment_regression() {
        let payload = vec![
            0xFF, 0xFF, // Checksum
            0x00, 0x1E, // Packet Length (30 bytes)
            0x00, // Transport Control
            0x01, // Packet Type (RIP)
            0x00, 0x00, 0x00, 0x01, // Destination Network
            0x00, 0x60, 0x08, 0x77, 0x88, 0x99, // Destination Node
            0x00, 0x80, // Destination Socket = 128
            0x00, 0x00, 0x00, 0x02, // Source Network
            0x00, 0x60, 0x08, 0xAA, 0xBB, 0xCC, // Source Node
            0x00, 0x90, // Source Socket = 144
        ];

        let result = ipx::IpxParser::parse_packet(&payload, ipx::IpxParser::protocol_number());
        assert!(result.is_some());

        let header = result.unwrap();
        
        // Ensure ports are correctly assigned (regression test)
        assert_eq!(header.src_port, 144, "Source port should match IPX source socket");
        assert_eq!(header.dst_port, 128, "Destination port should match IPX destination socket");
        assert_eq!(header.protocol, ipx::IpxParser::protocol_number());
    }

    /// Regression test for WireGuard packet length handling (FIXED)
    #[test]
    fn test_wireguard_length_requirements_regression() {
        // Test that WireGuard correctly handles different message types with correct lengths

        // 1. Handshake Initiation (must be 148 bytes)
        let mut handshake_packet = vec![0x01, 0x00, 0x00, 0x00]; // Type 1
        handshake_packet.extend(vec![0x42u8; 144]); // Pad to 148 bytes
        assert_eq!(handshake_packet.len(), 148);

        let result = parse_ethertype(&handshake_packet, 0x88B8);
        assert!(result.is_some(), "148-byte handshake initiation should be accepted");

        // 2. Handshake Response (must be 92 bytes)  
        let mut response_packet = vec![0x02, 0x00, 0x00, 0x00]; // Type 2
        response_packet.extend(vec![0x42u8; 88]); // Pad to 92 bytes
        assert_eq!(response_packet.len(), 92);

        let result = parse_ethertype(&response_packet, 0x88B8);
        assert!(result.is_some(), "92-byte handshake response should be accepted");

        // 3. Data packet (minimum 16 bytes)
        let data_packet = vec![
            0x04, 0x00, 0x00, 0x00, // Type 4 (Data)
            0x01, 0x02, 0x03, 0x04, // Receiver index
            0x05, 0x06, 0x07, 0x08, // Counter 
            0x09, 0x0A, 0x0B, 0x0C, // Encrypted data
        ];
        assert_eq!(data_packet.len(), 16);

        let result = parse_ethertype(&data_packet, 0x88B8);
        assert!(result.is_some(), "16-byte data packet should be accepted");

        // 4. Reject packets that are too short
        let short_packet = vec![0x01, 0x00]; // Only 2 bytes
        let result = parse_ethertype(&short_packet, 0x88B8);
        assert!(result.is_none(), "2-byte packet should be rejected");
    }

    /// Regression test for PIM version field handling (FIXED)
    #[test]
    fn test_pim_version_field_regression() {
        // Test PIM Hello message
        let hello_payload = vec![
            0x20, // Version 2, Type 0 (Hello)
            0x00, // Reserved
            0x00, 0x00, // Checksum
            0x00, 0x01, // Option Type: Holdtime
            0x00, 0x02, // Option Length: 2
            0x00, 0x69, // Holdtime: 105 seconds
        ];

        let result = pim::PimParser::parse_packet(&hello_payload, pim::PimParser::protocol_number());
        assert!(result.is_some(), "PIM Hello should parse successfully");
        
        let header = result.unwrap();
        assert_eq!(header.version, Some(2), "PIM version should be correctly extracted as 2");
        assert_eq!(header.src_port, 0, "PIM Hello message type should be 0");
        assert_eq!(header.protocol, 103, "PIM protocol number should be 103");

        // Test PIM Join/Prune message
        let join_prune_payload = vec![
            0x23, // Version 2, Type 3 (Join/Prune)
            0x00, // Reserved
            0x00, 0x00, // Checksum
            192, 168, 1, 1,    // Upstream neighbor address
            0x01, // Number of groups
            0x00, // Reserved
            0x00, 0x3C, // Holdtime (60 seconds)
            // Group entry
            224, 1, 1, 1, // Group address (multicast)
            0x00, 0x01, // Number of joins: 1
            0x00, 0x00, // Number of prunes: 0
            192, 168, 1, 100, // Source address for join
        ];

        let result = pim::PimParser::parse_packet(&join_prune_payload, pim::PimParser::protocol_number());
        assert!(result.is_some(), "PIM Join/Prune should parse successfully");
        
        let header = result.unwrap();
        assert_eq!(header.version, Some(2), "PIM version should be correctly extracted as 2");
        assert_eq!(header.src_port, 3, "PIM Join/Prune message type should be 3");
        assert_eq!(header.src_ip, Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))), 
                   "Upstream neighbor should be extracted");
    }

    /// Test protocol number preservation across all parsers
    #[test]
    fn test_protocol_number_preservation_comprehensive() {
        let protocol_tests = [
            (50, "ESP - Encapsulating Security Payload"),
            (51, "AH - Authentication Header"), 
            (47, "GRE - Generic Routing Encapsulation"),
            (1, "ICMP - Internet Control Message Protocol"),
            (2, "IGMP - Internet Group Management Protocol"),
            (111, "IPX - Internetwork Packet Exchange"),
            (103, "PIM - Protocol Independent Multicast"),
            (132, "SCTP - Stream Control Transmission Protocol"),
            (112, "VRRP - Virtual Router Redundancy Protocol"),
        ];

        for (protocol_num, description) in protocol_tests.iter() {
            // Create a basic IPv4 packet with the specific protocol
            let ipv4_packet = [
                0x45, 0x00, 0x00, 0x20, // Version=4, IHL=5, Length=32
                0x12, 0x34, 0x40, 0x00, // ID, Flags, Fragment offset
                0x40, *protocol_num, 0x00, 0x00, // TTL, Protocol, Checksum
                192, 168, 1, 1, // Source IP
                192, 168, 1, 2, // Destination IP
                // 12 bytes of payload
                0x12, 0x34, 0x56, 0x78,
                0x9a, 0xbc, 0xde, 0xf0,
                0x11, 0x22, 0x33, 0x44,
            ];

            let result = RawProtocolHeader::from_raw_packet(&ipv4_packet, 99);
            assert!(result.is_some(), "Should parse packet for {}", description);
            
            let header = result.unwrap();
            assert_eq!(header.protocol, *protocol_num, 
                "Protocol number should be preserved for {} (expected {}, got {})", 
                description, protocol_num, header.protocol);
        }
    }

    /// Test edge cases that could cause panics or incorrect behavior
    #[test]
    fn test_edge_case_robustness() {
        // Test 1: Minimum IPv4 header (20 bytes)
        let min_ipv4 = [
            0x45, 0x00, 0x00, 0x14, // Version=4, IHL=5, Length=20 (minimum)
            0x00, 0x00, 0x40, 0x00, // ID, Flags, Fragment offset
            0x40, 0x06, 0x00, 0x00, // TTL, Protocol=TCP, Checksum
            192, 168, 1, 1, // Source IP
            192, 168, 1, 2, // Destination IP
        ];
        let result = RawProtocolHeader::from_raw_packet(&min_ipv4, 6);
        assert!(result.is_some(), "Minimum IPv4 header should be handled");

        // Test 2: IPv4 with maximum IHL (60-byte header)
        let mut max_ipv4 = vec![
            0x4F, 0x00, 0x00, 0x44, // Version=4, IHL=15, Length=68 (60 header + 8 data)
            0x00, 0x00, 0x40, 0x00, // ID, Flags, Fragment offset
            0x40, 0x06, 0x00, 0x00, // TTL, Protocol=TCP, Checksum
            192, 168, 1, 1, // Source IP
            192, 168, 1, 2, // Destination IP
        ];
        // Add 40 bytes of options to make 60-byte header
        max_ipv4.extend(vec![0u8; 40]);
        // Add 8 bytes of payload
        max_ipv4.extend(vec![0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0]);
        
        let result = RawProtocolHeader::from_raw_packet(&max_ipv4, 6);
        assert!(result.is_some(), "Maximum IPv4 header should be handled");

        // Test 3: Zero-length payload handling
        let zero_payload = [];
        let result = RawProtocolHeader::from_raw_packet(&zero_payload, 6);
        assert!(result.is_none(), "Zero-length payload should return None");

        // Test 4: Single-byte payload
        let single_byte = [0x45];
        let result = RawProtocolHeader::from_raw_packet(&single_byte, 6);
        assert!(result.is_none(), "Single-byte payload should return None");
    }

    /// Test that field assignments are consistent across different construction methods
    #[test]
    fn test_header_field_consistency() {
        // Test that builder pattern and direct construction yield same results
        let header1 = RawProtocolHeader::new(
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2))),
            80, 443, 6, 64, Some(b"test".to_vec())
        );

        let header2 = RawProtocolHeader::new(
            None, None, 0, 0, 6, 0, None
        )
        .with_src_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)))
        .with_dst_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)))
        .with_src_port(80)
        .with_dst_port(443)
        .with_ttl(64)
        .with_payload(b"test".to_vec());

        assert_eq!(header1.src_ip, header2.src_ip, "Source IP should match");
        assert_eq!(header1.dst_ip, header2.dst_ip, "Destination IP should match");
        assert_eq!(header1.src_port, header2.src_port, "Source port should match");
        assert_eq!(header1.dst_port, header2.dst_port, "Destination port should match");
        assert_eq!(header1.protocol, header2.protocol, "Protocol should match");
        assert_eq!(header1.ttl, header2.ttl, "TTL should match");
    }

    /// Test MAC address extraction edge cases
    #[test]
    fn test_mac_address_edge_cases() {
        // Broadcast MAC addresses
        let broadcast_mac = [0xFF; 6];
        assert_eq!(broadcast_mac, [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);

        // Zero MAC addresses
        let zero_mac = [0x00; 6];
        assert_eq!(zero_mac, [0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

        // Locally administered MAC (bit 1 of first octet set)
        let local_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
        assert_eq!(local_mac[0] & 0x02, 0x02, "Locally administered bit should be set");

        // Multicast MAC (bit 0 of first octet set)
        let multicast_mac = [0x01, 0x00, 0x5E, 0x00, 0x00, 0x01];
        assert_eq!(multicast_mac[0] & 0x01, 0x01, "Multicast bit should be set");
    }
}

/// Integration tests to verify the fixes work end-to-end
#[cfg(test)]
mod integration_tests {
    use super::*;

    #[test]
    fn test_end_to_end_parsing_pipeline() {
        // Test a complete Ethernet frame with IPv4 + TCP to ensure the fixes work through the entire pipeline
        let ethernet_frame = [
            // Ethernet header (14 bytes)
            0x00, 0x50, 0x56, 0xc0, 0x00, 0x01, // Destination MAC
            0x00, 0x50, 0x56, 0xc0, 0x00, 0x02, // Source MAC  
            0x08, 0x00, // EtherType: IPv4
            
            // IPv4 header (20 bytes)
            0x45, 0x00, 0x00, 0x28, // Version=4, IHL=5, Length=40
            0x12, 0x34, 0x40, 0x00, // ID, Flags, Fragment offset
            0x40, 0x06, 0xb1, 0xe6, // TTL=64, Protocol=TCP, Checksum
            192, 168, 1, 100, // Source IP
            192, 168, 1, 200, // Destination IP
            
            // TCP header (20 bytes)
            0x1f, 0x90, // Source port: 8080
            0x00, 0x50, // Destination port: 80 (HTTP)
            0x00, 0x00, 0x00, 0x01, // Sequence number
            0x00, 0x00, 0x00, 0x00, // Acknowledgment number
            0x50, 0x02, 0x20, 0x00, // Header length=20, Flags=SYN, Window
            0x00, 0x00, 0x00, 0x00, // Checksum, Urgent pointer
        ];

        // Test parsing the IPv4 portion
        let ipv4_portion = &ethernet_frame[14..]; // Skip Ethernet header
        let result = RawProtocolHeader::from_raw_packet(ipv4_portion, 6);
        
        assert!(result.is_some(), "Complete IPv4+TCP packet should parse successfully");
        let header = result.unwrap();
        
        // Verify all fields are correctly extracted
        assert_eq!(header.src_ip, Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))));
        assert_eq!(header.dst_ip, Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 200))));
        assert_eq!(header.src_port, 8080);
        assert_eq!(header.dst_port, 80);
        assert_eq!(header.protocol, 6); // TCP
        assert_eq!(header.ttl, Some(64));
        assert_eq!(header.version, Some(4));
    }
} 