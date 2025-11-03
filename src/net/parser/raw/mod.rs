mod ethertypes;
mod protocols;
mod utils;

use std::net::{IpAddr, Ipv4Addr};

use log::{debug, trace, warn};

#[derive(Debug)]
pub struct RawProtocolHeader {
    pub src_ip: Option<IpAddr>,
    pub dst_ip: Option<IpAddr>,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub length: u16,
    pub payload: Option<Vec<u8>>,
    pub raw_packet: Option<Vec<u8>>,
    pub ethertype: Option<u16>,
    pub flags: Option<u8>,
    pub version: Option<u8>,
    pub next_header: Option<u8>,
    pub sequence: Option<u32>,
    pub spi: Option<u32>,

    // IGMP specific fields
    pub qrv: Option<u8>,  // Querier's Robustness Variable
    pub qqic: Option<u8>, // Querier's Query Interval Code

    pub ttl: Option<u8>, // Time To Live

    // Add IPX specific fields
    pub src_network: Option<u32>,
    pub dst_network: Option<u32>,

    pub checksum: Option<u16>, // IP checksum
}

impl RawProtocolHeader {
    pub fn new(
        src_ip: Option<IpAddr>,
        dst_ip: Option<IpAddr>,
        src_port: u16,
        dst_port: u16,
        protocol: u8,
        length: u16,
        payload: Option<Vec<u8>>,
    ) -> Self {
        Self {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
            length,
            payload,
            raw_packet: None,
            ethertype: None,
            flags: None,
            version: None,
            next_header: None,
            sequence: None,
            spi: None,
            ttl: None,
            qrv: None,
            qqic: None,
            src_network: None,
            dst_network: None,
            checksum: None,
        }
    }
    pub fn with_src_ip(mut self, src_ip: IpAddr) -> Self {
        self.src_ip = Some(src_ip);
        self
    }
    pub fn with_dst_ip(mut self, dst_ip: IpAddr) -> Self {
        self.dst_ip = Some(dst_ip);
        self
    }
    pub fn with_src_port(mut self, src_port: u16) -> Self {
        self.src_port = src_port;
        self
    }
    pub fn with_dst_port(mut self, dst_port: u16) -> Self {
        self.dst_port = dst_port;
        self
    }
    pub fn with_raw_packet(mut self, packet: Vec<u8>) -> Self {
        self.raw_packet = Some(packet);
        self
    }
    pub fn with_next_header(mut self, next_header: u8) -> Self {
        self.next_header = Some(next_header);
        self
    }

    pub fn with_sequence(mut self, sequence: u32) -> Self {
        self.sequence = Some(sequence);
        self
    }

    pub fn with_spi(mut self, spi: u32) -> Self {
        self.spi = Some(spi);
        self
    }

    pub fn with_ethertype(mut self, ethertype: u16) -> Self {
        self.ethertype = Some(ethertype);
        self
    }

    pub fn with_flags(mut self, flags: u8) -> Self {
        self.flags = Some(flags);
        self
    }

    pub fn with_version(mut self, version: u8) -> Self {
        self.version = Some(version);
        self
    }

    pub fn with_qrv(mut self, qrv: u8) -> Self {
        self.qrv = Some(qrv);
        self
    }

    pub fn with_qqic(mut self, qqic: u8) -> Self {
        self.qqic = Some(qqic);
        self
    }

    pub fn with_ttl(mut self, ttl: u8) -> Self {
        self.ttl = Some(ttl);
        self
    }

    pub fn with_src_network(mut self, network: u32) -> Self {
        self.src_network = Some(network);
        self
    }

    pub fn with_dst_network(mut self, network: u32) -> Self {
        self.dst_network = Some(network);
        self
    }

    pub fn with_checksum(mut self, checksum: u16) -> Self {
        self.checksum = Some(checksum);
        self
    }

    pub fn from_raw_packet(payload: &[u8], protocol_hint: u8) -> Option<Self> {
        trace!(
            "Attempting raw packet parsing with protocol hint: {}",
            protocol_hint
        );

        // Try to parse as IPv4 first to capture outer IP information
        let outer_header = if payload.len() >= 20 && (payload[0] >> 4) == 4 {
            let _version = payload[0] >> 4;
            let header_length = (payload[0] & 0x0F) * 4;

            if header_length >= 20 && header_length as usize <= payload.len() {
                let src_ip = IpAddr::V4(Ipv4Addr::new(
                    payload[12],
                    payload[13],
                    payload[14],
                    payload[15],
                ));
                let dst_ip = IpAddr::V4(Ipv4Addr::new(
                    payload[16],
                    payload[17],
                    payload[18],
                    payload[19],
                ));

                let actual_protocol = payload[9];

                let (src_port, dst_port) = if header_length as usize + 4 <= payload.len() {
                    let transport_data = &payload[header_length as usize..];
                    if transport_data.len() >= 4 {
                        (
                            u16::from_be_bytes([transport_data[0], transport_data[1]]),
                            u16::from_be_bytes([transport_data[2], transport_data[3]]),
                        )
                    } else {
                        (0, 0)
                    }
                } else {
                    (0, 0)
                };

                debug!(
                    "IPv4 packet detected: {}:{} -> {}:{}",
                    src_ip, src_port, dst_ip, dst_port
                );

                Some((src_ip, dst_ip, src_port, dst_port, actual_protocol))
            } else {
                None
            }
        } else {
            None
        };

        // Try known protocols first
        if let Some(mut header) = protocols::parse_protocol(payload, protocol_hint) {
            debug!("Successfully parsed using protocol module");
            // Preserve outer IP/port information if inner protocol didn't set them
            if let Some((src_ip, dst_ip, src_port, dst_port, _)) = outer_header {
                if header.src_ip.is_none() {
                    header = header.with_src_ip(src_ip);
                }
                if header.dst_ip.is_none() {
                    header = header.with_dst_ip(dst_ip);
                }
                if header.src_port == 0 {
                    header = header.with_src_port(src_port);
                }
                if header.dst_port == 0 {
                    header = header.with_dst_port(dst_port);
                }
            }
            return Some(header);
        }

        // If we have outer IPv4 information, use it
        if let Some((src_ip, dst_ip, src_port, dst_port, actual_protocol)) = outer_header {
            return Some(Self::new(
                Some(src_ip),
                Some(dst_ip),
                src_port,
                dst_port,
                actual_protocol,
                payload.len() as u16,
                Some(payload.to_vec()),
            ));
        }

        // Fallback to generic packet analysis
        if payload.len() < 4 {
            warn!("Payload too short for generic analysis");
            debug!("Payload: {:?}", payload);
            return None;
        }

        // Look for common protocol patterns
        let possible_header = match protocol_hint {
            0xb9 => {
                // Netflix VPN pattern
                debug!("Detected possible Netflix VPN traffic");
                let (src_port, dst_port) = if payload.len() >= 4 {
                    (
                        u16::from_be_bytes([payload[0], payload[1]]),
                        u16::from_be_bytes([payload[2], payload[3]]),
                    )
                } else {
                    (0, 0)
                };

                Some(Self::new(
                    None,
                    None,
                    src_port,
                    dst_port,
                    protocol_hint,
                    payload.len() as u16,
                    Some(payload[4..].to_vec()),
                ))
            }
            0x36 => {
                // Custom VPN pattern
                debug!("Detected possible custom VPN traffic");
                Some(Self::new(
                    None,
                    None,
                    payload.first().copied().unwrap_or(0) as u16,
                    payload.get(1).copied().unwrap_or(0) as u16,
                    protocol_hint,
                    payload.len() as u16,
                    Some(payload.get(2..).unwrap_or(&[]).to_vec()),
                ))
            }
            _ => {
                trace!("Using generic packet analysis");
                let (src_port, dst_port) = if payload.len() >= 4 {
                    (
                        u16::from_be_bytes([payload[0], payload[1]]),
                        u16::from_be_bytes([payload[2], payload[3]]),
                    )
                } else {
                    (0, 0)
                };

                Some(Self::new(
                    None,
                    None,
                    src_port,
                    dst_port,
                    protocol_hint,
                    payload.len() as u16,
                    Some(payload.to_vec()),
                ))
            }
        };

        // If we created a header through generic analysis, preserve outer IP information
        if let Some(mut header) = possible_header {
            if let Some((src_ip, dst_ip, src_port, dst_port, _)) = outer_header {
                if header.src_ip.is_none() {
                    header = header.with_src_ip(src_ip);
                }
                if header.dst_ip.is_none() {
                    header = header.with_dst_ip(dst_ip);
                }
                if header.src_port == 0 {
                    header = header.with_src_port(src_port);
                }
                if header.dst_port == 0 {
                    header = header.with_dst_port(dst_port);
                }
            }
            debug!("Created raw protocol header through generic analysis");
            Some(header)
        } else {
            None
        }
    }

    pub fn from_ethertype(payload: &[u8], ethertype: u16) -> Option<Self> {
        trace!(
            "Attempting to parse raw protocol from EtherType: 0x{:04x}",
            ethertype
        );

        // Try ethertypes module first
        if let Some(header) = ethertypes::parse_ethertype(payload, ethertype) {
            debug!("Successfully parsed using ethertypes module");
            return Some(header);
        }

        // If ethertype indicates IPv4 (0x0800), try parsing as IPv4
        if ethertype == 0x0800 && payload.len() >= 20 {
            return Self::from_raw_packet(payload, payload[9]); // Use protocol from IPv4 header
        }

        // Fallback to protocol-based parsing
        Self::from_raw_packet(payload, ethertype as u8)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_raw_protocol_header_builder() {
        let header = RawProtocolHeader::new(
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2))),
            80,
            443,
            6,
            64,
            Some(b"test payload".to_vec()),
        )
        .with_flags(0x18)
        .with_ttl(64)
        .with_version(4)
        .with_checksum(0x1234);

        assert_eq!(header.src_port, 80);
        assert_eq!(header.dst_port, 443);
        assert_eq!(header.protocol, 6);
        assert_eq!(header.flags, Some(0x18));
        assert_eq!(header.ttl, Some(64));
        assert_eq!(header.version, Some(4));
        assert_eq!(header.checksum, Some(0x1234));
    }

    #[test]
    fn test_from_raw_packet_valid_ipv4() {
        // Valid IPv4 packet with TCP header
        let packet = [
            0x45, 0x00, 0x00, 0x28, // Version=4, IHL=5, TOS=0, Total Length=40
            0x12, 0x34, 0x40, 0x00, // ID=0x1234, Flags=Don't Fragment
            0x40, 0x06, 0x00, 0x00, // TTL=64, Protocol=TCP, Checksum=0
            192, 168, 1, 1, // Source IP
            192, 168, 1, 2, // Destination IP
            0x00, 0x50, 0x01, 0xbb, // Source Port=80, Dest Port=443
            0x00, 0x00, 0x00, 0x00, // Sequence number
        ];

        let header = RawProtocolHeader::from_raw_packet(&packet, 6).unwrap();

        assert_eq!(
            header.src_ip,
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)))
        );
        assert_eq!(
            header.dst_ip,
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)))
        );
        assert_eq!(header.src_port, 80);
        assert_eq!(header.dst_port, 443);
        assert_eq!(header.protocol, 6); // TCP
    }

    #[test]
    fn test_from_raw_packet_malformed_ipv4() {
        // IPv4 packet with invalid header length
        let packet = [
            0x44, 0x00, 0x00, 0x14, // Version=4, IHL=4 (invalid, minimum is 5)
            0x12, 0x34, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 192, 168, 1, 1, 192, 168, 1, 2,
        ];

        let header = RawProtocolHeader::from_raw_packet(&packet, 6);
        // Should still create a header through fallback mechanism
        assert!(header.is_some());
        let header = header.unwrap();
        assert_eq!(header.protocol, 6);
    }

    #[test]
    fn test_from_raw_packet_too_short() {
        let packet = [0x45, 0x00]; // Too short for IPv4 header

        let header = RawProtocolHeader::from_raw_packet(&packet, 6);
        assert!(header.is_none());
    }

    #[test]
    fn test_from_raw_packet_netflix_vpn_pattern() {
        let packet = [
            0x00, 0x50, // Source port 80
            0x01, 0xbb, // Dest port 443
            0xde, 0xad, 0xbe, 0xef, // Additional payload
        ];

        let header = RawProtocolHeader::from_raw_packet(&packet, 0xb9).unwrap();

        assert_eq!(header.src_port, 80);
        assert_eq!(header.dst_port, 443);
        assert_eq!(header.protocol, 0xb9);
        assert_eq!(header.payload.as_ref().unwrap(), &[0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn test_from_raw_packet_custom_vpn_pattern() {
        let packet = [
            0x50, // Source port/identifier
            0xbb, // Dest port/identifier
            0xde, 0xad, 0xbe, 0xef, // Payload
        ];

        let header = RawProtocolHeader::from_raw_packet(&packet, 0x36).unwrap();

        assert_eq!(header.src_port, 0x50);
        assert_eq!(header.dst_port, 0xbb);
        assert_eq!(header.protocol, 0x36);
        assert_eq!(header.payload.as_ref().unwrap(), &[0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn test_from_raw_packet_generic_fallback() {
        let packet = [
            0x12, 0x34, // First two bytes as source port
            0x56, 0x78, // Next two bytes as dest port
            0xaa, 0xbb, 0xcc, 0xdd, // Additional data
        ];

        let header = RawProtocolHeader::from_raw_packet(&packet, 99).unwrap();

        assert_eq!(header.src_port, 0x1234);
        assert_eq!(header.dst_port, 0x5678);
        assert_eq!(header.protocol, 99);
        assert_eq!(header.payload.as_ref().unwrap(), &packet);
    }

    #[test]
    fn test_from_ethertype_ipv4() {
        // Valid IPv4 packet
        let packet = [
            0x45, 0x00, 0x00, 0x1c, // Version=4, IHL=5, TOS=0, Total Length=28
            0x12, 0x34, 0x40, 0x00, // ID, Flags
            0x40, 0x11, 0x00, 0x00, // TTL=64, Protocol=UDP, Checksum
            192, 168, 1, 1, // Source IP
            192, 168, 1, 2, // Destination IP
            0x00, 0x35, 0x00, 0x35, // UDP source port 53, dest port 53
        ];

        let header = RawProtocolHeader::from_ethertype(&packet, 0x0800).unwrap();

        assert_eq!(
            header.src_ip,
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)))
        );
        assert_eq!(
            header.dst_ip,
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)))
        );
        assert_eq!(header.protocol, 17); // UDP
    }

    #[test]
    fn test_from_ethertype_unknown() {
        let packet = [0x12, 0x34, 0x56, 0x78, 0xaa, 0xbb, 0xcc, 0xdd];

        let header = RawProtocolHeader::from_ethertype(&packet, 0x9999);
        // Should create some header through fallback
        assert!(header.is_some());
    }

    #[test]
    fn test_ipv4_header_with_options() {
        // IPv4 packet with options (IHL=6, header length = 24 bytes)
        let packet = [
            0x46, 0x00, 0x00, 0x20, // Version=4, IHL=6, Total Length=32
            0x12, 0x34, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 192, 168, 1, 1, // Source IP
            192, 168, 1, 2, // Destination IP
            0x01, 0x02, 0x03, 0x04, // 4 bytes of options
            0x00, 0x50, 0x01, 0xbb, // TCP ports after options
            0x00, 0x00, 0x00, 0x00,
        ];

        let header = RawProtocolHeader::from_raw_packet(&packet, 6).unwrap();

        assert_eq!(
            header.src_ip,
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)))
        );
        assert_eq!(
            header.dst_ip,
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)))
        );
        assert_eq!(header.src_port, 80);
        assert_eq!(header.dst_port, 443);
    }

    #[test]
    fn test_ipv6_version_detection() {
        // Packet starting with IPv6 version (6)
        let packet = [
            0x60, 0x00, 0x00, 0x00, // Version=6, traffic class, flow label
            0x00, 0x08, 0x11, 0x40, // Payload length=8, next header=UDP, hop limit=64
            0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00, // Source IPv6 (first 8 bytes)
            0x00, 0x00, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x34, // Source IPv6 (last 8 bytes)
            0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00, // Dest IPv6 (first 8 bytes)
            0x00, 0x00, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x35, // Dest IPv6 (last 8 bytes)
            0x00, 0x35, 0x00, 0x35, // UDP ports
        ];

        let header = RawProtocolHeader::from_raw_packet(&packet, 17);
        assert!(header.is_some());
        // Should not be parsed as IPv4, should use generic fallback
        let header = header.unwrap();
        assert_eq!(header.protocol, 17);
    }

    #[test]
    fn test_port_extraction_edge_cases() {
        // Test with packet that has less than 4 bytes after IP header
        let packet = [
            0x45, 0x00, 0x00, 0x16, // IPv4 header, total length = 22
            0x12, 0x34, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 192, 168, 1, 1, 192, 168, 1, 2, 0x00,
            0x50, // Only 2 bytes of transport header
        ];

        let header = RawProtocolHeader::from_raw_packet(&packet, 6).unwrap();

        // Should handle gracefully and set ports to 0
        assert_eq!(header.src_port, 0);
        assert_eq!(header.dst_port, 0);
        assert_eq!(
            header.src_ip,
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)))
        );
    }

    #[test]
    fn test_protocol_preservation() {
        // Test that protocol from IPv4 header is preserved correctly
        let packet = [
            0x45, 0x00, 0x00, 0x1c, 0x12, 0x34, 0x40, 0x00, 0x40, 0x32, 0x00,
            0x00, // Protocol = 50 (ESP)
            192, 168, 1, 1, 192, 168, 1, 2, 0x12, 0x34, 0x56, 0x78, // ESP header
        ];

        let header = RawProtocolHeader::from_raw_packet(&packet, 99).unwrap();

        // Should use protocol from IPv4 header (50), not the hint (99)
        assert_eq!(header.protocol, 50);
        assert_eq!(
            header.src_ip,
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)))
        );
    }

    #[test]
    fn test_empty_payload() {
        let packet = [];

        let header = RawProtocolHeader::from_raw_packet(&packet, 6);
        assert!(header.is_none());
    }

    #[test]
    fn test_builder_pattern_completeness() {
        let header = RawProtocolHeader::new(None, None, 0, 0, 0, 0, None)
            .with_src_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
            .with_dst_ip(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)))
            .with_src_port(8080)
            .with_dst_port(9090)
            .with_ethertype(0x86dd)
            .with_sequence(12345)
            .with_spi(67890)
            .with_qrv(3)
            .with_qqic(125)
            .with_src_network(0xaabbccdd)
            .with_dst_network(0x11223344);

        assert_eq!(header.src_ip, Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert_eq!(
            header.dst_ip,
            Some(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)))
        );
        assert_eq!(header.src_port, 8080);
        assert_eq!(header.dst_port, 9090);
        assert_eq!(header.ethertype, Some(0x86dd));
        assert_eq!(header.sequence, Some(12345));
        assert_eq!(header.spi, Some(67890));
        assert_eq!(header.qrv, Some(3));
        assert_eq!(header.qqic, Some(125));
        assert_eq!(header.src_network, Some(0xaabbccdd));
        assert_eq!(header.dst_network, Some(0x11223344));
    }

    #[test]
    fn test_invalid_ipv4_total_length() {
        // IPv4 packet with total length larger than actual packet
        let packet = [
            0x45, 0x00, 0xff, 0xff, // Total length = 65535 (way larger than packet)
            0x12, 0x34, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 192, 168, 1, 1, 192, 168, 1, 2,
        ];

        let header = RawProtocolHeader::from_raw_packet(&packet, 6);
        // Should handle gracefully through fallback
        assert!(header.is_some());
    }

    #[test]
    fn test_ipv4_fragmented_packet() {
        // IPv4 packet with fragment flags set
        let packet = [
            0x45, 0x00, 0x00, 0x1c, 0x12, 0x34, 0x20, 0x00, // More Fragments flag set
            0x40, 0x06, 0x00, 0x00, 192, 168, 1, 1, 192, 168, 1, 2, 0x00, 0x50, 0x01, 0xbb,
        ];

        let header = RawProtocolHeader::from_raw_packet(&packet, 6).unwrap();

        // Should still parse correctly
        assert_eq!(
            header.src_ip,
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)))
        );
        assert_eq!(
            header.dst_ip,
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)))
        );
        assert_eq!(header.protocol, 6);
    }
}
