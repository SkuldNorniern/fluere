mod arp;
mod mpls;
mod vpn;
mod vxlan;
mod wireguard;

use log::{debug, trace, warn};

pub trait EtherTypeParser {
    /// Parse a packet for a specific EtherType
    fn parse_packet(&self, packet: &[u8]) -> Option<super::RawProtocolHeader>;

    /// Check if this parser can handle the given EtherType
    fn can_parse(&self, ethertype: u16) -> bool;

    /// Get the name of the protocol
    fn protocol_name(&self) -> &'static str;
}

pub fn parse_ethertype(packet: &[u8], ethertype: u16) -> Option<super::RawProtocolHeader> {
    trace!("Attempting to parse ethertype: 0x{:04x}", ethertype);

    // Add packet dump for debugging unknown types
    if !is_known_ethertype(ethertype) {
        debug!("Unknown EtherType: 0x{:04x}", ethertype);
        dump_packet_details(packet, "Unknown EtherType");
    }

    if vpn::is_vpn_packet(ethertype) {
        debug!(
            "Detected {} (0x{:04x})",
            vpn::get_vpn_protocol_name(ethertype),
            ethertype
        );
        match ethertype {
            0x0A08 => vpn::parse_vpn_data(packet),
            0x4B65 => vpn::parse_vpn_control(packet),
            _ => None,
        }
    } else {
        match ethertype {
            0x0806 => arp::parse_arp(packet),
            0x8847 | 0x8848 => mpls::parse_mpls(packet),
            0x12B5 => vxlan::parse_vxlan(packet),
            0x88B8 => wireguard::parse_wireguard(packet),
            // Add common experimental/vendor-specific ranges
            0xB800..=0xBFFF => {
                debug!("Experimental ethertype: 0x{:04x}", ethertype);
                parse_custom_protocol(packet)
            }
            0x3600..=0x36FF => {
                debug!("Vendor-specific ethertype: 0x{:04x}", ethertype);
                parse_custom_protocol(packet)
            }
            _ => {
                trace!("Unhandled ethertype: 0x{:04x}", ethertype);
                None
            }
        }
    }
}

// Helper function to identify known ethertypes
fn is_known_ethertype(ethertype: u16) -> bool {
    matches!(
        ethertype,
        0x0806 | // ARP
        0x8847 | 0x8848 | // MPLS
        0x12B5 | // VXLAN
        0x88B8 | // WireGuard
        0x0A08 | // VPN Data
        0x4B65 // VPN Control
    )
}

// Move dump_packet_details to mod.rs since it's useful for all ethertype parsers
pub(crate) fn dump_packet_details(packet: &[u8], prefix: &str) {
    trace!("{} packet dump:", prefix);
    trace!("Packet length: {} bytes", packet.len());

    // Print first few bytes as potential header
    if packet.len() >= 4 {
        debug!(
            "Potential header: {:02x} {:02x} {:02x} {:02x}",
            packet[0], packet[1], packet[2], packet[3]
        );
    }

    // Full packet dump in chunks
    for (i, chunk) in packet.chunks(16).enumerate() {
        let hex = chunk
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(" ");

        // Also show ASCII representation where possible
        let ascii: String = chunk
            .iter()
            .map(|&b| if b.is_ascii_graphic() { b as char } else { '.' })
            .collect();

        trace!("[{:04x}] {:<48} {}", i * 16, hex, ascii);
    }
}

fn parse_custom_protocol(packet: &[u8]) -> Option<super::RawProtocolHeader> {
    if packet.len() < 4 {
        warn!("Custom protocol packet too short: {} bytes", packet.len());
        dump_packet_details(packet, "Short custom protocol packet");
        return None;
    }

    // First try to identify if this is a header-only packet or contains payload
    let (header_size, has_payload) = analyze_packet_structure(packet);

    // Extract the payload if it exists
    let payload = if has_payload && packet.len() > header_size {
        Some(packet[header_size..].to_vec())
    } else {
        None
    };

    // Create header with the packet information
    Some(super::RawProtocolHeader::new(
        None,
        None,
        ((packet[0] as u16) << 8) | packet[1] as u16, // First two bytes often indicate source
        ((packet[2] as u16) << 8) | packet[3] as u16, // Next two bytes often indicate destination
        packet[0],                                    // First byte might indicate protocol type
        packet.len() as u16,
        payload,
    ))
}

fn analyze_packet_structure(packet: &[u8]) -> (usize, bool) {
    // Common packet patterns analysis
    match packet[0] {
        // Check for common header patterns
        0xB8..=0xBF => {
            debug!("Possible experimental protocol header");
            (8, true) // 8-byte header with payload
        }
        0x36..=0x37 => {
            debug!("Possible vendor-specific protocol header");
            (6, true) // 6-byte header with payload
        }
        0x6C => {
            debug!("Possible custom encapsulation protocol");
            (4, true) // 4-byte header with payload
        }
        _ => {
            // Default assumption: 4-byte header, rest is payload
            debug!("Unknown protocol structure, using default parsing");
            // dump_packet_details(packet, "Unknown protocol structure");
            (4, packet.len() > 4)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_parse_ethertype_arp() {
        // Standard ARP packet
        let packet = [
            0x00, 0x01, // Hardware type: Ethernet
            0x08, 0x00, // Protocol type: IPv4
            0x06, 0x04, // Hardware size: 6, Protocol size: 4
            0x00, 0x01, // Operation: Request
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, // Sender MAC
            192, 168, 1, 1, // Sender IP
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Target MAC
            192, 168, 1, 2, // Target IP
        ];

        let header = parse_ethertype(&packet, 0x0806).unwrap();
        assert_eq!(header.protocol, 0x08);
        assert_eq!(header.src_ip, Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert_eq!(header.dst_ip, Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2))));
    }

    #[test]
    fn test_parse_ethertype_mpls() {
        // MPLS packet with label 100
        let packet = [
            0x00, 0x01, 0x90, 0x3f, // Label: 100, TC: 0, S: 1, TTL: 63
            0x45, 0x00, 0x00, 0x1c, // Start of inner IPv4 packet
        ];

        let header = parse_ethertype(&packet, 0x8847);
        assert!(header.is_some());
        let header = header.unwrap();
        assert_eq!(header.protocol, 137); // MPLS protocol number
    }

    #[test]
    fn test_parse_ethertype_vxlan() {
        // VXLAN packet with standard header
        let packet = [
            0x08, 0x00, 0x00, 0x00, // VXLAN flags and reserved
            0x00, 0x00, 0x64, 0x00, // VNI: 100, reserved
            // Inner Ethernet frame would follow
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        ];

        let header = parse_ethertype(&packet, 0x12B5);
        assert!(header.is_some());
        let header = header.unwrap();
        assert_eq!(header.protocol, 0x12); // VXLAN protocol identifier
    }

    #[test]
    fn test_parse_ethertype_wireguard() {
        // WireGuard handshake initiation packet (must be exactly 148 bytes)
        let mut packet = vec![
            0x01, 0x00, 0x00, 0x00, // Message type: 1 (Handshake initiation)
        ];
        // Pad to exactly 148 bytes as required by WireGuard protocol
        packet.extend(vec![0u8; 144]);

        let header = parse_ethertype(&packet, 0x88B8);
        assert!(header.is_some());
        
        let header = header.unwrap();
        assert_eq!(header.protocol, 1); // Message type
        assert_eq!(header.flags, Some(1)); // Handshake flag
        assert_eq!(header.version, Some(1)); // WireGuard version

        // Test WireGuard data packet (minimum 16 bytes)
        let data_packet = vec![
            0x04, 0x00, 0x00, 0x00, // Message type: 4 (Data)
            0x12, 0x34, 0x56, 0x78, // Counter
            0x9a, 0xbc, 0xde, 0xf0, // Encrypted data
            0x11, 0x22, 0x33, 0x44, // More encrypted data
        ];

        let header = parse_ethertype(&data_packet, 0x88B8);
        assert!(header.is_some());
        let header = header.unwrap();
        assert_eq!(header.protocol, 4); // Data message type
    }

    #[test]
    fn test_parse_ethertype_vpn_data() {
        let packet = [
            0x05, 0x02, // Version 5, flags 2
            0x12, 0x34, // Sequence
            0xde, 0xad, 0xbe, 0xef, // Payload
        ];

        let header = parse_ethertype(&packet, 0x0A08);
        assert!(header.is_some());
        let header = header.unwrap();
        assert_eq!(header.src_port, 2186); // VPN_DATA_PORT
    }

    #[test]
    fn test_parse_ethertype_vpn_control() {
        let packet = [
            0x03, 0x01, // Type 3, flags 1
            0x56, 0x78, // Message ID
            0xca, 0xfe, 0xba, 0xbe, // Control data
        ];

        let header = parse_ethertype(&packet, 0x4B65);
        assert!(header.is_some());
        let header = header.unwrap();
        assert_eq!(header.src_port, 19301); // VPN_CONTROL_PORT
    }

    #[test]
    fn test_parse_ethertype_experimental() {
        let packet = [0xB8, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];

        let header = parse_ethertype(&packet, 0xB801);
        assert!(header.is_some());
    }

    #[test]
    fn test_parse_ethertype_vendor_specific() {
        let packet = [0x36, 0x01, 0x02, 0x03, 0x04, 0x05];

        let header = parse_ethertype(&packet, 0x3601);
        assert!(header.is_some());
    }

    #[test]
    fn test_parse_ethertype_unknown() {
        let packet = [0x12, 0x34, 0x56, 0x78];

        let header = parse_ethertype(&packet, 0xFFFF);
        assert!(header.is_none());
    }

    #[test]
    fn test_parse_ethertype_too_short() {
        let packet = [0x00]; // Too short for any meaningful parsing

        let header = parse_ethertype(&packet, 0x0806);
        assert!(header.is_none());
    }

    #[test]
    fn test_is_known_ethertype() {
        assert!(is_known_ethertype(0x0806)); // ARP
        assert!(is_known_ethertype(0x8847)); // MPLS
        assert!(is_known_ethertype(0x88B8)); // WireGuard
        assert!(!is_known_ethertype(0xFFFF)); // Unknown
    }

    #[test]
    fn test_analyze_packet_structure() {
        // Test experimental protocol
        let packet = [0xB8, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09];
        let (header_size, has_payload) = analyze_packet_structure(&packet);
        assert_eq!(header_size, 8);
        assert!(has_payload);

        // Test vendor-specific protocol
        let packet = [0x36, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
        let (header_size, has_payload) = analyze_packet_structure(&packet);
        assert_eq!(header_size, 6);
        assert!(has_payload);

        // Test custom encapsulation
        let packet = [0x6C, 0x01, 0x02, 0x03, 0x04, 0x05];
        let (header_size, has_payload) = analyze_packet_structure(&packet);
        assert_eq!(header_size, 4);
        assert!(has_payload);

        // Test unknown protocol
        let packet = [0xFF, 0x01, 0x02, 0x03, 0x04, 0x05];
        let (header_size, has_payload) = analyze_packet_structure(&packet);
        assert_eq!(header_size, 4);
        assert!(has_payload);
    }
}
