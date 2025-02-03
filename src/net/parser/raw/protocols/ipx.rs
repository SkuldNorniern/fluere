use crate::net::parser::raw::protocols::ProtocolParser;
use crate::net::parser::raw::RawProtocolHeader;

pub struct IpxParser;

// IPX Packet Types
const UNKNOWN: u8 = 0;
const RIP: u8 = 1; // Routing Information Protocol
const ECHO: u8 = 2; // Echo Packet
const ERROR: u8 = 3; // Error Packet
const PEP: u8 = 4; // Packet Exchange Protocol (used for SAP)
const SPX: u8 = 5; // Sequenced Packet Exchange
const NCP: u8 = 17; // NetWare Core Protocol
const BROADCAST: u8 = 20; // Broadcast

impl IpxParser {
    // IPX Packet Structure:
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |      Checksum (always 0xFFFF)  |         Packet Length         |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |    Transport Control (hops)    |        Packet Type            |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                     Destination Network (4 bytes)               |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                     Destination Node (6 bytes)                  |
    // |                                                                |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |         Destination Socket     |      Source Network (4 bytes)  |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                                                                |
    // |                      Source Node (6 bytes)                     |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |           Source Socket        |                               |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    fn parse_node_address(bytes: &[u8]) -> Option<String> {
        if bytes.len() < 6 {
            return None;
        }
        Some(format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
        ))
    }

    fn parse_network_number(bytes: &[u8]) -> Option<u32> {
        if bytes.len() < 4 {
            return None;
        }
        Some(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }
}

impl ProtocolParser for IpxParser {
    fn protocol_number() -> u8 {
        // IPX doesn't have a standard IP protocol number since it's a different protocol suite
        // Using a placeholder value
        0x1D
    }

    fn parse_packet(payload: &[u8], _protocol_number: u8) -> Option<RawProtocolHeader> {
        if payload.len() < 30 {
            // Minimum IPX header size
            return None;
        }

        // Verify checksum is 0xFFFF (IPX doesn't use checksum)
        let checksum = u16::from_be_bytes([payload[0], payload[1]]);
        if checksum != 0xFFFF {
            return None;
        }

        let packet_length = u16::from_be_bytes([payload[2], payload[3]]);
        let transport_control = payload[4]; // hop count
        let packet_type = payload[5];

        // Parse destination and source addresses
        let dst_network = Self::parse_network_number(&payload[6..10]);
        let dst_node = Self::parse_node_address(&payload[10..16]);
        let dst_socket = u16::from_be_bytes([payload[16], payload[17]]);

        let src_network = Self::parse_network_number(&payload[18..22]);
        let src_node = Self::parse_node_address(&payload[22..28]);
        let src_socket = u16::from_be_bytes([payload[28], payload[29]]);

        // Create header with the parsed information
        let mut header = RawProtocolHeader::new(
            None,
            None,
            dst_socket,
            src_socket,
            Self::protocol_number(),
            packet_length,
            if payload.len() > 30 {
                Some(payload[30..].to_vec())
            } else {
                None
            },
        )
        .with_raw_packet(payload.to_vec())
        .with_flags(packet_type)
        .with_ttl(transport_control);

        // Add network numbers as custom fields
        if let Some(dst_net) = dst_network {
            header = header.with_dst_network(dst_net);
        }
        if let Some(src_net) = src_network {
            header = header.with_src_network(src_net);
        }

        Some(header)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipx_parse_valid() {
        let payload = vec![
            0xFF, 0xFF, // Checksum (always 0xFFFF)
            0x00, 0x1E, // Packet Length (30 bytes)
            0x00, // Transport Control
            RIP,  // Packet Type (RIP)
            0x00, 0x00, 0x00, 0x01, // Destination Network
            0x00, 0x60, 0x08, 0x77, 0x88, 0x99, // Destination Node
            0x00, 0x01, // Destination Socket
            0x00, 0x00, 0x00, 0x02, // Source Network
            0x00, 0x60, 0x08, 0xAA, 0xBB, 0xCC, // Source Node
            0x00, 0x02, // Source Socket
        ];

        let result = IpxParser::parse_packet(&payload, IpxParser::protocol_number());
        assert!(result.is_some());

        let header = result.unwrap();
        assert_eq!(header.src_port, 2); // Source Socket
        assert_eq!(header.dst_port, 1); // Destination Socket
        assert_eq!(header.flags, Some(RIP)); // Packet Type
        assert_eq!(header.ttl, Some(0)); // Transport Control
        assert_eq!(header.dst_network, Some(1)); // Destination Network
        assert_eq!(header.src_network, Some(2)); // Source Network
    }

    #[test]
    fn test_ipx_parse_invalid_checksum() {
        let payload = vec![
            0x00, 0x00, // Invalid Checksum
            0x00, 0x1E, // Rest of the header...
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        let result = IpxParser::parse_packet(&payload, IpxParser::protocol_number());
        assert!(result.is_none());
    }

    #[test]
    fn test_ipx_parse_insufficient_length() {
        let payload = vec![0xFF, 0xFF, 0x00]; // Too short
        let result = IpxParser::parse_packet(&payload, IpxParser::protocol_number());
        assert!(result.is_none());
    }
}
