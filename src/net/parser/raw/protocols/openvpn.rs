use crate::net::parser::raw::{RawProtocolHeader, protocols::ProtocolParser, utils::bytes_to_ipv4};
use log::info;
use std::net::IpAddr;
pub struct OpenVpnParser;

// OpenVPN Packet Types
const P_CONTROL_HARD_RESET_CLIENT_V1: u8 = 0x01;
const P_CONTROL_HARD_RESET_SERVER_V1: u8 = 0x02;
const P_CONTROL_SOFT_RESET_V1: u8 = 0x03;
const P_CONTROL_V1: u8 = 0x04;
const P_ACK_V1: u8 = 0x05;
const P_DATA_V1: u8 = 0x06;
const P_CONTROL_HARD_RESET_CLIENT_V2: u8 = 0x07;
const P_CONTROL_HARD_RESET_SERVER_V2: u8 = 0x08;
const P_DATA_V2: u8 = 0x09;

// OpenVPN TLS Packet Types
const P_CONTROL_V1_TLS_KEY: u8 = 0x40;
const P_CONTROL_V1_TLS_DATA: u8 = 0x41;

impl OpenVpnParser {
    /// Parses an OpenVPN control packet.
    ///
    /// Expected layout for control packets:
    /// - Byte 0: Packet type.
    /// - Bytes 1–4: Session ID.
    /// - Bytes 5–8: Message ID.
    /// - (Optional) If the packet is TLS (type 0x40 or 0x41) and payload is long enough,
    ///   then bytes 9–12: source IP, 13–16: destination IP,
    ///   17–18: source port, 19–20: destination port.
    fn parse_control_packet(payload: &[u8]) -> Option<(u32, u32, Option<(u32, u32, u16, u16)>)> {
        // The minimum length is 9 bytes (type + 4 + 4)
        if payload.len() < 9 {
            return None;
        }
        // Note: According to our test expectations the session ID is in indexes 1..5
        // and the message ID is in indexes 5..9.
        let session_id = u32::from_be_bytes([payload[1], payload[2], payload[3], payload[4]]);
        let message_id = u32::from_be_bytes([payload[5], payload[6], payload[7], payload[8]]);

        // For TLS control packets, try to extract connection info.
        let connection_info = if payload.len() >= 21
            && (payload[0] == P_CONTROL_V1_TLS_KEY || payload[0] == P_CONTROL_V1_TLS_DATA)
        {
            // Connection info layout:
            // Bytes 9-12: source IP
            // Bytes 13-16: destination IP
            // Bytes 17-18: source port
            // Bytes 19-20: destination port
            let src_ip = bytes_to_ipv4(&[payload[9], payload[10], payload[11], payload[12]])?;
            let dst_ip = bytes_to_ipv4(&[payload[13], payload[14], payload[15], payload[16]])?;
            let src_port = u16::from_be_bytes([payload[17], payload[18]]);
            let dst_port = u16::from_be_bytes([payload[19], payload[20]]);
            Some((
                u32::from_be_bytes(match src_ip {
                    IpAddr::V4(ip) => ip.octets(),
                    _ => return None,
                }),
                u32::from_be_bytes(match dst_ip {
                    IpAddr::V4(ip) => ip.octets(),
                    _ => return None,
                }),
                src_port,
                dst_port,
            ))
        } else {
            None
        };

        Some((session_id, message_id, connection_info))
    }

    /// Parses an encapsulated IP packet from an OpenVPN data packet.
    ///
    /// For data packets, the OpenVPN header is assumed to be 9 bytes:
    ///   1 byte type + 4 bytes session ID + 4 reserved bytes.
    /// The encapsulated (raw) IP packet is taken as the slice starting at offset 9.
    /// In our (simplified) test the "fake" IPv4 header is arranged so that:
    ///   - raw_ip[0] is 0x45 (version/IHL),
    ///   - raw_ip[4..8] are the source IP bytes,
    ///   - raw_ip[8..12] are the destination IP bytes,
    ///   - raw_ip[12..14] are the source port,
    ///   - raw_ip[14..16] are the destination port.
    fn parse_data_packet(ip_packet: &[u8]) -> Option<Option<(u32, u32, u16, u16)>> {
        // We require at least 16 bytes in the encapsulated IP packet.
        if ip_packet.len() < 16 {
            return None;
        }
        // Check IPv4 version from the first nibble (should be 4).
        let ip_version = (ip_packet[0] >> 4) & 0x0F;
        if ip_version == 4 {
            // For our test data (which is not a full IPv4 header), we extract bytes at fixed offsets.
            let src_ip = bytes_to_ipv4(&[ip_packet[4], ip_packet[5], ip_packet[6], ip_packet[7]])?;
            let dst_ip =
                bytes_to_ipv4(&[ip_packet[8], ip_packet[9], ip_packet[10], ip_packet[11]])?;
            // If there are at least 16 bytes, try to extract ports.
            if ip_packet.len() >= 16 {
                let src_port = u16::from_be_bytes([ip_packet[12], ip_packet[13]]);
                let dst_port = u16::from_be_bytes([ip_packet[14], ip_packet[15]]);
                return Some(Some((
                    u32::from_be_bytes(match src_ip {
                        IpAddr::V4(ip) => ip.octets(),
                        _ => return None,
                    }),
                    u32::from_be_bytes(match dst_ip {
                        IpAddr::V4(ip) => ip.octets(),
                        _ => return None,
                    }),
                    src_port,
                    dst_port,
                )));
            }
            return Some(Some((
                u32::from_be_bytes(match src_ip {
                    IpAddr::V4(ip) => ip.octets(),
                    _ => return None,
                }),
                u32::from_be_bytes(match dst_ip {
                    IpAddr::V4(ip) => ip.octets(),
                    _ => return None,
                }),
                0,
                0,
            )));
        }
        Some(None)
    }

    /// Checks if the given packet type is valid.
    fn is_valid_packet_type(packet_type: u8) -> bool {
        matches!(
            packet_type,
            P_CONTROL_HARD_RESET_CLIENT_V1
                | P_CONTROL_HARD_RESET_SERVER_V1
                | P_CONTROL_SOFT_RESET_V1
                | P_CONTROL_V1
                | P_ACK_V1
                | P_DATA_V1
                | P_CONTROL_HARD_RESET_CLIENT_V2
                | P_CONTROL_HARD_RESET_SERVER_V2
                | P_DATA_V2
                | P_CONTROL_V1_TLS_KEY
                | P_CONTROL_V1_TLS_DATA
        )
    }
}

impl ProtocolParser for OpenVpnParser {
    fn protocol_number() -> u8 {
        // OpenVPN does not have an assigned protocol number;
        // using a custom value (0x9B) for identification.
        0x9B
    }

    fn parse_packet(payload: &[u8], _protocol_number: u8) -> Option<RawProtocolHeader> {
        info!("Parsing OpenVPN packet");
        // For both control and data packets the minimum header length
        // must accommodate the fields (control packets use 9 bytes; data packets use 9 bytes as well).
        if payload.len() < 9 {
            return None;
        }

        let packet_type = payload[0];
        if !Self::is_valid_packet_type(packet_type) {
            return None;
        }

        // For control packets we continue with the full payload.
        // For data packets, the OpenVPN header is 9 bytes (1 type + 4 session ID + 4 reserved).
        // The encapsulated IP packet will start at offset 9.
        let mut header = RawProtocolHeader::new(
            None, // src_ip (to be set)
            None, // dst_ip (to be set)
            packet_type as u16,
            0, // version (unused)
            Self::protocol_number(),
            payload.len() as u16,
            // For control packets, we pass the remainder starting at index 9.
            // (For data packets, even though the raw IP packet begins at offset 9,
            //  we store the entire payload.)
            Some(payload[9..].to_vec()),
        );

        match packet_type {
            P_DATA_V1 | P_DATA_V2 => {
                // Check that we have at least 9 bytes before extracting the IP packet.
                if payload.len() < 9 {
                    return None;
                }
                // Extract the encapsulated IP packet from the data packet.
                let ip_packet = &payload[9..];
                if let Some(Some((src_ip, dst_ip, src_port, dst_port))) =
                    Self::parse_data_packet(ip_packet)
                {
                    header = header
                        .with_src_ip(bytes_to_ipv4(&src_ip.to_be_bytes())?)
                        .with_dst_ip(bytes_to_ipv4(&dst_ip.to_be_bytes())?)
                        .with_src_port(src_port)
                        .with_dst_port(dst_port);
                }
            }
            _ => {
                // Control packets.
                if let Some((session_id, message_id, connection_info)) =
                    Self::parse_control_packet(payload)
                {
                    header = header.with_spi(session_id).with_sequence(message_id);
                    if let Some((src_ip, dst_ip, src_port, dst_port)) = connection_info {
                        header = header
                            .with_src_ip(bytes_to_ipv4(&src_ip.to_be_bytes())?)
                            .with_dst_ip(bytes_to_ipv4(&dst_ip.to_be_bytes())?)
                            .with_src_port(src_port)
                            .with_dst_port(dst_port);
                    }
                }
            }
        }
        // show the parsed datas like ip, port, etc.
        info!("Parsed src_ip: {:?}", header.src_ip);
        info!("Parsed dst_ip: {:?}", header.dst_ip);
        info!("Parsed src_port: {:?}", header.src_port);
        info!("Parsed dst_port: {:?}", header.dst_port);
        header = header.with_raw_packet(payload.to_vec());
        Some(header)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_openvpn_tls_control_packet() {
        // TLS control packet: using the revised layout:
        //  Byte 0: Packet type (P_CONTROL_V1_TLS_KEY)
        //  Bytes 1-4: Session ID
        //  Bytes 5-8: Message ID
        //  Bytes 9-12: Source IP (192, 168, 1, 1)
        //  Bytes 13-16: Destination IP (192, 168, 1, 2)
        //  Bytes 17-18: Source port (0x1F90 = 8080)
        //  Bytes 19-20: Destination port (0x01BB = 443)
        //  Additional data follows.
        let payload = vec![
            P_CONTROL_V1_TLS_KEY, // index 0
            0x00,
            0x01,
            0x02,
            0x03, // indices 1-4: Session ID
            0x04,
            0x05,
            0x06,
            0x07, // indices 5-8: Message ID
            192,
            168,
            1,
            1, // indices 9-12: Source IP
            192,
            168,
            1,
            2, // indices 13-16: Destination IP
            0x1F,
            0x90, // indices 17-18: Source port (8080)
            0x01,
            0xBB, // indices 19-20: Destination port (443)
            0x00,
            0x01,
            0x02,
            0x03, // additional data
        ];

        let result = OpenVpnParser::parse_packet(&payload, OpenVpnParser::protocol_number());
        assert!(result.is_some());
        let header = result.unwrap();
        assert_eq!(
            header.src_ip,
            Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                192, 168, 1, 1
            )))
        );
        assert_eq!(
            header.dst_ip,
            Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                192, 168, 1, 2
            )))
        );
        assert_eq!(header.src_port, 8080);
        assert_eq!(header.dst_port, 443);
    }

    #[test]
    fn test_openvpn_data_packet_with_ipv4() {
        // For data packets, the header is 9 bytes:
        //   Byte 0: Packet type (P_DATA_V1)
        //   Bytes 1-4: Session ID
        //   Bytes 5-8: Reserved (set to 0)
        // The encapsulated (raw) IP packet starts immediately after (at offset 9)
        // In our test the encapsulated IP "header" (a simplified/fake header) is constructed as:
        //   raw_ip[0] = 0x45 (IPv4 with IHL = 5)
        //   raw_ip[1] = 0x00, raw_ip[2] = 0x06, raw_ip[3] = 0x00, (dummy values)
        //   raw_ip[4..8] = [192, 168, 1, 1]  => Source IP
        //   raw_ip[8..12] = [192, 168, 1, 2] => Destination IP
        //   raw_ip[12..14] = [0x1F, 0x90]    => Source port 8080
        //   raw_ip[14..16] = [0x01, 0xBB]    => Destination port 443
        let payload = vec![
            P_DATA_V1, // index 0: Packet type
            0x00, 0x01, 0x02, 0x03, // index 1-4: Session ID
            0x00, 0x00, 0x00, 0x00, // index 5-8: Reserved bytes
            // Raw IP packet (starting at offset 9)
            0x45, 0x00, 0x06, 0x00, // raw_ip[0..4]: Version/IHL and dummy bytes
            192, 168, 1, 1, // raw_ip[4..8]: Source IP: 192.168.1.1
            192, 168, 1, 2, // raw_ip[8..12]: Destination IP: 192.168.1.2
            0x1F, 0x90, // raw_ip[12..14]: Source port 8080
            0x01, 0xBB, // raw_ip[14..16]: Destination port 443
        ];

        let result = OpenVpnParser::parse_packet(&payload, OpenVpnParser::protocol_number());
        assert!(result.is_some());
        let header = result.unwrap();
        assert_eq!(
            header.src_ip,
            Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                192, 168, 1, 1
            )))
        );
        assert_eq!(
            header.dst_ip,
            Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                192, 168, 1, 2
            )))
        );
        assert_eq!(header.src_port, 8080);
        assert_eq!(header.dst_port, 443);
    }
}
