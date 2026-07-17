use std::net::{IpAddr, Ipv4Addr};

use log::{debug, trace, warn};

use paccel::engine::{BuiltinPacketParser, TransportSegment};
use paccel::packet::{Ipv4Packet, Ipv6Packet, TcpPacket, UdpPacket};

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
    pub qrv: Option<u8>,
    pub qqic: Option<u8>,
    pub ttl: Option<u8>,
    pub src_network: Option<u32>,
    pub dst_network: Option<u32>,
    pub checksum: Option<u16>,
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

    fn build_ethernet_frame(payload: &[u8], ethertype: u16) -> Vec<u8> {
        let mut frame = Vec::with_capacity(14 + payload.len());
        frame.extend_from_slice(&[0u8; 12]);
        frame.extend_from_slice(&ethertype.to_be_bytes());
        frame.extend_from_slice(payload);
        frame
    }

    fn parsed_to_header(
        parsed: &paccel::engine::ParsedPacket,
        length: u16,
        payload: Option<Vec<u8>>,
    ) -> Option<Self> {
        if let Some(arp) = &parsed.arp {
            return Some(
                Self::new(
                    Some(IpAddr::V4(arp.sender_protocol_addr)),
                    Some(IpAddr::V4(arp.target_protocol_addr)),
                    0,
                    0,
                    4,
                    length,
                    payload,
                )
                .with_ethertype(0x0806),
            );
        }
        if let Some(ipv4) = &parsed.ipv4 {
            let (src_port, dst_port) = match &parsed.transport {
                Some(TransportSegment::Tcp(t)) => (t.source_port, t.destination_port),
                Some(TransportSegment::Udp(u)) => (u.source_port, u.destination_port),
                _ => (0, 0),
            };
            return Some(
                Self::new(
                    Some(IpAddr::V4(ipv4.source)),
                    Some(IpAddr::V4(ipv4.destination)),
                    src_port,
                    dst_port,
                    ipv4.protocol,
                    length,
                    payload,
                )
                .with_ttl(ipv4.ttl)
                .with_ethertype(0x0800),
            );
        }
        if let Some(ipv6) = &parsed.ipv6 {
            let (src_port, dst_port) = match &parsed.transport {
                Some(TransportSegment::Tcp(t)) => (t.source_port, t.destination_port),
                Some(TransportSegment::Udp(u)) => (u.source_port, u.destination_port),
                _ => (0, 0),
            };
            return Some(
                Self::new(
                    Some(IpAddr::V6(ipv6.source)),
                    Some(IpAddr::V6(ipv6.destination)),
                    src_port,
                    dst_port,
                    ipv6.next_header,
                    length,
                    payload,
                )
                .with_ethertype(0x86DD),
            );
        }
        None
    }

    pub fn from_raw_packet(payload: &[u8], protocol_hint: u8) -> Option<Self> {
        trace!(
            "Attempting raw packet parsing with protocol hint: {}",
            protocol_hint
        );

        let outer_ipv4 = if payload.len() >= 20 && (payload[0] >> 4) == 4 {
            let ihl = (payload[0] & 0x0F) as usize;
            let hdr_len = ihl * 4;
            if ihl >= 5 && hdr_len <= payload.len() {
                let src = IpAddr::V4(Ipv4Addr::new(
                    payload[12], payload[13], payload[14], payload[15],
                ));
                let dst = IpAddr::V4(Ipv4Addr::new(
                    payload[16], payload[17], payload[18], payload[19],
                ));
                let proto = payload[9];
                let (sp, dp) = if hdr_len + 4 <= payload.len() {
                    let t = &payload[hdr_len..];
                    (
                        u16::from_be_bytes([t[0], t[1]]),
                        u16::from_be_bytes([t[2], t[3]]),
                    )
                } else {
                    (0, 0)
                };
                Some((src, dst, sp, dp, proto))
            } else {
                None
            }
        } else {
            None
        };

        if payload.len() >= 1 && (payload[0] >> 4) == 6 {
            if let Some(ipv6) = Ipv6Packet::new(payload) {
                let proto = ipv6.next_header();
                let l4 = ipv6.payload();
                let (src_port, dst_port) = match proto {
                    6 => TcpPacket::new(l4)
                        .map(|t| (t.source_port(), t.destination_port()))
                        .or_else(|| {
                            if l4.len() >= 4 {
                                Some((
                                    u16::from_be_bytes([l4[0], l4[1]]),
                                    u16::from_be_bytes([l4[2], l4[3]]),
                                ))
                            } else {
                                None
                            }
                        })
                        .unwrap_or((0, 0)),
                    17 => UdpPacket::new(l4)
                        .map(|u| (u.source_port(), u.destination_port()))
                        .or_else(|| {
                            if l4.len() >= 4 {
                                Some((
                                    u16::from_be_bytes([l4[0], l4[1]]),
                                    u16::from_be_bytes([l4[2], l4[3]]),
                                ))
                            } else {
                                None
                            }
                        })
                        .unwrap_or((0, 0)),
                    _ => (0, 0),
                };
                return Some(Self::new(
                    Some(IpAddr::V6(ipv6.source())),
                    Some(IpAddr::V6(ipv6.destination())),
                    src_port,
                    dst_port,
                    proto,
                    payload.len() as u16,
                    Some(payload.to_vec()),
                ));
            }
        }

        if let Some(ipv4) = Ipv4Packet::new(payload) {
            let proto = ipv4.protocol();
            let l4 = ipv4.payload();
            let (src_port, dst_port) = match proto {
                6 => TcpPacket::new(l4)
                    .map(|t| (t.source_port(), t.destination_port()))
                    .or_else(|| {
                        if l4.len() >= 4 {
                            Some((
                                u16::from_be_bytes([l4[0], l4[1]]),
                                u16::from_be_bytes([l4[2], l4[3]]),
                            ))
                        } else {
                            None
                        }
                    })
                    .unwrap_or((0, 0)),
                17 => UdpPacket::new(l4)
                    .map(|u| (u.source_port(), u.destination_port()))
                    .or_else(|| {
                        if l4.len() >= 4 {
                            Some((
                                u16::from_be_bytes([l4[0], l4[1]]),
                                u16::from_be_bytes([l4[2], l4[3]]),
                            ))
                        } else {
                            None
                        }
                    })
                    .unwrap_or((0, 0)),
                _ => (0, 0),
            };
            return Some(
                Self::new(
                    Some(IpAddr::V4(ipv4.source())),
                    Some(IpAddr::V4(ipv4.destination())),
                    src_port,
                    dst_port,
                    proto,
                    payload.len() as u16,
                    Some(payload.to_vec()),
                )
                .with_ttl(64),
            );
        }

        if let Some((src_ip, dst_ip, src_port, dst_port, actual_protocol)) = outer_ipv4 {
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

        if let Some(tcp) = TcpPacket::new(payload) {
            debug!("Parsed as TCP via paccel");
            return Some(Self::new(
                None,
                None,
                tcp.source_port(),
                tcp.destination_port(),
                6,
                payload.len() as u16,
                Some(payload.to_vec()),
            ));
        }
        if let Some(udp) = UdpPacket::new(payload) {
            debug!("Parsed as UDP via paccel");
            return Some(Self::new(
                None,
                None,
                udp.source_port(),
                udp.destination_port(),
                17,
                payload.len() as u16,
                Some(payload.to_vec()),
            ));
        }

        if payload.len() < 4 {
            warn!("Payload too short for generic analysis");
            return None;
        }

        let (sp, dp, payload_vec) = match protocol_hint {
            0xb9 => {
                let (s, d) = if payload.len() >= 4 {
                    (
                        u16::from_be_bytes([payload[0], payload[1]]),
                        u16::from_be_bytes([payload[2], payload[3]]),
                    )
                } else {
                    (0, 0)
                };
                (s, d, payload.get(4..).unwrap_or(&[]).to_vec())
            }
            0x36 => {
                let (s, d) = if payload.len() >= 2 {
                    (payload[0] as u16, payload[1] as u16)
                } else {
                    (0, 0)
                };
                (s, d, payload.get(2..).unwrap_or(&[]).to_vec())
            }
            _ => {
                let s = u16::from_be_bytes([payload[0], payload[1]]);
                let d = u16::from_be_bytes([payload[2], payload[3]]);
                (s, d, payload.to_vec())
            }
        };

        let mut header = Self::new(
            None,
            None,
            sp,
            dp,
            protocol_hint,
            payload.len() as u16,
            Some(payload_vec),
        );
        if let Some((src_ip, dst_ip, s, d, _)) = outer_ipv4 {
            if header.src_ip.is_none() {
                header = header.with_src_ip(src_ip);
            }
            if header.dst_ip.is_none() {
                header = header.with_dst_ip(dst_ip);
            }
            if header.src_port == 0 {
                header = header.with_src_port(s);
            }
            if header.dst_port == 0 {
                header = header.with_dst_port(d);
            }
        }
        Some(header)
    }

    pub fn from_ethertype(payload: &[u8], ethertype: u16) -> Option<Self> {
        trace!(
            "Attempting to parse raw protocol from EtherType: 0x{:04x}",
            ethertype
        );

        if matches!(ethertype, 0x0806 | 0x0800 | 0x86DD) {
            let frame = Self::build_ethernet_frame(payload, ethertype);
            if let Ok(parsed) = BuiltinPacketParser::parse(&frame) {
                if let Some(header) = Self::parsed_to_header(
                    &parsed,
                    payload.len() as u16,
                    Some(payload.to_vec()),
                ) {
                    debug!("Parsed via paccel");
                    return Some(header);
                }
            }
        }

        if ethertype == 0x0800 && payload.len() >= 20 {
            return Self::from_raw_packet(payload, payload[9]);
        }

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
        let packet = [
            0x45, 0x00, 0x00, 0x28, 0x12, 0x34, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00,
            192, 168, 1, 1, 192, 168, 1, 2,
            0x00, 0x50, 0x01, 0xbb, 0x00, 0x00, 0x00, 0x00,
        ];
        let header = RawProtocolHeader::from_raw_packet(&packet, 6).unwrap();
        assert_eq!(header.src_ip, Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert_eq!(header.dst_ip, Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2))));
        assert_eq!(header.src_port, 80);
        assert_eq!(header.dst_port, 443);
        assert_eq!(header.protocol, 6);
    }

    #[test]
    fn test_from_raw_packet_malformed_ipv4() {
        let packet = [
            0x44, 0x00, 0x00, 0x14, 0x12, 0x34, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00,
            192, 168, 1, 1, 192, 168, 1, 2,
        ];
        let header = RawProtocolHeader::from_raw_packet(&packet, 6);
        assert!(header.is_some());
        let header = header.unwrap();
        assert_eq!(header.protocol, 6);
    }

    #[test]
    fn test_from_raw_packet_too_short() {
        let packet = [0x45, 0x00];
        let header = RawProtocolHeader::from_raw_packet(&packet, 6);
        assert!(header.is_none());
    }

    #[test]
    fn test_from_raw_packet_netflix_vpn_pattern() {
        let packet = [0x00, 0x50, 0x01, 0xbb, 0xde, 0xad, 0xbe, 0xef];
        let header = RawProtocolHeader::from_raw_packet(&packet, 0xb9).unwrap();
        assert_eq!(header.src_port, 80);
        assert_eq!(header.dst_port, 443);
        assert_eq!(header.protocol, 0xb9);
        assert_eq!(header.payload.as_ref().unwrap(), &[0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn test_from_raw_packet_custom_vpn_pattern() {
        let packet = [0x50, 0xbb, 0xde, 0xad, 0xbe, 0xef];
        let header = RawProtocolHeader::from_raw_packet(&packet, 0x36).unwrap();
        assert_eq!(header.src_port, 0x50);
        assert_eq!(header.dst_port, 0xbb);
        assert_eq!(header.protocol, 0x36);
        assert_eq!(header.payload.as_ref().unwrap(), &[0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn test_from_raw_packet_generic_fallback() {
        let packet = [0x12, 0x34, 0x56, 0x78, 0xaa, 0xbb, 0xcc, 0xdd];
        let header = RawProtocolHeader::from_raw_packet(&packet, 99).unwrap();
        assert_eq!(header.src_port, 0x1234);
        assert_eq!(header.dst_port, 0x5678);
        assert_eq!(header.protocol, 99);
        assert_eq!(header.payload.as_ref().unwrap(), &packet);
    }

    #[test]
    fn test_from_ethertype_ipv4() {
        let packet = [
            0x45, 0x00, 0x00, 0x1c, 0x12, 0x34, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00,
            192, 168, 1, 1, 192, 168, 1, 2, 0x00, 0x35, 0x00, 0x35,
        ];
        let header = RawProtocolHeader::from_ethertype(&packet, 0x0800).unwrap();
        assert_eq!(header.src_ip, Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert_eq!(header.dst_ip, Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2))));
        assert_eq!(header.protocol, 17);
    }

    #[test]
    fn test_from_ethertype_unknown() {
        let packet = [0x12, 0x34, 0x56, 0x78, 0xaa, 0xbb, 0xcc, 0xdd];
        let header = RawProtocolHeader::from_ethertype(&packet, 0x9999);
        assert!(header.is_some());
    }

    #[test]
    fn test_from_ethertype_ipv4_tcp_port_ordering() {
        let packet = [
            0x45, 0x00, 0x00, 0x28, 0x12, 0x34, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00,
            192, 0, 2, 1, 198, 51, 100, 2, 0x12, 0x34, 0x00, 0x50, 0x00, 0x00, 0x00,
            0x01, 0x00, 0x00, 0x00, 0x00, 0x50, 0x02, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        let header = RawProtocolHeader::from_ethertype(&packet, 0x0800).unwrap();

        assert_eq!(header.src_port, 4660);
        assert_eq!(header.dst_port, 80);
    }

    #[test]
    fn test_from_ethertype_ipv4_udp_port_ordering() {
        let packet = [
            0x45, 0x00, 0x00, 0x1c, 0x12, 0x34, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00,
            192, 0, 2, 1, 198, 51, 100, 2, 0x12, 0x34, 0x00, 0x50, 0x00, 0x08, 0x00,
            0x00,
        ];

        let header = RawProtocolHeader::from_ethertype(&packet, 0x0800).unwrap();

        assert_eq!(header.src_port, 4660);
        assert_eq!(header.dst_port, 80);
    }

    #[test]
    fn test_from_raw_packet_truncated_inputs_do_not_panic() {
        let short_inputs: &[&[u8]] = &[&[], &[0x45], &[0x45, 0x00, 0x00]];
        for packet in short_inputs {
            let result = std::panic::catch_unwind(|| {
                RawProtocolHeader::from_raw_packet(packet, 6)
            });
            assert!(result.is_ok());
            assert!(result.unwrap().is_none());
        }

        let truncated_ipv4 = [
            0x45, 0x00, 0x00, 0x28, 0x12, 0x34, 0x40, 0x00, 0x40, 0x06,
        ];
        assert!(std::panic::catch_unwind(|| {
            RawProtocolHeader::from_raw_packet(&truncated_ipv4, 6)
        })
        .is_ok());
    }

    #[test]
    fn test_from_ethertype_truncated_inputs_do_not_panic() {
        let short_inputs: &[&[u8]] = &[&[], &[0x45], &[0x45, 0x00, 0x00]];
        for packet in short_inputs {
            let result = std::panic::catch_unwind(|| {
                RawProtocolHeader::from_ethertype(packet, 0x0800)
            });
            assert!(result.is_ok());
            assert!(result.unwrap().is_none());
        }

        let truncated_ipv4 = [
            0x45, 0x00, 0x00, 0x28, 0x12, 0x34, 0x40, 0x00, 0x40, 0x06,
        ];
        assert!(std::panic::catch_unwind(|| {
            RawProtocolHeader::from_ethertype(&truncated_ipv4, 0x0800)
        })
        .is_ok());
    }

    #[test]
    fn test_from_ethertype_ipv4_tcp_field_assignment() {
        let packet = [
            0x45, 0x00, 0x00, 0x28, 0x12, 0x34, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00,
            203, 0, 113, 10, 192, 0, 2, 20, 0x12, 0x34, 0x00, 0x50, 0x00, 0x00, 0x00,
            0x01, 0x00, 0x00, 0x00, 0x00, 0x50, 0x02, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        let header = RawProtocolHeader::from_ethertype(&packet, 0x0800).unwrap();

        assert_eq!(header.src_ip, Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10))));
        assert_eq!(header.dst_ip, Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 20))));
        assert_eq!(header.protocol, 6);
    }

    #[test]
    fn test_from_ethertype_ipv6_udp_fields_and_port_ordering() {
        let packet = [
            0x60, 0x00, 0x00, 0x00, 0x00, 0x08, 0x11, 0x40, 0x20, 0x01, 0x0d, 0xb8,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x02, 0x12, 0x34, 0x00, 0x50, 0x00, 0x08, 0x00, 0x00,
        ];

        let header = RawProtocolHeader::from_ethertype(&packet, 0x86DD).unwrap();

        assert_eq!(
            header.src_ip,
            Some(IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1)))
        );
        assert_eq!(
            header.dst_ip,
            Some(IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 2)))
        );
        assert_eq!(header.src_port, 4660);
        assert_eq!(header.dst_port, 80);
        assert_eq!(header.protocol, 17);
    }

    #[test]
    fn test_from_ethertype_uncommon_short_payload_does_not_panic() {
        let packet = [0x12, 0x34, 0x56];
        let result = std::panic::catch_unwind(|| {
            RawProtocolHeader::from_ethertype(&packet, 0x88B8)
        });

        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn test_ipv4_header_with_options() {
        let packet = [
            0x46, 0x00, 0x00, 0x20, 0x12, 0x34, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00,
            192, 168, 1, 1, 192, 168, 1, 2, 0x01, 0x02, 0x03, 0x04,
            0x00, 0x50, 0x01, 0xbb, 0x00, 0x00, 0x00, 0x00,
        ];
        let header = RawProtocolHeader::from_raw_packet(&packet, 6).unwrap();
        assert_eq!(header.src_ip, Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert_eq!(header.dst_ip, Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2))));
        assert_eq!(header.src_port, 80);
        assert_eq!(header.dst_port, 443);
    }

    #[test]
    fn test_ipv6_version_detection() {
        let packet = [
            0x60, 0x00, 0x00, 0x00, 0x00, 0x08, 0x11, 0x40,
            0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00, 0x00, 0x00, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x34,
            0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00, 0x00, 0x00, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x35,
            0x00, 0x35, 0x00, 0x35, 0x00, 0x08, 0x00, 0x00,
        ];
        let header = RawProtocolHeader::from_raw_packet(&packet, 17);
        assert!(header.is_some());
        let header = header.unwrap();
        assert_eq!(header.protocol, 17);
    }

    #[test]
    fn test_port_extraction_edge_cases() {
        let packet = [
            0x45, 0x00, 0x00, 0x16, 0x12, 0x34, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00,
            192, 168, 1, 1, 192, 168, 1, 2, 0x00, 0x50,
        ];
        let header = RawProtocolHeader::from_raw_packet(&packet, 6).unwrap();
        assert_eq!(header.src_port, 0);
        assert_eq!(header.dst_port, 0);
        assert_eq!(header.src_ip, Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
    }

    #[test]
    fn test_protocol_preservation() {
        let packet = [
            0x45, 0x00, 0x00, 0x1c, 0x12, 0x34, 0x40, 0x00, 0x40, 0x32, 0x00, 0x00,
            192, 168, 1, 1, 192, 168, 1, 2, 0x12, 0x34, 0x56, 0x78,
        ];
        let header = RawProtocolHeader::from_raw_packet(&packet, 99).unwrap();
        assert_eq!(header.protocol, 50);
        assert_eq!(header.src_ip, Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
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
        let packet = [
            0x45, 0x00, 0xff, 0xff, 0x12, 0x34, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00,
            192, 168, 1, 1, 192, 168, 1, 2,
        ];
        let header = RawProtocolHeader::from_raw_packet(&packet, 6);
        assert!(header.is_some());
    }

    #[test]
    fn test_ipv4_fragmented_packet() {
        let packet = [
            0x45, 0x00, 0x00, 0x1c, 0x12, 0x34, 0x20, 0x00, 0x40, 0x06, 0x00, 0x00,
            192, 168, 1, 1, 192, 168, 1, 2, 0x00, 0x50, 0x01, 0xbb,
        ];
        let header = RawProtocolHeader::from_raw_packet(&packet, 6).unwrap();
        assert_eq!(header.src_ip, Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert_eq!(header.dst_ip, Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2))));
        assert_eq!(header.protocol, 6);
    }
}
