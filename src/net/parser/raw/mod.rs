use std::net::{IpAddr, Ipv4Addr};

use log::{trace, warn};

use paccel::engine::{BuiltinPacketParser, ParsedPacket, TransportSegment};

/// `LINKTYPE_RAW`: no link-layer header, the frame starts at the IP header.
const LINKTYPE_RAW: u16 = 101;

/// Minimal L3/L4 tuple recovered from a frame that paccel's normal path could
/// not turn into a flow key. Only the fields the flow builders read are kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawProtocolHeader {
    pub src_ip: Option<IpAddr>,
    pub dst_ip: Option<IpAddr>,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub ttl: Option<u8>,
}

impl RawProtocolHeader {
    fn new(
        src_ip: Option<IpAddr>,
        dst_ip: Option<IpAddr>,
        src_port: u16,
        dst_port: u16,
        protocol: u8,
    ) -> Self {
        Self {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
            ttl: None,
        }
    }

    fn with_ttl(mut self, ttl: u8) -> Self {
        self.ttl = Some(ttl);
        self
    }

    /// Ports of the transport segment paccel decoded, `(0, 0)` when there is
    /// none (non-TCP/UDP, or a header too truncated to decode).
    fn transport_ports(parsed: &ParsedPacket) -> (u16, u16) {
        match &parsed.transport {
            Some(TransportSegment::Tcp(tcp)) => (tcp.source_port, tcp.destination_port),
            Some(TransportSegment::Udp(udp)) => (udp.source_port, udp.destination_port),
            _ => (0, 0),
        }
    }

    /// Project a paccel parse onto the tuple, preferring ARP, then IPv4, then
    /// IPv6. Returns `None` when the parse reached no network layer at all.
    fn from_parsed(parsed: &ParsedPacket) -> Option<Self> {
        if let Some(arp) = &parsed.arp {
            return Some(Self::new(
                Some(IpAddr::V4(arp.sender_protocol_addr)),
                Some(IpAddr::V4(arp.target_protocol_addr)),
                0,
                0,
                // No IP protocol number: ARP is identified by its EtherType,
                // which the key carries.
                0,
            ));
        }
        if let Some(ipv4) = &parsed.ipv4 {
            let (src_port, dst_port) = Self::transport_ports(parsed);
            return Some(
                Self::new(
                    Some(IpAddr::V4(ipv4.source)),
                    Some(IpAddr::V4(ipv4.destination)),
                    src_port,
                    dst_port,
                    ipv4.protocol,
                )
                .with_ttl(ipv4.ttl),
            );
        }
        if let Some(ipv6) = &parsed.ipv6 {
            let (src_port, dst_port) = Self::transport_ports(parsed);
            // Historical record shape: IPv6 hop_limit is not mapped to TTL.
            return Some(Self::new(
                Some(IpAddr::V6(ipv6.source)),
                Some(IpAddr::V6(ipv6.destination)),
                src_port,
                dst_port,
                ipv6.resolved_next_header,
            ));
        }
        None
    }

    /// Parse `payload` as a bare IP packet (no link-layer header) through
    /// paccel, which covers IPv4, IPv6, extension-header chains and tunnels.
    fn try_ip(payload: &[u8]) -> Option<Self> {
        let parsed = BuiltinPacketParser::parse_with_linktype(payload, LINKTYPE_RAW).ok()?;
        Self::from_parsed(&parsed)
    }

    /// Sniff an IPv4 header out of `payload` even when paccel rejects the
    /// packet (bad total length, truncated body). Best-effort source of
    /// src/dst IP, protocol and the leading L4 port pair.
    fn sniff_outer_ipv4(payload: &[u8]) -> Option<Self> {
        if payload.len() < 20 || (payload[0] >> 4) != 4 {
            return None;
        }
        let ihl = (payload[0] & 0x0F) as usize;
        let hdr_len = ihl * 4;
        if ihl < 5 || hdr_len > payload.len() {
            return None;
        }
        let src = IpAddr::V4(Ipv4Addr::new(
            payload[12],
            payload[13],
            payload[14],
            payload[15],
        ));
        let dst = IpAddr::V4(Ipv4Addr::new(
            payload[16],
            payload[17],
            payload[18],
            payload[19],
        ));
        let (src_port, dst_port) = match payload.get(hdr_len..hdr_len + 4) {
            Some(l4) => (
                u16::from_be_bytes([l4[0], l4[1]]),
                u16::from_be_bytes([l4[2], l4[3]]),
            ),
            None => (0, 0),
        };
        Some(Self::new(Some(src), Some(dst), src_port, dst_port, payload[9]).with_ttl(payload[8]))
    }

    /// Last-resort port decode for a payload with no recoverable IP header,
    /// special-casing a couple of known VPN encapsulation patterns.
    fn generic_fallback(payload: &[u8], protocol_hint: u8) -> Option<Self> {
        if payload.len() < 4 {
            warn!("Payload too short for generic analysis");
            return None;
        }
        let (src_port, dst_port) = match protocol_hint {
            // Ports carried as a 16-bit big-endian pair after the hint byte.
            0xb9 => (
                u16::from_be_bytes([payload[0], payload[1]]),
                u16::from_be_bytes([payload[2], payload[3]]),
            ),
            // Single-byte port fields.
            0x36 => (u16::from(payload[0]), u16::from(payload[1])),
            _ => (
                u16::from_be_bytes([payload[0], payload[1]]),
                u16::from_be_bytes([payload[2], payload[3]]),
            ),
        };
        Some(Self::new(None, None, src_port, dst_port, protocol_hint))
    }

    /// Recover a tuple from a payload with no link-layer header, using
    /// `protocol_hint` only when no IP header can be found.
    pub fn from_raw_packet(payload: &[u8], protocol_hint: u8) -> Option<Self> {
        trace!(
            "Attempting raw packet parsing with protocol hint: {}",
            protocol_hint
        );

        Self::try_ip(payload)
            .or_else(|| Self::sniff_outer_ipv4(payload))
            .or_else(|| Self::generic_fallback(payload, protocol_hint))
    }

    /// Recover a tuple from an Ethernet payload of the given EtherType.
    pub fn from_ethertype(payload: &[u8], ethertype: u16) -> Option<Self> {
        trace!(
            "Attempting to parse raw protocol from EtherType: 0x{:04x}",
            ethertype
        );

        match ethertype {
            // ARP has no IP header, so it needs its Ethernet framing back.
            0x0806 => {
                let frame = build_ethernet_frame(payload, ethertype);
                let parsed = BuiltinPacketParser::parse(&frame).ok()?;
                Self::from_parsed(&parsed)
            }
            _ => Self::from_raw_packet(payload, ethertype as u8),
        }
    }
}

/// Wrap `payload` in a zero-addressed Ethernet header so parsers that expect a
/// link layer can see it.
fn build_ethernet_frame(payload: &[u8], ethertype: u16) -> Vec<u8> {
    let mut frame = Vec::with_capacity(14 + payload.len());
    frame.extend_from_slice(&[0u8; 12]);
    frame.extend_from_slice(&ethertype.to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    const SRC_V4: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
    const DST_V4: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));

    #[test]
    fn parses_valid_ipv4_tcp() {
        let packet = [
            0x45, 0x00, 0x00, 0x28, 0x12, 0x34, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 192, 168, 1, 1,
            192, 168, 1, 2, 0x00, 0x50, 0x01, 0xbb, 0x00, 0x00, 0x00, 0x00,
        ];
        let header = RawProtocolHeader::from_raw_packet(&packet, 6).unwrap();
        assert_eq!(header.src_ip, Some(SRC_V4));
        assert_eq!(header.dst_ip, Some(DST_V4));
        assert_eq!((header.src_port, header.dst_port), (80, 443));
        assert_eq!(header.protocol, 6);
        assert_eq!(header.ttl, Some(64));
    }

    #[test]
    fn keeps_ip_header_protocol_over_the_hint() {
        let packet = [
            0x45, 0x00, 0x00, 0x1c, 0x12, 0x34, 0x40, 0x00, 0x40, 0x32, 0x00, 0x00, 192, 168, 1, 1,
            192, 168, 1, 2, 0x12, 0x34, 0x56, 0x78,
        ];
        let header = RawProtocolHeader::from_raw_packet(&packet, 99).unwrap();
        assert_eq!(header.protocol, 50);
        assert_eq!(header.src_ip, Some(SRC_V4));
    }

    #[test]
    fn parses_ipv4_header_with_options() {
        let packet = [
            0x46, 0x00, 0x00, 0x20, 0x12, 0x34, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 192, 168, 1, 1,
            192, 168, 1, 2, 0x01, 0x02, 0x03, 0x04, 0x00, 0x50, 0x01, 0xbb, 0x00, 0x00, 0x00, 0x00,
        ];
        let header = RawProtocolHeader::from_raw_packet(&packet, 6).unwrap();
        assert_eq!(header.src_ip, Some(SRC_V4));
        assert_eq!(header.dst_ip, Some(DST_V4));
        assert_eq!((header.src_port, header.dst_port), (80, 443));
    }

    #[test]
    fn keeps_addresses_when_the_l4_header_is_truncated() {
        let packet = [
            0x45, 0x00, 0x00, 0x16, 0x12, 0x34, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 192, 168, 1, 1,
            192, 168, 1, 2, 0x00, 0x50,
        ];
        let header = RawProtocolHeader::from_raw_packet(&packet, 6).unwrap();
        assert_eq!((header.src_port, header.dst_port), (0, 0));
        assert_eq!(header.src_ip, Some(SRC_V4));
    }

    #[test]
    fn recovers_addresses_from_an_invalid_total_length() {
        let packet = [
            0x45, 0x00, 0xff, 0xff, 0x12, 0x34, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 192, 168, 1, 1,
            192, 168, 1, 2,
        ];
        let header = RawProtocolHeader::from_raw_packet(&packet, 6).unwrap();
        assert_eq!(header.src_ip, Some(SRC_V4));
        assert_eq!(header.protocol, 6);
    }

    #[test]
    fn parses_fragmented_ipv4() {
        let packet = [
            0x45, 0x00, 0x00, 0x1c, 0x12, 0x34, 0x20, 0x00, 0x40, 0x06, 0x00, 0x00, 192, 168, 1, 1,
            192, 168, 1, 2, 0x00, 0x50, 0x01, 0xbb,
        ];
        let header = RawProtocolHeader::from_raw_packet(&packet, 6).unwrap();
        assert_eq!(header.src_ip, Some(SRC_V4));
        assert_eq!(header.dst_ip, Some(DST_V4));
        assert_eq!(header.protocol, 6);
    }

    #[test]
    fn falls_back_to_the_hint_for_a_malformed_ipv4_header() {
        let packet = [
            0x44, 0x00, 0x00, 0x14, 0x12, 0x34, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 192, 168, 1, 1,
            192, 168, 1, 2,
        ];
        let header = RawProtocolHeader::from_raw_packet(&packet, 6).unwrap();
        assert_eq!(header.protocol, 6);
    }

    #[test]
    fn detects_bare_ipv6() {
        let packet = [
            0x60, 0x00, 0x00, 0x00, 0x00, 0x08, 0x11, 0x40, 0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3,
            0x00, 0x00, 0x00, 0x00, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x34, 0x20, 0x01, 0x0d, 0xb8,
            0x85, 0xa3, 0x00, 0x00, 0x00, 0x00, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x35, 0x00, 0x35,
            0x00, 0x35, 0x00, 0x08, 0x00, 0x00,
        ];
        let header = RawProtocolHeader::from_raw_packet(&packet, 17).unwrap();
        assert_eq!(header.protocol, 17);
    }

    #[test]
    fn decodes_netflix_vpn_port_pattern() {
        let packet = [0x00, 0x50, 0x01, 0xbb, 0xde, 0xad, 0xbe, 0xef];
        let header = RawProtocolHeader::from_raw_packet(&packet, 0xb9).unwrap();
        assert_eq!((header.src_port, header.dst_port), (80, 443));
        assert_eq!(header.protocol, 0xb9);
    }

    #[test]
    fn decodes_single_byte_vpn_port_pattern() {
        let packet = [0x50, 0xbb, 0xde, 0xad, 0xbe, 0xef];
        let header = RawProtocolHeader::from_raw_packet(&packet, 0x36).unwrap();
        assert_eq!((header.src_port, header.dst_port), (0x50, 0xbb));
        assert_eq!(header.protocol, 0x36);
    }

    #[test]
    fn decodes_leading_ports_for_an_unknown_protocol() {
        let packet = [0x12, 0x34, 0x56, 0x78, 0xaa, 0xbb, 0xcc, 0xdd];
        let header = RawProtocolHeader::from_raw_packet(&packet, 99).unwrap();
        assert_eq!((header.src_port, header.dst_port), (0x1234, 0x5678));
        assert_eq!(header.protocol, 99);
    }

    #[test]
    fn rejects_an_empty_payload() {
        assert!(RawProtocolHeader::from_raw_packet(&[], 6).is_none());
    }

    #[test]
    fn rejects_a_payload_shorter_than_a_port_pair() {
        assert!(RawProtocolHeader::from_raw_packet(&[0x45, 0x00], 6).is_none());
        assert!(RawProtocolHeader::from_ethertype(&[0x12, 0x34, 0x56], 0x88B8).is_none());
    }

    #[test]
    fn from_ethertype_parses_ipv4_udp() {
        let packet = [
            0x45, 0x00, 0x00, 0x1c, 0x12, 0x34, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, 192, 168, 1, 1,
            192, 168, 1, 2, 0x00, 0x35, 0x00, 0x35,
        ];
        let header = RawProtocolHeader::from_ethertype(&packet, 0x0800).unwrap();
        assert_eq!(header.src_ip, Some(SRC_V4));
        assert_eq!(header.dst_ip, Some(DST_V4));
        assert_eq!(header.protocol, 17);
    }

    #[test]
    fn from_ethertype_keeps_ipv4_tcp_field_order() {
        let packet = [
            0x45, 0x00, 0x00, 0x28, 0x12, 0x34, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 203, 0, 113,
            10, 192, 0, 2, 20, 0x12, 0x34, 0x00, 0x50, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
            0x00, 0x50, 0x02, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let header = RawProtocolHeader::from_ethertype(&packet, 0x0800).unwrap();
        assert_eq!(
            header.src_ip,
            Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)))
        );
        assert_eq!(
            header.dst_ip,
            Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 20)))
        );
        assert_eq!((header.src_port, header.dst_port), (4660, 80));
        assert_eq!(header.protocol, 6);
    }

    #[test]
    fn from_ethertype_keeps_ipv4_udp_field_order() {
        let packet = [
            0x45, 0x00, 0x00, 0x1c, 0x12, 0x34, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, 192, 0, 2, 1,
            198, 51, 100, 2, 0x12, 0x34, 0x00, 0x50, 0x00, 0x08, 0x00, 0x00,
        ];
        let header = RawProtocolHeader::from_ethertype(&packet, 0x0800).unwrap();
        assert_eq!((header.src_port, header.dst_port), (4660, 80));
    }

    #[test]
    fn from_ethertype_parses_ipv6_udp() {
        let packet = [
            0x60, 0x00, 0x00, 0x00, 0x00, 0x08, 0x11, 0x40, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x20, 0x01, 0x0d, 0xb8,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x12, 0x34,
            0x00, 0x50, 0x00, 0x08, 0x00, 0x00,
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
        assert_eq!((header.src_port, header.dst_port), (4660, 80));
        assert_eq!(header.protocol, 17);
    }

    #[test]
    fn from_ethertype_walks_ipv6_extension_headers() {
        let mut packet = vec![
            0x60, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x40, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x20, 0x01, 0x0d, 0xb8,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        ];
        // Hop-by-Hop header (next_header = UDP, one 8-byte block of PadN).
        packet.extend_from_slice(&[17, 0, 1, 4, 0, 0, 0, 0]);
        packet.extend_from_slice(&[0x12, 0x34, 0x00, 0x50, 0x00, 0x08, 0x00, 0x00]);

        let header = RawProtocolHeader::from_ethertype(&packet, 0x86DD).unwrap();
        assert_eq!(header.protocol, 17);
        assert_eq!((header.src_port, header.dst_port), (4660, 80));
    }

    #[test]
    fn from_ethertype_parses_arp() {
        let mut packet = vec![0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01];
        packet.extend_from_slice(&[0xaa; 6]);
        packet.extend_from_slice(&[10, 0, 0, 1]);
        packet.extend_from_slice(&[0x00; 6]);
        packet.extend_from_slice(&[10, 0, 0, 2]);

        let header = RawProtocolHeader::from_ethertype(&packet, 0x0806).unwrap();
        assert_eq!(header.src_ip, Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert_eq!(header.dst_ip, Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))));
        // ARP has no IP protocol number, and no longer borrows IP-in-IP's.
        assert_eq!(header.protocol, 0);
    }

    #[test]
    fn truncated_inputs_do_not_panic() {
        let short_inputs: &[&[u8]] = &[
            &[],
            &[0x45],
            &[0x45, 0x00, 0x00],
            &[0x45, 0x00, 0x00, 0x28, 0x12, 0x34, 0x40, 0x00, 0x40, 0x06],
            &[0x60, 0x00, 0x00],
        ];
        for packet in short_inputs {
            RawProtocolHeader::from_raw_packet(packet, 6);
            RawProtocolHeader::from_ethertype(packet, 0x0800);
            RawProtocolHeader::from_ethertype(packet, 0x86DD);
            RawProtocolHeader::from_ethertype(packet, 0x0806);
        }
    }
}
