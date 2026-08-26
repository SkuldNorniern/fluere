use std::net::{IpAddr, Ipv4Addr};

use crate::error::ParseError;
use crate::net::types::{Key, MacAddress};

use log::trace;
use paccel::engine::ParsedPacket;

use super::raw::RawProtocolHeader;

type FlowTuple = (IpAddr, IpAddr, u16, u16, u8);

pub fn parse_keys(packet: pcap::Packet, linktype: u16) -> Result<(Key, Key), ParseError> {
    if packet.is_empty() {
        return Err(ParseError::EmptyPacket);
    }

    let parsed = super::parse_frame(packet.data, linktype)?;
    keys_from_parsed(&parsed, packet.data)
}

/// Build a flow's forward and reverse key from an already parsed frame.
///
/// Split out of [`parse_keys`] so the capture path can decode a frame once and
/// derive both the keys and the flow record from the same parse.
pub(super) fn keys_from_parsed(
    parsed: &ParsedPacket,
    packet_data: &[u8],
) -> Result<(Key, Key), ParseError> {
    trace!("Parsing keys");
    let (src_mac, dst_mac) = mac_addresses(parsed);
    let (src_ip, dst_ip, src_port, dst_port, protocol) = extract_flow_tuple(parsed, packet_data)?;

    trace!(
        "Parsed keys: src_ip={:?} dst_ip={:?} src_port={:?} dst_port={:?} protocol={:?} src_mac={:?} dst_mac={:?}",
        src_ip, dst_ip, src_port, dst_port, protocol, src_mac, dst_mac
    );
    Ok(build_key_pair(
        src_ip, dst_ip, src_port, dst_port, protocol, src_mac, dst_mac,
    ))
}

fn mac_addresses(parsed: &ParsedPacket) -> (MacAddress, MacAddress) {
    parsed.ethernet.as_ref().map_or_else(
        || {
            let empty = MacAddress::new([0; 6]);
            (empty, empty)
        },
        |ethernet| {
            (
                MacAddress::new(ethernet.source),
                MacAddress::new(ethernet.destination),
            )
        },
    )
}

fn extract_flow_tuple(parsed: &ParsedPacket, packet_data: &[u8]) -> Result<FlowTuple, ParseError> {
    if let Some(arp) = parsed.arp.as_ref() {
        return Ok((
            IpAddr::V4(arp.sender_protocol_addr),
            IpAddr::V4(arp.target_protocol_addr),
            0,
            0,
            4,
        ));
    }

    if let Some(flow_key) = parsed.flow_key() {
        return Ok(flow_tuple_with_overrides(parsed, flow_key));
    }

    raw_fallback_tuple(parsed, packet_data)
}

fn flow_tuple_with_overrides(
    parsed: &ParsedPacket,
    flow_key: paccel::engine::FlowKey,
) -> FlowTuple {
    let mut src_port = flow_key.src_port;
    let mut dst_port = flow_key.dst_port;

    if flow_key.protocol == 58
        && let Some(icmpv6) = parsed.icmpv6.as_ref()
    {
        src_port = u16::from(icmpv6.icmp_type);
        dst_port = u16::from(icmpv6.icmp_code);
    } else if flow_key.protocol == 47
        && let Some(gre) = parsed.gre.as_ref()
    {
        // Preserve fluere's historical GRE pseudo-port only when paccel could
        // not decode an inner flow. A decoded tunnel has a different protocol.
        src_port = gre.protocol_type;
        dst_port = 0;
    }

    (
        flow_key.src_ip,
        flow_key.dst_ip,
        src_port,
        dst_port,
        flow_key.protocol,
    )
}

fn raw_fallback_tuple(parsed: &ParsedPacket, packet_data: &[u8]) -> Result<FlowTuple, ParseError> {
    let ethernet = parsed
        .ethernet
        .as_ref()
        .ok_or_else(|| ParseError::UnknownEtherType("missing Ethernet frame".to_owned()))?;
    let payload = packet_data
        .get(ethernet.payload_offset..)
        .ok_or_else(|| ParseError::UnknownEtherType(ethernet.ethertype.to_string()))?;
    let raw_header = RawProtocolHeader::from_ethertype(payload, ethernet.ethertype)
        .ok_or_else(|| ParseError::UnknownEtherType(ethernet.ethertype.to_string()))?;

    Ok((
        raw_header
            .src_ip
            .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
        raw_header
            .dst_ip
            .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
        raw_header.src_port,
        raw_header.dst_port,
        raw_header.protocol,
    ))
}

/// Build the forward and reverse `Key` for a flow from its extracted fields.
#[allow(clippy::too_many_arguments)]
fn build_key_pair(
    src_ip: IpAddr,
    dst_ip: IpAddr,
    src_port: u16,
    dst_port: u16,
    protocol: u8,
    src_mac: MacAddress,
    dst_mac: MacAddress,
) -> (Key, Key) {
    let key_value = Key {
        src_ip,
        src_port,
        dst_ip,
        dst_port,
        protocol,
        src_mac,
        dst_mac,
    };
    let key_reverse_value = Key {
        src_ip: dst_ip,
        src_port: dst_port,
        dst_ip: src_ip,
        dst_port: src_port,
        protocol,
        src_mac: dst_mac,
        dst_mac: src_mac,
    };
    (key_value, key_reverse_value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pcap::{Packet, PacketHeader};

    const SRC_MAC: [u8; 6] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
    const DST_MAC: [u8; 6] = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
    const OUTER_SRC: [u8; 4] = [192, 0, 2, 1];
    const OUTER_DST: [u8; 4] = [198, 51, 100, 2];

    fn parse_frame(frame: &[u8]) -> Result<(Key, Key), ParseError> {
        let header = PacketHeader {
            ts: libc::timeval {
                tv_sec: 0,
                tv_usec: 0,
            },
            caplen: frame.len() as u32,
            len: frame.len() as u32,
        };
        parse_keys(Packet::new(&header, frame), 1)
    }

    fn ethernet_frame(ethertype: u16, payload: &[u8]) -> Vec<u8> {
        let mut frame = Vec::with_capacity(14 + payload.len());
        frame.extend_from_slice(&DST_MAC);
        frame.extend_from_slice(&SRC_MAC);
        frame.extend_from_slice(&ethertype.to_be_bytes());
        frame.extend_from_slice(payload);
        frame
    }

    fn ipv4_packet(protocol: u8, source: [u8; 4], destination: [u8; 4], l4: &[u8]) -> Vec<u8> {
        let total_length = (20 + l4.len()) as u16;
        let mut packet = Vec::with_capacity(usize::from(total_length));
        packet.extend_from_slice(&[
            0x45,
            0,
            total_length.to_be_bytes()[0],
            total_length.to_be_bytes()[1],
        ]);
        packet.extend_from_slice(&[0, 1, 0, 0, 64, protocol, 0, 0]);
        packet.extend_from_slice(&source);
        packet.extend_from_slice(&destination);
        packet.extend_from_slice(l4);
        packet
    }

    fn tcp_segment(source_port: u16, destination_port: u16) -> Vec<u8> {
        let mut tcp = vec![0; 20];
        tcp[0..2].copy_from_slice(&source_port.to_be_bytes());
        tcp[2..4].copy_from_slice(&destination_port.to_be_bytes());
        tcp[12] = 0x50;
        tcp[13] = 0x02;
        tcp
    }

    fn udp_datagram(source_port: u16, destination_port: u16) -> Vec<u8> {
        let mut udp = vec![0; 8];
        udp[0..2].copy_from_slice(&source_port.to_be_bytes());
        udp[2..4].copy_from_slice(&destination_port.to_be_bytes());
        udp[4..6].copy_from_slice(&8u16.to_be_bytes());
        udp
    }

    fn assert_outer_ips(key: &Key) {
        assert_eq!(key.src_ip, IpAddr::V4(Ipv4Addr::from(OUTER_SRC)));
        assert_eq!(key.dst_ip, IpAddr::V4(Ipv4Addr::from(OUTER_DST)));
    }

    #[test]
    fn extracts_plain_ipv4_tcp_tuple_and_macs() {
        let tcp = tcp_segment(12_345, 443);
        let ipv4 = ipv4_packet(6, OUTER_SRC, OUTER_DST, &tcp);
        let key = parse_frame(&ethernet_frame(0x0800, &ipv4))
            .expect("valid TCP frame")
            .0;

        assert_outer_ips(&key);
        assert_eq!((key.src_port, key.dst_port, key.protocol), (12_345, 443, 6));
        assert_eq!(key.src_mac, MacAddress::new(SRC_MAC));
        assert_eq!(key.dst_mac, MacAddress::new(DST_MAC));
    }

    #[test]
    fn extracts_plain_ipv4_udp_tuple() {
        let udp = udp_datagram(53, 53_000);
        let ipv4 = ipv4_packet(17, OUTER_SRC, OUTER_DST, &udp);
        let key = parse_frame(&ethernet_frame(0x0800, &ipv4))
            .expect("valid UDP frame")
            .0;

        assert_outer_ips(&key);
        assert_eq!((key.src_port, key.dst_port, key.protocol), (53, 53_000, 17));
    }

    #[test]
    fn extracts_arp_with_fluere_protocol_convention() {
        let mut arp = Vec::with_capacity(28);
        arp.extend_from_slice(&[0, 1, 0x08, 0, 6, 4, 0, 1]);
        arp.extend_from_slice(&SRC_MAC);
        arp.extend_from_slice(&[10, 0, 0, 1]);
        arp.extend_from_slice(&[0; 6]);
        arp.extend_from_slice(&[10, 0, 0, 2]);
        let key = parse_frame(&ethernet_frame(0x0806, &arp))
            .expect("valid ARP frame")
            .0;

        assert_eq!(key.src_ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(key.dst_ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
        assert_eq!((key.src_port, key.dst_port, key.protocol), (0, 0, 4));
    }

    #[test]
    fn uses_icmpv6_type_and_code_as_pseudo_ports() {
        let source = [0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let destination = [0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let icmpv6 = [128, 0, 0, 0, 0, 1, 0, 1];
        let mut ipv6 = Vec::with_capacity(48);
        ipv6.extend_from_slice(&[0x60, 0, 0, 0, 0, 8, 58, 64]);
        ipv6.extend_from_slice(&source);
        ipv6.extend_from_slice(&destination);
        ipv6.extend_from_slice(&icmpv6);
        let key = parse_frame(&ethernet_frame(0x86dd, &ipv6))
            .expect("valid ICMPv6 frame")
            .0;

        assert_eq!(key.src_ip, IpAddr::from(source));
        assert_eq!(key.dst_ip, IpAddr::from(destination));
        assert_eq!((key.src_port, key.dst_port, key.protocol), (128, 0, 58));
    }

    #[test]
    fn falls_back_to_gre_protocol_type_pseudo_port() {
        let gre = [0, 0, 0x08, 0, 0xde, 0xad];
        let ipv4 = ipv4_packet(47, OUTER_SRC, OUTER_DST, &gre);
        let key = parse_frame(&ethernet_frame(0x0800, &ipv4))
            .expect("valid outer GRE frame")
            .0;

        assert_outer_ips(&key);
        assert_eq!((key.src_port, key.dst_port, key.protocol), (0x0800, 0, 47));
    }

    #[test]
    fn extracts_inner_flow_from_decodable_gre_tunnel() {
        let tcp = tcp_segment(23_456, 8443);
        let inner_ipv4 = ipv4_packet(6, [10, 1, 0, 1], [10, 2, 0, 2], &tcp);
        let mut gre = vec![0, 0, 0x08, 0];
        gre.extend_from_slice(&inner_ipv4);
        let outer_ipv4 = ipv4_packet(47, OUTER_SRC, OUTER_DST, &gre);
        let key = parse_frame(&ethernet_frame(0x0800, &outer_ipv4))
            .expect("valid GRE tunnel")
            .0;

        assert_eq!(key.src_ip, IpAddr::V4(Ipv4Addr::new(10, 1, 0, 1)));
        assert_eq!(key.dst_ip, IpAddr::V4(Ipv4Addr::new(10, 2, 0, 2)));
        assert_eq!(
            (key.src_port, key.dst_port, key.protocol),
            (23_456, 8443, 6)
        );
    }

    #[test]
    fn extracts_udp_tuple_through_vlan() {
        let udp = udp_datagram(5353, 42_000);
        let ipv4 = ipv4_packet(17, OUTER_SRC, OUTER_DST, &udp);
        let mut vlan_payload = vec![0, 100, 0x08, 0];
        vlan_payload.extend_from_slice(&ipv4);
        let key = parse_frame(&ethernet_frame(0x8100, &vlan_payload))
            .expect("valid VLAN UDP frame")
            .0;

        assert_outer_ips(&key);
        assert_eq!(
            (key.src_port, key.dst_port, key.protocol),
            (5353, 42_000, 17)
        );
    }

    #[test]
    fn rejects_empty_packet() {
        assert!(matches!(parse_frame(&[]), Err(ParseError::EmptyPacket)));
    }
}
