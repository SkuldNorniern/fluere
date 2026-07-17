use std::net::{IpAddr, Ipv4Addr};

use crate::error::ParseError;
use crate::net::parser::raw::RawProtocolHeader;
use crate::net::parser::{dscp_to_tos, parse_microseconds};

use fluereflow::FluereRecord;
use log::trace;
use paccel::engine::{BuiltinPacketParser, ParseConfig, ParsedPacket, StopLayer, TransportSegment};
use paccel::layer::datalink::arp::ArpPacket;
use paccel::layer::network::{ipv4::Ipv4Header, ipv6::Ipv6Header};

type FlowRecord = (usize, [u8; 9], FluereRecord);

/// Return the deepest packet decoded by paccel.
///
/// Flow records intentionally describe the innermost traffic for every tunnel
/// paccel understands, so VXLAN, GRE, GENEVE, MPLS, and IP-in-IP flows use the
/// real inner IP and transport fields rather than their encapsulating headers.
fn innermost(parsed: &ParsedPacket) -> &ParsedPacket {
    match parsed.inner.as_deref() {
        Some(inner) => innermost(inner),
        None => parsed,
    }
}

/// Parse one captured frame into a flow record.
///
/// Byte accounting intentionally uses the full top-level captured frame length
/// everywhere, including tunneled traffic. This consistently includes link and
/// tunnel overhead instead of mixing captured lengths with IP-declared lengths.
pub fn parse_fluereflow(
    packet: pcap::Packet,
    linktype: u16,
) -> Result<(usize, [u8; 9], FluereRecord), ParseError> {
    trace!("Parsing packet");
    if packet.is_empty() {
        return Err(ParseError::EmptyPacket);
    }

    let config = ParseConfig {
        stop_after: StopLayer::Transport,
        ..Default::default()
    };
    let parsed =
        BuiltinPacketParser::parse_with_config_and_linktype(packet.data, config, Some(linktype))
            .map_err(|_| ParseError::InvalidPacket)?;
    let time = parse_microseconds(
        packet.header.ts.tv_sec as u64,
        packet.header.ts.tv_usec as u64,
    );
    let doctets = packet.data.len();
    let inner = innermost(&parsed);

    if let Some(arp) = inner.arp.as_ref() {
        return Ok(arp_record(arp, doctets, time));
    }
    if let Some(ipv4) = inner.ipv4.as_ref() {
        return Ok(ipv4_record(ipv4, inner.transport.as_ref(), doctets, time));
    }
    if let Some(ipv6) = inner.ipv6.as_ref() {
        return Ok(ipv6_record(ipv6, inner.transport.as_ref(), doctets, time));
    }

    raw_fallback_record(&parsed, packet.data, doctets, time)
}

fn arp_record(arp: &ArpPacket, doctets: usize, time: u64) -> FlowRecord {
    let flags = [0; 9];
    (
        doctets,
        flags,
        new_record(
            IpAddr::V4(arp.sender_protocol_addr),
            IpAddr::V4(arp.target_protocol_addr),
            0,
            0,
            0,
            4,
            0,
            doctets,
            time,
        ),
    )
}

fn ipv4_record(
    ipv4: &Ipv4Header,
    transport: Option<&TransportSegment>,
    doctets: usize,
    time: u64,
) -> FlowRecord {
    if let Some(TransportSegment::Udp(udp)) = transport
        && (udp.source_port == 53 || udp.destination_port == 53)
    {
        let flags = [0; 9];
        return (
            doctets,
            flags,
            new_record(
                IpAddr::V4(ipv4.source),
                IpAddr::V4(ipv4.destination),
                udp.source_port,
                udp.destination_port,
                ipv4.ttl,
                17,
                0,
                doctets,
                time,
            ),
        );
    }

    let (src_port, dst_port, flags) = ports_and_flags(transport);
    let tos = dscp_to_tos(ipv4.dscp).unwrap_or(0);
    (
        doctets,
        flags,
        new_record(
            IpAddr::V4(ipv4.source),
            IpAddr::V4(ipv4.destination),
            src_port,
            dst_port,
            ipv4.ttl,
            ipv4.protocol,
            tos,
            doctets,
            time,
        ),
    )
}

fn ipv6_record(
    ipv6: &Ipv6Header,
    transport: Option<&TransportSegment>,
    doctets: usize,
    time: u64,
) -> FlowRecord {
    let (src_port, dst_port, flags) = ports_and_flags(transport);
    let tos = dscp_to_tos(ipv6.traffic_class >> 2).unwrap_or_default();
    // Preserve the historical record shape: IPv6 hop_limit was not mapped to TTL.
    (
        doctets,
        flags,
        new_record(
            IpAddr::V6(ipv6.source),
            IpAddr::V6(ipv6.destination),
            src_port,
            dst_port,
            0,
            ipv6.next_header,
            tos,
            doctets,
            time,
        ),
    )
}

fn ports_and_flags(transport: Option<&TransportSegment>) -> (u16, u16, [u8; 9]) {
    match transport {
        Some(TransportSegment::Tcp(tcp)) => (
            tcp.source_port,
            tcp.destination_port,
            [
                flag_byte(tcp.flags.fin),
                flag_byte(tcp.flags.syn),
                flag_byte(tcp.flags.rst),
                flag_byte(tcp.flags.psh),
                flag_byte(tcp.flags.ack),
                flag_byte(tcp.flags.urg),
                flag_byte(tcp.flags.ece),
                flag_byte(tcp.flags.cwr),
                flag_byte(tcp.flags.ns),
            ],
        ),
        Some(TransportSegment::Udp(udp)) => (udp.source_port, udp.destination_port, [0; 9]),
        None => (0, 0, [0; 9]),
    }
}

const fn flag_byte(flag: bool) -> u8 {
    if flag { 1 } else { 0 }
}

/// Fallback for ethertypes without a dedicated paccel decode.
fn raw_fallback_record(
    parsed: &ParsedPacket,
    packet_data: &[u8],
    doctets: usize,
    time: u64,
) -> Result<FlowRecord, ParseError> {
    let ethernet = parsed
        .ethernet
        .as_ref()
        .ok_or_else(|| ParseError::UnknownEtherType("missing Ethernet frame".to_owned()))?;
    trace!(
        "Attempting fallback parsing for EtherType: {}",
        ethernet.ethertype
    );
    let l3_payload = packet_data
        .get(ethernet.payload_offset..)
        .ok_or_else(|| ParseError::UnknownEtherType(ethernet.ethertype.to_string()))?;
    let raw_header = RawProtocolHeader::from_ethertype(l3_payload, ethernet.ethertype)
        .ok_or_else(|| ParseError::UnknownEtherType(ethernet.ethertype.to_string()))?;
    // The raw fallback has no TCP segment to inspect (only a protocol hint),
    // so no flag bits can ever be set here.
    let flags = [0u8; 9];

    Ok((
        doctets,
        flags,
        new_record(
            raw_header
                .src_ip
                .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
            raw_header
                .dst_ip
                .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
            raw_header.src_port,
            raw_header.dst_port,
            raw_header.ttl.unwrap_or(0),
            raw_header.protocol,
            0,
            doctets,
            time,
        ),
    ))
}

#[allow(clippy::too_many_arguments)]
fn new_record(
    source: IpAddr,
    destination: IpAddr,
    src_port: u16,
    dst_port: u16,
    ttl: u8,
    protocol: u8,
    tos: u8,
    doctets: usize,
    time: u64,
) -> FluereRecord {
    FluereRecord::new(
        source,
        destination,
        0,
        doctets,
        time,
        time,
        src_port,
        dst_port,
        doctets as u32,
        doctets as u32,
        ttl,
        ttl,
        0,
        0,
        doctets,
        doctets,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        protocol,
        tos,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use pcap::{Packet, PacketHeader};

    const SRC_MAC: [u8; 6] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
    const DST_MAC: [u8; 6] = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];

    fn parse_frame(frame: &[u8]) -> Result<FlowRecord, ParseError> {
        let header = PacketHeader {
            ts: libc::timeval {
                tv_sec: 1,
                tv_usec: 2,
            },
            caplen: frame.len() as u32,
            len: frame.len() as u32,
        };
        parse_fluereflow(Packet::new(&header, frame), 1)
    }

    fn ethernet_frame(ethertype: u16, payload: &[u8]) -> Vec<u8> {
        let mut frame = Vec::with_capacity(14 + payload.len());
        frame.extend_from_slice(&DST_MAC);
        frame.extend_from_slice(&SRC_MAC);
        frame.extend_from_slice(&ethertype.to_be_bytes());
        frame.extend_from_slice(payload);
        frame
    }

    fn ipv4_packet(
        protocol: u8,
        ttl: u8,
        dscp: u8,
        source: [u8; 4],
        destination: [u8; 4],
        l4: &[u8],
    ) -> Vec<u8> {
        let total_length = (20 + l4.len()) as u16;
        let mut packet = Vec::with_capacity(usize::from(total_length));
        packet.extend_from_slice(&[
            0x45,
            dscp << 2,
            total_length.to_be_bytes()[0],
            total_length.to_be_bytes()[1],
        ]);
        packet.extend_from_slice(&[0, 1, 0, 0, ttl, protocol, 0, 0]);
        packet.extend_from_slice(&source);
        packet.extend_from_slice(&destination);
        packet.extend_from_slice(l4);
        packet
    }

    fn ipv6_packet(
        traffic_class: u8,
        next_header: u8,
        source: [u8; 16],
        destination: [u8; 16],
        l4: &[u8],
    ) -> Vec<u8> {
        let payload_length = l4.len() as u16;
        let mut packet = Vec::with_capacity(40 + l4.len());
        packet.extend_from_slice(&[
            0x60 | (traffic_class >> 4),
            traffic_class << 4,
            0,
            0,
            payload_length.to_be_bytes()[0],
            payload_length.to_be_bytes()[1],
            next_header,
            55,
        ]);
        packet.extend_from_slice(&source);
        packet.extend_from_slice(&destination);
        packet.extend_from_slice(l4);
        packet
    }

    fn tcp_segment(source_port: u16, destination_port: u16, flags: u8) -> Vec<u8> {
        let mut tcp = vec![0; 20];
        tcp[0..2].copy_from_slice(&source_port.to_be_bytes());
        tcp[2..4].copy_from_slice(&destination_port.to_be_bytes());
        tcp[12] = 0x50;
        tcp[13] = flags;
        tcp
    }

    fn udp_datagram(source_port: u16, destination_port: u16, payload: &[u8]) -> Vec<u8> {
        let length = (8 + payload.len()) as u16;
        let mut udp = Vec::with_capacity(usize::from(length));
        udp.extend_from_slice(&source_port.to_be_bytes());
        udp.extend_from_slice(&destination_port.to_be_bytes());
        udp.extend_from_slice(&length.to_be_bytes());
        udp.extend_from_slice(&[0, 0]);
        udp.extend_from_slice(payload);
        udp
    }

    fn assert_plain_tcp_fields(record: &FluereRecord) {
        assert_eq!(record.source, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
        assert_eq!(
            record.destination,
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2))
        );
        assert_eq!((record.src_port, record.dst_port), (12_345, 443));
        assert_eq!((record.min_ttl, record.max_ttl), (42, 42));
        assert_eq!(record.tos, dscp_to_tos(10).unwrap_or(0));
        assert_eq!(record.prot, 6);
    }

    fn assert_plain_tcp_counts(record: &FluereRecord, frame_len: usize) {
        assert_eq!(record.syn_cnt, 0);
        assert_eq!(record.d_octets, frame_len);
        assert_eq!(
            (record.min_pkt, record.max_pkt),
            (frame_len as u32, frame_len as u32)
        );
        assert_eq!((record.in_bytes, record.out_bytes), (frame_len, frame_len));
    }

    #[test]
    fn extracts_plain_ipv4_tcp_record() {
        let tcp = tcp_segment(12_345, 443, 0x02);
        let ipv4 = ipv4_packet(6, 42, 10, [192, 0, 2, 1], [198, 51, 100, 2], &tcp);
        let frame = ethernet_frame(0x0800, &ipv4);
        let (doctets, flags, record) = parse_frame(&frame).expect("valid IPv4 TCP frame");

        assert_eq!(doctets, frame.len());
        assert_eq!(flags, [0, 1, 0, 0, 0, 0, 0, 0, 0]);
        assert_plain_tcp_fields(&record);
        assert_plain_tcp_counts(&record, frame.len());
    }

    #[test]
    fn preserves_ipv4_dns_shape() {
        let udp = udp_datagram(53, 40_000, &[]);
        let ipv4 = ipv4_packet(17, 61, 12, [10, 0, 0, 1], [10, 0, 0, 2], &udp);
        let (_, flags, record) =
            parse_frame(&ethernet_frame(0x0800, &ipv4)).expect("valid DNS frame");

        assert_eq!((record.src_port, record.dst_port), (53, 40_000));
        assert_eq!((record.min_ttl, record.max_ttl), (61, 61));
        assert_eq!(flags, [0; 9]);
        assert_eq!(record.prot, 17);
        assert_eq!(record.tos, 0);
    }

    #[test]
    fn extracts_ipv6_udp_and_preserves_zero_ttl() {
        let source = [0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let destination = [0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let traffic_class = 40;
        let udp = udp_datagram(5353, 40_001, &[]);
        let ipv6 = ipv6_packet(traffic_class, 17, source, destination, &udp);
        let (_, flags, record) =
            parse_frame(&ethernet_frame(0x86dd, &ipv6)).expect("valid IPv6 UDP frame");

        assert_eq!(record.source, IpAddr::from(source));
        assert_eq!(record.destination, IpAddr::from(destination));
        assert_eq!((record.src_port, record.dst_port), (5353, 40_001));
        assert_eq!((record.min_ttl, record.max_ttl), (0, 0));
        assert_eq!(record.prot, 17);
        assert_eq!(
            record.tos,
            dscp_to_tos(traffic_class >> 2).unwrap_or_default()
        );
        assert_eq!(flags, [0; 9]);
    }

    #[test]
    fn extracts_arp_with_fluere_protocol_convention() {
        let mut arp = Vec::with_capacity(28);
        arp.extend_from_slice(&[0, 1, 0x08, 0, 6, 4, 0, 1]);
        arp.extend_from_slice(&SRC_MAC);
        arp.extend_from_slice(&[10, 0, 0, 1]);
        arp.extend_from_slice(&[0; 6]);
        arp.extend_from_slice(&[10, 0, 0, 2]);
        let (_, flags, record) =
            parse_frame(&ethernet_frame(0x0806, &arp)).expect("valid ARP frame");

        assert_eq!(record.source, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(record.destination, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
        assert_eq!((record.src_port, record.dst_port), (0, 0));
        assert_eq!(record.prot, 4);
        assert_eq!(flags, [0; 9]);
    }

    #[test]
    fn extracts_innermost_tcp_from_vxlan() {
        let tcp = tcp_segment(23_456, 8443, 0x02);
        let inner_ip = ipv4_packet(6, 37, 8, [10, 1, 0, 1], [10, 2, 0, 2], &tcp);
        let inner_frame = ethernet_frame(0x0800, &inner_ip);
        let mut vxlan = vec![0x08, 0, 0, 0, 0, 0, 100, 0];
        vxlan.extend_from_slice(&inner_frame);
        let outer_udp = udp_datagram(40_000, 4789, &vxlan);
        let outer_ip = ipv4_packet(17, 64, 0, [192, 0, 2, 1], [198, 51, 100, 2], &outer_udp);
        let frame = ethernet_frame(0x0800, &outer_ip);
        let (doctets, flags, record) = parse_frame(&frame).expect("valid VXLAN tunnel");

        assert_eq!(record.source, IpAddr::V4(Ipv4Addr::new(10, 1, 0, 1)));
        assert_eq!(record.destination, IpAddr::V4(Ipv4Addr::new(10, 2, 0, 2)));
        assert_eq!((record.src_port, record.dst_port), (23_456, 8443));
        assert_eq!((record.min_ttl, record.max_ttl), (37, 37));
        assert_eq!(record.prot, 6);
        assert_eq!(flags, [0, 1, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(doctets, frame.len());
        assert_eq!(record.d_octets, frame.len());
    }

    #[test]
    fn rejects_empty_packet() {
        assert!(matches!(parse_frame(&[]), Err(ParseError::EmptyPacket)));
    }
}
