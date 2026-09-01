use std::net::{IpAddr, Ipv4Addr};

use crate::error::ParseError;
use crate::net::types::Key;
use fluereflow::{EncapKind, Encapsulation, Endpoints, MacAddress, VlanTags};

use log::trace;
use paccel::engine::ParsedPacket;

use super::raw::RawProtocolHeader;

type FlowTuple = (IpAddr, IpAddr, u16, u16, u8);

/// A flow tuple and, for traffic that is not IP, the EtherType identifying it.
type Identity = (FlowTuple, Option<u16>);

/// EtherTypes whose traffic is identified by its IP protocol number instead.
const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_IPV6: u16 = 0x86DD;

/// The EtherType to key on, or `None` when the address family already says
/// what the traffic is.
fn identifying_ethertype(ethertype: u16) -> Option<u16> {
    match ethertype {
        ETHERTYPE_IPV4 | ETHERTYPE_IPV6 => None,
        other => Some(other),
    }
}

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
    let (source_mac, destination_mac) = mac_addresses(parsed);
    let ((source, destination, src_port, dst_port, protocol), ethertype) =
        extract_flow_tuple(parsed, packet_data)?;
    let endpoints = super::endpoints_of(parsed, protocol, (src_port, dst_port));
    let encapsulation = encapsulation_of(parsed);
    let vlan = vlan_of(parsed);

    trace!(
        "Parsed keys: source={source:?} destination={destination:?} endpoints={endpoints:?} protocol={protocol:?}"
    );
    Ok(build_key_pair(
        source,
        destination,
        endpoints,
        protocol,
        ethertype,
        source_mac,
        destination_mac,
        vlan,
        encapsulation,
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

fn extract_flow_tuple(parsed: &ParsedPacket, packet_data: &[u8]) -> Result<Identity, ParseError> {
    if let Some(arp) = parsed.arp.as_ref() {
        // ARP has no IP protocol number. It used to be keyed as protocol 4,
        // IANA's number for IP-in-IP, purely as a marker, which meant an ARP
        // flow and a real IP-in-IP flow between the same addresses shared a key.
        return Ok((
            (
                IpAddr::V4(arp.sender_protocol_addr),
                IpAddr::V4(arp.target_protocol_addr),
                0,
                0,
                0,
            ),
            Some(fluereflow::ETHERTYPE_ARP),
        ));
    }

    if let Some(flow_key) = parsed.flow_key() {
        // Decoded IP traffic: the address family says what it is, so there is
        // no EtherType to key on.
        return Ok((
            (
                flow_key.src_ip,
                flow_key.dst_ip,
                flow_key.src_port,
                flow_key.dst_port,
                flow_key.protocol,
            ),
            None,
        ));
    }

    raw_fallback_tuple(parsed, packet_data)
}

fn raw_fallback_tuple(parsed: &ParsedPacket, packet_data: &[u8]) -> Result<Identity, ParseError> {
    let ethernet = parsed
        .ethernet
        .as_ref()
        .ok_or_else(|| ParseError::UnknownEtherType("missing Ethernet frame".to_owned()))?;
    let payload = packet_data
        .get(ethernet.payload_offset..)
        .ok_or_else(|| ParseError::UnknownEtherType(ethernet.ethertype.to_string()))?;
    let raw_header = RawProtocolHeader::from_ethertype(payload, ethernet.ethertype)
        .ok_or_else(|| ParseError::UnknownEtherType(ethernet.ethertype.to_string()))?;

    let ethertype = identifying_ethertype(ethernet.ethertype);
    // A frame with no IP header has no IP protocol number either. The raw
    // parser derives one from the EtherType to get something through, which is
    // a hint rather than a measurement, so it is not what the flow is keyed on.
    let protocol = if ethertype.is_some() {
        0
    } else {
        raw_header.protocol
    };

    Ok((
        (
            raw_header
                .src_ip
                .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
            raw_header
                .dst_ip
                .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
            raw_header.src_port,
            raw_header.dst_port,
            protocol,
        ),
        ethertype,
    ))
}

/// The VLAN segment a packet arrived on.
///
/// Taken from the outermost Ethernet header: an inner frame inside a tunnel is
/// already separated by the tunnel itself.
fn vlan_of(parsed: &ParsedPacket) -> VlanTags {
    parsed
        .ethernet
        .as_ref()
        .map_or_else(VlanTags::default, |ethernet| {
            VlanTags::from_stack(&ethernet.vlan_tags)
        })
}

/// The encapsulation a packet arrived inside, if any.
///
/// Detected from whichever tunnel header paccel decoded rather than from the
/// presence of an inner packet: MPLS and PPPoE carry IP directly, so they have
/// no inner packet and no addresses of their own, but they still separate
/// traffic that would otherwise collide.
fn encapsulation_of(parsed: &ParsedPacket) -> Option<Encapsulation> {
    let (kind, id, over_ip) = if let Some(vxlan) = parsed.vxlan.as_ref() {
        (EncapKind::Vxlan, Some(vxlan.vni), true)
    } else if let Some(geneve) = parsed.geneve.as_ref() {
        (EncapKind::Geneve, Some(geneve.vni), true)
    } else if let Some(gre) = parsed.gre.as_ref() {
        // RFC 2890 keys distinguish tunnels sharing a pair of endpoints. The
        // field is optional, and a tunnel that omits it is not the same tunnel
        // as one that sets it to zero.
        (EncapKind::Gre, gre.key, true)
    } else if let Some(mpls) = parsed.mpls.as_ref() {
        // The outermost label is the one the carrier switched on.
        let label = mpls.labels.first().map(|label| label.label);
        (EncapKind::Mpls, label, false)
    } else if let Some(pppoe) = parsed.pppoe.as_ref() {
        (EncapKind::Pppoe, Some(u32::from(pppoe.session_id)), false)
    } else if parsed.inner.is_some() {
        // IP carried directly inside IP, with no tunnel header between them,
        // and so nothing to distinguish two of them beyond their endpoints.
        (EncapKind::IpInIp, None, true)
    } else {
        return None;
    };

    Some(Encapsulation {
        kind,
        // Only an IP-based tunnel has endpoints of its own. For the others the
        // addresses on the packet are the carried traffic, not the carrier.
        outer: over_ip.then(|| outer_addresses(parsed)).flatten(),
        id,
    })
}

/// Addresses of the outermost IP header, which belong to the tunnel endpoints.
fn outer_addresses(parsed: &ParsedPacket) -> Option<(IpAddr, IpAddr)> {
    if let Some(ipv4) = parsed.ipv4.as_ref() {
        return Some((IpAddr::V4(ipv4.source), IpAddr::V4(ipv4.destination)));
    }
    parsed
        .ipv6
        .as_ref()
        .map(|ipv6| (IpAddr::V6(ipv6.source), IpAddr::V6(ipv6.destination)))
}

/// Build the forward and reverse `Key` for a flow from its extracted fields.
#[allow(clippy::too_many_arguments)]
fn build_key_pair(
    source: IpAddr,
    destination: IpAddr,
    endpoints: Endpoints,
    protocol: u8,
    ethertype: Option<u16>,
    source_mac: MacAddress,
    destination_mac: MacAddress,
    vlan: VlanTags,
    encapsulation: Option<Encapsulation>,
) -> (Key, Key) {
    let key = Key {
        source,
        destination,
        endpoints,
        protocol,
        ethertype,
        source_mac,
        destination_mac,
        vlan,
        encapsulation,
    };
    // Reversing swaps the addresses, ports and MACs but not the VLAN or the
    // tunnel: return traffic comes back on the same segment, through the same
    // tunnel.
    let reverse = key.reversed();
    (key, reverse)
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
        assert_eq!(key.source, IpAddr::V4(Ipv4Addr::from(OUTER_SRC)));
        assert_eq!(key.destination, IpAddr::V4(Ipv4Addr::from(OUTER_DST)));
    }

    #[test]
    fn extracts_plain_ipv4_tcp_tuple_and_macs() {
        let tcp = tcp_segment(12_345, 443);
        let ipv4 = ipv4_packet(6, OUTER_SRC, OUTER_DST, &tcp);
        let key = parse_frame(&ethernet_frame(0x0800, &ipv4))
            .expect("valid TCP frame")
            .0;

        assert_outer_ips(&key);
        assert_eq!(
            (key.ports().0, key.ports().1, key.protocol),
            (12_345, 443, 6)
        );
        assert_eq!(key.source_mac, MacAddress::new(SRC_MAC));
        assert_eq!(key.destination_mac, MacAddress::new(DST_MAC));
    }

    #[test]
    fn extracts_plain_ipv4_udp_tuple() {
        let udp = udp_datagram(53, 53_000);
        let ipv4 = ipv4_packet(17, OUTER_SRC, OUTER_DST, &udp);
        let key = parse_frame(&ethernet_frame(0x0800, &ipv4))
            .expect("valid UDP frame")
            .0;

        assert_outer_ips(&key);
        assert_eq!(
            (key.ports().0, key.ports().1, key.protocol),
            (53, 53_000, 17)
        );
    }

    #[test]
    fn arp_is_keyed_on_its_ethertype_not_a_protocol_number() {
        let mut arp = Vec::with_capacity(28);
        arp.extend_from_slice(&[0, 1, 0x08, 0, 6, 4, 0, 1]);
        arp.extend_from_slice(&SRC_MAC);
        arp.extend_from_slice(&[10, 0, 0, 1]);
        arp.extend_from_slice(&[0; 6]);
        arp.extend_from_slice(&[10, 0, 0, 2]);
        let key = parse_frame(&ethernet_frame(0x0806, &arp))
            .expect("valid ARP frame")
            .0;

        assert_eq!(key.source, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(key.destination, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
        assert_eq!(key.ports(), (0, 0));
        // Not protocol 4. That is IANA's number for IP-in-IP, and using it as
        // an ARP marker meant the two shared a key.
        assert_eq!(key.protocol, 0);
        assert_eq!(key.ethertype, Some(fluereflow::ETHERTYPE_ARP));
    }

    /// The collision the EtherType exists to prevent: ARP and IP-in-IP between
    /// the same pair of addresses are not the same conversation.
    #[test]
    fn arp_does_not_share_a_key_with_ip_in_ip() {
        let mut arp = Vec::with_capacity(28);
        arp.extend_from_slice(&[0, 1, 0x08, 0, 6, 4, 0, 1]);
        arp.extend_from_slice(&SRC_MAC);
        arp.extend_from_slice(&[10, 0, 0, 1]);
        arp.extend_from_slice(&[0; 6]);
        arp.extend_from_slice(&[10, 0, 0, 2]);
        let arp_key = parse_frame(&ethernet_frame(0x0806, &arp))
            .expect("valid ARP frame")
            .0;

        let mut ip_in_ip = arp_key;
        ip_in_ip.protocol = 4;
        ip_in_ip.ethertype = None;

        assert_ne!(arp_key, ip_in_ip);
    }

    #[test]
    fn icmpv6_reports_no_endpoints() {
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

        assert_eq!(key.source, IpAddr::from(source));
        assert_eq!(key.destination, IpAddr::from(destination));
        // Type and code say which direction this is, not which endpoint, so
        // they stay out of the port slots: the reverse key swaps those, and an
        // echo reply has to match the request's reverse key.
        assert_eq!((key.ports().0, key.ports().1, key.protocol), (0, 0, 58));
    }

    #[test]
    fn an_undecodable_gre_tunnel_reports_the_protocol_it_carried() {
        let gre = [0, 0, 0x08, 0, 0xde, 0xad];
        let ipv4 = ipv4_packet(47, OUTER_SRC, OUTER_DST, &gre);
        let key = parse_frame(&ethernet_frame(0x0800, &ipv4))
            .expect("valid outer GRE frame")
            .0;

        assert_outer_ips(&key);
        assert_eq!(key.protocol, 47);
        assert_eq!(
            key.endpoints,
            fluereflow::Endpoints::GreProtocol(0x0800),
            "the carried protocol, not a pair of fields named for ports"
        );
        assert_eq!(key.ports(), (0, 0), "a GRE tunnel has no transport ports");
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

        assert_eq!(key.source, IpAddr::V4(Ipv4Addr::new(10, 1, 0, 1)));
        assert_eq!(key.destination, IpAddr::V4(Ipv4Addr::new(10, 2, 0, 2)));
        assert_eq!(
            (key.ports().0, key.ports().1, key.protocol),
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
            (key.ports().0, key.ports().1, key.protocol),
            (5353, 42_000, 17)
        );
    }

    #[test]
    fn rejects_empty_packet() {
        assert!(matches!(parse_frame(&[]), Err(ParseError::EmptyPacket)));
    }
}
