//! What a packet contributes to a flow, beyond the key that identifies it.
//!
//! The flow key already carries the addresses, ports and protocol, so nothing
//! here repeats them. What is left is the per-packet measurements the record
//! accumulates: sizes, hop limit, differentiated-services bits, and TCP control
//! bits.

use fluereflow::{PacketFacts, TcpFlags, Timestamp};
use paccel::engine::{ParsedPacket, TransportSegment};

use super::fluereflows::innermost;
use super::raw::RawProtocolHeader;

/// One packet's measurable properties.
#[derive(Debug, Clone, Copy)]
pub(super) struct PacketProperties {
    pub facts: PacketFacts,
    /// Differentiated services code point, six bits. `None` without an IP
    /// header to read it from.
    pub dscp: Option<u8>,
    /// Explicit congestion notification, two bits. `None` on the same terms.
    pub ecn: Option<u8>,
}

/// Read one packet's properties from an already parsed frame.
///
/// Byte accounting uses the full top-level frame length, including link and
/// tunnel framing, so a tunnelled flow is measured as it appeared on the wire
/// rather than as its innermost payload.
pub(super) fn from_parsed(
    parsed: &ParsedPacket,
    packet_data: &[u8],
    frame_octets: u32,
    captured_octets: u32,
    time: Timestamp,
) -> PacketProperties {
    let inner = innermost(parsed);

    let (ttl, dscp, ecn) = if let Some(ipv4) = inner.ipv4.as_ref() {
        (Some(ipv4.ttl), Some(ipv4.dscp), Some(ipv4.ecn))
    } else if let Some(ipv6) = inner.ipv6.as_ref() {
        // The traffic class carries the same two fields as IPv4's ToS byte, and
        // the hop limit is the TTL by another name - the previous model
        // reported neither for IPv6.
        (
            Some(ipv6.hop_limit),
            Some(ipv6.traffic_class >> 2),
            Some(ipv6.traffic_class & 0x03),
        )
    } else if let Some(ipv4) = parsed.ipv4.as_ref() {
        // A tunnel whose payload did not decode. The flow is keyed on this
        // header's addresses, so this header's differentiated services are the
        // flow's, and reporting none of them said the flow had no IP header at
        // all when it plainly does.
        (Some(ipv4.ttl), Some(ipv4.dscp), Some(ipv4.ecn))
    } else if let Some(ipv6) = parsed.ipv6.as_ref() {
        (
            Some(ipv6.hop_limit),
            Some(ipv6.traffic_class >> 2),
            Some(ipv6.traffic_class & 0x03),
        )
    } else {
        // ARP and anything the fallback recovered: no IP header of its own, so
        // no differentiated services either. Reporting zero here made a real
        // code point of 0 look the same as having none.
        (raw_ttl(parsed, packet_data), None, None)
    };

    PacketProperties {
        facts: PacketFacts {
            time,
            frame_octets,
            captured_octets,
            ttl,
            tcp_flags: tcp_flags(inner),
            icmp: icmp_type_and_code(inner),
        },
        dscp,
        ecn,
    }
}

/// TCP control bits, or `None` for anything that is not TCP.
fn tcp_flags(parsed: &ParsedPacket) -> Option<TcpFlags> {
    match parsed.transport.as_ref() {
        Some(TransportSegment::Tcp(tcp)) => Some(TcpFlags {
            fin: tcp.flags.fin,
            syn: tcp.flags.syn,
            rst: tcp.flags.rst,
            psh: tcp.flags.psh,
            ack: tcp.flags.ack,
            urg: tcp.flags.urg,
            ece: tcp.flags.ece,
            cwr: tcp.flags.cwr,
            ns: tcp.flags.ns,
        }),
        _ => None,
    }
}

/// ICMP or ICMPv6 type and code, for the families that have them.
fn icmp_type_and_code(parsed: &ParsedPacket) -> Option<(u8, u8)> {
    if let Some(icmp) = parsed.icmp.as_ref() {
        return Some((icmp.icmp_type, icmp.icmp_code));
    }
    parsed
        .icmpv6
        .as_ref()
        .map(|icmpv6| (icmpv6.icmp_type, icmpv6.icmp_code))
}

/// Last resort for a frame with no IP header paccel could reach.
fn raw_ttl(parsed: &ParsedPacket, packet_data: &[u8]) -> Option<u8> {
    let ethernet = parsed.ethernet.as_ref()?;
    let payload = packet_data.get(ethernet.payload_offset..)?;

    RawProtocolHeader::from_ethertype(payload, ethernet.ethertype)?.ttl
}
