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
    /// Differentiated services code point, six bits.
    pub dscp: u8,
    /// Explicit congestion notification, two bits.
    pub ecn: u8,
    /// EtherType of the innermost traffic.
    pub ethertype: Option<u16>,
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
        (Some(ipv4.ttl), ipv4.dscp, ipv4.ecn)
    } else if let Some(ipv6) = inner.ipv6.as_ref() {
        // The traffic class carries the same two fields as IPv4's ToS byte, and
        // the hop limit is the TTL by another name - the previous model
        // reported neither for IPv6.
        (
            Some(ipv6.hop_limit),
            ipv6.traffic_class >> 2,
            ipv6.traffic_class & 0x03,
        )
    } else {
        // ARP and anything the fallback recovered: no IP header of its own,
        // though the raw parser may still have found a TTL.
        (raw_ttl(parsed, packet_data), 0, 0)
    };

    // Taken from what was actually decoded rather than the frame header, so a
    // tunnel reports the traffic it carried rather than its own framing.
    let ethertype = if inner.arp.is_some() {
        Some(0x0806)
    } else if inner.ipv4.is_some() {
        Some(0x0800)
    } else if inner.ipv6.is_some() {
        Some(0x86DD)
    } else {
        parsed.ethernet.as_ref().map(|ethernet| ethernet.ethertype)
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
        ethertype,
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
