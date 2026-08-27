use pcap::Packet;

use crate::error::ParseError;
use crate::net::types::Key;

use fluereflow::{PacketFacts, TcpFlags, Timestamp};

use super::fluereflows::{innermost, packet_time, wire_length};
use super::fragments::{FragmentTracker, Ipv4Fragment};
use super::keys::keys_from_parsed;
use super::properties;

/// Everything one captured frame contributes to a flow.
///
/// Produced by a single decode of the frame: the flow keys and the packet's
/// measurements both come from the same parse, rather than each parser decoding
/// the packet again for itself.
///
/// Note what is *not* here: a partly built flow record. The parser reports what
/// it measured and the engine does the accumulating, so a packet cannot be
/// counted once by the parser and again by the engine.
#[derive(Debug, Clone, Copy)]
pub struct PacketObservation {
    /// Flow key in the direction this packet travelled.
    pub key: Key,
    /// The same flow key with source and destination swapped.
    pub reverse_key: Key,
    /// What this packet measured.
    pub facts: PacketFacts,
    /// Differentiated services code point, from this packet's IP header.
    pub dscp: u8,
    /// Explicit congestion notification bits, from this packet's IP header.
    pub ecn: u8,
    /// EtherType of the traffic this packet carried.
    pub ethertype: Option<u16>,
    /// TCP control bits, `None` for anything that is not TCP.
    pub tcp_flags: Option<TcpFlags>,
}

impl PacketObservation {
    /// When this packet was captured.
    pub fn time(&self) -> Timestamp {
        self.facts.time
    }

    /// Bytes this packet contributed, as seen on the wire.
    pub fn frame_octets(&self) -> u32 {
        self.facts.frame_octets
    }
}

/// Decode one captured frame into the pieces the flow engine needs.
///
/// `use_mac` keeps MAC addresses in the flow key; without it the keys are
/// zeroed so that traffic between the same endpoints stays one flow regardless
/// of the link-layer hops it took.
pub fn observe(
    packet: Packet<'_>,
    use_mac: bool,
    linktype: u16,
    fragments: &mut FragmentTracker,
) -> Result<PacketObservation, ParseError> {
    if packet.is_empty() {
        return Err(ParseError::EmptyPacket);
    }

    let parsed = super::parse_frame(packet.data, linktype)?;

    let (mut key, mut reverse_key) = keys_from_parsed(&parsed, packet.data)?;
    if !use_mac {
        key.forget_link_addresses();
        reverse_key.forget_link_addresses();
    }

    let properties = properties::from_parsed(
        &parsed,
        packet.data,
        wire_length(&packet) as u32,
        packet.data.len() as u32,
        packet_time(&packet),
    );

    let mut observation = PacketObservation {
        key,
        reverse_key,
        facts: properties.facts,
        dscp: properties.dscp,
        ecn: properties.ecn,
        ethertype: properties.ethertype,
        tcp_flags: properties.facts.tcp_flags,
    };

    // A later fragment has no transport header of its own, so it inherits the
    // endpoints its first fragment reported.
    let fragment = innermost(&parsed).ipv4.as_ref().and_then(Ipv4Fragment::of);
    fragments.resolve(&mut observation, fragment.as_ref());

    Ok(observation)
}

#[cfg(test)]
mod tests {
    use pcap::PacketHeader;

    use super::{FragmentTracker, PacketObservation, observe};
    use crate::net::parser::parse_keys;

    const SRC_MAC: [u8; 6] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
    const DST_MAC: [u8; 6] = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];

    fn tcp_frame() -> Vec<u8> {
        let mut frame = Vec::new();
        frame.extend_from_slice(&DST_MAC);
        frame.extend_from_slice(&SRC_MAC);
        frame.extend_from_slice(&0x0800u16.to_be_bytes());

        frame.extend_from_slice(&[0x45, 0x28]);
        frame.extend_from_slice(&40u16.to_be_bytes());
        frame.extend_from_slice(&[0, 1, 0, 0, 42, 6, 0, 0]);
        frame.extend_from_slice(&[192, 0, 2, 1]);
        frame.extend_from_slice(&[198, 51, 100, 2]);

        frame.extend_from_slice(&12_345u16.to_be_bytes());
        frame.extend_from_slice(&443u16.to_be_bytes());
        frame.extend_from_slice(&[0; 8]);
        frame.extend_from_slice(&[0x50, 0x02, 0x20, 0x00, 0, 0, 0, 0]);
        frame
    }

    fn header(frame: &[u8]) -> PacketHeader {
        PacketHeader {
            ts: libc::timeval {
                tv_sec: 7,
                tv_usec: 8,
            },
            caplen: frame.len() as u32,
            len: frame.len() as u32,
        }
    }

    /// One decode produces both the key and the packet's measurements.
    #[test]
    fn a_single_decode_yields_the_key_and_the_measurements() {
        let frame = tcp_frame();
        let header = header(&frame);

        let observation = observed(&frame);

        let (key, reverse_key) =
            parse_keys(pcap::Packet::new(&header, &frame), 1).expect("keys parse");
        assert_eq!(observation.key, key);
        assert_eq!(observation.reverse_key, reverse_key);

        assert_eq!(observation.frame_octets(), frame.len() as u32);
        assert_eq!(observation.facts.captured_octets, frame.len() as u32);
        assert!(!observation.facts.truncated());
        assert_eq!(observation.facts.ttl, Some(42));
        assert_eq!(observation.time().micros(), 7_000_008);
        assert!(
            observation.tcp_flags.expect("a TCP packet").syn,
            "the SYN bit is reported"
        );
        assert_eq!(
            observation.dscp, 10,
            "the DSCP field, not a shifted ToS byte"
        );
    }

    #[test]
    fn without_use_mac_the_key_ignores_link_addresses() {
        let frame = tcp_frame();
        let header = header(&frame);

        let with_mac = observe(
            pcap::Packet::new(&header, &frame),
            true,
            1,
            &mut FragmentTracker::new(),
        )
        .expect("observed");
        let without = observe(
            pcap::Packet::new(&header, &frame),
            false,
            1,
            &mut FragmentTracker::new(),
        )
        .expect("observed");

        assert_ne!(with_mac.key, without.key);
        assert_eq!(without.key.source_mac.0, [0; 6]);
        assert_eq!(without.key.destination_mac.0, [0; 6]);
        assert_eq!(without.reverse_key.source_mac.0, [0; 6]);
    }

    fn ipv4_icmp(src: [u8; 4], dst: [u8; 4], icmp_type: u8) -> Vec<u8> {
        let mut frame = Vec::new();
        frame.extend_from_slice(&DST_MAC);
        frame.extend_from_slice(&SRC_MAC);
        frame.extend_from_slice(&0x0800u16.to_be_bytes());
        frame.extend_from_slice(&[0x45, 0x00]);
        frame.extend_from_slice(&(20u16 + 8).to_be_bytes());
        frame.extend_from_slice(&[0, 1, 0, 0, 64, 1, 0, 0]);
        frame.extend_from_slice(&src);
        frame.extend_from_slice(&dst);
        frame.extend_from_slice(&[icmp_type, 0, 0, 0, 0, 0, 0, 0]);
        frame
    }

    fn ipv6_icmp(src_last: u8, dst_last: u8, icmp_type: u8) -> Vec<u8> {
        let mut frame = Vec::new();
        frame.extend_from_slice(&DST_MAC);
        frame.extend_from_slice(&SRC_MAC);
        frame.extend_from_slice(&0x86DDu16.to_be_bytes());
        frame.extend_from_slice(&[0x60, 0, 0, 0, 0, 8, 58, 64]);
        for last in [src_last, dst_last] {
            frame.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
            frame.push(last);
        }
        frame.extend_from_slice(&[icmp_type, 0, 0, 0, 0, 0, 0, 0]);
        frame
    }

    fn observed(frame: &[u8]) -> PacketObservation {
        let header = header(frame);
        observe(
            pcap::Packet::new(&header, frame),
            true,
            1,
            &mut FragmentTracker::new(),
        )
        .expect("observed")
    }

    /// An ICMP echo request and its reply are the two directions of one
    /// exchange, so they must key as each other's reverse. Type and code
    /// identify the direction, not an endpoint, so they cannot live in the port
    /// slots: the reverse key swaps those, which would stop the two matching.
    #[test]
    fn an_icmp_echo_exchange_is_one_flow() {
        let a = [192, 0, 2, 1];
        let b = [198, 51, 100, 2];

        let request = observed(&ipv4_icmp(a, b, 8));
        let reply = observed(&ipv4_icmp(b, a, 0));

        assert_eq!(request.key.ports().0, 0, "no endpoint to report");
        assert_eq!(request.key.ports().1, 0);
        assert_eq!(
            request.reverse_key.source, reply.key.source,
            "the reply must match the request's reverse key"
        );
        assert_eq!(request.reverse_key.destination, reply.key.destination);
        assert_eq!(request.reverse_key.ports().0, reply.key.ports().0);
        assert_eq!(request.reverse_key.ports().1, reply.key.ports().1);
        assert_eq!(request.reverse_key.protocol, reply.key.protocol);
    }

    /// Both families group the same way.
    #[test]
    fn an_icmpv6_echo_exchange_is_one_flow() {
        let request = observed(&ipv6_icmp(1, 2, 128));
        let reply = observed(&ipv6_icmp(2, 1, 129));

        assert_eq!(request.key.protocol, 58);
        assert_eq!((request.key.ports().0, request.key.ports().1), (0, 0));
        assert_eq!(request.reverse_key.source, reply.key.source);
        assert_eq!(request.reverse_key.destination, reply.key.destination);
        assert_eq!(request.reverse_key.ports().0, reply.key.ports().0);
        assert_eq!(request.reverse_key.ports().1, reply.key.ports().1);
    }

    /// SCTP carries ports like TCP and UDP do, but paccel reports them on
    /// `parsed.sctp` rather than through `TransportSegment`, so fluere used to
    /// key every SCTP association between two hosts as a single flow.
    #[test]
    fn sctp_ports_reach_both_the_key_and_the_record() {
        let mut frame = Vec::new();
        frame.extend_from_slice(&DST_MAC);
        frame.extend_from_slice(&SRC_MAC);
        frame.extend_from_slice(&0x0800u16.to_be_bytes());

        // IPv4, protocol 132 (SCTP), 12-byte common header + no chunks.
        frame.extend_from_slice(&[0x45, 0x00]);
        frame.extend_from_slice(&(20u16 + 12).to_be_bytes());
        frame.extend_from_slice(&[0, 1, 0, 0, 64, 132, 0, 0]);
        frame.extend_from_slice(&[192, 0, 2, 1]);
        frame.extend_from_slice(&[198, 51, 100, 2]);
        frame.extend_from_slice(&50_005u16.to_be_bytes());
        frame.extend_from_slice(&38_412u16.to_be_bytes());
        frame.extend_from_slice(&[0; 8]); // verification tag + checksum

        let header = header(&frame);
        let observation = observe(
            pcap::Packet::new(&header, &frame),
            true,
            1,
            &mut FragmentTracker::new(),
        )
        .expect("observed");

        assert_eq!(observation.key.protocol, 132);
        assert_eq!(
            (observation.key.ports().0, observation.key.ports().1),
            (50_005, 38_412)
        );
    }

    /// Every IPsec association between two hosts used to collapse into one
    /// flow, because ESP and AH have no ports and their SPI went unread.
    #[test]
    fn ipsec_associations_are_told_apart_by_spi() {
        let esp = |spi: u32| {
            let mut frame = Vec::new();
            frame.extend_from_slice(&DST_MAC);
            frame.extend_from_slice(&SRC_MAC);
            frame.extend_from_slice(&0x0800u16.to_be_bytes());
            frame.extend_from_slice(&[0x45, 0x00]);
            frame.extend_from_slice(&(20u16 + 16).to_be_bytes());
            frame.extend_from_slice(&[0, 1, 0, 0, 64, 50, 0, 0]);
            frame.extend_from_slice(&[203, 0, 113, 1]);
            frame.extend_from_slice(&[203, 0, 113, 2]);
            frame.extend_from_slice(&spi.to_be_bytes());
            frame.extend_from_slice(&1u32.to_be_bytes());
            frame.extend_from_slice(&[0; 8]);
            frame
        };

        let first = observed(&esp(0x1111_1111));
        let second = observed(&esp(0x2222_2222));

        assert_eq!(first.key.protocol, 50);
        assert_eq!(
            first.key.endpoints,
            fluereflow::Endpoints::SecurityAssociation(0x1111_1111),
            "the SPI whole, not split across two port fields"
        );
        assert_eq!(
            second.key.endpoints,
            fluereflow::Endpoints::SecurityAssociation(0x2222_2222)
        );
        assert_eq!(first.key.ports(), (0, 0), "IPsec has no transport ports");
        assert_ne!(
            first.key, second.key,
            "different associations must be different flows"
        );
    }

    /// A VXLAN frame carrying `inner`, on segment `vni`, between the given
    /// outer endpoints.
    fn vxlan(outer_dst_last: u8, vni: u32) -> Vec<u8> {
        let mut frame = Vec::new();
        frame.extend_from_slice(&DST_MAC);
        frame.extend_from_slice(&SRC_MAC);
        frame.extend_from_slice(&0x0800u16.to_be_bytes());

        // Outer IPv4 + UDP to the VXLAN port.
        let inner_len = 8 + 14 + 20 + 20; // vxlan + eth + ip + tcp
        frame.extend_from_slice(&[0x45, 0x00]);
        frame.extend_from_slice(&((20 + 8 + inner_len) as u16).to_be_bytes());
        frame.extend_from_slice(&[0, 1, 0, 0, 64, 17, 0, 0]);
        frame.extend_from_slice(&[203, 0, 113, 1]);
        frame.extend_from_slice(&[203, 0, 113, outer_dst_last]);
        frame.extend_from_slice(&50_000u16.to_be_bytes());
        frame.extend_from_slice(&4789u16.to_be_bytes());
        frame.extend_from_slice(&((8 + inner_len) as u16).to_be_bytes());
        frame.extend_from_slice(&[0, 0]);

        // VXLAN header: flags, reserved, VNI, reserved.
        frame.extend_from_slice(&[0x08, 0, 0, 0]);
        frame.extend_from_slice(&vni.to_be_bytes()[1..]);
        frame.push(0);

        // Inner Ethernet + IPv4 + TCP, identical for every tenant.
        frame.extend_from_slice(&DST_MAC);
        frame.extend_from_slice(&SRC_MAC);
        frame.extend_from_slice(&0x0800u16.to_be_bytes());
        frame.extend_from_slice(&[0x45, 0x00]);
        frame.extend_from_slice(&40u16.to_be_bytes());
        frame.extend_from_slice(&[0, 1, 0, 0, 32, 6, 0, 0]);
        frame.extend_from_slice(&[10, 1, 0, 1]);
        frame.extend_from_slice(&[10, 2, 0, 2]);
        frame.extend_from_slice(&41_001u16.to_be_bytes());
        frame.extend_from_slice(&9_000u16.to_be_bytes());
        frame.extend_from_slice(&[0; 8]);
        frame.extend_from_slice(&[0x50, 0x02, 0x20, 0x00, 0, 0, 0, 0]);
        frame
    }

    /// Tenants on separate VXLAN segments reuse the same private ranges, so
    /// their inner five-tuples collide. Keying on the inner addresses alone
    /// would put two tenants' traffic in one record.
    #[test]
    fn tenants_on_different_segments_do_not_share_a_flow() {
        let tenant_a = observed(&vxlan(2, 100));
        let tenant_b = observed(&vxlan(2, 200));

        assert_eq!(tenant_a.key.source, tenant_b.key.source, "same inner tuple");
        assert_eq!(tenant_a.key.ports().0, tenant_b.key.ports().0);
        assert_ne!(tenant_a.key, tenant_b.key, "but different flows");

        let encap = tenant_a.key.encapsulation.expect("tunnel recorded");
        assert_eq!(encap.kind.as_str(), "vxlan");
        assert_eq!(encap.id, 100, "the VXLAN VNI");
    }

    /// Different tunnel endpoints separate flows even on the same segment.
    #[test]
    fn the_same_segment_through_different_tunnels_stays_separate() {
        let one = observed(&vxlan(2, 100));
        let other = observed(&vxlan(9, 100));

        assert_ne!(one.key, other.key);
        assert_ne!(
            one.key.encapsulation.expect("tunnel").outer,
            other.key.encapsulation.expect("tunnel").outer
        );
    }

    /// Untunnelled traffic carries no encapsulation, so nothing changes for it.
    #[test]
    fn plain_traffic_has_no_encapsulation() {
        let frame = tcp_frame();
        let observation = observed(&frame);
        assert!(observation.key.encapsulation.is_none());
    }

    #[test]
    fn an_empty_packet_is_rejected() {
        let header = header(&[]);
        assert!(
            observe(
                pcap::Packet::new(&header, &[]),
                true,
                1,
                &mut FragmentTracker::new()
            )
            .is_err()
        );
    }
}
