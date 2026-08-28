//! End-to-end scenarios: packets in, flow records out.
//!
//! The unit tests elsewhere check one decision at a time. These drive whole
//! captures through the real parser and flow engine, which is where the two
//! meet and where the bugs found by hand testing actually lived: endpoints
//! disagreeing between the key and the record, tunnels merging, fragments
//! splitting off, packets counted twice.
//!
//! Every scenario also asserts the conservation invariants, so a change that
//! quietly loses or duplicates traffic fails here even if no named assertion
//! covers it.

use fluereflow::{FlowRecord, StartState};

use fluereflow::Flow;
use pcap::{Packet, PacketHeader};

use crate::net::flow_engine::FlowEngine;
use crate::net::parser::{ParserState, observe};

const SRC_MAC: [u8; 6] = [0xaa; 6];
const DST_MAC: [u8; 6] = [0xbb; 6];

// ---------------------------------------------------------------- builders

/// An Ethernet frame carrying a stack of VLAN tags, outermost first.
pub fn vlan_ethernet(tags: &[u16], ethertype: u16, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(14 + 4 * tags.len() + payload.len());
    frame.extend_from_slice(&DST_MAC);
    frame.extend_from_slice(&SRC_MAC);

    for tag in tags {
        frame.extend_from_slice(&0x8100u16.to_be_bytes());
        frame.extend_from_slice(&tag.to_be_bytes());
    }

    frame.extend_from_slice(&ethertype.to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

pub fn ethernet(ethertype: u16, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(14 + payload.len());
    frame.extend_from_slice(&DST_MAC);
    frame.extend_from_slice(&SRC_MAC);
    frame.extend_from_slice(&ethertype.to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

/// An IPv4 packet. `fragment` is `(identification, offset, more_fragments)`;
/// pass `None` for an unfragmented datagram.
pub fn ipv4_with(
    protocol: u8,
    ttl: u8,
    src: [u8; 4],
    dst: [u8; 4],
    fragment: Option<(u16, u16, bool)>,
    payload: &[u8],
) -> Vec<u8> {
    let (identification, offset, more) = fragment.unwrap_or((0, 0, false));
    let flags_and_offset = (u16::from(more) << 13) | (offset & 0x1FFF);

    let mut packet = Vec::with_capacity(20 + payload.len());
    packet.extend_from_slice(&[0x45, 0x00]);
    packet.extend_from_slice(&((20 + payload.len()) as u16).to_be_bytes());
    packet.extend_from_slice(&identification.to_be_bytes());
    packet.extend_from_slice(&flags_and_offset.to_be_bytes());
    packet.extend_from_slice(&[ttl, protocol, 0, 0]);
    packet.extend_from_slice(&src);
    packet.extend_from_slice(&dst);
    packet.extend_from_slice(payload);
    packet
}

pub fn ipv4(protocol: u8, ttl: u8, src: [u8; 4], dst: [u8; 4], payload: &[u8]) -> Vec<u8> {
    ipv4_with(protocol, ttl, src, dst, None, payload)
}

/// An IPv6 fragment header, followed by its payload.
pub fn ipv6_fragment(next_header: u8, identification: u32, offset: u16, more: bool) -> Vec<u8> {
    let offset_and_flags = (offset << 3) | u16::from(more);

    let mut header = Vec::with_capacity(8);
    header.push(next_header);
    header.push(0);
    header.extend_from_slice(&offset_and_flags.to_be_bytes());
    header.extend_from_slice(&identification.to_be_bytes());
    header
}

pub fn ipv6(next_header: u8, src: [u8; 16], dst: [u8; 16], payload: &[u8]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(40 + payload.len());
    packet.extend_from_slice(&[0x60, 0, 0, 0]);
    packet.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    packet.extend_from_slice(&[next_header, 64]);
    packet.extend_from_slice(&src);
    packet.extend_from_slice(&dst);
    packet.extend_from_slice(payload);
    packet
}

pub fn tcp(source_port: u16, destination_port: u16, flags: u8) -> Vec<u8> {
    let mut segment = Vec::with_capacity(20);
    segment.extend_from_slice(&source_port.to_be_bytes());
    segment.extend_from_slice(&destination_port.to_be_bytes());
    segment.extend_from_slice(&[0; 8]);
    segment.extend_from_slice(&[0x50, flags, 0x20, 0x00, 0, 0, 0, 0]);
    segment
}

pub fn udp(source_port: u16, destination_port: u16, payload: &[u8]) -> Vec<u8> {
    let mut datagram = Vec::with_capacity(8 + payload.len());
    datagram.extend_from_slice(&source_port.to_be_bytes());
    datagram.extend_from_slice(&destination_port.to_be_bytes());
    datagram.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    datagram.extend_from_slice(&[0, 0]);
    datagram.extend_from_slice(payload);
    datagram
}

pub fn icmp(icmp_type: u8) -> Vec<u8> {
    vec![icmp_type, 0, 0, 0, 0, 0, 0, 0]
}

pub fn esp(spi: u32) -> Vec<u8> {
    let mut header = Vec::with_capacity(16);
    header.extend_from_slice(&spi.to_be_bytes());
    header.extend_from_slice(&1u32.to_be_bytes());
    header.extend_from_slice(&[0; 8]);
    header
}

pub fn sctp(source_port: u16, destination_port: u16) -> Vec<u8> {
    let mut header = Vec::with_capacity(12);
    header.extend_from_slice(&source_port.to_be_bytes());
    header.extend_from_slice(&destination_port.to_be_bytes());
    header.extend_from_slice(&[0; 8]);
    header
}

/// A GRE header carrying `protocol`, optionally with an RFC 2890 key.
pub fn gre(protocol: u16, key: Option<u32>) -> Vec<u8> {
    let mut header = Vec::with_capacity(8);
    let flags: u16 = if key.is_some() { 0x2000 } else { 0 };
    header.extend_from_slice(&flags.to_be_bytes());
    header.extend_from_slice(&protocol.to_be_bytes());
    if let Some(key) = key {
        header.extend_from_slice(&key.to_be_bytes());
    }
    header
}

/// A single-label MPLS shim, bottom of stack.
pub fn mpls(label: u32) -> Vec<u8> {
    let word = (label << 12) | (1 << 8) | 64; // label, bottom-of-stack, TTL
    word.to_be_bytes().to_vec()
}

/// A PPPoE session header carrying IPv4 over PPP.
pub fn pppoe(session_id: u16, payload: &[u8]) -> Vec<u8> {
    let ppp_len = (payload.len() + 2) as u16;
    let mut header = Vec::with_capacity(8 + payload.len());
    header.extend_from_slice(&[0x11, 0x00]); // version/type, session data
    header.extend_from_slice(&session_id.to_be_bytes());
    header.extend_from_slice(&ppp_len.to_be_bytes());
    header.extend_from_slice(&0x0021u16.to_be_bytes()); // PPP: IPv4
    header.extend_from_slice(payload);
    header
}

/// A QUIC long header announcing `scid` as this side's connection ID.
///
/// Only the fields a passive observer needs are filled in; the payload behind
/// the header is opaque without the connection's keys.
pub fn quic_long_header(scid: &[u8]) -> Vec<u8> {
    let mut packet = vec![0xc0]; // long header, fixed bit set
    packet.extend_from_slice(&1u32.to_be_bytes()); // version 1
    packet.push(0); // empty destination connection ID
    packet.push(scid.len() as u8);
    packet.extend_from_slice(scid);
    packet.extend_from_slice(&[0; 4]);
    packet
}

/// A QUIC short header addressed to `dcid`, as every 1-RTT packet is.
pub fn quic_short_header(dcid: &[u8]) -> Vec<u8> {
    let mut packet = vec![0x40]; // short header, fixed bit set
    packet.extend_from_slice(dcid);
    packet.extend_from_slice(&[0; 8]);
    packet
}

/// Wrap an inner Ethernet frame in a VXLAN header, ready to be a UDP payload.
pub fn vxlan(vni: u32, inner_frame: &[u8]) -> Vec<u8> {
    let mut header = Vec::with_capacity(8 + inner_frame.len());
    header.extend_from_slice(&[0x08, 0, 0, 0]);
    header.extend_from_slice(&vni.to_be_bytes()[1..]);
    header.push(0);
    header.extend_from_slice(inner_frame);
    header
}

/// The inner frame every tenant in these scenarios sends: identical addresses
/// and ports, which is what makes overlapping tenants collide.
pub fn tenant_traffic() -> Vec<u8> {
    ethernet(
        0x0800,
        &ipv4(
            6,
            32,
            [10, 1, 0, 1],
            [10, 2, 0, 2],
            &tcp(41_001, 9_000, 0x02),
        ),
    )
}

// ---------------------------------------------------------------- harness

/// Drives frames through the real parser and flow engine, and remembers what
/// was offered so conservation can be checked at the end.
pub struct Capture {
    engine: FlowEngine,
    parser_state: ParserState,
    time: u64,
    completed: Vec<Flow>,
    offered_packets: usize,
    offered_octets: usize,
    skipped: usize,
}

impl Capture {
    /// `timeout` is the flow idle timeout in milliseconds.
    pub fn new(timeout: u64) -> Self {
        Capture {
            engine: FlowEngine::new(timeout),
            parser_state: ParserState::new(),
            time: 1_000,
            completed: Vec::new(),
            offered_packets: 0,
            offered_octets: 0,
            skipped: 0,
        }
    }

    /// Offer one frame, one millisecond after the last.
    pub fn push(&mut self, frame: &[u8]) -> &mut Self {
        self.push_at(frame, self.time + 1_000)
    }

    /// Offer one frame at an explicit time, in microseconds.
    pub fn push_at(&mut self, frame: &[u8], time: u64) -> &mut Self {
        self.time = time;
        self.offered_packets += 1;
        self.offered_octets += frame.len();

        let header = PacketHeader {
            ts: libc::timeval {
                tv_sec: (time / 1_000_000) as i64,
                tv_usec: (time % 1_000_000) as i64,
            },
            caplen: frame.len() as u32,
            len: frame.len() as u32,
        };

        match observe(
            Packet::new(&header, frame),
            false,
            1,
            &mut self.parser_state,
        ) {
            Ok(observation) => {
                let outcome = self.engine.accept(observation);
                self.completed.extend(outcome.completed);
            }
            Err(_) => self.skipped += 1,
        }

        self
    }

    /// Every flow the capture produced, closed and still open.
    pub fn finish(mut self) -> Flows {
        let mut records = std::mem::take(&mut self.completed);
        records.extend(self.engine.drain());

        Flows {
            flows: records,
            offered_packets: self.offered_packets,
            offered_octets: self.offered_octets,
            skipped: self.skipped,
        }
    }
}

pub struct Flows {
    pub flows: Vec<Flow>,
    offered_packets: usize,
    offered_octets: usize,
    skipped: usize,
}

impl Flows {
    pub fn len(&self) -> usize {
        self.flows.len()
    }

    /// The identifying keys of every flow, for assertions about what separated
    /// them rather than what they counted.
    pub fn keys(&self) -> impl Iterator<Item = &crate::net::types::Key> {
        self.flows.iter().map(|flow| &flow.key)
    }

    /// The one flow matching `predicate`, failing if there is not exactly one.
    ///
    /// Predicates take the whole flow. Addresses, ports and protocol live on the
    /// key; what the flow counted lives on the record.
    pub fn only(&self, predicate: impl Fn(&Flow) -> bool) -> &FlowRecord {
        &self.only_flow(predicate).record
    }

    /// The one flow matching `predicate`, key included, for assertions about
    /// what identified it rather than what it counted.
    pub fn only_flow(&self, predicate: impl Fn(&Flow) -> bool) -> &Flow {
        let matched: Vec<&Flow> = self
            .flows
            .iter()
            .filter(|flow| predicate(flow))
            .collect();
        assert_eq!(
            matched.len(),
            1,
            "expected exactly one matching flow, found {}",
            matched.len()
        );
        matched[0]
    }

    pub fn count(&self, predicate: impl Fn(&Flow) -> bool) -> usize {
        self.flows.iter().filter(|flow| predicate(flow)).count()
    }

    /// Nothing was lost, duplicated, or invented.
    ///
    /// Called by every scenario, so a change that quietly miscounts fails even
    /// where no named assertion covers it.
    pub fn assert_conserved(&self) {
        let packets: u64 = self.flows.iter().map(|flow| flow.record.packets()).sum();
        let octets: u64 = self
            .flows
            .iter()
            .map(|flow| flow.record.frame_octets())
            .sum();

        assert_eq!(
            packets as usize,
            self.offered_packets - self.skipped,
            "every parsed packet must appear in exactly one flow"
        );
        assert_eq!(
            octets as usize, self.offered_octets,
            "flow octets must equal the bytes offered"
        );

        for record in self.flows.iter().map(|flow| &flow.record) {
            // Totals are derived, so they cannot disagree with the directions.
            // What can still go wrong is a direction reporting bytes it never
            // carried, which is the shape of the original double-count bug.
            if record.reverse.packets == 0 {
                assert_eq!(
                    record.reverse.frame_octets, 0,
                    "no reverse packets means no reverse bytes"
                );
                assert_eq!(record.reverse.packet_length, None);
            }
            if record.forward.packets == 0 {
                assert_eq!(
                    record.forward.frame_octets, 0,
                    "no forward packets means no forward bytes"
                );
            }
            assert!(
                record.time.start <= record.time.end,
                "a flow cannot end before it starts"
            );
            for direction in [&record.forward, &record.reverse] {
                if let Some(range) = direction.packet_length {
                    assert!(range.min <= range.max);
                }
            }
            if let Some(ttl) = record.network.ttl {
                assert!(ttl.min <= ttl.max);
            }
        }
    }
}

// ---------------------------------------------------------------- scenarios

#[cfg(test)]
mod tests {
    use super::*;

    const A: [u8; 4] = [192, 0, 2, 10];
    const B: [u8; 4] = [198, 51, 100, 20];
    const A6: [u8; 16] = [0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    const B6: [u8; 16] = [0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];

    const SYN: u8 = 0x02;
    const SYN_ACK: u8 = 0x12;
    const ACK: u8 = 0x10;
    const FIN_ACK: u8 = 0x11;
    const RST: u8 = 0x04;

    fn v4(protocol: u8, ttl: u8, src: [u8; 4], dst: [u8; 4], payload: &[u8]) -> Vec<u8> {
        ethernet(0x0800, &ipv4(protocol, ttl, src, dst, payload))
    }

    /// A whole TCP conversation, including the half-close where the server
    /// keeps sending after the client's FIN, is one record.
    #[test]
    fn a_tcp_conversation_is_one_flow() {
        let mut capture = Capture::new(600_000);
        capture
            .push(&v4(6, 64, A, B, &tcp(40_001, 443, SYN)))
            .push(&v4(6, 52, B, A, &tcp(443, 40_001, SYN_ACK)))
            .push(&v4(6, 64, A, B, &tcp(40_001, 443, ACK)))
            .push(&v4(6, 64, A, B, &tcp(40_001, 443, FIN_ACK)))
            // Half-closed: the server still has data to send.
            .push(&v4(6, 52, B, A, &tcp(443, 40_001, ACK)))
            .push(&v4(6, 52, B, A, &tcp(443, 40_001, FIN_ACK)));

        let flows = capture.finish();
        flows.assert_conserved();

        assert_eq!(
            flows.len(),
            1,
            "a half-close must not split the conversation"
        );
        let flow = flows.only(|f| f.key.protocol == 6);
        assert_eq!(flow.packets(), 6);
        assert_eq!((flow.forward.packets, flow.reverse.packets), (3, 3));
        assert_eq!(flow.forward.tcp_flags.fin + flow.reverse.tcp_flags.fin, 2);
        assert_eq!(flow.forward.tcp_flags.syn + flow.reverse.tcp_flags.syn, 2);
        assert_eq!(flow.time.start_state, StartState::SynObserved);
        assert_eq!(
            (
                flow.network.ttl.expect("ttl").min,
                flow.network.ttl.expect("ttl").max
            ),
            (52, 64)
        );
    }

    #[test]
    fn a_reset_ends_a_conversation_on_its_own() {
        let mut capture = Capture::new(600_000);
        capture
            .push(&v4(6, 64, A, B, &tcp(40_002, 22, SYN)))
            .push(&v4(6, 64, B, A, &tcp(22, 40_002, RST)));

        let flows = capture.finish();
        flows.assert_conserved();
        assert_eq!(flows.len(), 1);
        let flow = flows.only(|f| f.key.protocol == 6);
        assert_eq!(flow.forward.tcp_flags.rst + flow.reverse.tcp_flags.rst, 1);
    }

    #[test]
    fn a_capture_that_starts_mid_conversation_says_so() {
        let mut capture = Capture::new(600_000);
        capture
            .push(&v4(6, 64, A, B, &tcp(40_003, 80, ACK)))
            .push(&v4(6, 64, B, A, &tcp(80, 40_003, ACK)));

        let flows = capture.finish();
        flows.assert_conserved();

        let flow = flows.only(|f| f.key.protocol == 6);
        assert_eq!(
            flow.time.start_state,
            StartState::MidStream,
            "no SYN was ever seen"
        );
        assert_eq!(flow.forward.tcp_flags.syn + flow.reverse.tcp_flags.syn, 0);
    }

    /// Reusing a port pair after the first conversation closed starts a new
    /// flow rather than reopening the old one.
    #[test]
    fn a_reused_port_pair_starts_a_new_flow() {
        let mut capture = Capture::new(600_000);
        capture
            .push(&v4(6, 64, A, B, &tcp(40_006, 443, SYN)))
            .push(&v4(6, 64, B, A, &tcp(443, 40_006, FIN_ACK)))
            .push(&v4(6, 64, A, B, &tcp(40_006, 443, FIN_ACK)))
            // Same five-tuple again, after the first one closed.
            .push(&v4(6, 64, A, B, &tcp(40_006, 443, SYN)))
            .push(&v4(6, 64, B, A, &tcp(443, 40_006, SYN_ACK)));

        let flows = capture.finish();
        flows.assert_conserved();
        assert_eq!(
            flows.count(|f| f.key.ports().0 == 40_006 || f.key.ports().1 == 40_006),
            2
        );
    }

    /// An echo request and its reply are the two directions of one exchange,
    /// in both address families.
    #[test]
    fn an_icmp_exchange_is_one_bidirectional_flow() {
        let mut capture = Capture::new(600_000);
        capture
            .push(&v4(1, 64, A, B, &icmp(8)))
            .push(&v4(1, 64, B, A, &icmp(0)))
            .push(&ethernet(0x86DD, &ipv6(58, A6, B6, &icmp(128))))
            .push(&ethernet(0x86DD, &ipv6(58, B6, A6, &icmp(129))));

        let flows = capture.finish();
        flows.assert_conserved();

        for protocol in [1, 58] {
            let flow = flows.only(|f| f.key.protocol == protocol);
            assert_eq!(flow.packets(), 2, "protocol {} exchange", protocol);
            assert_eq!((flow.forward.packets, flow.reverse.packets), (1, 1));
        }
    }

    /// Only the first fragment carries the ports; the rest must join it rather
    /// than opening a portless flow of their own.
    #[test]
    fn the_fragments_of_a_datagram_stay_together() {
        let mut capture = Capture::new(600_000);
        let first = ipv4_with(
            17,
            64,
            A,
            B,
            Some((42, 0, true)),
            &udp(50_003, 9_999, &[b'F'; 400]),
        );
        let rest = ipv4_with(17, 64, A, B, Some((42, 51, false)), &[b'F'; 200]);

        capture
            .push(&ethernet(0x0800, &first))
            .push(&ethernet(0x0800, &rest));

        let flows = capture.finish();
        flows.assert_conserved();

        assert_eq!(flows.len(), 1, "one datagram is one flow");
        assert_eq!(flows.only(|f| f.key.protocol == 17).packets(), 2);
        assert_eq!(
            flows.count(|f| f.key.ports().0 == 50_003 && f.key.ports().1 == 9_999),
            1,
            "the later fragment joined the datagram's flow"
        );
    }

    /// A large ping fragments like anything else, and ICMP has no ports. The
    /// later fragments used to inherit a remembered `(0, 0)` port pair, which
    /// is a different endpoint kind from the first fragment's "no endpoints",
    /// so one datagram became two flows.
    #[test]
    fn the_fragments_of_a_portless_datagram_stay_together() {
        let mut capture = Capture::new(600_000);
        let mut echo = icmp(8);
        echo.extend_from_slice(&[b'P'; 400]);

        let first = ipv4_with(1, 64, A, B, Some((77, 0, true)), &echo);
        let rest = ipv4_with(1, 64, A, B, Some((77, 51, false)), &[b'P'; 200]);

        capture
            .push(&ethernet(0x0800, &first))
            .push(&ethernet(0x0800, &rest));

        let flows = capture.finish();
        flows.assert_conserved();

        assert_eq!(flows.len(), 1, "one datagram is one flow");
        let flow = flows.only_flow(|f| f.key.protocol == 1);
        assert_eq!(flow.record.packets(), 2);
        assert_eq!(
            flow.key.endpoints,
            fluereflow::Endpoints::None,
            "ICMP has no ports to inherit"
        );
    }

    /// Two tenants on separate VLANs reuse the same private addresses, and
    /// nothing stops them reusing an IP identification too. The fragment table
    /// keyed on addresses alone, so one tenant's later fragments could inherit
    /// the other's ports.
    #[test]
    fn fragmented_datagrams_on_separate_segments_do_not_cross() {
        let mut capture = Capture::new(600_000);

        for (vlan, port) in [(100u16, 50_010u16), (200, 50_020)] {
            let first = ipv4_with(
                17,
                64,
                [10, 0, 0, 1],
                [10, 0, 0, 2],
                Some((99, 0, true)),
                &udp(port, 9_999, &[b'F'; 400]),
            );
            capture.push(&vlan_ethernet(&[vlan], 0x0800, &first));
        }

        for vlan in [100u16, 200] {
            let rest = ipv4_with(
                17,
                64,
                [10, 0, 0, 1],
                [10, 0, 0, 2],
                Some((99, 51, false)),
                &[b'F'; 200],
            );
            capture.push(&vlan_ethernet(&[vlan], 0x0800, &rest));
        }

        let flows = capture.finish();
        flows.assert_conserved();

        assert_eq!(flows.len(), 2, "one flow per tenant");
        for port in [50_010u16, 50_020] {
            assert_eq!(
                flows.only(|f| f.key.ports().0 == port).packets(),
                2,
                "each tenant kept its own fragments"
            );
        }
    }

    /// IPv6 carries fragmentation in an extension header rather than the IP
    /// header, so it needs its own handling. The outcome must match IPv4's: one
    /// datagram is one flow.
    #[test]
    fn the_fragments_of_an_ipv6_datagram_stay_together() {
        const FRAGMENT_HEADER: u8 = 44;
        let mut capture = Capture::new(600_000);

        let mut first = ipv6_fragment(17, 7, 0, true);
        first.extend_from_slice(&udp(5_000, 6_000, &[b'F'; 200]));

        let mut rest = ipv6_fragment(17, 7, 26, false);
        rest.extend_from_slice(&[b'F'; 100]);

        capture
            .push(&ethernet(0x86DD, &ipv6(FRAGMENT_HEADER, A6, B6, &first)))
            .push(&ethernet(0x86DD, &ipv6(FRAGMENT_HEADER, A6, B6, &rest)));

        let flows = capture.finish();
        flows.assert_conserved();

        assert_eq!(flows.len(), 1, "one datagram is one flow");
        assert_eq!(flows.only(|f| f.key.protocol == 17).packets(), 2);
        assert_eq!(
            flows.count(|f| f.key.ports() == (5_000, 6_000)),
            1,
            "the later fragment joined the datagram's flow"
        );
    }

    /// A QUIC connection survives its client changing address: the client keeps
    /// the connection alive by its Connection ID, not its 5-tuple. Keyed on
    /// addresses alone this reads as one flow going quiet and another starting.
    #[test]
    fn a_migrated_quic_connection_stays_one_flow() {
        const CID: &[u8] = &[0xab, 0xcd, 0xef, 0x01];
        let mut capture = Capture::new(600_000);

        let client = [192, 0, 2, 10];
        let roamed = [203, 0, 113, 77];
        let server = [198, 51, 100, 20];

        // Handshake: the server announces the ID the client will address.
        capture.push(&v4(
            17,
            64,
            server,
            client,
            &udp(443, 50_000, &quic_long_header(CID)),
        ));
        // 1-RTT traffic from the client's original address.
        capture.push(&v4(
            17,
            64,
            client,
            server,
            &udp(50_000, 443, &quic_short_header(CID)),
        ));
        // The client moves to a different network and keeps sending.
        capture.push(&v4(
            17,
            64,
            roamed,
            server,
            &udp(60_000, 443, &quic_short_header(CID)),
        ));

        let flows = capture.finish();
        flows.assert_conserved();

        assert_eq!(
            flows.len(),
            1,
            "the migrated packet belongs to the connection it continues"
        );

        let flow = flows.only(|f| f.key.protocol == 17);
        assert_eq!(flow.packets(), 3);
        assert!(flow.paths.migrated(), "and the record says it moved");
        assert_eq!(
            flow.paths.count(),
            2,
            "where it opened, plus where it moved to"
        );
    }

    /// A connection ID says which connection a packet belongs to, not which
    /// segment it is on. Two tenants can carry the same ID through a replayed
    /// capture or a mirror that sees both copies of one connection, and
    /// following it across the boundary would merge their traffic.
    #[test]
    fn quic_migration_does_not_cross_a_segment_boundary() {
        const CID: &[u8] = &[0xab, 0xcd, 0xef, 0x02];
        let mut capture = Capture::new(600_000);

        let client = [192, 0, 2, 10];
        let roamed = [203, 0, 113, 77];
        let server = [198, 51, 100, 20];

        // The connection is established on one tenant's VLAN.
        capture.push(&vlan_ethernet(
            &[100],
            0x0800,
            &ipv4(17, 64, server, client, &udp(443, 50_000, &quic_long_header(CID))),
        ));
        capture.push(&vlan_ethernet(
            &[100],
            0x0800,
            &ipv4(17, 64, client, server, &udp(50_000, 443, &quic_short_header(CID))),
        ));
        // The same ID turns up on another tenant's VLAN.
        capture.push(&vlan_ethernet(
            &[200],
            0x0800,
            &ipv4(17, 64, roamed, server, &udp(60_000, 443, &quic_short_header(CID))),
        ));

        let flows = capture.finish();
        flows.assert_conserved();

        assert_eq!(flows.len(), 2, "one flow per tenant");
        let tenant = flows.only_flow(|f| f.key.vlan.tags() == [100]);
        assert_eq!(tenant.record.packets(), 2);
        assert!(
            !tenant.record.paths.migrated(),
            "the other tenant's packet is not this connection moving"
        );
    }

    /// Merged captures and multi-queue interfaces deliver packets out of
    /// order. `last` is the latest packet the flow saw, not whichever arrived
    /// most recently, or a late-delivered early packet drags it backwards and
    /// takes the idle deadline with it.
    #[test]
    fn an_out_of_order_packet_does_not_move_the_flow_backwards() {
        let mut capture = Capture::new(600_000);
        capture
            .push_at(&v4(6, 64, A, B, &tcp(40_001, 443, SYN)), 1_000)
            .push_at(&v4(6, 64, B, A, &tcp(443, 40_001, SYN_ACK)), 9_000)
            .push_at(&v4(6, 64, A, B, &tcp(40_001, 443, ACK)), 3_000);

        let flows = capture.finish();
        flows.assert_conserved();

        assert_eq!(flows.len(), 1, "still one conversation");
        let flow = flows.only(|f| f.key.protocol == 6);
        assert_eq!(flow.time.start.nanos(), 1_000_000);
        assert_eq!(flow.time.end.nanos(), 9_000_000, "the latest packet seen");
        assert_eq!(flow.time.duration(), 8_000_000);
    }

    /// A flow that stays where it started reports a single path, so `migrated`
    /// means what it says.
    #[test]
    fn a_flow_that_never_moves_reports_one_path() {
        let mut capture = Capture::new(600_000);
        capture
            .push(&v4(6, 64, A, B, &tcp(40_001, 443, SYN)))
            .push(&v4(6, 64, A, B, &tcp(40_001, 443, ACK)));

        let flows = capture.finish();
        flows.assert_conserved();

        let flow = flows.only(|f| f.key.protocol == 6);
        assert_eq!(flow.paths.count(), 1);
        assert!(!flow.paths.migrated());
    }

    /// Without a handshake to learn the connection ID from, there is nothing to
    /// attribute a migrated packet to, and it opens its own flow.
    #[test]
    fn quic_traffic_with_no_observed_handshake_is_not_reattributed() {
        const CID: &[u8] = &[0x11, 0x22, 0x33, 0x44];
        let mut capture = Capture::new(600_000);

        capture.push(&v4(
            17,
            64,
            [192, 0, 2, 10],
            [198, 51, 100, 20],
            &udp(50_000, 443, &quic_short_header(CID)),
        ));
        capture.push(&v4(
            17,
            64,
            [203, 0, 113, 77],
            [198, 51, 100, 20],
            &udp(60_000, 443, &quic_short_header(CID)),
        ));

        let flows = capture.finish();
        flows.assert_conserved();
        assert_eq!(flows.len(), 2, "nothing was learned to attribute them to");
    }

    /// Tenants on different segments reuse the same private addresses, so
    /// their inner five-tuples are identical.
    #[test]
    fn tenants_on_different_segments_stay_apart() {
        let mut capture = Capture::new(600_000);
        for vni in [100, 200] {
            let tunnelled = v4(
                17,
                64,
                [203, 0, 113, 1],
                [203, 0, 113, 2],
                &udp(50_000, 4789, &vxlan(vni, &tenant_traffic())),
            );
            capture.push(&tunnelled);
        }

        let flows = capture.finish();
        flows.assert_conserved();

        assert_eq!(
            flows.count(|f| f.key.ports().0 == 41_001),
            2,
            "two tenants with the same inner tuple must not share a record"
        );
    }

    /// A VLAN is its own broadcast domain, so two segments reuse addresses
    /// freely. Without the tag in the key their traffic shares one record.
    #[test]
    fn vlan_segments_stay_apart() {
        let mut capture = Capture::new(600_000);
        let inner = ipv4(
            6,
            64,
            [10, 1, 0, 1],
            [10, 2, 0, 2],
            &tcp(41_001, 9_000, SYN),
        );

        capture
            .push(&vlan_ethernet(&[100], 0x0800, &inner))
            .push(&vlan_ethernet(&[200], 0x0800, &inner));

        let flows = capture.finish();
        flows.assert_conserved();

        assert_eq!(
            flows.count(|f| f.key.ports().0 == 41_001),
            2,
            "two segments with the same inner tuple must not share a record"
        );

        // And the reason they are separate is reportable, not just internal.
        let mut segments: Vec<Vec<u16>> =
            flows.keys().map(|key| key.vlan.tags().to_vec()).collect();
        segments.sort_unstable();
        assert_eq!(segments, vec![vec![100], vec![200]]);
    }

    /// A tagged frame and an untagged one are different segments too.
    #[test]
    fn tagged_and_untagged_traffic_stay_apart() {
        let mut capture = Capture::new(600_000);
        let inner = ipv4(
            6,
            64,
            [10, 1, 0, 1],
            [10, 2, 0, 2],
            &tcp(41_002, 9_000, SYN),
        );

        capture
            .push(&vlan_ethernet(&[100], 0x0800, &inner))
            .push(&ethernet(0x0800, &inner));

        let flows = capture.finish();
        flows.assert_conserved();
        assert_eq!(flows.count(|f| f.key.ports().0 == 41_002), 2);
    }

    /// Stacked tags identify a service and a customer separately.
    #[test]
    fn qinq_inner_tags_separate_customers() {
        let mut capture = Capture::new(600_000);
        let inner = ipv4(
            6,
            64,
            [10, 1, 0, 1],
            [10, 2, 0, 2],
            &tcp(41_003, 9_000, SYN),
        );

        capture
            .push(&vlan_ethernet(&[10, 20], 0x0800, &inner))
            .push(&vlan_ethernet(&[10, 30], 0x0800, &inner));

        let flows = capture.finish();
        flows.assert_conserved();
        assert_eq!(
            flows.count(|f| f.key.ports().0 == 41_003),
            2,
            "same outer tag, different customer"
        );
    }

    /// Return traffic comes back on the same segment, so the tag is not
    /// reversed with the addresses.
    #[test]
    fn a_conversation_on_one_vlan_is_one_flow() {
        let mut capture = Capture::new(600_000);
        capture
            .push(&vlan_ethernet(
                &[100],
                0x0800,
                &ipv4(6, 64, A, B, &tcp(40_010, 443, SYN)),
            ))
            .push(&vlan_ethernet(
                &[100],
                0x0800,
                &ipv4(6, 64, B, A, &tcp(443, 40_010, SYN_ACK)),
            ));

        let flows = capture.finish();
        flows.assert_conserved();

        assert_eq!(flows.len(), 1);
        let flow = flows.only(|f| f.key.protocol == 6);
        assert_eq!((flow.forward.packets, flow.reverse.packets), (1, 1));
    }

    /// Two GRE tunnels can share a pair of endpoints and be told apart only by
    /// their RFC 2890 key.
    #[test]
    fn gre_tunnels_are_separated_by_their_key() {
        let mut capture = Capture::new(600_000);
        let inner = ipv4(
            6,
            32,
            [10, 1, 0, 1],
            [10, 2, 0, 2],
            &tcp(41_001, 9_000, SYN),
        );

        for key in [0x1111, 0x2222] {
            let mut payload = gre(0x0800, Some(key));
            payload.extend_from_slice(&inner);
            capture.push(&v4(47, 64, [203, 0, 113, 1], [203, 0, 113, 2], &payload));
        }

        let flows = capture.finish();
        flows.assert_conserved();
        assert_eq!(flows.count(|f| f.key.ports().0 == 41_001), 2, "two tunnels");
    }

    /// A GRE key is optional, so a tunnel that omits it and one that sets it to
    /// zero are different tunnels. Recording the absent key as 0 merged them.
    #[test]
    fn a_keyless_gre_tunnel_is_not_one_keyed_zero() {
        let mut capture = Capture::new(600_000);
        let inner = ipv4(
            6,
            32,
            [10, 1, 0, 1],
            [10, 2, 0, 2],
            &tcp(41_006, 9_000, SYN),
        );

        for key in [None, Some(0)] {
            let mut payload = gre(0x0800, key);
            payload.extend_from_slice(&inner);
            capture.push(&v4(47, 64, [203, 0, 113, 1], [203, 0, 113, 2], &payload));
        }

        let flows = capture.finish();
        flows.assert_conserved();
        assert_eq!(flows.count(|f| f.key.ports().0 == 41_006), 2, "two tunnels");
    }

    /// MPLS label 0 is IPv4 Explicit NULL, a label in everyday use, not the
    /// absence of one.
    #[test]
    fn mpls_label_zero_is_a_label() {
        let mut capture = Capture::new(600_000);
        let inner = ipv4(
            6,
            32,
            [10, 1, 0, 1],
            [10, 2, 0, 2],
            &tcp(41_007, 9_000, SYN),
        );

        let mut payload = mpls(0);
        payload.extend_from_slice(&inner);
        capture.push(&ethernet(0x8847, &payload));

        let flows = capture.finish();
        flows.assert_conserved();

        let flow = flows.only_flow(|f| f.key.ports().0 == 41_007);
        let encapsulation = flow.key.encapsulation.expect("an MPLS encapsulation");
        assert_eq!(encapsulation.id, Some(0), "explicit null, not absent");
    }

    /// MPLS sits below IP and has no addresses of its own, but the label still
    /// separates traffic that would otherwise collide.
    #[test]
    fn mpls_labels_separate_traffic() {
        let mut capture = Capture::new(600_000);
        let inner = ipv4(
            6,
            32,
            [10, 1, 0, 1],
            [10, 2, 0, 2],
            &tcp(41_004, 9_000, SYN),
        );

        for label in [1_000, 2_000] {
            let mut payload = mpls(label);
            payload.extend_from_slice(&inner);
            capture.push(&ethernet(0x8847, &payload));
        }

        let flows = capture.finish();
        flows.assert_conserved();
        assert_eq!(
            flows.count(|f| f.key.ports().0 == 41_004),
            2,
            "two label paths"
        );
    }

    /// Subscribers on one access network share addresses and are told apart
    /// only by their PPPoE session.
    #[test]
    fn pppoe_sessions_separate_subscribers() {
        let mut capture = Capture::new(600_000);
        let inner = ipv4(
            6,
            32,
            [10, 1, 0, 1],
            [10, 2, 0, 2],
            &tcp(41_005, 9_000, SYN),
        );

        for session in [1, 2] {
            capture.push(&ethernet(0x8864, &pppoe(session, &inner)));
        }

        let flows = capture.finish();
        flows.assert_conserved();
        assert_eq!(
            flows.count(|f| f.key.ports().0 == 41_005),
            2,
            "two subscribers"
        );
    }

    /// IPsec associations are one-way and identified by their SPI, not by ports.
    #[test]
    fn ipsec_associations_are_separate_flows() {
        let mut capture = Capture::new(600_000);
        capture
            .push(&v4(50, 64, A, B, &esp(0x1111_1111)))
            .push(&v4(50, 64, A, B, &esp(0x2222_2222)))
            .push(&v4(50, 64, A, B, &esp(0x1111_1111)));

        let flows = capture.finish();
        flows.assert_conserved();
        assert_eq!(flows.count(|f| f.key.protocol == 50), 2, "two associations");
    }

    #[test]
    fn sctp_associations_are_keyed_on_their_ports() {
        let mut capture = Capture::new(600_000);
        capture
            .push(&v4(132, 64, A, B, &sctp(50_005, 38_412)))
            .push(&v4(132, 64, A, B, &sctp(50_006, 38_412)));

        let flows = capture.finish();
        flows.assert_conserved();
        assert_eq!(flows.count(|f| f.key.protocol == 132), 2);
    }

    /// A flow that goes quiet for longer than the timeout is closed, and later
    /// traffic on the same tuple is a new flow.
    #[test]
    fn an_idle_flow_times_out() {
        let mut capture = Capture::new(1_000);
        capture
            .push_at(&v4(17, 64, A, B, &udp(1111, 9, &[b'x'; 10])), 1_000)
            .push_at(&v4(17, 64, A, B, &udp(1111, 9, &[b'x'; 10])), 100_000)
            // Ten seconds later: the first flow has long since idled out.
            .push_at(&v4(17, 64, A, B, &udp(1111, 9, &[b'x'; 10])), 10_100_000);

        let flows = capture.finish();
        flows.assert_conserved();
        assert_eq!(
            flows.count(|f| f.key.ports().0 == 1111),
            2,
            "one gap, two flows"
        );
    }

    #[test]
    fn a_zero_timeout_keeps_flows_open() {
        let mut capture = Capture::new(0);
        capture
            .push_at(&v4(17, 64, A, B, &udp(2222, 9, &[b'x'; 10])), 1_000)
            .push_at(&v4(17, 64, A, B, &udp(2222, 9, &[b'x'; 10])), 999_999_000);

        let flows = capture.finish();
        flows.assert_conserved();
        assert_eq!(flows.len(), 1, "nothing expires without a timeout");
    }

    /// A mixed capture, to catch anything that only misbehaves alongside
    /// other traffic.
    #[test]
    fn a_mixed_capture_conserves_every_packet() {
        let mut capture = Capture::new(600_000);
        capture
            .push(&v4(6, 64, A, B, &tcp(40_001, 443, SYN)))
            .push(&v4(6, 52, B, A, &tcp(443, 40_001, SYN_ACK)))
            .push(&v4(17, 64, A, B, &udp(53_000, 53, &[b'q'; 40])))
            .push(&v4(1, 64, A, B, &icmp(8)))
            .push(&v4(50, 64, A, B, &esp(0xabcd_1234)))
            .push(&v4(132, 64, A, B, &sctp(50_005, 38_412)))
            .push(&ethernet(0x86DD, &ipv6(6, A6, B6, &tcp(40_004, 8443, SYN))))
            .push(&ethernet(
                0x0806,
                &[
                    0, 1, 8, 0, 6, 4, 0, 1, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 10, 0, 0, 1, 0, 0,
                    0, 0, 0, 0, 10, 0, 0, 2,
                ],
            ))
            .push(&v4(
                17,
                64,
                [203, 0, 113, 1],
                [203, 0, 113, 2],
                &udp(50_000, 4789, &vxlan(100, &tenant_traffic())),
            ));

        let flows = capture.finish();
        flows.assert_conserved();

        assert_eq!(flows.len(), 8, "one flow per distinct conversation");
        assert_eq!(
            flows.count(|f| f.key.protocol == 6),
            3,
            "two plain TCP plus the tunnelled one"
        );
    }
}
