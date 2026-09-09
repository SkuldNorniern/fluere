//! Keeping a QUIC connection together when its addresses change.
//!
//! A QUIC connection is identified by its Connection ID, not by the addresses
//! carrying it. A client moving from WiFi to cellular keeps the same connection
//! and simply starts sending from a new address and port. Keyed on the 5-tuple
//! alone that reads as one flow going quiet and an unrelated one starting.
//!
//! During the handshake, each side announces a connection ID in a long header.
//! Afterwards, every 1-RTT packet carries the peer's ID in a short header. This
//! remembers which flow issued each ID, so a packet arriving on an address
//! nobody has seen before can still be attributed to the connection it belongs
//! to.

use std::collections::HashMap;

use log::trace;

use paccel::engine::{
    Endpoint, ParsedPacket, QuicConnectionId, QuicConnectionTracker, QuicDirection,
};
use paccel::layer::Confidence;

use crate::net::types::Key;

use super::observation::PacketObservation;

/// Most connections to track at once. Reached only under a lot of concurrent
/// QUIC; the least recently used entries are dropped first.
const MAX_TRACKED: usize = 8192;

/// How long a connection ID stays useful, in nanoseconds. A connection idle for
/// this long is not going to migrate.
const MAX_AGE: u64 = 300_000_000_000;

/// A UDP header is a fixed eight bytes, after which the QUIC packet begins.
const UDP_HEADER_LEN: usize = 8;

/// A QUIC connection's flow, and the direction that flow key names.
#[derive(Debug, Clone, Copy)]
struct Origin {
    /// The flow key in the initiator-to-responder direction. The other
    /// direction is its reverse, derived rather than stored so the two cannot
    /// disagree after a migration rewrites one of them.
    initiator_to_responder: Key,
}

/// Follows a QUIC connection across a change of address.
///
/// Connection identity is paccel's: it knows the connection-ID lengths in use,
/// which endpoint issued which id, and how to follow a move. What it does not
/// know is what fluere means by a flow - the VLAN, the tunnel, the link
/// addresses - so the mapping from a connection to a flow stays here.
#[derive(Debug)]
pub struct QuicTracker {
    connections: QuicConnectionTracker,
    /// The flow each connection was first seen on.
    origins: HashMap<QuicConnectionId, Origin>,
    /// When the last age-out ran, so it runs on capture time, not wall clock.
    last_expiry: u64,
}

impl Default for QuicTracker {
    fn default() -> Self {
        QuicTracker {
            connections: QuicConnectionTracker::new().with_max_flows(MAX_TRACKED),
            origins: HashMap::new(),
            last_expiry: 0,
        }
    }
}

impl QuicTracker {
    pub fn new() -> Self {
        QuicTracker::default()
    }

    /// Drop connections idle for longer than `MAX_AGE`, and the origins that
    /// pointed at them.
    ///
    /// paccel bounds its own side, but it has never heard of `origins`, so the
    /// two are swept together or this map keeps every connection the capture
    /// ever saw.
    fn expire(&mut self, now: u64) {
        if now.saturating_sub(self.last_expiry) < MAX_AGE {
            return;
        }
        self.last_expiry = now;
        self.connections.expire_before(now.saturating_sub(MAX_AGE));
        let connections = &self.connections;
        self.origins
            .retain(|id, _| !connections.tuples_for_connection(*id).is_empty());
    }

    /// Learn from a handshake packet, and attribute a migrated one.
    ///
    /// Returns `true` if the observation was reattributed to a connection first
    /// seen on different addresses.
    pub fn resolve(
        &mut self,
        observation: &mut PacketObservation,
        parsed: &ParsedPacket,
        packet_data: &[u8],
    ) -> bool {
        let now = observation.time().nanos();
        self.expire(now);
        let Some((source, destination)) = endpoints_of(observation) else {
            return false;
        };

        if let Some(quic) = parsed.quic() {
            self.learn(observation, source, destination, &quic.scid, now);
            return false;
        }

        let Some(payload) = udp_payload(parsed, packet_data) else {
            return false;
        };
        self.attribute(observation, source, destination, payload, now)
    }

    /// Records a handshake packet, and the flow the connection is on.
    fn learn(
        &mut self,
        observation: &PacketObservation,
        source: Endpoint,
        destination: Endpoint,
        scid: &[u8],
        now: u64,
    ) {
        self.connections.observe_long_header_at(
            source.address,
            source.port,
            destination.address,
            destination.port,
            scid,
            now,
        );
        let Some(id) = self.connections.connection_id_for_dcid(scid) else {
            return;
        };
        let Some(direction) = self.connections.direction_for(id, source, destination) else {
            return;
        };
        // Stored in one canonical direction, so a packet the other way is the
        // reverse of it rather than a second entry that could drift.
        let initiator_to_responder = match direction {
            QuicDirection::InitiatorToResponder => observation.key,
            QuicDirection::ResponderToInitiator => observation.reverse_key(),
        };
        self.origins.entry(id).or_insert(Origin {
            initiator_to_responder,
        });
    }

    /// Puts a short-header packet back on the flow its connection started on.
    fn attribute(
        &mut self,
        observation: &mut PacketObservation,
        source: Endpoint,
        destination: Endpoint,
        payload: &[u8],
        now: u64,
    ) -> bool {
        let Some((header, confidence)) = self.connections.classify_short_header(
            source.address,
            source.port,
            destination.address,
            destination.port,
            payload,
        ) else {
            return false;
        };
        // Only a connection paccel actually knows. A structural match is a
        // well-shaped header, not evidence of which connection it is.
        if confidence != Confidence::Stateful {
            return false;
        }
        let Some(id) = self.connections.connection_id_for_dcid(header.dcid) else {
            return false;
        };
        let dcid = header.dcid.to_vec();

        let Some(origin) = self.origins.get(&id).copied() else {
            return false;
        };
        let Some(direction) = self.connections.direction_for(id, source, destination) else {
            return false;
        };
        let target = match direction {
            QuicDirection::InitiatorToResponder => origin.initiator_to_responder,
            QuicDirection::ResponderToInitiator => origin.initiator_to_responder.reversed(),
        };

        if target == observation.key {
            // Same addresses as before: nothing migrated.
            return false;
        }
        // A connection ID says which connection a packet belongs to, not which
        // segment it is on. Two tenants can carry the same one, through a
        // replayed capture or a mirror that sees both copies of a connection,
        // and reattributing across the boundary would merge their traffic.
        if !same_segment(&target, &observation.key) {
            return false;
        }

        // Bind the new address pair, so paccel's own state follows the move
        // too rather than only fluere's view of it.
        self.connections.observe_short_header_at(
            source.address,
            source.port,
            destination.address,
            destination.port,
            &dcid,
            now,
        );
        trace!(
            "quic connection {id:?} moved to {}:{}",
            source.address, source.port
        );
        observation.key = target;
        true
    }
}

/// The addresses a packet travelled between, as paccel names them.
fn endpoints_of(observation: &PacketObservation) -> Option<(Endpoint, Endpoint)> {
    let (source_port, destination_port) = observation.key.ports();
    Some((
        Endpoint::new(observation.key.source, source_port),
        Endpoint::new(observation.key.destination, destination_port),
    ))
}

fn same_segment(remembered: &Key, observed: &Key) -> bool {
    remembered.vlan == observed.vlan && remembered.encapsulation == observed.encapsulation
}

/// The bytes a UDP datagram carried, which for QUIC is the packet itself.
///
/// paccel reports where the transport segment starts, so the payload is that
/// plus the fixed UDP header, with no need to re-walk the link and network
/// headers it already resolved.
fn udp_payload<'a>(parsed: &ParsedPacket, packet_data: &'a [u8]) -> Option<&'a [u8]> {
    use paccel::engine::TransportSegment;

    if !matches!(parsed.transport, Some(TransportSegment::Udp(_))) {
        return None;
    }

    let offset = parsed
        .transport_segment_offset?
        .checked_add(UDP_HEADER_LEN)?;
    packet_data.get(offset..)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> Key {
        use fluereflow::{Endpoints, MacAddress, VlanTags};
        use std::net::{IpAddr, Ipv4Addr};

        Key {
            source: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            destination: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)),
            endpoints: Endpoints::Ports {
                source: 50_000,
                destination: 443,
            },
            protocol: 17,
            ethertype: None,
            source_mac: MacAddress::new([0; 6]),
            destination_mac: MacAddress::new([1; 6]),
            vlan: VlanTags::default(),
            encapsulation: None,
        }
    }

    use crate::net::parser::observation::PacketObservation;
    use fluereflow::{PacketFacts, Timestamp};
    use paccel::engine::{BuiltinPacketParser, ParseConfig, ParsedPacket};
    use std::net::{IpAddr, Ipv4Addr};

    const SERVER: [u8; 4] = [192, 0, 2, 1];
    const CLIENT: [u8; 4] = [198, 51, 100, 2];
    const MOVED: [u8; 4] = [203, 0, 113, 9];

    /// An ethernet/IPv4/UDP frame carrying `payload` between the given ports.
    fn udp_frame(source: ([u8; 4], u16), destination: ([u8; 4], u16), payload: &[u8]) -> Vec<u8> {
        let mut frame = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00];
        let total = 20 + 8 + payload.len();
        frame.extend([0x45, 0x00]);
        frame.extend(u16::try_from(total).expect("short frame").to_be_bytes());
        frame.extend([0x00, 0x01, 0x00, 0x00, 64, 17, 0, 0]);
        frame.extend(source.0);
        frame.extend(destination.0);
        frame.extend(source.1.to_be_bytes());
        frame.extend(destination.1.to_be_bytes());
        frame.extend(
            u16::try_from(8 + payload.len())
                .expect("short")
                .to_be_bytes(),
        );
        frame.extend([0, 0]);
        frame.extend(payload);
        frame
    }

    /// A QUIC v1 Initial announcing `scid`, with no destination id.
    fn long_header(scid: &[u8]) -> Vec<u8> {
        let mut packet = vec![0xc0, 0x00, 0x00, 0x00, 0x01, 0x00];
        packet.push(u8::try_from(scid.len()).expect("short id"));
        packet.extend(scid);
        packet.extend([0x00, 0x41, 0x00]);
        packet
    }

    /// A 1-RTT packet addressed to `dcid`.
    fn short_header(dcid: &[u8]) -> Vec<u8> {
        let mut packet = vec![0x40];
        packet.extend(dcid);
        packet.extend([0xaa; 16]);
        packet
    }

    fn observe(tracker: &mut QuicTracker, frame: &[u8], now: u64) -> (PacketObservation, bool) {
        let mut parsed = ParsedPacket::default();
        BuiltinPacketParser::parse_into(frame, ParseConfig::default(), Some(1), &mut parsed)
            .expect("the fixture parses");
        let (source_port, destination_port) = match &parsed.transport {
            Some(paccel::engine::TransportSegment::Udp(udp)) => {
                (udp.source_port, udp.destination_port)
            }
            _ => panic!("the fixture is udp"),
        };
        let mut observation = PacketObservation {
            key: Key {
                source: parsed.ipv4.as_ref().expect("addresses").source.into(),
                destination: parsed.ipv4.as_ref().expect("addresses").destination.into(),
                endpoints: fluereflow::Endpoints::Ports {
                    source: source_port,
                    destination: destination_port,
                },
                // Zeroed, as they are when MACs are not in the key, so that
                // reversing a key is symmetric on the link addresses too.
                source_mac: fluereflow::MacAddress::new([0; 6]),
                destination_mac: fluereflow::MacAddress::new([0; 6]),
                ..key()
            },
            facts: PacketFacts {
                time: Timestamp::from_nanos(now),
                frame_octets: 0,
                captured_octets: 0,
                ttl: None,
                tcp_flags: None,
                icmp: None,
            },
            dscp: None,
            ecn: None,
            arrived_from: (IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0),
            tcp_flags: None,
        };
        let moved = tracker.resolve(&mut observation, &parsed, frame);
        (observation, moved)
    }

    /// The point of the tracker: a connection that changes address is still
    /// the same flow, and its connection id is what says so.
    #[test]
    fn a_migrated_packet_goes_back_to_the_flow_it_started_on() {
        let cid = [9u8, 9, 9, 9];
        let mut tracker = QuicTracker::new();

        // Handshake from the server, announcing the id clients will address.
        let handshake = udp_frame((SERVER, 443), (CLIENT, 50_000), &long_header(&cid));
        let (opened, _) = observe(&mut tracker, &handshake, 1_000);

        // The client now appears from a new address, using that id.
        let moved = udp_frame((MOVED, 53_000), (SERVER, 443), &short_header(&cid));
        let (attributed, was_moved) = observe(&mut tracker, &moved, 2_000);

        assert!(was_moved, "the packet was not reattributed");
        assert_eq!(
            attributed.key,
            opened.reverse_key(),
            "it belongs to the flow the handshake opened, seen the other way"
        );
    }

    /// An id nobody has announced says nothing, so the packet stays on the
    /// flow its own addresses name.
    #[test]
    fn an_unknown_connection_id_moves_nothing() {
        let mut tracker = QuicTracker::new();
        let frame = udp_frame((MOVED, 53_000), (SERVER, 443), &short_header(&[7u8; 4]));
        let (observation, moved) = observe(&mut tracker, &frame, 1_000);

        assert!(!moved);
        assert_eq!(observation.key.source, IpAddr::V4(Ipv4Addr::from(MOVED)));
    }

    /// A packet on the addresses the connection already had is not a move.
    /// An idle connection stops being followed, and its origin goes with it.
    ///
    /// The map fluere keeps beside paccel's tracker is the one that would grow
    /// without bound, so it is what this asserts on.
    #[test]
    fn an_idle_connection_is_forgotten_along_with_its_origin() {
        let mut tracker = QuicTracker::new();
        let cid = [9u8, 8, 7, 6, 5, 4, 3, 2];

        let handshake = udp_frame((SERVER, 443), (CLIENT, 50_000), &long_header(&cid));
        observe(&mut tracker, &handshake, 1_000);
        assert_eq!(tracker.origins.len(), 1, "the handshake should be learned");

        // A packet far enough later that the connection has aged out.
        let later = udp_frame((SERVER, 443), (CLIENT, 50_000), &long_header(&[1u8; 8]));
        observe(&mut tracker, &later, 1_000 + MAX_AGE * 2);

        assert_eq!(
            tracker.origins.len(),
            1,
            "only the connection just seen should remain, not both"
        );

        // And the aged-out id no longer follows a migration.
        let moved = udp_frame((MOVED, 53_000), (SERVER, 443), &short_header(&cid));
        let (observation, migrated) = observe(&mut tracker, &moved, 1_000 + MAX_AGE * 2);
        assert!(!migrated, "a forgotten connection cannot be migrated to");
        assert_eq!(observation.key.source, IpAddr::V4(Ipv4Addr::from(MOVED)));
    }

    #[test]
    fn a_packet_that_did_not_move_is_not_reattributed() {
        let cid = [1u8, 2, 3, 4];
        let mut tracker = QuicTracker::new();
        let handshake = udp_frame((SERVER, 443), (CLIENT, 50_000), &long_header(&cid));
        observe(&mut tracker, &handshake, 1_000);

        // The client replying from the address it has had all along.
        let same = udp_frame((CLIENT, 50_000), (SERVER, 443), &short_header(&cid));
        let (_, moved) = observe(&mut tracker, &same, 2_000);
        assert!(!moved, "nothing migrated, so nothing to reattribute");
    }
}
