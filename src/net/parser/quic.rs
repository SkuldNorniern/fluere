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

#[cfg(feature = "quic-l7")]
use paccel::engine::QuicStreamReassembler;
use paccel::engine::{
    Endpoint, ParsedPacket, QuicConnectionId, QuicConnectionTracker, QuicDirection,
};
use paccel::layer::Confidence;
#[cfg(feature = "quic-l7")]
use paccel::layer::application::quic::{
    decrypt::decrypt_initial_packet, frame::QuicFrame, frame::iter_quic_frames,
    split_coalesced_packets,
};

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
    /// The handshake bytes of each connection, keyed on the connection and not
    /// the address pair.
    ///
    /// A ClientHello does not always fit one Initial packet, and a client that
    /// moves between them would have its handshake split in two if this were
    /// keyed on addresses. Keyed on the connection, the move is invisible.
    #[cfg(feature = "quic-l7")]
    crypto: QuicStreamReassembler,
    /// What has been reassembled of each handshake so far, and whether it has
    /// already been read.
    #[cfg(feature = "quic-l7")]
    handshakes: HashMap<HandshakeKey, Handshake>,
    /// When the last age-out ran, so it runs on capture time, not wall clock.
    last_expiry: u64,
}

impl Default for QuicTracker {
    fn default() -> Self {
        QuicTracker {
            connections: QuicConnectionTracker::new().with_max_flows(MAX_TRACKED),
            origins: HashMap::new(),
            #[cfg(feature = "quic-l7")]
            crypto: QuicStreamReassembler::default(),
            #[cfg(feature = "quic-l7")]
            handshakes: HashMap::new(),
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
        #[cfg(feature = "quic-l7")]
        {
            self.handshakes.retain(|held, _| match held {
                HandshakeKey::Connection(id) => !connections.tuples_for_connection(*id).is_empty(),
                // An untracked handshake has no connection to outlive, so it goes
                // with the reassembly under it.
                HandshakeKey::Tuple(..) => false,
            });
            self.crypto.expire_before(now.saturating_sub(MAX_AGE));
        }
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
            // Same addresses as before, so nothing migrated - but the
            // connection is plainly still in use, and saying so is what keeps
            // it from ageing out. Without this only a move refreshed it, so a
            // connection that carried traffic steadily on one address pair was
            // forgotten while busy, and the move that eventually came opened a
            // second flow.
            self.connections.observe_short_header_at(
                source.address,
                source.port,
                destination.address,
                destination.port,
                &dcid,
                now,
            );
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

#[cfg(feature = "quic-l7")]
impl QuicTracker {
    /// The server name a QUIC client asked for, once its handshake is readable.
    ///
    /// A client Initial is encrypted with keys derived from its own connection
    /// ID, so this needs no secrets: RFC 9001 section 5.2 makes the Initial
    /// packet protection a formality against middleboxes, not a secret.
    ///
    /// Returns the name once per connection, on the packet that completed the
    /// ClientHello, so a flow is annotated rather than every packet of it.
    pub fn client_hello(
        &mut self,
        parsed: &ParsedPacket,
        packet_data: &[u8],
        now: u64,
    ) -> Option<String> {
        let header = parsed.quic()?;
        if !header.is_initial {
            return None;
        }
        // Looked up by address pair rather than connection ID: the tracker
        // indexes the id an endpoint *issued*, and a client's first Initial may
        // carry a zero-length SCID and a DCID of its own invention, neither of
        // which names a connection yet.
        let key = parsed.flow_key()?;
        let scope = self.connections.connection_and_direction(
            key.src_ip,
            key.src_port,
            key.dst_ip,
            key.dst_port,
            &header.dcid,
        );
        let handshake = HandshakeKey::of(&key, scope);
        if self
            .handshakes
            .get(&handshake)
            .is_some_and(|held| held.read)
        {
            return None;
        }

        let datagram = udp_payload(parsed, packet_data)?;
        // A datagram may hold several QUIC packets; only the Initials matter,
        // and each is decrypted from its own header.
        for packet in split_coalesced_packets(datagram) {
            self.absorb_initial(handshake, scope, &key, packet, now);
        }

        let held = self.handshakes.get_mut(&handshake)?;
        let hello = paccel::layer::application::tls::parse_tls_client_hello(&wrap_as_tls_record(
            &held.bytes,
        )?)
        .ok()?;
        held.read = true;
        held.bytes = Vec::new();
        hello.server_name
    }

    /// Feeds one Initial packet's CRYPTO frames into the handshake buffer.
    fn absorb_initial(
        &mut self,
        handshake: HandshakeKey,
        scope: Option<(QuicConnectionId, QuicDirection)>,
        key: &paccel::engine::FlowKey,
        packet: &[u8],
        now: u64,
    ) {
        let Ok(header) = paccel::layer::application::quic::parse_quic_long_header(packet) else {
            return;
        };
        if !header.is_initial {
            return;
        }
        let Ok(decrypted) = decrypt_initial_packet(&header, packet) else {
            return;
        };

        for frame in iter_quic_frames(&decrypted.payload) {
            // A frame that does not decode poisons the iterator, so the rest
            // of the packet is simply not there to read.
            let Ok(QuicFrame::Crypto { offset, data }) = frame else {
                continue;
            };
            // Keyed on the connection wherever there is one: a client that
            // moves mid-handshake keeps a single stream instead of starting a
            // second at its new address. A connection that named itself with a
            // zero-length SCID is not tracked, and falls back to its addresses,
            // which is what it had before this existed.
            let delivered = match scope {
                Some((id, direction)) => {
                    self.crypto
                        .offer_for_connection_at(
                            id,
                            direction,
                            CRYPTO_STREAM_ID,
                            offset,
                            false,
                            data,
                            now,
                        )
                        .data
                }
                None => self.crypto.offer_at(
                    key.src_ip,
                    key.src_port,
                    key.dst_ip,
                    key.dst_port,
                    CRYPTO_STREAM_ID,
                    offset,
                    false,
                    data,
                    now,
                ),
            };
            if delivered.is_empty() {
                continue;
            }
            let held = self.handshakes.entry(handshake).or_default();
            if held.bytes.len() + delivered.len() > MAX_HANDSHAKE_BYTES {
                continue;
            }
            held.bytes.extend_from_slice(&delivered);
        }
    }
}

#[cfg(feature = "quic-l7")]
#[cfg(feature = "quic-l7")]
/// Wraps handshake bytes in the TLS record header QUIC leaves out.
///
/// RFC 9001 section 4: a QUIC CRYPTO stream carries handshake messages with no
/// record layer, and the ClientHello parser expects one.
fn wrap_as_tls_record(handshake: &[u8]) -> Option<Vec<u8>> {
    let length = u16::try_from(handshake.len()).ok()?;
    let mut record = Vec::with_capacity(5 + handshake.len());
    record.extend_from_slice(&[0x16, 0x03, 0x03]);
    record.extend_from_slice(&length.to_be_bytes());
    record.extend_from_slice(handshake);
    Some(record)
}

#[cfg(feature = "quic-l7")]
/// The largest handshake worth holding, in bytes.
///
/// A ClientHello runs to a few kilobytes; one that does not fit this is not a
/// handshake anybody needs read, and holding more per connection would let a
/// sender that never finishes one cost memory without limit.
const MAX_HANDSHAKE_BYTES: usize = 16_384;

#[cfg(feature = "quic-l7")]
/// QUIC's CRYPTO frames carry no stream id, so one is invented for them. It is
/// never mixed with a real STREAM id: the two are offered under separate keys.
const CRYPTO_STREAM_ID: u64 = 0;

#[cfg(feature = "quic-l7")]
/// What the handshake buffer is filed under.
///
/// The connection where one is known, so a migration mid-handshake does not
/// split it; the address pair otherwise, which is all an untracked connection
/// has.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum HandshakeKey {
    Connection(QuicConnectionId),
    Tuple(std::net::IpAddr, u16, std::net::IpAddr, u16),
}

#[cfg(feature = "quic-l7")]
impl HandshakeKey {
    fn of(key: &paccel::engine::FlowKey, scope: Option<(QuicConnectionId, QuicDirection)>) -> Self {
        match scope {
            Some((id, _)) => HandshakeKey::Connection(id),
            None => HandshakeKey::Tuple(key.src_ip, key.src_port, key.dst_ip, key.dst_port),
        }
    }
}

#[cfg(feature = "quic-l7")]
/// What has been reassembled of one connection's handshake.
#[derive(Debug, Default)]
struct Handshake {
    bytes: Vec<u8>,
    /// Set once a ClientHello has been read out, so the work is not repeated
    /// for every later packet of the connection.
    read: bool,
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
            quoted: None,
            l7: None,
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

    /// Traffic on the original addresses keeps a connection alive.
    ///
    /// A connection that has been carrying packets all along has not gone
    /// quiet, so ageing it out and losing the migration that follows reports
    /// two flows for one connection.
    #[test]
    fn traffic_on_the_original_tuple_keeps_a_connection_alive() {
        let mut tracker = QuicTracker::new();
        let cid = [1u8, 2, 3, 4, 5, 6, 7, 8];

        let handshake = udp_frame((SERVER, 443), (CLIENT, 50_000), &long_header(&cid));
        observe(&mut tracker, &handshake, 1_000);

        // Steady traffic on the addresses it opened on, well past MAX_AGE.
        let steady = udp_frame((CLIENT, 50_000), (SERVER, 443), &short_header(&cid));
        let mut now = 1_000;
        for _ in 0..8 {
            now += MAX_AGE / 2;
            observe(&mut tracker, &steady, now);
        }

        // Then it moves.
        let moved = udp_frame((MOVED, 53_000), (SERVER, 443), &short_header(&cid));
        let (observation, migrated) = observe(&mut tracker, &moved, now + 1_000);

        assert!(migrated, "a connection in constant use has not gone quiet");
        assert_eq!(observation.key.source, IpAddr::V4(Ipv4Addr::from(CLIENT)));
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
