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

use paccel::engine::ParsedPacket;
use paccel::layer::application::quic::parse_quic_short_header;

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

/// Where a connection ID's traffic belongs.
#[derive(Debug, Clone, Copy)]
struct Destination {
    /// The key a packet bearing this ID should be counted under.
    key: Key,
    /// That key reversed, so the engine can match either direction.
    reverse: Key,
    last_seen: u64,
    /// Whether more than one connection has claimed this ID.
    ///
    /// A connection ID identifies a connection to the endpoint that issued it.
    /// It is not unique across a capture, so two connections can hold the same
    /// one. When that happens there is no way to tell which of them a later
    /// packet belongs to, and attributing it to either would merge two
    /// conversations. Failing to follow a migration is the smaller mistake, so
    /// an ambiguous ID stops being used.
    ambiguous: bool,
}

#[derive(Debug, Default)]
pub struct QuicTracker {
    connections: HashMap<Vec<u8>, Destination>,
    /// Connection ID lengths seen so far, longest first. A short header does
    /// not carry the length, so the only way to read one is to try the lengths
    /// that handshakes have actually used.
    ///
    /// Kept sorted as it is built rather than collected and sorted per packet:
    /// every candidate short header used to allocate and sort a fresh list.
    lengths: Vec<usize>,
}

impl QuicTracker {
    pub fn new() -> Self {
        QuicTracker {
            connections: HashMap::new(),
            lengths: Vec::new(),
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

        if let Some(quic) = parsed.quic.as_ref() {
            // The sender announces its own ID here; the peer will put it in the
            // destination field of every later packet, which travel the other
            // way. Those belong to this flow seen in reverse.
            self.remember(&quic.scid, observation.reverse_key, observation.key, now);
            return false;
        }

        let Some(payload) = udp_payload(parsed, packet_data) else {
            return false;
        };

        self.attribute(observation, payload, now)
    }

    fn remember(&mut self, cid: &[u8], key: Key, reverse: Key, now: u64) {
        if cid.is_empty() {
            return;
        }

        // The same connection re-announcing its ID is normal. A different one
        // claiming it is not, and there is no way to tell the two apart later,
        // so the ID stops being used rather than pointing at whichever arrived
        // last.
        if let Some(existing) = self.connections.get_mut(cid) {
            if existing.key != key || existing.reverse != reverse {
                trace!("connection ID claimed by a second connection, no longer usable");
                existing.ambiguous = true;
            }
            existing.last_seen = existing.last_seen.max(now);
            return;
        }

        if self.connections.len() >= MAX_TRACKED {
            super::expiry::make_room(&mut self.connections, now, MAX_AGE, |entry| entry.last_seen);
        }

        if let Err(at) = self.lengths.binary_search_by(|len| cid.len().cmp(len)) {
            self.lengths.insert(at, cid.len());
        }

        self.connections.insert(
            cid.to_vec(),
            Destination {
                key,
                reverse,
                last_seen: now,
                ambiguous: false,
            },
        );
    }

    /// Read the destination connection ID out of a short header and, if it
    /// belongs to a connection seen elsewhere, point this packet at it.
    fn attribute(&mut self, observation: &mut PacketObservation, payload: &[u8], now: u64) -> bool {
        // Try only the lengths handshakes have used, longest first: a short ID
        // can be a prefix of a longer one, and the longer match is the specific
        // connection.
        for length in self.lengths.clone() {
            let Some(header) = parse_quic_short_header(payload, length) else {
                continue;
            };
            let Some(destination) = self.connections.get_mut(header.dcid) else {
                continue;
            };

            if now.saturating_sub(destination.last_seen) > MAX_AGE {
                let stale = header.dcid.to_vec();
                self.connections.remove(&stale);
                return false;
            }
            if destination.ambiguous {
                // Two connections hold this ID. Leave the packet on the flow
                // its own addresses name.
                return false;
            }
            // Never backwards, for the same reason the record's end time is
            // not: out-of-order delivery would age the entry out early.
            destination.last_seen = destination.last_seen.max(now);

            let (key, reverse) = (destination.key, destination.reverse);
            if key == observation.key {
                // Same addresses as before: nothing migrated.
                return false;
            }

            // A connection ID says which connection a packet belongs to, not
            // which segment it is on. Two tenants can carry the same ID,
            // through a replayed capture or a mirror that sees both copies of
            // one connection, and reattributing across the boundary would
            // merge their traffic, which is what keying on the VLAN and tunnel
            // exists to prevent. Migration within a segment is what gets
            // followed.
            if !same_segment(&key, &observation.key) {
                return false;
            }

            observation.key = key;
            observation.reverse_key = reverse;
            return true;
        }

        false
    }

    #[cfg(test)]
    fn tracked(&self) -> usize {
        self.connections.len()
    }
}

/// Whether two keys describe traffic on the same VLAN and tunnel.
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

    /// A connection ID is unique to the endpoint that issued it, not to the
    /// capture. Two connections holding the same one must not be merged: a
    /// wrong attribution is worse than a missed migration.
    #[test]
    fn an_id_claimed_by_two_connections_stops_being_used() {
        let mut tracker = QuicTracker::new();
        let first = key();
        let mut second = key();
        second.source = "203.0.113.9".parse().expect("valid address");

        tracker.remember(&[1, 2, 3, 4], first, first.reversed(), 1_000);
        tracker.remember(&[1, 2, 3, 4], second, second.reversed(), 2_000);

        let destination = tracker
            .connections
            .get(&vec![1, 2, 3, 4])
            .expect("still tracked");
        assert!(destination.ambiguous, "neither connection owns it now");
    }

    /// The same connection re-announcing its ID during a handshake is ordinary
    /// and must not poison it.
    #[test]
    fn a_repeated_announcement_from_one_connection_is_fine() {
        let mut tracker = QuicTracker::new();
        let flow = key();

        tracker.remember(&[1, 2, 3, 4], flow, flow.reversed(), 1_000);
        tracker.remember(&[1, 2, 3, 4], flow, flow.reversed(), 2_000);

        let destination = tracker
            .connections
            .get(&vec![1, 2, 3, 4])
            .expect("still tracked");
        assert!(!destination.ambiguous);
        assert_eq!(destination.last_seen, 2_000);
    }

    /// Out-of-order delivery must not age an entry out early.
    #[test]
    fn a_late_delivered_packet_does_not_age_an_entry() {
        let mut tracker = QuicTracker::new();
        let flow = key();

        tracker.remember(&[1, 2, 3, 4], flow, flow.reversed(), 9_000);
        tracker.remember(&[1, 2, 3, 4], flow, flow.reversed(), 3_000);

        let destination = tracker
            .connections
            .get(&vec![1, 2, 3, 4])
            .expect("still tracked");
        assert_eq!(destination.last_seen, 9_000, "the latest packet seen");
    }

    /// Lengths are tried longest first, so a short ID that is a prefix of a
    /// longer one does not shadow the more specific match.
    #[test]
    fn connection_id_lengths_are_kept_longest_first() {
        let mut tracker = QuicTracker::new();
        let flow = key();

        tracker.remember(&[1, 2, 3, 4], flow, flow.reversed(), 1_000);
        tracker.remember(&[9; 8], flow, flow.reversed(), 1_000);
        tracker.remember(&[7; 6], flow, flow.reversed(), 1_000);

        assert_eq!(tracker.lengths, vec![8, 6, 4]);
    }

    #[test]
    fn an_empty_connection_id_is_not_tracked() {
        let mut tracker = QuicTracker::new();
        tracker.remember(&[], key(), key().reversed(), 1_000);

        assert_eq!(tracker.tracked(), 0, "an empty ID identifies nothing");
    }

    #[test]
    fn tracking_stays_bounded_under_a_flood_of_connections() {
        let mut tracker = QuicTracker::new();

        for connection in 0..(MAX_TRACKED as u32 * 2) {
            tracker.remember(
                &connection.to_be_bytes(),
                key(),
                key().reversed(),
                u64::from(connection),
            );
        }

        assert!(
            tracker.tracked() <= MAX_TRACKED,
            "tracked {} connections, cap is {}",
            tracker.tracked(),
            MAX_TRACKED
        );
    }

    /// Short headers carry no length, so the only readable IDs are the lengths
    /// handshakes have actually used.
    #[test]
    fn only_observed_id_lengths_are_tried() {
        let mut tracker = QuicTracker::new();
        assert!(tracker.lengths.is_empty());

        tracker.remember(&[1, 2, 3, 4], key(), key().reversed(), 1_000);
        tracker.remember(&[9; 8], key(), key().reversed(), 1_000);

        assert_eq!(tracker.lengths, vec![8, 4], "longest first");
    }
}
