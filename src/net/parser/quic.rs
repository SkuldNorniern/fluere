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

use std::collections::{HashMap, HashSet};

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
}

#[derive(Debug, Default)]
pub struct QuicTracker {
    connections: HashMap<Vec<u8>, Destination>,
    /// Connection ID lengths seen so far. A short header does not carry the
    /// length, so the only way to read one is to try the lengths that
    /// handshakes have actually used.
    lengths: HashSet<usize>,
}

impl QuicTracker {
    pub fn new() -> Self {
        QuicTracker {
            connections: HashMap::new(),
            lengths: HashSet::new(),
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

        if self.connections.len() >= MAX_TRACKED && !self.connections.contains_key(cid) {
            self.evict(now);
        }

        self.lengths.insert(cid.len());
        self.connections.insert(
            cid.to_vec(),
            Destination {
                key,
                reverse,
                last_seen: now,
            },
        );
    }

    /// Read the destination connection ID out of a short header and, if it
    /// belongs to a connection seen elsewhere, point this packet at it.
    fn attribute(&mut self, observation: &mut PacketObservation, payload: &[u8], now: u64) -> bool {
        // Try only the lengths handshakes have used, longest first: a short ID
        // can be a prefix of a longer one, and the longer match is the specific
        // connection.
        let mut lengths: Vec<usize> = self.lengths.iter().copied().collect();
        lengths.sort_unstable_by(|a, b| b.cmp(a));

        for length in lengths {
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
            destination.last_seen = now;

            let (key, reverse) = (destination.key, destination.reverse);
            if key == observation.key {
                // Same addresses as before: nothing migrated.
                return false;
            }

            observation.key = key;
            observation.reverse_key = reverse;
            return true;
        }

        false
    }

    /// Drop everything past its age, and if that frees nothing, the single
    /// oldest entry, so an insert always has room.
    fn evict(&mut self, now: u64) {
        let before = self.connections.len();
        self.connections
            .retain(|_, seen| now.saturating_sub(seen.last_seen) <= MAX_AGE);

        if self.connections.len() < before {
            return;
        }

        if let Some(oldest) = self
            .connections
            .iter()
            .min_by_key(|(_, seen)| seen.last_seen)
            .map(|(cid, _)| cid.clone())
        {
            self.connections.remove(&oldest);
        }
    }

    #[cfg(test)]
    fn tracked(&self) -> usize {
        self.connections.len()
    }
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

        let mut lengths: Vec<usize> = tracker.lengths.iter().copied().collect();
        lengths.sort_unstable();
        assert_eq!(lengths, vec![4, 8]);
    }
}
