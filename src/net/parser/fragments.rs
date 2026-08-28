//! Keeping a fragmented datagram's fragments in one flow.
//!
//! Only the first fragment of an IP datagram carries the transport header, so
//! every later fragment arrives with no ports. Left alone it opens a second,
//! portless flow for traffic that belongs to the first one. This remembers
//! where a datagram was going when its first fragment went past, and applies
//! those endpoints to the rest of it.
//!
//! Payloads are never buffered. Flow accounting needs each fragment counted as
//! it arrives, with its own size and timestamp; only the endpoints have to be
//! carried forward, which costs a few bytes per datagram in flight rather than
//! the datagram itself.

use std::collections::HashMap;
use std::net::IpAddr;

use fluereflow::{Encapsulation, Endpoints, VlanTags};

use super::observation::PacketObservation;

/// Most datagrams to track at once. Reached only when a lot of fragmented
/// traffic is in flight; the oldest entries are dropped first.
const MAX_TRACKED: usize = 8192;

/// How long a datagram's endpoints stay useful, in nanoseconds. Past this the
/// rest of it is never going to arrive.
const MAX_AGE: u64 = 30_000_000_000;

/// Identifies one IP datagram, across all of its fragments.
///
/// IPv4 identification is 16 bits and IPv6's is 32; the wider one holds both.
///
/// The VLAN and tunnel are part of it for the same reason they are part of a
/// flow key: separate segments reuse the same private addresses, and nothing
/// stops two tenants picking the same identification. Without them one tenant's
/// later fragments could inherit the other's ports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct DatagramId {
    source: IpAddr,
    destination: IpAddr,
    identification: u32,
    protocol: u8,
    vlan: VlanTags,
    encapsulation: Option<Encapsulation>,
}

/// The endpoints a datagram's first fragment reported, and when they were last
/// useful.
///
/// The whole `Endpoints`, not a port pair: a fragmented ICMP echo or ESP
/// datagram has no ports, and remembering that as `(0, 0)` gave the later
/// fragments a different endpoint kind from the first, splitting one datagram
/// across two flows.
#[derive(Debug, Clone, Copy)]
struct Remembered {
    endpoints: Endpoints,
    last_seen: u64,
}

#[derive(Debug, Default)]
pub struct FragmentTracker {
    datagrams: HashMap<DatagramId, Remembered>,
}

impl FragmentTracker {
    pub fn new() -> Self {
        FragmentTracker {
            datagrams: HashMap::new(),
        }
    }

    /// Give a fragment the endpoints of the datagram it belongs to.
    ///
    /// The first fragment supplies them; a later one is rewritten to match, so
    /// both key onto the same flow. A packet that is not a fragment, and a
    /// fragment whose first part was never seen, are left as they are.
    pub fn resolve(&mut self, observation: &mut PacketObservation, fragment: Option<&Fragment>) {
        let Some(fragment) = fragment else {
            return;
        };

        let id = DatagramId {
            source: observation.key.source,
            destination: observation.key.destination,
            identification: fragment.identification,
            protocol: fragment.protocol,
            vlan: observation.key.vlan,
            encapsulation: observation.key.encapsulation,
        };
        let now = observation.time().nanos();

        if fragment.offset == 0 {
            // The first fragment carries the transport header. Remember where
            // it was going for the fragments that follow.
            self.remember(id, observation.key.endpoints, now);
            return;
        }

        if let Some(endpoints) = self.recall(&id, now) {
            apply(observation, endpoints);
        }
    }

    fn remember(&mut self, id: DatagramId, endpoints: Endpoints, now: u64) {
        if self.datagrams.len() >= MAX_TRACKED && !self.datagrams.contains_key(&id) {
            super::expiry::make_room(&mut self.datagrams, now, MAX_AGE, |entry| entry.last_seen);
        }

        self.datagrams.insert(
            id,
            Remembered {
                endpoints,
                last_seen: now,
            },
        );
    }

    fn recall(&mut self, id: &DatagramId, now: u64) -> Option<Endpoints> {
        let remembered = self.datagrams.get_mut(id)?;
        if now.saturating_sub(remembered.last_seen) > MAX_AGE {
            self.datagrams.remove(id);
            return None;
        }

        // Never backwards: an out-of-order fragment arriving with an earlier
        // timestamp would otherwise age the entry out early.
        remembered.last_seen = remembered.last_seen.max(now);
        Some(remembered.endpoints)
    }

    #[cfg(test)]
    fn tracked(&self) -> usize {
        self.datagrams.len()
    }
}

/// A packet that is part of a fragmented datagram, in either address family.
#[derive(Debug, Clone, Copy)]
pub struct Fragment {
    pub identification: u32,
    pub offset: u16,
    pub protocol: u8,
}

impl Fragment {
    /// The fragment a packet belongs to, or `None` if it is not fragmented.
    ///
    /// IPv4 carries fragmentation in its own header; IPv6 carries it in an
    /// extension header, which paccel reports separately.
    pub fn of(parsed: &paccel::engine::ParsedPacket) -> Option<Self> {
        if let Some(fragment) = parsed.ipv6_fragment.as_ref() {
            // The next header after the fragment header is the transport, and
            // `resolved_next_header` has already walked to it.
            let protocol = parsed
                .ipv6
                .as_ref()
                .map_or(0, |ipv6| ipv6.resolved_next_header);

            return Some(Fragment {
                identification: fragment.identification,
                offset: fragment.offset,
                protocol,
            });
        }

        Self::of_ipv4(parsed.ipv4.as_ref()?)
    }

    /// A datagram is fragmented if More Fragments is set or the offset is
    /// non-zero; a lone packet has neither.
    fn of_ipv4(header: &paccel::layer::network::ipv4::Ipv4Header) -> Option<Self> {
        const MORE_FRAGMENTS: u8 = 0x1;

        let more = header.flags & MORE_FRAGMENTS != 0;
        if !more && header.fragment_offset == 0 {
            return None;
        }

        Some(Fragment {
            identification: u32::from(header.identification),
            offset: header.fragment_offset,
            protocol: header.protocol,
        })
    }
}

/// Rewrite every endpoint on the observation at once, so the key, its reverse
/// and the record cannot end up disagreeing.
fn apply(observation: &mut PacketObservation, endpoints: Endpoints) {
    observation.key.endpoints = endpoints;
    observation.reverse_key.endpoints = endpoints.reversed();
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;

    const A: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
    const B: IpAddr = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2));

    fn id(identification: u32) -> DatagramId {
        DatagramId {
            vlan: VlanTags::default(),
            encapsulation: None,
            source: A,
            destination: B,
            identification,
            protocol: 17,
        }
    }

    fn ports(source: u16, destination: u16) -> Endpoints {
        Endpoints::Ports {
            source,
            destination,
        }
    }

    #[test]
    fn a_later_fragment_recalls_the_first_fragments_endpoints() {
        let mut tracker = FragmentTracker::new();
        tracker.remember(id(42), ports(50_003, 9_999), 1_000);

        assert_eq!(tracker.recall(&id(42), 2_000), Some(ports(50_003, 9_999)));
    }

    #[test]
    fn an_unseen_datagram_is_left_alone() {
        let mut tracker = FragmentTracker::new();
        tracker.remember(id(42), ports(50_003, 9_999), 1_000);

        assert_eq!(tracker.recall(&id(43), 2_000), None, "different datagram");
    }

    #[test]
    fn endpoints_stop_being_recalled_once_they_are_stale() {
        let mut tracker = FragmentTracker::new();
        tracker.remember(id(42), ports(50_003, 9_999), 1_000);

        assert_eq!(tracker.recall(&id(42), 1_000 + MAX_AGE + 1), None);
        assert_eq!(tracker.tracked(), 0, "the stale entry is dropped");
    }

    #[test]
    fn tracking_stays_bounded_under_a_flood_of_datagrams() {
        let mut tracker = FragmentTracker::new();

        for i in 0..(MAX_TRACKED as u32 * 2) {
            tracker.remember(id(i), ports(1, 2), u64::from(i));
        }

        assert!(
            tracker.tracked() <= MAX_TRACKED,
            "tracked {} entries, cap is {}",
            tracker.tracked(),
            MAX_TRACKED
        );
    }

    /// A fragmented ICMP echo or ESP datagram has no ports. Remembering that
    /// as `(0, 0)` gave later fragments a different endpoint kind from the
    /// first, so one datagram became two flows.
    #[test]
    fn a_datagram_without_ports_is_remembered_as_having_none() {
        let mut tracker = FragmentTracker::new();
        tracker.remember(id(42), Endpoints::None, 1_000);

        assert_eq!(tracker.recall(&id(42), 2_000), Some(Endpoints::None));
    }

    #[test]
    fn an_ipv4_fragment_is_recognised_only_when_the_header_says_so() {
        use paccel::layer::network::ipv4::Ipv4Header;

        let header = |flags: u8, offset: u16| Ipv4Header {
            version: 4,
            ihl: 5,
            dscp: 0,
            ecn: 0,
            total_length: 40,
            identification: 7,
            flags,
            fragment_offset: offset,
            ttl: 64,
            protocol: 17,
            checksum: 0,
            source: Ipv4Addr::new(192, 0, 2, 1),
            destination: Ipv4Addr::new(198, 51, 100, 2),
            options: None,
        };

        assert!(Fragment::of_ipv4(&header(0, 0)).is_none(), "not fragmented");
        assert!(
            Fragment::of_ipv4(&header(0x2, 0)).is_none(),
            "don't fragment"
        );

        let first = Fragment::of_ipv4(&header(0x1, 0)).expect("first fragment");
        assert_eq!(first.offset, 0);

        let later = Fragment::of_ipv4(&header(0, 185)).expect("later fragment");
        assert_eq!(later.offset, 185);
    }
}
