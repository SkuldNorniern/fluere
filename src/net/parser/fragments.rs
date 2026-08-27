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

use super::observation::PacketObservation;

/// Most datagrams to track at once. Reached only when a lot of fragmented
/// traffic is in flight; the oldest entries are dropped first.
const MAX_TRACKED: usize = 8192;

/// How long a datagram's endpoints stay useful, in nanoseconds. Past this the
/// rest of it is never going to arrive.
const MAX_AGE: u64 = 30_000_000_000;

/// Identifies one IP datagram, across all of its fragments.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct DatagramId {
    source: IpAddr,
    destination: IpAddr,
    identification: u16,
    protocol: u8,
}

#[derive(Debug, Clone, Copy)]
struct Endpoints {
    src_port: u16,
    dst_port: u16,
    last_seen: u64,
}

#[derive(Debug, Default)]
pub struct FragmentTracker {
    datagrams: HashMap<DatagramId, Endpoints>,
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
    pub fn resolve(&mut self, observation: &mut PacketObservation, ipv4: Option<&Ipv4Fragment>) {
        let Some(fragment) = ipv4 else {
            return;
        };

        let id = DatagramId {
            source: observation.key.src_ip,
            destination: observation.key.dst_ip,
            identification: fragment.identification,
            protocol: fragment.protocol,
        };
        let now = observation.time().nanos();

        if fragment.offset == 0 {
            // The first fragment carries the transport header. Remember where
            // it was going for the fragments that follow.
            self.remember(id, observation.key.src_port, observation.key.dst_port, now);
            return;
        }

        if let Some(endpoints) = self.recall(&id, now) {
            apply(observation, endpoints.0, endpoints.1);
        }
    }

    fn remember(&mut self, id: DatagramId, src_port: u16, dst_port: u16, now: u64) {
        if self.datagrams.len() >= MAX_TRACKED && !self.datagrams.contains_key(&id) {
            self.evict_oldest(now);
        }

        self.datagrams.insert(
            id,
            Endpoints {
                src_port,
                dst_port,
                last_seen: now,
            },
        );
    }

    fn recall(&mut self, id: &DatagramId, now: u64) -> Option<(u16, u16)> {
        let endpoints = self.datagrams.get_mut(id)?;
        if now.saturating_sub(endpoints.last_seen) > MAX_AGE {
            self.datagrams.remove(id);
            return None;
        }

        endpoints.last_seen = now;
        Some((endpoints.src_port, endpoints.dst_port))
    }

    /// Drop everything past its age, and if that freed nothing, the single
    /// oldest entry, so an insert always has room.
    fn evict_oldest(&mut self, now: u64) {
        let before = self.datagrams.len();
        self.datagrams
            .retain(|_, seen| now.saturating_sub(seen.last_seen) <= MAX_AGE);

        if self.datagrams.len() < before {
            return;
        }

        if let Some(oldest) = self
            .datagrams
            .iter()
            .min_by_key(|(_, seen)| seen.last_seen)
            .map(|(id, _)| *id)
        {
            self.datagrams.remove(&oldest);
        }
    }

    #[cfg(test)]
    fn tracked(&self) -> usize {
        self.datagrams.len()
    }
}

/// The fragmentation fields of an IPv4 header, for a packet that is one.
#[derive(Debug, Clone, Copy)]
pub struct Ipv4Fragment {
    pub identification: u16,
    pub offset: u16,
    pub protocol: u8,
}

impl Ipv4Fragment {
    /// `None` when the packet is not part of a fragmented datagram.
    ///
    /// A datagram is fragmented if More Fragments is set or the offset is
    /// non-zero; a lone packet has neither.
    pub fn of(header: &paccel::layer::network::ipv4::Ipv4Header) -> Option<Self> {
        const MORE_FRAGMENTS: u8 = 0x1;

        let more = header.flags & MORE_FRAGMENTS != 0;
        if !more && header.fragment_offset == 0 {
            return None;
        }

        Some(Ipv4Fragment {
            identification: header.identification,
            offset: header.fragment_offset,
            protocol: header.protocol,
        })
    }
}

/// Rewrite every endpoint on the observation at once, so the key, its reverse
/// and the record cannot end up disagreeing.
fn apply(observation: &mut PacketObservation, src_port: u16, dst_port: u16) {
    observation.key.src_port = src_port;
    observation.key.dst_port = dst_port;
    observation.reverse_key.src_port = dst_port;
    observation.reverse_key.dst_port = src_port;
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;

    const A: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
    const B: IpAddr = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2));

    fn id(identification: u16) -> DatagramId {
        DatagramId {
            source: A,
            destination: B,
            identification,
            protocol: 17,
        }
    }

    #[test]
    fn a_later_fragment_recalls_the_first_fragments_endpoints() {
        let mut tracker = FragmentTracker::new();
        tracker.remember(id(42), 50_003, 9_999, 1_000);

        assert_eq!(tracker.recall(&id(42), 2_000), Some((50_003, 9_999)));
    }

    #[test]
    fn an_unseen_datagram_is_left_alone() {
        let mut tracker = FragmentTracker::new();
        tracker.remember(id(42), 50_003, 9_999, 1_000);

        assert_eq!(tracker.recall(&id(43), 2_000), None, "different datagram");
    }

    #[test]
    fn endpoints_stop_being_recalled_once_they_are_stale() {
        let mut tracker = FragmentTracker::new();
        tracker.remember(id(42), 50_003, 9_999, 1_000);

        assert_eq!(tracker.recall(&id(42), 1_000 + MAX_AGE + 1), None);
        assert_eq!(tracker.tracked(), 0, "the stale entry is dropped");
    }

    #[test]
    fn tracking_stays_bounded_under_a_flood_of_datagrams() {
        let mut tracker = FragmentTracker::new();

        for i in 0..(MAX_TRACKED as u32 * 2) {
            tracker.remember(id(i as u16), 1, 2, u64::from(i));
        }

        assert!(
            tracker.tracked() <= MAX_TRACKED,
            "tracked {} entries, cap is {}",
            tracker.tracked(),
            MAX_TRACKED
        );
    }

    #[test]
    fn a_fragment_is_recognised_only_when_the_header_says_so() {
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

        assert!(Ipv4Fragment::of(&header(0, 0)).is_none(), "not fragmented");
        assert!(
            Ipv4Fragment::of(&header(0x2, 0)).is_none(),
            "don't fragment"
        );

        let first = Ipv4Fragment::of(&header(0x1, 0)).expect("first fragment");
        assert_eq!(first.offset, 0);

        let later = Ipv4Fragment::of(&header(0, 185)).expect("later fragment");
        assert_eq!(later.offset, 185);
    }
}
