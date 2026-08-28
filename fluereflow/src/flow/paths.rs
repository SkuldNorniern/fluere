//! Where a flow was seen arriving from.

use std::net::IpAddr;

use super::Direction;

/// One endpoint a flow was seen arriving from, and which side of the flow it
/// was.
///
/// The direction is what says whether the client moved or the server did. An
/// endpoint on its own leaves that to be guessed from the addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathChange {
    pub direction: Direction,
    pub endpoint: (IpAddr, u16),
}

impl std::fmt::Display for PathChange {
    /// `fwd:203.0.113.77:60000`. One spelling for the CSV and the plugin view,
    /// so the two cannot drift.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (address, port) = self.endpoint;
        write!(f, "{}:{}:{}", self.direction.as_str(), address, port)
    }
}

/// Most endpoints to remember for one flow.
///
/// A connection that changes address more than a few times is rare, and the
/// record stays a fixed size so it can still be copied cheaply.
const MAX_PATHS: usize = 4;

/// Endpoints a flow arrived from that its own key does not name.
///
/// A flow's key names both endpoints it opened between, so ordinary traffic in
/// either direction adds nothing here. What does is a packet arriving from
/// somewhere else and still belonging to the flow: a QUIC connection migrating
/// when its client changes network, or a NAT rebinding moving the port beneath
/// it. Without this the record shows only where the flow opened, and the move
/// is invisible.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Paths {
    count: u8,
    endpoints: [Option<PathChange>; MAX_PATHS],
    /// The endpoint seen most recently, kept even once the list is full.
    ///
    /// Without it a flow that moves past the list and then stays put looks
    /// like a new move on every packet, because nothing it could be compared
    /// against was retained.
    latest: Option<PathChange>,
}

impl Paths {
    /// Note that a packet arrived from an endpoint the flow's key does not
    /// name.
    ///
    /// Endpoints already seen are ignored, so the count is of distinct paths
    /// rather than packets. Once full, later paths are dropped from the list:
    /// the count still says how far the flow moved, and the first few say
    /// where to.
    pub fn observe(&mut self, direction: Direction, endpoint: (IpAddr, u16)) {
        let change = PathChange {
            direction,
            endpoint,
        };
        if self.latest == Some(change) || self.endpoints().contains(&change) {
            return;
        }
        self.latest = Some(change);

        let seen = self.count as usize;
        if seen < MAX_PATHS {
            self.endpoints[seen] = Some(change);
        }
        self.count = self.count.saturating_add(1);
    }

    /// How many endpoints the flow was seen on in total, counting the one its
    /// key names. One means it never moved.
    pub fn count(&self) -> usize {
        self.count as usize + 1
    }

    /// Whether the flow ever arrived from somewhere its key does not name.
    pub fn migrated(&self) -> bool {
        self.count > 0
    }

    /// The path changes, in the order they were first seen.
    pub fn endpoints(&self) -> Vec<PathChange> {
        self.endpoints.iter().flatten().copied().collect()
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    fn endpoint(last: u8, port: u16) -> (IpAddr, u16) {
        (IpAddr::V4(Ipv4Addr::new(192, 0, 2, last)), port)
    }

    fn moved(last: u8, port: u16) -> PathChange {
        PathChange {
            direction: Direction::Forward,
            endpoint: endpoint(last, port),
        }
    }

    #[test]
    fn a_flow_that_never_moved_records_nothing() {
        let paths = Paths::default();

        assert_eq!(paths.count(), 1, "the endpoint its key names");
        assert!(!paths.migrated());
        assert!(paths.endpoints().is_empty());
    }

    #[test]
    fn moving_records_where_it_moved_to() {
        let mut paths = Paths::default();
        paths.observe(Direction::Forward, endpoint(77, 60_000));

        assert_eq!(paths.count(), 2, "the original plus the new one");
        assert!(paths.migrated());
        assert_eq!(paths.endpoints(), vec![moved(77, 60_000)]);
    }

    #[test]
    fn repeated_arrivals_from_one_endpoint_count_once() {
        let mut paths = Paths::default();
        paths.observe(Direction::Forward, endpoint(77, 60_000));
        paths.observe(Direction::Forward, endpoint(77, 60_000));

        assert_eq!(paths.count(), 2);
    }

    /// The same address on a different port is a different path: that is what a
    /// NAT rebinding looks like.
    #[test]
    fn a_new_port_on_the_same_address_is_a_new_path() {
        let mut paths = Paths::default();
        paths.observe(Direction::Forward, endpoint(10, 50_000));
        paths.observe(Direction::Forward, endpoint(10, 51_000));

        assert_eq!(paths.count(), 3);
    }

    /// A flow that moves past the recorded list and then stays put is on one
    /// endpoint, not a new one per packet. Deduping only against the stored
    /// list counted every later packet as another move.
    #[test]
    fn settling_on_an_endpoint_past_the_list_still_counts_once() {
        let mut paths = Paths::default();
        for port in 0..MAX_PATHS as u16 {
            paths.observe(Direction::Forward, endpoint(10, port));
        }

        let settled = endpoint(77, 60_000);
        for _ in 0..100 {
            paths.observe(Direction::Forward, settled);
        }

        assert_eq!(paths.endpoints().len(), MAX_PATHS, "the list is still full");
        assert_eq!(
            paths.count(),
            MAX_PATHS + 2,
            "the four recorded, the one it settled on, and its own key"
        );
    }

    /// A flow that keeps moving must not grow the record without bound.
    #[test]
    fn the_recorded_endpoints_are_capped_but_the_count_is_not() {
        let mut paths = Paths::default();
        for port in 0..20u16 {
            paths.observe(Direction::Forward, endpoint(10, port));
        }

        assert_eq!(paths.endpoints().len(), MAX_PATHS, "the list is bounded");
        assert_eq!(paths.count(), 21, "the count still says how far it moved");
        assert!(paths.migrated());
    }
}
