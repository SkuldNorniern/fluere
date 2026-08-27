//! Where a flow was seen arriving from.

use std::net::IpAddr;

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
    endpoints: [Option<(IpAddr, u16)>; MAX_PATHS],
}

impl Paths {
    /// Note that a packet arrived from an endpoint the flow's key does not
    /// name.
    ///
    /// Endpoints already seen are ignored, so the count is of distinct paths
    /// rather than packets. Once full, later paths are dropped: the count still
    /// says how far the flow moved, and the first few say where to.
    pub fn observe(&mut self, endpoint: (IpAddr, u16)) {
        if self.endpoints().contains(&endpoint) {
            return;
        }

        let seen = self.count as usize;
        if seen < MAX_PATHS {
            self.endpoints[seen] = Some(endpoint);
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

    /// The endpoints, in the order they were first seen.
    pub fn endpoints(&self) -> Vec<(IpAddr, u16)> {
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
        paths.observe(endpoint(77, 60_000));

        assert_eq!(paths.count(), 2, "the original plus the new one");
        assert!(paths.migrated());
        assert_eq!(paths.endpoints(), vec![endpoint(77, 60_000)]);
    }

    #[test]
    fn repeated_arrivals_from_one_endpoint_count_once() {
        let mut paths = Paths::default();
        paths.observe(endpoint(77, 60_000));
        paths.observe(endpoint(77, 60_000));

        assert_eq!(paths.count(), 2);
    }

    /// The same address on a different port is a different path: that is what a
    /// NAT rebinding looks like.
    #[test]
    fn a_new_port_on_the_same_address_is_a_new_path() {
        let mut paths = Paths::default();
        paths.observe(endpoint(10, 50_000));
        paths.observe(endpoint(10, 51_000));

        assert_eq!(paths.count(), 3);
    }

    /// A flow that keeps moving must not grow the record without bound.
    #[test]
    fn the_recorded_endpoints_are_capped_but_the_count_is_not() {
        let mut paths = Paths::default();
        for port in 0..20u16 {
            paths.observe(endpoint(10, port));
        }

        assert_eq!(paths.endpoints().len(), MAX_PATHS, "the list is bounded");
        assert_eq!(paths.count(), 21, "the count still says how far it moved");
        assert!(paths.migrated());
    }
}
