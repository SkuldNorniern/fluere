//! Keeping the cross-packet trackers bounded without a scan per packet.
//!
//! Both trackers cap how much they remember. The old way to make room was to
//! drop stale entries and, if that freed nothing, walk the whole map to find
//! the single oldest one. That is a full scan for every new identity once the
//! map is full, which ordinary traffic never reaches but a flood of made-up
//! connection IDs or fragment identifications does.
//!
//! Dropping a batch instead means the scan happens once per batch, so the cost
//! per insert stays flat however hostile the traffic is.

use std::collections::HashMap;
use std::hash::Hash;

/// How much of the map to drop when age alone frees nothing.
const EVICT_FRACTION: usize = 4;

/// Make room in `map`, first by age and then by dropping the oldest batch.
///
/// `last_seen` reads the timestamp out of an entry, in nanoseconds.
pub(super) fn make_room<K, V>(
    map: &mut HashMap<K, V>,
    now: u64,
    max_age: u64,
    last_seen: impl Fn(&V) -> u64,
) where
    K: Eq + Hash + Clone,
{
    let before = map.len();
    map.retain(|_, entry| now.saturating_sub(last_seen(entry)) <= max_age);

    if map.len() < before {
        return;
    }

    if map.is_empty() {
        return;
    }

    // Nothing was stale, so the map is full of live entries and one has to go
    // regardless. Take a batch: doing this per insert is what made a flood
    // expensive.
    //
    // The batch is picked by key rather than by a timestamp cutoff. A capture's
    // clock is routinely coarser than its packet rate, so entries share a
    // timestamp often; dropping everything at or below a cutoff then took far
    // more than the batch, and emptied the map outright when every entry shared
    // one. That loses the fragment and connection-ID state the trackers exist
    // to hold.
    let drop_count = (map.len() / EVICT_FRACTION).max(1);
    let mut by_age: Vec<(u64, K)> = map
        .iter()
        .map(|(key, entry)| (last_seen(entry), key.clone()))
        .collect();
    by_age.sort_unstable_by_key(|(age, _)| *age);

    for (_, key) in by_age.into_iter().take(drop_count) {
        map.remove(&key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map_of(entries: &[(u32, u64)]) -> HashMap<u32, u64> {
        entries.iter().copied().collect()
    }

    #[test]
    fn stale_entries_go_first() {
        let mut map = map_of(&[(1, 0), (2, 500), (3, 900)]);
        make_room(&mut map, 1_000, 600, |seen| *seen);

        assert_eq!(map.len(), 2, "only the entry past its age is dropped");
        assert!(!map.contains_key(&1));
    }

    /// With nothing stale, a batch goes rather than a single entry, so the
    /// scan happens once per batch instead of once per insert.
    #[test]
    fn a_batch_goes_when_nothing_is_stale() {
        let mut map: HashMap<u32, u64> = (0..100u32).map(|i| (i, u64::from(i))).collect();
        make_room(&mut map, 100, 10_000, |seen| *seen);

        assert_eq!(map.len(), 75);
        assert!(!map.contains_key(&0), "the oldest went");
        assert!(map.contains_key(&99), "the newest stayed");
    }

    /// Every entry sharing one timestamp leaves the batch cutoff with nothing
    /// to separate, and an insert still needs room.
    /// Every entry sharing one timestamp leaves a cutoff with nothing to
    /// separate. Choosing the batch by key instead keeps that from emptying the
    /// map, which is what used to happen: a capture whose clock is coarser than
    /// its packet rate would lose the whole tracker rather than a quarter of it.
    #[test]
    fn one_batch_goes_when_every_entry_is_the_same_age() {
        let mut map: HashMap<u32, u64> = (0..100u32).map(|i| (i, 5)).collect();
        make_room(&mut map, 5, 10_000, |seen| *seen);

        assert_eq!(map.len(), 75, "a quarter went, not the whole map");
    }

    /// Coarse timestamps put many entries on the same tick without putting all
    /// of them there.
    #[test]
    fn a_coarse_clock_still_drops_only_one_batch() {
        let mut map: HashMap<u32, u64> = (0..8192u32).map(|i| (i, u64::from(i / 1000))).collect();
        make_room(&mut map, 8, 10_000, |seen| *seen);

        assert_eq!(map.len(), 8192 - 2048);
    }

    /// A single entry still has to give way, or an insert has nowhere to go.
    #[test]
    fn the_only_entry_goes_when_it_has_to() {
        let mut map: HashMap<u32, u64> = map_of(&[(1, 5)]);
        make_room(&mut map, 5, 10_000, |seen| *seen);

        assert!(map.is_empty());
    }

    #[test]
    fn an_empty_map_is_left_alone() {
        let mut map: HashMap<u32, u64> = HashMap::new();
        make_room(&mut map, 1_000, 10, |seen| *seen);

        assert!(map.is_empty());
    }
}
