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

    // Nothing was stale, so the map is full of live entries and one has to go
    // regardless. Take a batch: doing this per insert is what made a flood
    // expensive.
    let drop_count = (map.len() / EVICT_FRACTION).max(1);
    let mut ages: Vec<u64> = map.values().map(&last_seen).collect();
    ages.sort_unstable();
    let Some(&cutoff) = ages.get(drop_count.saturating_sub(1)) else {
        return;
    };

    map.retain(|_, entry| last_seen(entry) > cutoff);

    // A cutoff shared by more entries than the batch can leave the map
    // untouched. Drop one outright so an insert always has room.
    if map.len() >= before
        && let Some(oldest) = map
            .iter()
            .min_by_key(|(_, entry)| last_seen(entry))
            .map(|(key, _)| key.clone())
    {
        map.remove(&oldest);
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
    #[test]
    fn room_is_made_even_when_every_entry_is_the_same_age() {
        let mut map: HashMap<u32, u64> = (0..10u32).map(|i| (i, 5)).collect();
        make_room(&mut map, 5, 10_000, |seen| *seen);

        assert!(map.len() < 10, "something was dropped");
    }

    #[test]
    fn an_empty_map_is_left_alone() {
        let mut map: HashMap<u32, u64> = HashMap::new();
        make_room(&mut map, 1_000, 10, |seen| *seen);

        assert!(map.is_empty());
    }
}
