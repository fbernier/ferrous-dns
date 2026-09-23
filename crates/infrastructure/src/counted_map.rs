//! A `DashMap` whose size is an O(1) read.

use dashmap::mapref::multiple::RefMulti;
use dashmap::mapref::one::Ref;
use dashmap::DashMap;
use std::borrow::Borrow;
use std::hash::{BuildHasher, Hash, RandomState};
use std::sync::atomic::{AtomicUsize, Ordering};

/// Wraps a `DashMap` with an entry count, for maps that bound their size on
/// every insert: `DashMap::len()` read-locks every shard.
///
/// The count is incremented before an insert lands and decremented only after
/// a removal succeeds, so a concurrent reader may see it transiently high but
/// never below the map's true size, and it is exact whenever the map is quiet.
pub struct CountedDashMap<K, V, S = RandomState> {
    map: DashMap<K, V, S>,
    len: AtomicUsize,
}

impl<K: Eq + Hash, V> CountedDashMap<K, V, RandomState> {
    pub fn new() -> Self {
        Self::from_map(DashMap::new())
    }
}

impl<K: Eq + Hash, V> Default for CountedDashMap<K, V, RandomState> {
    fn default() -> Self {
        Self::new()
    }
}

impl<K: Eq + Hash, V, S: BuildHasher + Clone> CountedDashMap<K, V, S> {
    pub fn with_capacity_and_hasher(capacity: usize, hasher: S) -> Self {
        Self::from_map(DashMap::with_capacity_and_hasher(capacity, hasher))
    }

    fn from_map(map: DashMap<K, V, S>) -> Self {
        Self {
            len: AtomicUsize::new(map.len()),
            map,
        }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.len.load(Ordering::Relaxed)
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[inline]
    pub fn get<Q>(&self, key: &Q) -> Option<Ref<'_, K, V>>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.map.get(key)
    }

    pub fn insert(&self, key: K, value: V) -> Option<V> {
        // Counted before the entry is visible, so no removal can undercount.
        self.len.fetch_add(1, Ordering::Relaxed);
        let previous = self.map.insert(key, value);
        if previous.is_some() {
            self.len.fetch_sub(1, Ordering::Relaxed);
        }
        previous
    }

    pub fn remove<Q>(&self, key: &Q) -> Option<(K, V)>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let removed = self.map.remove(key);
        if removed.is_some() {
            self.len.fetch_sub(1, Ordering::Relaxed);
        }
        removed
    }

    pub fn remove_if<Q>(&self, key: &Q, f: impl FnOnce(&K, &V) -> bool) -> Option<(K, V)>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let removed = self.map.remove_if(key, f);
        if removed.is_some() {
            self.len.fetch_sub(1, Ordering::Relaxed);
        }
        removed
    }

    /// Keeps the entries `f` accepts; returns how many were removed.
    pub fn retain(&self, mut f: impl FnMut(&K, &mut V) -> bool) -> usize {
        let mut removed = 0;
        self.map.retain(|k, v| {
            let keep = f(k, v);
            removed += usize::from(!keep);
            keep
        });
        self.len.fetch_sub(removed, Ordering::Relaxed);
        removed
    }

    pub fn clear(&self) {
        // Not `DashMap::clear`: its removals would go uncounted.
        self.retain(|_, _| false);
    }

    pub fn iter(&self) -> impl Iterator<Item = RefMulti<'_, K, V>> {
        self.map.iter()
    }

    #[cfg(test)]
    pub fn iter_mut(&self) -> dashmap::iter::IterMut<'_, K, V, S> {
        self.map.iter_mut()
    }
}

impl<K: Eq + Hash, V> FromIterator<(K, V)> for CountedDashMap<K, V, RandomState> {
    fn from_iter<I: IntoIterator<Item = (K, V)>>(iter: I) -> Self {
        Self::from_map(iter.into_iter().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn count_matches_the_map_after_concurrent_mixed_mutation() {
        let map: Arc<CountedDashMap<u32, u32>> = Arc::new(CountedDashMap::new());
        let workers: Vec<_> = (0..8u32)
            .map(|t| {
                let map = Arc::clone(&map);
                std::thread::spawn(move || {
                    for i in 0..20_000u32 {
                        // Overlapping key ranges force replacements and
                        // removals that race with other threads' inserts.
                        let key = (i * 7 + t * 13) % 512;
                        match i % 5 {
                            0 | 1 => {
                                map.insert(key, i);
                            }
                            2 => {
                                map.remove(&key);
                            }
                            3 => {
                                map.remove_if(&key, |_, v| v % 2 == 0);
                            }
                            _ if i % 1000 == 4 => {
                                map.retain(|k, _| k % 3 != 0);
                            }
                            _ => {}
                        }
                    }
                })
            })
            .collect();
        for worker in workers {
            worker.join().unwrap();
        }

        assert_eq!(map.len(), map.map.len());
        map.clear();
        assert_eq!((map.len(), map.map.len()), (0, 0));
    }
}
