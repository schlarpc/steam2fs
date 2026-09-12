//! Byte-bounded LRU cache of immutable buffers, and the lock that keeps
//! concurrent misses from doing the same work twice.

use std::collections::HashMap;
use std::hash::Hash;
use std::sync::Arc;

use parking_lot::Mutex;

pub struct ByteLru<K> {
    inner: Mutex<Inner<K>>,
}

struct Inner<K> {
    lru: lru::LruCache<K, Arc<Vec<u8>>>,
    bytes: usize,
    capacity: usize,
}

impl<K: Hash + Eq + Clone> ByteLru<K> {
    pub fn new(capacity_bytes: usize) -> Self {
        Self {
            inner: Mutex::new(Inner {
                lru: lru::LruCache::unbounded(),
                bytes: 0,
                capacity: capacity_bytes,
            }),
        }
    }

    pub fn get(&self, key: &K) -> Option<Arc<Vec<u8>>> {
        self.inner.lock().lru.get(key).cloned()
    }

    pub fn insert(&self, key: K, value: Arc<Vec<u8>>) {
        let mut g = self.inner.lock();
        if value.len() > g.capacity {
            return;
        }
        if let Some(old) = g.lru.push(key, value.clone()) {
            g.bytes -= old.1.len();
        }
        g.bytes += value.len();
        while g.bytes > g.capacity {
            match g.lru.pop_lru() {
                Some((_, v)) => g.bytes -= v.len(),
                None => break,
            }
        }
    }

    #[allow(dead_code)]
    pub fn bytes(&self) -> usize {
        self.inner.lock().bytes
    }
}

/// Serializes work per key, so that when several threads miss the same
/// cache entry only the first one does the work and the rest find it
/// already there.
///
/// Callers must re-check the cache inside the closure: by the time a waiter
/// runs, the thread it waited on has already stored its result.
pub struct SingleFlight<K> {
    inflight: Mutex<HashMap<K, Arc<Mutex<()>>>>,
}

impl<K> Default for SingleFlight<K> {
    fn default() -> Self {
        Self {
            inflight: Mutex::new(HashMap::new()),
        }
    }
}

impl<K: Hash + Eq + Clone> SingleFlight<K> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn dedupe<T>(&self, key: &K, f: impl FnOnce() -> T) -> T {
        let slot = self
            .inflight
            .lock()
            .entry(key.clone())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone();
        let out = {
            let _held = slot.lock();
            f()
        };
        // Drop the slot once nobody else is holding or waiting on it; the
        // map lock keeps a new waiter from picking it up mid-check. Two
        // references means the map's and ours.
        let mut map = self.inflight.lock();
        if map.get(key).is_some_and(|s| Arc::strong_count(s) == 2) {
            map.remove(key);
        }
        out
    }

    #[cfg(test)]
    fn tracked(&self) -> usize {
        self.inflight.lock().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_flight_runs_the_work_once() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let flight = SingleFlight::<u32>::new();
        let cache = ByteLru::new(1 << 20);
        let runs = AtomicUsize::new(0);
        let work = || {
            flight.dedupe(&7, || {
                if let Some(v) = cache.get(&7) {
                    return v;
                }
                runs.fetch_add(1, Ordering::Relaxed);
                std::thread::sleep(std::time::Duration::from_millis(20));
                let v = Arc::new(vec![1u8; 32]);
                cache.insert(7, v.clone());
                v
            })
        };
        std::thread::scope(|s| {
            for _ in 0..8 {
                s.spawn(work);
            }
        });
        assert_eq!(runs.load(Ordering::Relaxed), 1);
        assert_eq!(
            flight.tracked(),
            0,
            "keys are dropped once nobody holds them"
        );
    }

    #[test]
    fn evicts_by_bytes() {
        let c = ByteLru::new(10);
        c.insert(1, Arc::new(vec![0; 4]));
        c.insert(2, Arc::new(vec![0; 4]));
        assert!(c.get(&1).is_some());
        c.insert(3, Arc::new(vec![0; 4]));
        assert!(c.get(&2).is_none(), "least recently used entry should go");
        assert!(c.get(&1).is_some());
        assert!(c.bytes() <= 10);
        c.insert(4, Arc::new(vec![0; 11]));
        assert!(c.get(&4).is_none(), "oversized entries are skipped");
    }
}
