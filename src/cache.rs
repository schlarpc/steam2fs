//! Byte-bounded LRU cache of immutable buffers.

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

#[cfg(test)]
mod tests {
    use super::*;

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
