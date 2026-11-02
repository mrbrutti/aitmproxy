//! The `ProcessKey → identity` cache (spec D3): bounded, FIFO-evicting, and it
//! remembers misses (`None`) as well as hits so a process the OS will not name is
//! asked about once, not once per connection.

use std::collections::{HashMap, VecDeque};

use crate::types::ProcessKey;

/// Sanitised identities keyed by `(pid, start)`; a recycled pid has a new `start`
/// and therefore never serves a stale name.
pub(crate) struct IdentityCache {
    map: HashMap<ProcessKey, Option<String>>,
    order: VecDeque<ProcessKey>,
    cap: usize,
}

impl IdentityCache {
    pub(crate) fn new(cap: usize) -> Self {
        Self {
            map: HashMap::new(),
            order: VecDeque::new(),
            cap,
        }
    }

    /// Outer `None` = miss; `Some(None)` = the OS would not name this process.
    pub(crate) fn get(&self, key: &ProcessKey) -> Option<Option<String>> {
        self.map.get(key).cloned()
    }

    /// Insert, evicting the oldest entry when at capacity. Re-inserting a known
    /// key replaces its value and keeps its place in the eviction order.
    pub(crate) fn insert(&mut self, key: ProcessKey, identity: Option<String>) {
        if self.cap == 0 {
            return;
        }
        if self.map.insert(key, identity).is_some() {
            return;
        }
        self.order.push_back(key);
        while self.order.len() > self.cap {
            if let Some(oldest) = self.order.pop_front() {
                self.map.remove(&oldest);
            }
        }
    }

    // Only tests read the size today; `#[allow]` rather than `#[cfg(test)]` so the
    // plan's signature stays available to the resolver.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn len(&self) -> usize {
        self.map.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(pid: u32) -> ProcessKey {
        ProcessKey { pid, start: 1 }
    }

    #[test]
    fn cache_evicts_fifo_at_capacity() {
        let mut cache = IdentityCache::new(256);
        for pid in 0..=256u32 {
            cache.insert(key(pid), Some(format!("p{pid}")));
        }
        assert_eq!(cache.len(), 256);
        assert_eq!(cache.get(&key(0)), None);
        assert_eq!(cache.get(&key(1)), Some(Some("p1".to_string())));
        assert_eq!(cache.get(&key(256)), Some(Some("p256".to_string())));
    }

    #[test]
    fn cache_remembers_misses_and_reinsert_does_not_grow() {
        let mut cache = IdentityCache::new(2);
        cache.insert(key(7), None);
        cache.insert(key(7), Some("seven".to_string()));
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.get(&key(7)), Some(Some("seven".to_string())));
        cache.insert(key(8), None);
        assert_eq!(cache.get(&key(8)), Some(None));
        cache.insert(key(9), None);
        assert_eq!(cache.len(), 2);
        assert_eq!(cache.get(&key(7)), None);
    }
}
