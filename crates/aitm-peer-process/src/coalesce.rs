//! The spec D3 concurrency shape: one socket scan at a time, callers that arrive
//! mid-scan join the next one, a token bucket bounds scans per second, and
//! identities go through the per-process cache. Platform-independent; the OS
//! lives behind [`SocketScanner`].
//!
//! Mechanics: a caller registers its tuple as *wanted* and *pending*. If no scan
//! is running it becomes the leader: it takes a token (or returns `None` at once
//! if the bucket is dry), drains the pending set, scans once with a deadline of
//! `now + scan_deadline`, writes a result for every tuple it scanned (absent
//! from the map = `None`), and wakes everyone. A non-leader sleeps on the
//! `Condvar` until its result is in or its own deadline passes; when it wakes to
//! find no scan running and no result it leads the next scan itself, so tuples
//! that arrived mid-scan are served without anyone spinning.

use std::collections::{HashMap, HashSet};
use std::sync::{Condvar, Mutex, MutexGuard};
use std::time::Instant;

use crate::cache::IdentityCache;
use crate::sanitize::sanitize;
use crate::types::{Limits, ProcessKey, SocketScanner, Tuple};

/// Serialises scans over one scanner and resolves tuples to sanitised identities.
// Assembled into `ProcessResolver` by plan Task 5; until then only tests drive it.
#[allow(dead_code)]
pub(crate) struct Coalescer<S: SocketScanner> {
    scanner: S,
    limits: Limits,
    state: Mutex<State>,
    wake: Condvar,
}

struct State {
    scanning: bool,
    /// Tuples registered since the last scan started.
    pending: HashSet<Tuple>,
    /// Scan outcomes not yet collected by their callers.
    results: HashMap<Tuple, Option<ProcessKey>>,
    /// Live callers per tuple; a result is kept only while someone wants it.
    wanted: HashMap<Tuple, u32>,
    tokens: f64,
    last_refill: Instant,
    cache: IdentityCache,
}

impl State {
    /// Refill the bucket for the time elapsed, then take one token if there is
    /// one. Fractional tokens accumulate so a rate of 10/s is 10/s, not 0.
    fn take_token(&mut self, limits: &Limits) -> bool {
        let now = Instant::now();
        let elapsed = now
            .saturating_duration_since(self.last_refill)
            .as_secs_f64();
        self.last_refill = now;
        let cap = f64::from(limits.scan_tokens);
        self.tokens = (self.tokens + elapsed * f64::from(limits.scan_refill_per_s)).min(cap);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Drop one caller's interest in `tuple`; the last one out clears its entries.
    fn release(&mut self, tuple: &Tuple) {
        let last = match self.wanted.get_mut(tuple) {
            Some(n) if *n > 1 => {
                *n -= 1;
                false
            }
            _ => true,
        };
        if last {
            self.wanted.remove(tuple);
            self.pending.remove(tuple);
            self.results.remove(tuple);
        }
    }
}

#[allow(dead_code)]
impl<S: SocketScanner> Coalescer<S> {
    pub(crate) fn new(scanner: S, limits: Limits) -> Self {
        let state = State {
            scanning: false,
            pending: HashSet::new(),
            results: HashMap::new(),
            wanted: HashMap::new(),
            tokens: f64::from(limits.scan_tokens),
            last_refill: Instant::now(),
            cache: IdentityCache::new(limits.cache_entries),
        };
        Self {
            scanner,
            limits,
            state: Mutex::new(state),
            wake: Condvar::new(),
        }
    }

    /// The spec D3 algorithm: register, lead or wait, then identity via the
    /// cache; sanitised. `None` on any failure, timeout or drained budget.
    pub(crate) fn resolve(&self, tuple: Tuple) -> Option<String> {
        let key = self.owner_of(tuple)?;
        self.identity_of(key)
    }

    /// Find the process owning `tuple`'s client end, leading or joining a scan.
    fn owner_of(&self, tuple: Tuple) -> Option<ProcessKey> {
        let deadline = Instant::now() + self.limits.scan_deadline;
        let mut state = self.lock();
        *state.wanted.entry(tuple).or_insert(0) += 1;
        state.pending.insert(tuple);
        loop {
            if let Some(found) = state.results.get(&tuple).copied() {
                state.release(&tuple);
                return found;
            }
            if !state.scanning {
                if !state.take_token(&self.limits) {
                    state.release(&tuple);
                    return None;
                }
                state = self.lead_scan(state);
                continue;
            }
            let now = Instant::now();
            if now >= deadline {
                state.release(&tuple);
                return None;
            }
            state = match self.wake.wait_timeout(state, deadline - now) {
                Ok((guard, _)) => guard,
                Err(poisoned) => poisoned.into_inner().0,
            };
        }
    }

    /// Run one scan for everything pending, with the lock released while the
    /// scanner works; write a result for every tuple scanned and wake waiters.
    fn lead_scan<'a>(&'a self, mut state: MutexGuard<'a, State>) -> MutexGuard<'a, State> {
        state.scanning = true;
        let batch: Vec<Tuple> = state.pending.drain().collect();
        drop(state);

        let found = self
            .scanner
            .find_owners(&batch, Instant::now() + self.limits.scan_deadline);

        let mut state = self.lock();
        for t in batch {
            if state.wanted.contains_key(&t) {
                state.results.insert(t, found.get(&t).copied());
            }
        }
        state.scanning = false;
        self.wake.notify_all();
        state
    }

    /// Name a process through the cache; both hits and misses are remembered.
    /// The scanner's `identity` runs outside the lock (a cold bundle read can
    /// take milliseconds), so two first-time callers for one key may both ask.
    fn identity_of(&self, key: ProcessKey) -> Option<String> {
        if let Some(cached) = self.lock().cache.get(&key) {
            return cached;
        }
        let identity = self.scanner.identity(key).and_then(|raw| sanitize(&raw));
        self.lock().cache.insert(key, identity.clone());
        identity
    }

    /// A poisoned lock means a scanner panicked mid-scan; the state is still
    /// consistent (results are written under the lock), so keep serving.
    fn lock(&self) -> MutexGuard<'_, State> {
        match self.state.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::{Arc, Barrier};
    use std::thread;
    use std::time::Duration;

    /// A scanner that records each `find_owners` call, sleeps like a real scan
    /// would, and, like a real scan, stops at the deadline it was given (a
    /// scan that ran out of time found nothing).
    struct FakeScanner {
        calls: Mutex<Vec<Vec<Tuple>>>,
        delay: Duration,
        owners: HashMap<Tuple, ProcessKey>,
        identities: Mutex<Vec<ProcessKey>>,
        names: HashMap<ProcessKey, String>,
    }

    impl FakeScanner {
        fn new(delay: Duration) -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                delay,
                owners: HashMap::new(),
                identities: Mutex::new(Vec::new()),
                names: HashMap::new(),
            }
        }

        fn owned(mut self, tuple: Tuple, key: ProcessKey, name: &str) -> Self {
            self.owners.insert(tuple, key);
            self.names.insert(key, name.to_string());
            self
        }
    }

    impl SocketScanner for FakeScanner {
        fn find_owners(&self, wanted: &[Tuple], deadline: Instant) -> HashMap<Tuple, ProcessKey> {
            self.calls.lock().unwrap().push(wanted.to_vec());
            let now = Instant::now();
            let finish = now + self.delay;
            if finish > deadline {
                thread::sleep(deadline.saturating_duration_since(now));
                return HashMap::new();
            }
            thread::sleep(self.delay);
            wanted
                .iter()
                .filter_map(|t| self.owners.get(t).map(|k| (*t, *k)))
                .collect()
        }

        fn identity(&self, key: ProcessKey) -> Option<String> {
            self.identities.lock().unwrap().push(key);
            self.names.get(&key).cloned()
        }
    }

    /// Tests keep a handle on the fake to read its records after `resolve`.
    impl SocketScanner for Arc<FakeScanner> {
        fn find_owners(&self, wanted: &[Tuple], deadline: Instant) -> HashMap<Tuple, ProcessKey> {
            self.as_ref().find_owners(wanted, deadline)
        }

        fn identity(&self, key: ProcessKey) -> Option<String> {
            self.as_ref().identity(key)
        }
    }

    fn tuple(client_port: u16) -> Tuple {
        let lo = IpAddr::V4(Ipv4Addr::LOCALHOST);
        Tuple {
            client: SocketAddr::new(lo, client_port),
            proxy: SocketAddr::new(lo, 8080),
        }
    }

    fn key(pid: u32, start: u64) -> ProcessKey {
        ProcessKey { pid, start }
    }

    #[test]
    fn eight_concurrent_resolutions_share_at_most_two_scans() {
        let mut scanner = FakeScanner::new(Duration::from_millis(20));
        for i in 0..8u32 {
            let port = 50_000 + i as u16;
            scanner = scanner.owned(tuple(port), key(1000 + i, 1), &format!("proc{i}"));
        }
        let scanner = Arc::new(scanner);
        let coalescer = Arc::new(Coalescer::new(Arc::clone(&scanner), Limits::default()));
        let barrier = Arc::new(Barrier::new(8));
        let handles: Vec<_> = (0..8u32)
            .map(|i| {
                let c = Arc::clone(&coalescer);
                let b = Arc::clone(&barrier);
                thread::spawn(move || {
                    b.wait();
                    c.resolve(tuple(50_000 + i as u16))
                })
            })
            .collect();
        for (i, h) in handles.into_iter().enumerate() {
            assert_eq!(h.join().unwrap(), Some(format!("proc{i}")), "thread {i}");
        }
        let calls = scanner.calls.lock().unwrap();
        assert!(calls.len() <= 2, "scans: {}", calls.len());
        assert!(!calls.is_empty());
        let scanned: usize = calls.iter().map(Vec::len).sum();
        assert_eq!(scanned, 8, "every tuple scanned exactly once");
    }

    #[test]
    fn drained_bucket_returns_none_without_a_scan() {
        let scanner =
            Arc::new(FakeScanner::new(Duration::ZERO).owned(tuple(50_100), key(1, 1), "curl"));
        let limits = Limits {
            scan_tokens: 0,
            ..Limits::default()
        };
        let coalescer = Coalescer::new(Arc::clone(&scanner), limits);
        assert_eq!(coalescer.resolve(tuple(50_100)), None);
        assert!(scanner.calls.lock().unwrap().is_empty());

        // One token and no refill: the first call spends it, the second finds
        // the bucket dry and returns at once without a second scan.
        let scanner = Arc::new(
            FakeScanner::new(Duration::ZERO)
                .owned(tuple(50_101), key(1, 1), "curl")
                .owned(tuple(50_102), key(1, 1), "curl"),
        );
        let limits = Limits {
            scan_tokens: 1,
            scan_refill_per_s: 0,
            ..Limits::default()
        };
        let coalescer = Coalescer::new(Arc::clone(&scanner), limits);
        assert_eq!(coalescer.resolve(tuple(50_101)), Some("curl".to_string()));
        assert_eq!(coalescer.resolve(tuple(50_102)), None);
        assert_eq!(scanner.calls.lock().unwrap().len(), 1);
    }

    #[test]
    fn bucket_refills_over_time() {
        let scanner = Arc::new(
            FakeScanner::new(Duration::ZERO)
                .owned(tuple(50_110), key(1, 1), "curl")
                .owned(tuple(50_111), key(1, 1), "curl"),
        );
        let limits = Limits {
            scan_tokens: 1,
            scan_refill_per_s: 1000,
            ..Limits::default()
        };
        let coalescer = Coalescer::new(Arc::clone(&scanner), limits);
        assert_eq!(coalescer.resolve(tuple(50_110)), Some("curl".to_string()));
        thread::sleep(Duration::from_millis(5));
        assert_eq!(coalescer.resolve(tuple(50_111)), Some("curl".to_string()));
        assert_eq!(scanner.calls.lock().unwrap().len(), 2);
    }

    #[test]
    fn deadline_bounds_a_slow_scan() {
        let scanner = Arc::new(FakeScanner::new(Duration::from_millis(50)).owned(
            tuple(50_200),
            key(1, 1),
            "curl",
        ));
        let limits = Limits {
            scan_deadline: Duration::from_millis(1),
            ..Limits::default()
        };
        let coalescer = Coalescer::new(Arc::clone(&scanner), limits);
        let started = Instant::now();
        let got = coalescer.resolve(tuple(50_200));
        let elapsed = started.elapsed();
        assert_eq!(got, None);
        assert!(elapsed < Duration::from_millis(40), "took {elapsed:?}");
        assert_eq!(
            scanner.calls.lock().unwrap().len(),
            1,
            "the scan was attempted"
        );
    }

    #[test]
    fn identity_is_cached_per_pid_and_start() {
        let scanner = Arc::new(
            FakeScanner::new(Duration::ZERO)
                .owned(tuple(50_300), key(42, 100), "curl")
                .owned(tuple(50_301), key(42, 100), "curl")
                .owned(tuple(50_302), key(42, 101), "curl2"),
        );
        let coalescer = Coalescer::new(Arc::clone(&scanner), Limits::default());
        assert_eq!(coalescer.resolve(tuple(50_300)), Some("curl".to_string()));
        assert_eq!(coalescer.resolve(tuple(50_301)), Some("curl".to_string()));
        assert_eq!(scanner.identities.lock().unwrap().len(), 1);
        assert_eq!(coalescer.resolve(tuple(50_302)), Some("curl2".to_string()));
        assert_eq!(
            *scanner.identities.lock().unwrap(),
            vec![key(42, 100), key(42, 101)]
        );
    }

    #[test]
    fn unnamed_process_is_cached_as_none() {
        let mut scanner = FakeScanner::new(Duration::ZERO);
        scanner.owners.insert(tuple(50_400), key(7, 1));
        scanner.owners.insert(tuple(50_401), key(7, 1));
        let scanner = Arc::new(scanner);
        let coalescer = Coalescer::new(Arc::clone(&scanner), Limits::default());
        assert_eq!(coalescer.resolve(tuple(50_400)), None);
        assert_eq!(coalescer.resolve(tuple(50_401)), None);
        assert_eq!(scanner.identities.lock().unwrap().len(), 1);
        assert_eq!(
            scanner.calls.lock().unwrap().len(),
            2,
            "owner lookups still scan"
        );
    }

    #[test]
    fn sanitised_identity_leaves_the_coalescer() {
        let scanner = Arc::new(FakeScanner::new(Duration::ZERO).owned(
            tuple(50_500),
            key(9, 1),
            "cu\u{200E}rl",
        ));
        let coalescer = Coalescer::new(Arc::clone(&scanner), Limits::default());
        assert_eq!(coalescer.resolve(tuple(50_500)), Some("curl".to_string()));
    }

    #[test]
    fn unknown_tuple_resolves_none_after_one_scan() {
        let scanner = Arc::new(FakeScanner::new(Duration::ZERO));
        let coalescer = Coalescer::new(Arc::clone(&scanner), Limits::default());
        assert_eq!(coalescer.resolve(tuple(50_600)), None);
        assert_eq!(scanner.calls.lock().unwrap().len(), 1);
        assert!(scanner.identities.lock().unwrap().is_empty());
    }
}
