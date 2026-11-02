//! The spec D3 concurrency shape: one socket scan at a time, callers that arrive
//! mid-scan join the next one, a warm set of recently matched pids is probed
//! before any full scan, a token bucket bounds full scans per second, and
//! identities go through the per-process cache. Platform-independent; the OS
//! lives behind [`SocketScanner`].
//!
//! Mechanics: a caller registers its tuple as *wanted* and *pending*. If no scan
//! is running it becomes the leader: it drains the pending set and first probes
//! only the **warm** pids (the [`WARM_CAPACITY`] most recently matched, an MRU
//! list; free, no token). Tuples the probe missed cost one token for one full
//! scan (or resolve `None` at once if the bucket is dry). Every scanned tuple
//! gets a result (absent from both maps = `None`) and everyone is woken. A
//! non-leader sleeps on the `Condvar` until its result is in or its own deadline
//! passes; when it wakes to find no scan running and no result it leads the next
//! scan itself, so tuples that arrived mid-scan are served without anyone
//! spinning.
//!
//! Why the warm set (live-proof finding F2, 2026-11-01): one client process
//! opens many connections, a browser dozens per page, and every one of them
//! used to pay a full scan and a token, so a 20-request burst from one python
//! process named only 14 rows. A warm probe is one fd-table read plus one
//! socket read per fd for at most 16 processes, sub-millisecond, so a client
//! seen once is named on every later connection without touching the bucket.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Condvar, Mutex, MutexGuard};
use std::time::Instant;

use crate::cache::IdentityCache;
use crate::sanitize::sanitize;
use crate::types::{Limits, ProcessKey, SocketScanner, Tuple};

/// How many recently matched pids are probed before a full scan. Sixteen covers
/// every client a tester drives at once (browser, its helpers, curl, a script)
/// while keeping a probe at a handful of `proc_pidinfo` calls.
pub(crate) const WARM_CAPACITY: usize = 16;

/// Serialises scans over one scanner and resolves tuples to sanitised identities.
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
    /// Recently matched pids, most recent at the front, at most `WARM_CAPACITY`.
    warm: VecDeque<u32>,
}

impl State {
    /// `pid` matched a tuple: it becomes the most recent, evicting the least
    /// recent if the set is full.
    fn warm_hit(&mut self, pid: u32) {
        self.warm.retain(|p| *p != pid);
        self.warm.push_front(pid);
        self.warm.truncate(WARM_CAPACITY);
    }

    /// `pid` had no sockets when probed: forget it.
    fn warm_drop(&mut self, pid: u32) {
        self.warm.retain(|p| *p != pid);
    }

    /// The warm pids ascending, so the lowest matching pid wins as in a full scan.
    fn warm_sorted(&self) -> Vec<u32> {
        let mut pids: Vec<u32> = self.warm.iter().copied().collect();
        pids.sort_unstable();
        pids
    }

    /// Refill the bucket for the time elapsed, then take one token if there is
    /// one. Fractional tokens accumulate so a rate of 20/s is 20/s, not 0.
    /// Only full scans pay: at the default 20/s and the measured 7 ms per scan
    /// the worst case is 140 ms of one core per second (14 %); idle cost zero.
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
            warm: VecDeque::with_capacity(WARM_CAPACITY),
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
    /// scanner works: a free probe of the warm pids first, then, for the tuples
    /// it missed, one full scan if the bucket has a token. Write a result for
    /// every tuple scanned (unfound = `None`) and wake waiters.
    ///
    /// The scanner runs with the lock released, so a panic inside it unwinds
    /// through this frame with `scanning` still set. [`ScanGuard`] covers that
    /// path: on unwind it writes `None` for the batch, clears `scanning` and
    /// wakes the waiters, so the next caller leads a fresh scan instead of
    /// every later caller waiting out its deadline behind a scan that is not
    /// running (tester finding T-F1, 2026-11-01).
    fn lead_scan<'a>(&'a self, mut state: MutexGuard<'a, State>) -> MutexGuard<'a, State> {
        state.scanning = true;
        let deadline = Instant::now() + self.limits.scan_deadline;
        let batch: Vec<Tuple> = state.pending.drain().collect();
        let warm = state.warm_sorted();
        drop(state);
        let mut guard = ScanGuard {
            coalescer: self,
            batch,
            armed: true,
        };
        let batch = &guard.batch;

        let mut found: HashMap<Tuple, ProcessKey> = HashMap::with_capacity(batch.len());
        let mut gone: Vec<u32> = Vec::new();
        if !warm.is_empty() {
            let probe = self.scanner.find_owners_among(batch, deadline, &warm);
            found = probe.owners;
            gone = probe.gone;
        }

        let mut state = self.lock();
        for pid in gone {
            state.warm_drop(pid);
        }
        let missed: Vec<Tuple> = batch
            .iter()
            .copied()
            .filter(|t| !found.contains_key(t))
            .collect();
        if !missed.is_empty() && state.take_token(&self.limits) {
            drop(state);
            let full = self.scanner.find_owners(&missed, deadline);
            state = self.lock();
            found.extend(full);
        }

        // `warm_hit` puts each pid at the front, so after this loop the batch's
        // matches sit ahead of every pid from earlier batches, ordered among
        // themselves by descending pid (an arbitrary but deterministic order;
        // recency within one batch is not observable).
        let mut matched: Vec<u32> = found.values().map(|k| k.pid).collect();
        matched.sort_unstable();
        matched.dedup();
        for pid in matched {
            state.warm_hit(pid);
        }
        for t in batch {
            if state.wanted.contains_key(t) {
                state.results.insert(*t, found.get(t).copied());
            }
        }
        state.scanning = false;
        self.wake.notify_all();
        guard.armed = false;
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

    /// A poisoned lock means some thread panicked **while holding** it (the
    /// scanner itself runs with the lock released, so a scanner panic does not
    /// poison it). Every mutation of `State` under the lock is a single map or
    /// flag write that leaves it consistent at each statement, and
    /// [`ScanGuard`] clears `scanning` on unwind, so the inner value is safe to
    /// keep serving; refusing it would wedge every later caller instead.
    fn lock(&self) -> MutexGuard<'_, State> {
        match self.state.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

/// Armed for the span of one `lead_scan`; disarmed on the normal path. If the
/// scanner panics, `Drop` runs on unwind (with the lock **not** held: the
/// `MutexGuard` locals of `lead_scan` are declared after it and so dropped
/// first) and finishes the scan as a miss for every tuple in the batch.
struct ScanGuard<'a, S: SocketScanner> {
    coalescer: &'a Coalescer<S>,
    batch: Vec<Tuple>,
    armed: bool,
}

impl<S: SocketScanner> Drop for ScanGuard<'_, S> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let mut state = self.coalescer.lock();
        for t in &self.batch {
            if state.wanted.contains_key(t) {
                state.results.insert(*t, None);
            }
        }
        state.scanning = false;
        self.coalescer.wake.notify_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Probe;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::{Arc, Barrier};
    use std::thread;
    use std::time::Duration;

    /// A scanner that records each full `find_owners` call (`calls`) and each
    /// targeted `find_owners_among` call (`targeted`: the tuples and the pids
    /// probed), sleeps like a real full scan would, and, like a real scan, stops
    /// at the deadline it was given (a scan that ran out of time found nothing).
    /// A targeted probe reports a pid as `gone` when it owns no tuple at all.
    struct FakeScanner {
        calls: Mutex<Vec<Vec<Tuple>>>,
        targeted: Mutex<Vec<(Vec<Tuple>, Vec<u32>)>>,
        delay: Duration,
        owners: Mutex<HashMap<Tuple, ProcessKey>>,
        identities: Mutex<Vec<ProcessKey>>,
        names: HashMap<ProcessKey, String>,
    }

    impl FakeScanner {
        fn new(delay: Duration) -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                targeted: Mutex::new(Vec::new()),
                delay,
                owners: Mutex::new(HashMap::new()),
                identities: Mutex::new(Vec::new()),
                names: HashMap::new(),
            }
        }

        fn owned(mut self, tuple: Tuple, key: ProcessKey, name: &str) -> Self {
            self.owners.lock().unwrap().insert(tuple, key);
            self.names.insert(key, name.to_string());
            self
        }

        /// The process `pid` exits: every socket it owned is gone.
        fn exit(&self, pid: u32) {
            self.owners.lock().unwrap().retain(|_, k| k.pid != pid);
        }

        fn full_scans(&self) -> usize {
            self.calls.lock().unwrap().len()
        }

        /// The pid lists of every targeted probe so far.
        fn probed_pids(&self) -> Vec<Vec<u32>> {
            self.targeted
                .lock()
                .unwrap()
                .iter()
                .map(|(_, pids)| pids.clone())
                .collect()
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
            let owners = self.owners.lock().unwrap();
            wanted
                .iter()
                .filter_map(|t| owners.get(t).map(|k| (*t, *k)))
                .collect()
        }

        fn find_owners_among(&self, wanted: &[Tuple], _deadline: Instant, pids: &[u32]) -> Probe {
            self.targeted
                .lock()
                .unwrap()
                .push((wanted.to_vec(), pids.to_vec()));
            let owners = self.owners.lock().unwrap();
            let mut probe = Probe::default();
            for &pid in pids {
                if !owners.values().any(|k| k.pid == pid) {
                    probe.gone.push(pid);
                    continue;
                }
                for t in wanted {
                    if let Some(k) = owners.get(t).filter(|k| k.pid == pid) {
                        probe.owners.entry(*t).or_insert(*k);
                    }
                }
            }
            probe
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

        fn find_owners_among(&self, wanted: &[Tuple], deadline: Instant, pids: &[u32]) -> Probe {
            self.as_ref().find_owners_among(wanted, deadline, pids)
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

        // One token and no refill: the first call spends it, the second (a new
        // pid, so the warm probe misses) finds the bucket dry and returns at
        // once without a second full scan.
        let scanner = Arc::new(
            FakeScanner::new(Duration::ZERO)
                .owned(tuple(50_101), key(1, 1), "curl")
                .owned(tuple(50_102), key(2, 1), "wget"),
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
        // Two pids, so the second lookup is a warm miss that needs a token.
        let scanner = Arc::new(
            FakeScanner::new(Duration::ZERO)
                .owned(tuple(50_110), key(1, 1), "curl")
                .owned(tuple(50_111), key(2, 1), "wget"),
        );
        let limits = Limits {
            scan_tokens: 1,
            scan_refill_per_s: 1000,
            ..Limits::default()
        };
        let coalescer = Coalescer::new(Arc::clone(&scanner), limits);
        assert_eq!(coalescer.resolve(tuple(50_110)), Some("curl".to_string()));
        thread::sleep(Duration::from_millis(5));
        assert_eq!(coalescer.resolve(tuple(50_111)), Some("wget".to_string()));
        assert_eq!(scanner.full_scans(), 2);
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
        let scanner = FakeScanner::new(Duration::ZERO);
        scanner
            .owners
            .lock()
            .unwrap()
            .insert(tuple(50_400), key(7, 1));
        scanner
            .owners
            .lock()
            .unwrap()
            .insert(tuple(50_401), key(7, 1));
        let scanner = Arc::new(scanner);
        let coalescer = Coalescer::new(Arc::clone(&scanner), Limits::default());
        assert_eq!(coalescer.resolve(tuple(50_400)), None);
        assert_eq!(coalescer.resolve(tuple(50_401)), None);
        assert_eq!(scanner.identities.lock().unwrap().len(), 1);
        assert_eq!(scanner.full_scans(), 1, "the first lookup scans");
        assert_eq!(
            scanner.probed_pids(),
            vec![vec![7]],
            "the second is a warm probe of the same pid"
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

    /// F2 (2026-11-01): one client process opening many connections pays one
    /// full scan, then warm probes only, and the bucket is never touched again.
    /// With one token and no refill, the 50 later hits would be `None` if any
    /// of them took a token or ran a full scan.
    #[test]
    fn warm_hits_skip_the_full_scan_and_the_bucket() {
        let mut scanner = FakeScanner::new(Duration::ZERO);
        for port in 50_000..=50_050u16 {
            scanner = scanner.owned(tuple(port), key(4242, 1), "python3");
        }
        let scanner = Arc::new(scanner);
        let limits = Limits {
            scan_tokens: 1,
            scan_refill_per_s: 0,
            ..Limits::default()
        };
        let coalescer = Coalescer::new(Arc::clone(&scanner), limits);
        assert_eq!(
            coalescer.resolve(tuple(50_000)),
            Some("python3".to_string())
        );
        assert_eq!(scanner.full_scans(), 1);
        assert_eq!(
            scanner.probed_pids(),
            Vec::<Vec<u32>>::new(),
            "empty warm set: no probe"
        );

        for port in 50_001..=50_050u16 {
            assert_eq!(
                coalescer.resolve(tuple(port)),
                Some("python3".to_string()),
                "port {port}"
            );
        }
        assert_eq!(scanner.full_scans(), 1, "no further full scan");
        let probes = scanner.probed_pids();
        assert_eq!(probes.len(), 50, "one targeted probe per later connection");
        assert!(probes.iter().all(|p| p == &vec![4242]), "{probes:?}");
    }

    #[test]
    fn a_targeted_miss_falls_through_to_one_full_scan() {
        let scanner = Arc::new(
            FakeScanner::new(Duration::ZERO)
                .owned(tuple(50_000), key(4242, 1), "python3")
                .owned(tuple(50_001), key(4343, 1), "curl"),
        );
        let coalescer = Coalescer::new(Arc::clone(&scanner), Limits::default());
        assert_eq!(
            coalescer.resolve(tuple(50_000)),
            Some("python3".to_string())
        );
        assert_eq!(coalescer.resolve(tuple(50_001)), Some("curl".to_string()));
        assert_eq!(scanner.probed_pids(), vec![vec![4242]]);
        assert_eq!(
            *scanner.calls.lock().unwrap(),
            vec![vec![tuple(50_000)], vec![tuple(50_001)]],
            "the miss ran exactly one full scan, for the missed tuple only"
        );
    }

    #[test]
    fn warm_set_keeps_the_sixteen_most_recently_matched_pids() {
        // pid i owns port 50_000 + i (i in 1..=18) and pid 1 also owns 50_101.
        let mut scanner = FakeScanner::new(Duration::ZERO);
        for pid in 1..=18u32 {
            scanner = scanner.owned(tuple(50_000 + pid as u16), key(pid, 1), &format!("p{pid}"));
        }
        scanner = scanner.owned(tuple(50_101), key(1, 1), "p1");
        let scanner = Arc::new(scanner);
        let limits = Limits {
            scan_tokens: 100,
            ..Limits::default()
        };
        let coalescer = Coalescer::new(Arc::clone(&scanner), limits);

        for pid in 1..=17u32 {
            assert_eq!(
                coalescer.resolve(tuple(50_000 + pid as u16)),
                Some(format!("p{pid}"))
            );
        }
        assert_eq!(scanner.full_scans(), 17, "17 new pids, 17 full scans");

        // pid 1 was the first matched and the 17th push evicted it: the probe
        // before the next lookup covers exactly 2..=17, ascending.
        assert_eq!(coalescer.resolve(tuple(50_002)), Some("p2".to_string()));
        let expected: Vec<u32> = (2..=17).collect();
        assert_eq!(scanner.probed_pids().last(), Some(&expected));
        assert_eq!(scanner.full_scans(), 17, "a warm hit");

        // That hit moved pid 2 to the front, so the next eviction (pid 18 is
        // new) removes pid 3, not pid 2.
        assert_eq!(coalescer.resolve(tuple(50_018)), Some("p18".to_string()));
        assert_eq!(scanner.full_scans(), 18);
        assert_eq!(coalescer.resolve(tuple(50_002)), Some("p2".to_string()));
        let mut expected: Vec<u32> = (4..=18).collect();
        expected.insert(0, 2);
        assert_eq!(scanner.probed_pids().last(), Some(&expected));
        assert_eq!(scanner.full_scans(), 18);

        // The evicted pid 1 is cold again: its next connection is a full scan.
        assert_eq!(coalescer.resolve(tuple(50_101)), Some("p1".to_string()));
        assert_eq!(scanner.full_scans(), 19);
    }

    #[test]
    fn a_pid_whose_probe_finds_no_sockets_leaves_the_warm_set() {
        let scanner = Arc::new(
            FakeScanner::new(Duration::ZERO)
                .owned(tuple(50_000), key(7, 1), "short-lived")
                .owned(tuple(50_001), key(8, 1), "python3")
                .owned(tuple(50_002), key(8, 1), "python3"),
        );
        let coalescer = Coalescer::new(Arc::clone(&scanner), Limits::default());
        assert_eq!(
            coalescer.resolve(tuple(50_000)),
            Some("short-lived".to_string())
        );
        scanner.exit(7);

        // Warm probe of [7] finds no fds -> 7 dropped -> full scan names 8.
        assert_eq!(
            coalescer.resolve(tuple(50_001)),
            Some("python3".to_string())
        );
        assert_eq!(scanner.full_scans(), 2);
        // The next probe is of [8] alone: 7 is no longer warm.
        assert_eq!(
            coalescer.resolve(tuple(50_002)),
            Some("python3".to_string())
        );
        assert_eq!(scanner.full_scans(), 2);
        assert_eq!(scanner.probed_pids(), vec![vec![7], vec![8]]);
    }

    /// Refill is capped at the capacity: 300 ms idle at 10/s would be 3 tokens
    /// uncapped, but with capacity 1 the second new pid in a row still finds the
    /// bucket dry.
    #[test]
    fn the_bucket_never_exceeds_its_capacity() {
        let scanner = Arc::new(
            FakeScanner::new(Duration::ZERO)
                .owned(tuple(50_700), key(1, 1), "curl")
                .owned(tuple(50_701), key(2, 1), "wget"),
        );
        let limits = Limits {
            scan_tokens: 1,
            scan_refill_per_s: 10,
            ..Limits::default()
        };
        let coalescer = Coalescer::new(Arc::clone(&scanner), limits);
        thread::sleep(Duration::from_millis(300));
        assert_eq!(coalescer.resolve(tuple(50_700)), Some("curl".to_string()));
        assert_eq!(coalescer.resolve(tuple(50_701)), None);
        assert_eq!(scanner.full_scans(), 1);
    }

    /// D5: a name the sanitiser rejects is `None`, and that `None` is cached so
    /// the process is asked about once, not once per connection.
    #[test]
    fn an_unprintable_identity_is_none_and_asked_once() {
        let scanner = Arc::new(
            FakeScanner::new(Duration::ZERO)
                .owned(tuple(50_800), key(5, 1), "\u{7}\u{200B}")
                .owned(tuple(50_801), key(5, 1), "\u{7}\u{200B}"),
        );
        let coalescer = Coalescer::new(Arc::clone(&scanner), Limits::default());
        assert_eq!(coalescer.resolve(tuple(50_800)), None);
        assert_eq!(coalescer.resolve(tuple(50_801)), None);
        assert_eq!(scanner.identities.lock().unwrap().len(), 1);
    }

    /// `cache_entries: 0` disables caching without disabling resolution.
    #[test]
    fn a_zero_capacity_cache_still_resolves() {
        let scanner = Arc::new(
            FakeScanner::new(Duration::ZERO)
                .owned(tuple(50_850), key(6, 1), "curl")
                .owned(tuple(50_851), key(6, 1), "curl"),
        );
        let limits = Limits {
            cache_entries: 0,
            ..Limits::default()
        };
        let coalescer = Coalescer::new(Arc::clone(&scanner), limits);
        assert_eq!(coalescer.resolve(tuple(50_850)), Some("curl".to_string()));
        assert_eq!(coalescer.resolve(tuple(50_851)), Some("curl".to_string()));
        assert_eq!(scanner.identities.lock().unwrap().len(), 2);
    }

    /// D3: a caller that arrives while a scan is running is not folded into
    /// that scan (its tuple was not in the leader's batch); it waits, then leads
    /// the next one itself. Two callers, two single-tuple scans, both named.
    #[test]
    fn a_late_arrival_joins_the_next_scan_not_the_running_one() {
        let scanner = Arc::new(
            FakeScanner::new(Duration::from_millis(30))
                .owned(tuple(50_950), key(1, 1), "first")
                .owned(tuple(50_951), key(2, 1), "second"),
        );
        let coalescer = Arc::new(Coalescer::new(Arc::clone(&scanner), Limits::default()));
        let barrier = Arc::new(Barrier::new(2));
        let early = {
            let c = Arc::clone(&coalescer);
            let b = Arc::clone(&barrier);
            thread::spawn(move || {
                b.wait();
                c.resolve(tuple(50_950))
            })
        };
        barrier.wait();
        thread::sleep(Duration::from_millis(5));
        let late = coalescer.resolve(tuple(50_951));
        assert_eq!(early.join().unwrap(), Some("first".to_string()));
        assert_eq!(late, Some("second".to_string()));

        let calls = scanner.calls.lock().unwrap();
        assert_eq!(calls.len(), 2, "{calls:?}");
        assert!(
            calls.iter().all(|c| c.len() == 1),
            "each scan carried exactly one tuple: {calls:?}"
        );
        let mut seen: Vec<Tuple> = calls.iter().flatten().copied().collect();
        seen.sort_by_key(|t| t.client.port());
        assert_eq!(seen, vec![tuple(50_950), tuple(50_951)]);
    }

    /// Panics on the first `panics` full scans (after sleeping `delay` so a
    /// waiter can register mid-scan); every later full scan finds nothing.
    struct PanickingScanner {
        calls: Mutex<usize>,
        panics: usize,
        delay: Duration,
    }

    impl SocketScanner for PanickingScanner {
        fn find_owners(&self, _wanted: &[Tuple], _deadline: Instant) -> HashMap<Tuple, ProcessKey> {
            let call = {
                let mut calls = self.calls.lock().unwrap();
                *calls += 1;
                *calls
            };
            if call <= self.panics {
                thread::sleep(self.delay);
                panic!("scanner blew up");
            }
            HashMap::new()
        }

        fn find_owners_among(&self, _wanted: &[Tuple], _deadline: Instant, _pids: &[u32]) -> Probe {
            Probe::default()
        }

        fn identity(&self, _key: ProcessKey) -> Option<String> {
            None
        }
    }

    impl SocketScanner for Arc<PanickingScanner> {
        fn find_owners(&self, wanted: &[Tuple], deadline: Instant) -> HashMap<Tuple, ProcessKey> {
            self.as_ref().find_owners(wanted, deadline)
        }

        fn find_owners_among(&self, wanted: &[Tuple], deadline: Instant, pids: &[u32]) -> Probe {
            self.as_ref().find_owners_among(wanted, deadline, pids)
        }

        fn identity(&self, key: ProcessKey) -> Option<String> {
            self.as_ref().identity(key)
        }
    }

    /// Tester finding T-F1 (stage 5, 2026-11-01): `lead_scan` sets `scanning`
    /// and releases the lock before calling the scanner; without the
    /// `ScanGuard`, a scanner panic left the flag set, so every later caller
    /// waited out its full deadline behind a scan that was not running and
    /// resolved `None`. In production (`spawn_blocking`) that was one wedged
    /// resolver for the life of the process plus the full 25 ms budget on
    /// every connection. Before the fix: `calls == 1`, elapsed == deadline.
    #[test]
    fn a_scanner_panic_does_not_wedge_later_callers() {
        let scanner = Arc::new(PanickingScanner {
            calls: Mutex::new(0),
            panics: 1,
            delay: Duration::ZERO,
        });
        let limits = Limits {
            scan_deadline: Duration::from_millis(30),
            ..Limits::default()
        };
        let coalescer = Arc::new(Coalescer::new(Arc::clone(&scanner), limits));
        let c = Arc::clone(&coalescer);
        let first = thread::spawn(move || c.resolve(tuple(50_900))).join();
        assert!(
            first.is_err(),
            "the leader's thread panics with the scanner"
        );

        let started = Instant::now();
        let got = coalescer.resolve(tuple(50_901));
        let elapsed = started.elapsed();
        assert_eq!(got, None);
        assert_eq!(
            *scanner.calls.lock().unwrap(),
            2,
            "the second caller must lead a new scan, not wait behind a dead one"
        );
        assert!(
            elapsed < Duration::from_millis(20),
            "took {elapsed:?}: waited out the deadline behind a scan that is not running"
        );
        assert!(
            !coalescer.lock().scanning,
            "the guard cleared `scanning` after the panic"
        );
    }

    /// T-F1, the waiter's side: a caller that arrived while the leader's scan
    /// was running is woken the moment the leader panics (the guard clears
    /// `scanning` and notifies), finds no scan running and leads the next one
    /// itself, instead of sitting out its own 2 s deadline.
    #[test]
    fn a_waiter_is_released_when_the_leader_panics() {
        let scanner = Arc::new(PanickingScanner {
            calls: Mutex::new(0),
            panics: 1,
            delay: Duration::from_millis(100),
        });
        let limits = Limits {
            scan_deadline: Duration::from_secs(2),
            ..Limits::default()
        };
        let coalescer = Arc::new(Coalescer::new(Arc::clone(&scanner), limits));
        let c = Arc::clone(&coalescer);
        let leader = thread::spawn(move || c.resolve(tuple(50_910)));
        // Wait until the leader is inside the scanner (sleeping before its panic).
        let started = Instant::now();
        while *scanner.calls.lock().unwrap() == 0 {
            assert!(
                started.elapsed() < Duration::from_secs(1),
                "leader never scanned"
            );
            thread::sleep(Duration::from_millis(1));
        }
        assert!(coalescer.lock().scanning, "a scan is in flight");

        let waited = Instant::now();
        let got = coalescer.resolve(tuple(50_911));
        let elapsed = waited.elapsed();
        assert!(leader.join().is_err(), "the leader's thread panicked");
        assert_eq!(got, None);
        assert_eq!(
            *scanner.calls.lock().unwrap(),
            2,
            "woken by the guard, the waiter led the next scan itself"
        );
        assert!(
            elapsed < Duration::from_millis(1_000),
            "took {elapsed:?}: the waiter sat out the deadline instead of being woken"
        );
    }
}
