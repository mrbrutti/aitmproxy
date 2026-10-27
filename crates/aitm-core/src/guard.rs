//! The scope/rate guard: one gate every active action passes before reaching the
//! network, plus the SSRF address classifier the browser guard uses.
//!
//! `StdGuard` is deny-by-default on scope, token-bucketed on throughput (global
//! and per-host), capped on concurrency (released via an RAII [`ActionPermit`]),
//! and can disable a host whose error budget is exhausted.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use crate::config::{LimitConfig, ScopeEntry};
use crate::error::GuardError;

/// One gate for every active action: scope, rate, and concurrency.
pub trait ScopeRateGuard: Send + Sync {
    /// Check scope/rate/concurrency for `host`; returns a permit or a refusal.
    fn check_active(&self, host: &str) -> Result<ActionPermit, GuardError>;
    /// Add a host (or `host:port`, or `*.wildcard`) to scope.
    fn add_scope(&self, entry: ScopeEntry);
    /// The current scope entries.
    fn list_scope(&self) -> Vec<ScopeEntry>;
}

/// A granted concurrency slot. Dropping it releases the slot (RAII).
pub struct ActionPermit {
    in_flight: Arc<AtomicU32>,
}

impl Drop for ActionPermit {
    fn drop(&mut self) {
        self.in_flight.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Classification of a host/address for the SSRF guard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostClass {
    /// Loopback (`127.0.0.0/8`, `::1`, `localhost`).
    Loopback,
    /// Private / link-local / unspecified (RFC1918, `fc00::/7`, `fe80::/10`, …).
    Private,
    /// Everything else — a publicly routable address or an unresolved hostname.
    Public,
}

/// Classify a host literal or `localhost`. Hostnames that are not IP literals are
/// reported as `Public`; the SSRF guard (Task 19) resolves DNS and re-classifies.
pub fn classify_host(host: &str) -> HostClass {
    let host = host.trim();
    // Strip IPv6 brackets: `[::1]` -> `::1`.
    let stripped = host
        .strip_prefix('[')
        .and_then(|s| s.split(']').next())
        .unwrap_or(host);

    if stripped.eq_ignore_ascii_case("localhost") {
        return HostClass::Loopback;
    }
    if let Ok(ip) = stripped.parse::<IpAddr>() {
        return classify_ip(ip);
    }
    // Maybe `host:port` or `[v6]:port` — classify the host portion.
    if let Some(name) = host_without_port(host) {
        if name.eq_ignore_ascii_case("localhost") {
            return HostClass::Loopback;
        }
        if let Ok(ip) = name.parse::<IpAddr>() {
            return classify_ip(ip);
        }
    }
    HostClass::Public
}

/// The host portion of `host[:port]`, handling bracketed IPv6.
fn host_without_port(host: &str) -> Option<&str> {
    if let Some(rest) = host.strip_prefix('[') {
        // `[v6]:port` -> `v6`
        return rest.split(']').next();
    }
    match host.rsplit_once(':') {
        Some((name, port)) if port.chars().all(|c| c.is_ascii_digit()) && !port.is_empty() => {
            Some(name)
        }
        _ => None,
    }
}

fn classify_ip(ip: IpAddr) -> HostClass {
    match ip {
        IpAddr::V4(v4) => {
            if v4.is_loopback() {
                HostClass::Loopback
            } else if v4.is_private() || v4.is_link_local() || v4.is_unspecified() {
                HostClass::Private
            } else {
                HostClass::Public
            }
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return classify_ip(IpAddr::V4(v4));
            }
            let seg0 = v6.segments()[0];
            let is_ula = (seg0 & 0xfe00) == 0xfc00;
            let is_link_local = (seg0 & 0xffc0) == 0xfe80;
            if v6.is_loopback() {
                HostClass::Loopback
            } else if v6.is_unspecified() || is_ula || is_link_local {
                HostClass::Private
            } else {
                HostClass::Public
            }
        }
    }
}

/// A simple token bucket: `rate` tokens/sec, burst up to `capacity`.
struct TokenBucket {
    tokens: f64,
    capacity: f64,
    rate: f64,
    last: Instant,
}

impl TokenBucket {
    fn new(rate: u32) -> Self {
        let capacity = rate.max(1) as f64;
        Self {
            tokens: capacity,
            capacity,
            rate: capacity,
            last: Instant::now(),
        }
    }

    /// Try to consume one token, refilling for elapsed time first.
    fn try_take(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + elapsed * self.rate).min(self.capacity);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    fn retry_after(&self) -> Duration {
        if self.rate > 0.0 {
            Duration::from_secs_f64(1.0 / self.rate)
        } else {
            Duration::from_secs(1)
        }
    }
}

/// The default scope/rate guard.
pub struct StdGuard {
    scope: RwLock<Vec<ScopeEntry>>,
    global_bucket: Mutex<TokenBucket>,
    host_buckets: Mutex<HashMap<String, TokenBucket>>,
    per_host_rps: AtomicU32,
    max_concurrency: u32,
    in_flight: Arc<AtomicU32>,
    host_error_budget: u32,
    host_errors: Mutex<HashMap<String, u32>>,
}

impl StdGuard {
    /// Build a guard from the given limits.
    pub fn new(limits: LimitConfig) -> Self {
        Self {
            scope: RwLock::new(Vec::new()),
            global_bucket: Mutex::new(TokenBucket::new(limits.global_rps)),
            host_buckets: Mutex::new(HashMap::new()),
            per_host_rps: AtomicU32::new(limits.per_host_rps),
            max_concurrency: limits.max_concurrency,
            in_flight: Arc::new(AtomicU32::new(0)),
            host_error_budget: limits.host_error_budget,
            host_errors: Mutex::new(HashMap::new()),
        }
    }

    /// Reconfigure the per-host rate at runtime (drives AC-P4: changing the
    /// `per_host_rps` option changes observed throttling). Existing per-host
    /// buckets are reset so the new rate takes effect immediately.
    pub fn set_per_host_rps(&self, rps: u32) {
        self.per_host_rps.store(rps, Ordering::SeqCst);
        if let Ok(mut buckets) = self.host_buckets.lock() {
            buckets.clear();
        }
    }

    /// Record an error against a host; once the budget is exhausted the host is
    /// disabled and `check_active` refuses it with `HostDisabled`.
    pub fn record_error(&self, host: &str) {
        if let Ok(mut errors) = self.host_errors.lock() {
            *errors.entry(host.to_string()).or_insert(0) += 1;
        }
    }

    fn in_scope(&self, host: &str) -> bool {
        match self.scope.read() {
            Ok(entries) => entries.iter().any(|e| host_in_scope(host, &e.host)),
            Err(_) => false,
        }
    }

    fn is_disabled(&self, host: &str) -> bool {
        if self.host_error_budget == 0 {
            return false;
        }
        match self.host_errors.lock() {
            Ok(errors) => errors.get(host).copied().unwrap_or(0) >= self.host_error_budget,
            Err(_) => false,
        }
    }
}

impl Default for StdGuard {
    fn default() -> Self {
        Self::new(LimitConfig::default())
    }
}

/// Whether `host` falls under scope entry `entry` (exact, `host:port`, wildcard).
fn host_in_scope(host: &str, entry: &str) -> bool {
    let host = host.to_ascii_lowercase();
    let entry = entry.to_ascii_lowercase();
    if entry == host {
        return true;
    }
    // A portless entry matches a `host:port` request on the same host.
    if let Some((h, p)) = host.rsplit_once(':') {
        if p.chars().all(|c| c.is_ascii_digit()) && !p.is_empty() && entry == h {
            return true;
        }
    }
    // `*.domain` matches the domain and any subdomain.
    if let Some(suffix) = entry.strip_prefix("*.") {
        let hp = host
            .rsplit_once(':')
            .map(|(h, _)| h)
            .unwrap_or(host.as_str());
        if hp == suffix || hp.ends_with(&format!(".{suffix}")) {
            return true;
        }
    }
    false
}

impl ScopeRateGuard for StdGuard {
    fn check_active(&self, host: &str) -> Result<ActionPermit, GuardError> {
        if !self.in_scope(host) {
            return Err(GuardError::OutOfScope(host.to_string()));
        }
        if self.is_disabled(host) {
            return Err(GuardError::HostDisabled);
        }

        // Global then per-host rate.
        if let Ok(mut bucket) = self.global_bucket.lock() {
            if !bucket.try_take() {
                return Err(GuardError::RateLimited {
                    retry_after: bucket.retry_after(),
                });
            }
        }
        if let Ok(mut buckets) = self.host_buckets.lock() {
            let rps = self.per_host_rps.load(Ordering::SeqCst);
            let bucket = buckets
                .entry(host.to_string())
                .or_insert_with(|| TokenBucket::new(rps));
            if !bucket.try_take() {
                return Err(GuardError::RateLimited {
                    retry_after: bucket.retry_after(),
                });
            }
        }

        // Concurrency: reserve a slot atomically, or refuse.
        loop {
            let cur = self.in_flight.load(Ordering::SeqCst);
            if cur >= self.max_concurrency {
                return Err(GuardError::ConcurrencyExceeded);
            }
            if self
                .in_flight
                .compare_exchange(cur, cur + 1, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                break;
            }
        }

        Ok(ActionPermit {
            in_flight: self.in_flight.clone(),
        })
    }

    fn add_scope(&self, entry: ScopeEntry) {
        if let Ok(mut scope) = self.scope.write() {
            scope.push(entry);
        }
    }

    fn list_scope(&self) -> Vec<ScopeEntry> {
        self.scope.read().map(|s| s.clone()).unwrap_or_default()
    }
}
