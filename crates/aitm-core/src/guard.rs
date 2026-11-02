//! The scope/rate guard: one gate every active action passes before reaching the
//! network, plus the SSRF address classifier the browser guard uses.
//!
//! `StdGuard` is deny-by-default on scope, token-bucketed on throughput (global
//! and per-host), capped on concurrency (released via an RAII [`ActionPermit`]),
//! and can disable a host whose error budget is exhausted.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::{Duration, Instant};

use crate::authority::Authority;
use crate::config::{LimitConfig, ScopeEntry};
use crate::error::GuardError;

/// One gate for every active action: scope, rate, and concurrency.
pub trait ScopeRateGuard: Send + Sync {
    /// Check scope/rate/concurrency for `host`; returns a permit or a refusal.
    fn check_active(&self, host: &str) -> Result<ActionPermit, GuardError>;
    /// Add a host (or `host:port`, or `*.wildcard`) to scope.
    fn add_scope(&self, entry: ScopeEntry);
    /// Remove the scope entry matching `entry`; returns whether one was removed.
    /// Required (no default): a guard that silently kept the entry while reporting
    /// success would be an auth-relevant lie.
    fn remove_scope(&self, entry: &str) -> bool;
    /// The current scope entries.
    fn list_scope(&self) -> Vec<ScopeEntry>;
    /// Whether `host` is currently in the scope allowlist — a read-only predicate
    /// with no rate, concurrency, or error-budget effect. Callers pass `host:port`
    /// (the capture ingress gates a captured stream on the SNI / handoff hostname,
    /// else the dst IP, with the dst port) and an implementation matches the way
    /// [`Authority::matches_scope_entry`] does: a portless entry admits any port.
    /// Default is **deny-by-default**, so a guard that does not implement it refuses
    /// every host.
    fn in_scope(&self, _host: &str) -> bool {
        false
    }
    /// Record an error against `host`; once its budget is exhausted the guard
    /// disables it (with backoff) and `check_active` refuses it. Default: no-op.
    fn record_error(&self, _host: &str) {}
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
            let o = v4.octets();
            if v4.is_loopback() {
                HostClass::Loopback
            } else if v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                // "This host on this network" (0.0.0.0/8).
                || o[0] == 0
                // Carrier-grade NAT (100.64.0.0/10).
                || (o[0] == 100 && (64..=127).contains(&o[1]))
                // IETF protocol assignments (192.0.0.0/24).
                || (o[0] == 192 && o[1] == 0 && o[2] == 0)
                // Benchmarking (198.18.0.0/15).
                || (o[0] == 198 && (o[1] == 18 || o[1] == 19))
                // Documentation TEST-NET-1/2/3 (192.0.2.0/24, 198.51.100.0/24,
                // 203.0.113.0/24) — never a real target, so refuse by default.
                || (o[0] == 192 && o[1] == 0 && o[2] == 2)
                || (o[0] == 198 && o[1] == 51 && o[2] == 100)
                || (o[0] == 203 && o[1] == 0 && o[2] == 113)
                // Multicast + reserved + broadcast (224.0.0.0/3).
                || o[0] >= 224
            {
                HostClass::Private
            } else {
                HostClass::Public
            }
        }
        IpAddr::V6(v6) => {
            // NAT64 well-known prefix 64:ff9b::/96 carries an embedded v4.
            let seg = v6.segments();
            if seg[0] == 0x0064 && seg[1] == 0xff9b && seg[2..6] == [0, 0, 0, 0] {
                let o = v6.octets();
                return classify_ip(IpAddr::V4(std::net::Ipv4Addr::new(
                    o[12], o[13], o[14], o[15],
                )));
            }
            // NAT64 local-use prefix 64:ff9b:1::/48 (RFC 8215): a local translator,
            // not a public target — refuse by default.
            if seg[0] == 0x0064 && seg[1] == 0xff9b && seg[2] == 0x0001 {
                return HostClass::Private;
            }
            if let Some(v4) = v6.to_ipv4_mapped() {
                return classify_ip(IpAddr::V4(v4));
            }
            // Deprecated IPv4-compatible ::a.b.c.d (not ::/::1).
            if seg[0..6] == [0, 0, 0, 0, 0, 0] && !(seg[6] == 0 && (seg[7] == 0 || seg[7] == 1)) {
                let o = v6.octets();
                return classify_ip(IpAddr::V4(std::net::Ipv4Addr::new(
                    o[12], o[13], o[14], o[15],
                )));
            }
            let seg0 = seg[0];
            let is_ula = (seg0 & 0xfe00) == 0xfc00;
            let is_link_local = (seg0 & 0xffc0) == 0xfe80;
            // Site-local fec0::/10 (deprecated) and multicast ff00::/8.
            let is_site_local = (seg0 & 0xffc0) == 0xfec0;
            let is_multicast = (seg0 & 0xff00) == 0xff00;
            // Documentation 2001:db8::/32 (RFC 3849): never a real target.
            let is_doc = seg0 == 0x2001 && seg[1] == 0x0db8;
            // Teredo 2001:0000::/32 (RFC 4380): tunnels to an embedded relay; we do
            // not decode it, we refuse the whole prefix so it can't reach a private
            // host via the tunnel.
            let is_teredo = seg0 == 0x2001 && seg[1] == 0x0000;
            // 6to4 2002::/16 embeds the v4 relay; classify that address instead.
            if seg0 == 0x2002 {
                return classify_ip(IpAddr::V4(std::net::Ipv4Addr::new(
                    (seg[1] >> 8) as u8,
                    (seg[1] & 0xff) as u8,
                    (seg[2] >> 8) as u8,
                    (seg[2] & 0xff) as u8,
                )));
            }
            if v6.is_loopback() {
                HostClass::Loopback
            } else if v6.is_unspecified()
                || is_ula
                || is_link_local
                || is_site_local
                || is_multicast
                || is_doc
                || is_teredo
            {
                HostClass::Private
            } else {
                HostClass::Public
            }
        }
    }
}

/// Whether a host class is blocked by an SSRF policy.
fn blocked_by_policy(class: HostClass, policy: &crate::config::SsrfPolicy) -> bool {
    match class {
        HostClass::Loopback => policy.block_loopback,
        HostClass::Private => policy.block_private,
        HostClass::Public => false,
    }
}

/// Whether the SSRF policy ∪ the current scope could ever permit the embedded
/// engine to reach a private or loopback target — the input to obscura's
/// `--allow-private-network` engine flag (audit I15). True when the policy does
/// not block private ranges, or when scope lifts the block for at least one
/// private/loopback **address** host: an IP literal or `localhost`. A scoped DNS
/// *hostname* never counts (`classify_host` reports it `Public`), matching
/// [`ssrf_check`], which refuses a scoped name that resolves private as a
/// rebinding attempt — the engine flag must not widen past that.
///
/// This is only the coarse engine gate. The proxy connector's [`ssrf_check`]
/// remains the authoritative per-connection enforcement: this decides whether to
/// narrow the engine *below* it, never to widen past it. It is computed once at
/// launch from the seed scope; a host added later (`scope.add`) is still gated
/// correctly by the connector, but the engine only picks up a newly private
/// target on relaunch.
pub fn engine_may_reach_private(policy: &crate::config::SsrfPolicy, scope: &[ScopeEntry]) -> bool {
    !policy.block_private
        || (policy.allow_if_in_scope
            && scope.iter().any(|e| {
                matches!(
                    classify_host(&e.host),
                    HostClass::Private | HostClass::Loopback
                )
            }))
}

/// SSRF decision for an upstream connection: refuse a private/loopback target
/// (by the requested `authority` or the resolved `dst`) unless an **IP literal /
/// `localhost`** that matches `dst` is explicitly in scope (a wildcard, and —
/// crucially — a scoped *DNS hostname*, do not lift the block; a hostname that
/// resolves private is a DNS-rebinding attempt). Used by the browser proxy
/// connector so redirects, page `fetch`, sub-resources and `browser.eval` are all
/// covered, not only the first navigation.
///
/// With `confine_to_scope` set, a *public* target must additionally be in scope
/// (the normal wildcard-aware hostname match [`StdGuard::in_scope`] uses) or it
/// is refused `OutOfScope` — the scope-confined egress posture a scanner or
/// operator arms so the browser cannot be steered off-target. Confinement runs
/// only on the public branch; the private/loopback block and its rebinding
/// refusal are identical under either posture.
pub fn ssrf_check(
    policy: &crate::config::SsrfPolicy,
    scope: &[ScopeEntry],
    confine_to_scope: bool,
    authority: &str,
    dst: IpAddr,
) -> Result<(), GuardError> {
    let auth = Authority::parse_with_default(authority, 0).ok();
    let host = auth
        .as_ref()
        .map(|a| a.host.clone())
        .unwrap_or_else(|| authority.to_ascii_lowercase());

    let blocked = blocked_by_policy(classify_host(&host), policy)
        || blocked_by_policy(classify_ip(dst), policy);
    if !blocked {
        // Public target. In confined mode it must additionally be in scope. Match
        // the full requested `authority` (port included), exactly as
        // `StdGuard::in_scope` does, so a `host:port` scope entry is honored and an
        // unparseable authority never matches → deny by default. The refusal names
        // the full `authority`, not the bare host, so a port-mismatch refusal is
        // diagnosable (a host scoped only on another port is not silently blamed).
        if confine_to_scope && !scope.iter().any(|e| host_in_scope(authority, &e.host)) {
            return Err(GuardError::OutOfScope(authority.to_string()));
        }
        return Ok(());
    }

    // The block is lifted only by an *address* the operator scoped: the resolved
    // `dst` as an IP-literal entry, a `localhost` entry for a loopback dst, or a
    // requested authority that is itself this literal address / `localhost` and is
    // scoped. A scoped DNS *hostname* must NOT whitelist a private resolution —
    // otherwise an attacker scopes a public name they control and rebinds it to
    // 127.0.0.1 / 169.254.169.254 (DNS rebinding).
    let ip_auth = Authority::new(&dst.to_string(), dst_port(auth.as_ref()));
    let dst_loopback = matches!(classify_ip(dst), HostClass::Loopback);
    let auth_is_this_literal = auth
        .as_ref()
        .is_some_and(|a| a.ip() == Some(dst) || (a.host == "localhost" && dst_loopback));
    let lifted = policy.allow_if_in_scope
        && scope.iter().any(|e| {
            ip_auth.matches_scope_entry_exactly(&e.host)
                || (dst_loopback && e.host.trim().eq_ignore_ascii_case("localhost"))
                || (auth_is_this_literal
                    && auth
                        .as_ref()
                        .is_some_and(|a| a.matches_scope_entry_exactly(&e.host)))
        });
    if lifted {
        return Ok(());
    }

    // A scoped hostname that resolved to a private address is refused, not lifted:
    // warn so an operator who legitimately needs an internal host knows to scope
    // its IP literal instead.
    let scoped_name_resolved_private = auth.as_ref().is_some_and(|a| {
        a.ip().is_none()
            && a.host != "localhost"
            && scope.iter().any(|e| a.matches_scope_entry_exactly(&e.host))
    });
    if scoped_name_resolved_private {
        tracing::warn!(
            host = %host,
            dst = %dst,
            "scoped hostname resolved to a private/loopback address; refusing (possible DNS rebinding) — scope the IP literal to allow it"
        );
    }
    Err(GuardError::PrivateAddressBlocked(host))
}

fn dst_port(auth: Option<&Authority>) -> u16 {
    auth.map(|a| a.port).unwrap_or(0)
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
    host_errors: Mutex<HashMap<Authority, u32>>,
    backoff: crate::config::BackoffConfig,
    /// Per-host: how many times it has been disabled (drives exponential backoff).
    disable_count: Mutex<HashMap<Authority, u32>>,
    /// Per-host: the instant a disabled host becomes eligible again.
    disabled_until: Mutex<HashMap<Authority, Instant>>,
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
            backoff: limits.backoff,
            disable_count: Mutex::new(HashMap::new()),
            disabled_until: Mutex::new(HashMap::new()),
        }
    }

    /// The backoff duration for the `n`-th disable of a host (exponential,
    /// capped at `backoff.max`).
    fn backoff_for(&self, n: u32) -> Duration {
        let factor = self
            .backoff
            .factor
            .max(1.0)
            .powi(n.saturating_sub(1) as i32);
        // Clamp the (unbounded, possibly infinite) exponential to the cap
        // *before* converting: `Duration::from_secs_f64` panics on a value that
        // overflows `Duration`, and `disable_count` grows without bound, so a
        // host disabled enough times (~69 with the shipped defaults) would panic
        // the command task here — before the `.min(max)` cap could run.
        let max = self.backoff.max;
        let secs = (self.backoff.base.as_secs_f64() * factor).min(max.as_secs_f64());
        Duration::try_from_secs_f64(secs).unwrap_or(max).min(max)
    }

    /// Reconfigure the per-host rate at runtime (drives AC-P4: changing the
    /// `per_host_rps` option changes observed throttling). Existing per-host
    /// buckets are reset so the new rate takes effect immediately.
    pub fn set_per_host_rps(&self, rps: u32) {
        self.per_host_rps.store(rps, Ordering::SeqCst);
        self.host_buckets
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
    }

    /// Whether `authority` is inside a disable window. Windows are keyed on
    /// the [`Authority`] itself (host + port; port `0` is the host-wide window an
    /// unported `record_error` writes). An explicit port is one service:
    /// disabled when its own window or the host-wide one is live. An unported
    /// spelling is the host-wide view: disabled while any service on that host
    /// is, so a disabled target is not reachable under a spelling that drops
    /// the port. Expired windows are dropped on the way.
    fn is_disabled(&self, authority: &Authority) -> bool {
        if self.host_error_budget == 0 {
            return false;
        }
        let now = Instant::now();
        let mut windows = self
            .disabled_until
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        windows.retain(|_, until| now < *until);
        if authority.port == 0 {
            windows.keys().any(|key| key.host == authority.host)
        } else {
            windows.contains_key(authority)
                || windows.contains_key(&Authority {
                    host: authority.host.clone(),
                    port: 0,
                })
        }
    }
}

impl Default for StdGuard {
    fn default() -> Self {
        Self::new(LimitConfig::default())
    }
}

/// Normalize a scope entry so `scope.add` and `scope.remove` agree regardless of
/// surrounding whitespace or case (hosts are case-insensitive). Wildcards and
/// `host:port` forms are preserved, just trimmed and lowercased.
fn normalize_scope(entry: &str) -> String {
    entry.trim().to_ascii_lowercase()
}

/// Whether `host` (`host` or `host:port`) falls under scope entry `entry`
/// (exact, `host:port`, or `*.wildcard`). Parsing goes through [`Authority`] so
/// IPv6 and ports fold the same way the rest of the system keys on a target.
fn host_in_scope(host: &str, entry: &str) -> bool {
    match Authority::parse_with_default(host, 0) {
        Ok(a) => a.matches_scope_entry(entry),
        Err(_) => false,
    }
}

impl ScopeRateGuard for StdGuard {
    fn check_active(&self, host: &str) -> Result<ActionPermit, GuardError> {
        if !self.in_scope(host) {
            return Err(GuardError::OutOfScope(host.to_string()));
        }
        // The rate throttle is keyed on the *normalized* host (one bucket per
        // server, whatever the spelling); the error budget and the disable
        // window are keyed on the normalized `Authority` (host + port), because
        // two services on one address are two targets: a budget shared across
        // ports let one job's erroring target disable another job's target on
        // the same host (scanner v2 live run, 2026-11-02). `record_error` callers
        // pass the authority with its scheme's default port filled, so
        // `target.example`, `TARGET.example:443` and `Target.Example` share one
        // counter; an unported `check_active` is the host-wide view.
        let authority = match Authority::parse_with_default(host, 0) {
            Ok(a) => a,
            Err(_) => return Err(GuardError::OutOfScope(host.to_string())),
        };
        if self.is_disabled(&authority) {
            return Err(GuardError::HostDisabled);
        }
        let key = authority.host;

        // Global then per-host rate. A poisoned bucket lock is recovered (its
        // data is still valid) so a panic elsewhere cannot disable throttling.
        {
            let mut bucket = self
                .global_bucket
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if !bucket.try_take() {
                return Err(GuardError::RateLimited {
                    retry_after: bucket.retry_after(),
                });
            }
        }
        {
            let rps = self.per_host_rps.load(Ordering::SeqCst);
            // A zero per-host budget means refuse, not "one per second".
            if rps == 0 {
                return Err(GuardError::RateLimited {
                    retry_after: Duration::from_secs(1),
                });
            }
            let mut buckets = self
                .host_buckets
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            let bucket = buckets
                .entry(key.clone())
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
        let host = normalize_scope(&entry.host);
        let mut scope = self.scope.write().unwrap_or_else(PoisonError::into_inner);
        // Deduplicate so repeated adds do not grow the list unbounded, and so a
        // single remove fully drops the entry.
        if !scope.iter().any(|e| e.host == host) {
            scope.push(ScopeEntry { host });
        }
    }

    fn remove_scope(&self, entry: &str) -> bool {
        let want = normalize_scope(entry);
        let mut scope = self.scope.write().unwrap_or_else(PoisonError::into_inner);
        let before = scope.len();
        scope.retain(|e| e.host != want);
        scope.len() != before
    }

    fn list_scope(&self) -> Vec<ScopeEntry> {
        self.scope
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn in_scope(&self, host: &str) -> bool {
        // Recover from a poisoned lock rather than silently refusing/allowing:
        // deny-by-default still holds, every entry is still consulted. Same
        // normalized host matching `check_active` uses — no new matching logic.
        self.scope
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .any(|e| host_in_scope(host, &e.host))
    }

    /// Record an error. On reaching the per-host budget the host is disabled for
    /// a backoff window (exponential per disable); after the window it is eligible
    /// again. The error counter resets so the next budget triggers the next,
    /// longer, backoff.
    fn record_error(&self, host: &str) {
        if self.host_error_budget == 0 {
            return;
        }
        // Same normalized authority key as `check_active`'s disable check, so
        // the budget and disable window can't be evaded (or double-counted) by
        // spelling the host differently.
        // Port 0 (no port in the spelling) is the host-wide window.
        let key = match Authority::parse_with_default(host, 0) {
            Ok(a) => a,
            Err(_) => return,
        };
        let mut errors = self
            .host_errors
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let count = errors.entry(key.clone()).or_insert(0);
        *count += 1;
        if *count >= self.host_error_budget {
            *count = 0;
            drop(errors);
            let disables = {
                let mut d = self
                    .disable_count
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                let n = d.entry(key.clone()).or_insert(0);
                *n += 1;
                *n
            };
            let until = Instant::now() + self.backoff_for(disables);
            self.disabled_until
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .insert(key, until);
        }
    }
}

#[cfg(test)]
mod authority_key_tests {
    use super::*;

    /// Two services on one host are two targets: exhausting one's error budget
    /// disables that authority only, and the other is still served. (Before,
    /// the budget was keyed on the host alone and a full job against the
    /// vulnerable target on `127.0.0.1:a` disabled the patched one on
    /// `127.0.0.1:b` for the next job in the same core.)
    #[test]
    fn an_exhausted_error_budget_disables_that_authority_only() {
        let g = StdGuard::new(LimitConfig {
            per_host_rps: 1000,
            host_error_budget: 3,
            ..LimitConfig::default()
        });
        g.add_scope(ScopeEntry {
            host: "127.0.0.1".into(),
        });
        for _ in 0..3 {
            g.record_error("127.0.0.1:8001");
        }
        assert!(
            matches!(
                g.check_active("127.0.0.1:8001"),
                Err(GuardError::HostDisabled)
            ),
            "the erroring authority is disabled"
        );
        assert!(
            g.check_active("127.0.0.1:8002").is_ok(),
            "the other service on the same host is still served"
        );
        assert!(
            matches!(g.check_active("127.0.0.1"), Err(GuardError::HostDisabled)),
            "the unported spelling is the host-wide view: a disabled service makes it refused"
        );
    }

    /// An error charged under an unported spelling is host-wide: every port of
    /// that host is disabled (the pre-existing "disabled under every spelling"
    /// contract, in the direction `tests/guard.rs` does not cover).
    #[test]
    fn an_unported_disable_covers_every_port_of_the_host() {
        let g = StdGuard::new(LimitConfig {
            per_host_rps: 1000,
            host_error_budget: 1,
            ..LimitConfig::default()
        });
        g.add_scope(ScopeEntry {
            host: "target.example".into(),
        });
        g.record_error("target.example");
        for spelling in [
            "target.example:443",
            "target.example:8080",
            "target.example",
        ] {
            assert!(
                matches!(g.check_active(spelling), Err(GuardError::HostDisabled)),
                "{spelling} is disabled by the host-wide window"
            );
        }
    }

    /// IPv6 authorities key by host and port, never by a string prefix: `::1`
    /// and `::1:2` are different hosts, and a bracketed spelling folds to the
    /// same key as the unbracketed one.
    #[test]
    fn ipv6_authorities_are_keyed_by_host_and_port_not_by_prefix() {
        let g = StdGuard::new(LimitConfig {
            per_host_rps: 1000,
            host_error_budget: 1,
            ..LimitConfig::default()
        });
        g.add_scope(ScopeEntry {
            host: "[::1]".into(),
        });
        g.add_scope(ScopeEntry {
            host: "[::1:2]".into(),
        });
        g.record_error("[::1:2]:443");
        assert!(
            matches!(g.check_active("[::1:2]:443"), Err(GuardError::HostDisabled)),
            "the erroring IPv6 authority is disabled"
        );
        assert!(
            g.check_active("[::1]:443").is_ok() && g.check_active("[::1]").is_ok(),
            "a different IPv6 host that merely shares a prefix is still served"
        );
        g.record_error("[::1]:8443");
        assert!(
            matches!(g.check_active("[::1]:8443"), Err(GuardError::HostDisabled)),
            "a bracketed spelling folds to the same key"
        );
        assert!(
            g.check_active("[::1]:443").is_ok(),
            "another port of the same IPv6 host is a different service"
        );
    }
}

#[cfg(test)]
mod backoff_tests {
    use super::*;

    /// `backoff_for` must stay bounded by the cap for any disable count, never
    /// panicking in `Duration::from_secs_f64` when the exponential overflows a
    /// `Duration` (regression: the cap was applied only after the conversion).
    #[test]
    fn backoff_never_overflows_and_stays_capped() {
        let g = StdGuard::default();
        let max = g.backoff.max;
        for n in [1u32, 10, 69, 70, 128, 1000, u32::MAX] {
            let d = g.backoff_for(n);
            assert!(
                d <= max,
                "backoff for n={n} exceeded the cap: {d:?} > {max:?}"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The read-only `in_scope` predicate reflects the scope allowlist exactly: a
    /// scoped host is in scope, an unscoped host is not (deny-by-default).
    #[test]
    fn std_guard_in_scope_predicate() {
        let guard = StdGuard::default();
        guard.add_scope(ScopeEntry {
            host: "example.com".to_string(),
        });
        assert!(guard.in_scope("example.com"), "a scoped host is in scope");
        assert!(
            !guard.in_scope("evil.com"),
            "an unscoped host is out of scope (deny-by-default)"
        );
    }
}
