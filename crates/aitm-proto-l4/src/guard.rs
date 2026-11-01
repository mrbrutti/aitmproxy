//! The L4 authorization guard (M5 Tasks 4 + 5).
//!
//! [`L4Guard`] is the single, deny-by-default gate every wire-touching L4 action
//! passes before reaching the network: raw capture, crafted inject, send-and-
//! receive, and in-path mangling verdicts. It is intentionally **stronger** than
//! the core [`ScopeRateGuard`](aitm-core) (host-string + rps only): it matches on
//! interface + direction + CIDR + port, splits Capture / Inject / Intercept into
//! separate capabilities, enforces a dangerous-destination denylist, and meters
//! injection with per-entry and global token buckets plus packet size/count caps.
//!
//! The crate composes this guard with the core guard for defense in depth at the
//! command layer (M5 Task 9), where a resolved authority also passes
//! `CommandHost::guard().check_active(..)`; `L4Guard` itself is self-contained and
//! takes only an [`L4Config`].
//!
//! **One choke point.** The only key to the wire-write and mangling-verdict paths
//! is an [`L4Permit`], and the only way to mint one is [`L4Guard::check`]: the
//! permit's constructor is private to this module, so no sibling module can forge
//! one. A permit is an RAII token carrying a bounded send budget (size + count)
//! and an in-flight slot released on drop. There is no unchecked path.

use std::collections::{BTreeSet, HashMap};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::{Duration, Instant};

use crate::commands::scope::OperatorConfirmed;
use crate::config::L4Config;
use crate::craft::{PacketEndpoints, PacketSpec};
use crate::types::{
    IpCidr, L4Action, L4Capability, L4Proto, L4ScopeEntry, L4ScopeId, L4ScopeSource,
};

/// A typed refusal from the L4 guard. Every wire-touching action passes the guard
/// first; these are the ways it says no. Mirrors the core `GuardError` style
/// (hand-written `Display`/`Error`, no external derive crate).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum L4GuardError {
    /// No enabled scope entry matches the target's interface + direction + CIDR +
    /// port (deny-by-default).
    OutOfL4Scope(String),
    /// A scope entry matches the location, but none grants the requested
    /// capability (Capture / Inject / Intercept are separate).
    CapabilityNotGranted(L4Capability),
    /// The destination is on the dangerous-destination denylist (loopback,
    /// link-local, multicast/broadcast, cloud-metadata, unspecified) and no
    /// explicit scope entry covers it.
    DangerousDestinationBlocked(String),
    /// The per-entry or global injection rate ceiling was hit.
    InjectionRateExceeded {
        /// How long to wait before the next injection may succeed.
        retry_after: Duration,
    },
    /// A single packet exceeds `max_packet_bytes`.
    PacketTooLarge {
        /// The configured ceiling, in bytes.
        max: usize,
    },
    /// A command tried to emit more packets than `max_packets_per_call`.
    CountExceeded {
        /// The configured per-call ceiling.
        max: u32,
    },
    /// The L4 subsystem is unavailable (disabled, no privilege, libpcap/nfq
    /// absent, or OS-unsupported). Reserved here for downstream tasks.
    L4Unavailable(String),
    /// A runtime bus/MCP caller tried to widen the deny-by-default scope via
    /// `l4.scope.add` while `l4.allow_agent_widen` is false. The one escape hatch
    /// out of deny-by-default stays with the operator's config.
    ScopeWideningDisabled,
}

impl fmt::Display for L4GuardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            L4GuardError::OutOfL4Scope(t) => write!(f, "target {t} is out of L4 scope"),
            L4GuardError::CapabilityNotGranted(cap) => {
                write!(f, "scope matches but does not grant the {cap:?} capability")
            }
            L4GuardError::DangerousDestinationBlocked(dst) => write!(
                f,
                "destination {dst} is on the dangerous-destination denylist and not explicitly scoped"
            ),
            L4GuardError::InjectionRateExceeded { retry_after } => {
                write!(f, "injection rate exceeded; retry after {retry_after:?}")
            }
            L4GuardError::PacketTooLarge { max } => {
                write!(f, "packet exceeds the {max}-byte ceiling")
            }
            L4GuardError::CountExceeded { max } => {
                write!(f, "more than {max} packets in one call")
            }
            L4GuardError::L4Unavailable(why) => write!(f, "L4 unavailable: {why}"),
            L4GuardError::ScopeWideningDisabled => write!(
                f,
                "runtime L4 scope widening is disabled; declare scope in the `l4.scope` config \
                 block or set `l4.allow_agent_widen`"
            ),
        }
    }
}

impl std::error::Error for L4GuardError {}

/// An RAII authorization token: the only key to the wire-write and mangling-
/// verdict paths. It can be minted **only** by [`L4Guard::check`] (its
/// constructor is private to this module), carries a bounded send budget, and
/// releases its in-flight slot on drop.
pub struct L4Permit {
    /// What this permit authorizes.
    action: L4Action,
    /// Remaining packets this permit may still authorize in the call.
    remaining: u32,
    /// The original per-call budget, echoed in `CountExceeded`.
    budget: u32,
    /// Per-packet size ceiling.
    max_packet_bytes: usize,
    /// Per-packet injection rate metering: `Some` for an injection permit (one token
    /// spent per authorized packet), `None` for capture/interception permits, which
    /// consume no injection rate.
    rate: Option<RateSpender>,
    /// In-flight gauge, decremented on drop (RAII).
    in_flight: Arc<AtomicU32>,
}

impl L4Permit {
    /// Authorize one outgoing packet of `len` bytes against the permit's bounded
    /// budget. Returns, in order: [`L4GuardError::PacketTooLarge`] if the packet is
    /// over the size ceiling, [`L4GuardError::CountExceeded`] when the per-call
    /// budget is exhausted, [`L4GuardError::InjectionRateExceeded`] when the
    /// per-packet injection rate (per-entry or global) has no token left — none of
    /// which consume the per-call count slot; otherwise consumes one slot and
    /// succeeds.
    ///
    /// Called by the wire choke point (M5 Task 6) before every write, so one minted
    /// permit meters a whole batch: the count budget bounds the batch size and the
    /// rate buckets are spent **per packet**, making `inject_rate.pps` mean
    /// packets/sec rather than checks/sec.
    pub fn authorize_packet(&mut self, len: usize) -> Result<(), L4GuardError> {
        if len > self.max_packet_bytes {
            return Err(L4GuardError::PacketTooLarge {
                max: self.max_packet_bytes,
            });
        }
        if self.remaining == 0 {
            return Err(L4GuardError::CountExceeded { max: self.budget });
        }
        // Per-packet injection rate: spend one token (per-entry then global) before
        // this packet is admitted. Checked after the count budget so a count-exhausted
        // call wastes no rate token, and before the count is decremented so a
        // rate-refused packet consumes no count slot either.
        if let Some(rate) = &self.rate {
            rate.spend()?;
        }
        self.remaining -= 1;
        Ok(())
    }

    /// What this permit authorizes.
    #[must_use]
    pub fn action(&self) -> L4Action {
        self.action
    }

    /// Remaining packets this permit may still authorize.
    #[must_use]
    pub fn remaining(&self) -> u32 {
        self.remaining
    }
}

impl fmt::Debug for L4Permit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("L4Permit")
            .field("action", &self.action)
            .field("remaining", &self.remaining)
            .field("max_packet_bytes", &self.max_packet_bytes)
            .finish()
    }
}

impl Drop for L4Permit {
    fn drop(&mut self) {
        self.in_flight.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Per-packet injection-rate metering carried by an injection [`L4Permit`]. It holds
/// shared handles to the per-entry and tool-wide token buckets and spends one token
/// from each per authorized packet, so a batch threading one permit is metered
/// packet-by-packet (not once at `check` time).
struct RateSpender {
    /// The per-entry bucket for the scope entry that authorized this permit.
    entry: Arc<Mutex<TokenBucket>>,
    /// The tool-wide bucket, shared by every injection permit.
    global: Arc<Mutex<TokenBucket>>,
}

impl RateSpender {
    /// Spend one token from the per-entry bucket, then the tool-wide bucket. Returns
    /// [`L4GuardError::InjectionRateExceeded`] (carrying the limiting bucket's retry
    /// hint) the moment either bucket is empty.
    fn spend(&self) -> Result<(), L4GuardError> {
        {
            let mut entry = self.entry.lock().unwrap_or_else(PoisonError::into_inner);
            if !entry.try_take() {
                return Err(L4GuardError::InjectionRateExceeded {
                    retry_after: entry.retry_after(),
                });
            }
        }
        let mut global = self.global.lock().unwrap_or_else(PoisonError::into_inner);
        if !global.try_take() {
            return Err(L4GuardError::InjectionRateExceeded {
                retry_after: global.retry_after(),
            });
        }
        Ok(())
    }
}

/// A token bucket: `pps` tokens/sec refilling up to `capacity` (the burst).
struct TokenBucket {
    tokens: f64,
    capacity: f64,
    rate: f64,
    last: Instant,
}

impl TokenBucket {
    fn new(pps: u32, burst: u32) -> Self {
        let capacity = burst.max(1) as f64;
        Self {
            tokens: capacity,
            capacity,
            rate: f64::from(pps),
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

/// The deny-by-default L4 authorization guard.
pub struct L4Guard {
    scope: RwLock<Vec<L4ScopeEntry>>,
    /// Per-entry injection buckets, keyed by scope id. Shared (`Arc`) so an injection
    /// permit can spend a token per packet, not just once at `check` time.
    entry_buckets: Mutex<HashMap<L4ScopeId, Arc<Mutex<TokenBucket>>>>,
    /// Tool-wide injection bucket, shared with every injection permit.
    global_bucket: Arc<Mutex<TokenBucket>>,
    global_inject_pps: u32,
    max_packet_bytes: usize,
    max_packets_per_call: u32,
    /// Relaxes the dangerous-destination denylist to "any covering entry" instead
    /// of "an entry contained within the dangerous range"; it can never globally
    /// disable the denylist (an explicit covering entry is still required).
    dangerous_dst_override: bool,
    /// The shared per-capability agent gates (inject / capture / intercept / widen),
    /// seeded from `L4Config` (all default false). The guard owns the single instance
    /// so it is the one source of truth: the guard reads the **widen** gate here (SEC-2
    /// stays at the security boundary — not in a command wrapper — so no in-process
    /// caller of the shared guard can widen scope while the operator has it off), while
    /// the module shares this very `Arc` with the Mcp-only command wrapper and the
    /// operator-only `l4.agent.set`/`status`, so an operator toggle governs every
    /// enforcement point at once (a live, non-cosmetic switch).
    agent_gates: Arc<crate::gates::L4AgentGates>,
    in_flight: Arc<AtomicU32>,
    /// The core's **own** listener ports (proxy, embedded-browser proxy, loopback
    /// bus, web UI, MCP streamable HTTP), set by the binary once they are bound.
    /// A loopback frame to or from one of them is the core's own traffic — the
    /// bus's plaintext `{"token": …}` line among it — and is never recorded by a
    /// capture, whatever the scope says (L4PAR-AC34, spec §2.1). Empty until set.
    self_ports: RwLock<BTreeSet<u16>>,
}

impl L4Guard {
    /// Build a guard from config, seeding scope from `cfg.scope`.
    #[must_use]
    pub fn new(cfg: &L4Config) -> Self {
        Self {
            scope: RwLock::new(cfg.scope.clone()),
            entry_buckets: Mutex::new(HashMap::new()),
            global_bucket: Arc::new(Mutex::new(TokenBucket::new(
                cfg.global_inject_pps,
                cfg.global_inject_pps,
            ))),
            global_inject_pps: cfg.global_inject_pps,
            max_packet_bytes: cfg.max_packet_bytes,
            max_packets_per_call: cfg.max_packets_per_call,
            dangerous_dst_override: cfg.dangerous_dst_override,
            agent_gates: crate::gates::L4AgentGates::from_config(cfg),
            in_flight: Arc::new(AtomicU32::new(0)),
            self_ports: RwLock::new(BTreeSet::new()),
        }
    }

    /// Replace the set of the core's own listener ports (see `self_ports` on the
    /// struct). Port `0` is never a bound listener and is ignored, so a caller may
    /// pass a not-yet-bound ephemeral port through unchanged. Assembly uses this;
    /// the binary's later bind steps use [`add_self_ports`](Self::add_self_ports).
    pub fn set_self_ports(&self, ports: impl IntoIterator<Item = u16>) {
        let set: BTreeSet<u16> = ports.into_iter().filter(|p| *p != 0).collect();
        *self
            .self_ports
            .write()
            .unwrap_or_else(PoisonError::into_inner) = set;
    }

    /// Union `ports` into the core's own listener ports (port `0` ignored). The
    /// binary adds the listeners as they bind — the proxy / browser / web ports
    /// after the pre-bind, then the agent transport's port from `on_bound` — so
    /// no step can drop a port an earlier one recorded.
    pub fn add_self_ports(&self, ports: impl IntoIterator<Item = u16>) {
        self.self_ports
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .extend(ports.into_iter().filter(|p| *p != 0));
    }

    /// The core's own listener ports, ascending.
    #[must_use]
    pub fn self_ports(&self) -> Vec<u16> {
        self.self_ports
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .copied()
            .collect()
    }

    /// **The one choke point for self-exclusion** (spec §2.1, L4PAR-AC34). Whether
    /// a frame seen on `interface` may be recorded, parked or listed: it may
    /// **not** when it touches one of the core's own listener ports (source or
    /// destination) **and** either `interface` is a loopback interface by name
    /// (`lo`, `lo0`, …) or its source or destination is a loopback address. Every
    /// path that turns a wire frame into operator-visible state — the capture
    /// loop, the in-path reader, the send_recv reply capture — asks here first.
    /// Decodes with [`PacketSpec::endpoints`]; a frame without ports (ICMP, an
    /// undecodable buffer) carries nothing to refuse on and is admitted.
    #[must_use]
    pub fn admit_frame(&self, interface: &str, frame: &[u8]) -> bool {
        self.admit_endpoints(interface, &PacketSpec::endpoints(frame))
    }

    /// [`admit_frame`](Self::admit_frame) over an already-decoded frame, so a
    /// caller that needs the endpoints anyway decodes once.
    #[must_use]
    pub fn admit_endpoints(&self, interface: &str, ep: &PacketEndpoints) -> bool {
        if !self.touches_self_port(ep) {
            return true;
        }
        !(is_loopback_interface(interface) || has_loopback_addr(ep))
    }

    /// The BPF clause that keeps the core's own listener ports out of a capture
    /// on `interface` — the kernel-side first boundary
    /// ([`admit_frame`](Self::admit_frame) is the authoritative second): `not
    /// port P` for one self port, `not (port A or port B …)` ascending for
    /// several; `None` when there are none **or** `interface` is not a loopback
    /// interface, where a remote target may legitimately answer from a port
    /// number the core also happens to listen on locally. The capture ANDs it
    /// onto its scope filter; the send_recv reply capture opens with it.
    #[must_use]
    pub(crate) fn self_exclusion_bpf(&self, interface: &str) -> Option<String> {
        if !is_loopback_interface(interface) {
            return None;
        }
        let ports = self.self_ports();
        match ports.as_slice() {
            [] => None,
            [port] => Some(format!("not port {port}")),
            ports => Some(format!(
                "not ({})",
                ports
                    .iter()
                    .map(|p| format!("port {p}"))
                    .collect::<Vec<_>>()
                    .join(" or ")
            )),
        }
    }

    /// Whether `ep`'s source or destination port is one of the self ports.
    fn touches_self_port(&self, ep: &PacketEndpoints) -> bool {
        let set = self
            .self_ports
            .read()
            .unwrap_or_else(PoisonError::into_inner);
        ep.src_port
            .iter()
            .chain(ep.dst_port.iter())
            .any(|p| set.contains(p))
    }

    /// The shared per-capability agent gates (an `Arc` clone). The module hands this
    /// same object to the Mcp-only command wrapper and the `l4.agent.*` commands, so
    /// the widen gate the guard enforces here and the inject/capture/intercept gates
    /// the wrapper enforces are one live source of truth.
    #[must_use]
    pub fn agent_gates(&self) -> Arc<crate::gates::L4AgentGates> {
        self.agent_gates.clone()
    }

    /// The ONLY gate. Called before a capture/interception binds and before any
    /// packet is written to the wire or a mangling verdict is issued. Applies, in
    /// order: (1) scope + capability match, (2) dangerous-destination denylist,
    /// (3) for `Inject`, refuse up front if the per-entry or tool-wide rate is
    /// disabled (`pps == 0`), then mint an [`L4Permit`] carrying the bounded size +
    /// count budget and — for injection — a per-packet rate meter over the per-entry
    /// and tool-wide buckets. The size, count, and rate caps are spent **per packet**
    /// at [`L4Permit::authorize_packet`] time (the wire choke point), so a batch
    /// threading one permit is metered packet-by-packet. There is no unchecked path.
    pub fn check(&self, action: L4Action, target: &L4Target) -> Result<L4Permit, L4GuardError> {
        let want = capability_for(action);

        // Phase 1 (scope + capability) and phase 2 (denylist) read the scope; pull
        // out the chosen entry's id + rate and release the lock before metering.
        let (entry_id, inject_rate) = {
            let scope = self.scope.read().unwrap_or_else(PoisonError::into_inner);

            let location: Vec<&L4ScopeEntry> = scope
                .iter()
                .filter(|e| entry_matches_location(e, target))
                .collect();
            if location.is_empty() {
                return Err(L4GuardError::OutOfL4Scope(describe(target)));
            }
            let granting: Vec<&L4ScopeEntry> = location
                .into_iter()
                .filter(|e| e.capability == want)
                .collect();
            let chosen = match granting.first() {
                Some(e) => *e,
                None => return Err(L4GuardError::CapabilityNotGranted(want)),
            };

            // Phase 2: dangerous-destination denylist. A dangerous destination is
            // refused unless a granting entry is *contained within* the dangerous
            // range (an explicit, deliberate scope — not a broad catch-all). The
            // override relaxes "contained" to "covers", never to "nothing".
            //
            // Only a **config-declared** entry (operator authority) can lift the
            // denylist: a runtime bus `l4.scope.add` entry can never reach a
            // control-plane destination the operator did not declare, even with
            // `dangerous_dst_override` set. (SEC-2: deny-by-default's one escape
            // hatch stays with config.)
            if let Some(dst) = target.dst {
                if let Some((range_addr, range_prefix)) = danger_range(dst) {
                    let lifted = granting.iter().any(|e| {
                        e.source == L4ScopeSource::Config
                            && (self.dangerous_dst_override
                                || cidr_within(&e.cidr, range_addr, range_prefix))
                    });
                    if !lifted {
                        return Err(L4GuardError::DangerousDestinationBlocked(dst.to_string()));
                    }
                }
            }

            (chosen.id, chosen.inject_rate)
        };

        // Phase 3: rate metering applies to injection only (capture/interception bind
        // without consuming an injection budget). A disabled rate (`pps == 0`, per
        // entry or tool-wide) refuses up front — no permit. Otherwise the permit
        // carries a [`RateSpender`] over the per-entry + tool-wide buckets, and one
        // token is spent **per packet** at `authorize_packet` time, so `inject_rate.pps`
        // means packets/sec across the whole batch (not one token per `check`).
        let rate = if action == L4Action::Inject {
            if inject_rate.pps == 0 || self.global_inject_pps == 0 {
                return Err(L4GuardError::InjectionRateExceeded {
                    retry_after: Duration::from_secs(1),
                });
            }
            let entry_bucket = self
                .entry_buckets
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .entry(entry_id)
                .or_insert_with(|| {
                    Arc::new(Mutex::new(TokenBucket::new(
                        inject_rate.pps,
                        inject_rate.burst,
                    )))
                })
                .clone();
            Some(RateSpender {
                entry: entry_bucket,
                global: self.global_bucket.clone(),
            })
        } else {
            None
        };

        // Mint the permit (the only path that constructs one).
        self.in_flight.fetch_add(1, Ordering::SeqCst);
        Ok(L4Permit {
            action,
            remaining: self.max_packets_per_call,
            budget: self.max_packets_per_call,
            max_packet_bytes: self.max_packet_bytes,
            rate,
            in_flight: self.in_flight.clone(),
        })
    }

    /// Add a **runtime** (bus/MCP) scope entry — the one public widening path, and the
    /// place SEC-2 is enforced. It refuses with [`L4GuardError::ScopeWideningDisabled`]
    /// unless `allow_agent_widen` is set, and it forces `source = Runtime` so a runtime
    /// caller can never mint operator (`Config`) provenance — the provenance the
    /// dangerous-destination denylist trusts to be liftable. Because the gate and the
    /// forced provenance live in the guard, a second in-process caller of the shared
    /// guard cannot bypass them (the bug the command-wrapper-only check left open).
    /// Returns the entry's id.
    pub fn add_runtime_scope(&self, entry: L4ScopeEntry) -> Result<L4ScopeId, L4GuardError> {
        if !self.agent_gates.allowed(crate::gates::AgentGate::Widen) {
            return Err(L4GuardError::ScopeWideningDisabled);
        }
        Ok(self.push_runtime(entry))
    }

    /// Add a scope entry on behalf of a **confirmed operator** (spec §3, fork (ii)):
    /// the operator confirm-over-the-wire handshake (or the CLI's `Confirmer`) has
    /// already asked the human, so the agent **widen** gate — which means exactly
    /// "may the *agent* widen" — does not apply. The `_proof` argument is the
    /// [`OperatorConfirmed`] token only `commands::scope` can mint, so the compiler,
    /// not a source grep, guarantees no other in-process caller (Rhai, the PoC `l4:`
    /// step, a future command) reaches this ungated path. Like every runtime add it
    /// funnels through [`push_runtime`](Self::push_runtime), so the entry is stored
    /// as `Runtime` and never lifts the dangerous-destination denylist.
    pub(crate) fn add_operator_scope(
        &self,
        entry: L4ScopeEntry,
        _proof: OperatorConfirmed,
    ) -> L4ScopeId {
        self.push_runtime(entry)
    }

    /// The one funnel for both runtime add paths (agent-gated
    /// [`add_runtime_scope`](Self::add_runtime_scope) and operator-confirmed
    /// [`add_operator_scope`](Self::add_operator_scope)): forces `source = Runtime`
    /// so neither can mint operator (`Config`) provenance — the provenance the
    /// dangerous-destination denylist trusts to be liftable — then pushes.
    fn push_runtime(&self, mut entry: L4ScopeEntry) -> L4ScopeId {
        entry.source = L4ScopeSource::Runtime;
        self.push_scope(entry)
    }

    /// Seed a scope entry directly, trusting the caller's `source` — a **test-only**
    /// helper (production config scope is seeded straight into the list by
    /// [`L4Guard::new`]). A runtime widening path must go through
    /// [`add_runtime_scope`](L4Guard::add_runtime_scope), which enforces SEC-2.
    #[cfg(test)]
    pub(crate) fn add_scope(&self, entry: L4ScopeEntry) -> Result<L4ScopeId, L4GuardError> {
        Ok(self.push_scope(entry))
    }

    /// Push an entry onto the scope list; returns its id. The single mutation point
    /// both add paths funnel through.
    fn push_scope(&self, entry: L4ScopeEntry) -> L4ScopeId {
        let id = entry.id;
        self.scope
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .push(entry);
        id
    }

    /// Remove the scope entry with the given id; returns whether one was removed.
    pub fn remove_scope(&self, id: L4ScopeId) -> bool {
        let mut scope = self.scope.write().unwrap_or_else(PoisonError::into_inner);
        let before = scope.len();
        scope.retain(|e| e.id != id);
        let removed = scope.len() != before;
        drop(scope);
        if removed {
            self.entry_buckets
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .remove(&id);
        }
        removed
    }

    /// The current scope entries.
    #[must_use]
    pub fn list_scope(&self) -> Vec<L4ScopeEntry> {
        self.scope
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// The number of live (undropped) permits — the in-flight gauge the RAII
    /// permit maintains.
    #[must_use]
    pub fn in_flight(&self) -> u32 {
        self.in_flight.load(Ordering::SeqCst)
    }
}

/// The capability an action requests.
fn capability_for(action: L4Action) -> L4Capability {
    match action {
        L4Action::Capture => L4Capability::Capture,
        L4Action::Inject => L4Capability::Inject,
        L4Action::Intercept => L4Capability::Intercept,
    }
}

/// A short, human-readable name for a refused target (its destination, else its
/// interface).
fn describe(target: &L4Target) -> String {
    match target.dst {
        Some(ip) => ip.to_string(),
        None => target.interface.clone(),
    }
}

/// Whether a scope entry matches the target's *location* — interface + direction,
/// plus CIDR and (for Tcp/Udp) port when the target carries them. Capability is
/// checked separately so "no entry here" and "entry here, wrong capability" are
/// distinguishable.
fn entry_matches_location(entry: &L4ScopeEntry, target: &L4Target) -> bool {
    if entry.interface != target.interface || entry.direction != target.direction {
        return false;
    }
    if let Some(dst) = target.dst {
        if !cidr_contains(&entry.cidr, dst) {
            return false;
        }
    }
    if matches!(target.proto, L4Proto::Tcp | L4Proto::Udp) {
        if let Some(port) = target.dst_port {
            if port < entry.ports.lo || port > entry.ports.hi {
                return false;
            }
        }
    }
    true
}

fn mask_v4(bits: u32, prefix: u8) -> u32 {
    match prefix {
        0 => 0,
        p if p >= 32 => bits,
        p => bits & (!0u32 << (32 - p)),
    }
}

fn mask_v6(bits: u128, prefix: u8) -> u128 {
    match prefix {
        0 => 0,
        p if p >= 128 => bits,
        p => bits & (!0u128 << (128 - p)),
    }
}

/// Whether `ip` falls inside `cidr` (same family required).
fn cidr_contains(cidr: &IpCidr, ip: IpAddr) -> bool {
    match (cidr.addr, ip) {
        (IpAddr::V4(net), IpAddr::V4(host)) => {
            mask_v4(host.into(), cidr.prefix) == mask_v4(net.into(), cidr.prefix)
        }
        (IpAddr::V6(net), IpAddr::V6(host)) => {
            mask_v6(host.into(), cidr.prefix) == mask_v6(net.into(), cidr.prefix)
        }
        _ => false,
    }
}

/// Whether `cidr` is fully contained within the block `outer_addr`/`outer_prefix`
/// — i.e. the operator scoped specifically into (not merely across) that block.
fn cidr_within(cidr: &IpCidr, outer_addr: IpAddr, outer_prefix: u8) -> bool {
    if cidr.prefix < outer_prefix {
        return false;
    }
    match (cidr.addr, outer_addr) {
        (IpAddr::V4(net), IpAddr::V4(outer)) => {
            mask_v4(net.into(), outer_prefix) == mask_v4(outer.into(), outer_prefix)
        }
        (IpAddr::V6(net), IpAddr::V6(outer)) => {
            mask_v6(net.into(), outer_prefix) == mask_v6(outer.into(), outer_prefix)
        }
        _ => false,
    }
}

/// Whether `interface` is a loopback interface by name: `lo` (Linux) or
/// `lo<digits>` (`lo0` on macOS and the BSDs). One of the two tests
/// [`L4Guard::admit_frame`] applies; [`L4Guard::self_exclusion_bpf`] uses it too.
#[must_use]
pub(crate) fn is_loopback_interface(interface: &str) -> bool {
    interface
        .strip_prefix("lo")
        .is_some_and(|rest| rest.chars().all(|c| c.is_ascii_digit()))
}

/// Whether `ep`'s source or destination is a loopback address (an IPv4-mapped
/// `::ffff:127.0.0.1` included).
fn has_loopback_addr(ep: &PacketEndpoints) -> bool {
    ep.src
        .iter()
        .chain(ep.dst.iter())
        .any(|ip| ip.to_canonical().is_loopback())
}

/// The dangerous-destination block governing `ip`, if any: loopback, link-local
/// (incl. cloud metadata `169.254.169.254`), unspecified/this-network, multicast,
/// and reserved/broadcast. RFC1918 private ranges are deliberately **not** here —
/// an L4 robustness test legitimately drives a private LAN target; it is loopback
/// and control-plane addresses that must be deliberately scoped.
fn danger_range(ip: IpAddr) -> Option<(IpAddr, u8)> {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            if o[0] == 127 {
                Some((IpAddr::V4(Ipv4Addr::new(127, 0, 0, 0)), 8))
            } else if o[0] == 169 && o[1] == 254 {
                Some((IpAddr::V4(Ipv4Addr::new(169, 254, 0, 0)), 16))
            } else if o[0] == 0 {
                Some((IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 8))
            } else if (224..=239).contains(&o[0]) {
                Some((IpAddr::V4(Ipv4Addr::new(224, 0, 0, 0)), 4))
            } else if o[0] >= 240 {
                // 240.0.0.0/4 reserved, incl. 255.255.255.255 limited broadcast.
                Some((IpAddr::V4(Ipv4Addr::new(240, 0, 0, 0)), 4))
            } else {
                None
            }
        }
        IpAddr::V6(v6) => {
            // An IPv4-mapped (`::ffff:a.b.c.d`) or NAT64 (`64:ff9b::/96`) address
            // routes to the embedded IPv4, so classify that: otherwise the v4
            // control-plane denylist (loopback, 169.254 metadata, ...) is
            // bypassable by sending the v6 form of the same target. Report the
            // block in v6 space (the v4 prefix shifted into the low 32 bits) so
            // a config scope override declared against the v6 dst still lifts it.
            if let Some(v4) = mapped_ipv4_dst(v6) {
                if let Some((IpAddr::V4(net), p4)) = danger_range(IpAddr::V4(v4)) {
                    let mut seg = v6.segments();
                    let n = net.octets();
                    seg[6] = u16::from_be_bytes([n[0], n[1]]);
                    seg[7] = u16::from_be_bytes([n[2], n[3]]);
                    return Some((IpAddr::V6(Ipv6Addr::from(seg)), 96 + p4));
                }
            }
            if v6.is_loopback() {
                Some((IpAddr::V6(Ipv6Addr::LOCALHOST), 128))
            } else if v6.is_unspecified() {
                Some((IpAddr::V6(Ipv6Addr::UNSPECIFIED), 128))
            } else {
                let seg0 = v6.segments()[0];
                if (seg0 & 0xffc0) == 0xfe80 {
                    Some((IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0)), 10))
                } else if (seg0 & 0xff00) == 0xff00 {
                    Some((IpAddr::V6(Ipv6Addr::new(0xff00, 0, 0, 0, 0, 0, 0, 0)), 8))
                } else {
                    None
                }
            }
        }
    }
}

/// The embedded IPv4 of an IPv4-mapped (`::ffff:a.b.c.d`) or NAT64
/// (`64:ff9b::/96`) IPv6 address — both of which route to that v4 destination.
fn mapped_ipv4_dst(v6: Ipv6Addr) -> Option<Ipv4Addr> {
    if let Some(v4) = v6.to_ipv4_mapped() {
        return Some(v4);
    }
    let s = v6.segments();
    if s[0] == 0x0064 && s[1] == 0xff9b && s[2..6].iter().all(|&x| x == 0) {
        let hi = s[6].to_be_bytes();
        let lo = s[7].to_be_bytes();
        return Some(Ipv4Addr::new(hi[0], hi[1], lo[0], lo[1]));
    }
    None
}

/// The target of a guard check — resolved from a capture/interception bind or a
/// decoded packet.
pub type L4Target = crate::types::L4Target;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{L4Direction, L4ScopeSource, PortRange, RateCap};

    /// An IPv4-mapped or NAT64 IPv6 destination must be classified by its
    /// embedded IPv4, so the v4 control-plane denylist cannot be bypassed by
    /// sending the v6 form of the same target.
    #[test]
    fn mapped_and_nat64_dangerous_v4_are_blocked() {
        let m = |s: &str| danger_range(s.parse::<IpAddr>().unwrap());
        // IPv4-mapped forms of dangerous v4 targets.
        assert!(m("::ffff:169.254.169.254").is_some(), "mapped metadata");
        assert!(m("::ffff:127.0.0.1").is_some(), "mapped loopback");
        assert!(m("::ffff:0.0.0.0").is_some(), "mapped unspecified");
        // NAT64 well-known prefix form.
        assert!(m("64:ff9b::169.254.169.254").is_some(), "nat64 metadata");
        // A mapped *public* address is not blocked (and neither is a public v6).
        assert!(m("::ffff:93.184.216.34").is_none(), "mapped public v4");
        assert!(
            m("2606:2800:220:1:248:1893:25c8:1946").is_none(),
            "public v6"
        );
        // The reported block stays in v6 space so a v6 scope override can match.
        if let Some((addr, prefix)) = m("::ffff:169.254.169.254") {
            assert!(matches!(addr, IpAddr::V6(_)), "block reported in v6 space");
            assert_eq!(prefix, 96 + 16, "169.254.0.0/16 mapped to a /112");
        }
    }

    /// L4PAR-AC34 (plan A10): the self-port set is replaced on each `set`,
    /// read back ascending, ignores port 0 (never a bound listener), and on a
    /// **non-loopback** interface name (`en0`, so only the address test can
    /// fire) `admit_endpoints` refuses exactly a loopback-addressed frame whose
    /// src **or** dst port is in the set.
    #[test]
    fn self_ports_and_admit_endpoints_by_address() {
        use crate::craft::PacketEndpoints;
        let g = L4Guard::new(&cfg());
        assert!(
            g.self_ports().is_empty(),
            "no self ports until the binary sets them"
        );

        g.set_self_ports([28182, 27431, 27431, 0]);
        assert_eq!(g.self_ports(), vec![27431, 28182]);

        let ep = |src: &str, src_port: u16, dst: &str, dst_port: u16| PacketEndpoints {
            proto: Some(L4Proto::Tcp),
            src: Some(src.parse().unwrap()),
            dst: Some(dst.parse().unwrap()),
            src_port: Some(src_port),
            dst_port: Some(dst_port),
        };
        assert!(!g.admit_endpoints("en0", &ep("127.0.0.1", 51000, "127.0.0.1", 27431)));
        assert!(!g.admit_endpoints("en0", &ep("127.0.0.1", 27431, "127.0.0.1", 51000)));
        assert!(!g.admit_endpoints("en0", &ep("::1", 51000, "::1", 28182)));
        assert!(
            g.admit_endpoints("en0", &ep("127.0.0.1", 51000, "127.0.0.1", 9099)),
            "a loopback frame to a non-self port is not the core's own traffic"
        );
        assert!(
            g.admit_endpoints("en0", &ep("10.0.0.5", 51000, "10.0.0.9", 27431)),
            "a non-loopback frame on a real NIC is never self traffic, whatever its ports"
        );
        assert!(g.admit_endpoints("en0", &PacketEndpoints::default()));

        g.set_self_ports([9]);
        assert_eq!(g.self_ports(), vec![9], "set replaces, it does not union");
        assert!(g.admit_endpoints("en0", &ep("127.0.0.1", 51000, "127.0.0.1", 27431)));
    }

    /// L4PAR-AC34 (tester): `admit_endpoints` address edge cases on a non-loopback
    /// interface name. An IPv4-mapped IPv6 loopback (`::ffff:127.0.0.1`) is
    /// loopback; a frame with only one loopback side still counts; UDP is covered
    /// like TCP; a frame with no ports (ICMP, or an undecodable transport) is never
    /// self traffic; the empty set excludes nothing.
    #[test]
    fn admit_endpoints_address_edge_cases() {
        use crate::craft::PacketEndpoints;
        let g = L4Guard::new(&cfg());
        let ep = |proto: L4Proto, src: &str, sp: Option<u16>, dst: &str, dp: Option<u16>| {
            PacketEndpoints {
                proto: Some(proto),
                src: Some(src.parse().unwrap()),
                dst: Some(dst.parse().unwrap()),
                src_port: sp,
                dst_port: dp,
            }
        };
        let bus = ep(
            L4Proto::Tcp,
            "127.0.0.1",
            Some(51000),
            "127.0.0.1",
            Some(27431),
        );
        assert!(
            g.admit_endpoints("en0", &bus),
            "an empty self-port set excludes nothing"
        );

        g.set_self_ports([27431]);
        assert!(!g.admit_endpoints("en0", &bus));
        assert!(!g.admit_endpoints(
            "en0",
            &ep(
                L4Proto::Tcp,
                "::ffff:127.0.0.1",
                Some(51000),
                "::ffff:127.0.0.1",
                Some(27431)
            )
        ));
        assert!(!g.admit_endpoints(
            "en0",
            &ep(
                L4Proto::Udp,
                "127.0.0.1",
                Some(27431),
                "127.0.0.1",
                Some(51000)
            )
        ));
        assert!(
            !g.admit_endpoints(
                "en0",
                &ep(
                    L4Proto::Tcp,
                    "10.0.0.5",
                    Some(51000),
                    "127.0.0.1",
                    Some(27431)
                )
            ),
            "one loopback side is enough"
        );
        assert!(!g.admit_endpoints(
            "en0",
            &ep(
                L4Proto::Tcp,
                "127.0.0.2",
                Some(51000),
                "127.0.0.9",
                Some(27431)
            )
        ));
        assert!(
            g.admit_endpoints(
                "en0",
                &ep(L4Proto::Icmp, "127.0.0.1", None, "127.0.0.1", None)
            ),
            "no ports, no self traffic"
        );
        assert!(
            g.admit_endpoints(
                "en0",
                &ep(
                    L4Proto::Tcp,
                    "::ffff:10.0.0.5",
                    Some(51000),
                    "::ffff:10.0.0.9",
                    Some(27431)
                )
            ),
            "a mapped non-loopback address is not loopback"
        );

        g.set_self_ports(std::iter::empty());
        assert!(g.self_ports().is_empty(), "set to empty clears the set");
        assert!(g.admit_endpoints("en0", &bus));
    }

    /// A crafted TCP frame `src:sp → dst:dp` (IPv4 or IPv6 by address family)
    /// carrying a bus-shaped token line — the frame an agent must never read.
    fn tcp_frame(src: &str, sp: u16, dst: &str, dp: u16) -> Vec<u8> {
        use crate::craft::{Ipv4Spec, Ipv6Spec, Layer, PacketSpec, TcpSpec};
        let src: IpAddr = src.parse().unwrap();
        let dst: IpAddr = dst.parse().unwrap();
        let net = match (src, dst) {
            (IpAddr::V4(s), IpAddr::V4(d)) => Layer::Ipv4(Ipv4Spec {
                src: Some(s),
                dst: Some(d),
                ..Ipv4Spec::default()
            }),
            (IpAddr::V6(s), IpAddr::V6(d)) => Layer::Ipv6(Ipv6Spec {
                src: Some(s),
                dst: Some(d),
                ..Ipv6Spec::default()
            }),
            _ => panic!("one address family per frame"),
        };
        PacketSpec {
            layers: vec![
                net,
                Layer::Tcp(TcpSpec {
                    src_port: Some(sp),
                    dst_port: Some(dp),
                    ..TcpSpec::default()
                }),
                Layer::Raw(b"{\"token\": \"not-for-agents\"}\n".to_vec()),
            ],
        }
        .build()
        .expect("craft builds")
    }

    /// Security fix (spec §2.1, L4PAR-AC34): `admit_frame` is the one choke point
    /// for self-exclusion. A frame that touches a self port is refused when the
    /// interface is a loopback interface **by name** (`lo`, `lo0`) **or** its
    /// source/destination is a loopback address (`127.0.0.1`, `::1`); an
    /// in-scope frame to 9099 is admitted; a LAN frame to the same port number on
    /// a real NIC is not the core's traffic.
    #[test]
    fn admit_frame_refuses_self_port_frames_on_loopback() {
        let g = L4Guard::new(&cfg());
        g.set_self_ports([27431]);
        let bus_v4 = tcp_frame("127.0.0.1", 51000, "127.0.0.1", 27431);
        let bus_v4_rev = tcp_frame("127.0.0.1", 27431, "127.0.0.1", 51000);
        let bus_v6 = tcp_frame("::1", 51000, "::1", 27431);

        // Loopback by interface name (and by address, both hold here).
        for iface in ["lo0", "lo", "lo1"] {
            assert!(
                !g.admit_frame(iface, &bus_v4),
                "{iface}: a loopback frame to the bus port is refused"
            );
            assert!(
                !g.admit_frame(iface, &bus_v4_rev),
                "{iface}: a loopback frame from the bus port is refused"
            );
            assert!(
                !g.admit_frame(iface, &bus_v6),
                "{iface}: ::1 is loopback too"
            );
        }
        // Loopback by address only: the interface name is not loopback.
        assert!(
            !g.admit_frame("en0", &bus_v4),
            "127.0.0.1 ↔ the bus port on en0 is refused by address"
        );
        assert!(
            !g.admit_frame("en0", &bus_v6),
            "::1 ↔ the bus port on en0 is refused by address"
        );
        // Loopback by name only: non-loopback addresses on `lo0` are still refused.
        let lan_to_bus_port = tcp_frame("10.0.0.5", 51000, "10.0.0.9", 27431);
        assert!(
            !g.admit_frame("lo0", &lan_to_bus_port),
            "a frame on lo0 touching the bus port is refused whatever its addresses"
        );
        // Neither: a LAN frame to port 27431 on a real NIC is someone else's.
        assert!(
            g.admit_frame("en0", &lan_to_bus_port),
            "a LAN frame to port 27431 on en0 is not the core's traffic"
        );
        // In scope: a loopback frame to 9099 is admitted.
        assert!(g.admit_frame("lo0", &tcp_frame("127.0.0.1", 51000, "127.0.0.1", 9099)));
        // No ports / undecodable / empty: nothing to refuse on, admitted.
        assert!(g.admit_frame("lo0", &[0xde, 0xad]));
        assert!(g.admit_frame("lo0", &[]));
        // The empty set excludes nothing.
        g.set_self_ports(std::iter::empty());
        assert!(g.admit_frame("lo0", &bus_v4));
    }

    /// `add_self_ports` unions into the set (ignoring port 0); `set_self_ports`
    /// still replaces. The binary adds the bound listener ports one step at a
    /// time (post-bind, then `on_bound`) without losing assembly's set.
    #[test]
    fn add_self_ports_unions() {
        let g = L4Guard::new(&cfg());
        g.set_self_ports([28182]);
        g.add_self_ports([27431, 0, 28182]);
        assert_eq!(g.self_ports(), vec![27431, 28182]);
        g.add_self_ports([9]);
        assert_eq!(g.self_ports(), vec![9, 27431, 28182]);
        g.set_self_ports([1]);
        assert_eq!(g.self_ports(), vec![1], "set still replaces");
    }

    /// The BPF self-exclusion clause the capture (and the send_recv reply
    /// capture) AND into their filters on a loopback interface: `None` with no
    /// self ports, `not port P` for one, `not (port A or port B)` ascending for
    /// several; `None` on a non-loopback interface whatever the set, since a
    /// remote target may answer from a port number the core also listens on.
    #[test]
    fn self_exclusion_bpf_clause() {
        let g = L4Guard::new(&cfg());
        assert_eq!(g.self_exclusion_bpf("lo0"), None);
        g.set_self_ports([27431]);
        assert_eq!(
            g.self_exclusion_bpf("lo0"),
            Some("not port 27431".to_string())
        );
        assert_eq!(
            g.self_exclusion_bpf("lo"),
            Some("not port 27431".to_string())
        );
        g.set_self_ports([28182, 27431]);
        assert_eq!(
            g.self_exclusion_bpf("lo0"),
            Some("not (port 27431 or port 28182)".to_string())
        );
        for nic in ["en0", "eth0", "utun3", ""] {
            assert_eq!(g.self_exclusion_bpf(nic), None, "{nic:?} is not loopback");
        }
    }

    /// L4PAR-AC34 (tester): which interface names count as loopback.
    #[test]
    fn loopback_interface_names() {
        for yes in ["lo", "lo0", "lo1", "lo10"] {
            assert!(is_loopback_interface(yes), "{yes} is loopback");
        }
        for no in [
            "", "l", "lo0x", "low", "lo-1", "eth0", "en0", "utun3", "mock0",
        ] {
            assert!(!is_loopback_interface(no), "{no:?} is not loopback");
        }
    }

    fn cfg() -> L4Config {
        L4Config::default()
    }

    fn entry(
        cidr: (&str, u8),
        iface: &str,
        dir: L4Direction,
        cap: L4Capability,
        rate: (u32, u32),
    ) -> L4ScopeEntry {
        L4ScopeEntry {
            id: L4ScopeId::new(),
            cidr: IpCidr {
                addr: cidr.0.parse().unwrap(),
                prefix: cidr.1,
            },
            ports: PortRange { lo: 0, hi: 65535 },
            interface: iface.to_string(),
            direction: dir,
            capability: cap,
            inject_rate: RateCap {
                pps: rate.0,
                burst: rate.1,
            },
            source: L4ScopeSource::Config,
        }
    }

    fn target(iface: &str, dir: L4Direction, dst: &str, port: u16) -> L4Target {
        L4Target {
            interface: iface.to_string(),
            direction: dir,
            dst: Some(dst.parse().unwrap()),
            dst_port: Some(port),
            proto: L4Proto::Tcp,
        }
    }

    /// AC1 — empty scope refuses every action with `OutOfL4Scope`, including the
    /// capture/interception binds.
    #[test]
    fn empty_scope_refuses() {
        let g = L4Guard::new(&cfg());
        let t = target("lo0", L4Direction::Outbound, "127.0.0.1", 1234);
        assert_eq!(
            g.check(L4Action::Inject, &t).unwrap_err(),
            L4GuardError::OutOfL4Scope("127.0.0.1".into())
        );
        assert!(matches!(
            g.check(L4Action::Capture, &t),
            Err(L4GuardError::OutOfL4Scope(_))
        ));
        assert!(matches!(
            g.check(L4Action::Intercept, &t),
            Err(L4GuardError::OutOfL4Scope(_))
        ));
    }

    /// AC2 — in-scope (explicit loopback) inject succeeds.
    #[test]
    fn in_scope_ok() {
        let g = L4Guard::new(&cfg());
        g.add_scope(entry(
            ("127.0.0.1", 32),
            "lo0",
            L4Direction::Outbound,
            L4Capability::Inject,
            (100, 100),
        ))
        .unwrap();
        let t = target("lo0", L4Direction::Outbound, "127.0.0.1", 1234);
        assert!(g.check(L4Action::Inject, &t).is_ok());
    }

    /// AC2 — injecting to a public address outside the scoped CIDR is refused.
    #[test]
    fn out_of_scope_inject_refused() {
        let g = L4Guard::new(&cfg());
        g.add_scope(entry(
            ("10.0.0.0", 8),
            "eth0",
            L4Direction::Outbound,
            L4Capability::Inject,
            (100, 100),
        ))
        .unwrap();
        let t = target("eth0", L4Direction::Outbound, "8.8.8.8", 443);
        assert_eq!(
            g.check(L4Action::Inject, &t).unwrap_err(),
            L4GuardError::OutOfL4Scope("8.8.8.8".into())
        );
    }

    /// AC3 — Capture / Inject / Intercept are separate capabilities: a
    /// Capture-only entry grants capture but refuses inject and intercept.
    #[test]
    fn capability_split() {
        let g = L4Guard::new(&cfg());
        g.add_scope(entry(
            ("127.0.0.1", 32),
            "lo0",
            L4Direction::Outbound,
            L4Capability::Capture,
            (100, 100),
        ))
        .unwrap();
        let t = target("lo0", L4Direction::Outbound, "127.0.0.1", 1234);
        assert_eq!(
            g.check(L4Action::Inject, &t).unwrap_err(),
            L4GuardError::CapabilityNotGranted(L4Capability::Inject)
        );
        assert_eq!(
            g.check(L4Action::Intercept, &t).unwrap_err(),
            L4GuardError::CapabilityNotGranted(L4Capability::Intercept)
        );
        assert!(g.check(L4Action::Capture, &t).is_ok());
    }

    /// AC4 — a dangerous destination (cloud metadata) covered only by a broad,
    /// non-specific entry is still blocked by the denylist.
    #[test]
    fn denylist() {
        let g = L4Guard::new(&cfg());
        g.add_scope(entry(
            ("0.0.0.0", 0),
            "eth0",
            L4Direction::Outbound,
            L4Capability::Inject,
            (100, 100),
        ))
        .unwrap();
        let t = target("eth0", L4Direction::Outbound, "169.254.169.254", 80);
        assert_eq!(
            g.check(L4Action::Inject, &t).unwrap_err(),
            L4GuardError::DangerousDestinationBlocked("169.254.169.254".into())
        );
    }

    /// AC4 — an explicit entry contained within the dangerous range is the way
    /// through the denylist.
    #[test]
    fn denylist_explicit_entry_lifts() {
        let g = L4Guard::new(&cfg());
        g.add_scope(entry(
            ("169.254.169.254", 32),
            "eth0",
            L4Direction::Outbound,
            L4Capability::Inject,
            (100, 100),
        ))
        .unwrap();
        let t = target("eth0", L4Direction::Outbound, "169.254.169.254", 80);
        assert!(g.check(L4Action::Inject, &t).is_ok());
    }

    /// AC5 — rate is metered **per packet**: with `inject_rate` N pps the (N+1)-th
    /// packet authorized against one permit is refused with `InjectionRateExceeded`.
    /// (Minting the permit via `check` consumes no token; the tokens are spent at
    /// `authorize_packet` time, so `pps` means packets/sec, not checks/sec.)
    #[test]
    fn rate_cap_trips() {
        let g = L4Guard::new(&cfg());
        g.add_scope(entry(
            ("127.0.0.1", 32),
            "lo0",
            L4Direction::Outbound,
            L4Capability::Inject,
            (2, 2),
        ))
        .unwrap();
        let t = target("lo0", L4Direction::Outbound, "127.0.0.1", 1234);
        let mut permit = g
            .check(L4Action::Inject, &t)
            .expect("mint injection permit");
        assert!(permit.authorize_packet(64).is_ok());
        assert!(permit.authorize_packet(64).is_ok());
        assert!(matches!(
            permit.authorize_packet(64),
            Err(L4GuardError::InjectionRateExceeded { .. })
        ));
    }

    /// AC5 (per-packet) — a *second* permit minted after the bucket is drained also
    /// sees the exhaustion, proving the rate state is shared across permits (the bug
    /// the panel caught: one `check` must not grant a fresh batch of `pps` writes).
    #[test]
    fn rate_cap_shared_across_permits() {
        let g = L4Guard::new(&cfg());
        g.add_scope(entry(
            ("127.0.0.1", 32),
            "lo0",
            L4Direction::Outbound,
            L4Capability::Inject,
            (2, 2),
        ))
        .unwrap();
        let t = target("lo0", L4Direction::Outbound, "127.0.0.1", 1234);
        // Drain the two-token bucket through the first permit.
        let mut first = g.check(L4Action::Inject, &t).unwrap();
        assert!(first.authorize_packet(64).is_ok());
        assert!(first.authorize_packet(64).is_ok());
        // A second permit cannot conjure more budget: the shared bucket is empty.
        let mut second = g.check(L4Action::Inject, &t).unwrap();
        assert!(matches!(
            second.authorize_packet(64),
            Err(L4GuardError::InjectionRateExceeded { .. })
        ));
    }

    /// AC5 — a per-entry rate of 0 pps means refuse, not "one per second".
    #[test]
    fn rate_zero_refuses() {
        let g = L4Guard::new(&cfg());
        g.add_scope(entry(
            ("127.0.0.1", 32),
            "lo0",
            L4Direction::Outbound,
            L4Capability::Inject,
            (0, 0),
        ))
        .unwrap();
        let t = target("lo0", L4Direction::Outbound, "127.0.0.1", 1234);
        assert!(matches!(
            g.check(L4Action::Inject, &t),
            Err(L4GuardError::InjectionRateExceeded { .. })
        ));
    }

    /// AC6 — a packet over `max_packet_bytes` is refused with `PacketTooLarge`.
    #[test]
    fn oversize() {
        let mut c = cfg();
        c.max_packet_bytes = 1500;
        let g = L4Guard::new(&c);
        g.add_scope(entry(
            ("127.0.0.1", 32),
            "lo0",
            L4Direction::Outbound,
            L4Capability::Inject,
            (100, 100),
        ))
        .unwrap();
        let t = target("lo0", L4Direction::Outbound, "127.0.0.1", 1234);
        let mut permit = g.check(L4Action::Inject, &t).unwrap();
        assert_eq!(
            permit.authorize_packet(1501),
            Err(L4GuardError::PacketTooLarge { max: 1500 })
        );
        // A refused oversize packet consumes no budget.
        assert!(permit.authorize_packet(1500).is_ok());
    }

    /// AC6 — more packets than `max_packets_per_call` is refused with
    /// `CountExceeded`.
    #[test]
    fn count() {
        let mut c = cfg();
        c.max_packets_per_call = 2;
        let g = L4Guard::new(&c);
        g.add_scope(entry(
            ("127.0.0.1", 32),
            "lo0",
            L4Direction::Outbound,
            L4Capability::Inject,
            (100, 100),
        ))
        .unwrap();
        let t = target("lo0", L4Direction::Outbound, "127.0.0.1", 1234);
        let mut permit = g.check(L4Action::Inject, &t).unwrap();
        assert!(permit.authorize_packet(100).is_ok());
        assert!(permit.authorize_packet(100).is_ok());
        assert_eq!(
            permit.authorize_packet(100),
            Err(L4GuardError::CountExceeded { max: 2 })
        );
    }

    /// AC21 — the permit is RAII: it holds an in-flight slot that is released when
    /// it drops.
    #[test]
    fn permit_releases_slot_on_drop() {
        let g = L4Guard::new(&cfg());
        g.add_scope(entry(
            ("127.0.0.1", 32),
            "lo0",
            L4Direction::Outbound,
            L4Capability::Inject,
            (100, 100),
        ))
        .unwrap();
        let t = target("lo0", L4Direction::Outbound, "127.0.0.1", 1234);
        assert_eq!(g.in_flight(), 0);
        let permit = g.check(L4Action::Inject, &t).unwrap();
        assert_eq!(g.in_flight(), 1);
        drop(permit);
        assert_eq!(g.in_flight(), 0);
    }

    /// SEC-2 — a RUNTIME-sourced scope entry can never lift the dangerous-
    /// destination denylist, even with `dangerous_dst_override` set, while a
    /// CONFIG-sourced entry covering the same address does. This is the structural
    /// guarantee that an unauthenticated bus `l4.scope.add` cannot self-authorize a
    /// control-plane destination the operator did not declare.
    #[test]
    fn runtime_entry_cannot_lift_denylist() {
        let mut c = cfg();
        c.dangerous_dst_override = true;
        let g = L4Guard::new(&c);
        let t = target("eth0", L4Direction::Outbound, "169.254.169.254", 80);

        // A runtime-added /32 entry covering the cloud-metadata address does NOT
        // lift the denylist, override notwithstanding.
        let mut runtime = entry(
            ("169.254.169.254", 32),
            "eth0",
            L4Direction::Outbound,
            L4Capability::Inject,
            (100, 100),
        );
        runtime.source = L4ScopeSource::Runtime;
        g.add_scope(runtime).unwrap();
        assert_eq!(
            g.check(L4Action::Inject, &t).unwrap_err(),
            L4GuardError::DangerousDestinationBlocked("169.254.169.254".into()),
            "a runtime-added entry must not lift the denylist, even with override"
        );

        // The same entry declared in config (operator authority) DOES lift it.
        let config = entry(
            ("169.254.169.254", 32),
            "eth0",
            L4Direction::Outbound,
            L4Capability::Inject,
            (100, 100),
        ); // helper defaults `source: Config`
        g.add_scope(config).unwrap();
        assert!(
            g.check(L4Action::Inject, &t).is_ok(),
            "a config-declared entry must still lift the denylist"
        );
    }

    /// I12 / SEC-2 — the widen gate lives in the guard: `add_runtime_scope` refuses
    /// with `ScopeWideningDisabled` when `allow_agent_widen` is off (the default), and
    /// adds nothing. This holds for any caller of the shared guard, not just the
    /// `l4.scope.add` command wrapper.
    #[test]
    fn add_runtime_scope_refused_when_widen_disabled() {
        let g = L4Guard::new(&cfg()); // default ⇒ allow_agent_widen false
        let e = entry(
            ("127.0.0.1", 32),
            "lo0",
            L4Direction::Outbound,
            L4Capability::Inject,
            (100, 100),
        );
        assert_eq!(
            g.add_runtime_scope(e).unwrap_err(),
            L4GuardError::ScopeWideningDisabled
        );
        assert!(
            g.list_scope().is_empty(),
            "a refused runtime add widens nothing"
        );
    }

    /// I12 / SEC-2 — `add_runtime_scope` forces `source = Runtime` in the guard, so a
    /// runtime caller cannot mint operator (`Config`) provenance even by passing a
    /// `Config`-sourced entry: the forced Runtime source means the denylist is not
    /// lifted, override notwithstanding.
    #[test]
    fn add_runtime_scope_forces_runtime_source() {
        let mut c = cfg();
        c.allow_agent_widen = true;
        c.dangerous_dst_override = true;
        let g = L4Guard::new(&c);

        // A caller passes a Config-sourced /32 covering the cloud-metadata address.
        let mut spoofed = entry(
            ("169.254.169.254", 32),
            "eth0",
            L4Direction::Outbound,
            L4Capability::Inject,
            (100, 100),
        );
        spoofed.source = L4ScopeSource::Config;
        g.add_runtime_scope(spoofed).unwrap();

        // The guard forced it to Runtime, so the denylist still blocks the target.
        let t = target("eth0", L4Direction::Outbound, "169.254.169.254", 80);
        assert_eq!(
            g.check(L4Action::Inject, &t).unwrap_err(),
            L4GuardError::DangerousDestinationBlocked("169.254.169.254".into()),
            "a runtime add must not mint Config provenance that lifts the denylist"
        );
        assert_eq!(
            g.list_scope()[0].source,
            L4ScopeSource::Runtime,
            "the stored entry is forced to Runtime provenance"
        );
    }

    /// `remove_scope` reverts to deny-by-default for that target.
    #[test]
    fn remove_scope_reverts_to_deny() {
        let g = L4Guard::new(&cfg());
        let e = entry(
            ("127.0.0.1", 32),
            "lo0",
            L4Direction::Outbound,
            L4Capability::Inject,
            (100, 100),
        );
        let id = g.add_scope(e).unwrap();
        let t = target("lo0", L4Direction::Outbound, "127.0.0.1", 1234);
        assert!(g.check(L4Action::Inject, &t).is_ok());
        assert!(g.remove_scope(id));
        assert!(matches!(
            g.check(L4Action::Inject, &t),
            Err(L4GuardError::OutOfL4Scope(_))
        ));
    }

    /// L4PAR-AC7 (plan A6) — the operator-confirmed path (`add_operator_scope`)
    /// skips the widen gate but, like every runtime add, funnels through
    /// `push_runtime`: the stored entry is `Runtime` even when the caller passed
    /// `Config`, so an operator runtime add of the cloud-metadata address never lifts
    /// the dangerous-destination denylist, `dangerous_dst_override` notwithstanding.
    #[test]
    fn operator_scope_cannot_lift_denylist() {
        let mut c = cfg();
        c.dangerous_dst_override = true;
        assert!(
            !c.allow_agent_widen,
            "widen stays off: the operator path skips it"
        );
        let g = L4Guard::new(&c);

        let mut spoofed = entry(
            ("169.254.169.254", 32),
            "eth0",
            L4Direction::Outbound,
            L4Capability::Inject,
            (100, 100),
        );
        spoofed.source = L4ScopeSource::Config;
        let id = g.add_operator_scope(
            spoofed,
            crate::commands::scope::OperatorConfirmed::test_only(),
        );

        let stored = g.list_scope();
        assert_eq!(stored.len(), 1, "the operator add stored exactly one entry");
        assert_eq!(stored[0].id, id);
        assert_eq!(
            stored[0].source,
            L4ScopeSource::Runtime,
            "an operator runtime add is stored as Runtime, never Config"
        );
        let t = target("eth0", L4Direction::Outbound, "169.254.169.254", 80);
        assert_eq!(
            g.check(L4Action::Inject, &t).unwrap_err(),
            L4GuardError::DangerousDestinationBlocked("169.254.169.254".into()),
            "an operator runtime add must not lift the denylist"
        );
    }
}
