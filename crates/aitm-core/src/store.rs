//! The flow store: a shared, queryable collection of captured flows.
//!
//! `query` is the seam a future multi-flow scanner uses for correlation. The
//! default [`MemFlowStore`] is interior-mutable (`RwLock`) and `Send + Sync` so
//! protocol modules, plugins, and command handlers can all reach it behind a
//! shared reference.

use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Mutex, PoisonError, RwLock};

use indexmap::IndexMap;

use crate::authority::Authority;
use crate::body::Body;
use crate::flow::{Flow, FlowId, InterceptState};

/// A shared, queryable store of captured flows.
///
/// Every method is required: a store that silently no-ops `clear`, the capture
/// toggle, or ephemeral retirement would lie to the operator (e.g. `scope.remove`
/// reporting success while leaving a host in scope), so the trait forces each
/// implementation to make a real choice.
pub trait FlowStore: Send + Sync {
    /// Store a flow, keyed by its own id; returns that id. The flow is always
    /// retained so the pipeline can `get`/`update` it; when capture is paused the
    /// flow is additionally marked *ephemeral* (hidden from `list`/`query` and
    /// retired at its terminal event).
    fn insert(&self, flow: Flow) -> FlowId;
    /// A clone of the stored flow, if present. Returns ephemeral flows too, so a
    /// by-id lookup (resume, replay, detail) works while capture is paused.
    fn get(&self, id: FlowId) -> Option<Flow>;
    /// Mutate a stored flow in place.
    fn update(&self, id: FlowId, f: &mut dyn FnMut(&mut Flow));
    /// Visible flow ids (ephemeral flows excluded), in insertion order.
    fn list(&self) -> Vec<FlowId>;
    /// Visible ids matching every set filter in `q` (ephemeral excluded).
    fn query(&self, q: &FlowQuery) -> Vec<FlowId>;
    /// Remove terminal flows (a completed/killed HTTP response, a killed WS);
    /// in-flight and intercepted (parked) flows are kept so the pipeline is never
    /// stranded. Reports how many were cleared and how many were skipped.
    fn clear(&self) -> ClearOutcome;
    /// Whether new flows are being retained (the capture/record toggle).
    fn is_capturing(&self) -> bool;
    /// Enable (`true`) or disable (`false`) retaining newly inserted flows. While
    /// disabled, flows still flow through the pipeline but are marked ephemeral.
    fn set_capturing(&self, on: bool);
    /// Remove a flow iff it was marked ephemeral (captured while paused) and is now
    /// at its terminal event; returns whether it was removed. A no-op for a
    /// non-ephemeral flow, so the chain can call it on every terminal event.
    fn retire_ephemeral(&self, id: FlowId) -> bool;
    /// The number of visible (non-ephemeral) flows, without cloning any flow.
    fn count(&self) -> usize;
    /// The number of visible flows currently intercepted (parked), without cloning.
    fn intercepted_count(&self) -> usize;
}

/// The outcome of [`FlowStore::clear`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ClearOutcome {
    /// Terminal flows removed.
    pub cleared: usize,
    /// In-flight or intercepted flows kept.
    pub skipped_in_flight: usize,
}

/// A filter over the store. `None` fields do not constrain the result; the seam a
/// future scanner uses for multi-flow correlation.
#[derive(Debug, Clone, Default)]
pub struct FlowQuery {
    pub host: Option<String>,
    pub method: Option<String>,
    pub status: Option<u16>,
    pub kind: Option<FlowKind>,
    pub is_replay: Option<bool>,
}

/// The protocol family of a flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowKind {
    Http,
    WebSocket,
}

/// How many flows the default store keeps before evicting the oldest.
pub const DEFAULT_MAX_FLOWS: usize = 50_000;

/// The default resident-byte budget (512 MiB): a second bound so a few huge
/// captures cannot exhaust memory even while well under the flow *count* cap.
pub const DEFAULT_MAX_FLOW_BYTES: usize = 512 * 1024 * 1024;

/// The default in-memory flow store. Bounded on **both** flow count and resident
/// bytes: a new insertion (or an update that grows a flow) evicts the oldest
/// flows (FIFO) until under both limits, so a long-running proxy — or a handful
/// of very large bodies — cannot grow memory without limit.
pub struct MemFlowStore {
    flows: RwLock<IndexMap<FlowId, Flow>>,
    capacity: usize,
    max_bytes: usize,
    /// Estimated resident bytes of all held flows. Mutated only under the `flows`
    /// write lock, so it stays consistent with the map.
    resident: AtomicUsize,
    /// Whether new flows are retained as visible. `false` keeps the flow resident
    /// (so the pipeline works) but marks it ephemeral (the record toggle).
    capturing: AtomicBool,
    /// Ids captured while paused: resident but hidden from `list`/`query`, retired
    /// at their terminal event. Always locked **after** `flows` to avoid deadlock.
    ephemeral: Mutex<HashSet<FlowId>>,
}

impl Default for MemFlowStore {
    fn default() -> Self {
        Self::with_limits(DEFAULT_MAX_FLOWS, DEFAULT_MAX_FLOW_BYTES)
    }
}

impl MemFlowStore {
    /// An empty store bounded at [`DEFAULT_MAX_FLOWS`] / [`DEFAULT_MAX_FLOW_BYTES`].
    pub fn new() -> Self {
        Self::default()
    }

    /// An empty store bounded at `capacity` flows (0 = unbounded count) and the
    /// default byte budget.
    pub fn with_capacity(capacity: usize) -> Self {
        Self::with_limits(capacity, DEFAULT_MAX_FLOW_BYTES)
    }

    /// An empty store bounded at `capacity` flows and `max_bytes` resident bytes
    /// (0 = that bound is off).
    pub fn with_limits(capacity: usize, max_bytes: usize) -> Self {
        Self {
            flows: RwLock::new(IndexMap::new()),
            capacity,
            max_bytes,
            resident: AtomicUsize::new(0),
            capturing: AtomicBool::new(true),
            ephemeral: Mutex::new(HashSet::new()),
        }
    }

    /// Lock the ephemeral set, recovering from poisoning.
    fn ephemeral(&self) -> std::sync::MutexGuard<'_, HashSet<FlowId>> {
        self.ephemeral
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Estimated resident bytes currently held (for tests / introspection).
    pub fn resident_bytes(&self) -> usize {
        self.resident.load(Ordering::Relaxed)
    }

    /// Evict the oldest flows until both the count and byte bounds hold. Called
    /// under the write lock after a mutation that may have pushed over a bound.
    fn evict_over_limit(&self, flows: &mut IndexMap<FlowId, Flow>) {
        if self.capacity > 0 && flows.len() > self.capacity {
            // Drop down to ~90% of capacity in one `drain` (amortized cheap).
            let keep = self.capacity - self.capacity / 10;
            let remove = flows.len().saturating_sub(keep);
            self.drain_oldest(flows, remove);
        }
        if self.max_bytes > 0 && self.resident.load(Ordering::Relaxed) > self.max_bytes {
            // Drop oldest down to ~90% of the byte budget.
            let target = self.max_bytes - self.max_bytes / 10;
            let cur = self.resident.load(Ordering::Relaxed);
            let mut freed = 0usize;
            let mut remove = 0usize;
            for (_, f) in flows.iter() {
                if cur - freed <= target {
                    break;
                }
                freed += flow_size(f);
                remove += 1;
            }
            self.drain_oldest(flows, remove);
        }
    }

    /// Drain the `remove` oldest flows, decrementing the resident-byte counter by
    /// their estimated size and dropping any of them from the ephemeral set.
    fn drain_oldest(&self, flows: &mut IndexMap<FlowId, Flow>, remove: usize) {
        let remove = remove.min(flows.len());
        if remove == 0 {
            return;
        }
        let mut ephemeral = self.ephemeral();
        let freed: usize = flows
            .drain(0..remove)
            .map(|(id, f)| {
                ephemeral.remove(&id);
                flow_size(&f)
            })
            .sum();
        self.resident.fetch_sub(freed, Ordering::Relaxed);
    }
}

/// Whether a flow has reached a point where it can be removed without stranding
/// the pipeline: an intercepted (parked) flow never qualifies; an HTTP flow does
/// once it is killed or has a fully-buffered response; a WebSocket flow once
/// killed (there is no end marker on the flow yet — see the F-list retention gap).
fn is_terminal(flow: &Flow) -> bool {
    match flow {
        Flow::Http(f) => match &f.intercept {
            InterceptState::Intercepted { .. } => false,
            InterceptState::Killed => true,
            _ => f
                .response
                .as_ref()
                .is_some_and(|r| !matches!(r.body, Body::Streamed(_))),
        },
        Flow::WebSocket(f) => matches!(f.intercept, InterceptState::Killed),
    }
}

/// Whether a flow is currently intercepted (parked).
fn is_intercepted(flow: &Flow) -> bool {
    matches!(flow.intercept(), InterceptState::Intercepted { .. })
}

/// Estimated resident bytes of a flow: the buffered body bytes (the dominant
/// cost) plus header and request-line text, over a small fixed base.
fn flow_size(flow: &Flow) -> usize {
    const BASE: usize = 256;
    match flow {
        Flow::Http(f) => {
            let req = f.request.method.len()
                + f.request.authority.len()
                + f.request.path.len()
                + header_bytes(&f.request.headers)
                + body_bytes(&f.request.body);
            let resp = f
                .response
                .as_ref()
                .map(|r| header_bytes(&r.headers) + body_bytes(&r.body))
                .unwrap_or(0);
            BASE + req + resp + meta_bytes(&f.metadata)
        }
        Flow::WebSocket(f) => {
            BASE + f.messages.iter().map(|m| m.data.len()).sum::<usize>() + meta_bytes(&f.metadata)
        }
    }
}

/// Operator-supplied metadata bytes (marks + comment), so `flow.mark`/`flow.comment`
/// are accounted against the store's memory budget like any other growth.
fn meta_bytes(m: &crate::flow::FlowMeta) -> usize {
    m.marks.iter().map(String::len).sum::<usize>() + m.comment.as_ref().map_or(0, String::len)
}

fn body_bytes(b: &Body) -> usize {
    match b {
        Body::Bytes(v) => v.len(),
        _ => 0,
    }
}

fn header_bytes(h: &crate::header::HeaderMap) -> usize {
    h.iter().map(|(n, v)| n.len() + v.len()).sum()
}

/// The host portion of an `authority` (`host[:port]`), without the port, folded
/// to lowercase — parsed through [`Authority`] so IPv6 and ports are uniform.
fn authority_host(authority: &str) -> String {
    match Authority::parse_with_default(authority, 0) {
        Ok(a) => a.host,
        Err(_) => authority.to_ascii_lowercase(),
    }
}

/// Whether a stored flow satisfies every set filter in `q`.
fn matches(flow: &Flow, q: &FlowQuery) -> bool {
    if let Some(kind) = q.kind {
        let actual = match flow {
            Flow::Http(_) => FlowKind::Http,
            Flow::WebSocket(_) => FlowKind::WebSocket,
        };
        if actual != kind {
            return false;
        }
    }
    if let Some(want) = q.is_replay {
        let actual = match flow {
            Flow::Http(f) => f.metadata.is_replay,
            Flow::WebSocket(f) => f.metadata.is_replay,
        };
        if actual != want {
            return false;
        }
    }
    match flow {
        Flow::Http(f) => {
            if let Some(host) = &q.host {
                let want = host.to_ascii_lowercase();
                if authority_host(&f.request.authority) != want
                    && f.request.authority.to_ascii_lowercase() != want
                {
                    return false;
                }
            }
            if let Some(method) = &q.method {
                if &f.request.method != method {
                    return false;
                }
            }
            if let Some(status) = q.status {
                match &f.response {
                    Some(resp) if resp.status == status => {}
                    _ => return false,
                }
            }
            true
        }
        Flow::WebSocket(_) => {
            // host/method/status are HTTP concepts; a WebSocket flow cannot match
            // any of them when they are set.
            q.host.is_none() && q.method.is_none() && q.status.is_none()
        }
    }
}

impl FlowStore for MemFlowStore {
    fn insert(&self, flow: Flow) -> FlowId {
        let id = flow.id();
        let size = flow_size(&flow);
        // Record toggle: a flow captured while paused is still stored (so the
        // pipeline can get/update it and intercept/replay keep working) but marked
        // ephemeral — hidden from list/query and retired at its terminal event.
        let paused = !self.capturing.load(Ordering::Relaxed);
        let mut flows = self.flows.write().unwrap_or_else(PoisonError::into_inner);
        if paused {
            self.ephemeral().insert(id);
        }
        // Re-inserting an existing id replaces in place: discount the old size.
        if let Some(old) = flows.insert(id, flow) {
            self.resident.fetch_sub(flow_size(&old), Ordering::Relaxed);
        }
        self.resident.fetch_add(size, Ordering::Relaxed);
        // Bound memory on both count and bytes. Batched eviction keeps sustained
        // capture cheap (one `drain` amortized over many inserts) versus a
        // per-insert `shift_remove_index(0)`, which is O(n) *every* time.
        self.evict_over_limit(&mut flows);
        id
    }

    fn get(&self, id: FlowId) -> Option<Flow> {
        self.flows
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&id)
            .cloned()
    }

    fn update(&self, id: FlowId, f: &mut dyn FnMut(&mut Flow)) {
        let mut flows = self.flows.write().unwrap_or_else(PoisonError::into_inner);
        if let Some(flow) = flows.get_mut(&id) {
            // Most body bytes arrive here (a flow is inserted head-first, then
            // updated with its body/response), so track the size delta and evict
            // if the update pushed the store over a bound.
            let before = flow_size(flow);
            f(flow);
            let after = flow_size(flow);
            if after >= before {
                self.resident.fetch_add(after - before, Ordering::Relaxed);
            } else {
                self.resident.fetch_sub(before - after, Ordering::Relaxed);
            }
            self.evict_over_limit(&mut flows);
        }
    }

    fn list(&self) -> Vec<FlowId> {
        let flows = self.flows.read().unwrap_or_else(PoisonError::into_inner);
        let ephemeral = self.ephemeral();
        flows
            .keys()
            .filter(|id| !ephemeral.contains(id))
            .copied()
            .collect()
    }

    fn query(&self, q: &FlowQuery) -> Vec<FlowId> {
        let flows = self.flows.read().unwrap_or_else(PoisonError::into_inner);
        let ephemeral = self.ephemeral();
        flows
            .iter()
            .filter(|(id, _)| !ephemeral.contains(*id))
            .filter(|(_, flow)| matches(flow, q))
            .map(|(id, _)| *id)
            .collect()
    }

    fn clear(&self) -> ClearOutcome {
        let mut flows = self.flows.write().unwrap_or_else(PoisonError::into_inner);
        let mut ephemeral = self.ephemeral();
        let mut cleared = 0usize;
        let mut skipped_in_flight = 0usize;
        let mut freed = 0usize;
        // Keep in-flight and parked flows; removing one would strand the pipeline
        // (the proto module's `get` after dispatch would miss it) or its resume.
        flows.retain(|id, flow| {
            if is_terminal(flow) {
                cleared += 1;
                freed += flow_size(flow);
                ephemeral.remove(id);
                false
            } else {
                skipped_in_flight += 1;
                true
            }
        });
        self.resident.fetch_sub(freed, Ordering::Relaxed);
        ClearOutcome {
            cleared,
            skipped_in_flight,
        }
    }

    fn is_capturing(&self) -> bool {
        self.capturing.load(Ordering::Relaxed)
    }

    fn set_capturing(&self, on: bool) {
        self.capturing.store(on, Ordering::Relaxed);
    }

    fn retire_ephemeral(&self, id: FlowId) -> bool {
        let mut flows = self.flows.write().unwrap_or_else(PoisonError::into_inner);
        if !self.ephemeral().remove(&id) {
            return false;
        }
        if let Some(flow) = flows.shift_remove(&id) {
            self.resident.fetch_sub(flow_size(&flow), Ordering::Relaxed);
        }
        true
    }

    fn count(&self) -> usize {
        let flows = self.flows.read().unwrap_or_else(PoisonError::into_inner);
        let ephemeral = self.ephemeral();
        flows.keys().filter(|id| !ephemeral.contains(id)).count()
    }

    fn intercepted_count(&self) -> usize {
        let flows = self.flows.read().unwrap_or_else(PoisonError::into_inner);
        let ephemeral = self.ephemeral();
        flows
            .iter()
            .filter(|(id, _)| !ephemeral.contains(*id))
            .filter(|(_, flow)| is_intercepted(flow))
            .count()
    }
}
