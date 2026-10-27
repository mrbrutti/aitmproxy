//! The flow store: a shared, queryable collection of captured flows.
//!
//! `query` is the seam a future multi-flow scanner uses for correlation. The
//! default [`MemFlowStore`] is interior-mutable (`RwLock`) and `Send + Sync` so
//! protocol modules, plugins, and command handlers can all reach it behind a
//! shared reference.

use std::sync::{PoisonError, RwLock};

use indexmap::IndexMap;

use crate::authority::Authority;
use crate::flow::{Flow, FlowId};

/// A shared, queryable store of captured flows.
pub trait FlowStore: Send + Sync {
    /// Store a flow, keyed by its own id; returns that id.
    fn insert(&self, flow: Flow) -> FlowId;
    /// A clone of the stored flow, if present.
    fn get(&self, id: FlowId) -> Option<Flow>;
    /// Mutate a stored flow in place.
    fn update(&self, id: FlowId, f: &mut dyn FnMut(&mut Flow));
    /// All stored flow ids, in insertion order.
    fn list(&self) -> Vec<FlowId>;
    /// Ids of flows matching every set filter in `q`, in insertion order.
    fn query(&self, q: &FlowQuery) -> Vec<FlowId>;
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

/// The default in-memory flow store. Bounded: once `capacity` flows are held, a
/// new insertion evicts the oldest (FIFO) so a long-running proxy cannot grow
/// without limit.
pub struct MemFlowStore {
    flows: RwLock<IndexMap<FlowId, Flow>>,
    capacity: usize,
}

impl Default for MemFlowStore {
    fn default() -> Self {
        Self::with_capacity(DEFAULT_MAX_FLOWS)
    }
}

impl MemFlowStore {
    /// An empty store bounded at [`DEFAULT_MAX_FLOWS`].
    pub fn new() -> Self {
        Self::default()
    }

    /// An empty store bounded at `capacity` flows (0 means unbounded).
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            flows: RwLock::new(IndexMap::new()),
            capacity,
        }
    }
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
        let mut flows = self.flows.write().unwrap_or_else(PoisonError::into_inner);
        flows.insert(id, flow);
        // Bound memory: once over capacity, evict the oldest flows in a batch
        // (down to ~90% of capacity). Dropping the oldest `k` in one `drain` is a
        // single O(n) shift amortized over `k` inserts, so sustained capture stays
        // cheap — a per-insert `shift_remove_index(0)` is O(n) *every* time.
        // Re-inserting an existing id updates in place and does not grow the map.
        if self.capacity > 0 && flows.len() > self.capacity {
            let keep = self.capacity - self.capacity / 10;
            let remove = flows.len().saturating_sub(keep);
            flows.drain(0..remove);
        }
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
            f(flow);
        }
    }

    fn list(&self) -> Vec<FlowId> {
        self.flows
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .keys()
            .copied()
            .collect()
    }

    fn query(&self, q: &FlowQuery) -> Vec<FlowId> {
        self.flows
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .filter(|(_, flow)| matches(flow, q))
            .map(|(id, _)| *id)
            .collect()
    }
}
