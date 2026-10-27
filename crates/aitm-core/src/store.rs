//! The flow store: a shared, queryable collection of captured flows.
//!
//! `query` is the seam a future multi-flow scanner uses for correlation. The
//! default [`MemFlowStore`] is interior-mutable (`RwLock`) and `Send + Sync` so
//! protocol modules, plugins, and command handlers can all reach it behind a
//! shared reference.

use std::sync::RwLock;

use indexmap::IndexMap;

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

/// The default in-memory flow store.
#[derive(Default)]
pub struct MemFlowStore {
    flows: RwLock<IndexMap<FlowId, Flow>>,
}

impl MemFlowStore {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }
}

/// The host portion of an `authority` (`host[:port]`), without the port.
fn authority_host(authority: &str) -> &str {
    // IPv6 literals are bracketed (`[::1]:443`); split on the last colon only
    // when it is not inside brackets. Hosts in M1 are plain names or IPv4.
    match authority.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') && port.chars().all(|c| c.is_ascii_digit()) => {
            host
        }
        _ => authority,
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
                if authority_host(&f.request.authority) != host && &f.request.authority != host {
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
        if let Ok(mut flows) = self.flows.write() {
            flows.insert(id, flow);
        }
        id
    }

    fn get(&self, id: FlowId) -> Option<Flow> {
        self.flows.read().ok()?.get(&id).cloned()
    }

    fn update(&self, id: FlowId, f: &mut dyn FnMut(&mut Flow)) {
        if let Ok(mut flows) = self.flows.write() {
            if let Some(flow) = flows.get_mut(&id) {
                f(flow);
            }
        }
    }

    fn list(&self) -> Vec<FlowId> {
        match self.flows.read() {
            Ok(flows) => flows.keys().copied().collect(),
            Err(_) => Vec::new(),
        }
    }

    fn query(&self, q: &FlowQuery) -> Vec<FlowId> {
        match self.flows.read() {
            Ok(flows) => flows
                .iter()
                .filter(|(_, flow)| matches(flow, q))
                .map(|(id, _)| *id)
                .collect(),
            Err(_) => Vec::new(),
        }
    }
}
