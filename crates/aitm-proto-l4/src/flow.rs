//! The l4-owned flow store and packet model (M5 Task 3).
//!
//! L4 flows mirror `WsFlow`, but live here rather than in `aitm-core`: OQ1 is
//! decided in favour of an `aitm-proto-l4`-owned [`L4FlowStore`], so M5 lands
//! with **zero `aitm-core` edits** while captured / crafted / stimulus-response /
//! intercepted flows stay first-class over MCP / CLI / Rhai via `l4.flow.*`.
//! Promotion to a unified `Flow::L4` variant is a blessed later follow-up.
//!
//! A [`L4Flow`] is an ordered log of [`L4Packet`]s under one [`L4Bind`]: a
//! capture session appends decoded packets as they arrive; a send-and-receive
//! records the stimulus then its reply(s); an interception session records the
//! parked packets. `injected` marks the packets aitmproxy authored and put on
//! the wire (`l4.inject` / `l4.send_recv`), distinguishing them from observed
//! traffic.
//!
//! The in-memory [`InMemoryL4FlowStore`] is **bounded**: it is a testing tool,
//! not a sink that grows without limit (M5 anti-goal — bounded, controlled
//! machinery only), so it keeps at most [`InMemoryL4FlowStore::DEFAULT_MAX_FLOWS`]
//! flows, evicting the oldest when full. The trait signatures are fixed by the
//! spec; the impl is the builder's.

use std::collections::{HashMap, VecDeque};
use std::sync::{Mutex, PoisonError};
use std::time::SystemTime;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::craft::PacketSummary;
use crate::types::L4Direction;

/// A whole L4 flow: an ordered packet log under one bind, mirroring `WsFlow`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct L4Flow {
    /// Stable identity, minted by the store on [`L4FlowStore::insert`].
    pub id: L4FlowId,
    /// What kind of session produced this flow.
    pub kind: L4FlowKind,
    /// The interface / filter / target this flow is bound to.
    pub bind: L4Bind,
    /// Packets in arrival order; `append_packet` pushes to the back and evicts
    /// from the front at the cap. A `VecDeque` so that eviction is O(1): a
    /// `Vec::remove(0)` shifted the whole log on every packet past the cap,
    /// under the shared store lock (quadratic stall on a busy capture).
    pub packets: VecDeque<L4Packet>,
    /// Marks, comment, and creation time.
    pub metadata: L4Meta,
}

/// Which L4 primitive produced a flow — the four first-class flow sources.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum L4FlowKind {
    /// Raw-packet capture (`l4.capture`).
    Capture,
    /// A scapy-style crafted packet (`l4.craft` / `l4.inject`).
    Craft,
    /// A stimulus plus its reply(s) (`l4.send_recv`).
    SendRecv,
    /// An in-path interception session (NFQUEUE).
    Intercept,
}

/// Stable identifier for an L4 flow (uuid-backed), like [`L4ScopeId`].
///
/// [`L4ScopeId`]: crate::types::L4ScopeId
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct L4FlowId(Uuid);

impl L4FlowId {
    /// Mint a fresh flow id.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for L4FlowId {
    fn default() -> Self {
        Self::new()
    }
}

/// One packet in a flow: its direction, when it was seen/sent, the raw bytes, a
/// structural decode, and whether aitmproxy authored and injected it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct L4Packet {
    /// Direction relative to the host running aitmproxy.
    pub dir: L4Direction,
    /// When the packet was captured or put on the wire.
    pub timestamp: SystemTime,
    /// The raw on-wire bytes.
    pub bytes: Vec<u8>,
    /// Structural decode of `bytes` (layer names + length).
    pub decoded: PacketSummary,
    /// `true` iff aitmproxy authored and sent it (`l4.inject` / `l4.send_recv`);
    /// `false` for observed / captured traffic.
    pub injected: bool,
}

/// Where a flow is bound: an interface, an optional scope-derived capture
/// filter, and an optional in-path target (NFQUEUE number).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct L4Bind {
    /// The interface this flow is bound to (e.g. `lo0`, `eth0`).
    pub interface: String,
    /// Scope-derived capture filter (e.g. a BPF expression), when one applies.
    pub filter: Option<String>,
    /// In-path target queue number, for `Intercept` flows.
    pub queue: Option<u16>,
}

/// Flow-level annotations: operator marks, a free-text comment, and the
/// creation timestamp.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct L4Meta {
    /// Operator-applied marks (e.g. `"crash-repro"`).
    pub marks: Vec<String>,
    /// Free-text comment.
    pub comment: Option<String>,
    /// When the flow was created.
    pub created: SystemTime,
}

impl Default for L4Meta {
    fn default() -> Self {
        Self {
            marks: Vec::new(),
            comment: None,
            created: SystemTime::now(),
        }
    }
}

/// The l4-owned flow store. Thread-safe so background capture / nfqueue tasks and
/// the async command layer share one store. Signatures are fixed by the M5 spec.
pub trait L4FlowStore: Send + Sync {
    /// Store `flow` and return its id. The returned id is the one carried on the
    /// stored flow (the store may re-key it), so callers address the flow by the
    /// returned value.
    fn insert(&self, flow: L4Flow) -> L4FlowId;
    /// Fetch a clone of the flow with `id`, or `None` if absent / evicted.
    fn get(&self, id: L4FlowId) -> Option<L4Flow>;
    /// All live flow ids, oldest first.
    fn list(&self) -> Vec<L4FlowId>;
    /// Append `pkt` to the flow with `id`. A no-op if the flow is absent.
    fn append_packet(&self, id: L4FlowId, pkt: L4Packet);
}

/// A bounded, in-memory [`L4FlowStore`]. Keeps at most [`Self::DEFAULT_MAX_FLOWS`]
/// flows (or the cap passed to [`Self::with_capacity`]), evicting the oldest when
/// full, **and** at most [`Self::DEFAULT_MAX_PACKETS_PER_FLOW`] packets per flow,
/// ring-buffering out the oldest packet when a flow is full — a testing tool holds
/// bounded, controlled state, never an unbounded sink. Without the per-flow cap a
/// single long `l4.capture` on a busy interface grows one flow's packet log without
/// limit (the flow-count cap alone does not bound it).
#[derive(Debug)]
pub struct InMemoryL4FlowStore {
    inner: Mutex<Inner>,
    max_flows: usize,
    max_packets_per_flow: usize,
}

#[derive(Debug, Default)]
struct Inner {
    flows: HashMap<L4FlowId, L4Flow>,
    /// Insertion order, oldest at the front — the eviction queue.
    order: VecDeque<L4FlowId>,
}

impl InMemoryL4FlowStore {
    /// Default retained-flow ceiling.
    pub const DEFAULT_MAX_FLOWS: usize = 4096;

    /// Default retained-packet ceiling **per flow**. Bounds a single long capture's
    /// packet log: once a flow holds this many packets, `append_packet` evicts the
    /// oldest to make room for the newest (ring-buffer).
    pub const DEFAULT_MAX_PACKETS_PER_FLOW: usize = 65_536;

    /// A store with the default capacities.
    #[must_use]
    pub fn new() -> Self {
        Self::with_capacity(Self::DEFAULT_MAX_FLOWS)
    }

    /// A store that retains at most `max_flows` flows (clamped to at least 1), with the
    /// default per-flow packet cap.
    #[must_use]
    pub fn with_capacity(max_flows: usize) -> Self {
        Self::with_limits(max_flows, Self::DEFAULT_MAX_PACKETS_PER_FLOW)
    }

    /// A store that retains at most `max_flows` flows and at most
    /// `max_packets_per_flow` packets per flow (each clamped to at least 1).
    #[must_use]
    pub fn with_limits(max_flows: usize, max_packets_per_flow: usize) -> Self {
        Self {
            inner: Mutex::new(Inner::default()),
            max_flows: max_flows.max(1),
            max_packets_per_flow: max_packets_per_flow.max(1),
        }
    }
}

impl Default for InMemoryL4FlowStore {
    fn default() -> Self {
        Self::new()
    }
}

impl L4FlowStore for InMemoryL4FlowStore {
    fn insert(&self, mut flow: L4Flow) -> L4FlowId {
        let id = L4FlowId::new();
        flow.id = id;
        let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        inner.flows.insert(id, flow);
        inner.order.push_back(id);
        while inner.order.len() > self.max_flows {
            if let Some(oldest) = inner.order.pop_front() {
                inner.flows.remove(&oldest);
            }
        }
        id
    }

    fn get(&self, id: L4FlowId) -> Option<L4Flow> {
        let inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        inner.flows.get(&id).cloned()
    }

    fn list(&self) -> Vec<L4FlowId> {
        let inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        inner.order.iter().copied().collect()
    }

    fn append_packet(&self, id: L4FlowId, pkt: L4Packet) {
        let max = self.max_packets_per_flow;
        let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(flow) = inner.flows.get_mut(&id) {
            flow.packets.push_back(pkt);
            // Ring-buffer: a long capture never grows one flow's log without bound —
            // past the cap, the oldest packet is evicted (O(1)) to make room for the newest.
            while flow.packets.len() > max {
                flow.packets.pop_front();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn craft_flow() -> L4Flow {
        L4Flow {
            id: L4FlowId::new(),
            kind: L4FlowKind::Craft,
            bind: L4Bind {
                interface: "lo0".to_string(),
                filter: None,
                queue: None,
            },
            packets: VecDeque::new(),
            metadata: L4Meta::default(),
        }
    }

    fn injected_packet() -> L4Packet {
        L4Packet {
            dir: L4Direction::Outbound,
            timestamp: SystemTime::now(),
            bytes: vec![0xde, 0xad, 0xbe, 0xef],
            decoded: PacketSummary {
                layers: vec!["IPv4".to_string(), "UDP".to_string()],
                length: 4,
            },
            injected: true,
        }
    }

    /// Pinned (plan Task 3): insert a `Craft` flow, append one injected packet,
    /// `get` it back, and see exactly that packet and kind.
    #[test]
    fn store_insert_append_get() {
        let store = InMemoryL4FlowStore::new();

        let id = store.insert(craft_flow());
        store.append_packet(id, injected_packet());

        let flow = store.get(id).expect("flow present after insert");
        assert_eq!(flow.packets.len(), 1);
        assert!(flow.packets.back().expect("one packet").injected);
        assert_eq!(flow.kind, L4FlowKind::Craft);
    }

    /// The store re-keys the inserted flow to the id it returns, so the stored
    /// flow's own `id` matches what the caller holds.
    #[test]
    fn insert_rekeys_flow_to_returned_id() {
        let store = InMemoryL4FlowStore::new();
        let id = store.insert(craft_flow());
        assert_eq!(store.get(id).expect("present").id, id);
        assert_eq!(store.list(), vec![id]);
    }

    /// `get` / `append_packet` on an unknown id are safe: `None`, and a no-op.
    #[test]
    fn unknown_id_is_absent_and_append_is_noop() {
        let store = InMemoryL4FlowStore::new();
        let ghost = L4FlowId::new();
        assert!(store.get(ghost).is_none());
        store.append_packet(ghost, injected_packet()); // must not panic
        assert!(store.list().is_empty());
    }

    /// I11 — the per-flow packet log is bounded: past the per-flow cap the oldest
    /// packet is ring-buffered out, so a single long capture can never grow one flow
    /// without limit. The retained packets are the newest `cap`, newest last.
    #[test]
    fn per_flow_packet_log_is_bounded() {
        let store = InMemoryL4FlowStore::with_limits(16, 2);
        let id = store.insert(craft_flow());

        for marker in 0u8..5 {
            let mut pkt = injected_packet();
            pkt.bytes = vec![marker]; // a distinguishable per-packet marker
            store.append_packet(id, pkt);
        }

        let flow = store.get(id).expect("flow present");
        assert_eq!(flow.packets.len(), 2, "the per-flow cap holds");
        // Only the two newest survive, in arrival order (markers 3 then 4).
        assert_eq!(flow.packets[0].bytes, vec![3]);
        assert_eq!(flow.packets[1].bytes, vec![4]);
    }

    /// Bounded storage: past capacity the oldest flow is evicted, newest kept,
    /// and `list` stays at the cap in oldest-first order.
    #[test]
    fn bounded_evicts_oldest() {
        let store = InMemoryL4FlowStore::with_capacity(2);

        let a = store.insert(craft_flow());
        let b = store.insert(craft_flow());
        let c = store.insert(craft_flow());

        assert!(store.get(a).is_none(), "oldest evicted at capacity");
        assert_eq!(store.list(), vec![b, c]);
    }
}
