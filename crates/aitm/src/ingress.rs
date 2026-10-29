//! The protocol-general capture / ingress boundary (Stage C; L4OPS-AC17).
//!
//! A capture backend presents captured traffic here with enough protocol-dispatch
//! context for the core to route each unit behind that protocol's **own** guard.
//! Phase 1 wires only the Linux/CLI L4 backend: an L4 unit is checked by the
//! deny-by-default [`L4Guard`] and, if authorized, recorded into the l4-owned
//! [`L4FlowStore`] — guarded **identically** to a `pcap`-fed packet, because it is
//! the *same* [`L4Guard::check`]. The boundary names no single protocol or backend,
//! so Phase 2's macOS Network/System Extension implements the same [`CaptureIngress`]
//! trait without reshaping it (spec Part 7, "one capture path, all protocols").
//!
//! This boundary is binary-layer wiring only: it adds **no** wire-write path. It
//! reads the guard and appends to the store; it never injects. The one guarded
//! wire-write choke point ([`aitm_proto_l4::wire::send_on_wire`], an `L4Permit` by
//! type) is left untouched — pinned by [`one_choke_point_survives_ingress`].
//!
//! [`L4Guard`]: aitm_proto_l4::guard::L4Guard
//! [`L4FlowStore`]: aitm_proto_l4::flow::L4FlowStore
//! [`L4Guard::check`]: aitm_proto_l4::guard::L4Guard::check

use std::sync::{Arc, Mutex, PoisonError};
use std::time::SystemTime;

use aitm_proto_l4::craft::PacketSpec;
use aitm_proto_l4::flow::{L4Bind, L4Flow, L4FlowId, L4FlowKind, L4FlowStore, L4Meta, L4Packet};
use aitm_proto_l4::guard::L4Guard;
use aitm_proto_l4::types::{L4Action, L4Target};

/// One unit of captured traffic, tagged with the protocol context the core dispatches
/// on. Phase 1 defines the L4 unit; HTTP/WebSocket enter through the existing acceptor
/// seam and are not ingress units yet. Marked `#[non_exhaustive]` so a new protocol is
/// added here without breaking a backend.
#[non_exhaustive]
pub enum CapturedUnit {
    /// A raw L4 frame, already decoded by the capture backend to the [`L4Target`] the
    /// guard authorizes against. `bytes` are the on-wire bytes recorded on capture.
    L4 {
        /// What [`L4Guard::check`](aitm_proto_l4::guard::L4Guard::check) decides on.
        target: L4Target,
        /// The raw on-wire bytes of the captured frame.
        bytes: Vec<u8>,
    },
}

/// What the ingress did with a unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngressOutcome {
    /// The unit passed its protocol's guard and was recorded in the store.
    Captured,
    /// The protocol's guard refused the unit (out of scope / not a capture grant);
    /// nothing was recorded.
    Refused,
    /// No backend is wired for this protocol in this build (e.g. L4 is disabled).
    Unhandled,
}

/// The protocol-general capture / ingress boundary. A capture backend — Phase 1: the
/// Linux/CLI L4 `pcap` backend; Phase 2: the macOS Network/System Extension — calls
/// [`accept`](CaptureIngress::accept) with each captured unit, and the implementation
/// routes it behind that protocol's own guard. No method or type here names a single
/// backend, so a new ingress source is a new caller of this one trait.
pub trait CaptureIngress: Send + Sync {
    /// Route one captured unit behind its protocol's guard, recording it on success.
    fn accept(&self, unit: CapturedUnit) -> IngressOutcome;
}

/// The core's capture ingress. Holds the per-protocol dispatch wiring; Phase 1 wires
/// the L4 dispatch (the shared guard + flow store). A protocol with no dispatch wired
/// yields [`IngressOutcome::Unhandled`].
pub struct CoreIngress {
    l4: Option<L4Dispatch>,
}

impl CoreIngress {
    /// An ingress with no protocol wired — every unit is [`IngressOutcome::Unhandled`].
    #[must_use]
    pub fn empty() -> Self {
        Self { l4: None }
    }

    /// Wire the L4 dispatch over the module's **shared** guard and flow store, so an
    /// ingress-fed L4 packet is guarded by the same [`L4Guard`] and lands in the same
    /// [`L4FlowStore`] the operator reads through `l4.flow.*`.
    #[must_use]
    pub fn with_l4(guard: Arc<L4Guard>, store: Arc<dyn L4FlowStore>) -> Self {
        Self {
            l4: Some(L4Dispatch {
                guard,
                store,
                flow: Mutex::new(None),
            }),
        }
    }
}

impl CaptureIngress for CoreIngress {
    fn accept(&self, unit: CapturedUnit) -> IngressOutcome {
        match unit {
            CapturedUnit::L4 { target, bytes } => match &self.l4 {
                Some(l4) => l4.record(&target, bytes),
                None => IngressOutcome::Unhandled,
            },
        }
    }
}

/// The L4 half of the ingress: the deny-by-default guard a packet must pass and the
/// l4-owned store it lands in. `flow` is the capture flow ingress-fed packets append
/// to, created lazily on the first authorized packet so an all-refused stream leaves
/// no empty flow behind.
struct L4Dispatch {
    guard: Arc<L4Guard>,
    store: Arc<dyn L4FlowStore>,
    flow: Mutex<Option<L4FlowId>>,
}

impl L4Dispatch {
    /// Route one L4 unit through the **same** guard a `pcap`-fed packet passes. An
    /// out-of-scope or non-`Capture` packet is refused here and nothing is stored; an
    /// authorized one is appended to the capture flow. The momentary `Capture` permit
    /// is dropped at once (a capture spends no injection budget).
    fn record(&self, target: &L4Target, bytes: Vec<u8>) -> IngressOutcome {
        if self.guard.check(L4Action::Capture, target).is_err() {
            return IngressOutcome::Refused;
        }
        let flow_id = self.ensure_flow(&target.interface);
        self.store.append_packet(
            flow_id,
            L4Packet {
                dir: target.direction,
                timestamp: SystemTime::now(),
                decoded: PacketSpec::summarize(&bytes),
                bytes,
                injected: false,
            },
        );
        IngressOutcome::Captured
    }

    /// The capture flow this ingress records into, created on first use. The store may
    /// re-key the flow on insert, so the returned id is the one cached and addressed.
    fn ensure_flow(&self, interface: &str) -> L4FlowId {
        let mut slot = self.flow.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(id) = *slot {
            return id;
        }
        let id = self.store.insert(L4Flow {
            id: L4FlowId::new(),
            kind: L4FlowKind::Capture,
            bind: L4Bind {
                interface: interface.to_string(),
                filter: None,
                queue: None,
            },
            packets: Vec::new(),
            metadata: L4Meta::default(),
        });
        *slot = Some(id);
        id
    }
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use aitm_proto_l4::config::L4Config;
    use aitm_proto_l4::flow::InMemoryL4FlowStore;
    use aitm_proto_l4::guard::L4Guard;
    use aitm_proto_l4::types::{
        IpCidr, L4Capability, L4Direction, L4Proto, L4ScopeEntry, L4ScopeId, L4ScopeSource,
        L4Target, PortRange, RateCap,
    };

    use super::*;

    const IFACE: &str = "lo0";

    /// A `Capture` scope entry for one host on [`IFACE`], outbound.
    fn capture_entry(host: &str) -> L4ScopeEntry {
        L4ScopeEntry {
            id: L4ScopeId::new(),
            cidr: IpCidr {
                addr: host.parse().unwrap(),
                prefix: 32,
            },
            ports: PortRange {
                lo: 0,
                hi: u16::MAX,
            },
            interface: IFACE.to_string(),
            direction: L4Direction::Outbound,
            capability: L4Capability::Capture,
            inject_rate: RateCap { pps: 10, burst: 10 },
            source: L4ScopeSource::Config,
        }
    }

    /// An outbound UDP target to `host:9` on [`IFACE`] — what the backend decodes a
    /// captured frame to and hands the ingress as its dispatch context.
    fn l4_target(host: &str) -> L4Target {
        L4Target {
            interface: IFACE.to_string(),
            direction: L4Direction::Outbound,
            dst: Some(host.parse().unwrap()),
            dst_port: Some(9),
            proto: L4Proto::Udp,
        }
    }

    fn l4_unit(host: &str) -> CapturedUnit {
        CapturedUnit::L4 {
            target: l4_target(host),
            bytes: b"probe".to_vec(),
        }
    }

    /// AC17: the boundary dispatches an L4 unit through the deny-by-default `L4Guard`
    /// into the l4-owned `L4FlowStore`. An in-scope packet is captured and stored; an
    /// out-of-scope packet on the same interface is refused by the guard and nothing
    /// is stored. The guard below the ingress is authoritative — the ingress presents
    /// no out-of-scope packet the store keeps.
    #[test]
    fn ingress_dispatches_by_protocol() {
        // Deny-by-default guard with a single Capture grant on 127.0.0.1.
        let guard = Arc::new(L4Guard::new(&L4Config::default()));
        guard.add_scope(capture_entry("127.0.0.1")).unwrap();
        let store: Arc<dyn L4FlowStore> = Arc::new(InMemoryL4FlowStore::new());
        let ingress = CoreIngress::with_l4(guard, store.clone());

        // In scope → routed through the guard and recorded.
        assert_eq!(
            ingress.accept(l4_unit("127.0.0.1")),
            IngressOutcome::Captured
        );
        // Out of scope → the guard refuses; nothing is stored.
        assert_eq!(
            ingress.accept(l4_unit("127.0.0.2")),
            IngressOutcome::Refused
        );

        // Exactly one capture flow, holding exactly the one in-scope packet, observed.
        let flows = store.list();
        assert_eq!(flows.len(), 1, "one capture flow is created on first store");
        let flow = store.get(flows[0]).expect("capture flow present");
        assert_eq!(flow.kind, L4FlowKind::Capture);
        assert_eq!(flow.packets.len(), 1, "only the in-scope packet is stored");
        assert!(
            !flow.packets[0].injected,
            "ingress-fed capture is observed, never injected"
        );
    }

    /// The production (non-test) prefix of a source file — everything before the
    /// trailing `#[cfg(test)]` block — so the scan never trips over test code.
    fn production_prefix(source: &str) -> &str {
        match source.find("#[cfg(test)]") {
            Some(idx) => &source[..idx],
            None => source,
        }
    }

    /// AC17 / M5-AC21: adding the ingress introduces **no** new wire-write path. The
    /// ingress source neither injects (`.inject(`) nor calls the choke point
    /// (`send_on_wire(`); the single guarded wire write remains
    /// `aitm_proto_l4::wire::send_on_wire`, an `L4Permit` by type. A structural
    /// tripwire over the type-level proof (the permit is unforgeable), not the proof.
    #[test]
    fn one_choke_point_survives_ingress() {
        let aitm_src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let ingress =
            std::fs::read_to_string(aitm_src.join("ingress.rs")).expect("read ingress.rs");
        let prod = production_prefix(&ingress);
        assert_eq!(
            prod.matches(".inject(").count(),
            0,
            "the capture ingress must not write to the wire"
        );
        assert_eq!(
            prod.matches("send_on_wire(").count(),
            0,
            "the capture ingress must not reach the wire-write choke point"
        );

        // The one choke point still exists, still gated by an `L4Permit` by type.
        let l4_wire: PathBuf = aitm_src
            .parent()
            .and_then(Path::parent)
            .expect("workspace crates dir")
            .join("aitm-proto-l4")
            .join("src")
            .join("wire.rs");
        let wire = std::fs::read_to_string(&l4_wire).expect("read aitm-proto-l4 wire.rs");
        let wire_prod = production_prefix(&wire);
        assert!(
            wire_prod.contains("pub fn send_on_wire("),
            "the single wire-write choke point must remain send_on_wire"
        );
        assert!(
            wire_prod.contains("permit: &mut L4Permit"),
            "the choke point must still require an L4Permit by type"
        );
    }
}
