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

/// One captured **UDP** flow: a batch of datagrams to one [`L4Target`], tagged with
/// the dispatch context the L4 guard authorizes against. A thin, symmetric companion
/// to [`CapturedTcpFlow`] over the existing deny-by-default L4 path.
pub struct CapturedUdpFlow {
    /// What [`L4Guard::check`](aitm_proto_l4::guard::L4Guard::check) decides on
    /// (interface / direction / dst / port / proto).
    pub target: aitm_proto_l4::types::L4Target,
    /// The raw on-wire bytes of each captured datagram.
    pub datagrams: Vec<Vec<u8>>,
    /// The source-app signing identity, if the backend knows it.
    pub peer_identity: Option<String>,
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

/// One captured **TCP/stream** flow, tagged with the dispatch context the core routes
/// on. A capture backend (Phase 2's macOS Network/System Extension) presents the
/// client stream with the **authoritative original destination** it observed, so the
/// core dispatches on the real remote endpoint — not an accepted-socket peer.
pub struct CapturedTcpFlow {
    /// The captured client byte stream. It must still yield `first_bytes` (the backend
    /// observes them without consuming, mirroring today's `TcpStream::peek`).
    pub stream: aitm_core::ByteStream,
    /// The authoritative original remote endpoint the client was reaching.
    pub dst: std::net::SocketAddr,
    /// The remote hostname / ClientHello SNI, if the backend knows it.
    pub sni: Option<String>,
    /// The backend's observed initial bytes (for protocol sniffing); the `stream`
    /// still yields them.
    pub first_bytes: Vec<u8>,
    /// The source-app signing identity, if the backend knows it (macOS `SourceAppId`).
    pub peer_identity: Option<String>,
    /// The capture backend's interface name — the string an operator's L4 scope names
    /// it by (the macOS NE backend sends `"macos-ne"`). Supplied by the backend's
    /// adapter; the ingress copies it onto the hint and knows no backend's name.
    pub interface: String,
}

/// What the ingress did with a captured TCP/stream flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamOutcome {
    /// A [`ProtocolModule`](aitm_core::ProtocolModule) claimed the flow and was spawned.
    Dispatched,
    /// In scope but unclaimed: the original dst was dialled and bytes tunnelled verbatim.
    PassedThrough,
    /// Out of scope: refused before any module match, spawn, or connector dial.
    Refused,
    /// Stream dispatch is not wired in this build.
    Unhandled,
}

/// The core's capture ingress. Holds the per-protocol dispatch wiring; the L4 dispatch
/// (the shared guard + flow store) and the stream dispatch (the module list, chain,
/// guarded connector + scope guard). A protocol with no dispatch wired yields
/// [`IngressOutcome::Unhandled`] / [`StreamOutcome::Unhandled`].
pub struct CoreIngress {
    l4: Option<L4Dispatch>,
    stream: Option<StreamDispatch>,
}

impl CoreIngress {
    /// An ingress with no protocol wired — every unit is [`IngressOutcome::Unhandled`].
    #[must_use]
    pub fn empty() -> Self {
        Self {
            l4: None,
            stream: None,
        }
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
            stream: None,
        }
    }

    /// Wire the TCP/stream dispatch over the live proxy's **shared** module list, event
    /// chain, guarded upstream connector, and scope guard — the same wiring the acceptor
    /// uses — so a captured stream is claimed, emitted, dialled, and scope-gated exactly
    /// as a proxied one. Builder-style so the L4 and stream halves compose.
    #[must_use]
    pub fn with_stream(
        mut self,
        modules: Arc<[Arc<dyn aitm_core::ProtocolModule>]>,
        store: Arc<dyn aitm_core::FlowStore>,
        sink: Arc<dyn aitm_core::EventSink>,
        connector: Arc<dyn aitm_core::UpstreamConnector>,
        guard: Arc<dyn aitm_core::ScopeRateGuard>,
    ) -> Self {
        self.stream = Some(StreamDispatch {
            modules,
            store,
            sink,
            connector,
            guard,
        });
        self
    }

    /// Whether backend-supplied hostname text is a plain DNS name — at most 253 bytes
    /// of letters, digits, `-`, `_` and `.`, nothing else. Brackets, a `:port`, a
    /// `/path`, whitespace or control characters never occur in a real SNI /
    /// connect-by-name hostname, so a value carrying them is not trusted as the scope
    /// host.
    fn is_plain_hostname(name: &str) -> bool {
        !name.is_empty()
            && name.len() <= 253
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
    }

    /// Dispatch one captured TCP/stream flow: scope-gate it (authority = `host:port`,
    /// the SNI / handoff hostname when it is a plain DNS name else the dst IP, with the
    /// dst port) through the L7 [`ScopeRateGuard`](aitm_core::ScopeRateGuard), then
    /// route it behind the **authoritative original destination**. An in-scope flow a
    /// module claims is spawned ([`StreamOutcome::Dispatched`]); an in-scope flow no
    /// module claims is dialled through the SSRF-guarded connector and tunnelled
    /// verbatim ([`StreamOutcome::PassedThrough`]); an out-of-scope flow is refused
    /// before any module match, spawn, or dial ([`StreamOutcome::Refused`]).
    pub async fn dispatch_tcp(&self, mut flow: CapturedTcpFlow) -> StreamOutcome {
        let Some(sd) = self.stream.as_ref() else {
            return StreamOutcome::Unhandled;
        };

        // Deny-by-default. Gate on `host:port`, the same shape a proxied request is
        // gated on: `Authority::matches_scope_entry` compares ports when the entry
        // carries one, so a port-qualified entry can only match a ported authority,
        // while a portless entry still admits any port. The same string goes to
        // `connector.connect` below, whose SSRF check matches it the same way. A refusal
        // is a WARN, not a debug line: the client's connection is cut here, and a
        // capture backend normally hands over only flows it believed in scope.
        // The hostname is backend-supplied text: only a plain name is trusted as the
        // host (no brackets, port, path or whitespace — an SNI never carries those, and
        // `Authority::new` would normalise some of them away); anything else gates on
        // the dst IP, which only an IP entry can admit.
        let host = match flow.sni.as_deref() {
            Some(name) if Self::is_plain_hostname(name) => name.to_string(),
            _ => flow.dst.ip().to_string(),
        };
        let authority = aitm_core::Authority::new(&host, flow.dst.port()).to_string();
        if !sd.guard.in_scope(&authority) {
            // `?authority`: Debug-escaped, so a hostile hostname cannot forge log lines.
            tracing::warn!(
                ?authority,
                dst = %flow.dst,
                "captured flow refused: authority not in the core's scope"
            );
            return StreamOutcome::Refused;
        }

        // `dst` is the authoritative original destination — not an accepted-socket peer.
        let hint = aitm_core::NextLayerHint {
            dst: flow.dst,
            is_tls: flow.first_bytes.first() == Some(&0x16),
            client_hello_sni: flow.sni.clone(),
            alpn: Vec::new(),
            first_bytes: flow.first_bytes,
            from_upgrade: false,
            // The attribution the backend observed rides the hint to the claiming
            // module, which stamps it on the flows it stores. Copied, not interpreted:
            // the identity is data about the client, never a scope input.
            peer_identity: flow.peer_identity.take(),
            capture_interface: Some(flow.interface.clone()),
        };

        match sd.modules.iter().find(|m| m.matches(&hint)).cloned() {
            Some(module) => {
                let dst = flow.dst;
                let ctx = aitm_core::ModuleCtx::new(
                    sd.store.clone(),
                    sd.sink.clone(),
                    sd.connector.clone(),
                )
                .with_modules(sd.modules.clone())
                .with_hint(hint);
                // Log a module-spawn error the way the acceptor's `handle_conn` does
                // (warn with the dst + error), rather than silently dropping it.
                if let Err(e) = module.spawn(flow.stream, ctx).await {
                    tracing::warn!(%dst, error = %e, "captured-stream dispatch: module ended with an error");
                }
                StreamOutcome::Dispatched
            }
            None => {
                // In scope but unclaimed: dial the original dst through the SSRF-guarded
                // connector and tunnel verbatim. The flow was taken, not silently
                // dropped — a dial failure still reports PassedThrough.
                match sd.connector.connect(&authority, flow.dst).await {
                    Ok(mut up) => {
                        let _ = tokio::io::copy_bidirectional(&mut flow.stream, &mut up).await;
                    }
                    Err(e) => {
                        tracing::warn!(
                            dst = %flow.dst,
                            error = %e,
                            "captured-stream passthrough: upstream dial failed"
                        );
                    }
                }
                StreamOutcome::PassedThrough
            }
        }
    }

    /// Dispatch a captured UDP flow over the **existing** L4 path: each datagram goes
    /// through the same [`L4Guard::check`](aitm_proto_l4::guard::L4Guard::check)
    /// `(Capture, target)` a `pcap`-fed packet passes — no new guard. [`Captured`] if at
    /// least one datagram was authorized and stored, else [`Refused`]; [`Unhandled`] when
    /// no L4 backend is wired.
    ///
    /// [`Captured`]: IngressOutcome::Captured
    /// [`Refused`]: IngressOutcome::Refused
    /// [`Unhandled`]: IngressOutcome::Unhandled
    /// The admission decision for a captured UDP flow to `target`, taken **without**
    /// any datagram payload — the same `(Capture, target)` check
    /// [`dispatch_udp`](CoreIngress::dispatch_udp) applies per datagram, exposed so a
    /// capture backend refuses an out-of-scope flow *before* buffering its payload
    /// (guard-before-work, mirroring [`dispatch_tcp`](CoreIngress::dispatch_tcp)).
    /// [`Unhandled`] when no L4 backend is wired; [`Refused`] when the guard refuses;
    /// [`Captured`] means **admitted** (the guard passed) — nothing is stored by this
    /// check, the caller then streams and dispatches the datagrams.
    ///
    /// [`Captured`]: IngressOutcome::Captured
    /// [`Refused`]: IngressOutcome::Refused
    /// [`Unhandled`]: IngressOutcome::Unhandled
    #[must_use]
    pub fn udp_admits(&self, target: &L4Target) -> IngressOutcome {
        match &self.l4 {
            None => IngressOutcome::Unhandled,
            Some(l4) => {
                if l4.guard.check(L4Action::Capture, target).is_ok() {
                    IngressOutcome::Captured
                } else {
                    IngressOutcome::Refused
                }
            }
        }
    }

    pub fn dispatch_udp(&self, flow: CapturedUdpFlow) -> IngressOutcome {
        if self.l4.is_none() {
            return IngressOutcome::Unhandled;
        }
        let mut captured = 0usize;
        for datagram in flow.datagrams {
            if self.accept(CapturedUnit::L4 {
                target: flow.target.clone(),
                bytes: datagram,
            }) == IngressOutcome::Captured
            {
                captured += 1;
            }
        }
        if captured >= 1 {
            IngressOutcome::Captured
        } else {
            IngressOutcome::Refused
        }
    }
}

/// The stream half of the ingress: the shared dispatch wiring a captured TCP flow is
/// routed through — the ordered module list, the flow store, the event chain, the
/// guarded upstream connector, and the L7 scope guard.
struct StreamDispatch {
    modules: Arc<[Arc<dyn aitm_core::ProtocolModule>]>,
    store: Arc<dyn aitm_core::FlowStore>,
    sink: Arc<dyn aitm_core::EventSink>,
    connector: Arc<dyn aitm_core::UpstreamConnector>,
    guard: Arc<dyn aitm_core::ScopeRateGuard>,
}

/// Dispatch a captured TCP/stream flow through `ingress`. The entry point a capture
/// backend (macOS-NE Band B) calls; delegates to [`CoreIngress::dispatch_tcp`]. A free
/// function because the stream-wired, async dispatch cannot ride the object-safe
/// [`CaptureIngress`] trait without a new `async-trait` dependency.
pub async fn dispatch_captured_tcp(ingress: &CoreIngress, flow: CapturedTcpFlow) -> StreamOutcome {
    ingress.dispatch_tcp(flow).await
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
            packets: std::collections::VecDeque::new(),
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
        // Deny-by-default guard with a single Capture grant on 127.0.0.1, seeded
        // via config scope (the ungated, operator-authority path) since the runtime
        // `add_scope` is crate-private to aitm-proto-l4.
        let mut cfg = L4Config::default();
        cfg.scope.push(capture_entry("127.0.0.1"));
        let guard = Arc::new(L4Guard::new(&cfg));
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

    // ---- Task 2: captured TCP/stream dispatch ----

    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use aitm_core::{
        ActionPermit, ByteStream, Event, EventSink, FlowStore, GuardError, MemFlowStore, ModuleCtx,
        NextLayerHint, ProtocolModule, ScopeEntry, ScopeRateGuard, UpstreamConnector, Verdict,
    };
    use futures::future::BoxFuture;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// A scope guard whose only consulted method is `in_scope`, fixed per test; it
    /// records every authority it is asked about, so a test can assert exactly what
    /// `dispatch_tcp` gates on.
    struct MockGuard {
        in_scope: bool,
        asked: Mutex<Vec<String>>,
    }

    impl MockGuard {
        fn fixed(in_scope: bool) -> Self {
            Self {
                in_scope,
                asked: Mutex::new(Vec::new()),
            }
        }
    }

    impl ScopeRateGuard for MockGuard {
        fn check_active(&self, _host: &str) -> Result<ActionPermit, GuardError> {
            unreachable!("dispatch_tcp consults only in_scope")
        }
        fn add_scope(&self, _entry: ScopeEntry) {}
        fn remove_scope(&self, _entry: &str) -> bool {
            false
        }
        fn list_scope(&self) -> Vec<ScopeEntry> {
            Vec::new()
        }
        fn in_scope(&self, host: &str) -> bool {
            self.asked
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(host.to_string());
            self.in_scope
        }
    }

    /// An event sink that is never emitted to in these tests (no module emits).
    struct MockSink;

    impl EventSink for MockSink {
        fn emit(&self, _ev: Event) -> BoxFuture<'_, Verdict> {
            Box::pin(async { unreachable!("no event is emitted in these tests") })
        }
    }

    /// A stub module: claims or not per `claims`, counts spawns, and records the
    /// `NextLayerHint` it was spawned with so the test can assert the dst/SNI.
    struct StubModule {
        claims: bool,
        spawn_calls: Arc<AtomicUsize>,
        recorded: Arc<Mutex<Option<NextLayerHint>>>,
    }

    impl ProtocolModule for StubModule {
        fn id(&self) -> &str {
            "stub"
        }
        fn matches(&self, _hint: &NextLayerHint) -> bool {
            self.claims
        }
        fn spawn(&self, _io: ByteStream, ctx: ModuleCtx) -> BoxFuture<'_, anyhow::Result<()>> {
            self.spawn_calls.fetch_add(1, Ordering::SeqCst);
            if let Some(h) = ctx.hint() {
                *self.recorded.lock().unwrap_or_else(PoisonError::into_inner) = Some(h.clone());
            }
            Box::pin(async { Ok(()) })
        }
    }

    /// A connector that counts dials and hands back a pre-seeded upstream stream once.
    struct MockConnector {
        dial_calls: Arc<AtomicUsize>,
        upstream: Mutex<Option<ByteStream>>,
    }

    impl UpstreamConnector for MockConnector {
        fn connect(
            &self,
            _authority: &str,
            _dst: SocketAddr,
        ) -> BoxFuture<'_, anyhow::Result<ByteStream>> {
            self.dial_calls.fetch_add(1, Ordering::SeqCst);
            let taken = self
                .upstream
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .take();
            Box::pin(async move { taken.ok_or_else(|| anyhow::anyhow!("no upstream seeded")) })
        }
    }

    fn store() -> Arc<dyn FlowStore> {
        Arc::new(MemFlowStore::with_limits(16, 1 << 20))
    }

    /// A tiny open duplex end, for a flow stream whose bytes a test does not drive.
    fn dummy_stream() -> ByteStream {
        Box::pin(tokio::io::duplex(16).0)
    }

    /// AC17 (stream half): an in-scope flow a module claims is dispatched, and the
    /// module is spawned with the **authoritative original destination** as the hint's
    /// `dst` (not an accepted-socket peer) and the SNI the backend observed.
    #[tokio::test]
    async fn tcp_flow_dispatches_to_http_with_original_dst() {
        let spawn_calls = Arc::new(AtomicUsize::new(0));
        let recorded = Arc::new(Mutex::new(None));
        let module: Arc<dyn ProtocolModule> = Arc::new(StubModule {
            claims: true,
            spawn_calls: spawn_calls.clone(),
            recorded: recorded.clone(),
        });
        let dial_calls = Arc::new(AtomicUsize::new(0));
        let connector: Arc<dyn UpstreamConnector> = Arc::new(MockConnector {
            dial_calls: dial_calls.clone(),
            upstream: Mutex::new(None),
        });
        let ingress = CoreIngress::empty().with_stream(
            Arc::from(vec![module]),
            store(),
            Arc::new(MockSink),
            connector,
            Arc::new(MockGuard::fixed(true)),
        );

        let flow = CapturedTcpFlow {
            stream: dummy_stream(),
            dst: "93.184.216.34:443".parse().unwrap(),
            sni: Some("example.com".to_string()),
            first_bytes: vec![0x16, 0x03, 0x01],
            peer_identity: None,
            interface: "test-if".to_string(),
        };

        assert_eq!(ingress.dispatch_tcp(flow).await, StreamOutcome::Dispatched);
        assert_eq!(
            spawn_calls.load(Ordering::SeqCst),
            1,
            "the module is spawned"
        );
        assert_eq!(
            dial_calls.load(Ordering::SeqCst),
            0,
            "a claimed flow is not dialled"
        );
        let hint = recorded
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
            .expect("the module recorded its hint");
        assert_eq!(
            hint.dst.to_string(),
            "93.184.216.34:443",
            "the hint carries the authoritative original dst, not a socket peer"
        );
        assert_eq!(hint.client_hello_sni.as_deref(), Some("example.com"));
        assert_eq!(
            hint.peer_identity, None,
            "a backend that sent no identity yields none — never a placeholder"
        );
        assert_eq!(
            hint.capture_interface.as_deref(),
            Some("test-if"),
            "the backend's interface name rides the hint as the ingress received it"
        );
    }

    /// SA-AC0: the source-app identity and the backend's interface name a captured
    /// flow arrives with ride the hint the claiming module is spawned with, verbatim.
    /// The ingress copies the interface name; it does not know any backend's.
    #[tokio::test]
    async fn captured_tcp_identity_rides_the_hint() {
        let spawn_calls = Arc::new(AtomicUsize::new(0));
        let recorded = Arc::new(Mutex::new(None));
        let module: Arc<dyn ProtocolModule> = Arc::new(StubModule {
            claims: true,
            spawn_calls: spawn_calls.clone(),
            recorded: recorded.clone(),
        });
        let connector: Arc<dyn UpstreamConnector> = Arc::new(MockConnector {
            dial_calls: Arc::new(AtomicUsize::new(0)),
            upstream: Mutex::new(None),
        });
        let ingress = CoreIngress::empty().with_stream(
            Arc::from(vec![module]),
            store(),
            Arc::new(MockSink),
            connector,
            Arc::new(MockGuard::fixed(true)),
        );

        let flow = CapturedTcpFlow {
            stream: dummy_stream(),
            dst: "93.184.216.34:443".parse().unwrap(),
            sni: Some("example.com".to_string()),
            first_bytes: vec![0x16, 0x03, 0x01],
            peer_identity: Some("com.apple.Safari".to_string()),
            interface: "macos-ne".to_string(),
        };

        assert_eq!(ingress.dispatch_tcp(flow).await, StreamOutcome::Dispatched);
        assert_eq!(spawn_calls.load(Ordering::SeqCst), 1);
        let hint = recorded
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
            .expect("the module recorded its hint");
        assert_eq!(hint.peer_identity.as_deref(), Some("com.apple.Safari"));
        assert_eq!(hint.capture_interface.as_deref(), Some("macos-ne"));
    }

    /// AC17 (stream half): an out-of-scope flow is refused before any module match,
    /// spawn, or connector dial.
    #[tokio::test]
    async fn out_of_scope_tcp_refused_before_any_work() {
        let spawn_calls = Arc::new(AtomicUsize::new(0));
        let module: Arc<dyn ProtocolModule> = Arc::new(StubModule {
            claims: true,
            spawn_calls: spawn_calls.clone(),
            recorded: Arc::new(Mutex::new(None)),
        });
        let dial_calls = Arc::new(AtomicUsize::new(0));
        let connector: Arc<dyn UpstreamConnector> = Arc::new(MockConnector {
            dial_calls: dial_calls.clone(),
            upstream: Mutex::new(None),
        });
        let ingress = CoreIngress::empty().with_stream(
            Arc::from(vec![module]),
            store(),
            Arc::new(MockSink),
            connector,
            Arc::new(MockGuard::fixed(false)),
        );

        let flow = CapturedTcpFlow {
            stream: dummy_stream(),
            dst: "93.184.216.34:443".parse().unwrap(),
            sni: Some("example.com".to_string()),
            first_bytes: vec![0x16, 0x03, 0x01],
            peer_identity: None,
            interface: "test-if".to_string(),
        };

        assert_eq!(ingress.dispatch_tcp(flow).await, StreamOutcome::Refused);
        assert_eq!(
            spawn_calls.load(Ordering::SeqCst),
            0,
            "no module is spawned"
        );
        assert_eq!(
            dial_calls.load(Ordering::SeqCst),
            0,
            "no upstream is dialled"
        );
    }

    /// Dispatch one captured flow through an ingress whose only module claims
    /// everything, against `guard`: the outcome is `Dispatched` iff the guard admits
    /// the authority `dispatch_tcp` builds. The stream is never read.
    async fn gate_only(
        guard: Arc<dyn ScopeRateGuard>,
        sni: Option<&str>,
        dst: &str,
    ) -> StreamOutcome {
        let module: Arc<dyn ProtocolModule> = Arc::new(StubModule {
            claims: true,
            spawn_calls: Arc::new(AtomicUsize::new(0)),
            recorded: Arc::new(Mutex::new(None)),
        });
        let connector: Arc<dyn UpstreamConnector> = Arc::new(MockConnector {
            dial_calls: Arc::new(AtomicUsize::new(0)),
            upstream: Mutex::new(None),
        });
        let ingress = CoreIngress::empty().with_stream(
            Arc::from(vec![module]),
            store(),
            Arc::new(MockSink),
            connector,
            guard,
        );
        ingress
            .dispatch_tcp(CapturedTcpFlow {
                stream: dummy_stream(),
                dst: dst.parse().unwrap(),
                sni: sni.map(str::to_string),
                first_bytes: b"GET / HTTP/1.1\r\n".to_vec(),
                peer_identity: None,
                interface: "test-if".to_string(),
            })
            .await
    }

    /// The scope gate sees `host:port` — the handoff hostname (or the dst IP when the
    /// backend knows none) WITH the destination port, bracketed for IPv6 — never a bare
    /// host, so port-qualified scope entries can match a captured flow at all.
    #[tokio::test]
    async fn captured_tcp_is_gated_on_host_and_port() {
        let guard = Arc::new(MockGuard::fixed(true));
        let as_guard: Arc<dyn ScopeRateGuard> = guard.clone();
        assert_eq!(
            gate_only(
                as_guard.clone(),
                Some("www.example.com"),
                "93.184.216.34:80"
            )
            .await,
            StreamOutcome::Dispatched
        );
        assert_eq!(
            gate_only(as_guard.clone(), None, "93.184.216.34:443").await,
            StreamOutcome::Dispatched
        );
        assert_eq!(
            gate_only(as_guard.clone(), None, "[2001:db8::1]:8443").await,
            StreamOutcome::Dispatched
        );
        // The plain-name length cap: 253 bytes is still a hostname, 254 is not and
        // gates on the dst IP instead.
        let longest = "a".repeat(253);
        let too_long = "a".repeat(254);
        _ = gate_only(as_guard.clone(), Some(&longest), "93.184.216.34:443").await;
        _ = gate_only(as_guard, Some(&too_long), "93.184.216.34:443").await;
        assert_eq!(
            *guard.asked.lock().unwrap_or_else(PoisonError::into_inner),
            vec![
                "www.example.com:80".to_string(),
                "93.184.216.34:443".to_string(),
                "[2001:db8::1]:8443".to_string(),
                format!("{longest}:443"),
                "93.184.216.34:443".to_string(),
            ]
        );
    }

    /// Against the real `StdGuard`: a port-qualified entry admits a captured flow on
    /// that port only, a portless entry admits any port, and an unrelated host is
    /// refused — the same semantics `Authority::matches_scope_entry` gives a proxied
    /// request.
    #[tokio::test]
    async fn port_qualified_scope_entry_admits_a_captured_flow_on_that_port_only() {
        let guard = Arc::new(aitm_core::StdGuard::default());
        guard.add_scope(ScopeEntry {
            host: "www.example.com:80".to_string(),
        });
        guard.add_scope(ScopeEntry {
            host: "api.example.com".to_string(),
        });
        let guard: Arc<dyn ScopeRateGuard> = guard;

        assert_eq!(
            gate_only(guard.clone(), Some("www.example.com"), "93.184.216.34:80").await,
            StreamOutcome::Dispatched,
            "host:port entry admits the flow on that port"
        );
        assert_eq!(
            gate_only(guard.clone(), Some("www.example.com"), "93.184.216.34:443").await,
            StreamOutcome::Refused,
            "host:port entry refuses another port"
        );
        assert_eq!(
            gate_only(guard.clone(), Some("api.example.com"), "93.184.216.34:443").await,
            StreamOutcome::Dispatched,
            "a portless entry admits any port"
        );
        assert_eq!(
            gate_only(guard.clone(), Some("api.example.com"), "93.184.216.34:8443").await,
            StreamOutcome::Dispatched
        );
        assert_eq!(
            gate_only(guard, Some("evil.example"), "93.184.216.34:80").await,
            StreamOutcome::Refused,
            "an unrelated host is refused"
        );
    }

    /// Backend-supplied hostname text that is not a plain DNS name — a `:port`, a
    /// bracket, a path, whitespace — is not trusted as the scope host: the flow gates
    /// on its dst IP instead, which a host entry cannot admit. In particular an SNI
    /// carrying `:80` must not override the real dst port in the match.
    #[tokio::test]
    async fn hostile_hostname_shapes_are_not_trusted_as_the_scope_host() {
        let guard = Arc::new(aitm_core::StdGuard::default());
        guard.add_scope(ScopeEntry {
            host: "scope.example".to_string(),
        });
        guard.add_scope(ScopeEntry {
            host: "scope.example:80".to_string(),
        });
        let guard: Arc<dyn ScopeRateGuard> = guard;

        assert_eq!(
            gate_only(guard.clone(), Some("scope.example"), "93.184.216.34:443").await,
            StreamOutcome::Dispatched,
            "the plain name is admitted"
        );
        for hostile in [
            "scope.example:80",
            "[scope.example",
            "scope.example]",
            "scope.example/x",
            "scope example",
            "scope.example\n",
            "",
        ] {
            assert_eq!(
                gate_only(guard.clone(), Some(hostile), "93.184.216.34:443").await,
                StreamOutcome::Refused,
                "{hostile:?} is not a hostname and must not match a host entry"
            );
        }
        // The same shapes are harmless when the dst IP itself is in scope.
        let by_ip = Arc::new(aitm_core::StdGuard::default());
        by_ip.add_scope(ScopeEntry {
            host: "93.184.216.34".to_string(),
        });
        let by_ip: Arc<dyn ScopeRateGuard> = by_ip;
        assert_eq!(
            gate_only(by_ip, Some("[scope.example"), "93.184.216.34:443").await,
            StreamOutcome::Dispatched,
            "an IP entry admits the flow by its dst, whatever the hostname text"
        );
    }

    /// AC17 (stream half): an in-scope flow no module claims is passed through — the
    /// original dst is dialled once and bytes are tunnelled verbatim, not dropped.
    #[tokio::test]
    async fn in_scope_unclaimed_tcp_passes_through_not_dropped() {
        let spawn_calls = Arc::new(AtomicUsize::new(0));
        let module: Arc<dyn ProtocolModule> = Arc::new(StubModule {
            claims: false,
            spawn_calls: spawn_calls.clone(),
            recorded: Arc::new(Mutex::new(None)),
        });

        // The client stream: the flow holds one end, the test drives the other.
        let (mut client_ctl, client_io) = tokio::io::duplex(1024);
        // The upstream the connector hands back; the test holds the far end.
        let (up_near, mut up_far) = tokio::io::duplex(1024);

        let dial_calls = Arc::new(AtomicUsize::new(0));
        let connector: Arc<dyn UpstreamConnector> = Arc::new(MockConnector {
            dial_calls: dial_calls.clone(),
            upstream: Mutex::new(Some(Box::pin(up_near))),
        });
        let ingress = CoreIngress::empty().with_stream(
            Arc::from(vec![module]),
            store(),
            Arc::new(MockSink),
            connector,
            Arc::new(MockGuard::fixed(true)),
        );

        let flow = CapturedTcpFlow {
            stream: Box::pin(client_io),
            dst: "93.184.216.34:443".parse().unwrap(),
            sni: Some("example.com".to_string()),
            first_bytes: b"GET / HTTP/1.1\r\n".to_vec(),
            peer_identity: None,
            interface: "test-if".to_string(),
        };

        let (outcome, _) = tokio::join!(ingress.dispatch_tcp(flow), async {
            client_ctl.write_all(b"hello").await.unwrap();
            client_ctl.shutdown().await.unwrap();
            drop(client_ctl);
            let mut got = Vec::new();
            up_far.read_to_end(&mut got).await.unwrap();
            assert_eq!(
                got, b"hello",
                "client bytes are tunnelled to the upstream verbatim"
            );
            drop(up_far);
        });

        assert_eq!(outcome, StreamOutcome::PassedThrough);
        assert_eq!(
            spawn_calls.load(Ordering::SeqCst),
            0,
            "no module claimed the flow"
        );
        assert_eq!(
            dial_calls.load(Ordering::SeqCst),
            1,
            "the original dst is dialled once"
        );
    }

    /// AC17 (stream half): an in-scope flow no module claims whose upstream **dial
    /// fails** is still reported [`StreamOutcome::PassedThrough`] (the flow was taken,
    /// not silently dropped), and the dial was attempted exactly once. Carry-over
    /// Minor (c) from the PR #47 panel.
    #[tokio::test]
    async fn in_scope_unclaimed_tcp_passthrough_survives_dial_failure() {
        let spawn_calls = Arc::new(AtomicUsize::new(0));
        let module: Arc<dyn ProtocolModule> = Arc::new(StubModule {
            claims: false,
            spawn_calls: spawn_calls.clone(),
            recorded: Arc::new(Mutex::new(None)),
        });
        // No upstream seeded → the connector returns an error on dial.
        let dial_calls = Arc::new(AtomicUsize::new(0));
        let connector: Arc<dyn UpstreamConnector> = Arc::new(MockConnector {
            dial_calls: dial_calls.clone(),
            upstream: Mutex::new(None),
        });
        let ingress = CoreIngress::empty().with_stream(
            Arc::from(vec![module]),
            store(),
            Arc::new(MockSink),
            connector,
            Arc::new(MockGuard::fixed(true)),
        );

        let flow = CapturedTcpFlow {
            stream: dummy_stream(),
            dst: "93.184.216.34:443".parse().unwrap(),
            sni: Some("example.com".to_string()),
            first_bytes: b"GET / HTTP/1.1\r\n".to_vec(),
            peer_identity: None,
            interface: "test-if".to_string(),
        };

        assert_eq!(
            ingress.dispatch_tcp(flow).await,
            StreamOutcome::PassedThrough,
            "a dial failure is still a taken flow, not a drop"
        );
        assert_eq!(
            spawn_calls.load(Ordering::SeqCst),
            0,
            "no module claimed it"
        );
        assert_eq!(
            dial_calls.load(Ordering::SeqCst),
            1,
            "the original dst is dialled exactly once, even when it fails"
        );
    }

    /// AC17 (symmetry): a captured UDP flow rides the **same** deny-by-default L4 path.
    /// An in-scope datagram is admitted and stored; an out-of-scope one on the same
    /// interface is refused and reaches no store.
    #[test]
    fn udp_in_scope_admitted_out_of_scope_refused() {
        let mut cfg = L4Config::default();
        cfg.scope.push(capture_entry("127.0.0.1"));
        let guard = Arc::new(L4Guard::new(&cfg));
        let store: Arc<dyn L4FlowStore> = Arc::new(InMemoryL4FlowStore::new());
        let ingress = CoreIngress::with_l4(guard, store.clone());

        // In scope → admitted through the real L4 guard and stored.
        let in_flow = CapturedUdpFlow {
            target: l4_target("127.0.0.1"),
            datagrams: vec![b"probe".to_vec()],
            peer_identity: None,
        };
        assert_eq!(ingress.dispatch_udp(in_flow), IngressOutcome::Captured);
        assert_eq!(
            store.list().len(),
            1,
            "one capture flow holds the admitted datagram"
        );

        // Out of scope → refused by the same guard; nothing new is stored.
        let out_flow = CapturedUdpFlow {
            target: l4_target("127.0.0.2"),
            datagrams: vec![b"probe".to_vec()],
            peer_identity: None,
        };
        assert_eq!(ingress.dispatch_udp(out_flow), IngressOutcome::Refused);
        assert_eq!(
            store.list().len(),
            1,
            "the out-of-scope datagram reached no store"
        );
    }

    /// Guard-before-work: `udp_admits` decides from the target alone — an in-scope
    /// target is admitted (`Captured`), an out-of-scope one on the same interface is
    /// `Refused`, and an ingress with no L4 backend is `Unhandled` — all **without**
    /// storing anything, so a backend refuses before buffering a flow's payload.
    #[test]
    fn udp_admits_decides_from_target_without_storing() {
        let mut cfg = L4Config::default();
        cfg.scope.push(capture_entry("127.0.0.1"));
        let guard = Arc::new(L4Guard::new(&cfg));
        let store: Arc<dyn L4FlowStore> = Arc::new(InMemoryL4FlowStore::new());
        let ingress = CoreIngress::with_l4(guard, store.clone());

        assert_eq!(
            ingress.udp_admits(&l4_target("127.0.0.1")),
            IngressOutcome::Captured,
            "an in-scope target is admitted"
        );
        assert_eq!(
            ingress.udp_admits(&l4_target("127.0.0.2")),
            IngressOutcome::Refused,
            "an out-of-scope target is refused"
        );
        assert_eq!(
            CoreIngress::empty().udp_admits(&l4_target("127.0.0.1")),
            IngressOutcome::Unhandled,
            "no L4 backend wired is unhandled"
        );
        assert!(
            store.list().is_empty(),
            "an admission check stores nothing — the guard ran, no payload was buffered"
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
    /// ingress source — and the macOS capture adapter that feeds it — neither inject
    /// (`.inject(`) nor call the choke point (`send_on_wire(`); the single guarded
    /// wire write remains `aitm_proto_l4::wire::send_on_wire`, an `L4Permit` by type.
    /// A structural tripwire over the type-level proof (the permit is unforgeable),
    /// not the proof.
    #[test]
    fn one_choke_point_survives_ingress() {
        let aitm_src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        // Every capture source that reaches the ingress must stay read-only on the
        // wire: the ingress itself, the macOS capture-backend adapter, and the live
        // feeder that pumps captured flows into it.
        for rel in [
            "ingress.rs",
            "macos_capture/adapter.rs",
            "macos_capture/feeder.rs",
        ] {
            let source = std::fs::read_to_string(aitm_src.join(rel))
                .unwrap_or_else(|e| panic!("read {rel}: {e}"));
            let prod = production_prefix(&source);
            assert_eq!(
                prod.matches(".inject(").count(),
                0,
                "{rel} must not write to the wire"
            );
            assert_eq!(
                prod.matches("send_on_wire(").count(),
                0,
                "{rel} must not reach the wire-write choke point"
            );
        }

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
