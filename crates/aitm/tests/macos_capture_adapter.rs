//! Task 2 — the macOS capture-backend adapter → `CaptureIngress` (NE-AC1/2/3).
//!
//! A loopback UDS client stands in for the Band-C Swift provider: it dials the
//! per-flow data socket, sends the [`DataHandshake`], then the flow bytes (TCP) or
//! length-delimited datagrams (UDP). The core accepts the data connection and the
//! adapter turns the [`FlowOpen`] + data socket into the ingress's own flow types
//! and dispatches it. Provable in the sandbox with no Mac.
//!
//! - NE-AC1: a captured TCP flow reaches a protocol module with `hint.dst` = the
//!   authoritative original destination (not a socket peer).
//! - NE-AC2: a captured UDP flow enters behind `L4Guard`; an out-of-scope one is
//!   refused before any datagram is stored.
//! - NE-AC3: deny-by-default — an out-of-scope flow (TCP or UDP) is never
//!   dispatched; the guard below the ingress is authoritative.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use aitm::ingress::{CoreIngress, IngressOutcome, StreamOutcome};
use aitm::macos_capture::adapter::{dispatch_captured_flow, CaptureOutcome, CAPTURE_INTERFACE};
use aitm::macos_capture::listener::{
    write_data_handshake, write_datagram, CaptureListener, DataHandshake, FlowKind, FlowOpen,
};
use aitm_core::{
    ActionPermit, ByteStream, Event, EventSink, FlowStore, GuardError, MemFlowStore, ModuleCtx,
    NextLayerHint, ProtocolModule, ScopeEntry, ScopeRateGuard, UpstreamConnector, Verdict,
};
use aitm_proto_l4::config::L4Config;
use aitm_proto_l4::flow::{InMemoryL4FlowStore, L4FlowStore};
use aitm_proto_l4::guard::L4Guard;
use aitm_proto_l4::types::{
    IpCidr, L4Capability, L4Direction, L4ScopeEntry, L4ScopeId, L4ScopeSource, PortRange, RateCap,
};
use futures::future::BoxFuture;
use tokio::io::AsyncWriteExt;
use tokio::net::UnixStream;

// ---- A short-lived private temp dir (mirrors the listener test's pattern; a UDS
// path must stay under ~104 bytes, and $TMPDIR on macOS is already long). ----

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "ama-{tag}-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        Self(dir)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

// ---- Stream-dispatch doubles (same shapes the ingress's own unit tests use;
// those live in a private #[cfg(test)] module, so an integration test replicates
// them over the public `aitm_core` traits). ----

/// A scope guard whose only consulted method is `in_scope`, fixed per test.
struct MockGuard {
    in_scope: bool,
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
    fn in_scope(&self, _host: &str) -> bool {
        self.in_scope
    }
}

struct MockSink;

impl EventSink for MockSink {
    fn emit(&self, _ev: Event) -> BoxFuture<'_, Verdict> {
        Box::pin(async { unreachable!("no event is emitted in these tests") })
    }
}

/// A stub module: claims or not, counts spawns, and records the `NextLayerHint` it
/// was spawned with so the test can assert the authoritative dst / SNI.
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

/// A connector that counts dials; it hands back nothing (no passthrough is
/// exercised here — the claimed/refused cases never dial).
struct MockConnector {
    dial_calls: Arc<AtomicUsize>,
}

impl UpstreamConnector for MockConnector {
    fn connect(
        &self,
        _authority: &str,
        _dst: SocketAddr,
    ) -> BoxFuture<'_, anyhow::Result<ByteStream>> {
        self.dial_calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Err(anyhow::anyhow!("no upstream seeded")) })
    }
}

fn l7_store() -> Arc<dyn FlowStore> {
    Arc::new(MemFlowStore::with_limits(16, 1 << 20))
}

/// Wire a stream ingress with one stub module and a fixed-scope guard.
fn tcp_ingress(
    claims: bool,
    in_scope: bool,
    spawn_calls: Arc<AtomicUsize>,
    dial_calls: Arc<AtomicUsize>,
    recorded: Arc<Mutex<Option<NextLayerHint>>>,
) -> CoreIngress {
    let module: Arc<dyn ProtocolModule> = Arc::new(StubModule {
        claims,
        spawn_calls,
        recorded,
    });
    CoreIngress::empty().with_stream(
        Arc::from(vec![module]),
        l7_store(),
        Arc::new(MockSink),
        Arc::new(MockConnector { dial_calls }),
        Arc::new(MockGuard { in_scope }),
    )
}

/// A `Capture` scope entry for one host on the NE capture interface, outbound.
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
        interface: CAPTURE_INTERFACE.to_string(),
        direction: L4Direction::Outbound,
        capability: L4Capability::Capture,
        inject_rate: RateCap { pps: 10, burst: 10 },
        source: L4ScopeSource::Config,
    }
}

fn udp_ingress(scoped_host: &str) -> (CoreIngress, Arc<dyn L4FlowStore>) {
    let mut cfg = L4Config::default();
    cfg.scope.push(capture_entry(scoped_host));
    let guard = Arc::new(L4Guard::new(&cfg));
    let store: Arc<dyn L4FlowStore> = Arc::new(InMemoryL4FlowStore::new());
    (CoreIngress::with_l4(guard, store.clone()), store)
}

/// Feed a synthesized TCP flow through the adapter: the provider writes
/// `first_bytes` on the data socket, the core accepts it, and the adapter adapts +
/// dispatches `open`. Returns the adapter outcome.
async fn run_tcp_flow(
    ingress: &CoreIngress,
    open: FlowOpen,
    first_bytes: Vec<u8>,
) -> CaptureOutcome {
    let tmp = TempDir::new("tcp");
    let listener = CaptureListener::bind(tmp.path().join("s")).expect("bind");
    let data_path = listener.data_path();
    let flow_id = open.flow_id;
    let provider = tokio::spawn(async move {
        let mut data = UnixStream::connect(&data_path).await.expect("connect data");
        write_data_handshake(&mut data, DataHandshake { flow_id })
            .await
            .expect("handshake");
        data.write_all(&first_bytes).await.expect("write bytes");
        data.shutdown().await.expect("shutdown");
    });

    let data = listener.accept_data().await.expect("accept data");
    let outcome = dispatch_captured_flow(ingress, &open, data)
        .await
        .expect("dispatch");
    provider.await.expect("provider task");
    drop(tmp);
    outcome
}

/// Feed a synthesized UDP flow through the adapter: the provider writes each
/// datagram length-delimited on the data socket, the core accepts it, and the
/// adapter adapts + dispatches `open`.
async fn run_udp_flow(
    ingress: &CoreIngress,
    open: FlowOpen,
    datagrams: Vec<Vec<u8>>,
) -> CaptureOutcome {
    let tmp = TempDir::new("udp");
    let listener = CaptureListener::bind(tmp.path().join("s")).expect("bind");
    let data_path = listener.data_path();
    let flow_id = open.flow_id;
    let provider = tokio::spawn(async move {
        let mut data = UnixStream::connect(&data_path).await.expect("connect data");
        write_data_handshake(&mut data, DataHandshake { flow_id })
            .await
            .expect("handshake");
        for dg in &datagrams {
            write_datagram(&mut data, dg).await.expect("write datagram");
        }
        data.shutdown().await.expect("shutdown");
    });

    let data = listener.accept_data().await.expect("accept data");
    let outcome = dispatch_captured_flow(ingress, &open, data)
        .await
        .expect("dispatch");
    provider.await.expect("provider task");
    drop(tmp);
    outcome
}

/// NE-AC1: a captured TCP flow (bytes + authoritative original destination + SNI)
/// reaches the HTTP-style module with `hint.dst` = the **original destination**,
/// and the source-app id rode in as `peer_identity` (mapping proven in the
/// adapter's unit tests). An out-of-scope flow is refused before any dispatch
/// (NE-AC3).
#[tokio::test]
async fn macos_tcp_flow_adapts_and_dispatches() {
    let spawn_calls = Arc::new(AtomicUsize::new(0));
    let dial_calls = Arc::new(AtomicUsize::new(0));
    let recorded = Arc::new(Mutex::new(None));
    let ingress = tcp_ingress(
        true,
        true,
        spawn_calls.clone(),
        dial_calls.clone(),
        recorded.clone(),
    );

    let open = FlowOpen {
        flow_id: 1,
        kind: FlowKind::Tcp,
        remote: "93.184.216.34:443".parse().unwrap(),
        remote_hostname: Some("example.com".to_string()),
        source_app: Some("com.example.browser".to_string()),
        local: None,
    };
    let outcome = run_tcp_flow(&ingress, open, vec![0x16, 0x03, 0x01, 0x00, 0x05]).await;

    assert_eq!(outcome, CaptureOutcome::Tcp(StreamOutcome::Dispatched));
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
        .expect("module recorded its hint");
    assert_eq!(
        hint.dst.to_string(),
        "93.184.216.34:443",
        "the hint carries the authoritative original dst, not a socket peer"
    );
    assert_eq!(hint.client_hello_sni.as_deref(), Some("example.com"));

    // NE-AC3: an out-of-scope TCP flow is refused before any module match or dial.
    let spawn_calls = Arc::new(AtomicUsize::new(0));
    let dial_calls = Arc::new(AtomicUsize::new(0));
    let ingress = tcp_ingress(
        true,
        false,
        spawn_calls.clone(),
        dial_calls.clone(),
        Arc::new(Mutex::new(None)),
    );
    let open = FlowOpen {
        flow_id: 2,
        kind: FlowKind::Tcp,
        remote: "93.184.216.34:443".parse().unwrap(),
        remote_hostname: Some("example.com".to_string()),
        source_app: None,
        local: None,
    };
    let outcome = run_tcp_flow(&ingress, open, Vec::new()).await;
    assert_eq!(outcome, CaptureOutcome::Tcp(StreamOutcome::Refused));
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

/// NE-AC2 / NE-AC3: a captured UDP flow enters behind `L4Guard`. An in-scope
/// datagram is admitted and stored as a capture flow; an out-of-scope flow on the
/// same interface is refused by the guard and reaches no store.
#[tokio::test]
async fn macos_udp_flow_adapts_and_dispatches() {
    let (ingress, store) = udp_ingress("127.0.0.1");

    let in_open = FlowOpen {
        flow_id: 10,
        kind: FlowKind::Udp,
        remote: "127.0.0.1:53".parse().unwrap(),
        remote_hostname: None,
        source_app: Some("com.example.resolver".to_string()),
        local: Some("127.0.0.1:50000".parse().unwrap()),
    };
    let outcome = run_udp_flow(&ingress, in_open, vec![b"probe".to_vec()]).await;
    assert_eq!(outcome, CaptureOutcome::Udp(IngressOutcome::Captured));
    assert_eq!(
        store.list().len(),
        1,
        "one capture flow holds the admitted datagram"
    );

    let out_open = FlowOpen {
        flow_id: 11,
        kind: FlowKind::Udp,
        remote: "127.0.0.2:53".parse().unwrap(),
        remote_hostname: None,
        source_app: None,
        local: Some("127.0.0.1:50001".parse().unwrap()),
    };
    let outcome = run_udp_flow(&ingress, out_open, vec![b"probe".to_vec()]).await;
    assert_eq!(outcome, CaptureOutcome::Udp(IngressOutcome::Refused));
    assert_eq!(
        store.list().len(),
        1,
        "the out-of-scope datagram reached no store"
    );
}

/// A control flow-open paired with the wrong data socket is refused before any
/// dispatch — the adapter never routes a mis-paired flow (fail-closed).
#[tokio::test]
async fn flow_id_mismatch_is_refused() {
    let tmp = TempDir::new("mismatch");
    let listener = CaptureListener::bind(tmp.path().join("s")).expect("bind");
    let data_path = listener.data_path();
    let provider = tokio::spawn(async move {
        let mut data = UnixStream::connect(&data_path).await.expect("connect data");
        write_data_handshake(&mut data, DataHandshake { flow_id: 999 })
            .await
            .expect("handshake");
        data.shutdown().await.expect("shutdown");
    });

    let data = listener.accept_data().await.expect("accept data");
    let open = FlowOpen {
        flow_id: 7,
        kind: FlowKind::Tcp,
        remote: "93.184.216.34:443".parse().unwrap(),
        remote_hostname: None,
        source_app: None,
        local: None,
    };
    let err = dispatch_captured_flow(&CoreIngress::empty(), &open, data)
        .await
        .expect_err("a mis-paired data socket must be refused");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    provider.await.expect("provider task");
}
