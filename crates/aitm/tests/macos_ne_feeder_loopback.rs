//! Task 4 (macOS NE live-capture feeder plan) — the loopback fake-provider test.
//!
//! This test **acts as the Swift provider** over the real sockets. It starts a real
//! [`CaptureSession`] on a scratch socket directory and then does what
//! `FlowHandoff.swift` does: reads the rendezvous file, dials `control.sock`, sends
//! `Hello`, receives `Scope`, announces flows with `FlowOpen`, and dials `data.sock`
//! once per flow to send the handshake and the flow's bytes. The session under test
//! feeds a recording [`CoreIngress`] (a stub protocol module and an in-memory L4
//! store behind the real `L4Guard`).
//!
//! Acceptance criteria exercised end to end (spec LF-AC2/6/7/8/10):
//!
//! - **LF-AC2** the rendezvous file names the 0700 socket dir and is mode 0600;
//! - **LF-AC6** an in-scope TCP flow spawns the module with `hint.dst` = the
//!   authoritative remote, an out-of-scope one is refused; a UDP datagram lands in
//!   the L4 store in scope and is refused out of scope;
//! - **LF-AC7** a data socket whose peer the verifier rejects feeds no bytes, and the
//!   control channel and later flows are unaffected;
//! - **LF-AC8** only metadata crosses the control channel; bulk bytes cross the data
//!   sockets;
//! - **LF-AC10** on shutdown the rendezvous file and both socket files are gone and
//!   a running pump stops.
//!
//! # Running it
//!
//! The test **binds Unix domain sockets**, which the Bash sandbox refuses (EPERM), and
//! it writes the real rendezvous file at `RENDEZVOUS_PATH`. Run it through the
//! Terminal panel. Where the bind is refused it prints a skip notice and passes, so a
//! stray sandbox `cargo test` stays green without proving anything.
//!
//! `RENDEZVOUS_PATH` is one fixed system-wide path, so the tests here are serialized
//! on a lock, and the test must not run while a real `aitm` with
//! `macos_capture.enabled` is live on the same machine (they would fight over it).

use std::fs;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::os::fd::RawFd;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use aitm::ingress::CoreIngress;
use aitm::macos_capture::adapter::{CAPTURE_INTERFACE, HANDOFF_PROTOCOL_VERSION};
use aitm::macos_capture::feeder::CaptureSession;
use aitm::macos_capture::listener::{
    write_data_handshake, write_datagram, CaptureListener, ControlChannel, ControlMessage,
    DataHandshake, FlowKind, FlowOpen, Hello, ScopeSpec,
};
use aitm::macos_capture::peer_auth::PeerVerifier;
use aitm::macos_capture::rendezvous::RENDEZVOUS_PATH;
use aitm::macos_capture::scope_spec::provider_scope_spec;
use aitm_core::{
    ActionPermit, ByteStream, Event, EventSink, GuardError, MemFlowStore, ModuleCtx, NextLayerHint,
    ProtocolModule, ScopeEntry, ScopeRateGuard, UpstreamConnector, Verdict,
};
use aitm_proto_l4::config::L4Config;
use aitm_proto_l4::flow::{InMemoryL4FlowStore, L4FlowStore};
use aitm_proto_l4::guard::L4Guard;
use aitm_proto_l4::types::{
    IpCidr, L4Capability, L4Direction, L4ScopeEntry, L4ScopeId, L4ScopeSource, PortRange, RateCap,
};
use futures::future::BoxFuture;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

/// How long the test waits for anything that should happen promptly. A hang fails
/// with a named timeout instead of wedging the Terminal-panel gate.
const PROMPT: Duration = Duration::from_secs(5);

/// The notice printed when this environment cannot bind Unix sockets.
const SKIP_NOTICE: &str = "skipped: UDS bind unavailable (run via Terminal panel)";

/// The bytes the fake provider forwards on an in-scope TCP flow.
const HTTP_BYTES: &[u8] = b"GET / HTTP/1.1\r\nhi";

/// The authoritative remote of the in-scope TCP flows (the plan's literal).
const REMOTE: &str = "93.184.216.34:443";

/// The size of the bulk UDP datagram that proves bulk bytes cross the data socket.
const BULK_LEN: usize = 4096;

/// The wire size of the one `Scope` frame the core sends for the seeded scope
/// (`"example.com 198.51.100.7"`): a 4-byte length prefix and a 45-byte JSON body.
/// `control_frame_sizes_match_the_loopback_literals` keeps this honest without a bind.
const SCOPE_FRAME_LEN: u64 = 49;

// ---- Serialization: one fixed rendezvous path, so one session at a time. ----

static RENDEZVOUS_LOCK: Mutex<()> = Mutex::new(());

/// Drive `test` to completion on its own runtime while holding the rendezvous lock.
fn run_serialized(test: impl Future<Output = ()>) {
    let _serial = RENDEZVOUS_LOCK
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build the test runtime")
        .block_on(test);
}

/// Await `fut`, panicking with `what` if it does not finish within [`PROMPT`].
async fn within<T>(what: &str, fut: impl Future<Output = T>) -> T {
    tokio::time::timeout(PROMPT, fut)
        .await
        .unwrap_or_else(|_| panic!("timed out waiting for {what}"))
}

/// Poll `ready` every 10 ms until it holds, panicking with `what` after [`PROMPT`].
async fn until(what: &str, mut ready: impl FnMut() -> bool) {
    within(what, async {
        while !ready() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
}

// ---- A short scratch dir. A UDS path must stay under ~104 bytes and $TMPDIR on
// macOS is already long, so the names are kept short (see `rendezvous.rs`). ----

struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("nef-{tag}-{}", std::process::id()));
        fs::create_dir_all(&dir).expect("create the scratch dir");
        Self(dir)
    }

    /// The socket dir the session binds (created and locked 0700 by `bind`).
    fn socket_dir(&self) -> PathBuf {
        self.0.join("s")
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Whether this environment lets us bind the capture sockets and publish the
/// rendezvous file. Two environments can't, and both skip rather than fail: the Bash
/// sandbox refuses the UDS bind (EPERM, `PermissionDenied`); and a non-macOS host
/// (e.g. Linux CI) has no `/private/tmp`, so `publish_rendezvous` fails with
/// `NotFound` — the NE capture path is macOS-only. In either case the test prints
/// [`SKIP_NOTICE`] and returns so the run stays green. Any *other* failure is a real
/// error and panics. Everything the probe created is released again before it returns.
///
/// Must run inside the tokio runtime: binding a Unix listener registers with it.
fn uds_bind_available(socket_dir: &Path) -> bool {
    let cant_run_here =
        |k: io::ErrorKind| matches!(k, io::ErrorKind::PermissionDenied | io::ErrorKind::NotFound);
    let listener = match CaptureListener::bind(socket_dir) {
        Ok(listener) => listener,
        Err(e) if cant_run_here(e.kind()) => return false,
        Err(e) => panic!("binding the capture sockets failed for an unexpected reason: {e}"),
    };
    match listener.publish_rendezvous() {
        Ok(_guard) => true,
        Err(e) if cant_run_here(e.kind()) => false,
        Err(e) => panic!("publishing the rendezvous file failed for an unexpected reason: {e}"),
    }
}

// ---- The recording ingress. These are the doubles `ingress.rs`'s own tests use;
// they live in a private `#[cfg(test)]` module there, so the integration test
// replicates them over the public `aitm_core` traits. ----

/// The L7 scope guard, shared by the session (which lists its scope to push to the
/// provider) and by the ingress (which enforces it) — as in production. A real
/// [`StdGuard`](aitm_core::StdGuard) seeded once with the test's scope answers both
/// `list_scope` and `in_scope`, so the test asserts the real matching contract
/// (`host:port` authority, a portless entry admits any port) rather than a copy of
/// it; `check_active` stays unreachable because the feeder and the ingress must
/// consume no rate or concurrency budget.
struct SeededScope(aitm_core::StdGuard);

impl SeededScope {
    fn seeded(entries: Vec<ScopeEntry>) -> Self {
        let guard = aitm_core::StdGuard::default();
        for entry in entries {
            guard.add_scope(entry);
        }
        Self(guard)
    }
}

impl ScopeRateGuard for SeededScope {
    fn check_active(&self, _host: &str) -> Result<ActionPermit, GuardError> {
        unreachable!("the feeder and the ingress consult only list_scope / in_scope")
    }
    fn add_scope(&self, _entry: ScopeEntry) {}
    fn remove_scope(&self, _entry: &str) -> bool {
        false
    }
    fn list_scope(&self) -> Vec<ScopeEntry> {
        self.0.list_scope()
    }
    fn in_scope(&self, host: &str) -> bool {
        self.0.in_scope(host)
    }
}

struct MockSink;

impl EventSink for MockSink {
    fn emit(&self, _ev: Event) -> BoxFuture<'_, Verdict> {
        Box::pin(async { unreachable!("the stub module emits no events") })
    }
}

/// A stub module that claims every flow, counts its spawns, and records the
/// `NextLayerHint` it was spawned with (the authoritative dst, SNI, sniffed bytes).
struct StubModule {
    spawns: Arc<AtomicUsize>,
    recorded: Arc<Mutex<Option<NextLayerHint>>>,
}

impl ProtocolModule for StubModule {
    fn id(&self) -> &str {
        "stub"
    }
    fn matches(&self, _hint: &NextLayerHint) -> bool {
        true
    }
    fn spawn(&self, _io: ByteStream, ctx: ModuleCtx) -> BoxFuture<'_, anyhow::Result<()>> {
        self.spawns.fetch_add(1, Ordering::SeqCst);
        if let Some(hint) = ctx.hint() {
            *self.recorded.lock().unwrap_or_else(PoisonError::into_inner) = Some(hint.clone());
        }
        Box::pin(async { Ok(()) })
    }
}

/// A connector that counts dials. Nothing in this test may dial: a claimed flow is
/// handled by the module and a refused one stops before any dial.
struct MockConnector {
    dials: Arc<AtomicUsize>,
}

impl UpstreamConnector for MockConnector {
    fn connect(
        &self,
        _authority: &str,
        _dst: SocketAddr,
    ) -> BoxFuture<'_, anyhow::Result<ByteStream>> {
        self.dials.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Err(anyhow::anyhow!("no upstream is seeded")) })
    }
}

/// The L7 scope the session pushes and the ingress enforces.
fn l7_scope() -> Vec<ScopeEntry> {
    vec![ScopeEntry {
        host: "example.com".to_string(),
    }]
}

/// A `Capture` scope entry for `198.51.100.7` on the NE capture interface, outbound.
fn l4_scope() -> Vec<L4ScopeEntry> {
    vec![L4ScopeEntry {
        id: L4ScopeId::new(),
        cidr: IpCidr {
            addr: "198.51.100.7".parse().expect("valid address"),
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
    }]
}

/// What the recording ingress saw.
struct Observed {
    spawns: Arc<AtomicUsize>,
    dials: Arc<AtomicUsize>,
    recorded: Arc<Mutex<Option<NextLayerHint>>>,
    l4_store: Arc<dyn L4FlowStore>,
}

impl Observed {
    fn spawns(&self) -> usize {
        self.spawns.load(Ordering::SeqCst)
    }

    fn dials(&self) -> usize {
        self.dials.load(Ordering::SeqCst)
    }

    /// The hint the stub module was last spawned with, if it was ever spawned.
    fn hint(&self) -> Option<NextLayerHint> {
        self.recorded
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Packets stored across every L4 capture flow.
    fn packet_count(&self) -> usize {
        self.l4_store
            .list()
            .into_iter()
            .filter_map(|id| self.l4_store.get(id))
            .map(|flow| flow.packets.len())
            .sum()
    }
}

/// A [`CaptureSession`] over a recording ingress: the L7 stream half wired to
/// [`StubModule`] and the L4 half to the real `L4Guard` and an in-memory store, with
/// the session reading its scope from the same two guards the ingress enforces.
fn build_session(
    verifier: Arc<dyn PeerVerifier>,
    socket_dir: PathBuf,
) -> (CaptureSession, Observed) {
    let spawns = Arc::new(AtomicUsize::new(0));
    let dials = Arc::new(AtomicUsize::new(0));
    let recorded = Arc::new(Mutex::new(None));
    let module: Arc<dyn ProtocolModule> = Arc::new(StubModule {
        spawns: spawns.clone(),
        recorded: recorded.clone(),
    });

    let mut l4_config = L4Config::default();
    l4_config.scope.extend(l4_scope());
    let l4_guard = Arc::new(L4Guard::new(&l4_config));
    let l4_store: Arc<dyn L4FlowStore> = Arc::new(InMemoryL4FlowStore::new());
    let l7_guard = Arc::new(SeededScope::seeded(l7_scope()));

    let ingress = CoreIngress::with_l4(l4_guard.clone(), l4_store.clone()).with_stream(
        Arc::from(vec![module]),
        Arc::new(MemFlowStore::with_limits(16, 1 << 20)),
        Arc::new(MockSink),
        Arc::new(MockConnector {
            dials: dials.clone(),
        }),
        l7_guard.clone(),
    );
    let session = CaptureSession::new(
        Arc::new(ingress),
        l7_guard,
        Some(l4_guard),
        verifier,
        socket_dir,
    );
    (
        session,
        Observed {
            spawns,
            dials,
            recorded,
            l4_store,
        },
    )
}

// ---- The stand-in for the provider's code-signature check. ----

/// A [`PeerVerifier`] that answers from a script, one answer per call in call order
/// (the control peer is verified first, then each data peer as it is dialled), and
/// counts its calls. Past the script it answers `otherwise`.
struct ScriptedVerifier {
    script: Vec<bool>,
    otherwise: bool,
    calls: AtomicUsize,
}

impl ScriptedVerifier {
    /// Accepts every peer.
    fn accepting() -> Arc<Self> {
        Arc::new(Self {
            script: Vec::new(),
            otherwise: true,
            calls: AtomicUsize::new(0),
        })
    }

    /// Answers `script` in order, then rejects (fail-closed).
    fn scripted(script: Vec<bool>) -> Arc<Self> {
        Arc::new(Self {
            script,
            otherwise: false,
            calls: AtomicUsize::new(0),
        })
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl PeerVerifier for ScriptedVerifier {
    fn verify(&self, _fd: RawFd) -> bool {
        let call = self.calls.fetch_add(1, Ordering::SeqCst);
        self.script.get(call).copied().unwrap_or(self.otherwise)
    }
}

// ---- Running the session. ----

/// A session running on its own task, stopped through its `shutdown` future.
struct Running {
    stop: oneshot::Sender<()>,
    task: JoinHandle<()>,
}

impl Running {
    fn start(session: CaptureSession) -> Self {
        let (stop, stopped) = oneshot::channel::<()>();
        let task = tokio::spawn(session.run(async move {
            let _ = stopped.await;
        }));
        Self { stop, task }
    }

    /// Fire `shutdown` and wait for the session to return.
    async fn shutdown(self) {
        // A send error means the session already ended; the join below reports it.
        let _ = self.stop.send(());
        within("the session to stop after shutdown", self.task)
            .await
            .expect("the session task must not panic");
    }
}

/// Wait for the session to publish the rendezvous file and return its whole
/// contents. The file is created, then written, so wait for the trailing newline
/// that marks the write complete.
async fn wait_for_rendezvous() -> String {
    let mut last = String::new();
    let published = async {
        loop {
            if let Ok(contents) = fs::read_to_string(RENDEZVOUS_PATH) {
                if contents.ends_with('\n') {
                    return contents;
                }
                last = contents;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    };
    match tokio::time::timeout(PROMPT, published).await {
        Ok(contents) => contents,
        Err(_) => panic!("the session never completed its rendezvous file (last read: {last:?})"),
    }
}

/// LF-AC10: after shutdown the rendezvous file and both socket files are gone.
fn assert_cleaned_up(socket_dir: &Path) {
    assert!(
        !Path::new(RENDEZVOUS_PATH).exists(),
        "the rendezvous file is removed at shutdown"
    );
    assert!(
        !socket_dir.join("control.sock").exists(),
        "control.sock is removed at shutdown"
    );
    assert!(
        !socket_dir.join("data.sock").exists(),
        "data.sock is removed at shutdown"
    );
}

// ---- The fake provider. ----

/// The wire size of one control frame: a 4-byte length prefix plus the JSON body.
fn frame_len(msg: &ControlMessage) -> u64 {
    let body = serde_json::to_vec(msg).expect("serialize a control message");
    4 + u64::try_from(body.len()).expect("a control frame fits in u64")
}

/// The provider's side of an attachment: the control channel to the core and the
/// socket dir the rendezvous file named. It counts the control bytes it writes.
struct Provider {
    control: ControlChannel,
    dir: PathBuf,
    control_written: u64,
}

impl Provider {
    /// Dial `<dir>/control.sock` and announce ourselves with the `Hello` the core
    /// speaks.
    async fn attach(dir: PathBuf) -> Self {
        let stream = within(
            "connecting to control.sock",
            UnixStream::connect(dir.join("control.sock")),
        )
        .await
        .expect("connect to control.sock");
        let mut provider = Self {
            control: ControlChannel::from_stream(stream),
            dir,
            control_written: 0,
        };
        provider
            .send(ControlMessage::Hello(Hello {
                protocol_version: HANDOFF_PROTOCOL_VERSION,
            }))
            .await;
        provider
    }

    async fn send(&mut self, msg: ControlMessage) {
        self.control_written += frame_len(&msg);
        within("a control send", self.control.send(&msg))
            .await
            .expect("send on the control channel");
    }

    /// The next control message from the core, `None` at a clean end of stream.
    async fn next_message(&mut self) -> Option<ControlMessage> {
        within("the next control frame from the core", self.control.recv())
            .await
            .expect("a well-formed control frame")
    }

    /// Announce `open`, then dial `data.sock` once for it and send the handshake. The
    /// order is the provider's (control first); the core accepts either order.
    async fn open_flow(&mut self, open: FlowOpen) -> UnixStream {
        let flow_id = open.flow_id;
        self.send(ControlMessage::FlowOpen(open)).await;
        let mut data = within(
            "connecting to data.sock",
            UnixStream::connect(self.dir.join("data.sock")),
        )
        .await
        .expect("connect to data.sock");
        within(
            "the data handshake write",
            write_data_handshake(&mut data, DataHandshake { flow_id }),
        )
        .await
        .expect("write the data handshake");
        data
    }
}

/// Wait until the core closes `data`, which proves the pump that owned it has
/// finished (a claimed flow's module dropped the stream, a refused flow was dropped,
/// a rejected peer was cut off, a UDP flow reached end of stream). The core never
/// writes on a data socket, so reading any byte is itself a failure. A reset counts
/// as closed: a socket closed with our bytes unread resets the peer.
async fn wait_closed(data: &mut UnixStream, what: &str) {
    let mut buf = [0u8; 64];
    match within(what, data.read(&mut buf)).await {
        Ok(0) | Err(_) => {}
        Ok(n) => panic!("{what}: the core wrote {n} bytes on a data socket"),
    }
}

/// A TCP `FlowOpen` to `remote` carrying `hostname` as its SNI.
fn tcp_open(flow_id: u64, remote: &str, hostname: &str) -> FlowOpen {
    FlowOpen {
        flow_id,
        kind: FlowKind::Tcp,
        remote: remote.parse().expect("valid remote"),
        remote_hostname: Some(hostname.to_string()),
        source_app: Some("com.example.browser".to_string()),
        local: None,
    }
}

/// A UDP `FlowOpen` to `remote`.
fn udp_open(flow_id: u64, remote: &str) -> FlowOpen {
    FlowOpen {
        flow_id,
        kind: FlowKind::Udp,
        remote: remote.parse().expect("valid remote"),
        remote_hostname: None,
        source_app: Some("com.example.resolver".to_string()),
        local: Some("192.0.2.1:50000".parse().expect("valid local")),
    }
}

/// Run one TCP flow to completion: announce it, send its handshake and `bytes`, and
/// wait for the core to finish with the socket. A write that fails because the core
/// already closed the socket is fine: refusing a flow early is what it does.
async fn run_tcp_flow(provider: &mut Provider, open: FlowOpen, bytes: &[u8]) {
    let flow_id = open.flow_id;
    let mut data = provider.open_flow(open).await;
    let _ = data.write_all(bytes).await;
    wait_closed(&mut data, &format!("the core to finish TCP flow {flow_id}")).await;
}

/// Run one UDP flow to completion: announce it, send each datagram length-delimited,
/// close our write side, and wait for the core to finish with the socket.
async fn run_udp_flow(provider: &mut Provider, open: FlowOpen, datagrams: &[&[u8]]) {
    let flow_id = open.flow_id;
    let mut data = provider.open_flow(open).await;
    for datagram in datagrams {
        if write_datagram(&mut data, datagram).await.is_err() {
            break; // a refused flow's socket is already closed
        }
    }
    let _ = data.shutdown().await;
    wait_closed(&mut data, &format!("the core to finish UDP flow {flow_id}")).await;
}

/// The literal frame sizes the loopback test's LF-AC8 assertions rest on are the
/// codec's real ones. This needs no socket, so it runs in the Bash sandbox too, where
/// the loopback tests skip: it is the part of their arithmetic that can be checked
/// there.
#[test]
fn control_frame_sizes_match_the_loopback_literals() {
    let hello = ControlMessage::Hello(Hello {
        protocol_version: HANDOFF_PROTOCOL_VERSION,
    });
    assert_eq!(frame_len(&hello), 36, "4-byte prefix + 32-byte Hello body");

    let scope = ControlMessage::Scope(ScopeSpec {
        spec: "example.com 198.51.100.7".to_string(),
    });
    assert_eq!(frame_len(&scope), SCOPE_FRAME_LEN);
}

/// LF-AC2, LF-AC6, LF-AC8, LF-AC10: a provider that the verifier accepts attaches,
/// receives the scope, and has in-scope flows fed to the recording ingress and
/// out-of-scope flows refused, with only metadata on the control channel; shutdown
/// retracts everything.
#[test]
fn loopback_provider_feeds_in_scope_flows_and_shutdown_cleans_up() {
    run_serialized(async {
        let scratch = Scratch::new("a");
        let socket_dir = scratch.socket_dir();
        if !uds_bind_available(&socket_dir) {
            eprintln!("{SKIP_NOTICE}");
            return;
        }
        let canonical = fs::canonicalize(&socket_dir).expect("canonicalize the socket dir");

        let verifier = ScriptedVerifier::accepting();
        let (session, seen) = build_session(verifier.clone(), socket_dir.clone());
        let running = Running::start(session);

        // LF-AC2: the rendezvous file names the 0700 socket dir, mode 0600, one line.
        let rendezvous = wait_for_rendezvous().await;
        assert_eq!(
            rendezvous,
            format!("{}\n", canonical.display()),
            "one line: the canonical socket dir, then a newline"
        );
        assert_eq!(
            fs::metadata(RENDEZVOUS_PATH)
                .expect("stat the rendezvous file")
                .permissions()
                .mode()
                & 0o777,
            0o600,
            "the rendezvous file is mode 0600"
        );
        assert_eq!(
            fs::metadata(&canonical)
                .expect("stat the socket dir")
                .permissions()
                .mode()
                & 0o777,
            0o700,
            "the socket dir it names is mode 0700"
        );

        // From here on, find the sockets the way the provider does: from the file.
        let mut provider = Provider::attach(PathBuf::from(rendezvous.trim_end())).await;

        // LF-AC6 setup: after a verified Hello the core pushes the scope, and it is
        // exactly what the emitter renders for the seeded L7 and L4 scope.
        let scope = provider.next_message().await;
        assert_eq!(
            scope,
            Some(ControlMessage::Scope(ScopeSpec {
                spec: "example.com 198.51.100.7".to_string()
            })),
            "the pushed scope is the seeded L7 host then the seeded L4 address"
        );
        assert_eq!(
            scope,
            Some(ControlMessage::Scope(provider_scope_spec(
                &l7_scope(),
                &l4_scope()
            ))),
            "and it equals the emitter's output for that scope"
        );

        // LF-AC6, TCP in scope: the stub module is spawned exactly once with the
        // authoritative remote as `hint.dst`, the SNI, and the bytes the provider sent.
        run_tcp_flow(
            &mut provider,
            tcp_open(1, REMOTE, "example.com"),
            HTTP_BYTES,
        )
        .await;
        assert_eq!(
            seen.spawns(),
            1,
            "the in-scope TCP flow spawns the module once"
        );
        let hint = seen.hint().expect("the module recorded its hint");
        assert_eq!(hint.dst.to_string(), REMOTE);
        assert_eq!(hint.client_hello_sni.as_deref(), Some("example.com"));
        assert_eq!(hint.first_bytes, HTTP_BYTES);
        assert!(!hint.is_tls, "plain HTTP bytes are not sniffed as TLS");

        // LF-AC6, TCP out of scope: refused before any module match, spawn, or dial.
        run_tcp_flow(
            &mut provider,
            tcp_open(2, "203.0.113.50:443", "blocked.test"),
            HTTP_BYTES,
        )
        .await;
        assert_eq!(
            seen.spawns(),
            1,
            "the out-of-scope TCP flow spawns the module zero times"
        );
        assert_eq!(
            seen.hint().map(|h| h.dst.to_string()).as_deref(),
            Some(REMOTE),
            "no hint was recorded for the refused flow"
        );
        assert_eq!(seen.dials(), 0, "no flow dials an upstream");

        // LF-AC6, UDP in scope: the datagrams land in the L4 store. The second is a
        // bulk datagram: bulk bytes cross the data socket.
        let bulk = vec![0xAB_u8; BULK_LEN];
        run_udp_flow(
            &mut provider,
            udp_open(3, "198.51.100.7:53"),
            &[b"probe", &bulk],
        )
        .await;
        let flows = seen.l4_store.list();
        assert_eq!(
            flows.len(),
            1,
            "one capture flow holds the in-scope datagrams"
        );
        let flow = seen
            .l4_store
            .get(flows[0])
            .expect("the capture flow exists");
        assert_eq!(flow.packets.len(), 2, "both in-scope datagrams are stored");
        assert_eq!(flow.packets[0].bytes, b"probe");
        assert_eq!(flow.packets[1].bytes, bulk);
        assert!(
            flow.packets.iter().all(|p| !p.injected),
            "capture observes, it never injects"
        );

        // LF-AC6, UDP out of scope: refused, nothing new is stored.
        run_udp_flow(&mut provider, udp_open(4, "198.51.100.8:53"), &[b"probe"]).await;
        assert_eq!(
            seen.l4_store.list().len(),
            1,
            "the out-of-scope UDP flow adds no capture flow"
        );
        assert_eq!(
            seen.packet_count(),
            2,
            "the out-of-scope UDP datagram reaches no store"
        );

        // The accepting verifier was asked about every peer: the control peer, then
        // each of the four data peers.
        assert_eq!(verifier.calls(), 5);

        // LF-AC8: only metadata crossed the control channel. The core wrote exactly
        // one Scope frame (49 bytes) back and nothing else. What the core read is
        // exactly what we wrote: a Hello (36 bytes) and four FlowOpens, well under 1
        // KiB, while the data sockets carried the 4 KiB bulk datagram.
        //
        // The core-side `ControlChannel::bytes_read()` the plan names is consumed
        // inside the session (split into halves, never handed out), so it cannot be
        // read from here; this measures both directions from the provider's side.
        assert_eq!(
            provider.control.bytes_read(),
            SCOPE_FRAME_LEN,
            "the core wrote one Scope frame on control and no bulk"
        );
        assert!(
            provider.control_written < 1024,
            "the provider wrote only metadata on control, saw {} bytes",
            provider.control_written
        );
        assert!(
            u64::try_from(flow.packets[1].bytes.len()).expect("fits") > provider.control_written,
            "the bulk datagram alone outweighs everything on the control channel"
        );

        // LF-AC10: a pump that is still running when shutdown fires is stopped. This
        // UDP flow stays open (no end of stream) so its pump is parked reading it.
        let mut lingering = provider.open_flow(udp_open(5, "198.51.100.7:53")).await;
        write_datagram(&mut lingering, b"still-open")
            .await
            .expect("write the lingering datagram");
        until("the lingering datagram to be stored", || {
            seen.packet_count() == 3
        })
        .await;

        // LF-AC10: shutdown retracts the rendezvous file and both sockets, and stops
        // the pump (the core closes the lingering data socket).
        running.shutdown().await;
        assert_cleaned_up(&canonical);
        wait_closed(&mut lingering, "the lingering pump to stop at shutdown").await;
        // The provider sees the control channel end: it detaches and fails open.
        assert!(
            matches!(
                within("the control channel to end", provider.control.recv()).await,
                Ok(None) | Err(_)
            ),
            "the control channel ends at shutdown"
        );
    });
}

/// LF-AC7: a data socket whose peer the verifier rejects is dropped and no bytes are
/// fed for its flow, while the control channel and a later, verified flow are
/// unaffected.
#[test]
fn rejected_data_peer_feeds_no_bytes_and_leaves_other_flows_alone() {
    run_serialized(async {
        let scratch = Scratch::new("b");
        let socket_dir = scratch.socket_dir();
        if !uds_bind_available(&socket_dir) {
            eprintln!("{SKIP_NOTICE}");
            return;
        }
        let canonical = fs::canonicalize(&socket_dir).expect("canonicalize the socket dir");

        // In call order: the control peer is accepted, flow 10's data peer is
        // rejected, flow 11's data peer is accepted.
        let verifier = ScriptedVerifier::scripted(vec![true, false, true]);
        let (session, seen) = build_session(verifier.clone(), socket_dir.clone());
        let running = Running::start(session);

        let rendezvous = wait_for_rendezvous().await;
        assert_eq!(rendezvous, format!("{}\n", canonical.display()));
        let mut provider = Provider::attach(PathBuf::from(rendezvous.trim_end())).await;
        assert_eq!(
            provider.next_message().await,
            Some(ControlMessage::Scope(ScopeSpec {
                spec: "example.com 198.51.100.7".to_string()
            })),
            "the verified control peer gets the scope"
        );

        // Flow 10: in scope, but its data peer is rejected. The provider sent its
        // FlowOpen and its bytes; none of it reaches the ingress.
        run_tcp_flow(
            &mut provider,
            tcp_open(10, REMOTE, "example.com"),
            HTTP_BYTES,
        )
        .await;
        assert_eq!(
            verifier.calls(),
            2,
            "the control peer, then flow 10's data peer, were verified"
        );
        assert_eq!(
            seen.spawns(),
            0,
            "no module is spawned for the rejected peer"
        );
        assert!(seen.hint().is_none(), "no bytes were fed to the ingress");
        assert_eq!(seen.dials(), 0, "no upstream is dialled");

        // Flow 11 on the same control channel: its data peer is accepted, so it is
        // fed normally. The rejection above did not poison the attachment.
        run_tcp_flow(
            &mut provider,
            tcp_open(11, REMOTE, "example.com"),
            HTTP_BYTES,
        )
        .await;
        assert_eq!(verifier.calls(), 3);
        assert_eq!(seen.spawns(), 1, "the verified flow spawns the module once");
        let hint = seen.hint().expect("the module recorded its hint");
        assert_eq!(hint.dst.to_string(), REMOTE);
        assert_eq!(hint.first_bytes, HTTP_BYTES);

        running.shutdown().await;
        assert_cleaned_up(&canonical);
    });
}
