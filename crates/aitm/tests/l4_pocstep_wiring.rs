//! L4 PoC-step wiring (plan: l4 wiring, Task 2): the binary's assembly builds the
//! `l4:` PoC-step registry from the SAME `L4Guard` + `L4FlowStore` the `L4Module`
//! and `Features::l4_shared` carry, and threads it into `poc.run`.
//!
//! Hermetic: a file-local `MockBackend` records injected frames, so nothing binds a
//! socket or needs raw privilege. The PoC is `l4:`-only, so the runner ends with its
//! "no HTTP flow" error even when the `l4:` step runs — that error class plus the
//! backend's wire record are the security observable, not the overall verdict.

use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use aitm::wire::{assemble_with_scripts, Assembled, Features, L4Shared, ScriptWiring};
use aitm_core::{CommandHost, Config, Frontend, HttpFlow, HttpRequest, Params, ProxyClient, Value};
use aitm_plugin::language::ProtocolLanguage;
use aitm_poc::step_registry::PocStepRegistry;
use aitm_poc::{ScriptStepCtx, ScriptStepError, ScriptStepExecutor, ScriptVerdict};
use aitm_proto_l4::backend::pcap::PcapBackend;
use aitm_proto_l4::backend::{CaptureInjectBackend, CaptureSource, L4Error};
use aitm_proto_l4::config::L4Config;
use aitm_proto_l4::flow::{InMemoryL4FlowStore, L4FlowStore};
use aitm_proto_l4::guard::L4Guard;
use aitm_proto_l4::language::L4Language;
use aitm_proto_l4::module::L4Privilege;
use aitm_proto_l4::types::{
    IpCidr, L4Capability, L4Direction, L4ScopeEntry, L4ScopeId, L4ScopeSource, PortRange, RateCap,
};

/// The scope interface: the per-OS loopback the `l4:` step defaults to
/// (`lo0` on macOS/BSD, `lo` on Linux), so the normative no-`interface`
/// PoC steps below prove the default on the OS the tests compiled for.
const IFACE: &str = aitm_proto_l4::language::DEFAULT_INTERFACE;

/// The normative `l4:` PoC (one `send_recv` step to the in-scope loopback target).
const L4_POC: &str = r#"id: l4-send-recv
info:
  name: l4 send_recv wiring
  severity: low
steps:
  - l4:
      op: send_recv
      packet:
        layers:
          - ipv4: { dst: "127.0.0.1" }
          - tcp:  { dport: 80, flags: S }
      timeout_ms: 1000
success:
  - dsl: 'l4_outcome == "no_response"'
"#;

/// The same PoC with a FULL L2 frame (`ether` first), for the real-wire test only.
/// libpcap injects the bytes verbatim and Linux `lo` is Ethernet (`DLT_EN10MB`), so
/// the real backend needs the link-layer header; the mock backend ignores framing,
/// which is why the hermetic tests keep the L3-only body above.
const L4_POC_L2: &str = r#"id: l4-send-recv-l2
info:
  name: l4 send_recv real-wire wiring
  severity: low
steps:
  - l4:
      op: send_recv
      packet:
        layers:
          - ether: {}
          - ipv4: { dst: "127.0.0.1" }
          - tcp:  { dport: 80, flags: S }
      timeout_ms: 1000
success:
  - dsl: 'l4_outcome == "no_response"'
"#;

// --- a hermetic capture/inject backend (no socket, no privilege) ------------

struct MockBackend {
    injected: Mutex<Vec<Vec<u8>>>,
}

impl MockBackend {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            injected: Mutex::new(Vec::new()),
        })
    }

    fn injected(&self) -> Vec<Vec<u8>> {
        self.injected.lock().unwrap().clone()
    }
}

impl CaptureInjectBackend for MockBackend {
    fn open_capture(
        &self,
        _iface: &str,
        _filter: Option<&str>,
        _read_timeout: Duration,
    ) -> Result<Box<dyn CaptureSource>, L4Error> {
        Ok(Box::new(EmptySource))
    }

    fn inject(&self, _iface: &str, bytes: &[u8]) -> Result<(), L4Error> {
        self.injected.lock().unwrap().push(bytes.to_vec());
        Ok(())
    }
}

struct EmptySource;

impl CaptureSource for EmptySource {
    fn next_frame(&mut self) -> Result<Option<Vec<u8>>, L4Error> {
        std::thread::sleep(Duration::from_millis(2));
        Ok(None)
    }
}

// --- fixtures ---------------------------------------------------------------

fn entry(dir: L4Direction, cap: L4Capability) -> L4ScopeEntry {
    L4ScopeEntry {
        id: L4ScopeId::new(),
        cidr: IpCidr {
            addr: "127.0.0.1".parse().unwrap(),
            prefix: 32,
        },
        ports: PortRange { lo: 0, hi: 65535 },
        interface: IFACE.to_string(),
        direction: dir,
        capability: cap,
        inject_rate: RateCap {
            pps: 100,
            burst: 100,
        },
        source: L4ScopeSource::Config,
    }
}

/// A guard scoped for a loopback send_recv, with the agent inject gate as requested.
fn loopback_guard(allow_agent_inject: bool) -> Arc<L4Guard> {
    let cfg = L4Config {
        scope: vec![
            entry(L4Direction::Outbound, L4Capability::Inject),
            entry(L4Direction::Inbound, L4Capability::Capture),
        ],
        allow_agent_inject,
        ..L4Config::default()
    };
    Arc::new(L4Guard::new(&cfg))
}

/// Never reached: the `l4:`-only PoC has no `script` step. It exists because
/// `PocCommands::load` threads the step registry only when an executor is present,
/// exactly as production `main` always supplies one.
struct NoopExec;

impl ScriptStepExecutor for NoopExec {
    fn run_step(
        &self,
        _step: &aitm_poc::model::ScriptStep,
        _ctx: &mut ScriptStepCtx<'_>,
    ) -> Result<ScriptVerdict, ScriptStepError> {
        Ok(ScriptVerdict::Neutral)
    }
}

/// A client that is never reached: the `l4:` PoC has no `http` step.
struct StubClient;

impl ProxyClient for StubClient {
    fn send(
        &self,
        _req: HttpRequest,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<HttpFlow>> + Send + '_>> {
        Box::pin(async { anyhow::bail!("stub client") })
    }
}

fn unique_dir(tag: &str) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("aitm-l4poc-{tag}-{nanos}-{n}"))
}

/// Assemble a proxy the way `main` does for the l4 PoC path: ONE guard + store feed
/// `Features::l4_shared` (hence the `L4Module`) and the `l4:` step registry.
fn assemble_l4_poc_run(
    allow_agent_inject: bool,
    backend: Arc<dyn CaptureInjectBackend>,
) -> Assembled {
    let guard = loopback_guard(allow_agent_inject);
    let store: Arc<dyn L4FlowStore> = Arc::new(InMemoryL4FlowStore::new());
    let registry = {
        let mut r = PocStepRegistry::new();
        let lang = L4Language::new(guard.clone(), backend, store.clone());
        if let Some(h) = lang.poc_step() {
            r.register(Arc::from(h));
        }
        r
    };
    let cfg = {
        let mut c = Config::default();
        c.ca.dir = unique_dir("ca");
        c
    };
    let features = Features {
        l4: L4Config {
            enabled: true,
            ..L4Config::default()
        },
        l4_shared: Some(L4Shared { guard, store }),
        l4_privilege: Some(L4Privilege::available()),
        ..Features::default()
    };
    assemble_with_scripts(
        &cfg,
        &features,
        ScriptWiring {
            poc_step_handlers: registry,
            executor: Some(Arc::new(NoopExec)),
            ..ScriptWiring::default()
        },
    )
    .expect("assemble proxy")
}

/// Run `poc.run` on the l4 fixture; `frontend = None` leaves the host unseeded.
async fn run_poc(
    allow_agent_inject: bool,
    frontend: Option<Frontend>,
) -> (anyhow::Result<Value>, Arc<MockBackend>) {
    let backend = MockBackend::new();
    let result = run_poc_with(allow_agent_inject, frontend, backend.clone(), L4_POC).await;
    (result, backend)
}

/// Run `poc.run` on the l4 fixture over an arbitrary backend (mock or real pcap).
async fn run_poc_with(
    allow_agent_inject: bool,
    frontend: Option<Frontend>,
    backend: Arc<dyn CaptureInjectBackend>,
    poc_body: &'static str,
) -> anyhow::Result<Value> {
    let assembled = assemble_l4_poc_run(allow_agent_inject, backend);
    let proxy = assembled.proxy;
    let store = proxy.store();
    let guard = proxy.guard();
    let registry = proxy.registry_arc();
    let client: Arc<dyn ProxyClient> = Arc::new(StubClient);

    let dir = unique_dir("poc");
    std::fs::create_dir_all(&dir).expect("poc dir");
    let path = dir.join("l4-send-recv.poc.yaml");
    std::fs::write(&path, poc_body).expect("write poc");

    tokio::task::spawn_blocking(move || {
        // These tests exercise the L4 *inject* gate (and unseeded fail-closed
        // trust), not poc.run's separate agent gate. Opt into `poc.allow_agent_run`
        // via the host config so an agent/unseeded run passes that gate and reaches
        // the `l4:` step, where the L4 inject gate is the thing under test.
        let run_cfg = {
            let mut c = Config::default();
            c.poc.allow_agent_run = true;
            Arc::new(c)
        };
        let mut host = CommandHost::new(store.as_ref(), client.as_ref(), guard.as_ref(), None)
            .with_config(run_cfg);
        if let Some(f) = frontend {
            host = host.with_frontend(f);
        }
        let args = Params::new(
            [(
                "poc_path".to_string(),
                Value::Str(path.display().to_string()),
            )]
            .into_iter()
            .collect(),
        );
        registry
            .command("poc.run")
            .expect("poc.run registered")
            .invoke(args, &host)
    })
    .await
    .expect("poc.run task")
}

fn err_text(result: anyhow::Result<Value>) -> String {
    format!("{:#}", result.expect_err("poc.run must end in Err"))
}

/// AC1/AC2: an Operator run reaches the `l4:` handler (not "no handler registered")
/// and the step runs, putting exactly one frame on the wire; the overall run then
/// ends with the l4-only PoC's "no HTTP flow" error.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn operator_runs_l4_step() {
    let (result, backend) = run_poc(false, Some(Frontend::Operator)).await;
    let msg = err_text(result);
    assert!(
        !msg.contains("no handler registered"),
        "the l4 handler must be wired into poc.run, got: {msg}"
    );
    assert!(msg.contains("no HTTP flow"), "got: {msg}");
    assert_eq!(backend.injected().len(), 1);
}

/// AC1/AC3: an Agent run with the inject gate closed is refused by the l4 gate and
/// nothing reaches the wire.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn agent_gate_off_refused_nothing_on_wire() {
    let (result, backend) = run_poc(false, Some(Frontend::Mcp)).await;
    let msg = err_text(result);
    assert!(
        !msg.contains("no handler registered"),
        "the l4 handler must be wired into poc.run, got: {msg}"
    );
    assert!(
        msg.contains("disabled") && msg.contains("inject"),
        "refusal names the disabled inject gate, got: {msg}"
    );
    assert!(backend.injected().is_empty());
}

/// AC4: an Agent run with the inject gate open runs the step.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn agent_gate_on_runs() {
    let (result, backend) = run_poc(true, Some(Frontend::Mcp)).await;
    let msg = err_text(result);
    assert!(msg.contains("no HTTP flow"), "got: {msg}");
    assert_eq!(backend.injected().len(), 1);
}

/// AC5: a host never seeded with a frontend defaults to Agent trust and is
/// fail-closed against the closed inject gate.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unseeded_host_is_fail_closed() {
    let (result, backend) = run_poc(false, None).await;
    let msg = err_text(result);
    assert!(
        msg.contains("disabled") && msg.contains("inject"),
        "an unseeded host is refused by the disabled inject gate, got: {msg}"
    );
    assert!(backend.injected().is_empty());
}

/// AC9: the real-wire proof. Privilege-gated like `aitm-proto-l4`'s
/// `active_roundtrip.rs`: skipped on macOS or without `AITM_L4_TESTS=1`, and it
/// skips (not fails) when the host lacks raw L4 privilege / libpcap.
///
/// The PoC is `l4:`-only (no `http:` step), so a run whose `l4:` step reached the
/// real wire still ends in the finding-anchor's "no HTTP flow" error. That error is
/// the success signal here: it proves the stimulus went through the assembled
/// `poc.run` past the registration, scope and agent gates onto a real libpcap
/// backend. Either real outcome (RST => response, silence => no_response) ends at
/// the anchor, so no `l4_outcome` is asserted. A gate or registration failure would instead read "no handler
/// registered", "disabled" or "out of L4 scope".
#[test]
#[ignore = "needs raw L4 privilege + Linux loopback; run with AITM_L4_TESTS=1 via the Terminal panel"]
fn operator_l4_step_injects_on_real_loopback() {
    if !(!cfg!(target_os = "macos") && std::env::var("AITM_L4_TESTS").ok().as_deref() == Some("1"))
    {
        return;
    }
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("runtime");
    let backend: Arc<dyn CaptureInjectBackend> = Arc::new(PcapBackend::new());
    let result = rt.block_on(run_poc_with(
        false,
        Some(Frontend::Operator),
        backend,
        L4_POC_L2,
    ));
    let msg = err_text(result);
    if msg.to_ascii_lowercase().contains("unavailable") {
        // No raw privilege / libpcap on this host: fail-closed, skip.
        return;
    }
    for broken in ["no handler registered", "disabled", "out of L4 scope"] {
        assert!(
            !msg.contains(broken),
            "gate/registration must not refuse an operator loopback run ({broken}), got: {msg}"
        );
    }
    assert!(
        msg.contains("no HTTP flow"),
        "the l4 step must reach the wire, then hit the finding-anchor, got: {msg}"
    );
}
