//! R14 Task 6 (socket, Terminal-run): the dedicated loopback operator bus
//! `operator_bus::start` serves when `mcp.transport` is stdio, proved against
//! the real `aitm-mcp` server over a real socket with the real
//! `aitm-bus-client` the one-shot will use (spec D2 "Start", D4 lifecycle;
//! AC-R14-8, AC-R14-9, AC-R14-10).
//!
//! This file holds the **only** test in the workspace that calls
//! `pointer::publish`: the process context is a write-once `OnceLock`, so
//! the pointer write with a context can be proved in exactly one test binary
//! (plan Task 5 "The pointer write with a context is proved by T6's live
//! test"). The run dir is a temp directory carried in the context, so nothing
//! is written under the developer's data directory (AC-R14-12).
//!
//! The Claude sandbox denies socket binds (`Operation not permitted`); these
//! tests are run from the Terminal panel (plan rule 2).
//!
//! Spec: docs/superpowers/specs/2026-11-01-cli-oneshot-live-core-design.md (D2, D4, D10)
//! Plan: docs/superpowers/plans/2026-11-01-cli-oneshot-live-core-plan.md (Task 6)

mod support;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use aitm::operator_bus::{self, OperatorBus, ROLE};
use aitm::startup::card::OperatorBusWord;
use aitm::startup::errors::StartupError;
use aitm::tui::Services;
use aitm_bus_client::{BusClient, BusError, TcpTransport};
use aitm_core::{AgentState, AuditRing, Config, Event};
use aitm_mcp::pointer::{self, CorePointer, Liveness, PointerContext};
use serde_json::json;
use tokio::net::TcpListener;
use tokio::sync::{broadcast, oneshot};
use tokio::time::{sleep, timeout, Instant};

/// The operator token the dedicated bus admits (a test literal, plan rule 6).
const OPERATOR_TOKEN: &str = "optoken-test-dedicated-bus-2026";
/// A string that is not the operator token; the bus must refuse it.
const WRONG_TOKEN: &str = "optoken-test-not-the-token";
/// Longest any single wait in these tests is allowed to take.
const STEP: Duration = Duration::from_secs(2);
/// Spec D4: the pointer is gone within 1 s of the bus ending.
const POINTER_GONE: Duration = Duration::from_secs(1);

/// A fresh, unique directory under the system temp dir, removed on drop.
struct TempRoot(PathBuf);

impl TempRoot {
    fn new(tag: &str) -> Self {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let nanos = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "aitm-operator-bus-live-{tag}-{}-{nanos}-{n}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("create the temp root");
        Self(dir)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Removes the throwaway CA directory `support::config` chose.
struct CaDirGuard(PathBuf);

impl Drop for CaDirGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The governance pair and the push channel `start` is handed, built as the
/// other `aitm` integration tests build them. The dedicated bus serves
/// operator-role connections, which the agent gate does not apply to, so a
/// fresh pair is as good as the assembly's for what these tests observe.
fn governance(cfg: &Config) -> (Arc<AgentState>, Arc<AuditRing>, broadcast::Sender<Event>) {
    let (push_tx, _rx) = broadcast::channel::<Event>(16);
    (
        Arc::new(AgentState::new(cfg.mcp.policy)),
        Arc::new(AuditRing::new(16)),
        push_tx,
    )
}

/// A default config (stdio MCP transport, `operator_bus` on with an ephemeral
/// port) with a throwaway CA dir and the operator token the bus admits.
fn config(tag: &str) -> (Config, CaDirGuard) {
    let mut cfg = support::config(tag);
    cfg.mcp.operator_token = Some(OPERATOR_TOKEN.into());
    let guard = CaDirGuard(cfg.ca.dir.clone());
    (cfg, guard)
}

/// `operator_bus::start` exactly as `run()` will call it for a serving mode.
async fn start(
    cfg: &Config,
    config_path: &Path,
    services: &Services,
    on_bound: Option<Box<dyn FnOnce(SocketAddr) + Send>>,
) -> anyhow::Result<OperatorBus> {
    let (agent_state, audit_ring, push_tx) = governance(cfg);
    operator_bus::start(
        cfg,
        config_path,
        services,
        &agent_state,
        &audit_ring,
        push_tx,
        on_bound,
        None,
    )
    .await
}

/// Wait until `pred()` holds or `limit` passes; `true` when it held.
async fn wait_for(limit: Duration, mut pred: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + limit;
    while !pred() {
        if Instant::now() >= deadline {
            return false;
        }
        sleep(Duration::from_millis(10)).await;
    }
    true
}

/// Spec D2 "Start" (`Dedicated`) and D4 (the pointer written with a context):
/// the bus binds `127.0.0.1`, fires `on_bound`, writes `<run dir>/<pid>.json`
/// `0600` with `operator: true`, the bound address and the context's config
/// path, holds its advisory lock, admits the operator token as `operator`,
/// refuses any other string with `-32001`, and takes the pointer with it when
/// the `OperatorBus` drops.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dedicated_bus_serves_the_operator_and_publishes_a_pointer() {
    let root = TempRoot::new("dedicated");
    let tmp_cfg = root.path().join("config.yaml");
    let tmp_run = root.path().join("run").join("cores");
    assert!(
        pointer::publish(PointerContext {
            config: tmp_cfg.clone(),
            run_dir: tmp_run.clone(),
        }),
        "this test is the only publisher in the binary, so the first publish wins"
    );

    let (cfg, _ca) = config("operator-bus-live");
    let (_proxy, services, _governance) = support::assemble_services(&cfg);

    let (bound_tx, bound_rx) = oneshot::channel::<SocketAddr>();
    let on_bound: Box<dyn FnOnce(SocketAddr) + Send> = Box::new(move |addr| {
        let _ = bound_tx.send(addr);
    });
    let bus = start(&cfg, &tmp_cfg, &services, Some(on_bound))
        .await
        .expect("the dedicated operator bus starts on an ephemeral port");

    let OperatorBusWord::Dedicated(a) = bus.word() else {
        panic!(
            "a stdio transport with a token is Dedicated: {:?}",
            bus.word()
        );
    };
    assert_eq!(a.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
    assert_ne!(a.port(), 0, "the ephemeral port resolved");
    let hooked = timeout(STEP, bound_rx)
        .await
        .expect("on_bound fires before start returns")
        .expect("the hook's sender was not dropped unfired");
    assert_eq!(hooked, a, "on_bound receives the bound address");

    // The pointer is written when the spawned task starts serving, a few
    // milliseconds after `start` returns.
    let it = tmp_run.join(format!("{}.json", std::process::id()));
    assert!(
        wait_for(STEP, || it.exists()).await,
        "the pointer {} appears once the listener serves",
        it.display()
    );
    let meta = std::fs::metadata(&it).expect("pointer metadata");
    assert_eq!(
        meta.permissions().mode() & 0o777,
        0o600,
        "the pointer is 0600"
    );
    let dir_meta = std::fs::metadata(&tmp_run).expect("run dir metadata");
    assert_eq!(
        dir_meta.permissions().mode() & 0o777,
        0o700,
        "the run dir is 0700"
    );
    let text = std::fs::read_to_string(&it).expect("read the pointer");
    assert_eq!(text.lines().count(), 1, "one JSON line: {text:?}");
    assert!(text.ends_with('\n'), "trailing newline: {text:?}");
    assert!(
        !text.contains(OPERATOR_TOKEN),
        "the pointer never carries the token"
    );
    let ptr = CorePointer::parse(&text).expect("the pointer parses");
    assert_eq!(ptr.v, 1);
    assert_eq!(ptr.pid, std::process::id());
    assert!(ptr.operator, "the dedicated bus accepts an operator token");
    assert_eq!(ptr.bus, a, "bus == the bound address");
    assert_eq!(
        ptr.config, tmp_cfg,
        "config == the published context's path"
    );
    assert_eq!(ptr.version, env!("CARGO_PKG_VERSION"));
    assert_eq!(
        pointer::liveness(&it),
        Liveness::Alive,
        "the writer holds the exclusive lock while it serves"
    );

    // The operator token is served as the operator role and reaches the registry.
    let transport = timeout(STEP, TcpTransport::connect(a, OPERATOR_TOKEN))
        .await
        .unwrap_or_else(|_| panic!("connect within {STEP:?}"))
        .expect("connect to the operator bus");
    let client = BusClient::new(Box::new(transport));
    let info = timeout(STEP, client.initialize("operator-bus-live", "test"))
        .await
        .unwrap_or_else(|_| panic!("initialize within {STEP:?}"))
        .expect("initialize as the operator");
    assert_eq!(
        info.role.as_deref(),
        Some("operator"),
        "the operator token is served as the operator role: {info:?}"
    );
    let list = timeout(STEP, client.call("scope.list", json!({})))
        .await
        .unwrap_or_else(|_| panic!("scope.list within {STEP:?}"))
        .expect("scope.list over the operator bus");
    assert_eq!(list, json!([]), "a fresh core's Scope is empty");

    // Any other string is refused with the token-refusal code (AC-R14-8).
    let wrong = timeout(STEP, TcpTransport::connect(a, WRONG_TOKEN))
        .await
        .unwrap_or_else(|_| panic!("connect within {STEP:?}"))
        .expect("the socket accepts before the token is judged");
    let wrong = BusClient::new(Box::new(wrong));
    let refused = timeout(STEP, wrong.initialize("operator-bus-live", "test"))
        .await
        .unwrap_or_else(|_| panic!("the refusal arrives within {STEP:?}"));
    match refused {
        Err(BusError::Rpc { code: -32001, .. }) => {}
        other => panic!("a wrong token is refused with -32001, got {other:?}"),
    }
    drop(wrong);
    drop(client);

    // Dropping the bus aborts the task, which drops the listener, which
    // removes the pointer (spec D2 "Start", D4 lifecycle).
    drop(bus);
    assert!(
        wait_for(POINTER_GONE, || !it.exists()).await,
        "the pointer {} is removed within {POINTER_GONE:?} of the bus dropping",
        it.display()
    );
}

/// Spec D2 "Start" and AC-R14-9: a held fixed port is the typed M2 error,
/// before any ready card, naming the role, the address and the remedy with
/// the config key and file.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fixed_port_conflict_is_the_port_in_use_error() {
    let holder = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("hold a loopback port");
    let port = holder.local_addr().expect("holder addr").port();

    let (mut cfg, _ca) = config("operator-bus-conflict");
    cfg.mcp.operator_bus.port = port;
    let (_proxy, services, _governance) = support::assemble_services(&cfg);
    let config_path = Path::new("/x/config.yaml");

    let err = match start(&cfg, config_path, &services, None).await {
        Ok(bus) => panic!("start on a held port must fail, got {:?}", bus.word()),
        Err(err) => err,
    };
    let startup = err
        .downcast_ref::<StartupError>()
        .unwrap_or_else(|| panic!("the error is a StartupError: {err:#}"));
    match startup {
        StartupError::PortInUse { role, addr, remedy } => {
            assert_eq!(role, ROLE);
            assert_eq!(role, "the operator bus");
            assert_eq!(
                *addr,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
            );
            assert_eq!(
                remedy,
                "Free it, or set mcp.operator_bus.port to another port in /x/config.yaml."
            );
        }
        other => panic!("expected PortInUse, got {other:?}"),
    }
    assert!(
        err.to_string().starts_with(&format!(
            "cannot start: the operator bus port 127.0.0.1:{port} is already in use"
        )),
        "the M2 headline: {err}"
    );
    drop(holder);
}
