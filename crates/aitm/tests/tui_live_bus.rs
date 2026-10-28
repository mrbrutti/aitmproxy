//! TUI plan Task 6: the TUI's bus task against the **real** `aitm-mcp` server
//! over loopback TCP, not the fixture or the in-process handler. This is the
//! literal "a bus client like the others" claim of foundation §4.1–4.2: the
//! same `initialize` → `tools/list` handshake, the same `tools/call` shapes,
//! the same token line, through the same `TcpTransport` the macOS and web
//! apps would use.
//!
//! The Claude sandbox cannot bind TCP ports. When `McpServer::serve` fails its
//! bind with `PermissionDenied`, the test prints a note and returns; it must
//! be run for real in the Terminal panel (the plan's "Done when").

use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use aitm::wire::{assemble, Assembled, Http1Sender};
use aitm_core::{Config, McpTransport, PipelineClient, ProxyClient, ScopeRateGuard};
use aitm_mcp::McpServer;
use aitm_tui::action::{BusEvent, BusRequest, Level};
use aitm_tui::TransportChoice;
use anyhow::Context as _;
use serde_json::{json, Value};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio::time::{timeout, Instant};

/// The loopback token both ends agree on.
const TOKEN: &str = "tui-live-bus-token";
/// Longest any single wait in this test is allowed to take.
const STEP: Duration = Duration::from_secs(2);
/// The TUI poll interval under test (the plan says 50 ms).
const POLL: Duration = Duration::from_millis(50);

fn temp_ca_dir(tag: &str) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("aitm-tui-live-bus-{tag}-{nanos}-{n}"))
}

fn config(tag: &str) -> Config {
    let mut cfg = Config::default();
    cfg.ca.dir = temp_ca_dir(tag);
    cfg
}

/// The agent-facing server exactly as `aitm` builds it: `assemble`, the shared
/// service handles, then one `McpServer` on loopback TCP port 0.
fn build_server(cfg: &Config) -> McpServer {
    let Assembled { proxy, ca: _ } = assemble(cfg).expect("assemble");
    let registry = proxy.registry_arc();
    let store = proxy.store();
    let guard: Arc<dyn ScopeRateGuard> = proxy.guard();
    let client: Arc<dyn ProxyClient> = Arc::new(PipelineClient::new(
        store.clone(),
        guard.clone(),
        Arc::new(Http1Sender::new().with_insecure(cfg.ssl_insecure)),
    ));
    McpServer::new(
        registry,
        McpTransport::LoopbackTcp {
            port: 0,
            token: TOKEN.into(),
        },
    )
    .with_services(store, client, guard, None)
}

/// Spawn `serve()` and wait for `on_bound` to report the address.
///
/// `Ok(None)` when the bind was refused with `PermissionDenied`: that is the
/// Claude sandbox, not a bug, and the caller skips with a note.
async fn start_server(server: McpServer) -> anyhow::Result<Option<(SocketAddr, JoinHandle<()>)>> {
    let (bound_tx, bound_rx) = oneshot::channel::<SocketAddr>();
    let server = server.on_bound(move |addr| {
        let _ = bound_tx.send(addr);
    });
    let (done_tx, done_rx) = oneshot::channel::<anyhow::Result<()>>();
    let task = tokio::spawn(async move {
        let _ = done_tx.send(server.serve().await);
    });
    match timeout(STEP, bound_rx)
        .await
        .context("waiting for on_bound")?
    {
        Ok(addr) => Ok(Some((addr, task))),
        Err(_closed) => {
            // `on_bound` was dropped unfired: `serve` ended before binding.
            let outcome = timeout(STEP, done_rx)
                .await
                .context("server task did not end after a failed bind")?
                .context("server task dropped its result")?;
            match outcome {
                Ok(()) => anyhow::bail!("serve returned Ok without ever binding"),
                Err(e) if is_permission_denied(&e) => Ok(None),
                Err(e) => Err(e.context("McpServer::serve failed to bind 127.0.0.1:0")),
            }
        }
    }
}

/// Whether an `io::Error` with `PermissionDenied` is anywhere in the chain
/// (`LoopbackTcp::bind` wraps `TcpListener::bind`'s error directly).
fn is_permission_denied(e: &anyhow::Error) -> bool {
    e.chain().any(|cause| {
        cause
            .downcast_ref::<io::Error>()
            .is_some_and(|io| io.kind() == io::ErrorKind::PermissionDenied)
    })
}

/// The next event, bounded by `STEP`.
async fn next_event(rx: &mut mpsc::Receiver<BusEvent>) -> BusEvent {
    timeout(STEP, rx.recv())
        .await
        .expect("a bus event within 2 s")
        .expect("the bus task closed its event channel")
}

/// Skip events until `pick` accepts one; bounded by `STEP` overall.
async fn wait_for<T>(
    rx: &mut mpsc::Receiver<BusEvent>,
    what: &str,
    pick: impl Fn(&BusEvent) -> Option<T>,
) -> T {
    let deadline = Instant::now() + STEP;
    let mut skipped = Vec::new();
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        let ev = timeout(left, rx.recv())
            .await
            .unwrap_or_else(|_| panic!("no {what} within 2 s; skipped {skipped:?}"))
            .expect("the bus task closed its event channel");
        if let Some(t) = pick(&ev) {
            return t;
        }
        skipped.push(ev);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tui_bus_task_runs_against_the_live_loopback_server() {
    let cfg = config("live");
    let Some((addr, server_task)) = start_server(build_server(&cfg))
        .await
        .expect("start the MCP server on loopback TCP")
    else {
        eprintln!(
            "tui_live_bus: skipped — this sandbox refuses to bind 127.0.0.1:0 \
             (PermissionDenied); run `cargo test -p aitm --test tui_live_bus` in the \
             Terminal panel for the real run"
        );
        return;
    };

    let (connect, label) = aitm_tui::connector(TransportChoice::Tcp {
        addr,
        token: TOKEN.into(),
    })
    .expect("build the TCP connector");
    assert_eq!(label, addr.to_string());

    let (req_tx, req_rx) = mpsc::channel::<BusRequest>(16);
    let (ev_tx, mut ev_rx) = mpsc::channel::<BusEvent>(256);
    let bus_task = tokio::spawn(aitm_tui::bus::run(connect, req_rx, ev_tx, POLL));

    // 1. The first event is the handshake result, read straight off the live
    //    tools/list: present tools, and the one the bus does not have yet.
    let first = next_event(&mut ev_rx).await;
    let BusEvent::Connected {
        server,
        tools,
        listening,
    } = first
    else {
        panic!("the first event must be Connected, got {first:?}");
    };
    assert_eq!(server, format!("aitmproxy {}", aitm_core::VERSION));
    let names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
    for want in ["flow.list", "flow.intercept", "request.send"] {
        assert!(
            names.contains(&want),
            "tools must contain {want}: {names:?}"
        );
    }
    assert!(
        !names.contains(&"flow.detail"),
        "flow.detail is not on the bus yet (foundation §4.4): {names:?}"
    );
    // `proxy.status` is not registered, so the bus has nothing to report here.
    assert_eq!(listening, None);

    // 2. The first poll over a fresh proxy: `flow.list` is empty.
    let flows = wait_for(&mut ev_rx, "Flows", |e| match e {
        BusEvent::Flows(v) => Some(v.clone()),
        _ => None,
    })
    .await;
    assert!(flows.is_empty(), "a fresh proxy has no flows: {flows:?}");

    // 3. A real tools/call through the TCP transport; polls may interleave.
    req_tx
        .send(BusRequest::Intercept(true))
        .await
        .expect("the bus task is still taking requests");
    let (name, value) = wait_for(&mut ev_rx, "CallOk", |e| match e {
        BusEvent::CallOk { name, value } => Some((name.clone(), value.clone())),
        _ => None,
    })
    .await;
    assert_eq!(name, "flow.intercept");
    assert_eq!(value, Value::Bool(true));

    // 4. A tool the live tools/list does not offer is refused locally.
    req_tx
        .send(BusRequest::Call {
            name: "nope".into(),
            args: json!({}),
        })
        .await
        .expect("the bus task is still taking requests");
    let (level, message) = wait_for(&mut ev_rx, "Toast", |e| match e {
        BusEvent::Toast(level, m) => Some((*level, m.clone())),
        _ => None,
    })
    .await;
    assert_eq!(level, Level::Warn);
    assert_eq!(message, "nope is not on this bus");

    // 5. Closing the request channel ends `run`.
    drop(req_tx);
    timeout(STEP, bus_task)
        .await
        .expect("the bus task ends within 2 s of the request channel closing")
        .expect("the bus task did not panic");

    server_task.abort();
}
