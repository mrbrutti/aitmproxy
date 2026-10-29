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

mod support;

use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use aitm::tui::build_servers;
use aitm_core::{Config, McpTransport};
use aitm_mcp::McpServer;
use aitm_tui::action::{BusEvent, BusRequest};
use aitm_tui::TransportChoice;
use anyhow::Context as _;
use serde_json::json;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio::time::{timeout, Instant};

/// The loopback agent token both ends agree on.
const TOKEN: &str = "tui-live-bus-token";
/// The operator token: a connection presenting it is `Frontend::Operator` and
/// bypasses the agent policy gate, as a real operator's `aitm-tui --bus --token`
/// does. The TUI is the operator, so it presents this.
const OPERATOR_TOKEN: &str = "tui-live-bus-operator-token";
/// Longest any single wait in this test is allowed to take.
const STEP: Duration = Duration::from_secs(2);
/// The TUI poll interval under test (the plan says 50 ms).
const POLL: Duration = Duration::from_millis(50);

/// The default config with a throwaway CA and the loopback-TCP agent
/// transport `aitm tui` serves beside the UI.
fn config(tag: &str) -> Config {
    let mut cfg = support::config(tag);
    cfg.mcp.transport = McpTransport::LoopbackTcp {
        port: 0,
        token: TOKEN.into(),
        endpoint_file: None,
    };
    // The loopback transport is agent-facing and gated by the M4 policy, so a
    // Sensitive command like `flow.intercept` is refused to an agent. The TUI is
    // the operator and connects with the operator token below, so it is served as
    // `Frontend::Operator` and bypasses the gate.
    cfg.mcp.operator_token = Some(OPERATOR_TOKEN.into());
    cfg
}

/// The agent-facing server exactly as `aitm tui` builds it: `assemble`, the
/// shared service handles, then `tui::build_servers` — the loopback-TCP half.
fn build_server(cfg: &Config) -> McpServer {
    let (_proxy, services) = support::assemble_services(cfg);
    build_servers(cfg, services)
        .0
        .expect("a loopback-TCP transport gets an agent server")
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
        token: OPERATOR_TOKEN.into(),
    })
    .expect("build the TCP connector");
    assert_eq!(label, addr.to_string());

    let (req_tx, req_rx) = mpsc::channel::<BusRequest>(16);
    let (ev_tx, mut ev_rx) = mpsc::channel::<BusEvent>(256);
    let bus_task = tokio::spawn(aitm_tui::bus::run(connect, req_rx, ev_tx, POLL));

    // 1. The first event is the handshake result, read straight off the live
    //    tools/list: exactly the tools the TUI's `CORE_TOOLS` says today's
    //    core serves (the 2026-10-28 merge: F5/F6/F7/F12/F13 and the M3
    //    commands), `flow.detail` among them.
    let first = next_event(&mut ev_rx).await;
    let BusEvent::Connected {
        server,
        tools,
        role,
    } = first
    else {
        panic!("the first event must be Connected, got {first:?}");
    };
    assert_eq!(server, format!("aitmproxy {}", aitm_core::VERSION));
    // AC6: the operator token resolves to operator and the role is echoed in
    // the `initialize` result the TUI's bus client now reads.
    assert_eq!(role.as_deref(), Some("operator"));
    let mut names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
    names.sort_unstable();
    // This harness assembles the proxy without the M3 script tier, so the
    // three `script.*`/`findings.*` tools are absent; everything it serves
    // must be in `CORE_TOOLS`, and every operator command must be served.
    for name in &names {
        assert!(
            aitm_tui::CORE_TOOLS.contains(name),
            "live tool `{name}` is missing from aitm_tui::CORE_TOOLS"
        );
    }
    let script_tier = ["findings.list", "script.reload", "script.validate"];
    for want in aitm_tui::CORE_TOOLS
        .iter()
        .filter(|t| !script_tier.contains(t))
    {
        assert!(
            names.contains(want),
            "the live bus lacks `{want}`: {names:?}"
        );
    }
    assert!(names.contains(&"flow.detail"), "{names:?}");

    // 2. The handshake reads `proxy.status` (F7) and reports it as the next
    //    event, in the control plugin's shape. Nothing bound the proxy's
    //    listen address in this test, so `listening` is honestly false while
    //    `address` is the configured one; a fresh store has no flows.
    let second = next_event(&mut ev_rx).await;
    let BusEvent::ProxyStatus(status) = second else {
        panic!("Connected is followed by ProxyStatus, got {second:?}");
    };
    assert_eq!(status.address, Some(cfg.listen.to_string()));
    assert!(!status.listening, "the proxy is not serving in this test");
    assert!(!status.intercept_armed);
    assert!(status.capturing);
    assert_eq!((status.paused, status.flows), (0, 0));

    // 3. The first poll over a fresh proxy: `flow.list` is empty.
    let flows = wait_for(&mut ev_rx, "Flows", |e| match e {
        BusEvent::Flows(v) => Some(v.clone()),
        _ => None,
    })
    .await;
    assert!(flows.is_empty(), "a fresh proxy has no flows: {flows:?}");

    // 4. A real tools/call through the TCP transport; polls may interleave.
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
    assert_eq!(value["enabled"], json!(true));

    // 5. A tool the live tools/list does not offer is refused locally.
    req_tx
        .send(BusRequest::Call {
            name: "nope".into(),
            args: json!({}),
        })
        .await
        .expect("the bus task is still taking requests");
    let (name, message) = wait_for(&mut ev_rx, "CallFailed", |e| match e {
        BusEvent::CallFailed { name, message } => Some((name.clone(), message.clone())),
        _ => None,
    })
    .await;
    assert_eq!(name, "nope");
    assert_eq!(message, "nope is not on this bus");

    // 6. Closing the request channel ends `run`.
    drop(req_tx);
    timeout(STEP, bus_task)
        .await
        .expect("the bus task ends within 2 s of the request channel closing")
        .expect("the bus task did not panic");

    server_task.abort();
}
