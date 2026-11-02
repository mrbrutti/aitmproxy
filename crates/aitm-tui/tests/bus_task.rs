//! The bus task (`aitm_tui::bus::run`) against a transport whose every reply
//! is a literal written in this file (spec 2026-10-31-remove-fake-data-ui-modes,
//! rule 2: a test-local `BusTransport` with literal replies). Three properties
//! the deleted fixture-driven suite guarded and nothing else does: a refused
//! token during the handshake is reported once and the task does not retry;
//! a failed connect backs off before it reconnects; a malformed `flow.detail`
//! reply becomes `DetailFailed` plus a warn toast, never a panic. The live
//! counterpart against the real server is `crates/aitm/tests/tui_live_bus.rs`.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use aitm_bus_client::{BoxFuture, BusClient, BusTransport};
use aitm_tui::action::{BusEvent, BusRequest, Level};
use aitm_tui::bus::{self, Connector};
use serde_json::{json, Value};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::timeout;

const WAIT: Duration = Duration::from_secs(3);

/// The tools the scripted bus lists: enough for the poll (`flow.list`,
/// `flow.get`) and for a `BusRequest::Detail` to reach the wire.
const TOOLS: &[&str] = &["flow.list", "flow.get", "flow.detail"];

/// A bus whose replies are literals: `initialize` names a test server,
/// `tools/list` offers [`TOOLS`], and each `tools/call` is answered by
/// `answer(tool, arguments)`. A notification (no `id`) gets no reply, as on
/// the wire.
struct Scripted {
    answer: fn(&str, &Value) -> Value,
}

impl BusTransport for Scripted {
    fn send(&self, line: String) -> BoxFuture<'_, anyhow::Result<Option<String>>> {
        let req: Value = serde_json::from_str(&line).expect("the client sends JSON");
        let Some(id) = req.get("id").filter(|id| !id.is_null()).cloned() else {
            return Box::pin(async { Ok(None) });
        };
        let result = match req["method"].as_str() {
            Some("initialize") => json!({
                "protocolVersion": "2025-06-18",
                "serverInfo": {"name": "aitmproxy", "version": "0.0.0-test"},
                "role": "operator",
            }),
            Some("tools/list") => json!({
                "tools": TOOLS
                    .iter()
                    .map(|n| json!({
                        "name": n,
                        "description": format!("{n} (test)"),
                        "inputSchema": {"type": "object", "properties": {}},
                    }))
                    .collect::<Vec<_>>(),
            }),
            Some("tools/call") => (self.answer)(
                req["params"]["name"].as_str().unwrap_or(""),
                &req["params"]["arguments"],
            ),
            _ => json!({}),
        };
        let reply = json!({"jsonrpc": "2.0", "id": id, "result": result}).to_string();
        Box::pin(async move { Ok(Some(reply)) })
    }
}

/// A `tools/call` result carrying `value` as its structured content.
fn structured(value: Value) -> Value {
    json!({
        "content": [{"type": "text", "text": value.to_string()}],
        "structuredContent": value,
        "isError": false,
    })
}

/// A `tools/call` result whose tool reports failure with `message`.
fn tool_error(message: &str) -> Value {
    json!({"content": [{"type": "text", "text": message}], "isError": true})
}

/// A bus with no flows: every poll's `flow.list` is empty.
fn empty_bus(tool: &str, _args: &Value) -> Value {
    match tool {
        "flow.list" => structured(json!([])),
        other => tool_error(&format!("{other} is not scripted")),
    }
}

/// [`empty_bus`], except that `flow.detail` answers with an object the model
/// rejects (no `id`, none of the detail's fields).
fn garbage_detail(tool: &str, args: &Value) -> Value {
    match tool {
        "flow.detail" => structured(json!({"garbage": true})),
        other => empty_bus(other, args),
    }
}

/// A server that refuses the token: every request is answered with the
/// `-32001` error `aitm-mcp` sends before it hangs up.
struct Refusing;

impl BusTransport for Refusing {
    fn send(&self, line: String) -> BoxFuture<'_, anyhow::Result<Option<String>>> {
        let req: Value = serde_json::from_str(&line).expect("the client sends JSON");
        let reply = req.get("id").filter(|id| !id.is_null()).map(|id| {
            json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32001, "message": "unauthorized"}})
                .to_string()
        });
        Box::pin(async move { Ok(reply) })
    }
}

struct Running {
    req_tx: mpsc::Sender<BusRequest>,
    ev_rx: mpsc::Receiver<BusEvent>,
    task: JoinHandle<()>,
}

fn start(connect: Connector, poll: Duration) -> Running {
    let (req_tx, req_rx) = mpsc::channel(32);
    let (ev_tx, ev_rx) = mpsc::channel(256);
    let task = tokio::spawn(bus::run(connect, req_rx, ev_tx, poll));
    Running {
        req_tx,
        ev_rx,
        task,
    }
}

/// A connector that counts its calls and hands out `Scripted { answer }`.
fn scripted(answer: fn(&str, &Value) -> Value, attempts: Arc<AtomicUsize>) -> Connector {
    Arc::new(move || {
        attempts.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move { Ok(BusClient::new(Box::new(Scripted { answer }))) })
    })
}

async fn next_where(
    rx: &mut mpsc::Receiver<BusEvent>,
    pred: impl Fn(&BusEvent) -> bool,
) -> BusEvent {
    timeout(WAIT, async {
        loop {
            let ev = rx.recv().await.expect("the bus task is alive");
            if pred(&ev) {
                return ev;
            }
        }
    })
    .await
    .expect("the expected event arrives within 3 s")
}

/// The app goes away: both channels drop. A connected session sees the closed
/// request channel at once; a session stuck in connect back-off notices when
/// its next `Disconnected` event has nobody to go to (the live loop also
/// aborts the task from `TerminalGuard`).
async fn finish(r: Running) {
    drop(r.req_tx);
    drop(r.ev_rx);
    timeout(WAIT, r.task)
        .await
        .expect("the task ends when the app goes away")
        .expect("the task does not panic");
}

/// The bus answering the handshake with `-32001` means our token is wrong.
/// Retrying with back-off cannot fix that, so the task reports it once, with
/// the fix in the message, and stops.
#[tokio::test]
async fn a_refused_token_during_the_handshake_is_reported_once_and_not_retried() {
    let attempts = Arc::new(AtomicUsize::new(0));
    let counter = attempts.clone();
    let connect: Connector = Arc::new(move || {
        counter.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Ok(BusClient::new(Box::new(Refusing))) })
    });
    let mut r = start(connect, Duration::from_millis(20));
    let first = timeout(WAIT, r.ev_rx.recv()).await.unwrap().unwrap();
    assert_eq!(first, BusEvent::Disconnected(bus::REFUSED.into()));
    // The task ends on its own: no second connect, no back-off loop. Both
    // channels are still open here, so this is the task's decision.
    timeout(WAIT, r.task)
        .await
        .expect("the task stops after a token refusal")
        .expect("the task does not panic");
    assert_eq!(attempts.load(Ordering::SeqCst), 1, "no retry");
    assert!(
        r.ev_rx.try_recv().is_err(),
        "the refusal is reported exactly once"
    );
    drop(r.req_tx);
}

/// A connect that fails (the proxy is not up yet) is reported as
/// `Disconnected` with the error, and the retry waits out the back-off
/// (500 ms to start) instead of hammering the socket.
#[tokio::test]
async fn a_failed_connect_reports_disconnected_then_retries_with_backoff() {
    let attempts = Arc::new(AtomicUsize::new(0));
    let counter = attempts.clone();
    let connect: Connector = Arc::new(move || {
        let n = counter.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            if n == 0 {
                anyhow::bail!("connection refused (os error 61)");
            }
            Ok(BusClient::new(Box::new(Scripted { answer: empty_bus })))
        })
    });
    let started = Instant::now();
    let mut r = start(connect, Duration::from_millis(50));
    let first = timeout(WAIT, r.ev_rx.recv()).await.unwrap().unwrap();
    assert_eq!(
        first,
        BusEvent::Disconnected("connection refused (os error 61)".into())
    );
    let connected = next_where(&mut r.ev_rx, |e| matches!(e, BusEvent::Connected { .. })).await;
    assert!(
        started.elapsed() >= Duration::from_millis(400),
        "back-off before the retry: {:?}",
        started.elapsed()
    );
    assert_eq!(attempts.load(Ordering::SeqCst), 2);
    let BusEvent::Connected {
        server,
        tools,
        role,
    } = connected
    else {
        unreachable!()
    };
    assert_eq!(server, "aitmproxy 0.0.0-test");
    assert_eq!(role.as_deref(), Some("operator"));
    assert_eq!(
        tools.iter().map(|t| t.name.as_str()).collect::<Vec<_>>(),
        TOOLS
    );
    finish(r).await;
}

/// A `flow.detail` reply the model rejects is reported, and the app is told
/// not to ask again for that id — the task neither panics nor drops the
/// session.
#[tokio::test]
async fn a_malformed_flow_detail_reply_is_a_warn_toast_and_a_detail_failed_event() {
    let attempts = Arc::new(AtomicUsize::new(0));
    let mut r = start(
        scripted(garbage_detail, attempts.clone()),
        Duration::from_millis(50),
    );
    let _ = next_where(&mut r.ev_rx, |e| matches!(e, BusEvent::Connected { .. })).await;
    r.req_tx
        .send(BusRequest::Detail("f41".into()))
        .await
        .unwrap();
    let failed = next_where(&mut r.ev_rx, |e| matches!(e, BusEvent::DetailFailed(_))).await;
    assert_eq!(failed, BusEvent::DetailFailed("f41".into()));
    let toast = next_where(&mut r.ev_rx, |e| matches!(e, BusEvent::Toast(..))).await;
    assert_eq!(
        toast,
        BusEvent::Toast(Level::Warn, "flow.detail f41: malformed reply".into())
    );
    // The session is still the same one: polling goes on, no reconnect.
    let _ = next_where(&mut r.ev_rx, |e| matches!(e, BusEvent::Flows(_))).await;
    assert_eq!(attempts.load(Ordering::SeqCst), 1, "no reconnect");
    finish(r).await;
}
