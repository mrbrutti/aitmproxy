//! The bus task (`aitm_tui::bus::run`) against a transport whose every reply
//! is a literal written in this file (spec 2026-10-31-remove-fake-data-ui-modes,
//! rule 2: a test-local `BusTransport` with literal replies). Three properties
//! the deleted fixture-driven suite guarded and nothing else does: a refused
//! token during the handshake is reported once and the task does not retry;
//! a failed connect backs off before it reconnects; a malformed `flow.detail`
//! reply becomes `DetailFailed` plus a warn toast, never a panic. Scanner v2
//! T7 (spec D4, D5, T7-15) adds, through a transport that also records every
//! line it sends: the handshake subscribes once when the bus offers
//! `flow.subscribe` and a refused subscribe is a warning, not a session
//! loss; `prune()` keeps the reserved `_confirm` key; a `CallTagged` answers
//! under its tag. The 0.5.16 acceptance (T7 D5 as amended 2026-11-03) adds:
//! on a transport with no push sink (`aitm tui`'s in-process server) the
//! handshake never calls `flow.subscribe` and raises no toast. The live
//! counterpart against the real server is `crates/aitm/tests/tui_live_bus.rs`.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
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

/// [`TOOLS`] plus what the scanner v2 handshake and dispatch pins need:
/// `proxy.status` and `flow.subscribe` for the handshake, `flow.resume` for
/// a tool that reports an error.
const SCAN_TOOLS: &[&str] = &[
    "flow.list",
    "flow.get",
    "flow.detail",
    "proxy.status",
    "flow.subscribe",
    "flow.resume",
];

/// The `tools/list` entry for `name`: `flow.get` declares its `id`, so
/// `prune()` has a schema to prune against; every other tool declares no
/// property.
fn tool_entry(name: &str) -> Value {
    let properties = if name == "flow.get" {
        json!({"id": {"type": "string"}})
    } else {
        json!({})
    };
    json!({
        "name": name,
        "description": format!("{name} (test)"),
        "inputSchema": {"type": "object", "properties": properties},
    })
}

/// A bus whose replies are literals: `initialize` names a test server,
/// `tools/list` offers `tools`, and each `tools/call` is answered by
/// `answer(tool, arguments)`. A notification (no `id`) gets no reply, as on
/// the wire.
struct Scripted {
    answer: fn(&str, &Value) -> Value,
    tools: &'static [&'static str],
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
                "tools": self.tools.iter().map(|n| tool_entry(n)).collect::<Vec<_>>(),
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

type Lines = Arc<Mutex<Vec<String>>>;

/// [`Scripted`], recording every line the client sends.
struct Recording {
    inner: Scripted,
    lines: Lines,
}

impl BusTransport for Recording {
    fn send(&self, line: String) -> BoxFuture<'_, anyhow::Result<Option<String>>> {
        self.lines.lock().unwrap().push(line.clone());
        self.inner.send(line)
    }
}

/// Every line sent so far, parsed.
fn sent(lines: &Lines) -> Vec<Value> {
    lines
        .lock()
        .unwrap()
        .iter()
        .map(|l| serde_json::from_str(l).expect("the client sends JSON"))
        .collect()
}

/// The name of the tool a `tools/call` line invokes (empty for any other
/// method).
fn tool_name(req: &Value) -> &str {
    if req["method"] == "tools/call" {
        req["params"]["name"].as_str().unwrap_or("")
    } else {
        ""
    }
}

/// A v2-shaped bus with no flows: `proxy.status` reports a listening proxy,
/// `flow.subscribe` succeeds, `flow.get` echoes the id asked for as a GET
/// summary, `flow.resume` reports a tool error.
fn scan_bus(tool: &str, args: &Value) -> Value {
    match tool {
        "flow.list" => structured(json!([])),
        "proxy.status" => structured(json!({
            "listening": true, "address": "127.0.0.1:8080", "intercept_armed": false,
            "capturing": true, "paused": 0, "flows": 0,
        })),
        "flow.subscribe" => structured(json!({"sub_id": 1})),
        "flow.get" => structured(json!({
            "id": args["id"], "kind": "http", "method": "GET", "scheme": "https",
            "authority": "api.test", "path": "/", "status": 200,
            "is_replay": false, "intercept": "observed",
        })),
        "flow.resume" => tool_error("flow is not intercepted"),
        other => tool_error(&format!("{other} is not scripted")),
    }
}

/// [`scan_bus`], except that `flow.subscribe` reports a tool error.
fn refusing_subscribe(tool: &str, args: &Value) -> Value {
    match tool {
        "flow.subscribe" => tool_error("nope"),
        other => scan_bus(other, args),
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

/// The task on a transport that can (`push == true`, the TCP bus) or cannot
/// (`push == false`, the in-process server) deliver server pushes.
fn start(connect: Connector, poll: Duration, push: bool) -> Running {
    let (req_tx, req_rx) = mpsc::channel(32);
    let (ev_tx, ev_rx) = mpsc::channel(256);
    let task = tokio::spawn(bus::run(connect, req_rx, ev_tx, poll, push));
    Running {
        req_tx,
        ev_rx,
        task,
    }
}

/// A connector that counts its calls and hands out `Scripted { answer }`
/// offering [`TOOLS`].
fn scripted(answer: fn(&str, &Value) -> Value, attempts: Arc<AtomicUsize>) -> Connector {
    Arc::new(move || {
        attempts.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            Ok(BusClient::new(Box::new(Scripted {
                answer,
                tools: TOOLS,
            })))
        })
    })
}

/// The task against a recording [`Scripted`] bus offering [`SCAN_TOOLS`],
/// and the lines it sends. `push` as for [`start`].
fn start_recording(
    answer: fn(&str, &Value) -> Value,
    poll: Duration,
    push: bool,
) -> (Running, Lines) {
    let lines: Lines = Arc::new(Mutex::new(Vec::new()));
    let recorded = lines.clone();
    let connect: Connector = Arc::new(move || {
        let lines = recorded.clone();
        Box::pin(async move {
            Ok(BusClient::new(Box::new(Recording {
                inner: Scripted {
                    answer,
                    tools: SCAN_TOOLS,
                },
                lines,
            })))
        })
    });
    (start(connect, poll, push), lines)
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
    let mut r = start(connect, Duration::from_millis(20), true);
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
            Ok(BusClient::new(Box::new(Scripted {
                answer: empty_bus,
                tools: TOOLS,
            })))
        })
    });
    let started = Instant::now();
    let mut r = start(connect, Duration::from_millis(50), true);
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
/// not to ask again for that id: the task neither panics nor drops the
/// session.
#[tokio::test]
async fn a_malformed_flow_detail_reply_is_a_warn_toast_and_a_detail_failed_event() {
    let attempts = Arc::new(AtomicUsize::new(0));
    let mut r = start(
        scripted(garbage_detail, attempts.clone()),
        Duration::from_millis(50),
        true,
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

/// Scanner v2 T7, spec D5: after the handshake, when the bus offers
/// `flow.subscribe`, the task subscribes exactly once so job and flow lines
/// reach it as pushes. It follows `proxy.status` and precedes the first poll.
#[tokio::test]
async fn the_handshake_subscribes_once_when_the_bus_offers_flow_subscribe() {
    let (mut r, lines) = start_recording(scan_bus, Duration::from_millis(50), true);
    let _ = next_where(&mut r.ev_rx, |e| matches!(e, BusEvent::Flows(_))).await;
    let wire = sent(&lines);
    // initialize, notifications/initialized, tools/list, then the reads.
    assert_eq!(wire[0]["method"], "initialize");
    assert_eq!(wire[2]["method"], "tools/list");
    assert_eq!(wire[3]["params"]["name"], "proxy.status");
    assert_eq!(wire[4]["method"], "tools/call");
    assert_eq!(wire[4]["params"]["name"], "flow.subscribe");
    assert_eq!(wire[4]["params"]["arguments"], json!({}));
    assert_eq!(wire[5]["params"]["name"], "flow.list");
    assert_eq!(
        wire.iter()
            .filter(|w| tool_name(w) == "flow.subscribe")
            .count(),
        1,
        "subscribed once across the handshake and the first poll: {wire:?}"
    );
    finish(r).await;
}

/// Scanner v2 T7, spec D5: a tool error from `flow.subscribe` is one Warn
/// toast with the fixed wording and the session carries on into its first
/// poll; it is never a `Disconnected`.
#[tokio::test]
async fn a_failed_subscribe_is_a_warn_toast_not_a_session_loss() {
    let (mut r, _lines) = start_recording(refusing_subscribe, Duration::from_millis(50), true);
    let _ = next_where(&mut r.ev_rx, |e| matches!(e, BusEvent::Connected { .. })).await;
    let mut toasts = Vec::new();
    let flows = loop {
        let ev = timeout(WAIT, r.ev_rx.recv()).await.unwrap().unwrap();
        match ev {
            BusEvent::Flows(s) => break s,
            BusEvent::Toast(level, text) => toasts.push((level, text)),
            BusEvent::Disconnected(why) => panic!("a failed subscribe lost the session: {why}"),
            _ => {}
        }
    };
    assert_eq!(
        toasts,
        vec![(
            Level::Warn,
            "flow.subscribe failed: nope; scan progress will poll only".to_string()
        )]
    );
    assert!(
        flows.is_empty(),
        "the first poll follows the warning: {flows:?}"
    );
    finish(r).await;
}

/// T7 spec D5 as amended 2026-11-03 (0.5.16 acceptance, TUI-1): `aitm tui`
/// talks to its embedded core over an in-process transport that has no push
/// sink, so the server refuses `flow.subscribe` by design and the poll is
/// the truth. With `push == false` the handshake never puts `flow.subscribe`
/// on the wire and raises no toast, even against a bus that offers the tool
/// and would refuse it; the session still reaches its first poll. Before
/// the fix every `aitm tui` start toasted `flow.subscribe failed: …`, which
/// hid the startup log note.
#[tokio::test]
async fn the_in_process_handshake_never_subscribes() {
    let (mut r, lines) = start_recording(refusing_subscribe, Duration::from_millis(50), false);
    let _ = next_where(&mut r.ev_rx, |e| matches!(e, BusEvent::Connected { .. })).await;
    let mut toasts = Vec::new();
    loop {
        let ev = timeout(WAIT, r.ev_rx.recv()).await.unwrap().unwrap();
        match ev {
            BusEvent::Flows(_) => break,
            BusEvent::Toast(level, text) => toasts.push((level, text)),
            BusEvent::Disconnected(why) => panic!("the handshake lost the session: {why}"),
            _ => {}
        }
    }
    assert_eq!(
        toasts,
        Vec::new(),
        "no toast between Connected and the first poll"
    );
    let wire = sent(&lines);
    assert_eq!(
        wire.iter()
            .filter(|w| tool_name(w) == "flow.subscribe")
            .count(),
        0,
        "flow.subscribe never reaches the wire on the in-process transport: {wire:?}"
    );
    // The handshake is otherwise unchanged: proxy.status, then the poll.
    assert_eq!(wire[3]["params"]["name"], "proxy.status");
    assert_eq!(wire[4]["params"]["name"], "flow.list");
    finish(r).await;
}

/// Scanner v2 T7, Constraints finding and T7-15: `prune()` keeps the reserved
/// `_confirm` key although no tool schema declares it (the server strips it
/// itself); every other undeclared key is still dropped.
#[tokio::test]
async fn prune_keeps_the_reserved_confirm_key() {
    let (mut r, lines) = start_recording(scan_bus, Duration::from_millis(50), true);
    let _ = next_where(&mut r.ev_rx, |e| matches!(e, BusEvent::Connected { .. })).await;
    let before = sent(&lines).len();
    r.req_tx
        .send(BusRequest::Call {
            name: "flow.get".into(),
            args: json!({"id": "f40", "_confirm": "tok-1", "bogus": true}),
        })
        .await
        .unwrap();
    let ev = next_where(
        &mut r.ev_rx,
        |e| matches!(e, BusEvent::CallOk { name, .. } if name == "flow.get"),
    )
    .await;
    assert!(
        matches!(&ev, BusEvent::CallOk { value, .. } if value["id"] == "f40"),
        "{ev:?}"
    );
    let wire = sent(&lines);
    let gets: Vec<&Value> = wire[before..]
        .iter()
        .filter(|w| tool_name(w) == "flow.get")
        .map(|w| &w["params"]["arguments"])
        .collect();
    assert_eq!(
        gets,
        vec![&json!({"id": "f40", "_confirm": "tok-1"})],
        "one flow.get, carrying _confirm and not bogus: {gets:?}"
    );
    finish(r).await;
}

/// Scanner v2 T7, spec D4 and T7-15: a `CallTagged` is run exactly like a
/// `Call` and its reply echoes the tag, whether the call succeeded, the tool
/// reported an error, or the bus does not offer the tool at all. The task
/// stays verb-agnostic: the tag is opaque to it.
#[tokio::test]
async fn a_tagged_call_answers_with_the_same_tag() {
    let (mut r, lines) = start_recording(scan_bus, Duration::from_millis(50), true);
    let _ = next_where(&mut r.ev_rx, |e| matches!(e, BusEvent::Connected { .. })).await;

    r.req_tx
        .send(BusRequest::CallTagged {
            tag: "scan.status:scan-1a2b3c4d".into(),
            name: "flow.get".into(),
            args: json!({"id": "f40"}),
        })
        .await
        .unwrap();
    let ev = next_where(&mut r.ev_rx, |e| matches!(e, BusEvent::CallTaggedOk { .. })).await;
    let BusEvent::CallTaggedOk { tag, name, value } = ev else {
        unreachable!()
    };
    assert_eq!(tag, "scan.status:scan-1a2b3c4d");
    assert_eq!(name, "flow.get");
    assert_eq!(value["id"], "f40");
    assert_eq!(value["method"], "GET");

    // A tool the bus does not offer is refused locally, under the same tag,
    // and never reaches the wire.
    r.req_tx
        .send(BusRequest::CallTagged {
            tag: "scan.list".into(),
            name: "scan.list".into(),
            args: json!({}),
        })
        .await
        .unwrap();
    let ev = next_where(&mut r.ev_rx, |e| {
        matches!(e, BusEvent::CallTaggedFailed { .. })
    })
    .await;
    assert_eq!(
        ev,
        BusEvent::CallTaggedFailed {
            tag: "scan.list".into(),
            name: "scan.list".into(),
            message: "scan.list is not on this bus".into(),
        }
    );
    assert!(
        !sent(&lines).iter().any(|w| tool_name(w) == "scan.list"),
        "never sent to the bus"
    );

    // A tool error (isError) is a tagged failure carrying the tool's message.
    r.req_tx
        .send(BusRequest::CallTagged {
            tag: "scan.cancel:f41".into(),
            name: "flow.resume".into(),
            args: json!({"id": "f41"}),
        })
        .await
        .unwrap();
    let ev = next_where(&mut r.ev_rx, |e| {
        matches!(e, BusEvent::CallTaggedFailed { .. })
    })
    .await;
    assert_eq!(
        ev,
        BusEvent::CallTaggedFailed {
            tag: "scan.cancel:f41".into(),
            name: "flow.resume".into(),
            message: "flow is not intercepted".into(),
        }
    );
    finish(r).await;
}

/// Tester, 0.5.16 acceptance Task 1: the flag `bus::run` reads comes from
/// `lib::connector`, so the fix is only as good as that wiring. The TCP choice
/// reports pushes (`true`), the in-process choice reports none (`false`),
/// beside the labels the status bar shows. Neither connector is invoked, so
/// no socket is opened and the handler is never called.
#[test]
fn the_connector_reports_pushes_for_tcp_and_none_for_in_process() {
    use aitm_bus_client::InProcessHandler;
    use aitm_tui::{connector, TransportChoice};

    let handler: InProcessHandler = Arc::new(|_line: &str| -> Option<String> {
        panic!("the connector must not call the handler while being built")
    });
    let (_connect, label, push) =
        connector(TransportChoice::InProcess(handler)).expect("build the in-process connector");
    assert_eq!(label, "in-process");
    assert!(
        !push,
        "the in-process server has no push sink: the bus task must not subscribe on it"
    );

    let addr: std::net::SocketAddr = "127.0.0.1:1".parse().unwrap();
    let (_connect, label, push) = connector(TransportChoice::Tcp {
        addr,
        token: "t".into(),
    })
    .expect("build the TCP connector");
    assert_eq!(label, addr.to_string());
    assert!(push, "the loopback TCP bus carries server pushes");
}

/// [`Recording`] whose connection dies at its first `flow.list` when `dies`
/// is set: from then on every send fails the way a reset socket does.
struct Dropping {
    inner: Recording,
    dies: bool,
    dead: std::sync::atomic::AtomicBool,
}

impl BusTransport for Dropping {
    fn send(&self, line: String) -> BoxFuture<'_, anyhow::Result<Option<String>>> {
        if self.dies {
            let req: Value = serde_json::from_str(&line).expect("the client sends JSON");
            if tool_name(&req) == "flow.list" || self.dead.load(Ordering::SeqCst) {
                self.dead.store(true, Ordering::SeqCst);
                self.inner.lines.lock().unwrap().push(line);
                return Box::pin(async { Err(anyhow::anyhow!("connection reset by peer")) });
            }
        }
        self.inner.send(line)
    }
}

/// The task against a bus that refuses `flow.subscribe`, whose first
/// connection drops mid-stream (at the first poll) and whose second one is
/// healthy. Returns every line sent over both connections, the toasts seen,
/// and the connect attempts.
async fn drop_then_reconnect(push: bool) -> (Vec<Value>, Vec<(Level, String)>, usize) {
    let lines: Lines = Arc::new(Mutex::new(Vec::new()));
    let attempts = Arc::new(AtomicUsize::new(0));
    let recorded = lines.clone();
    let counter = attempts.clone();
    let connect: Connector = Arc::new(move || {
        let n = counter.fetch_add(1, Ordering::SeqCst);
        let lines = recorded.clone();
        Box::pin(async move {
            Ok(BusClient::new(Box::new(Dropping {
                inner: Recording {
                    inner: Scripted {
                        answer: refusing_subscribe,
                        tools: SCAN_TOOLS,
                    },
                    lines,
                },
                dies: n == 0,
                dead: std::sync::atomic::AtomicBool::new(false),
            })))
        })
    });
    let mut r = start(connect, Duration::from_millis(50), push);
    let mut toasts = Vec::new();
    let mut connected = 0;
    let mut lost = 0;
    // Connected, (toast), Disconnected, Connected, (toast), Flows.
    let deadline = Instant::now() + WAIT * 2;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        let ev = timeout(left, r.ev_rx.recv())
            .await
            .unwrap_or_else(|_| panic!("the reconnect completes within {:?}", WAIT * 2))
            .expect("the bus task is alive");
        match ev {
            BusEvent::Connected { .. } => connected += 1,
            BusEvent::Disconnected(_) => lost += 1,
            BusEvent::Toast(level, text) => toasts.push((level, text)),
            BusEvent::Flows(_) if connected == 2 => break,
            _ => {}
        }
    }
    assert_eq!((connected, lost), (2, 1), "one drop, one reconnect");
    finish(r).await;
    (sent(&lines), toasts, attempts.load(Ordering::SeqCst))
}

/// Tester: a connection that dies mid-stream is `Disconnected`, backed off
/// and reconnected (`bus::run`'s `Outcome::Lost` arm). On the TCP transport
/// every connection subscribes once more: two connections, two
/// `flow.subscribe` lines, two refusal toasts.
#[tokio::test]
async fn a_dropped_push_connection_subscribes_again_on_reconnect() {
    let (wire, toasts, attempts) = drop_then_reconnect(true).await;
    assert_eq!(attempts, 2);
    assert_eq!(
        wire.iter()
            .filter(|w| tool_name(w) == "flow.subscribe")
            .count(),
        2,
        "once per connection: {wire:?}"
    );
    assert_eq!(
        toasts.len(),
        2,
        "one refusal toast per connection: {toasts:?}"
    );
    assert!(toasts
        .iter()
        .all(|(l, t)| *l == Level::Warn && t.starts_with("flow.subscribe failed")));
}

/// Tester, T7 D5 as amended 2026-11-03: the in-process flag survives a drop.
/// The second connection is a fresh `Session`, built from `bus::run`'s own
/// `push`, so it must not start subscribing (or toasting) after a reconnect
/// either: zero `flow.subscribe` lines and zero toasts over both connections.
#[tokio::test]
async fn a_dropped_in_process_connection_still_never_subscribes() {
    let (wire, toasts, attempts) = drop_then_reconnect(false).await;
    assert_eq!(attempts, 2);
    assert_eq!(
        wire.iter()
            .filter(|w| tool_name(w) == "flow.subscribe")
            .count(),
        0,
        "flow.subscribe never reaches the wire on either connection: {wire:?}"
    );
    assert_eq!(
        toasts,
        Vec::new(),
        "no toast over the drop and the reconnect"
    );
    // Both connections completed their handshake: two `initialize` lines.
    assert_eq!(
        wire.iter().filter(|w| w["method"] == "initialize").count(),
        2
    );
}
