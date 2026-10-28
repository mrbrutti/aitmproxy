//! Tester (stage 5) — the bus task against the recorded fixture, through a
//! transport that records every line it sends. Proves foundation §4.2's
//! connect sequence as the TUI performs it (`initialize` with
//! `clientInfo.name == "aitm-tui"`, then `tools/list` once, features from the
//! tool list), the poll, request → call → event, error → toast, argument
//! pruning, and reconnection with back-off. The live-bus counterpart against
//! the real `aitm-mcp` server is Task 6 (`crates/aitm/tests/tui_live_bus.rs`).

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use aitm_bus_client::{BoxFuture, BusClient, BusTransport};
use aitm_tui::action::{BusEvent, BusRequest, Level, ToolSchema as _};
use aitm_tui::bus::{self, Connector, CLIENT_NAME};
use aitm_tui::fixture::{Fixture, FixtureTransport, Shared};
use serde_json::{json, Value};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::timeout;

const WAIT: Duration = Duration::from_secs(3);

type Lines = Arc<Mutex<Vec<String>>>;

/// The fixture transport, recording every line the client sends.
struct Recording {
    inner: FixtureTransport,
    lines: Lines,
}

impl BusTransport for Recording {
    fn send(&self, line: String) -> BoxFuture<'_, anyhow::Result<Option<String>>> {
        self.lines.lock().unwrap().push(line.clone());
        self.inner.send(line)
    }
}

/// A transport that dies after `budget` lines: the proxy going away mid-session.
/// Every line, including the one that fails, is recorded.
struct Flaky {
    inner: FixtureTransport,
    budget: AtomicUsize,
    lines: Lines,
}

impl BusTransport for Flaky {
    fn send(&self, line: String) -> BoxFuture<'_, anyhow::Result<Option<String>>> {
        self.lines.lock().unwrap().push(line.clone());
        if self
            .budget
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
            .is_err()
        {
            return Box::pin(async { anyhow::bail!("connection reset by peer") });
        }
        self.inner.send(line)
    }
}

/// `(request, the fixture's reply) -> the reply to deliver`: lets a test hand
/// the client a malformed or failing answer for one tool while the rest of
/// the fixture behaves.
type Rewrite = Arc<dyn Fn(&Value, Option<String>) -> Option<String> + Send + Sync>;

/// The fixture transport with one tool's replies rewritten.
struct Rewriting {
    inner: FixtureTransport,
    rewrite: Rewrite,
}

impl BusTransport for Rewriting {
    fn send(&self, line: String) -> BoxFuture<'_, anyhow::Result<Option<String>>> {
        let req: Value = serde_json::from_str(&line).expect("the client sends JSON");
        let inner = self.inner.send(line);
        let rewrite = self.rewrite.clone();
        Box::pin(async move {
            let reply = inner.await?;
            Ok(rewrite(&req, reply))
        })
    }
}

/// A server that refuses the token: every request is answered with the
/// `-32001` error `aitm-mcp` sends before it hangs up.
struct Refusing;

impl BusTransport for Refusing {
    fn send(&self, line: String) -> BoxFuture<'_, anyhow::Result<Option<String>>> {
        let req: Value = serde_json::from_str(&line).expect("the client sends JSON");
        let reply = req.get("id").filter(|id| !id.is_null()).map(|id| {
            json!({"jsonrpc":"2.0","id":id,"error":{"code":-32001,"message":"unauthorized"}})
                .to_string()
        });
        Box::pin(async move { Ok(reply) })
    }
}

/// The name of the tool a `tools/call` line invokes.
fn tool_name(req: &Value) -> &str {
    if req["method"] == "tools/call" {
        req["params"]["name"].as_str().unwrap_or("")
    } else {
        ""
    }
}

/// A `tools/call` reply for `req` whose tool reports failure with `message`.
fn tool_error_reply(req: &Value, message: &str) -> String {
    json!({"jsonrpc":"2.0","id":req["id"],"result":{
        "content":[{"type":"text","text":message}],"isError":true}})
    .to_string()
}

fn start_rewriting(poll: Duration, rewrite: Rewrite) -> Running {
    let shared = Fixture::builtin().shared();
    let connect: Connector = Arc::new(move || {
        let shared = shared.clone();
        let rewrite = rewrite.clone();
        Box::pin(async move {
            Ok(BusClient::new(Box::new(Rewriting {
                inner: FixtureTransport::new(shared),
                rewrite,
            })))
        })
    });
    start_with(connect, poll, Arc::new(Mutex::new(Vec::new())))
}

struct Running {
    req_tx: mpsc::Sender<BusRequest>,
    ev_rx: mpsc::Receiver<BusEvent>,
    task: JoinHandle<()>,
    lines: Lines,
}

fn start_with(connect: Connector, poll: Duration, lines: Lines) -> Running {
    let (req_tx, req_rx) = mpsc::channel(32);
    let (ev_tx, ev_rx) = mpsc::channel(256);
    let task = tokio::spawn(bus::run(connect, req_rx, ev_tx, poll));
    Running {
        req_tx,
        ev_rx,
        task,
        lines,
    }
}

fn start(shared: Shared, poll: Duration) -> Running {
    let lines: Lines = Arc::new(Mutex::new(Vec::new()));
    let recorded = lines.clone();
    let connect: Connector = Arc::new(move || {
        let shared = shared.clone();
        let lines = recorded.clone();
        Box::pin(async move {
            Ok(BusClient::new(Box::new(Recording {
                inner: FixtureTransport::new(shared),
                lines,
            })))
        })
    });
    start_with(connect, poll, lines)
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

fn sent(lines: &Lines) -> Vec<Value> {
    lines
        .lock()
        .unwrap()
        .iter()
        .map(|l| serde_json::from_str(l).expect("every sent line is JSON"))
        .collect()
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

#[tokio::test]
async fn connect_sequence_identifies_as_aitm_tui_and_builds_features_from_tools_list() {
    assert_eq!(CLIENT_NAME, "aitm-tui");
    let mut r = start(Fixture::builtin().shared(), Duration::from_millis(50));

    let first = timeout(WAIT, r.ev_rx.recv()).await.unwrap().unwrap();
    let BusEvent::Connected {
        server,
        tools,
        listening,
    } = first
    else {
        panic!("the first event must be Connected, got {first:?}");
    };
    assert_eq!(server, "aitmproxy 0.3.0-fixture");
    assert_eq!(listening.as_deref(), Some("127.0.0.1:8080"));
    let names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
    for n in [
        "flow.list",
        "flow.get",
        "flow.intercept",
        "flow.resume",
        "flow.kill",
        "flow.mutate",
        "flow.replay",
        "request.send",
        "scope.add",
        "scope.list",
        "flow.detail",
        "agent.status",
    ] {
        assert!(names.contains(&n), "{n} missing from {names:?}");
    }
    let get = tools.iter().find(|t| t.name == "flow.get").unwrap();
    assert_eq!(
        get.description,
        "Summarize one captured flow: kind, request line, status, state."
    );
    assert!(
        get.params()
            .iter()
            .any(|(n, ty, required, _)| n == "id" && ty == "string" && *required),
        "forms are built from the schema"
    );

    // The wire, in order: initialize (named), initialized notice, tools/list, proxy.status.
    let wire = sent(&r.lines);
    assert_eq!(wire[0]["jsonrpc"], "2.0");
    assert_eq!(wire[0]["method"], "initialize");
    assert_eq!(wire[0]["params"]["clientInfo"]["name"], "aitm-tui");
    assert_eq!(
        wire[0]["params"]["clientInfo"]["version"],
        env!("CARGO_PKG_VERSION")
    );
    assert_eq!(
        wire[0]["params"]["protocolVersion"],
        aitm_bus_client::PROTOCOL_VERSION
    );
    assert_eq!(wire[1]["method"], "notifications/initialized");
    assert!(wire[1].get("id").is_none(), "a notification carries no id");
    assert_eq!(wire[2]["method"], "tools/list");
    assert_eq!(wire[3]["method"], "tools/call");
    assert_eq!(wire[3]["params"]["name"], "proxy.status");
    assert_eq!(wire[0]["id"], 1);
    assert_eq!(wire[2]["id"], 2);
    assert_eq!(wire[3]["id"], 3);

    // The first poll: flow.list, then flow.get per id, as one Flows event.
    let flows = next_where(&mut r.ev_rx, |e| matches!(e, BusEvent::Flows(_))).await;
    let BusEvent::Flows(s) = flows else {
        unreachable!()
    };
    assert_eq!(s.len(), 14);
    assert_eq!(s[0]["id"], "f41");
    assert_eq!(s[13]["id"], "f54");
    assert_eq!(s[9]["intercept"], "intercepted");
    let wire = sent(&r.lines);
    assert_eq!(wire[4]["params"]["name"], "flow.list");
    assert_eq!(wire[5]["params"]["name"], "flow.get");
    assert_eq!(wire[5]["params"]["arguments"], json!({"id": "f41"}));
    assert_eq!(
        wire.iter().filter(|w| w["method"] == "tools/list").count(),
        1,
        "tools/list once"
    );
    assert_eq!(
        wire.iter().filter(|w| w["method"] == "initialize").count(),
        1
    );

    // The slow panels ride along on the first poll.
    let scope = next_where(&mut r.ev_rx, |e| matches!(e, BusEvent::Scope(_))).await;
    assert_eq!(
        scope,
        BusEvent::Scope(vec![
            "api.shop-staging.test".into(),
            "auth.shop-staging.test".into(),
            "cdn.shop-staging.test".into()
        ])
    );
    let agent = next_where(&mut r.ev_rx, |e| matches!(e, BusEvent::Agent(_))).await;
    let BusEvent::Agent(a) = agent else {
        unreachable!()
    };
    assert_eq!(a.policy, Some(aitm_tui::model::AgentPolicy::All));
    assert_eq!(a.log.len(), 7);
    let findings = next_where(&mut r.ev_rx, |e| matches!(e, BusEvent::Findings(_))).await;
    let BusEvent::Findings(f) = findings else {
        unreachable!()
    };
    assert_eq!(f.len(), 2);

    // Settled flows are not re-fetched on the next poll; the paused ones are.
    let before = sent(&r.lines).len();
    let _ = next_where(&mut r.ev_rx, |e| matches!(e, BusEvent::Flows(_))).await;
    let _ = next_where(&mut r.ev_rx, |e| matches!(e, BusEvent::Flows(_))).await;
    let wire = sent(&r.lines);
    let gets: Vec<&Value> = wire[before..]
        .iter()
        .filter(|w| w["params"]["name"] == "flow.get")
        .collect();
    let ids: std::collections::HashSet<&str> = gets
        .iter()
        .filter_map(|w| w["params"]["arguments"]["id"].as_str())
        .collect();
    assert!(
        ids.contains("f50") && ids.contains("f51"),
        "paused flows are polled: {ids:?}"
    );
    assert!(
        ids.contains("f47"),
        "WebSocket flows are polled for new frames: {ids:?}"
    );
    assert!(ids.contains("f52"), "pending flows are polled: {ids:?}");
    assert!(
        !ids.contains("f41"),
        "a settled flow is not re-fetched: {ids:?}"
    );

    finish(r).await;
}

#[tokio::test]
async fn requests_become_tool_calls_and_results_become_events() {
    let mut r = start(Fixture::builtin().shared(), Duration::from_millis(50));
    let _ = next_where(&mut r.ev_rx, |e| matches!(e, BusEvent::Connected { .. })).await;

    // A tool the bus does not offer is refused locally with a warning toast.
    r.req_tx
        .send(BusRequest::Call {
            name: "nope".into(),
            args: json!({}),
        })
        .await
        .unwrap();
    let ev = next_where(&mut r.ev_rx, |e| matches!(e, BusEvent::Toast(..))).await;
    assert_eq!(
        ev,
        BusEvent::Toast(Level::Warn, "nope is not on this bus".into())
    );
    assert!(
        !sent(&r.lines).iter().any(|w| w["params"]["name"] == "nope"),
        "never sent to the bus"
    );

    // flow.intercept: the structured result comes back as CallOk.
    r.req_tx.send(BusRequest::Intercept(false)).await.unwrap();
    let ev = next_where(&mut r.ev_rx, |e| matches!(e, BusEvent::CallOk { .. })).await;
    assert_eq!(
        ev,
        BusEvent::CallOk {
            name: "flow.intercept".into(),
            value: json!(false)
        }
    );
    let line = sent(&r.lines)
        .into_iter()
        .find(|w| w["params"]["name"] == "flow.intercept")
        .unwrap();
    assert_eq!(line["params"]["arguments"], json!({"enabled": false}));

    // flow.detail asks for the inline body (the F5 shape) and yields Detail.
    r.req_tx
        .send(BusRequest::Detail("f41".into()))
        .await
        .unwrap();
    let ev = next_where(&mut r.ev_rx, |e| matches!(e, BusEvent::Detail(_))).await;
    let BusEvent::Detail(d) = ev else {
        unreachable!()
    };
    assert_eq!(d.id, "f41");
    assert!(d
        .response
        .as_ref()
        .unwrap()
        .body_text()
        .unwrap()
        .contains("\"items\""));
    let line = sent(&r.lines)
        .into_iter()
        .find(|w| w["params"]["name"] == "flow.detail")
        .unwrap();
    assert_eq!(
        line["params"]["arguments"],
        json!({"id": "f41", "body": "inline"})
    );

    // A tool error (isError) is an error toast with the tool's message.
    r.req_tx
        .send(BusRequest::Resume("f41".into()))
        .await
        .unwrap();
    let ev = next_where(&mut r.ev_rx, |e| {
        matches!(e, BusEvent::Toast(Level::Error, _))
    })
    .await;
    assert_eq!(
        ev,
        BusEvent::Toast(Level::Error, "flow is not intercepted".into())
    );
    // (Task 10 gave the fixture a browser; `ca.*` mutations are what it
    // still refuses, so that is the arbitrary-tool error path now.)
    r.req_tx
        .send(BusRequest::Call {
            name: "ca.install".into(),
            args: json!({}),
        })
        .await
        .unwrap();
    let ev = next_where(&mut r.ev_rx, |e| {
        matches!(e, BusEvent::Toast(Level::Error, _))
    })
    .await;
    assert_eq!(
        ev,
        BusEvent::Toast(
            Level::Error,
            "CA changes are not simulated by the fixture".into()
        )
    );

    // Arguments the schema does not declare are pruned; the result is a new flow.
    r.req_tx
        .send(BusRequest::Send(json!({
            "authority": "api.shop-staging.test", "path": "/x", "method": "POST", "bogus": 1
        })))
        .await
        .unwrap();
    let ev = next_where(
        &mut r.ev_rx,
        |e| matches!(e, BusEvent::CallOk { name, .. } if name == "request.send"),
    )
    .await;
    assert_eq!(
        ev,
        BusEvent::CallOk {
            name: "request.send".into(),
            value: json!("f55")
        }
    );
    let line = sent(&r.lines)
        .into_iter()
        .find(|w| w["params"]["name"] == "request.send")
        .unwrap();
    assert!(line["params"]["arguments"].get("bogus").is_none(), "{line}");
    assert_eq!(
        line["params"]["arguments"]["authority"],
        "api.shop-staging.test"
    );
    // After a mutation the next poll re-reads everything: 15 flows now.
    let _ = next_where(
        &mut r.ev_rx,
        |e| matches!(e, BusEvent::Flows(s) if s.len() == 15),
    )
    .await;

    // Scope add, agent set, poc build and mark/comment map to their tools.
    r.req_tx
        .send(BusRequest::ScopeAdd("*.x.test".into()))
        .await
        .unwrap();
    let ev = next_where(
        &mut r.ev_rx,
        |e| matches!(e, BusEvent::CallOk { name, .. } if name == "scope.add"),
    )
    .await;
    assert_eq!(
        ev,
        BusEvent::CallOk {
            name: "scope.add".into(),
            value: json!("*.x.test")
        }
    );
    r.req_tx
        .send(BusRequest::AgentSet(aitm_tui::model::AgentPolicy::Paused))
        .await
        .unwrap();
    let ev = next_where(
        &mut r.ev_rx,
        |e| matches!(e, BusEvent::CallOk { name, .. } if name == "agent.set"),
    )
    .await;
    assert_eq!(
        ev,
        BusEvent::CallOk {
            name: "agent.set".into(),
            value: json!("paused")
        }
    );
    r.req_tx
        .send(BusRequest::PocBuild {
            flow_id: "f48".into(),
            name: Some("Reflected XSS".into()),
            param: Some("q".into()),
        })
        .await
        .unwrap();
    let ev = next_where(
        &mut r.ev_rx,
        |e| matches!(e, BusEvent::CallOk { name, .. } if name == "poc.build"),
    )
    .await;
    assert_eq!(
        ev,
        BusEvent::CallOk {
            name: "poc.build".into(),
            value: json!("pocs/reflected-xss.yaml")
        }
    );
    let line = sent(&r.lines)
        .into_iter()
        .find(|w| w["params"]["name"] == "poc.build")
        .unwrap();
    assert_eq!(
        line["params"]["arguments"],
        json!({"flow_id": "f48", "name": "Reflected XSS", "param": "q"})
    );
    r.req_tx
        .send(BusRequest::Mark {
            id: "f41".into(),
            marks: vec!["red".into()],
        })
        .await
        .unwrap();
    let _ = next_where(
        &mut r.ev_rx,
        |e| matches!(e, BusEvent::CallOk { name, .. } if name == "flow.mark"),
    )
    .await;
    // Refresh is a poll on demand.
    let before = sent(&r.lines).len();
    r.req_tx.send(BusRequest::Refresh).await.unwrap();
    let _ = next_where(&mut r.ev_rx, |e| matches!(e, BusEvent::Flows(_))).await;
    assert!(sent(&r.lines)[before..]
        .iter()
        .any(|w| w["params"]["name"] == "flow.list"));

    finish(r).await;
}

#[tokio::test]
async fn a_failed_connect_reports_disconnected_then_retries_with_backoff() {
    let attempts = Arc::new(AtomicUsize::new(0));
    let shared = Fixture::builtin().shared();
    let counter = attempts.clone();
    let connect: Connector = Arc::new(move || {
        let n = counter.fetch_add(1, Ordering::SeqCst);
        let shared = shared.clone();
        Box::pin(async move {
            if n == 0 {
                anyhow::bail!("bus refused the token");
            }
            Ok(BusClient::new(Box::new(FixtureTransport::new(shared))))
        })
    });
    let started = std::time::Instant::now();
    let mut r = start_with(
        connect,
        Duration::from_millis(50),
        Arc::new(Mutex::new(Vec::new())),
    );
    let first = timeout(WAIT, r.ev_rx.recv()).await.unwrap().unwrap();
    assert!(
        matches!(&first, BusEvent::Disconnected(why) if why.contains("bus refused the token")),
        "{first:?}"
    );
    let _ = next_where(&mut r.ev_rx, |e| matches!(e, BusEvent::Connected { .. })).await;
    assert!(
        started.elapsed() >= Duration::from_millis(400),
        "back-off before the retry: {:?}",
        started.elapsed()
    );
    assert_eq!(attempts.load(Ordering::SeqCst), 2);
    finish(r).await;
}

/// A bus whose transport dies after `budget` lines, every line recorded.
fn start_flaky(budget: usize, poll: Duration) -> Running {
    let shared = Fixture::builtin().shared();
    let lines: Lines = Arc::new(Mutex::new(Vec::new()));
    let recorded = lines.clone();
    let connect: Connector = Arc::new(move || {
        let shared = shared.clone();
        let lines = recorded.clone();
        Box::pin(async move {
            Ok(BusClient::new(Box::new(Flaky {
                inner: FixtureTransport::new(shared),
                budget: AtomicUsize::new(budget),
                lines,
            })))
        })
    });
    start_with(connect, poll, lines)
}

#[tokio::test]
async fn a_transport_failure_mid_session_reconnects_and_resumes_polling() {
    // initialize, initialized, tools/list, proxy.status, flow.list,
    // flow.get f41 — then the socket "resets".
    let mut r = start_flaky(6, Duration::from_millis(20));
    let _ = next_where(&mut r.ev_rx, |e| matches!(e, BusEvent::Connected { .. })).await;
    let lost = next_where(&mut r.ev_rx, |e| matches!(e, BusEvent::Disconnected(_))).await;
    assert!(
        matches!(&lost, BusEvent::Disconnected(why) if why.contains("connection reset by peer")),
        "{lost:?}"
    );
    // A fresh connection: initialize again, tools/list again.
    let _ = next_where(&mut r.ev_rx, |e| matches!(e, BusEvent::Connected { .. })).await;
    finish(r).await;
}

/// Q9: a transport failure while reading a slow panel (scope.list here) ends
/// the session at once — the next line on the wire is a fresh `initialize`,
/// not the remaining panels on a dead socket.
#[tokio::test]
async fn a_transport_failure_in_a_slow_panel_reconnects_at_once() {
    // initialize, initialized, tools/list, proxy.status, flow.list, 14 × flow.get
    // = 19 lines succeed; the 20th, scope.list, "resets".
    let mut r = start_flaky(19, Duration::from_millis(20));
    let _ = next_where(&mut r.ev_rx, |e| matches!(e, BusEvent::Connected { .. })).await;
    let flows = next_where(&mut r.ev_rx, |e| matches!(e, BusEvent::Flows(_))).await;
    assert!(
        matches!(&flows, BusEvent::Flows(s) if s.len() == 14),
        "{flows:?}"
    );
    let lost = next_where(&mut r.ev_rx, |e| matches!(e, BusEvent::Disconnected(_))).await;
    assert!(
        matches!(&lost, BusEvent::Disconnected(why) if why.contains("connection reset by peer")),
        "{lost:?}"
    );
    let _ = next_where(&mut r.ev_rx, |e| matches!(e, BusEvent::Connected { .. })).await;
    let wire = sent(&r.lines);
    let scope_at = wire
        .iter()
        .position(|w| tool_name(w) == "scope.list")
        .expect("scope.list was attempted");
    assert_eq!(
        wire[scope_at + 1]["method"],
        "initialize",
        "after the failed scope.list the session reconnects instead of trying \
         agent.status / poc.list on the dead transport: {:?}",
        &wire[scope_at..]
    );
    finish(r).await;
}

/// Q9: the bus answering the handshake with `-32001` means our token is wrong.
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
    let mut r = start_with(
        connect,
        Duration::from_millis(20),
        Arc::new(Mutex::new(Vec::new())),
    );
    let first = timeout(WAIT, r.ev_rx.recv()).await.unwrap().unwrap();
    assert_eq!(
        first,
        BusEvent::Disconnected("bus refused the token — check --token-file".into())
    );
    // The task ends on its own: no second connect, no back-off loop. Both
    // channels are still open here, so this is the task's decision.
    timeout(WAIT, r.task)
        .await
        .expect("the task stops after a token refusal")
        .expect("the task does not panic");
    assert_eq!(attempts.load(Ordering::SeqCst), 1, "no retry");
    drop(r.req_tx);
}

/// Q1: a `flow.detail` reply the model rejects is reported, and the app is
/// told not to ask again for that id.
#[tokio::test]
async fn a_malformed_flow_detail_reply_is_a_warn_toast_and_a_detail_failed_event() {
    let rewrite: Rewrite = Arc::new(|req, reply| {
        if tool_name(req) == "flow.detail" {
            Some(
                json!({"jsonrpc":"2.0","id":req["id"],"result":{
                    "content":[{"type":"text","text":"{}"}],
                    "structuredContent":{"garbage":true},"isError":false}})
                .to_string(),
            )
        } else {
            reply
        }
    });
    let mut r = start_rewriting(Duration::from_millis(50), rewrite);
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
    finish(r).await;
}

/// Q1: a per-flow `flow.get` error must not drop the row (the app would evict
/// it and lose the selection); the cached summary stays and the operator
/// sees one warning per poll, however many flows failed.
#[tokio::test]
async fn a_per_flow_get_error_keeps_the_cached_row_and_warns_once_per_poll() {
    let lists = Arc::new(AtomicUsize::new(0));
    let rewrite: Rewrite = Arc::new(move |req, reply| {
        match tool_name(req) {
            "flow.list" => {
                lists.fetch_add(1, Ordering::SeqCst);
                reply
            }
            // From the second poll on, the two paused flows (re-fetched every
            // poll) fail at the store.
            "flow.get"
                if lists.load(Ordering::SeqCst) >= 2
                    && matches!(
                        req["params"]["arguments"]["id"].as_str(),
                        Some("f50") | Some("f51")
                    ) =>
            {
                Some(tool_error_reply(req, "store hiccup"))
            }
            _ => reply,
        }
    });
    let mut r = start_rewriting(Duration::from_millis(50), rewrite);
    let _ = next_where(&mut r.ev_rx, |e| matches!(e, BusEvent::Flows(_))).await;

    let second = next_where(&mut r.ev_rx, |e| matches!(e, BusEvent::Flows(_))).await;
    let BusEvent::Flows(rows) = second else {
        unreachable!()
    };
    assert_eq!(rows.len(), 14, "no row is dropped: {rows:?}");
    let f50 = rows
        .iter()
        .find(|s| s["id"] == "f50")
        .expect("f50 is still a row");
    assert_eq!(
        f50["intercept"], "intercepted",
        "the cached summary is kept"
    );

    // Between this Flows and the next: exactly one warning, naming the first
    // failure, although two flows failed.
    let mut toasts = Vec::new();
    loop {
        let ev = timeout(WAIT, r.ev_rx.recv()).await.unwrap().unwrap();
        match ev {
            BusEvent::Flows(_) => break,
            BusEvent::Toast(level, text) => toasts.push((level, text)),
            _ => {}
        }
    }
    assert_eq!(
        toasts,
        vec![(Level::Warn, "flow.get f50: store hiccup".to_string())]
    );
    finish(r).await;
}

/// Q6: a mutation invalidates the row it touched, not every settled row — the
/// next poll re-reads that one id (plus the flows that are always polled).
#[tokio::test]
async fn a_mutation_re_reads_only_the_touched_flow() {
    let mut r = start(Fixture::builtin().shared(), Duration::from_millis(50));
    let _ = next_where(&mut r.ev_rx, |e| matches!(e, BusEvent::Flows(_))).await;
    r.req_tx
        .send(BusRequest::Mark {
            id: "f41".into(),
            marks: vec!["red".into()],
        })
        .await
        .unwrap();
    let _ = next_where(
        &mut r.ev_rx,
        |e| matches!(e, BusEvent::CallOk { name, .. } if name == "flow.mark"),
    )
    .await;
    let _ = next_where(&mut r.ev_rx, |e| matches!(e, BusEvent::Flows(_))).await;
    let wire = sent(&r.lines);
    let mark_at = wire
        .iter()
        .position(|w| tool_name(w) == "flow.mark")
        .expect("flow.mark was sent");
    let gets: Vec<&str> = wire[mark_at..]
        .iter()
        .filter(|w| tool_name(w) == "flow.get")
        .filter_map(|w| w["params"]["arguments"]["id"].as_str())
        .collect();
    assert!(
        gets.contains(&"f41"),
        "the marked flow is re-read: {gets:?}"
    );
    assert!(
        !gets.contains(&"f42"),
        "an untouched settled flow is not re-read: {gets:?}"
    );
    finish(r).await;
}

#[tokio::test]
async fn a_request_during_an_outage_is_not_lost_silently() {
    // No connection ever succeeds: the app sees Disconnected, never a silent drop.
    let connect: Connector = Arc::new(|| Box::pin(async { anyhow::bail!("nobody listening") }));
    let mut r = start_with(
        connect,
        Duration::from_millis(20),
        Arc::new(Mutex::new(Vec::new())),
    );
    let first = timeout(WAIT, r.ev_rx.recv()).await.unwrap().unwrap();
    assert!(matches!(first, BusEvent::Disconnected(_)));
    r.req_tx.send(BusRequest::Intercept(true)).await.unwrap();
    let second = timeout(WAIT, r.ev_rx.recv()).await.unwrap().unwrap();
    assert!(matches!(second, BusEvent::Disconnected(_)), "{second:?}");
    finish(r).await;
}
