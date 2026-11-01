//! Tester (stage 5): the bus task against the recorded fixture, through a
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
use aitm_tui::model::ProxyStatus;
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
    let BusEvent::Connected { server, tools, .. } = first else {
        panic!("the first event must be Connected, got {first:?}");
    };
    assert_eq!(server, "aitmproxy 0.3.0-fixture");
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
        "proxy.resume",
        "poc.get",
        "poc.artifact",
        "config.get",
        "findings.list",
    ] {
        assert!(names.contains(&n), "{n} missing from {names:?}");
    }
    // C3: the handshake reads `proxy.status` and reports it as its own event,
    // in the control plugin's shape.
    let second = timeout(WAIT, r.ev_rx.recv()).await.unwrap().unwrap();
    assert_eq!(
        second,
        BusEvent::ProxyStatus(ProxyStatus {
            listening: true,
            address: Some("127.0.0.1:8080".into()),
            intercept_armed: true,
            capturing: true,
            paused: 2,
            flows: 15,
        })
    );
    let get = tools.iter().find(|t| t.name == "flow.get").unwrap();
    assert_eq!(
        get.description,
        "Summarize one captured flow: kind, request line, status, state."
    );
    assert!(
        get.params()
            .iter()
            .any(|p| p.name == "id" && p.ty == "string" && p.required),
        "forms are built from the schema"
    );

    // The wire, in order: initialize (named), initialized notice, tools/list,
    // proxy.status, flow.subscribe (D5: the one push subscription).
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
    assert_eq!(s.len(), 15);
    assert_eq!(s[0]["id"], "f40");
    assert_eq!(s[14]["id"], "f54");
    assert_eq!(s[10]["intercept"], "intercepted");
    let wire = sent(&r.lines);
    assert_eq!(wire[4]["params"]["name"], "flow.subscribe");
    assert_eq!(wire[5]["params"]["name"], "flow.list");
    assert_eq!(wire[6]["params"]["name"], "flow.get");
    assert_eq!(wire[6]["params"]["arguments"], json!({"id": "f40"}));
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
    // C8: `poc.list` is the PoC library (files, not runs), so none has run.
    let findings = next_where(&mut r.ev_rx, |e| matches!(e, BusEvent::Findings(_))).await;
    let BusEvent::Findings(f) = findings else {
        unreachable!()
    };
    assert_eq!(f.len(), 3);
    assert!(f.iter().all(|x| !x.ran), "{f:?}");
    assert_eq!(f[0].poc_path, "pocs/idor-cart-items.yaml");
    assert_eq!(f[0].title, "IDOR on /api/cart/items/{id}");
    assert_eq!(f[2].poc_path, "pocs/reflected-xss-search.yaml");
    // The Rhai findings sink and the proxy state ride on the slow pass too.
    let scripted = next_where(&mut r.ev_rx, |e| matches!(e, BusEvent::ScriptFindings(_))).await;
    assert_eq!(scripted, BusEvent::ScriptFindings(vec![]));
    let status = next_where(&mut r.ev_rx, |e| matches!(e, BusEvent::ProxyStatus(_))).await;
    assert!(
        matches!(&status, BusEvent::ProxyStatus(s) if s.flows == 15 && s.paused == 2),
        "{status:?}"
    );

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

    // A tool the bus does not offer is refused locally as a failed call
    // naming it (QI-1: the app routes it by tool, not by toast text).
    r.req_tx
        .send(BusRequest::Call {
            name: "nope".into(),
            args: json!({}),
        })
        .await
        .unwrap();
    let ev = next_where(&mut r.ev_rx, |e| matches!(e, BusEvent::CallFailed { .. })).await;
    assert_eq!(
        ev,
        BusEvent::CallFailed {
            name: "nope".into(),
            message: "nope is not on this bus".into()
        }
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

    // A tool error (isError) is a failed call carrying the tool's message.
    r.req_tx
        .send(BusRequest::Resume("f41".into()))
        .await
        .unwrap();
    let ev = next_where(&mut r.ev_rx, |e| matches!(e, BusEvent::CallFailed { .. })).await;
    assert_eq!(
        ev,
        BusEvent::CallFailed {
            name: "flow.resume".into(),
            message: "flow is not intercepted".into()
        }
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
    let ev = next_where(&mut r.ev_rx, |e| matches!(e, BusEvent::CallFailed { .. })).await;
    assert_eq!(
        ev,
        BusEvent::CallFailed {
            name: "ca.install".into(),
            message: "CA changes are not simulated by the fixture".into()
        }
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
    // After a mutation the next poll re-reads everything: 16 flows now.
    let _ = next_where(
        &mut r.ev_rx,
        |e| matches!(e, BusEvent::Flows(s) if s.len() == 16),
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

/// C4: `proxy.pause` and `proxy.resume` are two parameterless tools whose
/// result is the capture state; the one `ProxyPause(bool)` request picks
/// the tool.
#[tokio::test]
async fn pause_and_resume_are_two_parameterless_tools_answering_the_capture_state() {
    let mut r = start(Fixture::builtin().shared(), Duration::from_millis(50));
    let _ = next_where(&mut r.ev_rx, |e| matches!(e, BusEvent::Connected { .. })).await;
    r.req_tx.send(BusRequest::ProxyPause(true)).await.unwrap();
    let ev = next_where(
        &mut r.ev_rx,
        |e| matches!(e, BusEvent::CallOk { name, .. } if name == "proxy.pause"),
    )
    .await;
    assert_eq!(
        ev,
        BusEvent::CallOk {
            name: "proxy.pause".into(),
            value: json!({"capturing": false})
        }
    );
    r.req_tx.send(BusRequest::ProxyPause(false)).await.unwrap();
    let ev = next_where(
        &mut r.ev_rx,
        |e| matches!(e, BusEvent::CallOk { name, .. } if name == "proxy.resume"),
    )
    .await;
    assert_eq!(
        ev,
        BusEvent::CallOk {
            name: "proxy.resume".into(),
            value: json!({"capturing": true})
        }
    );
    let wire = sent(&r.lines);
    let pause = wire
        .iter()
        .find(|w| tool_name(w) == "proxy.pause")
        .expect("proxy.pause sent");
    assert_eq!(pause["params"]["arguments"], json!({}));
    let resume = wire
        .iter()
        .find(|w| tool_name(w) == "proxy.resume")
        .expect("proxy.resume sent");
    assert_eq!(resume["params"]["arguments"], json!({}));
    finish(r).await;
}

/// C9: `PocGet(path)` is `poc.get {poc_path}`; the result carries the YAML
/// and description the panel shows.
#[tokio::test]
async fn poc_get_asks_by_path_and_answers_with_the_yaml() {
    let mut r = start(Fixture::builtin().shared(), Duration::from_millis(50));
    let _ = next_where(&mut r.ev_rx, |e| matches!(e, BusEvent::Connected { .. })).await;
    r.req_tx
        .send(BusRequest::PocGet("pocs/idor-cart-items.yaml".into()))
        .await
        .unwrap();
    let ev = next_where(
        &mut r.ev_rx,
        |e| matches!(e, BusEvent::CallOk { name, .. } if name == "poc.get"),
    )
    .await;
    let BusEvent::CallOk { value, .. } = ev else {
        unreachable!()
    };
    assert_eq!(value["poc_path"], "pocs/idor-cart-items.yaml");
    assert_eq!(value["id"], "idor-cart-items");
    assert_eq!(value["severity"], "medium");
    assert!(value["yaml"]
        .as_str()
        .unwrap()
        .starts_with("name: IDOR on /api/cart/items/{id}"));
    assert!(value["description"].is_string());
    let line = sent(&r.lines)
        .into_iter()
        .find(|w| tool_name(w) == "poc.get")
        .unwrap();
    assert_eq!(
        line["params"]["arguments"],
        json!({"poc_path": "pocs/idor-cart-items.yaml"})
    );
    // An unknown path is the tool's error, not a transport failure.
    r.req_tx
        .send(BusRequest::PocGet("pocs/nope.yaml".into()))
        .await
        .unwrap();
    let ev = next_where(
        &mut r.ev_rx,
        |e| matches!(e, BusEvent::CallFailed { name, .. } if name == "poc.get"),
    )
    .await;
    assert!(
        matches!(&ev, BusEvent::CallFailed { message, .. } if message.starts_with("poc.get: ")),
        "{ev:?}"
    );
    finish(r).await;
}

/// `findings.list` (the Rhai findings sink, M3) is read on the slow pass
/// when the bus has it; each entry becomes a script finding.
#[tokio::test]
async fn findings_list_entries_arrive_as_script_findings() {
    let fx = Fixture::parse(
        r#"{"tools":[{"name":"flow.list"},{"name":"findings.list"}],
            "script_findings":[{"name":"admin write","severity":"high","flow_id":"f1",
                                "detail":"unauthenticated","tags":["auth"],"source":"observer",
                                "at":39904067}]}"#,
    )
    .unwrap();
    let mut r = start(fx.shared(), Duration::from_millis(50));
    let ev = next_where(&mut r.ev_rx, |e| matches!(e, BusEvent::ScriptFindings(_))).await;
    let BusEvent::ScriptFindings(list) = ev else {
        unreachable!()
    };
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].title, "admin write");
    assert_eq!(list[0].severity, aitm_tui::model::Severity::High);
    assert_eq!(list[0].script.as_deref(), Some("observer"));
    assert_eq!(list[0].finding_capture.as_deref(), Some("f1"));
    assert_eq!(list[0].description.as_deref(), Some("unauthenticated"));
    assert_eq!(list[0].when, "11:05:04.067");
    assert!(list[0].ran);
    assert_eq!(list[0].poc_path, "");
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
    // initialize, initialized, tools/list, proxy.status, flow.subscribe,
    // flow.list, flow.get f40 (7 lines succeed), then the socket "resets".
    let mut r = start_flaky(7, Duration::from_millis(20));
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
/// the session at once: the next line on the wire is a fresh `initialize`,
/// not the remaining panels on a dead socket.
#[tokio::test]
async fn a_transport_failure_in_a_slow_panel_reconnects_at_once() {
    // initialize, initialized, tools/list, proxy.status, flow.subscribe,
    // flow.list, 15 × flow.get = 21 lines succeed; the 22nd, scope.list, "resets".
    let mut r = start_flaky(21, Duration::from_millis(20));
    let _ = next_where(&mut r.ev_rx, |e| matches!(e, BusEvent::Connected { .. })).await;
    let flows = next_where(&mut r.ev_rx, |e| matches!(e, BusEvent::Flows(_))).await;
    assert!(
        matches!(&flows, BusEvent::Flows(s) if s.len() == 15),
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
    assert_eq!(first, BusEvent::Disconnected(bus::REFUSED.into()));
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
    assert_eq!(rows.len(), 15, "no row is dropped: {rows:?}");
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

/// Q6: a mutation invalidates the row it touched, not every settled row: the
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

/// Scanner v2 T7, spec D5: after the handshake, when the bus offers
/// `flow.subscribe`, the task subscribes exactly once so job and flow lines
/// reach it as pushes. It follows `proxy.status` and precedes the first poll.
#[tokio::test]
async fn the_handshake_subscribes_once_when_the_bus_offers_flow_subscribe() {
    let mut r = start(Fixture::builtin().shared(), Duration::from_millis(50));
    let _ = next_where(&mut r.ev_rx, |e| matches!(e, BusEvent::Flows(_))).await;
    let wire = sent(&r.lines);
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

/// Scanner v2 T7, Constraints finding and T7-15: `prune()` keeps the reserved
/// `_confirm` key although no tool schema declares it (the server strips it
/// itself); every other undeclared key is still dropped.
#[tokio::test]
async fn prune_keeps_the_reserved_confirm_key() {
    let mut r = start(Fixture::builtin().shared(), Duration::from_millis(50));
    let _ = next_where(&mut r.ev_rx, |e| matches!(e, BusEvent::Connected { .. })).await;
    let before = sent(&r.lines).len();
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
    let wire = sent(&r.lines);
    let gets: Vec<&Value> = wire[before..]
        .iter()
        .filter(|w| tool_name(w) == "flow.get")
        .map(|w| &w["params"]["arguments"])
        .collect();
    let confirmed: Vec<&&Value> = gets
        .iter()
        .filter(|a| a.get("_confirm").is_some())
        .collect();
    assert_eq!(
        confirmed.len(),
        1,
        "exactly one flow.get carries _confirm (the poll's never do): {gets:?}"
    );
    assert_eq!(*confirmed[0], &json!({"id": "f40", "_confirm": "tok-1"}));
    finish(r).await;
}

/// Scanner v2 T7, spec D4 and T7-15: a `CallTagged` is run exactly like a
/// `Call` and its reply echoes the tag, whether the call succeeded, the tool
/// reported an error, or the bus does not offer the tool at all. The task
/// stays verb-agnostic: the tag is opaque to it.
#[tokio::test]
async fn a_tagged_call_answers_with_the_same_tag() {
    let mut r = start(Fixture::builtin().shared(), Duration::from_millis(50));
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
        !sent(&r.lines).iter().any(|w| tool_name(w) == "scan.list"),
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

/// Scanner v2 T7, spec D5: a tool error from `flow.subscribe` is one Warn
/// toast with the fixed wording and the session carries on into its first
/// poll; it is never a `Disconnected`.
#[tokio::test]
async fn a_failed_subscribe_is_a_warn_toast_not_a_session_loss() {
    let rewrite: Rewrite = Arc::new(|req, reply| {
        if tool_name(req) == "flow.subscribe" {
            Some(tool_error_reply(req, "nope"))
        } else {
            reply
        }
    });
    let mut r = start_rewriting(Duration::from_millis(50), rewrite);
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
    assert_eq!(flows.len(), 15, "the first poll follows the warning");
    finish(r).await;
}
