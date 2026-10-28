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
use aitm_tui::action::{BusEvent, BusRequest, Level};
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
struct Flaky {
    inner: FixtureTransport,
    budget: AtomicUsize,
}

impl BusTransport for Flaky {
    fn send(&self, line: String) -> BoxFuture<'_, anyhow::Result<Option<String>>> {
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
    r.req_tx
        .send(BusRequest::Call {
            name: "browser.navigate".into(),
            args: json!({"url": "https://x"}),
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
            "fixture has no browser engine; run against a live proxy".into()
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

#[tokio::test]
async fn a_transport_failure_mid_session_reconnects_and_resumes_polling() {
    let shared = Fixture::builtin().shared();
    let connect: Connector = Arc::new(move || {
        let shared = shared.clone();
        Box::pin(async move {
            Ok(BusClient::new(Box::new(Flaky {
                inner: FixtureTransport::new(shared),
                // initialize, initialized, tools/list, proxy.status, flow.list,
                // flow.get f41 — then the socket "resets".
                budget: AtomicUsize::new(6),
            })))
        })
    });
    let mut r = start_with(
        connect,
        Duration::from_millis(20),
        Arc::new(Mutex::new(Vec::new())),
    );
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
