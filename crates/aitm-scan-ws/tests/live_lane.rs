//! Live proof of the WebSocket lane against the **real** seeded target (T4
//! plan task 18, amended by call 35).
//!
//! Nothing here is a fixture. The target is T10's `aitm-testtarget-serve`
//! binary, spawned as a process from `$AITM_TESTTARGET_BIN` with its own
//! control origin; the capture is a real `tokio_tungstenite` client driven
//! through a real `aitm_core::Proxy` carrying the real `HttpModule` and
//! `WsModule`; the lane dials with the production [`TcpTransport`]; and every
//! assertion about what reached the target is read back **from the target's
//! own observer**, not from the scanner (`GET /log/ws`, `GET /log/conns`,
//! `POST /reset`). The observer rows are printed, so the Terminal log is the
//! evidence the plan's Shipped section quotes.
//!
//! Each test needs a loopback port, so each is `#[ignore]`d and run in the
//! Terminal:
//!
//! ```text
//! cargo test -p aitm-scan-ws --test live_lane --test live_language -- --ignored --nocapture
//! ```
//!
//! Without `AITM_TESTTARGET_BIN` the tests **panic** rather than return early:
//! a missing target must read as a failure to be fixed, never as a green run
//! (plan task 18, "never a silent green").
//!
//! What is proved, per mode (`vulnerable` then `patched`, each a fresh target
//! process):
//!
//! | AC | Assertion |
//! |---|---|
//! | T4-1 | discovery over the captured conversation yields a `ws_json_value` point named `msg` |
//! | T4-2 | `cswsh` is `(Vulnerable, Certain)` on V and not vulnerable on P; the target's handshake log shows the dialer's regenerated `Sec-WebSocket-Key` and the kept `session` cookie |
//! | T4-3 | `ws-input-reflection` on `msg` is `Vulnerable` with the canary unencoded on V and not vulnerable on P (P HTML-escapes the field, which is `Clean`, plan call 36); one `ws-oversize-frame` run puts exactly one frame of `2 x largest captured client frame` on the wire, by the target's frame log |
//! | — | `ws-subprotocol-observe` is `Vulnerable` on V (echoes any offered token) and not vulnerable on P (selects none, plan call 33) |
//! | — | at no instant were more than [`MAX_CONNECTIONS`] dialer connections open, by the target's connection log |
//! | — | the session cookie's literal value is in no verdict `Debug` and in no discovery JSON |
//!
//! ## One assertion this file deliberately does **not** make
//!
//! **The cookie in `held_flows()`.** Task 18 asked for an empty grep of every
//! held flow's `Debug`, but a held flow is the replayed handshake with its
//! `Cookie` header — store data the engine re-records only for an issue — and
//! `aitm_core::HeaderMap` derives `Debug`. Accepted as by design (task 18
//! ruling on gap 2): the redaction rule covers verdicts, evidence, points and
//! log lines, and those are asserted. Whether the cookie is in a held flow is
//! printed as a fact, not asserted either way.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use aitm_core::{
    Config, Flow, FlowStore, HttpFlow, Proxy, ScopeConfig, ScopeEntry, ScopeRateGuard, StdGuard,
    WsDir, WsFlow,
};
use aitm_proto_http::HttpModule;
use aitm_proto_ws::WsModule;
use aitm_scan_model::{Confidence, InsertionKind, InsertionPoint, JobCtx, Lane, Outcome, Verdict};
use aitm_scan_ws::checks;
use aitm_scan_ws::dialer::WsDialer;
use aitm_scan_ws::lane::WsLane;
use aitm_scan_ws::testing::live::{control_json, strip_scheme, Target};
use aitm_scan_ws::testing::TestJob;
use aitm_scan_ws::transport::TcpTransport;
use aitm_scan_ws::types::{TlsPolicy, MAX_CONNECTIONS};
use futures::stream::{self, StreamExt};
use futures::SinkExt;
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::Message;

/// The fixture login `POST /login` accepts on the seeded target.
const LOGIN_FORM: &str = "user=alice&pass=wonderland";

/// The one frame the capture client sends; its JSON fields are the points.
const CAPTURED_FRAME: &str = r#"{"type":"echo","msg":"hi"}"#;

/// Budget for the whole-sweep job: every check over every point, each costing
/// a unit per dial and per frame. Generous on purpose — an exhausted budget
/// degrades a verdict to `Inconclusive` and would prove nothing.
const SWEEP_BUDGET: u32 = 4_000;

/// How many check runs may be in flight at once. Above [`MAX_CONNECTIONS`] on
/// purpose: the point of the concurrency observation is that the lane's own
/// semaphore, not the test's pacing, is what bounds the target's connections.
const SWEEP_CONCURRENCY: usize = 12;

// --- a dependency-free HTTP/1.1 client for the control origin -----------------

/// One request over a fresh connection, read to EOF; `(head, body)`.
///
/// Deliberately hand-written: the control origin speaks plain HTTP/1.1 and the
/// crate takes no HTTP client dependency for its tests.
async fn http(
    origin: &str,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> (String, String) {
    let authority = strip_scheme(origin);
    let mut stream = TcpStream::connect(authority)
        .await
        .unwrap_or_else(|err| panic!("connect {authority}: {err}"));
    let mut request =
        format!("{method} {path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n");
    for (name, value) in headers {
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    request.push_str(&format!("Content-Length: {}\r\n\r\n{body}", body.len()));
    stream
        .write_all(request.as_bytes())
        .await
        .unwrap_or_else(|err| panic!("send {method} {path}: {err}"));
    let mut raw = Vec::new();
    stream
        .read_to_end(&mut raw)
        .await
        .unwrap_or_else(|err| panic!("read {method} {path}: {err}"));
    let text = String::from_utf8_lossy(&raw).into_owned();
    text.split_once("\r\n\r\n").map_or_else(
        || (text.clone(), String::new()),
        |(h, b)| (h.to_string(), b.to_string()),
    )
}

/// `POST /reset` on the control origin: every log ring is cleared.
async fn control_reset(control: &str) {
    let (head, _) = http(control, "POST", "/reset", &[], "").await;
    assert!(
        head.starts_with("HTTP/1.1 200"),
        "POST /reset answered {head:?}"
    );
}

/// `POST /login` with the fixture credentials; the `session` cookie's value.
async fn login(origin: &str) -> String {
    let (head, _) = http(
        origin,
        "POST",
        "/login",
        &[("Content-Type", "application/x-www-form-urlencoded")],
        LOGIN_FORM,
    )
    .await;
    head.lines()
        .filter(|line| {
            line.split_once(':')
                .is_some_and(|(name, _)| name.eq_ignore_ascii_case("set-cookie"))
        })
        .find_map(|line| {
            let (_, cookie) = line.split_once("session=")?;
            Some(
                cookie
                    .split(';')
                    .next()
                    .unwrap_or(cookie)
                    .trim()
                    .to_string(),
            )
        })
        .unwrap_or_else(|| panic!("POST /login set no `session` cookie; head was {head:?}"))
}

// --- the real proxy the capture goes through ----------------------------------

/// A `Proxy` with the real HTTP and WebSocket modules on a loopback port.
async fn run_proxy() -> (SocketAddr, Arc<dyn FlowStore>) {
    let config = Config {
        scope: ScopeConfig {
            entries: vec![ScopeEntry {
                host: "127.0.0.1".to_string(),
            }],
            ..ScopeConfig::default()
        },
        ..Config::default()
    };
    let proxy = Proxy::builder()
        .with_config(config)
        .register_module(Arc::new(HttpModule::new().with_insecure(true)))
        .register_module(Arc::new(WsModule::new()))
        .build()
        .expect("build the capture proxy");
    let store = proxy.store();
    let addr = std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|listener| listener.local_addr())
        .expect("pick a free proxy port");
    tokio::spawn(async move {
        let _ = proxy.run(addr).await;
    });
    let deadline = Instant::now() + Duration::from_secs(5);
    while TcpStream::connect(addr).await.is_err() {
        assert!(
            Instant::now() < deadline,
            "the proxy never started listening"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    (addr, store)
}

/// Read the head of an HTTP response off a raw stream.
async fn read_head(stream: &mut TcpStream) -> String {
    let mut head = Vec::new();
    let mut chunk = [0u8; 1024];
    while !head.windows(4).any(|window| window == b"\r\n\r\n") {
        let read = stream.read(&mut chunk).await.expect("read a response head");
        if read == 0 {
            break;
        }
        head.extend_from_slice(&chunk[..read]);
    }
    String::from_utf8_lossy(&head).into_owned()
}

/// Drive one real WebSocket conversation to the target **through the proxy**.
///
/// Returns the `Sec-WebSocket-Key` the capture client generated, so the proof
/// can show the lane's dialer did not reuse it (AC T4-2).
async fn capture_conversation(proxy: SocketAddr, target: &Target, cookie: &str) -> String {
    let authority = target.authority();
    let mut request = format!("ws://{authority}/ws")
        .into_client_request()
        .expect("a client request for the target's /ws");
    let headers = request.headers_mut();
    headers.insert(
        "origin",
        HeaderValue::from_str(&target.origin).expect("the target origin is a header value"),
    );
    headers.insert(
        "cookie",
        HeaderValue::from_str(&format!("session={cookie}")).expect("the cookie is a header value"),
    );
    let client_key = request
        .headers()
        .get("sec-websocket-key")
        .and_then(|value| value.to_str().ok())
        .expect("tungstenite generated a Sec-WebSocket-Key")
        .to_string();

    let mut tcp = TcpStream::connect(proxy).await.expect("connect the proxy");
    tcp.write_all(format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n").as_bytes())
        .await
        .expect("send CONNECT");
    let reply = read_head(&mut tcp).await;
    assert!(
        reply.starts_with("HTTP/1.1 200"),
        "the proxy refused the tunnel: {reply:?}"
    );

    let (mut ws, response) = tokio_tungstenite::client_async(request, tcp)
        .await
        .expect("the WebSocket handshake through the proxy");
    assert_eq!(
        response.status().as_u16(),
        101,
        "the seeded target accepted the capture upgrade"
    );

    ws.send(Message::text(CAPTURED_FRAME))
        .await
        .expect("send the captured frame");
    let mut replies = Vec::new();
    while replies.len() < 2 {
        let message = tokio::time::timeout(Duration::from_secs(5), ws.next())
            .await
            .expect("the target answered within 5 s")
            .expect("the stream is still open")
            .expect("a well-formed frame");
        if message.is_text() || message.is_binary() {
            replies.push(message.to_text().unwrap_or_default().to_string());
        }
    }
    println!("capture: client_key={client_key} replies={replies:?}");
    ws.close(None).await.ok();
    // Drain the close handshake so the target stamps the connection closed
    // before the connection log is reset.
    while let Ok(Some(Ok(_))) = tokio::time::timeout(Duration::from_secs(2), ws.next()).await {}
    client_key
}

/// The captured `WsFlow` once it holds `want` messages, plus its handshake.
async fn captured_flow(store: &dyn FlowStore, want: usize) -> (WsFlow, HttpFlow) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let found = store.list().into_iter().find_map(|id| match store.get(id) {
            Some(Flow::WebSocket(flow)) if flow.messages.len() >= want => Some(flow),
            _ => None,
        });
        if let Some(flow) = found {
            let Some(Flow::Http(handshake)) = store.get(flow.handshake) else {
                panic!("the captured WsFlow has no handshake HttpFlow");
            };
            return (flow, handshake);
        }
        assert!(
            Instant::now() < deadline,
            "no WsFlow with {want} messages was captured ({} flows in the store)",
            store.list().len()
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

// --- reading the target's observers -------------------------------------------

/// Every `/log/ws` entry whose `kind` is `want`.
fn entries_of<'a>(log: &'a Value, want: &str) -> Vec<&'a Value> {
    log["entries"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default()
        .iter()
        .filter(|entry| entry["kind"] == Value::String(want.to_string()))
        .collect()
}

/// The greatest number of target connections open at the same instant.
///
/// Open and close stamps are millisecond-resolution, so a close and an open in
/// the same millisecond are ordered close-first (`-1 < 1` sorts first); the raw
/// rows are printed alongside so an operator can see the ties.
fn max_concurrent(conns: &Value) -> usize {
    let mut events: Vec<(u64, i32)> = Vec::new();
    for entry in conns["entries"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default()
    {
        let Some(opened) = entry["opened_ms"].as_u64() else {
            continue;
        };
        events.push((opened, 1));
        events.push((entry["closed_ms"].as_u64().unwrap_or(u64::MAX), -1));
    }
    events.sort_unstable();
    let mut open = 0i32;
    let mut peak = 0i32;
    for (_, delta) in events {
        open += delta;
        peak = peak.max(open);
    }
    usize::try_from(peak.max(0)).unwrap_or(0)
}

// --- the proof ----------------------------------------------------------------

/// Everything one mode's run observed, for the per-mode assertions.
struct Proof {
    /// `(check id, point name, verdict)` for every check over every point.
    verdicts: Vec<(String, String, Verdict)>,
    /// The discovered points.
    points: Vec<InsertionPoint>,
    /// Whether any held flow's `Debug` carries the literal cookie (printed,
    /// not asserted — see the module docs).
    cookie_in_held_flows: bool,
    /// The one `ws-oversize-frame` run's padded frame length.
    pad_target: usize,
    /// How many client->server frames of exactly `pad_target` bytes the target
    /// logged during the isolated oversize run.
    pad_frames_seen: usize,
}

impl Proof {
    /// The verdict of `check` on the point named `point`.
    fn verdict(&self, check: &str, point: &str) -> &Verdict {
        self.verdicts
            .iter()
            .find(|(id, name, _)| id == check && name == point)
            .map(|(_, _, verdict)| verdict)
            .unwrap_or_else(|| panic!("no verdict recorded for {check} on the {point} point"))
    }
}

/// Capture, discover, sweep every check over every point, read the observers.
#[allow(clippy::too_many_lines)]
async fn prove(mode: &str) -> Proof {
    let target = Target::start(mode);
    let cookie = login(&target.origin).await;
    let (proxy, store) = run_proxy().await;
    let client_key = capture_conversation(proxy, &target, &cookie).await;
    let (ws_flow, handshake) = captured_flow(store.as_ref(), 3).await;
    println!(
        "capture[{mode}]: handshake {} {} {} messages, origin {}",
        handshake.request.method,
        handshake.request.path,
        ws_flow.messages.len(),
        target.origin
    );

    // The lane, over the real pipeline's store and a guard holding exactly the
    // target authority, dialling with the production TCP transport.
    let guard = StdGuard::default();
    guard.add_scope(ScopeEntry {
        host: target.authority(),
    });
    let origin = target.origin.clone();
    let job = TestJob::over(
        Arc::clone(&store),
        Arc::new(guard),
        SWEEP_BUDGET,
        move |profile| profile.target.origins = vec![origin],
    );
    let lane = Arc::new(WsLane::new(Arc::new(WsDialer::new(Arc::new(
        TcpTransport::new(TlsPolicy::AcceptAny, Duration::from_secs(10)),
    )))));

    let discovery = lane
        .discover(&job.profile().target, job.as_ref())
        .await
        .expect("discovery over the captured conversation");
    let points = discovery.points;
    println!(
        "discovery[{mode}]: {} points {:?}",
        points.len(),
        points
            .iter()
            .map(|point| (point.kind, point.name.as_str()))
            .collect::<Vec<_>>()
    );

    // The pad target the oversize check will aim at, computed from the capture
    // exactly as the probe host does: `min(2 x largest client frame,
    // profile.ws.max_frame_bytes)`.
    let largest = ws_flow
        .messages
        .iter()
        .filter(|message| message.dir == WsDir::ClientToServer)
        .map(|message| message.data.len())
        .max()
        .expect("the capture sent at least one client frame");
    let pad_target = (largest * 2).min(job.profile().ws.max_frame_bytes as usize);

    // From here on the target's logs are the scanner's alone.
    control_reset(&target.control).await;

    let pairs: Vec<_> = points
        .iter()
        .flat_map(|point| {
            checks::all()
                .into_iter()
                .map(move |check| (point.clone(), check))
        })
        .collect();
    let swept: Vec<(String, String, Verdict, bool)> = stream::iter(pairs)
        .map(|(point, check)| {
            let lane = Arc::clone(&lane);
            let job = Arc::clone(&job) as Arc<dyn JobCtx>;
            let cookie = cookie.clone();
            async move {
                let host = lane
                    .probe_host_for(&point, job)
                    .expect("the lane hosts a point it registered itself");
                let verdict = check.run(&point, host.as_ref()).await;
                let held = host
                    .held_flows()
                    .iter()
                    .any(|flow| format!("{flow:?}").contains(&cookie));
                (check.meta().id.clone(), point.name.clone(), verdict, held)
            }
        })
        .buffer_unordered(SWEEP_CONCURRENCY)
        .collect()
        .await;

    let cookie_in_held_flows = swept.iter().any(|(_, _, _, held)| *held);
    let verdicts: Vec<(String, String, Verdict)> = swept
        .into_iter()
        .map(|(check, point, verdict, _)| (check, point, verdict))
        .collect();
    for (check, point, verdict) in &verdicts {
        println!(
            "verdict[{mode}]: {check} @ {point} -> {:?}/{:?} — {}",
            verdict.outcome, verdict.confidence, verdict.detail
        );
    }

    // The observers, for the whole sweep.
    let ws_log = control_json(&target.control, "/log/ws");
    for entry in entries_of(&ws_log, "handshake") {
        println!(
            "handshake[{mode}]: origin={} key={} cookies={} session_valid={} status={} subprotocol={}",
            entry["origin"], entry["sec_websocket_key"], entry["cookie_names"],
            entry["session_valid"], entry["status"], entry["subprotocol"]
        );
    }
    let handshakes = entries_of(&ws_log, "handshake");
    assert!(
        !handshakes.is_empty(),
        "the sweep reached the target: /log/ws has handshake entries"
    );

    // AC T4-2, observer half: the dialer regenerated the key and kept the
    // cookie. The cswsh probe is the one identifiable by its foreign Origin.
    let foreign = handshakes
        .iter()
        .find(|entry| entry["origin"] == Value::String("https://attacker.invalid".to_string()))
        .unwrap_or_else(|| panic!("no handshake with the cswsh check's foreign Origin was logged"));
    let foreign_key = foreign["sec_websocket_key"]
        .as_str()
        .expect("a handshake entry carries sec_websocket_key");
    assert_ne!(
        foreign_key, client_key,
        "the dialer must regenerate Sec-WebSocket-Key, not replay the capture's"
    );
    let cookie_names: Vec<&str> = foreign["cookie_names"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(
        cookie_names.contains(&"session"),
        "the cswsh probe must keep the session cookie; cookie_names were {cookie_names:?}"
    );
    for entry in handshakes {
        assert_ne!(
            entry["sec_websocket_key"].as_str(),
            Some(client_key.as_str()),
            "every dialer handshake carries a fresh key"
        );
    }

    let conns = control_json(&target.control, "/log/conns");
    for entry in conns["entries"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default()
    {
        println!(
            "conn[{mode}]: {} opened={} closed={}",
            entry["conn_id"], entry["opened_ms"], entry["closed_ms"]
        );
    }
    let peak = max_concurrent(&conns);
    println!("concurrency[{mode}]: peak {peak} of at most {MAX_CONNECTIONS} dialer connections");
    assert!(
        peak <= MAX_CONNECTIONS,
        "the lane's semaphore bounds the target's open connections at {MAX_CONNECTIONS}, saw {peak}"
    );

    // AC T4-3: one oversize run, on a freshly reset log, puts exactly one
    // padded frame on the wire. It is isolated because the sweep runs the
    // check once per frame-bearing point and "exactly one" is a per-run claim.
    control_reset(&target.control).await;
    let msg_point = points
        .iter()
        .find(|point| point.kind == InsertionKind::WsJsonValue && point.name == "msg")
        .expect("the msg point exists (T4-1)")
        .clone();
    let oversize = checks::oversize::check();
    let host = lane
        .probe_host_for(&msg_point, Arc::clone(&job) as Arc<dyn JobCtx>)
        .expect("the msg point is hostable");
    let oversize_verdict = oversize.run(&msg_point, host.as_ref()).await;
    println!(
        "oversize[{mode}]: {:?}/{:?} — {}",
        oversize_verdict.outcome, oversize_verdict.confidence, oversize_verdict.detail
    );
    let pad_log = control_json(&target.control, "/log/ws");
    let frames = entries_of(&pad_log, "frame");
    for entry in &frames {
        println!(
            "frame[{mode}]: dir={} opcode={} len={}",
            entry["dir"], entry["opcode"], entry["len"]
        );
    }
    let pad_frames_seen = frames
        .iter()
        .filter(|entry| entry["dir"] == Value::String("in".to_string()))
        .filter(|entry| entry["len"].as_u64() == Some(pad_target as u64))
        .count();

    let points_json = serde_json::to_string(&points).expect("the points serialise");
    assert!(
        !points_json.contains(&cookie),
        "the discovery JSON must not carry the session cookie's value"
    );
    for (check, point, verdict) in &verdicts {
        assert!(
            !format!("{verdict:?}").contains(&cookie),
            "{check} on {point} leaked the session cookie into its verdict"
        );
    }
    println!(
        "redaction[{mode}]: cookie absent from {} verdicts and from the discovery JSON; \
         present in a held flow: {cookie_in_held_flows} (store data, see the module docs)",
        verdicts.len()
    );

    Proof {
        verdicts,
        points,
        cookie_in_held_flows,
        pad_target,
        pad_frames_seen,
    }
}

/// Assertions every mode shares: T4-1, T4-3's frame count, and the printed
/// held-flow observation.
fn assert_shared(mode: &str, proof: &Proof) {
    let msg = proof
        .points
        .iter()
        .find(|point| point.kind == InsertionKind::WsJsonValue && point.name == "msg")
        .unwrap_or_else(|| {
            panic!("T4-1: discovery over the real capture must yield a ws_json_value point `msg`")
        });
    assert_eq!(msg.path.as_deref(), Some("msg"));
    assert_eq!(
        proof.pad_frames_seen, 1,
        "T4-3[{mode}]: exactly one frame of {} bytes (2 x the largest captured client frame) \
         must have reached the target",
        proof.pad_target
    );
    println!(
        "shared[{mode}]: msg point {}, one pad frame of {} bytes, cookie in held flows: {}",
        msg.id, proof.pad_target, proof.cookie_in_held_flows
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "binds a loopback port; run in the Terminal"]
async fn vulnerable_target_yields_the_seeded_ws_issues() {
    let proof = prove("vulnerable").await;
    assert_shared("vulnerable", &proof);

    // AC T4-2: the upgrade completes with a foreign Origin and answers exactly
    // as the authenticated baseline did.
    let cswsh = proof.verdict(checks::cswsh::ID, "origin");
    assert_eq!(
        cswsh.outcome,
        Outcome::Vulnerable,
        "cswsh: {}",
        cswsh.detail
    );
    assert_eq!(
        cswsh.confidence,
        Confidence::Certain,
        "cswsh: {}",
        cswsh.detail
    );

    // AC T4-3, scanner half: the canary comes back with its metacharacters
    // intact, which is what makes the V reflection an injection.
    let reflection = proof.verdict(checks::reflection::ID, "msg");
    assert_eq!(
        reflection.outcome,
        Outcome::Vulnerable,
        "reflection: {}",
        reflection.detail
    );
    assert!(
        reflection.detail.contains("unencoded"),
        "V reflects the canary unencoded; detail was {:?}",
        reflection.detail
    );

    // The V seed echoes the first offered subprotocol token, whatever it is.
    let subprotocol = proof.verdict(checks::subprotocol::ID, "origin");
    assert_eq!(
        subprotocol.outcome,
        Outcome::Vulnerable,
        "subprotocol: {}",
        subprotocol.detail
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "binds a loopback port; run in the Terminal"]
async fn patched_target_yields_none_of_them() {
    let proof = prove("patched").await;
    assert_shared("patched", &proof);

    // P answers 403 to a foreign Origin, so the upgrade never completes.
    let cswsh = proof.verdict(checks::cswsh::ID, "origin");
    assert_ne!(
        cswsh.outcome,
        Outcome::Vulnerable,
        "cswsh on P: {}",
        cswsh.detail
    );

    // P ignores Sec-WebSocket-Protocol, and a 101 that selects none is Clean
    // (plan call 33).
    let subprotocol = proof.verdict(checks::subprotocol::ID, "origin");
    assert_ne!(
        subprotocol.outcome,
        Outcome::Vulnerable,
        "subprotocol on P: {}",
        subprotocol.detail
    );

    // AC T4-3 on P: the echoed field is HTML-escaped, so the marker comes back
    // but the canary does not, and an encoded reflection is Clean (plan call
    // 36).
    let reflection = proof.verdict(checks::reflection::ID, "msg");
    assert_ne!(
        reflection.outcome,
        Outcome::Vulnerable,
        "reflection on P: {}",
        reflection.detail
    );
    assert!(
        !reflection.detail.contains("unencoded"),
        "P must not reflect the canary unencoded; detail was {:?}",
        reflection.detail
    );
    println!(
        "patched: ws-input-reflection is {:?}/{:?} — {}",
        reflection.outcome, reflection.confidence, reflection.detail
    );
}
