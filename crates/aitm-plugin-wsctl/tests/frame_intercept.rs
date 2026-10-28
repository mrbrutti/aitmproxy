//! AC-F9.2: `ws.intercept` parks a live WebSocket frame matched by a
//! `Phase::WsFrame` rule; `ws.frame` edit-then-forwards it or drops it.
//!
//! Each test stands up a real client ↔ `Proxy` (HTTP hand-off + `WsModule` +
//! `WsCtlPlugin`) ↔ echo server. The frame is parked on the wire; the test then
//! invokes `ws.frame` through the command registry (as a frontend would) while
//! the module is suspended inside `emit().await`, and asserts what the echo peer
//! actually received.
//!
//! These bind loopback TCP ports, so they run in the Terminal panel (the Claude
//! sandbox forbids `bind`), per `CLAUDE.md`.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use aitm_core::{
    CommandHost, Flow, FlowId, FlowStore, HttpRequest, InterceptState, Params, Proxy, ProxyClient,
    Registry, ScopeConfig, ScopeEntry, ScopeRateGuard, Value, WsFlow,
};
use aitm_plugin_wsctl::WsCtlPlugin;
use aitm_proto_http::HttpModule;
use aitm_proto_ws::WsModule;
use futures::future::BoxFuture;
use futures::{SinkExt, StreamExt};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::tungstenite::Message;

// --- command-invocation plumbing --------------------------------------------

/// `ws.intercept`/`ws.frame` never reach the proxy client in Task 6 (no active
/// egress); a stub satisfies `CommandHost`.
struct StubClient;
impl ProxyClient for StubClient {
    fn send(&self, _req: HttpRequest) -> BoxFuture<'_, anyhow::Result<aitm_core::HttpFlow>> {
        Box::pin(async { anyhow::bail!("stub client") })
    }
}

fn params(pairs: Vec<(&str, Value)>) -> Params {
    Params::new(
        pairs
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect::<BTreeMap<_, _>>(),
    )
}

/// One rule object as it crosses the command bus (flat: condition clauses at the
/// top level).
fn rule(pairs: Vec<(&str, Value)>) -> Value {
    Value::Object(
        pairs
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect::<BTreeMap<_, _>>(),
    )
}

fn invoke(
    reg: &Registry,
    store: &dyn FlowStore,
    guard: &dyn ScopeRateGuard,
    name: &str,
    args: Params,
) -> anyhow::Result<Value> {
    let client = StubClient;
    let host = CommandHost::new(store, &client, guard, None);
    reg.command(name)
        .unwrap_or_else(|| panic!("{name} registered"))
        .invoke(args, &host)
}

// --- proxy + echo harness (mirrors aitm-proto-ws/tests/ws_capture.rs) --------

fn free_port() -> SocketAddr {
    std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .expect("pick a free port")
}

async fn read_head<S: AsyncRead + Unpin>(s: &mut S) -> String {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
        let n = s.read(&mut chunk).await.expect("read head");
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    String::from_utf8_lossy(&buf).into_owned()
}

/// A WebSocket server echoing every text/binary frame back.
async fn spawn_echo() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind echo");
    let addr = listener.local_addr().expect("echo addr");
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let Ok(mut ws) = tokio_tungstenite::accept_async(tcp).await else {
                    return;
                };
                while let Some(Ok(msg)) = ws.next().await {
                    if msg.is_text() || msg.is_binary() {
                        if ws.send(msg).await.is_err() {
                            break;
                        }
                    } else if msg.is_close() {
                        break;
                    }
                }
            });
        }
    });
    addr
}

/// A built proxy with the HTTP module, WS module and wsctl plugin, plus the
/// shared handles a frontend needs to drive commands.
struct Harness {
    addr: SocketAddr,
    store: Arc<dyn FlowStore>,
    guard: Arc<dyn ScopeRateGuard>,
    reg: Arc<Registry>,
}

async fn run_proxy() -> Harness {
    let config = aitm_core::Config {
        scope: ScopeConfig {
            entries: vec![ScopeEntry {
                host: "127.0.0.1".to_string(),
            }],
            ..ScopeConfig::default()
        },
        ..aitm_core::Config::default()
    };
    let proxy = Proxy::builder()
        .with_config(config)
        .register_module(Arc::new(HttpModule::new().with_insecure(true)))
        .register_module(Arc::new(WsModule::new()))
        .register_plugin(Box::new(WsCtlPlugin::new()))
        .build()
        .expect("build proxy");
    let store = proxy.store();
    let guard = proxy.guard();
    let reg = proxy.registry_arc();
    let addr = free_port();
    tokio::spawn(async move {
        let _ = proxy.run(addr).await;
    });
    let deadline = Instant::now() + Duration::from_secs(5);
    while TcpStream::connect(addr).await.is_err() {
        assert!(Instant::now() < deadline, "proxy never started listening");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    Harness {
        addr,
        store,
        guard,
        reg,
    }
}

/// Open a WebSocket to `echo` through the proxy's CONNECT tunnel.
async fn ws_through_proxy(
    proxy: SocketAddr,
    echo: SocketAddr,
) -> tokio_tungstenite::WebSocketStream<TcpStream> {
    let mut tcp = TcpStream::connect(proxy).await.expect("connect proxy");
    tcp.write_all(format!("CONNECT {echo} HTTP/1.1\r\nHost: {echo}\r\n\r\n").as_bytes())
        .await
        .expect("send CONNECT");
    let reply = read_head(&mut tcp).await;
    assert!(
        reply.starts_with("HTTP/1.1 200"),
        "CONNECT reply: {reply:?}"
    );
    let (ws, response) = tokio_tungstenite::client_async(format!("ws://{echo}/chat"), tcp)
        .await
        .expect("WebSocket handshake through the proxy");
    assert_eq!(response.status().as_u16(), 101);
    ws
}

/// Poll the store until some `WsFlow` is parked (`Intercepted`); return its id
/// and the index of the frame to act on (the newest one).
async fn wait_for_parked_frame(store: &dyn FlowStore) -> (FlowId, usize) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let found = store.list().into_iter().find_map(|id| match store.get(id) {
            Some(Flow::WebSocket(w))
                if matches!(w.intercept, InterceptState::Intercepted { .. }) =>
            {
                Some((id, w.messages.len().saturating_sub(1)))
            }
            _ => None,
        });
        if let Some(found) = found {
            return found;
        }
        assert!(Instant::now() < deadline, "no WS frame was ever parked");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

fn ws_flow(store: &dyn FlowStore) -> Option<WsFlow> {
    store.list().into_iter().find_map(|id| match store.get(id) {
        Some(Flow::WebSocket(w)) => Some(w),
        _ => None,
    })
}

/// Arm `ws.intercept` with one `ws_dir`-filtered WsFrame rule on the given dir.
fn arm_ws_frame_rule(h: &Harness, ws_dir: &str) {
    let rules = Value::Array(vec![rule(vec![
        ("phase", Value::Str("ws_frame".into())),
        ("ws_dir", Value::Str(ws_dir.into())),
    ])]);
    invoke(
        &h.reg,
        h.store.as_ref(),
        h.guard.as_ref(),
        "ws.intercept",
        params(vec![("enabled", Value::Bool(true)), ("rules", rules)]),
    )
    .expect("ws.intercept arms");
}

// --- the three AC-F9.2 tests -------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn frame_forward_edited_delivered() {
    let echo = spawn_echo().await;
    let h = run_proxy().await;
    arm_ws_frame_rule(&h, "c2s");

    let mut ws = ws_through_proxy(h.addr, echo).await;
    ws.send(Message::text("orig")).await.expect("send text");

    let (id, index) = wait_for_parked_frame(h.store.as_ref()).await;

    invoke(
        &h.reg,
        h.store.as_ref(),
        h.guard.as_ref(),
        "ws.frame",
        params(vec![
            ("id", Value::Str(id.to_string())),
            ("index", Value::Int(index as i64)),
            ("action", Value::Str("forward".into())),
            ("data", Value::Bytes(b"edited".to_vec())),
        ]),
    )
    .expect("ws.frame forward succeeds");

    // The echo peer receives the EDITED bytes and echoes them back to the client.
    let echoed = tokio::time::timeout(Duration::from_secs(5), ws.next())
        .await
        .expect("echo arrives")
        .expect("a frame")
        .expect("frame ok");
    assert_eq!(echoed.to_text().expect("text frame"), "edited");

    ws.close(None).await.ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn frame_drop_not_delivered() {
    let echo = spawn_echo().await;
    let h = run_proxy().await;
    arm_ws_frame_rule(&h, "c2s");

    let mut ws = ws_through_proxy(h.addr, echo).await;
    ws.send(Message::text("secret")).await.expect("send text");

    let (id, index) = wait_for_parked_frame(h.store.as_ref()).await;

    invoke(
        &h.reg,
        h.store.as_ref(),
        h.guard.as_ref(),
        "ws.frame",
        params(vec![
            ("id", Value::Str(id.to_string())),
            ("index", Value::Int(index as i64)),
            ("action", Value::Str("drop".into())),
        ]),
    )
    .expect("ws.frame drop succeeds");

    // The dropped frame never reaches the echo peer, so no echo ever comes back:
    // the client reads a close/EOF (not the text), within a bounded window.
    let got = tokio::time::timeout(Duration::from_secs(2), ws.next()).await;
    if let Ok(Some(Ok(msg))) = got {
        assert!(
            !(msg.is_text() && msg.to_text().unwrap_or_default() == "secret"),
            "dropped frame must not be echoed back"
        );
    }

    // The store holds only the single dropped frame — no echoed second frame.
    let flow = ws_flow(h.store.as_ref()).expect("ws flow");
    assert_eq!(flow.messages.len(), 1, "no frame was forwarded/echoed");
    assert!(matches!(flow.intercept, InterceptState::Killed));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn non_matching_frame_forwarded() {
    let echo = spawn_echo().await;
    let h = run_proxy().await;
    // A request-phase rule never fires at the WsFrame dispatch point.
    let rules = Value::Array(vec![rule(vec![("phase", Value::Str("request".into()))])]);
    invoke(
        &h.reg,
        h.store.as_ref(),
        h.guard.as_ref(),
        "ws.intercept",
        params(vec![("enabled", Value::Bool(true)), ("rules", rules)]),
    )
    .expect("ws.intercept arms");

    let mut ws = ws_through_proxy(h.addr, echo).await;
    ws.send(Message::text("hello")).await.expect("send text");

    // The frame is forwarded unchanged and echoed straight back.
    let echoed = tokio::time::timeout(Duration::from_secs(5), ws.next())
        .await
        .expect("echo arrives")
        .expect("a frame")
        .expect("frame ok");
    assert_eq!(echoed.to_text().expect("text frame"), "hello");

    // The flow was never parked.
    let flow = ws_flow(h.store.as_ref()).expect("ws flow");
    assert!(
        !matches!(flow.intercept, InterceptState::Intercepted { .. }),
        "a non-matching frame must not be parked"
    );

    ws.close(None).await.ok();
}
