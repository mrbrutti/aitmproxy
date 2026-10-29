//! AC-F9.1 / AC-F9.3: `ws.send` composes and injects a live WebSocket frame.
//!
//! Each test stands up a real client ↔ `Proxy` (HTTP hand-off + `WsModule` wired
//! with the plugin's shared `InjectRegistry` + `WsCtlPlugin`) ↔ echo server. With
//! the WebSocket live (but no client frame yet), the test invokes `ws.send`
//! through the command registry (as a frontend would); the module's `select!`
//! drains the inject channel, frames it towards the chosen side and appends a
//! `WsMessage { injected: true }`.
//!
//! `ws.send` injects active egress, so it passes `ScopeRateGuard::check_active`.
//! The command invocation therefore uses its own guard (a real `StdGuard`),
//! independent of the permissive guard the proxy itself runs on so the WebSocket
//! can open — that separation is what lets `ws_send_out_of_scope_refused` deny the
//! inject while the live socket exists.
//!
//! These bind loopback TCP ports, so they run in the Terminal panel (the Claude
//! sandbox forbids `bind`), per `CLAUDE.md`.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use aitm_core::{
    CommandHost, Flow, FlowId, FlowStore, HttpRequest, LimitConfig, Params, Proxy, ProxyClient,
    Registry, ScopeConfig, ScopeEntry, ScopeRateGuard, StdGuard, Value, WsFlow,
};
use aitm_plugin_wsctl::WsCtlPlugin;
use aitm_proto_http::HttpModule;
use aitm_proto_ws::WsModule;
use futures::future::BoxFuture;
use futures::{SinkExt, StreamExt};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

// --- command-invocation plumbing --------------------------------------------

/// `ws.send` never reaches the proxy client (it enqueues onto the inject
/// channel); a stub satisfies `CommandHost`.
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

/// Invoke a command with a caller-chosen guard, so a test can refuse or allow the
/// inject independently of the proxy's own forwarding guard.
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

// --- proxy + echo harness (mirrors frame_intercept.rs) -----------------------

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

/// A built proxy sharing one `InjectRegistry` between its `WsModule` and
/// `WsCtlPlugin`, plus the handles a frontend needs to drive commands.
struct Harness {
    addr: SocketAddr,
    store: Arc<dyn FlowStore>,
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
    // The plugin owns the inject registry; the module injects through the same
    // Arc (what Task 14 wires in the binary).
    let plugin = WsCtlPlugin::new();
    let inject = plugin.inject_registry();
    let proxy = Proxy::builder()
        .with_config(config)
        .register_module(Arc::new(HttpModule::new().with_insecure(true)))
        .register_module(Arc::new(WsModule::new().with_inject_registry(inject)))
        .register_plugin(Box::new(plugin))
        .build()
        .expect("build proxy");
    let store = proxy.store();
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
    Harness { addr, store, reg }
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

/// Poll the store until a live `WsFlow` exists (the module registered its inject
/// sender before inserting the flow, so once it is visible `ws.send` can resolve
/// the channel). Returns its id.
async fn wait_for_ws_flow(store: &dyn FlowStore) -> FlowId {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let found = store
            .list()
            .into_iter()
            .find(|id| matches!(store.get(*id), Some(Flow::WebSocket(_))));
        if let Some(id) = found {
            return id;
        }
        assert!(Instant::now() < deadline, "no WebSocket flow ever opened");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

fn ws_flow(store: &dyn FlowStore) -> Option<WsFlow> {
    store.list().into_iter().find_map(|id| match store.get(id) {
        Some(Flow::WebSocket(w)) => Some(w),
        _ => None,
    })
}

/// A real guard seeded with the given scope hosts, for the command side.
fn guard_with_scope(hosts: &[&str]) -> Arc<StdGuard> {
    let guard = Arc::new(StdGuard::new(LimitConfig::default()));
    for host in hosts {
        guard.add_scope(ScopeEntry {
            host: (*host).to_string(),
        });
    }
    guard
}

fn send_args(id: FlowId, dir: &str, opcode: &str, data: &str) -> Params {
    params(vec![
        ("id", Value::Str(id.to_string())),
        ("dir", Value::Str(dir.into())),
        ("opcode", Value::Str(opcode.into())),
        ("data", Value::Bytes(data.as_bytes().to_vec())),
    ])
}

// --- AC-F9.1 -----------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ws_send_reaches_upstream() {
    let echo = spawn_echo().await;
    let h = run_proxy().await;

    // Open the WebSocket but do not send a client frame; the only frame on the
    // wire will be the injected one.
    let mut ws = ws_through_proxy(h.addr, echo).await;
    let id = wait_for_ws_flow(h.store.as_ref()).await;

    // In scope → the inject is permitted.
    let guard = guard_with_scope(&["127.0.0.1"]);
    let result = invoke(
        &h.reg,
        h.store.as_ref(),
        guard.as_ref(),
        "ws.send",
        send_args(id, "c2s", "text", "ping-inject"),
    )
    .expect("ws.send succeeds in scope");

    let index = match &result {
        Value::Object(o) => match o.get("index") {
            Some(Value::Int(i)) => usize::try_from(*i).expect("non-negative index"),
            other => panic!("ws.send result index: {other:?}"),
        },
        other => panic!("ws.send result: {other:?}"),
    };

    // The upstream echo server received the injected text and echoed it back to
    // the client — proof it reached upstream.
    let echoed = tokio::time::timeout(Duration::from_secs(5), ws.next())
        .await
        .expect("echo arrives")
        .expect("a frame")
        .expect("frame ok");
    assert_eq!(echoed.to_text().expect("text frame"), "ping-inject");

    // The appended message is marked injected and the returned index points at it.
    let flow = ws_flow(h.store.as_ref()).expect("ws flow");
    let msg = flow
        .messages
        .get(index)
        .expect("returned index points at a message");
    assert!(msg.injected, "the injected frame is marked injected");
    assert_eq!(msg.data, b"ping-inject");

    ws.close(None).await.ok();
}

// --- AC-F9.3 (Review focus #3) -----------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ws_send_out_of_scope_refused() {
    let echo = spawn_echo().await;
    let h = run_proxy().await;

    let mut ws = ws_through_proxy(h.addr, echo).await;
    let id = wait_for_ws_flow(h.store.as_ref()).await;

    // Out of scope → refused, naming the host, with no frame injected.
    let guard = guard_with_scope(&[]);
    let err = invoke(
        &h.reg,
        h.store.as_ref(),
        guard.as_ref(),
        "ws.send",
        send_args(id, "c2s", "text", "nope"),
    )
    .expect_err("ws.send is refused out of scope");
    assert!(
        err.to_string().contains("127.0.0.1"),
        "refusal must name the host: {err}"
    );
    let flow = ws_flow(h.store.as_ref()).expect("ws flow");
    assert!(
        flow.messages.iter().all(|m| !m.injected),
        "a refused inject must not append a frame"
    );

    // After scope.add of the host, the same inject succeeds and reaches upstream.
    guard.add_scope(ScopeEntry {
        host: "127.0.0.1".to_string(),
    });
    invoke(
        &h.reg,
        h.store.as_ref(),
        guard.as_ref(),
        "ws.send",
        send_args(id, "c2s", "text", "now-allowed"),
    )
    .expect("ws.send succeeds once in scope");

    let echoed = tokio::time::timeout(Duration::from_secs(5), ws.next())
        .await
        .expect("echo arrives")
        .expect("a frame")
        .expect("frame ok");
    assert_eq!(echoed.to_text().expect("text frame"), "now-allowed");

    let flow = ws_flow(h.store.as_ref()).expect("ws flow");
    assert!(
        flow.messages
            .iter()
            .any(|m| m.injected && m.data == b"now-allowed"),
        "the permitted inject is recorded"
    );

    ws.close(None).await.ok();
}
