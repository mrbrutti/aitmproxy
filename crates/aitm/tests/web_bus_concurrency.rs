//! `aitm web` `/bus` concurrency (fast-follow #1): a long-running command on one
//! connection must not freeze the rest of that connection.
//!
//! The bridge used to run every line inline in its read loop, so while
//! `scan.discover` ran (up to its 600 s budget) the socket read nothing: the web
//! UI's 500 ms `flow.list` polls, queued behind it on the same socket, all stalled.
//! The contract these tests pin:
//!
//! - frames run **concurrently** — a slow `tools/call` does not delay the reply to a
//!   fast request sent after it on the same socket;
//! - lines batched in **one** frame still run and answer in order (a frame is the
//!   unit of work);
//! - at most 16 frames are in flight per connection; further frames wait unread
//!   (TCP backpressure) and none is lost.
//!
//! Hermetic: the slow commands are in-process test commands (`test.block`,
//! `test.sleep`) registered through the scripting wiring's command-provider slot;
//! `flow.list` is the real one. No browser, no network beyond loopback.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, SystemTime};

use aitm::web::{self, WebState};
use aitm::wire::{assemble_with_scripts, Assembled, Features, ScriptWiring};
use aitm_core::{
    Command, CommandHost, Config, HttpFlow, HttpRequest, McpTransport, ParamSchema, Params, Plugin,
    ProxyClient, Registry, Sensitivity, TypeDesc, Value,
};
use aitm_mcp::McpServer;
use futures::future::BoxFuture;
use futures::{SinkExt as _, StreamExt as _};
use serde_json::{json, Value as JsonValue};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;
use tokio_tungstenite::tungstenite::{Error as WsError, Message};
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};

const AGENT_TOKEN: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
/// Generous bound for anything that is expected to happen.
const TIMEOUT: Duration = Duration::from_secs(10);
/// Short bound for a reply that must arrive while a sibling command is still parked.
/// The unfixed bridge never produces it (the release comes only afterwards), so this
/// only has to be long enough for a loaded machine to serve one `flow.list`.
const FAST: Duration = Duration::from_secs(5);
/// How long `test.sleep` holds its blocking thread.
const SLEEP: Duration = Duration::from_millis(100);
/// The most a parked `test.block` may wait for the test to release it. The test
/// releases it (or drops the sender on a panic, which wakes it at once); this only
/// stops a wedged run from pinning the runtime's blocking pool at shutdown.
const BLOCK_LIMIT: Duration = Duration::from_secs(30);
/// The per-connection in-flight cap (the bridge's `MAX_IN_FLIGHT`, spec requirement 3).
const IN_FLIGHT_CAP: usize = 16;

fn temp_ca_dir(tag: &str) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("aitm-web-concurrency-{tag}-{nanos}-{n}"))
}

/// A `ProxyClient` nothing in these tests invokes.
struct UnusedClient;
impl ProxyClient for UnusedClient {
    fn send(&self, _req: HttpRequest) -> BoxFuture<'_, anyhow::Result<HttpFlow>> {
        Box::pin(async { anyhow::bail!("not called") })
    }
}

/// What the test commands report to, and wait on, the test body.
struct Gate {
    /// `test.block` parks on this until the test sends `()`; dropping the sender
    /// wakes it too.
    release: Mutex<mpsc::Receiver<()>>,
    /// `test.block` has started running (it is parked, or about to be).
    entered: AtomicBool,
    /// `test.block` returned: it was released.
    finished: AtomicBool,
    /// `test.sleep` invocations running right now.
    sleeping: AtomicUsize,
    /// The most `test.sleep` invocations ever running at once.
    peak_sleeping: AtomicUsize,
}

impl Gate {
    fn new() -> (Arc<Self>, mpsc::Sender<()>) {
        let (tx, rx) = mpsc::channel();
        let gate = Arc::new(Self {
            release: Mutex::new(rx),
            entered: AtomicBool::new(false),
            finished: AtomicBool::new(false),
            sleeping: AtomicUsize::new(0),
            peak_sleeping: AtomicUsize::new(0),
        });
        (gate, tx)
    }
}

fn str_schema(description: &str) -> ParamSchema {
    ParamSchema {
        description: description.into(),
        params: vec![],
        result: TypeDesc::Str,
    }
}

/// `test.block`: a synchronous `invoke` that parks until the test releases it.
struct BlockCmd(Arc<Gate>);

impl Command for BlockCmd {
    fn name(&self) -> &str {
        "test.block"
    }
    fn sensitivity(&self) -> Sensitivity {
        Sensitivity::Read
    }
    fn schema(&self) -> ParamSchema {
        str_schema("Parks until the test releases it.")
    }
    fn invoke(&self, _args: Params, _host: &CommandHost) -> anyhow::Result<Value> {
        self.0.entered.store(true, Ordering::SeqCst);
        let release = self
            .0
            .release
            .lock()
            .map_err(|_| anyhow::anyhow!("release gate poisoned"))?;
        release
            .recv_timeout(BLOCK_LIMIT)
            .map_err(|e| anyhow::anyhow!("test.block was never released: {e}"))?;
        self.0.finished.store(true, Ordering::SeqCst);
        Ok(Value::Str("released".into()))
    }
}

/// `test.sleep`: holds its blocking thread for [`SLEEP`], recording how many
/// invocations overlap.
struct SleepCmd(Arc<Gate>);

impl Command for SleepCmd {
    fn name(&self) -> &str {
        "test.sleep"
    }
    fn sensitivity(&self) -> Sensitivity {
        Sensitivity::Read
    }
    fn schema(&self) -> ParamSchema {
        str_schema("Sleeps briefly, then replies.")
    }
    fn invoke(&self, _args: Params, _host: &CommandHost) -> anyhow::Result<Value> {
        let now = self.0.sleeping.fetch_add(1, Ordering::SeqCst) + 1;
        self.0.peak_sleeping.fetch_max(now, Ordering::SeqCst);
        std::thread::sleep(SLEEP);
        self.0.sleeping.fetch_sub(1, Ordering::SeqCst);
        Ok(Value::Str("slept".into()))
    }
}

struct TestCommands(Arc<Gate>);

impl Plugin for TestCommands {
    fn name(&self) -> &str {
        "web-bus-concurrency-test"
    }
    fn load(&mut self, reg: &mut Registry) {
        reg.add_command(Arc::new(BlockCmd(self.0.clone())));
        reg.add_command(Arc::new(SleepCmd(self.0.clone())));
    }
}

struct Server {
    addr: std::net::SocketAddr,
    task: tokio::task::JoinHandle<anyhow::Result<()>>,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// A served `aitm web` over the real wired registry plus the test commands.
async fn start(tag: &str, gate: Arc<Gate>) -> Server {
    let mut cfg = Config::default();
    cfg.ca.dir = temp_ca_dir(tag);
    let scripts = ScriptWiring {
        commands: vec![Box::new(TestCommands(gate))],
        ..ScriptWiring::default()
    };
    let Assembled { proxy, .. } =
        assemble_with_scripts(&cfg, &Features::default(), scripts).expect("assemble");
    let client: Arc<dyn ProxyClient> = Arc::new(UnusedClient);
    let mcp = McpServer::new(proxy.registry_arc(), McpTransport::Stdio).with_services(
        proxy.store(),
        client,
        proxy.guard(),
        None,
    );
    let state = Arc::new(WebState {
        mcp: Arc::new(mcp),
        agent_token: AGENT_TOKEN.to_owned(),
        operator_token: None,
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("local addr");
    let task = tokio::spawn(web::serve(listener, state));
    Server { addr, task }
}

type Ws = WebSocketStream<MaybeTlsStream<TcpStream>>;

async fn ws_connect(server: &Server) -> Ws {
    let req = format!("ws://{}/bus", server.addr)
        .into_client_request()
        .expect("client request");
    let (ws, _) = tokio::time::timeout(TIMEOUT, connect_async(req))
        .await
        .expect("handshake within the timeout")
        .expect("handshake");
    ws
}

async fn send_text(ws: &mut Ws, text: impl Into<String>) {
    ws.send(Message::text(text.into())).await.expect("send");
}

/// The next text frame; `None` when the stream closed first.
async fn recv_text(ws: &mut Ws) -> Option<String> {
    loop {
        let next = tokio::time::timeout(TIMEOUT, ws.next())
            .await
            .expect("frame within the timeout");
        match next {
            Some(Ok(Message::Text(t))) => return Some(t.to_string()),
            Some(Ok(Message::Close(_))) | None => return None,
            Some(Ok(_)) => continue,
            Some(Err(WsError::ConnectionClosed)) | Some(Err(WsError::AlreadyClosed)) => {
                return None
            }
            Some(Err(e)) => panic!("websocket error: {e}"),
        }
    }
}

async fn recv_json(ws: &mut Ws) -> JsonValue {
    let text = recv_text(ws).await.expect("a text frame");
    serde_json::from_str(&text).expect("reply is JSON")
}

/// The token line, as its own frame (the way the web client authenticates).
fn token_line() -> String {
    json!({ "token": AGENT_TOKEN }).to_string()
}

/// A `tools/call` request line for `name` with no arguments.
fn call_line(id: u64, name: &str) -> String {
    json!({"jsonrpc": "2.0", "id": id, "method": "tools/call",
           "params": {"name": name, "arguments": {}}})
    .to_string()
}

/// Open the bus: connect, send the token, and `initialize`.
async fn open_bus(server: &Server) -> Ws {
    let mut ws = ws_connect(server).await;
    send_text(&mut ws, token_line()).await;
    send_text(
        &mut ws,
        json!({"jsonrpc": "2.0", "id": 0, "method": "initialize",
               "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                          "clientInfo": {"name": "aitm-web", "version": "0"}}})
        .to_string(),
    )
    .await;
    let init = recv_json(&mut ws).await;
    assert_eq!(init["id"], 0, "initialize reply: {init}");
    ws
}

/// Poll `cond` until it holds; panic after [`TIMEOUT`].
async fn wait_until(what: &str, cond: impl Fn() -> bool) {
    let deadline = tokio::time::Instant::now() + TIMEOUT;
    while !cond() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for {what}"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test]
async fn slow_command_does_not_block_the_connection() {
    let (gate, release) = Gate::new();
    let server = start("slow", gate.clone()).await;
    let mut ws = open_bus(&server).await;

    // id 1 parks inside `test.block`; wait until it really is running there, so
    // id 2 is sent while id 1 is provably still in flight.
    send_text(&mut ws, call_line(1, "test.block")).await;
    wait_until("test.block to start", || {
        gate.entered.load(Ordering::SeqCst)
    })
    .await;
    send_text(&mut ws, call_line(2, "flow.list")).await;

    // The fast request is answered while the slow one is still blocked.
    let fast = tokio::time::timeout(FAST, recv_json(&mut ws))
        .await
        .expect("the flow.list reply must arrive while test.block is still parked");
    assert_eq!(fast["id"], 2, "the first reply is flow.list's: {fast}");
    assert_eq!(fast["result"]["isError"], false, "{fast}");
    assert_eq!(fast["result"]["structuredContent"], json!([]), "{fast}");
    assert!(
        !gate.finished.load(Ordering::SeqCst),
        "test.block must still be parked when flow.list is answered"
    );

    // Release the slow command; its reply then arrives.
    release.send(()).expect("release test.block");
    let slow = recv_json(&mut ws).await;
    assert_eq!(slow["id"], 1, "the second reply is test.block's: {slow}");
    assert_eq!(slow["result"]["isError"], false, "{slow}");
    assert_eq!(slow["result"]["structuredContent"], json!("released"));
}

#[tokio::test]
async fn lines_in_one_frame_still_answer_in_order() {
    let (gate, _release) = Gate::new();
    let server = start("order", gate).await;
    let mut ws = open_bus(&server).await;

    // One frame, a slow line first and a fast line second: the replies must come
    // back slow-then-fast even though the fast line is quicker. A single frame is
    // the unit of work, so its lines run one after another.
    let batch = format!(
        "{}\n{}\n",
        call_line(10, "test.sleep"),
        call_line(11, "flow.list")
    );
    send_text(&mut ws, batch).await;
    // A later frame races the batch; it may be answered at any point, but never
    // between the batch's own lines being reordered.
    send_text(&mut ws, call_line(12, "flow.list")).await;

    let mut ids = Vec::new();
    for _ in 0..3 {
        ids.push(recv_json(&mut ws).await["id"].as_u64().expect("numeric id"));
    }
    let at = |id: u64| {
        ids.iter()
            .position(|&i| i == id)
            .unwrap_or_else(|| panic!("id {id} was never answered, got {ids:?}"))
    };
    assert!(
        at(10) < at(11),
        "the batch's replies must stay in order, got {ids:?}"
    );
    let mut sorted = ids.clone();
    sorted.sort_unstable();
    assert_eq!(sorted, vec![10, 11, 12], "every request answered once");
}

#[tokio::test]
async fn more_frames_than_the_cap_are_all_answered() {
    let (gate, _release) = Gate::new();
    let server = start("cap", gate.clone()).await;
    let mut ws = ws_connect(&server).await;

    // 40 slow frames back-to-back without reading: well over the cap of 16. The
    // first frame carries the token line too, so its request is the first one in
    // flight (the lines that share the token's frame).
    const FRAMES: u64 = 40;
    send_text(
        &mut ws,
        format!("{}\n{}", token_line(), call_line(1, "test.sleep")),
    )
    .await;
    for id in 2..=FRAMES {
        send_text(&mut ws, call_line(id, "test.sleep")).await;
    }

    let mut ids = Vec::new();
    for _ in 0..FRAMES {
        let reply = recv_json(&mut ws).await;
        assert_eq!(reply["result"]["structuredContent"], json!("slept"));
        ids.push(reply["id"].as_u64().expect("numeric id"));
    }
    ids.sort_unstable();
    assert_eq!(
        ids,
        (1..=FRAMES).collect::<Vec<_>>(),
        "every frame answered exactly once"
    );

    // The frames really ran concurrently, and never more than the cap at once.
    let peak = gate.peak_sleeping.load(Ordering::SeqCst);
    assert!(
        peak > 1,
        "frames must run concurrently, but at most {peak} ever overlapped"
    );
    assert!(
        peak <= IN_FLIGHT_CAP,
        "at most {IN_FLIGHT_CAP} frames may be in flight, but {peak} overlapped"
    );
}
