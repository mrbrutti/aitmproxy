//! `aitm web` `/bus` concurrency: a long-running command on one connection must
//! not freeze the rest of that connection. The web UI polls `flow.list` every
//! 500 ms on the same socket as a `scan.discover` that can run for minutes.
//!
//! The contract these tests pin:
//!
//! - frames run **concurrently** — a slow `tools/call` does not delay the reply to a
//!   fast request sent after it on the same socket, including a request that shares
//!   the token's frame;
//! - lines batched in **one** frame run and answer in order (a frame is the unit of
//!   work), and a frame may carry at most 256 lines: a longer one closes the
//!   connection with `Size` before any of its lines runs;
//! - at most `MAX_IN_FLIGHT` frames are in flight per connection; further frames
//!   wait unread (TCP backpressure) and none is lost;
//! - a command that panics ends its own connection only; a client Close is seen
//!   while a command is still parked, and the parked command then runs to completion.
//!
//! Hermetic: the commands under test are in-process test commands (`test.block`,
//! `test.sleep`, `test.tick`, `test.panic`) registered through the scripting wiring's
//! command-provider slot; `flow.list` is the real one. No browser, no network
//! beyond loopback.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, SystemTime};

use aitm::web::bridge::MAX_IN_FLIGHT;
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
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::{Error as WsError, Message};
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};

const AGENT_TOKEN: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
/// Generous bound for anything that is expected to happen.
const TIMEOUT: Duration = Duration::from_secs(10);
/// Short bound for something that must happen while a sibling command is still
/// parked: long enough for a loaded machine to serve one `flow.list` or notice a
/// close, short enough that a bridge that waits for the command fails the test.
const FAST: Duration = Duration::from_secs(5);
/// How long a bridge that ignores the in-flight cap is given to start more
/// commands before the cap is asserted.
const SETTLE: Duration = Duration::from_millis(200);
/// How long `test.sleep` holds its blocking thread.
const SLEEP: Duration = Duration::from_millis(100);
/// The most a parked `test.block` waits for the test to release it. The test
/// releases it (a panicking test releases it on unwind); this only stops a wedged
/// run from pinning the runtime's blocking pool at shutdown.
const BLOCK_LIMIT: Duration = Duration::from_secs(30);
/// The most request lines one frame may carry: the contract figure, the same as
/// `MAX_BATCH_LEN` in the MCP HTTP transport, pinned here as a literal.
const MAX_LINES_PER_FRAME: u64 = 256;

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

/// What `test.block` parks on: a one-shot latch that stays open once opened, so
/// any number of parked commands are released together, and a count of how many
/// have started and finished.
struct Parking {
    open: Mutex<bool>,
    opened: Condvar,
    entered: AtomicUsize,
    completed: AtomicUsize,
}

impl Parking {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            open: Mutex::new(false),
            opened: Condvar::new(),
            entered: AtomicUsize::new(0),
            completed: AtomicUsize::new(0),
        })
    }

    fn entered(&self) -> usize {
        self.entered.load(Ordering::SeqCst)
    }

    fn completed(&self) -> usize {
        self.completed.load(Ordering::SeqCst)
    }

    fn open(&self) {
        // A poisoned latch is still a latch: open it so no command stays parked.
        let mut open = self.open.lock().unwrap_or_else(|e| e.into_inner());
        *open = true;
        self.opened.notify_all();
    }

    /// Block the calling thread until the latch opens, or [`BLOCK_LIMIT`] passes.
    fn park(&self) -> anyhow::Result<()> {
        let open = self
            .open
            .lock()
            .map_err(|_| anyhow::anyhow!("parking latch poisoned"))?;
        let (_open, timed_out) = self
            .opened
            .wait_timeout_while(open, BLOCK_LIMIT, |open| !*open)
            .map_err(|_| anyhow::anyhow!("parking latch poisoned"))?;
        anyhow::ensure!(!timed_out.timed_out(), "test.block was never released");
        Ok(())
    }
}

/// Opens the latch on [`Release::release`] or when dropped, so a test that
/// panics still wakes every parked blocking thread.
struct Release(Arc<Parking>);

impl Release {
    fn release(&self) {
        self.0.open();
    }
}

impl Drop for Release {
    fn drop(&mut self) {
        self.0.open();
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
struct BlockCmd(Arc<Parking>);

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
        self.0.entered.fetch_add(1, Ordering::SeqCst);
        self.0.park()?;
        self.0.completed.fetch_add(1, Ordering::SeqCst);
        Ok(Value::Str("released".into()))
    }
}

/// `test.sleep`: holds its blocking thread for [`SLEEP`], then replies.
struct SleepCmd;

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
        std::thread::sleep(SLEEP);
        Ok(Value::Str("slept".into()))
    }
}

/// `test.tick`: counts its invocations, so a test can tell whether a line ran.
struct TickCmd(Arc<AtomicUsize>);

impl Command for TickCmd {
    fn name(&self) -> &str {
        "test.tick"
    }
    fn sensitivity(&self) -> Sensitivity {
        Sensitivity::Read
    }
    fn schema(&self) -> ParamSchema {
        str_schema("Counts one invocation, then replies.")
    }
    fn invoke(&self, _args: Params, _host: &CommandHost) -> anyhow::Result<Value> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(Value::Str("ticked".into()))
    }
}

/// `test.panic`: a command that panics.
struct PanicCmd;

impl Command for PanicCmd {
    fn name(&self) -> &str {
        "test.panic"
    }
    fn sensitivity(&self) -> Sensitivity {
        Sensitivity::Read
    }
    fn schema(&self) -> ParamSchema {
        str_schema("Panics.")
    }
    fn invoke(&self, _args: Params, _host: &CommandHost) -> anyhow::Result<Value> {
        panic!("test.panic: deliberate panic in a command");
    }
}

/// The test commands and the state a test reads back from them.
#[derive(Clone)]
struct TestCommands {
    parking: Arc<Parking>,
    ticks: Arc<AtomicUsize>,
}

impl TestCommands {
    fn new() -> Self {
        Self {
            parking: Parking::new(),
            ticks: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// The guard that releases `test.block`; hold it for the whole test.
    fn release_guard(&self) -> Release {
        Release(self.parking.clone())
    }

    fn ticks(&self) -> usize {
        self.ticks.load(Ordering::SeqCst)
    }
}

impl Plugin for TestCommands {
    fn name(&self) -> &str {
        "web-bus-concurrency-test"
    }
    fn load(&mut self, reg: &mut Registry) {
        reg.add_command(Arc::new(BlockCmd(self.parking.clone())));
        reg.add_command(Arc::new(SleepCmd));
        reg.add_command(Arc::new(TickCmd(self.ticks.clone())));
        reg.add_command(Arc::new(PanicCmd));
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
async fn start(tag: &str, commands: &TestCommands) -> Server {
    let mut cfg = Config::default();
    cfg.ca.dir = temp_ca_dir(tag);
    let scripts = ScriptWiring {
        commands: vec![Box::new(commands.clone())],
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

/// Everything a socket yielded until its stream ended or a bound passed.
struct Drained {
    /// The text frames received before the end.
    replies: Vec<String>,
    /// The code of the Close frame, when the stream ended with one.
    close_code: Option<CloseCode>,
    /// The stream ended — a Close frame, end of stream, or a connection reset —
    /// before the bound elapsed.
    ended: bool,
}

/// Read until the stream ends or `bound` elapses. Unlike [`recv_text`] this
/// treats any error as the end of the stream: the callers are waiting for the
/// server to drop the connection, cleanly or not, and must not panic when it does.
async fn drain_until_end(ws: &mut Ws, bound: Duration) -> Drained {
    let deadline = tokio::time::Instant::now() + bound;
    let mut out = Drained {
        replies: Vec::new(),
        close_code: None,
        ended: false,
    };
    loop {
        match tokio::time::timeout_at(deadline, ws.next()).await {
            Err(_) => return out,
            Ok(Some(Ok(Message::Text(text)))) => out.replies.push(text.to_string()),
            Ok(Some(Ok(Message::Close(frame)))) => {
                out.close_code = frame.map(|f| f.code);
                out.ended = true;
                return out;
            }
            Ok(Some(Ok(_))) => {}
            Ok(Some(Err(_))) | Ok(None) => {
                out.ended = true;
                return out;
            }
        }
    }
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
    let commands = TestCommands::new();
    let release = commands.release_guard();
    let server = start("slow", &commands).await;
    let mut ws = open_bus(&server).await;

    // id 1 parks inside `test.block`; wait until it really is running there, so
    // id 2 is sent while id 1 is provably still in flight.
    send_text(&mut ws, call_line(1, "test.block")).await;
    wait_until("test.block to start", || commands.parking.entered() == 1).await;
    send_text(&mut ws, call_line(2, "flow.list")).await;

    // The fast request is answered while the slow one is still blocked.
    let fast = tokio::time::timeout(FAST, recv_json(&mut ws))
        .await
        .expect("the flow.list reply must arrive while test.block is still parked");
    assert_eq!(fast["id"], 2, "the first reply is flow.list's: {fast}");
    assert_eq!(fast["result"]["isError"], false, "{fast}");
    assert_eq!(fast["result"]["structuredContent"], json!([]), "{fast}");

    // Release the slow command; its reply then arrives.
    release.release();
    let slow = recv_json(&mut ws).await;
    assert_eq!(slow["id"], 1, "the second reply is test.block's: {slow}");
    assert_eq!(slow["result"]["isError"], false, "{slow}");
    assert_eq!(slow["result"]["structuredContent"], json!("released"));
}

#[tokio::test]
async fn a_request_sharing_the_token_frame_does_not_block_later_frames() {
    let commands = TestCommands::new();
    let release = commands.release_guard();
    let server = start("token-frame", &commands).await;
    let mut ws = ws_connect(&server).await;

    // The token line and a request that parks share the first frame; the request
    // is the first frame in flight.
    send_text(
        &mut ws,
        format!("{}\n{}", token_line(), call_line(1, "test.block")),
    )
    .await;
    wait_until("test.block to start", || commands.parking.entered() == 1).await;
    send_text(&mut ws, call_line(2, "flow.list")).await;

    let fast = tokio::time::timeout(FAST, recv_json(&mut ws))
        .await
        .expect("the flow.list reply must arrive while test.block is still parked");
    assert_eq!(fast["id"], 2, "the first reply is flow.list's: {fast}");
    assert_eq!(fast["result"]["structuredContent"], json!([]), "{fast}");

    release.release();
    let slow = recv_json(&mut ws).await;
    assert_eq!(slow["id"], 1, "the second reply is test.block's: {slow}");
    assert_eq!(slow["result"]["structuredContent"], json!("released"));
}

#[tokio::test]
async fn lines_in_one_frame_still_answer_in_order() {
    let commands = TestCommands::new();
    let server = start("order", &commands).await;
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
    // A later frame runs concurrently with the batch, so its reply may arrive
    // before or after the batch's replies.
    send_text(&mut ws, call_line(12, "flow.list")).await;

    let mut replies = Vec::new();
    for _ in 0..3 {
        let reply = recv_json(&mut ws).await;
        let id = reply["id"].as_u64().expect("numeric id");
        replies.push((id, reply["result"]["structuredContent"].clone()));
    }
    let position = |id: u64| {
        replies
            .iter()
            .position(|(i, _)| *i == id)
            .unwrap_or_else(|| panic!("id {id} was never answered, got {replies:?}"))
    };
    assert!(
        position(10) < position(11),
        "the batch's replies must stay in order, got {replies:?}"
    );
    replies.sort_by_key(|(id, _)| *id);
    assert_eq!(
        replies,
        vec![(10, json!("slept")), (11, json!([])), (12, json!([]))],
        "every request answered once, with its own result"
    );
}

#[tokio::test]
async fn at_most_the_cap_run_at_once_and_no_frame_is_lost() {
    let commands = TestCommands::new();
    let release = commands.release_guard();
    let server = start("cap", &commands).await;
    let mut ws = open_bus(&server).await;

    // Well over the cap, every frame parked, sent back-to-back without reading.
    const FRAMES: u64 = MAX_IN_FLIGHT as u64 * 2 + 8;
    for id in 1..=FRAMES {
        send_text(&mut ws, call_line(id, "test.block")).await;
    }

    // The cap fills, and then — with more frames queued — does not overflow.
    wait_until("the in-flight cap to fill", || {
        commands.parking.entered() >= MAX_IN_FLIGHT
    })
    .await;
    tokio::time::sleep(SETTLE).await;
    assert_eq!(
        commands.parking.entered(),
        MAX_IN_FLIGHT,
        "exactly the cap may run at once while every command is parked"
    );

    // Releasing them lets the queued frames through; each is answered once.
    release.release();
    let mut ids = Vec::new();
    for _ in 0..FRAMES {
        let reply = recv_json(&mut ws).await;
        assert_eq!(reply["result"]["structuredContent"], json!("released"));
        ids.push(reply["id"].as_u64().expect("numeric id"));
    }
    ids.sort_unstable();
    assert_eq!(
        ids,
        (1..=FRAMES).collect::<Vec<_>>(),
        "every frame answered exactly once"
    );
}

#[tokio::test]
async fn a_frame_of_exactly_the_line_cap_is_answered_in_full() {
    let commands = TestCommands::new();
    let server = start("lines-at-cap", &commands).await;
    let mut ws = open_bus(&server).await;

    let frame = (1..=MAX_LINES_PER_FRAME)
        .map(|id| call_line(id, "flow.list"))
        .collect::<Vec<_>>()
        .join("\n");
    send_text(&mut ws, frame).await;

    // One reply per line, one text frame each, in the order the lines were sent.
    for id in 1..=MAX_LINES_PER_FRAME {
        let reply = recv_json(&mut ws).await;
        assert_eq!(reply["id"], id, "replies stay in line order: {reply}");
        assert_eq!(reply["result"]["structuredContent"], json!([]), "{reply}");
    }
}

#[tokio::test]
async fn a_frame_over_the_line_cap_closes_the_connection_and_runs_nothing() {
    let commands = TestCommands::new();
    let server = start("lines-over-cap", &commands).await;
    let mut ws = open_bus(&server).await;

    let frame = (1..=MAX_LINES_PER_FRAME + 1)
        .map(|id| call_line(id, "test.tick"))
        .collect::<Vec<_>>()
        .join("\n");
    send_text(&mut ws, frame).await;

    // The connection is closed — a Close frame or an abrupt reset, either is the
    // server dropping it — and not one of the frame's lines was answered or run.
    let drained = drain_until_end(&mut ws, FAST).await;
    assert!(
        drained.ended,
        "an oversized frame must close the connection; it answered {} lines instead",
        drained.replies.len()
    );
    assert!(
        drained.replies.is_empty(),
        "no line of an oversized frame may be answered, got {:?}",
        drained.replies
    );
    if let Some(code) = drained.close_code {
        assert_eq!(code, CloseCode::Size, "the Close frame says why");
    }
    assert_eq!(commands.ticks(), 0, "no line of an oversized frame may run");
}

#[tokio::test]
async fn a_panicking_command_ends_only_its_own_connection() {
    let commands = TestCommands::new();
    let server = start("panic", &commands).await;
    let mut ws = open_bus(&server).await;

    send_text(&mut ws, call_line(1, "test.panic")).await;
    let drained = drain_until_end(&mut ws, FAST).await;
    assert!(drained.ended, "a panicking command must end its connection");
    assert!(
        drained.replies.is_empty(),
        "a panicked line has no reply, got {:?}",
        drained.replies
    );

    // The server and its other connections are untouched.
    let mut other = open_bus(&server).await;
    send_text(&mut other, call_line(2, "flow.list")).await;
    let reply = recv_json(&mut other).await;
    assert_eq!(reply["id"], 2, "{reply}");
    assert_eq!(reply["result"]["structuredContent"], json!([]), "{reply}");
}

#[tokio::test]
async fn a_client_close_is_seen_while_a_command_is_parked() {
    let commands = TestCommands::new();
    let release = commands.release_guard();
    let server = start("close", &commands).await;
    let mut ws = open_bus(&server).await;

    send_text(&mut ws, call_line(1, "test.block")).await;
    wait_until("test.block to start", || commands.parking.entered() == 1).await;

    // The client closes while the command is still parked; the bridge notices at
    // once rather than after the command, and the stream ends.
    ws.close(None).await.expect("client close");
    let drained = drain_until_end(&mut ws, FAST).await;
    assert!(
        drained.ended,
        "the close must be observed while test.block is still parked"
    );
    assert!(
        drained.replies.is_empty(),
        "no reply may arrive after the close, got {:?}",
        drained.replies
    );

    // The parked command cannot be cancelled: once released it runs to completion
    // on its own, and its reply is dropped with the connection.
    assert_eq!(commands.parking.completed(), 0);
    release.release();
    wait_until("the detached test.block to run to completion", || {
        commands.parking.completed() == 1
    })
    .await;
}
