//! Shared harness for the `web_bus_*` suites of the `aitm web` `/bus` bridge: one
//! served `aitm web` over the real wired registry plus a few in-process test
//! commands, a websocket client, and the receive and probe helpers the suites
//! build their assertions from.
//!
//! Including files declare it the way the `rig` and `scripted_driver` modules are
//! declared (not through `support/mod.rs`):
//!
//! ```ignore
//! #[path = "support/web_bus.rs"]
//! #[allow(dead_code)]
//! mod web_bus;
//! ```
//!
//! Where a suite needs a different signature or a stricter check it keeps a thin
//! file-local wrapper around the item here (`web_bus_concurrency`'s `open_bus`
//! asserts that the `initialize` reply is the first frame instead of skipping
//! ahead to it). The suites assert on roles and behaviour, never on the token
//! values, so one token pair serves them all.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, SystemTime};

use aitm::web::{self, WebState};
use aitm::wire::{assemble_with_scripts, Assembled, Features, ScriptWiring};
use aitm_core::{
    AgentPolicy, Body, Command, CommandHost, Config, ConnInfo, Event, Flow, FlowId, FlowMeta,
    FlowStore, HeaderMap, HttpFlow, HttpRequest, HttpVersion, InterceptState, McpTransport,
    ParamSchema, Params, Plugin, ProxyClient, Registry, Sensitivity, TypeDesc, Value,
};
use aitm_mcp::{ConnCtx, McpServer};
use futures::future::BoxFuture;
use futures::{SinkExt as _, StreamExt as _};
use serde_json::{json, Value as JsonValue};
use tokio::net::TcpStream;
use tokio::sync::broadcast;
use tokio::time::Instant;
use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::{Error as WsError, Message};
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};

pub const AGENT_TOKEN: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
pub const OPERATOR_TOKEN: &str = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
/// Generous bound for anything that is expected to happen.
pub const TIMEOUT: Duration = Duration::from_secs(10);
/// Short bound for something that must happen while a sibling command is still
/// parked: long enough for a loaded machine, short enough that a bridge that
/// waits for the command fails the test.
pub const FAST: Duration = Duration::from_secs(5);
/// How long to listen for a frame that must not arrive.
pub const QUIET: Duration = Duration::from_millis(500);
/// How long the server is given to notice a close and tear the connection down.
pub const SETTLE: Duration = Duration::from_millis(200);
/// The `Ask` approval timeout in these tests: a parked probe returns after this,
/// a refused one at once, so the two outcomes are told apart by their reason and,
/// generously, by their elapsed time.
pub const APPROVAL_TIMEOUT: Duration = Duration::from_secs(1);
/// The most a parked `test.block` waits for the test to release it. The test
/// releases it (a panicking test releases it on unwind); this only stops a wedged
/// run from pinning the runtime's blocking pool at shutdown.
const BLOCK_LIMIT: Duration = Duration::from_secs(30);
/// How long `test.sleep` holds its blocking thread.
const SLEEP: Duration = Duration::from_millis(100);
/// The reason `park_for_approval` gives when it refuses at once for want of a
/// subscribed operator (no park).
pub const NO_OPERATOR: &str = "no operator is connected to approve it";
/// The reason it gives when the call did park and nobody approved in time.
pub const PARKED_TIMED_OUT: &str =
    "no operator approved the parked sensitive command within the approval timeout";

/// A fresh, unique CA directory under the system temp dir for one test's server.
fn temp_ca_dir(tag: &str) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("aitm-web-bus-{tag}-{nanos}-{n}"))
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
pub struct Parking {
    open: Mutex<bool>,
    opened: Condvar,
    entered: AtomicUsize,
    completed: AtomicUsize,
}

impl Parking {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            open: Mutex::new(false),
            opened: Condvar::new(),
            entered: AtomicUsize::new(0),
            completed: AtomicUsize::new(0),
        })
    }

    pub fn entered(&self) -> usize {
        self.entered.load(Ordering::SeqCst)
    }

    pub fn completed(&self) -> usize {
        self.completed.load(Ordering::SeqCst)
    }

    pub fn open(&self) {
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
pub struct Release(Arc<Parking>);

impl Release {
    pub fn release(&self) {
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

/// The size of the string `test.blob` returns: 1 MiB. A reply carries it twice (in
/// `structuredContent` and in the rendered `content` text, neither of which is
/// truncated), so one reply is a little over 2 MiB on the wire.
const BLOB_BYTES: usize = 1 << 20;

/// `test.blob`: replies with [`BLOB_BYTES`] bytes of text, so a test can make the
/// bridge's reply send site write far more than the socket buffers hold.
struct BlobCmd;

impl Command for BlobCmd {
    fn name(&self) -> &str {
        "test.blob"
    }
    fn sensitivity(&self) -> Sensitivity {
        Sensitivity::Read
    }
    fn schema(&self) -> ParamSchema {
        str_schema("Replies with 1 MiB of text.")
    }
    fn invoke(&self, _args: Params, _host: &CommandHost) -> anyhow::Result<Value> {
        Ok(Value::Str("b".repeat(BLOB_BYTES)))
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

/// `test.sensitive`: a `Sensitive` command, so an agent call under `Ask` parks for
/// operator approval. Counts how often it actually ran.
struct SensitiveCmd(Arc<AtomicUsize>);

impl Command for SensitiveCmd {
    fn name(&self) -> &str {
        "test.sensitive"
    }
    fn sensitivity(&self) -> Sensitivity {
        Sensitivity::Sensitive
    }
    fn schema(&self) -> ParamSchema {
        str_schema("A sensitive command; counts one run, then replies.")
    }
    fn invoke(&self, _args: Params, _host: &CommandHost) -> anyhow::Result<Value> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(Value::Str("ran".into()))
    }
}

/// The test commands and the state a test reads back from them.
#[derive(Clone)]
pub struct TestCommands {
    pub parking: Arc<Parking>,
    ticks: Arc<AtomicUsize>,
    sensitive_runs: Arc<AtomicUsize>,
    /// Whether `test.blob` and `test.sensitive` are registered (see
    /// [`TestCommands::without_extras`]).
    extras: bool,
}

impl TestCommands {
    pub fn new() -> Self {
        Self {
            parking: Parking::new(),
            ticks: Arc::new(AtomicUsize::new(0)),
            sensitive_runs: Arc::new(AtomicUsize::new(0)),
            extras: true,
        }
    }

    /// The same commands and shared state without `test.blob` and
    /// `test.sensitive`, for a suite that runs against exactly `test.block`,
    /// `test.sleep`, `test.tick` and `test.panic`.
    pub fn without_extras(&self) -> Self {
        Self {
            extras: false,
            ..self.clone()
        }
    }

    /// The guard that releases `test.block`; hold it for the whole test.
    pub fn release_guard(&self) -> Release {
        Release(self.parking.clone())
    }

    pub fn ticks(&self) -> usize {
        self.ticks.load(Ordering::SeqCst)
    }

    pub fn sensitive_runs(&self) -> usize {
        self.sensitive_runs.load(Ordering::SeqCst)
    }
}

impl Plugin for TestCommands {
    fn name(&self) -> &str {
        "web-bus-test"
    }
    fn load(&mut self, reg: &mut Registry) {
        reg.add_command(Arc::new(BlockCmd(self.parking.clone())));
        reg.add_command(Arc::new(SleepCmd));
        if self.extras {
            reg.add_command(Arc::new(BlobCmd));
        }
        reg.add_command(Arc::new(TickCmd(self.ticks.clone())));
        reg.add_command(Arc::new(PanicCmd));
        if self.extras {
            reg.add_command(Arc::new(SensitiveCmd(self.sensitive_runs.clone())));
        }
    }
}

/// How a test's server differs from the default one. Call sites use struct-update
/// syntax (`..ServerOptions::default()`), so a field added here later cannot break
/// them.
pub struct ServerOptions {
    /// The agent policy the server's gate reads (shared with the wired `AgentPlugin`).
    pub policy: AgentPolicy,
    pub approval_timeout: Duration,
    /// The per-connection push-sink capacity; `None` keeps the server default.
    pub push_capacity: Option<usize>,
    /// Feed the server the assembled core event broadcast and spawn its push
    /// dispatcher, exactly as `main.rs` wires the web server.
    pub dispatcher: bool,
    /// The operator bridge token; `None` leaves the operator role unconfigured, so
    /// the web UI is agent-only.
    pub operator_token: Option<String>,
    /// Hand the bridge's `McpServer` the assembled agent state and `approval_timeout`
    /// (`with_agent_state`, `with_approval_timeout`), as `main.rs` does. When
    /// `false`, the server is built without the wired agent gate, as the older
    /// suites run it: it keeps its own defaults, an `Auto` gate and the default
    /// approval timeout, and `policy` and `approval_timeout` do not reach the gate.
    pub wired_gate: bool,
    /// Register the `commands` passed to [`start`] through the scripting wiring.
    /// When `false`, the server assembles with an empty `ScriptWiring` (the plain
    /// `assemble`), for a suite that needs no test commands.
    pub test_commands: bool,
    /// The bridge's write deadline (`McpServer::with_write_timeout`); `None` keeps
    /// the server default.
    pub write_timeout: Option<Duration>,
    /// The listener's `SO_SNDBUF` in bytes, set before `bind` and `listen` so every
    /// accepted socket inherits it; `None` keeps the platform default. A small value
    /// makes the server's side of a stopped peer's socket fill quickly.
    pub send_buffer: Option<u32>,
}

impl Default for ServerOptions {
    fn default() -> Self {
        Self {
            policy: AgentPolicy::Auto,
            approval_timeout: APPROVAL_TIMEOUT,
            push_capacity: None,
            dispatcher: false,
            operator_token: Some(OPERATOR_TOKEN.to_owned()),
            wired_gate: true,
            test_commands: true,
            write_timeout: None,
            send_buffer: None,
        }
    }
}

pub struct Server {
    pub addr: SocketAddr,
    /// The bridge's `McpServer`, shared so a test can push events and probe the
    /// policy gate without a socket.
    pub mcp: Arc<McpServer>,
    pub store: Arc<dyn FlowStore>,
    /// The core event broadcast the `SubscriptionPlugin` feeds; a test sends on it
    /// to exercise the dispatcher.
    pub push_tx: broadcast::Sender<Event>,
    task: tokio::task::JoinHandle<anyhow::Result<()>>,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// A served `aitm web` over the real wired registry plus the test commands, with
/// the agent bridge token and, unless `opts` says otherwise, the operator one.
pub async fn start(tag: &str, commands: &TestCommands, opts: ServerOptions) -> Server {
    let mut cfg = Config::default();
    cfg.ca.dir = temp_ca_dir(tag);
    cfg.mcp.policy = opts.policy;
    let scripts = if opts.test_commands {
        ScriptWiring {
            commands: vec![Box::new(commands.clone())],
            ..ScriptWiring::default()
        }
    } else {
        ScriptWiring::default()
    };
    let Assembled {
        proxy,
        agent_state,
        push_tx,
        ..
    } = assemble_with_scripts(&cfg, &Features::default(), scripts).expect("assemble");
    let client: Arc<dyn ProxyClient> = Arc::new(UnusedClient);
    let store = proxy.store();
    let mut mcp = McpServer::new(proxy.registry_arc(), McpTransport::Stdio).with_services(
        store.clone(),
        client,
        proxy.guard(),
        None,
    );
    if opts.wired_gate {
        mcp = mcp
            .with_agent_state(agent_state)
            .with_approval_timeout(opts.approval_timeout);
    }
    if let Some(capacity) = opts.push_capacity {
        mcp = mcp.with_push_capacity(capacity);
    }
    if let Some(timeout) = opts.write_timeout {
        mcp = mcp.with_write_timeout(timeout);
    }
    if opts.dispatcher {
        mcp = mcp.with_push(push_tx.clone());
    }
    let mcp = Arc::new(mcp);
    if opts.dispatcher {
        mcp.spawn_push_dispatcher();
    }
    let state = Arc::new(WebState {
        mcp: mcp.clone(),
        agent_token: AGENT_TOKEN.to_owned(),
        operator_token: opts.operator_token,
    });
    let listener = match opts.send_buffer {
        // A `TcpSocket` is the only way to set `SO_SNDBUF` before `listen`, which
        // is what lets the accepted sockets inherit it.
        Some(size) => {
            let socket = tokio::net::TcpSocket::new_v4().expect("listener socket");
            socket.set_send_buffer_size(size).expect("send buffer size");
            socket
                .bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))
                .expect("bind");
            socket.listen(1024).expect("listen")
        }
        None => tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind"),
    };
    let addr = listener.local_addr().expect("local addr");
    let task = tokio::spawn(web::serve(listener, state));
    Server {
        addr,
        mcp,
        store,
        push_tx,
        task,
    }
}

/// A stored HTTP flow for `authority` and `path`, the shape the proxy would store.
pub fn http_flow(authority: &str, path: &str) -> Flow {
    let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
    Flow::Http(HttpFlow {
        id: FlowId::new(),
        request: HttpRequest {
            method: "GET".into(),
            scheme: "http".into(),
            authority: authority.into(),
            path: path.into(),
            version: HttpVersion::Http11,
            headers: HeaderMap::new(),
            body: Body::Empty,
            timestamp: SystemTime::now(),
        },
        response: None,
        client_conn: ConnInfo {
            peer: addr,
            sni: None,
            alpn: None,
            tls: false,
            established: SystemTime::now(),
        },
        server_conn: None,
        metadata: FlowMeta::default(),
        intercept: InterceptState::Observed,
    })
}

/// Store a flow and push its `RequestHeaders` event straight into the server (the
/// dispatcher's one call), returning the flow id.
pub fn push_flow(server: &Server, path: &str) -> FlowId {
    let id = server.store.insert(http_flow("example.com:443", path));
    server.mcp.push_flow_event(&Event::RequestHeaders(id));
    id
}

pub type Ws = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// Connect to the bus, handing back the handshake error instead of panicking on it.
/// A handshake that takes longer than [`TIMEOUT`] still panics.
pub async fn try_ws_connect(server: &Server) -> Result<Ws, WsError> {
    let req = format!("ws://{}/bus", server.addr)
        .into_client_request()
        .expect("client request");
    let (ws, _) = tokio::time::timeout(TIMEOUT, connect_async(req))
        .await
        .expect("handshake within the timeout")?;
    Ok(ws)
}

pub async fn ws_connect(server: &Server) -> Ws {
    try_ws_connect(server).await.expect("handshake")
}

pub async fn send_text(ws: &mut Ws, text: impl Into<String>) {
    ws.send(Message::text(text.into())).await.expect("send");
}

/// The next text frame, parsed; `None` when the stream ended first. Unbounded:
/// the caller puts a deadline on it.
pub async fn next_frame(ws: &mut Ws) -> Option<JsonValue> {
    loop {
        match ws.next().await {
            Some(Ok(Message::Text(t))) => {
                return Some(
                    serde_json::from_str(&t)
                        .unwrap_or_else(|e| panic!("a frame must be JSON ({e}): {t}")),
                )
            }
            Some(Ok(Message::Close(_))) | None => return None,
            Some(Ok(_)) => continue,
            Some(Err(WsError::ConnectionClosed)) | Some(Err(WsError::AlreadyClosed)) => {
                return None
            }
            Some(Err(e)) => panic!("websocket error: {e}"),
        }
    }
}

/// The next text frame as received; `None` when the stream closed first. Panics
/// when no frame arrives within [`TIMEOUT`].
pub async fn recv_text(ws: &mut Ws) -> Option<String> {
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

/// [`recv_text`], parsed; panics when the stream ended first.
pub async fn recv_json(ws: &mut Ws) -> JsonValue {
    let text = recv_text(ws).await.expect("a text frame");
    serde_json::from_str(&text).expect("reply is JSON")
}

/// The next text frame within `bound`; panics, naming `what`, when the bound
/// passes or the stream ends first.
pub async fn recv_within(ws: &mut Ws, bound: Duration, what: &str) -> JsonValue {
    match tokio::time::timeout(bound, next_frame(ws)).await {
        Ok(Some(frame)) => frame,
        Ok(None) => panic!("the stream ended while waiting for {what}"),
        Err(_) => panic!("no frame within {bound:?} while waiting for {what}"),
    }
}

/// Frames until one satisfies `pred`, within [`TIMEOUT`]. The frames skipped on
/// the way are in the failure message, so a wrong frame is diagnosable.
pub async fn recv_until(ws: &mut Ws, what: &str, pred: impl Fn(&JsonValue) -> bool) -> JsonValue {
    recv_until_collecting(ws, what, pred).await.0
}

/// [`recv_until`], also returning the frames skipped on the way in arrival order,
/// for a test that must check what reached the socket before the awaited frame.
pub async fn recv_until_collecting(
    ws: &mut Ws,
    what: &str,
    pred: impl Fn(&JsonValue) -> bool,
) -> (JsonValue, Vec<JsonValue>) {
    let deadline = Instant::now() + TIMEOUT;
    let mut skipped: Vec<JsonValue> = Vec::new();
    loop {
        match tokio::time::timeout_at(deadline, next_frame(ws)).await {
            Err(_) => panic!("timed out waiting for {what}; frames seen meanwhile: {skipped:?}"),
            Ok(None) => {
                panic!(
                    "the stream ended while waiting for {what}; frames seen meanwhile: {skipped:?}"
                )
            }
            Ok(Some(frame)) if pred(&frame) => return (frame, skipped),
            Ok(Some(frame)) => skipped.push(frame),
        }
    }
}

/// Every frame that arrives within `bound`; the stream must stay open.
pub async fn drain_for(ws: &mut Ws, bound: Duration) -> Vec<JsonValue> {
    let deadline = Instant::now() + bound;
    let mut frames = Vec::new();
    loop {
        match tokio::time::timeout_at(deadline, next_frame(ws)).await {
            Err(_) => return frames,
            Ok(Some(frame)) => frames.push(frame),
            Ok(None) => panic!("the stream ended while listening; frames seen: {frames:?}"),
        }
    }
}

/// Everything a socket yielded until its stream ended or a bound passed.
pub struct Drained {
    /// The text frames received before the end.
    pub replies: Vec<String>,
    /// The code of the Close frame, when the stream ended with one that has a code.
    pub close_code: Option<CloseCode>,
    /// A Close frame arrived, with a code or without one, as opposed to the stream
    /// ending by end of stream or a reset.
    pub saw_close: bool,
    /// The stream ended — a Close frame, end of stream, or a connection reset —
    /// before the bound elapsed.
    pub ended: bool,
}

/// Read until the stream ends or `bound` elapses. Unlike [`recv_text`] this
/// treats any error as the end of the stream: the callers are waiting for the
/// server to drop the connection, cleanly or not, and must not panic when it does.
pub async fn drain_until_end(ws: &mut Ws, bound: Duration) -> Drained {
    let deadline = Instant::now() + bound;
    let mut out = Drained {
        replies: Vec::new(),
        close_code: None,
        saw_close: false,
        ended: false,
    };
    loop {
        match tokio::time::timeout_at(deadline, ws.next()).await {
            Err(_) => return out,
            Ok(Some(Ok(Message::Text(text)))) => out.replies.push(text.to_string()),
            Ok(Some(Ok(Message::Close(frame)))) => {
                out.close_code = frame.map(|f| f.code);
                out.saw_close = true;
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

/// Whether the stream ends (Close, EOF, or a reset) within `bound`. Any error
/// counts as the end: the caller is waiting for the server to drop the connection.
pub async fn stream_ends_within(ws: &mut Ws, bound: Duration) -> bool {
    let deadline = Instant::now() + bound;
    loop {
        match tokio::time::timeout_at(deadline, ws.next()).await {
            Err(_) => return false,
            Ok(Some(Ok(Message::Close(_)))) | Ok(Some(Err(_))) | Ok(None) => return true,
            Ok(Some(Ok(_))) => {}
        }
    }
}

/// A `tools/call` request line for `name` with no arguments.
pub fn call_line(id: u64, name: &str) -> String {
    call_line_with(id, name, json!({}))
}

/// A `tools/call` request line for `name` with `arguments`.
pub fn call_line_with(id: u64, name: &str, arguments: JsonValue) -> String {
    json!({"jsonrpc": "2.0", "id": id, "method": "tools/call",
           "params": {"name": name, "arguments": arguments}})
    .to_string()
}

/// Authenticate an already connected bus socket as `token`, run `initialize`, and
/// check the role echo is `role`. For a socket a test connects itself, for example
/// with socket options [`ws_connect`] does not set.
pub async fn authenticate(mut ws: Ws, token: &str, role: &str) -> Ws {
    send_text(&mut ws, json!({ "token": token }).to_string()).await;
    send_text(
        &mut ws,
        json!({"jsonrpc": "2.0", "id": 0, "method": "initialize",
               "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                          "clientInfo": {"name": "aitm-web", "version": "0"}}})
        .to_string(),
    )
    .await;
    let init = recv_until(&mut ws, "the initialize reply", |v| v["id"] == 0).await;
    assert_eq!(init["result"]["role"], role, "initialize reply: {init}");
    ws
}

/// Open the bus as `token`: connect, then [`authenticate`].
pub async fn open_bus(server: &Server, token: &str, role: &str) -> Ws {
    authenticate(ws_connect(server).await, token, role).await
}

pub async fn open_agent(server: &Server) -> Ws {
    open_bus(server, AGENT_TOKEN, "agent").await
}

pub async fn open_operator(server: &Server) -> Ws {
    open_bus(server, OPERATOR_TOKEN, "operator").await
}

/// The request id every [`subscribe`] uses.
const SUBSCRIBE_ID: u64 = 1;

/// `flow.subscribe {}` on `ws`; the reply must carry a `sub_id` (web-bus-push
/// AC1). A notification may precede the reply (web-bus-push spec D6), so the
/// reply is found by id.
pub async fn subscribe(ws: &mut Ws) -> u64 {
    send_text(ws, call_line(SUBSCRIBE_ID, "flow.subscribe")).await;
    let reply = recv_until(ws, "the flow.subscribe reply", |v| v["id"] == SUBSCRIBE_ID).await;
    reply["result"]["structuredContent"]["sub_id"]
        .as_u64()
        .unwrap_or_else(|| {
            panic!("flow.subscribe over /bus must succeed with a sub_id, got: {reply}")
        })
}

/// Poll `cond` until it holds; panic after [`TIMEOUT`].
pub async fn wait_until(what: &str, cond: impl Fn() -> bool) {
    let deadline = Instant::now() + TIMEOUT;
    while !cond() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// What an `Ask`-policy `test.sensitive` call from the agent role came back with.
/// Nothing in these tests approves a probe, so it is always a refusal: at once
/// when no operator is subscribed, or after the approval timeout when one is.
pub struct Probe {
    pub text: String,
    pub elapsed: Duration,
}

/// Call `test.sensitive` as the agent, in-process, under the server's policy gate:
/// the same path an agent connection's `tools/call` takes. Runs on a blocking
/// thread because a parked call blocks for the approval timeout.
pub async fn probe_ask_gate(mcp: &Arc<McpServer>) -> Probe {
    let mcp = Arc::clone(mcp);
    let started = Instant::now();
    let reply = tokio::time::timeout(
        TIMEOUT,
        tokio::task::spawn_blocking(move || {
            mcp.handle_on(&ConnCtx::agent(), &call_line(99, "test.sensitive"))
        }),
    )
    .await
    .unwrap_or_else(|_| panic!("the Ask-policy probe did not return within {TIMEOUT:?}"))
    .expect("the probe thread did not panic")
    .expect("a tools/call has a reply");
    let elapsed = started.elapsed();
    let reply: JsonValue = serde_json::from_str(&reply).expect("reply is JSON");
    assert_eq!(
        reply["result"]["isError"], true,
        "nothing approves the probe, so it is always refused: {reply}"
    );
    let text = reply["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("a refusal carries its reason as text: {reply}"))
        .to_owned();
    Probe { text, elapsed }
}

/// The probe was refused at once because no operator is subscribed: the reason
/// says so, and it came back before the approval timeout could have expired.
pub fn assert_refused_without_operator(probe: &Probe) {
    assert!(
        probe.text.contains(NO_OPERATOR),
        "the Ask-policy probe must be refused because no operator is subscribed, got: {}",
        probe.text
    );
    assert!(
        probe.elapsed < APPROVAL_TIMEOUT,
        "a refusal for want of an operator is immediate, not a park that timed out; took {:?}",
        probe.elapsed
    );
}
