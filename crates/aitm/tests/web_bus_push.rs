//! `aitm web` `/bus` push: `flow.subscribe` over the bridge, and the
//! `notifications/aitm/{flow,state,agent}` lines that follow it on the same
//! socket (spec `2026-10-30-web-bus-push-design.md`, AC1-AC6).
//!
//! The contract these tests pin:
//!
//! - a bridge connection that subscribes receives flow pushes whose `params.id`
//!   is the stored flow's id (AC1), including through the real broadcast
//!   dispatcher `main.rs` relies on (AC1/AC9);
//! - replies keep arriving, in line order within a frame, while pushes flow, and
//!   a parked command does not hold pushes back (AC2);
//! - a connection's subscriptions end with it: on a Close (AC3), and when a frame
//!   still running at disconnect subscribes afterwards (AC4);
//! - a subscriber that stops reading is bounded: it lags, is told so, and still
//!   gets the newest event when it resumes (AC5);
//! - an agent-role connection never receives operator-only notifications (AC6).
//!
//! Hermetic: loopback only; the in-process test commands (`test.block`,
//! `test.tick`, `test.sensitive`) are registered through the scripting wiring's
//! command-provider slot; `flow.subscribe`, `flow.list` and `agent.approve` are
//! the real ones. The `McpServer` is shared with the test so it can push events
//! and probe the agent policy gate directly.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, SystemTime};

use aitm::web::bridge::MAX_IN_FLIGHT;
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
use tokio_tungstenite::tungstenite::{Error as WsError, Message};
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};

const AGENT_TOKEN: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
const OPERATOR_TOKEN: &str = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
/// Generous bound for anything that is expected to happen.
const TIMEOUT: Duration = Duration::from_secs(10);
/// Short bound for something that must happen while a sibling command is still
/// parked: long enough for a loaded machine, short enough that a bridge that
/// waits for the command fails the test.
const FAST: Duration = Duration::from_secs(5);
/// How long to listen for a frame that must not arrive.
const QUIET: Duration = Duration::from_millis(500);
/// How long the server is given to notice a close and tear the connection down.
const SETTLE: Duration = Duration::from_millis(200);
/// The `Ask` approval timeout in these tests: a parked probe returns after this,
/// a refused one at once, so the two outcomes are told apart by their reason and,
/// generously, by their elapsed time.
const APPROVAL_TIMEOUT: Duration = Duration::from_secs(1);
/// The most a parked `test.block` waits for the test to release it. The test
/// releases it (a panicking test releases it on unwind); this only stops a wedged
/// run from pinning the runtime's blocking pool at shutdown.
const BLOCK_LIMIT: Duration = Duration::from_secs(30);
/// The reason `park_for_approval` gives when it refuses at once for want of a
/// subscribed operator (no park).
const NO_OPERATOR: &str = "no operator is connected to approve it";
/// The reason it gives when the call did park and nobody approved in time.
const PARKED_TIMED_OUT: &str =
    "no operator approved the parked sensitive command within the approval timeout";

fn temp_ca_dir(tag: &str) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("aitm-web-push-{tag}-{nanos}-{n}"))
}

/// A `ProxyClient` nothing in these tests invokes.
struct UnusedClient;
impl ProxyClient for UnusedClient {
    fn send(&self, _req: HttpRequest) -> BoxFuture<'_, anyhow::Result<HttpFlow>> {
        Box::pin(async { anyhow::bail!("not called") })
    }
}

/// What `test.block` parks on: a one-shot latch that stays open once opened, and
/// a count of how many have started and finished.
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
struct TestCommands {
    parking: Arc<Parking>,
    ticks: Arc<AtomicUsize>,
    sensitive_runs: Arc<AtomicUsize>,
}

impl TestCommands {
    fn new() -> Self {
        Self {
            parking: Parking::new(),
            ticks: Arc::new(AtomicUsize::new(0)),
            sensitive_runs: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// The guard that releases `test.block`; hold it for the whole test.
    fn release_guard(&self) -> Release {
        Release(self.parking.clone())
    }

    fn ticks(&self) -> usize {
        self.ticks.load(Ordering::SeqCst)
    }

    fn sensitive_runs(&self) -> usize {
        self.sensitive_runs.load(Ordering::SeqCst)
    }
}

impl Plugin for TestCommands {
    fn name(&self) -> &str {
        "web-bus-push-test"
    }
    fn load(&mut self, reg: &mut Registry) {
        reg.add_command(Arc::new(BlockCmd(self.parking.clone())));
        reg.add_command(Arc::new(TickCmd(self.ticks.clone())));
        reg.add_command(Arc::new(SensitiveCmd(self.sensitive_runs.clone())));
    }
}

/// How a test's server differs from the default one.
struct ServerOptions {
    /// The agent policy the server's gate reads (shared with the wired `AgentPlugin`).
    policy: AgentPolicy,
    approval_timeout: Duration,
    /// The per-connection push-sink capacity; `None` keeps the server default.
    push_capacity: Option<usize>,
    /// Feed the server the assembled core event broadcast and spawn its push
    /// dispatcher, exactly as `main.rs` wires the web server.
    dispatcher: bool,
}

impl Default for ServerOptions {
    fn default() -> Self {
        Self {
            policy: AgentPolicy::Auto,
            approval_timeout: APPROVAL_TIMEOUT,
            push_capacity: None,
            dispatcher: false,
        }
    }
}

struct Server {
    addr: SocketAddr,
    /// The bridge's `McpServer`, shared so a test can push events and probe the
    /// policy gate without a socket.
    mcp: Arc<McpServer>,
    store: Arc<dyn FlowStore>,
    /// The core event broadcast the `SubscriptionPlugin` feeds; a test sends on it
    /// to exercise the dispatcher.
    push_tx: broadcast::Sender<Event>,
    task: tokio::task::JoinHandle<anyhow::Result<()>>,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// A served `aitm web` over the real wired registry plus the test commands, with
/// both bridge tokens configured.
async fn start(tag: &str, commands: &TestCommands, opts: ServerOptions) -> Server {
    let mut cfg = Config::default();
    cfg.ca.dir = temp_ca_dir(tag);
    cfg.mcp.policy = opts.policy;
    let scripts = ScriptWiring {
        commands: vec![Box::new(commands.clone())],
        ..ScriptWiring::default()
    };
    let Assembled {
        proxy,
        agent_state,
        push_tx,
        ..
    } = assemble_with_scripts(&cfg, &Features::default(), scripts).expect("assemble");
    let client: Arc<dyn ProxyClient> = Arc::new(UnusedClient);
    let store = proxy.store();
    let mut mcp = McpServer::new(proxy.registry_arc(), McpTransport::Stdio)
        .with_services(store.clone(), client, proxy.guard(), None)
        .with_agent_state(agent_state)
        .with_approval_timeout(opts.approval_timeout);
    if let Some(capacity) = opts.push_capacity {
        mcp = mcp.with_push_capacity(capacity);
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
        operator_token: Some(OPERATOR_TOKEN.to_owned()),
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
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
fn http_flow(authority: &str, path: &str) -> Flow {
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
fn push_flow(server: &Server, path: &str) -> FlowId {
    let id = server.store.insert(http_flow("example.com:443", path));
    server.mcp.push_flow_event(&Event::RequestHeaders(id));
    id
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

/// The next text frame, parsed; `None` when the stream ended first. Unbounded:
/// the caller puts a deadline on it.
async fn next_frame(ws: &mut Ws) -> Option<JsonValue> {
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

/// The next text frame within `bound`; panics, naming `what`, when the bound
/// passes or the stream ends first.
async fn recv_within(ws: &mut Ws, bound: Duration, what: &str) -> JsonValue {
    match tokio::time::timeout(bound, next_frame(ws)).await {
        Ok(Some(frame)) => frame,
        Ok(None) => panic!("the stream ended while waiting for {what}"),
        Err(_) => panic!("no frame within {bound:?} while waiting for {what}"),
    }
}

/// Frames until one satisfies `pred`, within [`TIMEOUT`]. The frames skipped on
/// the way are in the failure message, so a wrong frame is diagnosable.
async fn recv_until(ws: &mut Ws, what: &str, pred: impl Fn(&JsonValue) -> bool) -> JsonValue {
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
            Ok(Some(frame)) if pred(&frame) => return frame,
            Ok(Some(frame)) => skipped.push(frame),
        }
    }
}

/// Every frame that arrives within `bound`; the stream must stay open.
async fn drain_for(ws: &mut Ws, bound: Duration) -> Vec<JsonValue> {
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

/// Whether the stream ends (Close, EOF, or a reset) within `bound`. Any error
/// counts as the end: the caller is waiting for the server to drop the connection.
async fn stream_ends_within(ws: &mut Ws, bound: Duration) -> bool {
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
fn call_line(id: u64, name: &str) -> String {
    call_line_with(id, name, json!({}))
}

/// A `tools/call` request line for `name` with `arguments`.
fn call_line_with(id: u64, name: &str, arguments: JsonValue) -> String {
    json!({"jsonrpc": "2.0", "id": id, "method": "tools/call",
           "params": {"name": name, "arguments": arguments}})
    .to_string()
}

/// Open the bus as `token`: connect, authenticate, `initialize`, and check the
/// role echo is `role`.
async fn open_bus(server: &Server, token: &str, role: &str) -> Ws {
    let mut ws = ws_connect(server).await;
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

async fn open_agent(server: &Server) -> Ws {
    open_bus(server, AGENT_TOKEN, "agent").await
}

async fn open_operator(server: &Server) -> Ws {
    open_bus(server, OPERATOR_TOKEN, "operator").await
}

/// The request id every `flow.subscribe` in these tests uses.
const SUBSCRIBE_ID: u64 = 1;

/// `flow.subscribe {}` on `ws`; the reply must carry a `sub_id` (AC1's first
/// clause). A notification may precede the reply (spec D6), so the reply is
/// found by id.
async fn subscribe(ws: &mut Ws) -> u64 {
    send_text(ws, call_line(SUBSCRIBE_ID, "flow.subscribe")).await;
    let reply = recv_until(ws, "the flow.subscribe reply", |v| v["id"] == SUBSCRIBE_ID).await;
    reply["result"]["structuredContent"]["sub_id"]
        .as_u64()
        .unwrap_or_else(|| {
            panic!("flow.subscribe over /bus must succeed with a sub_id, got: {reply}")
        })
}

/// Poll `cond` until it holds; panic after [`TIMEOUT`].
async fn wait_until(what: &str, cond: impl Fn() -> bool) {
    let deadline = Instant::now() + TIMEOUT;
    while !cond() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// What an `Ask`-policy `test.sensitive` call from the agent role came back with.
/// Nothing in these tests approves a probe, so it is always a refusal: at once
/// when no operator is subscribed, or after the approval timeout when one is.
struct Probe {
    text: String,
    elapsed: Duration,
}

/// Call `test.sensitive` as the agent, in-process, under the server's policy gate:
/// the same path an agent connection's `tools/call` takes. Runs on a blocking
/// thread because a parked call blocks for the approval timeout.
async fn probe_ask_gate(mcp: &Arc<McpServer>) -> Probe {
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
fn assert_refused_without_operator(probe: &Probe) {
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

/// AC1: a bridge connection that subscribes gets `{sub_id}`, and a flow push for
/// a stored flow arrives on that socket with the flow's id.
#[tokio::test]
async fn subscribe_over_bus_then_a_flow_push_arrives() {
    let commands = TestCommands::new();
    let server = start("subscribe", &commands, ServerOptions::default()).await;
    let mut ws = open_agent(&server).await;

    let sub_id = subscribe(&mut ws).await;
    assert_eq!(sub_id, 1, "the first subscription on a fresh server");

    let id = push_flow(&server, "/pushed");
    let note = recv_until(&mut ws, "a notifications/aitm/flow frame", |v| {
        v["method"] == "notifications/aitm/flow"
    })
    .await;
    assert_eq!(note["params"]["id"], id.to_string(), "{note}");
    assert_eq!(note["params"]["event"], "created", "{note}");
    assert_eq!(
        note["params"]["summary"]["authority"], "example.com:443",
        "{note}"
    );
    assert_eq!(note["params"]["summary"]["path"], "/pushed", "{note}");
}

/// AC1/AC9 at the wiring level: a server built `.with_push(tx)` whose
/// `spawn_push_dispatcher()` was called delivers a broadcast `Event` to a bridge
/// subscriber. This is the contract `main.rs` relies on for the web server.
#[tokio::test]
async fn pushes_flow_through_the_real_broadcast_dispatcher() {
    let commands = TestCommands::new();
    let server = start(
        "dispatcher",
        &commands,
        ServerOptions {
            dispatcher: true,
            ..ServerOptions::default()
        },
    )
    .await;
    let mut ws = open_agent(&server).await;
    subscribe(&mut ws).await;

    let id = server
        .store
        .insert(http_flow("example.com:443", "/broadcast"));
    server
        .push_tx
        .send(Event::Response(id))
        .unwrap_or_else(|_| panic!("the dispatcher must hold a receiver on the broadcast"));

    let note = recv_until(
        &mut ws,
        "the dispatched notifications/aitm/flow frame",
        |v| v["method"] == "notifications/aitm/flow",
    )
    .await;
    assert_eq!(note["params"]["id"], id.to_string(), "{note}");
    assert_eq!(note["params"]["event"], "response", "{note}");
    assert_eq!(note["params"]["summary"]["path"], "/broadcast", "{note}");
}

/// AC2: pushes arrive while a frame's command is parked (they do not wait behind
/// it), and the frame's replies still come back in line order, none lost, while
/// more pushes flow; every push below the sink capacity arrives, once, in order.
#[tokio::test]
async fn replies_stay_in_order_while_pushes_flow() {
    const TICKS: u64 = 40;
    const PARKED_PUSHES: usize = 5;
    const LIVE_PUSHES: usize = 200;
    let commands = TestCommands::new();
    let release = commands.release_guard();
    let server = start("interleave", &commands, ServerOptions::default()).await;
    let mut ws = open_agent(&server).await;
    subscribe(&mut ws).await;

    // One frame: a parked line first, then the ticks, then flow.list. Its replies
    // are held until the whole frame is done, so until the release only pushes
    // can reach the socket.
    let first_id = 10;
    let last_id = first_id + TICKS + 1;
    let frame = std::iter::once(call_line(first_id, "test.block"))
        .chain((1..=TICKS).map(|i| call_line(first_id + i, "test.tick")))
        .chain(std::iter::once(call_line(last_id, "flow.list")))
        .collect::<Vec<_>>()
        .join("\n");
    send_text(&mut ws, frame).await;
    wait_until("test.block to start", || commands.parking.entered() == 1).await;

    let parked_ids: Vec<String> = (0..PARKED_PUSHES)
        .map(|i| push_flow(&server, &format!("/parked/{i}")).to_string())
        .collect();
    for expected in &parked_ids {
        let frame = recv_within(
            &mut ws,
            FAST,
            "a push while the frame's test.block is still parked",
        )
        .await;
        assert_eq!(
            frame["method"], "notifications/aitm/flow",
            "while the frame is parked only a push can arrive: {frame}"
        );
        assert_eq!(
            frame["params"]["id"], *expected,
            "pushes arrive in push order: {frame}"
        );
    }

    // Release the frame and keep pushing from a task while its replies come back.
    release.release();
    let pusher = {
        let mcp = server.mcp.clone();
        let store = server.store.clone();
        tokio::spawn(async move {
            let mut ids = Vec::with_capacity(LIVE_PUSHES);
            for i in 0..LIVE_PUSHES {
                let id = store.insert(http_flow("example.com:443", &format!("/live/{i}")));
                mcp.push_flow_event(&Event::RequestHeaders(id));
                ids.push(id.to_string());
                if i % 8 == 7 {
                    tokio::task::yield_now().await;
                }
            }
            ids
        })
    };

    let want_replies = usize::try_from(TICKS).expect("small") + 2;
    let mut replies: Vec<u64> = Vec::new();
    let mut notes: Vec<String> = Vec::new();
    let deadline = Instant::now() + TIMEOUT;
    while replies.len() < want_replies || notes.len() < LIVE_PUSHES {
        let frame = match tokio::time::timeout_at(deadline, next_frame(&mut ws)).await {
            Ok(Some(frame)) => frame,
            Ok(None) => panic!(
                "the stream ended with {replies:?} replies and {} pushes",
                notes.len()
            ),
            Err(_) => panic!(
                "timed out with {} of {want_replies} replies and {} of {LIVE_PUSHES} pushes",
                replies.len(),
                notes.len()
            ),
        };
        if let Some(id) = frame["id"].as_u64() {
            assert_eq!(frame["result"]["isError"], false, "{frame}");
            replies.push(id);
        } else if frame["method"] == "notifications/aitm/flow" {
            notes.push(
                frame["params"]["id"]
                    .as_str()
                    .unwrap_or_default()
                    .to_owned(),
            );
        } else if frame["method"] == "notifications/aitm/agent" {
            // Every finished tool call is audited and fanned to all subscribers, so
            // this frame's own commands show up on the stream. Neither a reply nor
            // a flow push.
        } else {
            panic!("unexpected frame: {frame}");
        }
    }
    assert_eq!(
        replies,
        (first_id..=last_id).collect::<Vec<_>>(),
        "the frame's replies arrive in line order, each exactly once"
    );
    assert_eq!(commands.ticks(), usize::try_from(TICKS).expect("small"));
    let live_ids = pusher.await.expect("the pusher task");
    assert_eq!(
        notes, live_ids,
        "every push below the sink capacity arrives once, in push order"
    );
}

/// AC3: when the client closes, its subscriptions go with it. With the operator
/// subscribed, an `Ask`-policy Sensitive agent call parks (the control); once that
/// operator has closed, the same call is refused at once for want of an operator.
#[tokio::test]
async fn disconnect_drops_the_subscription() {
    let commands = TestCommands::new();
    let server = start(
        "disconnect",
        &commands,
        ServerOptions {
            policy: AgentPolicy::Ask,
            ..ServerOptions::default()
        },
    )
    .await;
    let mut operator = open_operator(&server).await;
    subscribe(&mut operator).await;

    // Control: with the operator subscribed the probe parks. It is still pending
    // after a short wait, and is refused only when the approval timeout expires.
    let mut parked = Box::pin(probe_ask_gate(&server.mcp));
    assert!(
        tokio::time::timeout(SETTLE, &mut parked).await.is_err(),
        "the control probe must park while the operator is subscribed, but it returned at once"
    );
    let probe = parked.await;
    assert!(
        probe.text.contains(PARKED_TIMED_OUT),
        "the control probe must have parked and timed out, got: {}",
        probe.text
    );
    assert!(
        probe.elapsed >= APPROVAL_TIMEOUT / 2,
        "a parked probe waits out the approval timeout; took {:?}",
        probe.elapsed
    );
    let request = recv_until(&mut operator, "the approval request", |v| {
        v["method"] == "notifications/aitm/agent"
    })
    .await;
    assert_eq!(
        request["params"]["event"], "approval_requested",
        "{request}"
    );
    assert_eq!(request["params"]["command"], "test.sensitive", "{request}");

    // The operator closes; the stream ends; its subscription is gone.
    operator.close(None).await.expect("client close");
    assert!(
        stream_ends_within(&mut operator, FAST).await,
        "the server must end the stream after the client's Close"
    );
    tokio::time::sleep(SETTLE).await;
    let probe = probe_ask_gate(&server.mcp).await;
    assert_refused_without_operator(&probe);
    assert_eq!(commands.sensitive_runs(), 0, "no probe ever ran");
}

/// AC4 (the late-subscribe race): a frame `[test.block, flow.subscribe]` is still
/// running when its operator connection drops; the subscribe runs only after the
/// teardown and must register nothing, so for a good while afterwards every
/// `Ask`-policy probe is refused at once rather than parked.
#[tokio::test]
async fn a_frame_still_running_at_disconnect_cannot_resubscribe() {
    let commands = TestCommands::new();
    let release = commands.release_guard();
    let server = start(
        "late-subscribe",
        &commands,
        ServerOptions {
            policy: AgentPolicy::Ask,
            ..ServerOptions::default()
        },
    )
    .await;
    let mut operator = open_operator(&server).await;
    // Subscriptions work on this bridge, so a missing one below means teardown.
    subscribe(&mut operator).await;

    send_text(
        &mut operator,
        format!(
            "{}\n{}",
            call_line(10, "test.block"),
            call_line(11, "flow.subscribe")
        ),
    )
    .await;
    wait_until("test.block to start", || commands.parking.entered() == 1).await;

    // The client vanishes while the frame is parked. One frame is in flight,
    // below the cap, so the bridge is reading and sees the drop at once.
    drop(operator);
    tokio::time::sleep(SETTLE).await;
    assert_eq!(
        commands.parking.completed(),
        0,
        "test.block is still parked"
    );
    // The teardown has already run: the subscription made above is gone. So the
    // `flow.subscribe` released below really runs after it, against the closed
    // sink, rather than before a slow teardown that would then sweep it.
    assert_refused_without_operator(&probe_ask_gate(&server.mcp).await);

    // The detached frame finishes: test.block returns, then flow.subscribe runs
    // against the torn-down connection.
    release.release();
    wait_until("the detached frame to finish test.block", || {
        commands.parking.completed() == 1
    })
    .await;

    let until = Instant::now() + Duration::from_secs(1);
    let mut probes = 0;
    while Instant::now() < until {
        let probe = probe_ask_gate(&server.mcp).await;
        assert_refused_without_operator(&probe);
        probes += 1;
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(probes > 0, "at least one probe ran");
    assert_eq!(commands.sensitive_runs(), 0, "no probe ever ran");
}

/// AC5: a subscriber that stops reading while far more than `push_capacity` large
/// events are pushed is not sent them all. When it resumes it receives fewer
/// lines than were pushed, a `notifications/aitm/state {lagged:true}` marker,
/// and the newest event.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_non_reading_subscriber_is_bounded_and_lags() {
    const CAPACITY: usize = 16;
    const PUSHES: usize = 5000;
    let commands = TestCommands::new();
    let server = start(
        "lag",
        &commands,
        ServerOptions {
            push_capacity: Some(CAPACITY),
            ..ServerOptions::default()
        },
    )
    .await;
    let mut ws = open_agent(&server).await;
    subscribe(&mut ws).await;

    // Each notification carries this ~4 KiB path, so the burst is some 20 MiB:
    // more than the loopback socket buffers absorb while the client is not
    // reading, so the bridge's send really does block and the sink overflows.
    let big_path = format!("/{}", "x".repeat(4096));
    let big = server.store.insert(http_flow("example.com:443", &big_path));
    for i in 0..PUSHES {
        server.mcp.push_flow_event(&Event::RequestHeaders(big));
        if i % 64 == 63 {
            tokio::task::yield_now().await;
        }
    }
    let final_id = push_flow(&server, "/final");

    // Resume reading until the final event arrives, counting what came.
    let deadline = Instant::now() + TIMEOUT;
    let mut flows = 0usize;
    let mut lagged = false;
    loop {
        let frame = match tokio::time::timeout_at(deadline, next_frame(&mut ws)).await {
            Ok(Some(frame)) => frame,
            Ok(None) => {
                panic!("the stream ended after {flows} flow frames, before the final event")
            }
            Err(_) => {
                panic!("the final event did not arrive; {flows} flow frames, lagged seen: {lagged}")
            }
        };
        match frame["method"].as_str() {
            Some("notifications/aitm/flow") => {
                flows += 1;
                if frame["params"]["id"] == final_id.to_string() {
                    assert_eq!(frame["params"]["summary"]["path"], "/final", "{frame}");
                    break;
                }
            }
            Some("notifications/aitm/state") if frame["params"]["lagged"] == true => {
                lagged = true;
            }
            _ => panic!("unexpected frame during the burst: {frame}"),
        }
    }
    assert!(
        flows <= PUSHES,
        "a subscriber that was not reading must not be sent every event: {flows} of {} arrived",
        PUSHES + 1
    );
    assert!(
        lagged,
        "a lagged state marker must tell the subscriber it missed events ({flows} of {} arrived)",
        PUSHES + 1
    );
}

/// AC6: with an operator and an agent connection both subscribed, a parked
/// `Ask`-policy call produces `approval_requested` on the operator connection
/// only; the agent connection keeps receiving flow pushes but never that line;
/// `agent.approve {allow:false}` from the operator refuses the parked call.
#[tokio::test]
async fn agent_role_never_gets_operator_only_pushes() {
    let commands = TestCommands::new();
    let server = start(
        "roles",
        &commands,
        ServerOptions {
            policy: AgentPolicy::Ask,
            // Long enough for the operator to read the request and answer it.
            approval_timeout: FAST,
            ..ServerOptions::default()
        },
    )
    .await;
    let mut operator = open_operator(&server).await;
    let mut agent = open_agent(&server).await;
    subscribe(&mut operator).await;
    subscribe(&mut agent).await;

    // The agent asks for a Sensitive command; under Ask it parks for the operator.
    send_text(&mut agent, call_line(5, "test.sensitive")).await;
    let request = recv_until(
        &mut operator,
        "the approval request on the operator connection",
        |v| v["method"] == "notifications/aitm/agent",
    )
    .await;
    assert_eq!(
        request["params"]["event"], "approval_requested",
        "{request}"
    );
    assert_eq!(request["params"]["command"], "test.sensitive", "{request}");
    let request_id = request["params"]["request_id"]
        .as_str()
        .unwrap_or_else(|| panic!("the approval request carries a request_id: {request}"))
        .to_owned();

    // A flow push reaches the agent connection; the approval request never does,
    // and the parked call has no reply yet.
    let id = push_flow(&server, "/both");
    let on_operator = recv_until(
        &mut operator,
        "the flow push on the operator connection",
        |v| v["method"] == "notifications/aitm/flow",
    )
    .await;
    assert_eq!(on_operator["params"]["id"], id.to_string(), "{on_operator}");
    let on_agent = drain_for(&mut agent, QUIET).await;
    let flow_pushes: Vec<&JsonValue> = on_agent
        .iter()
        .filter(|f| f["method"] == "notifications/aitm/flow")
        .collect();
    assert_eq!(
        flow_pushes.len(),
        1,
        "the agent connection receives the one flow push: {on_agent:?}"
    );
    assert_eq!(
        flow_pushes[0]["params"]["id"],
        id.to_string(),
        "{on_agent:?}"
    );
    assert!(
        on_agent
            .iter()
            .all(|f| f["method"] != "notifications/aitm/agent"),
        "the agent connection must never receive an operator-only notification: {on_agent:?}"
    );
    assert!(
        on_agent.iter().all(|f| f["id"] != 5),
        "the Sensitive call must still be parked while the operator has not answered: {on_agent:?}"
    );

    // The operator denies; the parked call is refused and never ran.
    send_text(
        &mut operator,
        call_line_with(
            6,
            "agent.approve",
            json!({ "request_id": request_id, "allow": false }),
        ),
    )
    .await;
    let approved = recv_until(&mut operator, "the agent.approve reply", |v| v["id"] == 6).await;
    assert_eq!(
        approved["result"]["isError"], false,
        "agent.approve from the operator connection resolves the request: {approved}"
    );
    let done = recv_until(&mut agent, "the parked call's reply", |v| v["id"] == 5).await;
    assert_eq!(
        done["result"]["isError"], true,
        "a denied agent call is refused: {done}"
    );
    let text = done["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_default();
    assert!(
        text.contains("denied"),
        "the refusal names the denial: {text}"
    );
    assert_eq!(commands.sensitive_runs(), 0, "a denied command never ran");
}

/// Spec D3, added by the tester: the drain arm is not gated on the in-flight cap.
/// With `MAX_IN_FLIGHT` frames parked the bridge has stopped reading, yet a push
/// still reaches the subscriber; the parked frames are answered once released.
#[tokio::test]
async fn pushes_flow_while_the_read_branch_is_paused_at_the_cap() {
    let commands = TestCommands::new();
    let release = commands.release_guard();
    let server = start("at-cap", &commands, ServerOptions::default()).await;
    let mut ws = open_agent(&server).await;
    subscribe(&mut ws).await;

    // One frame per parked command, exactly the cap: the read branch is now off.
    let cap = u64::try_from(MAX_IN_FLIGHT).expect("small");
    let first_id = 100;
    for id in first_id..first_id + cap {
        send_text(&mut ws, call_line(id, "test.block")).await;
    }
    wait_until("every in-flight frame to park in test.block", || {
        commands.parking.entered() == MAX_IN_FLIGHT
    })
    .await;

    let id = push_flow(&server, "/at-cap");
    let note = recv_within(&mut ws, FAST, "a push while the bridge is at the cap").await;
    assert_eq!(
        note["method"], "notifications/aitm/flow",
        "while every frame is parked only a push can arrive: {note}"
    );
    assert_eq!(note["params"]["id"], id.to_string(), "{note}");

    release.release();
    let mut replies = Vec::new();
    while replies.len() < MAX_IN_FLIGHT {
        let reply = recv_until(&mut ws, "a released test.block reply", |v| v["id"].is_u64()).await;
        assert_eq!(reply["result"]["isError"], false, "{reply}");
        replies.push(reply["id"].as_u64().unwrap_or_default());
    }
    replies.sort_unstable();
    assert_eq!(
        replies,
        (first_id..first_id + cap).collect::<Vec<_>>(),
        "every parked frame is answered exactly once"
    );
}

/// Spec Intent ("exactly as over loopback TCP"), added by the tester: the
/// connection's one `ConnCtx` spans frames, so a `flow.unsubscribe` sent in a later
/// frame removes the subscription an earlier frame made, and pushes stop.
#[tokio::test]
async fn unsubscribe_in_a_later_frame_stops_pushes() {
    let commands = TestCommands::new();
    let server = start("unsubscribe", &commands, ServerOptions::default()).await;
    let mut ws = open_agent(&server).await;
    let sub_id = subscribe(&mut ws).await;

    // Control: while subscribed, a push arrives.
    let before = push_flow(&server, "/before");
    let note = recv_until(&mut ws, "the push before unsubscribing", |v| {
        v["method"] == "notifications/aitm/flow"
    })
    .await;
    assert_eq!(note["params"]["id"], before.to_string(), "{note}");

    send_text(
        &mut ws,
        call_line_with(2, "flow.unsubscribe", json!({ "sub_id": sub_id })),
    )
    .await;
    let reply = recv_until(&mut ws, "the flow.unsubscribe reply", |v| v["id"] == 2).await;
    assert_eq!(reply["result"]["isError"], false, "{reply}");

    push_flow(&server, "/after");
    let after = drain_for(&mut ws, QUIET).await;
    assert!(
        after
            .iter()
            .all(|f| f["method"] != "notifications/aitm/flow"),
        "no flow push reaches a connection that unsubscribed: {after:?}"
    );
}

/// Spec D4's refusal exit path, added by the tester: a post-auth refusal drops the
/// connection's subscriptions before its close handshake (`refuse` drops the guard
/// first), so a peer that never answers our Close is not counted as a subscribed
/// operator for the drain budget. The client reads the server's Close and then
/// stops reading, so its answer is never flushed and the server is still inside
/// the handshake when the probe runs; the probe must be refused at once anyway.
#[tokio::test]
async fn a_refused_connection_is_unsubscribed_before_the_close_handshake() {
    let commands = TestCommands::new();
    let server = start(
        "refused",
        &commands,
        ServerOptions {
            policy: AgentPolicy::Ask,
            ..ServerOptions::default()
        },
    )
    .await;
    let mut operator = open_operator(&server).await;
    subscribe(&mut operator).await;

    // A binary frame after auth is refused (`Unsupported`).
    operator
        .send(Message::binary(vec![0u8; 4]))
        .await
        .expect("send");
    assert!(
        stream_ends_within(&mut operator, FAST).await,
        "the server must refuse a binary frame by closing"
    );
    let probe = probe_ask_gate(&server.mcp).await;
    assert_refused_without_operator(&probe);
    assert_eq!(commands.sensitive_runs(), 0, "no probe ever ran");
}
