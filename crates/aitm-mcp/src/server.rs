//! The MCP server: JSON-RPC 2.0 dispatch over the command registry.
//!
//! `handle` is transport-neutral — one JSON-RPC message in, at most one out — so
//! the stdio and loopback-TCP transports (and in-process test clients) all run
//! the identical path: `tools/list` enumerates every registered command,
//! `tools/call` coerces the arguments by the command's schema and runs
//! `Command::invoke` against a `CommandHost` built from the attached services.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use aitm_core::{
    AgentPolicy, AgentState, BrowserDriver, Command, CommandHost, Event, Flow, FlowId, FlowQuery,
    FlowStore, Frontend, McpTransport, ProxyClient, Registry, ScopeRateGuard, Sensitivity,
    SsrfPolicy,
};
use serde_json::{json, Map, Value as JsonValue};
use tokio::sync::{broadcast, Notify};

use crate::json::{params_from_json, to_json};
use crate::schema::{McpSchemaDerive, StdSchemaDerive};
use crate::transport::{self, LoopbackTcp};

/// The default per-connection push-sink capacity (notification lines). A slow
/// subscriber's notification lane is bounded to this many lines before the oldest
/// are dropped and the connection is flagged `lagged`; replies are never bounded.
pub const DEFAULT_PUSH_CAPACITY: usize = 4096;

/// The default capacity of the core→server event broadcast ring.
pub const DEFAULT_BROADCAST_CAPACITY: usize = 8192;

/// The MCP protocol revision this server speaks when the client names none.
pub const PROTOCOL_VERSION: &str = "2025-06-18";

// JSON-RPC 2.0 error codes, plus the transport's own refusal.
pub const PARSE_ERROR: i64 = -32700;
pub const INVALID_REQUEST: i64 = -32600;
pub const METHOD_NOT_FOUND: i64 = -32601;
pub const INVALID_PARAMS: i64 = -32602;
pub const INTERNAL_ERROR: i64 = -32603;
/// A loopback-TCP connection whose first line was not the expected token.
pub const UNAUTHORIZED: i64 = -32001;

/// Per-connection context, built once by the transport after it has classified
/// the connection's auth token (or, for stdio, from `mcp.stdio_role`), and
/// threaded into every message on that connection through [`McpServer::handle_on`].
///
/// The `role` drives policy and confirmation decisions (Tasks 4/5/9); the
/// `client_label` is the connection's `initialize.clientInfo.name`, carried for
/// audit only. `out` is the bounded push sink the transport's writer task drains
/// (F4); `conn_id` identifies the connection so its subscriptions are dropped
/// when it ends. In-process callers (`McpServer::handle`) have no push sink.
#[derive(Debug, Clone)]
pub struct ConnCtx {
    /// The frontend this connection speaks as.
    pub role: Frontend,
    /// The human-readable client label from `initialize.clientInfo.name`.
    pub client_label: Option<String>,
    /// A per-connection id, assigned by the transport, used to drop this
    /// connection's subscriptions when it ends. `0` means "not a streaming
    /// connection" (an in-process `handle` call).
    pub conn_id: u64,
    /// The bounded push sink the transport's writer task drains to the socket;
    /// `None` for in-process callers that have no writer task.
    pub out: Option<NotificationSink>,
}

impl ConnCtx {
    /// A context for `role` with no client label, no connection id, and no sink.
    pub fn new(role: Frontend) -> Self {
        Self {
            role,
            client_label: None,
            conn_id: 0,
            out: None,
        }
    }

    /// The default agent context (`Frontend::Mcp`, no label) the back-compat
    /// [`McpServer::handle`] wrapper uses.
    pub fn agent() -> Self {
        Self::new(Frontend::Mcp)
    }
}

/// A bounded, per-connection push sink feeding one connection's writer task.
///
/// Two lanes share the sink so a slow subscriber can never grow core memory or
/// block the proxy data path:
/// - **replies** to the connection's own requests are unbounded (a stalled reader
///   stops sending requests, so replies cannot grow without bound) and are
///   **never dropped**;
/// - **notifications** (`notifications/aitm/{flow,state}`) are bounded to
///   `capacity` lines; on overflow the *oldest* notification is dropped and the
///   connection is flagged `lagged`, surfaced on the next drain as a
///   `notifications/aitm/state {lagged:true}` line.
///
/// Every `push`/`push_reply` is non-blocking: the producer (the dispatcher task,
/// or the read loop) never awaits the socket.
#[derive(Clone)]
pub struct NotificationSink {
    inner: Arc<SinkInner>,
}

struct SinkInner {
    queues: Mutex<SinkQueues>,
    capacity: usize,
    lagged: AtomicBool,
    closed: AtomicBool,
    notify: Notify,
}

#[derive(Default)]
struct SinkQueues {
    replies: VecDeque<String>,
    notes: VecDeque<String>,
}

impl std::fmt::Debug for NotificationSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NotificationSink")
            .field("capacity", &self.inner.capacity)
            .field("queued", &self.queued_len())
            .field("lagged", &self.lagged())
            .finish()
    }
}

impl NotificationSink {
    /// A sink whose notification lane holds at most `capacity` lines (clamped to
    /// at least 1) before dropping the oldest.
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: Arc::new(SinkInner {
                queues: Mutex::new(SinkQueues::default()),
                capacity: capacity.max(1),
                lagged: AtomicBool::new(false),
                closed: AtomicBool::new(false),
                notify: Notify::new(),
            }),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, SinkQueues> {
        self.inner
            .queues
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Enqueue a reply to the connection's own request. Never dropped.
    pub fn push_reply(&self, line: String) {
        self.lock().replies.push_back(line);
        self.inner.notify.notify_one();
    }

    /// Enqueue a server-initiated notification. On overflow the oldest
    /// notification is dropped and the connection is flagged `lagged`.
    pub fn push(&self, line: String) {
        {
            let mut q = self.lock();
            if q.notes.len() >= self.inner.capacity {
                q.notes.pop_front();
                self.inner.lagged.store(true, Ordering::Relaxed);
            }
            q.notes.push_back(line);
        }
        self.inner.notify.notify_one();
    }

    /// Take everything queued, replies first (priority), then — if the lag flag
    /// is set — a `lagged` state marker, then the surviving notifications. Clears
    /// the lag flag.
    pub fn drain(&self) -> Vec<String> {
        let mut q = self.lock();
        let mut out: Vec<String> = q.replies.drain(..).collect();
        if self.inner.lagged.swap(false, Ordering::Relaxed) {
            out.push(lagged_state_line());
        }
        out.extend(q.notes.drain(..));
        out
    }

    /// How many notifications are currently queued (for tests / introspection).
    pub fn queued_len(&self) -> usize {
        self.lock().notes.len()
    }

    /// Whether the notification lane has overflowed since the last drain.
    pub fn lagged(&self) -> bool {
        self.inner.lagged.load(Ordering::Relaxed)
    }

    /// Mark the sink closed and wake the writer so it can drain and exit.
    pub fn close(&self) {
        self.inner.closed.store(true, Ordering::Relaxed);
        self.inner.notify.notify_one();
    }

    /// Whether the sink is closed and holds nothing more to write.
    pub fn is_closed_and_drained(&self) -> bool {
        if !self.inner.closed.load(Ordering::Relaxed) {
            return false;
        }
        let q = self.lock();
        q.replies.is_empty() && q.notes.is_empty() && !self.inner.lagged.load(Ordering::Relaxed)
    }

    /// Wait until there may be something new to write (or the sink was closed).
    pub async fn wait(&self) {
        self.inner.notify.notified().await;
    }
}

/// The `notifications/aitm/state {lagged:true}` line a drain surfaces after an
/// overflow, so a slow subscriber knows to catch up via `flow.list`/`since`.
fn lagged_state_line() -> String {
    json!({
        "jsonrpc": "2.0",
        "method": "notifications/aitm/state",
        "params": {"lagged": true},
    })
    .to_string()
}

/// The subscription filter (a subset of [`FlowQuery`]): match live and replayed
/// flows by host and/or method. An unset field does not constrain.
#[derive(Debug, Clone, Default)]
struct FlowFilter {
    host: Option<String>,
    method: Option<String>,
}

impl FlowFilter {
    /// Parse the optional `filter` argument object (`{host?, method?}`).
    fn parse(filter: Option<&JsonValue>) -> Self {
        let Some(obj) = filter.and_then(JsonValue::as_object) else {
            return Self::default();
        };
        Self {
            host: obj
                .get("host")
                .and_then(JsonValue::as_str)
                .map(str::to_string),
            method: obj
                .get("method")
                .and_then(JsonValue::as_str)
                .map(str::to_string),
        }
    }

    /// Whether `flow` passes every set constraint.
    fn matches(&self, flow: &Flow) -> bool {
        match flow {
            Flow::Http(f) => {
                if let Some(host) = &self.host {
                    if !host_eq(&f.request.authority, host) {
                        return false;
                    }
                }
                if let Some(method) = &self.method {
                    if !f.request.method.eq_ignore_ascii_case(method) {
                        return false;
                    }
                }
                true
            }
            // host/method are HTTP concepts: a WebSocket flow matches only an
            // otherwise-unconstrained filter.
            Flow::WebSocket(_) => self.host.is_none() && self.method.is_none(),
        }
    }

    /// The equivalent store query, for `since` replay.
    fn as_query(&self) -> FlowQuery {
        FlowQuery {
            host: self.host.clone(),
            method: self.method.clone(),
            ..FlowQuery::default()
        }
    }
}

/// Case-insensitive host match: compare the host portion of `authority`
/// (`host[:port]`) against `want`.
fn host_eq(authority: &str, want: &str) -> bool {
    let host = authority.rsplit_once(':').map_or(authority, |(h, _)| h);
    host.eq_ignore_ascii_case(want) || authority.eq_ignore_ascii_case(want)
}

/// One live subscription: the connection it belongs to, that connection's push
/// sink, and the filter it watches.
struct Subscription {
    sub_id: u64,
    conn_id: u64,
    sink: NotificationSink,
    filter: FlowFilter,
}

/// The per-server subscription registry. Subscriptions are keyed by an opaque
/// `sub_id` and tagged with their `conn_id`, so a connection's subscriptions are
/// all dropped when it ends.
#[derive(Default)]
struct Subscriptions {
    inner: Mutex<SubState>,
}

#[derive(Default)]
struct SubState {
    next_sub: u64,
    subs: Vec<Subscription>,
}

impl Subscriptions {
    fn lock(&self) -> std::sync::MutexGuard<'_, SubState> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Register a subscription for `conn_id` over `sink`; returns its `sub_id`.
    fn add(&self, conn_id: u64, sink: NotificationSink, filter: FlowFilter) -> u64 {
        let mut st = self.lock();
        st.next_sub += 1;
        let sub_id = st.next_sub;
        st.subs.push(Subscription {
            sub_id,
            conn_id,
            sink,
            filter,
        });
        sub_id
    }

    /// Remove `sub_id` if it belongs to `conn_id`. Returns whether it existed.
    fn remove(&self, conn_id: u64, sub_id: u64) -> bool {
        let mut st = self.lock();
        let before = st.subs.len();
        st.subs
            .retain(|s| !(s.sub_id == sub_id && s.conn_id == conn_id));
        st.subs.len() != before
    }

    /// Drop every subscription belonging to `conn_id` (connection ended).
    fn drop_connection(&self, conn_id: u64) {
        self.lock().subs.retain(|s| s.conn_id != conn_id);
    }

    /// Push `line` to each connection with at least one subscription matching
    /// `flow` (at most once per connection, even with several matching subs).
    fn fanout_flow(&self, flow: &Flow, line: &str) {
        let st = self.lock();
        let mut seen: Vec<u64> = Vec::new();
        for sub in &st.subs {
            if seen.contains(&sub.conn_id) || !sub.filter.matches(flow) {
                continue;
            }
            seen.push(sub.conn_id);
            sub.sink.push(line.to_string());
        }
    }

    /// Push `line` to every subscribed connection (once each), regardless of
    /// filter — state changes concern the whole session.
    fn fanout_state(&self, line: &str) {
        let st = self.lock();
        let mut seen: Vec<u64> = Vec::new();
        for sub in &st.subs {
            if seen.contains(&sub.conn_id) {
                continue;
            }
            seen.push(sub.conn_id);
            sub.sink.push(line.to_string());
        }
    }
}

/// The core services a `CommandHost` borrows; shared handles so one server can
/// answer many connections.
struct Services {
    store: Arc<dyn FlowStore>,
    client: Arc<dyn ProxyClient>,
    guard: Arc<dyn ScopeRateGuard>,
    browser: Option<Arc<dyn BrowserDriver>>,
}

type OnBound = Box<dyn FnOnce(SocketAddr) + Send>;

/// Registry handle + transport selection + the services commands run against.
pub struct McpServer {
    registry: Arc<Registry>,
    transport: McpTransport,
    services: Option<Services>,
    on_bound: Mutex<Option<OnBound>>,
    ssrf: SsrfPolicy,
    poc_dir: Option<std::path::PathBuf>,
    config: Option<Arc<aitm_core::Config>>,
    /// The second loopback-TCP token; a connection presenting it is an operator.
    operator_token: Option<Arc<str>>,
    /// The role a stdio connection speaks as (default [`Frontend::Mcp`]).
    stdio_role: Frontend,
    /// The agent policy in effect, enforced by [`McpServer::call_tool`] for the
    /// agent role. Shared with the `AgentPlugin`, so an operator `agent.set` is
    /// seen here at once.
    agent_state: Arc<AgentState>,
    /// The live per-connection subscription registry (F4). `flow.subscribe`/
    /// `flow.unsubscribe` manage it; the dispatcher fans notifications to it.
    subscriptions: Arc<Subscriptions>,
    /// The core→server event broadcast sender; a connection built from the
    /// `SubscriptionPlugin`'s chain tap. `serve` subscribes a dispatcher task to
    /// it. `None` disables live flow push (the in-process path).
    push_tx: Option<broadcast::Sender<Event>>,
    /// Per-connection push-sink capacity (notification lines) before drop-oldest.
    push_capacity: usize,
    /// Monotonic source of per-connection ids, so each streaming connection's
    /// subscriptions can be dropped when it ends.
    conn_seq: Arc<AtomicU64>,
}

/// A JSON-RPC level failure (as opposed to a tool's own error result).
struct RpcError {
    code: i64,
    message: String,
}

impl RpcError {
    fn new(code: i64, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl McpServer {
    /// A server over `registry` that will listen on `transport`. Attach the core
    /// services with [`McpServer::with_services`] before serving `tools/call`.
    pub fn new(registry: Arc<Registry>, transport: McpTransport) -> Self {
        Self {
            registry,
            transport,
            services: None,
            on_bound: Mutex::new(None),
            ssrf: SsrfPolicy::default(),
            poc_dir: None,
            config: None,
            operator_token: None,
            stdio_role: Frontend::Mcp,
            // The milestone default; wiring overrides it from `McpConfig.policy`.
            agent_state: Arc::new(AgentState::new(AgentPolicy::Auto)),
            subscriptions: Arc::new(Subscriptions::default()),
            push_tx: None,
            push_capacity: DEFAULT_PUSH_CAPACITY,
            conn_seq: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Attach the core→server event broadcast (the `SubscriptionPlugin`'s chain
    /// tap). `serve` spawns a dispatcher that renders each event as a
    /// `notifications/aitm/flow` line and fans it to matching subscriptions.
    pub fn with_push(mut self, tx: broadcast::Sender<Event>) -> Self {
        self.push_tx = Some(tx);
        self
    }

    /// Set the per-connection push-sink capacity (notification lines before the
    /// oldest is dropped and the connection is flagged `lagged`).
    pub fn with_push_capacity(mut self, capacity: usize) -> Self {
        self.push_capacity = capacity.max(1);
        self
    }

    /// The configured per-connection push-sink capacity. The transport uses it to
    /// size a connection's sink when the caller did not inject one.
    pub fn push_capacity(&self) -> usize {
        self.push_capacity
    }

    /// Mint the next per-connection id (the transport tags each connection so its
    /// subscriptions are dropped when it ends).
    pub fn next_conn_id(&self) -> u64 {
        self.conn_seq.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// Drop every subscription a connection held (called by the transport when
    /// the connection ends).
    pub fn drop_connection(&self, conn_id: u64) {
        self.subscriptions.drop_connection(conn_id);
    }

    /// Render `ev` as a `notifications/aitm/flow` line and fan it to every
    /// subscription whose filter matches the event's flow. Non-blocking; a slow
    /// subscriber's sink absorbs or drops the line without stalling the caller.
    pub fn push_flow_event(&self, ev: &Event) {
        let Some(id) = event_flow_id(ev) else {
            return;
        };
        let Some(services) = self.services.as_ref() else {
            return;
        };
        let Some(flow) = services.store.get(id) else {
            return;
        };
        let line = json!({
            "jsonrpc": "2.0",
            "method": "notifications/aitm/flow",
            "params": {
                "event": event_label(ev),
                "id": id.to_string(),
                "summary": flow_summary(&flow),
            },
        })
        .to_string();
        self.subscriptions.fanout_flow(&flow, &line);
    }

    /// Render a `notifications/aitm/state` line from `state` (a params object)
    /// and fan it to every subscribed connection. Non-blocking.
    pub fn push_state(&self, state: JsonValue) {
        let line = json!({
            "jsonrpc": "2.0",
            "method": "notifications/aitm/state",
            "params": state,
        })
        .to_string();
        self.subscriptions.fanout_state(&line);
    }

    /// The shared agent-policy state the policy gate reads and `agent.set` writes.
    /// Wiring seeds it from `McpConfig.policy` and hands the same `Arc` to the
    /// `AgentPlugin`.
    pub fn with_agent_state(mut self, agent_state: Arc<AgentState>) -> Self {
        self.agent_state = agent_state;
        self
    }

    /// The operator token (loopback TCP) and the stdio connection's role. The
    /// agent token stays on [`McpTransport::LoopbackTcp`]; an operator token here
    /// lets a loopback connection present it to be treated as [`Frontend::Operator`].
    pub fn with_mcp_roles(mut self, operator_token: Option<String>, stdio_role: Frontend) -> Self {
        self.operator_token = operator_token.map(Into::into);
        self.stdio_role = stdio_role;
        self
    }

    /// The role a stdio connection is served as (default [`Frontend::Mcp`]).
    pub fn stdio_role(&self) -> Frontend {
        self.stdio_role
    }

    /// Attach the proxy configuration so `config.get`/`proxy.status` can read it.
    pub fn with_config(mut self, config: Arc<aitm_core::Config>) -> Self {
        self.config = Some(config);
        self
    }

    /// Use the configured SSRF policy for command-side pre-flights (the PoC
    /// runner's browser navigation), so it matches the connector instead of
    /// silently falling back to the default.
    pub fn with_ssrf_policy(mut self, policy: SsrfPolicy) -> Self {
        self.ssrf = policy;
        self
    }

    /// Confine `poc.run` to PoC files under `dir` (opt-in; `None` = unconfined).
    pub fn with_poc_dir(mut self, dir: Option<std::path::PathBuf>) -> Self {
        self.poc_dir = dir;
        self
    }

    /// The services every `Command::invoke` receives through its `CommandHost`.
    pub fn with_services(
        mut self,
        store: Arc<dyn FlowStore>,
        client: Arc<dyn ProxyClient>,
        guard: Arc<dyn ScopeRateGuard>,
        browser: Option<Arc<dyn BrowserDriver>>,
    ) -> Self {
        self.services = Some(Services {
            store,
            client,
            guard,
            browser,
        });
        self
    }

    /// Called once with the bound address when `serve` listens on loopback TCP
    /// (lets a caller that asked for port 0 learn the port).
    pub fn on_bound(self, f: impl FnOnce(SocketAddr) + Send + 'static) -> Self {
        if let Ok(mut slot) = self.on_bound.lock() {
            *slot = Some(Box::new(f));
        }
        self
    }

    /// Serve the configured transport until it ends (stdio EOF) or fails.
    /// `tools/list` enumerates every registered command; `tools/call` →
    /// `Command::invoke`.
    pub async fn serve(self) -> anyhow::Result<()> {
        let McpServer {
            registry,
            transport: selected,
            services,
            on_bound,
            ssrf,
            poc_dir,
            config,
            operator_token,
            stdio_role,
            agent_state,
            subscriptions,
            push_tx,
            push_capacity,
            conn_seq,
        } = self;
        let on_bound = on_bound.into_inner().unwrap_or(None);
        let server = Arc::new(McpServer {
            registry,
            transport: selected.clone(),
            services,
            on_bound: Mutex::new(None),
            ssrf,
            poc_dir,
            config,
            operator_token: operator_token.clone(),
            stdio_role,
            agent_state,
            subscriptions,
            push_tx: push_tx.clone(),
            push_capacity,
            conn_seq,
        });
        // The push dispatcher: for each core event, render + fan a flow
        // notification to matching subscriptions. One task per server, draining
        // the broadcast ring; it ends when every sender drops.
        if let Some(tx) = &push_tx {
            let dispatch_server = server.clone();
            let mut rx = tx.subscribe();
            tokio::spawn(async move {
                loop {
                    match rx.recv().await {
                        Ok(ev) => dispatch_server.push_flow_event(&ev),
                        // The dispatcher fell behind the ring: skip the missed
                        // events rather than block the chain (spec D3.5).
                        Err(broadcast::error::RecvError::Lagged(_)) => continue,
                        Err(broadcast::error::RecvError::Closed) => break,
                    }
                }
            });
        }
        match selected {
            McpTransport::Stdio => transport::serve_stdio(server).await,
            McpTransport::LoopbackTcp { port, token } => {
                let listener = LoopbackTcp::bind(port, token)
                    .await?
                    .with_operator_token(operator_token.map(|t| t.to_string()));
                if let Some(f) = on_bound {
                    f(listener.local_addr());
                }
                listener.serve(server).await
            }
        }
    }

    /// Handle one JSON-RPC message with a default agent connection
    /// ([`Frontend::Mcp`], no client label). Back-compat wrapper over
    /// [`McpServer::handle_on`] for in-process callers and existing tests.
    pub fn handle(&self, message: &str) -> Option<String> {
        self.handle_on(&ConnCtx::agent(), message)
    }

    /// Handle one JSON-RPC message on a specific connection; `None` when it was
    /// a notification (no reply). The `conn` carries the frontend role and the
    /// client label, so `tools/call` runs against the right [`Frontend`].
    pub fn handle_on(&self, conn: &ConnCtx, message: &str) -> Option<String> {
        let parsed: JsonValue = match serde_json::from_str(message) {
            Ok(v) => v,
            Err(e) => {
                return Some(
                    error_response(JsonValue::Null, PARSE_ERROR, format!("parse error: {e}"))
                        .to_string(),
                )
            }
        };
        let Some(req) = parsed.as_object() else {
            return Some(
                error_response(
                    JsonValue::Null,
                    INVALID_REQUEST,
                    "a request must be a JSON object",
                )
                .to_string(),
            );
        };
        // Absent id = notification; a present-but-null id still gets a reply.
        let id = req.get("id").cloned();
        let Some(method) = req.get("method").and_then(JsonValue::as_str) else {
            return Some(
                error_response(
                    id.unwrap_or(JsonValue::Null),
                    INVALID_REQUEST,
                    "missing `method`",
                )
                .to_string(),
            );
        };
        let params = req.get("params").cloned().unwrap_or_else(|| json!({}));
        let outcome = self.dispatch(conn, method, &params);
        let id = id?;
        Some(
            match outcome {
                Ok(result) => json!({"jsonrpc": "2.0", "id": id, "result": result}),
                Err(e) => error_response(id, e.code, e.message),
            }
            .to_string(),
        )
    }

    fn dispatch(
        &self,
        conn: &ConnCtx,
        method: &str,
        params: &JsonValue,
    ) -> Result<JsonValue, RpcError> {
        match method {
            "initialize" => {
                let version = params
                    .get("protocolVersion")
                    .and_then(JsonValue::as_str)
                    .unwrap_or(PROTOCOL_VERSION);
                Ok(json!({
                    "protocolVersion": version,
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "aitmproxy", "version": aitm_core::VERSION},
                }))
            }
            "ping" => Ok(json!({})),
            "tools/list" => {
                let tools: Vec<JsonValue> = self
                    .registry
                    .commands()
                    .map(|cmd| StdSchemaDerive.to_mcp_tool(cmd.as_ref()).to_json())
                    .collect();
                Ok(json!({"tools": tools}))
            }
            "tools/call" => self.call_tool(conn, params),
            m if m.starts_with("notifications/") => Ok(JsonValue::Null),
            other => Err(RpcError::new(
                METHOD_NOT_FOUND,
                format!("unknown method `{other}`"),
            )),
        }
    }

    fn call_tool(&self, conn: &ConnCtx, params: &JsonValue) -> Result<JsonValue, RpcError> {
        let name = params
            .get("name")
            .and_then(JsonValue::as_str)
            .ok_or_else(|| RpcError::new(INVALID_PARAMS, "missing tool `name`"))?;
        let empty = Map::new();
        let arguments = match params.get("arguments") {
            None | Some(JsonValue::Null) => &empty,
            Some(JsonValue::Object(args)) => args,
            Some(other) => {
                return Err(RpcError::new(
                    INVALID_PARAMS,
                    format!("`arguments` must be an object, got {other}"),
                ))
            }
        };
        // F4 connection-scoped subscription management. These need the ConnCtx's
        // push sink and the server's subscription registry — neither of which a
        // `CommandHost` can carry — so the server handles them directly instead
        // of through `Command::invoke`. They are `Read`: gated like any read
        // (blocked only under `Paused`, and only for the agent role).
        if name == "flow.subscribe" || name == "flow.unsubscribe" {
            if let Some(reason) = self.read_refusal(conn, name) {
                return Ok(tool_error(reason));
            }
            return Ok(self.handle_subscription(conn, name, arguments));
        }
        let cmd = self
            .registry
            .command(name)
            .ok_or_else(|| RpcError::new(INVALID_PARAMS, format!("unknown tool `{name}`")))?;
        // The agent policy gate (D2), before anything runs. Only the agent role
        // is gated; an operator or the CLI is the control and bypasses it.
        if let Some(reason) = self.policy_refusal(conn, cmd.as_ref()) {
            return Ok(tool_error(reason));
        }
        let services = self.services.as_ref().ok_or_else(|| {
            RpcError::new(
                INTERNAL_ERROR,
                "no core services attached; call McpServer::with_services first",
            )
        })?;
        let args = match params_from_json(arguments, &cmd.schema(), name) {
            Ok(args) => args,
            Err(e) => return Ok(tool_error(e.to_string())),
        };
        let host = CommandHost::new(
            services.store.as_ref(),
            services.client.as_ref(),
            services.guard.as_ref(),
            services.browser.as_deref(),
        )
        .with_ssrf(self.ssrf.clone())
        .with_poc_dir(self.poc_dir.clone())
        // The role comes from the connection (token class, or stdio_role), not a
        // hard-coded agent: an operator UI is treated as a human, an agent as an
        // agent, so gated commands and policy decide by who is actually on the end.
        .with_frontend(conn.role);
        let host = match &conn.client_label {
            Some(label) => host.with_client_label(label.clone()),
            None => host,
        };
        let host = match &self.config {
            Some(cfg) => host.with_config(cfg.clone()),
            None => host,
        };
        Ok(match cmd.invoke(args, &host) {
            Ok(value) => {
                let structured = to_json(&value);
                json!({
                    "content": [{"type": "text", "text": structured.to_string()}],
                    "structuredContent": structured,
                    "isError": false,
                })
            }
            // A failing command is a tool result, not a protocol failure.
            Err(e) => tool_error(format!("{e:#}")),
        })
    }

    /// The D2 policy decision for one command on one connection: `Some(reason)`
    /// when the agent policy refuses it, `None` when it may proceed. Only the
    /// agent role (`Frontend::Mcp`) is gated — `Operator`/`Cli` are the control.
    fn policy_refusal(&self, conn: &ConnCtx, cmd: &dyn Command) -> Option<String> {
        if conn.role != Frontend::Mcp {
            return None;
        }
        let policy = self.agent_state.policy();
        let sens = cmd.sensitivity();
        let allowed = match (policy, sens) {
            (AgentPolicy::All, Sensitivity::Read | Sensitivity::Write) => true,
            // `All` permits the Sensitive dimension, but only for a command that
            // carries its own per-command agent config gate (ca.install/uninstall →
            // ca.allow_agent_install, scope.add → scope.allow_agent_widen): the call
            // is deferred to the command, which self-governs — honouring its config
            // flag (runs iff on), dry-run escape, and its own audit/refusal — so the
            // two dimensions (policy + config gate) stay independent (spec D2). A
            // Sensitive command with no such gate is refused here (deny-by-default).
            (AgentPolicy::All, Sensitivity::Sensitive) => defers_to_command_gate(cmd.name()),
            (AgentPolicy::Auto, Sensitivity::Read | Sensitivity::Write) => true,
            // Autonomous with zero Sensitive actions: `Auto` always refuses a
            // Sensitive command for the agent, config gate on or not — switch to
            // `All` (unconditional) or `Ask` (operator approval) to permit one.
            (AgentPolicy::Auto, Sensitivity::Sensitive) => false,
            (AgentPolicy::Ask, Sensitivity::Read | Sensitivity::Write) => true,
            // `Ask` parks a Sensitive call for operator approval (Task 9); until
            // that lands it is refused rather than run.
            (AgentPolicy::Ask, Sensitivity::Sensitive) => false,
            (AgentPolicy::ReadOnly, Sensitivity::Read) => true,
            (AgentPolicy::ReadOnly, _) => false,
            (AgentPolicy::Paused, _) => false,
            // `AgentPolicy` is `#[non_exhaustive]`: a future posture fails closed.
            _ => false,
        };
        if allowed {
            None
        } else {
            Some(policy_refusal_reason(policy, sens, cmd.name()))
        }
    }

    /// The policy decision for a `Read` command (`flow.subscribe`/`unsubscribe`):
    /// `Some(reason)` only when the agent role is `Paused` (which refuses all),
    /// `None` otherwise. Operator/CLI always pass.
    fn read_refusal(&self, conn: &ConnCtx, name: &str) -> Option<String> {
        if conn.role != Frontend::Mcp {
            return None;
        }
        match self.agent_state.policy() {
            AgentPolicy::Paused => Some(format!(
                "`{name}` refused: the agent policy is `paused`; no agent command runs. An operator \
                 can change it with agent.set."
            )),
            _ => None,
        }
    }

    /// Run `flow.subscribe`/`flow.unsubscribe` against the connection and the
    /// subscription registry, returning the `tools/call` result.
    fn handle_subscription(
        &self,
        conn: &ConnCtx,
        name: &str,
        args: &Map<String, JsonValue>,
    ) -> JsonValue {
        let Some(sink) = conn.out.clone() else {
            return tool_error(format!(
                "`{name}` is only meaningful over a streaming MCP connection (it has no push sink \
                 to deliver notifications on)."
            ));
        };
        match name {
            "flow.subscribe" => self.subscribe(conn.conn_id, sink, args),
            "flow.unsubscribe" => self.unsubscribe(conn.conn_id, args),
            _ => tool_error(format!("unknown subscription command `{name}`")),
        }
    }

    /// Register a subscription for this connection; optionally replay matching
    /// store entries after `since` before live events. Returns `{sub_id}`.
    fn subscribe(
        &self,
        conn_id: u64,
        sink: NotificationSink,
        args: &Map<String, JsonValue>,
    ) -> JsonValue {
        let filter = FlowFilter::parse(args.get("filter"));
        let since = args
            .get("since")
            .and_then(JsonValue::as_str)
            .and_then(|s| s.parse::<FlowId>().ok());
        let sub_id = self
            .subscriptions
            .add(conn_id, sink.clone(), filter.clone());
        if let Some(since) = since {
            self.replay_since(&sink, &filter, since);
        }
        tool_ok(json!({ "sub_id": sub_id }))
    }

    /// Remove a subscription this connection owns. Returns `{}` whether or not it
    /// existed (idempotent).
    fn unsubscribe(&self, conn_id: u64, args: &Map<String, JsonValue>) -> JsonValue {
        let Some(sub_id) = args.get("sub_id").and_then(JsonValue::as_u64) else {
            return tool_error("flow.unsubscribe requires an integer `sub_id`".to_string());
        };
        self.subscriptions.remove(conn_id, sub_id);
        tool_ok(json!({}))
    }

    /// Replay the matching flows currently in the store that were captured after
    /// `since` (exclusive), oldest first, as `created` flow notifications — a
    /// reconnecting subscriber catches up before the live stream resumes.
    fn replay_since(&self, sink: &NotificationSink, filter: &FlowFilter, since: FlowId) {
        let Some(services) = self.services.as_ref() else {
            return;
        };
        let store = services.store.as_ref();
        let ids = store.query(&filter.as_query());
        // `query` returns ids in insertion order; replay only those after `since`.
        let start = ids.iter().position(|id| *id == since).map_or(0, |p| p + 1);
        for id in &ids[start..] {
            let Some(flow) = store.get(*id) else {
                continue;
            };
            let line = json!({
                "jsonrpc": "2.0",
                "method": "notifications/aitm/flow",
                "params": {
                    "event": "created",
                    "id": id.to_string(),
                    "summary": flow_summary(&flow),
                },
            })
            .to_string();
            sink.push(line);
        }
    }
}

/// Whether a Sensitive command carries its own per-command agent config gate, so
/// the `All` policy defers the agent's call to the command (which enforces the
/// flag, dry-run, and audit) instead of pre-empting it (spec D2, "runs iff its
/// config gate is on"). Any other Sensitive command is refused by the policy gate.
fn defers_to_command_gate(name: &str) -> bool {
    matches!(name, "ca.install" | "ca.uninstall" | "scope.add")
}

/// The refusal text for a command the agent policy blocked, tuned to why.
fn policy_refusal_reason(policy: AgentPolicy, sens: Sensitivity, name: &str) -> String {
    match policy {
        AgentPolicy::Paused => format!(
            "`{name}` refused: the agent policy is `paused`; no agent command runs. An operator can \
             change it with agent.set."
        ),
        AgentPolicy::ReadOnly => format!(
            "`{name}` refused: the agent policy is `readonly`; only read-only commands run. An \
             operator can change it with agent.set."
        ),
        // `Auto` runs read/write autonomously but permits no sensitive actions at
        // all — its config gate is irrelevant here (spec D2).
        AgentPolicy::Auto if sens == Sensitivity::Sensitive => format!(
            "`{name}` refused: the agent policy is `auto`, which runs read and write commands \
             autonomously but permits no sensitive actions. An operator can switch to `all` or \
             `ask` with agent.set to allow sensitive commands."
        ),
        _ if sens == Sensitivity::Sensitive => format!(
            "`{name}` refused: a sensitive command is not allowed to the agent under the `{}` \
             policy without its config gate (e.g. ca.allow_agent_install, scope.allow_agent_widen). \
             An operator can run or approve it, or open that gate.",
            policy.label()
        ),
        _ => format!(
            "`{name}` refused by the agent policy `{}`.",
            policy.label()
        ),
    }
}

/// A JSON-RPC error response.
pub(crate) fn error_response(id: JsonValue, code: i64, message: impl Into<String>) -> JsonValue {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {"code": code, "message": message.into()},
    })
}

fn tool_error(text: String) -> JsonValue {
    json!({
        "content": [{"type": "text", "text": text}],
        "isError": true,
    })
}

/// A successful `tools/call` result carrying `value` as its structured content,
/// mirroring the shape the normal command path produces.
fn tool_ok(value: JsonValue) -> JsonValue {
    json!({
        "content": [{"type": "text", "text": value.to_string()}],
        "structuredContent": value,
        "isError": false,
    })
}

/// The flow id an event concerns (every current variant names one).
fn event_flow_id(ev: &Event) -> Option<FlowId> {
    match ev {
        Event::RequestHeaders(id)
        | Event::Request(id)
        | Event::ResponseHeaders(id)
        | Event::Response(id)
        | Event::WsStart(id)
        | Event::WsEnd(id) => Some(*id),
        Event::WsMessage { flow, .. } | Event::Error { flow, .. } => Some(*flow),
        // `Event` is `#[non_exhaustive]`: a future flowless event pushes nothing.
        _ => None,
    }
}

/// The `notifications/aitm/flow` `event` label for a lifecycle event.
fn event_label(ev: &Event) -> &'static str {
    match ev {
        // The first event about an HTTP or WebSocket flow is its creation.
        Event::RequestHeaders(_) | Event::WsStart(_) => "created",
        Event::Request(_) => "request",
        Event::ResponseHeaders(_) | Event::Response(_) => "response",
        Event::WsMessage { .. } => "ws_message",
        Event::WsEnd(_) => "killed",
        Event::Error { .. } => "killed",
        _ => "meta",
    }
}

/// The `flow.get`-shaped summary a notification carries (full detail stays a
/// `flow.detail` pull, F5).
fn flow_summary(flow: &Flow) -> JsonValue {
    match flow {
        Flow::Http(f) => json!({
            "id": f.id.to_string(),
            "kind": "http",
            "method": f.request.method,
            "authority": f.request.authority,
            "path": f.request.path,
            "status": f.response.as_ref().map(|r| r.status),
        }),
        Flow::WebSocket(f) => json!({
            "id": f.id.to_string(),
            "kind": "ws",
            "handshake": f.handshake.to_string(),
            "messages": f.messages.len(),
        }),
    }
}
