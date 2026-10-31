//! The MCP server: JSON-RPC 2.0 dispatch over the command registry.
//!
//! `handle` is transport-neutral — one JSON-RPC message in, at most one out — so
//! the stdio and loopback-TCP transports (and in-process test clients) all run
//! the identical path: `tools/list` enumerates every registered command,
//! `tools/call` coerces the arguments by the command's schema and runs
//! `Command::invoke` against a `CommandHost` built from the attached services.

use std::borrow::Cow;
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant, SystemTime};

use aitm_core::{
    AgentPolicy, AgentState, AuditEntry, AuditResult, AuditRing, AuditSink, BrowserDriver, Command,
    CommandHost, EgressConfinement, Event, Flow, FlowId, FlowQuery, FlowStore, Frontend,
    McpTransport, ProxyClient, Registry, ScopeRateGuard, Sensitivity, SsrfPolicy,
};
use serde_json::{json, Map, Value as JsonValue};
use tokio::sync::{broadcast, Notify};

use crate::http::{StreamableHttp, StreamableHttpCfg};
use crate::json::{params_from_json, to_json};
use crate::schema::{McpSchemaDerive, StdSchemaDerive};
use crate::transport::{self, LoopbackTcp};

/// The default per-connection push-sink capacity (notification lines). A slow
/// subscriber's notification lane is bounded to this many lines before the oldest
/// are dropped and the connection is flagged `lagged`; replies are never bounded.
pub const DEFAULT_PUSH_CAPACITY: usize = 4096;

/// The most subscriptions one connection may hold at once (web-bus-push spec
/// AC11). Each is a registry entry retained until `flow.unsubscribe` or the end
/// of the connection, and every pushed event is matched against all of them
/// under the registry lock, so an authenticated client must not be able to grow
/// them without bound.
const MAX_SUBS_PER_CONN: usize = 32;

/// The longest `filter.host` or `filter.method` a subscribe may carry, in bytes
/// (web-bus-push spec AC11). A longer value is refused, never truncated: a
/// truncated filter would silently watch a different host or method than the
/// client asked for.
const MAX_FILTER_VALUE_BYTES: usize = 1024;

/// The default capacity of the core→server event broadcast ring.
pub const DEFAULT_BROADCAST_CAPACITY: usize = 8192;

/// How long an operator confirm-over-the-wire token stays valid before it is
/// rejected as expired (spec D4: "short TTL, single use").
pub const DEFAULT_CONFIRM_TTL: Duration = Duration::from_secs(120);

/// How long a Sensitive agent call parked under the `Ask` policy waits for an
/// operator's `agent.approve` before it is refused on timeout (spec D4 / Review
/// Focus #4: a parked call never hangs).
pub const DEFAULT_APPROVAL_TIMEOUT: Duration = Duration::from_secs(120);

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

/// How many replies may be queued before the read loop stops consuming new
/// requests (backpressure, RF#3). Replies are never dropped — the reader pauses
/// until the writer has drained the lane below this mark, so a client that sends
/// without reading cannot grow the reply queue without bound.
pub const DEFAULT_REPLY_HIGH_WATER: usize = 1024;

/// A bounded, per-connection push sink feeding one connection's writer task.
///
/// Two lanes share the sink so a slow subscriber can never grow core memory or
/// block the proxy data path:
/// - **replies** to the connection's own requests are **never dropped**, but the
///   lane is bounded by backpressure: once `reply_high_water` replies are queued,
///   the read loop stops consuming new requests ([`await_reply_capacity`]) until
///   the writer drains below the mark. A client that pipelines requests and never
///   reads therefore stalls (TCP backpressure) instead of growing memory (RF#3);
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
    reply_high_water: usize,
    lagged: AtomicBool,
    closed: AtomicBool,
    /// Wakes the writer task when there may be something new to write.
    notify: Notify,
    /// Wakes a read loop parked in [`NotificationSink::await_reply_capacity`] once
    /// the reply lane has drained below the high-water mark (or the sink closed).
    drained: Notify,
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
    /// at least 1) before dropping the oldest, and whose reply lane backpressures
    /// the reader at [`DEFAULT_REPLY_HIGH_WATER`].
    pub fn new(capacity: usize) -> Self {
        Self::with_limits(capacity, DEFAULT_REPLY_HIGH_WATER)
    }

    /// As [`NotificationSink::new`], but with an explicit reply-lane high-water
    /// mark (both clamped to at least 1). Used by tests to force backpressure
    /// cheaply.
    pub fn with_limits(capacity: usize, reply_high_water: usize) -> Self {
        Self {
            inner: Arc::new(SinkInner {
                queues: Mutex::new(SinkQueues::default()),
                capacity: capacity.max(1),
                reply_high_water: reply_high_water.max(1),
                lagged: AtomicBool::new(false),
                closed: AtomicBool::new(false),
                notify: Notify::new(),
                drained: Notify::new(),
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
    /// the lag flag, and wakes a reader parked for reply-lane capacity, since the
    /// reply lane is now empty.
    pub fn drain(&self) -> Vec<String> {
        let out: Vec<String> = {
            let mut q = self.lock();
            let mut out: Vec<String> = q.replies.drain(..).collect();
            if self.inner.lagged.swap(false, Ordering::Relaxed) {
                out.push(lagged_state_line());
            }
            out.extend(q.notes.drain(..));
            out
        };
        // Replies drained → a backpressured reader has room again.
        self.inner.drained.notify_one();
        out
    }

    /// How many notifications are currently queued (for tests / introspection).
    pub fn queued_len(&self) -> usize {
        self.lock().notes.len()
    }

    /// How many replies are currently queued (for tests / introspection).
    pub fn reply_queued_len(&self) -> usize {
        self.lock().replies.len()
    }

    /// Pause the read loop until the reply lane has room (below its high-water
    /// mark) or the sink is closed. This is the backpressure lever (RF#3): while a
    /// client is not reading its socket the writer cannot drain, so replies stay
    /// queued; the reader stops consuming new requests until the writer catches
    /// up, bounding memory without ever dropping a reply.
    pub async fn await_reply_capacity(&self) {
        loop {
            if self.inner.closed.load(Ordering::Relaxed)
                || self.lock().replies.len() < self.inner.reply_high_water
            {
                return;
            }
            // `drain`/`close` call `drained.notify_one`, which stores a permit even
            // if no waiter is parked yet, so a wake between the check above and the
            // await below is not lost; the loop then re-checks the condition.
            self.inner.drained.notified().await;
        }
    }

    /// Whether the notification lane has overflowed since the last drain.
    pub fn lagged(&self) -> bool {
        self.inner.lagged.load(Ordering::Relaxed)
    }

    /// Mark the sink closed and wake both the writer (so it can drain and exit)
    /// and any read loop parked for reply-lane capacity (so it unblocks when the
    /// connection is torn down rather than hanging on a writer that has gone).
    pub fn close(&self) {
        self.inner.closed.store(true, Ordering::Relaxed);
        self.inner.notify.notify_one();
        self.inner.drained.notify_one();
    }

    /// Whether [`NotificationSink::close`] has been called. The subscription
    /// registry checks this before registering, so a `flow.subscribe` from a frame
    /// that outlived its connection (a detached web `/bus` frame) is refused
    /// instead of registering a subscription nothing will ever drain.
    pub fn is_closed(&self) -> bool {
        self.inner.closed.load(Ordering::Relaxed)
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
    /// Parse the optional `filter` argument object (`{host?, method?}`). A string
    /// value longer than `MAX_FILTER_VALUE_BYTES` is an error naming the field.
    fn parse(filter: Option<&JsonValue>) -> Result<Self, String> {
        let Some(obj) = filter.and_then(JsonValue::as_object) else {
            return Ok(Self::default());
        };
        Ok(Self {
            host: bounded_filter_value(obj, "host")?,
            method: bounded_filter_value(obj, "method")?,
        })
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

/// The string field `key` of a filter object, or an error when it is longer than
/// `MAX_FILTER_VALUE_BYTES`. A missing or non-string field is `None`: unconstrained.
fn bounded_filter_value(obj: &Map<String, JsonValue>, key: &str) -> Result<Option<String>, String> {
    let Some(value) = obj.get(key).and_then(JsonValue::as_str) else {
        return Ok(None);
    };
    if value.len() > MAX_FILTER_VALUE_BYTES {
        return Err(format!(
            "flow.subscribe refused: filter.{key} is longer than {MAX_FILTER_VALUE_BYTES} bytes"
        ));
    }
    Ok(Some(value.to_string()))
}

/// One live subscription: the connection it belongs to, that connection's push
/// sink, and the filter it watches.
struct Subscription {
    sub_id: u64,
    conn_id: u64,
    /// The role of the connection that owns this subscription, so the server can
    /// tell whether an operator is present (to route `Ask`-policy approval
    /// requests, and to refuse at once when none is) without a separate
    /// connection registry.
    role: Frontend,
    sink: NotificationSink,
    filter: FlowFilter,
}

/// Why [`Subscriptions::add`] refused to register a subscription.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SubscribeRefused {
    /// The connection's sink is already closed: its teardown ran first.
    Closed,
    /// The connection already holds `MAX_SUBS_PER_CONN` subscriptions.
    TooMany,
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

    /// Register a subscription for `conn_id` (speaking as `role`) over `sink`;
    /// returns its `sub_id`, or a refusal without registering: `Closed` when
    /// `sink` is already closed, `TooMany` when the connection already holds
    /// `MAX_SUBS_PER_CONN` subscriptions. Both checks run under the registry
    /// lock. For `Closed` that means, with a transport that closes the sink
    /// before `drop_connection`, a subscribe racing the teardown is either
    /// refused here or swept by the pending drop; it cannot slip in between and
    /// outlive its connection (web-bus-push spec D4).
    fn add(
        &self,
        conn_id: u64,
        role: Frontend,
        sink: NotificationSink,
        filter: FlowFilter,
    ) -> Result<u64, SubscribeRefused> {
        let mut st = self.lock();
        if sink.is_closed() {
            return Err(SubscribeRefused::Closed);
        }
        let held = st.subs.iter().filter(|s| s.conn_id == conn_id).count();
        if held >= MAX_SUBS_PER_CONN {
            return Err(SubscribeRefused::TooMany);
        }
        st.next_sub += 1;
        let sub_id = st.next_sub;
        st.subs.push(Subscription {
            sub_id,
            conn_id,
            role,
            sink,
            filter,
        });
        Ok(sub_id)
    }

    /// Whether any live subscription belongs to a connection of `role` (e.g. an
    /// operator present to approve `Ask`-policy parked calls).
    fn any_role(&self, role: Frontend) -> bool {
        self.lock().subs.iter().any(|s| s.role == role)
    }

    /// Push `line` to each subscribed connection of `role` (once per connection).
    fn fanout_role(&self, role: Frontend, line: &str) {
        let st = self.lock();
        let mut seen: Vec<u64> = Vec::new();
        for sub in &st.subs {
            if sub.role != role || seen.contains(&sub.conn_id) {
                continue;
            }
            seen.push(sub.conn_id);
            sub.sink.push(line.to_string());
        }
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

/// The operator confirm-over-the-wire token store (spec D4). A `needs_confirmation`
/// reply mints one token bound to `{connection, command, arguments}`; the operator
/// re-sends the identical call carrying `_confirm:"<token>"`, which is validated
/// and consumed here. Tokens are single-use and expire after a short TTL, so a
/// leaked or replayed token cannot run the gated command.
#[derive(Default)]
struct ConfirmTokens {
    inner: Mutex<ConfirmState>,
}

#[derive(Default)]
struct ConfirmState {
    entries: Vec<ConfirmEntry>,
}

/// One outstanding confirmation, bound to the exact call it authorises.
struct ConfirmEntry {
    token: String,
    conn_id: u64,
    command: String,
    /// A stable, order-independent fingerprint of the call's arguments.
    fingerprint: String,
    expires: Instant,
}

impl ConfirmTokens {
    fn lock(&self) -> std::sync::MutexGuard<'_, ConfirmState> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Mint a token for this connection/command/arguments, valid for `ttl`.
    /// Expired entries are swept first so the table never grows unbounded.
    fn issue(&self, conn_id: u64, command: &str, fingerprint: &str, ttl: Duration) -> String {
        let now = Instant::now();
        let mut st = self.lock();
        st.entries.retain(|e| e.expires > now);
        let token = confirm_token_value();
        st.entries.push(ConfirmEntry {
            token: token.clone(),
            conn_id,
            command: command.to_string(),
            fingerprint: fingerprint.to_string(),
            expires: now + ttl,
        });
        token
    }

    /// Validate and consume `token`: it must match this connection, command, and
    /// argument fingerprint, and be unexpired. A match is removed (single-use).
    /// Returns whether it was accepted.
    fn consume(&self, conn_id: u64, command: &str, fingerprint: &str, token: &str) -> bool {
        let now = Instant::now();
        let mut st = self.lock();
        st.entries.retain(|e| e.expires > now);
        match st.entries.iter().position(|e| {
            e.token == token
                && e.conn_id == conn_id
                && e.command == command
                && e.fingerprint == fingerprint
        }) {
            Some(pos) => {
                st.entries.remove(pos);
                true
            }
            None => false,
        }
    }
}

/// A fresh, opaque confirm-token value from a CSPRNG (`uuid::Uuid::new_v4`), so
/// the value is non-sequential and unguessable (RF: tokens must be opaque).
/// Security still rests on the entry's `{conn_id, command, fingerprint}` binding,
/// single-use, TTL, and the already-authenticated connection; this value is just
/// the opaque handle to that entry.
fn confirm_token_value() -> String {
    format!("cfm_{}", uuid::Uuid::new_v4().simple())
}

/// A stable, key-order-independent fingerprint of a call's `arguments`, so the
/// operator's re-send matches the mint even if its client reorders keys.
fn confirm_fingerprint(args: &Map<String, JsonValue>) -> String {
    let sorted: std::collections::BTreeMap<&String, &JsonValue> = args.iter().collect();
    serde_json::to_string(&sorted).unwrap_or_default()
}

/// The structured `needs_confirmation` tool result an operator gets for a
/// confirm-gated call that carried no valid `_confirm` (spec D4). Non-error.
fn needs_confirmation(prompt: &str, token: &str) -> JsonValue {
    json!({
        "content": [{"type": "text", "text": prompt}],
        "structuredContent": {
            "status": "needs_confirmation",
            "prompt": prompt,
            "confirm_token": token,
        },
        "isError": false,
    })
}

/// The `Ask`-policy parked-request table (spec D4 / AC-M4-5b). When an agent makes
/// a Sensitive call under `AgentPolicy::Ask`, the server parks it here — keyed by
/// an opaque `request_id` — and the agent's call blocks on the entry's [`ParkSlot`]
/// until an operator's `agent.approve {request_id, allow}` resolves it or the
/// bounded approval timeout elapses. The waiting agent thread holds the command and
/// its arguments on its own stack; this table holds only the resolution channel, so
/// resolving never has to re-run anything itself.
/// The default ceiling on concurrently parked `Ask` requests. Each parked call
/// occupies one blocking-pool thread (the agent's `spawn_blocking` task awaiting
/// the operator), so an uncapped table lets a runaway or compromised agent open
/// many connections, park one Sensitive call on each, and saturate the pool —
/// starving the operator's own `agent.approve`/`agent.set`/`agent.set paused` and
/// defeating oversight during the window. Capping well below Tokio's default 512
/// blocking threads leaves ample headroom for the operator's control path (RF#5).
const MAX_PARKED_REQUESTS: usize = 64;

struct ParkedRequests {
    inner: Mutex<ParkState>,
    /// Maximum number of requests parked at once; a further park is refused.
    cap: usize,
}

impl Default for ParkedRequests {
    fn default() -> Self {
        Self {
            inner: Mutex::new(ParkState::default()),
            cap: MAX_PARKED_REQUESTS,
        }
    }
}

#[derive(Default)]
struct ParkState {
    entries: Vec<(String, Arc<ParkSlot>)>,
}

/// One parked call's resolution channel: `None` until resolved, then `Some(true)`
/// (approved) or `Some(false)` (denied). The waiting agent thread blocks on `cv`
/// with a timeout; `agent.approve` sets the state and notifies.
struct ParkSlot {
    state: Mutex<Option<bool>>,
    cv: Condvar,
}

impl ParkSlot {
    fn new() -> Self {
        Self {
            state: Mutex::new(None),
            cv: Condvar::new(),
        }
    }

    /// Record the decision and wake the waiting thread.
    fn resolve(&self, allow: bool) {
        let mut st = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *st = Some(allow);
        self.cv.notify_all();
    }

    /// Block until resolved or `timeout` elapses; `Some(allow)` if resolved,
    /// `None` on timeout. Never hangs (Review Focus #4).
    fn wait(&self, timeout: Duration) -> Option<bool> {
        let guard = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let guard = match self.cv.wait_timeout_while(guard, timeout, |s| s.is_none()) {
            Ok((g, _)) => g,
            Err(poisoned) => poisoned.into_inner().0,
        };
        *guard
    }
}

impl ParkedRequests {
    fn lock(&self) -> std::sync::MutexGuard<'_, ParkState> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Park a new request: if the table is below its cap, mint an opaque,
    /// non-sequential `request_id` (CSPRNG, RF#4), register its slot, and return
    /// both. `None` when the cap is reached — the caller refuses the call rather
    /// than parking it, so a flood cannot grow the table or the blocking pool
    /// without bound (RF#5).
    fn try_park(&self) -> Option<(String, Arc<ParkSlot>)> {
        let mut st = self.lock();
        if st.entries.len() >= self.cap {
            return None;
        }
        let request_id = format!("apr_{}", uuid::Uuid::new_v4().simple());
        let slot = Arc::new(ParkSlot::new());
        st.entries.push((request_id.clone(), slot.clone()));
        Some((request_id, slot))
    }

    /// How many requests are currently parked (for tests / introspection).
    #[cfg(test)]
    fn len(&self) -> usize {
        self.lock().entries.len()
    }

    /// Resolve `request_id` with `allow`, removing it from the table. Returns
    /// whether a parked request by that id was found (so `agent.approve` can report
    /// an unknown or already-resolved id).
    fn resolve(&self, request_id: &str, allow: bool) -> bool {
        let slot = {
            let mut st = self.lock();
            st.entries
                .iter()
                .position(|(id, _)| id == request_id)
                .map(|pos| st.entries.remove(pos).1)
        };
        match slot {
            Some(slot) => {
                slot.resolve(allow);
                true
            }
            None => false,
        }
    }

    /// Drop `request_id` if still present (idempotent; used by the waiting thread
    /// to clean up after a timeout — a resolved entry was already removed).
    fn forget(&self, request_id: &str) {
        self.lock().entries.retain(|(id, _)| id != request_id);
    }
}

/// The result of parking a Sensitive agent call under the `Ask` policy.
enum ParkOutcome {
    /// An operator approved it; the caller runs the command and returns its result.
    Approved,
    /// Denied, timed out, or no operator was connected — the agent call is refused.
    Refused(String),
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

/// The wire string for a connection's role in the `initialize` echo (Decision C):
/// `"operator"` for the operator role, `"agent"` for every other frontend. The
/// two strings are a fixed part of the additive protocol.
fn role_str(role: Frontend) -> &'static str {
    match role {
        Frontend::Operator => "operator",
        _ => "agent",
    }
}

/// Registry handle + transport selection + the services commands run against.
pub struct McpServer {
    registry: Arc<Registry>,
    transport: McpTransport,
    services: Option<Services>,
    on_bound: Mutex<Option<OnBound>>,
    ssrf: SsrfPolicy,
    poc_dir: Option<std::path::PathBuf>,
    config: Option<Arc<aitm_core::Config>>,
    /// The finding recorder a `poc.run` persists through (the binary's
    /// `DiskFindingRecorder`). `None` = no persistence (deny-by-default; also
    /// gated on `findings.dir`). (T7)
    finding_recorder: Option<Arc<dyn aitm_core::FindingRecorder>>,
    /// The proxy's live browser-egress posture, handed to every host so
    /// `browser.confine` toggles the connector's real posture. `None` = the
    /// toggle is unavailable on this server (the command then errors).
    egress: Option<Arc<EgressConfinement>>,
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
    /// `SubscriptionPlugin`'s chain tap. [`McpServer::spawn_push_dispatcher`]
    /// (called by `serve`) subscribes a dispatcher task to it. `None` disables
    /// live flow push (the in-process path).
    push_tx: Option<broadcast::Sender<Event>>,
    /// Per-connection push-sink capacity (notification lines) before drop-oldest.
    push_capacity: usize,
    /// Monotonic source of per-connection ids, so each streaming connection's
    /// subscriptions can be dropped when it ends.
    conn_seq: Arc<AtomicU64>,
    /// Set by the first [`McpServer::spawn_push_dispatcher`] call, so a second
    /// call is a no-op rather than a second dispatcher delivering every event
    /// twice.
    dispatcher_spawned: AtomicBool,
    /// Outstanding operator confirm-over-the-wire tokens (spec D4).
    confirm_tokens: Arc<ConfirmTokens>,
    /// How long a minted confirm token stays valid.
    confirm_ttl: Duration,
    /// The F2 command-invocation audit ring (spec D3a). Always on; `call_tool`
    /// appends one entry per invocation (including refusals) after the gates, and
    /// `agent.activity` reads it. Shared with the `AgentPlugin` so both see the
    /// same entries.
    audit_ring: Arc<AuditRing>,
    /// An optional durable audit sink (a JSONL log, opt-in by config). When set,
    /// each entry is appended here as well as to the ring, so the full session is
    /// reconstructable after the fact (spec D3a.2); the CA plugin's log is a
    /// subset of this one format.
    durable_audit: Option<Arc<dyn AuditSink>>,
    /// The `Ask`-policy parked-request table (spec D4). A Sensitive agent call under
    /// `AgentPolicy::Ask` is parked here until an operator `agent.approve`s it or the
    /// approval timeout elapses.
    parked: Arc<ParkedRequests>,
    /// How long a parked Sensitive agent call waits for operator approval before it
    /// is refused on timeout (Review Focus #4: never hang).
    approval_timeout: Duration,
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
            finding_recorder: None,
            egress: None,
            operator_token: None,
            stdio_role: Frontend::Mcp,
            // The milestone default; wiring overrides it from `McpConfig.policy`.
            agent_state: Arc::new(AgentState::new(AgentPolicy::Auto)),
            subscriptions: Arc::new(Subscriptions::default()),
            push_tx: None,
            push_capacity: DEFAULT_PUSH_CAPACITY,
            conn_seq: Arc::new(AtomicU64::new(0)),
            dispatcher_spawned: AtomicBool::new(false),
            confirm_tokens: Arc::new(ConfirmTokens::default()),
            confirm_ttl: DEFAULT_CONFIRM_TTL,
            audit_ring: Arc::new(AuditRing::default()),
            durable_audit: None,
            parked: Arc::new(ParkedRequests::default()),
            approval_timeout: DEFAULT_APPROVAL_TIMEOUT,
        }
    }

    /// Set how long a Sensitive agent call parked under the `Ask` policy waits for
    /// an operator's `agent.approve` before it is refused on timeout (spec D4).
    /// Defaults to [`DEFAULT_APPROVAL_TIMEOUT`].
    pub fn with_approval_timeout(mut self, timeout: Duration) -> Self {
        self.approval_timeout = timeout;
        self
    }

    /// Share the F2 audit ring with the `AgentPlugin`, so `agent.activity` reads
    /// the very entries `call_tool` records. Wiring creates one ring, hands it
    /// here and to `AgentPlugin::with_audit_ring`.
    pub fn with_audit_ring(mut self, audit_ring: Arc<AuditRing>) -> Self {
        self.audit_ring = audit_ring;
        self
    }

    /// Attach a durable audit sink (a JSONL log). Opt-in: when absent, only the
    /// in-memory ring records. Every entry the ring gets is appended here too.
    pub fn with_durable_audit(mut self, sink: Arc<dyn AuditSink>) -> Self {
        self.durable_audit = Some(sink);
        self
    }

    /// Attach the core→server event broadcast (the `SubscriptionPlugin`'s chain
    /// tap). [`McpServer::spawn_push_dispatcher`] (which `serve` calls) spawns a
    /// dispatcher that renders each event as a `notifications/aitm/flow` line and
    /// fans it to matching subscriptions.
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

    /// Spawn this server's push dispatcher: one task that drains the core event
    /// broadcast attached by [`McpServer::with_push`] and fans each event to the
    /// matching subscriptions through [`McpServer::push_flow_event`]. A no-op
    /// when no broadcast was attached, and idempotent: a second call on the same
    /// server spawns nothing, so no subscriber receives an event twice.
    ///
    /// `serve` calls this before it listens. A server that is driven without
    /// `serve` (the web `/bus` bridge, which calls `handle_on` directly) must call
    /// it itself, or its subscriptions sit in a registry nothing ever feeds.
    ///
    /// The task holds this server and runs until the broadcast closes, that is
    /// until every sender has dropped. In the real wiring that is the life of
    /// the runtime: the server's own registry retains a sender (the
    /// `SubscriptionPlugin`'s), so the task, and the server with it, lives until
    /// the runtime shuts down.
    ///
    /// # Panics
    ///
    /// Outside a Tokio runtime, like `tokio::spawn`.
    pub fn spawn_push_dispatcher(self: &Arc<Self>) {
        let Some(tx) = &self.push_tx else {
            return;
        };
        // The swap alone decides which caller spawns; the flag orders no other
        // data, so `Relaxed` is enough.
        if self.dispatcher_spawned.swap(true, Ordering::Relaxed) {
            return;
        }
        let dispatch_server = Arc::clone(self);
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

    /// Set how long an operator confirm-over-the-wire token stays valid before it
    /// is rejected as expired (spec D4). Defaults to [`DEFAULT_CONFIRM_TTL`].
    pub fn with_confirm_ttl(mut self, ttl: Duration) -> Self {
        self.confirm_ttl = ttl;
        self
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

    /// Attach the proxy's live browser-egress posture (`Proxy::egress()`), so a
    /// `browser.confine` over this server flips the connector's real posture.
    /// Without it the command errors rather than toggling a detached copy.
    pub fn with_egress(mut self, egress: Arc<EgressConfinement>) -> Self {
        self.egress = Some(egress);
        self
    }

    /// Wire the finding recorder so a `poc.run` persists a durable finding (T7).
    /// Persistence stays gated on `findings.dir`; `None` records nothing.
    pub fn with_finding_recorder(mut self, recorder: Arc<dyn aitm_core::FindingRecorder>) -> Self {
        self.finding_recorder = Some(recorder);
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
            finding_recorder,
            egress,
            operator_token,
            stdio_role,
            agent_state,
            subscriptions,
            push_tx,
            push_capacity,
            conn_seq,
            dispatcher_spawned,
            confirm_tokens,
            confirm_ttl,
            audit_ring,
            durable_audit,
            parked,
            approval_timeout,
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
            finding_recorder,
            egress,
            operator_token: operator_token.clone(),
            stdio_role,
            agent_state,
            subscriptions,
            push_tx,
            push_capacity,
            conn_seq,
            dispatcher_spawned,
            confirm_tokens,
            confirm_ttl,
            audit_ring,
            durable_audit,
            parked,
            approval_timeout,
        });
        server.spawn_push_dispatcher();
        match selected {
            McpTransport::Stdio => transport::serve_stdio(server).await,
            McpTransport::LoopbackTcp {
                port,
                token,
                endpoint_file,
            } => {
                let listener = LoopbackTcp::bind(port, token, endpoint_file)
                    .await?
                    .with_operator_token(operator_token.map(|t| t.to_string()));
                if let Some(f) = on_bound {
                    f(listener.local_addr());
                }
                listener.serve(server).await
            }
            McpTransport::StreamableHttp {
                bind,
                token,
                allowed_origins,
                path,
            } => {
                let listener = StreamableHttp::bind(StreamableHttpCfg {
                    bind,
                    token,
                    allowed_origins,
                    path,
                })
                .await?;
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
                // Answer with the version we speak rather than echoing the
                // client's requested `protocolVersion` unchecked; a client that
                // needs a different version sees the one we support.
                Ok(json!({
                    "protocolVersion": PROTOCOL_VERSION,
                    // The connection's resolved role, echoed so each frontend can
                    // show it and warn on mismatch (Decision C). Additive and
                    // top-level — it describes this connection, not the server.
                    "role": role_str(conn.role),
                    // Additive (W2): advertise `resources` so MCP Apps hosts fetch
                    // the widget templates, plus the MCP Apps extension id. Clients
                    // that don't know these keys ignore them (research 08 §3.3).
                    "capabilities": {
                        "tools": {},
                        "resources": {},
                        "extensions": {
                            "io.modelcontextprotocol/ui": {
                                "mimeTypes": [crate::widgets::RESOURCE_MIME],
                            }
                        }
                    },
                    "serverInfo": {"name": "aitmproxy", "version": aitm_core::VERSION},
                }))
            }
            "ping" => Ok(json!({})),
            "resources/list" => {
                let resources: Vec<JsonValue> = crate::widgets::widgets()
                    .iter()
                    .map(|w| {
                        json!({
                            "uri": w.uri,
                            "name": w.name,
                            "title": w.title,
                            "description": w.description,
                            "mimeType": crate::widgets::RESOURCE_MIME,
                            "_meta": crate::widgets::resource_meta(w),
                        })
                    })
                    .collect();
                Ok(json!({"resources": resources}))
            }
            "resources/read" => {
                let uri = params
                    .get("uri")
                    .and_then(JsonValue::as_str)
                    .ok_or_else(|| RpcError::new(INVALID_PARAMS, "missing resource `uri`"))?;
                let widget = crate::widgets::widgets()
                    .iter()
                    .find(|w| w.uri == uri)
                    .ok_or_else(|| {
                        RpcError::new(INVALID_PARAMS, format!("unknown resource {uri}"))
                    })?;
                Ok(json!({
                    "contents": [{
                        "uri": widget.uri,
                        "mimeType": crate::widgets::RESOURCE_MIME,
                        "text": widget.html,
                        "_meta": crate::widgets::resource_meta(widget),
                    }]
                }))
            }
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
        let raw_arguments = match params.get("arguments") {
            None | Some(JsonValue::Null) => &empty,
            Some(JsonValue::Object(args)) => args,
            Some(other) => {
                return Err(RpcError::new(
                    INVALID_PARAMS,
                    format!("`arguments` must be an object, got {other}"),
                ))
            }
        };
        // Strip the reserved `_confirm` acknowledgment (spec D4) before anything
        // typed is built: it is never a declared command parameter, so it must not
        // reach `params_from_json` (which rejects unknown keys). Only the operator
        // confirm handshake reads it; every other role and path simply ignores it.
        let confirm_ack = raw_arguments
            .get("_confirm")
            .and_then(JsonValue::as_str)
            .map(str::to_string);
        let arguments: Cow<Map<String, JsonValue>> = if confirm_ack.is_some() {
            let mut m = raw_arguments.clone();
            m.remove("_confirm");
            Cow::Owned(m)
        } else {
            Cow::Borrowed(raw_arguments)
        };
        // Run the tool (gates, handshake, invoke); then audit every command
        // invocation that ran or was refused (F2, spec D3a.1). Two outcomes are
        // not audited: a `needs_confirmation` handshake step (it neither ran nor
        // was refused), and the server-handled subscription verbs
        // (`flow.subscribe`/`unsubscribe`) — those are connection management, not
        // registry command invocations, and pushing their line back to the very
        // subscriber would be self-referential noise.
        match self.run_tool(conn, name, &arguments, confirm_ack.as_deref()) {
            ToolOutcome::Rpc(e) => Err(e),
            ToolOutcome::Pending(value) => Ok(value),
            ToolOutcome::Done(value) => {
                // A subscription verb's *successful* run is connection management,
                // not a command invocation, so it is not audited (pushing its own
                // line back to the subscriber would be self-referential noise). A
                // *refusal* (the agent blocked under `Paused`, a closed connection,
                // the per-connection cap, an over-long filter) is audited like any
                // refused command (RF#6).
                if !is_subscription_verb(name) || is_error_result(&value) {
                    self.record_audit(conn, name, &arguments, &value);
                }
                Ok(value)
            }
        }
    }

    /// The tool-call core: the subscription shortcut, the policy/confirm gates,
    /// and `Command::invoke`. Returns a [`ToolOutcome`] so `call_tool` can audit
    /// what ran or was refused (`Done`) without auditing a protocol-level failure
    /// (`Rpc`) or a pending confirmation handshake (`Pending`).
    fn run_tool(
        &self,
        conn: &ConnCtx,
        name: &str,
        arguments: &Map<String, JsonValue>,
        confirm_ack: Option<&str>,
    ) -> ToolOutcome {
        // F4 connection-scoped subscription management. These need the ConnCtx's
        // push sink and the server's subscription registry — neither of which a
        // `CommandHost` can carry — so the server handles them directly instead
        // of through `Command::invoke`. They are `Read`: gated like any read
        // (blocked only under `Paused`; only trusted control —
        // `Frontend::is_trusted_control`: Operator, Cli — bypasses, every other
        // role, including any variant added later, is gated as an agent).
        if name == "flow.subscribe" || name == "flow.unsubscribe" {
            if let Some(reason) = self.read_refusal(conn, name) {
                return ToolOutcome::Done(tool_error(reason));
            }
            return ToolOutcome::Done(self.handle_subscription(conn, name, arguments));
        }
        // `agent.approve` is server-handled (spec D4): it resolves a parked `Ask`
        // request against the server's parked-request table, which a `CommandHost`
        // cannot carry. It is registered (for `tools/list`) but intercepted here,
        // before the registry/policy path. The agent role can never approve (RF#2).
        if name == "agent.approve" {
            return ToolOutcome::Done(self.handle_approve(conn, arguments));
        }
        let cmd = match self.registry.command(name) {
            Some(cmd) => cmd,
            None => {
                return ToolOutcome::Rpc(RpcError::new(
                    INVALID_PARAMS,
                    format!("unknown tool `{name}`"),
                ))
            }
        };
        // The agent policy gate (D2), before anything runs. Only trusted control
        // (`Frontend::is_trusted_control`: Operator, Cli) bypasses it; every other
        // role, including any variant added later, is gated as an agent. Under `Ask`, a
        // Sensitive agent call is parked for operator approval rather than refused.
        match self.policy_decision(conn, cmd.as_ref()) {
            PolicyDecision::Allow => {}
            PolicyDecision::Refuse(reason) => return ToolOutcome::Done(tool_error(reason)),
            PolicyDecision::Park => match self.park_for_approval(cmd.as_ref(), arguments) {
                // Approved: fall through and run the command as the agent.
                ParkOutcome::Approved => {}
                ParkOutcome::Refused(reason) => return ToolOutcome::Done(tool_error(reason)),
            },
        }
        let services = match self.services.as_ref() {
            Some(services) => services,
            None => {
                return ToolOutcome::Rpc(RpcError::new(
                    INTERNAL_ERROR,
                    "no core services attached; call McpServer::with_services first",
                ))
            }
        };
        let args = match params_from_json(arguments, &cmd.schema(), name) {
            Ok(args) => args,
            // Invalid arguments are a protocol error (per MCP), the same
            // INVALID_PARAMS envelope as the `unknown tool` / missing-`name` /
            // non-object `arguments` checks above — not a tool result, because the
            // command never ran (I16: one envelope for the whole arg-validation
            // class, expressed here in main's `ToolOutcome` return type).
            Err(e) => return ToolOutcome::Rpc(RpcError::new(INVALID_PARAMS, e.to_string())),
        };
        // D4 operator confirm-over-the-wire handshake. Only the operator role is
        // offered it; the agent is never handed a handshake — its confirm-gated
        // commands stay governed by their own config gate (applied inside the
        // command), so an agent can never self-confirm — and the CLI asks its own
        // local human through the `Confirmer`.
        if conn.role == Frontend::Operator {
            if let Some(prompt) = cmd.confirm_prompt(&args) {
                let fingerprint = confirm_fingerprint(arguments);
                match confirm_ack {
                    // A valid, matching, unexpired, single-use token: consume it
                    // and fall through to run the command.
                    Some(tok)
                        if self
                            .confirm_tokens
                            .consume(conn.conn_id, name, &fingerprint, tok) => {}
                    // A token was supplied but did not validate (wrong, expired,
                    // already used, or for a different call): refuse, do not run.
                    Some(_) => {
                        return ToolOutcome::Done(tool_error(format!(
                            "`{name}` confirmation token is invalid, expired, or already used; \
                             re-send the call without `_confirm` to obtain a fresh confirmation."
                        )));
                    }
                    // No acknowledgment: mint a token and ask for confirmation.
                    None => {
                        let token = self.confirm_tokens.issue(
                            conn.conn_id,
                            name,
                            &fingerprint,
                            self.confirm_ttl,
                        );
                        return ToolOutcome::Pending(needs_confirmation(&prompt, &token));
                    }
                }
            }
        }
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
        let host = match &self.egress {
            Some(egress) => host.with_egress(egress.clone()),
            None => host,
        };
        let host = match &conn.client_label {
            Some(label) => host.with_client_label(label.clone()),
            None => host,
        };
        let host = match &self.config {
            Some(cfg) => host.with_config(cfg.clone()),
            None => host,
        };
        let host = match &self.finding_recorder {
            Some(rec) => host.with_finding_recorder(rec.as_ref()),
            None => host,
        };
        // `summarize` reads the args and result, so keep a copy of the typed args
        // before `invoke` consumes them (D3b).
        let args_for_summary = args.clone();
        ToolOutcome::Done(match cmd.invoke(args, &host) {
            Ok(value) => {
                // `structuredContent` stays the exact machine value (contract
                // unchanged); only `content` text becomes a readable rendering —
                // the one-line summary (when the command provides one) plus pretty,
                // stable-key JSON — so the agent transcript reads cleanly (D3b).
                let structured = to_json(&value);
                let summary = cmd.summarize(&args_for_summary, &value);
                let text = crate::render::render_content(summary.as_deref(), &structured);
                json!({
                    "content": [{"type": "text", "text": text}],
                    "structuredContent": structured,
                    "isError": false,
                })
            }
            // A failing command is a tool result, not a protocol failure.
            Err(e) => tool_error(format!("{e:#}")),
        })
    }

    /// Append one [`AuditEntry`] for an invocation that ran or was refused (F2,
    /// spec D3a). `args_summary` is the arguments **redacted** (tokens, auth
    /// headers, and other secret-marked keys dropped) and size-capped, so a secret
    /// never reaches the ring, the durable log, or the pushed `agent` line. Each
    /// entry goes to the always-on ring, the optional durable sink, and the F4
    /// agent stream.
    fn record_audit(
        &self,
        conn: &ConnCtx,
        name: &str,
        arguments: &Map<String, JsonValue>,
        result: &JsonValue,
    ) {
        let outcome = if result
            .get("isError")
            .and_then(JsonValue::as_bool)
            .unwrap_or(false)
        {
            let reason = result
                .get("content")
                .and_then(JsonValue::as_array)
                .and_then(|c| c.first())
                .and_then(|m| m.get("text"))
                .and_then(JsonValue::as_str)
                .unwrap_or("error");
            // A refusal/error reason can echo a bad argument value (a header error
            // that quotes the offending value, a coercion error), so it is scrubbed
            // by content before it reaches the ring/durable log/pushed line (RF#3).
            AuditResult::Error(aitm_core::redact::scrub_text(reason))
        } else {
            AuditResult::Ok
        };
        let entry = AuditEntry {
            at: SystemTime::now(),
            origin: conn.role,
            client_label: conn.client_label.clone(),
            command: name.to_string(),
            args_summary: redact_args(arguments),
            result: outcome,
        };
        self.audit_ring.append(entry.clone());
        if let Some(durable) = &self.durable_audit {
            durable.append(entry.clone());
        }
        self.push_agent(&entry);
    }

    /// Render `entry` as a `notifications/aitm/agent` line and fan it to every
    /// subscribed connection (the agent stream concerns the whole session, so it
    /// is not flow-filtered). Non-blocking; a slow subscriber's sink absorbs or
    /// drops the line without stalling the caller (spec D3a.3).
    pub fn push_agent(&self, entry: &AuditEntry) {
        let line = json!({
            "jsonrpc": "2.0",
            "method": "notifications/aitm/agent",
            "params": to_json(&entry.to_value()),
        })
        .to_string();
        self.subscriptions.fanout_state(&line);
    }

    /// The D2 policy decision for one command on one connection. Every role that is
    /// not trusted control ([`Frontend::is_trusted_control`]: the agent role
    /// `Frontend::Mcp`, and any frontend added later) is gated — `Operator`/`Cli`
    /// are the control and always [`PolicyDecision::Allow`]. Under `Ask`, a
    /// Sensitive agent call is [`PolicyDecision::Park`]ed for operator approval
    /// instead of refused.
    fn policy_decision(&self, conn: &ConnCtx, cmd: &dyn Command) -> PolicyDecision {
        if conn.role.is_trusted_control() {
            return PolicyDecision::Allow;
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
            // `Ask` parks a Sensitive agent call for operator approval (spec D4) —
            // except the operator-only commands (`agent.set`/`agent.approve`), which
            // the agent can never run and so are refused outright, never parked.
            (AgentPolicy::Ask, Sensitivity::Sensitive) => {
                if is_operator_only(cmd.name()) {
                    false
                } else {
                    return PolicyDecision::Park;
                }
            }
            (AgentPolicy::ReadOnly, Sensitivity::Read) => true,
            (AgentPolicy::ReadOnly, _) => false,
            (AgentPolicy::Paused, _) => false,
            // `AgentPolicy` is `#[non_exhaustive]`: a future posture fails closed.
            _ => false,
        };
        if allowed {
            PolicyDecision::Allow
        } else {
            PolicyDecision::Refuse(policy_refusal_reason(policy, sens, cmd.name()))
        }
    }

    /// Park a Sensitive agent call under the `Ask` policy and block until an
    /// operator resolves it or the approval timeout elapses (spec D4 / RF#4). If no
    /// operator is connected to receive the request, refuse at once rather than park
    /// (an unseen request would only time out). On approval the caller runs the
    /// command as the agent; otherwise the agent call is refused with a clear reason.
    fn park_for_approval(
        &self,
        cmd: &dyn Command,
        arguments: &Map<String, JsonValue>,
    ) -> ParkOutcome {
        if !self.subscriptions.any_role(Frontend::Operator) {
            return ParkOutcome::Refused(format!(
                "`{}` refused: the agent policy is `ask`, which parks a sensitive command for \
                 operator approval, but no operator is connected to approve it. An operator can \
                 connect and subscribe, or change the policy with agent.set.",
                cmd.name()
            ));
        }
        let prompt = self.approval_prompt(cmd, arguments);
        let Some((request_id, slot)) = self.parked.try_park() else {
            return ParkOutcome::Refused(format!(
                "`{}` refused: too many sensitive agent commands ({}) are already awaiting \
                 operator approval. Wait for pending requests to resolve, or change the policy \
                 with agent.set.",
                cmd.name(),
                MAX_PARKED_REQUESTS,
            ));
        };
        self.push_approval_request(cmd.name(), arguments, &prompt, &request_id);
        let outcome = slot.wait(self.approval_timeout);
        // Clean up a timed-out entry (an approved/denied one was already removed).
        self.parked.forget(&request_id);
        match outcome {
            Some(true) => ParkOutcome::Approved,
            Some(false) => ParkOutcome::Refused(format!(
                "`{}` refused: an operator denied the parked sensitive command.",
                cmd.name()
            )),
            None => ParkOutcome::Refused(format!(
                "`{}` refused: no operator approved the parked sensitive command within the \
                 approval timeout.",
                cmd.name()
            )),
        }
    }

    /// The human-readable approval prompt for a parked command: the command's own
    /// `confirm_prompt` when it has one (the `Ask` policy reuses the confirm
    /// handshake, spec D4), else a generic one. Argument coercion failures fall back
    /// to the generic prompt — the operator still sees the redacted args and name.
    fn approval_prompt(&self, cmd: &dyn Command, arguments: &Map<String, JsonValue>) -> String {
        params_from_json(arguments, &cmd.schema(), cmd.name())
            .ok()
            .and_then(|args| cmd.confirm_prompt(&args))
            .unwrap_or_else(|| {
                format!(
                    "The agent requests approval to run the sensitive command `{}`.",
                    cmd.name()
                )
            })
    }

    /// Push a `notifications/aitm/agent {event:"approval_requested", …}` line to
    /// every connected operator (spec D4). `args_summary` is redacted (RF#3), so a
    /// secret in the parked call's arguments never reaches the operator's stream.
    fn push_approval_request(
        &self,
        command: &str,
        arguments: &Map<String, JsonValue>,
        prompt: &str,
        request_id: &str,
    ) {
        let line = json!({
            "jsonrpc": "2.0",
            "method": "notifications/aitm/agent",
            "params": {
                "event": "approval_requested",
                "command": command,
                "args_summary": redact_args(arguments),
                "prompt": prompt,
                "request_id": request_id,
            },
        })
        .to_string();
        self.subscriptions.fanout_role(Frontend::Operator, &line);
    }

    /// Resolve a parked `Ask` request (`agent.approve`, spec D4). Operator/CLI only:
    /// the agent can never approve its own request (RF#2). `allow:true` wakes the
    /// waiting agent to run the parked command; `allow:false` refuses it. An unknown
    /// or already-resolved id is a plain error, not a role refusal.
    fn handle_approve(&self, conn: &ConnCtx, arguments: &Map<String, JsonValue>) -> JsonValue {
        if !conn.role.is_trusted_control() {
            return tool_error(
                "agent.approve refused: the agent cannot approve its own requests; only an \
                 operator or the human CLI may approve a parked sensitive command."
                    .to_string(),
            );
        }
        let Some(request_id) = arguments.get("request_id").and_then(JsonValue::as_str) else {
            return tool_error("agent.approve requires a string `request_id`.".to_string());
        };
        let Some(allow) = arguments.get("allow").and_then(JsonValue::as_bool) else {
            return tool_error("agent.approve requires a boolean `allow`.".to_string());
        };
        if self.parked.resolve(request_id, allow) {
            tool_ok(json!({}))
        } else {
            tool_error(format!(
                "agent.approve: no parked request `{request_id}` is awaiting approval (it may have \
                 already been resolved or timed out)."
            ))
        }
    }

    /// The policy decision for a `Read` command (`flow.subscribe`/`unsubscribe`):
    /// `Some(reason)` only when the agent policy is `Paused` (which refuses all) and
    /// the role is not trusted control ([`Frontend::is_trusted_control`]), `None`
    /// otherwise. Operator/CLI always pass.
    fn read_refusal(&self, conn: &ConnCtx, name: &str) -> Option<String> {
        if conn.role.is_trusted_control() {
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
            "flow.subscribe" => self.subscribe(conn.conn_id, conn.role, sink, args),
            "flow.unsubscribe" => self.unsubscribe(conn.conn_id, args),
            _ => tool_error(format!("unknown subscription command `{name}`")),
        }
    }

    /// Register a subscription for this connection; optionally replay matching
    /// store entries after `since` before live events. Returns `{sub_id}`, or a
    /// tool error (and replays nothing) when a filter value is over-long, the
    /// connection's sink is already closed, or the connection is at its
    /// subscription cap.
    fn subscribe(
        &self,
        conn_id: u64,
        role: Frontend,
        sink: NotificationSink,
        args: &Map<String, JsonValue>,
    ) -> JsonValue {
        let filter = match FlowFilter::parse(args.get("filter")) {
            Ok(filter) => filter,
            Err(reason) => return tool_error(reason),
        };
        let since = args
            .get("since")
            .and_then(JsonValue::as_str)
            .and_then(|s| s.parse::<FlowId>().ok());
        let sub_id = match self
            .subscriptions
            .add(conn_id, role, sink.clone(), filter.clone())
        {
            Ok(sub_id) => sub_id,
            Err(SubscribeRefused::Closed) => {
                return tool_error("flow.subscribe refused: this connection is closed".to_string());
            }
            Err(SubscribeRefused::TooMany) => {
                return tool_error(format!(
                    "flow.subscribe refused: too many subscriptions on this connection (max \
                     {MAX_SUBS_PER_CONN}); flow.unsubscribe first"
                ));
            }
        };
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

/// The result of [`McpServer::run_tool`], distinguishing what `call_tool` must do
/// next: `Done` ran or was refused and is audited; `Pending` is a confirmation
/// handshake step that neither ran nor was refused (not audited); `Rpc` is a
/// protocol-level failure returned as a JSON-RPC error (not audited).
enum ToolOutcome {
    /// A tool result (success or `isError`) — audit it, then return it.
    Done(JsonValue),
    /// A `needs_confirmation` handshake reply — return it without auditing.
    Pending(JsonValue),
    /// A JSON-RPC level error (unknown tool, no services attached).
    Rpc(RpcError),
}

/// Whether `name` is a server-handled subscription verb rather than a registry
/// command. These manage the connection's push subscriptions directly (never
/// reaching `Command::invoke`), so they sit outside the command-invocation audit.
fn is_subscription_verb(name: &str) -> bool {
    name == "flow.subscribe" || name == "flow.unsubscribe"
}

/// Whether a `tools/call` result carries `isError: true` (a refusal or failure).
fn is_error_result(value: &JsonValue) -> bool {
    value
        .get("isError")
        .and_then(JsonValue::as_bool)
        .unwrap_or(false)
}

/// How long an argument summary may be (bytes of its JSON rendering) before it is
/// truncated, so a verbose or hostile argument set cannot grow an audit entry
/// without bound.
const ARGS_SUMMARY_CAP: usize = aitm_core::DEFAULT_ARGS_SUMMARY_CAP;

/// A redacted, size-capped rendering of a call's arguments for the audit entry.
/// Secret-named keys (auth headers, tokens, the confirm acknowledgment, and the
/// like) are replaced by `"<redacted>"` — recursively, so a secret nested inside
/// a `headers` object is caught too — and every surviving string value is run
/// through the content scrubber, so a token in a `path` query string or a
/// credential in a `body` is masked even though those keys are not secret-named
/// (RF#3). The result is truncated at a UTF-8 boundary. Secrets never reach the
/// ring, the durable log, or the pushed line.
fn redact_args(arguments: &Map<String, JsonValue>) -> String {
    let redacted = redact_value(&JsonValue::Object(arguments.clone()));
    let mut rendered = redacted.to_string();
    if rendered.len() > ARGS_SUMMARY_CAP {
        let mut cut = ARGS_SUMMARY_CAP;
        while cut > 0 && !rendered.is_char_boundary(cut) {
            cut -= 1;
        }
        rendered.truncate(cut);
        rendered.push('…');
    }
    rendered
}

/// Redact a value for the audit entry, by key *and* by content. A secret-named
/// key's value is dropped whole (`"<redacted>"`); every surviving string leaf is
/// run through the shared content scrubber, so a secret carried inside a
/// non-secret-named value — a token in a `path` query string, a credential in a
/// `body` — is masked too (RF#3). Recurses into objects and arrays.
fn redact_value(value: &JsonValue) -> JsonValue {
    match value {
        JsonValue::Object(map) => JsonValue::Object(
            map.iter()
                .map(|(key, val)| {
                    if is_secret_key(key) {
                        (key.clone(), JsonValue::from("<redacted>"))
                    } else {
                        (key.clone(), redact_value(val))
                    }
                })
                .collect(),
        ),
        JsonValue::Array(items) => JsonValue::Array(items.iter().map(redact_value).collect()),
        JsonValue::String(s) => JsonValue::String(aitm_core::redact::scrub_text(s)),
        other => other.clone(),
    }
}

/// Whether an argument key names a secret whose value must never be audited. The
/// vocabulary is the shared one in `aitm-core` (so audit and findings redaction
/// never diverge again); the reserved `_confirm` acknowledgment is an MCP-local
/// addition (it is already stripped before redaction, so this is belt and braces).
fn is_secret_key(key: &str) -> bool {
    aitm_core::redact::is_secret_key(key) || key.to_ascii_lowercase().contains("_confirm")
}

/// Whether a Sensitive command carries its own per-command agent config gate, so
/// the `All` policy defers the agent's call to the command (which enforces the
/// flag, dry-run, and audit) instead of pre-empting it (spec D2, "runs iff its
/// config gate is on"). Any other Sensitive command is refused by the policy gate.
fn defers_to_command_gate(name: &str) -> bool {
    matches!(
        name,
        "ca.install"
            | "ca.uninstall"
            | "scope.add"
            // The L4 Sensitive verbs each carry a per-capability agent gate
            // (`l4.allow_agent_*`, surfaced as the Mcp-only `L4AgentGate` wrapper and,
            // for widen, inside `l4.scope.add`): under `All` the call is deferred to
            // the command, which runs iff its flag is on — the two dimensions (policy
            // + per-capability flag) stay independent. `l4.agent.set` is deliberately
            // excluded (operator-only; the agent can never flip its own gates).
            | "l4.scope.add"
            | "l4.capture.start"
            | "l4.inject"
            | "l4.send_recv"
            | "l4.intercept.start"
            | "l4.intercept.mutate"
            | "l4.intercept.forward"
            | "l4.intercept.drop"
    )
}

/// Whether `name` is an operator/CLI-only command the agent can never run — so it
/// is refused for the agent rather than parked for approval under `Ask` (the agent
/// must not be able to have its own `agent.set`/`agent.approve` approved, RF#2).
/// `agent.approve` is also intercepted before the policy gate; this keeps `agent.set`
/// (and any future operator-only Sensitive command) from being parked.
fn is_operator_only(name: &str) -> bool {
    matches!(name, "agent.set" | "agent.approve" | "l4.agent.set")
}

/// The agent-policy gate's decision for one command (spec D2/D4).
enum PolicyDecision {
    /// The command may run: trusted control (`Frontend::is_trusted_control`), or
    /// an agent call the policy allows.
    Allow,
    /// The command is refused with this reason.
    Refuse(String),
    /// A Sensitive agent call under `Ask`: park it for operator approval.
    Park,
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

#[cfg(test)]
mod tests {
    use super::*;

    /// RF#5: the parked-request table refuses to park beyond its cap, so a flood
    /// of Sensitive `Ask` calls cannot grow the table (and the blocking pool)
    /// without bound.
    #[test]
    fn parked_requests_cap_refuses_beyond_limit() {
        let parked = ParkedRequests {
            inner: Mutex::new(ParkState::default()),
            cap: 2,
        };
        let first = parked.try_park();
        let second = parked.try_park();
        assert!(first.is_some() && second.is_some(), "first two park");
        assert_eq!(parked.len(), 2);
        assert!(
            parked.try_park().is_none(),
            "a third park is refused at the cap"
        );
        assert_eq!(parked.len(), 2, "a refused park does not grow the table");

        // Resolving one frees a slot, so a later park succeeds again (self-heals).
        let (id, _slot) = first.unwrap();
        assert!(parked.resolve(&id, true));
        assert_eq!(parked.len(), 1);
        assert!(parked.try_park().is_some(), "a slot frees up after resolve");
    }

    /// RF#4: confirm-token and parked-request-id values are opaque (CSPRNG) — not
    /// the old sequential counter / zero-entropy hash — and unique per mint.
    #[test]
    fn minted_ids_are_opaque_and_unique() {
        let a = confirm_token_value();
        let b = confirm_token_value();
        assert!(a.starts_with("cfm_") && b.starts_with("cfm_"));
        assert_ne!(a, b, "confirm tokens are unique");
        // A v4 UUID simple form is 32 hex chars after the prefix.
        assert_eq!(a.len(), "cfm_".len() + 32);

        let parked = ParkedRequests::default();
        let (id1, _) = parked.try_park().unwrap();
        let (id2, _) = parked.try_park().unwrap();
        assert!(id1.starts_with("apr_") && id2.starts_with("apr_"));
        assert_ne!(id1, id2, "request ids are unique");
        assert_ne!(
            id1, "apr_1",
            "request ids are not the old sequential counter"
        );
    }

    // ------------------------------------------------ Task 4b: egress wiring

    use aitm_core::{
        HttpFlow, HttpRequest, MemFlowStore, ParamSchema, Params, StdGuard, TypeDesc, Value,
    };
    use futures::future::BoxFuture;

    /// A `ProxyClient` the probe never reaches.
    struct NoClient;

    impl ProxyClient for NoClient {
        fn send(&self, _req: HttpRequest) -> BoxFuture<'_, anyhow::Result<HttpFlow>> {
            Box::pin(async { anyhow::bail!("egress.probe does not use the proxy client") })
        }
    }

    /// `egress.probe`: reports exactly what `browser.confine` reads off the
    /// host (`host.egress()`), so the wiring is testable here without the
    /// browser crate.
    struct EgressProbe;

    impl Command for EgressProbe {
        fn name(&self) -> &str {
            "egress.probe"
        }
        fn sensitivity(&self) -> Sensitivity {
            Sensitivity::Read
        }
        fn schema(&self) -> ParamSchema {
            ParamSchema {
                description: "Report the host's browser-egress posture.".into(),
                params: vec![],
                result: TypeDesc::Str,
            }
        }
        fn invoke(&self, _args: Params, host: &CommandHost) -> anyhow::Result<Value> {
            Ok(Value::Str(match host.egress() {
                None => "absent".into(),
                Some(e) if e.confined() => "confined".into(),
                Some(_) => "free".into(),
            }))
        }
    }

    fn probe_server() -> McpServer {
        let mut reg = Registry::new();
        reg.add_command(Arc::new(EgressProbe));
        McpServer::new(Arc::new(reg), McpTransport::Stdio).with_services(
            Arc::new(MemFlowStore::new()),
            Arc::new(NoClient),
            Arc::new(StdGuard::default()),
            None,
        )
    }

    fn probe(srv: &McpServer) -> JsonValue {
        let req = json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "egress.probe", "arguments": {}}
        });
        let resp = srv.handle(&req.to_string()).expect("a response");
        let resp: JsonValue = serde_json::from_str(&resp).expect("response is JSON");
        assert_eq!(resp["result"]["isError"], json!(false), "{resp}");
        resp["result"]["structuredContent"].clone()
    }

    /// Task 4b / AC9: the host an `McpServer` assembles per `tools/call` carries
    /// the live posture it was wired with — the same handle, so a later flip
    /// is visible through it.
    #[test]
    fn mcp_host_carries_the_wired_egress_posture() {
        let posture = Arc::new(EgressConfinement::new(false));
        let srv = probe_server().with_egress(posture.clone());
        assert_eq!(probe(&srv), json!("free"));

        posture.set_base(true);
        assert_eq!(
            probe(&srv),
            json!("confined"),
            "the host reads the live handle, not a snapshot"
        );
    }

    /// Without `with_egress` the host carries no posture (fail-closed: a
    /// `browser.confine` on such a host errors rather than toggling nothing).
    #[test]
    fn mcp_host_without_wiring_carries_no_posture() {
        assert_eq!(probe(&probe_server()), json!("absent"));
    }
}
