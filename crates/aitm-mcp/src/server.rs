//! The MCP server: JSON-RPC 2.0 dispatch over the command registry.
//!
//! `handle` is transport-neutral — one JSON-RPC message in, at most one out — so
//! the stdio and loopback-TCP transports (and in-process test clients) all run
//! the identical path: `tools/list` enumerates every registered command,
//! `tools/call` coerces the arguments by the command's schema and runs
//! `Command::invoke` against a `CommandHost` built from the attached services.

use std::borrow::Cow;
use std::collections::{HashSet, VecDeque};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant, SystemTime};

use aitm_core::{
    saturating_i64, AgentPolicy, AgentState, AuditEntry, AuditResult, AuditRing, AuditSink,
    BrowserDriver, Command, CommandHost, EgressConfinement, Event, Flow, FlowId, FlowQuery,
    FlowStore, Frontend, JobBus, JobEvent, McpTransport, ProxyClient, Registry, ScopeRateGuard,
    Sensitivity, SsrfPolicy,
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

/// The JSON-RPC notification method a [`aitm_core::JobEvent`] is rendered as
/// (spec D3 "Progress push", D9.2). The server does not interpret the event's
/// `kind`: a frontend that knows the kind reads `params`, one that does not
/// ignores the line. `aitm-scan-model` carries the same literal for its own
/// consumers; `aitm-mcp` does not depend on it, so the two are pinned by the
/// contract tests, not by a shared item.
pub const JOB_NOTIFICATION_METHOD: &str = "notifications/aitm/job";

/// The default for [`McpServer::write_timeout`], which defines what the deadline
/// bounds. At 30 s, one 16 MiB frame can still finish at about 0.53 MiB/s, far
/// below any real reader.
pub const DEFAULT_WRITE_TIMEOUT: Duration = Duration::from_secs(30);

/// The most subscriptions one connection may hold at once (web-bus-push spec
/// AC11). Each is a registry entry retained until `flow.unsubscribe` or the end
/// of the connection, and every pushed event is matched against all of them
/// under the registry lock, so an authenticated client must not be able to grow
/// them without bound. This bounds one connection only; opening many connections
/// is bounded by [`MAX_SUBS_TOTAL`].
const MAX_SUBS_PER_CONN: usize = 32;

/// The most subscriptions the registry holds at once across all connections
/// (bus-hardening spec D1), per `McpServer`. The registry's size drives the cost
/// of every fan-out (flow events, state pushes, the per-tool-call audit line),
/// all of which walk it under the registry lock, so a token-holder opening many
/// connections must not be able to grow it without bound either. 4096 is 128
/// connections at [`MAX_SUBS_PER_CONN`], far above real use, and keeps the
/// registry under 10 MiB. A subscribe past it is refused, not evicting anyone;
/// `flow.unsubscribe` or the end of a connection frees slots.
const MAX_SUBS_TOTAL: usize = 4096;

const _: () = assert!(MAX_SUBS_TOTAL >= MAX_SUBS_PER_CONN);

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
/// `client_label` is the connection's declared name, carried for audit only and
/// sanitised on every consumption (the audit entry and the command host both read
/// it through one helper), so whatever sets it, the ring never holds more than 64
/// characters of it. `out` is the bounded push sink the transport's writer task drains
/// (F4); `conn_id` identifies the connection so its subscriptions are dropped
/// when it ends. In-process callers (`McpServer::handle`) have no push sink.
#[derive(Debug, Clone)]
pub struct ConnCtx {
    /// The frontend this connection speaks as.
    pub role: Frontend,
    /// The human-readable client label: `initialize.clientInfo.name` for a TCP or
    /// stdio client, a server-minted name for the web bridge. Display only; it is
    /// sanitised (bounded, scrubbed) each time it is consumed, not trusted as set.
    pub client_label: Option<String>,
    /// A per-connection id, assigned by the transport, used to drop this
    /// connection's subscriptions when it ends. `0` means "not a streaming
    /// connection" (an in-process `handle` call): `connection_id` is `null` for
    /// it. It is also the sole per-connection input of `McpServer::connection_id`
    /// (the server's own random salt is the other input), so it must stay unique
    /// per server.
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
    /// The registry already holds `MAX_SUBS_TOTAL` subscriptions across all
    /// connections.
    TableFull,
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
    /// The connections that had a line suppressed under a muted policy and have
    /// not yet been told (so the first delivery after the mute is preceded by the
    /// `lagged` marker). Per connection, never a single registry-wide flag: the
    /// first delivery would clear a flag and a second connection would never be
    /// told. Written and cleared only inside [`Subscriptions::fanout`] and
    /// [`Subscriptions::drop_connection`], under the registry lock.
    gapped: Vec<u64>,
}

impl Subscriptions {
    fn lock(&self) -> std::sync::MutexGuard<'_, SubState> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Register a subscription for `conn_id` (speaking as `role`) over `sink`;
    /// returns its `sub_id`, or a refusal without registering. The checks run
    /// in this order, all under the one registry lock: `Closed` when `sink` is
    /// already closed, then `TooMany` when the connection already holds
    /// `MAX_SUBS_PER_CONN` subscriptions, then `TableFull` when the registry
    /// already holds `MAX_SUBS_TOTAL`. The per-connection cause comes before the
    /// table one because it is the cause the client controls and can fix, and it
    /// keeps its own text whatever the global load (bus-hardening spec D1).
    /// For `Closed` that means, with a transport that closes the sink before
    /// `drop_connection`, a subscribe racing the teardown is either refused here
    /// or swept by the pending drop; it cannot slip in between and outlive its
    /// connection (web-bus-push spec D4).
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
        if st.subs.len() >= MAX_SUBS_TOTAL {
            return Err(SubscribeRefused::TableFull);
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

    /// The only code that enqueues to a subscription's sink on a fan-out. The
    /// `fanout_*` entry points just say which subscriptions want the line, and
    /// `pushes_muted` is a required argument, so a new fan-out cannot forget the
    /// mute.
    ///
    /// While pushes are muted, a subscription whose role is not trusted control
    /// ([`Frontend::is_trusted_control`]) gets nothing and its connection is
    /// recorded in `gapped`. The next delivery to a recorded connection is preceded
    /// by one `lagged` state line. This function sends that marker itself instead of
    /// setting the sink's own overflow flag, because the next `drain` would write
    /// that flag while the policy is still muted and leak a bit under pause. The
    /// policy is read once, under the registry lock, so one snapshot covers every
    /// subscription and the read is as late as it can be. A connection gets the line
    /// at most once per call, and a due `lagged` marker precedes it.
    ///
    /// Ordering rule: `wants` is tested before any per-connection bookkeeping (the
    /// `seen` insert and the `gapped` record), so a connection is recorded only for
    /// a line it would have received. Recording first would let a non-matching
    /// subscription mask a later matching one on the same connection, a silent
    /// missed delivery.
    ///
    /// Cost under the lock: the once-per-call de-dup is a `HashSet`, so the `seen`
    /// check is O(1) per subscription. The `gapped` bookkeeping is not: it is a
    /// linear scan per connection delivered to or muted while any gap is recorded,
    /// and a gap entry stays until that connection is next delivered a line or
    /// ends. So a fan-out is O(subscriptions) under the lock only while no gap is
    /// recorded. Converting `gapped` to a `HashSet` is a known follow-up (the
    /// `gapped` scan in the bus-hardening spec's residuals).
    ///
    /// A mute stops new lines, not everything already in motion. These are accepted:
    ///
    /// - Lines already queued in an agent sink may still be written. Nothing is
    ///   purged, and the bound is the sink capacity. That includes the sink's own
    ///   overflow `lagged` marker if an overflow happened before the pause.
    /// - A `flow.subscribe {since}` that passed the gate just before the flip may
    ///   replay just after it (a replay is not a fan-out).
    /// - A fan-out that read the policy just before the flip may enqueue just after
    ///   it.
    fn fanout(
        &self,
        wants: &dyn Fn(&Subscription) -> bool,
        line: &str,
        pushes_muted: &dyn Fn() -> bool,
    ) {
        let mut guard = self.lock();
        let muted = pushes_muted();
        let st = &mut *guard;
        let mut seen: HashSet<u64> = HashSet::new();
        for sub in &st.subs {
            if !wants(sub) || !seen.insert(sub.conn_id) {
                continue;
            }
            if muted && !sub.role.is_trusted_control() {
                if !st.gapped.contains(&sub.conn_id) {
                    st.gapped.push(sub.conn_id);
                }
                continue;
            }
            if let Some(at) = st.gapped.iter().position(|c| *c == sub.conn_id) {
                st.gapped.swap_remove(at);
                sub.sink.push(lagged_state_line());
            }
            sub.sink.push(line.to_string());
        }
    }

    /// Push `line` to each subscribed connection of `role` (once per connection),
    /// through [`Subscriptions::fanout`]: an agent-role connection is not enqueued
    /// the line while `pushes_muted` says so.
    fn fanout_role(&self, role: Frontend, line: &str, pushes_muted: &dyn Fn() -> bool) {
        self.fanout(&|sub| sub.role == role, line, pushes_muted);
    }

    /// Remove `sub_id` if it belongs to `conn_id`. Returns whether it existed.
    fn remove(&self, conn_id: u64, sub_id: u64) -> bool {
        let mut st = self.lock();
        let before = st.subs.len();
        st.subs
            .retain(|s| !(s.sub_id == sub_id && s.conn_id == conn_id));
        st.subs.len() != before
    }

    /// Drop every subscription belonging to `conn_id` (connection ended), and its
    /// recorded gap if it has one, under the same lock: connection ids are never
    /// reused, so a gap left behind could never be cleared and would leak.
    fn drop_connection(&self, conn_id: u64) {
        let mut st = self.lock();
        st.subs.retain(|s| s.conn_id != conn_id);
        st.gapped.retain(|c| *c != conn_id);
    }

    /// Push `line` to each connection with at least one subscription matching
    /// `flow` (at most once per connection, even with several matching subs),
    /// through [`Subscriptions::fanout`]: an agent-role connection is not enqueued
    /// the line while `pushes_muted` says so.
    fn fanout_flow(&self, flow: &Flow, line: &str, pushes_muted: &dyn Fn() -> bool) {
        self.fanout(&|sub| sub.filter.matches(flow), line, pushes_muted);
    }

    /// Push `line` to every subscribed connection (once each), regardless of
    /// filter — state changes concern the whole session — through
    /// [`Subscriptions::fanout`]: an agent-role connection is not enqueued the line
    /// while `pushes_muted` says so.
    fn fanout_state(&self, line: &str, pushes_muted: &dyn Fn() -> bool) {
        self.fanout(&|_sub| true, line, pushes_muted);
    }

    /// Push the already-rendered audit `line` for `entry` to each subscribed
    /// connection whose role may see it, as decided by [`AuditEntry::visible_to`]:
    /// an agent-role subscriber never receives a line an operator or the CLI made.
    /// A connection gets the line at most once, however many subscriptions it
    /// holds, and a subscription's flow filter does not apply to an audit line;
    /// only the role's visibility does. The role is handed to the predicate, never
    /// compared here, so a role added later is classified in one place.
    ///
    /// The visibility predicate is the `wants` of [`Subscriptions::fanout`], which
    /// runs before the pause mute accounting. So a line a subscriber may not see
    /// neither reaches it nor **gaps** it while pushes are muted, and never causes
    /// a later `lagged` marker: the marker would otherwise tell a paused agent that
    /// the operator had acted. A marker follows only a push the subscriber could
    /// have seen.
    fn fanout_audit(&self, entry: &AuditEntry, line: &str, pushes_muted: &dyn Fn() -> bool) {
        self.fanout(&|sub| entry.visible_to(sub.role), line, pushes_muted);
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

/// How often a parked waiter re-reads the agent policy while it waits for an
/// operator. Short enough that a call whose policy has left `ask` is denied about
/// one slice later rather than at the approval timeout, long enough to cost almost
/// nothing: at most [`MAX_PARKED_REQUESTS`] waiters, each doing one atomic load
/// five times a second. See `McpServer::park_for_approval` and `ParkSlot::wait`.
const PARK_POLICY_RECHECK: Duration = Duration::from_millis(200);

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

    /// Block until the slot is resolved, `timeout` elapses, or `still_ask` says the
    /// policy the call was parked under no longer holds, whichever comes first.
    ///
    /// The wait is cut into slices of at most `recheck`, so the policy is read about
    /// that often rather than only at the timeout. A resolved slot is checked before
    /// the policy on every pass, so an approval that landed wins over a policy change
    /// seen in the same pass. The policy is not read before the first slice has run
    /// (a call is not second-guessed in the instant it parks). `still_ask` must be
    /// lock-free: it runs with the slot's mutex held. A `timeout` too large to
    /// matter, such as `Duration::MAX`, is effectively unbounded and does not panic.
    fn wait(&self, timeout: Duration, recheck: Duration, still_ask: &dyn Fn() -> bool) -> ParkWait {
        let start = Instant::now();
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        loop {
            if let Some(allow) = *state {
                return ParkWait::Resolved(allow);
            }
            let remaining = timeout.saturating_sub(start.elapsed());
            if remaining.is_zero() {
                return ParkWait::TimedOut;
            }
            let slice = recheck.min(remaining);
            state = match self.cv.wait_timeout_while(state, slice, |s| s.is_none()) {
                Ok((guard, _)) => guard,
                Err(poisoned) => poisoned.into_inner().0,
            };
            if let Some(allow) = *state {
                return ParkWait::Resolved(allow);
            }
            if !still_ask() {
                return ParkWait::PolicyChanged;
            }
        }
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
    /// Denied, timed out, the agent policy left `ask`, or no operator was connected
    /// — the agent call is refused.
    Refused(String),
}

/// How a parked waiter's wait ended (what [`ParkSlot::wait`] returns).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParkWait {
    /// An operator resolved the slot: `true` approved, `false` denied.
    Resolved(bool),
    /// The approval timeout elapsed with the slot unresolved.
    TimedOut,
    /// The agent policy was no longer `ask` at a recheck, with the slot unresolved.
    PolicyChanged,
}

/// The one test for "the policy a request was parked under still holds", used by
/// `agent.approve` (`McpServer::handle_approve`), by the waiter's slice recheck
/// (`McpServer::park_for_approval`), and by [`settle_park`], so the three layers
/// cannot disagree. A parked request exists only under `ask`.
///
/// An unknown future posture (`AgentPolicy` is `#[non_exhaustive]`) is not `Ask`,
/// so it fails closed and denies the request, as [`agent_reads_allowed`] does.
fn ask_still_in_force(policy: AgentPolicy) -> bool {
    policy == AgentPolicy::Ask
}

/// The pure decision after a parked waiter's wait returns: what the wait ended in,
/// and the policy read **after** it returned (the slot's guard already released),
/// become the call's [`ParkOutcome`]. Being pure it can be tested over its whole
/// table, including approve-then-pause, without a timer.
///
/// - `Resolved(true)` is `Approved` only while the policy is still `ask`; under any
///   other value (including an unknown future one) it is refused naming the change,
///   because an approval is a grant for the posture it was given under;
/// - `Resolved(false)` is refused with the existing denial text, under every policy;
/// - `TimedOut` is refused with the existing timeout text, under every policy;
/// - `PolicyChanged` is refused naming the change.
fn settle_park(name: &str, wait: ParkWait, policy: AgentPolicy) -> ParkOutcome {
    match wait {
        ParkWait::Resolved(true) if ask_still_in_force(policy) => ParkOutcome::Approved,
        ParkWait::Resolved(true) | ParkWait::PolicyChanged => ParkOutcome::Refused(format!(
            "`{name}` refused: the agent policy changed from `ask` to `{}` while this sensitive \
             command awaited operator approval, so it was not run. Re-issue it if the new \
             policy allows.",
            policy.label()
        )),
        ParkWait::Resolved(false) => ParkOutcome::Refused(format!(
            "`{name}` refused: an operator denied the parked sensitive command."
        )),
        ParkWait::TimedOut => ParkOutcome::Refused(format!(
            "`{name}` refused: no operator approved the parked sensitive command within the \
             approval timeout."
        )),
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

/// The wire string for a connection's role in the `initialize` echo (Decision C):
/// `"operator"` for the operator role, `"agent"` for every other frontend. The
/// two strings are a fixed part of the additive protocol.
fn role_str(role: Frontend) -> &'static str {
    match role {
        Frontend::Operator => "operator",
        _ => "agent",
    }
}

/// The per-server salt behind [`McpServer::connection_id`]: a v4 UUID (OS
/// randomness) folded to 64 bits. The fixed version and variant bits sit at
/// different positions in the two halves, so the xor leaves all 64 bits random.
fn draw_conn_salt() -> u64 {
    let (hi, lo) = uuid::Uuid::new_v4().as_u64_pair();
    hi ^ lo
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
    /// The write deadline (see [`McpServer::write_timeout`]). Always at least 1 ms.
    write_timeout: Duration,
    /// Monotonic source of per-connection ids, so each streaming connection's
    /// subscriptions can be dropped when it ends.
    conn_seq: Arc<AtomicU64>,
    /// 64 bits of OS randomness drawn once in [`McpServer::new`] and rendered,
    /// with `conn_id`, by [`McpServer::connection_id`]. It keeps two servers that
    /// share one audit ring (each counts connections from 1) from ever minting
    /// the same id, and a restart from repeating one.
    conn_salt: u64,
    /// Set by the first [`McpServer::spawn_push_dispatcher`] call, so a second
    /// call is a no-op rather than a second dispatcher delivering every event
    /// twice.
    dispatcher_spawned: AtomicBool,
    /// The generic job-progress bus (D9.2) this server renders as
    /// [`JOB_NOTIFICATION_METHOD`] lines and hands to every `CommandHost`, so a
    /// long-running command can publish progress. `None` = no job push on this
    /// server and `host.jobs()` is `None` (a publisher then simply has nowhere
    /// to publish; nothing fails).
    jobs: Option<Arc<JobBus>>,
    /// Set by the first [`McpServer::spawn_push_dispatcher`] call that finds a
    /// bus attached, so a second call does not deliver every job event twice.
    /// Separate from `dispatcher_spawned`: the two streams are attached
    /// independently, so a server may have either, both, or neither.
    job_dispatcher_spawned: AtomicBool,
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
            write_timeout: DEFAULT_WRITE_TIMEOUT,
            conn_seq: Arc::new(AtomicU64::new(0)),
            conn_salt: draw_conn_salt(),
            dispatcher_spawned: AtomicBool::new(false),
            jobs: None,
            job_dispatcher_spawned: AtomicBool::new(false),
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

    /// Attach the generic job-progress bus (D9.2). Every event published on it
    /// is rendered as a [`JOB_NOTIFICATION_METHOD`] line and fanned out with
    /// `fanout_state` semantics by the dispatcher
    /// [`McpServer::spawn_push_dispatcher`] starts, and the same bus is handed to
    /// every `CommandHost` this server builds, so a long-running command
    /// publishes to the bus its own frontend reads.
    ///
    /// Wiring creates one bus and hands the same `Arc` to every server (agent,
    /// in-process TUI, web bridge), so a job started on one is watched on all.
    pub fn with_jobs(mut self, bus: Arc<JobBus>) -> Self {
        self.jobs = Some(bus);
        self
    }

    /// The job bus attached by [`McpServer::with_jobs`], if any.
    pub fn jobs(&self) -> Option<Arc<JobBus>> {
        self.jobs.clone()
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

    /// Set the write deadline (see [`McpServer::write_timeout`] for what it
    /// bounds). Stored clamped to at least 1 ms: a zero deadline would fail every
    /// write at once. Defaults to [`DEFAULT_WRITE_TIMEOUT`].
    pub fn with_write_timeout(mut self, timeout: Duration) -> Self {
        self.write_timeout = timeout.max(Duration::from_millis(1));
        self
    }

    /// The write deadline a transport applies to its writes to a peer. This is
    /// the one statement of what the deadline means; the transports refer here.
    ///
    /// It bounds each send on its own: one websocket frame on the web bridge, one
    /// `write_all` or one `flush` on the line transport. It is not a budget for a
    /// connection or for a batch of writes, and a transport reads it once, when
    /// the connection starts.
    ///
    /// The clock stops when the socket has accepted the frame, not when the peer
    /// has read it. A peer that keeps reading frees room in the socket buffers as
    /// it goes, so its sends complete and it is not cut for being slow, unless it
    /// reads a frame slower than the frame's size over the deadline (see
    /// [`DEFAULT_WRITE_TIMEOUT`] for that rate). A peer that stops reading with
    /// the buffers full leaves the next send pending until the deadline expires,
    /// and the transport then ends the connection, so the peer cannot pin the
    /// connection's task, its descriptor and its subscriptions.
    ///
    /// A stopped peer is noticed only when something is sent to it, and then
    /// within one deadline. The deadline does not bound an idle connection.
    pub fn write_timeout(&self) -> Duration {
        self.write_timeout
    }

    /// Spawn this server's push dispatchers: one task per attached stream.
    ///
    /// - The **flow** stream: the core event broadcast attached by
    ///   [`McpServer::with_push`], each event fanned to the matching
    ///   subscriptions through [`McpServer::push_flow_event`].
    /// - The **job** stream: the [`JobBus`] attached by [`McpServer::with_jobs`],
    ///   each event rendered through [`McpServer::push_job_event`] (D9.2).
    ///
    /// Each half is a no-op when its stream was not attached, and each is
    /// idempotent on its own flag: a second call on the same server spawns
    /// nothing, so no subscriber receives an event twice.
    ///
    /// `serve` calls this before it listens. A server that is driven without
    /// `serve` (the web `/bus` bridge, which calls `handle_on` directly) must call
    /// it itself, or its subscriptions sit in a registry nothing ever feeds.
    ///
    /// A task holds this server and runs until its channel closes, that is until
    /// every sender has dropped. In the real wiring that is the life of the
    /// runtime: the server's own registry retains a flow sender (the
    /// `SubscriptionPlugin`'s) and the server itself retains the job bus, so the
    /// tasks, and the server with them, live until the runtime shuts down.
    ///
    /// # Panics
    ///
    /// Outside a Tokio runtime, like `tokio::spawn`.
    pub fn spawn_push_dispatcher(self: &Arc<Self>) {
        self.spawn_flow_dispatcher();
        self.spawn_job_dispatcher();
    }

    /// The flow half of [`McpServer::spawn_push_dispatcher`]: the core event
    /// broadcast attached by [`McpServer::with_push`]. A no-op without one, and
    /// idempotent.
    fn spawn_flow_dispatcher(self: &Arc<Self>) {
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

    /// The job half of [`McpServer::spawn_push_dispatcher`]: the [`JobBus`]
    /// attached by [`McpServer::with_jobs`] (D9.2). A no-op without one, and
    /// idempotent on its own flag, so a server may carry either stream, both, or
    /// neither. The subscription is taken here, before the task is spawned, so an
    /// event published the moment this returns is already in the receiver's ring.
    ///
    /// Progress is disposable: a dispatcher that falls behind the bus's ring skips
    /// the missed events (`Lagged`) rather than stall a job, because push is only
    /// a trigger — a frontend polls `scan.status` for truth (spec D3).
    fn spawn_job_dispatcher(self: &Arc<Self>) {
        let Some(bus) = &self.jobs else {
            return;
        };
        if self.job_dispatcher_spawned.swap(true, Ordering::Relaxed) {
            return;
        }
        let dispatch_server = Arc::clone(self);
        let mut rx = bus.subscribe();
        tokio::spawn(async move {
            loop {
                match rx.recv().await {
                    Ok(ev) => dispatch_server.push_job_event(&ev),
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

    /// The opaque, server-assigned id of `conn`, the one an audit line and the
    /// `initialize` reply carry; `None` when `conn` is not a streaming connection
    /// (`conn_id == 0`: in-process, HTTP POST, the embedded TUI).
    ///
    /// A pure function of this server's random salt and the connection's
    /// `conn_id`, rendered `conn_<16 lowercase hex>-<decimal>` (at most 64 bytes
    /// of printable ASCII). Nothing a request carries is read into it: not
    /// `clientInfo`, not `_meta`, not an argument, not the client label. Callers
    /// compare it for equality only, and no policy decision keys off it. It is not
    /// a secret (an agent that reads its own id can compute the lower-numbered
    /// ones on this server): nothing accepts it as input, and it cannot be forged
    /// because the server stamps it from the `ConnCtx`, not because it is hidden.
    fn connection_id(&self, conn: &ConnCtx) -> Option<String> {
        (conn.conn_id != 0).then(|| format!("conn_{:016x}-{}", self.conn_salt, conn.conn_id))
    }

    /// Drop every subscription a connection held (called by the transport when
    /// the connection ends), and the record that it had a push suppressed while
    /// the agent policy was `paused` (see [`McpServer::push_flow_event`]), so the
    /// per-connection gap set cannot outlive the connection. Close the connection's
    /// sink first, then call this; see `Subscriptions::add`, which refuses a
    /// subscribe on a closed sink and so makes that order the contract a transport
    /// must follow (`serve_lines` and the web bridge's `ConnGuard` both do).
    pub fn drop_connection(&self, conn_id: u64) {
        self.subscriptions.drop_connection(conn_id);
    }

    /// Whether pushes to a non-trusted-control (agent-role) subscription are
    /// suppressed right now: the live agent policy, read from the shared
    /// [`AgentState`] at the moment of the push. It is the same decision
    /// `read_refusal` makes for a fresh `flow.subscribe`, through the one predicate
    /// `agent_reads_allowed`, so "may subscribe" and "receives pushes" cannot drift.
    fn agent_pushes_muted(&self) -> bool {
        !agent_reads_allowed(self.agent_state.policy())
    }

    /// Render `ev` as a `notifications/aitm/flow` line and fan it to every
    /// subscription whose filter matches the event's flow. Non-blocking; a slow
    /// subscriber's sink absorbs or drops the line without stalling the caller.
    ///
    /// While the agent policy is `paused` the line is **not enqueued** for a
    /// non-trusted-control (agent-role) subscription; that connection is recorded
    /// as having a gap, and the first line delivered to it after the policy relaxes
    /// is preceded by one `notifications/aitm/state {"lagged":true}` marker ("catch
    /// up via `flow.list`"). Operator and CLI subscriptions are never muted. The
    /// policy is read at the push, from the state this server shares with every
    /// other server on it, so an `agent.set` run anywhere takes effect here.
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
        self.subscriptions
            .fanout_flow(&flow, &line, &|| self.agent_pushes_muted());
    }

    /// Render a `notifications/aitm/state` line from `state` (a params object)
    /// and fan it to every subscribed connection. Non-blocking.
    ///
    /// Under the `paused` agent policy the line is not enqueued for an agent-role
    /// subscription (a gap is recorded and the marker rides the first delivery
    /// after resume, exactly as for [`McpServer::push_flow_event`]); operator and
    /// CLI subscriptions always receive it.
    pub fn push_state(&self, state: JsonValue) {
        let line = json!({
            "jsonrpc": "2.0",
            "method": "notifications/aitm/state",
            "params": state,
        })
        .to_string();
        self.subscriptions
            .fanout_state(&line, &|| self.agent_pushes_muted());
    }

    /// Render `ev` as a [`JOB_NOTIFICATION_METHOD`] line and fan it to every
    /// subscribed connection, with the same `fanout_state` semantics as
    /// [`McpServer::push_state`] (every connection holding any `flow.subscribe`
    /// subscription, at most one line each, role-aware, muted for agents under
    /// `paused`). Non-blocking.
    ///
    /// `params` is the event's payload when that is an object (anything else is
    /// dropped: a notification's params must be an object), with `job`, `kind`,
    /// `event` and `seq` inserted **only when the payload does not already carry
    /// them** — the publisher owns the vocabulary and the server never overwrites
    /// its view of it (call B16). The server interprets nothing else: an unknown
    /// `kind` is forwarded verbatim.
    pub fn push_job_event(&self, ev: &JobEvent) {
        let mut params = match to_json(&ev.payload) {
            JsonValue::Object(fields) => fields,
            _ => Map::new(),
        };
        params
            .entry("job")
            .or_insert_with(|| JsonValue::String(ev.job.clone()));
        params
            .entry("kind")
            .or_insert_with(|| JsonValue::String(ev.kind.clone()));
        params
            .entry("event")
            .or_insert_with(|| JsonValue::String(ev.event.clone()));
        params
            .entry("seq")
            .or_insert_with(|| JsonValue::Number(ev.seq.into()));
        let line = json!({
            "jsonrpc": "2.0",
            "method": JOB_NOTIFICATION_METHOD,
            "params": JsonValue::Object(params),
        })
        .to_string();
        self.subscriptions
            .fanout_state(&line, &|| self.agent_pushes_muted());
    }

    /// The shared agent-policy state the policy gate reads and `agent.set` writes.
    /// Wiring seeds it from `McpConfig.policy` and hands the same `Arc` to the
    /// `AgentPlugin`.
    ///
    /// Sharing the `Arc` shares the policy live. A policy change on it cuts agent
    /// pushes and parked approvals on every server that shares the `Arc`, as it
    /// happens, with no hook to call.
    ///
    /// A change does not stop a call that already passed the gate. Its reply is
    /// still delivered, and work it started (an armed intercept, a running scan)
    /// carries on. A server that is not given the shared `Arc` sees none of this:
    /// it keeps its own `AgentState`, so an `agent.set` on it reaches no other
    /// server and one made elsewhere does not reach it. The agent servers of
    /// bare `aitm`, `aitm web` and `aitm tui` all share the core's `Arc`
    /// through `tui::with_shared_governance`.
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
            write_timeout,
            conn_seq,
            conn_salt,
            dispatcher_spawned,
            jobs,
            job_dispatcher_spawned,
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
            write_timeout,
            conn_seq,
            conn_salt,
            dispatcher_spawned,
            jobs,
            job_dispatcher_spawned,
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
                    // This connection's id (a string), or `null` when the caller
                    // is not a streaming connection. Additive and top-level like
                    // `role`, never inside `serverInfo`.
                    "connection_id": self.connection_id(conn),
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
                // the per-connection cap, a full subscription table, an over-long
                // filter) is audited like any refused command (RF#6).
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
        // (refused when `agent_reads_allowed` says no: `Paused` today, and any
        // posture added later; only trusted control —
        // `Frontend::is_trusted_control`: Operator, Cli — bypasses, every other
        // role, including any variant added later, is gated as an agent).
        if name == "flow.subscribe" || name == "flow.unsubscribe" {
            if let Some(reason) = self.read_refusal(conn, name) {
                return ToolOutcome::Done(tool_error(reason));
            }
            // These verbs are answered here, before the normal `params_from_json`
            // path, so enforce their published schema explicitly — otherwise they
            // bypass the `additionalProperties:false`, type, and flow-id checks
            // every other tool gets (an undeclared key, a non-string `method`, or
            // a non-flow-id `since` would slip through, the last silently).
            if let Err(e) = self.enforce_verb_schema(name, arguments) {
                return ToolOutcome::Rpc(e);
            }
            return ToolOutcome::Done(self.handle_subscription(conn, name, arguments));
        }
        // `agent.approve` is server-handled (spec D4): it resolves a parked `Ask`
        // request against the server's parked-request table, which a `CommandHost`
        // cannot carry. It is registered (for `tools/list`) but intercepted here,
        // before the registry/policy path. The agent role can never approve (RF#2).
        if name == "agent.approve" {
            // The role gate decides on the role alone, *before* any argument
            // validation: the agent can never approve, and its argument shape must
            // never become an oracle around the gate (RF#2). Only once the caller
            // is trusted control do we enforce the verb's published schema, like
            // any other command past its gate.
            if conn.role.is_trusted_control() {
                if let Err(e) = self.enforce_verb_schema(name, arguments) {
                    return ToolOutcome::Rpc(e);
                }
            }
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
        let host = match conn_audit_label(conn) {
            Some(label) => host.with_client_label(label),
            None => host,
        };
        // So a command can tell whose call it is.
        let host = match self.connection_id(conn) {
            Some(id) => host.with_connection_id(id),
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
        // So a long-running command can publish progress to the very bus this
        // server's dispatcher renders (D9.2).
        let host = match &self.jobs {
            Some(bus) => host.with_jobs(bus.clone()),
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
    ///
    /// The ring keeps the entry in the lane [`aitm_core::lane_for`] picks from the
    /// command's registered sensitivity and the outcome: a successful `Read` is
    /// routine, everything else (refused, failed, `Write`, `Sensitive`, and a name
    /// the registry does not know) is evidence, so a polling burst cannot evict a
    /// refusal. The lane only chooses where the ring keeps the entry; the durable
    /// sink and the agent stream still get every entry.
    ///
    /// The entry is bounded before any of them sees it: the label is sanitised on
    /// consumption and an error reason is scrubbed and then capped. The tool result
    /// returned to the caller is unchanged.
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
            // by content before it reaches the ring/durable log/pushed line (RF#3),
            // then capped so an echoed megabyte cannot fill the ring.
            AuditResult::Error(cap_reason(aitm_core::redact::scrub_text(reason)))
        } else {
            AuditResult::Ok
        };
        let entry = AuditEntry {
            at: SystemTime::now(),
            origin: conn.role,
            client_label: conn_audit_label(conn),
            connection_id: self.connection_id(conn),
            command: name.to_string(),
            args_summary: redact_args(arguments),
            result: outcome,
        };
        let sensitivity = self.registry.command(name).map(|c| c.sensitivity());
        let lane = aitm_core::lane_for(sensitivity, &entry.result);
        self.audit_ring.append_in(lane, entry.clone());
        if let Some(durable) = &self.durable_audit {
            durable.append(entry.clone());
        }
        self.push_agent(&entry);
    }

    /// Render `entry` as a `notifications/aitm/agent` line and fan it to every
    /// subscribed connection (the agent stream concerns the whole session, so it
    /// is not flow-filtered). Non-blocking; a slow subscriber's sink absorbs or
    /// drops the line without stalling the caller (spec D3a.3).
    ///
    /// Under the `paused` agent policy the line is not enqueued for an agent-role
    /// subscription that may see it; a gap is recorded and the marker rides the
    /// first delivery after resume (see [`McpServer::push_flow_event`]). Operator
    /// and CLI subscriptions always receive it.
    ///
    /// Only a subscription whose role may see the entry receives it
    /// ([`AuditEntry::visible_to`]: trusted control sees all, any other role only
    /// entries made by a non-trusted caller). The role filter lives here, in the one
    /// `pub` entry point, so every caller is covered, and it is applied before the
    /// mute accounting: an operator's audit line neither reaches an agent nor gaps
    /// it, so the audit line of the operator's own `agent.set paused` leaves no
    /// marker for the agent (see `Subscriptions::fanout_audit`).
    pub fn push_agent(&self, entry: &AuditEntry) {
        let line = json!({
            "jsonrpc": "2.0",
            "method": "notifications/aitm/agent",
            "params": to_json(&entry.to_value()),
        })
        .to_string();
        self.subscriptions
            .fanout_audit(entry, &line, &|| self.agent_pushes_muted());
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
            // Autonomous with zero Sensitive actions: `Auto` refuses a Sensitive
            // command for the agent, config gate on or not — switch to `All`
            // (unconditional) or `Ask` (operator approval) to permit one. The one
            // exception is a command that gates the agent *itself* under `auto`
            // (`defers_to_command_gate_under_auto`): it is let through to answer
            // in its own refusal vocabulary, and still refuses (call B6).
            (AgentPolicy::Auto, Sensitivity::Sensitive) => {
                defers_to_command_gate_under_auto(cmd.name())
            }
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
    /// operator resolves it, the approval timeout elapses, or the policy leaves
    /// `ask` (spec D4 / RF#4). If no operator is connected to receive the request,
    /// refuse at once rather than park (an unseen request would only time out). On
    /// approval the caller runs the command as the agent; otherwise the agent call
    /// is refused with a clear reason.
    ///
    /// The policy is live here, not a snapshot, because an approval is a grant for
    /// the posture it was given under: once the policy has left `ask`, the call must
    /// not run even if someone approves it. So the waiter re-reads the policy every
    /// `PARK_POLICY_RECHECK` and once more after the wait returns (the slot's guard
    /// already released), which catches an approval that landed just before a pause.
    /// Both reads use `ask_still_in_force` over the shared [`AgentState`], so an
    /// `agent.set` on any server sharing it reaches this waiter.
    ///
    /// Accepted: a policy flap shorter than one recheck slice is not seen (the state
    /// is one atomic with no generation), so the request stays parked and an
    /// approval is applied under the policy then in force. A call past its post-wake
    /// recheck is in flight, like one that passed the gate; the window is
    /// microseconds.
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
        let waited = slot.wait(self.approval_timeout, PARK_POLICY_RECHECK, &|| {
            ask_still_in_force(self.agent_state.policy())
        });
        // Clean up a timed-out or policy-denied entry (an approved/denied one was
        // already removed). The slot's guard is released by now.
        self.parked.forget(&request_id);
        // The policy is read after the wait returns, so an approval that landed just
        // before a policy change is still caught.
        settle_park(cmd.name(), waited, self.agent_state.policy())
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
        // Required by the fan-out, but trusted control is never muted, so it cannot suppress this.
        self.subscriptions
            .fanout_role(Frontend::Operator, &line, &|| self.agent_pushes_muted());
    }

    /// Resolve a parked `Ask` request (`agent.approve`, spec D4). Operator/CLI only:
    /// the agent can never approve its own request (RF#2). `allow:true` wakes the
    /// waiting agent to run the parked command; `allow:false` refuses it. An unknown
    /// or already-resolved id is a plain error, not a role refusal.
    ///
    /// A parked request is only approvable under the policy it was parked under, so
    /// after the role gate and the two parameter checks the live policy is read once
    /// (through `ask_still_in_force`). Under `ask` nothing changes. Under anything
    /// else, `allow:true` resolves the request as **denied** (waking the waiter) and
    /// returns an error saying the policy is no longer `ask` and the request was
    /// denied, so the operator is not told "approved" about a call that will not run;
    /// an id that does not exist still gets the plain "no parked request" error, so
    /// an unknown id is told apart from a policy refusal. `allow:false` is unchanged
    /// under every policy: the request is resolved as denied and the reply is a
    /// success, because a denial is always honoured and an error would suggest the
    /// request is still pending.
    fn handle_approve(&self, conn: &ConnCtx, arguments: &Map<String, JsonValue>) -> JsonValue {
        if !conn.role.is_trusted_control() {
            return tool_error(
                "agent.approve refused: the agent cannot approve its own requests; only an \
                 operator or the human CLI may approve a parked sensitive command."
                    .to_string(),
            );
        }
        // Fallback param checks for a server that intercepts `agent.approve`
        // without registering the command: on the normal path `enforce_verb_schema`
        // has already validated `request_id`/`allow` against the published schema
        // before this runs, so these only fire when there is no schema to enforce.
        let Some(request_id) = arguments.get("request_id").and_then(JsonValue::as_str) else {
            return tool_error("agent.approve requires a string `request_id`.".to_string());
        };
        let Some(allow) = arguments.get("allow").and_then(JsonValue::as_bool) else {
            return tool_error("agent.approve requires a boolean `allow`.".to_string());
        };
        let policy = self.agent_state.policy();
        // An approve counts only under the policy the request was parked under;
        // elsewhere it is resolved as a denial instead.
        let granted = allow && ask_still_in_force(policy);
        if !self.parked.resolve(request_id, granted) {
            return tool_error(format!(
                "agent.approve: no parked request `{request_id}` is awaiting approval (it may have \
                 already been resolved or timed out)."
            ));
        }
        if allow && !granted {
            return tool_error(format!(
                "agent.approve: the agent policy is no longer `ask` (it is `{}`), so parked \
                 request `{request_id}` was denied, not approved. The agent may re-issue the call \
                 under the current policy.",
                policy.label()
            ));
        }
        tool_ok(json!({}))
    }

    /// The policy decision for a `Read` command (`flow.subscribe`/`unsubscribe`):
    /// `Some(reason)` when the role is not trusted control
    /// ([`Frontend::is_trusted_control`]) and the live policy does not pass
    /// `agent_reads_allowed`, `None` otherwise. Operator/CLI always pass.
    ///
    /// Pushes ask the same predicate through `McpServer::agent_pushes_muted`, so a
    /// fresh subscribe is accepted exactly when a push would be delivered.
    fn read_refusal(&self, conn: &ConnCtx, name: &str) -> Option<String> {
        if conn.role.is_trusted_control() {
            return None;
        }
        let policy = self.agent_state.policy();
        if agent_reads_allowed(policy) {
            return None;
        }
        Some(format!(
            "`{name}` refused: the agent policy is `{}`; no agent command runs. An operator \
             can change it with agent.set.",
            policy.label()
        ))
    }

    /// Enforce a server-handled verb's published schema. `flow.subscribe`,
    /// `flow.unsubscribe`, and `agent.approve` are answered in [`McpServer::run_tool`]
    /// before the normal [`params_from_json`] path, so without this they would
    /// bypass the very `additionalProperties:false`, type, and flow-id checks every
    /// registry command gets. Validate the raw arguments against the command's own
    /// registered schema and surface a violation as the same `INVALID_PARAMS`
    /// envelope a mistyped regular command returns (so live and replay — and every
    /// frontend — see one validation contract). If the verb is not registered in
    /// this server, `tools/list` published no schema for it, so there is nothing to
    /// enforce and the call proceeds unchanged.
    fn enforce_verb_schema(
        &self,
        name: &str,
        arguments: &Map<String, JsonValue>,
    ) -> Result<(), RpcError> {
        let Some(cmd) = self.registry.command(name) else {
            return Ok(());
        };
        params_from_json(arguments, &cmd.schema(), name)
            .map(|_| ())
            .map_err(|e| RpcError::new(INVALID_PARAMS, e.to_string()))
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
    /// connection's sink is already closed, the connection is at its
    /// subscription cap, or the server's whole subscription table is full
    /// (each refusal has its own text; see `Subscriptions::add` for the order).
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
        // A malformed `since` is already rejected by `enforce_verb_schema` on the
        // registered path, so this `.ok()` only silently drops one when the verb is
        // unregistered (no published schema) — never on the normal path.
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
            Err(SubscribeRefused::TableFull) => {
                return tool_error(format!(
                    "flow.subscribe refused: the server's subscription table is full (max \
                     {MAX_SUBS_TOTAL} across all connections); try again later"
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
        // Fallback for an unregistered `flow.unsubscribe`: on the normal path
        // `enforce_verb_schema` has already required a well-typed `sub_id` against
        // the published schema before this runs.
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
    cap_text(redacted.to_string(), ARGS_SUMMARY_CAP)
}

/// The audit copy of an error reason, already scrubbed: at most
/// [`aitm_core::DEFAULT_RESULT_REASON_CAP`] bytes plus the `…` marker. The caller
/// of the tool still gets the whole text in the tool result; only the ring, the
/// durable log, and the pushed line carry the capped one.
fn cap_reason(reason: String) -> String {
    cap_text(reason, aitm_core::DEFAULT_RESULT_REASON_CAP)
}

/// Truncate `text` to at most `cap` bytes on a char boundary and append `…`, but
/// only when something was cut; text within the cap is returned untouched.
fn cap_text(mut text: String, cap: usize) -> String {
    if text.len() > cap {
        let mut cut = cap;
        while cut > 0 && !text.is_char_boundary(cut) {
            cut -= 1;
        }
        text.truncate(cut);
        text.push('…');
    }
    text
}

/// The connection's client label as the audit entry and the command host see it:
/// [`aitm_core::sanitize_client_label`] applied to `conn.client_label`. The field
/// is `pub`, so a transport or a test can set it to anything; sanitising here, at
/// consumption, bounds it (64 chars, control and bidi characters dropped,
/// credentials scrubbed) however it got there. The reserved-name guard is not
/// applied: `web-bridge` is the server's own label and passes unchanged.
fn conn_audit_label(conn: &ConnCtx) -> Option<String> {
    conn.client_label
        .as_deref()
        .and_then(aitm_core::sanitize_client_label)
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
            // `scan.start` reads the agent policy and its own
            // `scanner.allow_agent_active` / `scanner.allow_agent_l4_fuzz` gates
            // itself, and answers with its own `scan: refused_*` code (spec D11).
            | "scan.start"
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

/// Whether a Sensitive command refuses the agent *itself* under `AgentPolicy::Auto`,
/// so the policy gate lets it answer instead of pre-empting it with the generic
/// `auto` refusal (call B6).
///
/// A command listed here **must** refuse an agent under `auto` on its own — the
/// server makes no decision for it beyond letting the call through, and a command
/// that forgot would run. In exchange the caller gets one code vocabulary
/// (`scan: refused_agent: ...`) instead of two refusal texts for the same posture.
/// Every other Sensitive command keeps today's flat `auto` refusal, including the
/// L4 verbs, whose per-capability gates speak only under `all`.
fn defers_to_command_gate_under_auto(name: &str) -> bool {
    matches!(name, "scan.start")
}

/// Whether `name` is an operator/CLI-only command the agent can never run — so it
/// is refused for the agent rather than parked for approval under `Ask` (the agent
/// must not be able to have its own `agent.set`/`agent.approve` approved, RF#2).
/// `agent.approve` is also intercepted before the policy gate; this keeps `agent.set`
/// (and any future operator-only Sensitive command) from being parked.
fn is_operator_only(name: &str) -> bool {
    matches!(
        name,
        "agent.set"
            | "agent.approve"
            | "l4.agent.set"
            // The system-proxy mutators (spec 2026-10-31-system-proxy-automation-design,
            // SP-AC16): an agent can never point the OS at this core or restore it, so
            // under `Ask` the call is refused outright, never parked for approval.
            | "proxy.system.set"
            | "proxy.system.unset"
    )
}

/// The one decision behind both "may an agent-role caller subscribe now"
/// (`read_refusal`) and "does an agent-role subscription receive pushes now"
/// (`McpServer::agent_pushes_muted`): a push is a read channel, so pushes are
/// allowed to exactly the extent that reads are.
///
/// An allow-list of the four postures that are not `Paused`. `Paused` and any
/// posture added later (`AgentPolicy` is `#[non_exhaustive]`) are refused, so this
/// fails closed like `policy_decision` and `ask_still_in_force`. Whoever adds a
/// variant must decide it here, once.
fn agent_reads_allowed(policy: AgentPolicy) -> bool {
    matches!(
        policy,
        AgentPolicy::All | AgentPolicy::Auto | AgentPolicy::Ask | AgentPolicy::ReadOnly
    )
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

/// The summary a `notifications/aitm/flow` line carries: field for field the
/// `flow.get` object (`summarize` in `aitm-plugins`' capture module). The size
/// and timing rules are the core types' own (`Body::buffered_len`,
/// `FlowMeta::started_at_ms`, `FlowMeta::duration_ms`), so the null rules are
/// shared by construction: a `Streamed` body is `null`; no response is a `null`
/// status and `null` `response_bytes`; an in-flight flow has a `null`
/// `duration_ms`; a pre-epoch clock is a `null` `started_at`. The per-host
/// decryption keys (`tunnel`, `tunnel_reason`, `bytes_up`, `bytes_down`,
/// `passive`; spec D7) read `FlowMeta::tunnel` / `FlowMeta::passive` with the
/// core's own wire codes (`TunnelMode::label`, `TunnelReason::label`). Full
/// detail stays a `flow.detail` pull (F5).
///
/// Kept hand-written because `aitm-mcp` must not depend on `aitm-plugins`. The
/// key set and spelling of the two renderings are locked together by
/// `push_summary_equals_flow_get_for_http_and_websocket_flows` in
/// `tests/mcp.rs`, which compares a pushed summary with the real `flow.get`
/// value and fails on any drift on either side.
fn flow_summary(flow: &Flow) -> JsonValue {
    // Per-host decryption keys (spec D7), the same five on both kinds: a WebSocket
    // is never a tunnel row, so its tunnel keys are null; `passive` is as stamped.
    let tunnel = flow.metadata().tunnel.as_ref();
    let tunnel_mode = tunnel.map(|t| t.mode.label());
    let tunnel_reason = tunnel.and_then(|t| t.reason).map(|r| r.label());
    let bytes_up = tunnel.and_then(|t| t.bytes_up).map(saturating_i64);
    let bytes_down = tunnel.and_then(|t| t.bytes_down).map(saturating_i64);
    let passive = flow.metadata().passive;
    match flow {
        Flow::Http(f) => json!({
            "id": f.id.to_string(),
            "kind": "http",
            "intercept": f.intercept.label(),
            "is_replay": f.metadata.is_replay,
            "method": f.request.method,
            "scheme": f.request.scheme,
            "authority": f.request.authority,
            "path": f.request.path,
            "status": f.response.as_ref().map(|r| r.status),
            "request_bytes": f.request.body.buffered_len(),
            "response_bytes": f.response.as_ref().and_then(|r| r.body.buffered_len()),
            "started_at": f.metadata.started_at_ms(),
            "duration_ms": f.metadata.duration_ms(),
            "source_app": f.metadata.source_app,
            "capture_interface": f.metadata.capture_interface,
            "tunnel": tunnel_mode,
            "tunnel_reason": tunnel_reason,
            "bytes_up": bytes_up,
            "bytes_down": bytes_down,
            "passive": passive,
        }),
        Flow::WebSocket(f) => json!({
            "id": f.id.to_string(),
            "kind": "websocket",
            "intercept": f.intercept.label(),
            "is_replay": f.metadata.is_replay,
            "handshake": f.handshake.to_string(),
            "messages": f.messages.len(),
            "started_at": f.metadata.started_at_ms(),
            "duration_ms": f.metadata.duration_ms(),
            "source_app": f.metadata.source_app,
            "capture_interface": f.metadata.capture_interface,
            "tunnel": tunnel_mode,
            "tunnel_reason": tunnel_reason,
            "bytes_up": bytes_up,
            "bytes_down": bytes_down,
            "passive": passive,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use aitm_core::{Body, ConnInfo, FlowMeta, HeaderMap, HttpVersion, InterceptState};
    use aitm_plugins::AgentPlugin;
    use std::sync::atomic::AtomicUsize;

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

    /// Bus-hardening AC7: a fresh server carries the 30 s default write deadline,
    /// and the exported constant is that same 30 s.
    #[test]
    fn write_timeout_defaults_to_30_seconds() {
        let srv = McpServer::new(Arc::new(Registry::new()), McpTransport::Stdio);
        assert_eq!(srv.write_timeout(), Duration::from_secs(30));
        assert_eq!(DEFAULT_WRITE_TIMEOUT, Duration::from_secs(30));
    }

    /// Bus-hardening AC7: `with_write_timeout` stores the value it is given, and
    /// clamps zero up to 1 ms (a zero deadline would fail every write at once).
    #[test]
    fn with_write_timeout_sets_it_and_clamps_zero() {
        let srv = McpServer::new(Arc::new(Registry::new()), McpTransport::Stdio)
            .with_write_timeout(Duration::from_secs(7));
        assert_eq!(srv.write_timeout(), Duration::from_secs(7));

        let srv = McpServer::new(Arc::new(Registry::new()), McpTransport::Stdio)
            .with_write_timeout(Duration::ZERO);
        assert_eq!(srv.write_timeout(), Duration::from_millis(1));
    }

    /// Connections it takes to fill the registry at the per-connection cap.
    const FULL_CONNECTIONS: u64 = 128;

    /// Register `per_conn` unfiltered subscriptions for each id in `conn_ids`,
    /// speaking as `role`, each connection on its own `NotificationSink::new(4)`.
    /// Every add must succeed. Returns the sinks in `conn_ids` order.
    fn add_connections(
        reg: &Subscriptions,
        role: Frontend,
        conn_ids: impl IntoIterator<Item = u64>,
        per_conn: usize,
    ) -> Vec<NotificationSink> {
        conn_ids
            .into_iter()
            .map(|conn_id| {
                let sink = NotificationSink::new(4);
                for n in 0..per_conn {
                    let added = reg.add(conn_id, role, sink.clone(), FlowFilter::default());
                    assert!(
                        added.is_ok(),
                        "connection {conn_id}, subscription {n}: {added:?}"
                    );
                }
                sink
            })
            .collect()
    }

    /// A registry holding exactly `MAX_SUBS_TOTAL` subscriptions: connections
    /// `1..=128` of `MAX_SUBS_PER_CONN` (32) each.
    fn full_registry() -> (Subscriptions, Vec<NotificationSink>) {
        let reg = Subscriptions::default();
        let sinks = add_connections(
            &reg,
            Frontend::Operator,
            1..=FULL_CONNECTIONS,
            MAX_SUBS_PER_CONN,
        );
        assert_eq!(reg.lock().subs.len(), MAX_SUBS_TOTAL);
        (reg, sinks)
    }

    /// `add` as an operator with no filter: the call shape every refusal test
    /// below repeats.
    fn add_unfiltered(
        reg: &Subscriptions,
        conn_id: u64,
        sink: NotificationSink,
    ) -> Result<u64, SubscribeRefused> {
        reg.add(conn_id, Frontend::Operator, sink, FlowFilter::default())
    }

    /// A sink whose connection has already been torn down.
    fn closed_sink() -> NotificationSink {
        let sink = NotificationSink::new(4);
        sink.close();
        sink
    }

    /// The `sub_id` of the first subscription `conn_id` holds.
    fn a_sub_id_of(reg: &Subscriptions, conn_id: u64) -> u64 {
        reg.lock()
            .subs
            .iter()
            .find(|s| s.conn_id == conn_id)
            .map(|s| s.sub_id)
            .unwrap_or_else(|| panic!("connection {conn_id} holds no subscription"))
    }

    /// Bus-hardening AC1 / D1: the registry holds at most 4096 subscriptions
    /// across all connections. 128 connections at the per-connection cap fill it
    /// (every add succeeds), and a 129th connection is refused `TableFull`
    /// without growing it.
    #[test]
    fn the_table_cap_refuses_another_connection() {
        assert_eq!(MAX_SUBS_TOTAL, 4096);
        let (reg, _sinks) = full_registry();

        assert_eq!(
            add_unfiltered(&reg, FULL_CONNECTIONS + 1, NotificationSink::new(4)),
            Err(SubscribeRefused::TableFull)
        );
        assert_eq!(
            reg.lock().subs.len(),
            4096,
            "a refused add registers nothing"
        );
    }

    /// Bus-hardening AC2 / D1: with the registry full the refusal precedence is
    /// closed, then per-connection, then table. A closed sink is `Closed` even
    /// for a connection that is also at its own cap; a connection at its cap is
    /// `TooMany` even though the table is also full; a connection with room under
    /// its own cap (fresh, or holding 31) gets `TableFull`.
    #[test]
    fn refusal_precedence_is_closed_then_per_connection_then_table() {
        let (reg, _sinks) = full_registry();

        // Connection 1 holds 32 and the table is full: every later check would
        // fire, yet a closed sink is reported as `Closed`.
        assert_eq!(
            add_unfiltered(&reg, 1, closed_sink()),
            Err(SubscribeRefused::Closed)
        );
        assert_eq!(
            add_unfiltered(&reg, FULL_CONNECTIONS + 1, closed_sink()),
            Err(SubscribeRefused::Closed)
        );
        // Open sink, connection 1 at its cap, table full: the cause the client
        // controls wins.
        assert_eq!(
            add_unfiltered(&reg, 1, NotificationSink::new(4)),
            Err(SubscribeRefused::TooMany)
        );
        // Open sink, connection with no subscriptions, table full.
        assert_eq!(
            add_unfiltered(&reg, FULL_CONNECTIONS + 1, NotificationSink::new(4)),
            Err(SubscribeRefused::TableFull)
        );

        // A connection holding 31 (room under its own cap) is still refused by
        // the table: move one slot from connection 1 to a new connection first.
        let sub_id = a_sub_id_of(&reg, 1);
        assert!(reg.remove(1, sub_id));
        assert!(add_unfiltered(&reg, FULL_CONNECTIONS + 1, NotificationSink::new(4)).is_ok());
        assert_eq!(
            add_unfiltered(&reg, 1, NotificationSink::new(4)),
            Err(SubscribeRefused::TableFull),
            "connection 1 holds 31 of 32, so only the table can refuse it"
        );
        assert_eq!(reg.lock().subs.len(), MAX_SUBS_TOTAL);
    }

    /// Bus-hardening AC3 / D1: with the registry full, removing one subscription
    /// frees exactly one slot: one more add succeeds and the next is refused.
    #[test]
    fn unsubscribe_frees_exactly_one_table_slot() {
        let (reg, _sinks) = full_registry();
        let sub_id = a_sub_id_of(&reg, 1);

        assert!(reg.remove(1, sub_id), "the subscription existed");
        assert_eq!(reg.lock().subs.len(), MAX_SUBS_TOTAL - 1);

        assert!(
            add_unfiltered(&reg, FULL_CONNECTIONS + 1, NotificationSink::new(4)).is_ok(),
            "the freed slot is usable"
        );
        assert_eq!(
            add_unfiltered(&reg, FULL_CONNECTIONS + 2, NotificationSink::new(4)),
            Err(SubscribeRefused::TableFull),
            "only one slot was freed"
        );
        assert_eq!(reg.lock().subs.len(), MAX_SUBS_TOTAL);
    }

    /// Bus-hardening AC3 / D1: ending a connection frees all of its table slots.
    /// Dropping connection 1 (32 subscriptions) lets a new connection add 32, and
    /// its 33rd is the per-connection refusal, not the table one.
    #[test]
    fn ending_a_connection_frees_its_table_slots() {
        let (reg, _sinks) = full_registry();

        reg.drop_connection(1);
        assert_eq!(reg.lock().subs.len(), MAX_SUBS_TOTAL - MAX_SUBS_PER_CONN);

        let sink = NotificationSink::new(4);
        for n in 0..MAX_SUBS_PER_CONN {
            assert!(
                add_unfiltered(&reg, FULL_CONNECTIONS + 1, sink.clone()).is_ok(),
                "add {n} fits in the 32 freed slots"
            );
        }
        assert_eq!(
            add_unfiltered(&reg, FULL_CONNECTIONS + 1, sink),
            Err(SubscribeRefused::TooMany),
            "the new connection is now at its own cap, which takes precedence"
        );
        assert_eq!(
            add_unfiltered(&reg, FULL_CONNECTIONS + 2, NotificationSink::new(4)),
            Err(SubscribeRefused::TableFull),
            "and the table is full again"
        );
        assert_eq!(reg.lock().subs.len(), MAX_SUBS_TOTAL);
    }

    /// Bus-hardening AC4 / D1: through `handle_on`, a `flow.subscribe` on a full
    /// table is a tool error with its own text (not the per-connection one), no
    /// `structuredContent`, and registers nothing.
    #[test]
    fn a_full_table_refuses_flow_subscribe_with_its_own_text() {
        let srv = McpServer::new(Arc::new(Registry::new()), McpTransport::Stdio);
        // Pre-fill with other connections' ids, minted the way a transport does,
        // so the connection under test is a different one.
        let _sinks = add_connections(
            &srv.subscriptions,
            Frontend::Mcp,
            (0..FULL_CONNECTIONS).map(|_| srv.next_conn_id()),
            MAX_SUBS_PER_CONN,
        );
        assert_eq!(srv.subscriptions.lock().subs.len(), MAX_SUBS_TOTAL);

        let conn = ConnCtx {
            role: Frontend::Operator,
            client_label: None,
            conn_id: srv.next_conn_id(),
            out: Some(NotificationSink::new(4)),
        };
        let req = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "flow.subscribe", "arguments": {}}});
        let reply = srv
            .handle_on(&conn, &req.to_string())
            .expect("flow.subscribe replies");
        let reply: JsonValue = serde_json::from_str(&reply).expect("the reply is JSON");

        assert_eq!(reply["result"]["isError"], json!(true), "{reply}");
        assert_eq!(
            reply["result"]["content"][0]["text"],
            "flow.subscribe refused: the server's subscription table is full (max 4096 across \
             all connections); try again later"
        );
        assert!(
            reply["result"].get("structuredContent").is_none(),
            "no sub_id is minted for a refused subscribe: {reply}"
        );
        assert_eq!(
            srv.subscriptions.lock().subs.len(),
            MAX_SUBS_TOTAL,
            "a refused subscribe registers nothing"
        );
    }

    /// Bus-hardening AC5 / D2: `fanout_state` at the table cap (4096 connections
    /// of one subscription each) reaches every connection exactly once.
    #[test]
    fn fanout_state_reaches_every_connection_once_at_the_table_cap() {
        let reg = Subscriptions::default();
        let sinks = add_connections(&reg, Frontend::Operator, 1..=MAX_SUBS_TOTAL as u64, 1);
        assert_eq!(sinks.len(), 4096);

        reg.fanout_state("state-line", &|| false);

        for (i, sink) in sinks.iter().enumerate() {
            assert_eq!(
                sink.queued_len(),
                1,
                "connection {} got exactly one line",
                i + 1
            );
        }
        assert_eq!(sinks[0].drain(), vec!["state-line".to_string()]);
    }

    /// Bus-hardening AC5 / D2: `fanout_role(Operator, ..)` reaches each operator
    /// connection once however many subscriptions it holds (3 here), and no
    /// agent connection at all.
    #[test]
    fn fanout_role_reaches_only_that_role_once_per_connection() {
        let reg = Subscriptions::default();
        let operators = add_connections(&reg, Frontend::Operator, 1..=10, 3);
        let agents = add_connections(&reg, Frontend::Mcp, 11..=20, 3);

        reg.fanout_role(Frontend::Operator, "operator-line", &|| false);

        for (i, sink) in operators.iter().enumerate() {
            assert_eq!(
                sink.queued_len(),
                1,
                "operator connection {} got exactly one line",
                i + 1
            );
        }
        for (i, sink) in agents.iter().enumerate() {
            assert_eq!(
                sink.queued_len(),
                0,
                "agent connection {} got nothing",
                i + 11
            );
        }
        assert_eq!(operators[0].drain(), vec!["operator-line".to_string()]);
    }

    /// Bus-hardening D2: `fanout_role` goes through the one
    /// `Subscriptions::fanout`, which tests `wants` before it records the
    /// connection as seen. This registry-level test pins that insert-after-`wants`
    /// rule with a role-shaped `wants`; the same line that
    /// `a_non_matching_subscription_does_not_mask_a_matching_one` in `tests/mcp.rs`
    /// pins with a filter-shaped one. The real transports never mix roles on one
    /// connection id, so the registry is driven directly: connection 1 holds an
    /// agent subscription first and an operator one second, and an operator-only
    /// line must still reach it, once.
    #[test]
    fn fanout_role_does_not_let_another_roles_subscription_mask_a_matching_one() {
        let reg = Subscriptions::default();
        let sink = NotificationSink::new(4);
        for role in [Frontend::Mcp, Frontend::Operator] {
            assert!(reg
                .add(1, role, sink.clone(), FlowFilter::default())
                .is_ok());
        }

        reg.fanout_role(Frontend::Operator, "operator-line", &|| false);

        assert_eq!(sink.drain(), vec!["operator-line".to_string()]);
    }

    // ------------------- agent policy revocation: the read refusal and the gap record

    /// A server whose agent policy is `policy`, with nothing else attached.
    fn revoke_server_under(policy: AgentPolicy) -> McpServer {
        McpServer::new(Arc::new(Registry::new()), McpTransport::Stdio)
            .with_agent_state(Arc::new(AgentState::new(policy)))
    }

    /// AC21: the `paused` refusal for the two subscription verbs is byte for byte
    /// the text it always was, and `read_refusal` still refuses only a
    /// non-trusted-control role, only under `Paused`.
    #[test]
    fn revoke_read_refusal_text_is_unchanged() {
        let paused = revoke_server_under(AgentPolicy::Paused);
        assert_eq!(
            paused.read_refusal(&ConnCtx::agent(), "flow.subscribe"),
            Some(
                "`flow.subscribe` refused: the agent policy is `paused`; no agent command runs. \
                 An operator can change it with agent.set."
                    .to_string()
            )
        );
        assert_eq!(
            paused.read_refusal(&ConnCtx::agent(), "flow.unsubscribe"),
            Some(
                "`flow.unsubscribe` refused: the agent policy is `paused`; no agent command runs. \
                 An operator can change it with agent.set."
                    .to_string()
            )
        );
        for role in [Frontend::Operator, Frontend::Cli] {
            assert_eq!(
                paused.read_refusal(&ConnCtx::new(role), "flow.subscribe"),
                None,
                "{role:?} is never refused under Paused"
            );
        }
        for policy in [
            AgentPolicy::All,
            AgentPolicy::Auto,
            AgentPolicy::Ask,
            AgentPolicy::ReadOnly,
        ] {
            assert_eq!(
                revoke_server_under(policy).read_refusal(&ConnCtx::agent(), "flow.subscribe"),
                None,
                "the agent is not refused under {policy:?}"
            );
        }
    }

    /// Insert a minimal HTTP flow into `store`; returns its id.
    fn revoke_insert_flow(store: &MemFlowStore) -> FlowId {
        let addr = SocketAddr::from(([127, 0, 0, 1], 0));
        store.insert(Flow::Http(HttpFlow {
            id: FlowId::new(),
            request: HttpRequest {
                method: "GET".into(),
                scheme: "http".into(),
                authority: "example.com:443".into(),
                path: "/x".into(),
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
        }))
    }

    /// Design 3 ("required, or it leaks"): the per-connection gap record is removed
    /// by `drop_connection`. Connection ids are monotonic and never reused, so a
    /// leaked entry could never be cleared again; it is observable only through the
    /// private field, which this in-file module can read.
    #[test]
    fn revoke_gap_is_dropped_with_its_connection() {
        let state = Arc::new(AgentState::new(AgentPolicy::Auto));
        let store = Arc::new(MemFlowStore::new());
        let srv = McpServer::new(Arc::new(Registry::new()), McpTransport::Stdio)
            .with_agent_state(state.clone())
            .with_services(
                store.clone(),
                Arc::new(NoClient),
                Arc::new(StdGuard::default()),
                None,
            );
        // An agent-role connection with a push sink, subscribed through the real verb
        // (an unregistered verb has no published schema, so it is not schema-checked).
        let conn = ConnCtx {
            conn_id: srv.next_conn_id(),
            out: Some(NotificationSink::new(16)),
            ..ConnCtx::agent()
        };
        let reply = srv
            .handle_on(
                &conn,
                &json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                    "params": {"name": "flow.subscribe", "arguments": {}}})
                .to_string(),
            )
            .expect("flow.subscribe replies");
        let reply: JsonValue = serde_json::from_str(&reply).expect("the reply is JSON");
        assert!(
            reply["result"]["structuredContent"]["sub_id"].is_u64(),
            "setup: the agent subscribes under Auto: {reply}"
        );

        // One suppressed flow push records the connection's gap.
        state.set_policy(AgentPolicy::Paused);
        let id = revoke_insert_flow(&store);
        srv.push_flow_event(&Event::RequestHeaders(id));
        assert_eq!(
            srv.subscriptions.lock().gapped,
            vec![conn.conn_id],
            "setup: a suppressed push records the connection's gap"
        );

        srv.drop_connection(conn.conn_id);
        assert!(
            srv.subscriptions.lock().gapped.is_empty(),
            "gapped must be empty after drop_connection"
        );
    }

    // ------------------- the gap record's bounds

    /// A server over `state` and a fresh store, with an empty registry (an
    /// unregistered verb is not schema-checked, so `flow.subscribe` is served by
    /// the server itself, as in the test above).
    fn revoke_server_with_store(state: &Arc<AgentState>) -> (McpServer, Arc<MemFlowStore>) {
        let store = Arc::new(MemFlowStore::new());
        let srv = McpServer::new(Arc::new(Registry::new()), McpTransport::Stdio)
            .with_agent_state(state.clone())
            .with_services(
                store.clone(),
                Arc::new(NoClient),
                Arc::new(StdGuard::default()),
                None,
            );
        (srv, store)
    }

    /// A new connection (a role taken from `base`, its own sink and id) subscribed
    /// through the real `flow.subscribe` verb with no filter.
    fn revoke_subscribe(srv: &McpServer, base: ConnCtx) -> ConnCtx {
        let conn = ConnCtx {
            conn_id: srv.next_conn_id(),
            out: Some(NotificationSink::new(16)),
            ..base
        };
        let reply = srv
            .handle_on(
                &conn,
                &json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                    "params": {"name": "flow.subscribe", "arguments": {}}})
                .to_string(),
            )
            .expect("flow.subscribe replies");
        let reply: JsonValue = serde_json::from_str(&reply).expect("the reply is JSON");
        assert!(
            reply["result"]["structuredContent"]["sub_id"].is_u64(),
            "setup: the subscribe is accepted: {reply}"
        );
        conn
    }

    /// The gap record is one entry per connection, however many pushes were
    /// suppressed (so a long pause cannot grow it, and a connection is not marked
    /// more than once), and `drop_connection` removes only its own connection's
    /// entry.
    #[test]
    fn revoke_gap_is_one_entry_per_connection_however_many_pushes() {
        let state = Arc::new(AgentState::new(AgentPolicy::Auto));
        let (srv, store) = revoke_server_with_store(&state);
        let first = revoke_subscribe(&srv, ConnCtx::agent());
        let second = revoke_subscribe(&srv, ConnCtx::agent());

        state.set_policy(AgentPolicy::Paused);
        for n in 0..500 {
            let id = revoke_insert_flow(&store);
            srv.push_flow_event(&Event::RequestHeaders(id));
            srv.push_state(json!({ "n": n }));
        }
        let mut gapped = srv.subscriptions.lock().gapped.clone();
        assert_eq!(
            gapped.len(),
            2,
            "1000 suppressed pushes leave exactly one record per connection"
        );
        gapped.sort_unstable();
        assert_eq!(
            gapped,
            vec![first.conn_id, second.conn_id],
            "the two records are the two subscribed connections"
        );

        srv.drop_connection(first.conn_id);
        assert_eq!(
            srv.subscriptions.lock().gapped,
            vec![second.conn_id],
            "drop_connection removes only its own connection's record"
        );
    }

    /// A gap is recorded only for a connection that lost a line: not when nobody is
    /// subscribed, and never for a trusted-control (operator or CLI) subscription,
    /// which is not muted and so receives every push under `Paused`.
    #[test]
    fn revoke_gap_is_never_recorded_for_nobody_or_for_trusted_control() {
        let state = Arc::new(AgentState::new(AgentPolicy::Paused));
        let (srv, store) = revoke_server_with_store(&state);

        srv.push_flow_event(&Event::RequestHeaders(revoke_insert_flow(&store)));
        srv.push_state(json!({"n": 0}));
        assert!(
            srv.subscriptions.lock().gapped.is_empty(),
            "no subscriber, so no gap"
        );

        let operator = revoke_subscribe(&srv, ConnCtx::new(Frontend::Operator));
        let cli = revoke_subscribe(&srv, ConnCtx::new(Frontend::Cli));
        srv.push_flow_event(&Event::RequestHeaders(revoke_insert_flow(&store)));
        srv.push_state(json!({"n": 1}));
        assert!(
            srv.subscriptions.lock().gapped.is_empty(),
            "operator and CLI subscriptions are never muted, so never gapped"
        );
        for (name, conn) in [("operator", &operator), ("cli", &cli)] {
            let sink = conn.out.as_ref().expect("the connection has a sink");
            assert_eq!(
                sink.drain().len(),
                2,
                "the {name} subscription received the flow and the state line under Paused"
            );
        }
    }

    // ------------------- agent policy revocation: parked requests follow the live policy

    /// A Sensitive stub (`demo.sensitive`) that counts how often it really ran, so a
    /// test can tell "the call was refused" from "the call ran and was reported".
    struct RevokeSensitive {
        runs: Arc<AtomicUsize>,
    }

    impl Command for RevokeSensitive {
        fn name(&self) -> &str {
            "demo.sensitive"
        }
        fn sensitivity(&self) -> Sensitivity {
            Sensitivity::Sensitive
        }
        fn schema(&self) -> ParamSchema {
            ParamSchema {
                description: "A Sensitive stub that counts its runs.".into(),
                params: vec![],
                result: TypeDesc::Str,
            }
        }
        fn invoke(&self, _args: Params, _host: &CommandHost) -> anyhow::Result<Value> {
            self.runs.fetch_add(1, Ordering::SeqCst);
            Ok(Value::Str("ran".into()))
        }
    }

    /// A server whose policy starts at `policy`, with the counting Sensitive stub and
    /// the real `agent.*` verbs over the same state, and an approval timeout (60 s)
    /// so long that only a policy change or a release can end a wait inside a test.
    /// Returns the server, the state, and the stub's run counter.
    fn revoke_park_server(
        policy: AgentPolicy,
    ) -> (Arc<McpServer>, Arc<AgentState>, Arc<AtomicUsize>) {
        let state = Arc::new(AgentState::new(policy));
        let runs = Arc::new(AtomicUsize::new(0));
        let mut registry = Registry::new();
        registry.add_command(Arc::new(RevokeSensitive { runs: runs.clone() }));
        registry.add_plugin(Box::new(AgentPlugin::new(state.clone())));
        let srv = McpServer::new(Arc::new(registry), McpTransport::Stdio)
            .with_agent_state(state.clone())
            .with_approval_timeout(Duration::from_secs(60))
            .with_services(
                Arc::new(MemFlowStore::new()),
                Arc::new(NoClient),
                Arc::new(StdGuard::default()),
                None,
            );
        (Arc::new(srv), state, runs)
    }

    /// The `result` of an operator `agent.approve {request_id, allow}` on `srv`.
    fn revoke_operator_approve(srv: &McpServer, request_id: &str, allow: bool) -> JsonValue {
        let reply = srv
            .handle_on(
                &ConnCtx::new(Frontend::Operator),
                &json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                    "params": {"name": "agent.approve",
                        "arguments": {"request_id": request_id, "allow": allow}}})
                .to_string(),
            )
            .expect("agent.approve replies");
        let reply: JsonValue = serde_json::from_str(&reply).expect("the reply is JSON");
        reply["result"].clone()
    }

    /// The first text content of a `tools/call` result.
    fn revoke_result_text(result: &JsonValue) -> String {
        result["content"][0]["text"]
            .as_str()
            .unwrap_or_default()
            .to_string()
    }

    /// A slot's current state (`None` until resolved).
    fn revoke_slot_state(slot: &ParkSlot) -> Option<bool> {
        *slot
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    // ------------------- SP-AC16: proxy.system.set/unset are operator-only, never parked

    /// A stand-in for one `proxy.system.*` verb (spec 2026-10-31-system-proxy-
    /// automation-design, SP-AC16): the real verbs live in `aitm-sysproxy`, which
    /// this crate must not depend on, so the gate is proved over fakes that carry
    /// the real names and sensitivities and count their runs.
    struct SysProxyVerb {
        name: &'static str,
        sensitivity: Sensitivity,
        runs: Arc<AtomicUsize>,
    }

    impl Command for SysProxyVerb {
        fn name(&self) -> &str {
            self.name
        }
        fn sensitivity(&self) -> Sensitivity {
            self.sensitivity
        }
        fn schema(&self) -> ParamSchema {
            ParamSchema {
                description: format!("A stand-in for {}.", self.name),
                params: vec![],
                result: TypeDesc::Str,
            }
        }
        fn invoke(&self, _args: Params, _host: &CommandHost) -> anyhow::Result<Value> {
            self.runs.fetch_add(1, Ordering::SeqCst);
            Ok(Value::Str("ran".into()))
        }
    }

    /// A server under `policy` with the three `proxy.system.*` stand-ins (`set` and
    /// `unset` Sensitive, `status` Read), the real `agent.*` verbs, a 1 s approval
    /// timeout, and an operator subscribed through `flow.subscribe` so that an `Ask`
    /// park would be possible (and visible on the operator's sink). Returns the
    /// server, the operator connection, and the stand-ins' shared run counter.
    fn sysproxy_server(policy: AgentPolicy) -> (McpServer, ConnCtx, Arc<AtomicUsize>) {
        let state = Arc::new(AgentState::new(policy));
        let runs = Arc::new(AtomicUsize::new(0));
        let mut registry = Registry::new();
        for (name, sensitivity) in [
            ("proxy.system.status", Sensitivity::Read),
            ("proxy.system.set", Sensitivity::Sensitive),
            ("proxy.system.unset", Sensitivity::Sensitive),
        ] {
            registry.add_command(Arc::new(SysProxyVerb {
                name,
                sensitivity,
                runs: runs.clone(),
            }));
        }
        registry.add_plugin(Box::new(AgentPlugin::new(state.clone())));
        let srv = McpServer::new(Arc::new(registry), McpTransport::Stdio)
            .with_agent_state(state)
            .with_approval_timeout(Duration::from_secs(1))
            .with_services(
                Arc::new(MemFlowStore::new()),
                Arc::new(NoClient),
                Arc::new(StdGuard::default()),
                None,
            );
        let operator = revoke_subscribe(&srv, ConnCtx::new(Frontend::Operator));
        (srv, operator, runs)
    }

    /// The reply to an agent-role `tools/call name {}` on `srv`.
    fn sysproxy_agent_call(srv: &McpServer, name: &str) -> JsonValue {
        let reply = srv
            .handle_on(
                &ConnCtx::agent(),
                &json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                    "params": {"name": name, "arguments": {}}})
                .to_string(),
            )
            .expect("the call replies");
        serde_json::from_str(&reply).expect("the reply is JSON")
    }

    /// SP-AC16. Under each of `All`, `Auto` and `Ask`, an agent-role call to
    /// `proxy.system.set` and to `proxy.system.unset` is refused outright and never
    /// parked: the reply is a tool error naming the operator, the stand-in never
    /// ran, the parked table is empty, and the connected operator received no
    /// `approval_requested` line (under `Ask` a parkable command would have pushed
    /// one and then timed out). `proxy.system.status` is a Read verb and runs under
    /// `ReadOnly`. The two source predicates agree: both mutating names are
    /// operator-only and neither defers to a command gate.
    #[test]
    fn proxy_system_verbs_are_operator_only_never_parked() {
        for policy in [AgentPolicy::All, AgentPolicy::Auto, AgentPolicy::Ask] {
            let (srv, operator, runs) = sysproxy_server(policy);
            let sink = operator.out.as_ref().expect("the operator has a sink");
            sink.drain();
            for name in ["proxy.system.set", "proxy.system.unset"] {
                let reply = sysproxy_agent_call(&srv, name);
                let text = revoke_result_text(&reply["result"]);
                assert_eq!(
                    reply["result"]["isError"],
                    json!(true),
                    "{name} under {policy:?} is a tool error: {reply}"
                );
                assert!(
                    text.starts_with(&format!("`{name}` refused:")) && text.contains("operator"),
                    "{name} under {policy:?} is refused, naming the operator: {text:?}"
                );
                assert!(
                    !text.contains("approval timeout")
                        && !text.contains("approved")
                        && !text.contains("awaiting"),
                    "{name} under {policy:?} was refused, not parked and timed out: {text:?}"
                );
                assert_eq!(
                    srv.parked.len(),
                    0,
                    "{name} under {policy:?} left no parked entry"
                );
                let pushed = sink.drain();
                assert!(
                    pushed
                        .iter()
                        .all(|line| !line.contains("approval_requested")),
                    "{name} under {policy:?} pushed no approval request to the operator: \
                     {pushed:?}"
                );
            }
            assert_eq!(
                runs.load(Ordering::SeqCst),
                0,
                "no mutating stand-in ran under {policy:?}"
            );
        }

        let (srv, _operator, runs) = sysproxy_server(AgentPolicy::ReadOnly);
        let reply = sysproxy_agent_call(&srv, "proxy.system.status");
        assert_eq!(
            reply["result"]["isError"],
            json!(false),
            "proxy.system.status is Read, so ReadOnly allows it: {reply}"
        );
        assert_eq!(
            revoke_result_text(&reply["result"]),
            "\"ran\"",
            "the transcript carries the stand-in's JSON-rendered result"
        );
        assert_eq!(
            runs.load(Ordering::SeqCst),
            1,
            "the status stand-in ran once"
        );

        // The source predicates the gate is built from agree with the behaviour.
        assert!(is_operator_only("proxy.system.set"));
        assert!(is_operator_only("proxy.system.unset"));
        assert!(!is_operator_only("proxy.system.status"));
        assert!(!defers_to_command_gate("proxy.system.set"));
        assert!(!defers_to_command_gate("proxy.system.unset"));
    }

    /// AC11: once the policy has left `ask`, an `agent.approve allow:true` does not
    /// approve. It returns an error that says why, and the request is denied (the
    /// slot is `Some(false)`, the table is empty). The parked slot has no waiter, so
    /// the reply is deterministic whatever the slice timer does.
    #[test]
    fn revoke_park_approve_after_leaving_ask_is_refused_and_denies() {
        for policy in [
            AgentPolicy::Paused,
            AgentPolicy::ReadOnly,
            AgentPolicy::Auto,
            AgentPolicy::All,
        ] {
            let (srv, state, _runs) = revoke_park_server(AgentPolicy::Ask);
            let (id, slot) = srv.parked.try_park().expect("the table has room");
            state.set_policy(policy);

            let reply = revoke_operator_approve(&srv, &id, true);
            let text = revoke_result_text(&reply);
            assert_eq!(
                reply["isError"],
                json!(true),
                "an approve under {policy:?} must be an error, got: {reply}"
            );
            assert!(
                text.contains("no longer `ask`") && text.contains("denied"),
                "the refusal says the policy is no longer `ask` and that the request was \
                 denied (policy {policy:?}): {text}"
            );
            assert_eq!(
                revoke_slot_state(&slot),
                Some(false),
                "the slot is resolved as denied under {policy:?}"
            );
            assert_eq!(srv.parked.len(), 0, "the table is empty under {policy:?}");

            let again = revoke_operator_approve(&srv, &id, true);
            assert_eq!(
                again["isError"],
                json!(true),
                "a second approve is an error: {again}"
            );
            assert!(
                revoke_result_text(&again).contains(&format!("no parked request `{id}`")),
                "a second approve is told the request no longer exists: {again}"
            );
        }

        // Unchanged behaviour: with the policy still `ask`, an approve approves.
        let (srv, _state, _runs) = revoke_park_server(AgentPolicy::Ask);
        let (id, slot) = srv.parked.try_park().expect("the table has room");
        let reply = revoke_operator_approve(&srv, &id, true);
        assert_eq!(
            reply["isError"],
            json!(false),
            "an approve under `ask` still succeeds: {reply}"
        );
        assert_eq!(
            revoke_slot_state(&slot),
            Some(true),
            "the slot is approved under `ask`"
        );
        assert_eq!(srv.parked.len(), 0, "the table is empty after the approve");
    }

    /// AC12(i): a denial is always honoured. `agent.approve allow:false` after the
    /// policy left `ask` still resolves the request as denied and reports success.
    #[test]
    fn revoke_park_deny_after_leaving_ask_is_honoured() {
        let (srv, state, _runs) = revoke_park_server(AgentPolicy::Ask);
        let (id, slot) = srv.parked.try_park().expect("the table has room");
        state.set_policy(AgentPolicy::Paused);

        let reply = revoke_operator_approve(&srv, &id, false);
        assert_eq!(
            reply["isError"],
            json!(false),
            "a denial under Paused is a success: {reply}"
        );
        assert_eq!(
            revoke_slot_state(&slot),
            Some(false),
            "the slot is resolved as denied"
        );
        assert_eq!(srv.parked.len(), 0, "the table is empty");
    }

    /// AC13, end to end: a real `park_for_approval` waiter, the policy goes
    /// `paused`, and then the slot is resolved as **approved** directly through the
    /// table (bypassing `agent.approve`). Whichever of the waiter's slice recheck or
    /// the direct resolve gets there first, the call comes back refused naming the
    /// policy change, and the stub never ran.
    #[test]
    fn revoke_park_approve_then_pause_is_denied_end_to_end() {
        let (srv, state, runs) = revoke_park_server(AgentPolicy::Ask);
        // An operator subscription registered directly, so the call can park.
        let operator_sink = NotificationSink::new(16);
        srv.subscriptions
            .add(
                srv.next_conn_id(),
                Frontend::Operator,
                operator_sink,
                FlowFilter::default(),
            )
            .expect("the operator subscription registers");

        let (tx, rx) = std::sync::mpsc::channel();
        let agent_srv = srv.clone();
        std::thread::spawn(move || {
            let reply = agent_srv
                .handle_on(
                    &ConnCtx::agent(),
                    &json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                        "params": {"name": "demo.sensitive", "arguments": {}}})
                    .to_string(),
                )
                .expect("the call replies");
            let _ = tx.send(serde_json::from_str::<JsonValue>(&reply).expect("JSON"));
        });

        // Wait for the call to park (10 ms steps, 5 s cap), then read its id.
        let mut waited = Duration::ZERO;
        while srv.parked.len() < 1 && waited < Duration::from_secs(5) {
            std::thread::sleep(Duration::from_millis(10));
            waited += Duration::from_millis(10);
        }
        assert_eq!(srv.parked.len(), 1, "setup: the agent call parked");
        let id = srv.parked.lock().entries[0].0.clone();

        state.set_policy(AgentPolicy::Paused);
        // The waiter may already have denied; whether the id was still there is
        // not the point, so the bool is ignored.
        let _ = srv.parked.resolve(&id, true);

        let reply = match rx.recv_timeout(Duration::from_secs(5)) {
            Ok(reply) => reply,
            Err(e) => {
                let _ = srv.parked.resolve(&id, false);
                panic!("the agent call did not return within 5s ({e:?})");
            }
        };
        let text = revoke_result_text(&reply["result"]);
        assert_eq!(
            reply["result"]["isError"],
            json!(true),
            "an approval that lands after the pause must not run the command (counter {}): \
             {reply}",
            runs.load(Ordering::SeqCst)
        );
        assert!(
            text.contains("the agent policy changed") && text.contains("`paused`"),
            "the refusal names the policy change and the new policy: {text}"
        );
        assert_eq!(
            runs.load(Ordering::SeqCst),
            0,
            "the Sensitive stub must not have run"
        );
    }

    /// `Some(reason)` for a refusal, `None` for an approval.
    fn revoke_refusal(outcome: ParkOutcome) -> Option<String> {
        match outcome {
            ParkOutcome::Approved => None,
            ParkOutcome::Refused(reason) => Some(reason),
        }
    }

    /// AC13, the pure post-wait decision over its full table (spec Design 5.3): an
    /// approval stands only if the live policy is still `ask`; a denial and a
    /// timeout keep their existing texts under every policy; a policy change
    /// refuses and names the new policy.
    #[test]
    fn revoke_park_settle_decision_table() {
        let name = "demo.sensitive";
        let every_policy = [
            AgentPolicy::All,
            AgentPolicy::Auto,
            AgentPolicy::Ask,
            AgentPolicy::ReadOnly,
            AgentPolicy::Paused,
        ];

        assert_eq!(
            revoke_refusal(settle_park(
                name,
                ParkWait::Resolved(true),
                AgentPolicy::Ask
            )),
            None,
            "(Resolved(true), Ask) is Approved"
        );
        for policy in [
            AgentPolicy::All,
            AgentPolicy::Auto,
            AgentPolicy::ReadOnly,
            AgentPolicy::Paused,
        ] {
            let text = revoke_refusal(settle_park(name, ParkWait::Resolved(true), policy))
                .unwrap_or_else(|| {
                    panic!("(Resolved(true), {policy:?}) must be Refused, got Approved")
                });
            assert!(
                text.contains("the agent policy changed")
                    && text.contains(&format!("`{}`", policy.label())),
                "(Resolved(true), {policy:?}) names the policy change and the new label: {text}"
            );
        }

        for policy in every_policy {
            assert_eq!(
                revoke_refusal(settle_park(name, ParkWait::Resolved(false), policy)),
                Some(
                    "`demo.sensitive` refused: an operator denied the parked sensitive command."
                        .to_string()
                ),
                "(Resolved(false), {policy:?}) keeps the unchanged denial text"
            );
            assert_eq!(
                revoke_refusal(settle_park(name, ParkWait::TimedOut, policy)),
                Some(
                    "`demo.sensitive` refused: no operator approved the parked sensitive \
                     command within the approval timeout."
                        .to_string()
                ),
                "(TimedOut, {policy:?}) keeps the unchanged timeout text"
            );
            let text = revoke_refusal(settle_park(name, ParkWait::PolicyChanged, policy))
                .unwrap_or_else(|| {
                    panic!("(PolicyChanged, {policy:?}) must be Refused, got Approved")
                });
            assert!(
                text.contains("the agent policy changed")
                    && text.contains(&format!("`{}`", policy.label())),
                "(PolicyChanged, {policy:?}) names the policy change and the new label: {text}"
            );
        }
    }

    /// `ParkSlot::wait` itself (Design 5.2): the total never exceeds the timeout
    /// (the last slice is shortened to the time remaining), a resolve ends the wait
    /// at once whatever the slice, a failing recheck ends it as `PolicyChanged`, and
    /// a slot that is already resolved is `Resolved` even if the policy has moved.
    #[test]
    fn revoke_park_slot_wait_honours_timeout_resolve_and_recheck() {
        // (a) A 50 ms timeout against a 2 s slice: the one slice is cut to the 50 ms
        // that remain, so the wait is a timeout after at least 50 ms and far short of
        // the slice.
        let slot = ParkSlot::new();
        let started = Instant::now();
        let waited = slot.wait(Duration::from_millis(50), Duration::from_secs(2), &|| true);
        let took = started.elapsed();
        assert_eq!(
            waited,
            ParkWait::TimedOut,
            "(a) an unresolved wait times out"
        );
        assert!(
            took >= Duration::from_millis(50),
            "(a) the wait lasts the whole timeout, took {took:?}"
        );
        assert!(
            took < Duration::from_secs(1),
            "(a) the last slice is shortened to the time remaining: a 50 ms timeout \
             must not wait out a 2 s slice, took {took:?}"
        );

        // (b) A resolve from another thread ends a long wait at once, not at the
        // next slice (10 s) and not at the timeout (30 s).
        let slot = Arc::new(ParkSlot::new());
        let resolver = {
            let slot = slot.clone();
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(50));
                slot.resolve(true);
            })
        };
        let started = Instant::now();
        let waited = slot.wait(Duration::from_secs(30), Duration::from_secs(10), &|| true);
        let took = started.elapsed();
        resolver.join().expect("the resolver thread finishes");
        assert_eq!(
            waited,
            ParkWait::Resolved(true),
            "(b) a resolve ends the wait with its decision"
        );
        assert!(
            took < Duration::from_secs(5),
            "(b) a resolve ends the wait at once, took {took:?}"
        );

        // (c) A failing recheck ends an unresolved wait after about one slice
        // (20 ms), not at the 30 s timeout.
        let slot = ParkSlot::new();
        let started = Instant::now();
        let waited = slot.wait(Duration::from_secs(30), Duration::from_millis(20), &|| {
            false
        });
        let took = started.elapsed();
        assert_eq!(
            waited,
            ParkWait::PolicyChanged,
            "(c) a recheck that says the policy moved ends the wait"
        );
        assert!(
            took < Duration::from_secs(5),
            "(c) the recheck ends the wait within a slice, took {took:?}"
        );

        // (d) Resolved wins over PolicyChanged: a slot that is already resolved is
        // reported as resolved even though the policy check would say it moved.
        let slot = ParkSlot::new();
        slot.resolve(true);
        let waited = slot.wait(Duration::from_secs(30), Duration::from_millis(20), &|| {
            false
        });
        assert_eq!(
            waited,
            ParkWait::Resolved(true),
            "(d) a resolved slot is Resolved even when the policy has moved"
        );
    }

    // ------------- parked-request edge cases and races (in-process, every wait bounded)

    /// A server under `policy` with the counting Sensitive stub, the real `agent.*`
    /// verbs, an operator subscription registered directly (so a Sensitive call can
    /// park), and the given approval timeout. Returns the server, the state, and the
    /// stub's run counter.
    fn revoke_tester_server(
        policy: AgentPolicy,
        approval_timeout: Duration,
    ) -> (Arc<McpServer>, Arc<AgentState>, Arc<AtomicUsize>) {
        let state = Arc::new(AgentState::new(policy));
        let runs = Arc::new(AtomicUsize::new(0));
        let mut registry = Registry::new();
        registry.add_command(Arc::new(RevokeSensitive { runs: runs.clone() }));
        registry.add_plugin(Box::new(AgentPlugin::new(state.clone())));
        let srv = Arc::new(
            McpServer::new(Arc::new(registry), McpTransport::Stdio)
                .with_agent_state(state.clone())
                .with_approval_timeout(approval_timeout)
                .with_services(
                    Arc::new(MemFlowStore::new()),
                    Arc::new(NoClient),
                    Arc::new(StdGuard::default()),
                    None,
                ),
        );
        srv.subscriptions
            .add(
                srv.next_conn_id(),
                Frontend::Operator,
                NotificationSink::new(1024),
                FlowFilter::default(),
            )
            .expect("the operator subscription registers");
        (srv, state, runs)
    }

    /// Deny every parked request on `srv`, so no waiter outlives a failing test by
    /// the approval timeout.
    fn revoke_tester_release_all(srv: &McpServer) {
        let ids: Vec<String> = srv
            .parked
            .lock()
            .entries
            .iter()
            .map(|(id, _)| id.clone())
            .collect();
        for id in ids {
            let _ = srv.parked.resolve(&id, false);
        }
    }

    /// An agent-role `demo.sensitive` call on its own thread; the whole JSON-RPC
    /// reply arrives on the returned channel (a thread that dies drops the sender,
    /// so the receiver sees a disconnect rather than hanging).
    fn revoke_tester_spawn_call(srv: &Arc<McpServer>) -> std::sync::mpsc::Receiver<JsonValue> {
        let (tx, rx) = std::sync::mpsc::channel();
        let srv = srv.clone();
        std::thread::spawn(move || {
            let reply = srv
                .handle_on(
                    &ConnCtx::agent(),
                    &json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                        "params": {"name": "demo.sensitive", "arguments": {}}})
                    .to_string(),
                )
                .expect("the call replies");
            let _ = tx.send(serde_json::from_str::<JsonValue>(&reply).expect("JSON"));
        });
        rx
    }

    /// Poll (1 ms steps, 5 s cap) until at least `n` requests are parked; returns the
    /// parked ids. On the cap, releases whatever is parked and panics.
    fn revoke_tester_wait_parked(srv: &McpServer, n: usize) -> Vec<String> {
        let started = Instant::now();
        loop {
            let ids: Vec<String> = srv
                .parked
                .lock()
                .entries
                .iter()
                .map(|(id, _)| id.clone())
                .collect();
            if ids.len() >= n {
                return ids;
            }
            if started.elapsed() > Duration::from_secs(5) {
                revoke_tester_release_all(srv);
                panic!("only {} of {n} calls parked within 5s", ids.len());
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    /// The reply of a spawned call within 5 s. On a timeout, or a thread that died
    /// (a disconnect), every parked request is released first and then the test
    /// panics with `what`.
    fn revoke_tester_recv(
        srv: &McpServer,
        rx: &std::sync::mpsc::Receiver<JsonValue>,
        what: &str,
    ) -> JsonValue {
        match rx.recv_timeout(Duration::from_secs(5)) {
            Ok(reply) => reply,
            Err(e) => {
                revoke_tester_release_all(srv);
                panic!("{what} ({e:?})");
            }
        }
    }

    /// Whether a `tools/call` reply is a tool error.
    fn revoke_tester_is_tool_error(reply: &JsonValue) -> bool {
        reply["result"]["isError"] == json!(true)
    }

    /// A JSON object as the `Map` `handle_approve` takes.
    fn revoke_tester_args(value: JsonValue) -> Map<String, JsonValue> {
        value
            .as_object()
            .expect("the arguments are an object")
            .clone()
    }

    /// A waiter that was denied because the policy left `ask` has removed its table
    /// entry: the table is empty, a late `agent.approve` (either way, under any
    /// policy) is told no such request exists, and nothing ever ran. Without the
    /// cleanup a stranded entry would count against the cap forever and a late
    /// approve would report success for a call that is gone.
    #[test]
    fn revoke_park_a_policy_denial_leaves_no_table_entry_and_no_late_grant() {
        let (srv, state, runs) = revoke_tester_server(AgentPolicy::Ask, Duration::from_secs(60));
        let rx = revoke_tester_spawn_call(&srv);
        let ids = revoke_tester_wait_parked(&srv, 1);
        state.set_policy(AgentPolicy::Paused);
        let reply = revoke_tester_recv(
            &srv,
            &rx,
            "the parked call did not return within 5s after set_policy(paused)",
        );
        let text = revoke_result_text(&reply["result"]);
        assert!(
            revoke_tester_is_tool_error(&reply) && text.contains("the agent policy changed"),
            "the waiter was denied for the policy change: {reply}"
        );
        assert_eq!(
            srv.parked.len(),
            0,
            "the waiter removed its table entry after a PolicyChanged"
        );
        for policy in [AgentPolicy::Paused, AgentPolicy::Ask] {
            state.set_policy(policy);
            for allow in [true, false] {
                let late = revoke_operator_approve(&srv, &ids[0], allow);
                assert_eq!(
                    late["isError"],
                    json!(true),
                    "a late approve(allow={allow}) under {policy:?} is an error: {late}"
                );
                assert!(
                    revoke_result_text(&late).contains(&format!("no parked request `{}`", ids[0])),
                    "a late approve(allow={allow}) under {policy:?} is told the request is gone: \
                     {late}"
                );
            }
        }
        assert_eq!(
            runs.load(Ordering::SeqCst),
            0,
            "the Sensitive stub must not have run"
        );
    }

    /// The same cleanup after a timeout: the entry is gone, a late approve finds
    /// nothing, and the unchanged timeout text is what the agent saw.
    #[test]
    fn revoke_park_a_timeout_leaves_no_table_entry_and_no_late_grant() {
        let (srv, _state, runs) = revoke_tester_server(AgentPolicy::Ask, Duration::from_secs(2));
        let rx = revoke_tester_spawn_call(&srv);
        let ids = revoke_tester_wait_parked(&srv, 1);
        let reply = revoke_tester_recv(&srv, &rx, "the call did not time out within 5s");
        let text = revoke_result_text(&reply["result"]);
        assert!(
            revoke_tester_is_tool_error(&reply) && text.contains("within the approval timeout"),
            "the unchanged timeout refusal: {reply}"
        );
        assert_eq!(
            srv.parked.len(),
            0,
            "the waiter removed its entry on timeout"
        );
        let late = revoke_operator_approve(&srv, &ids[0], true);
        assert_eq!(
            late["isError"],
            json!(true),
            "a late approve is an error: {late}"
        );
        assert!(
            revoke_result_text(&late).contains(&format!("no parked request `{}`", ids[0])),
            "a late approve is told the request is gone: {late}"
        );
        assert_eq!(runs.load(Ordering::SeqCst), 0, "the stub must not have run");
    }

    /// A zero approval timeout is an immediate timeout refusal (a slot that is not
    /// resolved has no time left on entry), not a hang, and leaves no entry.
    #[test]
    fn revoke_park_a_zero_approval_timeout_refuses_at_once_and_leaves_no_entry() {
        let (srv, _state, runs) = revoke_tester_server(AgentPolicy::Ask, Duration::ZERO);
        let rx = revoke_tester_spawn_call(&srv);
        let reply = revoke_tester_recv(&srv, &rx, "a zero-timeout call did not return within 5s");
        let text = revoke_result_text(&reply["result"]);
        assert!(
            revoke_tester_is_tool_error(&reply) && text.contains("within the approval timeout"),
            "a zero timeout is the timeout refusal: {reply}"
        );
        assert_eq!(srv.parked.len(), 0, "no entry is left behind");
        assert_eq!(runs.load(Ordering::SeqCst), 0, "the stub must not have run");
    }

    /// An operator decision removes the entry too: approve runs the command, deny
    /// refuses it with the unchanged text, and the table is empty after each.
    #[test]
    fn revoke_park_a_decided_request_leaves_no_table_entry() {
        let (srv, _state, runs) = revoke_tester_server(AgentPolicy::Ask, Duration::from_secs(60));

        let rx = revoke_tester_spawn_call(&srv);
        let ids = revoke_tester_wait_parked(&srv, 1);
        let approve = revoke_operator_approve(&srv, &ids[0], true);
        assert_eq!(
            approve["isError"],
            json!(false),
            "approve under ask: {approve}"
        );
        let reply = revoke_tester_recv(&srv, &rx, "the approved call did not return within 5s");
        assert_eq!(
            reply["result"]["structuredContent"],
            json!("ran"),
            "the approved call ran: {reply}"
        );
        assert_eq!(runs.load(Ordering::SeqCst), 1, "the stub ran once");
        assert_eq!(srv.parked.len(), 0, "an approved request leaves no entry");

        let rx = revoke_tester_spawn_call(&srv);
        let ids = revoke_tester_wait_parked(&srv, 1);
        let deny = revoke_operator_approve(&srv, &ids[0], false);
        assert_eq!(deny["isError"], json!(false), "deny under ask: {deny}");
        let reply = revoke_tester_recv(&srv, &rx, "the denied call did not return within 5s");
        let text = revoke_result_text(&reply["result"]);
        assert!(
            revoke_tester_is_tool_error(&reply)
                && text.contains("an operator denied the parked sensitive command"),
            "the unchanged denial refusal: {reply}"
        );
        assert_eq!(
            runs.load(Ordering::SeqCst),
            1,
            "the denied call did not run"
        );
        assert_eq!(srv.parked.len(), 0, "a denied request leaves no entry");
    }

    /// An approval timeout too large for `Instant` arithmetic (`Duration::MAX`) must
    /// not panic the waiter. Revocation still ends the wait, and an ordinary approve
    /// still approves.
    #[test]
    fn revoke_park_an_overflowing_approval_timeout_neither_panics_nor_blocks_revocation() {
        let (srv, state, runs) = revoke_tester_server(AgentPolicy::Ask, Duration::MAX);
        let rx = revoke_tester_spawn_call(&srv);
        let _ = revoke_tester_wait_parked(&srv, 1);
        state.set_policy(AgentPolicy::Paused);
        let reply = revoke_tester_recv(
            &srv,
            &rx,
            "a call parked with an unbounded timeout did not return within 5s of the pause",
        );
        let text = revoke_result_text(&reply["result"]);
        assert!(
            revoke_tester_is_tool_error(&reply) && text.contains("the agent policy changed"),
            "the unbounded wait still ends on the policy change: {reply}"
        );
        assert_eq!(srv.parked.len(), 0, "no entry is left behind");
        assert_eq!(runs.load(Ordering::SeqCst), 0, "the stub must not have run");

        let (srv, _state, runs) = revoke_tester_server(AgentPolicy::Ask, Duration::MAX);
        let rx = revoke_tester_spawn_call(&srv);
        let ids = revoke_tester_wait_parked(&srv, 1);
        let approve = revoke_operator_approve(&srv, &ids[0], true);
        assert_eq!(approve["isError"], json!(false), "approve: {approve}");
        let reply = revoke_tester_recv(&srv, &rx, "the approved call did not return within 5s");
        assert_eq!(
            reply["result"]["structuredContent"],
            json!("ran"),
            "an unbounded-timeout call is still approvable: {reply}"
        );
        assert_eq!(runs.load(Ordering::SeqCst), 1, "the stub ran once");
        assert_eq!(srv.parked.len(), 0, "no entry is left behind");
    }

    /// A full table (`MAX_PARKED_REQUESTS` parked calls, one waiter thread each) is
    /// denied by one policy change, all within the bound, the table drains to empty,
    /// the cap refusal for one more call is unchanged, and the capacity is usable
    /// again afterwards.
    #[test]
    fn revoke_park_one_policy_change_denies_a_full_table_and_frees_it() {
        let (srv, state, runs) = revoke_tester_server(AgentPolicy::Ask, Duration::from_secs(60));
        let receivers: Vec<_> = (0..MAX_PARKED_REQUESTS)
            .map(|_| revoke_tester_spawn_call(&srv))
            .collect();
        let _ = revoke_tester_wait_parked(&srv, MAX_PARKED_REQUESTS);

        let over = srv
            .handle_on(
                &ConnCtx::agent(),
                &json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                    "params": {"name": "demo.sensitive", "arguments": {}}})
                .to_string(),
            )
            .expect("the over-cap call replies");
        let over: JsonValue = serde_json::from_str(&over).expect("JSON");
        assert!(
            revoke_tester_is_tool_error(&over)
                && revoke_result_text(&over["result"])
                    .contains("too many sensitive agent commands"),
            "the cap refusal is unchanged: {over}"
        );
        assert_eq!(
            srv.parked.len(),
            MAX_PARKED_REQUESTS,
            "a refused park does not grow the table"
        );

        state.set_policy(AgentPolicy::Paused);
        for (i, rx) in receivers.iter().enumerate() {
            let reply = revoke_tester_recv(
                &srv,
                rx,
                &format!("parked call {i} did not return within 5s after set_policy(paused)"),
            );
            let text = revoke_result_text(&reply["result"]);
            assert!(
                revoke_tester_is_tool_error(&reply) && text.contains("the agent policy changed"),
                "parked call {i} is denied for the policy change: {reply}"
            );
        }
        assert_eq!(srv.parked.len(), 0, "the table drained to empty");
        assert_eq!(runs.load(Ordering::SeqCst), 0, "no parked call ran");

        // The capacity is usable again: under `ask` a fresh call parks and is approved.
        state.set_policy(AgentPolicy::Ask);
        let rx = revoke_tester_spawn_call(&srv);
        let ids = revoke_tester_wait_parked(&srv, 1);
        let approve = revoke_operator_approve(&srv, &ids[0], true);
        assert_eq!(approve["isError"], json!(false), "approve: {approve}");
        let reply = revoke_tester_recv(&srv, &rx, "the fresh call did not return within 5s");
        assert_eq!(
            reply["result"]["structuredContent"],
            json!("ran"),
            "the freed capacity works: {reply}"
        );
        assert_eq!(srv.parked.len(), 0, "the table is empty again");
    }

    /// Malformed `agent.approve` input (empty, missing or mistyped fields, an extra
    /// field, an empty or 1 MiB `request_id`) must resolve nothing and must not be
    /// mistaken for the policy refusal, under `ask` and after the policy left it:
    /// the parked slot stays unresolved and in the table.
    #[test]
    fn revoke_park_malformed_approve_input_resolves_nothing() {
        let oversized = "x".repeat(1 << 20);
        for policy in [AgentPolicy::Ask, AgentPolicy::Paused] {
            let (srv, state, _runs) = revoke_park_server(AgentPolicy::Ask);
            let (id, slot) = srv.parked.try_park().expect("the table has room");
            state.set_policy(policy);

            let malformed = [
                json!({}),
                json!({"request_id": id}),
                json!({"allow": true}),
                json!({"request_id": id, "allow": "yes"}),
                json!({"request_id": 42, "allow": true}),
                json!({"request_id": id, "allow": true, "unexpected": 1}),
            ];
            for args in malformed {
                let reply = srv
                    .handle_on(
                        &ConnCtx::new(Frontend::Operator),
                        &json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                            "params": {"name": "agent.approve", "arguments": args}})
                        .to_string(),
                    )
                    .expect("a malformed approve still gets a response");
                let reply: JsonValue = serde_json::from_str(&reply).expect("JSON");
                assert!(
                    reply["error"].is_object() || revoke_tester_is_tool_error(&reply),
                    "a malformed approve ({args}) under {policy:?} is an error: {reply}"
                );
                assert!(
                    !reply.to_string().contains("no longer `ask`"),
                    "a malformed approve is not the policy refusal ({args}): {reply}"
                );
                assert_eq!(
                    revoke_slot_state(&slot),
                    None,
                    "a malformed approve ({args}) under {policy:?} leaves the slot unresolved"
                );
                assert_eq!(
                    srv.parked.len(),
                    1,
                    "a malformed approve ({args}) under {policy:?} leaves the table alone"
                );
            }

            for (label, bad_id) in [("empty", ""), ("1 MiB", oversized.as_str())] {
                let reply = revoke_operator_approve(&srv, bad_id, true);
                assert_eq!(
                    reply["isError"],
                    json!(true),
                    "an unknown ({label}) request_id under {policy:?} is an error"
                );
                assert!(
                    revoke_result_text(&reply).contains("no parked request"),
                    "an unknown ({label}) request_id under {policy:?} is a plain unknown-id error"
                );
                assert_eq!(
                    revoke_slot_state(&slot),
                    None,
                    "an unknown ({label}) id leaves the slot unresolved"
                );
                assert_eq!(
                    srv.parked.len(),
                    1,
                    "an unknown ({label}) id leaves the table alone"
                );
            }
        }
    }

    /// `handle_approve` keeps its order: the role gate first, then the two parameter
    /// checks, and only then the live policy. An agent is told it cannot approve (and
    /// resolves nothing, not even a denial) whatever the policy; trusted control with
    /// missing or mistyped parameters gets the parameter error, not a policy denial.
    #[test]
    fn revoke_park_approve_checks_role_then_parameters_before_the_policy() {
        for policy in [AgentPolicy::Ask, AgentPolicy::Paused] {
            let (srv, state, _runs) = revoke_park_server(AgentPolicy::Ask);
            let (id, slot) = srv.parked.try_park().expect("the table has room");
            state.set_policy(policy);

            for allow in [true, false] {
                let reply = srv.handle_approve(
                    &ConnCtx::agent(),
                    &revoke_tester_args(json!({"request_id": id, "allow": allow})),
                );
                assert_eq!(
                    reply["isError"],
                    json!(true),
                    "an agent approve(allow={allow}) under {policy:?} is refused: {reply}"
                );
                assert!(
                    revoke_result_text(&reply).contains("cannot approve its own requests"),
                    "an agent gets the role refusal, not a policy one: {reply}"
                );
                assert_eq!(
                    revoke_slot_state(&slot),
                    None,
                    "an agent must not resolve a parked request (allow={allow}, {policy:?})"
                );
                assert_eq!(srv.parked.len(), 1, "the entry is untouched");
            }

            for role in [Frontend::Operator, Frontend::Cli] {
                let conn = ConnCtx::new(role);
                let missing =
                    srv.handle_approve(&conn, &revoke_tester_args(json!({"allow": true})));
                assert!(
                    revoke_result_text(&missing).contains("requires a string `request_id`"),
                    "{role:?} without a request_id under {policy:?}: {missing}"
                );
                let mistyped = srv.handle_approve(
                    &conn,
                    &revoke_tester_args(json!({"request_id": id, "allow": "true"})),
                );
                assert!(
                    revoke_result_text(&mistyped).contains("requires a boolean `allow`"),
                    "{role:?} with a string allow under {policy:?}: {mistyped}"
                );
                assert_eq!(revoke_slot_state(&slot), None, "nothing was resolved");
                assert_eq!(srv.parked.len(), 1, "the entry is untouched");
            }
        }
    }

    /// The human CLI is trusted control: its approve follows the same live policy as
    /// the operator's. Under `ask` it approves; once the policy has left `ask` it is
    /// refused and the request is denied.
    #[test]
    fn revoke_park_cli_approve_follows_the_live_policy_like_the_operator() {
        let (srv, state, _runs) = revoke_park_server(AgentPolicy::Ask);
        let cli = ConnCtx::new(Frontend::Cli);

        let (id, slot) = srv.parked.try_park().expect("the table has room");
        let reply = srv.handle_approve(
            &cli,
            &revoke_tester_args(json!({"request_id": id, "allow": true})),
        );
        assert_eq!(
            reply["isError"],
            json!(false),
            "a CLI approve under ask: {reply}"
        );
        assert_eq!(revoke_slot_state(&slot), Some(true), "approved under ask");
        assert_eq!(srv.parked.len(), 0, "the table is empty");

        let (id, slot) = srv.parked.try_park().expect("the table has room");
        state.set_policy(AgentPolicy::Paused);
        let reply = srv.handle_approve(
            &cli,
            &revoke_tester_args(json!({"request_id": id, "allow": true})),
        );
        let text = revoke_result_text(&reply);
        assert_eq!(
            reply["isError"],
            json!(true),
            "a CLI approve under paused: {reply}"
        );
        assert!(
            text.contains("no longer `ask`") && text.contains("denied"),
            "the CLI is told the policy moved and the request was denied: {text}"
        );
        assert_eq!(
            revoke_slot_state(&slot),
            Some(false),
            "denied, not approved"
        );
        assert_eq!(srv.parked.len(), 0, "the table is empty");
    }

    /// Two approves racing for one parked request (`allow:true` against
    /// `allow:false`) have exactly one winner: one finds the request, the other is
    /// told no such request exists, the winner's decision is the slot's, and the
    /// table is empty. Odd rounds race under `paused`, where the winner is always a
    /// denial (an `allow:true` there resolves as denied). 100 rounds.
    #[test]
    fn revoke_park_two_racing_approves_have_exactly_one_winner() {
        for round in 0..100 {
            let paused = round % 2 == 1;
            let (srv, state, _runs) = revoke_park_server(AgentPolicy::Ask);
            let (id, slot) = srv.parked.try_park().expect("the table has room");
            if paused {
                state.set_policy(AgentPolicy::Paused);
            }
            let barrier = Arc::new(std::sync::Barrier::new(2));
            let racer = |allow: bool| {
                let srv = srv.clone();
                let id = id.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    revoke_operator_approve(&srv, &id, allow)
                })
            };
            let approver = racer(true);
            let denier = racer(false);
            let approve = approver.join().expect("the approve thread finishes");
            let deny = denier.join().expect("the deny thread finishes");

            let found =
                |reply: &JsonValue| !revoke_result_text(reply).contains("no parked request");
            assert_eq!(
                [found(&approve), found(&deny)]
                    .iter()
                    .filter(|f| **f)
                    .count(),
                1,
                "round {round} (paused {paused}): exactly one racer finds the request: \
                 approve {approve}, deny {deny}"
            );
            assert_eq!(
                revoke_slot_state(&slot),
                Some(!paused && found(&approve)),
                "round {round} (paused {paused}): the slot holds the winner's decision \
                 (approve {approve}, deny {deny})"
            );
            if found(&approve) && paused {
                assert!(
                    revoke_result_text(&approve).contains("no longer `ask`"),
                    "round {round}: a winning approve under paused is the policy refusal: {approve}"
                );
            } else if found(&approve) {
                assert_eq!(approve["isError"], json!(false), "round {round}: {approve}");
            } else {
                assert_eq!(deny["isError"], json!(false), "round {round}: {deny}");
            }
            assert_eq!(srv.parked.len(), 0, "round {round}: the table is empty");
        }
    }

    /// An `agent.approve allow:true`, a pause, and the parked waiter all touching one
    /// slot at once. Invariants over 60 rounds: every call returns; the stub runs at
    /// most once; a call the operator was told was denied (the policy refusal or no
    /// such request) never runs; when the approve was issued after the pause had
    /// returned (odd rounds), the call never runs; and the table is empty at the end.
    #[test]
    fn revoke_park_approve_racing_a_pause_never_runs_a_call_the_operator_saw_denied() {
        for round in 0..60 {
            let ordered = round % 2 == 1;
            let (srv, state, runs) =
                revoke_tester_server(AgentPolicy::Ask, Duration::from_secs(60));
            let rx = revoke_tester_spawn_call(&srv);
            let ids = revoke_tester_wait_parked(&srv, 1);
            let id = ids[0].clone();

            let barrier = Arc::new(std::sync::Barrier::new(2));
            let flipped = Arc::new(AtomicBool::new(false));
            let flipper = {
                let (state, barrier, flipped) = (state.clone(), barrier.clone(), flipped.clone());
                std::thread::spawn(move || {
                    barrier.wait();
                    state.set_policy(AgentPolicy::Paused);
                    flipped.store(true, Ordering::SeqCst);
                })
            };
            let approver = {
                let (srv, barrier, flipped) = (srv.clone(), barrier.clone(), flipped.clone());
                let id = id.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    if ordered {
                        while !flipped.load(Ordering::SeqCst) {
                            std::thread::yield_now();
                        }
                    }
                    revoke_operator_approve(&srv, &id, true)
                })
            };
            let approve = approver.join().expect("the approver thread finishes");
            flipper.join().expect("the flipper thread finishes");
            let reply = revoke_tester_recv(&srv, &rx, "the racing call did not return within 5s");

            let ran = runs.load(Ordering::SeqCst);
            let approve_ok = approve["isError"] == json!(false);
            assert!(ran <= 1, "round {round}: the stub ran {ran} times");
            if ordered {
                assert_eq!(
                    ran, 0,
                    "round {round}: an approve issued after the pause returned must not run \
                     the call (approve {approve}, call {reply})"
                );
            }
            if ran == 1 {
                assert!(
                    approve_ok && !revoke_tester_is_tool_error(&reply),
                    "round {round}: a call that ran was approved: approve {approve}, call {reply}"
                );
            } else {
                assert!(
                    revoke_tester_is_tool_error(&reply),
                    "round {round}: a call that did not run is refused: {reply}"
                );
            }
            if !approve_ok {
                assert_eq!(
                    ran, 0,
                    "round {round}: an approve the operator saw refused must not run the call \
                     (approve {approve})"
                );
            }
            assert_eq!(srv.parked.len(), 0, "round {round}: the table is empty");
        }
    }

    /// `slot.wait(timeout, recheck, ..)` with a recheck that always answers
    /// `still_ask`, run on its own thread and bounded: if it has not returned within
    /// `within` (or its thread died), the slot is resolved as denied, which releases
    /// the thread, and the test panics. A wait that never ends therefore fails the
    /// test instead of hanging the run.
    fn revoke_tester_bounded_wait(
        slot: &Arc<ParkSlot>,
        timeout: Duration,
        recheck: Duration,
        still_ask: bool,
        within: Duration,
        what: &str,
    ) -> ParkWait {
        let (tx, rx) = std::sync::mpsc::channel();
        let waiter = slot.clone();
        std::thread::spawn(move || {
            let _ = tx.send(waiter.wait(timeout, recheck, &move || still_ask));
        });
        match rx.recv_timeout(within) {
            Ok(waited) => waited,
            Err(e) => {
                slot.resolve(false);
                panic!("{what}: the wait did not end within {within:?} ({e:?})");
            }
        }
    }

    /// `ParkSlot` tolerates a poisoned mutex, as `resolve` and the old `wait` did: a
    /// recheck that panics while the slot's guard is held poisons it, and the slot
    /// still times out, still reports a policy change, and still resolves.
    #[test]
    fn revoke_park_slot_survives_a_poisoned_mutex() {
        let slot = Arc::new(ParkSlot::new());
        let poisoner = {
            let slot = slot.clone();
            std::thread::spawn(move || {
                let _ = slot.wait(Duration::from_secs(30), Duration::from_millis(10), &|| {
                    panic!("poisoning the slot mutex on purpose")
                });
            })
        };
        assert!(
            poisoner.join().is_err(),
            "setup: the recheck panicked with the slot's guard held"
        );
        assert!(
            slot.state.is_poisoned(),
            "setup: the slot mutex is poisoned"
        );

        let within = Duration::from_secs(5);
        assert_eq!(
            revoke_tester_bounded_wait(
                &slot,
                Duration::from_millis(50),
                Duration::from_millis(10),
                true,
                within,
                "poisoned, timeout"
            ),
            ParkWait::TimedOut,
            "a poisoned slot still times out"
        );
        assert_eq!(
            revoke_tester_bounded_wait(
                &slot,
                Duration::from_secs(30),
                Duration::from_millis(10),
                false,
                within,
                "poisoned, recheck"
            ),
            ParkWait::PolicyChanged,
            "a poisoned slot still reports a policy change"
        );
        slot.resolve(true);
        assert_eq!(
            revoke_tester_bounded_wait(
                &slot,
                Duration::from_secs(30),
                Duration::from_millis(10),
                false,
                within,
                "poisoned, resolved"
            ),
            ParkWait::Resolved(true),
            "a poisoned slot still resolves"
        );
    }

    /// `ParkSlot::wait` edge cases: (e) a resolve that wakes the wait wins over a
    /// recheck that would say the policy moved; (f) a resolved slot beats a zero
    /// timeout, and an unresolved zero timeout is `TimedOut` with no recheck; (g) a
    /// timeout too large for `Instant` arithmetic does not panic and is ended by the
    /// recheck or by a resolve; (h) the recheck runs on a cadence: not once at the
    /// end, and not continuously.
    #[test]
    fn revoke_park_slot_wait_edge_cases() {
        // (e) The slice is 10 s and the recheck would say "moved"; a resolve from
        // another thread wakes the condvar first, so the decision is the answer.
        let slot = Arc::new(ParkSlot::new());
        let resolver = {
            let slot = slot.clone();
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(50));
                slot.resolve(false);
            })
        };
        let waited = revoke_tester_bounded_wait(
            &slot,
            Duration::from_secs(30),
            Duration::from_secs(10),
            false,
            Duration::from_secs(5),
            "(e)",
        );
        resolver.join().expect("the resolver thread finishes");
        assert_eq!(
            waited,
            ParkWait::Resolved(false),
            "(e) a resolve that wakes the wait wins over a failing recheck"
        );

        // (f) Resolved before the deadline is not lost to a zero timeout; an
        // unresolved zero timeout is a timeout without ever asking the policy.
        let slot = ParkSlot::new();
        slot.resolve(true);
        assert_eq!(
            slot.wait(Duration::ZERO, Duration::from_millis(20), &|| false),
            ParkWait::Resolved(true),
            "(f) a resolved slot is Resolved even with a zero timeout"
        );
        let slot = ParkSlot::new();
        let asked = AtomicUsize::new(0);
        let started = Instant::now();
        let waited = slot.wait(Duration::ZERO, Duration::from_millis(20), &|| {
            asked.fetch_add(1, Ordering::SeqCst);
            false
        });
        assert_eq!(
            waited,
            ParkWait::TimedOut,
            "(f) an unresolved zero timeout is TimedOut"
        );
        assert_eq!(
            asked.load(Ordering::SeqCst),
            0,
            "(f) a zero timeout ends before the policy is asked"
        );
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "(f) a zero timeout does not wait"
        );

        // (g) `Duration::MAX` overflows `Instant` addition. No panic; the recheck
        // ends it, and so does a resolve.
        let slot = Arc::new(ParkSlot::new());
        assert_eq!(
            revoke_tester_bounded_wait(
                &slot,
                Duration::MAX,
                Duration::from_millis(10),
                false,
                Duration::from_secs(5),
                "(g) recheck"
            ),
            ParkWait::PolicyChanged,
            "(g) an unbounded wait is ended by the recheck"
        );
        let slot = Arc::new(ParkSlot::new());
        let resolver = {
            let slot = slot.clone();
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(30));
                slot.resolve(true);
            })
        };
        let started = Instant::now();
        let waited = revoke_tester_bounded_wait(
            &slot,
            Duration::MAX,
            Duration::from_secs(5),
            true,
            Duration::from_secs(4),
            "(g) resolve",
        );
        resolver.join().expect("the resolver thread finishes");
        assert_eq!(
            waited,
            ParkWait::Resolved(true),
            "(g) an unbounded wait is ended by a resolve"
        );
        assert!(
            started.elapsed() < Duration::from_secs(4),
            "(g) the resolve ends the unbounded wait at once"
        );

        // (h) 500 ms in 100 ms slices: the recheck runs after each slice, so several
        // times (not once at the end of the timeout) and nowhere near continuously.
        let slot = ParkSlot::new();
        let rechecks = AtomicUsize::new(0);
        let started = Instant::now();
        let waited = slot.wait(
            Duration::from_millis(500),
            Duration::from_millis(100),
            &|| {
                rechecks.fetch_add(1, Ordering::SeqCst);
                true
            },
        );
        let took = started.elapsed();
        let rechecks = rechecks.load(Ordering::SeqCst);
        assert_eq!(waited, ParkWait::TimedOut, "(h) the wait times out");
        assert!(
            took >= Duration::from_millis(500),
            "(h) the wait lasts the whole timeout, took {took:?}"
        );
        assert!(
            (2..=10).contains(&rechecks),
            "(h) the recheck runs once per slice (about 5 times in 500 ms of 100 ms \
             slices), not once and not continuously: {rechecks}"
        );
    }

    /// The post-wait decision over the whole cross product of wait result and live
    /// policy: it is `Approved` exactly for `(Resolved(true), Ask)` and `Refused`
    /// everywhere else, so no row of the table can grant by accident.
    #[test]
    fn revoke_park_settle_approves_only_a_resolved_approval_under_ask() {
        let waits = [
            ParkWait::Resolved(true),
            ParkWait::Resolved(false),
            ParkWait::TimedOut,
            ParkWait::PolicyChanged,
        ];
        let policies = [
            AgentPolicy::All,
            AgentPolicy::Auto,
            AgentPolicy::Ask,
            AgentPolicy::ReadOnly,
            AgentPolicy::Paused,
        ];
        for wait in waits {
            for policy in policies {
                let approved =
                    revoke_refusal(settle_park("demo.sensitive", wait, policy)).is_none();
                assert_eq!(
                    approved,
                    wait == ParkWait::Resolved(true) && policy == AgentPolicy::Ask,
                    "({wait:?}, {policy:?}) is approved only for an approval under ask"
                );
            }
        }
    }

    /// The recheck slice is the spec's 100 to 250 ms band, so a call is denied
    /// within one slice plus scheduling. A slice of minutes would defeat the
    /// bound, a slice of microseconds would make `MAX_PARKED_REQUESTS` waiters spin.
    #[test]
    fn revoke_park_recheck_slice_is_within_the_specified_band() {
        assert!(
            PARK_POLICY_RECHECK >= Duration::from_millis(100)
                && PARK_POLICY_RECHECK <= Duration::from_millis(250),
            "PARK_POLICY_RECHECK is {PARK_POLICY_RECHECK:?}, outside 100 to 250 ms"
        );
    }
    // ------------------- Task 5: the generic job bus → `notifications/aitm/job`

    /// A `Value` object from `(key, value)` pairs, so a test payload reads as the
    /// JSON it renders to.
    fn job_object(fields: Vec<(&str, Value)>) -> Value {
        Value::Object(
            fields
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect::<std::collections::BTreeMap<_, _>>(),
        )
    }

    /// A progress event for job `scan-1a2b3c4d` carrying `payload`.
    fn job_event(event: &str, seq: u64, payload: Value) -> JobEvent {
        JobEvent {
            job: "scan-1a2b3c4d".to_string(),
            kind: "scan".to_string(),
            event: event.to_string(),
            seq,
            payload,
        }
    }

    /// The one line a connection's sink holds, parsed.
    fn job_one_line(conn: &ConnCtx) -> JsonValue {
        let sink = conn.out.as_ref().expect("the connection has a sink");
        let lines = sink.drain();
        assert_eq!(lines.len(), 1, "exactly one pushed line: {lines:?}");
        serde_json::from_str(&lines[0]).expect("the pushed line is JSON")
    }

    /// Spec D3 "Progress push" / D9.2: a `JobEvent` renders as one
    /// `notifications/aitm/job` line whose `params` is the payload object with the
    /// envelope fields (`job`, `kind`, `event`, `seq`) folded in.
    #[test]
    fn job_event_renders_as_a_job_notification() {
        let state = Arc::new(AgentState::new(AgentPolicy::Auto));
        let (srv, _store) = revoke_server_with_store(&state);
        let operator = revoke_subscribe(&srv, ConnCtx::new(Frontend::Operator));

        srv.push_job_event(&job_event(
            "progress",
            3,
            job_object(vec![(
                "status",
                job_object(vec![("state", Value::Str("running".into()))]),
            )]),
        ));

        let line = job_one_line(&operator);
        assert_eq!(line["jsonrpc"], json!("2.0"), "{line}");
        assert_eq!(line["method"], json!("notifications/aitm/job"), "{line}");
        assert_eq!(line["method"], json!(JOB_NOTIFICATION_METHOD), "{line}");
        assert_eq!(line["params"]["job"], json!("scan-1a2b3c4d"), "{line}");
        assert_eq!(line["params"]["kind"], json!("scan"), "{line}");
        assert_eq!(line["params"]["event"], json!("progress"), "{line}");
        assert_eq!(line["params"]["seq"], json!(3), "{line}");
        assert_eq!(
            line["params"]["status"]["state"],
            json!("running"),
            "{line}"
        );
    }

    /// The payload wins: an envelope field is inserted only when the publisher did
    /// not already carry it (B16 — the server renders a vocabulary it does not
    /// interpret and never overwrites the publisher's own view of it).
    #[test]
    fn job_payload_fields_win_over_envelope() {
        let state = Arc::new(AgentState::new(AgentPolicy::Auto));
        let (srv, _store) = revoke_server_with_store(&state);
        let operator = revoke_subscribe(&srv, ConnCtx::new(Frontend::Operator));

        srv.push_job_event(&job_event(
            "progress",
            3,
            job_object(vec![("seq", Value::Int(9))]),
        ));

        let line = job_one_line(&operator);
        assert_eq!(line["params"]["seq"], json!(9), "{line}");
        assert_eq!(
            line["params"]["event"],
            json!("progress"),
            "an absent field still comes from the envelope: {line}"
        );
    }

    /// `fanout_state` semantics: a job line is not enqueued for an agent-role
    /// subscription while the policy is `paused`; operator subscriptions keep
    /// receiving it (spec D3, "role-aware; muted for agents under `paused`").
    #[test]
    fn job_lines_are_muted_for_agents_under_paused() {
        let state = Arc::new(AgentState::new(AgentPolicy::Auto));
        let (srv, _store) = revoke_server_with_store(&state);
        let agent = revoke_subscribe(&srv, ConnCtx::agent());
        let operator = revoke_subscribe(&srv, ConnCtx::new(Frontend::Operator));

        state.set_policy(AgentPolicy::Paused);
        srv.push_job_event(&job_event("progress", 1, job_object(vec![])));

        assert_eq!(
            agent
                .out
                .as_ref()
                .expect("the agent connection has a sink")
                .queued_len(),
            0,
            "the agent subscription is muted under `paused`"
        );
        assert_eq!(
            operator
                .out
                .as_ref()
                .expect("the operator connection has a sink")
                .queued_len(),
            1,
            "the operator subscription is never muted"
        );
    }

    /// D9.2: a server built `with_jobs` spawns, from `spawn_push_dispatcher`, a
    /// task that renders every published event — with no core event broadcast
    /// attached, so the job stream is independent of the flow stream.
    #[tokio::test]
    async fn with_jobs_dispatcher_delivers_published_events() {
        let state = Arc::new(AgentState::new(AgentPolicy::Auto));
        let bus = Arc::new(JobBus::default());
        let srv = Arc::new(
            McpServer::new(Arc::new(Registry::new()), McpTransport::Stdio)
                .with_agent_state(state)
                .with_services(
                    Arc::new(MemFlowStore::new()),
                    Arc::new(NoClient),
                    Arc::new(StdGuard::default()),
                    None,
                )
                .with_jobs(bus.clone()),
        );
        assert!(srv.jobs().is_some(), "setup: the bus is wired");
        let operator = revoke_subscribe(&srv, ConnCtx::new(Frontend::Operator));
        srv.spawn_push_dispatcher();

        bus.publish(job_event("started", 1, job_object(vec![])));

        let sink = operator.out.clone().expect("the connection has a sink");
        let deadline = Instant::now() + Duration::from_secs(2);
        let lines = loop {
            let lines = sink.drain();
            if !lines.is_empty() {
                break lines;
            }
            assert!(
                Instant::now() < deadline,
                "no job line was delivered within 2 s"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        };
        assert_eq!(lines.len(), 1, "exactly one line: {lines:?}");
        let line: JsonValue = serde_json::from_str(&lines[0]).expect("the line is JSON");
        assert_eq!(line["method"], json!("notifications/aitm/job"), "{line}");
        assert_eq!(line["params"]["event"], json!("started"), "{line}");
    }

    /// A Sensitive stub that refuses the way the real `scan.start` does: with its
    /// own `scan: <code>: <message>` vocabulary.
    struct JobGateStub(&'static str);

    impl Command for JobGateStub {
        fn name(&self) -> &str {
            self.0
        }
        fn sensitivity(&self) -> Sensitivity {
            Sensitivity::Sensitive
        }
        fn schema(&self) -> ParamSchema {
            ParamSchema {
                description: "A Sensitive stub that refuses with its own code.".into(),
                params: vec![],
                result: TypeDesc::Str,
            }
        }
        fn invoke(&self, _args: Params, _host: &CommandHost) -> anyhow::Result<Value> {
            anyhow::bail!("scan: refused_agent: test gate")
        }
    }

    /// The `result` of an agent `tools/call <name>` on `srv`.
    fn job_agent_call(srv: &McpServer, name: &str) -> JsonValue {
        let reply = srv
            .handle_on(
                &ConnCtx::agent(),
                &json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                    "params": {"name": name, "arguments": {}}})
                .to_string(),
            )
            .expect("the call replies");
        let reply: JsonValue = serde_json::from_str(&reply).expect("the reply is JSON");
        reply["result"].clone()
    }

    /// AC T1-4 / call B6: under both `auto` and `all` the policy gate lets
    /// `scan.start` answer the agent itself, so the refusal carries the command's
    /// own `scan: refused_*` code; every other Sensitive command keeps today's
    /// generic refusal under `auto`.
    #[test]
    fn scan_start_is_deferred_to_its_command_gate_under_auto_and_all() {
        for policy in [AgentPolicy::Auto, AgentPolicy::All] {
            let state = Arc::new(AgentState::new(policy));
            let mut registry = Registry::new();
            registry.add_command(Arc::new(JobGateStub("scan.start")));
            registry.add_command(Arc::new(JobGateStub("l4.inject")));
            let srv = McpServer::new(Arc::new(registry), McpTransport::Stdio)
                .with_agent_state(state)
                .with_services(
                    Arc::new(MemFlowStore::new()),
                    Arc::new(NoClient),
                    Arc::new(StdGuard::default()),
                    None,
                );

            let result = job_agent_call(&srv, "scan.start");
            assert_eq!(result["isError"], json!(true), "{policy:?}: {result}");
            let text = result["content"][0]["text"]
                .as_str()
                .expect("the result carries text");
            assert!(
                text.contains("scan: refused_agent: test gate"),
                "{policy:?}: the command's own code answers the agent: {text}"
            );
        }

        // No other Sensitive verb changes: `l4.inject` keeps the `auto` refusal.
        let state = Arc::new(AgentState::new(AgentPolicy::Auto));
        let mut registry = Registry::new();
        registry.add_command(Arc::new(JobGateStub("l4.inject")));
        let srv = McpServer::new(Arc::new(registry), McpTransport::Stdio)
            .with_agent_state(state)
            .with_services(
                Arc::new(MemFlowStore::new()),
                Arc::new(NoClient),
                Arc::new(StdGuard::default()),
                None,
            );
        let result = job_agent_call(&srv, "l4.inject");
        assert_eq!(result["isError"], json!(true), "{result}");
        let text = result["content"][0]["text"]
            .as_str()
            .expect("the result carries text");
        assert!(
            text.contains("permits no sensitive actions"),
            "l4.inject keeps the generic `auto` refusal: {text}"
        );
        assert!(
            !text.contains("scan: refused_agent"),
            "the command never ran: {text}"
        );
    }

    /// A Read stub reporting whether the host it ran against carries the job bus.
    struct JobsProbe;

    impl Command for JobsProbe {
        fn name(&self) -> &str {
            "jobs.probe"
        }
        fn sensitivity(&self) -> Sensitivity {
            Sensitivity::Read
        }
        fn schema(&self) -> ParamSchema {
            ParamSchema {
                description: "Report whether the host carries a job bus.".into(),
                params: vec![],
                result: TypeDesc::Bool,
            }
        }
        fn invoke(&self, _args: Params, host: &CommandHost) -> anyhow::Result<Value> {
            Ok(Value::Bool(host.jobs().is_some()))
        }
    }

    /// D9.2: the host the server assembles per `tools/call` carries the bus it was
    /// built `with_jobs`, so a long-running command can publish progress; without
    /// the wiring it carries none (and such a command simply publishes nowhere).
    #[test]
    fn command_host_carries_the_job_bus() {
        fn probe(srv: &McpServer) -> JsonValue {
            let reply = srv
                .handle(
                    &json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                        "params": {"name": "jobs.probe", "arguments": {}}})
                    .to_string(),
                )
                .expect("the call replies");
            let reply: JsonValue = serde_json::from_str(&reply).expect("the reply is JSON");
            assert_eq!(reply["result"]["isError"], json!(false), "{reply}");
            reply["result"]["structuredContent"].clone()
        }
        fn server() -> McpServer {
            let mut registry = Registry::new();
            registry.add_command(Arc::new(JobsProbe));
            McpServer::new(Arc::new(registry), McpTransport::Stdio).with_services(
                Arc::new(MemFlowStore::new()),
                Arc::new(NoClient),
                Arc::new(StdGuard::default()),
                None,
            )
        }

        assert_eq!(
            probe(&server().with_jobs(Arc::new(JobBus::default()))),
            json!(true)
        );
        assert_eq!(probe(&server()), json!(false));
    }

    // ------------------- Task 5 (tester): edges of the job push and the gate

    /// B16: a notification's `params` must be an object. A publisher whose
    /// payload is not one (a string, a number, null) still gets a well-formed
    /// line: the envelope fields alone, and nothing of the stray payload.
    #[test]
    fn job_payload_that_is_not_an_object_yields_envelope_only_params() {
        let state = Arc::new(AgentState::new(AgentPolicy::Auto));
        let (srv, _store) = revoke_server_with_store(&state);
        let operator = revoke_subscribe(&srv, ConnCtx::new(Frontend::Operator));

        for payload in [Value::Str("stray".into()), Value::Int(7), Value::Null] {
            srv.push_job_event(&job_event("progress", 4, payload.clone()));
            let line = job_one_line(&operator);
            let params = line["params"]
                .as_object()
                .unwrap_or_else(|| panic!("params is an object for {payload:?}: {line}"));
            let mut keys: Vec<&str> = params.keys().map(String::as_str).collect();
            keys.sort_unstable();
            assert_eq!(
                keys,
                ["event", "job", "kind", "seq"],
                "only the envelope for {payload:?}: {line}"
            );
            assert_eq!(line["params"]["seq"], json!(4), "{line}");
            assert_eq!(line["params"]["job"], json!("scan-1a2b3c4d"), "{line}");
            assert!(
                !line.to_string().contains("stray"),
                "a non-object payload never leaks into the line: {line}"
            );
        }
    }

    /// `spawn_push_dispatcher` is idempotent on the job stream too: two calls on
    /// one server deliver each published event once, not twice.
    #[tokio::test]
    async fn job_dispatcher_is_spawned_once() {
        let state = Arc::new(AgentState::new(AgentPolicy::Auto));
        let bus = Arc::new(JobBus::default());
        let srv = Arc::new(
            McpServer::new(Arc::new(Registry::new()), McpTransport::Stdio)
                .with_agent_state(state)
                .with_services(
                    Arc::new(MemFlowStore::new()),
                    Arc::new(NoClient),
                    Arc::new(StdGuard::default()),
                    None,
                )
                .with_jobs(bus.clone()),
        );
        let operator = revoke_subscribe(&srv, ConnCtx::new(Frontend::Operator));
        srv.spawn_push_dispatcher();
        srv.spawn_push_dispatcher();
        assert_eq!(
            bus.receiver_count(),
            1,
            "a second spawn takes no second subscription"
        );

        bus.publish(job_event("started", 1, job_object(vec![])));
        bus.publish(job_event("finished", 2, job_object(vec![])));

        let sink = operator.out.clone().expect("the connection has a sink");
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut lines = Vec::new();
        while lines.len() < 2 && Instant::now() < deadline {
            lines.extend(sink.drain());
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        // Give a (wrongly) doubled dispatcher time to show itself.
        tokio::time::sleep(Duration::from_millis(100)).await;
        lines.extend(sink.drain());
        let events: Vec<String> = lines
            .iter()
            .map(|l| {
                let v: JsonValue = serde_json::from_str(l).expect("JSON");
                v["params"]["event"].as_str().unwrap_or("").to_string()
            })
            .collect();
        assert_eq!(
            events,
            ["started", "finished"],
            "each event exactly once, in order: {lines:?}"
        );
    }

    /// Call B6 widens the `auto` gate by exactly one name. Every other Sensitive
    /// command — whatever it is called, `scan.*` included — keeps the generic
    /// refusal and is never invoked.
    #[test]
    fn only_scan_start_defers_to_its_command_under_auto() {
        let others = [
            "l4.inject",
            "l4.scope.add",
            "poc.run",
            "scan.map",
            "scan.cancel",
            "scan.issue.update",
            "scan.start.now",
            "proxy.system.enable",
        ];
        let state = Arc::new(AgentState::new(AgentPolicy::Auto));
        let mut registry = Registry::new();
        registry.add_command(Arc::new(JobGateStub("scan.start")));
        for name in others {
            registry.add_command(Arc::new(JobGateStub(name)));
        }
        let srv = McpServer::new(Arc::new(registry), McpTransport::Stdio)
            .with_agent_state(state)
            .with_services(
                Arc::new(MemFlowStore::new()),
                Arc::new(NoClient),
                Arc::new(StdGuard::default()),
                None,
            );

        for name in others {
            let result = job_agent_call(&srv, name);
            assert_eq!(result["isError"], json!(true), "{name}: {result}");
            let text = result["content"][0]["text"]
                .as_str()
                .expect("the result carries text");
            assert!(
                text.contains("permits no sensitive actions"),
                "{name} keeps the generic `auto` refusal: {text}"
            );
            assert!(
                !text.contains("test gate"),
                "{name} was invoked under `auto`: {text}"
            );
        }

        let result = job_agent_call(&srv, "scan.start");
        let text = result["content"][0]["text"]
            .as_str()
            .expect("the result carries text");
        assert!(
            text.contains("scan: refused_agent: test gate"),
            "scan.start alone answers in its own vocabulary: {text}"
        );
    }
}
