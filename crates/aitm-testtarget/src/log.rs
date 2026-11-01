//! In-memory observer log behind the control origin (spec D2): bounded rings
//! for HTTP requests / TLS handshakes, `/ws` events and L4 speaker traffic, a
//! connection table, the `/services` registry, and the header redaction that
//! keeps `cookie` / `authorization` out of every snapshot.
//!
//! Every entry carries `seq` (one global monotonic counter across all rings),
//! `ts_ms` (epoch milliseconds) and `conn_id` (`c-<8 hex>` per accepted TCP
//! connection; UDP datagrams use `u-<peer port>`, minted by the L4 driver).
//! Each ring holds [`RING_CAP`] entries; a full ring drops the oldest and
//! counts it in `dropped`.

use std::collections::{BTreeMap, VecDeque};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use hyper::header::HeaderMap;
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::seed::SeedMode;

/// Capacity of every log ring (D2: 50 000 entries).
pub(crate) const RING_CAP: usize = 50_000;

/// Request headers kept verbatim in a `request` entry (D2). Anything else
/// except `x-*` is dropped; `cookie` / `authorization` are hashed, never
/// kept; the `x-*` names in [`X_CREDENTIAL_DENYLIST`] keep only their name.
const HEADER_ALLOWLIST: &[&str] = &[
    "host",
    "origin",
    "referer",
    "user-agent",
    "content-type",
    "content-length",
    "accept",
    "connection",
    "upgrade",
    "sec-websocket-key",
    "sec-websocket-version",
    "sec-websocket-protocol",
];

/// `x-*` headers that carry a credential: kept as the name with the value
/// `"<redacted>"`, never the value itself (names lower-cased).
const X_CREDENTIAL_DENYLIST: &[&str] = &[
    "x-api-key",
    "x-auth-token",
    "x-csrf-token",
    "x-amz-security-token",
];

// --- Tokens -----------------------------------------------------------------

/// Which HTTP listener accepted a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Listener {
    Plain,
    Tls,
    TlsH1,
}

impl Listener {
    /// The URL scheme requests on this listener arrive under.
    pub(crate) fn scheme(self) -> &'static str {
        match self {
            Listener::Plain => "http",
            Listener::Tls | Listener::TlsH1 => "https",
        }
    }
}

/// HTTP version a request was parsed as.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum HttpVersion {
    H1,
    H2,
}

impl From<hyper::Version> for HttpVersion {
    fn from(v: hyper::Version) -> Self {
        if v == hyper::Version::HTTP_2 {
            HttpVersion::H2
        } else {
            HttpVersion::H1
        }
    }
}

/// Direction of a frame or datagram relative to the target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Dir {
    In,
    Out,
}

/// How the L4 driver classified a message (D5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Classified {
    Ok,
    ProtocolError,
    Denylisted,
    Trigger,
}

/// Why an L4 connection closed (D2 `closes[].reason`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CloseReason {
    Eof,
    Quit,
    Trigger,
    Oversize,
    Error,
}

/// WebSocket opcode token on a `frame` entry (D2 `/log/ws`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum WsOpcode {
    Text,
    Binary,
    Ping,
    Pong,
    Close,
}

// --- Connections ------------------------------------------------------------

/// One accepted HTTP-listener TCP connection, shared by the serving task and
/// the connection table so `/log/conns` can show when it closed.
#[derive(Debug)]
pub(crate) struct ConnInfo {
    pub(crate) conn_id: String,
    pub(crate) listener: Listener,
    pub(crate) alpn: Option<String>,
    pub(crate) peer: SocketAddr,
    pub(crate) opened_ms: u64,
    pub(crate) requests: AtomicU32,
    /// Set when `/ws` answered 101 on this connection: from then on only the
    /// frame loop's end closes it ([`ControlLog::close_conn_upgraded`]).
    pub(crate) upgraded: AtomicBool,
    pub(crate) closed_ms: Mutex<Option<u64>>,
}

impl ConnInfo {
    /// Per-connection 1-based request counter (`conn_req_index`, AC T3-3).
    pub(crate) fn next_request_index(&self) -> u32 {
        self.requests.fetch_add(1, Ordering::SeqCst) + 1
    }

    /// Record that `/ws` took this connection over (the 101 was produced).
    pub(crate) fn mark_upgraded(&self) {
        self.upgraded.store(true, Ordering::SeqCst);
    }

    /// Whether `/ws` took this connection over.
    pub(crate) fn is_upgraded(&self) -> bool {
        self.upgraded.load(Ordering::SeqCst)
    }

    fn to_json(&self) -> Value {
        json!({
            "conn_id": self.conn_id,
            "listener": self.listener,
            "alpn": self.alpn,
            "peer": self.peer.to_string(),
            "opened_ms": self.opened_ms,
            "closed_ms": *lock(&self.closed_ms),
            "requests": self.requests.load(Ordering::SeqCst),
        })
    }
}

// --- HTTP entries -----------------------------------------------------------

/// One `/log/http` entry.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum HttpLogEntry {
    Request(RequestEntry),
    TlsHandshake(TlsHandshakeEntry),
}

/// A served request (D2 `request`). `seq` and `ts_ms` are stamped by
/// [`ControlLog::log_request`]; whatever the caller put there is overwritten.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct RequestEntry {
    pub(crate) seq: u64,
    pub(crate) ts_ms: u64,
    pub(crate) conn_id: String,
    pub(crate) listener: Listener,
    pub(crate) version: HttpVersion,
    pub(crate) conn_req_index: u32,
    pub(crate) method: String,
    pub(crate) path: String,
    pub(crate) query: String,
    pub(crate) headers: BTreeMap<String, String>,
    pub(crate) cookie_names: Vec<String>,
    pub(crate) cookie_sha256: Option<String>,
    pub(crate) auth_sha256: Option<String>,
    pub(crate) body_len: usize,
    pub(crate) body_sha256: String,
    pub(crate) status: u16,
}

/// A TLS handshake on `tls` / `tls_h1` (D2 `tls_handshake`); `alpn` is
/// `h2`, `http/1.1` or `none`.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct TlsHandshakeEntry {
    pub(crate) seq: u64,
    pub(crate) ts_ms: u64,
    pub(crate) conn_id: String,
    pub(crate) listener: Listener,
    pub(crate) alpn: String,
}

// --- WebSocket entries ------------------------------------------------------

/// One `/log/ws` entry. `seq` and `ts_ms` are stamped by
/// [`ControlLog::log_ws`].
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum WsLogEntry {
    Handshake(WsHandshakeEntry),
    Frame(WsFrameEntry),
    Close(WsCloseEntry),
}

/// The `/ws` upgrade decision (D2 `/log/ws` `handshake`, D4 log row).
#[derive(Debug, Clone, Serialize)]
pub(crate) struct WsHandshakeEntry {
    pub(crate) seq: u64,
    pub(crate) ts_ms: u64,
    pub(crate) conn_id: String,
    pub(crate) listener: Listener,
    pub(crate) path: String,
    pub(crate) origin: Option<String>,
    pub(crate) sec_websocket_key: String,
    pub(crate) cookie_names: Vec<String>,
    pub(crate) session_valid: bool,
    pub(crate) accepted: bool,
    pub(crate) status: u16,
    pub(crate) subprotocol: Option<String>,
}

/// One WebSocket frame in either direction.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct WsFrameEntry {
    pub(crate) seq: u64,
    pub(crate) ts_ms: u64,
    pub(crate) conn_id: String,
    pub(crate) dir: Dir,
    pub(crate) opcode: WsOpcode,
    pub(crate) len: usize,
    pub(crate) sha256: String,
}

/// Written when a `/ws` loop ends (D4 log row); `code` is the close code sent
/// or echoed, `None` when the connection ended without one.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct WsCloseEntry {
    pub(crate) seq: u64,
    pub(crate) ts_ms: u64,
    pub(crate) conn_id: String,
    pub(crate) code: Option<u16>,
}

// --- L4 entries -------------------------------------------------------------

/// A TCP accept on an L4 service (UDP services never log one).
#[derive(Debug, Clone, Serialize)]
pub(crate) struct L4Accept {
    pub(crate) seq: u64,
    pub(crate) ts_ms: u64,
    pub(crate) conn_id: String,
    pub(crate) peer: String,
}

/// One L4 message (a TCP read the speaker parsed, a write, or a datagram).
#[derive(Debug, Clone, Serialize)]
pub(crate) struct L4Message {
    pub(crate) seq: u64,
    pub(crate) ts_ms: u64,
    pub(crate) conn_id: String,
    pub(crate) dir: Dir,
    pub(crate) len: usize,
    pub(crate) sha256: String,
    pub(crate) verb: Option<String>,
    pub(crate) classified: Classified,
}

/// An L4 TCP connection close with its byte counters (T6).
#[derive(Debug, Clone, Serialize)]
pub(crate) struct L4Close {
    pub(crate) seq: u64,
    pub(crate) ts_ms: u64,
    pub(crate) conn_id: String,
    pub(crate) reason: CloseReason,
    pub(crate) bytes_in: u64,
    pub(crate) bytes_out: u64,
}

/// A V-mode crash window (D5): the service was down from `down_at_ms` until
/// `up_at_ms`; `trigger_sha256` hashes the input that caused it.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct L4Downtime {
    pub(crate) seq: u64,
    pub(crate) ts_ms: u64,
    pub(crate) service: String,
    pub(crate) conn_id: String,
    pub(crate) down_at_ms: u64,
    pub(crate) up_at_ms: u64,
    pub(crate) trigger_sha256: String,
}

/// The four rings kept per L4 service.
#[derive(Debug, Default)]
pub(crate) struct L4Log {
    pub(crate) accepts: Ring<L4Accept>,
    pub(crate) messages: Ring<L4Message>,
    pub(crate) closes: Ring<L4Close>,
    pub(crate) downtime: Ring<L4Downtime>,
}

impl L4Log {
    fn dropped(&self) -> u64 {
        self.accepts.dropped + self.messages.dropped + self.closes.dropped + self.downtime.dropped
    }

    fn clear(&mut self) {
        self.accepts.clear();
        self.messages.clear();
        self.closes.clear();
        self.downtime.clear();
    }

    fn to_json(&self) -> Value {
        json!({
            "accepts": self.accepts.items,
            "messages": self.messages.items,
            "closes": self.closes.items,
            "downtime": self.downtime.items,
        })
    }
}

// --- Services ---------------------------------------------------------------

/// One `/services` row. `alpn` is serialized only when present (HTTP
/// listeners); `grammar` is serialized (possibly `null`) for `role == "l4"`.
#[derive(Debug, Clone)]
pub(crate) struct ServiceInfo {
    pub(crate) name: String,
    pub(crate) proto: &'static str,
    pub(crate) addr: SocketAddr,
    pub(crate) role: &'static str,
    pub(crate) alpn: Option<Vec<&'static str>>,
    pub(crate) grammar: Option<&'static str>,
}

impl ServiceInfo {
    fn to_json(&self) -> Value {
        let mut row = serde_json::Map::new();
        row.insert("name".into(), json!(self.name));
        row.insert("proto".into(), json!(self.proto));
        row.insert("addr".into(), json!(self.addr.to_string()));
        row.insert("role".into(), json!(self.role));
        if let Some(alpn) = &self.alpn {
            row.insert("alpn".into(), json!(alpn));
        }
        if self.role == "l4" {
            row.insert("grammar".into(), json!(self.grammar));
        }
        Value::Object(row)
    }
}

// --- Ring -------------------------------------------------------------------

/// A bounded FIFO of at most [`RING_CAP`] items; pushing into a full ring
/// drops the oldest item and counts it in `dropped`.
#[derive(Debug)]
pub(crate) struct Ring<T> {
    items: VecDeque<T>,
    dropped: u64,
}

impl<T> Default for Ring<T> {
    fn default() -> Self {
        Ring::new()
    }
}

impl<T> Ring<T> {
    pub(crate) fn new() -> Self {
        Ring {
            items: VecDeque::new(),
            dropped: 0,
        }
    }

    pub(crate) fn push(&mut self, item: T) {
        if self.items.len() >= RING_CAP {
            self.items.pop_front();
            self.dropped += 1;
        }
        self.items.push_back(item);
    }

    pub(crate) fn clear(&mut self) {
        self.items.clear();
        self.dropped = 0;
    }
}

impl<T: Clone> Ring<T> {
    /// The items oldest-first plus the drop count.
    #[cfg(test)]
    pub(crate) fn snapshot(&self) -> (Vec<T>, u64) {
        (self.items.iter().cloned().collect(), self.dropped)
    }
}

impl<T: Serialize> Ring<T> {
    fn to_json(&self) -> Value {
        json!({ "entries": self.items, "dropped": self.dropped })
    }
}

// --- Hashing / redaction ----------------------------------------------------

/// Lower-case hex SHA-256 (64 chars).
pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

/// The first 16 hex chars of [`sha256_hex`] (the `cookie_sha256` /
/// `auth_sha256` shape).
pub(crate) fn sha256_prefix16(bytes: &[u8]) -> String {
    let mut s = sha256_hex(bytes);
    s.truncate(16);
    s
}

/// Split every `Cookie` header into name/value pairs; the first occurrence of a
/// name wins, values are kept raw (no decoding).
pub(crate) fn parse_cookies(headers: &HeaderMap) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for value in headers.get_all("cookie") {
        let Ok(text) = value.to_str() else {
            continue;
        };
        for pair in text.split(';') {
            let Some((name, val)) = pair.split_once('=') else {
                continue;
            };
            let name = name.trim();
            if name.is_empty() {
                continue;
            }
            out.entry(name.to_string())
                .or_insert_with(|| val.trim().to_string());
        }
    }
    out
}

/// What a `request` / `handshake` entry keeps of the request headers.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Redacted {
    pub(crate) headers: BTreeMap<String, String>,
    pub(crate) cookie_names: Vec<String>,
    pub(crate) cookie_sha256: Option<String>,
    pub(crate) auth_sha256: Option<String>,
}

/// Apply the D2 header policy: keep the allowlist and `x-*` verbatim (names
/// lower-cased; a non-UTF-8 value becomes `"<binary>"`; repeated headers are
/// joined with `", "`), except that an `x-*` name on [`X_CREDENTIAL_DENYLIST`]
/// is kept as `"<redacted>"`; hash `cookie` / `authorization` (first 16 hex
/// of SHA-256 over the raw value; several `cookie` headers are joined with
/// `"; "` first) and list the cookie names ([`parse_cookies`], sorted).
/// Nothing else survives.
pub(crate) fn redact_headers(h: &HeaderMap) -> Redacted {
    let mut out = Redacted::default();
    let mut cookie_raw: Option<Vec<u8>> = None;
    let mut auth_raw: Option<Vec<u8>> = None;

    for (name, value) in h {
        let name = name.as_str().to_ascii_lowercase();
        match name.as_str() {
            "cookie" => append_raw(&mut cookie_raw, b"; ", value.as_bytes()),
            "authorization" => append_raw(&mut auth_raw, b", ", value.as_bytes()),
            n if X_CREDENTIAL_DENYLIST.contains(&n) => {
                out.headers.insert(name.clone(), "<redacted>".to_string());
            }
            n if HEADER_ALLOWLIST.contains(&n) || n.starts_with("x-") => {
                let text = value.to_str().unwrap_or("<binary>");
                out.headers
                    .entry(name.clone())
                    .and_modify(|existing| {
                        existing.push_str(", ");
                        existing.push_str(text);
                    })
                    .or_insert_with(|| text.to_string());
            }
            _ => {}
        }
    }

    // One cookie parser for the routes and the log: a `BTreeMap`'s keys are
    // already sorted and unique.
    out.cookie_names = parse_cookies(h).into_keys().collect();
    out.cookie_sha256 = cookie_raw.as_deref().map(sha256_prefix16);
    out.auth_sha256 = auth_raw.as_deref().map(sha256_prefix16);
    out
}

fn append_raw(slot: &mut Option<Vec<u8>>, sep: &[u8], value: &[u8]) {
    match slot {
        Some(buf) => {
            buf.extend_from_slice(sep);
            buf.extend_from_slice(value);
        }
        None => *slot = Some(value.to_vec()),
    }
}

/// Lock a std mutex, recovering the data if a panicking holder poisoned it:
/// an observer log must keep answering after any single serving task dies.
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

// --- ControlLog -------------------------------------------------------------

/// The per-instance observer log every served module writes into and the
/// control origin reads from. Shared as an `Arc`; every method takes `&self`.
#[derive(Debug)]
pub(crate) struct ControlLog {
    mode: SeedMode,
    seq: AtomicU64,
    conn_counter: AtomicU64,
    http: Mutex<Ring<HttpLogEntry>>,
    ws: Mutex<Ring<WsLogEntry>>,
    l4: Mutex<BTreeMap<String, L4Log>>,
    conns: Mutex<Ring<Arc<ConnInfo>>>,
    services: Mutex<Vec<ServiceInfo>>,
}

impl ControlLog {
    pub(crate) fn new(mode: SeedMode) -> Arc<ControlLog> {
        Arc::new(ControlLog {
            mode,
            seq: AtomicU64::new(0),
            conn_counter: AtomicU64::new(0),
            http: Mutex::new(Ring::new()),
            ws: Mutex::new(Ring::new()),
            l4: Mutex::new(BTreeMap::new()),
            conns: Mutex::new(Ring::new()),
            services: Mutex::new(Vec::new()),
        })
    }

    #[cfg(test)]
    pub(crate) fn mode(&self) -> SeedMode {
        self.mode
    }

    /// The D2 mode token (`vulnerable` / `patched`).
    pub(crate) fn mode_token(&self) -> &'static str {
        match self.mode {
            SeedMode::Vulnerable => "vulnerable",
            SeedMode::Patched => "patched",
        }
    }

    /// Issue the next global sequence number (first issued is 1).
    pub(crate) fn next_seq(&self) -> u64 {
        self.seq.fetch_add(1, Ordering::SeqCst) + 1
    }

    /// Epoch milliseconds now (0 if the clock is before the epoch).
    pub(crate) fn now_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
            .unwrap_or(0)
    }

    // -- connections --

    /// Mint a `c-<8 hex>` connection and add it to `/log/conns`.
    pub(crate) fn open_conn(
        &self,
        listener: Listener,
        alpn: Option<&str>,
        peer: SocketAddr,
    ) -> Arc<ConnInfo> {
        let conn = Arc::new(ConnInfo {
            conn_id: self.next_conn_id(),
            listener,
            alpn: alpn.map(str::to_string),
            peer,
            opened_ms: Self::now_ms(),
            requests: AtomicU32::new(0),
            upgraded: AtomicBool::new(false),
            closed_ms: Mutex::new(None),
        });
        lock(&self.conns).push(conn.clone());
        conn
    }

    /// Stamp `closed_ms` on a connection the listener is done with. A no-op
    /// for an upgraded connection: hyper resolves `serve_h1` as soon as the
    /// `/ws` upgrade is handed off, so the listener gets here right after
    /// the 101 while the frame loop is still running; that loop's end
    /// ([`close_conn_upgraded`](Self::close_conn_upgraded)) is the close.
    pub(crate) fn close_conn(&self, conn: &ConnInfo) {
        if conn.is_upgraded() {
            return;
        }
        *lock(&conn.closed_ms) = Some(Self::now_ms());
    }

    /// Stamp `closed_ms` on an upgraded connection: the `/ws` frame loop's
    /// end, the only close that counts once the 101 went out.
    pub(crate) fn close_conn_upgraded(&self, conn: &ConnInfo) {
        *lock(&conn.closed_ms) = Some(Self::now_ms());
    }

    fn next_conn_id(&self) -> String {
        let n = self.conn_counter.fetch_add(1, Ordering::SeqCst) + 1;
        format!("c-{n:08x}")
    }

    // -- HTTP --

    /// Append a `request` entry; `seq` / `ts_ms` are assigned here.
    pub(crate) fn log_request(&self, mut e: RequestEntry) {
        e.seq = self.next_seq();
        e.ts_ms = Self::now_ms();
        lock(&self.http).push(HttpLogEntry::Request(e));
    }

    /// Append a `tls_handshake` entry for an accepted TLS connection; `alpn`
    /// is the negotiated protocol or `none`.
    pub(crate) fn log_tls_handshake(&self, conn: &ConnInfo) {
        let alpn = conn.alpn.clone().unwrap_or_else(|| "none".to_string());
        self.push_tls_handshake(conn.conn_id.clone(), conn.listener, alpn);
    }

    /// Append a `tls_handshake` entry with `alpn: "none"` for a TCP accept
    /// whose TLS handshake failed, so no `ConnInfo` exists. The entry still
    /// carries a fresh `conn_id`; no `/log/conns` row is created.
    pub(crate) fn log_tls_handshake_failed(&self, listener: Listener) {
        self.push_tls_handshake(self.next_conn_id(), listener, "none".to_string());
    }

    fn push_tls_handshake(&self, conn_id: String, listener: Listener, alpn: String) {
        let entry = TlsHandshakeEntry {
            seq: self.next_seq(),
            ts_ms: Self::now_ms(),
            conn_id,
            listener,
            alpn,
        };
        lock(&self.http).push(HttpLogEntry::TlsHandshake(entry));
    }

    // -- WebSocket --

    /// Append a `/log/ws` entry; `seq` / `ts_ms` are assigned here.
    pub(crate) fn log_ws(&self, mut e: WsLogEntry) {
        let (seq, ts_ms) = (self.next_seq(), Self::now_ms());
        match &mut e {
            WsLogEntry::Handshake(h) => {
                h.seq = seq;
                h.ts_ms = ts_ms;
            }
            WsLogEntry::Frame(f) => {
                f.seq = seq;
                f.ts_ms = ts_ms;
            }
            WsLogEntry::Close(c) => {
                c.seq = seq;
                c.ts_ms = ts_ms;
            }
        }
        lock(&self.ws).push(e);
    }

    // -- L4 --

    /// Run `f` on `service`'s rings, creating them on first use.
    fn with_l4(&self, service: &str, f: impl FnOnce(&mut L4Log)) {
        let mut l4 = lock(&self.l4);
        match l4.get_mut(service) {
            Some(log) => f(log),
            None => f(l4.entry(service.to_string()).or_default()),
        }
    }

    pub(crate) fn l4_accept(&self, service: &str, conn_id: &str, peer: SocketAddr) {
        let entry = L4Accept {
            seq: self.next_seq(),
            ts_ms: Self::now_ms(),
            conn_id: conn_id.to_string(),
            peer: peer.to_string(),
        };
        self.with_l4(service, |log| log.accepts.push(entry));
    }

    /// Log one message; `bytes` is hashed and measured, never stored.
    pub(crate) fn l4_message(
        &self,
        service: &str,
        conn_id: &str,
        dir: Dir,
        bytes: &[u8],
        verb: Option<&str>,
        classified: Classified,
    ) {
        let entry = L4Message {
            seq: self.next_seq(),
            ts_ms: Self::now_ms(),
            conn_id: conn_id.to_string(),
            dir,
            len: bytes.len(),
            sha256: sha256_hex(bytes),
            verb: verb.map(str::to_string),
            classified,
        };
        self.with_l4(service, |log| log.messages.push(entry));
    }

    pub(crate) fn l4_close(
        &self,
        service: &str,
        conn_id: &str,
        reason: CloseReason,
        bytes_in: u64,
        bytes_out: u64,
    ) {
        let entry = L4Close {
            seq: self.next_seq(),
            ts_ms: Self::now_ms(),
            conn_id: conn_id.to_string(),
            reason,
            bytes_in,
            bytes_out,
        };
        self.with_l4(service, |log| log.closes.push(entry));
    }

    /// Log a V-mode crash window; `trigger` is hashed, never stored.
    pub(crate) fn l4_downtime(
        &self,
        service: &str,
        conn_id: &str,
        down_at_ms: u64,
        up_at_ms: u64,
        trigger: &[u8],
    ) {
        let entry = L4Downtime {
            seq: self.next_seq(),
            ts_ms: Self::now_ms(),
            service: service.to_string(),
            conn_id: conn_id.to_string(),
            down_at_ms,
            up_at_ms,
            trigger_sha256: sha256_hex(trigger),
        };
        self.with_l4(service, |log| log.downtime.push(entry));
    }

    // -- services --

    /// Add a `/services` row. An `l4` role also pre-creates the service's
    /// `/log/l4` slot so an idle service still appears with empty rings.
    pub(crate) fn register_service(&self, s: ServiceInfo) {
        if s.role == "l4" {
            lock(&self.l4).entry(s.name.clone()).or_default();
        }
        lock(&self.services).push(s);
    }

    // -- snapshots --

    /// `GET /services` body.
    pub(crate) fn services_json(&self) -> Value {
        let services: Vec<Value> = lock(&self.services)
            .iter()
            .map(ServiceInfo::to_json)
            .collect();
        json!({ "mode": self.mode_token(), "services": services })
    }

    /// `GET /log/http` body.
    pub(crate) fn http_json(&self) -> Value {
        lock(&self.http).to_json()
    }

    /// `GET /log/ws` body.
    pub(crate) fn ws_json(&self) -> Value {
        lock(&self.ws).to_json()
    }

    /// `GET /log/l4[?service=NAME]` body; `dropped` sums the rings shown.
    pub(crate) fn l4_json(&self, service: Option<&str>) -> Value {
        let l4 = lock(&self.l4);
        let mut services = serde_json::Map::new();
        let mut dropped = 0u64;
        for (name, log) in l4.iter() {
            if service.is_some_and(|wanted| wanted != name) {
                continue;
            }
            dropped += log.dropped();
            services.insert(name.clone(), log.to_json());
        }
        json!({ "services": services, "dropped": dropped })
    }

    /// `GET /log/conns` body.
    pub(crate) fn conns_json(&self) -> Value {
        let entries: Vec<Value> = lock(&self.conns)
            .items
            .iter()
            .map(|c| c.to_json())
            .collect();
        json!({ "entries": entries })
    }

    /// `POST /reset`: clear every ring and its `dropped`; return the last
    /// `seq` issued before the reset. The counter itself keeps counting.
    pub(crate) fn reset(&self) -> u64 {
        lock(&self.http).clear();
        lock(&self.ws).clear();
        for log in lock(&self.l4).values_mut() {
            log.clear();
        }
        lock(&self.conns).clear();
        self.seq.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use hyper::header::{HeaderMap, HeaderName, HeaderValue};

    use super::*;
    use crate::seed::SeedMode;

    fn peer() -> SocketAddr {
        "127.0.0.1:40000".parse().expect("literal socket addr")
    }

    fn request_entry(conn: &ConnInfo) -> RequestEntry {
        RequestEntry {
            seq: 0,
            ts_ms: 0,
            conn_id: conn.conn_id.clone(),
            listener: conn.listener,
            version: HttpVersion::H1,
            conn_req_index: conn.next_request_index(),
            method: "GET".to_string(),
            path: "/preview".to_string(),
            query: "msg=a".to_string(),
            headers: std::collections::BTreeMap::new(),
            cookie_names: Vec::new(),
            cookie_sha256: None,
            auth_sha256: None,
            body_len: 0,
            body_sha256: sha256_hex(b""),
            status: 200,
        }
    }

    #[test]
    fn redact_never_stores_cookie_or_authorization() {
        let mut h = HeaderMap::new();
        h.insert(
            HeaderName::from_static("cookie"),
            HeaderValue::from_static("session=abc; theme=dark"),
        );
        h.insert(
            HeaderName::from_static("authorization"),
            HeaderValue::from_static("Bearer x"),
        );
        h.insert(
            HeaderName::from_static("x-role"),
            HeaderValue::from_static("admin"),
        );
        h.insert(
            HeaderName::from_static("host"),
            HeaderValue::from_static("h"),
        );

        let r = redact_headers(&h);

        assert_eq!(
            r.cookie_names,
            vec!["session".to_string(), "theme".to_string()]
        );
        // The literal prefixes (`printf 'session=abc; theme=dark' | shasum -a 256`).
        assert_eq!(r.cookie_sha256.as_deref(), Some("5c5fc99ebd5b1b93"));
        assert_eq!(r.auth_sha256.as_deref(), Some("b937a6fd6074f365"));
        assert_eq!(
            r.cookie_sha256.as_deref(),
            Some(sha256_prefix16(b"session=abc; theme=dark").as_str())
        );
        assert_eq!(
            r.auth_sha256.as_deref(),
            Some(sha256_prefix16(b"Bearer x").as_str())
        );
        assert_eq!(r.headers.get("x-role").map(String::as_str), Some("admin"));
        assert_eq!(r.headers.get("host").map(String::as_str), Some("h"));
        assert!(!r.headers.contains_key("cookie"));
        assert!(!r.headers.contains_key("authorization"));
        let dumped = serde_json::to_string(&r.headers).expect("serialize headers");
        assert!(!dumped.contains("abc"), "raw cookie leaked: {dumped}");
        assert!(
            !dumped.contains("Bearer"),
            "raw authorization leaked: {dumped}"
        );
    }

    #[test]
    fn x_credential_headers_are_redacted_not_kept() {
        // `x-*` is kept verbatim except the credential-bearing names, which
        // survive only as `"<redacted>"` (name kept, value never stored).
        let mut h = HeaderMap::new();
        for (name, value) in [
            ("x-api-key", "k-secret"),
            ("X-Auth-Token", "t-secret"),
            ("x-csrf-token", "c-secret"),
            ("x-amz-security-token", "a-secret"),
            ("x-request-id", "req-1"),
        ] {
            h.append(
                HeaderName::from_bytes(name.as_bytes()).expect("header name"),
                HeaderValue::from_static(value),
            );
        }
        let r = redact_headers(&h);
        for name in [
            "x-api-key",
            "x-auth-token",
            "x-csrf-token",
            "x-amz-security-token",
        ] {
            assert_eq!(
                r.headers.get(name).map(String::as_str),
                Some("<redacted>"),
                "{name}"
            );
        }
        assert_eq!(
            r.headers.get("x-request-id").map(String::as_str),
            Some("req-1")
        );
        let dumped = serde_json::to_string(&r.headers).expect("serialize headers");
        assert!(!dumped.contains("secret"), "credential leaked: {dumped}");

        // Tester (stage 5): a repeated or non-UTF-8 credential header is
        // still one `"<redacted>"`, never joined or dumped as `<binary>`.
        let mut h = HeaderMap::new();
        h.append(
            HeaderName::from_static("x-api-key"),
            HeaderValue::from_static("first-secret"),
        );
        h.append(
            HeaderName::from_static("x-api-key"),
            HeaderValue::from_bytes(&[0xff, 0xfe]).expect("opaque header value"),
        );
        h.append(
            HeaderName::from_static("x-amz-security-token"),
            HeaderValue::from_bytes(&[0xff]).expect("opaque header value"),
        );
        let r = redact_headers(&h);
        assert_eq!(
            r.headers.get("x-api-key").map(String::as_str),
            Some("<redacted>")
        );
        assert_eq!(
            r.headers.get("x-amz-security-token").map(String::as_str),
            Some("<redacted>")
        );
        let dumped = serde_json::to_string(&r.headers).expect("serialize headers");
        assert!(!dumped.contains("secret"), "credential leaked: {dumped}");
        assert!(!dumped.contains("<binary>"), "{dumped}");
    }

    #[test]
    fn ring_is_bounded() {
        let mut ring: Ring<usize> = Ring::new();
        for i in 0..RING_CAP + 5 {
            ring.push(i);
        }
        let (items, dropped) = ring.snapshot();
        assert_eq!(items.len(), 50_000);
        assert_eq!(dropped, 5);
        // The oldest five were the ones dropped.
        assert_eq!(items.first().copied(), Some(5));
        assert_eq!(items.last().copied(), Some(RING_CAP + 4));
    }

    #[test]
    fn seq_is_global_and_monotonic() {
        let log = ControlLog::new(SeedMode::Vulnerable);
        let conn = log.open_conn(Listener::Plain, None, peer());

        log.log_request(request_entry(&conn));
        log.l4_message(
            "l4-resp",
            "c-00000009",
            Dir::In,
            b"PING\r\n",
            Some("PING"),
            Classified::Ok,
        );
        log.log_ws(WsLogEntry::Close(WsCloseEntry {
            seq: 0,
            ts_ms: 0,
            conn_id: conn.conn_id.clone(),
            code: Some(1000),
        }));
        log.log_request(request_entry(&conn));
        log.l4_message(
            "l4-resp",
            "c-00000009",
            Dir::Out,
            b"+PONG\r\n",
            None,
            Classified::Ok,
        );

        let http = log.http_json();
        let ws = log.ws_json();
        let l4 = log.l4_json(None);

        let seq_of = |v: &serde_json::Value| v["seq"].as_u64().expect("seq is a u64");
        let http_entries = http["entries"].as_array().expect("http entries");
        let ws_entries = ws["entries"].as_array().expect("ws entries");
        let l4_msgs = l4["services"]["l4-resp"]["messages"]
            .as_array()
            .expect("l4 messages")
            .clone();
        assert_eq!(http_entries.len(), 2);
        assert_eq!(ws_entries.len(), 1);
        assert_eq!(l4_msgs.len(), 2);

        // Issue order: http(1) l4(2) ws(3) http(4) l4(5).
        assert_eq!(
            (
                seq_of(&http_entries[0]),
                seq_of(&l4_msgs[0]),
                seq_of(&ws_entries[0]),
                seq_of(&http_entries[1]),
                seq_of(&l4_msgs[1]),
            ),
            (1, 2, 3, 4, 5)
        );
        assert_eq!(l4_msgs[0]["verb"], serde_json::json!("PING"));
        assert_eq!(l4_msgs[1]["verb"], serde_json::Value::Null);
        assert_eq!(l4_msgs[0]["classified"], serde_json::json!("ok"));
        assert_eq!(l4_msgs[0]["dir"], serde_json::json!("in"));
        assert_eq!(l4_msgs[0]["len"], serde_json::json!(6));
        assert_eq!(
            l4_msgs[0]["sha256"],
            serde_json::json!(sha256_hex(b"PING\r\n"))
        );
        assert_eq!(ws_entries[0]["kind"], serde_json::json!("close"));
        assert_eq!(ws_entries[0]["code"], serde_json::json!(1000));
        assert_eq!(http_entries[0]["kind"], serde_json::json!("request"));
        assert_eq!(http_entries[0]["conn_req_index"], serde_json::json!(1));
        assert_eq!(http_entries[1]["conn_req_index"], serde_json::json!(2));
    }

    #[test]
    fn reset_clears_and_returns_last_seq() {
        let log = ControlLog::new(SeedMode::Patched);
        let conn = log.open_conn(Listener::Tls, Some("h2"), peer());
        log.log_tls_handshake(&conn);
        log.log_request(request_entry(&conn));
        log.l4_accept("l4-tlv-crash", "c-00000042", peer());
        log.l4_close("l4-tlv-crash", "c-00000042", CloseReason::Eof, 5, 5);
        log.l4_downtime("l4-tlv-crash", "c-00000042", 1_000, 6_000, b"\xff\xff");
        log.close_conn(&conn);
        assert_eq!(
            log.conns_json()["entries"].as_array().map(Vec::len),
            Some(1)
        );

        let last = log.reset();
        assert_eq!(last, 5);

        assert_eq!(
            log.http_json(),
            serde_json::json!({"entries": [], "dropped": 0})
        );
        assert_eq!(
            log.ws_json(),
            serde_json::json!({"entries": [], "dropped": 0})
        );
        let l4 = log.l4_json(Some("l4-tlv-crash"));
        assert_eq!(l4["dropped"], serde_json::json!(0));
        assert_eq!(
            l4["services"]["l4-tlv-crash"]["accepts"],
            serde_json::json!([])
        );
        assert_eq!(
            l4["services"]["l4-tlv-crash"]["closes"],
            serde_json::json!([])
        );
        assert_eq!(
            l4["services"]["l4-tlv-crash"]["downtime"],
            serde_json::json!([])
        );
        assert_eq!(log.conns_json(), serde_json::json!({"entries": []}));

        // The counter is not reset: the next entry continues after `last`.
        assert_eq!(log.next_seq(), 6);
        assert_eq!(log.mode(), SeedMode::Patched);
    }

    #[test]
    fn close_conn_skips_an_upgraded_conn_until_the_ws_loop_closes_it() {
        // hyper resolves an upgraded h1 connection as soon as the upgrade is
        // handed off, so the listener calls `close_conn` right after the 101;
        // that must not stamp `closed_ms`. Only the `/ws` loop's
        // `close_conn_upgraded` does.
        let log = ControlLog::new(SeedMode::Vulnerable);
        let conn = log.open_conn(Listener::Plain, None, peer());
        assert!(!conn.is_upgraded());
        conn.mark_upgraded();
        assert!(conn.is_upgraded());
        log.close_conn(&conn);
        assert_eq!(*lock(&conn.closed_ms), None);
        assert_eq!(
            log.conns_json()["entries"][0]["closed_ms"],
            serde_json::Value::Null
        );
        log.close_conn_upgraded(&conn);
        let closed = *lock(&conn.closed_ms);
        assert!(closed.is_some_and(|c| c >= conn.opened_ms), "{closed:?}");
        assert_eq!(
            log.conns_json()["entries"][0]["closed_ms"],
            serde_json::json!(closed)
        );
        // A connection that was never upgraded is stamped by `close_conn`.
        let plain = log.open_conn(Listener::Plain, None, peer());
        log.close_conn(&plain);
        assert!(lock(&plain.closed_ms).is_some());
    }

    #[test]
    fn tls_handshake_entry_serializes_kind() {
        let log = ControlLog::new(SeedMode::Vulnerable);
        let conn = log.open_conn(Listener::Tls, Some("h2"), peer());
        log.log_tls_handshake(&conn);

        let http = log.http_json();
        let entry = &http["entries"][0];
        assert_eq!(entry["kind"], serde_json::json!("tls_handshake"));
        assert_eq!(entry["alpn"], serde_json::json!("h2"));
        assert_eq!(entry["listener"], serde_json::json!("tls"));
        assert_eq!(entry["conn_id"], serde_json::json!(conn.conn_id.clone()));
        assert_eq!(entry["seq"], serde_json::json!(1));
        assert!(entry["ts_ms"].as_u64().is_some());
        assert_eq!(http["dropped"], serde_json::json!(0));

        let conns = log.conns_json();
        let row = &conns["entries"][0];
        assert_eq!(row["conn_id"], serde_json::json!(conn.conn_id.clone()));
        assert_eq!(row["listener"], serde_json::json!("tls"));
        assert_eq!(row["alpn"], serde_json::json!("h2"));
        assert_eq!(row["peer"], serde_json::json!("127.0.0.1:40000"));
        assert_eq!(row["closed_ms"], serde_json::Value::Null);
        assert_eq!(row["requests"], serde_json::json!(0));
    }

    // --- Tester additions (stage 5): redaction edges, failed TLS, shapes, overflow ---

    #[test]
    fn redact_edge_cases() {
        let mut h = HeaderMap::new();
        h.append(
            HeaderName::from_static("x-bin"),
            HeaderValue::from_bytes(&[0xff, 0xfe]).expect("opaque header value"),
        );
        h.append(
            HeaderName::from_static("accept-language"),
            HeaderValue::from_static("en"),
        );
        h.append(
            HeaderName::from_static("x-a"),
            HeaderValue::from_static("1"),
        );
        h.append(
            HeaderName::from_static("x-a"),
            HeaderValue::from_static("2"),
        );
        h.append(
            HeaderName::from_static("cookie"),
            HeaderValue::from_static("b=2; a=1"),
        );
        h.append(
            HeaderName::from_static("cookie"),
            HeaderValue::from_static("a=3; =x; c"),
        );
        h.append(
            HeaderName::from_static("user-agent"),
            HeaderValue::from_static("ua/1"),
        );
        let r = redact_headers(&h);
        assert_eq!(r.headers.get("x-bin").map(String::as_str), Some("<binary>"));
        assert!(
            !r.headers.contains_key("accept-language"),
            "{:?}",
            r.headers
        );
        assert_eq!(r.headers.get("x-a").map(String::as_str), Some("1, 2"));
        assert_eq!(
            r.headers.get("user-agent").map(String::as_str),
            Some("ua/1")
        );
        // Names come from the one cookie parser (`parse_cookies`): sorted,
        // deduplicated, and a bare `c` without `=` is not a cookie-pair.
        assert_eq!(r.cookie_names, vec!["a".to_string(), "b".to_string()]);
        assert_eq!(
            r.cookie_names,
            parse_cookies(&h).keys().cloned().collect::<Vec<_>>()
        );
        assert_eq!(
            r.cookie_sha256.as_deref(),
            Some(sha256_prefix16(b"b=2; a=1; a=3; =x; c").as_str())
        );
        assert_eq!(r.auth_sha256, None);

        // No cookie / authorization at all: empty names and null hashes.
        let r = redact_headers(&HeaderMap::new());
        assert_eq!(r, Redacted::default());
        assert!(r.cookie_names.is_empty());
        assert_eq!(r.cookie_sha256, None);
        assert_eq!(r.auth_sha256, None);
    }

    #[test]
    fn failed_tls_handshake_logs_none_without_a_conn_row() {
        let log = ControlLog::new(SeedMode::Vulnerable);
        log.log_tls_handshake_failed(Listener::TlsH1);
        let http = log.http_json();
        let e = &http["entries"][0];
        assert_eq!(e["kind"], serde_json::json!("tls_handshake"));
        assert_eq!(e["alpn"], serde_json::json!("none"));
        assert_eq!(e["listener"], serde_json::json!("tls_h1"));
        assert_eq!(e["conn_id"], serde_json::json!("c-00000001"));
        assert_eq!(e["seq"], serde_json::json!(1));
        assert_eq!(log.conns_json(), serde_json::json!({ "entries": [] }));
        // An accepted connection with no ALPN also reads `none`, but has a row.
        let conn = log.open_conn(Listener::Tls, None, peer());
        log.log_tls_handshake(&conn);
        assert_eq!(conn.conn_id, "c-00000002");
        assert_eq!(
            log.http_json()["entries"][1]["alpn"],
            serde_json::json!("none")
        );
        assert_eq!(
            log.conns_json()["entries"][0]["alpn"],
            serde_json::Value::Null
        );
    }

    #[test]
    fn services_json_shape_follows_d2() {
        let log = ControlLog::new(SeedMode::Patched);
        log.register_service(ServiceInfo {
            name: "http".into(),
            proto: "tcp",
            addr: peer(),
            role: "http",
            alpn: Some(vec!["http/1.1"]),
            grammar: None,
        });
        log.register_service(ServiceInfo {
            name: "control".into(),
            proto: "tcp",
            addr: peer(),
            role: "control",
            alpn: None,
            grammar: None,
        });
        log.register_service(ServiceInfo {
            name: "l4-resp".into(),
            proto: "tcp",
            addr: peer(),
            role: "l4",
            alpn: None,
            grammar: Some("resp"),
        });
        log.register_service(ServiceInfo {
            name: "l4-udp-echo".into(),
            proto: "udp",
            addr: peer(),
            role: "l4",
            alpn: None,
            grammar: None,
        });
        let v = log.services_json();
        assert_eq!(v["mode"], serde_json::json!("patched"));
        let rows = v["services"].as_array().expect("services");
        assert_eq!(rows.len(), 4);
        assert_eq!(
            rows[0],
            serde_json::json!({"name":"http","proto":"tcp","addr":"127.0.0.1:40000","role":"http","alpn":["http/1.1"]})
        );
        assert_eq!(
            rows[1],
            serde_json::json!({"name":"control","proto":"tcp","addr":"127.0.0.1:40000","role":"control"})
        );
        assert_eq!(
            rows[2],
            serde_json::json!({"name":"l4-resp","proto":"tcp","addr":"127.0.0.1:40000","role":"l4","grammar":"resp"})
        );
        assert_eq!(
            rows[3],
            serde_json::json!({"name":"l4-udp-echo","proto":"udp","addr":"127.0.0.1:40000","role":"l4","grammar":null})
        );
        // Registering an l4 service pre-creates its empty /log/l4 slot; the
        // HTTP and control rows get none.
        let l4 = log.l4_json(None);
        assert_eq!(
            l4["services"]["l4-resp"],
            serde_json::json!({"accepts":[],"messages":[],"closes":[],"downtime":[]})
        );
        assert!(l4["services"].get("http").is_none());
        assert_eq!(l4["services"].as_object().map(|m| m.len()), Some(2));
        assert_eq!(
            log.l4_json(Some("nope")),
            serde_json::json!({ "services": {}, "dropped": 0 })
        );
    }

    #[test]
    fn l4_ring_overflow_counts_dropped_and_reset_clears_it() {
        let log = ControlLog::new(SeedMode::Vulnerable);
        for _ in 0..RING_CAP + 3 {
            log.l4_message(
                "l4-tlv-crash",
                "c-00000001",
                Dir::In,
                b"\0\0",
                Some("frame"),
                Classified::Ok,
            );
        }
        let l4 = log.l4_json(Some("l4-tlv-crash"));
        assert_eq!(l4["dropped"], serde_json::json!(3));
        assert_eq!(
            l4["services"]["l4-tlv-crash"]["messages"]
                .as_array()
                .map(Vec::len),
            Some(RING_CAP)
        );
        // The oldest three were dropped: the first remaining carries seq 4.
        assert_eq!(
            l4["services"]["l4-tlv-crash"]["messages"][0]["seq"],
            serde_json::json!(4)
        );
        let last = log.reset();
        assert_eq!(last, u64::try_from(RING_CAP + 3).expect("fits"));
        let l4 = log.l4_json(Some("l4-tlv-crash"));
        assert_eq!(l4["dropped"], serde_json::json!(0));
        assert_eq!(
            l4["services"]["l4-tlv-crash"]["messages"],
            serde_json::json!([])
        );
    }
}
