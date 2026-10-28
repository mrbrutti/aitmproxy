//! What the TUI knows about the proxy, parsed from bus results. `flow.get`
//! gives a row its summary (foundation §4.3); `flow.detail` (core follow-up F5)
//! fills headers, bodies, connections and metadata when the bus offers it. Every
//! parser is lenient: a missing field is a dash in the UI, never a crash.

use std::collections::{BTreeMap, VecDeque};

use serde_json::Value;

/// `http` or `websocket`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowKind {
    Http,
    WebSocket,
}

/// The core's `InterceptState`, as `flow.get` labels it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Intercept {
    #[default]
    Observed,
    Intercepted,
    Resumed,
    Killed,
}

impl Intercept {
    fn parse(s: &str) -> Self {
        match s {
            "intercepted" => Self::Intercepted,
            "resumed" => Self::Resumed,
            "killed" => Self::Killed,
            _ => Self::Observed,
        }
    }
}

/// Who caused a flow: a human client, the agent over MCP, or unknown (F2 absent).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Origin {
    #[default]
    Unknown,
    Human,
    Agent,
}

impl Origin {
    fn parse(v: Option<&Value>) -> Self {
        match v.and_then(Value::as_str) {
            Some("agent") | Some("mcp") => Self::Agent,
            Some("human") | Some("cli") | Some("mac") | Some("web") | Some("tui") => Self::Human,
            _ => Self::Unknown,
        }
    }
}

/// One row of the flow list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowRow {
    pub id: String,
    /// Arrival order, the `#` column; assigned by the app, stable for the session.
    pub seq: usize,
    pub kind: FlowKind,
    pub method: String,
    pub scheme: String,
    pub authority: String,
    pub path: String,
    pub status: Option<u16>,
    pub intercept: Intercept,
    pub is_replay: bool,
    pub handshake: Option<String>,
    pub ws_messages: Option<i64>,
    // Below: known only after `flow.detail` (F5); dashes until then.
    pub client: Option<String>,
    pub time: Option<String>,
    pub duration_ms: Option<u64>,
    pub req_size: Option<u64>,
    pub resp_size: Option<u64>,
    pub tls: Option<bool>,
    pub version: Option<String>,
    pub content_type: Option<String>,
    pub edited: bool,
    pub origin: Origin,
    pub comment: Option<String>,
    pub marks: Vec<String>,
}

impl FlowRow {
    /// Parse a `flow.get` summary object. `None` if `id` is missing.
    pub fn from_summary(v: &Value, seq: usize) -> Option<Self> {
        let id = v.get("id")?.as_str()?.to_string();
        let kind = match v.get("kind").and_then(Value::as_str) {
            Some("websocket") => FlowKind::WebSocket,
            _ => FlowKind::Http,
        };
        let s = |k: &str| v.get(k).and_then(Value::as_str).map(str::to_string);
        Some(Self {
            id,
            seq,
            kind,
            method: s("method").unwrap_or_else(|| match kind {
                FlowKind::WebSocket => "WS".into(),
                FlowKind::Http => "—".into(),
            }),
            scheme: s("scheme").unwrap_or_else(|| match kind {
                FlowKind::WebSocket => "wss".into(),
                FlowKind::Http => "http".into(),
            }),
            authority: s("authority").unwrap_or_default(),
            path: s("path").unwrap_or_default(),
            status: v
                .get("status")
                .and_then(Value::as_u64)
                .and_then(|n| u16::try_from(n).ok()),
            intercept: Intercept::parse(v.get("intercept").and_then(Value::as_str).unwrap_or("")),
            is_replay: v.get("is_replay").and_then(Value::as_bool).unwrap_or(false),
            handshake: s("handshake"),
            ws_messages: v.get("messages").and_then(Value::as_i64),
            client: None,
            time: None,
            duration_ms: None,
            req_size: None,
            resp_size: None,
            tls: None,
            version: None,
            content_type: None,
            edited: false,
            origin: Origin::Unknown,
            comment: None,
            marks: Vec::new(),
        })
    }

    /// Fold a `flow.detail` result into the row's detail-only columns.
    pub fn apply_detail(&mut self, d: &FlowDetail) {
        if let Some(req) = &d.request {
            if let Some(m) = &req.method {
                self.method = m.clone();
            }
            if let Some(a) = &req.authority {
                self.authority = a.clone();
            }
            if let Some(p) = &req.path {
                self.path = p.clone();
            }
            if let Some(s) = &req.scheme {
                self.scheme = s.clone();
            }
            self.version = req.version.clone();
            self.req_size = Some(req.body.len() as u64);
        }
        if let Some(resp) = &d.response {
            self.status = resp.status.or(self.status);
            self.resp_size = Some(resp.body.len() as u64);
            self.content_type = resp.content_type();
        }
        if let Some(c) = &d.client_conn {
            self.client = c.process.clone().or_else(|| c.peer.clone());
            self.tls = Some(c.tls);
        }
        self.time = d.meta.created.clone();
        self.duration_ms = d.meta.duration_ms;
        self.edited = d.edited;
        self.origin = d.meta.origin;
        self.comment = d.meta.comment.clone();
        self.marks = d.meta.marks.clone();
        self.is_replay = d.meta.is_replay || self.is_replay;
        // Interception state stays the summary's: `flow.get` is polled far more
        // often than a detail is fetched, so it is the fresher source.
    }

    /// `scheme://authority/path?query`.
    pub fn url(&self) -> String {
        format!("{}://{}{}", self.scheme, self.authority, self.path)
    }

    /// The host without a port.
    pub fn host(&self) -> &str {
        self.authority
            .rsplit_once(':')
            .map_or(self.authority.as_str(), |(h, _)| h)
    }

    /// Path without its query string.
    pub fn path_only(&self) -> &str {
        self.path.split('?').next().unwrap_or(&self.path)
    }

    /// The query string including `?`, if any.
    pub fn query(&self) -> Option<&str> {
        self.path.find('?').map(|i| &self.path[i..])
    }

    pub fn paused(&self) -> bool {
        self.intercept == Intercept::Intercepted
    }

    pub fn killed(&self) -> bool {
        self.intercept == Intercept::Killed
    }

    /// In flight: no response yet, not paused, not killed.
    pub fn pending(&self) -> bool {
        self.status.is_none() && !self.paused() && !self.killed() && self.kind == FlowKind::Http
    }

    pub fn is_tls(&self) -> bool {
        self.tls
            .unwrap_or(self.scheme == "https" || self.scheme == "wss")
    }
}

/// One HTTP message (request or response) from `flow.detail`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Message {
    pub method: Option<String>,
    pub scheme: Option<String>,
    pub authority: Option<String>,
    pub path: Option<String>,
    pub status: Option<u16>,
    pub version: Option<String>,
    /// Name/value pairs in wire order; names as sent.
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub body_truncated: bool,
}

impl Message {
    fn parse(v: &Value) -> Self {
        let s = |k: &str| v.get(k).and_then(Value::as_str).map(str::to_string);
        let headers = match v.get("headers") {
            Some(Value::Array(items)) => items
                .iter()
                .filter_map(|h| match h {
                    Value::Array(pair) if pair.len() == 2 => {
                        Some((pair[0].as_str()?.to_string(), pair[1].as_str()?.to_string()))
                    }
                    Value::Object(o) => Some((
                        o.get("name")?.as_str()?.to_string(),
                        o.get("value")?.as_str()?.to_string(),
                    )),
                    _ => None,
                })
                .collect(),
            Some(Value::Object(map)) => map
                .iter()
                .filter_map(|(k, v)| Some((k.clone(), v.as_str()?.to_string())))
                .collect(),
            _ => Vec::new(),
        };
        let body = match v.get("body") {
            Some(Value::String(b64)) => crate::base64::decode(b64).unwrap_or_default(),
            _ => Vec::new(),
        };
        Self {
            method: s("method"),
            scheme: s("scheme"),
            authority: s("authority"),
            path: s("path"),
            status: v
                .get("status")
                .and_then(Value::as_u64)
                .and_then(|n| u16::try_from(n).ok()),
            version: s("version"),
            headers,
            body,
            body_truncated: v
                .get("body_truncated")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        }
    }

    /// First header with that name, case-insensitively.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// The media type without parameters, lowercased.
    pub fn content_type(&self) -> Option<String> {
        self.header("content-type")
            .map(|v| v.split(';').next().unwrap_or(v).trim().to_ascii_lowercase())
    }

    /// The body as text when it is valid UTF-8.
    pub fn body_text(&self) -> Option<&str> {
        std::str::from_utf8(&self.body).ok()
    }
}

/// One side of a connection (`ConnInfo` plus the resolved process, §2.10(c)).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Conn {
    pub peer: Option<String>,
    pub sni: Option<String>,
    pub alpn: Option<String>,
    pub tls: bool,
    pub process: Option<String>,
}

impl Conn {
    fn parse(v: &Value) -> Self {
        let s = |k: &str| v.get(k).and_then(Value::as_str).map(str::to_string);
        Self {
            peer: s("peer"),
            sni: s("sni"),
            alpn: s("alpn"),
            tls: v.get("tls").and_then(Value::as_bool).unwrap_or(false),
            process: s("process"),
        }
    }
}

/// `FlowMeta` plus the origin tag (F2).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Meta {
    pub marks: Vec<String>,
    pub comment: Option<String>,
    pub is_replay: bool,
    pub created: Option<String>,
    pub duration_ms: Option<u64>,
    pub truncated: bool,
    pub origin: Origin,
}

/// One WebSocket frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WsFrame {
    pub dir: String,
    pub opcode: String,
    pub data: Vec<u8>,
    pub time: Option<String>,
    pub injected: bool,
}

/// Everything the inspector shows for one flow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowDetail {
    pub id: String,
    pub kind: FlowKind,
    pub request: Option<Message>,
    pub response: Option<Message>,
    pub client_conn: Option<Conn>,
    pub server_conn: Option<Conn>,
    pub meta: Meta,
    pub intercept: Intercept,
    pub edited: bool,
    pub frames: Vec<WsFrame>,
}

impl FlowDetail {
    /// Parse a `flow.detail` result. `None` without an `id`.
    pub fn from_json(v: &Value) -> Option<Self> {
        let id = v.get("id")?.as_str()?.to_string();
        let meta_v = v.get("meta").cloned().unwrap_or(Value::Null);
        let meta = Meta {
            marks: meta_v
                .get("marks")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(|m| m.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default(),
            comment: meta_v
                .get("comment")
                .and_then(Value::as_str)
                .map(str::to_string),
            is_replay: meta_v
                .get("is_replay")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            created: meta_v
                .get("created")
                .and_then(Value::as_str)
                .map(str::to_string),
            duration_ms: meta_v.get("duration_ms").and_then(Value::as_u64),
            truncated: meta_v
                .get("truncated")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            origin: Origin::parse(meta_v.get("origin")),
        };
        let frames = v
            .get("frames")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .map(|f| WsFrame {
                        dir: f
                            .get("dir")
                            .and_then(Value::as_str)
                            .unwrap_or("?")
                            .to_string(),
                        opcode: f
                            .get("opcode")
                            .and_then(Value::as_str)
                            .unwrap_or("text")
                            .to_string(),
                        data: f
                            .get("data")
                            .and_then(Value::as_str)
                            .and_then(crate::base64::decode)
                            .unwrap_or_default(),
                        time: f.get("time").and_then(Value::as_str).map(str::to_string),
                        injected: f.get("injected").and_then(Value::as_bool).unwrap_or(false),
                    })
                    .collect()
            })
            .unwrap_or_default();
        Some(Self {
            id,
            kind: match v.get("kind").and_then(Value::as_str) {
                Some("websocket") => FlowKind::WebSocket,
                _ => FlowKind::Http,
            },
            request: v
                .get("request")
                .filter(|r| r.is_object())
                .map(Message::parse),
            response: v
                .get("response")
                .filter(|r| r.is_object())
                .map(Message::parse),
            client_conn: v
                .get("client_conn")
                .filter(|c| c.is_object())
                .map(Conn::parse),
            server_conn: v
                .get("server_conn")
                .filter(|c| c.is_object())
                .map(Conn::parse),
            meta,
            intercept: Intercept::parse(v.get("intercept").and_then(Value::as_str).unwrap_or("")),
            edited: v.get("edited").and_then(Value::as_bool).unwrap_or(false),
            frames,
        })
    }
}

/// PoC finding severity, as `aitm-poc` names them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn parse(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "critical" => Self::Critical,
            "high" => Self::High,
            "medium" => Self::Medium,
            "low" => Self::Low,
            _ => Self::Info,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
            Self::Info => "info",
        }
    }
}

/// One PoC run (the Findings panel, §2.7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub title: String,
    pub severity: Severity,
    pub target: String,
    pub passed: bool,
    pub when: String,
    pub origin: Origin,
    pub poc_path: String,
    pub finding_capture: Option<String>,
    pub screenshot_path: Option<String>,
    /// `(assertion, matched)`.
    pub assertions: Vec<(String, bool)>,
    /// The PoC YAML, from the result or (on a loopback bus) read from
    /// `poc_path` by the app.
    pub yaml: Option<String>,
    /// Why `poc_path` could not be read, when the app tried.
    pub yaml_error: Option<String>,
}

impl Finding {
    /// Parse one entry of `poc.list` (F13) or a `poc.run` result.
    pub fn from_json(v: &Value) -> Option<Self> {
        let s = |k: &str| v.get(k).and_then(Value::as_str).map(str::to_string);
        let poc_path = s("poc_path")?;
        let assertions = v
            .get("evaluated")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|e| {
                        Some((
                            e.get("assertion")?.as_str()?.to_string(),
                            e.get("matched").and_then(Value::as_bool).unwrap_or(false),
                        ))
                    })
                    .collect()
            })
            .unwrap_or_default();
        Some(Self {
            title: s("title").or_else(|| s("name")).unwrap_or_else(|| {
                std::path::Path::new(&poc_path)
                    .file_stem()
                    .and_then(|x| x.to_str())
                    .unwrap_or("poc")
                    .to_string()
            }),
            severity: Severity::parse(v.get("severity").and_then(Value::as_str).unwrap_or("info")),
            target: s("target").unwrap_or_default(),
            passed: v.get("passed").and_then(Value::as_bool).unwrap_or(false),
            when: s("at").or_else(|| s("when")).unwrap_or_default(),
            origin: Origin::parse(v.get("origin")),
            poc_path,
            finding_capture: s("finding_capture"),
            screenshot_path: s("screenshot_path"),
            assertions,
            yaml: s("yaml"),
            yaml_error: None,
        })
    }
}

/// Agent policy (F1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentPolicy {
    All,
    ReadOnly,
    Paused,
}

impl AgentPolicy {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "all" => Some(Self::All),
            "readonly" | "read_only" | "read-only" => Some(Self::ReadOnly),
            "paused" => Some(Self::Paused),
            _ => None,
        }
    }

    pub fn wire(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::ReadOnly => "readonly",
            Self::Paused => "paused",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::All => "all tools",
            Self::ReadOnly => "read-only",
            Self::Paused => "paused",
        }
    }
}

/// One activity-log row (F2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivityEntry {
    pub at: String,
    pub origin: Origin,
    pub origin_name: String,
    pub command: String,
    pub args: String,
    pub result: String,
}

/// The agent's state. `policy == None` means the bus has no `agent.status` yet.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AgentState {
    pub policy: Option<AgentPolicy>,
    pub actions_last_minute: u64,
    pub connected_clients: u64,
    pub log: VecDeque<ActivityEntry>,
}

impl AgentState {
    /// Parse an `agent.status` result, keeping the existing log.
    pub fn apply_status(&mut self, v: &Value) {
        self.policy = v
            .get("policy")
            .and_then(Value::as_str)
            .and_then(AgentPolicy::parse);
        self.actions_last_minute = v
            .get("actions_last_minute")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        self.connected_clients = v
            .get("connected_clients")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        if let Some(log) = v.get("log").and_then(Value::as_array) {
            self.log = log.iter().filter_map(ActivityEntry::from_json).collect();
        }
    }
}

impl ActivityEntry {
    pub fn from_json(v: &Value) -> Option<Self> {
        let s = |k: &str| v.get(k).and_then(Value::as_str).map(str::to_string);
        Some(Self {
            at: s("at").unwrap_or_default(),
            origin: Origin::parse(v.get("origin")),
            origin_name: s("origin").unwrap_or_else(|| "?".into()),
            command: s("command")?,
            args: v
                .get("args")
                .map(|a| match a {
                    Value::String(s) => s.clone(),
                    other => compact_json(other),
                })
                .unwrap_or_default(),
            result: s("result").unwrap_or_default(),
        })
    }
}

/// `{"a":1,"b":"x"}` → `a=1 b=x`, for one-line argument summaries.
pub fn compact_json(v: &Value) -> String {
    match v {
        Value::Object(map) => map
            .iter()
            .map(|(k, v)| match v {
                Value::String(s) => format!("{k}={s}"),
                other => format!("{k}={other}"),
            })
            .collect::<Vec<_>>()
            .join(" "),
        other => other.to_string(),
    }
}

/// Human byte count: `0 B`, `412 B`, `1.1 KB`, `18.2 KB`, `2.3 MB`.
pub fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    if n < 1000 {
        return format!("{n} B");
    }
    let mut v = n as f64;
    let mut unit = 0;
    while v >= 1000.0 && unit < UNITS.len() - 1 {
        v /= 1000.0;
        unit += 1;
    }
    if v >= 100.0 {
        format!("{v:.0} {}", UNITS[unit])
    } else {
        format!("{v:.1} {}", UNITS[unit])
    }
}

/// Human duration: `89 ms`, `1.21 s`.
pub fn human_ms(ms: u64) -> String {
    if ms < 1000 {
        format!("{ms} ms")
    } else {
        format!("{:.2} s", ms as f64 / 1000.0)
    }
}

/// `2026-10-27T11:05:22.994Z` → `11:05:22.994`; anything else passes through.
pub fn clock_of(ts: &str) -> String {
    ts.split_once('T')
        .map(|(_, t)| t.trim_end_matches('Z').to_string())
        .unwrap_or_else(|| ts.to_string())
}

/// Scope-as-authorisation (§2.7): whether `authority` is covered by any scope
/// entry — `host`, `host:port` (exact) or `*.wildcard` (the suffix itself or
/// any subdomain of it).
pub fn scope_covers(scope: &[String], authority: &str) -> bool {
    let host = authority.rsplit_once(':').map_or(authority, |(h, _)| h);
    scope.iter().any(|e| {
        if let Some(suffix) = e.strip_prefix("*.") {
            host == suffix || host.ends_with(&format!(".{suffix}"))
        } else if e.contains(':') {
            e == authority
        } else {
            e == host
        }
    })
}

/// Count flows per key, preserving first-seen order.
pub fn counts_by<'a, I, F>(rows: I, key: F) -> Vec<(String, usize)>
where
    I: IntoIterator<Item = &'a FlowRow>,
    F: Fn(&FlowRow) -> Option<String>,
{
    let mut order = Vec::new();
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for row in rows {
        if let Some(k) = key(row) {
            if !counts.contains_key(&k) {
                order.push(k.clone());
            }
            *counts.entry(k).or_insert(0) += 1;
        }
    }
    order
        .into_iter()
        .map(|k| {
            let n = counts[&k];
            (k, n)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn summary_parses_an_http_flow() {
        let v = json!({"id":"f1","kind":"http","method":"POST","scheme":"https","authority":"auth.shop-staging.test",
                       "path":"/api/auth/login?x=1","status":null,"is_replay":false,"intercept":"intercepted"});
        let row = FlowRow::from_summary(&v, 50).unwrap();
        assert_eq!(row.seq, 50);
        assert_eq!(row.method, "POST");
        assert_eq!(
            row.url(),
            "https://auth.shop-staging.test/api/auth/login?x=1"
        );
        assert_eq!(row.path_only(), "/api/auth/login");
        assert_eq!(row.query(), Some("?x=1"));
        assert!(row.paused());
        assert!(!row.pending());
        assert_eq!(row.status, None);
        assert!(row.is_tls());
    }

    #[test]
    fn summary_parses_a_websocket_flow() {
        let v = json!({"id":"w1","kind":"websocket","handshake":"f9","messages":38,"is_replay":false,"intercept":"observed"});
        let row = FlowRow::from_summary(&v, 47).unwrap();
        assert_eq!(row.kind, FlowKind::WebSocket);
        assert_eq!(row.method, "WS");
        assert_eq!(row.ws_messages, Some(38));
        assert_eq!(row.handshake.as_deref(), Some("f9"));
        assert!(!row.pending());
    }

    #[test]
    fn detail_fills_the_row() {
        let v = json!({"id":"f1","kind":"http",
            "request":{"method":"GET","scheme":"https","authority":"api.test:8443","path":"/p","version":"HTTP/2",
                       "headers":[["Host","api.test"],["Accept","*/*"]],"body":"aGVsbG8="},
            "response":{"status":200,"version":"HTTP/2","headers":[["Content-Type","application/json; charset=utf-8"]],"body":"e30="},
            "client_conn":{"peer":"127.0.0.1:1","sni":"api.test","alpn":"h2","tls":true,"process":"curl"},
            "meta":{"marks":["red"],"comment":"hi","is_replay":true,"created":"2026-10-27T11:05:04.067Z","duration_ms":412,"truncated":false,"origin":"agent"},
            "intercept":"resumed","edited":true});
        let d = FlowDetail::from_json(&v).unwrap();
        let req = d.request.as_ref().unwrap();
        assert_eq!(req.body_text(), Some("hello"));
        assert_eq!(req.header("host"), Some("api.test"));
        assert_eq!(
            d.response.as_ref().unwrap().content_type().as_deref(),
            Some("application/json")
        );
        let mut row = FlowRow::from_summary(&json!({"id":"f1","kind":"http"}), 1).unwrap();
        row.apply_detail(&d);
        assert_eq!(row.host(), "api.test");
        assert_eq!(row.client.as_deref(), Some("curl"));
        assert_eq!(row.req_size, Some(5));
        assert_eq!(row.resp_size, Some(2));
        assert_eq!(row.content_type.as_deref(), Some("application/json"));
        assert_eq!(row.origin, Origin::Agent);
        assert!(row.edited);
        assert!(row.is_replay);
        assert_eq!(row.duration_ms, Some(412));
        assert_eq!(row.status, Some(200));
    }

    #[test]
    fn finding_parses_a_poc_run_result() {
        let v = json!({"passed":true,"finding_capture":"f48","poc_path":"/pocs/reflected-xss.yaml","screenshot_path":"/pocs/reflected-xss.png",
                       "evaluated":[{"assertion":"status == 200","matched":true},{"assertion":"word: onerror","matched":false}],
                       "severity":"high","target":"https://api.shop-staging.test"});
        let f = Finding::from_json(&v).unwrap();
        assert_eq!(f.title, "reflected-xss");
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.assertions.len(), 2);
        assert_eq!(f.assertions[1], ("word: onerror".to_string(), false));
        assert_eq!(f.finding_capture.as_deref(), Some("f48"));
    }

    #[test]
    fn formatting_helpers() {
        assert_eq!(human_bytes(0), "0 B");
        assert_eq!(human_bytes(412), "412 B");
        assert_eq!(human_bytes(1_100), "1.1 KB");
        assert_eq!(human_bytes(18_200), "18.2 KB");
        assert_eq!(human_bytes(196_000_000), "196 MB");
        assert_eq!(human_ms(89), "89 ms");
        assert_eq!(human_ms(1210), "1.21 s");
        assert_eq!(clock_of("2026-10-27T11:05:22.994Z"), "11:05:22.994");
        assert_eq!(compact_json(&json!({"id":"f1","n":2})), "id=f1 n=2");
    }

    /// Q3: scope matching lives with the model, not the reducer.
    #[test]
    fn scope_matching_rules() {
        let s = vec![
            "api.test".to_string(),
            "*.shop.test".to_string(),
            "h.test:8443".to_string(),
        ];
        assert!(scope_covers(&s, "api.test"));
        assert!(scope_covers(&s, "api.test:443"));
        assert!(scope_covers(&s, "shop.test"));
        assert!(scope_covers(&s, "a.b.shop.test"));
        assert!(scope_covers(&s, "h.test:8443"));
        assert!(!scope_covers(&s, "h.test"));
        assert!(!scope_covers(&s, "notshop.test"));
        assert!(!scope_covers(&[], "api.test"));
    }

    /// Q7: the row's content type comes from `Message::content_type`, so the
    /// two cannot drift (parameters stripped, lowercased).
    #[test]
    fn apply_detail_uses_the_message_content_type() {
        let d = FlowDetail::from_json(&json!({"id":"f1",
            "response":{"status":200,"headers":[["Content-Type"," Text/HTML ; charset=utf-8"]]}}))
        .unwrap();
        let mut row = FlowRow::from_summary(&json!({"id":"f1"}), 1).unwrap();
        row.apply_detail(&d);
        assert_eq!(
            row.content_type,
            d.response.as_ref().unwrap().content_type()
        );
        assert_eq!(row.content_type.as_deref(), Some("text/html"));
    }

    #[test]
    fn agent_status_applies() {
        let mut a = AgentState::default();
        a.apply_status(&json!({"policy":"readonly","actions_last_minute":14,"connected_clients":1,
            "log":[{"at":"11:05","origin":"mcp","command":"flow.replay","args":{"id":"f45"},"result":"ok"}]}));
        assert_eq!(a.policy, Some(AgentPolicy::ReadOnly));
        assert_eq!(a.actions_last_minute, 14);
        assert_eq!(a.log[0].args, "id=f45");
        assert_eq!(a.log[0].origin, Origin::Agent);
    }
}
