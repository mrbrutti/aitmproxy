//! What the TUI knows about the proxy, parsed from bus results. `flow.get`
//! gives a row its summary (foundation §4.3); `flow.detail` (core follow-up F5)
//! fills headers, bodies, connections and metadata when the bus offers it. Every
//! parser is lenient: a missing field is a dash in the UI, never a crash.

use std::collections::{BTreeMap, VecDeque};

use serde_json::Value;

/// `http`, `websocket`, or `l4` (ui-ext §3.1: the flow list and inspector
/// iterate this enum with per-kind renderers, so a surface can never "only
/// render HTTP" — an unknown/absent kind renders a labelled placeholder).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowKind {
    Http,
    WebSocket,
    /// A raw-L4 flow (capture / craft / send-recv / intercept). Its list cells
    /// come from [`L4Row`]; the full packet log lives in `App::l4`.
    L4,
}

/// The list-row view of an L4 flow (ui-ext §3.2): the badge sub-label, target,
/// session state, and packet / injected counts. Built by [`FlowRow::from_l4`];
/// the full packet log lives in `App::l4.flows` keyed by the flow id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct L4Row {
    /// `TCP` / `UDP` / `ICMP` sub-label, when a transport layer decoded.
    pub proto: Option<String>,
    /// The bound interface (+ filter), the row's "URL" cell.
    pub target: String,
    /// The session state: `capture` / `craft` / `send_recv` / `intercept`.
    pub state: String,
    /// Packets recorded so far (the "Request" count cell).
    pub packets: u64,
    /// Of those, how many aitmproxy injected (the "Response" count cell).
    pub injected: u64,
    /// The interface, for scope-as-authorisation matching.
    pub interface: String,
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
    /// Present exactly when `kind == FlowKind::L4`: the L4 list cells.
    pub l4: Option<L4Row>,
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
                FlowKind::L4 => "L4".into(),
                FlowKind::Http => "—".into(),
            }),
            scheme: s("scheme").unwrap_or_else(|| match kind {
                FlowKind::WebSocket => "wss".into(),
                FlowKind::L4 => "l4".into(),
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
            l4: None,
        })
    }

    /// Build the list row of an L4 flow (ui-ext §3.2). Carries the L4 cells in
    /// [`FlowRow::l4`]; the HTTP-shaped fields stay empty/defaulted so the shared
    /// list machinery (selection, `visible`) treats it like any other row.
    pub fn from_l4(flow: &crate::l4::L4Flow, seq: usize) -> Self {
        Self {
            id: flow.id.clone(),
            seq,
            kind: FlowKind::L4,
            method: "L4".into(),
            scheme: "l4".into(),
            authority: String::new(),
            path: String::new(),
            status: None,
            intercept: Intercept::Observed,
            is_replay: false,
            handshake: None,
            ws_messages: None,
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
            l4: Some(L4Row {
                proto: flow.proto().map(str::to_string),
                target: flow.target(),
                state: flow.kind.clone(),
                packets: flow.packet_count,
                injected: flow.injected_count,
                interface: flow.interface.clone(),
            }),
        }
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
            self.req_size = Some(req.size());
        }
        if let Some(resp) = &d.response {
            self.status = resp.status.or(self.status);
            self.resp_size = Some(resp.size());
            self.content_type = resp.content_type();
        }
        if let Some(c) = &d.client_conn {
            // The Client column is the owning process (null until the core
            // resolves peer→process, foundation Q6); the peer address stays
            // on the Connection tab.
            self.client = c.process.clone();
            self.tls = Some(c.tls);
        }
        if d.kind == FlowKind::WebSocket && self.ws_messages.is_none() {
            self.ws_messages = i64::try_from(d.messages.len()).ok();
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
    /// The core's `body_size`: the stored body's length even when `body` is
    /// null (body mode `none`, or a body still streaming).
    pub body_size: Option<u64>,
    pub body_truncated: bool,
}

impl Message {
    /// The body's size for the list columns: `body_size` when the core
    /// reported one, else the bytes it sent.
    pub fn size(&self) -> u64 {
        self.body_size.unwrap_or(self.body.len() as u64)
    }

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
            body_size: v.get("body_size").and_then(Value::as_u64),
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
    /// When the connection was established (RFC3339), as the core reports it.
    pub established: Option<String>,
    /// The owning process; `None` until the core resolves it (foundation Q6).
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
            established: s("established"),
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

/// A WebSocket message's direction, as `flow.detail` labels it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WsDir {
    ClientToServer,
    ServerToClient,
}

impl WsDir {
    /// `client_to_server` / `server_to_client`; anything else is unknown.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "client_to_server" => Some(Self::ClientToServer),
            "server_to_client" => Some(Self::ServerToClient),
            _ => None,
        }
    }

    /// The glyph the frame list draws: `→` to the server, `←` back.
    pub fn arrow(self) -> &'static str {
        match self {
            Self::ClientToServer => "→",
            Self::ServerToClient => "←",
        }
    }
}

/// One WebSocket message (`flow.detail` `messages[]`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WsFrame {
    /// `None` when the bus named a direction the model does not know.
    pub dir: Option<WsDir>,
    pub opcode: String,
    /// The core's `length`: the message's size even when `data` is null.
    pub length: Option<u64>,
    pub data: Vec<u8>,
    pub timestamp: Option<String>,
    pub injected: bool,
}

impl WsFrame {
    fn parse(f: &Value) -> Self {
        Self {
            dir: f.get("dir").and_then(Value::as_str).and_then(WsDir::parse),
            opcode: f
                .get("opcode")
                .and_then(Value::as_str)
                .unwrap_or("text")
                .to_string(),
            length: f.get("length").and_then(Value::as_u64),
            data: f
                .get("data")
                .and_then(Value::as_str)
                .and_then(crate::base64::decode)
                .unwrap_or_default(),
            timestamp: f
                .get("timestamp")
                .and_then(Value::as_str)
                .map(str::to_string),
            injected: f.get("injected").and_then(Value::as_bool).unwrap_or(false),
        }
    }
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
    /// A WebSocket flow's messages, oldest first; empty for HTTP.
    pub messages: Vec<WsFrame>,
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
        let messages = v
            .get("messages")
            .and_then(Value::as_array)
            .map(|a| a.iter().map(WsFrame::parse).collect())
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
            messages,
        })
    }
}

/// `proxy.status` as the control plugin (F7) reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyStatus {
    /// Whether the proxy is actually serving (false on a one-shot command
    /// that never bound).
    pub listening: bool,
    /// The configured listen address.
    pub address: Option<String>,
    pub intercept_armed: bool,
    /// Whether new flows are retained (`proxy.pause` turns this off).
    pub capturing: bool,
    /// Parked (intercepted) flows in the store.
    pub paused: u64,
    /// Visible flows in the store.
    pub flows: u64,
}

impl ProxyStatus {
    /// Parse the result object. Lenient: a missing flag reads as the quiet
    /// state (not listening, not armed, capturing).
    pub fn from_json(v: &Value) -> Self {
        let b = |k: &str, default: bool| v.get(k).and_then(Value::as_bool).unwrap_or(default);
        let n = |k: &str| v.get(k).and_then(Value::as_u64).unwrap_or(0);
        Self {
            listening: b("listening", false),
            address: v.get("address").and_then(Value::as_str).map(str::to_string),
            intercept_armed: b("intercept_armed", false),
            capturing: b("capturing", true),
            paused: n("paused"),
            flows: n("flows"),
        }
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

/// One entry of the Findings panel (§2.7): a PoC from the library
/// (`poc.list`, not run yet), a `poc.run` result (run, with a verdict), or a
/// finding a Rhai script recorded (`findings.list`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub title: String,
    pub severity: Severity,
    pub target: String,
    /// Whether this entry carries a verdict: true for a `poc.run` result
    /// (`passed` / `evaluated` present) and a script finding; false for a
    /// library entry, which only names a PoC file.
    pub ran: bool,
    pub passed: bool,
    pub when: String,
    pub origin: Origin,
    /// The PoC file; empty for a script finding, which has none.
    pub poc_path: String,
    /// The PoC's `info.description` (from `poc.get`, or the library entry).
    pub description: Option<String>,
    /// The script that recorded this finding (`findings.list` `source`).
    pub script: Option<String>,
    pub finding_capture: Option<String>,
    pub screenshot_path: Option<String>,
    /// `(assertion, matched)`.
    pub assertions: Vec<(String, bool)>,
    /// The PoC YAML, from `poc.get`, the result, or (on a loopback bus
    /// without `poc.get`) read from `poc_path` by the app.
    pub yaml: Option<String>,
    /// Why the YAML could not be read, when the app tried.
    pub yaml_error: Option<String>,
}

impl Finding {
    /// Parse one `findings.list` entry (a Rhai `finding(...)`): `at` is Unix
    /// milliseconds, `source` the script's name. `None` without a `name`.
    pub fn from_script_json(v: &Value) -> Option<Self> {
        let s = |k: &str| v.get(k).and_then(Value::as_str).map(str::to_string);
        let title = s("name")?;
        let when = v
            .get("at")
            .and_then(Value::as_i64)
            .filter(|ms| *ms > 0)
            .map(|ms| {
                let secs = (ms / 1000).rem_euclid(86_400);
                format!(
                    "{:02}:{:02}:{:02}.{:03}",
                    secs / 3600,
                    (secs / 60) % 60,
                    secs % 60,
                    ms.rem_euclid(1000)
                )
            })
            .unwrap_or_default();
        Some(Self {
            title,
            severity: Severity::parse(v.get("severity").and_then(Value::as_str).unwrap_or("info")),
            target: String::new(),
            ran: true,
            passed: true,
            when,
            origin: Origin::Unknown,
            poc_path: String::new(),
            description: s("detail"),
            script: Some(s("source").unwrap_or_else(|| "script".into())),
            finding_capture: s("flow_id"),
            screenshot_path: None,
            assertions: Vec::new(),
            yaml: None,
            yaml_error: None,
        })
    }

    /// Parse one entry of `poc.list` (a library file) or a `poc.run` result.
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
            ran: v.get("passed").is_some() || v.get("evaluated").is_some(),
            passed: v.get("passed").and_then(Value::as_bool).unwrap_or(false),
            when: s("at").or_else(|| s("when")).unwrap_or_default(),
            origin: Origin::parse(v.get("origin")),
            poc_path,
            description: s("description"),
            script: None,
            finding_capture: s("finding_capture"),
            screenshot_path: s("screenshot_path"),
            assertions,
            yaml: s("yaml"),
            yaml_error: None,
        })
    }
}

/// Agent policy, the core's five words: `all | auto | ask | readonly | paused`.
/// `Auto` and `Ask` are parsed and labelled for display only; the TUI sets
/// only `All`, `ReadOnly` and `Paused` (see [`AgentPolicy::settable`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentPolicy {
    All,
    Auto,
    Ask,
    ReadOnly,
    Paused,
}

impl AgentPolicy {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "all" => Some(Self::All),
            "auto" => Some(Self::Auto),
            "ask" => Some(Self::Ask),
            "readonly" | "read_only" | "read-only" => Some(Self::ReadOnly),
            "paused" => Some(Self::Paused),
            _ => None,
        }
    }

    pub fn wire(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Auto => "auto",
            Self::Ask => "ask",
            Self::ReadOnly => "readonly",
            Self::Paused => "paused",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::All => "all tools",
            Self::Auto => "auto",
            Self::Ask => "ask",
            Self::ReadOnly => "read-only",
            Self::Paused => "paused",
        }
    }

    /// Whether the TUI may set this policy over `agent.set`. `auto` and `ask`
    /// are display only here (plan decision 7): the core shows them, the TUI
    /// never sends them.
    pub fn settable(self) -> bool {
        matches!(self, Self::All | Self::ReadOnly | Self::Paused)
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

/// A JSON value as one line of text: a string as itself (no quotes),
/// anything else as compact JSON (`null`, `3.5`, `[1,2]`, `{"a":1}`).
pub fn value_text(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
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

/// `2026-10-27T11:05:22.994Z` → `11:05:22.994`; anything without a `T` passes
/// through. The zone suffix is dropped and the fraction kept to milliseconds:
/// the core emits RFC 3339 with nanoseconds and the Time column has 12 cells.
pub fn clock_of(ts: &str) -> String {
    let Some((_, t)) = ts.split_once('T') else {
        return ts.to_string();
    };
    let t = t.trim_end_matches('Z');
    let t = t.split(['+', '-']).next().unwrap_or(t);
    match t.split_once('.') {
        Some((hms, frac)) => format!("{hms}.{}", &frac[..frac.len().min(3)]),
        None => t.to_string(),
    }
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
        assert_eq!(clock_of("2026-10-28T16:54:34.859123456Z"), "16:54:34.859");
        assert_eq!(clock_of("2026-10-28T16:54:34+02:00"), "16:54:34");
        assert_eq!(clock_of("16:54"), "16:54");
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

    /// C1: the core's WebSocket `flow.detail` — `messages`, not `frames`;
    /// `dir` as `client_to_server` / `server_to_client`; `timestamp`; `data`
    /// base64 or null.
    #[test]
    fn detail_parses_websocket_messages_in_the_core_shape() {
        let v = json!({"id":"w1","kind":"websocket","handshake":"f40",
            "messages":[
                {"dir":"client_to_server","opcode":"text","length":5,"injected":false,
                 "timestamp":"2026-10-27T11:05:05.001Z","data":"aGVsbG8="},
                {"dir":"server_to_client","opcode":"binary","length":2,"injected":true,
                 "timestamp":"2026-10-27T11:05:05.040Z","data":null},
                {"dir":"sideways"}
            ],
            "client_conn":{"peer":"127.0.0.1:1","sni":null,"alpn":null,"tls":true,
                           "established":"2026-10-27T11:05:04.900Z","process":null},
            "server_conn":null,
            "meta":{"marks":[],"comment":null,"is_replay":false,"created":"2026-10-27T11:05:04.966Z",
                    "duration_ms":null,"truncated":false,"edited":false,"origin":null},
            "intercept":"observed","edited":false});
        let d = FlowDetail::from_json(&v).unwrap();
        assert_eq!(d.kind, FlowKind::WebSocket);
        assert!(d.request.is_none() && d.response.is_none());
        assert_eq!(d.messages.len(), 3);
        assert_eq!(d.messages[0].dir, Some(WsDir::ClientToServer));
        assert_eq!(d.messages[0].data, b"hello");
        assert_eq!(d.messages[0].length, Some(5));
        assert_eq!(
            d.messages[0].timestamp.as_deref(),
            Some("2026-10-27T11:05:05.001Z")
        );
        assert_eq!(d.messages[1].dir, Some(WsDir::ServerToClient));
        assert_eq!(d.messages[1].opcode, "binary");
        assert!(d.messages[1].injected);
        assert!(d.messages[1].data.is_empty(), "data: null is no bytes");
        assert_eq!(
            d.messages[2].dir, None,
            "an unknown direction is not guessed"
        );
        assert_eq!(WsDir::ClientToServer.arrow(), "→");
        assert_eq!(WsDir::ServerToClient.arrow(), "←");
        assert_eq!(
            d.client_conn.as_ref().unwrap().established.as_deref(),
            Some("2026-10-27T11:05:04.900Z")
        );
        // The row's message count comes from the detail when the summary lacked it.
        let mut row =
            FlowRow::from_summary(&json!({"id":"w1","kind":"websocket","handshake":"f40"}), 1)
                .unwrap();
        assert_eq!(row.ws_messages, None);
        row.apply_detail(&d);
        assert_eq!(row.ws_messages, Some(3));
        assert_eq!(row.client, None, "process is null: no client");
    }

    /// C2: `body: null` with `body_size` (body mode `none`, or a body still
    /// streaming) feeds the size columns; `client_conn.process: null` is a
    /// dash in the Client column, never the peer address.
    #[test]
    fn detail_uses_body_size_when_the_body_is_null_and_no_client_without_a_process() {
        let v = json!({"id":"f1","kind":"http",
            "request":{"method":"GET","scheme":"https","authority":"h.test","path":"/","version":"HTTP/1.1",
                       "headers":[],"body":null,"body_size":1234,"body_truncated":false},
            "response":{"status":200,"version":"HTTP/1.1","headers":[["content-type","text/plain"]],
                        "body":null,"body_size":0,"body_truncated":false},
            "client_conn":{"peer":"127.0.0.1:50000","sni":null,"alpn":null,"tls":false,
                           "established":"2026-10-27T11:05:04.900Z","process":null},
            "server_conn":{"peer":"203.0.113.1:443","sni":"h.test","alpn":"http/1.1","tls":true,
                           "established":"2026-10-27T11:05:04.950Z"},
            "meta":{"marks":[],"comment":null,"is_replay":false,"created":"2026-10-27T11:05:04.966Z",
                    "duration_ms":12,"truncated":false,"edited":false,"origin":null},
            "intercept":"observed","edited":false});
        let d = FlowDetail::from_json(&v).unwrap();
        let req = d.request.as_ref().unwrap();
        assert_eq!(req.body_size, Some(1234));
        assert!(req.body.is_empty());
        let mut row = FlowRow::from_summary(&json!({"id":"f1","kind":"http"}), 1).unwrap();
        row.apply_detail(&d);
        assert_eq!(row.req_size, Some(1234));
        assert_eq!(row.resp_size, Some(0));
        assert_eq!(row.client, None);
        assert_eq!(
            d.client_conn.as_ref().unwrap().peer.as_deref(),
            Some("127.0.0.1:50000")
        );
        assert_eq!(row.origin, Origin::Unknown);
        assert_eq!(row.duration_ms, Some(12));
        // An inline body without `body_size` still sizes from the bytes.
        let d = FlowDetail::from_json(&json!({"id":"f2","request":{"body":"aGVsbG8="}})).unwrap();
        let mut row = FlowRow::from_summary(&json!({"id":"f2"}), 2).unwrap();
        row.apply_detail(&d);
        assert_eq!(row.req_size, Some(5));
    }

    /// C8: a `poc.list` entry is a PoC file, not a run — `ran` is false until
    /// a `poc.run` result (which carries `passed` / `evaluated`) says otherwise.
    #[test]
    fn finding_from_a_library_entry_is_not_run_and_a_run_result_is() {
        let lib = Finding::from_json(
            &json!({"id":"open-redirect","title":"Open redirect","severity":"low",
            "poc_path":"/pocs/open-redirect.yaml","description":"Follows next="}),
        )
        .unwrap();
        assert!(!lib.ran);
        assert_eq!(lib.description.as_deref(), Some("Follows next="));
        assert_eq!(lib.title, "Open redirect");
        assert_eq!(lib.severity, Severity::Low);
        assert!(lib.assertions.is_empty());
        let run = Finding::from_json(&json!({"poc_path":"/pocs/x.yaml","passed":false})).unwrap();
        assert!(run.ran);
        assert!(!run.passed);
        assert_eq!(run.description, None);
        assert!(
            Finding::from_json(&json!({"poc_path":"/pocs/y.yaml","evaluated":[]}))
                .unwrap()
                .ran
        );
    }

    /// C3: `proxy.status` as the control plugin shapes it.
    #[test]
    fn proxy_status_parses_the_control_plugin_shape() {
        let s = ProxyStatus::from_json(&json!({"listening":true,"address":"127.0.0.1:8080",
            "intercept_armed":false,"capturing":true,"paused":2,"flows":15}));
        assert_eq!(
            s,
            ProxyStatus {
                listening: true,
                address: Some("127.0.0.1:8080".into()),
                intercept_armed: false,
                capturing: true,
                paused: 2,
                flows: 15
            }
        );
        let off = ProxyStatus::from_json(&json!({"listening":false,"address":null}));
        assert!(!off.listening);
        assert_eq!(off.address, None);
        assert!(off.capturing, "an absent capture state is not 'paused'");
        assert_eq!(off.paused, 0);
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
