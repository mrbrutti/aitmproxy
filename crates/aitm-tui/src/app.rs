//! The operator UI's state and its reducer. `App` is plain data; `update`
//! takes an [`Action`] and returns the [`BusRequest`]s it implies; `on_bus`
//! folds a [`BusEvent`] in. No terminal, no socket, no clock: the loop in
//! `lib.rs` owns those, which is what lets every screen be tested from
//! `BusEvent`s written inline in the core's wire shapes.

use std::collections::{HashMap, HashSet, VecDeque};
use std::ffi::OsStr;
use std::fs::File;
use std::io::{Read as _, Write as _};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

use crate::action::ToolSchema as _;
use crate::action::{Action, BusEvent, BusRequest, Level, ToolInfo};
use crate::caps::TermCaps;
use crate::filter::{self, Expr};
use crate::model::{
    counts_by, human_bytes, scope_covers, value_text, AgentPolicy, AgentState, CaTrustWord,
    Finding, FlowDetail, FlowKind, FlowRow, Message, Severity, SystemProxyWord,
};
use crate::open::{self, OpenTarget};
use crate::theme::Theme;
use crate::viewers::json;

/// Terminal widths below which the shell changes shape (§2.10(c)).
pub const NARROW_COLS: u16 = 120;
/// Two lists side by side need this many columns (§2.9); the split view
/// itself is not built in this pass, so `:split` only says so.
pub const SPLIT_COLS: u16 = 160;

/// How many flow details the app keeps; past this the oldest non-selected
/// ones are dropped (they are fetched again on demand).
pub const MAX_DETAILS: usize = 2_000;

/// The tools that change the CA's trust-store state (§D17): they get the
/// scope default, raise the pill's in-flight word, and are re-read after.
pub(crate) const CA_TRUST_TOOLS: &[&str] = &["ca.install", "ca.uninstall"];

/// Tools that ask the operator for a local `y/N` before they are sent
/// (§4.2 step 4: the bus has no `confirm` on the wire until F1, and the
/// TUI's server identity is `Frontend::Mcp`). A `dry_run` the tool's schema
/// declares, given as the JSON boolean `true`, bypasses. Today these are
/// exactly the CA-trust tools.
pub const CONFIRM_TOOLS: &[&str] = CA_TRUST_TOOLS;

/// The most PoC YAML the Findings panel reads from disk for one finding
/// (`poc_path` on a loopback bus without `poc.get`).
pub const MAX_POC_YAML_BYTES: u64 = 256 * 1024;

/// How many `-2`, `-3`, … suffixes a written PoC tries before giving up,
/// so a name collision never overwrites and never loops forever.
const MAX_POC_NAME_TRIES: u32 = 1000;

/// Which screen owns the keyboard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Flows,
    /// The inspector has focus (full-screen on narrow terminals).
    Inspector,
    /// Editing a paused request in the inspector.
    Edit,
    /// A one-line prompt is open.
    Prompt(PromptKind),
    Compose,
    Scope,
    Findings,
    Agent,
    /// The CA panel (`:ca`): `ca.status` facts, export / install / uninstall.
    Ca,
    /// The browser view (§2.7): URL, DOM outline, last-screenshot placeholder;
    /// navigate / eval / screenshot through `browser.*`.
    Browser,
    /// The config panel (`:config`, F7): the redacted `config.get` object,
    /// read-only.
    Config,
    /// The Scan view (scanner-integration Stage 1): a scope-bound
    /// `scan.discover` launch header, the discovered endpoints and the
    /// discovered injection points. Inert until the bus offers `scan.discover`.
    Scan,
    Help,
    QuickLook,
    /// The L4 inject confirm-over-the-wire overlay (ui-ext §3.4, L4OPS-AC10):
    /// shows the server's wire summary; `y` re-issues with `_confirm`.
    L4Confirm,
    /// The L4 panel (`:l4`, `L`): capture / intercept availability from the
    /// status verbs, the running captures and the capture commands (L4 parity
    /// spec §1, AC15). Renders live state only.
    L4,
}

/// What the one-line prompt is collecting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PromptKind {
    /// `:` — the command palette.
    Palette,
    /// `/` — the filter expression.
    Filter,
    Comment,
    Mark,
    Pin,
    ScopeAdd,
    /// `poc.build`: the finding's title (blank = none), then…
    PocName,
    /// …the parameter to parameterize (blank = none).
    PocParam,
    /// `poc.run`: the base URL for `target` (blank = the PoC's own), then…
    PocTarget,
    /// …`k=v …` variable bindings (blank = none).
    PocVars,
    /// `ca.export`: `[pem|der] [path]`.
    CaExport,
    /// `y/N` for a tool in [`CONFIRM_TOOLS`]; the call waits in `App::confirm`.
    Confirm,
    /// Browser view `g`: the URL for `browser.navigate`, prefilled.
    BrowserUrl,
    /// Browser view `e`: a JavaScript expression for `browser.eval`.
    BrowserEval,
}

/// The last `browser.screenshot`: its header facts and the bytes `o` hands
/// to the desktop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Screenshot {
    /// Pixel width from the image header; 0 when the format has none we read.
    pub width: u32,
    /// Pixel height; 0 as above.
    pub height: u32,
    /// `PNG`, `JPEG`, …, or `image` when the bytes match no known magic.
    pub format: &'static str,
    /// The image itself.
    pub bytes: Vec<u8>,
}

/// The browser view's state (§2.7 "Browser view", TUI column of §2.9): what
/// the `browser.*` commands have reported so far. Plain data; `App::on_bus`
/// fills it and `ui::browser` draws it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BrowserState {
    /// The URL `browser.navigate` last confirmed (`final_url`); empty until
    /// the operator navigates, since the bus has no "where are you" call.
    pub url: String,
    /// The URL a navigate in flight asked for, used when the reply has no
    /// `final_url`.
    pub pending_url: Option<String>,
    /// The last `browser.get_dom` text.
    pub dom: Option<String>,
    /// [`crate::ui::browser::outline`] of `dom`.
    pub dom_outline: Vec<String>,
    /// The outline line ↑↓ is on.
    pub dom_cursor: usize,
    /// The last screenshot, for the placeholder line and `o`.
    pub screenshot: Option<Screenshot>,
    /// The last `browser.eval` result as text.
    pub last_eval: Option<String>,
    /// What the panel says is in flight; cleared when `inflight` reaches 0.
    pub busy: Option<&'static str>,
    /// `browser.*` calls awaiting an answer.
    pub inflight: usize,
    /// The last `browser.*` failure, shown in the panel until the next call.
    pub error: Option<String>,
}

/// One discovered injection point, mirroring an entry of `scan.discover`'s
/// `injection_points` array (`{flow, location, name, example}`). The `example`
/// is whatever the scanner handed us (redacted at the source for cookies and
/// secret-named parameters); the UI renders it verbatim and never re-derives a
/// raw value.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct InjectionPointRow {
    /// The flow this point was discovered in.
    pub flow: String,
    /// Where it lives (`query`, `body_param`, `header`, `cookie`,
    /// `path_segment`, `redirect`).
    pub location: String,
    /// The parameter / header / segment name.
    pub name: String,
    /// The observed (already-redacted) example value.
    pub example: String,
}

impl InjectionPointRow {
    /// Read one `injection_points` entry; missing fields read as empty.
    fn from_json(v: &Value) -> Self {
        let s = |k: &str| v.get(k).and_then(Value::as_str).unwrap_or("").to_string();
        Self {
            flow: s("flow"),
            location: s("location"),
            name: s("name"),
            example: s("example"),
        }
    }
}

/// Which of the Scan view's two lists holds the cursor. Tab toggles it; ↑↓ walk
/// the focused list and ⏎ opens its selected row's flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ScanFocus {
    /// The reached-endpoints list (⏎ opens the endpoint's linked flow, AC3).
    Endpoints,
    /// The injection-points list (⏎ opens the point's flow). The default, so
    /// the point list stays the first thing the operator walks.
    #[default]
    Points,
}

/// The Scan view's state (scanner-integration Stage 1): what `scan.discover`
/// has reported so far. Plain data; `App::on_bus` fills it and `ui::scan` draws
/// it. The model mirrors the scanner's `endpoints` + `injection_points` JSON.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ScanState {
    /// A `scan.discover` crawl is in flight; disables re-launch until it
    /// settles (the Browser `busy` precedent).
    pub running: bool,
    /// The scope-bound target URL the last launch sent.
    pub target: Option<String>,
    /// The reached endpoints from the last result (each a flow in the store).
    pub endpoints: Vec<String>,
    /// AC3 endpoint→flow links from the last result: the scrubbed endpoint URL
    /// (as it appears in `endpoints`) → the flow id it was reached as. Not every
    /// endpoint has an entry; ⏎ on an unlinked endpoint opens nothing.
    pub endpoint_flows: HashMap<String, String>,
    /// The discovered injection points from the last result.
    pub points: Vec<InjectionPointRow>,
    /// The injection-point list cursor.
    pub cursor: usize,
    /// The endpoints-list cursor.
    pub endpoint_cursor: usize,
    /// Which list the cursor is on; Tab toggles it.
    pub focus: ScanFocus,
    /// The last `scan.discover` failure, shown until the next launch.
    pub error: Option<String>,
}

/// Whether the browser view counts a call as in flight: exactly the calls
/// [`browser_busy_label`] has a word for. The same predicate gates the
/// increment in `call_tool` and the decrements on `CallOk`/`CallFailed`, so
/// an answer for an untracked `browser.*` tool never settles a tracked one.
fn is_tracked_browser_call(name: &str) -> bool {
    browser_busy_label(name).is_some()
}

/// The panel's word for a `browser.*` call in flight.
fn browser_busy_label(name: &str) -> Option<&'static str> {
    Some(match name {
        "browser.navigate" => "navigating",
        "browser.eval" => "evaluating",
        "browser.get_dom" => "reading the DOM",
        "browser.screenshot" => "capturing a screenshot",
        "browser.click" => "clicking",
        "browser.type" => "typing",
        _ => return None,
    })
}

/// The seed URL `scan.discover` is given for an in-scope host.
fn scan_target_url(host: &str) -> String {
    format!("http://{host}/")
}

/// Reduce a scan target (`host`, `host:port`, `http://host/path?q`) to the bare
/// host the scope guard checks.
fn scan_host(raw: &str) -> String {
    let s = raw.trim();
    let s = s.split_once("://").map_or(s, |(_, rest)| rest);
    let s = s.split(['/', '?', '#']).next().unwrap_or(s);
    s.rsplit_once(':').map_or(s, |(h, _)| h).to_string()
}

/// A tool call held back for the operator's `y/N`.
#[derive(Debug, Clone, PartialEq)]
pub struct ConfirmCall {
    pub name: String,
    pub description: String,
    pub args: Value,
    /// Where to go after the answer.
    pub return_to: Mode,
}

/// Inspector placement; the TUI has horizontal and vertical only (§2.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    /// Inspector below the list (default).
    Horizontal,
    /// Inspector right of the list.
    Vertical,
}

/// The content-type chip bar (§2.7). `Tcp` / `Udp` / `L4` are the L4 group
/// after `WebSocket` (L4 parity AC14; the order web and macOS ship).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Chip {
    All,
    Http,
    Https,
    WebSocket,
    Tcp,
    Udp,
    L4,
    H1,
    H2,
    Json,
    Form,
    Xml,
    Js,
    Css,
    GraphQl,
    Document,
    Media,
    Other,
}

impl Chip {
    pub const ALL: [Chip; 18] = [
        Chip::All,
        Chip::Http,
        Chip::Https,
        Chip::WebSocket,
        Chip::Tcp,
        Chip::Udp,
        Chip::L4,
        Chip::H1,
        Chip::H2,
        Chip::Json,
        Chip::Form,
        Chip::Xml,
        Chip::Js,
        Chip::Css,
        Chip::GraphQl,
        Chip::Document,
        Chip::Media,
        Chip::Other,
    ];

    /// The content-type chips; `Other` is "typed, but none of these".
    pub const CONTENT: [Chip; 8] = [
        Chip::Json,
        Chip::Form,
        Chip::Xml,
        Chip::Js,
        Chip::Css,
        Chip::GraphQl,
        Chip::Document,
        Chip::Media,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Chip::All => "All",
            Chip::Http => "HTTP",
            Chip::Https => "HTTPS",
            Chip::WebSocket => "WebSocket",
            Chip::Tcp => "TCP",
            Chip::Udp => "UDP",
            Chip::L4 => "L4",
            Chip::H1 => "h1",
            Chip::H2 => "h2",
            Chip::Json => "JSON",
            Chip::Form => "Form",
            Chip::Xml => "XML",
            Chip::Js => "JS",
            Chip::Css => "CSS",
            Chip::GraphQl => "GraphQL",
            Chip::Document => "Document",
            Chip::Media => "Media",
            Chip::Other => "Other",
        }
    }

    /// Chips are a quick filter layered under the expression (§2.7).
    pub fn matches(self, row: &FlowRow, detail: Option<&FlowDetail>) -> bool {
        let ct = row.content_type.as_deref().unwrap_or("");
        let is_graphql = || {
            row.path_only().contains("graphql")
                || detail
                    .and_then(|d| d.request.as_ref())
                    .and_then(Message::content_type)
                    .is_some_and(|t| t.contains("graphql"))
        };
        match self {
            Chip::All => true,
            Chip::Http => row.kind == FlowKind::Http && row.scheme == "http",
            Chip::Https => row.kind == FlowKind::Http && row.scheme == "https",
            Chip::WebSocket => row.kind == FlowKind::WebSocket,
            Chip::L4 => row.kind == FlowKind::L4,
            Chip::Tcp => l4_proto(row) == Some("TCP"),
            Chip::Udp => l4_proto(row) == Some("UDP"),
            Chip::H1 => row
                .version
                .as_deref()
                .is_some_and(|v| v.starts_with("HTTP/1")),
            Chip::H2 => row
                .version
                .as_deref()
                .is_some_and(|v| v == "HTTP/2" || v == "h2"),
            Chip::Json => ct.contains("json") && !is_graphql(),
            Chip::Form => ct.contains("form"),
            Chip::Xml => ct.contains("xml"),
            Chip::Js => ct.contains("javascript") || ct.contains("ecmascript"),
            Chip::Css => ct.contains("css"),
            Chip::GraphQl => is_graphql(),
            Chip::Document => ct.starts_with("text/html") || ct.contains("pdf"),
            Chip::Media => {
                ct.starts_with("image/")
                    || ct.starts_with("video/")
                    || ct.starts_with("audio/")
                    || ct.contains("font")
            }
            Chip::Other => !ct.is_empty() && !Chip::CONTENT.iter().any(|c| c.matches(row, detail)),
        }
    }
}

/// The transport sub-label of an L4 row (`TCP` / `UDP` / `ICMP`); `None` for
/// an HTTP or WebSocket row.
fn l4_proto(row: &FlowRow) -> Option<&str> {
    row.l4.as_ref().and_then(|l| l.proto.as_deref())
}

/// Sidebar entries (§2.6 "Sidebar groups").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SidebarItem {
    Pinned,
    Saved,
    All,
    Apps,
    Domains,
    Scope,
    Findings,
    Browser,
    Scripts,
    Agent,
    Scan,
    /// The L4 panel; drawn only when the bus offers `l4.capture.status`.
    L4,
}

impl SidebarItem {
    pub const ALL: [SidebarItem; 12] = [
        SidebarItem::Pinned,
        SidebarItem::Saved,
        SidebarItem::All,
        SidebarItem::Apps,
        SidebarItem::Domains,
        SidebarItem::Scope,
        SidebarItem::Findings,
        SidebarItem::Browser,
        SidebarItem::Scripts,
        SidebarItem::Agent,
        SidebarItem::Scan,
        SidebarItem::L4,
    ];

    pub fn label(self) -> &'static str {
        match self {
            SidebarItem::Pinned => "Pinned",
            SidebarItem::Saved => "Saved",
            SidebarItem::All => "All flows",
            SidebarItem::Apps => "Apps",
            SidebarItem::Domains => "Domains",
            SidebarItem::Scope => "Scope",
            SidebarItem::Findings => "Findings",
            SidebarItem::Browser => "Browser",
            SidebarItem::Scripts => "Scripts",
            SidebarItem::Agent => "Agent",
            SidebarItem::Scan => "Scan",
            SidebarItem::L4 => "L4",
        }
    }
}

/// Grouping of the flow list, driven by the Apps/Domains sidebar items.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupBy {
    Host,
    Client,
}

/// Which inspector pane has focus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pane {
    Request,
    Response,
}

/// Inspector tabs, in the foundation's order (§2.7). `Cookies` and
/// `Set-Cookie` parse the served `Cookie:` / `Set-Cookie:` headers and render
/// live. Only `Timing` waits on core follow-up F5 and renders disabled with
/// that label (see [`tab_follow_up`]); it is listed so the absence is never
/// silent.
pub const REQUEST_TABS: [&str; 8] = [
    "Headers",
    "Cookies",
    "Query",
    "Body",
    "Raw",
    "Summary",
    "Timing",
    "Connection",
];
pub const RESPONSE_TABS: [&str; 7] = [
    "Headers",
    "Set-Cookie",
    "Body",
    "Raw",
    "JSON",
    "Hex",
    "Diff",
];

/// The core follow-up a tab waits on, if any.
pub fn tab_follow_up(tab: &str) -> Option<&'static str> {
    match tab {
        "Timing" => Some("F5"),
        _ => None,
    }
}

/// Index of `name` in `tabs` (0 when absent, which cannot happen for the
/// constants above).
fn tab_index(tabs: &[&str], name: &str) -> usize {
    tabs.iter().position(|t| *t == name).unwrap_or(0)
}

/// Inspector view state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InspectorState {
    pub pane: Pane,
    pub request_tab: usize,
    pub response_tab: usize,
    pub scroll: u16,
    /// The highlighted line in the focused pane (0-based). Up/Down move it;
    /// the renderer scrolls so it stays visible.
    pub cursor_line: usize,
    /// JSON-tree paths that are folded.
    pub folds: HashSet<String>,
    /// The other flow for the Diff tab.
    pub diff_with: Option<String>,
}

impl Default for InspectorState {
    fn default() -> Self {
        Self {
            pane: Pane::Request,
            request_tab: 0,
            response_tab: tab_index(&RESPONSE_TABS, "Body"),
            scroll: 0,
            cursor_line: 0,
            folds: HashSet::new(),
            diff_with: None,
        }
    }
}

impl InspectorState {
    /// Back to the top of the pane: a new flow, pane or tab.
    fn reset_view(&mut self) {
        self.scroll = 0;
        self.cursor_line = 0;
    }
}

/// A paused request being edited as raw text: request line, headers, blank
/// line, body. `to_edits` turns it back into `flow.mutate` edits.
///
/// The body is sent back only when its lines changed, and then with the line
/// ending and trailing newline the original had, so an untouched body — and
/// any body that is not UTF-8, which the editor only describes — reaches the
/// upstream byte for byte as it was captured.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EditBuffer {
    pub id: String,
    pub lines: Vec<String>,
    pub cursor_line: usize,
    pub cursor_col: usize,
    pub original: Vec<String>,
    /// Whether the captured body was UTF-8 text (editable); a binary body is
    /// shown as a placeholder and never sent back.
    pub body_is_text: bool,
    /// `"\r\n"` when the captured text body used CRLF, else `"\n"`.
    pub line_ending: &'static str,
    /// Whether the captured text body ended with a newline.
    pub trailing_newline: bool,
}

/// The body line shown for a body the editor cannot represent as text.
fn binary_placeholder(len: usize) -> String {
    format!("<{len} binary bytes — edit in hex is a follow-up>")
}

impl EditBuffer {
    /// Start from the request as captured.
    pub fn from_request(id: &str, req: &Message) -> Self {
        let mut lines = vec![format!(
            "{} {} {}",
            req.method.as_deref().unwrap_or("GET"),
            req.path.as_deref().unwrap_or("/"),
            req.version.as_deref().unwrap_or("HTTP/1.1")
        )];
        for (n, v) in &req.headers {
            lines.push(format!("{n}: {v}"));
        }
        lines.push(String::new());
        let (body_is_text, line_ending, trailing_newline) = match req.body_text() {
            Some(text) => {
                lines.extend(text.lines().map(str::to_string));
                let crlf = text.contains("\r\n");
                (true, if crlf { "\r\n" } else { "\n" }, text.ends_with('\n'))
            }
            None => {
                lines.push(binary_placeholder(req.body.len()));
                (false, "\n", false)
            }
        };
        Self {
            id: id.to_string(),
            original: lines.clone(),
            lines,
            cursor_line: 0,
            cursor_col: 0,
            body_is_text,
            line_ending,
            trailing_newline,
        }
    }

    pub fn dirty(&self) -> bool {
        self.lines != self.original
    }

    /// The lines after the first blank line: the body as the editor shows it.
    fn body_lines(lines: &[String]) -> &[String] {
        lines
            .iter()
            .skip(1)
            .position(String::is_empty)
            .map_or(&lines[lines.len()..], |i| &lines[i + 2..])
    }

    /// The `flow.mutate` `edits` object: method, path, every header (the core
    /// replaces by name) and — only when its lines changed and the body is
    /// text — the body, rebuilt with the original line ending and trailing
    /// newline. An untouched or binary body is left to the core as captured.
    pub fn to_edits(&self) -> Value {
        let mut edits = Map::new();
        let mut it = self.lines.iter();
        if let Some(first) = it.next() {
            let mut parts = first.split_whitespace();
            if let Some(m) = parts.next() {
                edits.insert("method".into(), Value::String(m.to_string()));
            }
            if let Some(p) = parts.next() {
                edits.insert("path".into(), Value::String(p.to_string()));
            }
        }
        let mut headers = Map::new();
        for line in it.take_while(|l| !l.is_empty()) {
            if let Some((n, v)) = line.split_once(':') {
                headers.insert(n.trim().to_string(), Value::String(v.trim().to_string()));
            }
        }
        edits.insert("headers".into(), Value::Object(headers));

        let body = Self::body_lines(&self.lines);
        if self.body_is_text && body != Self::body_lines(&self.original) {
            let mut text = body.join(self.line_ending);
            if self.trailing_newline {
                text.push_str(self.line_ending);
            }
            edits.insert("body".into(), Value::String(text));
        }
        Value::Object(edits)
    }
}

/// The compose form (§2.7 "Compose / repeat").
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ComposeForm {
    pub method: String,
    pub url: String,
    pub headers: String,
    pub body: String,
    /// 0 method · 1 url · 2 headers · 3 body.
    pub field: usize,
}

impl ComposeForm {
    pub fn template_get() -> Self {
        Self {
            method: "GET".into(),
            url: "https://".into(),
            headers: String::new(),
            body: String::new(),
            field: 1,
        }
    }

    /// `:compose post-json` (§2.7 "Templates: … POST JSON").
    pub fn template_post_json() -> Self {
        Self {
            method: "POST".into(),
            headers: "Content-Type: application/json".into(),
            body: "{}".into(),
            ..Self::template_get()
        }
    }

    /// `:compose post-form` (§2.7 "Templates: … POST Form").
    pub fn template_post_form() -> Self {
        Self {
            method: "POST".into(),
            headers: "Content-Type: application/x-www-form-urlencoded".into(),
            body: String::new(),
            ..Self::template_get()
        }
    }

    /// The template a `:compose <name>` argument names; `None` for an
    /// unknown one. `ws` is not here: WebSocket inject is core follow-up F9.
    pub fn template(name: &str) -> Option<Self> {
        Some(match name {
            "get" | "empty" => Self::template_get(),
            "post-json" | "json" => Self::template_post_json(),
            "post-form" | "form" => Self::template_post_form(),
            _ => return None,
        })
    }

    /// Prefill from a captured flow (Edit & repeat).
    pub fn from_flow(row: &FlowRow, detail: Option<&FlowDetail>) -> Self {
        let req = detail.and_then(|d| d.request.as_ref());
        Self {
            method: row.method.clone(),
            url: row.url(),
            headers: req
                .map(|r| {
                    r.headers
                        .iter()
                        .map(|(n, v)| format!("{n}: {v}"))
                        .collect::<Vec<_>>()
                        .join("\n")
                })
                .unwrap_or_default(),
            body: req
                .and_then(|r| r.body_text().map(str::to_string))
                .unwrap_or_default(),
            field: 1,
        }
    }

    /// Fill the form from a `curl …` command line (Import cURL).
    pub fn from_curl(cmd: &str) -> Option<Self> {
        let toks = shell_words(cmd);
        if toks.first().map(String::as_str) != Some("curl") {
            return None;
        }
        let mut f = Self {
            method: "GET".into(),
            field: 1,
            ..Self::default()
        };
        let mut headers = Vec::new();
        let mut i = 1;
        while i < toks.len() {
            match toks[i].as_str() {
                "-X" | "--request" => {
                    f.method = toks.get(i + 1)?.to_uppercase();
                    i += 1;
                }
                "-H" | "--header" => {
                    headers.push(toks.get(i + 1)?.clone());
                    i += 1;
                }
                "-d" | "--data" | "--data-raw" | "--data-binary" => {
                    f.body = toks.get(i + 1)?.clone();
                    if f.method == "GET" {
                        f.method = "POST".into();
                    }
                    i += 1;
                }
                "-u" | "--user" | "-o" | "--output" | "-A" | "--user-agent" => {
                    i += 1;
                }
                t if t.starts_with('-') => {}
                url => f.url = url.to_string(),
            }
            i += 1;
        }
        f.headers = headers.join("\n");
        (!f.url.is_empty()).then_some(f)
    }

    /// `request.send` arguments: authority, scheme, path, method, headers, body.
    pub fn to_send_args(&self) -> Result<Value, String> {
        let (scheme, rest) = self
            .url
            .split_once("://")
            .ok_or_else(|| "URL needs a scheme (http:// or https://)".to_string())?;
        let (authority, path) = match rest.split_once('/') {
            Some((a, p)) => (a, format!("/{p}")),
            None => (rest, "/".to_string()),
        };
        if authority.is_empty() {
            return Err("URL needs a host".into());
        }
        let mut headers = Map::new();
        for line in self.headers.lines().filter(|l| !l.trim().is_empty()) {
            let (n, v) = line
                .split_once(':')
                .ok_or_else(|| format!("header `{line}` needs `name: value`"))?;
            headers.insert(n.trim().to_string(), Value::String(v.trim().to_string()));
        }
        let mut args = json!({
            "method": self.method.trim().to_uppercase(),
            "scheme": scheme,
            "authority": authority,
            "path": path,
            "headers": headers,
        });
        if !self.body.is_empty() {
            args["body"] = Value::String(self.body.clone());
        }
        Ok(args)
    }

    pub fn authority(&self) -> Option<String> {
        let rest = self.url.split_once("://")?.1;
        let a = rest.split('/').next()?;
        (!a.is_empty()).then(|| a.to_string())
    }
}

/// Split a command line on whitespace honouring single/double quotes and `\`.
fn shell_words(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<char> = None;
    let mut chars = s.chars().peekable();
    let mut had = false;
    while let Some(c) = chars.next() {
        match (quote, c) {
            (Some(q), ch) if ch == q => quote = None,
            (Some(_), ch) => cur.push(ch),
            (None, '\'') | (None, '"') => {
                quote = Some(c);
                had = true;
            }
            (None, '\\') => {
                if let Some(n) = chars.next() {
                    if n != '\n' {
                        cur.push(n);
                    }
                }
            }
            (None, ch) if ch.is_whitespace() => {
                if !cur.is_empty() || had {
                    out.push(std::mem::take(&mut cur));
                    had = false;
                }
            }
            (None, ch) => cur.push(ch),
        }
    }
    if !cur.is_empty() || had {
        out.push(cur);
    }
    out
}

/// A status-line message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Toast {
    pub level: Level,
    pub text: String,
    pub expires_at_tick: u64,
}

/// Connection state shown in the status bar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BusStatus {
    Connecting,
    Connected {
        server: String,
        address: String,
        /// The server-resolved role echoed in `initialize` (`"operator"`/
        /// `"agent"`), or `None` when the server did not echo one.
        role: Option<String>,
    },
    Disconnected(String),
}

/// One palette entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaletteItem {
    pub label: String,
    pub detail: String,
    pub kind: PaletteKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PaletteKind {
    /// A `:` command line to run.
    Command(String),
    Tool(String),
    Flow(String),
}

/// A completion candidate for a `:` line is a command palette item: the
/// candidate's label is the command line to run.
impl From<crate::ui::complete::Candidate> for PaletteItem {
    fn from(c: crate::ui::complete::Candidate) -> Self {
        PaletteItem {
            label: format!(":{}", c.label),
            detail: c.detail,
            kind: PaletteKind::Command(c.label),
        }
    }
}

/// The whole UI state.
#[derive(Debug, Clone)]
pub struct App {
    pub flows: Vec<FlowRow>,
    /// `flows[index[id]].id == id`; rebuilt whenever `flows` changes shape
    /// (`on_bus(Flows)`), so row lookups are O(1).
    pub index: HashMap<String, usize>,
    pub details: HashMap<String, FlowDetail>,
    /// Flows whose `flow.detail` reply was malformed: not asked for again.
    pub detail_failed: HashSet<String>,
    pub selected: Option<String>,
    pub next_seq: usize,
    pub mode: Mode,
    pub layout: Layout,
    pub sidebar_open: bool,
    pub sidebar: SidebarItem,
    pub chip: Chip,
    pub filter: Option<Expr>,
    pub filter_text: String,
    pub prompt: String,
    /// The mode the open prompt was opened from — where Esc or Enter
    /// returns. Set by `open_prompt` only when a prompt is not already open,
    /// so a chained prompt (PoC name → param) keeps the first one's origin.
    pub prompt_from: Mode,
    pub palette_cursor: usize,
    pub pinned_hosts: Vec<String>,
    pub auto_select: bool,
    pub intercept_armed: bool,
    pub capture_paused: bool,
    /// `proxy.status.system_proxy` from the last poll (spec §D14); `None`
    /// until the first reply, or when the core does not report it.
    pub system_proxy: Option<SystemProxyWord>,
    /// This TUI's own `proxy.system.set`/`unset` is in flight: the pill reads
    /// `· sys-proxy setting…` until the reply or the error.
    pub sysproxy_setting: bool,
    pub scope: Vec<String>,
    pub findings: Vec<Finding>,
    pub finding_cursor: usize,
    pub scope_cursor: usize,
    pub agent: AgentState,
    pub bus: BusStatus,
    pub bus_address: String,
    /// The role the operator expects the token to resolve to (`--expect-role`),
    /// client-side only: never sent to the server, it only drives the status
    /// line's mismatch warning. `None` means no expectation was set.
    pub expect_role: Option<String>,
    pub tools: Vec<ToolInfo>,
    pub caps: TermCaps,
    /// The proxy's listen address: from `proxy.status` (F7) or the embed.
    pub listening: Option<String>,
    /// `proxy.status.listening`: whether the proxy is actually serving;
    /// `None` until a status arrives.
    pub serving: Option<bool>,
    /// `proxy.status.paused`: the store's own parked-flow count, which the
    /// status bar prefers to its filtered view when the list is filtered.
    pub store_paused: Option<u64>,
    /// The redacted `config.get` object (F7), once fetched (`:config`, the
    /// scope panel).
    pub config: Option<Value>,
    /// Where a built PoC is written (C12): `--poc-dir` / the embed's
    /// `poc.dir`; else `config.get`'s `poc_dir`; else a temp fallback.
    pub poc_dir: Option<PathBuf>,
    pub toasts: VecDeque<Toast>,
    pub compose: ComposeForm,
    pub compose_history: Vec<Value>,
    pub edit: Option<EditBuffer>,
    pub inspector: InspectorState,
    pub width: u16,
    pub height: u16,
    pub ticks: u64,
    pub should_quit: bool,
    /// Scroll offset of the flow list (first visible entry).
    pub list_offset: usize,
    /// Pending PoC build: the flow and the name typed so far.
    pub poc_pending: Option<(String, Option<String>)>,
    /// Pending PoC run: the YAML path and the target typed so far.
    pub poc_run_pending: Option<(String, Option<String>)>,
    /// A tool call waiting for the operator's `y/N` (`Mode::Prompt(Confirm)`).
    pub confirm: Option<ConfirmCall>,
    /// What `o` asked to open; the run loop takes it with [`App::take_open_target`].
    pub pending_open: Option<OpenTarget>,
    /// The last `ca.status` result, for the CA panel and the pill word.
    pub ca_status: Option<Value>,
    /// A `ca.install`/`ca.uninstall` is on the wire: the pill reads
    /// `· CA trusting…` until the reply (D17.6).
    pub ca_installing: bool,
    /// The browser view (§2.7).
    pub browser: BrowserState,
    /// Hosts whose `scope.remove` is in flight, oldest first: the reply is a
    /// bare bool, so the toast takes its host from here.
    pub pending_scope_removals: VecDeque<String>,
    /// PoC paths whose `poc.get` is in flight, oldest first (a failure
    /// carries no path, so it settles the oldest).
    pub poc_get_inflight: VecDeque<String>,
    /// The screenshot path a `poc.artifact` fetch will open (Findings `o`).
    pub pending_artifact: Option<String>,
    /// File-name slugs for `poc.build` calls in flight, oldest first (C12:
    /// the reply is the YAML text, named after what the operator typed).
    pub poc_build_pending: VecDeque<String>,
    /// The L4 operator surface's state (ui-ext Part 3): flows, scope, agent
    /// gates, craft editor, inject confirm. Inert until the bus offers `l4.*`.
    pub l4: crate::l4::L4State,
    /// The Scan view's state (scanner-integration Stage 1). Inert until the bus
    /// offers `scan.discover`.
    pub scan: ScanState,
}

impl App {
    pub fn new(caps: TermCaps, bus_address: impl Into<String>) -> Self {
        Self {
            flows: Vec::new(),
            index: HashMap::new(),
            details: HashMap::new(),
            detail_failed: HashSet::new(),
            selected: None,
            next_seq: 1,
            mode: Mode::Flows,
            layout: Layout::Horizontal,
            sidebar_open: true,
            sidebar: SidebarItem::All,
            chip: Chip::All,
            filter: None,
            filter_text: String::new(),
            prompt: String::new(),
            prompt_from: Mode::Flows,
            palette_cursor: 0,
            pinned_hosts: Vec::new(),
            auto_select: false,
            intercept_armed: false,
            capture_paused: false,
            system_proxy: None,
            sysproxy_setting: false,
            scope: Vec::new(),
            findings: Vec::new(),
            finding_cursor: 0,
            scope_cursor: 0,
            agent: AgentState::default(),
            bus: BusStatus::Connecting,
            bus_address: bus_address.into(),
            expect_role: None,
            tools: Vec::new(),
            caps,
            listening: None,
            serving: None,
            store_paused: None,
            config: None,
            poc_dir: None,
            toasts: VecDeque::new(),
            compose: ComposeForm::template_get(),
            compose_history: Vec::new(),
            edit: None,
            inspector: InspectorState::default(),
            width: 200,
            height: 50,
            ticks: 0,
            should_quit: false,
            list_offset: 0,
            poc_pending: None,
            poc_run_pending: None,
            confirm: None,
            pending_open: None,
            ca_status: None,
            ca_installing: false,
            browser: BrowserState::default(),
            pending_scope_removals: VecDeque::new(),
            poc_get_inflight: VecDeque::new(),
            pending_artifact: None,
            poc_build_pending: VecDeque::new(),
            l4: crate::l4::L4State::default(),
            scan: ScanState::default(),
        }
    }

    // ----------------------------------------------------------- queries

    /// Whether the bus offers a tool (adaptive features, see the brief).
    pub fn has_tool(&self, name: &str) -> bool {
        self.tools.iter().any(|t| t.name == name)
    }

    pub fn narrow(&self) -> bool {
        self.width < NARROW_COLS
    }

    /// The toolbar pill's CA-trust word (§D17.6), from the last `ca.status`
    /// and the in-flight flag; `None` while the trust state is unread.
    pub fn ca_trust_word(&self) -> Option<String> {
        self.ca_trust()?.pill(self.ca_installing)
    }

    fn ca_trust(&self) -> Option<CaTrustWord> {
        CaTrustWord::from_json(self.ca_status.as_ref()?)
    }

    /// The server-resolved role for the live connection (`"operator"`/
    /// `"agent"`), from the echoed `initialize` role; `None` when not connected
    /// or the server did not echo one.
    pub fn resolved_role(&self) -> Option<&str> {
        match &self.bus {
            BusStatus::Connected { role, .. } => role.as_deref(),
            _ => None,
        }
    }

    /// AC8: an expectation was set (`--expect-role`) and the connection did not
    /// resolve to it — a different role, or no role echoed at all. False when
    /// no expectation was set or while the bus is not connected.
    pub fn role_mismatch(&self) -> bool {
        match (&self.expect_role, &self.bus) {
            (Some(expect), BusStatus::Connected { role, .. }) => {
                role.as_deref() != Some(expect.as_str())
            }
            _ => false,
        }
    }

    /// The bus is on this machine: loopback TCP or the in-process channel.
    /// Local paths the bus reports (`poc_path`) are only meaningful then.
    pub fn is_loopback_bus(&self) -> bool {
        self.bus_address == "in-process"
            || self
                .bus_address
                .parse::<SocketAddr>()
                .is_ok_and(|a| a.ip().is_loopback())
    }

    /// Rebuild `index` from `flows`.
    fn rebuild_index(&mut self) {
        self.index = self
            .flows
            .iter()
            .enumerate()
            .map(|(i, r)| (r.id.clone(), i))
            .collect();
    }

    pub fn row(&self, id: &str) -> Option<&FlowRow> {
        self.index
            .get(id)
            .and_then(|&i| self.flows.get(i))
            .filter(|r| r.id == id)
    }

    pub fn row_mut(&mut self, id: &str) -> Option<&mut FlowRow> {
        let i = *self.index.get(id)?;
        self.flows.get_mut(i).filter(|r| r.id == id)
    }

    /// What `o` asked to open, once; the run loop performs it.
    pub fn take_open_target(&mut self) -> Option<OpenTarget> {
        self.pending_open.take()
    }

    pub fn selected_row(&self) -> Option<&FlowRow> {
        self.selected.as_deref().and_then(|id| self.row(id))
    }

    pub fn selected_detail(&self) -> Option<&FlowDetail> {
        self.selected.as_deref().and_then(|id| self.details.get(id))
    }

    /// The selected flow's response body when the Response pane's JSON tab
    /// is showing it; `None` on any other pane or tab, and for a large body
    /// (over `viewers::LARGE_BODY_BYTES`), which the tab previews as text
    /// instead of parsing.
    fn json_body(&self) -> Option<&str> {
        if self.inspector.pane != Pane::Response
            || RESPONSE_TABS.get(self.inspector.response_tab) != Some(&"JSON")
        {
            return None;
        }
        let resp = self.selected_detail()?.response.as_ref()?;
        if crate::viewers::is_large(resp) {
            return None;
        }
        resp.body_text()
    }

    /// The JSON tree as the JSON tab draws it (paths only matter here, so the
    /// theme is irrelevant), cut where the renderer cuts it
    /// (`viewers::MAX_VIEWER_LINES`); `None` off the JSON tab or when the
    /// body is not JSON.
    fn json_tree(&self) -> Option<Vec<Option<String>>> {
        let body = self.json_body()?;
        let (_, mut paths) =
            json::tree_with_paths(&Theme::new(false), body, &self.inspector.folds)?;
        paths.truncate(crate::viewers::MAX_VIEWER_LINES);
        Some(paths)
    }

    /// The node path (`$.items[0].name`) of the cursor line on the Response
    /// pane's JSON tab; `None` elsewhere or on a closing-bracket line.
    pub fn json_cursor_path(&self) -> Option<String> {
        let paths = self.json_tree()?;
        let at = self.inspector.cursor_line.min(paths.len().checked_sub(1)?);
        paths.get(at).cloned().flatten()
    }

    /// How many lines the focused viewer has, when the app can know it
    /// (the JSON tree). Other viewers are shaped by the renderer.
    fn viewer_line_count(&self) -> Option<usize> {
        self.json_tree().map(|p| p.len())
    }

    /// What `y` copies: the node path on the JSON tab in Inspector mode, the
    /// selected flow's URL otherwise.
    pub fn copy_text(&self) -> Option<String> {
        if self.mode == Mode::Inspector && self.json_body().is_some() {
            return self.json_cursor_path();
        }
        self.selected_row().map(FlowRow::url)
    }

    /// Scope-as-authorisation (§2.7): `host`, `host:port`, `*.wildcard`. An L4
    /// row is in scope when an `l4.scope.list` entry covers its interface
    /// (the courtesy signal; the guard is the enforcement, Part 5).
    pub fn in_scope(&self, row: &FlowRow) -> bool {
        if row.kind == FlowKind::L4 {
            return self
                .l4
                .flows
                .get(&row.id)
                .is_some_and(|f| self.l4.in_scope(f));
        }
        scope_covers(&self.scope, &row.authority)
    }

    /// The full L4 flow for the current selection, if it is an L4 flow.
    pub fn selected_l4(&self) -> Option<&crate::l4::L4Flow> {
        self.selected
            .as_deref()
            .and_then(|id| self.l4.flows.get(id))
    }

    pub fn group_by(&self) -> Option<GroupBy> {
        match self.sidebar {
            SidebarItem::Apps => Some(GroupBy::Client),
            SidebarItem::Domains => Some(GroupBy::Host),
            _ => None,
        }
    }

    fn passes(&self, row: &FlowRow) -> bool {
        let detail = self.details.get(&row.id);
        if !self.chip.matches(row, detail) {
            return false;
        }
        match self.sidebar {
            SidebarItem::Scope if !self.in_scope(row) => return false,
            SidebarItem::Pinned
                if !self.pinned_hosts.is_empty()
                    && !self.pinned_hosts.iter().any(|h| row.host() == h) =>
            {
                return false
            }
            _ => {}
        }
        match &self.filter {
            Some(expr) => expr.matches(
                row,
                &filter::Ctx {
                    detail,
                    in_scope: self.in_scope(row),
                },
            ),
            None => true,
        }
    }

    fn group_key(&self, row: &FlowRow) -> Option<String> {
        match self.group_by()? {
            // A WebSocket row whose handshake is not listed has no host:
            // it is not a group of its own.
            GroupBy::Host => (!row.host().is_empty()).then(|| row.host().to_string()),
            GroupBy::Client => Some(row.client.clone().unwrap_or_else(|| "unknown".into())),
        }
    }

    /// Indices into `flows` in display order: pinned hosts first, then by
    /// group (first-seen order) when grouping, else arrival order.
    pub fn visible(&self) -> Vec<usize> {
        let mut idx: Vec<usize> = (0..self.flows.len())
            .filter(|&i| self.passes(&self.flows[i]))
            .collect();
        let pin_rank = |r: &FlowRow| {
            self.pinned_hosts
                .iter()
                .position(|h| h == r.host())
                .unwrap_or(usize::MAX)
        };
        if self.group_by().is_some() {
            let mut first_seen: Vec<String> = Vec::new();
            for &i in &idx {
                if let Some(k) = self.group_key(&self.flows[i]) {
                    if !first_seen.contains(&k) {
                        first_seen.push(k);
                    }
                }
            }
            idx.sort_by_key(|&i| {
                let r = &self.flows[i];
                let g = self
                    .group_key(r)
                    .and_then(|k| first_seen.iter().position(|x| *x == k))
                    .unwrap_or(usize::MAX);
                (pin_rank(r), g, r.seq)
            });
        } else {
            idx.sort_by_key(|&i| (pin_rank(&self.flows[i]), self.flows[i].seq));
        }
        idx
    }

    /// The group header to draw above `flows[i]`, if it starts a group.
    pub fn group_header(&self, visible: &[usize], pos: usize) -> Option<(String, usize)> {
        let key = self.group_key(&self.flows[*visible.get(pos)?])?;
        let prev = pos
            .checked_sub(1)
            .and_then(|p| visible.get(p))
            .and_then(|&i| self.group_key(&self.flows[i]));
        if prev.as_deref() == Some(key.as_str()) {
            return None;
        }
        let n = visible
            .iter()
            .filter(|&&i| self.group_key(&self.flows[i]).as_deref() == Some(key.as_str()))
            .count();
        Some((key, n))
    }

    pub fn paused(&self) -> Vec<&FlowRow> {
        self.flows.iter().filter(|r| r.paused()).collect()
    }

    /// The oldest paused flow, or the selected one if it is paused (§2.7
    /// "Selecting a paused row … targets the bar's actions at it").
    pub fn intercept_target(&self) -> Option<&FlowRow> {
        match self.selected_row() {
            Some(r) if r.paused() => Some(r),
            _ => self.paused().into_iter().min_by_key(|r| r.seq),
        }
    }

    pub fn apps(&self) -> Vec<(String, usize)> {
        counts_by(&self.flows, |r| {
            Some(r.client.clone().unwrap_or_else(|| "unknown".into()))
        })
    }

    /// Hosts seen, with their flow counts; a row with no host (a WebSocket
    /// whose handshake is not listed) is not a domain.
    pub fn domains(&self) -> Vec<(String, usize)> {
        counts_by(&self.flows, |r| {
            (!r.host().is_empty()).then(|| r.host().to_string())
        })
    }

    pub fn in_scope_count(&self) -> usize {
        self.flows.iter().filter(|r| self.in_scope(r)).count()
    }

    /// Bytes captured across the list, once at least one row knows a size
    /// (sizes come with `flow.detail`, F5); `None` until then, which the
    /// status bar draws as a dash — a real `0 B` is `Some(0)` (§2.8).
    pub fn total_bytes(&self) -> Option<u64> {
        let mut known = false;
        let mut total = 0u64;
        for r in &self.flows {
            for size in [r.req_size, r.resp_size].into_iter().flatten() {
                known = true;
                total = total.saturating_add(size);
            }
        }
        known.then_some(total)
    }

    pub fn toast(&mut self, level: Level, text: impl Into<String>) {
        self.toasts.push_back(Toast {
            level,
            text: text.into(),
            expires_at_tick: self.ticks + 16,
        });
        while self.toasts.len() > 3 {
            self.toasts.pop_front();
        }
    }

    pub fn current_toast(&self) -> Option<&Toast> {
        self.toasts.back()
    }

    /// Everything the palette can run, filtered by the typed query.
    pub fn palette_items(&self) -> Vec<PaletteItem> {
        // An `:l4 …` line completes from live state only (L4 parity §7(b)):
        // the sub-commands, the known interface names, the directions and the
        // running capture ids. Case matters (ids), so the raw text is used.
        let raw = self.prompt.trim_start().trim_start_matches(':');
        // A `:scope …` line likewise: `add l4` and its words only against a
        // core that can confirm the add (spec §3 / AC39).
        if raw.starts_with("scope ") {
            return crate::ui::complete::scope_command_candidates(
                raw,
                crate::l4::supports_operator_scope_add(&self.tools),
                &self.l4_interfaces(),
            )
            .into_iter()
            .map(PaletteItem::from)
            .collect();
        }
        if raw.starts_with("l4 ") {
            return crate::ui::complete::l4_command_candidates(
                raw,
                &self.l4_interfaces(),
                &self.l4.captures,
            )
            .into_iter()
            .map(PaletteItem::from)
            .collect();
        }
        let q = self.prompt.trim().to_lowercase();
        let mut items: Vec<PaletteItem> = BUILTIN_COMMANDS
            .iter()
            .map(|(cmd, detail)| PaletteItem {
                label: format!(":{cmd}"),
                detail: (*detail).to_string(),
                kind: PaletteKind::Command((*cmd).to_string()),
            })
            .collect();
        for t in &self.tools {
            items.push(PaletteItem {
                label: t.name.clone(),
                detail: t.description.clone(),
                kind: PaletteKind::Tool(t.name.clone()),
            });
        }
        if q.len() >= 2 {
            for r in &self.flows {
                let url = r.url();
                if fuzzy(&q, &url.to_lowercase()) {
                    items.push(PaletteItem {
                        label: format!("#{} {} {}", r.seq, r.method, url),
                        detail: "flow".into(),
                        kind: PaletteKind::Flow(r.id.clone()),
                    });
                }
            }
        }
        if q.is_empty() {
            return items;
        }
        let mut scored: Vec<(usize, PaletteItem)> = items
            .into_iter()
            .filter_map(|it| {
                let hay = format!("{} {}", it.label.to_lowercase(), it.detail.to_lowercase());
                fuzzy(&q, &hay).then(|| {
                    let rank = if it.label.to_lowercase().contains(&q) {
                        0
                    } else {
                        1
                    };
                    (rank, it)
                })
            })
            .collect();
        scored.sort_by_key(|(rank, _)| *rank);
        scored.into_iter().map(|(_, it)| it).collect()
    }

    // ----------------------------------------------------------- reducer

    /// Apply a user action; returns the bus work it implies.
    pub fn update(&mut self, action: Action) -> Vec<BusRequest> {
        let mut out = Vec::new();
        match action {
            Action::Quit => self.should_quit = true,
            Action::Tick => {
                self.ticks += 1;
                let t = self.ticks;
                self.toasts.retain(|x| x.expires_at_tick > t);
            }
            Action::Resize(w, h) => {
                self.width = w;
                self.height = h;
            }
            Action::Help => self.mode = Mode::Help,
            Action::Back => self.back(),
            Action::Input(c) if self.mode == Mode::Prompt(PromptKind::Confirm) => {
                out.extend(self.answer_confirm(matches!(c, 'y' | 'Y')));
            }
            Action::Input(c) => self.input(c),
            Action::Backspace => match self.mode {
                Mode::Compose => {
                    let field = compose_field(&mut self.compose);
                    field.pop();
                }
                Mode::Edit => {
                    if let Some(e) = &mut self.edit {
                        edit_backspace(e);
                    }
                }
                _ => {
                    self.prompt.pop();
                    if self.mode == Mode::Prompt(PromptKind::Filter) {
                        self.apply_filter_live();
                    }
                }
            },
            Action::Submit => out.extend(self.submit()),
            Action::Command(line) => out.extend(self.run_command(&line)),
            Action::Up
            | Action::Down
            | Action::PageUp
            | Action::PageDown
            | Action::Home
            | Action::End => self.navigate(&action, &mut out),
            Action::Left | Action::Right => {
                let d: i32 = if action == Action::Left { -1 } else { 1 };
                match self.mode {
                    Mode::Edit => {
                        if let Some(e) = &mut self.edit {
                            let len = e.lines.get(e.cursor_line).map_or(0, |l| l.chars().count());
                            e.cursor_col =
                                usize::try_from((e.cursor_col as i64 + i64::from(d)).max(0))
                                    .unwrap_or(0)
                                    .min(len);
                        }
                    }
                    Mode::Inspector | Mode::QuickLook => self.tab_step(d),
                    Mode::Compose => {
                        self.compose.field =
                            usize::try_from((self.compose.field as i64 + i64::from(d)).clamp(0, 3))
                                .unwrap_or(0)
                    }
                    _ => self.chip = step(&Chip::ALL, self.chip, d),
                }
            }
            Action::Enter => match self.mode {
                Mode::Flows => {
                    if self.selected.is_some() {
                        self.mode = Mode::Inspector;
                        self.inspector.reset_view();
                        self.ensure_detail(&mut out);
                    }
                }
                Mode::Findings => {
                    if let Some(f) = self.findings.get(self.finding_cursor) {
                        if let Some(id) = f.finding_capture.clone() {
                            if self.row(&id).is_some() {
                                self.selected = Some(id);
                                self.mode = Mode::Inspector;
                                self.ensure_detail(&mut out);
                            } else {
                                self.toast(Level::Warn, "finding capture is not in the flow store");
                            }
                        }
                    }
                }
                // Scan: ⏎ opens the focused list's selected flow in the
                // inspector — the injection point's flow, or the endpoint's
                // linked flow (AC3). Parity with the web view's endpoint→flow
                // links. An endpoint with no linked flow opens nothing; a flow
                // no longer in the store is refused, not selected.
                Mode::Scan => {
                    let id = match self.scan.focus {
                        ScanFocus::Points => self
                            .scan
                            .points
                            .get(self.scan.cursor)
                            .map(|p| p.flow.clone()),
                        ScanFocus::Endpoints => self
                            .scan
                            .endpoints
                            .get(self.scan.endpoint_cursor)
                            .and_then(|e| self.scan.endpoint_flows.get(e).cloned()),
                    };
                    if let Some(id) = id {
                        if self.row(&id).is_some() {
                            self.selected = Some(id);
                            self.mode = Mode::Inspector;
                            self.inspector.reset_view();
                            self.ensure_detail(&mut out);
                        } else {
                            self.toast(
                                Level::Warn,
                                format!(
                                    "flow {id} is not in the flow list (cleared, or not captured here)"
                                ),
                            );
                        }
                    }
                }
                Mode::Prompt(_) | Mode::Compose => out.extend(self.submit()),
                Mode::Edit => {
                    if let Some(e) = &mut self.edit {
                        edit_newline(e);
                    }
                }
                _ => {}
            },
            Action::ToggleSidebar => self.sidebar_open = !self.sidebar_open,
            Action::SidebarNext => self.sidebar_step(1, &mut out),
            Action::SidebarPrev => self.sidebar_step(-1, &mut out),
            Action::ChipNext => self.chip = step(&Chip::ALL, self.chip, 1),
            Action::ChipPrev => self.chip = step(&Chip::ALL, self.chip, -1),
            Action::ChipIndex(i) => {
                if let Some(c) = Chip::ALL.get(i) {
                    self.chip = *c;
                }
            }
            Action::ToggleLayout => {
                self.layout = match self.layout {
                    Layout::Horizontal => Layout::Vertical,
                    Layout::Vertical => Layout::Horizontal,
                }
            }
            Action::ToggleAutoSelect => {
                self.auto_select = !self.auto_select;
                let msg = if self.auto_select {
                    "Auto-select on"
                } else {
                    "Auto-select off"
                };
                self.toast(Level::Info, msg);
            }
            Action::ToggleIntercept => {
                let armed = !self.intercept_armed;
                self.intercept_armed = armed;
                out.push(BusRequest::Intercept(armed));
            }
            // D14: `off` only when the word says the system proxy is already
            // ours; `on` otherwise, including before the first status poll.
            Action::ToggleSysProxy => {
                let ours = self
                    .system_proxy
                    .as_ref()
                    .is_some_and(SystemProxyWord::points_at_us);
                let line = if ours { "sysproxy off" } else { "sysproxy on" };
                out.extend(self.run_command(line));
            }
            Action::Resume => {
                if let Some(f) = self.selected_l4().cloned() {
                    // L4: resume == forward the parked in-path packet.
                    out.extend(self.l4_intercept_verb("l4.intercept.forward", &f));
                } else if let Some(r) = self.intercept_target().cloned() {
                    if self.gate(&r) {
                        out.push(BusRequest::Resume(r.id));
                    }
                } else {
                    self.toast(Level::Info, "Nothing paused.");
                }
            }
            Action::ResumeAll => {
                let ids: Vec<FlowRow> = self.paused().into_iter().cloned().collect();
                if ids.is_empty() {
                    self.toast(Level::Info, "Nothing paused.");
                }
                let mut skipped = 0usize;
                let mut sent = 0usize;
                for r in ids {
                    if self.in_scope(&r) {
                        out.push(BusRequest::Resume(r.id));
                        sent += 1;
                    } else {
                        skipped += 1;
                    }
                }
                if skipped > 0 {
                    self.toast(
                        Level::Warn,
                        format!(
                            "Resume all: {sent} resumed, {skipped} skipped — out of scope (add their hosts to scope to act)"
                        ),
                    );
                }
            }
            Action::Kill => {
                if let Some(f) = self.selected_l4().cloned() {
                    // L4: kill == drop the parked in-path packet.
                    out.extend(self.l4_intercept_verb("l4.intercept.drop", &f));
                } else if let Some(r) = self.intercept_target().cloned() {
                    if self.gate(&r) {
                        out.push(BusRequest::Kill(r.id));
                    }
                } else {
                    self.toast(Level::Info, "Nothing paused.");
                }
            }
            Action::Edit if self.selected_row().is_some_and(|r| r.kind == FlowKind::L4) => {
                // L4: edit == open the craft editor to mutate the packet.
                self.l4.pane = crate::l4::L4Pane::Craft;
                if self.mode == Mode::Flows {
                    self.mode = Mode::Inspector;
                }
            }
            Action::Edit => {
                let Some(r) = self.intercept_target().cloned() else {
                    self.toast(
                        Level::Info,
                        "Edit needs a paused flow (arm intercept with i).",
                    );
                    return out;
                };
                if !self.gate(&r) {
                    return out;
                }
                if !self.has_tool("flow.mutate") {
                    self.toast(Level::Warn, "flow.mutate is not on this bus");
                    return out;
                }
                match self.details.get(&r.id).and_then(|d| d.request.clone()) {
                    Some(req) => {
                        self.edit = Some(EditBuffer::from_request(&r.id, &req));
                        self.selected = Some(r.id.clone());
                        self.mode = Mode::Edit;
                        self.inspector.pane = Pane::Request;
                        self.inspector.request_tab = tab_index(&REQUEST_TABS, "Raw");
                    }
                    None => {
                        self.toast(Level::Warn, "Raw edit needs the request detail (core follow-up F5); headers-only edit via :flow.mutate");
                        self.request_detail(&r.id, &mut out);
                    }
                }
            }
            Action::ApplyAndResume => {
                if let Some(e) = self.edit.take() {
                    if e.dirty() {
                        out.push(BusRequest::Mutate {
                            id: e.id.clone(),
                            edits: e.to_edits(),
                        });
                    }
                    out.push(BusRequest::Resume(e.id));
                    self.mode = Mode::Flows;
                }
            }
            Action::RevertEdit => {
                if let Some(e) = &mut self.edit {
                    e.lines = e.original.clone();
                    e.cursor_line = 0;
                    e.cursor_col = 0;
                }
            }
            Action::Replay => {
                if self.refuse_http_verb_on_l4("Replay") {
                    return out;
                }
                if let Some(r) = self.selected_row().cloned() {
                    if r.kind != FlowKind::Http {
                        self.toast(
                            Level::Warn,
                            "Only HTTP flows replay (WebSocket inject is core follow-up F9)",
                        );
                    } else if self.gate(&r) {
                        out.push(BusRequest::Replay(r.id));
                    }
                }
            }
            Action::Compose => {
                if let Some(r) = self.selected_row().cloned() {
                    self.compose = ComposeForm::from_flow(&r, self.details.get(&r.id));
                } else {
                    self.compose = ComposeForm::template_get();
                }
                self.mode = Mode::Compose;
            }
            Action::Pin => {
                if let Some(h) = self.selected_row().map(|r| r.host().to_string()) {
                    if let Some(i) = self.pinned_hosts.iter().position(|x| *x == h) {
                        self.pinned_hosts.remove(i);
                        self.toast(Level::Info, format!("Unpinned {h}"));
                    } else {
                        self.pinned_hosts.push(h.clone());
                        self.toast(Level::Info, format!("Pinned {h}"));
                    }
                }
            }
            Action::Mark => {
                if self.refuse_http_verb_on_l4("Mark") {
                    return out;
                }
                if self.selected.is_some() {
                    if self.has_tool("flow.mark") {
                        self.open_prompt(PromptKind::Mark);
                    } else {
                        self.toast(Level::Warn, "Mark needs core follow-up F6 (flow.mark)");
                    }
                }
            }
            Action::Comment => {
                if self.refuse_http_verb_on_l4("Comment") {
                    return out;
                }
                if self.selected.is_some() {
                    if self.has_tool("flow.comment") {
                        self.open_prompt(PromptKind::Comment);
                    } else {
                        self.toast(
                            Level::Warn,
                            "Comment needs core follow-up F6 (flow.comment)",
                        );
                    }
                }
            }
            Action::BuildPoc => {
                if self.refuse_http_verb_on_l4("Build PoC") {
                    return out;
                }
                if let Some(r) = self.selected_row().cloned() {
                    if self.gate(&r) {
                        self.poc_pending = Some((r.id, None));
                        self.open_prompt(PromptKind::PocName);
                    }
                }
            }
            Action::QuickLook => {
                if self.selected.is_some() {
                    self.mode = if self.mode == Mode::QuickLook {
                        Mode::Flows
                    } else {
                        Mode::QuickLook
                    };
                    self.ensure_detail(&mut out);
                }
            }
            Action::CopyUrl => {
                let json_tab = self.mode == Mode::Inspector && self.json_body().is_some();
                let (what, shown) = if json_tab {
                    ("node path", "on the pane's tab row")
                } else {
                    ("URL", "in the status bar")
                };
                if self.copy_text().is_some() {
                    let msg = if self.caps.osc52 {
                        format!("{what} copied (OSC 52)")
                    } else {
                        format!("Terminal does not advertise OSC 52; {what} shown {shown}")
                    };
                    self.toast(Level::Info, msg);
                } else if json_tab {
                    self.toast(Level::Info, "No node on this line to copy");
                }
            }
            Action::OpenExternally => self.open_externally(&mut out),
            Action::OpenFindings => {
                self.mode = Mode::Findings;
                self.sidebar = SidebarItem::Findings;
            }
            Action::OpenScope => {
                self.mode = Mode::Scope;
                self.sidebar = SidebarItem::Scope;
                self.ensure_config(&mut out);
            }
            Action::OpenAgent => {
                self.mode = Mode::Agent;
                self.sidebar = SidebarItem::Agent;
            }
            Action::OpenBrowser => {
                self.mode = Mode::Browser;
                self.sidebar = SidebarItem::Browser;
                // First open: ask for what the panel shows, when the bus
                // can answer. Later opens keep what they have (`d`/`s`).
                let mut asked = false;
                if self.browser.dom.is_none() && self.has_tool("browser.get_dom") {
                    asked |= self.browser_call("browser.get_dom", json!({}), &mut out);
                }
                if self.browser.screenshot.is_none() && self.has_tool("browser.screenshot") {
                    asked |= self.browser_call("browser.screenshot", json!({}), &mut out);
                }
                if asked {
                    self.browser.busy = Some("loading the page");
                }
            }
            // The L4 panel reads only state the slow poll already holds; opening
            // it sends nothing (AC15: the controls are the `:l4` commands).
            Action::OpenL4 => {
                self.mode = Mode::L4;
                self.sidebar = SidebarItem::L4;
            }
            Action::OpenScan => {
                self.mode = Mode::Scan;
                self.sidebar = SidebarItem::Scan;
                // Viewing the panel never crawls: a `scan.discover` is up to
                // hundreds of real browser navigations against the target. Seed
                // the scope-bound target the header shows, so `r` (ScanLaunch)
                // and `:scan <host>` are the only paths that reach the wire.
                if self.scan.target.is_none() {
                    if let Some(host) = self.scan_target_host() {
                        self.scan.target = Some(scan_target_url(&host));
                    }
                }
            }
            Action::ScanLaunch => {
                if self.scan.running {
                    self.toast(Level::Info, "a scan is already running");
                } else {
                    self.scan_launch(None, &mut out);
                }
            }
            Action::ScanFocusToggle => {
                self.scan.focus = match self.scan.focus {
                    ScanFocus::Points => ScanFocus::Endpoints,
                    ScanFocus::Endpoints => ScanFocus::Points,
                };
            }
            Action::AgentSet(p) => {
                // `auto` and `ask` are the core's to set: the TUI shows them
                // but never sends them (plan 2026-10-31 decision 7).
                if !p.settable() {
                    self.toast(
                        Level::Warn,
                        format!(
                            "policy {} is display-only here; set it in the core config",
                            p.label()
                        ),
                    );
                } else if self.has_tool("agent.set") {
                    out.push(BusRequest::AgentSet(p));
                } else {
                    self.toast(Level::Warn, "agent.set is not on this bus");
                }
            }
            Action::PaletteOpen => self.open_prompt(PromptKind::Palette),
            Action::FilterOpen => {
                self.open_prompt(PromptKind::Filter);
                self.prompt = self.filter_text.clone();
            }
            Action::InspectorPaneToggle => {
                if self.selected_row().is_some_and(|r| r.kind == FlowKind::L4) {
                    self.l4.pane = self.l4.pane.next();
                } else {
                    self.inspector.pane = match self.inspector.pane {
                        Pane::Request => Pane::Response,
                        Pane::Response => Pane::Request,
                    };
                    self.inspector.reset_view();
                }
            }
            Action::InspectorTabNext => self.tab_step(1),
            Action::InspectorTabPrev => self.tab_step(-1),
            Action::ScrollBody(d) => {
                let s = i32::from(self.inspector.scroll) + d;
                self.inspector.scroll = u16::try_from(s.max(0)).unwrap_or(u16::MAX);
            }
            Action::ToggleFold => {
                // Only container nodes fold; a leaf or closing bracket is a no-op.
                let target = if self.mode == Mode::Inspector {
                    self.json_cursor_path().filter(|p| {
                        self.json_body()
                            .is_some_and(|b| json::container_paths(b).contains(p))
                    })
                } else {
                    None
                };
                if let Some(path) = target {
                    if !self.inspector.folds.remove(&path) {
                        self.inspector.folds.insert(path);
                    }
                }
            }
            // The browser view's keys (`keys::browser`): prompts open only
            // when the bus can take the call; the panel says so otherwise.
            Action::BrowserNavigatePrompt => {
                if self.has_tool("browser.navigate") {
                    self.open_prompt(PromptKind::BrowserUrl);
                    self.prompt = self.browser.url.clone();
                } else {
                    self.browser_missing("browser.navigate");
                }
            }
            Action::BrowserEvalPrompt => {
                if self.has_tool("browser.eval") {
                    self.open_prompt(PromptKind::BrowserEval);
                } else {
                    self.browser_missing("browser.eval");
                }
            }
            Action::BrowserRefreshDom => {
                self.browser_call("browser.get_dom", json!({}), &mut out);
            }
            Action::BrowserScreenshot => {
                self.browser_call("browser.screenshot", json!({}), &mut out);
            }
            Action::CaExportPrompt => {
                if self.has_tool("ca.export") {
                    self.open_prompt(PromptKind::CaExport);
                } else {
                    self.toast(Level::Warn, "ca.export is not on this bus");
                }
            }
            Action::PocRerun => {
                if let Some(f) = self.findings.get(self.finding_cursor) {
                    if f.poc_path.is_empty() {
                        // A Rhai `finding(...)` names no PoC file.
                        self.toast(Level::Info, "a script finding has no PoC to run");
                    } else {
                        self.poc_run_pending = Some((f.poc_path.clone(), None));
                        self.open_prompt(PromptKind::PocTarget);
                    }
                }
            }
            Action::ScopeAddPrompt => self.open_prompt(PromptKind::ScopeAdd),
            Action::ScopeRemoveSelected => {
                if let Some(h) = self.scope.get(self.scope_cursor).cloned() {
                    out.extend(self.run_command(&format!("scope rm {h}")));
                }
            }
            Action::ComposeSend => {
                if self.mode == Mode::Compose {
                    self.compose.field = 3;
                    out.extend(self.submit());
                }
            }
            Action::L4Build => out.extend(self.l4_build()),
            Action::L4Inject => out.extend(self.l4_inject()),
            Action::L4Confirm(yes) => out.extend(self.l4_answer_confirm(yes)),
            Action::L4MutateParked => out.extend(self.l4_mutate_parked()),
            Action::L4RevertParked => out.extend(self.l4_revert_parked()),
            Action::L4ToggleGate(gate) => out.extend(self.l4_toggle_gate(gate)),
        }
        out
    }

    // ---------------------------------------------------- L4 operator surface

    /// Build the craft YAML into a hex preview via `l4.craft` (L4OPS-AC8).
    fn l4_build(&mut self) -> Vec<BusRequest> {
        if self.selected_l4().is_none() {
            return Vec::new();
        }
        if !self.has_tool("l4.craft") {
            self.toast(Level::Warn, "l4.craft is not on this bus");
            return Vec::new();
        }
        match parse_craft_yaml(&self.l4.craft.text()) {
            Ok(spec) => {
                self.l4.craft.error = None;
                vec![BusRequest::Call {
                    name: "l4.craft".into(),
                    args: json!({ "spec": spec }),
                }]
            }
            Err(e) => {
                self.l4.craft.error = Some(e);
                Vec::new()
            }
        }
    }

    /// Inject the crafted packet via `l4.inject` only (L4OPS-AC10). Refused
    /// locally while `l4.capture.status` says unavailable (the status contract's
    /// `needs_privilege` covers capture *and* inject, L4 parity spec §1; the
    /// toast carries the core's reason, so nothing that can only fail reaches
    /// the bus, AC33). Then gated by L4 scope-as-authorisation; the guard's own
    /// refusal still surfaces verbatim from the server, and the operator
    /// confirms over the wire before it sends.
    fn l4_inject(&mut self) -> Vec<BusRequest> {
        let Some(flow) = self.selected_l4().cloned() else {
            return Vec::new();
        };
        if let Some(t) = self.l4.capture.refusal("inject") {
            self.toast(Level::Warn, t);
            return Vec::new();
        }
        if !self.has_tool("l4.inject") {
            self.toast(Level::Warn, "l4.inject is not on this bus");
            return Vec::new();
        }
        if !self.l4.inject_in_scope(&flow) {
            let iface = if flow.interface.is_empty() {
                "this interface".to_string()
            } else {
                format!("`{}`", flow.interface)
            };
            self.toast(
                Level::Warn,
                format!("Out of L4 scope — add an inject entry for {iface} to inject"),
            );
            return Vec::new();
        }
        let spec = match parse_craft_yaml(&self.l4.craft.text()) {
            Ok(s) => s,
            Err(e) => {
                self.l4.craft.error = Some(e);
                self.toast(Level::Warn, "Fix the craft YAML before injecting");
                return Vec::new();
            }
        };
        let mut args = json!({ "spec": spec.clone(), "interface": flow.interface });
        if let Some(dst) = craft_dst(&spec) {
            args["dst"] = Value::String(dst);
        }
        if self.l4_in_flight("l4.inject") {
            return Vec::new();
        }
        self.l4.pending = Some(("l4.inject".to_string(), args.clone()));
        vec![BusRequest::Call {
            name: "l4.inject".into(),
            args,
        }]
    }

    /// Answer the inject confirm overlay (L4OPS-AC10): `yes` re-issues the
    /// identical call plus the reserved `_confirm` token; `no` cancels.
    fn l4_answer_confirm(&mut self, yes: bool) -> Vec<BusRequest> {
        // The scope add was typed from the palette, not the inspector: go
        // back to the scope panel, where the entry will appear.
        self.mode = match self.l4.confirm.as_ref().map(|c| c.call.as_str()) {
            Some("l4.scope.add") => Mode::Scope,
            _ => Mode::Inspector,
        };
        let Some(c) = self.l4.confirm.take() else {
            return Vec::new();
        };
        if yes {
            vec![BusRequest::Call {
                name: c.call.clone(),
                args: c.confirmed_args(),
            }]
        } else {
            self.toast(Level::Info, format!("{} cancelled", c.call));
            Vec::new()
        }
    }

    /// `:scope add l4 <cidr> <ports> <iface> <direction> <capability>` (L4
    /// parity spec §3, AC13): the operator L4 scope add through the core's
    /// confirm-over-the-wire handshake. Only when `tools/list` marks
    /// `l4.scope.add` `confirmable` (a core with unit (a')); against any other
    /// core it is refused here and nothing reaches the bus (AC39, AC33). The
    /// five strings go verbatim; the core validates and summarises them in the
    /// prompt its `needs_confirmation` reply carries.
    fn l4_scope_add(&mut self, words: &str) -> Vec<BusRequest> {
        if !crate::l4::supports_operator_scope_add(&self.tools) {
            self.toast(
                Level::Warn,
                "this core cannot confirm an operator L4 scope add",
            );
            return Vec::new();
        }
        match crate::l4::scope_add_args(words) {
            Ok(_) if self.l4_in_flight("l4.scope.add") => Vec::new(),
            Ok(args) => {
                self.l4.pending = Some(("l4.scope.add".to_string(), args.clone()));
                vec![BusRequest::Call {
                    name: "l4.scope.add".into(),
                    args,
                }]
            }
            Err(usage) => {
                self.toast(Level::Error, usage);
                Vec::new()
            }
        }
    }

    /// Toggle one per-feature agent gate (L4OPS-AC11). Where `l4.agent.set` is
    /// present it flips the gate the guard enforces; where absent the toggle is
    /// read-only with an honest note. The agent can never flip its own gates
    /// (enforced by the core), so this is an operator action.
    fn l4_toggle_gate(&mut self, gate: crate::l4::L4Gate) -> Vec<BusRequest> {
        if !self.has_tool("l4.agent.set") {
            self.toast(
                Level::Warn,
                "L4 agent gates are read-only here — set `l4.allow_agent_*` in config and restart (l4.agent.set is not on this bus)",
            );
            return Vec::new();
        }
        let next = !self.l4.gates.get(gate);
        vec![BusRequest::Call {
            name: "l4.agent.set".into(),
            args: json!({ "capability": gate.wire(), "allowed": next }),
        }]
    }

    /// Forward / Drop a parked in-path L4 packet (ui-ext §3.4, L4OPS-AC12;
    /// L4 parity spec §4), through the same confirm-over-the-wire path. While
    /// `l4.intercept.status` says unavailable nothing reaches the bus: the
    /// toast carries the core's reason (AC11). The verdict names the **parked
    /// packet's id** from `l4.intercept.list`, the first listed for this flow
    /// (oldest first), never the flow id (AC10).
    fn l4_intercept_verb(&mut self, tool: &str, flow: &crate::l4::L4Flow) -> Vec<BusRequest> {
        let Some(parked_id) = self.l4_parked_target(tool, flow) else {
            return Vec::new();
        };
        let args = json!({ "id": parked_id });
        if self.l4_in_flight(tool) {
            return Vec::new();
        }
        self.l4.pending = Some((tool.to_string(), args.clone()));
        vec![BusRequest::Call {
            name: tool.to_string(),
            args,
        }]
    }

    /// The single-flight rule for a guarded L4 control: while `pending`
    /// already holds `call` (its first request has not been answered), a
    /// second press toasts and sends nothing, so one overlay can never bind
    /// to another in-flight request's prompt and token (the `CallOk` arm binds
    /// by name alone). `true` means the caller must send nothing.
    fn l4_in_flight(&mut self, call: &str) -> bool {
        if !matches!(&self.l4.pending, Some((c, _)) if c == call) {
            return false;
        }
        self.toast(
            Level::Warn,
            format!("{call} is already waiting for the core"),
        );
        true
    }

    /// The parked packet an `l4.intercept.*` verb acts on for `flow`, after the
    /// refusals every parked-packet verb shares (B4/B5): intercept unavailable
    /// (toast with the core's reason, AC11), the verb not on the bus, no parked
    /// packet listed for the flow, or the flow out of L4 scope. `None` means
    /// nothing may reach the bus; the toast says why.
    fn l4_parked_target(&mut self, tool: &str, flow: &crate::l4::L4Flow) -> Option<String> {
        if let Some(t) = self.l4.intercept.refusal("in-path intercept") {
            self.toast(Level::Warn, t);
            return None;
        }
        if !self.has_tool(tool) {
            self.toast(
                Level::Warn,
                format!("{tool} is not on this bus — in-path intercept is documented-limited here"),
            );
            return None;
        }
        let Some(parked_id) = self.l4.parked_for(&flow.id).map(|p| p.id.clone()) else {
            self.toast(Level::Info, "no parked packet on this flow");
            return None;
        };
        if !self.l4.in_scope(flow) {
            self.toast(Level::Warn, "Out of L4 scope — intercept actions disabled");
            return None;
        }
        Some(parked_id)
    }

    /// Craft pane `m` (L4 parity spec §4, AC12): apply the editor's spec to the
    /// selected intercept flow's parked packet — `l4.intercept.mutate {id, spec}`
    /// with the parked id from `l4.intercept.list` and the same spec the pane's
    /// Build sends to `l4.craft`. Same refusals as Forward / Drop; a spec the
    /// editor cannot parse stays in the pane as its error and sends nothing. The
    /// reply needs no confirm; the parked list refreshes on the slow poll.
    fn l4_mutate_parked(&mut self) -> Vec<BusRequest> {
        let Some(flow) = self.selected_l4().cloned() else {
            return Vec::new();
        };
        let Some(parked_id) = self.l4_parked_target("l4.intercept.mutate", &flow) else {
            return Vec::new();
        };
        let spec = match parse_craft_yaml(&self.l4.craft.text()) {
            Ok(s) => s,
            Err(e) => {
                self.l4.craft.error = Some(e);
                self.toast(
                    Level::Warn,
                    "Fix the craft YAML before applying it to the parked packet",
                );
                return Vec::new();
            }
        };
        self.l4.craft.error = None;
        vec![BusRequest::Call {
            name: "l4.intercept.mutate".into(),
            args: json!({ "id": parked_id, "spec": spec }),
        }]
    }

    /// Craft pane `u` (AC12): discard the staged edit of the selected intercept
    /// flow's parked packet — `l4.intercept.revert {id}`. Same refusals.
    fn l4_revert_parked(&mut self) -> Vec<BusRequest> {
        let Some(flow) = self.selected_l4().cloned() else {
            return Vec::new();
        };
        let Some(parked_id) = self.l4_parked_target("l4.intercept.revert", &flow) else {
            return Vec::new();
        };
        vec![BusRequest::Call {
            name: "l4.intercept.revert".into(),
            args: json!({ "id": parked_id }),
        }]
    }

    /// Ask for the selected L4 flow's packet window (spec §2: the inspector,
    /// not the list poll, fetches packets) on a core whose `l4.flow.get`
    /// declares `offset` / `limit`. An older core sends the whole log on the
    /// poll already, so nothing is asked.
    fn request_l4_window(&self, id: &str, out: &mut Vec<BusRequest>) {
        if self.has_tool("l4.flow.get") && crate::l4::supports_window(&self.tools) {
            out.push(BusRequest::Call {
                name: "l4.flow.get".into(),
                args: crate::l4::inspect_args(id),
            });
        }
    }

    /// Upsert one parsed `l4.flow.get` object: the union list row and the full
    /// flow in `self.l4.flows`. When the object carries no packets but the
    /// stored flow does (a `limit: 0` poll reply over an inspected window), the
    /// stored packets are kept; a grown `packet_count` on the selected flow
    /// asks for the window again.
    fn upsert_l4_flow(&mut self, mut f: crate::l4::L4Flow, out: &mut Vec<BusRequest>) {
        if f.packets.is_empty() {
            if let Some(prev) = self.l4.flows.get_mut(&f.id) {
                if !prev.packets.is_empty() {
                    let grown = f.packet_count != prev.packet_count;
                    // `prev` is replaced below, so its packets move, not copy.
                    f.packets = std::mem::take(&mut prev.packets);
                    if self.selected.as_deref() == Some(f.id.as_str()) && grown {
                        self.request_l4_window(&f.id, out);
                    }
                }
            }
        }
        if let Some(&i) = self.index.get(&f.id) {
            let seq = self.flows[i].seq;
            self.flows[i] = FlowRow::from_l4(&f, seq);
        } else {
            let row = FlowRow::from_l4(&f, self.next_seq);
            self.next_seq += 1;
            self.index.insert(row.id.clone(), self.flows.len());
            self.flows.push(row);
        }
        self.l4.flows.insert(f.id.clone(), f);
    }

    /// The HTTP verbs (replay, mark, comment, PoC) have no L4 meaning (L4
    /// parity spec AC16): on a selected L4 row, toast
    /// `<verb> is not available for L4 flows` and report `true` so the caller
    /// sends nothing. Checked when the verb is pressed and again when its
    /// prompt is submitted, in case the selection moved in between.
    fn refuse_http_verb_on_l4(&mut self, verb: &str) -> bool {
        if self.selected_row().is_some_and(|r| r.kind == FlowKind::L4) {
            self.toast(Level::Warn, format!("{verb} is not available for L4 flows"));
            return true;
        }
        false
    }

    fn gate(&mut self, r: &FlowRow) -> bool {
        if self.in_scope(r) {
            return true;
        }
        let host = r.host().to_string();
        let msg = if host.is_empty() {
            // Only a WebSocket row can lack a host: its summary carries the
            // handshake id alone, and that flow is not in the list.
            "Out of scope — unknown host (the WebSocket handshake is not listed)".to_string()
        } else {
            format!("Out of scope — add `{host}` to scope to act")
        };
        self.toast(Level::Warn, msg);
        false
    }

    /// `o`: hand the thing under the cursor to the desktop (§2.9). In the
    /// Findings panel that is the screenshot — a local file on a loopback
    /// bus, else fetched through `poc.artifact` (F13); elsewhere an image or
    /// large body, written to a private temp file first. Anything the
    /// terminal can show inline is not opened, and the toast says so.
    fn open_externally(&mut self, out: &mut Vec<BusRequest>) {
        if self.mode == Mode::Browser {
            match &self.browser.screenshot {
                Some(shot) => {
                    match open::body_to_temp_file("browser-screenshot", "png", &shot.bytes) {
                        Ok(path) => {
                            self.toast(Level::Info, "opening the screenshot");
                            self.pending_open = Some(OpenTarget {
                                path,
                                label: "screenshot".into(),
                            });
                        }
                        Err(e) => {
                            self.toast(Level::Error, format!("could not write the screenshot: {e}"))
                        }
                    }
                }
                None => self.toast(Level::Info, "no screenshot yet — s captures one"),
            }
            return;
        }
        if self.mode == Mode::Findings {
            let Some(f) = self.findings.get(self.finding_cursor) else {
                return;
            };
            let Some(p) = f.screenshot_path.clone() else {
                self.toast(Level::Info, "this finding has no screenshot to open");
                return;
            };
            // The path is the bus's word. On a loopback bus it may name a
            // file here: resolve it before the desktop sees it (SEC-2) and
            // open it only when it is a regular file whose header is an
            // image we know. Otherwise — a remote bus, or a path that does
            // not exist here — the bytes come through `poc.artifact` (F13).
            let local = if self.is_loopback_bus() {
                std::fs::canonicalize(&p).ok()
            } else {
                None
            };
            match local {
                Some(path) => {
                    if !is_image_file(&path) {
                        self.toast(Level::Warn, format!("not an image: {}", path.display()));
                        return;
                    }
                    self.toast(
                        Level::Info,
                        format!("opening screenshot {}", path.display()),
                    );
                    self.pending_open = Some(OpenTarget {
                        path,
                        label: "screenshot".into(),
                    });
                }
                None if self.has_tool("poc.artifact") => {
                    self.toast(
                        Level::Info,
                        format!("fetching screenshot {p} (poc.artifact)"),
                    );
                    self.pending_artifact = Some(p.clone());
                    out.push(BusRequest::Call {
                        name: "poc.artifact".into(),
                        args: json!({ "path": p }),
                    });
                }
                None => match std::fs::canonicalize(&p) {
                    Err(e) => self.toast(Level::Warn, format!("open: {p}: {e}")),
                    Ok(_) => self.toast(
                        Level::Warn,
                        format!(
                            "open: {p}: the bus is not on this machine and has no poc.artifact"
                        ),
                    ),
                },
            }
            return;
        }
        let Some(row) = self.selected_row() else {
            self.toast(
                Level::Info,
                "o opens the selected flow's image or large body",
            );
            return;
        };
        let id = row.id.clone();
        let Some(d) = self.details.get(&id) else {
            self.toast(
                Level::Warn,
                "o needs the flow's detail (core follow-up F5, flow.detail)",
            );
            return;
        };
        // The focused pane in the inspector; the response (else request) otherwise.
        let (which, msg) = match (self.mode, self.inspector.pane) {
            (Mode::Inspector | Mode::Edit, Pane::Request) => ("request", d.request.as_ref()),
            (Mode::Inspector | Mode::Edit, Pane::Response) => ("response", d.response.as_ref()),
            _ => match (&d.response, &d.request) {
                (Some(r), _) => ("response", Some(r)),
                (None, req) => ("request", req.as_ref()),
            },
        };
        let Some(msg) = msg else {
            self.toast(Level::Info, format!("no {which} body to open"));
            return;
        };
        let ct = msg.content_type().unwrap_or_default();
        let ext = if ct.starts_with("image/") {
            match ct.as_str() {
                "image/png" => "png",
                "image/jpeg" | "image/jpg" => "jpg",
                "image/gif" => "gif",
                "image/webp" => "webp",
                _ => "bin",
            }
        } else if crate::viewers::is_large(msg) {
            if msg.body_text().is_some() {
                "txt"
            } else {
                "bin"
            }
        } else {
            self.toast(
                Level::Info,
                "o opens images and large bodies; this body is shown inline",
            );
            return;
        };
        match open::body_to_temp_file(&id, ext, &msg.body) {
            Ok(path) => {
                self.toast(Level::Info, format!("wrote {} — opening", path.display()));
                self.pending_open = Some(OpenTarget {
                    path,
                    label: format!("{id} {which} body"),
                });
            }
            Err(e) => self.toast(Level::Error, format!("could not write the body: {e}")),
        }
    }

    /// One system-proxy change at a time, however it is reached (`s`,
    /// `:sysproxy on|off`, the raw `:proxy.system.set|unset`, the palette's
    /// tool list): refused with a Warn toast while ours is in flight or the
    /// core's `setting` flag (another client's call) is up — the core would
    /// refuse the second call anyway, and that refusal would wrongly settle
    /// the first one's pill. Otherwise raises the flag and returns `true`.
    fn sysproxy_begin_change(&mut self) -> bool {
        let in_flight =
            self.sysproxy_setting || self.system_proxy.as_ref().is_some_and(|w| w.setting);
        if in_flight {
            self.toast(Level::Warn, "a system-proxy change is already in flight");
            return false;
        }
        self.sysproxy_setting = true;
        true
    }

    /// Hold `name(args)` for a `y/N` when it is in [`CONFIRM_TOOLS`] (and not
    /// a dry run); otherwise send it.
    fn call_tool(&mut self, name: &str, mut args: Value) -> Vec<BusRequest> {
        // D17.1: the trust-store scope is explicit wherever the OS has a
        // user store, unless the operator typed one.
        if CA_TRUST_TOOLS.contains(&name) {
            if let (Some(scope), Some(obj)) = (
                self.ca_trust().and_then(|w| w.default_scope()),
                args.as_object_mut(),
            ) {
                obj.entry("scope")
                    .or_insert_with(|| Value::String(scope.to_string()));
            }
        }
        // A dry run bypasses the prompt only when the tool's schema declares
        // `dry_run` and the value is the JSON boolean `true` (SEC-4): a
        // string typed at the prompt against a schema without the parameter
        // would be pruned by the bus task and the real call would run.
        let declares_dry_run = self
            .tools
            .iter()
            .find(|t| t.name == name)
            .is_some_and(|t| t.params().iter().any(|p| p.name == "dry_run"));
        let dry_run = declares_dry_run && args.get("dry_run") == Some(&Value::Bool(true));
        if CONFIRM_TOOLS.contains(&name) && !dry_run {
            let description = self
                .tools
                .iter()
                .find(|t| t.name == name)
                .map(|t| t.description.clone())
                .unwrap_or_default();
            let return_to = match self.mode {
                Mode::Prompt(_) => Mode::Flows,
                other => other,
            };
            self.confirm = Some(ConfirmCall {
                name: name.to_string(),
                description,
                args,
                return_to,
            });
            self.open_prompt(PromptKind::Confirm);
            return Vec::new();
        }
        if matches!(name, "proxy.system.set" | "proxy.system.unset")
            && !self.sysproxy_begin_change()
        {
            return Vec::new();
        }
        if let Some(label) = browser_busy_label(name) {
            // However it was reached (panel key, palette, `:browser.* …`),
            // the browser view shows the call in flight and forgets the
            // last error. `is_tracked_browser_call` is this same test; the
            // settle paths on `CallOk`/`CallFailed` use it.
            self.browser.busy = Some(label);
            self.browser.inflight += 1;
            self.browser.error = None;
            if name == "browser.navigate" {
                self.browser.pending_url =
                    args.get("url").and_then(Value::as_str).map(str::to_string);
            }
        }
        vec![BusRequest::Call {
            name: name.to_string(),
            args,
        }]
    }

    /// A `browser.*` call from the view. When the bus lacks the tool the
    /// panel says so (not only a toast) and nothing is sent.
    fn browser_call(&mut self, name: &str, args: Value, out: &mut Vec<BusRequest>) -> bool {
        if !self.has_tool(name) {
            self.browser_missing(name);
            return false;
        }
        out.extend(self.call_tool(name, args));
        true
    }

    /// The bus does not offer `name`: say so in the panel and the status line.
    fn browser_missing(&mut self, name: &str) {
        let msg = format!("{name} is not on this bus");
        self.browser.error = Some(msg.clone());
        self.toast(Level::Warn, msg);
    }

    /// The name `browser.eval` gives its expression parameter, read from the
    /// tool's schema (`expr` on today's bus) so the form follows the bus.
    fn browser_eval_param(&self) -> String {
        let params = self
            .tools
            .iter()
            .find(|t| t.name == "browser.eval")
            .map(|t| t.params())
            .unwrap_or_default();
        params
            .iter()
            .find(|p| p.required)
            .or(params.first())
            .map_or_else(|| "expr".to_string(), |p| p.name.clone())
    }

    /// A `browser.*` call was answered or failed: one fewer in flight.
    fn browser_settled(&mut self) {
        self.browser.inflight = self.browser.inflight.saturating_sub(1);
        if self.browser.inflight == 0 {
            self.browser.busy = None;
        }
    }

    /// The bus went away (or came back): no call sent before now will be
    /// answered, so nothing stays "in flight" — the browser view's counters,
    /// the CA pill's `· CA trusting…` (D17.6) and the sys-proxy pill's
    /// `· sys-proxy setting…` (D14) alike.
    fn forget_inflight(&mut self) {
        self.browser.inflight = 0;
        self.browser.busy = None;
        self.ca_installing = false;
        // A `proxy.system.set|unset` reply that will never come must not
        // keep the guard refusing `s` / `:sysproxy on|off` (F-tui 6).
        self.sysproxy_setting = false;
    }

    /// Ask `ca.status` when the bus offers it (D17.5: the pill word is the
    /// read-back, never a reply's claim).
    fn ask_ca_status(&self, out: &mut Vec<BusRequest>) {
        if self.has_tool("ca.status") {
            out.push(BusRequest::Call {
                name: "ca.status".into(),
                args: json!({}),
            });
        }
    }

    /// Launch a scope-bound `scan.discover`. The target is bound to the
    /// authorized scope (deny-by-default): a host no scope entry covers is
    /// refused with a toast and nothing reaches the wire. `explicit` is a
    /// user-typed target (`:scan <host>`); `None` picks the selected flow's host
    /// when it is in scope, else the first concrete in-scope host.
    fn scan_launch(&mut self, explicit: Option<String>, out: &mut Vec<BusRequest>) {
        if !self.has_tool("scan.discover") {
            self.toast(
                Level::Warn,
                "scan.discover is not on this bus (needs the scanner plugin)",
            );
            return;
        }
        let host = match explicit {
            Some(raw) => scan_host(&raw),
            None => match self.scan_target_host() {
                Some(h) => h,
                None => {
                    self.toast(
                        Level::Warn,
                        "Scan needs an in-scope host — add one to scope (S) first",
                    );
                    return;
                }
            },
        };
        if host.is_empty() || !scope_covers(&self.scope, &host) {
            self.toast(
                Level::Warn,
                format!("Out of scope — add `{host}` to scope to scan it"),
            );
            return;
        }
        let target = scan_target_url(&host);
        self.scan.running = true;
        self.scan.error = None;
        self.scan.target = Some(target.clone());
        out.extend(self.call_tool("scan.discover", json!({ "target": target })));
    }

    /// The host a scan targets when none is typed: the selected flow's host when
    /// it is in scope, else the first concrete (non-wildcard) scope entry.
    fn scan_target_host(&self) -> Option<String> {
        if let Some(row) = self.selected_row() {
            let host = row.host();
            if !host.is_empty() && self.in_scope(row) {
                return Some(host.to_string());
            }
        }
        self.scope
            .iter()
            .find(|e| !e.starts_with("*.") && !e.is_empty())
            .map(|e| scan_host(e))
    }

    /// The operator answered the confirm prompt.
    fn answer_confirm(&mut self, yes: bool) -> Vec<BusRequest> {
        self.prompt.clear();
        let Some(c) = self.confirm.take() else {
            self.mode = Mode::Flows;
            return Vec::new();
        };
        self.mode = c.return_to;
        if yes {
            if CA_TRUST_TOOLS.contains(&c.name.as_str()) {
                self.ca_installing = true;
            }
            vec![BusRequest::Call {
                name: c.name,
                args: c.args,
            }]
        } else {
            self.toast(Level::Info, format!("{} cancelled", c.name));
            Vec::new()
        }
    }

    fn back(&mut self) {
        self.mode = match self.mode {
            Mode::Edit => {
                self.edit = None;
                Mode::Inspector
            }
            Mode::Prompt(PromptKind::Confirm) => {
                let _ = self.answer_confirm(false);
                return;
            }
            Mode::L4Confirm => {
                let _ = self.l4_answer_confirm(false);
                return;
            }
            Mode::Prompt(kind) => {
                match kind {
                    PromptKind::PocName | PromptKind::PocParam => self.poc_pending = None,
                    PromptKind::PocTarget | PromptKind::PocVars => self.poc_run_pending = None,
                    _ => {}
                }
                self.close_prompt();
                return;
            }
            Mode::Flows => {
                if self.filter.is_some() {
                    self.filter = None;
                    self.filter_text.clear();
                } else if self.chip != Chip::All {
                    self.chip = Chip::All;
                }
                Mode::Flows
            }
            _ => Mode::Flows,
        };
    }

    /// Open a prompt, remembering where it was opened from. A prompt opened
    /// on top of another (PoC name → param, target → vars) keeps the first
    /// one's origin.
    fn open_prompt(&mut self, kind: PromptKind) {
        self.prompt.clear();
        self.palette_cursor = 0;
        if !matches!(self.mode, Mode::Prompt(_)) {
            self.prompt_from = self.mode;
        }
        self.mode = Mode::Prompt(kind);
    }

    /// Leave the open prompt for the mode it was opened from, line cleared.
    /// The confirm prompt does not come here: both its answers go through
    /// `answer_confirm`, which returns to `ConfirmCall::return_to`.
    fn close_prompt(&mut self) {
        self.prompt.clear();
        if matches!(self.mode, Mode::Prompt(_)) {
            self.mode = self.prompt_from;
        }
    }

    fn input(&mut self, c: char) {
        match self.mode {
            Mode::Compose => compose_field(&mut self.compose).push(c),
            Mode::Edit => {
                if let Some(e) = &mut self.edit {
                    edit_insert(e, c);
                }
            }
            Mode::Prompt(kind) => {
                self.prompt.push(c);
                self.palette_cursor = 0;
                if kind == PromptKind::Filter {
                    self.apply_filter_live();
                }
            }
            _ => {}
        }
    }

    fn apply_filter_live(&mut self) {
        if let Ok(expr) = filter::parse(&self.prompt) {
            self.filter = expr;
        }
    }

    fn submit(&mut self) -> Vec<BusRequest> {
        let mut out = Vec::new();
        let text = self.prompt.trim().to_string();
        match self.mode {
            Mode::Prompt(PromptKind::Palette) => {
                let items = self.palette_items();
                let chosen = items.get(self.palette_cursor).cloned();
                match chosen {
                    Some(PaletteItem {
                        kind: PaletteKind::Flow(id),
                        ..
                    }) => {
                        self.selected = Some(id);
                        self.close_prompt();
                    }
                    Some(PaletteItem {
                        kind: PaletteKind::Tool(name),
                        ..
                    }) if !text.contains(' ') => {
                        let t = self.tools.iter().find(|t| t.name == name).cloned();
                        let needs = t
                            .map(|t| t.params().iter().any(|p| p.required))
                            .unwrap_or(false);
                        if needs {
                            self.prompt = format!("{name} ");
                            self.toast(
                                Level::Info,
                                format!("{name}: type key=value arguments, then Enter"),
                            );
                            return out;
                        }
                        self.close_prompt();
                        out.extend(self.call_tool(&name, json!({})));
                    }
                    // An `:l4 …` completion is a whole line: Enter runs the
                    // highlighted one (typed free text runs when none match).
                    Some(PaletteItem {
                        kind: PaletteKind::Command(cmd),
                        ..
                    }) if cmd.starts_with("l4 ") || cmd.starts_with("scope ") => {
                        self.close_prompt();
                        out.extend(self.run_command(&cmd));
                    }
                    Some(PaletteItem {
                        kind: PaletteKind::Command(cmd),
                        ..
                    }) if !text.contains(' ')
                        && !text.is_empty()
                        && cmd.split(' ').count() == 1 =>
                    {
                        self.close_prompt();
                        out.extend(self.run_command(&cmd));
                    }
                    _ => {
                        self.close_prompt();
                        out.extend(self.run_command(&text));
                    }
                }
            }
            Mode::Prompt(PromptKind::Filter) => match filter::parse(&text) {
                Ok(expr) => {
                    self.filter = expr;
                    self.filter_text = text;
                    self.close_prompt();
                }
                // The prompt stays open on a bad expression; the line is
                // cleared so the next attempt starts fresh.
                Err(e) => {
                    self.toast(Level::Error, format!("filter: {e}"));
                    self.prompt.clear();
                }
            },
            Mode::Prompt(PromptKind::Comment) => {
                if !self.refuse_http_verb_on_l4("Comment") {
                    if let Some(id) = self.selected.clone() {
                        out.push(BusRequest::Comment { id, text });
                    }
                }
                self.close_prompt();
            }
            Mode::Prompt(PromptKind::Mark) => {
                if !self.refuse_http_verb_on_l4("Mark") {
                    if let Some(id) = self.selected.clone() {
                        let marks = text.split_whitespace().map(str::to_string).collect();
                        out.push(BusRequest::Mark { id, marks });
                    }
                }
                self.close_prompt();
            }
            Mode::Prompt(PromptKind::Pin) => {
                if !text.is_empty() && !self.pinned_hosts.contains(&text) {
                    self.pinned_hosts.push(text);
                }
                self.close_prompt();
            }
            Mode::Prompt(PromptKind::ScopeAdd) => {
                if !text.is_empty() {
                    out.push(BusRequest::ScopeAdd(text));
                }
                self.close_prompt();
            }
            // `poc.build`: name, then param (§2.7 "Build PoC from flow … name, parameter").
            Mode::Prompt(PromptKind::PocName) => match self.poc_pending.take() {
                Some((id, _)) => {
                    self.poc_pending = Some((id, (!text.is_empty()).then_some(text)));
                    self.open_prompt(PromptKind::PocParam);
                }
                None => self.close_prompt(),
            },
            Mode::Prompt(PromptKind::PocParam) => {
                if let Some((id, name)) = self.poc_pending.take() {
                    // C12: the reply is YAML text; remember what to call the file.
                    let seq = self.row(&id).map_or(0, |r| r.seq);
                    self.poc_build_pending
                        .push_back(poc_slug(name.as_deref(), seq));
                    out.push(BusRequest::PocBuild {
                        flow_id: id,
                        name,
                        param: (!text.is_empty()).then_some(text),
                    });
                }
                self.close_prompt();
            }
            // `poc.run`: target, then vars (§2.7 "Run again … editable target/vars").
            Mode::Prompt(PromptKind::PocTarget) => match self.poc_run_pending.take() {
                Some((path, _)) => {
                    self.poc_run_pending = Some((path, (!text.is_empty()).then_some(text)));
                    self.open_prompt(PromptKind::PocVars);
                }
                None => self.close_prompt(),
            },
            Mode::Prompt(PromptKind::PocVars) => {
                let Some((poc_path, target)) = self.poc_run_pending.take() else {
                    self.close_prompt();
                    return out;
                };
                match parse_kv_args(&text, None) {
                    Ok(Value::Object(m)) if m.is_empty() => out.push(BusRequest::PocRun {
                        poc_path,
                        target,
                        vars: None,
                    }),
                    Ok(vars) => out.push(BusRequest::PocRun {
                        poc_path,
                        target,
                        vars: Some(vars),
                    }),
                    Err(e) => {
                        // Keep the prompt open with the pending run intact.
                        self.poc_run_pending = Some((poc_path, target));
                        self.toast(Level::Error, format!("vars: {e}"));
                        return out;
                    }
                }
                self.close_prompt();
            }
            Mode::Prompt(PromptKind::CaExport) => {
                let mut args = Map::new();
                let mut words = text.split_whitespace();
                match words.next() {
                    Some(fmt @ ("pem" | "der")) => {
                        args.insert("format".into(), Value::String(fmt.to_string()));
                    }
                    Some(path) => {
                        args.insert("out".into(), Value::String(path.to_string()));
                    }
                    None => {}
                }
                if let Some(path) = words.next() {
                    args.insert("out".into(), Value::String(path.to_string()));
                }
                self.close_prompt();
                out.extend(self.call_tool("ca.export", Value::Object(args)));
            }
            // The confirm answers on its first key (`Action::Input` in
            // `update`), so Enter only ever arrives on a blank line: a "no".
            Mode::Prompt(PromptKind::Confirm) => out.extend(self.answer_confirm(false)),
            Mode::Prompt(PromptKind::BrowserUrl) => {
                self.close_prompt();
                if !text.is_empty() {
                    self.browser_call("browser.navigate", json!({ "url": text }), &mut out);
                }
            }
            Mode::Prompt(PromptKind::BrowserEval) => {
                self.close_prompt();
                if !text.is_empty() {
                    let key = self.browser_eval_param();
                    self.browser_call("browser.eval", json!({ key: text }), &mut out);
                }
            }
            Mode::Compose => {
                if self.compose.field < 3 {
                    self.compose.field += 1;
                    return out;
                }
                match self.compose.to_send_args() {
                    Ok(args) => {
                        let authority = self.compose.authority().unwrap_or_default();
                        if !scope_covers(&self.scope, &authority) {
                            self.toast(
                                Level::Warn,
                                format!("Out of scope — add `{authority}` to scope to send"),
                            );
                            return out;
                        }
                        self.compose_history.push(args.clone());
                        out.push(BusRequest::Send(args));
                        self.mode = Mode::Flows;
                    }
                    Err(e) => self.toast(Level::Error, format!("compose: {e}")),
                }
            }
            _ => {}
        }
        out
    }

    fn navigate(&mut self, action: &Action, out: &mut Vec<BusRequest>) {
        match self.mode {
            Mode::Prompt(PromptKind::Palette) => {
                let n = self.palette_items().len();
                if n > 0 {
                    self.palette_cursor = match action {
                        Action::Up => self.palette_cursor.saturating_sub(1),
                        Action::Down => (self.palette_cursor + 1).min(n - 1),
                        Action::Home => 0,
                        Action::End => n - 1,
                        _ => self.palette_cursor,
                    };
                }
            }
            Mode::Findings => {
                let n = self.findings.len();
                if n > 0 {
                    self.finding_cursor = match action {
                        Action::Up => self.finding_cursor.saturating_sub(1),
                        Action::Down => (self.finding_cursor + 1).min(n - 1),
                        _ => self.finding_cursor,
                    };
                }
            }
            Mode::Browser => {
                let n = self.browser.dom_outline.len();
                if n > 0 {
                    // The outline region is the body minus the panel's own
                    // lines (border, URL, screenshot, state, header, eval,
                    // F14, hints) and the three bars.
                    let page = usize::from(self.height.saturating_sub(13)).max(1);
                    let c = self.browser.dom_cursor;
                    self.browser.dom_cursor = match action {
                        Action::Up => c.saturating_sub(1),
                        Action::Down => (c + 1).min(n - 1),
                        Action::PageUp => c.saturating_sub(page),
                        Action::PageDown => (c + page).min(n - 1),
                        Action::Home => 0,
                        Action::End => n - 1,
                        _ => c,
                    };
                }
            }
            Mode::Scope => {
                let n = self.scope.len();
                if n > 0 {
                    self.scope_cursor = match action {
                        Action::Up => self.scope_cursor.saturating_sub(1),
                        Action::Down => (self.scope_cursor + 1).min(n - 1),
                        _ => self.scope_cursor,
                    };
                }
            }
            Mode::Scan => {
                // ↑↓/paging walk whichever list Tab has focused.
                let (n, cursor) = match self.scan.focus {
                    ScanFocus::Points => (self.scan.points.len(), &mut self.scan.cursor),
                    ScanFocus::Endpoints => {
                        (self.scan.endpoints.len(), &mut self.scan.endpoint_cursor)
                    }
                };
                if n > 0 {
                    // A page is the list body: the terminal minus the panel
                    // chrome (three bars, two box edges, the target and hint
                    // lines, the list heading).
                    let page = usize::from(self.height.saturating_sub(8)).max(1);
                    let c = *cursor;
                    *cursor = match action {
                        Action::Up => c.saturating_sub(1),
                        Action::Down => (c + 1).min(n - 1),
                        Action::PageUp => c.saturating_sub(page),
                        Action::PageDown => (c + page).min(n - 1),
                        Action::Home => 0,
                        Action::End => n - 1,
                        _ => c,
                    };
                }
            }
            Mode::Compose => {
                self.compose.field = match action {
                    Action::Up => self.compose.field.saturating_sub(1),
                    Action::Down => (self.compose.field + 1).min(3),
                    _ => self.compose.field,
                };
            }
            Mode::Inspector | Mode::QuickLook
                if self.selected_row().is_some_and(|r| r.kind == FlowKind::L4) =>
            {
                // An L4 flow: Up/Down move the packet cursor (Packets pane) or
                // the craft editor's line (Craft pane); the renderer clamps.
                match self.l4.pane {
                    crate::l4::L4Pane::Craft => {
                        let n = self.l4.craft.lines.len().max(1);
                        let c = self.l4.craft.cursor_line;
                        self.l4.craft.cursor_line = match action {
                            Action::Up => c.saturating_sub(1),
                            Action::Down => (c + 1).min(n - 1),
                            Action::Home => 0,
                            Action::End => n - 1,
                            _ => c,
                        };
                    }
                    _ => {
                        let n = self.selected_l4().map_or(0, |f| f.packets.len());
                        let c = self.l4.packet_cursor;
                        self.l4.packet_cursor = match (action, n) {
                            (_, 0) => 0,
                            (Action::Up, _) => c.saturating_sub(1),
                            (Action::Down, _) => (c + 1).min(n - 1),
                            (Action::Home, _) => 0,
                            (Action::End, _) => n - 1,
                            _ => c.min(n - 1),
                        };
                    }
                }
            }
            Mode::Inspector | Mode::QuickLook => {
                // Up/Down move the cursor line (the renderer scrolls to keep it
                // visible); PgUp/PgDn move the window by a page and pull the
                // cursor into it. The line count is known for the JSON tree;
                // elsewhere the renderer clamps what it draws.
                const PAGE: usize = 20;
                let last = self.viewer_line_count().map(|n| n.saturating_sub(1));
                let clamp = |c: usize| last.map_or(c, |l| c.min(l));
                let ins = &mut self.inspector;
                let mut paged = matches!(action, Action::PageUp | Action::PageDown);
                match action {
                    Action::Up => ins.cursor_line = ins.cursor_line.saturating_sub(1),
                    Action::Down => ins.cursor_line = clamp(ins.cursor_line + 1),
                    Action::PageUp => ins.scroll = ins.scroll.saturating_sub(PAGE as u16),
                    Action::PageDown => ins.scroll = ins.scroll.saturating_add(PAGE as u16),
                    Action::Home => ins.reset_view(),
                    Action::End => match last {
                        Some(l) => ins.cursor_line = l,
                        None => {
                            ins.scroll = ins.scroll.saturating_add(PAGE as u16);
                            paged = true;
                        }
                    },
                    _ => {}
                }
                if paged {
                    let top = usize::from(ins.scroll);
                    ins.cursor_line = clamp(ins.cursor_line.clamp(top, top + PAGE - 1));
                }
            }
            Mode::Edit => {
                if let Some(e) = &mut self.edit {
                    match action {
                        Action::Up => e.cursor_line = e.cursor_line.saturating_sub(1),
                        Action::Down => {
                            e.cursor_line = (e.cursor_line + 1).min(e.lines.len().saturating_sub(1))
                        }
                        Action::Home => e.cursor_col = 0,
                        Action::End => {
                            e.cursor_col = e.lines.get(e.cursor_line).map_or(0, String::len)
                        }
                        _ => {}
                    }
                    let len = e.lines.get(e.cursor_line).map_or(0, String::len);
                    e.cursor_col = e.cursor_col.min(len);
                }
            }
            _ => {
                let vis = self.visible();
                if vis.is_empty() {
                    return;
                }
                let cur = self
                    .selected
                    .as_deref()
                    .and_then(|id| vis.iter().position(|&i| self.flows[i].id == id));
                let page = usize::from(self.height.saturating_sub(10).max(1));
                let next = match (action, cur) {
                    (Action::Up, Some(c)) => c.saturating_sub(1),
                    (Action::Down, Some(c)) => (c + 1).min(vis.len() - 1),
                    (Action::PageUp, Some(c)) => c.saturating_sub(page),
                    (Action::PageDown, Some(c)) => (c + page).min(vis.len() - 1),
                    (Action::Home, _) => 0,
                    (Action::End, _) | (Action::Down, None) => vis.len() - 1,
                    (_, None) => vis.len() - 1,
                    (_, Some(c)) => c,
                };
                self.selected = Some(self.flows[vis[next]].id.clone());
                self.auto_select = false;
                self.inspector.reset_view();
                self.ensure_detail(out);
            }
        }
    }

    /// `]`/`[`: the Scope item filters the list (§2.7 "The flow list's
    /// `Scope` sidebar item filters to in-scope"); the panel is `S`/`:scope`.
    fn sidebar_step(&mut self, d: i32, out: &mut Vec<BusRequest>) {
        let mut next = step(&SidebarItem::ALL, self.sidebar, d);
        // Rows drawn only when the bus offers their verb (Scan: `scan.discover`;
        // L4: `l4.capture.status`) are skipped: never land on a row the
        // operator cannot see. Bounded to one lap.
        for _ in 0..SidebarItem::ALL.len() {
            if !self.sidebar_hidden(next) {
                break;
            }
            next = step(&SidebarItem::ALL, next, d);
        }
        self.sidebar = next;
        match self.sidebar {
            SidebarItem::Findings => self.mode = Mode::Findings,
            SidebarItem::Agent => self.mode = Mode::Agent,
            SidebarItem::Browser => out.extend(self.update(Action::OpenBrowser)),
            SidebarItem::Scan => out.extend(self.update(Action::OpenScan)),
            SidebarItem::L4 => out.extend(self.update(Action::OpenL4)),
            SidebarItem::Scripts => {
                self.mode = Mode::Flows;
                self.toast(Level::Info, "Scripts arrive with M3 (core follow-up F8)");
            }
            SidebarItem::Saved => {
                self.mode = Mode::Flows;
                self.toast(Level::Info, "Saved sessions need core follow-up F10");
            }
            _ => self.mode = Mode::Flows,
        }
    }

    /// Whether a sidebar row is not drawn on this bus (`ui::sidebar` draws
    /// Scan and L4 only when their verb is offered).
    fn sidebar_hidden(&self, it: SidebarItem) -> bool {
        match it {
            SidebarItem::Scan => !self.has_tool("scan.discover"),
            SidebarItem::L4 => !self.has_tool("l4.capture.status"),
            _ => false,
        }
    }

    fn tab_step(&mut self, d: i32) {
        // An L4 flow cycles its inspector panes (Packets / Craft / Intercept).
        if self.selected_row().is_some_and(|r| r.kind == FlowKind::L4) {
            let cur = crate::l4::L4Pane::ALL
                .iter()
                .position(|p| *p == self.l4.pane)
                .unwrap_or(0);
            let n = crate::l4::L4Pane::ALL.len() as i32;
            let next = (cur as i32 + d).rem_euclid(n) as usize;
            self.l4.pane = crate::l4::L4Pane::ALL[next];
            return;
        }
        let (tab, n) = match self.inspector.pane {
            Pane::Request => (&mut self.inspector.request_tab, REQUEST_TABS.len()),
            Pane::Response => (&mut self.inspector.response_tab, RESPONSE_TABS.len()),
        };
        *tab = (*tab as i32 + d).rem_euclid(n as i32) as usize;
        self.inspector.reset_view();
    }

    fn ensure_detail(&mut self, out: &mut Vec<BusRequest>) {
        if let Some(id) = self.selected.clone() {
            self.request_detail(&id, out);
        }
    }

    /// Ask the bus for `id`'s detail when it can answer (`flow.detail`, F5)
    /// and the app neither has it nor has given up on it.
    fn request_detail(&mut self, id: &str, out: &mut Vec<BusRequest>) {
        // L4 flows carry no `flow.detail`; the list poll brings their fields and
        // the inspector asks for the packet window (spec §2).
        if self.row(id).is_some_and(|r| r.kind == FlowKind::L4) {
            self.request_l4_window(id, out);
            return;
        }
        if self.has_tool("flow.detail")
            && !self.details.contains_key(id)
            && !self.detail_failed.contains(id)
        {
            out.push(BusRequest::Detail(id.to_string()));
        }
    }

    /// The core's `flow.get` summary of a WebSocket flow carries no
    /// authority, scheme or path — only the id of its 101 handshake flow
    /// (`capture.rs` `summarize`). When that flow is listed, the row takes
    /// its URL from it: `https` → `wss`, `http` → `ws`. Until then (or when
    /// the handshake was evicted) the authority stays empty and the row is
    /// out of scope.
    fn resolve_websocket_urls(&mut self) {
        let fixes: Vec<(usize, String, String, String)> = self
            .flows
            .iter()
            .enumerate()
            .filter(|(_, r)| r.kind == FlowKind::WebSocket && r.authority.is_empty())
            .filter_map(|(i, r)| {
                let h = self.row(r.handshake.as_deref()?)?;
                if h.authority.is_empty() {
                    return None;
                }
                let scheme = if h.scheme == "http" { "ws" } else { "wss" };
                Some((i, h.authority.clone(), h.path.clone(), scheme.to_string()))
            })
            .collect();
        for (i, authority, path, scheme) in fixes {
            if let Some(r) = self.flows.get_mut(i) {
                r.authority = authority;
                r.path = path;
                r.scheme = scheme;
            }
        }
    }

    /// Drop details for flows that are gone, then cap the map at
    /// [`MAX_DETAILS`] by evicting the oldest non-selected ones.
    fn prune_details(&mut self, seen: &HashSet<String>) {
        self.details.retain(|id, _| seen.contains(id));
        if self.details.len() <= MAX_DETAILS {
            return;
        }
        let selected = self.selected.clone();
        let mut over = self.details.len() - MAX_DETAILS;
        for r in &self.flows {
            if over == 0 {
                break;
            }
            if selected.as_deref() == Some(r.id.as_str()) {
                continue;
            }
            if self.details.remove(&r.id).is_some() {
                over -= 1;
            }
        }
    }

    /// Get the YAML of findings that have none yet (§2.7 "PoC panel … the
    /// YAML"): through `poc.get` (F13) when the bus has it — one request per
    /// path, none while one is in flight — else from `poc_path` on this
    /// machine, which only means something on a loopback bus. What an
    /// earlier pass got (or failed to get) for the same `poc_path` is carried
    /// over from `previous`, so a `poc.list` poll does not ask again.
    fn fill_finding_yaml(&mut self, previous: &[Finding], out: &mut Vec<BusRequest>) {
        let over_bus = self.has_tool("poc.get");
        let local = self.is_loopback_bus();
        for f in &mut self.findings {
            if f.yaml.is_some() || f.yaml_error.is_some() || f.poc_path.is_empty() {
                continue;
            }
            if let Some(p) = previous
                .iter()
                .find(|p| p.poc_path == f.poc_path && (p.yaml.is_some() || p.yaml_error.is_some()))
            {
                f.yaml = p.yaml.clone();
                f.yaml_error = p.yaml_error.clone();
                if f.description.is_none() {
                    f.description = p.description.clone();
                }
                continue;
            }
            if over_bus {
                if !self.poc_get_inflight.contains(&f.poc_path) {
                    self.poc_get_inflight.push_back(f.poc_path.clone());
                    out.push(BusRequest::PocGet(f.poc_path.clone()));
                }
            } else if local {
                match read_poc_yaml(&f.poc_path) {
                    Ok(y) => f.yaml = Some(y),
                    Err(e) => f.yaml_error = Some(e),
                }
            }
        }
    }

    /// Fold a `poc.list` pass (the library: files, none run) into the
    /// findings. A run result from this session keeps its verdict and is
    /// never dropped because the library pass omitted it; a library entry
    /// fills only paths with no run, and lends its description to a run that
    /// has none. Script findings are untouched.
    fn merge_library(&mut self, library: Vec<Finding>, out: &mut Vec<BusRequest>) {
        let previous = std::mem::take(&mut self.findings);
        let mut merged: Vec<Finding> = previous
            .iter()
            .filter(|f| f.ran)
            .cloned()
            .map(|mut f| {
                if f.description.is_none() {
                    if let Some(lib) = library
                        .iter()
                        .find(|l| !f.poc_path.is_empty() && l.poc_path == f.poc_path)
                    {
                        f.description = lib.description.clone();
                    }
                }
                f
            })
            .collect();
        for lib in library {
            if !merged
                .iter()
                .any(|f| !f.poc_path.is_empty() && f.poc_path == lib.poc_path)
            {
                merged.push(lib);
            }
        }
        self.findings = merged;
        self.finding_cursor = self
            .finding_cursor
            .min(self.findings.len().saturating_sub(1));
        self.fill_finding_yaml(&previous, out);
    }

    /// A `poc.run` result (or a PoC the TUI just wrote) takes the place of
    /// any entry for the same path and goes to the top.
    fn upsert_finding(&mut self, f: Finding, out: &mut Vec<BusRequest>) {
        let previous = std::mem::take(&mut self.findings);
        let mut kept: Vec<Finding> = previous
            .iter()
            .filter(|p| p.poc_path.is_empty() || p.poc_path != f.poc_path)
            .cloned()
            .collect();
        let mut f = f;
        if let Some(old) = previous.iter().find(|p| p.poc_path == f.poc_path) {
            // The library's title/description/YAML are about the file; a
            // run result names only the path, so keep them.
            if old.title != default_title(&old.poc_path) && f.title == default_title(&f.poc_path) {
                f.title = old.title.clone();
            }
            if f.description.is_none() {
                f.description = old.description.clone();
            }
        }
        kept.insert(0, f);
        self.findings = kept;
        self.finding_cursor = 0;
        self.fill_finding_yaml(&previous, out);
    }

    /// Ask `config.get` (F7) once, when the bus has it and nothing is held.
    fn ensure_config(&mut self, out: &mut Vec<BusRequest>) {
        if self.config.is_none() && self.has_tool("config.get") {
            out.push(BusRequest::Call {
                name: "config.get".into(),
                args: json!({}),
            });
        }
    }

    /// C12: write a built PoC's YAML under the PoC dir. Returns the path and
    /// a note for the toast when the dir was the temp fallback.
    fn write_poc(&self, yaml: &str, slug: &str) -> Result<(PathBuf, &'static str), String> {
        let (dir, note) = match self.poc_dir.clone().or_else(|| {
            self.config
                .as_ref()
                .and_then(|c| c.get("poc_dir"))
                .and_then(Value::as_str)
                .map(PathBuf::from)
        }) {
            Some(d) => (d, ""),
            None => (
                std::env::temp_dir().join("aitm-pocs"),
                " — no PoC dir configured, so it went under the temp dir; poc.run confined to \
                 poc.dir will refuse it (pass --poc-dir)",
            ),
        };
        std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        for n in 1..=MAX_POC_NAME_TRIES {
            let name = if n == 1 {
                format!("{slug}.yaml")
            } else {
                format!("{slug}-{n}.yaml")
            };
            let path = dir.join(name);
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(mut f) => {
                    f.write_all(yaml.as_bytes())
                        .map_err(|e| format!("{}: {e}", path.display()))?;
                    return Ok((path, note));
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(format!("{}: {e}", path.display())),
            }
        }
        Err(format!(
            "{}: {MAX_POC_NAME_TRIES} files already carry that name",
            dir.display()
        ))
    }

    /// The interface names the `:l4` completion offers: live state only, the
    /// `l4.scope.list` entries and the L4 flows (never a built-in list).
    pub fn l4_interfaces(&self) -> Vec<String> {
        let mut v: Vec<String> = self
            .l4
            .scope
            .iter()
            .map(|e| e.interface.clone())
            .chain(self.l4.flows.values().map(|f| f.interface.clone()))
            .filter(|i| !i.is_empty() && i != "any")
            .collect();
        v.sort();
        v.dedup();
        v
    }

    /// `:l4 capture <iface> [inbound|outbound]` (AC15): refused locally while
    /// `l4.capture.status` says unavailable (the toast carries the core's
    /// reason, so nothing that can only fail reaches the bus, AC33); else
    /// exactly one `l4.capture.start {interface, direction}`.
    fn l4_capture_start(&mut self, args: &str) -> Vec<BusRequest> {
        let mut words = args.split_whitespace();
        let Some(interface) = words.next() else {
            self.toast(Level::Error, L4_USAGE);
            return Vec::new();
        };
        let direction = match words.next() {
            None | Some("inbound") => "inbound",
            Some("outbound") => "outbound",
            Some(_) => {
                self.toast(Level::Error, "direction must be inbound or outbound");
                return Vec::new();
            }
        };
        if words.next().is_some() {
            self.toast(Level::Error, L4_USAGE);
            return Vec::new();
        }
        if let Some(t) = self.l4.capture.refusal("capture") {
            self.toast(Level::Warn, t);
            return Vec::new();
        }
        if !self.has_tool("l4.capture.start") {
            self.toast(Level::Warn, "l4.capture.start is not on this bus");
            return Vec::new();
        }
        vec![BusRequest::Call {
            name: "l4.capture.start".into(),
            args: json!({"interface": interface, "direction": direction}),
        }]
    }

    /// `:l4 stop [<id>]`: one `l4.capture.stop {id}` for the named capture, or
    /// one per running capture (the ids `l4.capture.status` reported). A typed
    /// id is refused locally while capture is unavailable, like the start (the
    /// verb is in the core's gated set; AC33); the bare form stops the ids the
    /// status itself listed, and an unavailable status lists none.
    fn l4_capture_stop(&mut self, id: &str) -> Vec<BusRequest> {
        let mut words = id.split_whitespace();
        let named = words.next();
        if words.next().is_some() {
            self.toast(Level::Error, L4_USAGE);
            return Vec::new();
        }
        let ids: Vec<String> = match named {
            Some(id) => {
                if let Some(t) = self.l4.capture.refusal("capture") {
                    self.toast(Level::Warn, t);
                    return Vec::new();
                }
                vec![id.to_string()]
            }
            None => self.l4.captures.clone(),
        };
        if ids.is_empty() {
            self.toast(Level::Info, "no running capture");
            return Vec::new();
        }
        if !self.has_tool("l4.capture.stop") {
            self.toast(Level::Warn, "l4.capture.stop is not on this bus");
            return Vec::new();
        }
        ids.into_iter()
            .map(|id| BusRequest::Call {
                name: "l4.capture.stop".into(),
                args: json!({"id": id}),
            })
            .collect()
    }

    /// Run a `:` command line.
    pub fn run_command(&mut self, line: &str) -> Vec<BusRequest> {
        let mut out = Vec::new();
        let line = line.trim().trim_start_matches(':');
        let mut parts = line.splitn(2, ' ');
        let cmd = parts.next().unwrap_or("");
        let rest = parts.next().unwrap_or("").trim();
        match cmd {
            "" => {}
            "q" | "quit" => self.should_quit = true,
            "help" | "?" => self.mode = Mode::Help,
            "import" => {
                if rest.is_empty() {
                    self.toast(
                        Level::Error,
                        "usage: :import <path>  (HAR / mitmproxy / Proxyman)",
                    );
                } else if self.has_tool("flow.import") {
                    out.push(BusRequest::Import(rest.to_string()));
                } else {
                    self.toast(Level::Warn, "Import needs core follow-up F10 (flow.import)");
                }
            }
            "layout" => {
                self.layout = match rest {
                    "v" | "vertical" | "right" => Layout::Vertical,
                    _ => Layout::Horizontal,
                }
            }
            "sidebar" => self.sidebar_open = !self.sidebar_open,
            "filter" => match filter::parse(rest) {
                Ok(expr) => {
                    self.filter = expr;
                    self.filter_text = rest.to_string();
                }
                Err(e) => self.toast(Level::Error, format!("filter: {e}")),
            },
            "scope" => {
                let mut p = rest.splitn(2, ' ');
                match (p.next().unwrap_or(""), p.next().unwrap_or("").trim()) {
                    // `:scope add l4 …` is the operator L4 scope add (spec §3);
                    // a host that happens to start with "l4" is not it.
                    ("add", h) if h == "l4" || h.starts_with("l4 ") => {
                        out.extend(self.l4_scope_add(h.strip_prefix("l4").unwrap_or("")));
                    }
                    ("add", h) if !h.is_empty() => out.push(BusRequest::ScopeAdd(h.to_string())),
                    ("rm", h) | ("remove", h) if !h.is_empty() => {
                        if self.has_tool("scope.remove") {
                            self.pending_scope_removals.push_back(h.to_string());
                            out.push(BusRequest::ScopeRemove(h.to_string()));
                        } else {
                            self.toast(Level::Warn, "scope.remove needs core follow-up F12");
                        }
                    }
                    _ => {
                        self.mode = Mode::Scope;
                        self.ensure_config(&mut out);
                    }
                }
            }
            "config" => {
                self.mode = Mode::Config;
                if self.has_tool("config.get") {
                    out.push(BusRequest::Call {
                        name: "config.get".into(),
                        args: json!({}),
                    });
                } else {
                    self.toast(
                        Level::Warn,
                        "Config view needs core follow-up F7 (config.get)",
                    );
                }
            }
            "agent" => match AgentPolicy::parse(rest) {
                Some(p) => out.extend(self.update(Action::AgentSet(p))),
                None => self.mode = Mode::Agent,
            },
            "intercept" => {
                let on = !matches!(rest, "off" | "false" | "disarm");
                self.intercept_armed = on;
                out.push(BusRequest::Intercept(on));
            }
            "resume" => out.extend(self.update(if rest == "all" {
                Action::ResumeAll
            } else {
                Action::Resume
            })),
            "kill" => out.extend(self.update(Action::Kill)),
            "replay" | "repeat" => out.extend(self.update(Action::Replay)),
            // `:compose` prefills from the selection; `:compose <template>`
            // starts from a template (§2.7 "Templates").
            "compose" | "new" if rest.is_empty() => out.extend(self.update(Action::Compose)),
            "compose" | "new" => match rest {
                "ws" | "websocket" => self.toast(
                    Level::Warn,
                    "WebSocket compose needs core follow-up F9 (ws.inject)",
                ),
                other => match ComposeForm::template(other) {
                    Some(f) => {
                        self.compose = f;
                        self.mode = Mode::Compose;
                    }
                    None => self.toast(
                        Level::Error,
                        format!(
                            "unknown compose template `{other}` (get · post-json · post-form · ws)"
                        ),
                    ),
                },
            },
            "split" => self.toast(
                Level::Info,
                format!("split view: not built in this pass (needs ≥ {SPLIT_COLS} cols)"),
            ),
            "export" => self.toast(
                Level::Warn,
                "Export needs core follow-up F10 (flow.export); findings export F13",
            ),
            "ca" => {
                self.mode = Mode::Ca;
                self.ask_ca_status(&mut out);
            }
            "browser" => out.extend(self.update(Action::OpenBrowser)),
            // `:l4` opens the L4 panel; `:l4 capture <iface> [dir]` and
            // `:l4 stop [<id>]` are the capture controls (L4 parity AC15).
            "l4" => {
                let mut p = rest.splitn(2, ' ');
                match (p.next().unwrap_or(""), p.next().unwrap_or("").trim()) {
                    ("", _) => out.extend(self.update(Action::OpenL4)),
                    ("capture", args) => out.extend(self.l4_capture_start(args)),
                    ("stop", id) => out.extend(self.l4_capture_stop(id)),
                    _ => self.toast(Level::Error, L4_USAGE),
                }
            }
            // `:scan` opens the Scan view only (viewing never crawls; `r`
            // launches); `:scan <host>` opens it and crawls that host,
            // scope-gated.
            "scan" => {
                out.extend(self.update(Action::OpenScan));
                if !rest.is_empty() {
                    if self.scan.running {
                        self.toast(Level::Info, "a scan is already running");
                    } else {
                        self.scan_launch(Some(rest.to_string()), &mut out);
                    }
                }
            }
            "curl" => match ComposeForm::from_curl(line) {
                Some(f) => {
                    self.compose = f;
                    self.mode = Mode::Compose;
                }
                None => self.toast(Level::Error, "could not parse that curl command line"),
            },
            "pin" => {
                if rest.is_empty() {
                    out.extend(self.update(Action::Pin));
                } else if !self.pinned_hosts.iter().any(|h| h == rest) {
                    self.pinned_hosts.push(rest.to_string());
                }
            }
            "clear" => {
                if self.has_tool("flow.clear") {
                    out.push(BusRequest::ClearFlows);
                } else {
                    self.toast(Level::Warn, "Clear needs core follow-up F7 (flow.clear)");
                }
            }
            // F7: two tools, each checked on its own.
            "pause" | "record" => {
                let pause = cmd == "pause";
                let tool = if pause { "proxy.pause" } else { "proxy.resume" };
                if self.has_tool(tool) {
                    out.push(BusRequest::ProxyPause(pause));
                } else {
                    self.toast(
                        Level::Warn,
                        format!("{} needs core follow-up F7 ({tool})", title_case(cmd)),
                    );
                }
            }
            // D14: the OS system proxy. One gate for the three verbs: a core
            // with `proxy.system.set` has them all. `on` sends `{}` so the
            // config's bypass list applies; `status` only reads.
            "sysproxy" => {
                let tool = match rest {
                    "on" => "proxy.system.set",
                    "off" => "proxy.system.unset",
                    "status" => "proxy.system.status",
                    _ => {
                        self.toast(Level::Error, "usage: :sysproxy on|off|status");
                        return out;
                    }
                };
                if !self.has_tool("proxy.system.set") {
                    self.toast(
                        Level::Warn,
                        "System proxy needs the core's proxy.system.* verbs",
                    );
                    return out;
                }
                if tool != "proxy.system.status" && !self.sysproxy_begin_change() {
                    return out;
                }
                out.push(BusRequest::Call {
                    name: tool.into(),
                    args: json!({}),
                });
            }
            "findings" | "poc" => {
                if let Some(spec) = rest.strip_prefix("run ") {
                    let mut p = spec.splitn(2, ' ');
                    let path = p.next().unwrap_or("").to_string();
                    let target = p
                        .next()
                        .map(|t| t.trim().to_string())
                        .filter(|t| !t.is_empty());
                    out.push(BusRequest::PocRun {
                        poc_path: path,
                        target,
                        vars: None,
                    });
                } else if rest == "build" {
                    out.extend(self.update(Action::BuildPoc));
                } else {
                    self.mode = Mode::Findings;
                }
            }
            "copy" => out.extend(self.update(Action::CopyUrl)),
            "auto" | "autoselect" => out.extend(self.update(Action::ToggleAutoSelect)),
            "refresh" => out.push(BusRequest::Refresh),
            tool if self.has_tool(tool) => {
                match parse_kv_args(rest, self.tools.iter().find(|t| t.name == tool)) {
                    Ok(args) => out.extend(self.call_tool(tool, args)),
                    Err(e) => self.toast(Level::Error, format!("{tool}: {e}")),
                }
            }
            // The CA panel's `i`/`u` run these by name; without the CA
            // plugin the bus has no `ca.*` and the answer names that, not
            // "unknown command".
            tool if tool.starts_with("ca.") => self.toast(
                Level::Warn,
                format!("{tool} is not on this bus (needs the CA plugin)"),
            ),
            other => self.toast(
                Level::Error,
                format!("unknown command `{other}` (try :help)"),
            ),
        }
        out
    }

    // ----------------------------------------------------------- bus events

    /// Fold a bus event in; may ask for more work (details for new rows).
    pub fn on_bus(&mut self, event: BusEvent) -> Vec<BusRequest> {
        let mut out = Vec::new();
        match event {
            BusEvent::Connected {
                server,
                tools,
                role,
            } => {
                self.bus = BusStatus::Connected {
                    server,
                    address: self.bus_address.clone(),
                    role,
                };
                self.tools = tools;
                if self.role_mismatch() {
                    let resolved = self.resolved_role().unwrap_or("unknown");
                    let expected = self.expect_role.as_deref().unwrap_or("");
                    self.toast(
                        Level::Warn,
                        format!(
                            "expected to connect as {expected}, but the bus resolved this token as {resolved}"
                        ),
                    );
                }
                // A (re)connect is a new session: nothing sent before it
                // will be answered — including a `proxy.system.set|unset`
                // whose reply would have settled the pill.
                self.forget_inflight();
                out.push(BusRequest::Refresh);
                self.ask_ca_status(&mut out);
            }
            BusEvent::ProxyStatus(s) => {
                if s.address.is_some() {
                    self.listening = s.address;
                }
                self.serving = Some(s.listening);
                self.intercept_armed = s.intercept_armed;
                self.capture_paused = !s.capturing;
                self.store_paused = Some(s.paused);
                self.system_proxy = s.system_proxy;
            }
            BusEvent::ScriptFindings(list) => {
                self.findings.retain(|f| f.script.is_none());
                self.findings.extend(list);
                self.finding_cursor = self
                    .finding_cursor
                    .min(self.findings.len().saturating_sub(1));
            }
            BusEvent::Disconnected(why) => {
                self.bus = BusStatus::Disconnected(why.clone());
                self.forget_inflight();
                self.toast(Level::Error, format!("bus: {why}"));
            }
            BusEvent::Flows(summaries) => {
                let had = self.flows.len();
                let mut seen: HashSet<String> = HashSet::with_capacity(summaries.len());
                for s in &summaries {
                    let Some(id) = s.get("id").and_then(Value::as_str) else {
                        continue;
                    };
                    seen.insert(id.to_string());
                    if let Some(&i) = self.index.get(id) {
                        let existing = &mut self.flows[i];
                        if let Some(fresh) = FlowRow::from_summary(s, existing.seq) {
                            let changed = fresh.status != existing.status
                                || fresh.intercept != existing.intercept;
                            existing.status = fresh.status.or(existing.status);
                            existing.intercept = fresh.intercept;
                            existing.is_replay |= fresh.is_replay;
                            existing.ws_messages = fresh.ws_messages.or(existing.ws_messages);
                            // A state change makes the detail stale: drop it
                            // and ask again (when the bus can answer).
                            if changed && self.details.remove(id).is_some() {
                                self.request_detail(id, &mut out);
                            }
                        }
                    } else if let Some(row) = FlowRow::from_summary(s, self.next_seq) {
                        self.next_seq += 1;
                        self.request_detail(&row.id, &mut out);
                        self.index.insert(row.id.clone(), self.flows.len());
                        self.flows.push(row);
                    }
                }
                let before = self.flows.len();
                // Keep L4 rows: they are refreshed by the separate `l4.*` pass.
                self.flows
                    .retain(|r| r.kind == FlowKind::L4 || seen.contains(&r.id));
                if self.flows.len() != before {
                    self.rebuild_index();
                }
                self.resolve_websocket_urls();
                self.prune_details(&seen);
                self.detail_failed.retain(|id| seen.contains(id));
                if self
                    .selected
                    .as_deref()
                    .is_some_and(|id| self.row(id).is_none())
                {
                    self.selected = None;
                }
                if self.flows.len() > had && (self.auto_select || self.selected.is_none()) {
                    if let Some(last) = self.visible().last().map(|&i| self.flows[i].id.clone()) {
                        self.selected = Some(last);
                    }
                }
            }
            BusEvent::Detail(d) => {
                if let Some(row) = self.row_mut(&d.id) {
                    row.apply_detail(&d);
                }
                self.detail_failed.remove(&d.id);
                self.details.insert(d.id.clone(), *d);
            }
            BusEvent::DetailFailed(id) => {
                self.toast(
                    Level::Warn,
                    format!("flow.detail {id}: malformed reply — not asking again"),
                );
                self.detail_failed.insert(id);
            }
            BusEvent::Intercept(armed) => self.intercept_armed = armed,
            BusEvent::Scope(entries) => self.scope = entries,
            // A pass over `l4.flow.list` + `l4.flow.get`: upsert L4 rows into the
            // union flow list and keep the full packet logs in `self.l4.flows`.
            BusEvent::L4Flows(values) => {
                let mut seen: HashSet<String> = HashSet::with_capacity(values.len());
                let parsed: Vec<crate::l4::L4Flow> = values
                    .iter()
                    .filter_map(crate::l4::L4Flow::from_json)
                    .collect();
                for f in parsed {
                    seen.insert(f.id.clone());
                    self.upsert_l4_flow(f, &mut out);
                }
                let before = self.flows.len();
                self.flows
                    .retain(|r| r.kind != FlowKind::L4 || seen.contains(&r.id));
                if self.flows.len() != before {
                    self.rebuild_index();
                }
                self.l4.flows.retain(|id, _| seen.contains(id));
                if self
                    .selected
                    .as_deref()
                    .is_some_and(|id| self.row(id).is_none())
                {
                    self.selected = None;
                }
                let packets = self.selected_l4().map_or(0, |f| f.packets.len());
                self.l4.packet_cursor = self.l4.packet_cursor.min(packets.saturating_sub(1));
            }
            BusEvent::L4Scope(entries) => {
                self.l4.scope = entries
                    .iter()
                    .filter_map(crate::l4::L4ScopeEntry::from_json)
                    .collect();
            }
            BusEvent::L4Agent(v) => self.l4.gates = crate::l4::L4Gates::from_json(&v),
            // Spec §1: availability is whatever the core said last; a change
            // never toasts (the panel and the bars show it).
            BusEvent::L4Availability {
                capture,
                intercept,
                captures,
            } => {
                self.l4.capture = capture;
                self.l4.intercept = intercept;
                self.l4.captures = captures;
            }
            // Spec §4: the parked packets in the core's order (oldest first).
            BusEvent::L4Parked(values) => {
                self.l4.parked = values
                    .iter()
                    .filter_map(crate::l4::L4Parked::from_json)
                    .collect();
            }
            BusEvent::Findings(library) => self.merge_library(library, &mut out),
            BusEvent::Agent(a) => self.agent = a,
            BusEvent::CallOk { name, value } => {
                match name.as_str() {
                    "flow.replay" | "request.send" => {
                        if let Some(id) = value.as_str() {
                            self.selected = Some(id.to_string());
                        }
                        self.toast(
                            Level::Info,
                            format!("{name} → new flow {}", value.as_str().unwrap_or("?")),
                        );
                    }
                    // C12: the core answers with the PoC's YAML text, not a
                    // path — the TUI writes the file and lists it.
                    "poc.build" => {
                        let slug = self
                            .poc_build_pending
                            .pop_front()
                            .unwrap_or_else(|| "poc".into());
                        match value.as_str() {
                            Some(text) if looks_like_yaml(text) => {
                                match self.write_poc(text, &slug) {
                                    Ok((path, note)) => {
                                        self.toast(
                                            Level::Info,
                                            format!("PoC written: {}{note}", path.display()),
                                        );
                                        let f = Finding {
                                            title: yaml_field(text, "name")
                                                .unwrap_or_else(|| slug.clone()),
                                            severity: yaml_field(text, "severity")
                                                .map_or(Severity::Info, |s| Severity::parse(&s)),
                                            target: String::new(),
                                            ran: false,
                                            passed: false,
                                            when: String::new(),
                                            origin: crate::model::Origin::Human,
                                            poc_path: path.to_string_lossy().into_owned(),
                                            description: yaml_field(text, "description"),
                                            script: None,
                                            finding_capture: None,
                                            screenshot_path: None,
                                            assertions: Vec::new(),
                                            yaml: Some(text.to_string()),
                                            yaml_error: None,
                                        };
                                        self.upsert_finding(f, &mut out);
                                    }
                                    Err(e) => self.toast(
                                        Level::Error,
                                        format!("could not write the PoC: {e}"),
                                    ),
                                }
                            }
                            Some(path) => {
                                self.toast(Level::Info, format!("PoC written: {path}"));
                            }
                            None => self.toast(Level::Info, "PoC written: ?"),
                        }
                    }
                    "poc.run" => {
                        if let Some(f) = Finding::from_json(&value) {
                            let verdict = if f.passed { "passed" } else { "failed" };
                            self.toast(Level::Info, format!("PoC {verdict}: {}", f.title));
                            self.upsert_finding(f, &mut out);
                        }
                    }
                    "poc.get" => {
                        let path = value
                            .get("poc_path")
                            .and_then(Value::as_str)
                            .map(str::to_string);
                        if let Some(p) = &path {
                            self.poc_get_inflight.retain(|x| x != p);
                            for f in self.findings.iter_mut().filter(|f| &f.poc_path == p) {
                                f.yaml = value
                                    .get("yaml")
                                    .and_then(Value::as_str)
                                    .map(str::to_string)
                                    .or_else(|| f.yaml.clone());
                                if let Some(d) = value.get("description").and_then(Value::as_str) {
                                    f.description = Some(d.to_string());
                                }
                            }
                        }
                        return out;
                    }
                    "poc.artifact" => {
                        let p = self.pending_artifact.take().unwrap_or_default();
                        match value.as_str().and_then(crate::base64::decode) {
                            Some(bytes) if crate::viewers::image::dimensions(&bytes).is_some() => {
                                match open::body_to_temp_file("poc-screenshot", "png", &bytes) {
                                    Ok(path) => {
                                        self.toast(Level::Info, format!("opening screenshot {p}"));
                                        self.pending_open = Some(OpenTarget {
                                            path,
                                            label: format!("screenshot {p}"),
                                        });
                                    }
                                    Err(e) => self.toast(
                                        Level::Error,
                                        format!("could not write the screenshot: {e}"),
                                    ),
                                }
                            }
                            _ => self
                                .toast(Level::Warn, format!("poc.artifact: {p} is not an image")),
                        }
                        return out;
                    }
                    "config.get" => {
                        self.config = Some(value);
                        return out;
                    }
                    "ca.status" => {
                        self.ca_status = Some(value);
                        return out;
                    }
                    "ca.export" => self.toast(
                        Level::Info,
                        format!("CA exported: {}", value.as_str().unwrap_or("ok")),
                    ),
                    "ca.install" | "ca.uninstall" => {
                        self.ca_installing = false;
                        let text = match &value {
                            Value::Null => "ok".to_string(),
                            other => value_text(other),
                        };
                        self.toast(Level::Info, format!("{name}: {text}"));
                        self.ask_ca_status(&mut out);
                    }
                    "flow.mutate" => self.toast(Level::Info, "Edit applied"),
                    "flow.resume" => self.toast(Level::Info, "Resumed"),
                    "flow.kill" => self.toast(Level::Info, "Killed"),
                    "flow.intercept" => {
                        // M6 F3: `flow.intercept` now returns `{enabled, rules}`
                        // (was a bare bool). Read `enabled`; tolerate the old bool
                        // shape so a mixed-version bus does not wedge the toggle.
                        self.intercept_armed = value
                            .get("enabled")
                            .and_then(Value::as_bool)
                            .or_else(|| value.as_bool())
                            .unwrap_or(self.intercept_armed);
                        let msg = if self.intercept_armed {
                            "Intercept armed — every request pauses"
                        } else {
                            "Intercept disarmed"
                        };
                        self.toast(Level::Info, msg);
                    }
                    "scope.add" => self.toast(
                        Level::Info,
                        format!("Scope + {}", value.as_str().unwrap_or("?")),
                    ),
                    // F12: a bool; the host is the one we asked about.
                    "scope.remove" => {
                        let host = self
                            .pending_scope_removals
                            .pop_front()
                            .unwrap_or_else(|| "?".into());
                        if value.as_bool() == Some(true) {
                            self.scope.retain(|h| *h != host);
                            self.scope_cursor =
                                self.scope_cursor.min(self.scope.len().saturating_sub(1));
                            self.toast(Level::Info, format!("removed {host}"));
                        } else {
                            self.toast(Level::Info, format!("{host} was not in scope"));
                        }
                    }
                    // F7: both answer the capture state.
                    "proxy.pause" | "proxy.resume" => {
                        let capturing = value
                            .get("capturing")
                            .and_then(Value::as_bool)
                            .unwrap_or(name == "proxy.resume");
                        self.capture_paused = !capturing;
                        let msg = if capturing {
                            "capture resumed"
                        } else {
                            "capture paused"
                        };
                        self.toast(Level::Info, msg);
                    }
                    // D14: the reply is the full status object; its word
                    // replaces the last poll's and its `detail` is the toast.
                    "proxy.system.set" | "proxy.system.unset" => {
                        self.sysproxy_setting = false;
                        if let Some(word) = SystemProxyWord::from_json(&value) {
                            self.system_proxy = Some(word);
                        }
                        self.toast(Level::Info, sysproxy_detail(&name, &value));
                    }
                    // A status reply is a read: it refreshes the word when it
                    // parses but never settles our in-flight flag.
                    "proxy.system.status" => {
                        if let Some(word) = SystemProxyWord::from_json(&value) {
                            self.system_proxy = Some(word);
                        }
                        self.toast(Level::Info, sysproxy_detail(&name, &value));
                    }
                    "flow.clear" => {
                        let n = |k: &str| value.get(k).and_then(Value::as_u64).unwrap_or(0);
                        self.toast(
                            Level::Info,
                            format!(
                                "cleared {} flows · {} in flight kept",
                                n("cleared"),
                                n("skipped_in_flight")
                            ),
                        );
                    }
                    // F6: the row's swatch and comment come from its detail,
                    // which is now stale — drop it and ask again.
                    "flow.mark" | "flow.comment" => {
                        let msg = match (name.as_str(), &value) {
                            ("flow.mark", Value::Array(marks)) if marks.is_empty() => {
                                "marks cleared".to_string()
                            }
                            ("flow.mark", Value::Array(marks)) => format!(
                                "marked: {}",
                                marks
                                    .iter()
                                    .filter_map(Value::as_str)
                                    .collect::<Vec<_>>()
                                    .join(" ")
                            ),
                            ("flow.mark", _) => "marks saved".to_string(),
                            (_, Value::Null) => "comment cleared".to_string(),
                            _ => "comment saved".to_string(),
                        };
                        self.toast(Level::Info, msg);
                        if let Some(id) = self.selected.clone() {
                            self.details.remove(&id);
                            self.request_detail(&id, &mut out);
                        }
                    }
                    // The inspector's packet window (spec §2): fold it, no toast.
                    "l4.flow.get" => {
                        if let Some(f) = crate::l4::L4Flow::from_json(&value) {
                            self.upsert_l4_flow(f, &mut out);
                            let packets = self.selected_l4().map_or(0, |f| f.packets.len());
                            self.l4.packet_cursor =
                                self.l4.packet_cursor.min(packets.saturating_sub(1));
                        }
                        return out;
                    }
                    // L4 craft build() → the hex preview (L4OPS-AC8).
                    "l4.craft" => {
                        let bytes = value
                            .get("bytes")
                            .and_then(Value::as_str)
                            .and_then(crate::base64::decode);
                        let layers = value
                            .get("summary")
                            .and_then(|s| s.get("layers"))
                            .and_then(Value::as_array)
                            .map(|a| {
                                a.iter()
                                    .filter_map(|l| l.as_str().map(str::to_string))
                                    .collect()
                            })
                            .unwrap_or_default();
                        match bytes {
                            Some(b) => {
                                self.toast(Level::Info, format!("craft built: {} bytes", b.len()));
                                self.l4.craft.preview = Some(b);
                                self.l4.craft.preview_layers = layers;
                                self.l4.craft.error = None;
                            }
                            None => {
                                self.l4.craft.error = Some("l4.craft returned no bytes".into());
                            }
                        }
                        return out;
                    }
                    // The L4 guarded verbs (L4OPS-AC10; L4 parity spec §3):
                    // a `needs_confirmation` reply opens the confirm overlay
                    // **for the pending call of the same name only** — the
                    // overlay is the operator's trust point, so what it shows
                    // is what `y` sends. A handshake with nothing pending for
                    // its name (the generic tool form never sets `pending`)
                    // opens nothing; one without a token is malformed, not a
                    // success. A plain reply is the verb's success.
                    "l4.inject"
                    | "l4.send_recv"
                    | "l4.intercept.forward"
                    | "l4.intercept.drop"
                    | "l4.scope.add" => {
                        let pending = match self.l4.pending.take() {
                            Some((call, args)) if call == *name => Some((call, args)),
                            other => {
                                self.l4.pending = other;
                                None
                            }
                        };
                        let bound = pending.is_some();
                        let (call, args) = pending.unwrap_or((name.clone(), Value::Null));
                        match crate::l4::L4Confirm::classify(&call, &args, &value) {
                            crate::l4::ConfirmReply::Malformed => {
                                self.toast(
                                    Level::Warn,
                                    format!("{name}: malformed confirmation reply (no token)"),
                                );
                                return out;
                            }
                            crate::l4::ConfirmReply::Handshake(_) if !bound => {
                                self.toast(
                                    Level::Warn,
                                    format!(
                                        "{name} needs confirmation: re-run it from the L4 controls"
                                    ),
                                );
                                return out;
                            }
                            crate::l4::ConfirmReply::Handshake(confirm) => {
                                self.l4.confirm = Some(confirm);
                                self.mode = Mode::L4Confirm;
                                return out;
                            }
                            crate::l4::ConfirmReply::Plain => {}
                        }
                        match name.as_str() {
                            // The confirmed scope add's reply is the new id;
                            // the scope is re-read so the panel shows it now.
                            "l4.scope.add" => {
                                let shown: String = value_text(&value).chars().take(60).collect();
                                self.toast(Level::Info, format!("L4 scope + {shown}"));
                                if self.has_tool("l4.scope.list") {
                                    out.push(BusRequest::Call {
                                        name: "l4.scope.list".into(),
                                        args: json!({}),
                                    });
                                }
                            }
                            _ => {
                                let shown: String = value_text(&value).chars().take(120).collect();
                                self.toast(Level::Info, format!("{name}: {shown}"));
                            }
                        }
                    }
                    // A direct `l4.scope.list` read (after a scope add): the
                    // same fold as the slow poll's, silently.
                    "l4.scope.list" => {
                        if let Value::Array(entries) = &value {
                            self.l4.scope = entries
                                .iter()
                                .filter_map(crate::l4::L4ScopeEntry::from_json)
                                .collect();
                        }
                        return out;
                    }
                    // L4 agent gate set/status reply: the four gate states.
                    "l4.agent.set" => {
                        self.l4.gates = crate::l4::L4Gates::from_json(&value);
                        self.toast(Level::Info, "L4 agent gate updated");
                    }
                    // Scanner Stage 1: the crawl result — reached endpoints and
                    // the injection points enumerated from captured requests.
                    "scan.discover" => {
                        self.scan.running = false;
                        self.scan.error = None;
                        self.scan.endpoints = value
                            .get("endpoints")
                            .and_then(Value::as_array)
                            .map(|a| {
                                a.iter()
                                    .filter_map(|v| v.as_str().map(str::to_string))
                                    .collect()
                            })
                            .unwrap_or_default();
                        // AC3: endpoint URL → flow id. Keep only string→string
                        // pairs; a missing or garbage map leaves it empty.
                        self.scan.endpoint_flows = value
                            .get("endpoint_flows")
                            .and_then(Value::as_object)
                            .map(|m| {
                                m.iter()
                                    .filter_map(|(k, v)| {
                                        v.as_str().map(|s| (k.clone(), s.to_string()))
                                    })
                                    .collect()
                            })
                            .unwrap_or_default();
                        self.scan.points = value
                            .get("injection_points")
                            .and_then(Value::as_array)
                            .map(|a| a.iter().map(InjectionPointRow::from_json).collect())
                            .unwrap_or_default();
                        self.scan.cursor = self
                            .scan
                            .cursor
                            .min(self.scan.points.len().saturating_sub(1));
                        self.scan.endpoint_cursor = self
                            .scan
                            .endpoint_cursor
                            .min(self.scan.endpoints.len().saturating_sub(1));
                        self.toast(
                            Level::Info,
                            format!(
                                "scan.discover → {} endpoints · {} injection points",
                                self.scan.endpoints.len(),
                                self.scan.points.len()
                            ),
                        );
                    }
                    n if is_tracked_browser_call(n) => {
                        self.browser_settled();
                        self.on_browser_ok(n, &value, &mut out);
                    }
                    _ => {
                        let text = match &value {
                            Value::Null => "ok".to_string(),
                            other => value_text(other),
                        };
                        let shown: String = text.chars().take(160).collect();
                        self.toast(Level::Info, format!("{name}: {shown}"));
                    }
                }
                out.push(BusRequest::Refresh);
            }
            BusEvent::CallFailed { name, message } => {
                // A failed tracked `browser.*` call is the view's answer: the
                // panel must show it (§2.10(c)), not only the status line.
                if is_tracked_browser_call(&name) {
                    self.browser_settled();
                    self.browser.error = Some(message.clone());
                }
                match name.as_str() {
                    // The reply names no path: it settles the oldest ask.
                    "poc.get" => {
                        if let Some(p) = self.poc_get_inflight.pop_front() {
                            for f in self.findings.iter_mut().filter(|f| f.poc_path == p) {
                                f.yaml_error = Some(message.clone());
                            }
                        }
                    }
                    "scope.remove" => {
                        self.pending_scope_removals.pop_front();
                    }
                    "poc.artifact" => self.pending_artifact = None,
                    "poc.build" => {
                        self.poc_build_pending.pop_front();
                    }
                    // D17.4/D17.5: the word comes from the read-back, so every
                    // reply re-asks; a dismissed OS dialog is information.
                    "ca.install" | "ca.uninstall" => {
                        self.ca_installing = false;
                        self.ask_ca_status(&mut out);
                        if message.starts_with("ca.install cancelled")
                            || message.starts_with("ca.uninstall cancelled")
                        {
                            self.toast(Level::Info, "CA trust cancelled");
                            return out;
                        }
                    }
                    // A guard refusal (out-of-scope / rate / denylist / oversize /
                    // count) is surfaced verbatim; drop the pending confirm —
                    // only the one this failure names, so a foreign verb's
                    // failure leaves another control's pending call in place
                    // (symmetric with the `CallOk` take above).
                    "l4.inject"
                    | "l4.send_recv"
                    | "l4.intercept.forward"
                    | "l4.intercept.drop"
                    | "l4.scope.add" => {
                        if matches!(&self.l4.pending, Some((c, _)) if *c == name) {
                            self.l4.pending = None;
                        }
                    }
                    // A refused or failed crawl clears the running flag and keeps
                    // the reason in the Scan view until the next launch.
                    "scan.discover" => {
                        self.scan.running = false;
                        self.scan.error = Some(message.clone());
                    }
                    // D14: a refusal (agent-token bus) or a failed write
                    // settles the in-flight pill; the text below is verbatim.
                    "proxy.system.set" | "proxy.system.unset" => {
                        self.sysproxy_setting = false;
                    }
                    _ => {}
                }
                self.toast(Level::Error, message);
            }
            BusEvent::Toast(level, text) => self.toast(level, text),
            // An F4 push: whatever it says, the list is stale; poll now.
            BusEvent::Notification(_) => out.push(BusRequest::Refresh),
        }
        out
    }

    /// A `browser.*` call answered: fill the view. A navigate re-reads the
    /// page (DOM and screenshot) when the bus offers those calls, keeping the
    /// last ones on screen until the new ones land (§2.8: no layout shift).
    fn on_browser_ok(&mut self, name: &str, value: &Value, out: &mut Vec<BusRequest>) {
        match name {
            "browser.navigate" => {
                let url = value
                    .get("final_url")
                    .and_then(Value::as_str)
                    .map(str::to_string)
                    .or_else(|| self.browser.pending_url.take());
                if let Some(url) = url {
                    self.browser.url = url;
                }
                let status = value
                    .get("status")
                    .and_then(Value::as_u64)
                    .map_or(String::new(), |s| format!(" ({s})"));
                self.toast(
                    Level::Info,
                    format!("navigated: {}{status}", self.browser.url),
                );
                let mut asked = false;
                if self.has_tool("browser.get_dom") {
                    asked |= self.browser_call("browser.get_dom", json!({}), out);
                }
                if self.has_tool("browser.screenshot") {
                    asked |= self.browser_call("browser.screenshot", json!({}), out);
                }
                if asked {
                    self.browser.busy = Some("loading the page");
                }
            }
            "browser.get_dom" => {
                let html = value_text(value);
                self.browser.dom_outline = crate::ui::browser::outline(&html);
                self.browser.dom_cursor = self
                    .browser
                    .dom_cursor
                    .min(self.browser.dom_outline.len().saturating_sub(1));
                self.browser.dom = Some(html);
            }
            "browser.screenshot" => match value.as_str().and_then(crate::base64::decode) {
                Some(bytes) if !bytes.is_empty() => {
                    let (width, height, format) =
                        crate::viewers::image::dimensions(&bytes).unwrap_or((0, 0, "image"));
                    self.browser.screenshot = Some(Screenshot {
                        width,
                        height,
                        format,
                        bytes,
                    });
                }
                _ => {
                    self.browser.error =
                        Some("browser.screenshot: the result is not image bytes".into());
                }
            },
            "browser.eval" => self.browser.last_eval = Some(value_text(value)),
            _ => self.toast(Level::Info, format!("{name}: ok")),
        }
    }
}

/// Whether `path` is a regular file whose first bytes are an image header
/// [`crate::viewers::image::dimensions`] recognises — what Findings `o` is
/// willing to hand to the desktop. Judged on the opened handle, like
/// [`read_poc_yaml`]; a file that cannot be opened is not an image either.
fn is_image_file(path: &Path) -> bool {
    let Ok(file) = File::open(path) else {
        return false;
    };
    if !file.metadata().is_ok_and(|m| m.is_file()) {
        return false;
    }
    let mut head = Vec::with_capacity(32);
    if file.take(32).read_to_end(&mut head).is_err() {
        return false;
    }
    crate::viewers::image::dimensions(&head).is_some()
}

/// A finding's YAML from `poc_path`, when that is a regular `.yaml`/`.yml`
/// file of at most [`MAX_POC_YAML_BYTES`] (the path is the bus's word, read
/// only on a loopback bus); `Err` is the reason the panel shows.
fn read_poc_yaml(path: &str) -> Result<String, String> {
    let p = Path::new(path);
    let is_yaml = p
        .extension()
        .and_then(OsStr::to_str)
        .is_some_and(|e| e.eq_ignore_ascii_case("yaml") || e.eq_ignore_ascii_case("yml"));
    if !is_yaml {
        return Err("not a .yaml/.yml file".to_string());
    }
    // Open first, then judge the handle: the file-kind and size checks and
    // the read all see the same inode, so nothing can be swapped in between.
    let file = File::open(p).map_err(|e| e.to_string())?;
    let meta = file.metadata().map_err(|e| e.to_string())?;
    if !meta.is_file() {
        return Err("not a regular file".to_string());
    }
    if meta.len() > MAX_POC_YAML_BYTES {
        return Err(format!(
            "{} is over the 256 KiB cap",
            human_bytes(meta.len())
        ));
    }
    let mut text = String::new();
    file.take(MAX_POC_YAML_BYTES)
        .read_to_string(&mut text)
        .map_err(|e| e.to_string())?;
    Ok(text)
}

/// The toast for a `proxy.system.*` reply: the core's `detail` line, or the
/// verb's name when the reply carries none (spec §D14).
fn sysproxy_detail(name: &str, value: &Value) -> String {
    match value.get("detail").and_then(Value::as_str) {
        Some(d) if !d.is_empty() => d.to_string(),
        _ => format!("{name}: ok"),
    }
}

/// `pause` → `Pause`, for a toast that starts a sentence.
fn title_case(word: &str) -> String {
    let mut c = word.chars();
    match c.next() {
        Some(first) => first.to_uppercase().chain(c).collect(),
        None => String::new(),
    }
}

/// C12: whether a `poc.build` reply is the PoC's YAML text rather than a
/// path — it spans lines, or it neither contains a `/` nor ends in
/// `.yaml`/`.yml`.
fn looks_like_yaml(s: &str) -> bool {
    s.contains('\n') || !(s.contains('/') || s.ends_with(".yaml") || s.ends_with(".yml"))
}

/// The file-name slug for a built PoC: the name the operator typed, lower
/// case with spaces as `-`, reduced to safe characters; else `poc-<seq>`.
fn poc_slug(name: Option<&str>, seq: usize) -> String {
    let typed = name
        .map(|n| open::safe_name(&n.trim().to_lowercase().replace([' ', '\t'], "-")))
        .filter(|s| s != "flow");
    typed.unwrap_or_else(|| format!("poc-{seq}"))
}

/// The scalar value of the first `key:` line in a YAML text (any indent),
/// quotes stripped — enough to title a PoC the TUI just wrote.
fn yaml_field(yaml: &str, key: &str) -> Option<String> {
    yaml.lines().find_map(|l| {
        let (k, v) = l.trim_start().split_once(':')?;
        if k.trim() != key {
            return None;
        }
        let v = v.trim().trim_matches(|c| c == '"' || c == '\'').trim();
        (!v.is_empty()).then(|| v.to_string())
    })
}

/// The title `Finding::from_json` falls back to for a path: its file stem.
fn default_title(poc_path: &str) -> String {
    Path::new(poc_path)
        .file_stem()
        .and_then(|x| x.to_str())
        .unwrap_or("poc")
        .to_string()
}

/// Built-in `:` commands shown in the palette.
pub const BUILTIN_COMMANDS: &[(&str, &str)] = &[
    ("intercept", "Arm/disarm interception (i)"),
    ("resume", "Resume the targeted paused flow (⏎ in the bar)"),
    ("resume all", "Resume every paused flow"),
    ("kill", "Kill the targeted paused flow"),
    ("replay", "Repeat the selected flow unchanged (r)"),
    (
        "compose",
        "Compose a request, prefilled from the selection (n)",
    ),
    (
        "compose get|post-json|post-form|ws",
        "Compose from a template (ws needs F9)",
    ),
    ("curl <command>", "Import a curl command line into compose"),
    ("filter <expr>", "Set the filter expression (/)"),
    (
        "scope add <host>",
        "Add a host to scope (scope-as-authorisation)",
    ),
    ("scope", "Open the scope panel"),
    ("findings", "Open the PoC findings panel"),
    ("poc build", "Build a PoC from the selected flow"),
    ("poc run <path> [target]", "Run a PoC YAML"),
    ("agent all|readonly|paused", "Set the agent policy"),
    ("agent", "Open the agent panel and activity log"),
    (
        "sysproxy on|off|status",
        "Set / restore the OS system proxy (s)",
    ),
    ("ca", "CA panel: status, export, install, uninstall"),
    ("config", "Config panel: the redacted config.get view"),
    (
        "browser",
        "Browser view: URL, DOM outline, screenshot; navigate and eval",
    ),
    (
        "scan",
        "Scan view: scope-bound scan.discover (r crawls; :scan <host> crawls a host)",
    ),
    (
        "l4",
        "L4 panel: capture / intercept availability and running captures (L)",
    ),
    (
        "l4 capture <iface> [inbound|outbound]",
        "Start a packet capture (refused locally while capture is unavailable)",
    ),
    ("l4 stop [<id>]", "Stop one running capture, or every one"),
    ("layout h|v", "Inspector below or right"),
    ("split", "Split view (not built in this pass)"),
    ("export", "Export flows (needs F10)"),
    ("sidebar", "Toggle the sidebar (b)"),
    ("pin [host]", "Pin a host to the top of the list (p)"),
    ("import <path>", "Import HAR / mitmproxy / Proxyman flows"),
    ("clear", "Clear the session"),
    ("pause", "Pause capture"),
    ("record", "Resume capture"),
    ("copy", "Copy the selected URL (OSC 52)"),
    ("auto", "Toggle auto-select of new flows"),
    ("refresh", "Poll the bus now"),
    ("help", "Keys and commands"),
    ("quit", "Leave the TUI"),
];

/// The `:l4` usage toast.
const L4_USAGE: &str = "usage: :l4 [capture <iface> [inbound|outbound] | stop [<id>]]";

/// Subsequence match: every char of `needle` appears in order in `hay`.
/// Parse the craft editor's YAML into a `PacketSpec` JSON value for `l4.craft`
/// / `l4.inject`. The error is surfaced verbatim in the craft pane.
fn parse_craft_yaml(yaml: &str) -> Result<Value, String> {
    serde_yaml::from_str::<Value>(yaml).map_err(|e| format!("craft YAML: {e}"))
}

/// The destination IP from a craft spec's `ipv4` / `ipv6` layer, for
/// `l4.inject`'s `dst` argument; `None` when the spec declares no such layer.
fn craft_dst(spec: &Value) -> Option<String> {
    let layers = spec.get("layers")?.as_array()?;
    for layer in layers {
        for key in ["ipv4", "ipv6"] {
            if let Some(dst) = layer
                .get(key)
                .and_then(|l| l.get("dst"))
                .and_then(Value::as_str)
            {
                return Some(dst.to_string());
            }
        }
    }
    None
}

pub fn fuzzy(needle: &str, hay: &str) -> bool {
    let mut it = hay.chars();
    needle.chars().all(|n| it.any(|h| h == n))
}

fn step<T: Copy + PartialEq>(all: &[T], cur: T, d: i32) -> T {
    let i = all.iter().position(|x| *x == cur).unwrap_or(0) as i32;
    all[(i + d).rem_euclid(all.len() as i32) as usize]
}

fn compose_field(f: &mut ComposeForm) -> &mut String {
    match f.field {
        0 => &mut f.method,
        1 => &mut f.url,
        2 => &mut f.headers,
        _ => &mut f.body,
    }
}

fn edit_insert(e: &mut EditBuffer, c: char) {
    if e.lines.is_empty() {
        e.lines.push(String::new());
    }
    let line = &mut e.lines[e.cursor_line];
    let at = byte_at(line, e.cursor_col);
    line.insert(at, c);
    e.cursor_col += 1;
}

fn edit_backspace(e: &mut EditBuffer) {
    if e.cursor_col > 0 {
        let line = &mut e.lines[e.cursor_line];
        let at = byte_at(line, e.cursor_col - 1);
        line.remove(at);
        e.cursor_col -= 1;
    } else if e.cursor_line > 0 {
        let cur = e.lines.remove(e.cursor_line);
        e.cursor_line -= 1;
        e.cursor_col = e.lines[e.cursor_line].chars().count();
        e.lines[e.cursor_line].push_str(&cur);
    }
}

fn edit_newline(e: &mut EditBuffer) {
    let line = &mut e.lines[e.cursor_line];
    let at = byte_at(line, e.cursor_col);
    let rest = line.split_off(at);
    e.lines.insert(e.cursor_line + 1, rest);
    e.cursor_line += 1;
    e.cursor_col = 0;
}

fn byte_at(s: &str, col: usize) -> usize {
    s.char_indices().nth(col).map_or(s.len(), |(i, _)| i)
}

/// `key=value key2=value` → an arguments object, coerced by the tool's schema
/// (`integer`/`number`/`boolean`/`object`/`array` parse as JSON; else string).
pub fn parse_kv_args(rest: &str, tool: Option<&ToolInfo>) -> Result<Value, String> {
    let mut args = Map::new();
    let types: HashMap<String, String> = tool
        .map(|t| t.params().into_iter().map(|p| (p.name, p.ty)).collect())
        .unwrap_or_default();
    for word in shell_words(rest) {
        let (k, v) = word
            .split_once('=')
            .ok_or_else(|| format!("`{word}` is not key=value"))?;
        let coerced = match types.get(k).map(String::as_str) {
            Some("integer") | Some("number") | Some("boolean") | Some("object") | Some("array") => {
                serde_json::from_str(v).map_err(|e| format!("{k}: {e}"))?
            }
            _ => Value::String(v.to_string()),
        };
        args.insert(k.to_string(), coerced);
    }
    if let Some(t) = tool {
        for p in t.params() {
            if p.required && !args.contains_key(&p.name) {
                return Err(format!("missing required `{}`", p.name));
            }
        }
    }
    Ok(Value::Object(args))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::ProxyStatus;
    use crate::summary;
    use serde_json::json;

    fn tools(names: &[&str]) -> Vec<ToolInfo> {
        names
            .iter()
            .map(|n| ToolInfo {
                name: (*n).to_string(),
                description: String::new(),
                input_schema: json!({"type":"object","properties":{}}),
                confirmable: false,
            })
            .collect()
    }

    /// AC7/AC8: `Connected` carries the resolved role; with `--expect-role`
    /// set, a resolved role that differs (or a server that echoed none) is a
    /// mismatch, while a matching role is not. No expectation never warns.
    #[test]
    fn role_mismatch_follows_expect_role_and_the_resolved_role() {
        let connected = |role: Option<&str>| BusEvent::Connected {
            server: "aitmproxy test".into(),
            tools: Vec::new(),
            role: role.map(str::to_string),
        };

        // Expect operator, resolve agent → mismatch.
        let mut app = App::new(TermCaps::full(), "127.0.0.1:9090");
        app.expect_role = Some("operator".into());
        let _ = app.on_bus(connected(Some("agent")));
        assert_eq!(app.resolved_role(), Some("agent"));
        assert!(app.role_mismatch());

        // Expect operator, resolve operator → no mismatch.
        let mut app = App::new(TermCaps::full(), "127.0.0.1:9090");
        app.expect_role = Some("operator".into());
        let _ = app.on_bus(connected(Some("operator")));
        assert!(!app.role_mismatch());

        // Expect operator, server echoed no role → mismatch (cannot confirm).
        let mut app = App::new(TermCaps::full(), "127.0.0.1:9090");
        app.expect_role = Some("operator".into());
        let _ = app.on_bus(connected(None));
        assert!(app.role_mismatch());

        // No expectation → never a mismatch, whatever the role.
        let mut app = App::new(TermCaps::full(), "127.0.0.1:9090");
        let _ = app.on_bus(connected(Some("agent")));
        assert!(!app.role_mismatch());
        assert_eq!(app.resolved_role(), Some("agent"));
    }

    fn app_with_flows() -> App {
        let mut app = App::new(TermCaps::full(), "127.0.0.1:9090");
        app.tools = tools(&[
            "flow.list",
            "flow.get",
            "flow.intercept",
            "flow.resume",
            "flow.kill",
            "flow.mutate",
            "flow.replay",
            "scope.add",
            "scope.list",
        ]);
        app.scope = vec!["*.shop-staging.test".into()];
        let _ = app.on_bus(BusEvent::Flows(vec![
            summary(
                "f1",
                "GET",
                "api.shop-staging.test",
                "/api/products",
                Some(200),
                "observed",
            ),
            summary(
                "f2",
                "POST",
                "telemetry.vendor.example",
                "/v2/batch",
                Some(204),
                "observed",
            ),
            summary(
                "f3",
                "POST",
                "auth.shop-staging.test",
                "/api/auth/login",
                None,
                "intercepted",
            ),
        ]));
        app
    }

    #[test]
    fn flows_event_assigns_sequence_and_selects_the_newest() {
        let app = app_with_flows();
        assert_eq!(
            app.flows.iter().map(|r| r.seq).collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
        assert_eq!(app.selected.as_deref(), Some("f3"));
        assert_eq!(app.paused().len(), 1);
        assert_eq!(app.intercept_target().map(|r| r.id.as_str()), Some("f3"));
    }

    #[test]
    fn refresh_keeps_sequence_numbers_and_drops_vanished_flows() {
        let mut app = app_with_flows();
        let _ = app.on_bus(BusEvent::Flows(vec![
            summary(
                "f2",
                "POST",
                "telemetry.vendor.example",
                "/v2/batch",
                Some(204),
                "observed",
            ),
            summary(
                "f3",
                "POST",
                "auth.shop-staging.test",
                "/api/auth/login",
                Some(200),
                "resumed",
            ),
            summary(
                "f4",
                "GET",
                "api.shop-staging.test",
                "/api/me",
                None,
                "observed",
            ),
        ]));
        let seqs: Vec<(String, usize)> = app.flows.iter().map(|r| (r.id.clone(), r.seq)).collect();
        assert_eq!(
            seqs,
            vec![("f2".into(), 2), ("f3".into(), 3), ("f4".into(), 4)]
        );
        assert_eq!(app.row("f3").unwrap().status, Some(200));
        assert!(app.paused().is_empty());
    }

    #[test]
    fn out_of_scope_rows_are_dimmed_and_cannot_be_acted_on() {
        let mut app = app_with_flows();
        assert!(app.in_scope(app.row("f1").unwrap()));
        assert!(!app.in_scope(app.row("f2").unwrap()));
        app.selected = Some("f2".into());
        let reqs = app.update(Action::Replay);
        assert!(reqs.is_empty());
        assert_eq!(
            app.current_toast().map(|t| t.text.as_str()),
            Some("Out of scope — add `telemetry.vendor.example` to scope to act")
        );
        app.selected = Some("f1".into());
        assert_eq!(
            app.update(Action::Replay),
            vec![BusRequest::Replay("f1".into())]
        );
    }

    #[test]
    fn intercept_bar_verbs_target_the_paused_flow() {
        let mut app = app_with_flows();
        app.selected = Some("f1".into());
        assert_eq!(
            app.update(Action::Resume),
            vec![BusRequest::Resume("f3".into())]
        );
        assert_eq!(
            app.update(Action::Kill),
            vec![BusRequest::Kill("f3".into())]
        );
        assert_eq!(
            app.update(Action::ToggleIntercept),
            vec![BusRequest::Intercept(true)]
        );
        assert!(app.intercept_armed);
    }

    #[test]
    fn edit_apply_sends_mutate_then_resume() {
        let mut app = app_with_flows();
        let detail = FlowDetail::from_json(&json!({"id":"f3","kind":"http",
            "request":{"method":"POST","path":"/api/auth/login","version":"HTTP/2","headers":[["host","auth.shop-staging.test"],["content-type","application/json"]],"body":"eyJlbWFpbCI6Im9wcyJ9"}})).unwrap();
        let _ = app.on_bus(BusEvent::Detail(Box::new(detail)));
        assert!(app.update(Action::Edit).is_empty());
        assert_eq!(app.mode, Mode::Edit);
        let e = app.edit.as_ref().unwrap();
        assert_eq!(e.lines[0], "POST /api/auth/login HTTP/2");
        assert_eq!(e.lines[3], "");
        assert_eq!(e.lines[4], r#"{"email":"ops"}"#);
        // Type a header on a new line after the last header.
        app.edit.as_mut().unwrap().cursor_line = 2;
        app.edit.as_mut().unwrap().cursor_col = "content-type: application/json".len();
        let _ = app.update(Action::Enter);
        for c in "x-forwarded-for: 127.0.0.1".chars() {
            let _ = app.update(Action::Input(c));
        }
        let reqs = app.update(Action::ApplyAndResume);
        assert_eq!(reqs.len(), 2);
        match &reqs[0] {
            BusRequest::Mutate { id, edits } => {
                assert_eq!(id, "f3");
                assert_eq!(edits["method"], "POST");
                assert_eq!(edits["path"], "/api/auth/login");
                assert_eq!(edits["headers"]["x-forwarded-for"], "127.0.0.1");
                assert_eq!(edits["headers"]["host"], "auth.shop-staging.test");
                // The body was not touched, so it is not sent: the core keeps
                // the parked request's bytes exactly as they were.
                assert!(edits.get("body").is_none(), "{edits}");
            }
            other => panic!("expected Mutate, got {other:?}"),
        }
        assert_eq!(reqs[1], BusRequest::Resume("f3".into()));
        assert_eq!(app.mode, Mode::Flows);
    }

    fn message_with_body(body: &[u8]) -> Message {
        Message {
            method: Some("POST".into()),
            path: Some("/upload".into()),
            version: Some("HTTP/1.1".into()),
            headers: vec![("host".into(), "h.test".into())],
            body: body.to_vec(),
            ..Message::default()
        }
    }

    /// A body that is not UTF-8 is shown as a placeholder and never sent back:
    /// the edit → mutate round trip must leave the forwarded bytes untouched.
    #[test]
    fn binary_body_survives_the_edit_round_trip_untouched() {
        let bytes = [0x00u8, 0xff, 0x89, b'P', b'N', b'G', 0xfe];
        let mut e = EditBuffer::from_request("f9", &message_with_body(&bytes));
        assert!(!e.body_is_text);
        assert_eq!(e.lines[3], "<7 binary bytes — edit in hex is a follow-up>");
        // Edit a header: that is sent; the body key is absent.
        e.lines[1] = "host: other.test".into();
        let edits = e.to_edits();
        assert_eq!(edits["headers"]["host"], "other.test");
        assert!(edits.get("body").is_none(), "{edits}");
        // Even typing over the placeholder sends no body.
        e.lines[3] = "oops".into();
        assert!(e.to_edits().get("body").is_none());
    }

    /// CRLF line endings and a trailing newline are kept when a text body is
    /// edited; an untouched body is not sent at all.
    #[test]
    fn crlf_and_trailing_newline_survive_a_body_edit() {
        let mut e = EditBuffer::from_request("f9", &message_with_body(b"a=1\r\nb=2\r\n"));
        assert_eq!(&e.lines[3..], ["a=1", "b=2"]);
        assert!(
            e.to_edits().get("body").is_none(),
            "unchanged body is not sent"
        );
        e.lines[4] = "b=3".into();
        assert_eq!(e.to_edits()["body"], "a=1\r\nb=3\r\n");

        let mut e = EditBuffer::from_request("f9", &message_with_body(b"x\ny"));
        e.lines[4] = "z".into();
        assert_eq!(e.to_edits()["body"], "x\nz");

        let mut e = EditBuffer::from_request("f9", &message_with_body(b""));
        assert!(e.to_edits().get("body").is_none());
        e.lines.push("new".into());
        assert_eq!(e.to_edits()["body"], "new");
    }

    #[test]
    fn filter_prompt_applies_live_and_escape_clears() {
        let mut app = app_with_flows();
        let _ = app.update(Action::FilterOpen);
        for c in "~m POST".chars() {
            let _ = app.update(Action::Input(c));
        }
        assert_eq!(app.visible().len(), 2);
        let _ = app.update(Action::Submit);
        assert_eq!(app.mode, Mode::Flows);
        assert_eq!(app.filter_text, "~m POST");
        let _ = app.update(Action::Back);
        assert!(app.filter.is_none());
        assert_eq!(app.visible().len(), 3);
    }

    #[test]
    fn scope_sidebar_item_filters_to_in_scope_and_groups_by_host() {
        let mut app = app_with_flows();
        app.sidebar = SidebarItem::Scope;
        assert_eq!(app.visible().len(), 2);
        app.sidebar = SidebarItem::Domains;
        let vis = app.visible();
        assert_eq!(vis.len(), 3);
        assert_eq!(
            app.group_header(&vis, 0),
            Some(("api.shop-staging.test".into(), 1))
        );
        assert_eq!(
            app.group_header(&vis, 1),
            Some(("telemetry.vendor.example".into(), 1))
        );
        assert_eq!(
            app.group_header(&vis, 2),
            Some(("auth.shop-staging.test".into(), 1))
        );
    }

    #[test]
    fn pinned_hosts_sort_first() {
        let mut app = app_with_flows();
        app.sidebar = SidebarItem::Pinned;
        app.pinned_hosts = vec!["auth.shop-staging.test".into()];
        assert_eq!(app.visible(), vec![2]);
        app.sidebar = SidebarItem::Saved;
        assert_eq!(app.visible(), vec![2, 0, 1]);
    }

    #[test]
    fn chips_filter_by_content_type() {
        let mut app = app_with_flows();
        app.flows[0].content_type = Some("application/json".into());
        app.flows[1].content_type = Some("text/html".into());
        app.chip = Chip::Json;
        assert_eq!(app.visible(), vec![0]);
        app.chip = Chip::Document;
        assert_eq!(app.visible(), vec![1]);
        app.chip = Chip::Other;
        assert!(app.visible().is_empty());
    }

    #[test]
    fn palette_runs_commands_and_tools() {
        let mut app = app_with_flows();
        let _ = app.update(Action::PaletteOpen);
        for c in "scope add api.other.test".chars() {
            let _ = app.update(Action::Input(c));
        }
        assert_eq!(
            app.update(Action::Submit),
            vec![BusRequest::ScopeAdd("api.other.test".into())]
        );
        assert_eq!(app.mode, Mode::Flows);
        let _ = app.update(Action::PaletteOpen);
        for c in "flow.replay id=f1".chars() {
            let _ = app.update(Action::Input(c));
        }
        assert_eq!(
            app.update(Action::Submit),
            vec![BusRequest::Call {
                name: "flow.replay".into(),
                args: json!({"id":"f1"})
            }]
        );
        let items = App::new(TermCaps::full(), "x").palette_items();
        assert!(items.iter().any(|i| i.label == ":intercept"));
    }

    #[test]
    fn features_absent_from_the_bus_degrade_to_a_toast() {
        let mut app = app_with_flows();
        assert!(app.update(Action::AgentSet(AgentPolicy::Paused)).is_empty());
        assert!(app
            .current_toast()
            .unwrap()
            .text
            .contains("agent.set is not on this bus"));
        assert!(app.run_command("clear").is_empty());
        assert!(app.current_toast().unwrap().text.contains("F7"));
        app.tools.push(ToolInfo {
            name: "agent.set".into(),
            description: String::new(),
            input_schema: json!({}),
            confirmable: false,
        });
        assert_eq!(
            app.update(Action::AgentSet(AgentPolicy::Paused)),
            vec![BusRequest::AgentSet(AgentPolicy::Paused)]
        );
    }

    #[test]
    fn compose_builds_request_send_args_and_checks_scope() {
        let mut app = app_with_flows();
        app.compose = ComposeForm {
            method: "post".into(),
            url: "https://api.shop-staging.test/api/cart?x=1".into(),
            headers: "Content-Type: application/json\n".into(),
            body: "{}".into(),
            field: 3,
        };
        app.mode = Mode::Compose;
        let reqs = app.update(Action::Submit);
        assert_eq!(
            reqs,
            vec![BusRequest::Send(json!({
                "method":"POST","scheme":"https","authority":"api.shop-staging.test","path":"/api/cart?x=1",
                "headers":{"Content-Type":"application/json"},"body":"{}"
            }))]
        );
        app.compose.url = "https://evil.example/".into();
        app.compose.field = 3;
        app.mode = Mode::Compose;
        assert!(app.update(Action::Submit).is_empty());
        assert!(app
            .current_toast()
            .unwrap()
            .text
            .starts_with("Out of scope"));
    }

    #[test]
    fn curl_import_fills_the_form() {
        let f = ComposeForm::from_curl(r#"curl -X PUT 'https://api.shop-staging.test/api/cart/items/42' -H "Content-Type: application/json" -d '{"qty":2}'"#).unwrap();
        assert_eq!(f.method, "PUT");
        assert_eq!(f.url, "https://api.shop-staging.test/api/cart/items/42");
        assert_eq!(f.headers, "Content-Type: application/json");
        assert_eq!(f.body, r#"{"qty":2}"#);
        let f = ComposeForm::from_curl("curl https://a.test/ -d x=1").unwrap();
        assert_eq!(f.method, "POST");
        assert!(ComposeForm::from_curl("wget https://a.test").is_none());
    }

    // ------------------------------------------------- fix pass 1 (panel)

    /// S1 / I2: `ca.install` and `ca.uninstall` wait for a local `y/N`; `n`
    /// and Esc cancel with a toast; `dry_run=true` goes straight through.
    #[test]
    fn confirm_tools_wait_for_y_and_cancel_on_n_or_esc() {
        let mut app = app_with_flows();
        app.tools
            .extend(tools(&["ca.install", "ca.uninstall", "ca.status"]));
        app.tools
            .iter_mut()
            .find(|t| t.name == "ca.install")
            .unwrap()
            .description = "Install the CA into the OS trust store (confirmed).".into();
        // From the palette: nothing reaches the bus until `y`.
        let _ = app.update(Action::PaletteOpen);
        for c in "ca.install".chars() {
            let _ = app.update(Action::Input(c));
        }
        assert!(app.update(Action::Submit).is_empty());
        assert_eq!(app.mode, Mode::Prompt(PromptKind::Confirm));
        let c = app.confirm.as_ref().expect("held call");
        assert_eq!(c.name, "ca.install");
        assert_eq!(
            c.description,
            "Install the CA into the OS trust store (confirmed)."
        );
        assert_eq!(
            app.update(Action::Input('y')),
            vec![BusRequest::Call {
                name: "ca.install".into(),
                args: json!({})
            }]
        );
        assert_eq!(app.mode, Mode::Flows);
        assert!(app.confirm.is_none());
        // `n` cancels with a toast.
        assert!(app.run_command("ca.uninstall").is_empty());
        assert_eq!(app.mode, Mode::Prompt(PromptKind::Confirm));
        assert!(app.update(Action::Input('n')).is_empty());
        assert_eq!(app.mode, Mode::Flows);
        assert_eq!(
            app.current_toast().map(|t| t.text.as_str()),
            Some("ca.uninstall cancelled")
        );
        // Esc cancels too.
        assert!(app.run_command("ca.install").is_empty());
        assert!(app.update(Action::Back).is_empty());
        assert_eq!(app.mode, Mode::Flows);
        assert_eq!(
            app.current_toast().map(|t| t.text.as_str()),
            Some("ca.install cancelled")
        );
        // Enter only ever arrives on a blank line (the first typed key
        // answers), and a blank line is "N".
        assert!(app.run_command("ca.install").is_empty());
        assert!(app.update(Action::Submit).is_empty());
        assert_eq!(app.mode, Mode::Flows);
        // `dry_run=true` does not bypass the prompt while the tool's schema
        // declares no `dry_run` (SEC-4): the bus task would prune it.
        assert!(app.run_command("ca.install dry_run=true").is_empty());
        assert_eq!(app.mode, Mode::Prompt(PromptKind::Confirm));
        let _ = app.update(Action::Back);
        assert_eq!(app.mode, Mode::Flows);
        // From the CA panel the answer returns to the panel.
        let _ = app.run_command("ca");
        assert_eq!(app.mode, Mode::Ca);
        assert!(app.update(Action::Command("ca.install".into())).is_empty());
        assert_eq!(app.mode, Mode::Prompt(PromptKind::Confirm));
        assert_eq!(app.update(Action::Input('y')).len(), 1);
        assert_eq!(app.mode, Mode::Ca);
        // Unconfirmed tools are unchanged.
        assert_eq!(
            app.run_command("flow.replay id=f1"),
            vec![BusRequest::Call {
                name: "flow.replay".into(),
                args: json!({"id": "f1"})
            }]
        );
    }

    /// I2: `:ca` opens the panel and asks `ca.status`; the result fills it;
    /// `e` prompts for format/path and calls `ca.export`.
    #[test]
    fn ca_panel_shows_status_and_exports() {
        let mut app = app_with_flows();
        assert_eq!(app.run_command("ca"), vec![], "no ca.status on this bus");
        assert_eq!(app.mode, Mode::Ca);
        app.tools.extend(tools(&["ca.status", "ca.export"]));
        assert_eq!(
            app.run_command("ca"),
            vec![BusRequest::Call {
                name: "ca.status".into(),
                args: json!({})
            }]
        );
        let reqs = app.on_bus(BusEvent::CallOk {
            name: "ca.status".into(),
            value: json!({"path": "/tmp/ca.pem", "fingerprint": "AB:CD", "installed": false}),
        });
        assert!(
            reqs.is_empty(),
            "a status reply is not a mutation: no refresh"
        );
        assert_eq!(app.ca_status.as_ref().unwrap()["fingerprint"], "AB:CD");
        let _ = app.update(Action::CaExportPrompt);
        assert_eq!(app.mode, Mode::Prompt(PromptKind::CaExport));
        for c in "der /tmp/out.der".chars() {
            let _ = app.update(Action::Input(c));
        }
        assert_eq!(
            app.update(Action::Submit),
            vec![BusRequest::Call {
                name: "ca.export".into(),
                args: json!({"format": "der", "out": "/tmp/out.der"})
            }]
        );
        assert_eq!(app.mode, Mode::Ca);
        let _ = app.update(Action::CaExportPrompt);
        assert_eq!(
            app.update(Action::Submit),
            vec![BusRequest::Call {
                name: "ca.export".into(),
                args: json!({})
            }],
            "blank = defaults"
        );
        let _ = app.update(Action::Back);
        assert_eq!(app.mode, Mode::Flows);
    }

    fn ca_status_macos(trusted: &str) -> Value {
        json!({"exists": true, "platform": "macos", "fingerprint_sha256": "AB:CD",
            "stores": {"user": {"installed": "present", "trusted": trusted, "location": "login"},
                       "system": {"installed": "absent", "trusted": "no", "location": "System"}}})
    }

    fn ca_status_debian() -> Value {
        json!({"exists": true, "platform": "linux-debian",
            "stores": {"system": {"installed": "absent", "trusted": "no", "location": "/usr/local/share/ca-certificates"}}})
    }

    fn ca_status_call() -> BusRequest {
        BusRequest::Call {
            name: "ca.status".into(),
            args: json!({}),
        }
    }

    /// SP-AC35 / D17.1: `ca.install` and `ca.uninstall` carry `scope: "user"`
    /// when the reported platform has a user store (macOS, Windows) and none
    /// was typed; a typed scope wins; the in-flight flag is up from `y` until
    /// the reply and `n` never sets it.
    #[test]
    fn ca_install_scope_default_follows_the_reported_platform() {
        let mut app = app_with_flows();
        app.tools
            .extend(tools(&["ca.install", "ca.uninstall", "ca.status"]));
        app.ca_status = Some(ca_status_macos("no"));
        assert!(app.run_command("ca.install").is_empty());
        assert!(!app.ca_installing, "held for y/N: not in flight yet");
        assert_eq!(
            app.update(Action::Input('y')),
            vec![BusRequest::Call {
                name: "ca.install".into(),
                args: json!({"scope": "user"})
            }]
        );
        assert!(app.ca_installing);
        let reqs = app.on_bus(BusEvent::CallOk {
            name: "ca.install".into(),
            value: json!({"changed": true}),
        });
        assert!(!app.ca_installing, "the reply settles the flag");
        assert_eq!(reqs, vec![ca_status_call(), BusRequest::Refresh]);

        // `n` never sets the flag.
        assert!(app.run_command("ca.uninstall").is_empty());
        assert!(app.update(Action::Input('n')).is_empty());
        assert!(!app.ca_installing);

        // Uninstall carries the scope too.
        assert!(app.run_command("ca.uninstall").is_empty());
        assert_eq!(
            app.update(Action::Input('y')),
            vec![BusRequest::Call {
                name: "ca.uninstall".into(),
                args: json!({"scope": "user"})
            }]
        );

        // A typed scope wins.
        assert!(app.run_command("ca.install scope=system").is_empty());
        assert_eq!(
            app.update(Action::Input('y')),
            vec![BusRequest::Call {
                name: "ca.install".into(),
                args: json!({"scope": "system"})
            }]
        );

        // Windows has a user store too.
        app.ca_status = Some(json!({"exists": true, "platform": "windows",
            "stores": {"user": {"trusted": "no"}}}));
        assert!(app.run_command("ca.install").is_empty());
        assert_eq!(
            app.update(Action::Input('y')),
            vec![BusRequest::Call {
                name: "ca.install".into(),
                args: json!({"scope": "user"})
            }]
        );
    }

    /// SP-AC35 / D17.1: no scope is invented when the platform has only a
    /// system store (Linux), when `ca.status` has not answered yet, or when an
    /// older core reported the pre-D17 shape.
    #[test]
    fn ca_install_passes_no_scope_on_linux_or_without_status() {
        let mut app = app_with_flows();
        app.tools
            .extend(tools(&["ca.install", "ca.uninstall", "ca.status"]));
        let bare_install = vec![BusRequest::Call {
            name: "ca.install".into(),
            args: json!({}),
        }];

        // Linux: the only scope is system, so none is passed.
        app.ca_status = Some(ca_status_debian());
        assert!(app.run_command("ca.install").is_empty());
        assert_eq!(app.update(Action::Input('y')), bare_install);

        // No status yet: nothing is invented.
        app.ca_status = None;
        assert!(app.run_command("ca.install").is_empty());
        assert_eq!(app.update(Action::Input('y')), bare_install);

        // An older core's shape: nothing is invented either.
        app.ca_status = Some(json!({"path": "/tmp/ca.pem", "installed": false}));
        assert!(app.run_command("ca.install").is_empty());
        assert_eq!(app.update(Action::Input('y')), bare_install);
    }

    /// Both CA-trust tools are the ones the operator confirms locally.
    #[test]
    fn ca_trust_tools_are_the_confirm_tools() {
        assert_eq!(CA_TRUST_TOOLS, &["ca.install", "ca.uninstall"]);
        assert_eq!(CONFIRM_TOOLS, CA_TRUST_TOOLS);
    }

    /// D17.6: a bus drop while `ca.install` is on the wire settles the
    /// in-flight flag, so the reconnect's read-back is what the pill shows,
    /// never a stale `· CA trusting…`.
    #[test]
    fn bus_drop_mid_dialog_clears_the_in_flight_flag() {
        let mut app = app_with_flows();
        app.tools
            .extend(tools(&["ca.install", "ca.uninstall", "ca.status"]));
        app.ca_status = Some(ca_status_macos("no"));
        let _ = app.run_command("ca.install");
        let _ = app.update(Action::Input('y'));
        assert!(app.ca_installing);
        assert_eq!(app.ca_trust_word().as_deref(), Some("· CA trusting…"));

        let _ = app.on_bus(BusEvent::Disconnected("connection reset".into()));
        assert!(!app.ca_installing, "no reply will come: not in flight");
        assert_eq!(app.ca_trust_word().as_deref(), Some("· CA untrusted"));

        app.ca_installing = true;
        let reqs = app.on_bus(BusEvent::Connected {
            server: "aitmproxy test".into(),
            tools: tools(&["flow.list", "ca.status", "ca.install"]),
            role: Some("operator".into()),
        });
        assert!(!app.ca_installing, "a new session: nothing is in flight");
        assert!(reqs.contains(&ca_status_call()), "{reqs:?}");
        let _ = app.on_bus(BusEvent::CallOk {
            name: "ca.status".into(),
            value: ca_status_macos("no"),
        });
        assert_eq!(app.ca_trust_word().as_deref(), Some("· CA untrusted"));
    }

    /// SP-AC35 / D17.11: a connect whose tool list offers `ca.status` asks it
    /// exactly once; a bus without it is not asked.
    #[test]
    fn connect_asks_ca_status_once_when_the_bus_offers_it() {
        let mut app = App::new(TermCaps::full(), "127.0.0.1:9090");
        let reqs = app.on_bus(BusEvent::Connected {
            server: "aitmproxy test".into(),
            tools: tools(&["flow.list", "flow.get", "ca.status", "ca.install"]),
            role: Some("operator".into()),
        });
        assert_eq!(
            reqs.iter().filter(|r| **r == ca_status_call()).count(),
            1,
            "{reqs:?}"
        );
        assert!(reqs.contains(&BusRequest::Refresh));
        assert!(!app.ca_installing);

        let mut app = App::new(TermCaps::full(), "127.0.0.1:9090");
        app.ca_installing = true;
        let _ = app.on_bus(BusEvent::Connected {
            server: "aitmproxy test".into(),
            tools: tools(&["flow.list", "ca.status"]),
            role: Some("operator".into()),
        });
        assert!(!app.ca_installing, "a connect clears a stale flag");

        let mut app = App::new(TermCaps::full(), "127.0.0.1:9090");
        let reqs = app.on_bus(BusEvent::Connected {
            server: "aitmproxy test".into(),
            tools: tools(&["flow.list", "flow.get"]),
            role: Some("operator".into()),
        });
        assert_eq!(reqs, vec![BusRequest::Refresh]);
    }

    /// SP-AC35 / D17.6: the pill word follows the last `ca.status` and the
    /// in-flight flag.
    #[test]
    fn ca_trust_word_follows_status_and_the_in_flight_flag() {
        let mut app = app_with_flows();
        assert_eq!(app.ca_trust_word(), None);
        app.ca_status = Some(ca_status_macos("yes"));
        assert_eq!(app.ca_trust_word().as_deref(), Some("· CA trusted"));
        app.ca_status = Some(ca_status_macos("no"));
        assert_eq!(app.ca_trust_word().as_deref(), Some("· CA untrusted"));
        app.ca_installing = true;
        assert_eq!(app.ca_trust_word().as_deref(), Some("· CA trusting…"));
        app.ca_installing = false;
        app.ca_status = Some(ca_status_macos("unknown"));
        assert_eq!(
            app.ca_trust_word().as_deref(),
            Some("· CA untrusted"),
            "user unknown, System says no: a store says no and none yes"
        );
        app.ca_status = Some(json!({"exists": true, "platform": "macos",
            "stores": {"user": {"trusted": "unknown"}, "system": {"trusted": "unknown"}}}));
        assert_eq!(app.ca_trust_word(), None);
        app.ca_status = Some(json!({"path": "/tmp/ca.pem", "installed": true}));
        assert_eq!(app.ca_trust_word(), None, "an older core's shape: no word");
    }

    /// D17.4 / D17.5: a dismissed macOS dialog is an information toast, not
    /// an error; every `ca.install` failure settles the flag and re-reads
    /// `ca.status`.
    #[test]
    fn ca_install_cancelled_is_an_info_toast_and_rereads_status() {
        let mut app = app_with_flows();
        app.tools
            .extend(tools(&["ca.install", "ca.uninstall", "ca.status"]));
        app.ca_status = Some(ca_status_macos("no"));
        let _ = app.run_command("ca.install");
        let _ = app.update(Action::Input('y'));
        assert!(app.ca_installing);
        let reqs = app.on_bus(BusEvent::CallFailed {
            name: "ca.install".into(),
            message: "ca.install cancelled: the macOS authentication dialog was dismissed; the CA is not trusted".into(),
        });
        assert!(!app.ca_installing);
        assert_eq!(reqs, vec![ca_status_call()]);
        let t = app.current_toast().expect("toast");
        assert_eq!(t.level, Level::Info);
        assert_eq!(t.text, "CA trust cancelled");

        // Any other failure stays an error, and still re-reads the status.
        let _ = app.run_command("ca.install");
        let _ = app.update(Action::Input('y'));
        let reqs = app.on_bus(BusEvent::CallFailed {
            name: "ca.install".into(),
            message: "ca.install refused: agent frontend".into(),
        });
        assert!(!app.ca_installing);
        assert_eq!(reqs, vec![ca_status_call()]);
        let t = app.current_toast().expect("toast");
        assert_eq!(t.level, Level::Error);
        assert_eq!(t.text, "ca.install refused: agent frontend");

        // Record correction 15: the uninstall dialog can be dismissed too.
        let _ = app.run_command("ca.uninstall");
        let _ = app.update(Action::Input('y'));
        assert!(app.ca_installing);
        let reqs = app.on_bus(BusEvent::CallFailed {
            name: "ca.uninstall".into(),
            message: "ca.uninstall cancelled: the macOS authentication dialog was dismissed; the CA is still trusted".into(),
        });
        assert!(!app.ca_installing);
        assert_eq!(reqs, vec![ca_status_call()]);
        let t = app.current_toast().expect("toast");
        assert_eq!(t.level, Level::Info);
        assert_eq!(t.text, "CA trust cancelled");
    }

    /// S3: details follow the flows (vanished rows drop theirs) and never
    /// exceed `MAX_DETAILS`; the selected flow's detail survives the cap.
    #[test]
    fn details_are_pruned_with_the_flows_and_capped() {
        let mut app = App::new(TermCaps::full(), "x");
        app.tools = tools(&["flow.list", "flow.get", "flow.detail"]);
        let n = MAX_DETAILS + 150;
        let summaries: Vec<Value> = (0..n)
            .map(|i| {
                summary(
                    &format!("f{i}"),
                    "GET",
                    "h.test",
                    "/p",
                    Some(200),
                    "observed",
                )
            })
            .collect();
        let _ = app.on_bus(BusEvent::Flows(summaries.clone()));
        app.selected = Some("f3".into());
        for i in 0..n {
            let d = FlowDetail::from_json(&json!({"id": format!("f{i}"), "kind": "http"})).unwrap();
            let _ = app.on_bus(BusEvent::Detail(Box::new(d)));
        }
        assert_eq!(app.details.len(), n, "details arrive unbounded…");
        let _ = app.on_bus(BusEvent::Flows(summaries.clone()));
        assert_eq!(
            app.details.len(),
            MAX_DETAILS,
            "…and are capped on the next poll"
        );
        assert!(
            app.details.contains_key("f3"),
            "the selected flow keeps its detail"
        );
        assert!(
            !app.details.contains_key("f0"),
            "the oldest unselected go first"
        );
        assert!(app.details.contains_key(&format!("f{}", n - 1)));
        // A vanished flow takes its detail with it.
        let _ = app.on_bus(BusEvent::Flows(summaries[1..].to_vec()));
        assert!(!app.details.contains_key("f0"));
        assert!(app.row("f0").is_none());
        assert_eq!(app.row("f1").map(|r| r.seq), Some(2));
    }

    /// Q6: `index` keeps `flows[index[id]].id == id` through merges and
    /// evictions, so `row()` is a map lookup.
    #[test]
    fn index_tracks_flows_through_merges_and_evictions() {
        let mut app = app_with_flows();
        let check = |app: &App| {
            assert_eq!(app.index.len(), app.flows.len());
            for (id, &i) in &app.index {
                assert_eq!(&app.flows[i].id, id);
            }
        };
        check(&app);
        assert_eq!(app.row("f2").map(|r| r.seq), Some(2));
        let _ = app.on_bus(BusEvent::Flows(vec![
            summary(
                "f3",
                "POST",
                "auth.shop-staging.test",
                "/l",
                Some(200),
                "resumed",
            ),
            summary(
                "f4",
                "GET",
                "api.shop-staging.test",
                "/me",
                None,
                "observed",
            ),
        ]));
        check(&app);
        assert!(app.row("f1").is_none());
        assert_eq!(app.row("f4").map(|r| r.seq), Some(4));
        assert_eq!(app.row("f3").and_then(|r| r.status), Some(200));
        let d = FlowDetail::from_json(&json!({"id":"f4","kind":"http",
            "response":{"status":201,"headers":[["content-type","text/plain"]]}}))
        .unwrap();
        let _ = app.on_bus(BusEvent::Detail(Box::new(d)));
        assert_eq!(app.row("f4").and_then(|r| r.status), Some(201));
        assert_eq!(app.row_mut("f4").map(|r| r.seq), Some(4));
    }

    /// Q1 (app side): a flow whose detail came back malformed is not asked
    /// for again, by `ensure_detail` or by the poll merge.
    #[test]
    fn detail_failed_flows_are_not_requested_again() {
        let mut app = App::new(TermCaps::full(), "x");
        app.tools = tools(&["flow.list", "flow.get", "flow.detail"]);
        let a = summary("a", "GET", "h.test", "/a", None, "observed");
        assert_eq!(
            app.on_bus(BusEvent::Flows(vec![a.clone()])),
            vec![BusRequest::Detail("a".into())]
        );
        let _ = app.on_bus(BusEvent::DetailFailed("a".into()));
        assert!(app.detail_failed.contains("a"));
        assert!(app
            .current_toast()
            .unwrap()
            .text
            .starts_with("flow.detail a: malformed reply"));
        assert!(
            app.update(Action::Enter).is_empty(),
            "Enter does not refetch"
        );
        let done = summary("a", "GET", "h.test", "/a", Some(200), "observed");
        assert!(
            app.on_bus(BusEvent::Flows(vec![done])).is_empty(),
            "a state change does not refetch either"
        );
        // A good detail later clears the mark.
        let d = FlowDetail::from_json(&json!({"id":"a","kind":"http"})).unwrap();
        let _ = app.on_bus(BusEvent::Detail(Box::new(d)));
        assert!(!app.detail_failed.contains("a"));
    }

    /// C1: `o` yields an `OpenTarget` for a screenshot or an image / large
    /// body (written to a private temp file), and says why otherwise.
    #[test]
    fn open_externally_targets_screenshots_images_and_large_bodies() {
        let mut app = crate::connected_app(200, 50);
        // Two `poc.run` results, oldest first: the newest lands on top, so
        // the cursor starts on the one with a screenshot.
        let _ = app.on_bus(BusEvent::CallOk {
            name: "poc.run".into(),
            value: json!({
                "title": "Missing rate limit on /api/auth/login", "severity": "medium",
                "target": "https://auth.example.test", "passed": false,
                "at": "2026-10-31T12:00:01.000Z", "origin": "agent",
                "poc_path": "pocs/login-rate-limit.yaml",
                "evaluated": [{"assertion": "status == 429", "matched": false}]
            }),
        });
        let _ = app.on_bus(BusEvent::CallOk {
            name: "poc.run".into(),
            value: json!({
                "title": "Reflected XSS in /api/search q", "severity": "high",
                "target": "https://api.example.test", "passed": true,
                "at": "2026-10-31T12:00:02.000Z", "origin": "agent",
                "poc_path": "pocs/reflected-xss-search.yaml",
                "finding_capture": "f48",
                "screenshot_path": "pocs/reflected-xss-search.png",
                "evaluated": [{"assertion": "status == 200", "matched": true}]
            }),
        });
        assert_eq!(app.findings.len(), 2);
        // Findings: the bus address `test` is not loopback, so the screenshot
        // is fetched through `poc.artifact` (C10) rather than opened from a
        // local path; nothing opens before the bytes arrive.
        let _ = app.update(Action::OpenFindings);
        app.finding_cursor = 0;
        assert_eq!(
            app.update(Action::OpenExternally),
            vec![BusRequest::Call {
                name: "poc.artifact".into(),
                args: json!({"path": "pocs/reflected-xss-search.png"})
            }]
        );
        assert!(
            app.take_open_target().is_none(),
            "nothing opens before the bytes arrive"
        );
        assert_eq!(
            app.current_toast().map(|t| t.text.as_str()),
            Some("fetching screenshot pocs/reflected-xss-search.png (poc.artifact)")
        );
        app.pending_artifact = None;
        let _ = app.update(Action::Down);
        let _ = app.update(Action::OpenExternally);
        assert!(app.take_open_target().is_none());
        assert_eq!(
            app.current_toast().map(|t| t.text.as_str()),
            Some("this finding has no screenshot to open")
        );
        // A small text body (a short JSON document) is shown inline: nothing to open.
        let _ = app.on_bus(BusEvent::Flows(vec![summary(
            "f41",
            "GET",
            "api.example.test",
            "/api/products",
            Some(200),
            "observed",
        )]));
        let d = FlowDetail::from_json(&json!({"id":"f41","kind":"http",
            "response":{"status":200,"headers":[["content-type","application/json"]],
                        "body": crate::base64::encode(br#"{"items":[],"total":0}"#)}}))
        .unwrap();
        let _ = app.on_bus(BusEvent::Detail(Box::new(d)));
        app.selected = Some("f41".into());
        app.mode = Mode::Inspector;
        app.inspector.pane = Pane::Response;
        let _ = app.update(Action::OpenExternally);
        assert!(app.take_open_target().is_none());
        assert_eq!(
            app.current_toast().map(|t| t.text.as_str()),
            Some("o opens images and large bodies; this body is shown inline")
        );
        // Inspector on an image response: the bytes land in a temp .png.
        // (A `Flows` event is a full pass, so this becomes the only flow.)
        let mut png = b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR".to_vec();
        png.extend_from_slice(&[0u8; 32]);
        let _ = app.on_bus(BusEvent::Flows(vec![summary(
            "img",
            "GET",
            "cdn.shop-staging.test",
            "/hero.png",
            Some(200),
            "observed",
        )]));
        let d = FlowDetail::from_json(&json!({"id":"img","kind":"http",
            "response":{"status":200,"headers":[["content-type","image/png"]],"body": crate::base64::encode(&png)}}))
        .unwrap();
        let _ = app.on_bus(BusEvent::Detail(Box::new(d)));
        app.selected = Some("img".into());
        app.mode = Mode::Inspector;
        app.inspector.pane = Pane::Response;
        let _ = app.update(Action::OpenExternally);
        let t = app.take_open_target().expect("image target");
        assert!(t.path.ends_with("aitm-tui-img.png"), "{}", t.path.display());
        assert_eq!(std::fs::read(&t.path).unwrap(), png);
        assert_eq!(t.label, "img response body");
        assert!(app
            .current_toast()
            .unwrap()
            .text
            .ends_with("aitm-tui-img.png — opening"));
        assert!(app.take_open_target().is_none(), "taken once");
        let _ = std::fs::remove_file(&t.path);
        // The request pane of the same flow has no body to open.
        app.inspector.pane = Pane::Request;
        let _ = app.update(Action::OpenExternally);
        assert!(app.take_open_target().is_none());
        assert_eq!(
            app.current_toast().map(|t| t.text.as_str()),
            Some("no request body to open")
        );
        // A large text body goes to a .txt; from the flow list the response is taken.
        let big = "x".repeat(crate::viewers::LARGE_BODY_BYTES + 1);
        let d = FlowDetail::from_json(&json!({"id":"img","kind":"http",
            "response":{"status":200,"headers":[["content-type","text/plain"]],"body": crate::base64::encode(big.as_bytes())}}))
        .unwrap();
        let _ = app.on_bus(BusEvent::Detail(Box::new(d)));
        app.mode = Mode::Flows;
        let _ = app.update(Action::OpenExternally);
        let t = app.take_open_target().expect("large body target");
        assert!(t.path.ends_with("aitm-tui-img.txt"), "{}", t.path.display());
        assert_eq!(
            std::fs::metadata(&t.path).unwrap().len() as usize,
            big.len()
        );
        let _ = std::fs::remove_file(&t.path);
        // No selection: say what `o` is for.
        app.selected = None;
        let _ = app.update(Action::OpenExternally);
        assert!(app.take_open_target().is_none());
        assert_eq!(
            app.current_toast().map(|t| t.text.as_str()),
            Some("o opens the selected flow's image or large body")
        );
    }

    /// C4: `P` asks for the name, then the param; Findings `r` asks for the
    /// target, then `k=v` vars; blanks are `None`.
    #[test]
    fn poc_build_and_run_take_their_second_prompts() {
        let mut app = app_with_flows();
        app.selected = Some("f1".into());
        let _ = app.update(Action::BuildPoc);
        assert_eq!(app.mode, Mode::Prompt(PromptKind::PocName));
        for c in "IDOR".chars() {
            let _ = app.update(Action::Input(c));
        }
        assert!(app.update(Action::Submit).is_empty());
        assert_eq!(app.mode, Mode::Prompt(PromptKind::PocParam));
        assert_eq!(app.prompt, "");
        for c in "id".chars() {
            let _ = app.update(Action::Input(c));
        }
        assert_eq!(
            app.update(Action::Submit),
            vec![BusRequest::PocBuild {
                flow_id: "f1".into(),
                name: Some("IDOR".into()),
                param: Some("id".into())
            }]
        );
        assert_eq!(app.mode, Mode::Flows);
        // Blank name and param.
        let _ = app.update(Action::BuildPoc);
        let _ = app.update(Action::Submit);
        assert_eq!(
            app.update(Action::Submit),
            vec![BusRequest::PocBuild {
                flow_id: "f1".into(),
                name: None,
                param: None
            }]
        );
        // Esc on the second prompt drops the pending build.
        let _ = app.update(Action::BuildPoc);
        let _ = app.update(Action::Submit);
        let _ = app.update(Action::Back);
        assert!(app.poc_pending.is_none());
        assert_eq!(app.mode, Mode::Flows);

        // Run again: target, then vars.
        app.findings =
            vec![Finding::from_json(&json!({"poc_path": "pocs/x.yaml", "passed": true})).unwrap()];
        app.mode = Mode::Findings;
        let _ = app.update(Action::PocRerun);
        assert_eq!(app.mode, Mode::Prompt(PromptKind::PocTarget));
        for c in "https://t.test".chars() {
            let _ = app.update(Action::Input(c));
        }
        assert!(app.update(Action::Submit).is_empty());
        assert_eq!(app.mode, Mode::Prompt(PromptKind::PocVars));
        for c in "user=alice n=2".chars() {
            let _ = app.update(Action::Input(c));
        }
        assert_eq!(
            app.update(Action::Submit),
            vec![BusRequest::PocRun {
                poc_path: "pocs/x.yaml".into(),
                target: Some("https://t.test".into()),
                vars: Some(json!({"user": "alice", "n": "2"}))
            }]
        );
        assert_eq!(app.mode, Mode::Findings);
        // Blank target and vars.
        let _ = app.update(Action::PocRerun);
        let _ = app.update(Action::Submit);
        assert_eq!(
            app.update(Action::Submit),
            vec![BusRequest::PocRun {
                poc_path: "pocs/x.yaml".into(),
                target: None,
                vars: None
            }]
        );
        // A malformed vars line keeps the prompt open and says so.
        let _ = app.update(Action::PocRerun);
        let _ = app.update(Action::Submit);
        for c in "novalue".chars() {
            let _ = app.update(Action::Input(c));
        }
        assert!(app.update(Action::Submit).is_empty());
        assert_eq!(app.mode, Mode::Prompt(PromptKind::PocVars));
        assert_eq!(
            app.current_toast().map(|t| t.text.as_str()),
            Some("vars: `novalue` is not key=value")
        );
        let _ = app.update(Action::Back);
        assert_eq!(app.mode, Mode::Findings);
        assert!(app.poc_run_pending.is_none());
    }

    /// C4: on a loopback bus a finding without YAML reads it from `poc_path`;
    /// an unreadable path is reported; a remote bus never touches the disk.
    #[test]
    fn finding_yaml_is_read_from_poc_path_on_a_loopback_bus() {
        let dir = std::env::temp_dir();
        let path = dir.join("aitm-tui-test-finding.yaml");
        std::fs::write(&path, "name: from disk\n").unwrap();
        let findings = |p: &std::path::Path| {
            vec![
                Finding::from_json(&json!({"poc_path": p.to_string_lossy(), "passed": true}))
                    .unwrap(),
                Finding::from_json(
                    &json!({"poc_path": "/nonexistent/aitm-tui/x.yaml", "passed": false}),
                )
                .unwrap(),
                Finding::from_json(
                    &json!({"poc_path": "/nonexistent/y.yaml", "yaml": "name: inline\n"}),
                )
                .unwrap(),
            ]
        };
        let mut local = App::new(TermCaps::full(), "127.0.0.1:9090");
        assert!(local.is_loopback_bus());
        let _ = local.on_bus(BusEvent::Findings(findings(&path)));
        assert_eq!(local.findings[0].yaml.as_deref(), Some("name: from disk\n"));
        assert!(local.findings[1].yaml.is_none());
        assert!(
            local.findings[1]
                .yaml_error
                .as_deref()
                .is_some_and(|e| !e.is_empty()),
            "{:?}",
            local.findings[1].yaml_error
        );
        assert_eq!(local.findings[2].yaml.as_deref(), Some("name: inline\n"));
        let embedded = App::new(TermCaps::full(), "in-process");
        assert!(embedded.is_loopback_bus());
        let mut remote = App::new(TermCaps::full(), "10.0.0.5:9090");
        assert!(!remote.is_loopback_bus());
        let _ = remote.on_bus(BusEvent::Findings(findings(&path)));
        assert!(remote.findings[0].yaml.is_none());
        assert!(remote.findings[1].yaml_error.is_none());
        assert!(!App::new(TermCaps::full(), "remote.test:9090").is_loopback_bus());
        let _ = std::fs::remove_file(&path);
    }

    /// C4: `:compose <template>`; `ws` names F9.
    #[test]
    fn compose_templates_fill_the_form() {
        let mut app = app_with_flows();
        assert!(app.run_command("compose post-json").is_empty());
        assert_eq!(app.mode, Mode::Compose);
        assert_eq!(app.compose.method, "POST");
        assert_eq!(app.compose.headers, "Content-Type: application/json");
        assert_eq!(app.compose.body, "{}");
        assert_eq!(app.compose.field, 1);
        let _ = app.run_command("compose post-form");
        assert_eq!(
            app.compose.headers,
            "Content-Type: application/x-www-form-urlencoded"
        );
        assert_eq!(app.compose.body, "");
        let _ = app.run_command("compose get");
        assert_eq!(app.compose, ComposeForm::template_get());
        app.mode = Mode::Flows;
        let _ = app.run_command("compose ws");
        assert_eq!(app.mode, Mode::Flows);
        assert!(app.current_toast().unwrap().text.contains("F9"));
        let _ = app.run_command("compose nope");
        assert!(app
            .current_toast()
            .unwrap()
            .text
            .starts_with("unknown compose template `nope`"));
        // Bare `:compose` still prefills from the selection.
        app.selected = Some("f2".into());
        let _ = app.run_command("compose");
        assert_eq!(app.compose.method, "POST");
        assert_eq!(app.compose.url, "https://telemetry.vendor.example/v2/batch");
    }

    /// C3 / I1 / M-misc: `:split` and `:export` say what is missing; the
    /// Scope sidebar item filters the list; Resume all reports what it skipped.
    #[test]
    fn split_export_scope_item_and_resume_all_report_honestly() {
        let mut app = app_with_flows();
        assert!(app.run_command("split").is_empty());
        assert_eq!(
            app.current_toast().map(|t| t.text.as_str()),
            Some("split view: not built in this pass (needs ≥ 160 cols)")
        );
        assert!(app.run_command("export").is_empty());
        assert!(app.current_toast().unwrap().text.contains("F10"));
        app.sidebar = SidebarItem::Domains;
        let _ = app.update(Action::SidebarNext);
        assert_eq!(app.sidebar, SidebarItem::Scope);
        assert_eq!(app.mode, Mode::Flows, "the item filters; S opens the panel");
        assert_eq!(app.visible().len(), 2);
        let _ = app.update(Action::OpenScope);
        assert_eq!(app.mode, Mode::Scope);
        // Two paused flows, one out of scope.
        let _ = app.on_bus(BusEvent::Flows(vec![
            summary(
                "f1",
                "GET",
                "api.shop-staging.test",
                "/a",
                None,
                "intercepted",
            ),
            summary(
                "f2",
                "POST",
                "telemetry.vendor.example",
                "/b",
                None,
                "intercepted",
            ),
        ]));
        assert_eq!(
            app.update(Action::ResumeAll),
            vec![BusRequest::Resume("f1".into())]
        );
        assert_eq!(
            app.current_toast().map(|t| t.text.as_str()),
            Some(
                "Resume all: 1 resumed, 1 skipped — out of scope (add their hosts to scope to act)"
            )
        );
    }

    /// An app on `f41` — a completed GET whose response is a small JSON
    /// document, 18 lines as a tree — with the Response pane's JSON tab
    /// focused. Both the summary and the body are written here.
    fn json_tab_app() -> App {
        let mut app = crate::connected_app(200, 50);
        let _ = app.on_bus(BusEvent::Flows(vec![summary(
            "f41",
            "GET",
            "api.example.test",
            "/api/products?category=widgets&limit=2",
            Some(200),
            "observed",
        )]));
        let body = json!({
            "items": [
                {"id": 1, "name": "Widget", "price": 9.5, "in_stock": true},
                {"id": 2, "name": "Gadget", "price": 12.0, "in_stock": false}
            ],
            "page": 1,
            "total": 2
        })
        .to_string();
        let d = FlowDetail::from_json(&json!({"id":"f41","kind":"http",
            "response":{"status":200,"headers":[["content-type","application/json"]],
                        "body": crate::base64::encode(body.as_bytes())}}))
        .unwrap();
        let _ = app.on_bus(BusEvent::Detail(Box::new(d)));
        app.selected = Some("f41".into());
        app.mode = Mode::Inspector;
        app.inspector.pane = Pane::Response;
        app.inspector.response_tab = RESPONSE_TABS
            .iter()
            .position(|t| *t == "JSON")
            .expect("JSON tab");
        app
    }

    fn json_tab_text(app: &App) -> Vec<String> {
        let body = app
            .selected_detail()
            .and_then(|d| d.response.as_ref())
            .and_then(Message::body_text)
            .expect("f41 response body");
        crate::viewers::json::tree(&crate::theme::Theme::new(true), body, &app.inspector.folds)
            .expect("f41 body is JSON")
            .iter()
            .map(|l| {
                l.spans
                    .iter()
                    .map(|s| s.content.as_ref())
                    .collect::<String>()
            })
            .collect()
    }

    #[test]
    fn toggle_fold_folds_the_json_node_under_the_cursor() {
        let mut app = json_tab_app();
        // Line 0 is `{`; line 1 is `"items": [` (gutter line 2).
        app.inspector.cursor_line = 1;
        assert_eq!(app.json_cursor_path().as_deref(), Some("$.items"));
        assert!(app.update(Action::ToggleFold).is_empty());
        assert!(app.inspector.folds.contains("$.items"));
        let lines = json_tab_text(&app);
        assert_eq!(lines[1], "▸   \"items\": […] 2 items,");
        assert_eq!(lines.len(), 5);
        let _ = app.update(Action::ToggleFold);
        assert!(!app.inspector.folds.contains("$.items"));
        assert_eq!(json_tab_text(&app).len(), 18);

        // A leaf line has a path but nothing to fold.
        app.inspector.cursor_line = 3;
        assert_eq!(app.json_cursor_path().as_deref(), Some("$.items[0].id"));
        let _ = app.update(Action::ToggleFold);
        assert!(app.inspector.folds.is_empty());

        // Only the Response pane's JSON tab folds.
        app.inspector.cursor_line = 1;
        app.inspector.pane = Pane::Request;
        assert_eq!(app.json_cursor_path(), None);
        let _ = app.update(Action::ToggleFold);
        assert!(app.inspector.folds.is_empty());
        app.inspector.pane = Pane::Response;
        app.inspector.response_tab = 1;
        assert_eq!(app.json_cursor_path(), None);
        let _ = app.update(Action::ToggleFold);
        assert!(app.inspector.folds.is_empty());
    }

    #[test]
    fn inspector_up_down_move_the_cursor_line_and_clamp_to_the_tree() {
        let mut app = json_tab_app();
        assert_eq!(app.inspector.cursor_line, 0);
        let _ = app.update(Action::Down);
        let _ = app.update(Action::Down);
        assert_eq!(app.inspector.cursor_line, 2);
        assert_eq!(app.inspector.scroll, 0);
        assert_eq!(app.json_cursor_path().as_deref(), Some("$.items[0]"));
        let _ = app.update(Action::Up);
        let _ = app.update(Action::Up);
        let _ = app.update(Action::Up);
        assert_eq!(app.inspector.cursor_line, 0);
        // 18 lines in the unfolded tree: End lands on the last one.
        let _ = app.update(Action::End);
        assert_eq!(app.inspector.cursor_line, 17);
        let _ = app.update(Action::Down);
        assert_eq!(app.inspector.cursor_line, 17);
        let _ = app.update(Action::Home);
        assert_eq!(app.inspector.cursor_line, 0);
        assert_eq!(app.inspector.scroll, 0);
        // PageDown moves the window by 20 and pulls the cursor into it
        // (the tree is shorter than a page, so the cursor stops on the last line).
        let _ = app.update(Action::PageDown);
        assert_eq!(app.inspector.scroll, 20);
        assert_eq!(app.inspector.cursor_line, 17);
        let _ = app.update(Action::PageUp);
        assert_eq!(app.inspector.scroll, 0);
        assert_eq!(app.inspector.cursor_line, 17);
        // Changing tab or pane puts the cursor back at the top.
        let _ = app.update(Action::InspectorTabNext);
        assert_eq!(app.inspector.cursor_line, 0);
    }

    #[test]
    fn copy_offers_the_url_in_flows_and_the_node_path_on_the_json_tab() {
        let mut app = json_tab_app();
        app.inspector.cursor_line = 4;
        assert_eq!(
            app.copy_text().as_deref(),
            Some("$.items[0].name"),
            "JSON tab copies the node path"
        );
        let _ = app.update(Action::CopyUrl);
        assert_eq!(
            app.current_toast().map(|t| t.text.as_str()),
            Some("node path copied (OSC 52)")
        );
        app.mode = Mode::Flows;
        assert_eq!(
            app.copy_text().as_deref(),
            Some("https://api.example.test/api/products?category=widgets&limit=2")
        );
        let _ = app.update(Action::CopyUrl);
        assert_eq!(
            app.current_toast().map(|t| t.text.as_str()),
            Some("URL copied (OSC 52)")
        );
        app.selected = None;
        assert_eq!(app.copy_text(), None);
    }

    // ------------------------------------------- core sync 2026-10-28 (C3–C12)

    fn status(listening: bool, capturing: bool, paused: u64) -> ProxyStatus {
        ProxyStatus {
            listening,
            address: Some("127.0.0.1:8080".into()),
            intercept_armed: true,
            capturing,
            paused,
            flows: 3,
            system_proxy: None,
        }
    }

    /// C3: `proxy.status` drives the pill, the armed flag, the record toggle
    /// and the store's paused count.
    #[test]
    fn proxy_status_event_sets_listening_armed_capture_and_paused() {
        let mut app = app_with_flows();
        assert_eq!(app.listening, None);
        assert_eq!(app.serving, None);
        assert!(app
            .on_bus(BusEvent::ProxyStatus(status(true, false, 2)))
            .is_empty());
        assert_eq!(app.listening.as_deref(), Some("127.0.0.1:8080"));
        assert_eq!(app.serving, Some(true));
        assert!(app.intercept_armed);
        assert!(app.capture_paused, "capturing: false is a paused capture");
        assert_eq!(app.store_paused, Some(2));
        let _ = app.on_bus(BusEvent::ProxyStatus(status(false, true, 0)));
        assert_eq!(app.serving, Some(false));
        assert!(!app.capture_paused);
        assert_eq!(
            app.listening.as_deref(),
            Some("127.0.0.1:8080"),
            "the configured address is still known while not serving"
        );
    }

    /// C4: `:pause` → `proxy.pause`, `:record` → `proxy.resume`, each gated
    /// on its own tool; the reply's `capturing` sets the toggle and toasts.
    #[test]
    fn pause_and_record_need_their_own_tools_and_follow_the_capture_state() {
        let mut app = app_with_flows();
        app.tools.extend(tools(&["proxy.pause"]));
        assert_eq!(app.run_command("pause"), vec![BusRequest::ProxyPause(true)]);
        assert!(app.run_command("record").is_empty());
        assert!(app.current_toast().unwrap().text.contains("proxy.resume"));
        app.tools.extend(tools(&["proxy.resume"]));
        assert_eq!(
            app.run_command("record"),
            vec![BusRequest::ProxyPause(false)]
        );
        let reqs = app.on_bus(BusEvent::CallOk {
            name: "proxy.pause".into(),
            value: json!({"capturing": false}),
        });
        assert!(app.capture_paused);
        assert_eq!(
            app.current_toast().map(|t| t.text.as_str()),
            Some("capture paused")
        );
        assert_eq!(reqs, vec![BusRequest::Refresh]);
        let _ = app.on_bus(BusEvent::CallOk {
            name: "proxy.resume".into(),
            value: json!({"capturing": true}),
        });
        assert!(!app.capture_paused);
        assert_eq!(
            app.current_toast().map(|t| t.text.as_str()),
            Some("capture resumed")
        );
    }

    /// M6 F3: `flow.intercept` answers with `{enabled, rules}` (was a bare bool).
    /// The toggle reads `enabled` from the object shape, not `as_bool()` on the
    /// whole value (which would now always be `None` and freeze the armed state).
    #[test]
    fn flow_intercept_result_reads_enabled_from_object() {
        let mut app = app_with_flows();
        assert!(!app.intercept_armed);
        let _ = app.on_bus(BusEvent::CallOk {
            name: "flow.intercept".into(),
            value: json!({"enabled": true, "rules": []}),
        });
        assert!(app.intercept_armed, "enabled:true must arm the toggle");
        let _ = app.on_bus(BusEvent::CallOk {
            name: "flow.intercept".into(),
            value: json!({"enabled": false, "rules": [{"url": {"wildcard": "*/admin"}}]}),
        });
        assert!(!app.intercept_armed, "enabled:false must disarm the toggle");
    }

    /// C5: `flow.clear` answers with counts; the toast says both.
    #[test]
    fn flow_clear_result_is_a_counted_toast_then_a_refresh() {
        let mut app = app_with_flows();
        let reqs = app.on_bus(BusEvent::CallOk {
            name: "flow.clear".into(),
            value: json!({"cleared": 12, "skipped_in_flight": 3}),
        });
        assert_eq!(
            app.current_toast().map(|t| t.text.as_str()),
            Some("cleared 12 flows · 3 in flight kept")
        );
        assert_eq!(reqs, vec![BusRequest::Refresh]);
    }

    /// C6: after `flow.mark` / `flow.comment` the selected flow's detail is
    /// stale (the row's swatch and comment come from it): drop it and ask again.
    #[test]
    fn mark_and_comment_results_refetch_the_selected_detail() {
        let mut app = app_with_flows();
        app.tools
            .extend(tools(&["flow.detail", "flow.mark", "flow.comment"]));
        app.selected = Some("f1".into());
        let d = FlowDetail::from_json(&json!({"id":"f1","kind":"http","meta":{"marks":["red"]}}))
            .unwrap();
        let _ = app.on_bus(BusEvent::Detail(Box::new(d)));
        assert_eq!(app.row("f1").unwrap().marks, vec!["red".to_string()]);
        let reqs = app.on_bus(BusEvent::CallOk {
            name: "flow.mark".into(),
            value: json!(["red", "sky"]),
        });
        assert!(
            !app.details.contains_key("f1"),
            "the stale detail is dropped"
        );
        assert_eq!(
            reqs,
            vec![BusRequest::Detail("f1".into()), BusRequest::Refresh]
        );
        assert_eq!(
            app.current_toast().map(|t| t.text.as_str()),
            Some("marked: red sky")
        );
        let d = FlowDetail::from_json(&json!({"id":"f1","kind":"http"})).unwrap();
        let _ = app.on_bus(BusEvent::Detail(Box::new(d)));
        let reqs = app.on_bus(BusEvent::CallOk {
            name: "flow.comment".into(),
            value: Value::Null,
        });
        assert_eq!(
            reqs,
            vec![BusRequest::Detail("f1".into()), BusRequest::Refresh]
        );
        assert_eq!(
            app.current_toast().map(|t| t.text.as_str()),
            Some("comment cleared")
        );
    }

    /// C7: `scope.remove` answers a bool; the toast names the host either way
    /// and a removed host leaves the panel at once.
    #[test]
    fn scope_remove_result_names_the_host() {
        let mut app = app_with_flows();
        app.tools.extend(tools(&["scope.remove"]));
        app.scope = vec!["a.test".into(), "b.test".into()];
        assert_eq!(
            app.run_command("scope rm a.test"),
            vec![BusRequest::ScopeRemove("a.test".into())]
        );
        let _ = app.on_bus(BusEvent::CallOk {
            name: "scope.remove".into(),
            value: json!(true),
        });
        assert_eq!(
            app.current_toast().map(|t| t.text.as_str()),
            Some("removed a.test")
        );
        assert_eq!(app.scope, vec!["b.test".to_string()]);
        let _ = app.run_command("scope rm zzz.test");
        let _ = app.on_bus(BusEvent::CallOk {
            name: "scope.remove".into(),
            value: json!(false),
        });
        assert_eq!(
            app.current_toast().map(|t| t.text.as_str()),
            Some("zzz.test was not in scope")
        );
        assert_eq!(app.scope, vec!["b.test".to_string()]);
    }

    /// C8: a `poc.list` pass is the library: it fills paths with no run and
    /// never overrides or drops a run result from this session.
    #[test]
    fn library_pass_merges_under_this_sessions_run_results() {
        let mut app = App::new(TermCaps::full(), "10.0.0.5:9090");
        app.tools = tools(&["poc.list", "poc.run"]);
        let _ = app.on_bus(BusEvent::CallOk {
            name: "poc.run".into(),
            value: json!({"poc_path": "pocs/a.yaml", "passed": true, "finding_capture": "f1",
                          "evaluated": [{"assertion": "status == 200", "matched": true}]}),
        });
        let _ = app.on_bus(BusEvent::CallOk {
            name: "poc.run".into(),
            value: json!({"poc_path": "pocs/gone.yaml", "passed": false}),
        });
        assert_eq!(app.findings.len(), 2);
        let library = vec![
            Finding::from_json(
                &json!({"poc_path": "pocs/a.yaml", "id": "a", "title": "A", "severity": "high"}),
            )
            .unwrap(),
            Finding::from_json(
                &json!({"poc_path": "pocs/b.yaml", "id": "b", "title": "B", "severity": "low",
                                       "description": "about b"}),
            )
            .unwrap(),
        ];
        let _ = app.on_bus(BusEvent::Findings(library.clone()));
        let paths: Vec<&str> = app.findings.iter().map(|f| f.poc_path.as_str()).collect();
        assert_eq!(paths, vec!["pocs/gone.yaml", "pocs/a.yaml", "pocs/b.yaml"]);
        let a = app
            .findings
            .iter()
            .find(|f| f.poc_path == "pocs/a.yaml")
            .unwrap();
        assert!(a.ran && a.passed, "the run's verdict wins over the library");
        assert_eq!(a.assertions.len(), 1);
        let b = app
            .findings
            .iter()
            .find(|f| f.poc_path == "pocs/b.yaml")
            .unwrap();
        assert!(!b.ran);
        assert_eq!(b.title, "B");
        assert_eq!(b.description.as_deref(), Some("about b"));
        let gone = app
            .findings
            .iter()
            .find(|f| f.poc_path == "pocs/gone.yaml")
            .unwrap();
        assert!(
            gone.ran && !gone.passed,
            "a run the library pass omits is kept"
        );
        // A second run of a path replaces its entry instead of duplicating it.
        let _ = app.on_bus(BusEvent::CallOk {
            name: "poc.run".into(),
            value: json!({"poc_path": "pocs/b.yaml", "passed": true}),
        });
        assert_eq!(app.findings.len(), 3);
        assert_eq!(app.findings[0].poc_path, "pocs/b.yaml");
        assert!(app.findings[0].ran && app.findings[0].passed);
        assert_eq!(app.findings[0].title, "B", "the library's title is kept");
        assert_eq!(app.finding_cursor, 0);
        // Script findings sit beside them and survive a library pass.
        let _ = app.on_bus(BusEvent::ScriptFindings(vec![Finding::from_script_json(
            &json!({"name": "admin write", "severity": "high", "source": "observer", "at": 1}),
        )
        .unwrap()]));
        assert_eq!(app.findings.len(), 4);
        let _ = app.on_bus(BusEvent::Findings(library));
        assert_eq!(app.findings.len(), 4);
        assert!(app
            .findings
            .iter()
            .any(|f| f.script.as_deref() == Some("observer")));
        // `r` on a script finding has nothing to run.
        app.mode = Mode::Findings;
        app.finding_cursor = 3;
        assert!(app.update(Action::PocRerun).is_empty());
        assert_eq!(app.mode, Mode::Findings);
        assert_eq!(
            app.current_toast().map(|t| t.text.as_str()),
            Some("a script finding has no PoC to run")
        );
    }

    /// C9: with `poc.get` on the bus the YAML comes over the bus, once per
    /// path, and never from this machine's disk.
    #[test]
    fn poc_get_fills_the_yaml_when_the_bus_has_it() {
        let mut app = App::new(TermCaps::full(), "127.0.0.1:9090");
        assert!(app.is_loopback_bus());
        app.tools = tools(&["poc.list", "poc.get"]);
        let library = vec![
            Finding::from_json(&json!({"poc_path": "/nonexistent/a.yaml", "title": "A"})).unwrap(),
            Finding::from_json(&json!({"poc_path": "/nonexistent/b.yaml", "title": "B"})).unwrap(),
        ];
        let reqs = app.on_bus(BusEvent::Findings(library.clone()));
        assert_eq!(
            reqs,
            vec![
                BusRequest::PocGet("/nonexistent/a.yaml".into()),
                BusRequest::PocGet("/nonexistent/b.yaml".into())
            ]
        );
        assert!(
            app.findings.iter().all(|f| f.yaml_error.is_none()),
            "no disk read when poc.get exists: {:?}",
            app.findings
        );
        // The same pass again asks nothing while the first is in flight.
        assert!(app.on_bus(BusEvent::Findings(library.clone())).is_empty());
        let reqs = app.on_bus(BusEvent::CallOk {
            name: "poc.get".into(),
            value: json!({"poc_path": "/nonexistent/a.yaml", "id": "a", "title": "A", "severity": "high",
                          "description": "about a", "yaml": "name: A\n"}),
        });
        assert!(reqs.is_empty(), "a read is not a mutation: no refresh");
        let a = app
            .findings
            .iter()
            .find(|f| f.poc_path == "/nonexistent/a.yaml")
            .unwrap();
        assert_eq!(a.yaml.as_deref(), Some("name: A\n"));
        assert_eq!(a.description.as_deref(), Some("about a"));
        let _ = app.on_bus(BusEvent::CallFailed {
            name: "poc.get".into(),
            message: "poc.get: not found or outside the configured PoC directory".into(),
        });
        let b = app
            .findings
            .iter()
            .find(|f| f.poc_path == "/nonexistent/b.yaml")
            .unwrap();
        assert_eq!(
            b.yaml_error.as_deref(),
            Some("poc.get: not found or outside the configured PoC directory")
        );
        // A later pass asks for neither again.
        assert!(app.on_bus(BusEvent::Findings(library)).is_empty());
    }

    /// C10: on a bus that is not loopback the screenshot comes through
    /// `poc.artifact` and lands in a private temp file for `o`.
    #[test]
    fn findings_o_fetches_the_screenshot_through_poc_artifact_off_loopback() {
        let mut app = App::new(TermCaps::full(), "10.0.0.5:9090");
        app.tools = tools(&["poc.list", "poc.artifact"]);
        app.findings = vec![Finding::from_json(
            &json!({"poc_path": "pocs/x.yaml", "passed": true, "screenshot_path": "/srv/out/x.png"}),
        )
        .unwrap()];
        app.mode = Mode::Findings;
        assert_eq!(
            app.update(Action::OpenExternally),
            vec![BusRequest::Call {
                name: "poc.artifact".into(),
                args: json!({"path": "/srv/out/x.png"})
            }]
        );
        assert!(
            app.take_open_target().is_none(),
            "nothing opens before the bytes arrive"
        );
        let mut png = b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR".to_vec();
        png.extend_from_slice(&[0u8; 32]);
        let reqs = app.on_bus(BusEvent::CallOk {
            name: "poc.artifact".into(),
            value: Value::String(crate::base64::encode(&png)),
        });
        assert!(reqs.is_empty(), "a read is not a mutation: no refresh");
        let t = app.take_open_target().expect("the screenshot opens");
        assert!(
            t.path.ends_with("aitm-tui-poc-screenshot.png"),
            "{}",
            t.path.display()
        );
        assert_eq!(std::fs::read(&t.path).unwrap(), png);
        assert_eq!(t.label, "screenshot /srv/out/x.png");
        let _ = std::fs::remove_file(&t.path);
        // Bytes that are not an image are refused.
        let _ = app.update(Action::OpenExternally);
        let _ = app.on_bus(BusEvent::CallOk {
            name: "poc.artifact".into(),
            value: Value::String(crate::base64::encode(b"hello")),
        });
        assert!(app.take_open_target().is_none());
        assert_eq!(
            app.current_toast().map(|t| t.text.as_str()),
            Some("poc.artifact: /srv/out/x.png is not an image")
        );
        // Without `poc.artifact` an unresolved path is the old refusal.
        app.tools.retain(|t| t.name != "poc.artifact");
        assert!(app.update(Action::OpenExternally).is_empty());
        assert!(app
            .current_toast()
            .is_some_and(|t| t.text.starts_with("open: /srv/out/x.png: ")));
    }

    /// C11: `:config` asks `config.get` and shows the redacted object; without
    /// the tool the panel is labelled.
    #[test]
    fn config_command_fetches_and_holds_the_redacted_config() {
        let mut app = app_with_flows();
        assert!(app.run_command("config").is_empty());
        assert_eq!(app.mode, Mode::Config);
        assert!(app.current_toast().unwrap().text.contains("F7"));
        let _ = app.update(Action::Back);
        assert_eq!(app.mode, Mode::Flows);
        app.tools.extend(tools(&["config.get"]));
        assert_eq!(
            app.run_command("config"),
            vec![BusRequest::Call {
                name: "config.get".into(),
                args: json!({})
            }]
        );
        assert_eq!(app.mode, Mode::Config);
        let reqs = app.on_bus(BusEvent::CallOk {
            name: "config.get".into(),
            value: json!({"listen": "127.0.0.1:8080", "scope": {"entries": ["a.test"]}}),
        });
        assert!(reqs.is_empty(), "a read is not a mutation: no refresh");
        assert_eq!(app.config.as_ref().unwrap()["listen"], "127.0.0.1:8080");
        // The scope panel asks for it once too (its rate-limit readout).
        app.config = None;
        assert_eq!(
            app.update(Action::OpenScope),
            vec![BusRequest::Call {
                name: "config.get".into(),
                args: json!({})
            }]
        );
    }

    /// C12: the core's `poc.build` returns the YAML text, not a path. The TUI
    /// writes it under the PoC dir (never overwriting), toasts the path and
    /// lists it as a library entry `r` can run.
    #[test]
    fn poc_build_yaml_text_is_written_under_the_poc_dir_and_listed() {
        let dir = std::env::temp_dir().join(format!("aitm-tui-poc-build-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut app = app_with_flows();
        app.tools.extend(tools(&["poc.build", "poc.run"]));
        app.poc_dir = Some(dir.clone());
        app.selected = Some("f1".into());
        let _ = app.update(Action::BuildPoc);
        for c in "Reflected XSS".chars() {
            let _ = app.update(Action::Input(c));
        }
        let _ = app.update(Action::Submit);
        assert_eq!(app.update(Action::Submit).len(), 1, "poc.build is sent");
        let yaml = "id: reflected-xss\ninfo:\n  name: Reflected XSS in q\n  severity: high\n";
        let reqs = app.on_bus(BusEvent::CallOk {
            name: "poc.build".into(),
            value: Value::String(yaml.into()),
        });
        let path = dir.join("reflected-xss.yaml");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), yaml);
        assert_eq!(
            app.current_toast().map(|t| t.text.as_str()),
            Some(format!("PoC written: {}", path.display())).as_deref()
        );
        assert_eq!(reqs, vec![BusRequest::Refresh]);
        let f = app
            .findings
            .iter()
            .find(|f| f.poc_path == path.to_string_lossy())
            .expect("listed as a library entry");
        assert!(!f.ran);
        assert_eq!(f.title, "Reflected XSS in q");
        assert_eq!(f.severity, crate::model::Severity::High);
        assert_eq!(f.yaml.as_deref(), Some(yaml));
        // `r` on it runs that path.
        app.mode = Mode::Findings;
        app.finding_cursor = app
            .findings
            .iter()
            .position(|x| x.poc_path == f.poc_path)
            .unwrap();
        let _ = app.update(Action::PocRerun);
        let _ = app.update(Action::Submit);
        assert_eq!(
            app.update(Action::Submit),
            vec![BusRequest::PocRun {
                poc_path: path.to_string_lossy().into_owned(),
                target: None,
                vars: None
            }]
        );
        // A second build with the same name never overwrites: `-2`.
        app.mode = Mode::Flows;
        let _ = app.update(Action::BuildPoc);
        for c in "Reflected XSS".chars() {
            let _ = app.update(Action::Input(c));
        }
        let _ = app.update(Action::Submit);
        let _ = app.update(Action::Submit);
        let _ = app.on_bus(BusEvent::CallOk {
            name: "poc.build".into(),
            value: Value::String("id: again\n".into()),
        });
        let second = dir.join("reflected-xss-2.yaml");
        assert_eq!(std::fs::read_to_string(&second).unwrap(), "id: again\n");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), yaml, "untouched");
        // A blank name falls back to the flow's sequence number.
        let _ = app.update(Action::BuildPoc);
        let _ = app.update(Action::Submit);
        let _ = app.update(Action::Submit);
        let _ = app.on_bus(BusEvent::CallOk {
            name: "poc.build".into(),
            value: Value::String("id: blank\n".into()),
        });
        assert!(dir.join("poc-1.yaml").is_file());
        // A path-looking reply keeps today's behaviour.
        let _ = app.on_bus(BusEvent::CallOk {
            name: "poc.build".into(),
            value: json!("pocs/reflected-xss.yaml"),
        });
        assert_eq!(
            app.current_toast().map(|t| t.text.as_str()),
            Some("PoC written: pocs/reflected-xss.yaml")
        );
        let _ = std::fs::remove_dir_all(&dir);
        // No PoC dir anywhere: the temp fallback, and the toast says so.
        app.poc_dir = None;
        app.config = None;
        let _ = app.update(Action::BuildPoc);
        for c in "fallback".chars() {
            let _ = app.update(Action::Input(c));
        }
        let _ = app.update(Action::Submit);
        let _ = app.update(Action::Submit);
        let _ = app.on_bus(BusEvent::CallOk {
            name: "poc.build".into(),
            value: Value::String("id: fallback\n".into()),
        });
        let fallback = std::env::temp_dir().join("aitm-pocs");
        let toast = app.current_toast().unwrap().text.clone();
        assert!(
            toast.starts_with(&format!(
                "PoC written: {}",
                fallback.join("fallback").display()
            )),
            "{toast}"
        );
        assert!(toast.contains("no PoC dir configured"), "{toast}");
        assert!(toast.contains("--poc-dir"), "{toast}");
        for entry in std::fs::read_dir(&fallback).unwrap().flatten() {
            if entry.file_name().to_string_lossy().starts_with("fallback") {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }

    #[test]
    fn toasts_expire_on_ticks() {
        let mut app = App::new(TermCaps::full(), "x");
        app.toast(Level::Info, "hi");
        for _ in 0..15 {
            let _ = app.update(Action::Tick);
        }
        assert!(app.current_toast().is_some());
        let _ = app.update(Action::Tick);
        assert!(app.current_toast().is_none());
    }

    // ------------------------------------------------- system proxy (D14)

    fn sysproxy_call(name: &str) -> BusRequest {
        BusRequest::Call {
            name: name.into(),
            args: json!({}),
        }
    }

    fn sysproxy_word(state: &str) -> SystemProxyWord {
        SystemProxyWord {
            state: state.into(),
            supported: true,
            ..SystemProxyWord::default()
        }
    }

    /// SP-AC26 / D14: with the verbs on the bus, `:sysproxy on|off|status`
    /// is one bare call each; `on` and `off` raise the in-flight flag (the pill
    /// reads `setting…`), `status` does not; anything else is a usage error.
    #[test]
    fn sysproxy_on_calls_set_when_the_tool_exists() {
        let mut app = App::new(TermCaps::full(), "127.0.0.1:9090");
        app.tools.extend(tools(&[
            "proxy.system.set",
            "proxy.system.unset",
            "proxy.system.status",
        ]));
        assert_eq!(
            app.run_command(":sysproxy on"),
            vec![sysproxy_call("proxy.system.set")]
        );
        assert!(app.sysproxy_setting, "on → in flight until the reply");

        app.sysproxy_setting = false;
        assert_eq!(
            app.run_command(":sysproxy off"),
            vec![sysproxy_call("proxy.system.unset")]
        );
        assert!(app.sysproxy_setting, "off → in flight until the reply");

        app.sysproxy_setting = false;
        assert_eq!(
            app.run_command(":sysproxy status"),
            vec![sysproxy_call("proxy.system.status")]
        );
        assert!(!app.sysproxy_setting, "status reads; nothing is in flight");

        assert!(app.run_command(":sysproxy sideways").is_empty());
        assert!(app.run_command(":sysproxy").is_empty());
        let t = app.current_toast().expect("a usage toast");
        assert_eq!(t.level, Level::Error);
        assert_eq!(t.text, "usage: :sysproxy on|off|status");
    }

    /// SP-AC26 / D14: a bus without `proxy.system.set` (an older core, or a
    /// tools/list that hid it) gets the one warning toast and no call.
    #[test]
    fn sysproxy_without_the_tool_toasts() {
        let mut app = App::new(TermCaps::full(), "127.0.0.1:9090");
        assert!(app.run_command(":sysproxy on").is_empty());
        assert!(!app.sysproxy_setting);
        let t = app.current_toast().expect("a toast");
        assert_eq!(t.level, Level::Warn);
        assert_eq!(t.text, "System proxy needs the core's proxy.system.* verbs");
        // `off` and `status` are gated by the same tool.
        assert!(app.run_command(":sysproxy off").is_empty());
        assert!(app.run_command(":sysproxy status").is_empty());
        assert_eq!(app.toasts.len(), 3);
        assert!(app
            .toasts
            .iter()
            .all(|t| t.text == "System proxy needs the core's proxy.system.* verbs"));
    }

    /// D14: `s` in the flow list is `ToggleSysProxy`; the toggle sends `unset`
    /// only when the word says the system proxy already points at us, else `set`
    /// (including before the first `proxy.status` carried a word at all).
    #[test]
    fn s_key_toggles_by_state() {
        use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
        assert_eq!(
            crate::keys::map(
                KeyEvent::new(KeyCode::Char('s'), KeyModifiers::NONE),
                Mode::Flows
            ),
            Some(Action::ToggleSysProxy)
        );

        let mut app = App::new(TermCaps::full(), "127.0.0.1:9090");
        app.tools
            .extend(tools(&["proxy.system.set", "proxy.system.unset"]));

        app.system_proxy = Some(sysproxy_word("points_at_us"));
        assert_eq!(
            app.update(Action::ToggleSysProxy),
            vec![sysproxy_call("proxy.system.unset")]
        );
        assert!(app.sysproxy_setting);

        app.sysproxy_setting = false;
        app.system_proxy = Some(sysproxy_word("off"));
        assert_eq!(
            app.update(Action::ToggleSysProxy),
            vec![sysproxy_call("proxy.system.set")]
        );

        app.sysproxy_setting = false;
        app.system_proxy = Some(SystemProxyWord {
            host: Some("127.0.0.1".into()),
            port: Some(9090),
            ..sysproxy_word("other")
        });
        assert_eq!(
            app.update(Action::ToggleSysProxy),
            vec![sysproxy_call("proxy.system.set")]
        );

        app.sysproxy_setting = false;
        app.system_proxy = None;
        assert_eq!(
            app.update(Action::ToggleSysProxy),
            vec![sysproxy_call("proxy.system.set")]
        );

        // The key is gated like the command: no tool, no call, the warning.
        let mut bare = App::new(TermCaps::full(), "127.0.0.1:9090");
        bare.system_proxy = Some(sysproxy_word("off"));
        assert!(bare.update(Action::ToggleSysProxy).is_empty());
        assert_eq!(
            bare.current_toast().map(|t| t.text.as_str()),
            Some("System proxy needs the core's proxy.system.* verbs")
        );
    }

    /// D14: the `proxy.system.set` / `unset` reply clears the in-flight flag,
    /// replaces the word with the reply's state and toasts its `detail`; a bus
    /// error clears the flag and is shown verbatim; `proxy.system.status`
    /// toasts `detail`; every `proxy.status` poll refreshes the word.
    #[test]
    fn set_reply_clears_in_flight_and_updates_the_word() {
        let mut app = App::new(TermCaps::full(), "127.0.0.1:9090");
        app.tools.extend(tools(&[
            "proxy.system.set",
            "proxy.system.unset",
            "proxy.system.status",
        ]));
        app.system_proxy = Some(sysproxy_word("off"));

        let _ = app.run_command(":sysproxy on");
        assert!(app.sysproxy_setting);
        let reqs = app.on_bus(BusEvent::CallOk {
            name: "proxy.system.set".into(),
            value: json!({
                "state": "points_at_us", "host": null, "port": null,
                "managed_by_us": true, "setting": false, "supported": true,
                "mechanism": "networksetup", "services": ["Wi-Fi"],
                "detail": "HTTP and HTTPS → 127.0.0.1:8080 (this core)",
                "changed": true, "commands": ["networksetup -setwebproxy Wi-Fi 127.0.0.1 8080"]
            }),
        });
        assert!(
            !app.sysproxy_setting,
            "the reply settles the in-flight flag"
        );
        let word = app.system_proxy.as_ref().expect("the reply's word");
        assert_eq!(word.state, "points_at_us");
        assert!(word.managed_by_us);
        assert_eq!(
            word.pill(app.sysproxy_setting).as_deref(),
            Some("· sys-proxy → us")
        );
        let t = app.current_toast().expect("the detail toast");
        assert_eq!(t.level, Level::Info);
        assert_eq!(t.text, "HTTP and HTTPS → 127.0.0.1:8080 (this core)");
        assert_eq!(reqs, vec![BusRequest::Refresh]);

        // unset: the reply's `off` state replaces the word.
        let _ = app.run_command(":sysproxy off");
        assert!(app.sysproxy_setting);
        let _ = app.on_bus(BusEvent::CallOk {
            name: "proxy.system.unset".into(),
            value: json!({
                "state": "off", "host": null, "port": null, "managed_by_us": false,
                "setting": false, "supported": true, "detail": "HTTP and HTTPS off",
                "changed": true, "commands": [], "restored": ["Wi-Fi"], "left_alone": []
            }),
        });
        assert!(!app.sysproxy_setting);
        assert_eq!(
            app.system_proxy.as_ref().map(|w| w.state.as_str()),
            Some("off")
        );
        assert_eq!(
            app.current_toast().map(|t| t.text.as_str()),
            Some("HTTP and HTTPS off")
        );

        // A refusal from an agent-token bus: flag cleared, text verbatim, word kept.
        let _ = app.run_command(":sysproxy on");
        assert!(app.sysproxy_setting);
        let _ = app.on_bus(BusEvent::CallFailed {
            name: "proxy.system.set".into(),
            message: "proxy.system.set is operator-only".into(),
        });
        assert!(
            !app.sysproxy_setting,
            "an error settles the in-flight flag too"
        );
        assert_eq!(
            app.system_proxy.as_ref().map(|w| w.state.as_str()),
            Some("off")
        );
        let t = app.current_toast().expect("the error toast");
        assert_eq!(t.level, Level::Error);
        assert_eq!(t.text, "proxy.system.set is operator-only");

        // `status` toasts the detail and leaves the flag alone.
        let _ = app.run_command(":sysproxy status");
        let _ = app.on_bus(BusEvent::CallOk {
            name: "proxy.system.status".into(),
            value: json!({"state": "other", "host": "127.0.0.1", "port": 9090,
                "supported": true, "detail": "HTTP and HTTPS → 127.0.0.1:9090 (not this core)"}),
        });
        assert!(!app.sysproxy_setting);
        let t = app.current_toast().expect("the status toast");
        assert_eq!(t.level, Level::Info);
        assert_eq!(t.text, "HTTP and HTTPS → 127.0.0.1:9090 (not this core)");

        // Every proxy.status poll carries the word, next to the capture flags.
        let _ = app.on_bus(BusEvent::ProxyStatus(ProxyStatus::from_json(&json!({
            "listening": true, "address": "127.0.0.1:8080", "capturing": true,
            "system_proxy": {"state": "other", "host": "127.0.0.1", "port": 9090,
                "managed_by_us": false, "setting": false, "supported": true,
                "detail": "HTTP and HTTPS → 127.0.0.1:9090 (not this core)"}
        }))));
        assert_eq!(
            app.system_proxy
                .as_ref()
                .and_then(|w| w.pill(false))
                .as_deref(),
            Some("· sys-proxy → 127.0.0.1:9090")
        );
        let _ = app.on_bus(BusEvent::ProxyStatus(status(true, true, 0)));
        assert_eq!(
            app.system_proxy, None,
            "a poll without the key clears the word"
        );
    }

    /// F-tui 1 (review log, plan 2026-10-31-system-proxy-automation): a
    /// second `s` / `:sysproxy on|off` while a change is in flight — ours or
    /// the core's `setting` flag — is refused with a Warn toast and no call;
    /// `:sysproxy status` still goes through mid-flight.
    #[test]
    fn a_second_toggle_mid_flight_is_refused_with_a_warn_toast() {
        let mut app = App::new(TermCaps::full(), "127.0.0.1:9090");
        app.tools.extend(tools(&[
            "proxy.system.set",
            "proxy.system.unset",
            "proxy.system.status",
        ]));
        app.system_proxy = Some(sysproxy_word("off"));
        assert_eq!(
            app.update(Action::ToggleSysProxy),
            vec![sysproxy_call("proxy.system.set")]
        );
        assert!(app.sysproxy_setting);

        // The second toggle: no call, the Warn toast, the flag untouched.
        assert!(app.update(Action::ToggleSysProxy).is_empty());
        let t = app.current_toast().expect("the in-flight toast");
        assert_eq!(t.level, Level::Warn);
        assert_eq!(t.text, "a system-proxy change is already in flight");
        assert!(
            app.sysproxy_setting,
            "the refusal does not settle our flight"
        );

        // The same for both typed forms.
        assert!(app.run_command(":sysproxy on").is_empty());
        assert!(app.run_command(":sysproxy off").is_empty());
        assert_eq!(
            app.current_toast().map(|t| t.text.as_str()),
            Some("a system-proxy change is already in flight")
        );

        // `status` only reads; it is allowed mid-flight.
        assert_eq!(
            app.run_command(":sysproxy status"),
            vec![sysproxy_call("proxy.system.status")]
        );
        assert!(app.sysproxy_setting);

        // The core's own `setting` flag (another client's call) guards too,
        // and the refusal does not raise our flag.
        app.sysproxy_setting = false;
        app.system_proxy = Some(SystemProxyWord {
            setting: true,
            ..sysproxy_word("off")
        });
        assert!(app.run_command(":sysproxy on").is_empty());
        let t = app.current_toast().expect("the core-flag toast");
        assert_eq!(t.level, Level::Warn);
        assert_eq!(t.text, "a system-proxy change is already in flight");
        assert!(!app.sysproxy_setting);
        assert_eq!(
            app.run_command(":sysproxy status"),
            vec![sysproxy_call("proxy.system.status")]
        );
    }

    /// F-tui 6 (panel Important): a bus drop mid-flight loses the reply that
    /// would have settled the pill. A (re)connect is a new session, so it
    /// drops our in-flight flag too — otherwise the guard would refuse every
    /// later `s` / `:sysproxy on|off` for the rest of the run.
    #[test]
    fn a_reconnect_drops_the_in_flight_flag_so_the_guard_lets_the_retry_through() {
        let mut app = App::new(TermCaps::full(), "127.0.0.1:9090");
        let names = [
            "proxy.system.set",
            "proxy.system.unset",
            "proxy.system.status",
        ];
        app.tools.extend(tools(&names));
        app.system_proxy = Some(sysproxy_word("off"));
        assert_eq!(
            app.run_command(":sysproxy on"),
            vec![sysproxy_call("proxy.system.set")]
        );
        assert!(app.sysproxy_setting);

        // The bus drops before the reply: the pill stops claiming `setting…`.
        let _ = app.on_bus(BusEvent::Disconnected("core restarted".into()));
        assert!(
            !app.sysproxy_setting,
            "a disconnect settles nothing but ends the flight"
        );

        // Reconnect with the verbs: the retry is a real call, not the Warn toast.
        let _ = app.on_bus(BusEvent::Connected {
            server: "aitmproxy test".into(),
            tools: tools(&names),
            role: Some("operator".into()),
        });
        assert!(!app.sysproxy_setting);
        assert_eq!(
            app.update(Action::ToggleSysProxy),
            vec![sysproxy_call("proxy.system.set")]
        );
        assert!(
            app.sysproxy_setting,
            "the retry is in flight until its reply"
        );

        // And a reconnect alone (no disconnect seen) drops it as well.
        let _ = app.on_bus(BusEvent::Connected {
            server: "aitmproxy test".into(),
            tools: tools(&names),
            role: Some("operator".into()),
        });
        assert!(!app.sysproxy_setting);
        assert_ne!(
            app.current_toast().map(|t| t.text.as_str()),
            Some("a system-proxy change is already in flight")
        );
    }

    /// F-tui 7 (panel Minor): the raw `:proxy.system.set|unset` (and the
    /// palette's tool list, which calls the same path) goes through the same
    /// guard as `s` / `:sysproxy`: refused mid-flight, and a cold call raises
    /// the flag so its reply settles the pill it started.
    #[test]
    fn the_raw_verb_path_shares_the_in_flight_guard() {
        let mut app = App::new(TermCaps::full(), "127.0.0.1:9090");
        app.tools.extend(tools(&[
            "proxy.system.set",
            "proxy.system.unset",
            "proxy.system.status",
        ]));
        app.system_proxy = Some(sysproxy_word("off"));
        assert_eq!(
            app.run_command(":proxy.system.set"),
            vec![sysproxy_call("proxy.system.set")]
        );
        assert!(app.sysproxy_setting, "the raw call is a flight too");

        assert!(app.run_command(":proxy.system.unset").is_empty());
        assert!(app.run_command(":sysproxy off").is_empty());
        let t = app.current_toast().expect("the in-flight toast");
        assert_eq!(t.level, Level::Warn);
        assert_eq!(t.text, "a system-proxy change is already in flight");
        assert!(
            app.sysproxy_setting,
            "the refusal does not settle the first flight"
        );

        // `status` by name is a read; it passes.
        assert_eq!(
            app.run_command(":proxy.system.status"),
            vec![sysproxy_call("proxy.system.status")]
        );
    }

    /// F-tui 4: a `proxy.system.status` reply that parses updates the word
    /// (the toast stays `detail`) and never touches our in-flight flag.
    #[test]
    fn status_reply_updates_the_word_without_touching_the_flag() {
        let mut app = App::new(TermCaps::full(), "127.0.0.1:9090");
        app.tools.extend(tools(&[
            "proxy.system.set",
            "proxy.system.unset",
            "proxy.system.status",
        ]));
        app.system_proxy = Some(sysproxy_word("off"));
        let reply = json!({"state": "other", "host": "127.0.0.1", "port": 9090,
            "managed_by_us": false, "setting": false, "supported": true,
            "detail": "HTTP and HTTPS → 127.0.0.1:9090 (not this core)"});

        // Not in flight: the word follows the reply, the flag stays down.
        assert_eq!(
            app.run_command(":sysproxy status"),
            vec![sysproxy_call("proxy.system.status")]
        );
        let _ = app.on_bus(BusEvent::CallOk {
            name: "proxy.system.status".into(),
            value: reply.clone(),
        });
        assert!(!app.sysproxy_setting);
        let word = app.system_proxy.as_ref().expect("the reply's word");
        assert_eq!(word.state, "other");
        assert_eq!(word.host.as_deref(), Some("127.0.0.1"));
        assert_eq!(word.port, Some(9090));
        assert_eq!(
            word.pill(app.sysproxy_setting).as_deref(),
            Some("· sys-proxy → 127.0.0.1:9090")
        );
        let t = app.current_toast().expect("the status toast");
        assert_eq!(t.level, Level::Info);
        assert_eq!(t.text, "HTTP and HTTPS → 127.0.0.1:9090 (not this core)");

        // Mid-flight: the word still follows, the flag stays up.
        app.system_proxy = Some(sysproxy_word("off"));
        let _ = app.run_command(":sysproxy on");
        assert!(app.sysproxy_setting);
        let _ = app.on_bus(BusEvent::CallOk {
            name: "proxy.system.status".into(),
            value: reply,
        });
        assert!(
            app.sysproxy_setting,
            "a status reply is not our set's reply"
        );
        assert_eq!(
            app.system_proxy.as_ref().map(|w| w.state.as_str()),
            Some("other")
        );

        // A reply that does not parse keeps the word (and the fallback toast).
        let _ = app.on_bus(BusEvent::CallOk {
            name: "proxy.system.status".into(),
            value: json!(null),
        });
        assert_eq!(
            app.system_proxy.as_ref().map(|w| w.state.as_str()),
            Some("other")
        );
        assert_eq!(
            app.current_toast().map(|t| t.text.as_str()),
            Some("proxy.system.status: ok")
        );
    }
}
