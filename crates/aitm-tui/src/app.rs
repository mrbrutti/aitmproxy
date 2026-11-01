//! The operator UI's state and its reducer. `App` is plain data; `update`
//! takes an [`Action`] and returns the [`BusRequest`]s it implies; `on_bus`
//! folds a [`BusEvent`] in. No terminal, no socket, no clock: the loop in
//! `lib.rs` owns those, which is what lets every screen be tested from fixture
//! data (foundation §2.10: "one fixture file … so a screen renders the same
//! data on every platform").

use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::ffi::OsStr;
use std::fs::File;
use std::io::{Read as _, Write as _};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use aitm_scan_model::{
    is_builtin_name, ChecksResult, Issue, IssueStatus, IssuesResult, JobEvent, JobId,
    JobNotification, JobStatus, ListResult, Phase, ProfileDeleteResult, ProfileListResult,
    ProfileSaveResult, ScanProfile, SessionMode, SessionProfile, SitemapResult, StartResult,
    JOB_KIND_SCAN, JOB_NOTIFICATION_METHOD,
};
use serde::Deserialize as _;
use serde_json::{json, Map, Value};

use crate::action::ToolSchema as _;
use crate::action::{Action, BusEvent, BusRequest, Level, ToolInfo};
use crate::caps::TermCaps;
use crate::filter::{self, Expr};
use crate::model::{
    counts_by, human_bytes, scope_covers, value_text, AgentPolicy, AgentState, Finding, FlowDetail,
    FlowKind, FlowRow, Message, Severity,
};
use crate::open::{self, OpenTarget};
use crate::scan::{
    due, fold_profile, is_job_id, l4_gate, lane_token, launch_args, out_of_scope, parse_l4_target,
    parse_result, row_gate, scan_host, scroll, state_text, status_token, step, tag_keyed,
    tag_parts, typed_origin, usable_selector, walk, Dir, EditorField, FieldKind, IssueFilterKey,
    IssuePane, JobPane, Launch, LaunchVerb, MapPane, PendingLaunch, ProfileEditor, ProfilePane,
    ScanError, ScanOffer, ScanState, ScanTab, WireConfirm, CLAMPED_FIELD_MAX, CLAMPED_MAX,
    ERROR_DETAIL_MAX, ISSUES_POLL_TICKS, LIST_POLL_TICKS, MAX_STATUS_FOLLOWUPS, NO_SCANNER,
    OTHER_ISSUE, OTHER_JOB, OTHER_ORIGIN, OTHER_PROFILE, OTHER_SAVED, SAVED_NAME_MAX,
    SAVED_PATH_MAX, SITEMAP_POLL_TICKS, STATUS_POLL_TICKS,
};
use crate::text::{clean, truncate};
use crate::theme::Theme;
use crate::ui::overlays;
use crate::viewers::json;

/// Terminal widths below which the shell changes shape (§2.10(c)).
pub const NARROW_COLS: u16 = 120;
/// Two lists side by side need this many columns (§2.9); the split view
/// itself is not built in this pass, so `:split` only says so.
pub const SPLIT_COLS: u16 = 160;

/// How many flow details the app keeps; past this the oldest non-selected
/// ones are dropped (they are fetched again on demand).
pub const MAX_DETAILS: usize = 2_000;

/// Tools that ask the operator for a local `y/N` before they are sent
/// (§4.2 step 4: the bus has no `confirm` on the wire until F1, and the
/// TUI's server identity is `Frontend::Mcp`). A `dry_run` the tool's schema
/// declares, given as the JSON boolean `true`, bypasses.
pub const CONFIRM_TOOLS: &[&str] = &["ca.install", "ca.uninstall"];

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
    /// The confirm-over-the-wire overlay (spec D3, D7), shared by the `l4.*`
    /// guarded verbs and the `scan.*` launches: shows the server's prompt; `y`
    /// re-issues with `_confirm`.
    WireConfirm,
}

/// What the one-line prompt is collecting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PromptKind {
    /// `:`, the command palette.
    Palette,
    /// `/`, the filter expression.
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
    /// Profiles `o`: an origin to add to the draft, typed (scanner v2 spec
    /// D4, D8).
    ScanOrigin,
    /// Profiles `e` on a number or text field: the new value, prefilled
    /// with the current one (spec D4).
    ScanField,
    /// Profiles `w` on a builtin or an unnamed draft: the name to save it
    /// under (spec D4).
    ScanProfileName,
    /// Profiles `t`: an L4 target as `ip:port[/tcp|udp][ grammar]` (spec
    /// D4).
    ScanL4Target,
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

/// The rows the Scan view spends on chrome rather than list body, so a
/// PgUp/PgDn page is `height - SCAN_CHROME_ROWS`: the three bars, the two box
/// edges, the strip-and-banner row, a heading row, a rule, a detail line and
/// one spare footer row (spec D11, plan task 4).
const SCAN_CHROME_ROWS: u16 = 10;

// `SAVED_NAME_MAX`, `SAVED_PATH_MAX`, `CLAMPED_MAX` and `CLAMPED_FIELD_MAX`
// live with the other profile bounds in `scan::profiles` (fix round G,
// G41, G70).

/// The local refusal while a launch waits for its reply (spec D7).
const LAUNCH_IN_FLIGHT: &str = "a launch is already in flight";

/// The widest a `poc_ref` grows in the "not in the Findings list" toast.
const POC_TOAST_MAX: usize = 80;

/// What the Profiles keys say when no editor is open (plan task 10).
const NO_EDITOR: &str = "open a profile first (Enter on a row, or N for a new one)";

/// The most cells a toast keeps (fix round H, H47): every `CallFailed`
/// message reaches [`App::toast`] whole, so the text is bounded once, when
/// it is stored, never per frame.
pub const TOAST_MAX: usize = 400;

/// The toast the Scan views raise when `⏎` names a flow the store no
/// longer holds (D11): the one "not in the flow list" wording.
fn not_in_flow_list(id: &str) -> String {
    format!("flow {id} is not in the flow list (cleared, or not captured here)")
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

/// A tool call held back for the operator's `y/N`.
#[derive(Debug, Clone, PartialEq)]
pub struct ConfirmCall {
    pub name: String,
    pub description: String,
    pub args: Value,
    /// Where to go after the answer.
    pub return_to: Mode,
    /// The tag a `scan.*` call leaves under on `y` (spec D4; fix round G,
    /// G38): set by the caller that knows the key, `None` for a plain
    /// `Call`.
    pub tag: Option<String>,
}

/// Inspector placement; the TUI has horizontal and vertical only (§2.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    /// Inspector below the list (default).
    Horizontal,
    /// Inspector right of the list.
    Vertical,
}

/// The content-type chip bar (§2.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Chip {
    All,
    Http,
    Https,
    WebSocket,
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
    pub const ALL: [Chip; 15] = [
        Chip::All,
        Chip::Http,
        Chip::Https,
        Chip::WebSocket,
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

    pub fn label(self) -> &'static str {
        match self {
            Chip::All => "All",
            Chip::Http => "HTTP",
            Chip::Https => "HTTPS",
            Chip::WebSocket => "WebSocket",
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
            Chip::Other => {
                !ct.is_empty() && !Chip::ALL[6..14].iter().any(|c| c.matches(row, detail))
            }
        }
    }
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
}

impl SidebarItem {
    pub const ALL: [SidebarItem; 11] = [
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
/// ending and trailing newline the original had, so an untouched body, and
/// any body that is not UTF-8, which the editor only describes, reaches the
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
    format!("<{len} binary bytes: edit in hex is a follow-up>")
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
    /// replaces by name) and, only when its lines changed and the body is
    /// text, the body rebuilt with the original line ending and trailing
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
    /// The mode the open prompt was opened from, where Esc or Enter
    /// returns. Set by `open_prompt` only when a prompt is not already open,
    /// so a chained prompt (PoC name → param) keeps the first one's origin.
    pub prompt_from: Mode,
    pub palette_cursor: usize,
    pub pinned_hosts: Vec<String>,
    pub auto_select: bool,
    pub intercept_armed: bool,
    pub capture_paused: bool,
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
    /// The last `ca.status` result, for the CA panel.
    pub ca_status: Option<Value>,
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
    /// The Scan view's state (spec D1, D3): the four tabs, the launch
    /// bookkeeping and the legacy `scan.discover` one-shot. Inert until the
    /// bus offers `scan.start` or `scan.discover` (D2).
    pub scan: ScanState,
    /// The pending confirm-over-the-wire handshake (spec D3, D7), shared by the
    /// `l4.*` guarded verbs and the `scan.*` launches; `Some` while the overlay
    /// is open.
    pub wire_confirm: Option<WireConfirm>,
    /// The mode to return to when the wire-confirm overlay closes: `l4_inject`
    /// and `l4_intercept_verb` set `Mode::Inspector`, the scanner launch (Task
    /// 12) sets `Mode::Scan`.
    pub wire_confirm_from: Mode,
    /// A non-job push line arrived since the last `Tick` (spec D5): the flow
    /// list is stale and the next tick issues one `Refresh` for all of them.
    pub flows_dirty: bool,
    /// The help overlay's first visible line (fix round G, G85): reset when
    /// the overlay opens, moved by the arrow, page and Home/End keys while
    /// it is shown, clamped by the view to the lines that do not fit.
    pub help_scroll: u16,
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
            browser: BrowserState::default(),
            pending_scope_removals: VecDeque::new(),
            poc_get_inflight: VecDeque::new(),
            pending_artifact: None,
            poc_build_pending: VecDeque::new(),
            l4: crate::l4::L4State::default(),
            scan: ScanState::default(),
            wire_confirm: None,
            wire_confirm_from: Mode::Flows,
            flows_dirty: false,
            help_scroll: 0,
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
    /// resolve to it: a different role, or no role echoed at all. False when
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
    /// status bar draws as a dash: a real `0 B` is `Some(0)` (§2.8).
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

    /// Show `text` in the status bar for 16 ticks. The text is bounded here,
    /// once (fix round H, H47; D6 hostile-core bounds): control characters
    /// stripped, cut to [`TOAST_MAX`] cells (so at most `4 * TOAST_MAX`
    /// chars), and the buffer shrunk, so a raw core message a megabyte long
    /// neither sits in the ring nor overflows the bar's width sums.
    pub fn toast(&mut self, level: Level, text: impl Into<String>) {
        let mut text = truncate(&clean(&text.into()), TOAST_MAX);
        text.shrink_to_fit();
        self.toasts.push_back(Toast {
            level,
            text,
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
        // A Scan banner notice answers one key (D11 `already <state>`): the
        // next key clears it; the timer and a resize are not keys.
        if !matches!(action, Action::Tick | Action::Resize(..)) {
            self.scan.notice = None;
        }
        match action {
            Action::Quit => self.should_quit = true,
            Action::Tick => {
                self.ticks += 1;
                let t = self.ticks;
                self.toasts.retain(|x| x.expires_at_tick > t);
                // Every push line since the last tick collapses into one
                // flow sweep (spec D5): a subscribed bus can deliver many
                // lines per second and the list only needs one refresh.
                if self.flows_dirty {
                    self.flows_dirty = false;
                    out.push(BusRequest::Refresh);
                }
                self.scan_tick(t, &mut out);
            }
            Action::Resize(w, h) => {
                self.width = w;
                self.height = h;
            }
            Action::Help => self.open_help(),
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
                let dir = if action == Action::Left {
                    Dir::Prev
                } else {
                    Dir::Next
                };
                let d: i32 = match dir {
                    Dir::Prev => -1,
                    Dir::Next => 1,
                };
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
                    // Scan (plan task 10): in the Checks pane ← collapses
                    // and → (`l`) expands the node under the cursor;
                    // elsewhere in the view the keys do nothing (the chips
                    // are the flow list's).
                    Mode::Scan => self.scan_tree_fold(dir == Dir::Prev),
                    _ => self.chip = step(&Chip::ALL, self.chip, dir),
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
                    let capture = self
                        .findings
                        .get(self.finding_cursor)
                        .and_then(|f| f.finding_capture.clone());
                    if let Some(id) = capture {
                        self.open_flow(id, "finding capture is not in the flow store", &mut out);
                    }
                }
                // Scan: ⏎ acts per tab (D11). On Profiles it opens the
                // row's editor, edits the field, adds the origin or acts on
                // the tree node, by pane (plan task 10).
                Mode::Scan if self.scan.tab == ScanTab::Profiles => {
                    self.profiles_enter(&mut out);
                }
                // On Jobs it opens the Issues
                // tab filtered to the cursor's job and asks for its issues
                // once (D6, "entering Issues, any filter change"); the
                // legacy Jobs row has no job, so nothing happens there (D12).
                Mode::Scan if self.scan.tab == ScanTab::Jobs => {
                    if let Some(job) = self.scan.jobs.cursor_job().cloned() {
                        self.scan.issues.filters.job = Some(job);
                        self.scan.tab = ScanTab::Issues;
                        self.request_issues(&mut out);
                    }
                }
                // On Issues with the Detail pane focused it opens the probe
                // (or baseline) flow under the flow cursor (D11); on the
                // List pane it opens the row: the Detail pane takes the
                // focus (D11 "⏎ open or act"; fix round E, E18).
                Mode::Scan if self.scan.tab == ScanTab::Issues => {
                    if self.scan.issues.pane == IssuePane::Detail {
                        if let Some((id, _)) = self.scan.issues.flow_under_cursor() {
                            let id = id.to_string();
                            self.open_flow(id.clone(), &not_in_flow_list(&id), &mut out);
                        }
                    } else {
                        self.scan.issues.pane = IssuePane::Detail;
                    }
                }
                // On Site map it opens the focused list's selected flow in
                // the inspector, read from the same lists the cursor keys
                // walk (A2), which on a legacy bus is exactly today's
                // behaviour (D12): the injection point's flow in the Points
                // pane, the endpoint's linked flow (AC3) in the Nodes pane.
                // An endpoint with no linked flow opens nothing; a flow no
                // longer in the store is refused, not selected. The other
                // tabs act in their own tasks.
                Mode::Scan => {
                    if let Some(id) = self.scan.sitemap_selected_flow(self.scan_offer()) {
                        self.open_flow(id.clone(), &not_in_flow_list(&id), &mut out);
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
            Action::SidebarNext => self.sidebar_step(Dir::Next, &mut out),
            Action::SidebarPrev => self.sidebar_step(Dir::Prev, &mut out),
            Action::ChipNext => self.chip = step(&Chip::ALL, self.chip, Dir::Next),
            Action::ChipPrev => self.chip = step(&Chip::ALL, self.chip, Dir::Prev),
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
                            "Resume all: {sent} resumed, {skipped} skipped out of scope (add their hosts to scope to act)"
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
                if self.selected.is_some() {
                    if self.has_tool("flow.mark") {
                        self.open_prompt(PromptKind::Mark);
                    } else {
                        self.toast(Level::Warn, "Mark needs core follow-up F6 (flow.mark)");
                    }
                }
            }
            Action::Comment => {
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
            Action::OpenScan => {
                self.mode = Mode::Scan;
                self.sidebar = SidebarItem::Scan;
                // The first open lands on the tab this bus can serve (D2):
                // Profiles when it has the v2 scanner, Jobs otherwise. Later
                // opens restore the tab the operator left on.
                if self.scan.opened_at_tick.is_none() {
                    if self.scan_offer() == ScanOffer::V2 {
                        self.scan.tab = ScanTab::Profiles;
                    } else {
                        self.scan.tab = ScanTab::Jobs;
                        // A legacy result is read through its injection
                        // points first (today's default focus); the
                        // endpoints are the Nodes pane, one Tab away.
                        self.scan.sitemap.pane = crate::scan::MapPane::Points;
                    }
                    self.scan.opened_at_tick = Some(self.ticks);
                }
                // Viewing the panel never crawls: a `scan.discover` is up to
                // hundreds of real browser navigations against the target. Seed
                // the scope-bound target the header shows, so `r` (ScanLaunch)
                // and `:scan <host>` are the only paths that reach the wire.
                if self.scan.legacy.target.is_none() {
                    if let Some(host) = self.scan_target_host() {
                        // The seed follows the D8 origin rule (D12): the
                        // scheme the captured flows show, never a hard-coded
                        // `http://`. A host the rule refuses seeds nothing;
                        // the launch keys name the reason when pressed.
                        self.scan.legacy.target = typed_origin(&host, &self.flows).ok();
                    }
                }
                // D6, first row: opening the view lists the jobs. Quiet when
                // the bus has no `scan.list` (a legacy bus): the Jobs tab's
                // degraded text says so, a toast on every open would not.
                self.request_scan_list(&mut out);
                // Coming back to the view is entering its tab (D6): the
                // lists may have moved while the operator was away.
                let tab = self.scan.tab;
                self.enter_tab_reads(tab, &mut out);
            }
            Action::ScanLaunch => self.scan_launch(None, &mut out),
            Action::ScanTab(tab) => self.scan_tab(tab, &mut out),
            Action::ScanPaneNext => self.scan.step_pane(true),
            Action::ScanPanePrev => self.scan.step_pane(false),
            Action::ScanCancel => self.scan_cancel(&mut out),
            Action::ScanStart => self.scan_launch_v2(LaunchVerb::Start, &mut out),
            Action::ScanMap => self.scan_launch_v2(LaunchVerb::Map, &mut out),
            Action::ScanFilter(key) => self.scan_filter(key, &mut out),
            Action::ScanFilterReset => self.scan_filter_reset(&mut out),
            Action::ScanIssueStatus(status) => self.scan_issue_status(status, &mut out),
            Action::ScanOpenPoc => self.scan_open_poc(),
            Action::ScanNextPage => self.scan_next_page(&mut out),
            Action::ScanEdit => self.scan_edit(&mut out),
            Action::ScanToggle => self.scan_toggle(),
            Action::ScanSave => self.scan_save(&mut out),
            Action::ScanDelete => self.scan_delete(),
            Action::ScanNewProfile => self.scan_new_profile(),
            Action::ScanOriginPrompt => self.scan_origin_prompt(),
            Action::ScanOriginAdd => self.scan_origin_add(&mut out),
            Action::ScanOriginRemove => self.scan_origin_remove(),
            Action::ScanL4TargetPrompt => self.scan_l4_target_prompt(),
            Action::AgentSet(p) => {
                if self.has_tool("agent.set") {
                    out.push(BusRequest::AgentSet(p));
                } else {
                    self.toast(
                        Level::Warn,
                        "Agent policy needs core follow-up F1 (agent.set)",
                    );
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
            Action::WireConfirm(yes) => out.extend(self.answer_wire_confirm(yes)),
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

    /// Inject the crafted packet via `l4.inject` only (L4OPS-AC10). Gated by L4
    /// scope-as-authorisation; the guard's own refusal still surfaces verbatim
    /// from the server, and the operator confirms over the wire before it sends.
    fn l4_inject(&mut self) -> Vec<BusRequest> {
        let Some(flow) = self.selected_l4().cloned() else {
            return Vec::new();
        };
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
                format!("Out of L4 scope: add an inject entry for {iface} to inject"),
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
        self.l4.pending = Some(("l4.inject".to_string(), args.clone()));
        self.wire_confirm_from = Mode::Inspector;
        vec![BusRequest::Call {
            name: "l4.inject".into(),
            args,
        }]
    }

    /// Answer the wire-confirm overlay (spec D3, D7): `yes` re-issues the
    /// identical call plus the reserved `_confirm` token; `no` cancels with a
    /// `<call> cancelled` toast. Returns to the mode the launch came from. The
    /// `l4.*` verbs re-issue with `BusRequest::Call`; a `scan.*` launch goes
    /// back out tagged under its verb (the pending launch stays until the
    /// result), and a cancel clears the pending launch so the key is live.
    fn answer_wire_confirm(&mut self, yes: bool) -> Vec<BusRequest> {
        self.mode = self.wire_confirm_from;
        let Some(c) = self.wire_confirm.take() else {
            return Vec::new();
        };
        let is_scan = c.is_scan();
        if yes {
            if is_scan {
                let mut out = Vec::new();
                // A re-issue the reducer refuses (the verb left the bus)
                // settles the launch: nothing will answer it (fix round G,
                // G67).
                if !self.scan_call(c.call.clone(), &c.call, c.confirmed_args(), &mut out) {
                    self.scan.launch.pending = None;
                }
                return out;
            }
            vec![BusRequest::Call {
                name: c.call.clone(),
                args: c.confirmed_args(),
            }]
        } else {
            if is_scan {
                self.scan.launch.pending = None;
            }
            self.toast(Level::Info, format!("{} cancelled", c.call));
            Vec::new()
        }
    }

    /// Open the wire-confirm overlay on `confirm`, returning to `from` when
    /// it closes: the one spelling the `l4.*` guarded verbs and the `scan.*`
    /// launches share (fix round G, G67). A confirm already on screen is
    /// replaced, not answered: its call is toasted as dropped and, for a
    /// `scan.*` launch, the pending launch it held is cleared (the token
    /// is gone with the prompt, so nothing can re-issue it).
    fn open_wire_confirm(&mut self, confirm: WireConfirm, from: Mode) {
        if let Some(old) = self.wire_confirm.take() {
            if old.is_scan() {
                self.scan.launch.pending = None;
            }
            self.toast(Level::Warn, format!("{} confirmation dropped", old.call));
        }
        self.wire_confirm = Some(confirm);
        self.wire_confirm_from = from;
        self.mode = Mode::WireConfirm;
    }

    /// Toggle one per-feature agent gate (L4OPS-AC11). Where `l4.agent.set` is
    /// present it flips the gate the guard enforces; where absent the toggle is
    /// read-only with an honest note. The agent can never flip its own gates
    /// (enforced by the core), so this is an operator action.
    fn l4_toggle_gate(&mut self, gate: crate::l4::L4Gate) -> Vec<BusRequest> {
        if !self.has_tool("l4.agent.set") {
            self.toast(
                Level::Warn,
                "L4 agent gates are read-only here: set `l4.allow_agent_*` in config and restart (l4.agent.set is not on this bus)",
            );
            return Vec::new();
        }
        let next = !self.l4.gates.get(gate);
        vec![BusRequest::Call {
            name: "l4.agent.set".into(),
            args: json!({ "capability": gate.wire(), "allowed": next }),
        }]
    }

    /// Forward / Drop a parked in-path L4 packet (ui-ext §3.4, L4OPS-AC12),
    /// through the same confirm-over-the-wire path; feature-detected from
    /// `l4.intercept.*`, documented-limited when absent.
    fn l4_intercept_verb(&mut self, tool: &str, flow: &crate::l4::L4Flow) -> Vec<BusRequest> {
        if !self.has_tool(tool) {
            self.toast(
                Level::Warn,
                format!("{tool} is not on this bus: in-path intercept is documented-limited here"),
            );
            return Vec::new();
        }
        if flow.parked().is_none() {
            self.toast(
                Level::Info,
                "No parked L4 packet: Forward/Drop need an in-path intercept session",
            );
            return Vec::new();
        }
        if !self.l4.in_scope(flow) {
            self.toast(Level::Warn, "Out of L4 scope: intercept actions disabled");
            return Vec::new();
        }
        let args = json!({ "id": flow.id });
        self.l4.pending = Some((tool.to_string(), args.clone()));
        self.wire_confirm_from = Mode::Inspector;
        vec![BusRequest::Call {
            name: tool.to_string(),
            args,
        }]
    }

    fn gate(&mut self, r: &FlowRow) -> bool {
        if self.in_scope(r) {
            return true;
        }
        let host = r.host().to_string();
        let msg = if host.is_empty() {
            // Only a WebSocket row can lack a host: its summary carries the
            // handshake id alone, and that flow is not in the list.
            "Out of scope: unknown host (the WebSocket handshake is not listed)".to_string()
        } else {
            format!("Out of scope: add `{host}` to scope to act")
        };
        self.toast(Level::Warn, msg);
        false
    }

    /// `o`: hand the thing under the cursor to the desktop (§2.9). In the
    /// Findings panel that is the screenshot: a local file on a loopback
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
                None => self.toast(Level::Info, "no screenshot yet: s captures one"),
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
            // image we know. Otherwise, on a remote bus or for a path that does
            // not exist here, the bytes come through `poc.artifact` (F13).
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
                self.toast(Level::Info, format!("wrote {}, opening", path.display()));
                self.pending_open = Some(OpenTarget {
                    path,
                    label: format!("{id} {which} body"),
                });
            }
            Err(e) => self.toast(Level::Error, format!("could not write the body: {e}")),
        }
    }

    /// Hold `name(args)` for a `y/N` when it is in [`CONFIRM_TOOLS`] (and not
    /// a dry run); otherwise send it.
    fn call_tool(&mut self, name: &str, args: Value) -> Vec<BusRequest> {
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
                tag: None,
            });
            self.open_prompt(PromptKind::Confirm);
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
    /// answered, so the view stops waiting for them.
    fn browser_forget_inflight(&mut self) {
        self.browser.inflight = 0;
        self.browser.busy = None;
    }

    /// Launch a scope-bound `scan.discover`. The target is bound to the
    /// authorized scope (deny-by-default): a host no scope entry covers is
    /// refused with a toast and nothing reaches the wire. `explicit` is a
    /// user-typed target (`:scan <host>`); `None` picks the selected flow's host
    /// when it is in scope, else the first concrete in-scope host.
    fn scan_launch(&mut self, explicit: Option<String>, out: &mut Vec<BusRequest>) {
        // One crawl at a time (fix round G, G62: the one guard for `r`,
        // `:scan <host>`, `s`/`m` on a legacy bus and the map fallback).
        if self.scan.legacy.running {
            self.toast(Level::Info, "a scan is already running");
            return;
        }
        if !self.has_tool("scan.discover") {
            self.toast(
                Level::Warn,
                "scan.discover is not on this bus (needs the scanner plugin)",
            );
            return;
        }
        let raw = match explicit {
            Some(raw) => raw,
            None => match self.scan_target_host() {
                Some(h) => h,
                None => {
                    self.toast(
                        Level::Warn,
                        "Scan needs an in-scope host: add one to scope (S) first",
                    );
                    return;
                }
            },
        };
        if self.scope_host(&raw).is_none() {
            return;
        }
        // D8: a typed origin keeps its scheme and port (authority only), a
        // bare host gets the scheme its captured flows show; a host the
        // rule refuses is toasted and nothing reaches the wire.
        let target = match typed_origin(&raw, &self.flows) {
            Ok(target) => target,
            Err(reason) => {
                self.toast(Level::Warn, reason.to_string());
                return;
            }
        };
        self.scan.legacy.running = true;
        self.scan.legacy.error = None;
        self.scan.legacy.target = Some(target.clone());
        out.extend(self.call_tool("scan.discover", json!({ "target": target })));
    }

    /// What this bus can serve the Scan view (spec D2): the v2 scanner when
    /// it offers `scan.start`, the legacy one-shot when it offers only
    /// `scan.discover`, nothing otherwise. Each v2 control is gated by its
    /// own verb on top of this.
    pub fn scan_offer(&self) -> ScanOffer {
        if self.has_tool("scan.start") {
            ScanOffer::V2
        } else if self.has_tool("scan.discover") {
            ScanOffer::Legacy
        } else {
            ScanOffer::None
        }
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
            .map(|e| crate::scan::scan_host(e))
    }

    /// The D8 scope guard on a launch or origin path (fix round G, G61):
    /// `raw`'s host when the scope covers it; otherwise the one refusal
    /// toast ([`out_of_scope`]) and `None`, and the caller sends nothing.
    fn scope_host(&mut self, raw: &str) -> Option<String> {
        match out_of_scope(&self.scope, raw) {
            Some(text) => {
                self.toast(Level::Warn, text);
                None
            }
            None => Some(scan_host(raw)),
        }
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
            // A `scan.*` verb leaves through the tagged path (spec D4):
            // `scan.profile.delete` under `scan.profile.delete:<name>`.
            if let Some(tag) = c.tag {
                let mut out = Vec::new();
                self.scan_call(tag, &c.name, c.args, &mut out);
                return out;
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
            Mode::WireConfirm => {
                let _ = self.answer_wire_confirm(false);
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
            // Scan: Esc/`q` closes a focused detail, editor or points pane
            // back to its list pane, and only then leaves the view (D11).
            Mode::Scan => {
                if self.scan.close_pane(self.scan_offer()) {
                    return;
                }
                Mode::Flows
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
                if let Some(id) = self.selected.clone() {
                    out.push(BusRequest::Comment { id, text });
                }
                self.close_prompt();
            }
            Mode::Prompt(PromptKind::Mark) => {
                if let Some(id) = self.selected.clone() {
                    let marks = text.split_whitespace().map(str::to_string).collect();
                    out.push(BusRequest::Mark { id, marks });
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
            // A blank line is a "no" (nothing changes, the prompt closes,
            // like every other prompt); a refused value keeps the prompt
            // open with the line cleared (the filter prompt's convention),
            // so the operator tries again or leaves with Esc: the one rule
            // the four Scan prompts share (fix round G, G34).
            Mode::Prompt(
                PromptKind::ScanOrigin
                | PromptKind::ScanField
                | PromptKind::ScanL4Target
                | PromptKind::ScanProfileName,
            ) if text.is_empty() => self.close_prompt(),
            Mode::Prompt(PromptKind::ScanOrigin) => {
                let result = self.submit_scan_origin(&text, &mut out);
                self.submit_retrying(result);
            }
            Mode::Prompt(PromptKind::ScanField) => {
                let result = self.submit_scan_field(&text);
                self.submit_retrying(result);
            }
            Mode::Prompt(PromptKind::ScanL4Target) => {
                let result = self.submit_scan_l4_target(&text);
                self.submit_retrying(result);
            }
            Mode::Prompt(PromptKind::ScanProfileName) => {
                let result = self.submit_scan_profile_name(&text, &mut out);
                self.submit_retrying(result);
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
                                format!("Out of scope: add `{authority}` to scope to send"),
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

    /// Open the help overlay at its top (fix round G, G85).
    fn open_help(&mut self) {
        self.help_scroll = 0;
        self.mode = Mode::Help;
    }

    fn navigate(&mut self, action: &Action, out: &mut Vec<BusRequest>) {
        match self.mode {
            Mode::Help => {
                // The overlay scrolls over the lines its box cannot show
                // (fix round G, G85); the view clamps the same way.
                let max = overlays::help_scroll_max(self.width, self.height);
                let page = overlays::help_page(self.width, self.height);
                scroll(&mut self.help_scroll, action, max + 1, page);
            }
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
                // ↑↓/paging walk the focused pane of the active tab (D11).
                // A page is the list body: the terminal minus the view's
                // chrome rows.
                let page = usize::from(self.height.saturating_sub(SCAN_CHROME_ROWS)).max(1);
                let offer = self.scan_offer();
                let jobs_detail =
                    self.scan.tab == ScanTab::Jobs && self.scan.jobs.pane == JobPane::Detail;
                let issues_detail =
                    self.scan.tab == ScanTab::Issues && self.scan.issues.pane == IssuePane::Detail;
                if jobs_detail {
                    // The Jobs Detail pane scrolls its lines instead of
                    // moving a cursor (D11); the last line is the floor.
                    let n = self.scan.jobs.detail_len();
                    scroll(&mut self.scan.jobs.detail_scroll, action, n, page);
                } else if issues_detail {
                    // The Issues Detail pane: Up/Down walk the flow list
                    // (D11, "a walkable list") and ask the view to keep the
                    // flow under the cursor on screen; the paging keys
                    // scroll the lines (plan task 8) and take that back, so
                    // the scroll is what is drawn (fix round F, F7).
                    let issues = &mut self.scan.issues;
                    match action {
                        Action::Up | Action::Down => {
                            let flows = issues.flow_count();
                            issues.detail_view.walk_flow(action, flows, page);
                        }
                        _ => {
                            let n = issues.detail_len();
                            issues.detail_view.scroll(action, n, page);
                        }
                    }
                } else if self.scan.tab == ScanTab::Profiles
                    && self.scan.profiles.pane == ProfilePane::Checks
                {
                    // The Checks pane walks the flattened tree's rows
                    // (lanes, classes and checks), not the catalogue's
                    // entries (plan task 10).
                    let rows = self.scan.profiles.visible_len();
                    if let Some(editor) = self.scan.profiles.editor.as_mut() {
                        if rows > 0 {
                            editor.tree_cursor = walk(action, editor.tree_cursor, rows, page);
                        }
                    }
                } else if let Some((cursor, n)) = self.scan.cursor_mut(offer) {
                    if n > 0 {
                        let c = *cursor;
                        *cursor = walk(action, c, n, page);
                        let moved = *cursor != c;
                        // A new job under the Jobs cursor shows its detail
                        // from the top.
                        if moved && self.scan.tab == ScanTab::Jobs {
                            self.scan.jobs.detail_scroll = 0;
                        }
                        // The row under the Profiles cursor is what `s`
                        // launches without an editor: re-gate it (G73).
                        if moved && self.scan.tab == ScanTab::Profiles {
                            self.recompute_launch_gate();
                        }
                        // The Issues cursor landing on a row reads it (D6)
                        // and shows its detail from the top.
                        if moved && self.scan.tab == ScanTab::Issues {
                            self.scan.issues.detail_view.reset();
                            self.issue_cursor_landed(out);
                        }
                        // A new node under the Site map's Nodes cursor
                        // shows its points from the first (G24).
                        if moved
                            && self.scan.tab == ScanTab::SiteMap
                            && self.scan.sitemap.pane == MapPane::Nodes
                        {
                            self.scan.sitemap.point_offset = 0;
                        }
                    }
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
    fn sidebar_step(&mut self, dir: Dir, out: &mut Vec<BusRequest>) {
        let mut next = step(&SidebarItem::ALL, self.sidebar, dir);
        // The Scan row is drawn only when the bus offers a scanner (D2);
        // never land on a row the operator cannot see.
        if next == SidebarItem::Scan && self.scan_offer() == ScanOffer::None {
            next = step(&SidebarItem::ALL, next, dir);
        }
        self.sidebar = next;
        match self.sidebar {
            SidebarItem::Findings => self.mode = Mode::Findings,
            SidebarItem::Agent => self.mode = Mode::Agent,
            SidebarItem::Browser => out.extend(self.update(Action::OpenBrowser)),
            SidebarItem::Scan => out.extend(self.update(Action::OpenScan)),
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
        // L4 flows carry no `flow.detail`; their packets arrive on the `l4.*`
        // poll and live in `self.l4.flows`.
        if self.row(id).is_some_and(|r| r.kind == FlowKind::L4) {
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
    /// authority, scheme or path, only the id of its 101 handshake flow
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
    /// YAML"): through `poc.get` (F13) when the bus has it (one request per
    /// path, none while one is in flight), else from `poc_path` on this
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
                ": no PoC dir configured, so it went under the temp dir; poc.run confined to \
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
            "help" | "?" => self.open_help(),
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
                if self.has_tool("ca.status") {
                    out.push(BusRequest::Call {
                        name: "ca.status".into(),
                        args: json!({}),
                    });
                }
            }
            "browser" => out.extend(self.update(Action::OpenBrowser)),
            // `:scan` opens the Scan view only (viewing never crawls; `r`
            // launches); `:scan <host>` opens it and crawls that host,
            // scope-gated.
            "scan" => {
                out.extend(self.update(Action::OpenScan));
                if !rest.is_empty() {
                    match self.scan_offer() {
                        ScanOffer::None => self.toast(Level::Warn, NO_SCANNER),
                        // D8: `:scan <origin>` under v2 is `scan.start {target}`.
                        ScanOffer::V2 => self.scan_start_typed(rest, &mut out),
                        ScanOffer::Legacy => self.scan_launch(Some(rest.to_string()), &mut out),
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
        // The origin picker reads the scope and the captured flows (D8):
        // an open editor's rows follow them. A `Flows` sweep counts only
        // when it added or removed a row (fix round G, G37): the picker
        // reads authorities, which a status change never moves.
        let mut origins_moved = matches!(event, BusEvent::Scope(_));
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
                // The UI-3 gate reads the tool list (D7).
                self.recompute_launch_gate();
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
                // will be answered.
                self.browser_forget_inflight();
                out.push(BusRequest::Refresh);
            }
            BusEvent::ProxyStatus(s) => {
                if s.address.is_some() {
                    self.listening = s.address;
                }
                self.serving = Some(s.listening);
                self.intercept_armed = s.intercept_armed;
                self.capture_paused = !s.capturing;
                self.store_paused = Some(s.paused);
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
                self.browser_forget_inflight();
                // Nothing tagged before the drop will be answered (D4), and
                // a launch in flight is lost with the connection, as is the
                // one `scan.issue` read (D6).
                self.scan.inflight.clear();
                self.scan.issues.pending_read = None;
                self.scan.launch.pending = None;
                // A confirm token is bound to the connection that issued it
                // (D7): a pending confirm is dropped, not answered, whatever
                // mode is on screen; only the overlay itself closes back to
                // the mode the launch came from.
                if let Some(c) = self.wire_confirm.take() {
                    self.toast(
                        Level::Warn,
                        format!("{} confirmation dropped: bus disconnected", c.call),
                    );
                }
                if self.mode == Mode::WireConfirm {
                    self.mode = self.wire_confirm_from;
                }
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
                origins_moved = before > had || self.flows.len() != before;
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
                    format!("flow.detail {id}: malformed reply, not asking again"),
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
                // The UI-3 gate reads the L4 scope (D7).
                self.recompute_launch_gate();
            }
            BusEvent::L4Agent(v) => self.l4.gates = crate::l4::L4Gates::from_json(&v),
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
                    // path: the TUI writes the file and lists it.
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
                        let text = match &value {
                            Value::Null => "ok".to_string(),
                            other => value_text(other),
                        };
                        self.toast(Level::Info, format!("{name}: {text}"));
                        if self.has_tool("ca.status") {
                            out.push(BusRequest::Call {
                                name: "ca.status".into(),
                                args: json!({}),
                            });
                        }
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
                            "Intercept armed: every request pauses"
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
                    // which is now stale: drop it and ask again.
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
                    // L4 guarded wire verbs: a `needs_confirmation` reply opens
                    // the confirm overlay (L4OPS-AC10); a plain reply is success.
                    "l4.inject" | "l4.send_recv" | "l4.intercept.forward" | "l4.intercept.drop" => {
                        let (call, args) = self
                            .l4
                            .pending
                            .take()
                            .unwrap_or((name.clone(), Value::Null));
                        match WireConfirm::from_reply(&call, &args, &value) {
                            Some(confirm) => {
                                self.open_wire_confirm(confirm, Mode::Inspector);
                                return out;
                            }
                            None => {
                                let shown: String = value_text(&value).chars().take(120).collect();
                                self.toast(Level::Info, format!("{name}: {shown}"));
                            }
                        }
                    }
                    // L4 agent gate set/status reply: the four gate states.
                    "l4.agent.set" => {
                        self.l4.gates = crate::l4::L4Gates::from_json(&value);
                        self.toast(Level::Info, "L4 agent gate updated");
                    }
                    // Scanner Stage 1: the crawl result, reached endpoints and
                    // the injection points enumerated from captured requests.
                    "scan.discover" => {
                        self.scan.legacy.running = false;
                        self.scan.legacy.error = None;
                        self.scan.legacy.endpoints = value
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
                        self.scan.legacy.endpoint_flows = value
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
                        self.scan.legacy.points = value
                            .get("injection_points")
                            .and_then(Value::as_array)
                            .map(|a| {
                                a.iter()
                                    .map(crate::scan::legacy::InjectionPointRow::from_json)
                                    .collect()
                            })
                            .unwrap_or_default();
                        self.scan.legacy.cursor = self
                            .scan
                            .legacy
                            .cursor
                            .min(self.scan.legacy.points.len().saturating_sub(1));
                        self.scan.legacy.endpoint_cursor = self
                            .scan
                            .legacy
                            .endpoint_cursor
                            .min(self.scan.legacy.endpoints.len().saturating_sub(1));
                        // On a legacy bus the Site map draws the result as
                        // nodes and points (D12), built once here; on a v2
                        // bus that also offers `scan.discover` (the `m`
                        // fallback) the result stays in `legacy.*` and the
                        // folded v2 lists are kept (fix round H, H20; G19).
                        if crate::scan::MapSource::from(self.scan_offer())
                            == crate::scan::MapSource::Legacy
                        {
                            self.scan.sitemap.show_legacy(&self.scan.legacy);
                        }
                        self.toast(
                            Level::Info,
                            format!(
                                "scan.discover → {} endpoints · {} injection points",
                                self.scan.legacy.endpoints.len(),
                                self.scan.legacy.points.len()
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
                    // A guard refusal (out-of-scope / rate / denylist / oversize /
                    // count) is surfaced verbatim; drop the pending confirm.
                    "l4.inject" | "l4.send_recv" | "l4.intercept.forward" | "l4.intercept.drop" => {
                        self.l4.pending = None;
                    }
                    // A refused or failed crawl clears the running flag and keeps
                    // the reason in the Scan view until the next launch, bounded
                    // once here (fix round H, H35; D6 hostile-core bounds).
                    "scan.discover" => {
                        self.scan.legacy.running = false;
                        self.scan.legacy.error = Some(truncate(&clean(&message), ERROR_DETAIL_MAX));
                    }
                    _ => {}
                }
                self.toast(Level::Error, message);
            }
            BusEvent::Toast(level, text) => self.toast(level, text),
            BusEvent::Notification(v) => self.on_notification(&v, &mut out),
            // Every tagged call is a `scan.*` call (spec D4); the tag is
            // settled whatever the verb, the fold is per verb.
            BusEvent::CallTaggedOk { tag, name, value } => {
                self.on_scan_ok(&tag, &name, value, &mut out)
            }
            // The tag carries the verb (`tag_parts`), so the failure needs
            // no `name`.
            BusEvent::CallTaggedFailed { tag, message, .. } => {
                self.on_scan_failed(&tag, message, &mut out)
            }
        }
        if origins_moved && self.scan.profiles.editor.is_some() {
            self.refresh_origin_choices();
        }
        out
    }

    // ------------------------------------------------------ scan (v2) bus

    /// Route a push line (spec D5). A `notifications/aitm/job` line for a
    /// scan job is a trigger for the D6 reads and never touches the flow
    /// list; a job line of another kind, or one that does not parse, is
    /// ignored; any other method marks the flow list dirty for the next tick.
    fn on_notification(&mut self, v: &Value, out: &mut Vec<BusRequest>) {
        if v.get("method").and_then(Value::as_str) != Some(JOB_NOTIFICATION_METHOD) {
            self.flows_dirty = true;
            return;
        }
        let Some(params) = v.get("params") else {
            return;
        };
        if params.get("kind").and_then(Value::as_str) != Some(JOB_KIND_SCAN) {
            return;
        }
        let Ok(line) = JobNotification::deserialize(params) else {
            return;
        };
        self.on_job_line(&line, out);
    }

    /// The D6 reads a job line triggers: `scan.status {job}` for every event;
    /// the terminal and `issue` events also refresh the issue list when the
    /// operator has looked at Issues (the sidebar count reads `summaries`,
    /// which `scan.status` refreshes, so it never needs `scan.issues`).
    ///
    /// A job the TUI does not know (not in `order`, not started here) is
    /// polled only while the Scan view is shown: there a `scan.list` every
    /// ten seconds prunes what the core forgot, elsewhere nothing would, so
    /// a core pushing fresh ids could grow the state one row per line (D6
    /// hostile-core bounds). Outside the view the line is left to the list
    /// the next open requests. A known job is polled from every mode.
    fn on_job_line(&mut self, line: &JobNotification, out: &mut Vec<BusRequest>) {
        let job = line.job.as_str();
        // D6 hostile-core bound: a malformed id never becomes a tag key, an
        // argument or an `inflight` entry.
        if !is_job_id(job) {
            return;
        }
        let known = self.scan.jobs.order.iter().any(|id| id == job)
            || self.scan.jobs.started_here.contains(job);
        if !known && self.mode != Mode::Scan {
            return;
        }
        self.request_scan_status(job, out);
        let terminal = matches!(
            line.event,
            JobEvent::Finished | JobEvent::Cancelled | JobEvent::Failed
        );
        // A terminal line replaces what the job's issues said (D6): the
        // next landing on one of them reads it again.
        if terminal {
            self.scan.issues.forget_job(job);
        }
        let settles = terminal || line.event == JobEvent::Issue;
        if settles && self.issues_wanted() {
            self.request_issues(out);
        }
        // A terminal line for a job the Site map query covers re-reads the
        // map while the tab is on screen (D6); entering the tab reads it
        // anyway, so a hidden tab waits for that.
        if terminal
            && self.mode == Mode::Scan
            && self.scan.tab == ScanTab::SiteMap
            && self.scan.sitemap.query.matches(job)
        {
            self.request_sitemap(None, out);
        }
    }

    /// `scan.sitemap {query, cursor?}` under its single-slot tag (spec D6):
    /// the one spelling the tab's entry, `n`, `J`, the settling push line
    /// and the timer share. With a cursor the reply appends (D10), without
    /// one it replaces. Stamps `fetched_at_tick` when the call leaves.
    /// Quiet when the bus lacks the verb: the Site map banner already says
    /// so (D2), and the tag dedupe keeps one request in flight.
    fn request_sitemap(&mut self, cursor: Option<&str>, out: &mut Vec<BusRequest>) {
        let args = self.scan.sitemap.query.args(cursor);
        if self.scan_poll("scan.sitemap".to_string(), "scan.sitemap", args, out) {
            self.scan.sitemap.fetched_at_tick = Some(self.ticks);
            self.scan.sitemap.appending = cursor.is_some();
        }
    }

    /// Site map `n` (spec D11): the next page under the last reply's
    /// `next_cursor`; inert without one or off the tab.
    fn scan_next_page(&mut self, out: &mut Vec<BusRequest>) {
        if self.scan.tab != ScanTab::SiteMap {
            return;
        }
        let Some(cursor) = self.scan.sitemap.next_cursor.clone() else {
            return;
        };
        self.request_sitemap(Some(&cursor), out);
    }

    /// Whether a job the Site map query covers is crawling (D6): the
    /// filtered job when `J` names one, any job otherwise, by its last
    /// known summary.
    fn sitemap_crawling(&self) -> bool {
        self.scan.jobs.summaries.values().any(|s| {
            self.scan.sitemap.query.matches(&s.job)
                && !s.state.is_terminal()
                && s.phase == Phase::Crawling
        })
    }

    /// `scan.issues {filters, limit}` under its single-slot tag (spec D6):
    /// the one spelling the Jobs `Enter`, the settling push line, the Issues
    /// tab's entry, filters and timer share. Stamps `fetched_at_tick` when
    /// the call leaves. Quiet when the bus lacks the verb: the Issues banner
    /// already says so (D2), and the tag dedupe keeps one request in flight.
    fn request_issues(&mut self, out: &mut Vec<BusRequest>) {
        let args = self.scan.issues.filters.args();
        if self.scan_poll("scan.issues".to_string(), "scan.issues", args, out) {
            self.scan.issues.fetched_at_tick = Some(self.ticks);
        }
    }

    /// `1`..`4`: show a tab (spec D11), with the reads entering it makes
    /// ([`App::enter_tab_reads`]). Pressing `1` on the Profiles tab itself
    /// retries a read that failed or was lost (its reads run only while
    /// the lists are empty).
    fn scan_tab(&mut self, tab: ScanTab, out: &mut Vec<BusRequest>) {
        let entering = self.scan.tab != tab;
        self.scan.tab = tab;
        if entering || tab == ScanTab::Profiles {
            self.enter_tab_reads(tab, out);
        }
    }

    /// The reads entering `tab` makes (spec D6; fix round G, G28: the one
    /// list the open and `1`..`4` share): Issues re-reads its list with
    /// the current filters, the Site map its first page, Profiles its list
    /// and the check catalogue while they are empty; Jobs needs none, the
    /// open lists the jobs.
    fn enter_tab_reads(&mut self, tab: ScanTab, out: &mut Vec<BusRequest>) {
        match tab {
            ScanTab::Issues => self.request_issues(out),
            ScanTab::SiteMap => self.request_sitemap(None, out),
            ScanTab::Profiles => self.enter_profiles(out),
            ScanTab::Jobs => {}
        }
    }

    /// Issues `S` `C` `L` `T` `J` (spec D11): cycle one filter and refetch,
    /// `J` taking the Jobs cursor's job. On the Site map `J` toggles the
    /// map's job query the same way and re-reads the map; the other filter
    /// keys have no Site map meaning, and no other tab has filters.
    fn scan_filter(&mut self, key: IssueFilterKey, out: &mut Vec<BusRequest>) {
        let cursor_job = self.scan.jobs.cursor_job().cloned();
        match self.scan.tab {
            ScanTab::Issues => {
                self.scan.issues.filters.cycle(key, cursor_job.as_deref());
                self.request_issues(out);
            }
            ScanTab::SiteMap => {
                // Only `J` has a Site map meaning, and it refetches only
                // when the query changed (fix round G, G31).
                let changed = matches!(key, IssueFilterKey::Job)
                    && self.scan.sitemap.query.toggle_job(cursor_job);
                if changed {
                    self.request_sitemap(None, out);
                }
            }
            _ => {}
        }
    }

    /// Issues `R` (spec D11): clear every filter and refetch.
    fn scan_filter_reset(&mut self, out: &mut Vec<BusRequest>) {
        if self.scan.tab != ScanTab::Issues {
            return;
        }
        self.scan.issues.filters = Default::default();
        self.request_issues(out);
    }

    /// Issues `c` / `f` / `u` (spec D11): set the cursor's issue to `status`
    /// over the wire, `scan.issue.update {id, status}` under
    /// `scan.issue.update:<id>`, so one update per issue is in flight (the
    /// tag dedupe); the reply replaces the issue and its row through
    /// [`App::on_scan_ok`]. Inert off the Issues tab or on an empty list.
    fn scan_issue_status(&mut self, status: IssueStatus, out: &mut Vec<BusRequest>) {
        if self.scan.tab != ScanTab::Issues {
            return;
        }
        let Some(id) = self.scan.issues.cursor_issue().map(|i| i.id.clone()) else {
            return;
        };
        self.scan_call(
            tag_keyed("scan.issue.update", &id),
            "scan.issue.update",
            json!({ "id": id, "status": status_token(status) }),
            out,
        );
    }

    /// Issues `P` (spec D11): switch to Findings with the cursor on the
    /// first finding whose PoC file is the cursor issue's `poc_ref` or
    /// whose title equals the issue's name; without one, toast `PoC <ref>
    /// is not in the Findings list`, and without a `poc_ref`, `this issue
    /// has no PoC`. The row's summary carries both fields, so the key works
    /// before the `scan.issue` read lands.
    ///
    /// The ref matches the finding's `poc_path` by its file stem or its
    /// file name (`poc-3b1c` and `poc-3b1c.yaml` both name
    /// `/pocs/poc-3b1c.yaml`), never by substring, and a ref that is blank
    /// after trimming counts as no PoC, so `""`, `/` or `.yaml` from a
    /// hostile core cannot land on an unrelated finding (fix round F, F3).
    /// The match is computed before anything is changed (F10), and the
    /// toast cuts the ref to 80 cells (F4).
    fn scan_open_poc(&mut self) {
        if self.scan.tab != ScanTab::Issues {
            return;
        }
        let Some(row) = self.scan.issues.cursor_issue() else {
            return;
        };
        let poc_ref = row.poc_ref.as_deref().map(str::trim).unwrap_or_default();
        if poc_ref.is_empty() {
            self.toast(Level::Info, "this issue has no PoC");
            return;
        }
        let wanted = OsStr::new(poc_ref);
        let found = self.findings.iter().position(|f| {
            let path = Path::new(&f.poc_path);
            path.file_stem() == Some(wanted)
                || path.file_name() == Some(wanted)
                || f.title == row.name
        });
        match found {
            Some(k) => {
                self.finding_cursor = k;
                self.mode = Mode::Findings;
                self.sidebar = SidebarItem::Findings;
            }
            None => {
                let text = format!(
                    "PoC {} is not in the Findings list",
                    truncate(poc_ref, POC_TOAST_MAX)
                );
                self.toast(Level::Warn, text);
            }
        }
    }

    /// `⏎` on a flow another view names (a Findings capture, a Site map
    /// node or point, an Issues probe or baseline flow): open it in the
    /// inspector from the top when the store holds it, else refuse with
    /// `missing_toast` (the Scan views' [`not_in_flow_list`], the Findings
    /// view's own text; D11, fix round F, F14).
    fn open_flow(&mut self, id: String, missing_toast: &str, out: &mut Vec<BusRequest>) {
        if self.row(&id).is_some() {
            self.selected = Some(id);
            self.mode = Mode::Inspector;
            self.inspector.reset_view();
            self.ensure_detail(out);
        } else {
            self.toast(Level::Warn, missing_toast);
        }
    }

    /// The Issues cursor came to rest on a row (a key, or a list arriving
    /// under it while the tab is shown): read the issue (spec D6),
    /// `scan.issue {id}` under `scan.issue:<id>`, when `read` has no entry
    /// for the id and no read is pending; at most one read is in flight
    /// (fix round D, D1). The reply, not the send, fills `read`; an entry
    /// leaves on a terminal line for its job or a fold that drops the id.
    /// The row's id is already in the wire form (the fold dropped the rest).
    fn issue_cursor_landed(&mut self, out: &mut Vec<BusRequest>) {
        if self.scan.issues.pane != IssuePane::List || self.scan.issues.pending_read.is_some() {
            return;
        }
        let Some(id) = self.scan.issues.cursor_issue().map(|i| i.id.clone()) else {
            return;
        };
        if self.scan.issues.read.contains(&id) {
            // A landing on a read row keeps it from the next eviction
            // (fix round G, G3).
            self.scan.issues.read.touch(&id);
            return;
        }
        if self.scan_poll(
            tag_keyed("scan.issue", &id),
            "scan.issue",
            json!({ "id": id }),
            out,
        ) {
            self.scan.issues.pending_read = Some(id);
        }
    }

    /// Whether the D6 issues timer has a live job to follow: the filtered
    /// job when the `J` filter is set, any live job otherwise.
    fn issues_live(&self) -> bool {
        match &self.scan.issues.filters.job {
            Some(job) => self
                .scan
                .jobs
                .state_of(job)
                .is_some_and(|s| !s.is_terminal()),
            None => !self.scan.jobs.live().is_empty(),
        }
    }

    // ------------------------------------------------------ scan: Profiles

    /// Entering Profiles (D6): `scan.profile.list {}` while the list is
    /// empty and `scan.checks {}` while the catalogue is, each quiet when
    /// the bus lacks the verb (the tab's degraded text says so) and
    /// deduped by its tag while in flight.
    fn enter_profiles(&mut self, out: &mut Vec<BusRequest>) {
        if self.scan.profiles.list.is_empty() {
            self.request_profile_list(out);
        }
        if self.scan.profiles.checks.is_empty() {
            self.scan_poll("scan.checks".to_string(), "scan.checks", json!({}), out);
        }
    }

    /// `scan.profile.list {}` under its single-slot tag: the entry read and
    /// the refresh after a save or a delete (D6).
    fn request_profile_list(&mut self, out: &mut Vec<BusRequest>) {
        self.scan_poll(
            "scan.profile.list".to_string(),
            "scan.profile.list",
            json!({}),
            out,
        );
    }

    /// Profiles ⏎ by pane (D11): on the List it reads the row's profile
    /// (`scan.profile.get {name}` under `scan.profile.get:<name>`); on
    /// Fields it edits the field; on Origins it adds the highlighted row;
    /// on Checks it expands a collapsed node, else cycles the node's state.
    fn profiles_enter(&mut self, out: &mut Vec<BusRequest>) {
        match self.scan.profiles.pane {
            ProfilePane::List => {
                let Some(name) = self.scan.profiles.cursor_entry().map(|p| p.name.clone()) else {
                    return;
                };
                self.scan_call(
                    tag_keyed("scan.profile.get", &name),
                    "scan.profile.get",
                    json!({ "name": name }),
                    out,
                );
            }
            ProfilePane::Fields => self.scan_edit(out),
            ProfilePane::Origins => self.scan_origin_add(out),
            ProfilePane::Checks => {
                if self.scan.profiles.enter_node() {
                    self.recompute_launch_gate();
                }
            }
        }
    }

    /// A `scan.profile.get` reply, or `N`: show `editor` with the Fields
    /// pane focused, its picker rows from the scope and the flows (D8), and
    /// read the session preview an observed profile with an origin needs
    /// (D6).
    fn open_editor(&mut self, editor: ProfileEditor, out: &mut Vec<BusRequest>) {
        self.scan.profiles.editor = Some(editor);
        self.scan.profiles.pane = ProfilePane::Fields;
        self.scan.profiles.rebuild_tree();
        self.refresh_origin_choices();
        self.request_session_preview(out);
        self.recompute_launch_gate();
    }

    /// Rebuild the open editor's picker rows from the scope and the flows
    /// (D8); nothing without an editor.
    fn refresh_origin_choices(&mut self) {
        if let Some(editor) = self.scan.profiles.editor.as_mut() {
            editor.refresh_origins(&self.scope, &self.flows);
        }
    }

    /// `scan.session.preview {target: first origin}` under
    /// `scan.session.preview:<origin>` when the draft's session is observed
    /// and it has an origin (D6). A held preview never suppresses the read
    /// (D11 as amended; fix round G, G50): re-opening a profile re-reads
    /// the session, and only the in-flight dedupe holds a duplicate. Quiet
    /// when the bus lacks the verb: the session line is a display.
    fn request_session_preview(&mut self, out: &mut Vec<BusRequest>) {
        let Some(editor) = self.scan.profiles.editor.as_ref() else {
            return;
        };
        if editor.draft.session.mode != SessionMode::Observed {
            return;
        }
        let Some(origin) = editor.draft.target.origins.first().cloned() else {
            return;
        };
        self.scan_poll(
            tag_keyed("scan.session.preview", &origin),
            "scan.session.preview",
            json!({ "target": origin }),
            out,
        );
    }

    /// The UI-3 launch gate (spec D7): recomputed on every draft change, on
    /// `Connected` (the tool list), on `L4Scope` (the entries), on a
    /// Profiles cursor move, a list fold and an editor close. Without an
    /// editor the Profiles cursor row's lanes are gated instead
    /// ([`row_gate`]; D7 as amended, fix round G, G73).
    fn recompute_launch_gate(&mut self) {
        let has_layer = self.has_tool("l4.scope.list");
        self.scan.launch.blocked = match self.scan.profiles.editor.as_ref() {
            Some(e) => l4_gate(&e.draft, has_layer, &self.l4.scope),
            None => self
                .scan
                .profiles
                .cursor_entry()
                .and_then(|p| row_gate(&p.summary.lanes, has_layer)),
        };
    }

    /// Profiles and Jobs `s` / `m` (spec D7, D11): `verb` is `scan.start` or
    /// `scan.map`. On a legacy bus both run the one-shot `r` runs (D2). Under
    /// v2 the key is inert while the UI-3 gate holds a reason (the footer
    /// shows it) or a launch is in flight (toast); every draft origin's host
    /// is re-checked against the scope first (an origin can arrive from
    /// `scan.profile.get` or outlive a scope shrink: the D8 toast, nothing
    /// sent); `scan.map` falls back to `scan.discover` on the draft's first
    /// origin when the bus lacks it (D2). The args come from the editor's
    /// typed draft, else the Profiles list cursor's name.
    fn scan_launch_v2(&mut self, verb: LaunchVerb, out: &mut Vec<BusRequest>) {
        match self.scan_offer() {
            ScanOffer::None => {
                self.toast(Level::Warn, NO_SCANNER);
                return;
            }
            ScanOffer::Legacy => {
                self.scan_launch(None, out);
                return;
            }
            ScanOffer::V2 => {}
        }
        if !matches!(self.scan.tab, ScanTab::Profiles | ScanTab::Jobs) {
            return;
        }
        // The UI-3 gate holds `s` only: a map runs no L4 lane (D7 as
        // amended; fix round G, G71).
        if verb == LaunchVerb::Start && self.scan.launch.blocked.is_some() {
            return;
        }
        if self.scan.launch.pending.is_some() {
            self.toast(Level::Info, LAUNCH_IN_FLIGHT);
            return;
        }
        // Every draft origin's host against the scope (the D8 rule, one
        // helper for every path; fix round G, G61): the first uncovered
        // one is toasted and nothing leaves.
        let editor = self.scan.profiles.editor.as_ref();
        let refused = editor.and_then(|e| {
            e.draft
                .target
                .origins
                .iter()
                .find_map(|o| out_of_scope(&self.scope, o))
        });
        if let Some(text) = refused {
            self.toast(Level::Warn, text);
            return;
        }
        if verb == LaunchVerb::Map && !self.has_tool("scan.map") && self.has_tool("scan.discover") {
            let first = editor.and_then(|e| e.draft.target.origins.first().cloned());
            match first {
                Some(origin) => self.scan_launch(Some(origin), out),
                None => self.toast(Level::Info, "map needs an origin: add one (o) first"),
            }
            return;
        }
        let list_name = self
            .scan
            .profiles
            .list
            .get(self.scan.profiles.cursor)
            .map(|p| p.name.clone());
        let editor = self.scan.profiles.editor.as_ref();
        // The request and the toast's profile name follow one precedence
        // (fix round G, G63).
        let Some(launch) = launch_args(editor, list_name.as_deref(), None) else {
            self.toast(
                Level::Info,
                "nothing to launch: open a profile (⏎) or :scan <origin>",
            );
            return;
        };
        self.send_launch(verb, launch, out);
    }

    /// `:scan <origin>` under v2 (spec D8): the D8 origin rule and the scope
    /// check, then `scan.start {target}`; refused locally only while a
    /// launch is in flight.
    fn scan_start_typed(&mut self, raw: &str, out: &mut Vec<BusRequest>) {
        if self.scan.launch.pending.is_some() {
            self.toast(Level::Info, LAUNCH_IN_FLIGHT);
            return;
        }
        if self.scope_host(raw).is_none() {
            return;
        }
        let target = match typed_origin(raw, &self.flows) {
            Ok(target) => target,
            Err(reason) => {
                self.toast(Level::Warn, reason.to_string());
                return;
            }
        };
        let Some(launch) = launch_args(None, None, Some(&target)) else {
            return;
        };
        self.send_launch(LaunchVerb::Start, launch, out);
    }

    /// The one way a launch leaves (spec D7): tagged under its verb and
    /// recorded in `launch.pending` until the result, the prompt's cancel or
    /// the failure; the overlay, should the server ask, returns to Scan.
    fn send_launch(&mut self, verb: LaunchVerb, launch: Launch, out: &mut Vec<BusRequest>) {
        if self.scan_call(verb.to_string(), verb.as_str(), launch.args.clone(), out) {
            self.scan.launch.pending = Some(PendingLaunch { call: verb, launch });
        }
    }

    /// Fold a `StartResult` (spec D7, D10): the job lands in the Jobs state
    /// (`JobsState::land_started`: marked started here, fix round B, B3;
    /// its status in `full`, the id at the front, the List pane on it), the
    /// view switches to Jobs, the start line is toasted and a non-empty
    /// `clamped` list is a second Warn toast. D6 hostile-core bounds: an id
    /// outside the wire form, or a status naming another job, folds nothing
    /// and records the error.
    fn fold_start_result(&mut self, tag: &str, result: StartResult, fallback: Option<String>) {
        if !is_job_id(&result.job) {
            self.scan.set_error(ScanError::uncoded(
                tag,
                "reply named a job id outside the wire form",
            ));
            return;
        }
        if result.status.job != result.job {
            self.scan.set_error(ScanError::uncoded(tag, OTHER_JOB));
            return;
        }
        let id = result.job.clone();
        self.scan.jobs.land_started(result.status);
        self.scan.tab = ScanTab::Jobs;
        let profile = self
            .scan
            .jobs
            .full
            .get(&id)
            .map(|s| s.profile_name.clone())
            .filter(|n| !n.is_empty())
            .or_else(|| fallback.map(|n| truncate(&n, SAVED_NAME_MAX)))
            .unwrap_or_else(|| "profile".to_string());
        // The distinct run lanes (four at most, declaration order) and the
        // whole toast bounded (fix round G, G72).
        let lanes = result
            .lanes
            .run
            .iter()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .map(|l| lane_token(*l))
            .collect::<Vec<_>>()
            .join(" ");
        self.toast(
            Level::Info,
            truncate(
                &format!("{id} started: {profile} ({lanes})"),
                SAVED_PATH_MAX,
            ),
        );
        if !result.clamped.is_empty() {
            let parts: Vec<String> = result
                .clamped
                .iter()
                .take(CLAMPED_MAX)
                .map(|c| {
                    format!(
                        "{} {} -> {}",
                        truncate(&c.field, CLAMPED_FIELD_MAX),
                        c.requested,
                        c.applied
                    )
                })
                .collect();
            self.toast(Level::Warn, format!("clamped: {}", parts.join("; ")));
        }
    }

    /// Profiles `N` (D11): a fresh editor over the defaults.
    fn scan_new_profile(&mut self) {
        if self.scan.tab != ScanTab::Profiles {
            return;
        }
        let mut out = Vec::new();
        self.open_editor(
            ProfileEditor::new(ScanProfile::default(), None, false),
            &mut out,
        );
        debug_assert!(out.is_empty(), "a default profile has no origin to preview");
    }

    /// Profiles `e` (D11): edit the field under the Fields cursor by its
    /// kind; inert off the tab or without an editor (a toast says what to
    /// open).
    fn scan_edit(&mut self, out: &mut Vec<BusRequest>) {
        if self.scan.tab != ScanTab::Profiles {
            return;
        }
        let Some(editor) = self.scan.profiles.editor.as_mut() else {
            self.toast(Level::Info, NO_EDITOR);
            return;
        };
        let field = editor.field();
        match field.kind() {
            FieldKind::Cycle | FieldKind::Toggle => {
                if editor.cycle(field) {
                    self.recompute_launch_gate();
                    // A session switched to observed may now need its
                    // preview.
                    self.request_session_preview(out);
                }
            }
            FieldKind::Text | FieldKind::Number => {
                let text = editor.field_text();
                self.open_prompt(PromptKind::ScanField);
                self.prompt = text;
            }
            FieldKind::Origins => self.scan.profiles.pane = ProfilePane::Origins,
            FieldKind::Checks => self.scan.profiles.pane = ProfilePane::Checks,
            FieldKind::L4Targets => self.open_prompt(PromptKind::ScanL4Target),
        }
    }

    /// Profiles Space (D11): flip a lane or bool field on the Fields pane,
    /// or cycle the tri-state of the tree node under the Checks cursor.
    fn scan_toggle(&mut self) {
        if self.scan.tab != ScanTab::Profiles {
            return;
        }
        match self.scan.profiles.pane {
            ProfilePane::Fields => {
                let Some(editor) = self.scan.profiles.editor.as_mut() else {
                    self.toast(Level::Info, NO_EDITOR);
                    return;
                };
                let field = editor.field();
                if field.kind() == FieldKind::Toggle && editor.cycle(field) {
                    self.recompute_launch_gate();
                }
            }
            ProfilePane::Checks => {
                let Some(selector) = self.scan.profiles.cursor_node().map(|n| n.selector.clone())
                else {
                    return;
                };
                self.scan.profiles.toggle_node(&selector);
                self.recompute_launch_gate();
            }
            ProfilePane::List | ProfilePane::Origins => {}
        }
    }

    /// Profiles ← / → (`h` / `l`) in the Checks pane: collapse or expand
    /// the lane or class node under the cursor (a check node has nothing
    /// under it). Nothing elsewhere in the view.
    fn scan_tree_fold(&mut self, collapse: bool) {
        if self.scan.tab != ScanTab::Profiles || self.scan.profiles.pane != ProfilePane::Checks {
            return;
        }
        self.scan.profiles.fold_node(collapse);
    }

    /// Profiles `o` (D11): the typed-origin prompt; needs an editor.
    fn scan_origin_prompt(&mut self) {
        if self.scan.tab != ScanTab::Profiles {
            return;
        }
        if self.scan.profiles.editor.is_none() {
            self.toast(Level::Info, NO_EDITOR);
            return;
        }
        self.open_prompt(PromptKind::ScanOrigin);
    }

    /// The `o` prompt's line (D8): the typed origin keeps its scheme, a bare
    /// host gets the rule's; a host, port or scheme the rule refuses is the
    /// `Err` the prompt retries on; a host the scope does not cover is
    /// refused with the one D8 toast and the prompt closes (scope is fixed
    /// elsewhere, so there is nothing to retype), as is a missing editor;
    /// otherwise the origin joins the draft and the picker, and an observed
    /// session reads its preview.
    fn submit_scan_origin(&mut self, text: &str, out: &mut Vec<BusRequest>) -> Result<(), String> {
        let origin = typed_origin(text, &self.flows).map_err(|e| e.to_string())?;
        if self.scope_host(&origin).is_none() {
            // Close-on-refusal: the toast already names the host to add.
            return Ok(());
        }
        let Some(editor) = self.scan.profiles.editor.as_mut() else {
            self.toast(Level::Info, NO_EDITOR);
            return Ok(());
        };
        editor.note_typed_origin(&origin);
        if editor.add_origin(&origin) {
            self.recompute_launch_gate();
            self.request_session_preview(out);
        }
        Ok(())
    }

    /// Settle a Scan prompt's submit (fix round G, G34): `Ok` closes the
    /// prompt, `Err` toasts the reason and keeps the prompt open with the
    /// line cleared, so the operator retypes or leaves with Esc.
    fn submit_retrying(&mut self, result: Result<(), String>) {
        match result {
            Ok(()) => self.close_prompt(),
            Err(e) => {
                self.toast(Level::Error, e);
                self.prompt.clear();
            }
        }
    }

    /// Profiles `a` in the Origins pane (D11): the highlighted picker row
    /// joins the draft.
    fn scan_origin_add(&mut self, out: &mut Vec<BusRequest>) {
        if self.scan.tab != ScanTab::Profiles || self.scan.profiles.pane != ProfilePane::Origins {
            return;
        }
        let Some(editor) = self.scan.profiles.editor.as_mut() else {
            return;
        };
        let Some(origin) = editor.highlighted_origin().map(str::to_string) else {
            return;
        };
        if editor.add_origin(&origin) {
            self.recompute_launch_gate();
            self.request_session_preview(out);
        }
    }

    /// Profiles `d` in the Origins pane (D11): the highlighted row's origin
    /// leaves the draft.
    fn scan_origin_remove(&mut self) {
        if self.scan.tab != ScanTab::Profiles || self.scan.profiles.pane != ProfilePane::Origins {
            return;
        }
        let Some(editor) = self.scan.profiles.editor.as_mut() else {
            return;
        };
        let Some(origin) = editor.highlighted_origin().map(str::to_string) else {
            return;
        };
        if editor.remove_origin(&origin) {
            self.recompute_launch_gate();
        }
    }

    /// Profiles `t` (D11): the L4 target prompt; needs an editor.
    fn scan_l4_target_prompt(&mut self) {
        if self.scan.tab != ScanTab::Profiles {
            return;
        }
        if self.scan.profiles.editor.is_none() {
            self.toast(Level::Info, NO_EDITOR);
            return;
        }
        self.open_prompt(PromptKind::ScanL4Target);
    }

    /// The `t` prompt's line: parsed by [`parse_l4_target`], added once.
    fn submit_scan_l4_target(&mut self, text: &str) -> Result<(), String> {
        let target = parse_l4_target(text).map_err(|e| e.to_string())?;
        let Some(editor) = self.scan.profiles.editor.as_mut() else {
            return Err(NO_EDITOR.to_string());
        };
        if editor.add_l4_target(target) {
            self.recompute_launch_gate();
        }
        Ok(())
    }

    /// The `ScanField` prompt's line: written into the field under the
    /// Fields cursor (the one `e` opened the prompt on).
    fn submit_scan_field(&mut self, text: &str) -> Result<(), String> {
        let Some(editor) = self.scan.profiles.editor.as_mut() else {
            return Err(NO_EDITOR.to_string());
        };
        let field = editor.field();
        editor.set_text(field, text).map_err(|e| e.to_string())?;
        self.recompute_launch_gate();
        Ok(())
    }

    /// Profiles `w` (D11): `scan.profile.save {profile}` with the draft
    /// serialised with serde (D3: the whole typed copy); a builtin, a
    /// builtin's name or an unnamed draft asks `ScanProfileName` first.
    fn scan_save(&mut self, out: &mut Vec<BusRequest>) {
        if self.scan.tab != ScanTab::Profiles {
            return;
        }
        let Some((builtin, name)) = self
            .scan
            .profiles
            .editor
            .as_ref()
            .map(|e| (e.builtin, e.draft.name.trim().to_string()))
        else {
            self.toast(Level::Info, NO_EDITOR);
            return;
        };
        if !self.scan_verb_or_toast("scan.profile.save") {
            return;
        }
        if builtin || name.is_empty() || self.scan.profiles.is_builtin(&name) {
            self.open_prompt(PromptKind::ScanProfileName);
            return;
        }
        self.send_profile_save(out);
    }

    /// The `ScanProfileName` prompt's line: the trimmed name, when it is
    /// not a builtin's and follows the engine's rule (`set_text`, which
    /// refuses with `PROFILE_NAME_RULE`; fix round G, G42, G49), replaces
    /// `draft.name`, then the draft is saved.
    fn submit_scan_profile_name(
        &mut self,
        text: &str,
        out: &mut Vec<BusRequest>,
    ) -> Result<(), String> {
        let name = text.trim();
        if is_builtin_name(name) {
            return Err(format!("{name} is a builtin profile; pick another name"));
        }
        let Some(editor) = self.scan.profiles.editor.as_mut() else {
            return Err(NO_EDITOR.to_string());
        };
        editor
            .set_text(EditorField::Name, name)
            .map_err(|e| e.to_string())?;
        self.send_profile_save(out);
        Ok(())
    }

    /// `scan.profile.save {profile: <draft>}` under its single-slot tag.
    fn send_profile_save(&mut self, out: &mut Vec<BusRequest>) {
        let Some(editor) = self.scan.profiles.editor.as_ref() else {
            return;
        };
        let profile = match serde_json::to_value(&editor.draft) {
            Ok(v) => v,
            Err(e) => {
                self.toast(
                    Level::Error,
                    format!("profile could not be serialised: {e}"),
                );
                return;
            }
        };
        self.scan_call(
            "scan.profile.save".to_string(),
            "scan.profile.save",
            json!({ "profile": profile }),
            out,
        );
    }

    /// Profiles `D` (D11): the non-builtin under the cursor (the List
    /// row, or the open editor's profile off the List pane) goes through
    /// the one-line `y/N` prompt, "delete profile <name>? y/N"; `y` sends
    /// `scan.profile.delete {name}` under `scan.profile.delete:<name>`
    /// ([`App::answer_confirm`]). A builtin is refused without a prompt.
    fn scan_delete(&mut self) {
        if self.scan.tab != ScanTab::Profiles {
            return;
        }
        let Some((name, builtin)) = self.scan.profiles.delete_target() else {
            return;
        };
        if builtin {
            self.toast(
                Level::Info,
                format!(
                    "{} is a builtin profile and cannot be deleted",
                    truncate(&name, SAVED_NAME_MAX)
                ),
            );
            return;
        }
        if !self.scan_verb_or_toast("scan.profile.delete") {
            return;
        }
        // Keyed by the name it deletes (spec D4), so the `y` leaves through
        // the tagged path (fix round G, G38).
        self.confirm = Some(ConfirmCall {
            name: "scan.profile.delete".to_string(),
            description: format!("delete profile {}? y/N", truncate(&name, SAVED_NAME_MAX)),
            args: json!({ "name": name }),
            return_to: Mode::Scan,
            tag: Some(tag_keyed("scan.profile.delete", &name)),
        });
        self.open_prompt(PromptKind::Confirm);
    }

    /// Jobs `x` (spec D11): `scan.cancel {job}` for the cursor's job under
    /// the tag `scan.cancel:<job>`, idempotent through the tag dedupe and
    /// with no extra prompt (the engine's cancel is itself idempotent). A
    /// terminal job makes the key inert: the banner reads `already <state>`
    /// as a notice (nothing failed, so no `ScanError` is recorded), cleared
    /// by the next key. Only the Jobs tab has a job under its cursor;
    /// elsewhere, and on the legacy row (D12), the key does nothing.
    fn scan_cancel(&mut self, out: &mut Vec<BusRequest>) {
        if self.scan.tab != ScanTab::Jobs {
            return;
        }
        let Some(job) = self.scan.jobs.cursor_job().cloned() else {
            return;
        };
        match self.scan.jobs.state_of(&job) {
            Some(state) if state.is_terminal() => {
                self.scan.notice = Some(format!("already {}", state_text(state)));
            }
            _ => {
                let tag = tag_keyed("scan.cancel", &job);
                self.scan_call(tag, "scan.cancel", json!({ "job": job }), out);
            }
        }
    }

    /// Whether the Issues list is on screen or was ever fetched (spec D6,
    /// "when the Issues tab was ever opened"): `request_issues` stamps
    /// `fetched_at_tick` the first time the tab is entered.
    fn issues_wanted(&self) -> bool {
        (self.mode == Mode::Scan && self.scan.tab == ScanTab::Issues)
            || self.scan.issues.fetched_at_tick.is_some()
    }

    /// The D6 timers, run from every `Tick`: every [`STATUS_POLL_TICKS`] one
    /// `scan.status` per live job (the cursor's job first, then `order` from
    /// the rotating `poll_offset`, at most [`MAX_STATUS_FOLLOWUPS`] leaving
    /// per firing; the rest are reached by the next firings, which start
    /// where this one stopped), every [`LIST_POLL_TICKS`] a `scan.list`
    /// while the Scan view is shown, and a `scan.issues` while the Issues
    /// tab is shown and the filtered job (any job, without the filter) is
    /// live, once [`ISSUES_POLL_TICKS`] have passed since the last
    /// `scan.issues` left (`fetched_at_tick`, re-stamped by every request),
    /// so entering the tab just before a modulo boundary does not fetch
    /// twice (fix round D, D7), and a `scan.sitemap` by the same rule with
    /// [`SITEMAP_POLL_TICKS`] while the Site map is shown and a job it
    /// covers is crawling.
    fn scan_tick(&mut self, t: u64, out: &mut Vec<BusRequest>) {
        if t.is_multiple_of(STATUS_POLL_TICKS) {
            let live = self.scan.jobs.live();
            let attempted = self.request_scan_statuses(&live, out);
            self.scan.jobs.advance_poll(&live[..attempted]);
        }
        if t.is_multiple_of(LIST_POLL_TICKS) && self.mode == Mode::Scan {
            // A new timer window: the healed jobs may be polled again (G83).
            self.scan.jobs.healed.clear();
            self.request_scan_list(out);
        }
        let issues_due = due(self.scan.issues.fetched_at_tick, t, ISSUES_POLL_TICKS);
        if issues_due
            && self.mode == Mode::Scan
            && self.scan.tab == ScanTab::Issues
            && self.issues_live()
        {
            self.request_issues(out);
        }
        // The Site map: forty ticks after the last read, while the tab is
        // shown and a covered job is crawling (D6).
        let sitemap_due = due(self.scan.sitemap.fetched_at_tick, t, SITEMAP_POLL_TICKS);
        if sitemap_due
            && self.mode == Mode::Scan
            && self.scan.tab == ScanTab::SiteMap
            && self.sitemap_crawling()
        {
            self.request_sitemap(None, out);
        }
    }

    /// `scan.list {}` under its single-slot tag, stamping `listed_at_tick`.
    fn request_scan_list(&mut self, out: &mut Vec<BusRequest>) {
        if self.scan_poll("scan.list".to_string(), "scan.list", json!({}), out) {
            self.scan.jobs.listed_at_tick = self.ticks;
        }
    }

    /// `scan.status {job}` under its keyed tag: the one spelling of the
    /// request the push line, the status timer and the `scan.list` fold
    /// share. Returns whether the call left.
    fn request_scan_status(&mut self, job: &str, out: &mut Vec<BusRequest>) -> bool {
        self.scan_poll(
            tag_keyed("scan.status", job),
            "scan.status",
            json!({ "job": job }),
            out,
        )
    }

    /// `scan.status` for each of `jobs` in turn until [`MAX_STATUS_FOLLOWUPS`]
    /// have left (spec D6, hostile-core bounds): a job already in flight
    /// costs nothing and the rest wait for the next firing. Returns how many
    /// of `jobs` were attempted (the prefix the cap let through), which the
    /// status timer moves its walk past.
    fn request_scan_statuses(&mut self, jobs: &[JobId], out: &mut Vec<BusRequest>) -> usize {
        let mut sent = 0;
        let mut attempted = 0;
        for job in jobs {
            if sent >= MAX_STATUS_FOLLOWUPS {
                break;
            }
            attempted += 1;
            if self.request_scan_status(job, out) {
                sent += 1;
            }
        }
        attempted
    }

    /// A timer- or push-driven `scan.*` read: silent when the bus lacks the
    /// verb (the tab's degraded text already says so, and a toast four times
    /// a second would not help), otherwise [`App::scan_call`].
    fn scan_poll(
        &mut self,
        tag: String,
        name: &str,
        args: Value,
        out: &mut Vec<BusRequest>,
    ) -> bool {
        self.has_tool(name) && self.scan_call(tag, name, args, out)
    }

    /// Whether the bus offers `name` (spec D2; fix round G, G40): when it
    /// does not, the missing verb is recorded as `<name> is not on this
    /// bus` in the owning tab's error line and toasted, once, here.
    fn scan_verb_or_toast(&mut self, name: &str) -> bool {
        if self.has_tool(name) {
            return true;
        }
        let err = ScanError::missing_verb(name);
        self.toast(Level::Warn, err.wording());
        self.scan.set_error(err);
        false
    }

    /// The one way a `scan.*` call leaves the reducer (spec D4). A verb the
    /// bus lacks is [`App::scan_verb_or_toast`]'s refusal; a tag already in
    /// flight is not re-issued. Returns whether the call was pushed.
    fn scan_call(
        &mut self,
        tag: String,
        name: &str,
        args: Value,
        out: &mut Vec<BusRequest>,
    ) -> bool {
        if !self.scan_verb_or_toast(name) {
            return false;
        }
        if self.scan.inflight.contains(&tag) {
            return false;
        }
        self.scan.inflight.insert(tag.clone());
        out.push(BusRequest::CallTagged {
            tag,
            name: name.to_string(),
            args,
        });
        true
    }

    /// A tagged `scan.*` call answered: settle the tag and fold the reply by
    /// verb (spec D10) through [`App::scan_reply`]. A reply that does not
    /// match the contract leaves the state and records a
    /// `ScanError { code: None }`. No `Refresh` is ever pushed from here
    /// (D4). Later tasks add their verbs to this match.
    fn on_scan_ok(&mut self, tag: &str, name: &str, value: Value, out: &mut Vec<BusRequest>) {
        self.scan.inflight.remove(tag);
        match name {
            "scan.start" | "scan.map" => {
                // A `needs_confirmation` reply opens the shared overlay with
                // the pending launch kept for the re-issue (D7); any other
                // reply settles the launch, folded as a `StartResult` when
                // it matches the contract. A reply with no pending launch
                // (a cancel or a drop already settled it) is recorded, not
                // folded (D7 as amended; fix round G, G67).
                let Some(pending) = self.scan.launch.pending.as_ref() else {
                    self.scan
                        .set_error(ScanError::uncoded(tag, "reply with no pending launch"));
                    return;
                };
                if let Some(confirm) =
                    WireConfirm::from_reply(pending.call.as_str(), &pending.launch.args, &value)
                {
                    self.open_wire_confirm(confirm, Mode::Scan);
                    return;
                }
                let fallback = self
                    .scan
                    .launch
                    .pending
                    .take()
                    .and_then(|p| p.launch.profile_name);
                if let Some(result) = self.scan_reply::<StartResult>(tag, &value) {
                    self.fold_start_result(tag, result, fallback);
                }
            }
            "scan.status" | "scan.cancel" => {
                // D6 hostile-core bound: the reply is folded only under the
                // job the tag asked about, so a core cannot mint a new live
                // job (and a new poll) per reply.
                if let Some(status) = self.scan_reply_keyed::<JobStatus>(
                    tag,
                    &value,
                    |s: &JobStatus| s.job.as_str(),
                    OTHER_JOB,
                ) {
                    self.scan.jobs.fold_status(status);
                }
            }
            "scan.list" => {
                if let Some(list) = self.scan_reply::<ListResult>(tag, &value) {
                    let followups = self.scan.jobs.fold_list(list);
                    self.request_scan_statuses(&followups, out);
                    // The list a `not_found` self-heal asked for clears the
                    // error it left (D13 as amended; fix round G, G74).
                    if let Some(healed) = self.scan.heal_pending.take() {
                        self.scan.clear_error(&healed);
                    }
                }
            }
            "scan.issues" => {
                if let Some(result) = self.scan_reply::<IssuesResult>(tag, &value) {
                    self.scan.issues.fold_result(result);
                    // The page arriving puts the cursor on a row: read it
                    // while the tab is on screen (D6, cursor landing).
                    if self.mode == Mode::Scan && self.scan.tab == ScanTab::Issues {
                        self.issue_cursor_landed(out);
                    }
                }
            }
            "scan.sitemap" => {
                // The page replaces the map, or appends after `n` (D10);
                // a reply that misses the contract leaves the map (the
                // next send sets the append flag again).
                if let Some(result) = self.scan_reply::<SitemapResult>(tag, &value) {
                    // An over-long `next_cursor` is dropped by the fold
                    // and recorded here (fix round G, G16).
                    if let Some(err) = self.scan.sitemap.fold_result(result) {
                        self.scan.set_error(err);
                    }
                }
            }
            "scan.profile.list" => {
                if let Some(list) = self.scan_reply::<ProfileListResult>(tag, &value) {
                    self.scan.profiles.fold_list(list);
                    // The cursor row may have changed (G73).
                    self.recompute_launch_gate();
                }
            }
            "scan.checks" => {
                if let Some(result) = self.scan_reply::<ChecksResult>(tag, &value) {
                    self.scan.profiles.fold_checks(result);
                }
            }
            "scan.profile.get" => {
                // The same hostile-core bound as `scan.status`: the profile
                // is folded only under the name the tag asked for, so a
                // reply cannot swap another profile into the editor.
                // The draft is echoed back on `w` and `s`, so a profile
                // over the draft bounds is refused whole (fix round G,
                // G45): the editor stays closed and no preview leaves.
                if let Some(profile) = self.scan_reply_keyed::<ScanProfile>(
                    tag,
                    &value,
                    |p: &ScanProfile| p.name.as_str(),
                    OTHER_PROFILE,
                ) {
                    match fold_profile(tag, profile) {
                        Ok(profile) => {
                            let name = profile.name.clone();
                            let builtin = self.scan.profiles.is_builtin(&name);
                            self.open_editor(ProfileEditor::new(profile, Some(name), builtin), out);
                        }
                        Err(err) => self.scan.set_error(err),
                    }
                }
            }
            "scan.profile.save" => {
                // `saved` is adopted as `loaded_from` only when it is a
                // usable selector naming the draft (fix round G, G46); any
                // other reply is recorded, not adopted.
                if let Some(saved) = self.scan_reply::<ProfileSaveResult>(tag, &value) {
                    let names_draft = self
                        .scan
                        .profiles
                        .editor
                        .as_ref()
                        .is_some_and(|e| e.draft.name == saved.saved);
                    if usable_selector(&saved.saved) && names_draft {
                        let name = truncate(&saved.saved, SAVED_NAME_MAX);
                        let path = truncate(&saved.path, SAVED_PATH_MAX);
                        self.toast(Level::Info, format!("saved {name} at {path}"));
                        if let Some(editor) = self.scan.profiles.editor.as_mut() {
                            editor.saved_as(saved.saved);
                        }
                    } else {
                        self.scan.set_error(ScanError::uncoded(tag, OTHER_SAVED));
                    }
                    self.request_profile_list(out);
                }
            }
            "scan.profile.delete" => {
                // The result names no profile; the tag's key does.
                let name = tag_parts(tag).1.unwrap_or_default().to_string();
                if let Some(result) = self.scan_reply::<ProfileDeleteResult>(tag, &value) {
                    let shown = truncate(&name, SAVED_NAME_MAX);
                    if result.deleted {
                        self.toast(Level::Info, format!("deleted {shown}"));
                    } else {
                        self.toast(Level::Warn, format!("{shown} was not a saved profile"));
                    }
                    // The editor over the deleted profile is stale: it
                    // closes, and the launch key is re-gated on the row.
                    if self.scan.profiles.on_deleted(&name) {
                        self.recompute_launch_gate();
                    }
                    self.request_profile_list(out);
                }
            }
            "scan.session.preview" => {
                // Folded only under the origin the tag asked for (names
                // only are in the type, D7).
                if let Some(preview) = self.scan_reply_keyed::<SessionProfile>(
                    tag,
                    &value,
                    |p: &SessionProfile| p.origin.as_str(),
                    OTHER_ORIGIN,
                ) {
                    let origin = tag_parts(tag).1.unwrap_or_default().to_string();
                    self.scan.profiles.fold_preview(&origin, preview);
                }
            }
            "scan.issue" | "scan.issue.update" => {
                // The read's reply, ok or not, settles the one read in
                // flight (D6); an update is its own keyed call.
                if name == "scan.issue" {
                    self.scan.issues.pending_read = None;
                }
                // The same hostile-core bound as `scan.status`: the issue
                // is folded only under the id the tag asked for. Both
                // verbs replace `read[id]` and the matching list row (D10;
                // an id the page no longer lists is not inserted, fix
                // round E, E11).
                if let Some(issue) = self.scan_reply_keyed::<Issue>(
                    tag,
                    &value,
                    |i: &Issue| i.id.as_str(),
                    OTHER_ISSUE,
                ) {
                    let answered = issue.id.clone();
                    self.scan.issues.fold_issue(issue);
                    // A landing the pending read held back is retried once
                    // (fix round E, E10): while the Issues tab is shown,
                    // a cursor row other than the one answered is read
                    // now if it is still unread (`issue_cursor_landed`
                    // keeps the List-pane and `read` checks). Only a
                    // successful reply retries, so there is no loop.
                    let moved_on = self
                        .scan
                        .issues
                        .cursor_issue()
                        .is_some_and(|row| row.id != answered);
                    if name == "scan.issue"
                        && moved_on
                        && self.mode == Mode::Scan
                        && self.scan.tab == ScanTab::Issues
                    {
                        self.issue_cursor_landed(out);
                    }
                }
            }
            _ => {}
        }
    }

    /// Parse a `scan.*` reply into its D10 type: the one parse /
    /// clear-or-set scaffold every verb arm shares. A match clears the error
    /// this tag left behind (D13) and is returned for the fold; a mismatch
    /// records the contract error under the tag and yields `None`, so the
    /// prior state stays on screen. The banner notice is not touched here:
    /// only the next key clears it (spec D3; fix round F, F15), so a
    /// background status poll cannot erase `already done` before the
    /// operator reads it.
    fn scan_reply<T: serde::de::DeserializeOwned>(
        &mut self,
        tag: &str,
        value: &Value,
    ) -> Option<T> {
        match parse_result::<T>(tag, value) {
            Ok(parsed) => {
                self.scan.clear_error(tag);
                Some(parsed)
            }
            Err(e) => {
                self.scan.set_error(e);
                None
            }
        }
    }

    /// [`App::scan_reply`] for a keyed verb (`<verb>:<key>`): the parsed
    /// reply is returned only when `key` reads the tag's key off it (spec
    /// D6, hostile-core bounds); otherwise the uncoded error `other`
    /// (`OTHER_JOB`, `OTHER_ISSUE`) is recorded under the tag and nothing is
    /// folded. `scan.status`, `scan.cancel`, `scan.issue` and
    /// `scan.issue.update` share it (fix round D, D9). The tag is the
    /// verb's source ([`tag_parts`]), so no verb name travels beside it.
    fn scan_reply_keyed<T: serde::de::DeserializeOwned>(
        &mut self,
        tag: &str,
        value: &Value,
        key: fn(&T) -> &str,
        other: &'static str,
    ) -> Option<T> {
        let parsed = self.scan_reply::<T>(tag, value)?;
        if Some(key(&parsed)) == tag_parts(tag).1 {
            Some(parsed)
        } else {
            self.scan.set_error(ScanError::uncoded(tag, other));
            None
        }
    }

    /// A tagged `scan.*` call failed (spec D9, D13): the error is recorded
    /// where its tab shows it and toasted. Two whys: a `not_found` on a
    /// keyed `scan.status` / `scan.cancel` (`ScanError::not_found_job`,
    /// spec call 8) drops the job from `started_here` too, else the
    /// `scan.list` the self-heal asks for would put it back at the front;
    /// a refused launch clears `pending` so the key is live again, and the
    /// Profiles footer reads the wording off the tab's error
    /// (`ScanState::refused_launch`), the UI-3 `blocked` text taking
    /// precedence over it (D13), so nothing more is kept for it here.
    fn on_scan_failed(&mut self, tag: &str, message: String, out: &mut Vec<BusRequest>) {
        self.scan.inflight.remove(tag);
        let err = ScanError::from_message(tag, &message);
        if err.verb == "scan.issue" {
            self.scan.issues.pending_read = None;
        }
        // The pending launch is answered: the key is live again (D7, D13).
        if self
            .scan
            .launch
            .pending
            .as_ref()
            .is_some_and(|p| p.call.as_str() == tag)
        {
            self.scan.launch.pending = None;
        }
        if let Some(job) = err.not_found_job() {
            let job = job.to_string();
            self.scan.jobs.forget(&job);
            // The requested list's success clears this error (D13 as
            // amended, G74) and asks no status for the job until the
            // timer's list (G83).
            self.scan.jobs.healed.insert(job);
            self.scan.heal_pending = Some(tag.to_string());
            self.request_scan_list(out);
        }
        self.toast(Level::Error, err.wording());
        self.scan.set_error(err);
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
/// [`crate::viewers::image::dimensions`] recognises: what Findings `o` is
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

/// `pause` → `Pause`, for a toast that starts a sentence.
fn title_case(word: &str) -> String {
    let mut c = word.chars();
    match c.next() {
        Some(first) => first.to_uppercase().chain(c).collect(),
        None => String::new(),
    }
}

/// C12: whether a `poc.build` reply is the PoC's YAML text rather than a
/// path: it spans lines, or it neither contains a `/` nor ends in
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
/// quotes stripped: enough to title a PoC the TUI just wrote.
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
    ("ca", "CA panel: status, export, install, uninstall"),
    ("config", "Config panel: the redacted config.get view"),
    (
        "browser",
        "Browser view: URL, DOM outline, screenshot; navigate and eval",
    ),
    (
        "scan",
        "Scan view: profiles, jobs, site map, issues (s starts scan.start; :scan <origin> starts against an origin)",
    ),
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
    use serde_json::json;

    fn tools(names: &[&str]) -> Vec<ToolInfo> {
        names
            .iter()
            .map(|n| ToolInfo {
                name: (*n).to_string(),
                description: String::new(),
                input_schema: json!({"type":"object","properties":{}}),
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

    fn summary(
        id: &str,
        method: &str,
        authority: &str,
        path: &str,
        status: Option<u16>,
        intercept: &str,
    ) -> Value {
        json!({"id":id,"kind":"http","method":method,"scheme":"https","authority":authority,"path":path,
               "status":status,"is_replay":false,"intercept":intercept})
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
            Some("Out of scope: add `telemetry.vendor.example` to scope to act")
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
        assert_eq!(e.lines[3], "<7 binary bytes: edit in hex is a follow-up>");
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
        assert!(app.current_toast().unwrap().text.contains("F1"));
        assert!(app.run_command("clear").is_empty());
        assert!(app.current_toast().unwrap().text.contains("F7"));
        app.tools.push(ToolInfo {
            name: "agent.set".into(),
            description: String::new(),
            input_schema: json!({}),
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
        let mut app = crate::fixture_app(200, 50);
        // Findings: the fixture bus is not on this machine, so the screenshot
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
        // A small text body (f41's products JSON) is shown inline: nothing to open.
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
            .ends_with("aitm-tui-img.png, opening"));
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
        assert!(!App::new(TermCaps::full(), "fixture").is_loopback_bus());
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
            Some("Resume all: 1 resumed, 1 skipped out of scope (add their hosts to scope to act)")
        );
    }

    /// The fixture app on `f41` (products JSON) with the Response pane's JSON
    /// tab focused.
    fn json_tab_app() -> App {
        let mut app = crate::fixture_app(200, 50);
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
            Some("https://api.shop-staging.test/api/products?category=electronics&limit=20")
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
}
