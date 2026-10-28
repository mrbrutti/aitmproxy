//! The operator UI's state and its reducer. `App` is plain data; `update`
//! takes an [`Action`] and returns the [`BusRequest`]s it implies; `on_bus`
//! folds a [`BusEvent`] in. No terminal, no socket, no clock: the loop in
//! `lib.rs` owns those, which is what lets every screen be tested from fixture
//! data (foundation §2.10: "one fixture file … so a screen renders the same
//! data on every platform").

use std::collections::{HashMap, HashSet, VecDeque};

use serde_json::{json, Map, Value};

use crate::action::{Action, BusEvent, BusRequest, Level, ToolInfo};
use crate::caps::TermCaps;
use crate::filter::{self, Expr};
use crate::model::{
    counts_by, AgentPolicy, AgentState, Finding, FlowDetail, FlowKind, FlowRow, Message,
};
use crate::theme::Theme;
use crate::viewers::json;

/// Terminal widths below which the shell changes shape (§2.10(c)).
pub const NARROW_COLS: u16 = 120;
pub const SPLIT_COLS: u16 = 160;

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
    Help,
    QuickLook,
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
    PocName,
    PocTarget,
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
}

impl SidebarItem {
    pub const ALL: [SidebarItem; 10] = [
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

/// Inspector tabs, in the foundation's order (§2.7).
pub const REQUEST_TABS: [&str; 6] = ["Headers", "Query", "Body", "Raw", "Summary", "Connection"];
pub const RESPONSE_TABS: [&str; 6] = ["Headers", "Body", "Raw", "JSON", "Hex", "Diff"];

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
            response_tab: 1,
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EditBuffer {
    pub id: String,
    pub lines: Vec<String>,
    pub cursor_line: usize,
    pub cursor_col: usize,
    pub original: Vec<String>,
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
        if let Some(text) = req.body_text() {
            lines.extend(text.lines().map(str::to_string));
        } else if !req.body.is_empty() {
            lines.push(format!(
                "<{} binary bytes — edit in hex is a follow-up>",
                req.body.len()
            ));
        }
        Self {
            id: id.to_string(),
            original: lines.clone(),
            lines,
            cursor_line: 0,
            cursor_col: 0,
        }
    }

    pub fn dirty(&self) -> bool {
        self.lines != self.original
    }

    /// The `flow.mutate` `edits` object: method, path, every header (the core
    /// replaces by name) and the body as text.
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
        let mut body = Vec::new();
        let mut in_body = false;
        for line in it {
            if in_body {
                body.push(line.as_str());
            } else if line.is_empty() {
                in_body = true;
            } else if let Some((n, v)) = line.split_once(':') {
                headers.insert(n.trim().to_string(), Value::String(v.trim().to_string()));
            }
        }
        edits.insert("headers".into(), Value::Object(headers));
        edits.insert("body".into(), Value::String(body.join("\n")));
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
    Connected { server: String, address: String },
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
    pub details: HashMap<String, FlowDetail>,
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
    pub tools: Vec<ToolInfo>,
    pub caps: TermCaps,
    pub listening: Option<String>,
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
}

impl App {
    pub fn new(caps: TermCaps, bus_address: impl Into<String>) -> Self {
        Self {
            flows: Vec::new(),
            details: HashMap::new(),
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
            tools: Vec::new(),
            caps,
            listening: None,
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

    pub fn row(&self, id: &str) -> Option<&FlowRow> {
        self.flows.iter().find(|r| r.id == id)
    }

    pub fn selected_row(&self) -> Option<&FlowRow> {
        self.selected.as_deref().and_then(|id| self.row(id))
    }

    pub fn selected_detail(&self) -> Option<&FlowDetail> {
        self.selected.as_deref().and_then(|id| self.details.get(id))
    }

    /// The selected flow's response body when the Response pane's JSON tab
    /// is showing it; `None` on any other pane or tab.
    fn json_body(&self) -> Option<&str> {
        if self.inspector.pane != Pane::Response
            || RESPONSE_TABS.get(self.inspector.response_tab) != Some(&"JSON")
        {
            return None;
        }
        self.selected_detail()?.response.as_ref()?.body_text()
    }

    /// The JSON tree as the JSON tab draws it (paths only matter here, so the
    /// theme is irrelevant); `None` off the JSON tab or when the body is not JSON.
    fn json_tree(&self) -> Option<Vec<Option<String>>> {
        let body = self.json_body()?;
        json::tree_with_paths(&Theme::new(false), body, &self.inspector.folds).map(|(_, p)| p)
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

    /// Scope-as-authorisation (§2.7): `host`, `host:port`, `*.wildcard`.
    pub fn in_scope(&self, row: &FlowRow) -> bool {
        scope_covers(&self.scope, &row.authority)
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
            GroupBy::Host => Some(row.host().to_string()),
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

    pub fn domains(&self) -> Vec<(String, usize)> {
        counts_by(&self.flows, |r| Some(r.host().to_string()))
    }

    pub fn in_scope_count(&self) -> usize {
        self.flows.iter().filter(|r| self.in_scope(r)).count()
    }

    pub fn total_bytes(&self) -> u64 {
        self.flows
            .iter()
            .map(|r| r.req_size.unwrap_or(0) + r.resp_size.unwrap_or(0))
            .sum()
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
            Action::Resume => {
                if let Some(r) = self.intercept_target().cloned() {
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
                for r in ids {
                    if self.in_scope(&r) {
                        out.push(BusRequest::Resume(r.id));
                    }
                }
            }
            Action::Kill => {
                if let Some(r) = self.intercept_target().cloned() {
                    if self.gate(&r) {
                        out.push(BusRequest::Kill(r.id));
                    }
                } else {
                    self.toast(Level::Info, "Nothing paused.");
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
                        self.inspector.request_tab = 3;
                    }
                    None => {
                        self.toast(Level::Warn, "Raw edit needs the request detail (core follow-up F5); headers-only edit via :flow.mutate");
                        out.push(BusRequest::Detail(r.id));
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
            Action::OpenExternally => {
                self.toast(
                    Level::Info,
                    "Opening externally is deferred to the shell: see the status bar path",
                );
            }
            Action::OpenFindings => {
                self.mode = Mode::Findings;
                self.sidebar = SidebarItem::Findings;
            }
            Action::OpenScope => {
                self.mode = Mode::Scope;
                self.sidebar = SidebarItem::Scope;
            }
            Action::OpenAgent => {
                self.mode = Mode::Agent;
                self.sidebar = SidebarItem::Agent;
            }
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
                self.prompt = self.filter_text.clone();
                self.mode = Mode::Prompt(PromptKind::Filter);
            }
            Action::InspectorPaneToggle => {
                self.inspector.pane = match self.inspector.pane {
                    Pane::Request => Pane::Response,
                    Pane::Response => Pane::Request,
                };
                self.inspector.reset_view();
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
        }
        out
    }

    fn gate(&mut self, r: &FlowRow) -> bool {
        if self.in_scope(r) {
            true
        } else {
            let host = r.host().to_string();
            self.toast(
                Level::Warn,
                format!("Out of scope — add `{host}` to scope to act"),
            );
            false
        }
    }

    fn back(&mut self) {
        self.mode = match self.mode {
            Mode::Edit => {
                self.edit = None;
                Mode::Inspector
            }
            Mode::Prompt(PromptKind::Filter) => {
                self.prompt.clear();
                Mode::Flows
            }
            Mode::Prompt(_) => {
                self.prompt.clear();
                self.poc_pending = None;
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

    fn open_prompt(&mut self, kind: PromptKind) {
        self.prompt.clear();
        self.palette_cursor = 0;
        self.mode = Mode::Prompt(kind);
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
                        self.mode = Mode::Flows;
                    }
                    Some(PaletteItem {
                        kind: PaletteKind::Tool(name),
                        ..
                    }) if !text.contains(' ') => {
                        let t = self.tools.iter().find(|t| t.name == name).cloned();
                        let needs = t.map(|t| t.params().iter().any(|p| p.2)).unwrap_or(false);
                        if needs {
                            self.prompt = format!("{name} ");
                            self.toast(
                                Level::Info,
                                format!("{name}: type key=value arguments, then Enter"),
                            );
                            return out;
                        }
                        self.mode = Mode::Flows;
                        out.push(BusRequest::Call {
                            name,
                            args: json!({}),
                        });
                    }
                    Some(PaletteItem {
                        kind: PaletteKind::Command(cmd),
                        ..
                    }) if !text.contains(' ')
                        && !text.is_empty()
                        && cmd.split(' ').count() == 1 =>
                    {
                        self.mode = Mode::Flows;
                        out.extend(self.run_command(&cmd));
                    }
                    _ => {
                        self.mode = Mode::Flows;
                        out.extend(self.run_command(&text));
                    }
                }
                self.prompt.clear();
            }
            Mode::Prompt(PromptKind::Filter) => {
                match filter::parse(&text) {
                    Ok(expr) => {
                        self.filter = expr;
                        self.filter_text = text;
                        self.mode = Mode::Flows;
                    }
                    Err(e) => self.toast(Level::Error, format!("filter: {e}")),
                }
                self.prompt.clear();
            }
            Mode::Prompt(PromptKind::Comment) => {
                if let Some(id) = self.selected.clone() {
                    out.push(BusRequest::Comment { id, text });
                }
                self.mode = Mode::Flows;
                self.prompt.clear();
            }
            Mode::Prompt(PromptKind::Mark) => {
                if let Some(id) = self.selected.clone() {
                    let marks = text.split_whitespace().map(str::to_string).collect();
                    out.push(BusRequest::Mark { id, marks });
                }
                self.mode = Mode::Flows;
                self.prompt.clear();
            }
            Mode::Prompt(PromptKind::Pin) => {
                if !text.is_empty() && !self.pinned_hosts.contains(&text) {
                    self.pinned_hosts.push(text);
                }
                self.mode = Mode::Flows;
                self.prompt.clear();
            }
            Mode::Prompt(PromptKind::ScopeAdd) => {
                if !text.is_empty() {
                    out.push(BusRequest::ScopeAdd(text));
                }
                self.mode = Mode::Scope;
                self.prompt.clear();
            }
            Mode::Prompt(PromptKind::PocName) => {
                if let Some((id, _)) = self.poc_pending.take() {
                    let name = (!text.is_empty()).then_some(text);
                    out.push(BusRequest::PocBuild {
                        flow_id: id,
                        name,
                        param: None,
                    });
                }
                self.mode = Mode::Flows;
                self.prompt.clear();
            }
            Mode::Prompt(PromptKind::PocTarget) => {
                if let Some(f) = self.findings.get(self.finding_cursor) {
                    out.push(BusRequest::PocRun {
                        poc_path: f.poc_path.clone(),
                        target: (!text.is_empty()).then_some(text),
                    });
                }
                self.mode = Mode::Findings;
                self.prompt.clear();
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
            Mode::Compose => {
                self.compose.field = match action {
                    Action::Up => self.compose.field.saturating_sub(1),
                    Action::Down => (self.compose.field + 1).min(3),
                    _ => self.compose.field,
                };
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

    fn sidebar_step(&mut self, d: i32, out: &mut Vec<BusRequest>) {
        self.sidebar = step(&SidebarItem::ALL, self.sidebar, d);
        match self.sidebar {
            SidebarItem::Findings => self.mode = Mode::Findings,
            SidebarItem::Scope => self.mode = Mode::Scope,
            SidebarItem::Agent => self.mode = Mode::Agent,
            SidebarItem::Browser => {
                self.mode = Mode::Flows;
                self.toast(Level::Info, "Browser view: URL/DOM/navigate via :browser.* (viewport is core follow-up F14)");
            }
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
        let _ = out;
    }

    fn tab_step(&mut self, d: i32) {
        let (tab, n) = match self.inspector.pane {
            Pane::Request => (&mut self.inspector.request_tab, REQUEST_TABS.len()),
            Pane::Response => (&mut self.inspector.response_tab, RESPONSE_TABS.len()),
        };
        *tab = (*tab as i32 + d).rem_euclid(n as i32) as usize;
        self.inspector.reset_view();
    }

    fn ensure_detail(&mut self, out: &mut Vec<BusRequest>) {
        if let Some(id) = &self.selected {
            if !self.details.contains_key(id) && self.has_tool("flow.detail") {
                out.push(BusRequest::Detail(id.clone()));
            }
        }
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
                    ("add", h) if !h.is_empty() => out.push(BusRequest::ScopeAdd(h.to_string())),
                    ("rm", h) | ("remove", h) if !h.is_empty() => {
                        if self.has_tool("scope.remove") {
                            out.push(BusRequest::ScopeRemove(h.to_string()));
                        } else {
                            self.toast(Level::Warn, "scope.remove needs core follow-up F12");
                        }
                    }
                    _ => self.mode = Mode::Scope,
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
            "compose" | "new" => out.extend(self.update(Action::Compose)),
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
            "pause" | "record" => {
                if self.has_tool("proxy.pause") {
                    let pause = cmd == "pause";
                    out.push(BusRequest::ProxyPause(pause));
                } else {
                    self.toast(
                        Level::Warn,
                        "Pause/record needs core follow-up F7 (proxy.pause)",
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
                    });
                } else if rest == "build" {
                    out.extend(self.update(Action::BuildPoc));
                } else {
                    self.mode = Mode::Findings;
                }
            }
            "send" => {
                if self.mode == Mode::Compose {
                    self.compose.field = 3;
                    out.extend(self.submit());
                }
            }
            "poc-rerun" => {
                if self.findings.get(self.finding_cursor).is_some() {
                    self.prompt.clear();
                    self.mode = Mode::Prompt(PromptKind::PocTarget);
                }
            }
            "scope-prompt" => self.open_prompt(PromptKind::ScopeAdd),
            "scope-rm-selected" => {
                if let Some(h) = self.scope.get(self.scope_cursor).cloned() {
                    out.extend(self.run_command(&format!("scope rm {h}")));
                }
            }
            "copy" => out.extend(self.update(Action::CopyUrl)),
            "auto" | "autoselect" => out.extend(self.update(Action::ToggleAutoSelect)),
            "refresh" => out.push(BusRequest::Refresh),
            tool if self.has_tool(tool) => {
                match parse_kv_args(rest, self.tools.iter().find(|t| t.name == tool)) {
                    Ok(args) => out.push(BusRequest::Call {
                        name: tool.to_string(),
                        args,
                    }),
                    Err(e) => self.toast(Level::Error, format!("{tool}: {e}")),
                }
            }
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
                listening,
            } => {
                self.bus = BusStatus::Connected {
                    server,
                    address: self.bus_address.clone(),
                };
                self.tools = tools;
                if listening.is_some() {
                    self.listening = listening;
                }
                out.push(BusRequest::Refresh);
            }
            BusEvent::Disconnected(why) => {
                self.bus = BusStatus::Disconnected(why.clone());
                self.toast(Level::Error, format!("bus: {why}"));
            }
            BusEvent::Flows(summaries) => {
                let had = self.flows.len();
                let mut seen: HashSet<String> = HashSet::new();
                for s in &summaries {
                    let Some(id) = s.get("id").and_then(Value::as_str) else {
                        continue;
                    };
                    seen.insert(id.to_string());
                    if let Some(existing) = self.flows.iter_mut().find(|r| r.id == id) {
                        if let Some(fresh) = FlowRow::from_summary(s, existing.seq) {
                            let changed = fresh.status != existing.status
                                || fresh.intercept != existing.intercept;
                            existing.status = fresh.status.or(existing.status);
                            existing.intercept = fresh.intercept;
                            existing.is_replay |= fresh.is_replay;
                            existing.ws_messages = fresh.ws_messages.or(existing.ws_messages);
                            if changed
                                && self.details.remove(id).is_some()
                                && self.has_tool("flow.detail")
                            {
                                out.push(BusRequest::Detail(id.to_string()));
                            }
                        }
                    } else if let Some(row) = FlowRow::from_summary(s, self.next_seq) {
                        self.next_seq += 1;
                        if self.has_tool("flow.detail") {
                            out.push(BusRequest::Detail(row.id.clone()));
                        }
                        self.flows.push(row);
                    }
                }
                self.flows.retain(|r| seen.contains(&r.id));
                if self
                    .selected
                    .as_deref()
                    .is_some_and(|id| !seen.contains(id))
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
                if let Some(row) = self.flows.iter_mut().find(|r| r.id == d.id) {
                    row.apply_detail(&d);
                }
                self.details.insert(d.id.clone(), *d);
            }
            BusEvent::Intercept(armed) => self.intercept_armed = armed,
            BusEvent::Scope(entries) => self.scope = entries,
            BusEvent::Findings(f) => {
                self.findings = f;
                self.finding_cursor = self
                    .finding_cursor
                    .min(self.findings.len().saturating_sub(1));
            }
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
                    "poc.build" => {
                        self.toast(
                            Level::Info,
                            format!("PoC written: {}", value.as_str().unwrap_or("?")),
                        );
                    }
                    "poc.run" => {
                        if let Some(f) = Finding::from_json(&value) {
                            let verdict = if f.passed { "passed" } else { "failed" };
                            self.toast(Level::Info, format!("PoC {verdict}: {}", f.title));
                            self.findings.insert(0, f);
                            self.finding_cursor = 0;
                        }
                    }
                    "flow.mutate" => self.toast(Level::Info, "Edit applied"),
                    "flow.resume" => self.toast(Level::Info, "Resumed"),
                    "flow.kill" => self.toast(Level::Info, "Killed"),
                    "flow.intercept" => {
                        self.intercept_armed = value.as_bool().unwrap_or(self.intercept_armed);
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
                    _ => {
                        let text = match &value {
                            Value::String(s) => s.clone(),
                            Value::Null => "ok".into(),
                            other => other.to_string(),
                        };
                        let shown: String = text.chars().take(160).collect();
                        self.toast(Level::Info, format!("{name}: {shown}"));
                    }
                }
                out.push(BusRequest::Refresh);
            }
            BusEvent::Toast(level, text) => self.toast(level, text),
            BusEvent::Notification(v) => {
                if let Some(paused) = v.pointer("/params/paused").and_then(Value::as_u64) {
                    let _ = paused;
                }
                out.push(BusRequest::Refresh);
            }
        }
        out
    }
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
    ("layout h|v", "Inspector below or right"),
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

/// Whether `authority` is covered by any scope entry.
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

/// Subsequence match: every char of `needle` appears in order in `hay`.
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
        .map(|t| {
            t.params()
                .into_iter()
                .map(|(n, ty, _, _)| (n, ty))
                .collect()
        })
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
        for (name, _, required, _) in t.params() {
            if required && !args.contains_key(&name) {
                return Err(format!("missing required `{name}`"));
            }
        }
    }
    Ok(Value::Object(args))
}

#[cfg(test)]
mod tests {
    use super::*;
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
                assert_eq!(edits["body"], r#"{"email":"ops"}"#);
            }
            other => panic!("expected Mutate, got {other:?}"),
        }
        assert_eq!(reqs[1], BusRequest::Resume("f3".into()));
        assert_eq!(app.mode, Mode::Flows);
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
