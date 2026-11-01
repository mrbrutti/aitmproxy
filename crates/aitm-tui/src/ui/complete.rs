//! The completion engine and popup (UI-ext spec §1.2, plan Task 7). Candidates
//! for the Rhai and PoC-YAML editors are drawn from the shared catalogs
//! (`rhai.api.json`, `poc-yaml.schema.json`, embedded via [`crate::languages`])
//! so the terminal offers exactly the set the web and macOS surfaces do; the
//! shared completion conformance fixtures pin that set. [`CompleteState`] +
//! [`render`] are the floating popup an editor anchors at the caret — a
//! `floating`-style list, `↑`/`↓` to move, accept-selected to insert.
//!
//! Only the candidate source and the popup live here; wiring into an authorable
//! editor is the Scripts-view task (plan Task 8, gated on core F8). Highlighting
//! of PoC YAML is already wired into the Findings viewer (`crate::syntax`).

use std::collections::HashSet;
use std::sync::OnceLock;

use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::Widget as _;
use serde_json::Value;

use crate::languages::{POC_SCHEMA_JSON, RHAI_API_JSON};
use crate::theme::Theme;

/// One completion candidate: the text to insert and a one-line hint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    /// The identifier/key/enum value to insert.
    pub label: String,
    /// A one-line hint (a Rhai signature, a key/enum description).
    pub detail: String,
}

fn rhai_api() -> &'static Value {
    static API: OnceLock<Value> = OnceLock::new();
    API.get_or_init(|| {
        serde_json::from_str(RHAI_API_JSON).expect("rhai.api.json is validated at build time")
    })
}

fn poc_schema() -> &'static Value {
    static SCHEMA: OnceLock<Value> = OnceLock::new();
    SCHEMA.get_or_init(|| {
        serde_json::from_str(POC_SCHEMA_JSON)
            .expect("poc-yaml.schema.json is validated at build time")
    })
}

// ---- Rhai completion ----------------------------------------------------

fn is_ident(c: u8) -> bool {
    c == b'_' || c.is_ascii_alphanumeric()
}

/// Rhai completion candidates for the caret (a byte offset into `src`): the
/// hooks at top level, or the members of the receiver chain after a `.`.
pub fn rhai_candidates(src: &str, caret: usize) -> Vec<Candidate> {
    let caret = clamp_boundary(src, caret);
    let text = &src[..caret];
    let b = text.as_bytes();

    let mut ws = b.len();
    while ws > 0 && is_ident(b[ws - 1]) {
        ws -= 1;
    }
    let partial = &text[ws..];

    if ws > 0 && b[ws - 1] == b'.' {
        // Member: the dotted receiver chain ending just before the dot.
        let mut k = ws - 1;
        while k > 0 && (is_ident(b[k - 1]) || b[k - 1] == b'.') {
            k -= 1;
        }
        let receiver = text[k..ws].trim_matches('.');
        rhai_members(receiver, partial)
    } else if brace_depth(text) == 0 {
        // Module scope: the operator is declaring a hook.
        rhai_hooks(partial)
    } else {
        // Inside a hook body: the host globals and DSL helpers.
        rhai_globals(partial)
    }
}

/// A naive `{` − `}` nesting depth for `text` (string/comment contents are not
/// excluded — enough to tell "declaring a hook" from "inside a body").
fn brace_depth(text: &str) -> i32 {
    let mut depth = 0;
    for c in text.bytes() {
        match c {
            b'{' => depth += 1,
            b'}' => depth -= 1,
            _ => {}
        }
    }
    depth.max(0)
}

fn detail_of(e: &Value) -> String {
    e["signature"]
        .as_str()
        .or_else(|| e["description"].as_str())
        .unwrap_or("")
        .to_string()
}

fn rhai_members(receiver: &str, partial: &str) -> Vec<Candidate> {
    let api = rhai_api();
    let prefix = format!("{receiver}.");
    let mut out = Vec::new();
    for group in ["flow", "msg", "globals"] {
        let Some(arr) = api[group].as_array() else {
            continue;
        };
        for e in arr {
            let name = e["name"].as_str().unwrap_or("");
            if let Some(seg) = name.strip_prefix(&prefix) {
                if !seg.is_empty() && !seg.contains('.') && seg.starts_with(partial) {
                    out.push(Candidate {
                        label: seg.to_string(),
                        detail: detail_of(e),
                    });
                }
            }
        }
    }
    out
}

fn rhai_hooks(partial: &str) -> Vec<Candidate> {
    let api = rhai_api();
    api["hooks"]
        .as_array()
        .map(|a| a.as_slice())
        .unwrap_or_default()
        .iter()
        .filter_map(|e| {
            let name = e["name"].as_str().unwrap_or("");
            name.starts_with(partial).then(|| Candidate {
                label: name.to_string(),
                detail: detail_of(e),
            })
        })
        .collect()
}

fn rhai_globals(partial: &str) -> Vec<Candidate> {
    let api = rhai_api();
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    // Globals and DSL helpers, by their base identifier (`log`, `http`, …).
    for group in ["globals", "dsl"] {
        let Some(arr) = api[group].as_array() else {
            continue;
        };
        for e in arr {
            let name = e["name"].as_str().unwrap_or("");
            let base = name.split('.').next().unwrap_or(name);
            if base.starts_with(partial) && seen.insert(base.to_string()) {
                let detail = if base == name {
                    detail_of(e)
                } else {
                    "namespace".to_string()
                };
                out.push(Candidate {
                    label: base.to_string(),
                    detail,
                });
            }
        }
    }
    out
}

// ---- PoC YAML completion -----------------------------------------------

enum PocCtx {
    Key {
        path: Vec<String>,
        partial: String,
    },
    Enum {
        path: Vec<String>,
        key: String,
        partial: String,
    },
}

/// PoC-YAML completion candidates for the caret: the schema keys valid at the
/// current nesting, or the enum values valid after a `key:`.
pub fn poc_yaml_candidates(src: &str, caret: usize) -> Vec<Candidate> {
    let caret = clamp_boundary(src, caret);
    match poc_context(&src[..caret]) {
        PocCtx::Key { path, partial } => poc_keys(&path, &partial),
        PocCtx::Enum { path, key, partial } => poc_enum(&path, &key, &partial),
    }
}

fn indent_of(line: &str) -> usize {
    line.bytes().take_while(|&c| c == b' ').count()
}

/// A plain `key:` at the start of `s`, returning the key.
fn leading_key(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() && is_key_byte(b[i]) {
        i += 1;
    }
    if i > 0 && i < b.len() && b[i] == b':' {
        Some(s[..i].to_string())
    } else {
        None
    }
}

fn is_key_byte(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_' || c == b'-' || c == b'.'
}

fn pop_ge(stack: &mut Vec<(usize, String)>, col: usize) {
    while stack.last().is_some_and(|(c, _)| *c >= col) {
        stack.pop();
    }
}

/// Strips a leading `- ` (or a bare `-`) list marker, returning the content.
fn strip_dash(rest: &str) -> Option<&str> {
    rest.strip_prefix("- ")
        .or_else(|| (rest == "-").then_some(""))
}

fn poc_context(text: &str) -> PocCtx {
    let mut lines: Vec<&str> = text.split('\n').collect();
    let current = lines.pop().unwrap_or("");

    // Reconstruct the ancestor path from the completed lines above the caret.
    let mut stack: Vec<(usize, String)> = Vec::new();
    for line in &lines {
        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let indent = indent_of(line);
        let rest = &line[indent..];
        if let Some(inner) = strip_dash(rest) {
            let dash_col = indent;
            pop_ge(&mut stack, dash_col);
            stack.push((dash_col, "[]".to_string()));
            let inner_col = indent + 2;
            if let Some(key) = leading_key(inner) {
                pop_ge(&mut stack, inner_col);
                stack.push((inner_col, key));
            }
        } else if let Some(key) = leading_key(rest) {
            pop_ge(&mut stack, indent);
            stack.push((indent, key));
        }
    }

    // Parse the current (partial) line for the completion context.
    let indent = indent_of(current);
    let rest = &current[indent..];
    let (dash, key_col, content) = match strip_dash(rest) {
        Some(inner) => (true, indent + 2, inner),
        None => (false, indent, rest),
    };
    let mut path: Vec<String> = stack
        .iter()
        .filter(|(c, _)| *c < key_col)
        .map(|(_, s)| s.clone())
        .collect();
    if dash {
        path.push("[]".to_string());
    }

    if let Some(colon) = content.find(':') {
        let key = content[..colon].trim().to_string();
        if !key.is_empty() {
            return PocCtx::Enum {
                path,
                key,
                partial: content[colon + 1..].trim().to_string(),
            };
        }
    }
    PocCtx::Key {
        path,
        partial: content.trim().to_string(),
    }
}

/// Follows a `$ref` (`#/$defs/<name>`) to its definition, or returns `node`.
fn resolve<'a>(root: &'a Value, node: &'a Value) -> &'a Value {
    if let Some(name) = node
        .get("$ref")
        .and_then(Value::as_str)
        .and_then(|r| r.strip_prefix("#/$defs/"))
    {
        if let Some(def) = root.get("$defs").and_then(|d| d.get(name)) {
            return def;
        }
    }
    node
}

/// Walks the schema down a path of key segments and `[]` list markers.
fn navigate<'a>(root: &'a Value, path: &[String]) -> Option<&'a Value> {
    let mut node = root;
    for seg in path {
        node = if seg == "[]" {
            resolve(root, node.get("items")?)
        } else {
            resolve(root, node.get("keys")?.get(seg)?)
        };
    }
    Some(node)
}

fn poc_keys(path: &[String], partial: &str) -> Vec<Candidate> {
    let root = poc_schema();
    let Some(node) = navigate(root, path) else {
        return Vec::new();
    };
    let Some(keys) = node.get("keys").and_then(Value::as_object) else {
        return Vec::new();
    };
    keys.iter()
        .filter(|(k, _)| k.starts_with(partial))
        .map(|(k, v)| Candidate {
            label: k.clone(),
            detail: v
                .get("description")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
        })
        .collect()
}

fn poc_enum(path: &[String], key: &str, partial: &str) -> Vec<Candidate> {
    let root = poc_schema();
    let Some(node) = navigate(root, path) else {
        return Vec::new();
    };
    let Some(keynode) = node.get("keys").and_then(|k| k.get(key)) else {
        return Vec::new();
    };
    let keynode = resolve(root, keynode);
    let values: Vec<String> = match keynode.get("type").and_then(Value::as_str) {
        Some("enum") => keynode
            .get("enum")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default(),
        Some("boolean") => vec!["true".to_string(), "false".to_string()],
        _ => Vec::new(),
    };
    values
        .into_iter()
        .filter(|v| v.starts_with(partial))
        .map(|v| Candidate {
            label: v,
            detail: String::new(),
        })
        .collect()
}

/// Clamps `caret` to `src`'s length and back to a char boundary, so the
/// slice `&src[..caret]` is always valid.
fn clamp_boundary(src: &str, caret: usize) -> usize {
    let mut c = caret.min(src.len());
    while c > 0 && !src.is_char_boundary(c) {
        c -= 1;
    }
    c
}

// ---- The `:l4` command line ----------------------------------------------

/// Completion for the palette's `:l4` line (L4 parity spec §7(b): "capture
/// commands … with completion"). `line` is the typed text without the colon;
/// a trailing space means "the next word". The interface names and capture
/// ids are the caller's **live** state (`l4.scope.list` ∪ the L4 flows;
/// `l4.capture.status`), never a built-in list. Each label is the whole
/// completed line, so accepting one runs it as typed.
pub fn l4_command_candidates(
    line: &str,
    interfaces: &[String],
    captures: &[String],
) -> Vec<Candidate> {
    let Some(rest) = line.strip_prefix("l4 ") else {
        return Vec::new();
    };
    let words: Vec<&str> = rest.split_whitespace().collect();
    // The word under the caret is partial unless the line ends in a space.
    let (done, partial): (&[&str], &str) = match words.split_last() {
        Some((last, head)) if !rest.ends_with(' ') => (head, last),
        _ => (&words[..], ""),
    };
    let cand = |label: String, detail: &str| Candidate {
        label,
        detail: detail.to_string(),
    };
    let mut out = Vec::new();
    match done {
        [] => {
            for (sub, detail) in [
                (
                    "capture",
                    "start a capture: :l4 capture <iface> [inbound|outbound]",
                ),
                ("stop", "stop a running capture: :l4 stop [<id>]"),
            ] {
                if sub.starts_with(partial) {
                    out.push(cand(format!("l4 {sub}"), detail));
                }
            }
        }
        ["capture"] => {
            for iface in interfaces {
                if iface.starts_with(partial) {
                    out.push(cand(
                        format!("l4 capture {iface}"),
                        "interface (from the L4 scope and flows)",
                    ));
                }
            }
        }
        ["capture", iface] => {
            for dir in ["inbound", "outbound"] {
                if dir.starts_with(partial) {
                    out.push(cand(format!("l4 capture {iface} {dir}"), "direction"));
                }
            }
        }
        ["stop"] => {
            if partial.is_empty() {
                out.push(cand("l4 stop".to_string(), "stop every running capture"));
            }
            for id in captures {
                if id.starts_with(partial) {
                    out.push(cand(format!("l4 stop {id}"), "running capture"));
                }
            }
        }
        _ => {}
    }
    out
}

// ---- The popup ----------------------------------------------------------

/// The floating completion popup an editor anchors at the caret.
pub struct CompleteState {
    /// The candidates, in catalog order.
    pub items: Vec<Candidate>,
    /// The highlighted row.
    pub selected: usize,
    /// The caret column this popup hangs under.
    pub anchor_col: u16,
    /// The caret row this popup hangs under.
    pub anchor_row: u16,
}

impl CompleteState {
    /// A popup for `items`, anchored under the caret cell.
    pub fn new(items: Vec<Candidate>, anchor_col: u16, anchor_row: u16) -> Self {
        Self {
            items,
            selected: 0,
            anchor_col,
            anchor_row,
        }
    }

    /// Whether there is nothing to show (the editor dismisses it).
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Moves the highlight down, clamped at the last item.
    pub fn down(&mut self) {
        if self.selected + 1 < self.items.len() {
            self.selected += 1;
        }
    }

    /// Moves the highlight up, clamped at the first item.
    pub fn up(&mut self) {
        self.selected = self.selected.saturating_sub(1);
    }

    /// The highlighted candidate, if any.
    pub fn current(&self) -> Option<&Candidate> {
        self.items.get(self.selected)
    }

    /// The most rows the popup ever shows at once.
    const MAX_ROWS: usize = 8;

    /// The screen rectangle the popup occupies, flipping above the caret when
    /// it would fall off the bottom and clamping to the screen width.
    pub fn area(&self, screen: Rect) -> Rect {
        let rows = self.items.len().min(Self::MAX_ROWS) as u16;
        let widest = self
            .items
            .iter()
            .take(Self::MAX_ROWS)
            .map(|c| c.label.len() + c.detail.len() + 3)
            .max()
            .unwrap_or(12)
            .clamp(12, 48) as u16;
        let width = (widest + 2).min(screen.width.max(1));
        let height = rows + 2;
        let x = self
            .anchor_col
            .min(screen.right().saturating_sub(width))
            .max(screen.x);
        let below = self.anchor_row + 1;
        let y = if below + height <= screen.bottom() {
            below
        } else {
            self.anchor_row.saturating_sub(height)
        };
        Rect {
            x,
            y,
            width,
            height,
        }
    }
}

/// Draws the popup into `buf`: a `floating`-style bordered list, the selected
/// row highlighted, each row `label  detail`.
pub fn render(buf: &mut Buffer, screen: Rect, theme: &Theme, state: &CompleteState) {
    use ratatui::widgets::{Block, Borders};

    if state.is_empty() {
        return;
    }
    let area = state.area(screen);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(theme.rule())
        .style(theme.raised());
    let inner = block.inner(area);
    block.render(area, buf);

    let start = state
        .selected
        .saturating_sub(CompleteState::MAX_ROWS.saturating_sub(1));
    for (row, (i, cand)) in state
        .items
        .iter()
        .enumerate()
        .skip(start)
        .take(inner.height as usize)
        .enumerate()
    {
        let y = inner.y + row as u16;
        let selected = i == state.selected;
        let label_style = if selected {
            theme.selection()
        } else {
            theme.text_primary()
        };
        let mut spans = vec![Span::styled(cand.label.clone(), label_style)];
        if !cand.detail.is_empty() {
            spans.push(Span::styled(
                format!("  {}", cand.detail),
                theme.text_tertiary(),
            ));
        }
        let line = Line::from(spans);
        buf.set_line(inner.x, y, &line, inner.width);
    }
}
