//! The F2 command-invocation audit ring (spec D3a).
//!
//! Every command `invoke` the MCP server (and, in time, the CLI) runs — including
//! one a policy or confirm gate refused — is recorded as one [`AuditEntry`]:
//! who ran what, with what (redacted) arguments, and whether it ran or was
//! refused. The entries land in a bounded in-memory [`AuditRing`] that is always
//! on (the *live* view the operator "Agent" page and `agent.activity` read) and,
//! when a durable path is configured, in a JSONL [`AuditSink`] as well — the same
//! one format the CA plugin's log is a subset of (spec D3a.2).
//!
//! `args_summary` is a redacted, size-capped rendering produced by the caller:
//! tokens, auth headers, and the CA key material never reach an entry, matching
//! the M2 CA posture (the bounded-memory + secret-handling constraints).

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::ctx::Frontend;
use crate::value::Value;

/// The default audit-ring capacity (entries) before the oldest is evicted. A few
/// thousand entries is enough for the live "Agent" view; durable audit keeps the
/// full history when it is configured.
pub const DEFAULT_AUDIT_CAPACITY: usize = 4096;

/// How long `args_summary` may be before it is truncated (bytes of its JSON
/// rendering). A hostile or verbose argument set cannot grow an entry without
/// bound.
pub const DEFAULT_ARGS_SUMMARY_CAP: usize = 512;

/// The most bytes a connection's client label may keep (see [`cap_client_label`]).
/// The label is copied into every audit entry the connection makes, so an
/// unbounded one multiplies by the ring capacity.
pub const MAX_CLIENT_LABEL_BYTES: usize = 128;

/// How much of a client name [`cap_client_label`] hands to the secret scrubber:
/// at least four times the cap, so a secret that starts inside the kept 128 bytes
/// always starts inside the window, and the scrub work does not grow with the name.
const CLIENT_LABEL_SCRUB_WINDOW_BYTES: usize = 512;

/// The outcome of one recorded invocation: it ran (`Ok`) or it was refused /
/// failed, carrying the human reason (`Error`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditResult {
    /// The command ran to a successful result.
    Ok,
    /// The command was refused (a policy/confirm gate, a bad argument) or its
    /// `invoke` failed; the string is the reason already shown to the caller.
    Error(String),
}

/// One command-invocation audit record.
#[derive(Debug, Clone)]
pub struct AuditEntry {
    /// When the invocation was recorded (after the policy/confirm gates).
    pub at: SystemTime,
    /// The frontend role that invoked it (F1 identity).
    pub origin: Frontend,
    /// The connection's human-readable client label, when it declared one.
    pub client_label: Option<String>,
    /// The server-assigned, opaque id of the streaming connection that made the
    /// call. `None` means the call is not attributable to a streaming connection
    /// (an in-process caller, a request/response transport). Never derived from
    /// anything the client sent.
    pub connection_id: Option<String>,
    /// The dotted command name, e.g. `"flow.replay"`.
    pub command: String,
    /// A redacted, size-capped rendering of the arguments — never secrets.
    pub args_summary: String,
    /// Whether it ran or was refused/failed, with the reason when refused.
    pub result: AuditResult,
}

impl AuditEntry {
    /// `at` as Unix-epoch milliseconds — the single, dependency-free timestamp
    /// representation the ring, the agent stream, and the durable JSONL all share.
    pub fn at_millis(&self) -> i64 {
        self.at
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0)
    }

    /// Whether `viewer` may see this entry. Trusted control (the operator, the CLI)
    /// sees every entry; any other viewer sees only entries made by callers that
    /// are not trusted control, so an agent never reads what the operator did.
    /// Both sides ask [`Frontend::is_trusted_control`], the one definition of
    /// "trusted" in the workspace, never a comparison against a role.
    pub fn visible_to(&self, viewer: Frontend) -> bool {
        viewer.is_trusted_control() || !self.origin.is_trusted_control()
    }

    /// The transport-neutral rendering of the entry, used identically by
    /// `agent.activity` (its `[AuditEntry]` result), the `notifications/aitm/agent`
    /// line, and the durable JSONL — so every surface shows one shape.
    pub fn to_value(&self) -> Value {
        let mut m = std::collections::BTreeMap::new();
        m.insert("at".to_string(), Value::Int(self.at_millis()));
        m.insert(
            "origin".to_string(),
            Value::Str(origin_label(self.origin).to_string()),
        );
        m.insert(
            "client_label".to_string(),
            match &self.client_label {
                Some(label) => Value::Str(label.clone()),
                None => Value::Null,
            },
        );
        m.insert(
            "connection_id".to_string(),
            match &self.connection_id {
                Some(id) => Value::Str(id.clone()),
                None => Value::Null,
            },
        );
        m.insert("command".to_string(), Value::Str(self.command.clone()));
        m.insert("args".to_string(), Value::Str(self.args_summary.clone()));
        m.insert(
            "result".to_string(),
            match &self.result {
                AuditResult::Ok => Value::Str("ok".to_string()),
                AuditResult::Error(reason) => {
                    let mut e = std::collections::BTreeMap::new();
                    e.insert("error".to_string(), Value::Str(reason.clone()));
                    Value::Object(e)
                }
            },
        );
        Value::Object(m)
    }
}

/// The lower-case wire label for a frontend role, as it appears in an entry's
/// `origin`. Exhaustive over [`Frontend`]'s variants so a new role must be named
/// here deliberately.
#[deny(
    clippy::wildcard_enum_match_arm,
    clippy::match_wildcard_for_single_variants
)]
pub fn origin_label(frontend: Frontend) -> &'static str {
    match frontend {
        Frontend::Cli => "cli",
        Frontend::Mcp => "mcp",
        Frontend::Operator => "operator",
    }
}

/// The longest prefix of `s` that is at most `max` bytes and ends on a char
/// boundary, so the cut never splits a multi-byte character.
fn prefix_at_char_boundary(s: &str, max: usize) -> &str {
    let mut end = max.min(s.len());
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// The one place a client-declared name becomes a connection's client label.
///
/// A name arrives from the peer (`clientInfo.name`, up to a whole message long),
/// is copied into every audit entry the connection makes, and is rendered in
/// operator tables and written to logs. This bounds it and makes it safe to show.
/// Truncates, never refuses: a client with a long name keeps working. In order:
///
/// 1. `None` if `name` is empty.
/// 2. Every control character becomes `?`, so an escape sequence cannot drive a
///    terminal that prints the label.
/// 3. The text is cut to a 512-byte window at a char boundary, which bounds the
///    work of the next step however long the name is.
/// 4. [`crate::redact::scrub_text`] masks credential material (`token=abc` becomes
///    `token=[redacted]`) so a secret in a name never reaches the ring, the push
///    or the durable log.
/// 5. The scrubbed text is cut at the last char boundary at or below
///    [`MAX_CLIENT_LABEL_BYTES`] bytes, with no ellipsis.
///
/// The final cut is after the scrub on purpose: masking lengthens text
/// (`token=a,` is 8 bytes, `token=[redacted],` is 17), so cutting first could
/// leave a result over the cap.
pub fn cap_client_label(name: &str) -> Option<String> {
    if name.is_empty() {
        return None;
    }
    // Steps 2 and 3 in one pass that stops at the window, so a name of any
    // length costs at most one window of work and memory: the result is the
    // control-replaced text cut at the last char boundary at or below the window.
    let mut window = String::with_capacity(CLIENT_LABEL_SCRUB_WINDOW_BYTES);
    for c in name.chars() {
        let c = if c.is_control() { '?' } else { c };
        if window.len() + c.len_utf8() > CLIENT_LABEL_SCRUB_WINDOW_BYTES {
            break;
        }
        window.push(c);
    }
    let scrubbed = crate::redact::scrub_text(&window);
    Some(prefix_at_char_boundary(&scrubbed, MAX_CLIENT_LABEL_BYTES).to_string())
}

/// Where audit entries go. The in-memory [`AuditRing`] implements it (always on);
/// a durable JSONL log (opt-in by config) implements it too, so one `append`
/// fans to both without the caller knowing which sinks are attached.
pub trait AuditSink: Send + Sync {
    /// Record one entry. Infallible by contract: a durable sink that cannot write
    /// logs and drops the line rather than breaking the command that produced it.
    fn append(&self, entry: AuditEntry);
}

/// A bounded, in-memory ring of recent audit entries — the always-on live view.
/// Oldest entries are evicted once `capacity` is reached, so a long session has
/// bounded memory (the bounded-memory constraint).
#[derive(Debug)]
pub struct AuditRing {
    inner: Mutex<VecDeque<AuditEntry>>,
    capacity: usize,
}

impl AuditRing {
    /// A ring holding at most `capacity` entries (clamped to at least 1).
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: Mutex::new(VecDeque::new()),
            capacity: capacity.max(1),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, VecDeque<AuditEntry>> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Recent entries, oldest first. `since` keeps only entries strictly after it;
    /// `limit` keeps the most recent `limit` of those (presented oldest first), so
    /// a reconnecting surface catches up without replaying the whole ring.
    ///
    /// This is the **unfiltered** view: it returns every entry whatever its
    /// origin. No surface a role reads may use it (use [`AuditRing::recent_for`]);
    /// the in-process tests and the durable sink keep it.
    pub fn recent(&self, since: Option<SystemTime>, limit: Option<usize>) -> Vec<AuditEntry> {
        self.recent_where(since, limit, |_| true)
    }

    /// [`AuditRing::recent`] as `viewer` may see it: an entry is kept only when
    /// [`AuditEntry::visible_to`] says so. The visibility filter runs **before**
    /// `limit`, so `limit` counts the entries the viewer can see, never the
    /// hidden ones (a limit of 1 for an agent never returns the operator's
    /// entry, and never returns nothing because the newest entry was hidden).
    pub fn recent_for(
        &self,
        viewer: Frontend,
        since: Option<SystemTime>,
        limit: Option<usize>,
    ) -> Vec<AuditEntry> {
        self.recent_where(since, limit, |e| e.visible_to(viewer))
    }

    /// The shared body of [`AuditRing::recent`] and [`AuditRing::recent_for`]:
    /// `since` (strictly after), then `keep`, then `limit`, oldest first.
    fn recent_where(
        &self,
        since: Option<SystemTime>,
        limit: Option<usize>,
        keep: impl Fn(&AuditEntry) -> bool,
    ) -> Vec<AuditEntry> {
        let q = self.lock();
        let mut out: Vec<AuditEntry> = q
            .iter()
            .filter(|e| since.is_none_or(|s| e.at > s))
            .filter(|e| keep(e))
            .cloned()
            .collect();
        if let Some(limit) = limit {
            if out.len() > limit {
                out = out.split_off(out.len() - limit);
            }
        }
        out
    }

    /// How many entries were recorded at or after `since` — the source of
    /// `agent.status.actions_last_minute`.
    ///
    /// This is the **unfiltered** count: it includes every entry whatever its
    /// origin. No surface a role reads may use it (use
    /// [`AuditRing::count_since_for`]); the in-process tests keep it.
    pub fn count_since(&self, since: SystemTime) -> usize {
        self.lock().iter().filter(|e| e.at >= since).count()
    }

    /// [`AuditRing::count_since`] as `viewer` may see it: only entries recorded at
    /// or after `since` that are [`AuditEntry::visible_to`] the viewer, and, when
    /// `exclude_connection` is `Some(id)`, not made by the connection `id`. An
    /// entry with no `connection_id` is never excluded: an id the server did not
    /// assign cannot match one it did.
    pub fn count_since_for(
        &self,
        viewer: Frontend,
        since: SystemTime,
        exclude_connection: Option<&str>,
    ) -> usize {
        self.lock()
            .iter()
            .filter(|e| e.at >= since)
            .filter(|e| e.visible_to(viewer))
            .filter(|e| {
                !exclude_connection.is_some_and(|id| e.connection_id.as_deref() == Some(id))
            })
            .count()
    }

    /// The number of entries currently held.
    pub fn len(&self) -> usize {
        self.lock().len()
    }

    /// Whether the ring holds no entries.
    pub fn is_empty(&self) -> bool {
        self.lock().is_empty()
    }
}

impl Default for AuditRing {
    fn default() -> Self {
        Self::new(DEFAULT_AUDIT_CAPACITY)
    }
}

impl AuditSink for AuditRing {
    fn append(&self, entry: AuditEntry) {
        let mut q = self.lock();
        if q.len() >= self.capacity {
            q.pop_front();
        }
        q.push_back(entry);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(command: &str, result: AuditResult) -> AuditEntry {
        AuditEntry {
            at: SystemTime::now(),
            origin: Frontend::Mcp,
            client_label: None,
            connection_id: None,
            command: command.to_string(),
            args_summary: "{}".to_string(),
            result,
        }
    }

    fn entry_of(origin: Frontend, connection_id: Option<&str>, command: &str) -> AuditEntry {
        AuditEntry {
            origin,
            connection_id: connection_id.map(str::to_string),
            ..entry(command, AuditResult::Ok)
        }
    }

    #[test]
    fn visible_to_matrix() {
        let origins = [Frontend::Cli, Frontend::Operator, Frontend::Mcp];
        let entries = origins.map(|o| entry_of(o, None, "x"));

        let seen_by = |viewer: Frontend| entries.clone().map(|e| e.visible_to(viewer));
        assert_eq!(seen_by(Frontend::Cli), [true, true, true]);
        assert_eq!(seen_by(Frontend::Operator), [true, true, true]);
        assert_eq!(seen_by(Frontend::Mcp), [false, false, true]);
    }

    #[test]
    fn recent_for_applies_the_limit_after_the_filter() {
        let ring = AuditRing::new(8);
        ring.append(entry_of(Frontend::Operator, None, "op1"));
        ring.append(entry_of(Frontend::Mcp, None, "ag1"));
        ring.append(entry_of(Frontend::Operator, None, "op2"));
        ring.append(entry_of(Frontend::Mcp, None, "ag2"));
        ring.append(entry_of(Frontend::Operator, None, "op3"));

        let commands = |entries: Vec<AuditEntry>| -> Vec<String> {
            entries.into_iter().map(|e| e.command).collect()
        };
        assert_eq!(
            commands(ring.recent_for(Frontend::Mcp, None, Some(2))),
            ["ag1", "ag2"]
        );
        assert_eq!(
            commands(ring.recent_for(Frontend::Operator, None, Some(2))),
            ["ag2", "op3"]
        );
        assert_eq!(
            commands(ring.recent_for(Frontend::Mcp, None, None)),
            ["ag1", "ag2"]
        );
    }

    #[test]
    fn count_since_for_filters_and_excludes() {
        let t0 = SystemTime::now();
        let ring = AuditRing::new(32);
        for _ in 0..3 {
            ring.append(entry_of(Frontend::Mcp, Some("A"), "x"));
        }
        for _ in 0..2 {
            ring.append(entry_of(Frontend::Mcp, Some("B"), "x"));
        }
        for _ in 0..4 {
            ring.append(entry_of(Frontend::Operator, Some("O"), "x"));
        }
        ring.append(entry_of(Frontend::Mcp, None, "x"));

        assert_eq!(ring.count_since_for(Frontend::Mcp, t0, None), 6);
        assert_eq!(ring.count_since_for(Frontend::Mcp, t0, Some("A")), 3);
        assert_eq!(ring.count_since_for(Frontend::Mcp, t0, Some("nope")), 6);
        assert_eq!(ring.count_since_for(Frontend::Operator, t0, None), 10);
        assert_eq!(ring.count_since_for(Frontend::Operator, t0, Some("O")), 6);
    }

    #[test]
    fn ring_is_bounded_and_evicts_oldest() {
        let ring = AuditRing::new(2);
        ring.append(entry("a", AuditResult::Ok));
        ring.append(entry("b", AuditResult::Ok));
        ring.append(entry("c", AuditResult::Ok));
        let recent = ring.recent(None, None);
        assert_eq!(recent.len(), 2);
        assert_eq!(recent[0].command, "b");
        assert_eq!(recent[1].command, "c");
    }

    #[test]
    fn recent_honours_limit() {
        let ring = AuditRing::new(8);
        for name in ["a", "b", "c"] {
            ring.append(entry(name, AuditResult::Ok));
        }
        let last_two = ring.recent(None, Some(2));
        assert_eq!(last_two.len(), 2);
        assert_eq!(last_two[1].command, "c");
    }

    #[test]
    fn to_value_carries_connection_id() {
        let with_id = AuditEntry {
            connection_id: Some("conn_ab-1".to_string()),
            ..entry("x", AuditResult::Ok)
        };
        let Value::Object(m) = with_id.to_value() else {
            panic!("expected object")
        };
        assert_eq!(
            m.get("connection_id"),
            Some(&Value::Str("conn_ab-1".to_string()))
        );
        assert_eq!(
            m.keys().map(String::as_str).collect::<Vec<_>>(),
            [
                "args",
                "at",
                "client_label",
                "command",
                "connection_id",
                "origin",
                "result"
            ]
        );

        let without_id = AuditEntry {
            connection_id: None,
            ..entry("x", AuditResult::Ok)
        };
        let Value::Object(m) = without_id.to_value() else {
            panic!("expected object")
        };
        assert_eq!(m.get("connection_id"), Some(&Value::Null));
        assert_eq!(m.len(), 7);
    }

    #[test]
    fn cap_client_label_cuts_ascii_at_128() {
        let label = cap_client_label(&"x".repeat(300)).expect("non-empty name");
        assert_eq!(label.len(), 128);
        assert_eq!(label, "x".repeat(128));
    }

    #[test]
    fn cap_client_label_cuts_on_a_char_boundary() {
        // 2-byte chars: 128 is a boundary, so 64 whole chars fit.
        let two = cap_client_label(&"é".repeat(100)).expect("non-empty name");
        assert_eq!(two.len(), 128);
        assert_eq!(two.chars().count(), 64);

        // 3-byte chars: 128 falls inside the 43rd char, so the cut backs up to 126.
        let three = cap_client_label(&"€".repeat(50)).expect("non-empty name");
        assert_eq!(three.len(), 126);
        assert_eq!(three.chars().count(), 42);
    }

    #[test]
    fn cap_client_label_survives_the_window_boundary() {
        // 900 bytes of 3-byte chars: the 512-byte window falls inside the 171st
        // char, so it backs up to 510; the final cut then gives 126.
        let label = cap_client_label(&"€".repeat(300)).expect("non-empty name");
        assert_eq!(label.len(), 126);
        assert_eq!(label.chars().count(), 42);
    }

    #[test]
    fn cap_client_label_leaves_a_short_name() {
        assert_eq!(cap_client_label("aitm-mac"), Some("aitm-mac".to_string()));
    }

    #[test]
    fn cap_client_label_replaces_control_chars() {
        assert_eq!(
            cap_client_label("a\u{1b}[31mred"),
            Some("a?[31mred".to_string())
        );
    }

    #[test]
    fn cap_client_label_scrubs_secrets() {
        let label = cap_client_label("agent token=abc123").expect("non-empty name");
        assert!(label.contains("token=[redacted]"), "{label}");
        assert!(!label.contains("abc123"), "{label}");
    }

    #[test]
    fn cap_client_label_cuts_after_the_scrub() {
        // 320 bytes in; masking turns each `token=a,` (8 bytes) into
        // `token=[redacted],` (17 bytes), about 680 bytes. Cutting before the
        // scrub would leave 272 bytes, so only a cut after it is within 128.
        let label = cap_client_label(&"token=a,".repeat(40)).expect("non-empty name");
        assert!(label.len() <= 128, "{} bytes: {label}", label.len());
        assert_eq!(label, format!("{}token=[re", "token=[redacted],".repeat(7)));
    }

    #[test]
    fn cap_client_label_empty_is_none() {
        assert_eq!(cap_client_label(""), None);
    }

    #[test]
    fn error_renders_with_reason() {
        let v = entry("x", AuditResult::Error("nope".into())).to_value();
        let Value::Object(m) = v else {
            panic!("expected object")
        };
        assert_eq!(
            m.get("result"),
            Some(&Value::Object(
                [("error".to_string(), Value::Str("nope".into()))]
                    .into_iter()
                    .collect()
            ))
        );
    }
}
