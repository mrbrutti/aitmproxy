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

/// The `client_label` the web bridge stamps on every connection it serves. The
/// server mints it (a bridge connection never declares one), so it names the
/// path an entry arrived by, not the client behind it.
pub const WEB_BRIDGE_CLIENT_LABEL: &str = "web-bridge";

/// The longest `client_label` an entry or a host carries, in characters. A
/// client-declared label cannot grow an entry without bound.
pub const MAX_CLIENT_LABEL_CHARS: usize = 64;

/// The longest error reason an audit entry keeps, in bytes, before it is
/// truncated. A verbose or hostile reason cannot grow an entry without bound.
pub const DEFAULT_RESULT_REASON_CAP: usize = 1024;

/// Labels only the server may mint; a client that declares one is rewritten by
/// [`declared_client_label`].
const RESERVED_CLIENT_LABELS: &[&str] = &[WEB_BRIDGE_CLIENT_LABEL];

/// How many characters of a raw label [`sanitize_client_label`] ever reads, so
/// its work is bounded whatever the input size.
const LABEL_SCAN_CHARS: usize = 1024;

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

/// Whether a character is dropped from a client label: a control character, or
/// an invisible or bidirectional-override character that could make one label
/// pose as another in a UI.
fn is_label_noise(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{200B}'..='\u{200F}' | '\u{2028}'..='\u{202E}' | '\u{2060}'..='\u{2069}' | '\u{FEFF}'
        )
}

/// The one sanitiser for a client label, whatever its source.
///
/// It reads only the first [`LABEL_SCAN_CHARS`] characters of `raw`, so its work
/// is bounded however large the input. It drops control, invisible, and
/// bidirectional-override characters, masks credential material with
/// [`crate::redact::scrub_text`], trims, and truncates to
/// [`MAX_CLIENT_LABEL_CHARS`] characters. It returns `None` when nothing is left.
/// Applying it to its own output changes nothing, and it does not rewrite a
/// server-minted name such as [`WEB_BRIDGE_CLIENT_LABEL`]; use
/// [`declared_client_label`] where a client supplies the label.
pub fn sanitize_client_label(raw: &str) -> Option<String> {
    let cleaned: String = raw
        .chars()
        .take(LABEL_SCAN_CHARS)
        .filter(|c| !is_label_noise(*c))
        .collect();
    let scrubbed = crate::redact::scrub_text(&cleaned);
    let bounded: String = scrubbed
        .trim()
        .chars()
        .take(MAX_CLIENT_LABEL_CHARS)
        .collect();
    let label = bounded.trim();
    if label.is_empty() {
        None
    } else {
        Some(label.to_string())
    }
}

/// Sanitise a label a client declared (see [`sanitize_client_label`]) and keep it
/// from posing as a server-minted one: a label equal, ignoring ASCII case and
/// surrounding blanks, to a reserved name gets a ` (declared)` suffix. Apply it
/// only where a client declares its label, never to a label the server mints.
pub fn declared_client_label(raw: &str) -> Option<String> {
    let label = sanitize_client_label(raw)?;
    let reserved = RESERVED_CLIENT_LABELS
        .iter()
        .any(|name| label.trim().eq_ignore_ascii_case(name));
    if reserved {
        Some(format!("{label} (declared)"))
    } else {
        Some(label)
    }
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
    pub fn recent(&self, since: Option<SystemTime>, limit: Option<usize>) -> Vec<AuditEntry> {
        let q = self.lock();
        let mut out: Vec<AuditEntry> = q
            .iter()
            .filter(|e| since.is_none_or(|s| e.at > s))
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
    pub fn count_since(&self, since: SystemTime) -> usize {
        self.lock().iter().filter(|e| e.at >= since).count()
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
            command: command.to_string(),
            args_summary: "{}".to_string(),
            result,
        }
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

    #[test]
    fn sanitize_client_label_bounds_a_hostile_label() {
        assert_eq!(
            sanitize_client_label(&"A".repeat(10 << 20)),
            Some("A".repeat(64))
        );
        assert_eq!(sanitize_client_label(&"\u{0}".repeat(10 << 20)), None);
        assert_eq!(
            sanitize_client_label("a\u{0}b\nc\u{202E}d"),
            Some("abcd".to_string())
        );
        let scrubbed = sanitize_client_label("token=abc123").expect("a label remains");
        assert!(!scrubbed.contains("abc123"), "secret leaked: {scrubbed}");
        assert!(scrubbed.contains("[redacted]"), "not masked: {scrubbed}");
        assert_eq!(sanitize_client_label(""), None);
        assert_eq!(sanitize_client_label("   "), None);
        assert_eq!(
            sanitize_client_label("aitm-mac"),
            Some("aitm-mac".to_string())
        );
        assert_eq!(
            sanitize_client_label("web-bridge"),
            Some("web-bridge".to_string())
        );

        // Idempotent: sanitising a sanitised label changes nothing.
        let long = "A".repeat(10 << 20);
        let nuls = "\u{0}".repeat(10 << 20);
        // The 64-char cut lands inside the masked value, and inside the key.
        let cut_in_mask = format!("{}token=abc123", "x".repeat(56));
        let cut_in_key = format!("{}token=abc123", "x".repeat(60));
        for raw in [
            long.as_str(),
            nuls.as_str(),
            cut_in_mask.as_str(),
            cut_in_key.as_str(),
            "a\u{0}b\nc\u{202E}d",
            "token=abc123",
            "",
            "   ",
            "aitm-mac",
            "web-bridge",
        ] {
            let once = sanitize_client_label(raw);
            let bounded_and_clean = once
                .as_deref()
                .is_none_or(|l| l.chars().count() <= 64 && !l.contains("abc123"));
            assert!(bounded_and_clean, "unbounded or leaking: {once:?}");
            let twice = once.as_deref().and_then(sanitize_client_label);
            assert_eq!(twice, once, "not idempotent for a {}-byte input", raw.len());
        }
    }

    #[test]
    fn declared_client_label_rewrites_a_reserved_name() {
        assert_eq!(
            declared_client_label("web-bridge"),
            Some("web-bridge (declared)".to_string())
        );
        assert_eq!(
            declared_client_label("  WEB-BRIDGE "),
            Some("WEB-BRIDGE (declared)".to_string())
        );
        assert_eq!(
            declared_client_label("aitm-mac"),
            Some("aitm-mac".to_string())
        );
    }
}
