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
}
