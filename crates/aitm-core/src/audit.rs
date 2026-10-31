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
//!
//! # The ring keeps a fair, bounded record
//!
//! The ring is split into two bounded lanes (see [`AuditLane`]). The *evidence*
//! lane holds every entry that is not a successful `Read`: refusals, failures,
//! and every `Write` or `Sensitive` run. The *routine* lane holds only successful
//! `Read` calls, so a polling UI can never push evidence out. [`lane_for`] is the
//! one routing rule.
//!
//! Inside each lane a full ring evicts the oldest entry of the *source* holding
//! the most entries, where a source is an origin plus a client label. A lone busy
//! source still uses the whole lane, but a flood only ever eats the flooder's
//! own oldest entries. Each lane tracks at most [`MAX_AUDIT_SOURCES`] sources and
//! files the rest under one overflow source per origin, so a flooder minting a
//! fresh label per connection cannot shrink an honest source below a fixed floor
//! of about `capacity / (MAX_AUDIT_SOURCES + 3)` entries.
//!
//! A source can still overwrite its own history, and a restart empties the ring.
//! Only the durable JSONL sink keeps a complete record; the ring is a live view.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::command::Sensitivity;
use crate::ctx::Frontend;
use crate::value::Value;

/// The default capacity (entries) of the evidence lane before it evicts. A few
/// thousand entries is enough for the live "Agent" view; durable audit keeps the
/// full history when it is configured.
pub const DEFAULT_AUDIT_CAPACITY: usize = 4096;

/// The default capacity (entries) of the routine lane, half the evidence lane:
/// about thirteen minutes of one polling UI by itself.
pub const DEFAULT_ROUTINE_AUDIT_CAPACITY: usize = DEFAULT_AUDIT_CAPACITY / 2;

/// How many distinct sources (an origin plus a client label) each lane tracks by
/// name. A source beyond this shares its origin's overflow source, which bounds
/// the work of an append and sets a floor under what any source keeps.
pub const MAX_AUDIT_SOURCES: usize = 32;
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

/// Which lane of the [`AuditRing`] an entry is kept in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditLane {
    /// Everything that is not a successful `Read`: refusals, failures, and every
    /// `Write` or `Sensitive` run. Polling never touches this lane.
    Evidence,
    /// Successful `Read` calls only: UI polling and status checks.
    Routine,
}

/// The one routing rule: a successful `Read` is [`AuditLane::Routine`]; anything
/// else is [`AuditLane::Evidence`]. An unknown sensitivity (`None`) and any
/// outcome other than success fail closed into the evidence lane.
pub fn lane_for(sensitivity: Option<Sensitivity>, result: &AuditResult) -> AuditLane {
    match (sensitivity, result) {
        (Some(Sensitivity::Read), AuditResult::Ok) => AuditLane::Routine,
        _ => AuditLane::Evidence,
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

/// The identity of one bucket in a lane's source table.
#[derive(Debug, PartialEq, Eq)]
enum SourceKey {
    /// A source tracked under its own name: its origin label and client label.
    Tracked(&'static str, Option<String>),
    /// The shared bucket for every untracked source of one origin.
    Overflow(&'static str),
}

/// One source's entries in a lane, oldest first, each with its sequence number.
#[derive(Debug)]
struct Bucket {
    key: SourceKey,
    entries: VecDeque<(u64, AuditEntry)>,
}

impl Bucket {
    /// The sequence number of the oldest entry, or the maximum when empty.
    fn oldest_seq(&self) -> u64 {
        self.entries.front().map_or(u64::MAX, |(seq, _)| *seq)
    }
}

/// One bounded lane: a table of per-source buckets sharing one capacity.
#[derive(Debug)]
struct Lane {
    capacity: usize,
    buckets: Vec<Bucket>,
}

impl Lane {
    fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            buckets: Vec::new(),
        }
    }

    fn len(&self) -> usize {
        self.buckets.iter().map(|b| b.entries.len()).sum()
    }

    /// Every held entry with its sequence number, in no particular order.
    fn entries(&self) -> impl Iterator<Item = &(u64, AuditEntry)> {
        self.buckets.iter().flat_map(|b| b.entries.iter())
    }

    fn find(&self, key: &SourceKey) -> Option<usize> {
        self.buckets.iter().position(|b| b.key == *key)
    }

    /// File `entry` under its source (or its origin's overflow source when the
    /// table is full), then evict while the lane is over capacity.
    fn insert(&mut self, seq: u64, entry: AuditEntry) {
        let origin = origin_label(entry.origin);
        let tracked = SourceKey::Tracked(origin, entry.client_label.clone());
        let tracked_sources = self
            .buckets
            .iter()
            .filter(|b| matches!(b.key, SourceKey::Tracked(..)))
            .count();
        let key = if self.find(&tracked).is_some() || tracked_sources < MAX_AUDIT_SOURCES {
            tracked
        } else {
            SourceKey::Overflow(origin)
        };
        let at = match self.find(&key) {
            Some(at) => at,
            None => {
                self.buckets.push(Bucket {
                    key,
                    entries: VecDeque::new(),
                });
                self.buckets.len() - 1
            }
        };
        self.buckets[at].entries.push_back((seq, entry));
        if self.len() > self.capacity {
            self.evict_one();
        }
    }

    /// Drop the oldest entry of the bucket holding the most entries; between
    /// equally full buckets, the one whose oldest entry is the oldest overall. A
    /// bucket left empty leaves the table. The entry just inserted is never the
    /// victim: it is the newest, so it is the oldest of its bucket only when that
    /// bucket is the lone bucket, and then the lane is not over capacity.
    fn evict_one(&mut self) {
        let victim = self
            .buckets
            .iter()
            .enumerate()
            .max_by(|(_, a), (_, b)| {
                a.entries
                    .len()
                    .cmp(&b.entries.len())
                    .then(b.oldest_seq().cmp(&a.oldest_seq()))
            })
            .map(|(at, _)| at);
        let Some(at) = victim else { return };
        self.buckets[at].entries.pop_front();
        if self.buckets[at].entries.is_empty() {
            self.buckets.remove(at);
        }
    }
}

/// Everything the ring's one mutex guards.
#[derive(Debug)]
struct RingState {
    /// The sequence number the next entry gets; it orders entries across lanes.
    next_seq: u64,
    evidence: Lane,
    routine: Lane,
}

impl RingState {
    fn lane_mut(&mut self, lane: AuditLane) -> &mut Lane {
        match lane {
            AuditLane::Evidence => &mut self.evidence,
            AuditLane::Routine => &mut self.routine,
        }
    }
}

/// A bounded, in-memory record of recent audit entries — the always-on live view.
///
/// It has two bounded lanes, an evidence lane and a routine lane (see
/// [`AuditLane`]), so successful `Read` polling never evicts a refusal or a
/// state-changing call. When a lane is full it evicts the oldest entry of the
/// source holding the most entries, so one source cannot flush another's entries
/// however many calls it makes; each lane tracks at most [`MAX_AUDIT_SOURCES`]
/// sources and files the rest under a per-origin overflow source. Nothing is
/// evicted while a lane has room, and the newest entry is always kept.
///
/// Memory is bounded in entries and, because every entry field is capped by its
/// producer, in bytes. The ring is a live view, not a complete record: a source
/// can still overwrite its own history and a restart empties it. The durable
/// JSONL [`AuditSink`] is the complete answer.
#[derive(Debug)]
pub struct AuditRing {
    inner: Mutex<RingState>,
}

impl AuditRing {
    /// A ring whose evidence lane holds at most `capacity` entries and whose
    /// routine lane holds at most half that (each clamped to at least 1).
    pub fn new(capacity: usize) -> Self {
        Self::with_lane_capacities(capacity, (capacity / 2).max(1))
    }

    /// A ring with an explicit capacity for each lane (each clamped to at least 1).
    pub fn with_lane_capacities(evidence: usize, routine: usize) -> Self {
        Self {
            inner: Mutex::new(RingState {
                next_seq: 0,
                evidence: Lane::new(evidence),
                routine: Lane::new(routine),
            }),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, RingState> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Record `entry` in `lane`. [`AuditSink::append`] is this with the evidence
    /// lane; use [`lane_for`] to choose the lane for a command's outcome.
    pub fn append_in(&self, lane: AuditLane, entry: AuditEntry) {
        let mut state = self.lock();
        let seq = state.next_seq;
        state.next_seq = seq.saturating_add(1);
        state.lane_mut(lane).insert(seq, entry);
    }

    /// Recent entries of both lanes in call order, oldest first. `since` keeps
    /// only entries strictly after it; `limit` keeps the most recent `limit` of
    /// those (presented oldest first), so a reconnecting surface catches up
    /// without replaying the whole ring.
    pub fn recent(&self, since: Option<SystemTime>, limit: Option<usize>) -> Vec<AuditEntry> {
        let state = self.lock();
        let mut held: Vec<&(u64, AuditEntry)> = state
            .evidence
            .entries()
            .chain(state.routine.entries())
            .filter(|(_, e)| since.is_none_or(|s| e.at > s))
            .collect();
        held.sort_unstable_by_key(|(seq, _)| *seq);
        let skip = limit.map_or(0, |limit| held.len().saturating_sub(limit));
        held.into_iter()
            .skip(skip)
            .map(|(_, e)| e.clone())
            .collect()
    }

    /// How many entries, across both lanes, were recorded at or after `since` —
    /// the source of `agent.status.actions_last_minute`.
    pub fn count_since(&self, since: SystemTime) -> usize {
        let state = self.lock();
        state
            .evidence
            .entries()
            .chain(state.routine.entries())
            .filter(|(_, e)| e.at >= since)
            .count()
    }

    /// The number of entries currently held, across both lanes.
    pub fn len(&self) -> usize {
        let state = self.lock();
        state.evidence.len() + state.routine.len()
    }

    /// Whether the ring holds no entries.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The number of entries currently held in the evidence lane.
    pub fn evidence_len(&self) -> usize {
        self.lock().evidence.len()
    }

    /// The number of entries currently held in the routine lane.
    pub fn routine_len(&self) -> usize {
        self.lock().routine.len()
    }
}

impl Default for AuditRing {
    fn default() -> Self {
        Self::new(DEFAULT_AUDIT_CAPACITY)
    }
}

impl AuditSink for AuditRing {
    /// Records into the evidence lane: a caller that does not know the command's
    /// sensitivity gets the lane that fails closed.
    fn append(&self, entry: AuditEntry) {
        self.append_in(AuditLane::Evidence, entry);
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

    /// An entry from a chosen source (origin and label) running `command`.
    fn sourced(origin: Frontend, label: Option<&str>, command: &str) -> AuditEntry {
        AuditEntry {
            at: SystemTime::now(),
            origin,
            client_label: label.map(str::to_string),
            command: command.to_string(),
            args_summary: "{}".to_string(),
            result: AuditResult::Ok,
        }
    }

    /// The commands of `entries`, in the order given.
    fn commands(entries: &[AuditEntry]) -> Vec<&str> {
        entries.iter().map(|e| e.command.as_str()).collect()
    }

    #[test]
    fn lane_for_routes_only_successful_reads_to_routine() {
        assert_eq!(
            lane_for(Some(Sensitivity::Read), &AuditResult::Ok),
            AuditLane::Routine
        );
        assert_eq!(
            lane_for(Some(Sensitivity::Read), &AuditResult::Error("x".into())),
            AuditLane::Evidence
        );
        assert_eq!(
            lane_for(Some(Sensitivity::Write), &AuditResult::Ok),
            AuditLane::Evidence
        );
        assert_eq!(
            lane_for(Some(Sensitivity::Sensitive), &AuditResult::Ok),
            AuditLane::Evidence
        );
        assert_eq!(lane_for(None, &AuditResult::Ok), AuditLane::Evidence);
    }

    #[test]
    fn recent_merges_both_lanes_oldest_first() {
        let ring = AuditRing::with_lane_capacities(8, 8);
        ring.append_in(AuditLane::Evidence, entry("E1", AuditResult::Ok));
        ring.append_in(AuditLane::Routine, entry("R1", AuditResult::Ok));
        ring.append_in(AuditLane::Evidence, entry("E2", AuditResult::Ok));
        ring.append_in(AuditLane::Routine, entry("R2", AuditResult::Ok));
        assert_eq!(commands(&ring.recent(None, None)), ["E1", "R1", "E2", "R2"]);
        assert_eq!(commands(&ring.recent(None, Some(3))), ["R1", "E2", "R2"]);
        assert_eq!(ring.len(), 4);
        assert_eq!(ring.evidence_len(), 2);
        assert_eq!(ring.routine_len(), 2);
        assert_eq!(ring.count_since(UNIX_EPOCH), 4);
    }

    #[test]
    fn a_routine_flood_never_evicts_evidence() {
        let ring = AuditRing::with_lane_capacities(4, 2);
        for name in ["e1", "e2", "e3"] {
            ring.append_in(AuditLane::Evidence, entry(name, AuditResult::Ok));
        }
        for i in 1..=100 {
            ring.append_in(AuditLane::Routine, entry(&format!("r{i}"), AuditResult::Ok));
        }
        assert_eq!(ring.evidence_len(), 3);
        assert_eq!(ring.routine_len(), 2);
        assert_eq!(
            commands(&ring.recent(None, None)),
            ["e1", "e2", "e3", "r99", "r100"]
        );
    }

    #[test]
    fn a_lone_source_uses_the_whole_lane_then_evicts_its_own_oldest() {
        let ring = AuditRing::with_lane_capacities(5, 1);
        for name in ["c1", "c2", "c3", "c4", "c5"] {
            ring.append_in(AuditLane::Evidence, entry(name, AuditResult::Ok));
        }
        assert_eq!(ring.evidence_len(), 5);
        assert_eq!(
            commands(&ring.recent(None, None)),
            ["c1", "c2", "c3", "c4", "c5"]
        );
        ring.append_in(AuditLane::Evidence, entry("c6", AuditResult::Ok));
        assert_eq!(ring.evidence_len(), 5);
        assert_eq!(
            commands(&ring.recent(None, None)),
            ["c2", "c3", "c4", "c5", "c6"]
        );
    }

    #[test]
    fn fair_share_protects_a_quiet_source_from_a_flooder() {
        let ring = AuditRing::with_lane_capacities(8, 1);
        for name in ["a1", "a2", "a3"] {
            ring.append_in(
                AuditLane::Evidence,
                sourced(Frontend::Mcp, Some("agent-a"), name),
            );
        }
        for i in 1..=100 {
            ring.append_in(
                AuditLane::Evidence,
                sourced(Frontend::Mcp, Some("agent-b"), &format!("b{i}")),
            );
        }
        assert_eq!(
            commands(&ring.recent(None, None)),
            ["a1", "a2", "a3", "b96", "b97", "b98", "b99", "b100"]
        );
    }

    #[test]
    fn fair_share_ties_evict_the_globally_oldest() {
        let ring = AuditRing::with_lane_capacities(3, 1);
        for name in ["s1", "s2", "s3", "s4"] {
            ring.append_in(
                AuditLane::Evidence,
                sourced(Frontend::Mcp, Some(name), name),
            );
        }
        assert_eq!(commands(&ring.recent(None, None)), ["s2", "s3", "s4"]);
    }

    #[test]
    fn a_source_flood_of_distinct_labels_cannot_flush_a_tracked_source() {
        let ring = AuditRing::with_lane_capacities(330, 1);
        for _ in 0..200 {
            ring.append_in(AuditLane::Evidence, sourced(Frontend::Mcp, Some("a"), "a"));
        }
        for i in 0..5000 {
            ring.append_in(
                AuditLane::Evidence,
                sourced(Frontend::Mcp, Some(&format!("flood-{i}")), "flood"),
            );
        }
        assert_eq!(ring.evidence_len(), 330);
        let held_by_a = ring
            .recent(None, None)
            .iter()
            .filter(|e| origin_label(e.origin) == "mcp" && e.client_label.as_deref() == Some("a"))
            .count();
        let floor = 330 / (MAX_AUDIT_SOURCES + 3) - 1;
        assert_eq!(floor, 8);
        assert!(
            held_by_a >= floor,
            "source A kept {held_by_a} entries, the floor is {floor}"
        );
    }

    #[test]
    fn overflow_is_per_origin_and_the_table_is_bounded() {
        let ring = AuditRing::with_lane_capacities(100, 1);
        // Fill the whole table with single-entry `mcp` sources.
        for i in 0..MAX_AUDIT_SOURCES {
            ring.append_in(
                AuditLane::Evidence,
                sourced(Frontend::Mcp, Some(&format!("m{i}")), &format!("m{i}")),
            );
        }
        // An `operator` source arriving after the table is full shares only its
        // own origin's overflow bucket.
        ring.append_in(
            AuditLane::Evidence,
            sourced(Frontend::Operator, Some("op"), "op"),
        );
        // A flood of distinct `mcp` labels lands in the `mcp` overflow bucket.
        for i in 0..200 {
            ring.append_in(
                AuditLane::Evidence,
                sourced(Frontend::Mcp, Some(&format!("x{i}")), &format!("x{i}")),
            );
        }
        let kept = ring.recent(None, None);
        assert_eq!(ring.evidence_len(), 100);
        let tracked = kept.iter().filter(|e| e.command.starts_with('m')).count();
        assert_eq!(tracked, MAX_AUDIT_SOURCES, "a tracked source was flushed");
        let operator: Vec<&str> = kept
            .iter()
            .filter(|e| origin_label(e.origin) == "operator")
            .map(|e| e.command.as_str())
            .collect();
        assert_eq!(operator, ["op"]);
        // The flood keeps only its own newest entries: 100 - 32 - 1 = 67.
        let flood: Vec<&str> = kept
            .iter()
            .filter(|e| e.command.starts_with('x'))
            .map(|e| e.command.as_str())
            .collect();
        assert_eq!(flood.len(), 67);
        assert_eq!(flood.last().copied(), Some("x199"));
    }
}
