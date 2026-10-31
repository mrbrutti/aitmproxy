//! The F2 command-invocation audit ring (spec D3a).
//!
//! Every command `invoke` the MCP server (and, in time, the CLI) runs — including
//! one a policy or confirm gate refused — is recorded as one [`AuditEntry`]:
//! who ran what, with what (redacted) arguments, and whether it ran or was
//! refused. The entries land in a bounded in-memory [`AuditRing`] that is always
//! on: the bounded *live* view the operator "Agent" page and `agent.activity`
//! read. The `aitm` binary attaches a [`DurableAudit`] file writer to the ring by
//! default (config `mcp.audit_log`), and that file keeps the complete best-effort
//! record. The CA plugin's log is a separate, differently shaped file, not a
//! subset of it. `McpServer::with_durable_audit` remains a per-server
//! [`AuditSink`] tap that tests use.
//!
//! `args_summary` is a redacted, size-capped rendering produced by the caller:
//! tokens, auth headers, and the CA key material never reach an entry, matching
//! the M2 CA posture (the bounded-memory + secret-handling constraints).
//!
//! # Labels and reasons
//!
//! `client_label` is a display string, not an identity: `origin` is the only
//! authoritative field. The web bridge's connections carry the server-minted
//! [`WEB_BRIDGE_CLIENT_LABEL`] (`web-bridge`). Every other label is whatever the
//! client declared, run through [`sanitize_client_label`] (a whitespace control
//! such as a tab or a newline becomes one blank, every other control, invisible,
//! and bidirectional-override character is dropped, credential material is masked
//! by [`crate::redact::scrub_text`], at most [`MAX_CLIENT_LABEL_CHARS`] = 64
//! characters) and, where a client declares it, [`declared_client_label`], which
//! suffixes a label that reads as a reserved name (`web-bridge`, `Web Bridge`,
//! `web_bridge`) with ` (declared)`. A label is unauthenticated: a client can
//! still declare any other name, a first-party one included. An error reason is
//! scrubbed with [`crate::redact::scrub_text`] and kept to at most
//! [`DEFAULT_RESULT_REASON_CAP`] (1024) bytes plus a one-character `…` truncation
//! marker before it is recorded.
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
//! source still uses the whole lane. A flood can only take entries from sources
//! holding more than their fair share, never from one below the table-slot floor:
//! a source that holds a slot keeps about
//! `capacity / (MAX_AUDIT_SOURCES + one overflow bucket per origin)` entries
//! however many fresh labels a flooder mints.
//!
//! That floor is not isolation. Each lane tracks at most [`MAX_AUDIT_SOURCES`]
//! sources by name and files the rest under one overflow source per origin, and
//! labels are unauthenticated:
//!
//! - A source that first appears *after* the slots are taken shares its origin's
//!   overflow bucket with whoever took them, and a flood can flush it to nothing.
//! - A flooder that declares an honest source's label shares that source's
//!   entries, and can flush them.
//! - Every agent-token connection of the web bridge is ONE source,
//!   `(mcp, web-bridge)`, whichever client is behind it.
//! - A source can erase its own history, and a restart empties the ring.
//!
//! Origin still separates `mcp` from `operator` and `cli`. The ring is the bounded
//! live view; the durable file the `aitm` binary attaches by default (config
//! `mcp.audit_log`) is what keeps the complete best-effort record.
//!
//! # Who reads an entry
//!
//! A role only reads the entries [`AuditEntry::visible_to`] allows it (an agent
//! never sees what the operator or the CLI did); the ring and the durable log
//! themselves are never filtered, and neither is what the ring keeps: the filter
//! is applied on read only, so a hidden entry holds its slot and counts in its
//! source's share exactly as a visible one does. Each streaming connection's
//! entries carry a server-assigned `connection_id`, so two clients that share one
//! label (every agent-token bridge connection is `web-bridge`) stay tellable apart.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::command::Sensitivity;
use crate::ctx::Frontend;
use crate::value::Value;

/// The default capacity (entries) of the evidence lane before it evicts. A few
/// thousand entries is enough for the live "Agent" view; a durable sink, when one
/// is attached, keeps the full history.
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

/// How many bytes of an error reason an audit entry keeps before it is truncated:
/// a recorded reason is at most this many bytes plus a one-character `…`
/// truncation marker (three bytes in UTF-8), and the marker is added only when
/// something was cut. A verbose or hostile reason cannot grow an entry without
/// bound.
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
    /// `invoke` failed; the string is a scrubbed copy of the reason, at most
    /// [`DEFAULT_RESULT_REASON_CAP`] bytes plus a one-character `…` truncation
    /// marker.
    Error(String),
}

/// One command-invocation audit record.
#[derive(Debug, Clone)]
pub struct AuditEntry {
    /// When the invocation was recorded (after the policy/confirm gates).
    pub at: SystemTime,
    /// The frontend role that invoked it (F1 identity).
    pub origin: Frontend,
    /// The connection's client label: the server-minted [`WEB_BRIDGE_CLIENT_LABEL`]
    /// for the web bridge, otherwise the sanitised name the client declared, if it
    /// declared one. Display-only; `origin` is authoritative.
    pub client_label: Option<String>,
    /// The server-assigned, opaque id of the streaming connection that made the
    /// call. `None` means the call is not attributable to a streaming connection
    /// (an in-process caller, a request/response transport). Minted by the
    /// server; see `McpServer::connection_id` in `aitm-mcp`.
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

/// Whether a character is dropped from a client label: a control character, or
/// an invisible or bidirectional-override character that could make one label
/// pose as another in a UI (a soft hyphen, a variation selector, a Hangul filler,
/// a blank braille cell, a tag character, and the zero-width and bidi families).
fn is_label_noise(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{00AD}'
                | '\u{034F}'
                | '\u{061C}'
                | '\u{115F}'..='\u{1160}'
                | '\u{180B}'..='\u{180E}'
                | '\u{200B}'..='\u{200F}'
                | '\u{2028}'..='\u{202E}'
                | '\u{2060}'..='\u{2069}'
                | '\u{2800}'
                | '\u{3164}'
                | '\u{FE00}'..='\u{FE0F}'
                | '\u{FEFF}'
                | '\u{FFA0}'
                | '\u{E0000}'..='\u{E007F}'
        )
}

/// The one sanitiser for a client label, whatever its source.
///
/// It reads only the first `LABEL_SCAN_CHARS` characters of `raw`, so its work
/// is bounded however large the input. It turns a whitespace control (a tab,
/// a newline, NEL, a line or paragraph separator) into one blank, so
/// `Bearer\tabc` keeps the blank the scrubber's `Bearer` pattern needs, and drops
/// every other control, invisible, and bidirectional-override character. It masks
/// credential material with [`crate::redact::scrub_text`], trims, and truncates to
/// [`MAX_CLIENT_LABEL_CHARS`] characters. It returns `None` when nothing is left.
/// A second application can only mask more (masking can remove an escape, and the
/// cut can land inside a mask), never reveal more; the label stays bounded, up to
/// about 10 characters over the cap after a later `scrub_text`. It does not rewrite a
/// server-minted name such as [`WEB_BRIDGE_CLIENT_LABEL`]; use
/// [`declared_client_label`] where a client supplies the label.
pub fn sanitize_client_label(raw: &str) -> Option<String> {
    let cleaned: String = raw
        .chars()
        .take(LABEL_SCAN_CHARS)
        .filter_map(|c| match (is_label_noise(c), c.is_whitespace()) {
            (true, true) => Some(' '),
            (true, false) => None,
            (false, _) => Some(c),
        })
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

/// The skeleton of a label: its ASCII letters and digits, lower-cased. Two labels
/// with one skeleton read alike (`web-bridge`, `Web Bridge`, `web_bridge`, and
/// `web-bridge` with any invisible or punctuation character slipped in), whatever
/// padding sits between the letters.
fn label_skeleton(label: &str) -> String {
    label
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

/// The suffix [`declared_client_label`] puts on a label that reads as a reserved
/// name.
const DECLARED_SUFFIX: &str = " (declared)";

/// Whether a label's skeleton equals a reserved name's.
fn reads_as_reserved(label: &str) -> bool {
    let skeleton = label_skeleton(label);
    RESERVED_CLIENT_LABELS
        .iter()
        .any(|name| label_skeleton(name) == skeleton)
}

/// Sanitise a label a client declared (see [`sanitize_client_label`]) and keep it
/// from posing as a server-minted one: a label whose skeleton (its ASCII letters
/// and digits, lower-cased) equals a reserved name's gets a ` (declared)` suffix,
/// so case, blanks, punctuation, and any invisible character the sanitiser keeps
/// cannot make a client look like the server's `web-bridge`. Apply it only where a
/// client declares its label, never to a label the server mints.
///
/// The result is at most [`MAX_CLIENT_LABEL_CHARS`] characters including the
/// suffix, so the server's own pass over a stored label (which cuts to that cap)
/// leaves it unchanged and cannot drop the suffix. To fit it, a reserved-looking
/// label is first cut to the cap less the suffix and trimmed; if that head still
/// reads as the reserved name it gets the suffix, and if the cut took the name
/// apart the head is returned as it is, since it no longer poses as the reserved
/// one.
pub fn declared_client_label(raw: &str) -> Option<String> {
    let label = sanitize_client_label(raw)?;
    if !reads_as_reserved(&label) {
        return Some(label);
    }
    let room = MAX_CLIENT_LABEL_CHARS - DECLARED_SUFFIX.chars().count();
    let head: String = label.chars().take(room).collect();
    let head = head.trim_end();
    if reads_as_reserved(head) {
        Some(format!("{head}{DECLARED_SUFFIX}"))
    } else {
        Some(head.to_string())
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
/// a durable JSONL log implements it too when one is attached, so one `append`
/// fans to both without the caller knowing which sinks are attached.
pub trait AuditSink: Send + Sync {
    /// Record one entry. Infallible by contract: a durable sink that cannot write
    /// logs and drops the line rather than breaking the command that produced it.
    fn append(&self, entry: AuditEntry);
}

/// A snapshot of a durable audit writer's health: what a status surface reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DurableAuditStatus {
    /// Whether the writer is currently failing to persist entries.
    pub degraded: bool,
    /// How many entries the writer has dropped (a full queue).
    pub dropped: u64,
    /// How many writes to the file have failed.
    pub write_failures: u64,
}

/// A durable sink the ring forwards every entry to once one is attached with
/// [`AuditRing::attach_durable`] (the `aitm` binary's JSONL file writer).
///
/// An implementation must not block and must not panic. [`DurableAudit::record`]
/// runs on the appending caller's thread **after** the ring's lock is released,
/// so calling back into the ring from it is safe. [`DurableAudit::status`] reads
/// atomics only.
pub trait DurableAudit: Send + Sync + std::fmt::Debug {
    /// Take one entry, already routed to `lane` by the ring's caller.
    fn record(&self, lane: AuditLane, entry: AuditEntry);

    /// The writer's current health. Reads atomics only; never blocks.
    fn status(&self) -> DurableAuditStatus;
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
    /// victim: it is the newest, so it is the oldest of its bucket only when it is
    /// that bucket's only entry. Then every bucket holds one entry (the victim has
    /// the most) and the tie-break picks an older singleton instead; with no other
    /// bucket the lane is not over capacity, because its capacity is at least 1.
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
/// source holding the most entries, so a source that holds a table slot keeps a
/// floor of its entries against a flood. That is a floor, not isolation (see the
/// module docs): a source that arrives after all [`MAX_AUDIT_SOURCES`] slots of a
/// lane are taken shares its origin's overflow source, a flooder that declares an
/// honest source's label shares that source's entries, and every agent-token
/// connection of the web bridge is the one source `(mcp, web-bridge)`. Nothing is
/// evicted while a lane has room, and the newest entry is always kept.
///
/// Memory is bounded in entries and, because every entry field is capped by its
/// producer, in bytes. The ring is a live view, not a complete record: a source
/// can erase its own history and a restart empties it. The complete best-effort
/// record is the durable file the `aitm` binary attaches by default (config
/// `mcp.audit_log`) through [`AuditRing::attach_durable`].
#[derive(Debug)]
pub struct AuditRing {
    inner: Mutex<RingState>,
    /// The durable sink, set once by [`AuditRing::attach_durable`]. Read with one
    /// lock-free `get` on every append.
    durable: OnceLock<Arc<dyn DurableAudit>>,
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
            durable: OnceLock::new(),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, RingState> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Record `entry` in `lane`. [`AuditSink::append`] is this with the evidence
    /// lane; use [`lane_for`] to choose the lane for a command's outcome.
    ///
    /// When a [`DurableAudit`] sink is attached it also receives one clone of the
    /// entry, **after** the ring's lock is released. With none attached the only
    /// extra work is one lock-free read.
    pub fn append_in(&self, lane: AuditLane, entry: AuditEntry) {
        let sink = self.durable.get();
        // The clone is taken before the lock, so the critical section is as short
        // as it was without a sink, and only when a sink is attached.
        let for_sink = sink.map(|_| entry.clone());
        {
            let mut state = self.lock();
            let seq = state.next_seq;
            state.next_seq = seq.saturating_add(1);
            state.lane_mut(lane).insert(seq, entry);
        }
        if let (Some(sink), Some(copy)) = (sink, for_sink) {
            sink.record(lane, copy);
        }
    }

    /// Attach the durable sink. Set-once: the first call returns `true`; a second
    /// call returns `false`, drops its sink, and keeps the first.
    pub fn attach_durable(&self, sink: Arc<dyn DurableAudit>) -> bool {
        self.durable.set(sink).is_ok()
    }

    /// The attached sink's status, or `None` when none is attached. It reads
    /// atomics only and never takes the ring's lock.
    pub fn durable_status(&self) -> Option<DurableAuditStatus> {
        self.durable.get().map(|sink| sink.status())
    }

    /// Recent entries of both lanes in call order, oldest first. `since` keeps
    /// only entries strictly after it; `limit` keeps the most recent `limit` of
    /// those (presented oldest first), so a reconnecting surface catches up
    /// without replaying the whole ring.
    ///
    /// This is the **unfiltered** read: it returns every entry whatever its
    /// origin, so it is for in-process tests only. Never use it on a surface a
    /// role reads; use [`AuditRing::recent_for`] there.
    pub fn recent(&self, since: Option<SystemTime>, limit: Option<usize>) -> Vec<AuditEntry> {
        self.recent_where(since, limit, |_| true)
    }

    /// [`AuditRing::recent`] as `viewer` may see it: an entry is kept only when
    /// [`AuditEntry::visible_to`] says so. The visibility filter runs **before**
    /// `limit`, so `limit` counts the entries the viewer can see, never the
    /// hidden ones (a limit of 1 for an agent never returns the operator's
    /// entry, and never returns nothing because the newest entry was hidden).
    /// Both lanes are read and the result is in call order, as for `recent`.
    pub fn recent_for(
        &self,
        viewer: Frontend,
        since: Option<SystemTime>,
        limit: Option<usize>,
    ) -> Vec<AuditEntry> {
        self.recent_where(since, limit, |e| e.visible_to(viewer))
    }

    /// The shared body of [`AuditRing::recent`] and [`AuditRing::recent_for`]:
    /// both lanes, `since` (strictly after), then `keep`, then sort by call order,
    /// then `limit` (the most recent entries), oldest first.
    fn recent_where(
        &self,
        since: Option<SystemTime>,
        limit: Option<usize>,
        keep: impl Fn(&AuditEntry) -> bool,
    ) -> Vec<AuditEntry> {
        let state = self.lock();
        let mut held: Vec<&(u64, AuditEntry)> = state
            .evidence
            .entries()
            .chain(state.routine.entries())
            .filter(|(_, e)| since.is_none_or(|s| e.at > s))
            .filter(|(_, e)| keep(e))
            .collect();
        held.sort_unstable_by_key(|(seq, _)| *seq);
        let skip = limit.map_or(0, |limit| held.len().saturating_sub(limit));
        held.into_iter()
            .skip(skip)
            .map(|(_, e)| e.clone())
            .collect()
    }

    /// How many entries, across both lanes, were recorded at or after `since`,
    /// whatever their origin.
    ///
    /// This is the **unfiltered** count, compiled for in-process tests only: no
    /// surface a role reads may call it. It is [`AuditRing::count_since_for`] as the
    /// operator, who sees every entry. Use `count_since_for` everywhere else.
    #[cfg(test)]
    pub fn count_since(&self, since: SystemTime) -> usize {
        self.count_since_for(Frontend::Operator, since, None)
    }

    /// How many entries, across both lanes, were recorded at or after `since` that
    /// `viewer` may see (the source of `agent.status.actions_last_minute`): only
    /// entries that are [`AuditEntry::visible_to`] the viewer, and, when
    /// `exclude_connection` is `Some(id)`, not made by the connection `id`. An
    /// entry with no `connection_id` is never excluded: an id the server did not
    /// assign cannot match one it did.
    pub fn count_since_for(
        &self,
        viewer: Frontend,
        since: SystemTime,
        exclude_connection: Option<&str>,
    ) -> usize {
        let state = self.lock();
        state
            .evidence
            .entries()
            .chain(state.routine.entries())
            .filter(|(_, e)| e.at >= since)
            .filter(|(_, e)| {
                e.visible_to(viewer)
                    && !exclude_connection.is_some_and(|id| e.connection_id.as_deref() == Some(id))
            })
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
    use std::time::Duration;

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

        assert_eq!(
            commands(&ring.recent_for(Frontend::Mcp, None, Some(2))),
            ["ag1", "ag2"]
        );
        assert_eq!(
            commands(&ring.recent_for(Frontend::Operator, None, Some(2))),
            ["ag2", "op3"]
        );
        assert_eq!(
            commands(&ring.recent_for(Frontend::Mcp, None, None)),
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

    /// The instant `ms` milliseconds after the epoch, so a window edge can be
    /// placed exactly instead of racing `SystemTime::now()`.
    fn at_ms(ms: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_millis(ms)
    }

    /// An entry made at the explicit instant `ms` after the epoch ([`at_ms`]).
    fn entry_at_ms(
        origin: Frontend,
        connection_id: Option<&str>,
        command: &str,
        ms: u64,
    ) -> AuditEntry {
        AuditEntry {
            at: at_ms(ms),
            ..entry_of(origin, connection_id, command)
        }
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
            Some("ab cd".to_string())
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

        // For these inputs, sanitising a sanitised label changes nothing.
        let long = "A".repeat(10 << 20);
        let nuls = "\u{0}".repeat(10 << 20);
        // The 64-char cut lands inside the masked value, and inside the key.
        let cut_in_mask = format!("{}token=abc123", "x".repeat(56));
        let cut_in_key = format!("{}token=abc123", "x".repeat(60));
        let mut bad: Vec<String> = Vec::new();
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
            // Two inputs are 10 MiB: name an input by its length and a preview.
            let input = format!(
                "{}-byte input {:?}",
                raw.len(),
                raw.chars().take(80).collect::<String>()
            );
            let once = sanitize_client_label(raw);
            let bounded_and_clean = once
                .as_deref()
                .is_none_or(|l| l.chars().count() <= 64 && !l.contains("abc123"));
            if !bounded_and_clean {
                bad.push(format!("unbounded or leaking for a {input}: {once:?}"));
            }
            let twice = once.as_deref().and_then(sanitize_client_label);
            if twice != once {
                bad.push(format!(
                    "not idempotent for a {input}: {once:?} then {twice:?}"
                ));
            }
        }
        assert!(bad.is_empty(), "bad sanitiser rows: {bad:#?}");
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

    #[test]
    fn declared_client_label_rewrites_a_reserved_name_hidden_by_invisible_characters() {
        // Each of these renders as `web-bridge`; none may pass as the real one.
        let mut bad: Vec<(String, Option<String>)> = [
            "web-bridge\u{AD}",
            "web\u{AD}-bridge",
            "web-bridge\u{FE0F}",
            "web-bridge\u{200B}",
            "\u{3164}web-bridge",
            "web-bridge\u{E0020}",
        ]
        .into_iter()
        .map(|raw| (raw.to_string(), declared_client_label(raw)))
        .filter(|(_, label)| label.as_deref() != Some("web-bridge (declared)"))
        .collect();

        // Literal rows. A character the sanitiser keeps stays in the label; the
        // suffix is what tells a reader it is not the server's `web-bridge`.
        let rows: &[(&str, &str)] = &[
            ("web-bridge\u{FFF0}", "web-bridge\u{FFF0} (declared)"),
            ("web\u{17B4}-bridge", "web\u{17B4}-bridge (declared)"),
            ("web\u{2009}-bridge", "web\u{2009}-bridge (declared)"),
            ("web bridge", "web bridge (declared)"),
            ("web_bridge", "web_bridge (declared)"),
            ("webbridge", "webbridge (declared)"),
            ("WEB-BRIDGE", "WEB-BRIDGE (declared)"),
            ("Web  -  Bridge", "Web  -  Bridge (declared)"),
        ];
        for &(raw, want) in rows {
            let got = declared_client_label(raw);
            if got.as_deref() != Some(want) {
                bad.push((raw.to_string(), got));
            }
        }

        // `web-bridge` with one more code point at the end, and one inside the
        // name: a format, filler, variation-selector, tag, or space character the
        // sanitiser may or may not drop. Either way the label is the sanitised one
        // plus ` (declared)`.
        let hidden = "\u{061C}\u{00AD}\u{034F}\u{115F}\u{1160}\u{3164}\u{FFA0}\u{2800}\
                      \u{17B4}\u{17B5}\u{180B}\u{180E}\u{180F}\u{206A}\u{206F}\
                      \u{FFF0}\u{FFFB}\u{FE00}\u{FE0F}\u{1BCA0}\u{1D173}\
                      \u{E0000}\u{E007F}\u{E0080}\u{E0100}\u{E01EF}\u{2009}\u{200A}";
        assert_eq!(hidden.chars().count(), 28, "one row per code point");
        for c in hidden.chars() {
            for raw in [format!("web-bridge{c}"), format!("web{c}-bridge")] {
                let got = declared_client_label(&raw);
                let want = sanitize_client_label(&raw).map(|label| format!("{label} (declared)"));
                if want.is_none() || got != want {
                    bad.push((raw, got));
                }
            }
        }

        // Negative controls: another name is not rewritten, whatever invisible
        // character trails it, and a longer name that merely starts with the
        // reserved one is not the reserved name.
        for (raw, want) in [
            ("aitm-mac\u{3164}", "aitm-mac"),
            ("webbridges", "webbridges"),
            ("web-bridges", "web-bridges"),
        ] {
            let got = declared_client_label(raw);
            if got.as_deref() != Some(want) {
                bad.push((raw.to_string(), got));
            }
        }
        assert!(bad.is_empty(), "a reserved name got through: {bad:#?}");
    }

    #[test]
    fn declared_client_label_survives_the_consumption_pass() {
        // The server sanitises a stored label again where it consumes it, so what
        // `declared_client_label` returns must be a label that pass leaves alone:
        // at most the cap, the same text, and either still marked or no longer
        // reading as the reserved name. A padded lookalike of 62 to 64 characters
        // used to lose its suffix to that cut.
        assert_eq!(
            declared_client_label("web-bridge"),
            Some("web-bridge (declared)".to_string())
        );
        let reserved = label_skeleton(WEB_BRIDGE_CLIENT_LABEL);
        let mut bad: Vec<String> = Vec::new();
        for pad in ['\u{17B4}', '\u{FFF0}', '\u{206A}', '_'] {
            // `web-bridge` is 10 characters: pad it out to every length up to 70.
            for total in 10..=70 {
                let padding = pad.to_string().repeat(total - 10);
                for (shape, raw) in [
                    ("trailing pad", format!("web-bridge{padding}")),
                    ("inner pad", format!("web{padding}-bridge")),
                ] {
                    let row = format!("U+{:04X} {shape}, {total} chars", u32::from(pad));
                    let Some(got) = declared_client_label(&raw) else {
                        bad.push(format!("{row}: no label"));
                        continue;
                    };
                    let chars = got.chars().count();
                    if chars > MAX_CLIENT_LABEL_CHARS {
                        bad.push(format!("{row}: {chars} chars over the cap: {got:?}"));
                    }
                    let again = sanitize_client_label(&got);
                    if again.as_deref() != Some(got.as_str()) {
                        bad.push(format!(
                            "{row}: the consumption pass changed {got:?} to {again:?}"
                        ));
                    }
                    if !got.ends_with(" (declared)") && label_skeleton(&got) == reserved {
                        bad.push(format!("{row}: reads as the reserved name: {got:?}"));
                    }
                }
            }
        }
        assert!(bad.is_empty(), "bad declared labels: {bad:#?}");
    }

    #[test]
    fn sanitize_client_label_drops_every_invisible_character() {
        // One or more characters from each range of the dropped set: the label
        // `a<c>b` must come back as `ab`.
        let invisible = [
            '\u{AD}',
            '\u{34F}',
            '\u{61C}',
            '\u{115F}',
            '\u{1160}',
            '\u{180B}',
            '\u{180C}',
            '\u{180D}',
            '\u{180E}',
            '\u{200B}',
            '\u{200F}',
            '\u{202E}',
            '\u{2060}',
            '\u{2069}',
            '\u{2800}',
            '\u{3164}',
            '\u{FE00}',
            '\u{FE0F}',
            '\u{FEFF}',
            '\u{FFA0}',
            '\u{E0000}',
            '\u{E0001}',
            '\u{E0020}',
            '\u{E007F}',
        ];
        let bad: Vec<(char, Option<String>)> = invisible
            .into_iter()
            .map(|c| (c, sanitize_client_label(&format!("a{c}b"))))
            .filter(|(_, label)| label.as_deref() != Some("ab"))
            .collect();
        assert!(bad.is_empty(), "an invisible character was kept: {bad:#?}");
        // The line separator is whitespace: it becomes a blank, not nothing.
        assert_eq!(sanitize_client_label("a\u{2028}b"), Some("a b".to_string()));
        // A visible non-ASCII letter is not noise.
        assert_eq!(
            sanitize_client_label("caf\u{e9}"),
            Some("caf\u{e9}".to_string())
        );
    }

    #[test]
    fn sanitising_twice_only_ever_masks_more() {
        // A masked escape, and a cut inside a mask, are the two ways the second
        // pass sees different text from the first. Each row is (raw label, label
        // after one pass, label after two): the second pass hides more, or the same,
        // and never shows what the first hid.
        let cut_raw = format!("{}Bearer abc123", "x".repeat(50));
        // The 64-character cut lands inside `Bearer [redacted]`.
        let cut = format!("{}Bearer [redact", "x".repeat(50));
        let rows = [
            (
                "password:' auth:\\'",
                "password:' auth:[redacted]'",
                "password:'[redacted]'",
            ),
            (cut_raw.as_str(), cut.as_str(), cut.as_str()),
        ];
        let mut bad = Vec::new();
        for (raw, once_want, twice_want) in rows {
            let once = sanitize_client_label(raw);
            let twice = once.as_deref().and_then(sanitize_client_label);
            if once.as_deref() != Some(once_want) || twice.as_deref() != Some(twice_want) {
                bad.push((raw, once, twice));
            }
        }
        assert!(
            bad.is_empty(),
            "wrong label after one and two passes (raw, once, twice): {bad:#?}"
        );

        // A later `scrub_text` completes the cut mask: 3 characters over the cap.
        assert_eq!(
            crate::redact::scrub_text(&cut),
            format!("{}Bearer [redacted]", "x".repeat(50))
        );
    }

    /// An entry recorded `secs` seconds after the Unix epoch, running `command`.
    fn entry_at(command: &str, secs: u64) -> AuditEntry {
        AuditEntry {
            at: UNIX_EPOCH + Duration::from_secs(secs),
            ..entry(command, AuditResult::Ok)
        }
    }

    #[test]
    fn since_and_count_since_filter_both_lanes() {
        let ring = AuditRing::with_lane_capacities(8, 8);
        // Interleaved, so call order differs from lane order.
        ring.append_in(AuditLane::Routine, entry_at("R-old", 10));
        ring.append_in(AuditLane::Evidence, entry_at("E-old", 10));
        ring.append_in(AuditLane::Routine, entry_at("R-new", 100));
        ring.append_in(AuditLane::Evidence, entry_at("E-new", 100));
        let t = UNIX_EPOCH + Duration::from_secs(50);
        assert_eq!(commands(&ring.recent(Some(t), None)), ["R-new", "E-new"]);
        assert_eq!(ring.count_since(t), 2);
        // `limit` composes with `since`: the newest of the matching entries.
        assert_eq!(commands(&ring.recent(Some(t), Some(1))), ["E-new"]);
        // `recent` keeps entries strictly after `since`; `count_since` counts
        // entries at or after it.
        let at_new = UNIX_EPOCH + Duration::from_secs(100);
        assert!(ring.recent(Some(at_new), None).is_empty());
        assert_eq!(ring.count_since(at_new), 2);
        assert_eq!(ring.count_since(UNIX_EPOCH), 4);
        assert_eq!(ring.recent(None, None).len(), 4);
    }

    /// An entry from a chosen source (origin and label) running `command`.
    fn sourced(origin: Frontend, label: Option<&str>, command: &str) -> AuditEntry {
        AuditEntry {
            at: SystemTime::now(),
            origin,
            client_label: label.map(str::to_string),
            connection_id: None,
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

    // ---- Stage 5 tester additions: each one kills a mutant of the ring or the
    // label functions that the tests above let survive. ----

    /// One entry from each of `MAX_AUDIT_SOURCES` `mcp` sources (`m0`..`m31`, the
    /// label doubling as the command), so the evidence lane's source table is full.
    fn fill_source_table(ring: &AuditRing) {
        for i in 0..MAX_AUDIT_SOURCES {
            ring.append_in(
                AuditLane::Evidence,
                sourced(Frontend::Mcp, Some(&format!("m{i}")), &format!("m{i}")),
            );
        }
    }

    #[test]
    fn a_tracked_source_keeps_its_own_bucket_once_the_table_is_full() {
        let ring = AuditRing::with_lane_capacities(100, 1);
        fill_source_table(&ring);
        // `m31` already holds a slot, so its later entries stay in its own bucket
        // even though the table is now full.
        for n in 0..3 {
            ring.append_in(
                AuditLane::Evidence,
                sourced(Frontend::Mcp, Some("m31"), &format!("late{n}")),
            );
        }
        // A flood of fresh labels shares the overflow bucket and is evicted from it.
        for i in 0..500 {
            ring.append_in(
                AuditLane::Evidence,
                sourced(Frontend::Mcp, Some(&format!("x{i}")), "x"),
            );
        }
        assert_eq!(ring.evidence_len(), 100);
        let kept = ring.recent(None, None);
        let m31: Vec<&str> = kept
            .iter()
            .filter(|e| e.client_label.as_deref() == Some("m31"))
            .map(|e| e.command.as_str())
            .collect();
        assert_eq!(m31, ["m31", "late0", "late1", "late2"]);
    }

    #[test]
    fn a_slot_freed_by_eviction_goes_to_the_next_new_source() {
        // The lane is exactly full of 32 singleton sources.
        let ring = AuditRing::with_lane_capacities(MAX_AUDIT_SOURCES, 1);
        fill_source_table(&ring);
        // `late1` finds the table full and shares the overflow bucket; the lane is
        // now over capacity and the tie evicts the oldest singleton, `m0`, which
        // frees its slot.
        ring.append_in(
            AuditLane::Evidence,
            sourced(Frontend::Mcp, Some("late1"), "late1"),
        );
        // `late2` must take that free slot as its own bucket. Then every bucket is
        // a singleton again and the tie evicts `m1`; had `late2` joined `late1` in
        // the overflow bucket, that two-entry bucket would lose `late1` instead.
        ring.append_in(
            AuditLane::Evidence,
            sourced(Frontend::Mcp, Some("late2"), "late2"),
        );
        let mut want: Vec<String> = (2..MAX_AUDIT_SOURCES).map(|i| format!("m{i}")).collect();
        want.push("late1".to_string());
        want.push("late2".to_string());
        let kept: Vec<String> = ring
            .recent(None, None)
            .into_iter()
            .map(|e| e.command)
            .collect();
        assert_eq!(kept, want);
    }

    #[test]
    fn the_thirty_third_source_shares_its_origins_overflow_bucket() {
        let ring = AuditRing::with_lane_capacities(100, 1);
        fill_source_table(&ring);
        // The 33rd source finds no slot: it shares the `mcp` overflow bucket with
        // whatever floods in after it, and is flushed with them.
        ring.append_in(
            AuditLane::Evidence,
            sourced(Frontend::Mcp, Some("s32"), "s32"),
        );
        for i in 0..200 {
            ring.append_in(
                AuditLane::Evidence,
                sourced(Frontend::Mcp, Some(&format!("x{i}")), &format!("x{i}")),
            );
        }
        let kept = ring.recent(None, None);
        assert_eq!(ring.evidence_len(), 100);
        assert!(
            kept.iter().all(|e| e.command != "s32"),
            "the 33rd source got its own slot"
        );
        let holders = kept.iter().filter(|e| e.command.starts_with('m')).count();
        assert_eq!(holders, MAX_AUDIT_SOURCES, "a slot holder was flushed");
        let flood = kept.iter().filter(|e| e.command.starts_with('x')).count();
        assert_eq!(flood, 100 - MAX_AUDIT_SOURCES);
        assert_eq!(kept.last().map(|e| e.command.as_str()), Some("x199"));
    }

    #[test]
    fn the_same_label_under_two_origins_is_two_sources() {
        let ring = AuditRing::with_lane_capacities(8, 1);
        for name in ["m1", "m2", "m3"] {
            ring.append_in(
                AuditLane::Evidence,
                sourced(Frontend::Mcp, Some("ui"), name),
            );
        }
        for i in 1..=100 {
            ring.append_in(
                AuditLane::Evidence,
                sourced(Frontend::Operator, Some("ui"), &format!("o{i}")),
            );
        }
        assert_eq!(
            commands(&ring.recent(None, None)),
            ["m1", "m2", "m3", "o96", "o97", "o98", "o99", "o100"]
        );
    }

    #[test]
    fn a_zero_capacity_ring_still_keeps_the_newest_entry_of_each_lane() {
        for ring in [AuditRing::new(0), AuditRing::with_lane_capacities(0, 0)] {
            ring.append_in(AuditLane::Evidence, entry("e1", AuditResult::Ok));
            ring.append_in(AuditLane::Evidence, entry("e2", AuditResult::Ok));
            ring.append_in(AuditLane::Routine, entry("r1", AuditResult::Ok));
            ring.append_in(AuditLane::Routine, entry("r2", AuditResult::Ok));
            assert_eq!((ring.evidence_len(), ring.routine_len()), (1, 1));
            assert_eq!(commands(&ring.recent(None, None)), ["e2", "r2"]);
        }
    }

    #[test]
    fn new_gives_the_routine_lane_half_the_evidence_capacity_rounded_down() {
        // (evidence capacity asked for, routine capacity expected). Zero and one
        // are clamped to one lane slot each.
        for (capacity, want_routine) in [(0, 1), (1, 1), (2, 1), (3, 1), (5, 2), (7, 3), (100, 50)]
        {
            let ring = AuditRing::new(capacity);
            for i in 0..capacity + 10 {
                ring.append_in(
                    AuditLane::Evidence,
                    entry(&format!("e{i}"), AuditResult::Ok),
                );
                ring.append_in(AuditLane::Routine, entry(&format!("r{i}"), AuditResult::Ok));
            }
            assert_eq!(
                (ring.evidence_len(), ring.routine_len()),
                (capacity.max(1), want_routine),
                "AuditRing::new({capacity})"
            );
        }
        // The default ring: 4096 evidence entries, 2048 routine entries.
        assert_eq!(DEFAULT_ROUTINE_AUDIT_CAPACITY, 2048);
        let ring = AuditRing::default();
        for i in 0..DEFAULT_AUDIT_CAPACITY + 904 {
            ring.append_in(
                AuditLane::Evidence,
                entry(&format!("e{i}"), AuditResult::Ok),
            );
            ring.append_in(AuditLane::Routine, entry(&format!("r{i}"), AuditResult::Ok));
        }
        assert_eq!(
            (ring.evidence_len(), ring.routine_len()),
            (DEFAULT_AUDIT_CAPACITY, DEFAULT_ROUTINE_AUDIT_CAPACITY)
        );
    }

    #[test]
    fn a_poisoned_lock_does_not_brick_the_ring() {
        let ring = AuditRing::with_lane_capacities(4, 2);
        ring.append(entry("before", AuditResult::Ok));
        // A thread that panics while it holds the ring's lock poisons the mutex.
        let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _held = ring.lock();
            panic!("poison the audit ring on purpose");
        }));
        assert!(panicked.is_err());
        assert!(ring.inner.is_poisoned(), "the lock must really be poisoned");
        // The audit record keeps working, and keeps what was recorded before.
        ring.append(entry("after", AuditResult::Ok));
        ring.append_in(AuditLane::Routine, entry("polled", AuditResult::Ok));
        assert_eq!(
            commands(&ring.recent(None, None)),
            ["before", "after", "polled"]
        );
        assert_eq!(ring.len(), 3);
        assert_eq!((ring.evidence_len(), ring.routine_len()), (2, 1));
        assert_eq!(ring.count_since(UNIX_EPOCH), 3);
        assert!(!ring.is_empty());
    }

    #[test]
    fn recent_orders_by_call_not_by_timestamp_and_applies_since_before_limit() {
        // A clock that steps backwards, or two callers that took their timestamps
        // before racing to the ring: call order and timestamp order disagree.
        let ring = AuditRing::with_lane_capacities(8, 8);
        ring.append_in(AuditLane::Evidence, entry_at("first", 100));
        ring.append_in(AuditLane::Routine, entry_at("second", 50));
        ring.append_in(AuditLane::Evidence, entry_at("third", 75));
        assert_eq!(
            commands(&ring.recent(None, None)),
            ["first", "second", "third"]
        );
        assert_eq!(
            commands(&ring.recent(None, Some(2))),
            ["second", "third"],
            "limit keeps the most recently CALLED entries"
        );
        // `since` selects by timestamp (first, third), then `limit` keeps the last
        // of those. Applying `limit` first would keep (second, third) and leave
        // only `third`.
        let t = UNIX_EPOCH + Duration::from_secs(60);
        assert_eq!(commands(&ring.recent(Some(t), Some(2))), ["first", "third"]);
        assert_eq!(commands(&ring.recent(Some(t), Some(1))), ["third"]);
    }

    #[test]
    fn an_empty_ring_and_extreme_limits_are_handled() {
        let ring = AuditRing::default();
        assert!(ring.is_empty());
        assert!(ring.recent(None, None).is_empty());
        assert!(ring.recent(None, Some(0)).is_empty());
        assert!(ring.recent(Some(UNIX_EPOCH), Some(usize::MAX)).is_empty());
        assert_eq!(ring.count_since(UNIX_EPOCH), 0);
        assert_eq!((ring.evidence_len(), ring.routine_len()), (0, 0));

        ring.append(entry("a", AuditResult::Ok));
        ring.append_in(AuditLane::Routine, entry("b", AuditResult::Ok));
        assert!(ring.recent(None, Some(0)).is_empty(), "limit 0 is nothing");
        assert_eq!(commands(&ring.recent(None, Some(usize::MAX))), ["a", "b"]);
        assert_eq!(commands(&ring.recent(None, Some(2))), ["a", "b"]);
        // A `since` in the far future matches nothing; one at the epoch matches all.
        let future = SystemTime::now() + Duration::from_secs(3600);
        assert!(ring.recent(Some(future), None).is_empty());
        assert_eq!(ring.count_since(future), 0);
    }

    #[test]
    fn concurrent_appends_stay_bounded_and_keep_each_callers_order() {
        const THREADS: usize = 8;
        const PER_THREAD: usize = 500;
        let ring = AuditRing::with_lane_capacities(64, 32);
        std::thread::scope(|scope| {
            for t in 0..THREADS {
                let ring = &ring;
                scope.spawn(move || {
                    let label = format!("t{t}");
                    for i in 0..PER_THREAD {
                        let lane = if i % 2 == 0 {
                            AuditLane::Evidence
                        } else {
                            AuditLane::Routine
                        };
                        ring.append_in(
                            lane,
                            sourced(Frontend::Mcp, Some(&label), &format!("{t}:{i}")),
                        );
                    }
                });
            }
        });
        // Far more was appended than either lane holds, so both are exactly full.
        assert_eq!((ring.evidence_len(), ring.routine_len()), (64, 32));
        assert_eq!(ring.len(), 96);
        // Each thread's surviving entries are in the order that thread appended
        // them, and no entry appears twice.
        let kept = ring.recent(None, None);
        for t in 0..THREADS {
            let own: Vec<usize> = kept
                .iter()
                .filter_map(|e| e.command.strip_prefix(&format!("{t}:")))
                .map(|i| i.parse().expect("an index"))
                .collect();
            assert!(
                own.windows(2).all(|w| w[0] < w[1]),
                "thread {t}'s entries are out of order or duplicated: {own:?}"
            );
        }
    }

    #[test]
    fn declared_client_label_leaves_names_that_merely_contain_the_reserved_one_alone() {
        // None of these has the skeleton `webbridge`.
        for raw in [
            "web-bridge2",
            "2web-bridge",
            "web-bridge-2",
            "my-web-bridge",
            "web-bridge-ui",
            "xweb-bridge",
            "bridge-web",
            "web",
            "bridge",
        ] {
            assert_eq!(
                declared_client_label(raw),
                Some(raw.to_string()),
                "{raw:?} is not the reserved name"
            );
        }
    }

    #[test]
    fn sanitize_client_label_drops_c1_controls_and_delete() {
        let bad: Vec<(char, Option<String>)> = ['\u{7F}', '\u{80}', '\u{9B}', '\u{9F}']
            .into_iter()
            .map(|c| (c, sanitize_client_label(&format!("a{c}b"))))
            .filter(|(_, label)| label.as_deref() != Some("ab"))
            .collect();
        assert!(bad.is_empty(), "a control character was kept: {bad:#?}");
        // NEL is a whitespace control: it becomes a blank, not nothing.
        assert_eq!(sanitize_client_label("a\u{85}b"), Some("a b".to_string()));
        // The characters next to the C1 block are letters and symbols, not controls.
        assert_eq!(
            sanitize_client_label("a\u{A1}b"),
            Some("a\u{A1}b".to_string())
        );
    }

    #[test]
    fn sanitize_client_label_trims_blanks_that_the_cut_exposes() {
        // The 64-character cut lands right after a space: none may be left over.
        let cut_at_blank = format!("{} B", "A".repeat(63));
        assert_eq!(sanitize_client_label(&cut_at_blank), Some("A".repeat(63)));
        // Leading blanks do not use up the 64-character budget.
        let padded = format!("{}label", " ".repeat(100));
        assert_eq!(sanitize_client_label(&padded), Some("label".to_string()));
        let mixed = format!("\t \u{A0}{}label\t\n", " ".repeat(70));
        assert_eq!(sanitize_client_label(&mixed), Some("label".to_string()));
    }

    #[test]
    fn sanitize_client_label_reads_only_the_first_1024_chars() {
        // 1024 invisible characters use up the whole scan: the label behind them is
        // never read, so a hostile client cannot make the sanitiser scan far.
        let hidden = format!("{}tail", "\u{200B}".repeat(1024));
        assert_eq!(sanitize_client_label(&hidden), None);
        // One fewer and the first visible character is still inside the scan.
        let just_inside = format!("{}ab", "\u{200B}".repeat(1023));
        assert_eq!(sanitize_client_label(&just_inside), Some("a".to_string()));
        // A reserved name behind 1024 blanks never reaches the label either.
        let blanks = format!("{}web-bridge", " ".repeat(1024));
        assert_eq!(sanitize_client_label(&blanks), None);
        assert_eq!(declared_client_label(&blanks), None);
    }

    #[test]
    fn sanitize_client_label_masks_a_credential_hidden_by_invisible_characters() {
        // The invisible character is dropped first, so it cannot split a secret key
        // in two and hide its value from the scrubber.
        for (raw, secret) in [
            ("pass\u{200B}word=hunter2", "hunter2"),
            ("to\u{AD}ken=SECRET9", "SECRET9"),
            ("api\u{E0020}_key: abc123xyz", "abc123xyz"),
            ("Bearer\u{FEFF} tok3nvalue", "tok3nvalue"),
        ] {
            let label = sanitize_client_label(raw).expect("a label remains");
            assert!(!label.contains(secret), "{raw:?} leaked {secret}: {label}");
            assert!(
                label.contains("[redacted]"),
                "{raw:?} was not masked: {label}"
            );
        }
    }

    /// The scrubber's `Bearer` frame needs a blank between the word and its token.
    /// A whitespace control (tab, newline, NEL, line separator) is noise, but
    /// deleting it would join `Bearer` to the token and leave nothing to match, so
    /// it becomes a blank instead.
    #[test]
    fn sanitize_client_label_masks_a_bearer_token_after_a_whitespace_control() {
        for raw in [
            "agent Bearer\tabc123",
            "agent Bearer\nabc123",
            "Bearer\u{85}abc123",
            "Bearer\u{2028}abc123",
        ] {
            let label = sanitize_client_label(raw).expect("a label remains");
            assert!(!label.contains("abc123"), "{raw:?} leaked abc123: {label}");
            assert!(
                label.contains("Bearer [redacted]"),
                "{raw:?} was not masked as a bearer token: {label}"
            );
        }
        // These pair frames need no blank, so they were masked before the port too.
        for (raw, secret) in [
            ("agent token\t=abc123", "abc123"),
            ("password\n: hunter2", "hunter2"),
        ] {
            let label = sanitize_client_label(raw).expect("a label remains");
            assert!(!label.contains(secret), "{raw:?} leaked {secret}: {label}");
            assert!(
                label.contains("[redacted]"),
                "{raw:?} was not masked: {label}"
            );
        }
    }

    #[test]
    fn sanitize_client_label_turns_whitespace_controls_into_a_blank() {
        assert_eq!(sanitize_client_label("a\tb\nc"), Some("a b c".to_string()));
    }

    /// The viewer filter is read-side only (plan 2026-10-30-bus-audit-connection-id,
    /// spec A4 and AC28). `append_in`, eviction and the source table never look at
    /// who may read an entry, so an operator flood that an agent may not read still
    /// holds slots and still costs the agent its entries exactly as a visible flood
    /// would: here the agent's `m1` is evicted although the flood is hidden from it.
    #[test]
    fn the_viewer_filter_does_not_change_what_the_ring_keeps() {
        let ring = AuditRing::with_lane_capacities(4, 1);
        for command in ["m1", "m2", "m3"] {
            ring.append(sourced(Frontend::Mcp, None, command));
        }
        for i in 0..100 {
            ring.append(sourced(Frontend::Operator, None, &format!("o{i}")));
        }

        assert_eq!(ring.evidence_len(), 4);
        assert_eq!(
            commands(&ring.recent(None, None)),
            ["m2", "m3", "o98", "o99"]
        );
        assert_eq!(
            commands(&ring.recent_for(Frontend::Mcp, None, None)),
            ["m2", "m3"]
        );
        assert_eq!(
            commands(&ring.recent_for(Frontend::Mcp, None, Some(1))),
            ["m3"]
        );
        assert_eq!(
            commands(&ring.recent_for(Frontend::Operator, None, None)),
            ["m2", "m3", "o98", "o99"]
        );
    }

    /// `recent_for` and `count_since_for` read both lanes in one lock (spec A4 and
    /// AC29): `since`, then the viewer filter, then call order, then `limit`, so
    /// `limit` counts the entries the viewer may see across the evidence and the
    /// routine lane alike; and the count adds the viewer filter and the
    /// connection exclusion on top of `at >= since`.
    #[test]
    fn recent_for_and_count_since_for_span_both_lanes() {
        let t0 = SystemTime::now();
        let ring = AuditRing::with_lane_capacities(8, 8);
        ring.append_in(
            AuditLane::Evidence,
            entry_of(Frontend::Operator, None, "op-e1"),
        );
        ring.append_in(
            AuditLane::Routine,
            entry_of(Frontend::Mcp, Some("A"), "ag-r1"),
        );
        ring.append_in(
            AuditLane::Evidence,
            entry_of(Frontend::Mcp, Some("B"), "ag-e2"),
        );
        ring.append_in(
            AuditLane::Routine,
            entry_of(Frontend::Operator, None, "op-r2"),
        );
        ring.append_in(
            AuditLane::Evidence,
            entry_of(Frontend::Mcp, Some("A"), "ag-e3"),
        );

        assert_eq!(
            commands(&ring.recent_for(Frontend::Mcp, None, None)),
            ["ag-r1", "ag-e2", "ag-e3"]
        );
        assert_eq!(
            commands(&ring.recent_for(Frontend::Mcp, None, Some(2))),
            ["ag-e2", "ag-e3"]
        );
        assert_eq!(
            commands(&ring.recent_for(Frontend::Operator, None, Some(3))),
            ["ag-e2", "op-r2", "ag-e3"]
        );
        assert_eq!(commands(&ring.recent(None, Some(2))), ["op-r2", "ag-e3"]);

        assert_eq!(ring.count_since_for(Frontend::Mcp, t0, None), 3);
        assert_eq!(ring.count_since_for(Frontend::Operator, t0, None), 5);
        assert_eq!(ring.count_since_for(Frontend::Mcp, t0, Some("A")), 1);
        assert_eq!(ring.count_since_for(Frontend::Operator, t0, Some("A")), 3);
    }

    /// Eight entries over both lanes with explicit instants and ids, in call order
    /// (`E` is the evidence lane, `R` the routine lane; the id is the connection):
    ///
    /// | seq | lane | origin   | id  | command | at (ms) |
    /// |-----|------|----------|-----|---------|---------|
    /// | 0   | E    | Mcp      | A   | e-ag0   | 1000    |
    /// | 1   | R    | Operator | O   | r-op1   | 2000    |
    /// | 2   | R    | Mcp      | B   | r-ag2   | 3000    |
    /// | 3   | E    | Operator | O   | e-op3   | 4000    |
    /// | 4   | E    | Mcp      | A   | e-ag4   | 5000    |
    /// | 5   | R    | Mcp      | B   | r-ag5   | 6000    |
    /// | 6   | E    | Operator | O   | e-op6   | 7000    |
    /// | 7   | R    | Mcp      | A   | r-ag7   | 8000    |
    ///
    /// Connection A has entries in both lanes (seq 0, 4 in E; 7 in R), so does O
    /// (seq 1 in R; 3, 6 in E); B is routine only. Call order interleaves the
    /// lanes, so a read that concatenated one lane after the other would reorder.
    fn two_lane_ring() -> AuditRing {
        let ring = AuditRing::with_lane_capacities(8, 8);
        for (lane, origin, id, command, ms) in [
            (AuditLane::Evidence, Frontend::Mcp, "A", "e-ag0", 1000),
            (AuditLane::Routine, Frontend::Operator, "O", "r-op1", 2000),
            (AuditLane::Routine, Frontend::Mcp, "B", "r-ag2", 3000),
            (AuditLane::Evidence, Frontend::Operator, "O", "e-op3", 4000),
            (AuditLane::Evidence, Frontend::Mcp, "A", "e-ag4", 5000),
            (AuditLane::Routine, Frontend::Mcp, "B", "r-ag5", 6000),
            (AuditLane::Evidence, Frontend::Operator, "O", "e-op6", 7000),
            (AuditLane::Routine, Frontend::Mcp, "A", "r-ag7", 8000),
        ] {
            ring.append_in(lane, entry_at_ms(origin, Some(id), command, ms));
        }
        ring
    }

    /// `recent_for` with `since`, the viewer filter and `limit` all active over
    /// entries held in both lanes. A `recent_for` that ignored `since`, read it as
    /// inclusive, applied `limit` before the filter, or skipped the call-order sort
    /// across the lanes fails here;
    /// `recent_for_and_count_since_for_span_both_lanes` pins the filter and the
    /// limit over both lanes without `since`.
    #[test]
    fn recent_for_across_both_lanes_combines_since_the_filter_and_the_limit() {
        let ring = two_lane_ring();

        // No `since`, no `limit`: call order across the two lanes, not lane order
        // (lane order would put e-ag4 before r-ag2).
        assert_eq!(
            commands(&ring.recent_for(Frontend::Mcp, None, None)),
            ["e-ag0", "r-ag2", "e-ag4", "r-ag5", "r-ag7"]
        );
        // `since` is strictly after: r-ag2 sits exactly at 3000 and is out.
        assert_eq!(
            commands(&ring.recent_for(Frontend::Mcp, Some(at_ms(3000)), None)),
            ["e-ag4", "r-ag5", "r-ag7"]
        );
        // One millisecond earlier and it is back in.
        assert_eq!(
            commands(&ring.recent_for(Frontend::Mcp, Some(at_ms(2999)), None)),
            ["r-ag2", "e-ag4", "r-ag5", "r-ag7"]
        );
        // `limit` counts what survives `since` AND the filter, newest kept. Taking
        // the last 2 before the filter would give the operator's e-op6 and r-ag7,
        // and so only ["r-ag7"].
        assert_eq!(
            commands(&ring.recent_for(Frontend::Mcp, Some(at_ms(3000)), Some(2))),
            ["r-ag5", "r-ag7"]
        );
        assert_eq!(
            commands(&ring.recent_for(Frontend::Mcp, Some(at_ms(3000)), Some(1))),
            ["r-ag7"]
        );
        // A limit above what is visible pads nothing.
        assert_eq!(
            commands(&ring.recent_for(Frontend::Mcp, Some(at_ms(3000)), Some(50))),
            ["e-ag4", "r-ag5", "r-ag7"]
        );
        // A window that starts at the newest entry holds nothing, for every viewer.
        for viewer in [Frontend::Mcp, Frontend::Operator, Frontend::Cli] {
            assert_eq!(
                commands(&ring.recent_for(viewer, Some(at_ms(8000)), None)),
                Vec::<&str>::new()
            );
        }
        // Trusted control sees both lanes' operator entries, same window and limit.
        for viewer in [Frontend::Operator, Frontend::Cli] {
            assert_eq!(
                commands(&ring.recent_for(viewer, Some(at_ms(4000)), None)),
                ["e-ag4", "r-ag5", "e-op6", "r-ag7"]
            );
            assert_eq!(
                commands(&ring.recent_for(viewer, Some(at_ms(4000)), Some(3))),
                ["r-ag5", "e-op6", "r-ag7"]
            );
        }
        // The unfiltered read is unchanged by all of the above.
        assert_eq!(ring.recent(None, None).len(), 8);
    }

    /// `count_since_for` with the window edge, the viewer filter and the connection
    /// exclusion over both lanes, where the excluded connection's entries sit in
    /// both. AC29 pins the exclusion over both lanes at `t0` (every entry in the
    /// window); a count that dropped an entry from one lane when excluding, or
    /// mixed the edge up with `recent_for`'s strict one, passes it.
    #[test]
    fn count_since_for_across_both_lanes_combines_the_window_the_filter_and_the_exclusion() {
        let ring = two_lane_ring();

        // The window edge is inclusive: r-ag2 at 3000 counts at 3000, not at 3001.
        assert_eq!(ring.count_since_for(Frontend::Mcp, at_ms(3000), None), 4);
        assert_eq!(ring.count_since_for(Frontend::Mcp, at_ms(3001), None), 3);
        // A is in both lanes (e-ag4 evidence, r-ag7 routine): both go.
        assert_eq!(
            ring.count_since_for(Frontend::Mcp, at_ms(3000), Some("A")),
            2
        );
        // B is routine only (r-ag2, r-ag5).
        assert_eq!(
            ring.count_since_for(Frontend::Mcp, at_ms(3000), Some("B")),
            2
        );
        // Trusted control counts everything in the window, then drops its own id
        // from both lanes: O has r-op1 (routine) and e-op3, e-op6 (evidence).
        assert_eq!(
            ring.count_since_for(Frontend::Operator, at_ms(2000), None),
            7
        );
        assert_eq!(
            ring.count_since_for(Frontend::Operator, at_ms(2000), Some("O")),
            4
        );
        // From 4000 the window holds 5 entries: O's e-op3 and e-op6, A's e-ag4 and
        // r-ag7, B's r-ag5. Excluding O leaves A's two and B's one.
        assert_eq!(
            ring.count_since_for(Frontend::Operator, at_ms(4000), Some("O")),
            3
        );
        // The Cli viewer counts as the operator does.
        assert_eq!(
            ring.count_since_for(Frontend::Cli, at_ms(2000), Some("O")),
            4
        );
        // Excluding an id the viewer may not see changes nothing: an agent that
        // names the operator's id learns nothing and lowers nothing.
        assert_eq!(ring.count_since_for(Frontend::Mcp, at_ms(0), Some("O")), 5);
        assert_eq!(ring.count_since_for(Frontend::Mcp, at_ms(0), None), 5);
        // An empty id names no connection: it must not match the entries that have
        // no id, so nothing is excluded.
        assert_eq!(
            ring.count_since_for(Frontend::Operator, at_ms(0), Some("")),
            8
        );
        // ...including when the ring does hold an entry with no id: an in-process or
        // HTTP-POST call is `None`, and an empty excluded id must not match it.
        let mixed = AuditRing::new(8);
        mixed.append_in(
            AuditLane::Evidence,
            entry_at_ms(Frontend::Mcp, None, "anon-e", 1000),
        );
        mixed.append_in(
            AuditLane::Routine,
            entry_at_ms(Frontend::Mcp, None, "anon-r", 2000),
        );
        mixed.append_in(
            AuditLane::Routine,
            entry_at_ms(Frontend::Mcp, Some("A"), "own", 3000),
        );
        assert_eq!(mixed.count_since_for(Frontend::Mcp, at_ms(0), Some("")), 3);
        assert_eq!(mixed.count_since_for(Frontend::Mcp, at_ms(0), Some("A")), 2);
        assert_eq!(mixed.count_since_for(Frontend::Mcp, at_ms(0), None), 3);
        // A window after every entry counts nothing.
        assert_eq!(
            ring.count_since_for(Frontend::Mcp, at_ms(9000), Some("A")),
            0
        );
        assert_eq!(
            ring.count_since_for(Frontend::Operator, at_ms(9000), None),
            0
        );
    }

    /// An entry's `connection_id` belongs to the entry: eviction removes whole
    /// entries and never rewrites a survivor's id, and the id is not part of the
    /// source key. Two connections of one `(origin, label)` source (the web
    /// bridge's case: every agent-token connection is `(mcp, web-bridge)`) share
    /// one bucket, so the lane evicts the oldest entry of the pair, whichever
    /// connection made it, yet every survivor still names its own connection. A
    /// ring that bucketed by id would evict from the connection with more entries
    /// instead (spec A3: "the id is a read-side attribute").
    #[test]
    fn a_connection_id_survives_lane_eviction_and_is_not_a_bucket_key() {
        let bridge = |id: &str, command: &str| AuditEntry {
            client_label: Some(WEB_BRIDGE_CLIENT_LABEL.to_string()),
            ..entry_of(Frontend::Mcp, Some(id), command)
        };
        let ids = |entries: &[AuditEntry]| -> Vec<Option<String>> {
            entries.iter().map(|e| e.connection_id.clone()).collect()
        };
        let some = |id: &str| Some(id.to_string());
        let ring = AuditRing::with_lane_capacities(4, 2);

        // Evidence lane, capacity 4. C1 a1; C2 b1 b2 b3; C1 a2: the fifth entry
        // evicts the oldest of the one shared bucket, a1 (C1's). A bucket per
        // connection would hold C2's three against C1's two and evict b1.
        for (id, command) in [
            ("C1", "a1"),
            ("C2", "b1"),
            ("C2", "b2"),
            ("C2", "b3"),
            ("C1", "a2"),
        ] {
            ring.append(bridge(id, command));
        }
        let held = ring.recent(None, None);
        assert_eq!(commands(&held), ["b1", "b2", "b3", "a2"]);
        assert_eq!(ids(&held), [some("C2"), some("C2"), some("C2"), some("C1")]);

        // Routine lane, capacity 2, same source: r1 is evicted, r2 and r3 keep
        // their own ids and the evidence lane is untouched.
        for (id, command) in [("C1", "r1"), ("C2", "r2"), ("C1", "r3")] {
            ring.append_in(AuditLane::Routine, bridge(id, command));
        }
        assert_eq!(ring.evidence_len(), 4);
        assert_eq!(ring.routine_len(), 2);
        let held = ring.recent(None, None);
        assert_eq!(commands(&held), ["b1", "b2", "b3", "a2", "r2", "r3"]);
        assert_eq!(
            ids(&held),
            [
                some("C2"),
                some("C2"),
                some("C2"),
                some("C1"),
                some("C2"),
                some("C1")
            ]
        );
        // The viewer-filtered read and the count see the same survivors and ids.
        assert_eq!(ids(&ring.recent_for(Frontend::Mcp, None, None)), ids(&held));
        // Six survivors: C1 made a2 and r3, C2 made the other four.
        assert_eq!(
            ring.count_since_for(Frontend::Mcp, UNIX_EPOCH, Some("C1")),
            4
        );
        assert_eq!(
            ring.count_since_for(Frontend::Mcp, UNIX_EPOCH, Some("C2")),
            2
        );

        // Past the source table (the overflow bucket shares entries of many
        // sources) every entry still carries the id of the connection that made it.
        let sources = MAX_AUDIT_SOURCES + 8;
        let wide = AuditRing::with_lane_capacities(sources * 2, 1);
        for i in 0..sources {
            wide.append(AuditEntry {
                client_label: Some(format!("src-{i}")),
                ..entry_of(Frontend::Mcp, Some(&format!("id-{i}")), &format!("c{i}"))
            });
        }
        let held = wide.recent(None, None);
        assert_eq!(held.len(), sources);
        assert_eq!(
            ids(&held),
            (0..sources)
                .map(|i| Some(format!("id-{i}")))
                .collect::<Vec<_>>()
        );
    }

    /// Every whitespace character the sanitiser treats as noise (the five ASCII
    /// whitespace controls, NEL, and the line and paragraph separators).
    const WHITESPACE_NOISE: [char; 8] = [
        '\t', '\n', '\u{B}', '\u{C}', '\r', '\u{85}', '\u{2028}', '\u{2029}',
    ];

    /// The R2 port, for every whitespace noise character. The plan's literals pin
    /// `\t`, `\n`, U+0085 and U+2028 for the `Bearer` frame; `\r`, U+000B (vertical
    /// tab), U+000C (form feed) and U+2029 (paragraph separator) are the same bug
    /// if the blank substitution misses them: `Bearer\u{B}abc123` would be joined
    /// into `Bearerabc123`, which no scrubber frame matches, and the token would
    /// reach the ring, the push, `agent.activity` and the findings store.
    #[test]
    fn sanitize_client_label_masks_a_credential_after_every_whitespace_control() {
        for c in WHITESPACE_NOISE {
            let bearer = format!("agent Bearer{c}abc123");
            let label = sanitize_client_label(&bearer).expect("a label remains");
            assert!(
                !label.contains("abc123"),
                "{bearer:?} leaked the token: {label:?}"
            );
            assert!(
                label.contains("Bearer [redacted]"),
                "{bearer:?} was not masked as a bearer token: {label:?}"
            );
            // The pair frames do not need the blank, so they hold either way; they
            // must keep holding with the blank in place.
            for (raw, secret) in [
                (format!("agent token{c}=abc123"), "abc123"),
                (format!("password{c}: hunter2"), "hunter2"),
            ] {
                let label = sanitize_client_label(&raw).expect("a label remains");
                assert!(!label.contains(secret), "{raw:?} leaked: {label:?}");
                assert!(
                    label.contains("[redacted]"),
                    "{raw:?} not masked: {label:?}"
                );
            }
        }
    }

    /// A whitespace control is one blank, wherever it sits, and the blank counts
    /// toward the 64-character cut like any other character. The blank is what the
    /// existing `trim()` calls then act on at the edges: a whitespace control at the
    /// start or end of a label never survives as a blank, and a label made only of
    /// them is no label.
    #[test]
    fn sanitize_client_label_whitespace_controls_are_one_blank_each_and_count_toward_the_cap() {
        for c in WHITESPACE_NOISE {
            // Inside: one blank, never nothing (the label would be joined) and never
            // collapsed (two controls make two blanks).
            assert_eq!(
                sanitize_client_label(&format!("a{c}b")),
                Some("a b".to_string()),
                "{c:?} inside a label"
            );
            assert_eq!(
                sanitize_client_label(&format!("a{c}{c}b")),
                Some("a  b".to_string()),
                "two {c:?} inside a label"
            );
            // At the edges: the substituted blank is trimmed, so the label is bare.
            for raw in [
                format!("{c}label"),
                format!("label{c}"),
                format!("{c}{c}label{c}{c}"),
            ] {
                assert_eq!(
                    sanitize_client_label(&raw),
                    Some("label".to_string()),
                    "{raw:?}"
                );
            }
        }
        // Nothing but whitespace controls leaves nothing.
        assert_eq!(
            sanitize_client_label(&WHITESPACE_NOISE.iter().collect::<String>()),
            None
        );

        // The substituted blanks are characters of the label: 30 + 3 + 40 is 73
        // characters, cut to 64, keeps the three blanks and 31 of the 40 `B`s. Had
        // the controls been deleted the label would hold 34 `B`s and no blanks.
        let raw = format!("{}\t\r\u{2029}{}", "A".repeat(30), "B".repeat(40));
        assert_eq!(
            sanitize_client_label(&raw),
            Some(format!("{}   {}", "A".repeat(30), "B".repeat(31)))
        );
        // A cut that lands on a substituted blank leaves no trailing blank.
        let raw = format!("{}\u{B}B", "A".repeat(63));
        assert_eq!(sanitize_client_label(&raw), Some("A".repeat(63)));

        // The 1024-character scan window counts raw characters, before any
        // substitution: 1024 controls use it all up, and one fewer leaves room for
        // the first visible character.
        let spent = format!("{}tail", "\t".repeat(1024));
        assert_eq!(sanitize_client_label(&spent), None);
        let room = format!("{}ab", "\u{C}".repeat(1023));
        assert_eq!(sanitize_client_label(&room), Some("a".to_string()));
    }
}
