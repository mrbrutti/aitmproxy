//! The issue store and the spec D6 dedupe key.
//!
//! One weakness at one place is one [`Issue`], however many checks report it:
//! [`dedupe_key`] hashes the *place* (and the class), never the check, so two
//! checks that find one class on one insertion point raise the occurrence count
//! of a single issue and keep the higher-confidence evidence. A passive check
//! dedupes per origin instead and lists the paths it saw in `evidence.matched`.
//!
//! [`IssueStore`] holds them for the life of the process and, when the operator
//! configured `findings.dir`, writes each one to
//! `<findings.dir>/scan/issues/<id>.json` with a `key -> id` `index.json` beside
//! it (spec D6/D11), so a restart keeps triage state and keeps deduping against
//! what earlier jobs found. With no findings directory the store is memory only
//! and nothing is written.
//!
//! The store is the read model behind `scan.issues` (filters, severity-ordered
//! pages, a decimal-offset cursor, a tally of the whole filtered set),
//! `scan.issue`, `scan.issue.update` and the `issues_md` section of
//! `scan.report`.

use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap};
use std::fmt::Write as _;
use std::fs;
use std::io;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};

use anyhow::Context;

use aitm_poc::Severity;
use aitm_scan_model::{
    scan_error, BySeverity, Confidence, Evidence, InsertionKind, Issue, IssueId, IssueLocation,
    IssueStatus, IssueTarget, IssuesResult, JobId, L4Transport, LaneKind, ScanErrorCode,
};

use crate::util::{issue_id, normalize_origin, origin_key, scan_dir, scrub, wire_token};

/// The separator between the fields of a dedupe key's preimage. Every field is
/// length-prefixed (see [`field`]), so the boundaries are fixed by the lengths
/// and the separator is only there to keep the preimage readable.
const FIELD_SEP: &str = "\u{1f}";

/// How an absent optional field is written into a key preimage, and how an
/// absent method reads in a rendered location. A *present* optional field is
/// written `+<len>:<bytes>` (see [`optional`]), so `None` and `Some("-")` can
/// never share a preimage.
const ABSENT: &str = "-";

/// The largest page [`IssueStore::query`] returns, whatever the caller asks for
/// (spec D3: `limit? (<=1024)`).
pub const MAX_ISSUE_PAGE: usize = 1024;

/// How many times [`IssueStore::upsert`] re-mints an issue id before it gives
/// up.
///
/// `util::issue_id()` is 32 bits of randomness and nothing outside this store
/// checks it, so a candidate that is already taken — in memory or on disk — is
/// discarded rather than allowed to overwrite another issue's file. Eight
/// attempts is far past the point where a repeated collision means a broken
/// random source rather than bad luck.
const MAX_ID_ATTEMPTS: usize = 8;

/// The `key -> id` map written beside the issue files.
const INDEX_FILE: &str = "index.json";

/// The key the on-disk form of an issue carries beyond the [`Issue`] fields, so
/// the dedupe index can be rebuilt from the issue files alone when
/// [`INDEX_FILE`] is missing or truncated.
const KEY_FIELD: &str = "dedupe_key";

/// What the dedupe key is computed over (spec D6).
///
/// `check_id` is deliberately not a field of any variant: the key identifies the
/// weakness and the place, so a second check finding the same thing merges.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DedupeInput<'a> {
    /// An HTTP or WebSocket issue at one insertion point.
    Http {
        /// The weakness class.
        class: &'a str,
        /// The origin's scheme.
        scheme: &'a str,
        /// The origin's host.
        host: &'a str,
        /// The origin's port.
        port: u16,
        /// The request method.
        method: &'a str,
        /// The path with volatile segments templated.
        path_template: &'a str,
        /// The insertion kind.
        kind: InsertionKind,
        /// The parameter, header, cookie or field name.
        name: &'a str,
        /// The field path inside a structured body.
        field_path: Option<&'a str>,
    },
    /// A passive issue, which dedupes per origin: the paths are listed in the
    /// issue's `evidence.matched` instead of splitting it into one issue each.
    Passive {
        /// The weakness class.
        class: &'a str,
        /// The origin's scheme.
        scheme: &'a str,
        /// The origin's host.
        host: &'a str,
        /// The origin's port.
        port: u16,
    },
    /// A layer 4 issue at one target, grammar field and mutation.
    L4 {
        /// The weakness class.
        class: &'a str,
        /// The target IP.
        ip: &'a str,
        /// The target port.
        port: u16,
        /// The transport.
        proto: L4Transport,
        /// The grammar the message was built from.
        grammar: Option<&'a str>,
        /// The field path inside the message.
        field_path: Option<&'a str>,
        /// The class of mutation that provoked the issue.
        mutation_class: Option<&'a str>,
    },
}

/// The spec D6 dedupe key: the blake3 hex digest of the variant tag and every
/// field, each length-prefixed ([`field`]), an absent option written
/// [`ABSENT`] and a present one tagged ([`optional`]), joined by [`FIELD_SEP`].
///
/// The tag is part of the preimage so a passive key and an HTTP key over the
/// same origin can never collide; the length prefixes mean no field's bytes —
/// a separator in a path, an empty name — can shift the boundaries between
/// fields, so two different tuples can never share a preimage.
///
/// The preimage layout is the store format of every issue file's key: a
/// change here moves every pinned key (`dedupe_key_is_pinned_across_process_runs_and_variants_never_collide`).
pub fn dedupe_key(input: &DedupeInput<'_>) -> String {
    let fields: Vec<String> = match input {
        DedupeInput::Http {
            class,
            scheme,
            host,
            port,
            method,
            path_template,
            kind,
            name,
            field_path,
        } => vec![
            field("http"),
            field(class),
            field(scheme),
            field(host),
            field(&port.to_string()),
            field(method),
            field(path_template),
            field(&wire_token(kind)),
            field(name),
            optional(*field_path),
        ],
        DedupeInput::Passive {
            class,
            scheme,
            host,
            port,
        } => vec![
            field("passive"),
            field(class),
            field(scheme),
            field(host),
            field(&port.to_string()),
        ],
        DedupeInput::L4 {
            class,
            ip,
            port,
            proto,
            grammar,
            field_path,
            mutation_class,
        } => vec![
            field("l4"),
            field(class),
            field(ip),
            field(&port.to_string()),
            field(&wire_token(proto)),
            optional(*grammar),
            optional(*field_path),
            optional(*mutation_class),
        ],
    };
    blake3::hash(fields.join(FIELD_SEP).as_bytes())
        .to_hex()
        .to_string()
}

/// A key field as it is written into a preimage: `<len>:<bytes>`, so the
/// field's own bytes can never be read as a boundary.
fn field(value: &str) -> String {
    format!("{}:{value}", value.len())
}

/// An optional key field as it is written into a preimage: [`ABSENT`] for
/// `None`, `+<len>:<bytes>` for `Some`, so `None` and `Some("-")` differ.
fn optional(value: Option<&str>) -> String {
    match value {
        None => ABSENT.to_string(),
        Some(value) => format!("+{}", field(value)),
    }
}

/// Whether `id` has the spec D6 shape `issue-<8 lowercase hex>` — the only
/// shape an issue id is trusted as a file name in.
fn is_issue_id(id: &str) -> bool {
    id.strip_prefix("issue-").is_some_and(|hex| {
        hex.len() == 8
            && hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

/// One interpolated field of the Markdown report, rendered *inline*: scrubbed,
/// every `\r`/`\n` collapsed to a space so a field cannot start a line (a
/// heading, a list item) of its own, and every backtick escaped so it cannot
/// close the code span it is quoted in. Every attacker-reachable string in
/// `issues_md` goes through here.
fn md_inline(text: &str) -> String {
    let scrubbed = scrub(text);
    let mut out = String::with_capacity(scrubbed.len());
    for ch in scrubbed.chars() {
        match ch {
            '\r' | '\n' => out.push(' '),
            '`' => out.push_str("\\`"),
            other => out.push(other),
        }
    }
    out
}

/// What a lane or check hands the store: an issue without the fields the store
/// owns (`id`, `status`, the timestamps, the occurrence count and the links).
#[derive(Debug, Clone, PartialEq)]
pub struct NewIssue {
    /// The job that found it.
    pub job: JobId,
    /// The check that reported it.
    pub check_id: String,
    /// The weakness class; part of the dedupe key.
    pub class: String,
    /// The human-readable name.
    pub name: String,
    /// The severity.
    pub severity: Severity,
    /// How sure the reporting check is.
    pub confidence: Confidence,
    /// The lane the issue belongs to.
    pub lane: LaneKind,
    /// The origin.
    pub target: IssueTarget,
    /// Where it sits inside the request.
    pub location: IssueLocation,
    /// The bounded, already-scrubbed proof.
    pub evidence: Evidence,
    /// What the weakness is.
    pub description: String,
    /// What to do about it.
    pub remediation: Option<String>,
    /// Whether the reporting check is passive, which selects the per-origin
    /// dedupe key and the path-list consolidation of spec D6.
    pub passive: bool,
}

/// What [`IssueStore::upsert`] did: a new issue, or another sighting of one the
/// store already held.
#[derive(Debug, Clone, PartialEq)]
pub enum Upsert {
    /// The point was new; this is the issue the store minted.
    Created(Issue),
    /// The point was known; this is the issue after the merge.
    Merged(Issue),
}

impl Upsert {
    /// The issue, whichever arm this is.
    pub fn issue(&self) -> &Issue {
        match self {
            Upsert::Created(issue) | Upsert::Merged(issue) => issue,
        }
    }
}

/// Which issues `scan.issues` asks for (spec D3). Every field is a narrowing;
/// the default filter matches everything.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct IssueFilter {
    /// Only issues found by this job.
    pub job: Option<String>,
    /// Only issues on this origin (`scheme://host[:port]`, or a bare host).
    pub target: Option<String>,
    /// Only issues at least this severe.
    pub severity_min: Option<Severity>,
    /// Only issues at least this confident.
    pub confidence_min: Option<Confidence>,
    /// Only issues of this class.
    pub class: Option<String>,
    /// Only issues from this lane.
    pub lane: Option<LaneKind>,
    /// Only issues in this triage state.
    pub status: Option<IssueStatus>,
    /// Only issues last seen at or after this epoch-millisecond timestamp.
    pub since_ms: Option<u64>,
}

impl IssueFilter {
    /// Whether `issue` passes every narrowing this filter sets.
    fn matches(&self, issue: &Issue) -> bool {
        if let Some(job) = &self.job {
            if &issue.job != job {
                return false;
            }
        }
        if let Some(target) = &self.target {
            if !target_matches(&issue.target, target) {
                return false;
            }
        }
        if let Some(min) = self.severity_min {
            if severity_rank(issue.severity) < severity_rank(min) {
                return false;
            }
        }
        if let Some(min) = self.confidence_min {
            if issue.confidence < min {
                return false;
            }
        }
        if let Some(class) = &self.class {
            if &issue.class != class {
                return false;
            }
        }
        if let Some(lane) = self.lane {
            if issue.lane != lane {
                return false;
            }
        }
        if let Some(status) = self.status {
            if issue.status != status {
                return false;
            }
        }
        if let Some(since) = self.since_ms {
            if issue.last_seen < since {
                return false;
            }
        }
        true
    }
}

/// The issues one process knows about, deduped by spec D6 and — when the
/// operator configured `findings.dir` — persisted under `<dir>/scan/issues/`.
#[derive(Debug)]
pub struct IssueStore {
    inner: RwLock<Inner>,
    dir: Option<PathBuf>,
}

/// The two maps the store keeps: the dedupe index and the issues themselves,
/// ordered by id so every unfiltered walk is deterministic.
#[derive(Debug, Default)]
struct Inner {
    by_key: HashMap<String, IssueId>,
    issues: BTreeMap<IssueId, Issue>,
}

impl IssueStore {
    /// An empty store. `findings_dir` is the configured `findings.dir`; the
    /// store writes under `<dir>/scan/issues/` and is memory only when it is
    /// `None` (spec D11).
    pub fn new(findings_dir: Option<&Path>) -> Self {
        Self {
            inner: RwLock::new(Inner::default()),
            dir: findings_dir.map(|dir| scan_dir(dir, "issues")),
        }
    }

    /// Where this store writes, when it writes at all.
    pub fn dir(&self) -> Option<&Path> {
        self.dir.as_deref()
    }

    /// Read the issues on disk into the store, returning how many were read.
    ///
    /// Every `*.json` but [`INDEX_FILE`] is an issue. The dedupe index is
    /// rebuilt from each file's own [`KEY_FIELD`] and then overlaid with
    /// [`INDEX_FILE`] when it is there, so a lost or partial index costs
    /// nothing. A store with no directory, or whose directory does not exist
    /// yet, reads nothing and is not an error; a file that is there but
    /// unreadable or not an issue is, because silently dropping an operator's
    /// triage state is worse than refusing to start.
    pub fn load(&self) -> anyhow::Result<usize> {
        let Some(dir) = self.dir.as_ref() else {
            return Ok(0);
        };
        let entries = match fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(0),
            Err(e) => return Err(e).with_context(|| format!("read {}", dir.display())),
        };

        let mut inner = self.write();
        let mut loaded = 0usize;
        for entry in entries {
            let entry = entry.with_context(|| format!("read {}", dir.display()))?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            if path.file_name().and_then(|n| n.to_str()) == Some(INDEX_FILE) {
                continue;
            }
            let text =
                fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
            let value: serde_json::Value =
                serde_json::from_str(&text).with_context(|| format!("parse {}", path.display()))?;
            let key = value
                .get(KEY_FIELD)
                .and_then(serde_json::Value::as_str)
                .map(str::to_string);
            let issue: Issue = serde_json::from_value(value)
                .with_context(|| format!("parse {}", path.display()))?;
            // The id names the file every later write goes to, so it is
            // trusted only when it *is* this file's name: `issue-<8 hex>` and
            // equal to the stem. Anything else (`../../x`, another issue's id)
            // is refused here rather than written somewhere later.
            let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
            if !is_issue_id(&issue.id) || issue.id != stem {
                anyhow::bail!(
                    "refusing {}: its id `{}` is not the file's name \
                     (an issue id is `issue-<8 hex>` and names its own file)",
                    path.display(),
                    scrub(&issue.id)
                );
            }
            if let Some(key) = key {
                inner.by_key.insert(key, issue.id.clone());
            }
            inner.issues.insert(issue.id.clone(), issue);
            loaded += 1;
        }

        let index_path = dir.join(INDEX_FILE);
        match fs::read_to_string(&index_path) {
            Ok(text) => {
                let index: BTreeMap<String, IssueId> = serde_json::from_str(&text)
                    .with_context(|| format!("parse {}", index_path.display()))?;
                for (key, id) in index {
                    if inner.issues.contains_key(&id) {
                        inner.by_key.insert(key, id);
                    }
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).with_context(|| format!("read {}", index_path.display())),
        }

        Ok(loaded)
    }

    /// Record a sighting: a new issue, or another occurrence of one the store
    /// already holds (spec D6).
    ///
    /// A repeat raises the occurrence count and `last_seen`, raises
    /// `confidence` to the strongest seen and never lowers it, and keeps the
    /// evidence of the most confident sighting. A passive repeat also adds the
    /// path to the issue's `evidence.matched` list.
    pub fn upsert(&self, new: NewIssue, now_ms: u64) -> anyhow::Result<Upsert> {
        self.upsert_with_mint(new, now_ms, &mut issue_id)
    }

    /// [`IssueStore::upsert`] with the id source injected, so the collision
    /// path is testable without waiting for a 32-bit birthday.
    fn upsert_with_mint(
        &self,
        new: NewIssue,
        now_ms: u64,
        mint: &mut dyn FnMut() -> IssueId,
    ) -> anyhow::Result<Upsert> {
        let key = dedupe_key(&key_input(&new));
        let mut inner = self.write();

        if let Some(id) = inner.by_key.get(&key).cloned() {
            if let Some(existing) = inner.issues.get_mut(&id) {
                merge_into(existing, &new, now_ms);
                let merged = existing.clone();
                self.persist(&inner, Some(&key), &merged)?;
                return Ok(Upsert::Merged(merged));
            }
            // The index named an issue the store does not hold (a hand-edited
            // or half-deleted directory). Drop the stale entry and create.
            inner.by_key.remove(&key);
        }

        let mut issue = Issue {
            id: String::new(),
            job: new.job,
            check_id: new.check_id,
            class: new.class,
            name: new.name,
            severity: new.severity,
            confidence: new.confidence,
            status: IssueStatus::Open,
            lane: new.lane,
            target: new.target,
            evidence: new.evidence,
            first_seen: now_ms,
            last_seen: now_ms,
            occurrences: 1,
            poc_ref: None,
            finding_id: None,
            description: new.description,
            remediation: new.remediation,
            note: None,
            location: new.location,
        };
        if new.passive {
            issue.evidence.matched = Some(merged_paths(None, &issue.location.path));
        }

        for _ in 0..MAX_ID_ATTEMPTS {
            let candidate = mint();
            if inner.issues.contains_key(&candidate) {
                continue;
            }
            issue.id = candidate;
            // The file is created exclusively, so an id another process (or an
            // earlier run this store never loaded) already used is a collision
            // here rather than a silent overwrite there.
            if !self.create_file(&key, &issue)? {
                continue;
            }
            inner.by_key.insert(key.clone(), issue.id.clone());
            inner.issues.insert(issue.id.clone(), issue.clone());
            self.write_index(&inner)?;
            return Ok(Upsert::Created(issue));
        }

        // Not a verb refusal — no spec D3 code describes "the random source
        // keeps repeating itself" — so this error carries no `scan:` prefix.
        Err(anyhow::anyhow!(
            "issue store: no free issue id after {MAX_ID_ATTEMPTS} attempts"
        ))
    }

    /// One issue by id, or `None` when the store does not hold it.
    pub fn get(&self, id: &str) -> Option<Issue> {
        self.read().issues.get(id).cloned()
    }

    /// Triage an issue (`scan.issue.update`). A `None` note leaves the previous
    /// note alone; the verb's vocabulary has no way to clear one.
    pub fn update_status(
        &self,
        id: &str,
        status: IssueStatus,
        note: Option<String>,
    ) -> anyhow::Result<Issue> {
        let mut inner = self.write();
        let key = key_of(&inner, id);
        let Some(issue) = inner.issues.get_mut(id) else {
            return Err(scan_error(ScanErrorCode::NotFound, format!("issue {id}")));
        };
        issue.status = status;
        if let Some(note) = note {
            issue.note = Some(note);
        }
        let updated = issue.clone();
        self.persist(&inner, key.as_deref(), &updated)?;
        Ok(updated)
    }

    /// Link an issue to the PoC that reproduced it and the finding that was
    /// recorded for it (spec D6). A `None` argument leaves that link alone.
    pub fn set_links(
        &self,
        id: &str,
        poc_ref: Option<String>,
        finding_id: Option<String>,
    ) -> anyhow::Result<Issue> {
        let mut inner = self.write();
        let key = key_of(&inner, id);
        let Some(issue) = inner.issues.get_mut(id) else {
            return Err(scan_error(ScanErrorCode::NotFound, format!("issue {id}")));
        };
        if let Some(poc_ref) = poc_ref {
            issue.poc_ref = Some(poc_ref);
        }
        if let Some(finding_id) = finding_id {
            issue.finding_id = Some(finding_id);
        }
        let updated = issue.clone();
        self.persist(&inner, key.as_deref(), &updated)?;
        Ok(updated)
    }

    /// One page of issues (`scan.issues`), ordered severity desc, `first_seen`
    /// asc, id (call B12).
    ///
    /// `cursor` is the decimal offset of the next item, as `next_cursor`
    /// handed it out; anything else is `scan: not_found: cursor`.
    /// `by_severity` tallies the whole filtered set, not the page, and `limit`
    /// is capped at [`MAX_ISSUE_PAGE`]. A limit of zero would hand back a cursor
    /// that never advances, so one issue is the smallest page.
    pub fn query(
        &self,
        f: &IssueFilter,
        limit: usize,
        cursor: Option<&str>,
    ) -> anyhow::Result<IssuesResult> {
        let offset = match cursor {
            None => 0usize,
            Some(cursor) => cursor
                .parse::<usize>()
                .map_err(|_| scan_error(ScanErrorCode::NotFound, "cursor"))?,
        };
        let limit = limit.clamp(1, MAX_ISSUE_PAGE);

        let inner = self.read();
        let matched = sorted(&inner, f);
        let mut by_severity = BySeverity::default();
        for issue in &matched {
            by_severity.bump(issue.severity);
        }

        let issues: Vec<_> = matched
            .iter()
            .skip(offset)
            .take(limit)
            .map(|issue| issue.summary())
            .collect();
        let next = offset.saturating_add(issues.len());
        let next_cursor = (next < matched.len()).then(|| next.to_string());

        Ok(IssuesResult {
            issues,
            next_cursor,
            by_severity,
        })
    }

    /// Every issue one job found, in the `scan.issues` order.
    pub fn for_job(&self, job: &str) -> Vec<Issue> {
        let filter = IssueFilter {
            job: Some(job.to_string()),
            ..IssueFilter::default()
        };
        let inner = self.read();
        sorted(&inner, &filter).into_iter().cloned().collect()
    }

    /// How many issues the store holds.
    pub fn count(&self) -> usize {
        self.read().issues.len()
    }

    /// The `issues_md` section of `scan.report`: one section per issue, in the
    /// `scan.issues` order, every string through the scanner's one scrubber.
    ///
    /// `target` narrows to one origin; `None` renders them all. An empty store
    /// renders an empty string, so the report decides its own headings.
    pub fn render_issues_md(&self, target: Option<&str>) -> String {
        let filter = IssueFilter {
            target: target.map(str::to_string),
            ..IssueFilter::default()
        };
        let inner = self.read();

        let mut out = String::new();
        for issue in sorted(&inner, &filter) {
            // `write!` to a `String` cannot fail; the result is discarded
            // deliberately rather than unwrapped. Every string the target or
            // a check authored goes through `md_inline`, so it can only ever
            // be text inside its line.
            let _ = writeln!(
                out,
                "## {} {}\n",
                wire_token(&issue.severity),
                md_inline(&issue.name)
            );
            let _ = writeln!(out, "- Target: {}", md_inline(&origin_of(&issue.target)));
            let _ = writeln!(
                out,
                "- Location: {}",
                md_inline(&location_line(&issue.location))
            );
            let _ = writeln!(out, "- Confidence: {}", wire_token(&issue.confidence));
            let _ = writeln!(out, "- Occurrences: {}", issue.occurrences);
            if let Some(payload) = &issue.evidence.payload {
                let _ = writeln!(out, "- Payload: `{}`", md_inline(payload));
            }
            if let Some(matched) = &issue.evidence.matched {
                let _ = writeln!(out, "- Matched: `{}`", md_inline(matched));
            }
            out.push('\n');
        }
        out
    }

    // ---- locks and files --------------------------------------------------

    /// Read the store, recovering it if a writer panicked: a poisoned lock must
    /// not take the issue list down mid-scan.
    fn read(&self) -> RwLockReadGuard<'_, Inner> {
        self.inner.read().unwrap_or_else(|e| e.into_inner())
    }

    /// Write the store, recovering a poisoned lock the same way.
    fn write(&self) -> RwLockWriteGuard<'_, Inner> {
        self.inner.write().unwrap_or_else(|e| e.into_inner())
    }

    /// Write a brand new issue's file, refusing to touch a path that exists.
    ///
    /// `Ok(true)` — written, or there is no directory to write to. `Ok(false)` —
    /// the id is taken on disk, so the caller must mint another.
    fn create_file(&self, key: &str, issue: &Issue) -> anyhow::Result<bool> {
        let Some(dir) = self.dir.as_ref() else {
            return Ok(true);
        };
        fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
        let path = dir.join(format!("{}.json", issue.id));
        let text = issue_json(Some(key), issue)?;
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(mut file) => {
                file.write_all(text.as_bytes())
                    .with_context(|| format!("write {}", path.display()))?;
                Ok(true)
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(false),
            Err(e) => Err(e).with_context(|| format!("create {}", path.display())),
        }
    }

    /// Rewrite an issue that already exists, then the index. The file is
    /// written beside itself and renamed, so a crash leaves the previous
    /// version rather than half of the new one.
    fn persist(&self, inner: &Inner, key: Option<&str>, issue: &Issue) -> anyhow::Result<()> {
        let Some(dir) = self.dir.as_ref() else {
            return Ok(());
        };
        fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
        write_atomically(dir, &format!("{}.json", issue.id), &issue_json(key, issue)?)?;
        self.write_index(inner)
    }

    /// Write the `key -> id` index, sorted so the file is stable between runs.
    fn write_index(&self, inner: &Inner) -> anyhow::Result<()> {
        let Some(dir) = self.dir.as_ref() else {
            return Ok(());
        };
        let index: BTreeMap<&str, &str> = inner
            .by_key
            .iter()
            .map(|(key, id)| (key.as_str(), id.as_str()))
            .collect();
        let text = serde_json::to_string(&index).context("serialize the issue index")?;
        write_atomically(dir, INDEX_FILE, &text)
    }
}

/// The dedupe input one new issue keys on: per origin when the reporting check
/// is passive, on the L4 tuple when the location is an L4 one, else on the
/// insertion point (spec D6).
fn key_input(new: &NewIssue) -> DedupeInput<'_> {
    if new.passive {
        return DedupeInput::Passive {
            class: &new.class,
            scheme: &new.target.scheme,
            host: &new.target.host,
            port: new.target.port,
        };
    }
    if let Some(l4) = new.location.l4.as_ref() {
        return DedupeInput::L4 {
            class: &new.class,
            ip: &l4.ip,
            port: l4.port,
            proto: l4.proto,
            grammar: l4.grammar.as_deref(),
            field_path: l4.field_path.as_deref(),
            mutation_class: l4.mutation.as_deref(),
        };
    }
    DedupeInput::Http {
        class: &new.class,
        scheme: &new.target.scheme,
        host: &new.target.host,
        port: new.target.port,
        method: new.location.method.as_deref().unwrap_or(ABSENT),
        path_template: &new.location.path_template,
        kind: new.location.kind,
        name: &new.location.name,
        field_path: new.location.field_path.as_deref(),
    }
}

/// Fold another sighting into the issue the store already holds (spec D6).
fn merge_into(existing: &mut Issue, new: &NewIssue, now_ms: u64) {
    existing.occurrences = existing.occurrences.saturating_add(1);
    existing.last_seen = now_ms;

    // Read the paths before the evidence may be replaced: a passive issue's
    // path list survives a stronger sighting.
    let paths = new
        .passive
        .then(|| merged_paths(existing.evidence.matched.as_deref(), &new.location.path));

    if new.confidence > existing.confidence {
        existing.evidence = new.evidence.clone();
    }
    existing.confidence = existing.confidence.max(new.confidence);

    if let Some(paths) = paths {
        existing.evidence.matched = Some(paths);
    }
}

/// The `", "`-joined list of paths a passive issue was seen on, bounded by
/// [`Evidence::excerpt`] and scrubbed like every other evidence string.
fn merged_paths(previous: Option<&str>, path: &str) -> String {
    let path = scrub(path);
    let mut paths: Vec<&str> = previous
        .map(|seen| seen.split(", ").filter(|p| !p.is_empty()).collect())
        .unwrap_or_default();
    if !paths.contains(&path.as_str()) {
        paths.push(&path);
    }
    Evidence::excerpt(&paths.join(", "))
}

/// The dedupe key an issue is filed under, for the rewrite path.
///
/// A reverse walk of the index: the store keeps the plan's two maps, and a scan
/// of at most a few thousand keys is far cheaper than the file write it
/// precedes.
fn key_of(inner: &Inner, id: &str) -> Option<String> {
    inner
        .by_key
        .iter()
        .find(|(_, held)| held.as_str() == id)
        .map(|(key, _)| key.clone())
}

/// The issues matching `f`, ordered severity desc, `first_seen` asc, id.
fn sorted<'a>(inner: &'a Inner, f: &IssueFilter) -> Vec<&'a Issue> {
    let mut matched: Vec<&Issue> = inner.issues.values().filter(|i| f.matches(i)).collect();
    matched.sort_by(|a, b| order(a, b));
    matched
}

/// The `scan.issues` order (call B12).
fn order(a: &Issue, b: &Issue) -> Ordering {
    severity_rank(b.severity)
        .cmp(&severity_rank(a.severity))
        .then_with(|| a.first_seen.cmp(&b.first_seen))
        .then_with(|| a.id.cmp(&b.id))
}

/// How severe a severity is, highest last. `aitm_poc::Severity` is not `Ord`,
/// and the scanner must not change a shipped type to sort its own list.
fn severity_rank(severity: Severity) -> u8 {
    match severity {
        Severity::Info => 0,
        Severity::Low => 1,
        Severity::Medium => 2,
        Severity::High => 3,
        Severity::Critical => 4,
    }
}

/// An issue target as the operator writes an origin: the one normal form of
/// [`origin_key`] (`scheme://host`, the port kept when it is not the scheme's
/// default).
fn origin_of(target: &IssueTarget) -> String {
    origin_key(&target.scheme, &format!("{}:{}", target.host, target.port))
}

/// Whether `want` names this issue's origin: any spelling of the origin that
/// normalizes to it (case, a trailing slash, the default port spelled out), or
/// the bare host.
fn target_matches(target: &IssueTarget, want: &str) -> bool {
    match normalize_origin(want) {
        Ok(wanted) => wanted == origin_of(target),
        Err(_) => want
            .trim()
            .trim_end_matches('/')
            .eq_ignore_ascii_case(&target.host),
    }
}

/// One issue location on one line of the report.
fn location_line(location: &IssueLocation) -> String {
    let method = location.method.as_deref().unwrap_or(ABSENT);
    let mut line = format!(
        "{method} {} [{}] {}",
        location.path,
        wire_token(&location.kind),
        location.name
    );
    if let Some(l4) = &location.l4 {
        line.push_str(&format!(
            " ({}:{} {})",
            l4.ip,
            l4.port,
            wire_token(&l4.proto)
        ));
    }
    line.trim_end().to_string()
}

/// The on-disk form of an issue: its JSON plus the [`KEY_FIELD`] the index can
/// be rebuilt from. Compact, because these files are machine state, not a
/// report.
fn issue_json(key: Option<&str>, issue: &Issue) -> anyhow::Result<String> {
    let mut value =
        serde_json::to_value(issue).with_context(|| format!("serialize issue {}", issue.id))?;
    if let (Some(key), Some(object)) = (key, value.as_object_mut()) {
        object.insert(
            KEY_FIELD.to_string(),
            serde_json::Value::String(key.to_string()),
        );
    }
    serde_json::to_string(&value).with_context(|| format!("serialize issue {}", issue.id))
}

/// Write `name` under `dir` through a sibling temporary file, so a reader never
/// sees a half-written issue or index.
fn write_atomically(dir: &Path, name: &str, text: &str) -> anyhow::Result<()> {
    let path = dir.join(name);
    let tmp = dir.join(format!("{name}.tmp"));
    fs::write(&tmp, text).with_context(|| format!("write {}", tmp.display()))?;
    fs::rename(&tmp, &path).with_context(|| format!("rename {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use aitm_scan_model::L4Location;

    // ---- fixtures ---------------------------------------------------------

    fn target() -> IssueTarget {
        IssueTarget {
            scheme: "https".into(),
            host: "t.example".into(),
            port: 443,
        }
    }

    fn location(name: &str) -> IssueLocation {
        IssueLocation {
            method: Some("GET".into()),
            path: "/search".into(),
            path_template: "/search".into(),
            kind: InsertionKind::Query,
            name: name.into(),
            field_path: None,
            ws_path: None,
            l4: None,
        }
    }

    fn evidence(payload: &str) -> Evidence {
        Evidence {
            payload: Some(payload.into()),
            ..Evidence::default()
        }
    }

    /// One `reflected-xss` issue on `https://t.example:443 GET /search?<name>`.
    fn new_issue(check_id: &str, name: &str) -> NewIssue {
        NewIssue {
            job: "scan-01020304".into(),
            check_id: check_id.into(),
            class: "reflected-xss".into(),
            name: "Reflected XSS".into(),
            severity: Severity::High,
            confidence: Confidence::Firm,
            lane: LaneKind::Http,
            target: target(),
            location: location(name),
            evidence: evidence("<svg/onload=1>"),
            description: "A payload reflected unescaped.".into(),
            remediation: Some("Encode output.".into()),
            passive: false,
        }
    }

    /// A passive `security-header` issue on one path of one origin.
    fn passive_issue(path: &str, port: u16) -> NewIssue {
        let mut issue = new_issue("security-header", "content-security-policy");
        issue.class = "security-header".into();
        issue.name = "Missing security header".into();
        issue.severity = Severity::Low;
        issue.passive = true;
        issue.target = IssueTarget {
            scheme: "https".into(),
            host: "t.example".into(),
            port,
        };
        issue.location = IssueLocation {
            method: Some("GET".into()),
            path: path.into(),
            path_template: path.into(),
            kind: InsertionKind::Header,
            name: "content-security-policy".into(),
            field_path: None,
            ws_path: None,
            l4: None,
        };
        issue
    }

    /// An issue of a given class and severity, one per insertion point.
    fn graded(class: &str, severity: Severity, point: &str) -> NewIssue {
        let mut issue = new_issue("c", point);
        issue.class = class.into();
        issue.name = format!("{class} issue");
        issue.severity = severity;
        issue
    }

    /// A store holding the three graded issues of the paging and filter tests,
    /// first seen at 10, 20 and 30.
    fn graded_store() -> IssueStore {
        let store = IssueStore::new(None);
        store
            .upsert(graded("high", Severity::High, "a"), 10)
            .expect("high upsert");
        store
            .upsert(graded("low", Severity::Low, "b"), 20)
            .expect("low upsert");
        store
            .upsert(graded("critical", Severity::Critical, "c"), 30)
            .expect("critical upsert");
        store
    }

    /// A scratch findings directory, removed when dropped.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            let dir = std::env::temp_dir().join(format!(
                "aitm-issue-store-{}",
                uuid::Uuid::new_v4().simple()
            ));
            std::fs::create_dir_all(&dir).expect("create temp dir");
            Self(dir)
        }

        fn path(&self) -> &Path {
            &self.0
        }

        fn issue_file(&self, id: &str) -> PathBuf {
            self.0
                .join("scan")
                .join("issues")
                .join(format!("{id}.json"))
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    // ---- the dedupe key ---------------------------------------------------

    /// Spec D6: the key is `blake3(class, scheme, host, port, method,
    /// path_template, kind, name, field_path)` — stable for one point, different
    /// for another, and `check_id` is not in it, so two checks that find one
    /// class on one point produce **one** issue with two occurrences.
    #[test]
    fn dedupe_key_is_stable_and_ignores_check_id() {
        let point = |name| DedupeInput::Http {
            class: "reflected-xss",
            scheme: "https",
            host: "t.example",
            port: 443,
            method: "GET",
            path_template: "/search",
            kind: InsertionKind::Query,
            name,
            field_path: None,
        };
        assert_eq!(dedupe_key(&point("r")), dedupe_key(&point("r")));
        assert_ne!(dedupe_key(&point("r")), dedupe_key(&point("q")));
        assert_eq!(
            dedupe_key(&point("r")).len(),
            64,
            "a blake3 hex digest is 64 characters"
        );

        let store = IssueStore::new(None);
        let first = store
            .upsert(new_issue("a", "q"), 100)
            .expect("first upsert");
        assert!(
            matches!(first, Upsert::Created(_)),
            "the first upsert creates: {first:?}"
        );
        let second = store
            .upsert(new_issue("b", "q"), 200)
            .expect("second upsert");
        let Upsert::Merged(issue) = second else {
            panic!("a second check on the same point merges: {second:?}");
        };
        assert_eq!(issue.occurrences, 2);
        assert_eq!(issue.last_seen, 200);
        assert_eq!(issue.first_seen, 100);
        assert_eq!(issue.check_id, "a", "the reporting check is the first one");
        assert_eq!(store.count(), 1);
    }

    /// Spec D6: an L4 issue keys on `(class, ip, port, proto, grammar,
    /// field_path, mutation_class)`. Two cases that differ only in the mutation
    /// are two issues even though their HTTP location fields are identical.
    #[test]
    fn an_l4_location_keys_on_the_l4_tuple() {
        let case = |mutation: &str| {
            let mut issue = new_issue("l4-crash", "");
            issue.class = "l4-crash".into();
            issue.lane = LaneKind::L4Stream;
            issue.location = IssueLocation {
                method: None,
                path: String::new(),
                path_template: String::new(),
                kind: InsertionKind::EntireBody,
                name: String::new(),
                field_path: None,
                ws_path: None,
                l4: Some(L4Location {
                    ip: "10.0.0.1".into(),
                    port: 5353,
                    proto: L4Transport::Udp,
                    grammar: Some("dns".into()),
                    field_path: Some("qname".into()),
                    mutation: Some(mutation.into()),
                }),
            };
            issue
        };

        let store = IssueStore::new(None);
        store.upsert(case("overflow"), 1).expect("overflow upsert");
        store.upsert(case("truncate"), 2).expect("truncate upsert");
        assert_eq!(store.count(), 2, "two mutations are two issues");

        let again = store.upsert(case("overflow"), 3).expect("repeat upsert");
        assert!(
            matches!(again, Upsert::Merged(_)),
            "the same L4 case merges: {again:?}"
        );
        assert_eq!(store.count(), 2);
    }

    // ---- merge rules ------------------------------------------------------

    /// Spec D6: "A repeat raises `confidence` to the max seen ... it never
    /// lowers", and the evidence kept is the higher-confidence one.
    #[test]
    fn confidence_never_lowers_and_higher_replaces_evidence() {
        let store = IssueStore::new(None);

        let mut certain = new_issue("a", "q");
        certain.confidence = Confidence::Certain;
        certain.evidence = evidence("first");
        store.upsert(certain, 1).expect("certain upsert");

        let mut tentative = new_issue("b", "q");
        tentative.confidence = Confidence::Tentative;
        tentative.evidence = evidence("second");
        let merged = store.upsert(tentative, 2).expect("tentative upsert");
        let Upsert::Merged(issue) = merged else {
            panic!("the same point merges: {merged:?}");
        };
        assert_eq!(issue.confidence, Confidence::Certain, "confidence lowered");
        assert_eq!(
            issue.evidence.payload.as_deref(),
            Some("first"),
            "weaker evidence replaced the stronger"
        );

        let mut weak = new_issue("a", "r");
        weak.confidence = Confidence::Tentative;
        weak.evidence = evidence("weak");
        store.upsert(weak, 3).expect("weak upsert");

        let mut firm = new_issue("b", "r");
        firm.confidence = Confidence::Firm;
        firm.evidence = evidence("firm");
        let merged = store.upsert(firm, 4).expect("firm upsert");
        let Upsert::Merged(issue) = merged else {
            panic!("the same point merges: {merged:?}");
        };
        assert_eq!(issue.confidence, Confidence::Firm);
        assert_eq!(
            issue.evidence.payload.as_deref(),
            Some("firm"),
            "stronger evidence did not replace the weaker"
        );
    }

    /// Spec D6: "a `technique: passive` check dedupes on `(class, scheme, host,
    /// port)` and lists the paths in `evidence.matched`".
    #[test]
    fn passive_consolidates_per_origin() {
        let store = IssueStore::new(None);
        store
            .upsert(passive_issue("/a", 443), 1)
            .expect("/a upsert");
        let merged = store
            .upsert(passive_issue("/b", 443), 2)
            .expect("/b upsert");
        let Upsert::Merged(issue) = merged else {
            panic!("a second path on one origin merges: {merged:?}");
        };
        assert_eq!(issue.evidence.matched.as_deref(), Some("/a, /b"));
        assert_eq!(issue.occurrences, 2);
        assert_eq!(store.count(), 1);

        store
            .upsert(passive_issue("/a", 8443), 3)
            .expect("other port upsert");
        assert_eq!(store.count(), 2, "another origin is another issue");
    }

    // ---- query ------------------------------------------------------------

    /// Call B12: severity desc, `first_seen` asc, id; the cursor is the decimal
    /// offset of the next item; `by_severity` tallies the whole filtered set,
    /// not the page.
    #[test]
    fn query_orders_pages_and_tallies() {
        let store = graded_store();

        let page1 = store
            .query(&IssueFilter::default(), 2, None)
            .expect("page 1");
        let classes: Vec<&str> = page1.issues.iter().map(|i| i.class.as_str()).collect();
        assert_eq!(classes, ["critical", "high"]);
        assert_eq!(page1.next_cursor.as_deref(), Some("2"));
        assert_eq!(page1.by_severity.critical, 1);
        assert_eq!(page1.by_severity.high, 1);
        assert_eq!(page1.by_severity.low, 1);

        let page2 = store
            .query(&IssueFilter::default(), 2, Some("2"))
            .expect("page 2");
        let classes: Vec<&str> = page2.issues.iter().map(|i| i.class.as_str()).collect();
        assert_eq!(classes, ["low"]);
        assert_eq!(page2.next_cursor, None);
        assert_eq!(page2.by_severity, page1.by_severity);

        let bad = store
            .query(&IssueFilter::default(), 2, Some("x"))
            .expect_err("a non-numeric cursor is refused");
        assert_eq!(bad.to_string(), "scan: not_found: cursor");
    }

    /// Spec D3: every `scan.issues` filter narrows the set.
    #[test]
    fn filters_apply() {
        let store = graded_store();
        let count = |f: &IssueFilter| store.query(f, 10, None).expect("query").issues.len();

        assert_eq!(
            count(&IssueFilter {
                severity_min: Some(Severity::High),
                ..IssueFilter::default()
            }),
            2,
            "severity_min: high keeps critical and high"
        );
        assert_eq!(
            count(&IssueFilter {
                class: Some("low".into()),
                ..IssueFilter::default()
            }),
            1
        );
        assert_eq!(
            count(&IssueFilter {
                job: Some("scan-ffffffff".into()),
                ..IssueFilter::default()
            }),
            0
        );
        assert_eq!(
            count(&IssueFilter {
                lane: Some(LaneKind::L4Stream),
                ..IssueFilter::default()
            }),
            0
        );
        assert_eq!(
            count(&IssueFilter {
                target: Some("https://t.example".into()),
                ..IssueFilter::default()
            }),
            3
        );
        assert_eq!(
            count(&IssueFilter {
                target: Some("https://other.test".into()),
                ..IssueFilter::default()
            }),
            0
        );
        assert_eq!(
            count(&IssueFilter {
                since_ms: Some(25),
                ..IssueFilter::default()
            }),
            1,
            "since_ms keeps only what was last seen after it"
        );

        let false_positive = IssueFilter {
            status: Some(IssueStatus::FalsePositive),
            ..IssueFilter::default()
        };
        assert_eq!(count(&false_positive), 0);

        let id = store
            .query(&IssueFilter::default(), 10, None)
            .expect("query")
            .issues[0]
            .id
            .clone();
        store
            .update_status(&id, IssueStatus::FalsePositive, Some("intended".into()))
            .expect("update status");
        assert_eq!(count(&false_positive), 1);
    }

    /// `scan.issue.update` on an unknown id is the D3 `not_found` refusal.
    #[test]
    fn updating_an_unknown_issue_is_not_found() {
        let store = IssueStore::new(None);
        let err = store
            .update_status("issue-deadbeef", IssueStatus::Confirmed, None)
            .expect_err("unknown id is refused");
        assert_eq!(err.to_string(), "scan: not_found: issue issue-deadbeef");
    }

    /// `for_job` is the per-job view the worker reports from, and `set_links`
    /// writes the PoC/finding back-references of spec D6.
    #[test]
    fn for_job_and_links() {
        let store = graded_store();
        let mut other = graded("high", Severity::High, "z");
        other.job = "scan-aaaabbbb".into();
        store.upsert(other, 40).expect("other job upsert");

        assert_eq!(store.for_job("scan-01020304").len(), 3);
        let mine = store.for_job("scan-aaaabbbb");
        assert_eq!(mine.len(), 1);

        let linked = store
            .set_links(&mine[0].id, Some("poc-1".into()), Some("finding-1".into()))
            .expect("set links");
        assert_eq!(linked.poc_ref.as_deref(), Some("poc-1"));
        assert_eq!(linked.finding_id.as_deref(), Some("finding-1"));
    }

    // ---- persistence ------------------------------------------------------

    /// Spec D6: issues live in `<findings.dir>/scan/issues/<id>.json` with an
    /// index beside them; a fresh store reloads them and keeps deduping against
    /// what it read.
    #[test]
    fn status_update_persists_and_reloads() {
        let dir = TempDir::new();
        let store = IssueStore::new(Some(dir.path()));
        let created = store.upsert(new_issue("a", "q"), 100).expect("upsert");
        let Upsert::Created(issue) = created else {
            panic!("the first upsert creates: {created:?}");
        };

        store
            .update_status(
                &issue.id,
                IssueStatus::FalsePositive,
                Some("intended".into()),
            )
            .expect("update status");

        let text = std::fs::read_to_string(dir.issue_file(&issue.id)).expect("the issue file");
        assert!(
            text.contains("\"status\":\"false_positive\""),
            "status not persisted: {text}"
        );
        assert!(
            text.contains("\"note\":\"intended\""),
            "note not persisted: {text}"
        );

        let reloaded = IssueStore::new(Some(dir.path()));
        assert_eq!(reloaded.load().expect("load"), 1);
        let got = reloaded.get(&issue.id).expect("the reloaded issue");
        assert_eq!(got.status, IssueStatus::FalsePositive);
        assert_eq!(got.note.as_deref(), Some("intended"));

        let again = reloaded
            .upsert(new_issue("b", "q"), 200)
            .expect("re-upsert");
        let Upsert::Merged(merged) = again else {
            panic!("the same point merges after a reload: {again:?}");
        };
        assert_eq!(merged.id, issue.id);
        assert_eq!(merged.occurrences, 2);
    }

    /// The index is a convenience, not the only copy: each issue file carries
    /// its own `dedupe_key`, so a store whose index was lost still dedupes.
    #[test]
    fn load_without_an_index_recovers_keys_from_the_issue_files() {
        let dir = TempDir::new();
        let store = IssueStore::new(Some(dir.path()));
        let created = store.upsert(new_issue("a", "q"), 100).expect("upsert");
        let Upsert::Created(issue) = created else {
            panic!("the first upsert creates: {created:?}");
        };
        std::fs::remove_file(dir.path().join("scan").join("issues").join("index.json"))
            .expect("remove the index");

        let reloaded = IssueStore::new(Some(dir.path()));
        assert_eq!(reloaded.load().expect("load"), 1);
        let again = reloaded
            .upsert(new_issue("b", "q"), 200)
            .expect("re-upsert");
        let Upsert::Merged(merged) = again else {
            panic!("the same point merges without an index: {again:?}");
        };
        assert_eq!(merged.id, issue.id);
        assert_eq!(merged.occurrences, 2);
    }

    /// Wave-1 security review: `issue_id()` is 32 bits of randomness and nothing
    /// checks it, so a candidate that is already taken — in memory or on disk —
    /// is re-minted rather than silently overwriting another issue.
    #[test]
    fn a_colliding_issue_id_is_re_minted() {
        let dir = TempDir::new();
        let store = IssueStore::new(Some(dir.path()));
        let created = store.upsert(new_issue("a", "q"), 100).expect("upsert");
        let Upsert::Created(first) = created else {
            panic!("the first upsert creates: {created:?}");
        };

        // A file for an id the store has never heard of: the on-disk half.
        let on_disk = "issue-00000000";
        std::fs::write(dir.issue_file(on_disk), "{\"not\":\"ours\"}").expect("seed a stray file");

        // Minted back to front: the in-memory id, then the on-disk id, then free.
        let mut queue = vec![
            "issue-11111111".to_string(),
            on_disk.to_string(),
            first.id.clone(),
        ];
        let mut mint = move || queue.pop().expect("a candidate id");
        let created = store
            .upsert_with_mint(new_issue("a", "r"), 200, &mut mint)
            .expect("upsert with a colliding mint");
        let Upsert::Created(second) = created else {
            panic!("a new point creates: {created:?}");
        };

        assert_eq!(
            second.id, "issue-11111111",
            "the collisions were not skipped"
        );
        assert_eq!(store.count(), 2);
        assert_eq!(
            std::fs::read_to_string(dir.issue_file(on_disk)).expect("the stray file"),
            "{\"not\":\"ours\"}",
            "the stray file was overwritten"
        );
        assert_eq!(
            store.get(&first.id).expect("the first issue").location.name,
            "q",
            "the first issue was overwritten"
        );
    }

    /// A mint that never frees an id fails the upsert instead of looping or
    /// clobbering.
    #[test]
    fn an_id_that_never_frees_fails_the_upsert() {
        let store = IssueStore::new(None);
        let created = store.upsert(new_issue("a", "q"), 100).expect("upsert");
        let Upsert::Created(first) = created else {
            panic!("the first upsert creates: {created:?}");
        };

        let taken = first.id.clone();
        let mut mint = move || taken.clone();
        let err = store
            .upsert_with_mint(new_issue("a", "r"), 200, &mut mint)
            .expect_err("a mint that only collides fails");
        assert!(
            err.to_string().contains("issue id"),
            "unhelpful error: {err}"
        );
        assert_eq!(store.count(), 1);
    }

    // ---- markdown ---------------------------------------------------------

    /// Spec D3: `scan.report` renders the issue store, once per issue, with
    /// every string through the scanner's one scrubber.
    #[test]
    fn issues_md_lists_each_issue_once_scrubbed() {
        let store = IssueStore::new(None);
        let mut issue = new_issue("a", "q");
        issue.evidence = Evidence {
            payload: Some("sid=s3cr3t".into()),
            ..Evidence::default()
        };
        store.upsert(issue, 100).expect("upsert");
        store
            .upsert(new_issue("b", "q"), 200)
            .expect("the same point again");

        let md = store.render_issues_md(None);
        assert_eq!(
            md.matches("Reflected XSS").count(),
            1,
            "the issue is listed more than once: {md}"
        );
        assert!(!md.contains("s3cr3t"), "the payload was not scrubbed: {md}");
        assert!(
            md.contains("## high Reflected XSS"),
            "no severity heading: {md}"
        );
        assert!(md.contains("https://t.example"), "no target line: {md}");
        assert!(md.contains("Occurrences: 2"), "no occurrence count: {md}");

        assert!(
            store
                .render_issues_md(Some("https://other.test"))
                .is_empty(),
            "another target's report is not empty"
        );
        assert!(!store.render_issues_md(Some("https://t.example")).is_empty());
    }

    /// Wave-2/3 security fix: attacker-controlled text is rendered *inline*. A
    /// path carrying a decoded `%0A## Critical` cannot open a heading of its
    /// own, a carriage return cannot split a line, and a backtick in `matched`
    /// cannot close the code span it is quoted in.
    #[test]
    fn issues_md_keeps_attacker_text_inline() {
        let store = IssueStore::new(None);
        let mut issue = new_issue("a", "q");
        issue.location.path = "/search\n## Critical injected heading\r\n- Target: evil".into();
        issue.location.path_template = issue.location.path.clone();
        issue.evidence = Evidence {
            matched: Some("x`y".into()),
            ..Evidence::default()
        };
        store.upsert(issue, 100).expect("upsert");

        let md = store.render_issues_md(None);

        assert!(
            md.lines().all(|line| !line.starts_with("## Critical")),
            "an injected heading survived: {md}"
        );
        // The injected text is kept, inline, so substring counts are 2 by
        // design; what must hold is that it never *starts* a line.
        assert_eq!(
            md.lines().filter(|line| line.starts_with("## ")).count(),
            1,
            "exactly one heading line: {md}"
        );
        assert_eq!(
            md.lines()
                .filter(|line| line.starts_with("- Target:"))
                .count(),
            1,
            "exactly one target line: {md}"
        );
        assert!(!md.contains('\r'), "a carriage return survived: {md:?}");
        assert!(md.contains("x\\`y"), "the backtick was not escaped: {md}");
        assert!(
            md.contains("Critical injected heading"),
            "the text itself is kept, inline: {md}"
        );
    }

    // ---- tester additions ---------------------------------------------------

    /// Spec D6: the key is a function of its inputs alone, so two processes
    /// (and two releases) file the same weakness under the same key. The hex
    /// below was computed once and is pinned; a change to the preimage layout
    /// is a store-format change and must fail here. The three variants over
    /// one origin never collide, and an absent optional field is distinct from
    /// a present one — including a present one that is literally `-`.
    ///
    /// Re-pinned once, by the wave-2/3 fix task (2026-11-01), when every field
    /// became length-prefixed and present optionals tagged (`040b6604…` →
    /// `56695f37…`); the store had not shipped, so no issue file carried the
    /// old key.
    #[test]
    fn dedupe_key_is_pinned_across_process_runs_and_variants_never_collide() {
        let http = DedupeInput::Http {
            class: "reflected-xss",
            scheme: "https",
            host: "t.example",
            port: 443,
            method: "GET",
            path_template: "/search",
            kind: InsertionKind::Query,
            name: "q",
            field_path: None,
        };
        assert_eq!(
            dedupe_key(&http),
            "56695f37dedad95835a19d7c75ce78d7ffe7edf4d8173e062396d56f25ab32a7",
            "the pinned HTTP key moved: the preimage layout changed"
        );

        let passive = DedupeInput::Passive {
            class: "reflected-xss",
            scheme: "https",
            host: "t.example",
            port: 443,
        };
        let l4 = DedupeInput::L4 {
            class: "reflected-xss",
            ip: "t.example",
            port: 443,
            proto: L4Transport::Tcp,
            grammar: None,
            field_path: None,
            mutation_class: None,
        };
        let keys = [dedupe_key(&http), dedupe_key(&passive), dedupe_key(&l4)];
        assert_ne!(keys[0], keys[1], "http and passive over one origin differ");
        assert_ne!(keys[0], keys[2], "http and l4 over one target differ");
        assert_ne!(keys[1], keys[2], "passive and l4 over one target differ");

        let variant =
            |class: &'static str, method: &'static str, field_path: Option<&'static str>| {
                DedupeInput::Http {
                    class,
                    scheme: "https",
                    host: "t.example",
                    port: 443,
                    method,
                    path_template: "/search",
                    kind: InsertionKind::Query,
                    name: "q",
                    field_path,
                }
            };
        assert_eq!(
            dedupe_key(&http),
            dedupe_key(&variant("reflected-xss", "GET", None))
        );
        assert_ne!(
            dedupe_key(&http),
            dedupe_key(&variant("reflected-xss", "GET", Some("user.name"))),
            "a present field path is distinct from an absent one"
        );
        assert_ne!(
            dedupe_key(&http),
            dedupe_key(&variant("reflected-xss", "GET", Some("-"))),
            "a field path that is literally `-` is distinct from an absent one"
        );
        assert_ne!(
            dedupe_key(&http),
            dedupe_key(&variant("reflected-xss", "POST", None))
        );
        assert_ne!(
            dedupe_key(&http),
            dedupe_key(&variant("stored-xss", "GET", None))
        );
    }

    /// Spec D6 "lists the paths in `evidence.matched` (bounded)": a hundred
    /// sightings grow the occurrence count, never the evidence past the
    /// model's excerpt bound, and the store still holds one issue.
    #[test]
    fn passive_path_list_is_bounded() {
        let store = IssueStore::new(None);
        let mut last = None;
        for i in 0..100 {
            let path = format!("/section-{i:03}/page");
            last = Some(
                store
                    .upsert(passive_issue(&path, 443), i)
                    .expect("passive upsert"),
            );
        }
        let issue = last.expect("an upsert happened").issue().clone();
        assert_eq!(store.count(), 1, "one origin, one passive issue");
        assert_eq!(issue.occurrences, 100);
        let matched = issue.evidence.matched.expect("the path list");
        assert!(
            matched.len() <= aitm_scan_model::MAX_EXCERPT_BYTES,
            "the path list is unbounded: {} bytes",
            matched.len()
        );
        assert!(matched.starts_with("/section-000/page"), "{matched}");
    }

    /// `scan.issues` paging at the edges: a cursor at or past the end is an
    /// empty page with no `next_cursor` (and the tally still covers the set),
    /// `limit` is capped at [`MAX_ISSUE_PAGE`], and a zero limit still moves.
    #[test]
    fn cursor_at_the_end_and_limit_over_the_cap() {
        let store = graded_store();

        let at_end = store
            .query(&IssueFilter::default(), 2, Some("3"))
            .expect("a cursor at the end");
        assert!(at_end.issues.is_empty());
        assert_eq!(at_end.next_cursor, None);
        assert_eq!(at_end.by_severity.critical, 1, "the tally is of the set");

        let past_end = store
            .query(&IssueFilter::default(), 2, Some("99"))
            .expect("a cursor past the end");
        assert!(past_end.issues.is_empty());
        assert_eq!(past_end.next_cursor, None);

        let zero = store
            .query(&IssueFilter::default(), 0, None)
            .expect("a zero limit");
        assert_eq!(
            zero.issues.len(),
            1,
            "a zero limit is one issue, not a stuck cursor"
        );
        assert_eq!(zero.next_cursor.as_deref(), Some("1"));

        for bad in ["-1", "1.5", "", " 2", "0x10"] {
            let err = store
                .query(&IssueFilter::default(), 2, Some(bad))
                .expect_err("a non-decimal cursor is refused");
            assert_eq!(err.to_string(), "scan: not_found: cursor", "cursor `{bad}`");
        }

        // The cap: more issues than one page can hold.
        let big = IssueStore::new(None);
        for i in 0..(MAX_ISSUE_PAGE + 6) {
            big.upsert(graded("low", Severity::Low, &format!("p{i}")), i as u64)
                .expect("upsert");
        }
        assert_eq!(big.count(), MAX_ISSUE_PAGE + 6);
        let page = big
            .query(&IssueFilter::default(), 5_000, None)
            .expect("an over-cap limit");
        assert_eq!(
            page.issues.len(),
            MAX_ISSUE_PAGE,
            "limit is capped at MAX_ISSUE_PAGE"
        );
        assert_eq!(page.next_cursor.as_deref(), Some("1024"));
        assert_eq!(page.by_severity.low as usize, MAX_ISSUE_PAGE + 6);
        let rest = big
            .query(&IssueFilter::default(), 5_000, page.next_cursor.as_deref())
            .expect("the last page");
        assert_eq!(rest.issues.len(), 6);
        assert_eq!(rest.next_cursor, None);
    }

    /// Wave-2 amendment: the `target` filter matches the normalized origin,
    /// the explicit `scheme://host:port`, or the bare host — case-insensitively
    /// and with a trailing slash tolerated — and nothing else.
    #[test]
    fn target_filter_accepts_origin_explicit_port_and_bare_host() {
        let store = graded_store();
        let count = |target: &str| {
            store
                .query(
                    &IssueFilter {
                        target: Some(target.to_string()),
                        ..IssueFilter::default()
                    },
                    10,
                    None,
                )
                .expect("query")
                .issues
                .len()
        };
        assert_eq!(count("https://t.example"), 3, "the normalized origin");
        assert_eq!(
            count("https://t.example:443"),
            3,
            "the explicit default port"
        );
        assert_eq!(count("t.example"), 3, "the bare host");
        assert_eq!(count("HTTPS://T.EXAMPLE/"), 3, "case and a trailing slash");
        assert_eq!(
            count("https://t.example:8443"),
            0,
            "another port is another origin"
        );
        assert_eq!(
            count("http://t.example"),
            0,
            "another scheme is another origin"
        );
        assert_eq!(count("example"), 0, "a host suffix is not a match");
    }

    /// `by_severity` tallies every level, and `severity_min` / `confidence_min`
    /// are inclusive floors.
    #[test]
    fn tally_covers_every_level_and_minimums_are_inclusive() {
        let store = graded_store();
        store
            .upsert(graded("medium", Severity::Medium, "d"), 40)
            .expect("medium");
        store
            .upsert(graded("info", Severity::Info, "e"), 50)
            .expect("info");

        let all = store
            .query(&IssueFilter::default(), 10, None)
            .expect("query");
        assert_eq!(
            all.by_severity,
            BySeverity {
                critical: 1,
                high: 1,
                medium: 1,
                low: 1,
                info: 1
            }
        );
        let classes: Vec<&str> = all.issues.iter().map(|i| i.class.as_str()).collect();
        assert_eq!(classes, ["critical", "high", "medium", "low", "info"]);

        let at_least_medium = store
            .query(
                &IssueFilter {
                    severity_min: Some(Severity::Medium),
                    ..IssueFilter::default()
                },
                10,
                None,
            )
            .expect("query");
        assert_eq!(at_least_medium.issues.len(), 3);
        assert_eq!(
            at_least_medium.by_severity,
            BySeverity {
                critical: 1,
                high: 1,
                medium: 1,
                low: 0,
                info: 0
            },
            "the tally is of the filtered set"
        );

        // Every graded issue is `Firm`: a `Firm` floor keeps all, `Certain` none.
        let firm = IssueFilter {
            confidence_min: Some(Confidence::Firm),
            ..IssueFilter::default()
        };
        assert_eq!(store.query(&firm, 10, None).expect("query").issues.len(), 5);
        let certain = IssueFilter {
            confidence_min: Some(Confidence::Certain),
            ..IssueFilter::default()
        };
        assert_eq!(
            store.query(&certain, 10, None).expect("query").issues.len(),
            0
        );
    }

    /// A store directory that does not exist yet loads nothing and is not an
    /// error; a file that is there but is not an issue is, naming the file —
    /// an operator's triage state is never silently dropped.
    #[test]
    fn load_refuses_a_corrupt_issue_file_and_tolerates_a_missing_dir() {
        let dir = TempDir::new();
        let fresh = IssueStore::new(Some(dir.path()));
        assert_eq!(
            fresh.load().expect("a missing directory is not an error"),
            0
        );

        fresh.upsert(new_issue("a", "q"), 100).expect("upsert");
        std::fs::write(dir.issue_file("issue-bad00bad"), "{\"not\":\"an issue\"}")
            .expect("seed a corrupt file");
        std::fs::write(
            dir.path().join("scan").join("issues").join("notes.txt"),
            "not json at all",
        )
        .expect("seed a non-json file");

        let reloaded = IssueStore::new(Some(dir.path()));
        let err = reloaded
            .load()
            .expect_err("a corrupt issue file fails the load");
        assert!(
            format!("{err:#}").contains("issue-bad00bad.json"),
            "the error names the file: {err:#}"
        );

        std::fs::remove_file(dir.issue_file("issue-bad00bad")).expect("remove it");
        let reloaded = IssueStore::new(Some(dir.path()));
        assert_eq!(
            reloaded.load().expect("non-json files are ignored"),
            1,
            "only `*.json` issue files count"
        );
    }

    /// Wave-2/3 security fix: an id read from disk is trusted as a file name
    /// only when it *is* the file's name — `issue-<8 hex>` and equal to the
    /// stem. A file whose JSON `id` says `../../x`, or names another issue's
    /// file, is refused naming the file; the honest file still loads.
    #[test]
    fn load_refuses_an_issue_whose_id_disagrees_with_its_file() {
        let dir = TempDir::new();
        let store = IssueStore::new(Some(dir.path()));
        let id = store
            .upsert(new_issue("a", "q"), 100)
            .expect("upsert")
            .issue()
            .id
            .clone();
        let text = std::fs::read_to_string(dir.issue_file(&id)).expect("read the issue file");

        std::fs::write(
            dir.issue_file("issue-deadbeef"),
            text.replace(&id, "../../x"),
        )
        .expect("seed a traversal id");
        let err = IssueStore::new(Some(dir.path()))
            .load()
            .expect_err("a traversal id is refused");
        assert!(
            format!("{err:#}").contains("issue-deadbeef.json"),
            "the error names the file: {err:#}"
        );

        std::fs::write(
            dir.issue_file("issue-deadbeef"),
            text.replace(&id, "issue-cafebabe"),
        )
        .expect("seed a well-shaped id that is not this file's");
        let err = IssueStore::new(Some(dir.path()))
            .load()
            .expect_err("an id that is not the file's stem is refused");
        assert!(
            format!("{err:#}").contains("issue-deadbeef.json"),
            "the error names the file: {err:#}"
        );

        std::fs::remove_file(dir.issue_file("issue-deadbeef")).expect("remove it");
        assert_eq!(
            IssueStore::new(Some(dir.path()))
                .load()
                .expect("the honest file loads"),
            1
        );
    }
}
