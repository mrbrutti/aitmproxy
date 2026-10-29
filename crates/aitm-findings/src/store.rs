//! The [`FindingStore`] trait and its on-disk implementation, [`DiskFindingStore`].
//!
//! One human-readable YAML file per finding (`<id>.yaml`) under `findings.dir`, plus
//! an append-only `runs.jsonl` run-history log — one line per recorded `poc.run`
//! outcome (`{finding_id, poc_ref, passed, control_passed, at, origin}`). `get`/`list`
//! read from disk, so a fresh store over the same directory sees everything a prior
//! process wrote (survives restarts). `remove` deletes the finding's YAML and keeps
//! the runs log (the history of what ran is not rewritten).
//!
//! Secrets never reach disk: the free-text `title`/`notes` are redacted at
//! [`DiskFindingStore::record`] (the same posture as the audit ring). A finding `id`
//! is validated as a bare filename component, so a crafted id cannot escape the
//! directory via `findings.get`/`findings.remove`.

use std::io::Write;
use std::path::PathBuf;

use crate::record::{
    fmt_time, origin_str, FindingFilter, FindingRecord, FindingSummary, StoredRecord,
};

/// A persistent findings store.
pub trait FindingStore: Send + Sync {
    /// Persist `r` (writing a YAML file and a `runs.jsonl` line) and return its id.
    /// A record with an empty `id` is assigned a derived, filename-safe one.
    fn record(&self, r: FindingRecord) -> anyhow::Result<String>;
    /// The full record for `id`, or `None` if it is unknown or unreadable.
    fn get(&self, id: &str) -> Option<FindingRecord>;
    /// The summaries of every stored finding matching `f`, newest first.
    fn list(&self, f: &FindingFilter) -> Vec<FindingSummary>;
    /// Delete the finding's YAML file (the runs log is kept). Idempotent: removing
    /// an absent finding succeeds.
    fn remove(&self, id: &str) -> anyhow::Result<()>;
}

/// The default store: YAML files + a `runs.jsonl` under one directory.
pub struct DiskFindingStore {
    dir: PathBuf,
}

impl DiskFindingStore {
    /// A store rooted at `dir` (created on first write).
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    fn yaml_path(&self, id: &str) -> PathBuf {
        self.dir.join(format!("{id}.yaml"))
    }

    fn runs_path(&self) -> PathBuf {
        self.dir.join("runs.jsonl")
    }

    fn append_run(&self, r: &FindingRecord) -> anyhow::Result<()> {
        let line = serde_json::json!({
            "finding_id": r.id,
            "poc_ref": r.poc_ref,
            "passed": r.reproduction.passed,
            "control_passed": r.reproduction.control_passed,
            "at": fmt_time(r.reproduction.run_at),
            "origin": origin_str(r.origin),
        });
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.runs_path())?;
        writeln!(file, "{line}")?;
        Ok(())
    }
}

impl FindingStore for DiskFindingStore {
    fn record(&self, r: FindingRecord) -> anyhow::Result<String> {
        let mut r = r;
        if r.id.is_empty() {
            r.id = derive_id(&r.class);
        }
        if !valid_id(&r.id) {
            anyhow::bail!("invalid finding id `{}`", r.id);
        }
        // Secrets never reach disk: redact the free-text fields (poc_ref/paths are
        // references, not credential-bearing).
        r.title = aitm_core::redact::scrub_text(&r.title);
        r.notes = r.notes.as_deref().map(aitm_core::redact::scrub_text);

        std::fs::create_dir_all(&self.dir)?;
        let stored = StoredRecord::from(&r);
        let yaml = serde_yaml::to_string(&stored)?;
        std::fs::write(self.yaml_path(&r.id), yaml)?;
        self.append_run(&r)?;
        Ok(r.id)
    }

    fn get(&self, id: &str) -> Option<FindingRecord> {
        if !valid_id(id) {
            return None;
        }
        let text = std::fs::read_to_string(self.yaml_path(id)).ok()?;
        let stored: StoredRecord = serde_yaml::from_str(&text).ok()?;
        match FindingRecord::try_from(stored) {
            Ok(rec) => Some(rec),
            Err(e) => {
                tracing::warn!(id, error = %e, "findings.get: skipping unreadable record");
                None
            }
        }
    }

    fn list(&self, f: &FindingFilter) -> Vec<FindingSummary> {
        let entries = match std::fs::read_dir(&self.dir) {
            Ok(e) => e,
            // A missing/unreadable directory is simply empty; no path disclosure.
            Err(_) => return Vec::new(),
        };
        let mut out: Vec<FindingRecord> = Vec::new();
        for entry in entries.flatten() {
            let path = entry.path();
            let is_yaml = path
                .extension()
                .and_then(|e| e.to_str())
                .is_some_and(|e| e == "yaml");
            if !is_yaml || !entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
                continue;
            }
            let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
                continue;
            };
            match self.get(stem) {
                Some(rec) if f.matches(&rec) => out.push(rec),
                _ => {}
            }
        }
        // Newest first, with a stable id tie-break so the list does not reshuffle.
        out.sort_by(|a, b| {
            b.discovered_at
                .cmp(&a.discovered_at)
                .then_with(|| a.id.cmp(&b.id))
        });
        out.iter().map(FindingSummary::of).collect()
    }

    fn remove(&self, id: &str) -> anyhow::Result<()> {
        if !valid_id(id) {
            anyhow::bail!("invalid finding id `{id}`");
        }
        match std::fs::remove_file(self.yaml_path(id)) {
            Ok(()) => Ok(()),
            // Idempotent: an already-absent finding is a successful removal.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
}

/// Whether `id` is a safe bare filename component (no traversal, no separators).
pub(crate) fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id != "."
        && id != ".."
        && !id.contains("..")
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
}

/// Derive a readable, filename-safe id from a finding's class plus a short random
/// suffix, e.g. `reflected-xss-1a2b3c4d`.
pub(crate) fn derive_id(class: &str) -> String {
    let base = slug(class);
    let base: &str = if base.is_empty() { "finding" } else { &base };
    let suffix = uuid::Uuid::new_v4().simple().to_string();
    format!("{base}-{}", &suffix[..8])
}

/// Lowercase, hyphenate, and strip a string to `[a-z0-9-]` for use in an id.
fn slug(s: &str) -> String {
    let mut out = String::new();
    let mut prev_dash = false;
    for ch in s.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
            prev_dash = false;
        } else if !out.is_empty() && !prev_dash {
            out.push('-');
            prev_dash = true;
        }
    }
    out.trim_matches('-').to_string()
}
