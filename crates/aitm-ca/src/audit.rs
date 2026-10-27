//! Audit log: a record of every root-CA change that survives the session.
//!
//! `tracing` output is ephemeral and depends on the operator's `RUST_LOG`;
//! each `ca.install` / `ca.uninstall` / `ca.export` invocation that got past
//! argument parsing is also appended as one JSON line to an append-only log.
//! The log is fail-closed: a command proves the log is writable with
//! [`AuditLog::open`] before it touches anything.

use std::fs::{self, DirBuilder, OpenOptions};
use std::io::Write as _;
use std::path::PathBuf;

use anyhow::Context as _;
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

/// The closed vocabularies of the three `&'static str` fields. A record read
/// back from disk is interned into them; anything else is a deserialization
/// error, never a leak.
const COMMANDS: &[&str] = &["ca.install", "ca.uninstall", "ca.export"];
const FRONTENDS: &[&str] = &["cli", "mcp"];
const OUTCOMES: &[&str] = &["ok", "refused", "error", "dry_run"];

/// One audit line. Serializes to a JSON object with exactly these eight keys,
/// `null` for absent options.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuditRecord {
    /// RFC 3339 UTC, e.g. `2026-10-27T21:03:14Z`.
    pub ts: String,
    /// `"ca.install"` | `"ca.uninstall"` | `"ca.export"`.
    pub command: &'static str,
    /// `"cli"` | `"mcp"`.
    pub frontend: &'static str,
    /// `"ok"` | `"refused"` | `"error"` | `"dry_run"`.
    pub outcome: &'static str,
    /// Install/uninstall only.
    pub scope: Option<String>,
    /// `Platform::label()`, when detected.
    pub platform: Option<String>,
    /// Colon form; `None` when there is no `ca.crt`.
    pub fingerprint_sha256: Option<String>,
    /// `changed=true/false`, `written_to`, or the error text — never PEM or
    /// key material.
    pub detail: String,
}

/// The shape a record is read back as. `serde_derive` would make a
/// `Deserialize` impl on [`AuditRecord`] itself borrow for `'static` because
/// of its `&'static str` fields, so the owned form is read and interned.
#[derive(Deserialize)]
struct OwnedRecord {
    ts: String,
    command: String,
    frontend: String,
    outcome: String,
    scope: Option<String>,
    platform: Option<String>,
    fingerprint_sha256: Option<String>,
    detail: String,
}

impl<'de> Deserialize<'de> for AuditRecord {
    fn deserialize<D: Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        let owned = OwnedRecord::deserialize(de)?;
        Ok(Self {
            ts: owned.ts,
            command: intern::<D>(&owned.command, COMMANDS)?,
            frontend: intern::<D>(&owned.frontend, FRONTENDS)?,
            outcome: intern::<D>(&owned.outcome, OUTCOMES)?,
            scope: owned.scope,
            platform: owned.platform,
            fingerprint_sha256: owned.fingerprint_sha256,
            detail: owned.detail,
        })
    }
}

fn intern<'de, D: Deserializer<'de>>(
    value: &str,
    vocabulary: &'static [&'static str],
) -> Result<&'static str, D::Error> {
    vocabulary
        .iter()
        .copied()
        .find(|known| *known == value)
        .ok_or_else(|| D::Error::unknown_variant(value, vocabulary))
}

/// Where audit records go. Implemented by `FileAuditLog` (JSON Lines on
/// disk) and the in-memory double in [`crate::testing`].
pub trait AuditLog: Send + Sync {
    /// Prove the log is writable before anything else happens. `Err` ⇒ the
    /// command refuses to run.
    fn open(&self) -> anyhow::Result<()>;
    /// Append one record (one JSON line).
    fn record(&self, rec: &AuditRecord) -> anyhow::Result<()>;
}

/// JSON Lines on disk, append-only. The file is created `0600` inside a
/// parent created `0700` (Unix); aitmproxy never rewrites or truncates it.
#[derive(Debug, Clone)]
pub struct FileAuditLog {
    path: PathBuf,
}

impl FileAuditLog {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    /// The file opened for append, created `0600` if missing. Every write
    /// goes through a fresh `O_APPEND` handle so one `write_all` is one line.
    fn append_handle(&self) -> anyhow::Result<fs::File> {
        let mut opts = OpenOptions::new();
        opts.append(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            opts.mode(0o600);
        }
        opts.open(&self.path)
            .with_context(|| format!("audit log {} is not writable", self.path.display()))
    }
}

impl AuditLog for FileAuditLog {
    fn open(&self) -> anyhow::Result<()> {
        if let Some(parent) = self.path.parent().filter(|p| !p.as_os_str().is_empty()) {
            let mut builder = DirBuilder::new();
            builder.recursive(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt as _;
                builder.mode(0o700);
            }
            builder.create(parent).with_context(|| {
                format!(
                    "audit log {} is not writable: cannot create {}",
                    self.path.display(),
                    parent.display()
                )
            })?;
        }
        self.append_handle().map(drop)
    }

    fn record(&self, rec: &AuditRecord) -> anyhow::Result<()> {
        let mut line = serde_json::to_string(rec).context("serializing audit record")?;
        line.push('\n');
        self.append_handle()?
            .write_all(line.as_bytes())
            .with_context(|| format!("appending to audit log {}", self.path.display()))
    }
}

/// The current UTC time as `AuditRecord::ts` wants it: RFC 3339, seconds
/// precision, `Z` suffix — e.g. `2026-10-27T21:03:14Z`.
pub fn now_rfc3339() -> String {
    let now = OffsetDateTime::now_utc();
    now.replace_nanosecond(0)
        .unwrap_or(now)
        .format(&Rfc3339)
        .expect("RFC 3339 formatting of a UTC time cannot fail")
}
