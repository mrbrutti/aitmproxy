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

/// Route the core F2 audit through the CA plugin's JSONL file machinery (spec
/// D3a.2): the general command-invocation audit reuses the same append-only,
/// fail-closed JSONL the CA log uses, so **every** command's [`aitm_core::AuditEntry`]
/// — the `ca.*` ones among them — is a line of one format, not a second log.
///
/// Durable audit is best-effort: it must never break the command that produced
/// the entry, so a write failure is logged and the line dropped (the always-on
/// in-memory ring remains the authoritative live view).
impl aitm_core::AuditSink for FileAuditLog {
    fn append(&self, entry: aitm_core::AuditEntry) {
        let mut line = entry_to_jsonl(&entry);
        line.push('\n');
        match self.append_handle() {
            Ok(mut file) => {
                if let Err(err) = file.write_all(line.as_bytes()) {
                    tracing::warn!(
                        target: "aitm::audit",
                        path = %self.path.display(),
                        error = %err,
                        "durable audit append failed; entry kept only in the in-memory ring"
                    );
                }
            }
            Err(err) => tracing::warn!(
                target: "aitm::audit",
                path = %self.path.display(),
                error = %err,
                "durable audit log not writable; entry kept only in the in-memory ring"
            ),
        }
    }
}

/// One core [`aitm_core::AuditEntry`] as a JSON Lines object — the general-audit
/// format, one shape shared by the in-memory ring's rendering
/// ([`aitm_core::AuditEntry::to_value`]), the agent stream, and this durable log,
/// so CA entries are a subset of it. The key set is the same as `to_value`'s:
/// `at`, `origin`, `client_label`, `connection_id`, `command`, `args`, `result`.
/// `connection_id` is the server-assigned connection id (a string), or `null`
/// when the call is not attributable to a streaming connection.
pub fn entry_to_jsonl(entry: &aitm_core::AuditEntry) -> String {
    let result = match &entry.result {
        aitm_core::AuditResult::Ok => serde_json::json!("ok"),
        aitm_core::AuditResult::Error(reason) => serde_json::json!({ "error": reason }),
    };
    serde_json::json!({
        "at": entry.at_millis(),
        "origin": aitm_core::origin_label(entry.origin),
        "client_label": entry.client_label,
        "connection_id": entry.connection_id,
        "command": entry.command,
        "args": entry.args_summary,
        "result": result,
    })
    .to_string()
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
