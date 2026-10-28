//! Windows: `certutil [-user] -store|-addstore|-delstore Root`, keyed on the
//! SHA-1 thumbprint. Unit-tested only; not a shipped platform.
//!
//! Membership of the Root store is trust, so `trusted` mirrors `installed`.
//! `-addstore` is run without `-f`: the check-first query makes it
//! unnecessary, and `-f` is the malware signature. Windows never uses
//! `sudo`; elevation is the shell's, and the error says so.

use crate::cert::CaCert;
use crate::exec::{CmdLine, CmdOutput, Executor};
use crate::platform::{cmd, failure_text, run};
use crate::store::{
    Change, Platform, Presence, Scope, StoreStatus, Trust, TrustError, TrustErrorKind, TrustStore,
};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WindowsStore;

static PLATFORM: Platform = Platform::Windows;

const ELEVATION_HINT: &str = "run from an elevated (Administrator) shell for --scope system";
const DIALOG_HINT: &str = "the Security Warning dialog must be answered on an interactive desktop";
/// What `certutil` prints (to stdout, usually) when the store is not ours
/// to write.
const DENIED_MARKERS: [&str; 2] = ["0x80070005", "Access is denied"];
const HASH_LABEL: &str = "cert hash(sha1):";

fn location(scope: Scope) -> &'static str {
    match scope {
        Scope::User => r"CurrentUser\Root",
        Scope::System => r"LocalMachine\Root",
    }
}

/// `certutil [-user] <args…>`: `-user` only for the user scope.
fn certutil(scope: Scope, args: &[&str], mutating: bool) -> CmdLine {
    let mut all = Vec::with_capacity(args.len() + 1);
    if scope == Scope::User {
        all.push("-user");
    }
    all.extend_from_slice(args);
    cmd("certutil", &all, mutating)
}

/// Every `Cert Hash(sha1): <hex>` line of a store dump (label matched
/// case-insensitively), normalised to lowercase hex without spaces.
fn thumbprints(stdout: &str) -> Vec<String> {
    stdout
        .lines()
        .filter_map(|line| {
            // ASCII lowercasing keeps byte offsets, so the index is valid
            // in the original line.
            let idx = line.to_ascii_lowercase().find(HASH_LABEL)?;
            let hex: String = line[idx + HASH_LABEL.len()..]
                .chars()
                .filter(|c| !c.is_whitespace())
                .collect();
            Some(hex.to_ascii_lowercase())
        })
        .collect()
}

/// Presence from a `-store Root` dump, with a detail line whenever the
/// answer is `Unknown`.
fn parse_presence(cmd: &CmdLine, out: &CmdOutput, cert: &CaCert) -> (Presence, Option<String>) {
    if !out.success() {
        return (Presence::Unknown, Some(failure_text(cmd, out)));
    }
    let hashes = thumbprints(&out.stdout);
    if hashes.is_empty() {
        return (
            Presence::Unknown,
            Some("could not parse certutil output: no Cert Hash(sha1) lines".to_string()),
        );
    }
    if hashes.contains(&cert.sha1_hex_lower()) {
        (Presence::Present, None)
    } else {
        (Presence::Absent, None)
    }
}

fn trust_of(installed: Presence) -> Trust {
    match installed {
        Presence::Present => Trust::Yes,
        Presence::Absent => Trust::No,
        Presence::Stale | Presence::Unknown => Trust::Unknown,
    }
}

/// `certutil` explains failures on stdout, so quote that too.
fn failure_with_stdout(cmd: &CmdLine, out: &CmdOutput) -> String {
    let mut text = failure_text(cmd, out);
    let lines: Vec<&str> = out
        .stdout
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    if !lines.is_empty() {
        let start = lines.len().saturating_sub(5);
        text.push_str("; certutil output: ");
        text.push_str(&lines[start..].join(" | "));
    }
    text
}

/// One operation against one scope's Root store; keeps the rendered lines
/// for the [`Change`] report.
struct Op<'a> {
    scope: Scope,
    exec: &'a dyn Executor,
    commands: Vec<String>,
}

impl<'a> Op<'a> {
    fn new(scope: Scope, exec: &'a dyn Executor) -> Self {
        Self {
            scope,
            exec,
            commands: Vec::new(),
        }
    }

    fn run(&mut self, cmd: &CmdLine) -> Result<CmdOutput, TrustError> {
        self.commands.push(cmd.render());
        run(self.exec, cmd)
    }

    fn query(&mut self, cert: &CaCert) -> Result<(Presence, Option<String>), TrustError> {
        let cmd = certutil(self.scope, &["-store", "Root"], false);
        let out = self.run(&cmd)?;
        Ok(parse_presence(&cmd, &out, cert))
    }

    fn finish(self, changed: bool, detail: Vec<String>) -> Change {
        Change {
            changed,
            scope: self.scope,
            location: location(self.scope).to_string(),
            commands: self.commands,
            detail,
        }
    }
}

impl TrustStore for WindowsStore {
    fn platform(&self) -> &Platform {
        &PLATFORM
    }

    fn status(
        &self,
        cert: &CaCert,
        scope: Scope,
        exec: &dyn Executor,
    ) -> anyhow::Result<StoreStatus> {
        let mut op = Op::new(scope, exec);
        let (installed, note) = op.query(cert)?;
        Ok(StoreStatus {
            scope,
            location: location(scope).to_string(),
            installed,
            trusted: trust_of(installed),
            detail: note.into_iter().collect(),
        })
    }

    fn install(&self, cert: &CaCert, scope: Scope, exec: &dyn Executor) -> anyhow::Result<Change> {
        let mut op = Op::new(scope, exec);
        let store = location(scope);
        let (presence, note) = op.query(cert)?;
        let mut detail: Vec<String> = note.into_iter().collect();
        match presence {
            Presence::Present => {
                detail.push(format!("already in {store}"));
                return Ok(op.finish(false, detail));
            }
            // The Root store is keyed on the thumbprint, so adding a root
            // that is already there cannot duplicate it.
            Presence::Unknown => detail.push(
                "store could not be read; adding anyway (certutil does not duplicate an \
                 existing root)"
                    .to_string(),
            ),
            Presence::Absent | Presence::Stale => {}
        }

        let path = cert.path.display().to_string();
        let cmd = certutil(scope, &["-addstore", "Root", &path], true);
        let out = op.run(&cmd)?;
        if out.success() {
            detail.push(format!("added to {store}"));
            return Ok(op.finish(true, detail));
        }

        let text = failure_with_stdout(&cmd, &out);
        let denied = DENIED_MARKERS
            .iter()
            .any(|m| out.stdout.contains(m) || out.stderr.contains(m));
        let mut message = if denied {
            format!("{ELEVATION_HINT} ({text})")
        } else {
            text
        };
        if scope == Scope::User {
            message.push_str("; ");
            message.push_str(DIALOG_HINT);
        }
        let kind = if denied {
            TrustErrorKind::NeedsRoot
        } else {
            TrustErrorKind::ToolFailed
        };
        Err(TrustError::new(kind, message).into())
    }

    fn uninstall(
        &self,
        cert: &CaCert,
        scope: Scope,
        exec: &dyn Executor,
    ) -> anyhow::Result<Change> {
        let mut op = Op::new(scope, exec);
        let store = location(scope);
        let (presence, note) = op.query(cert)?;
        let mut detail: Vec<String> = note.into_iter().collect();
        match presence {
            Presence::Absent => {
                detail.push(format!("not in {store}"));
                return Ok(op.finish(false, detail));
            }
            Presence::Unknown => {
                detail.push("store could not be read; deleting by thumbprint anyway".to_string())
            }
            Presence::Present | Presence::Stale => {}
        }

        let thumbprint = cert.sha1_hex_lower();
        let cmd = certutil(scope, &["-delstore", "Root", &thumbprint], true);
        let out = op.run(&cmd)?;
        if out.success() {
            detail.push(format!("removed thumbprint {thumbprint} from {store}"));
            return Ok(op.finish(true, detail));
        }
        Err(TrustError::new(TrustErrorKind::ToolFailed, failure_with_stdout(&cmd, &out)).into())
    }
}
