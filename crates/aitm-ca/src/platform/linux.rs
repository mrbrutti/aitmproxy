//! Linux: an anchor file plus a bundle refresh — Debian family
//! (`/usr/local/share/ca-certificates`, `update-ca-certificates`) and Fedora
//! family (`/etc/pki/ca-trust/source/anchors`, `update-ca-trust extract`).
//!
//! The anchor has a fixed name (`aitmproxy-root-ca.{crt,pem}`), so a
//! regenerated CA overwrites rather than accumulates and the file is ours
//! by name even when its fingerprint is not (`Stale`). Status reads the
//! anchor and the extracted bundle and runs nothing; every mutation is
//! privileged, so each is `sudo --`-prefixed unless the executor is root.

use std::fmt::Write as _;
use std::path::Path;

use x509_parser::pem::Pem;

use crate::cert::{sha256_of, CaCert};
use crate::exec::{CmdLine, CmdOutput, Executor};
use crate::platform::{cmd, failure_text, run, sudo_if_needed};
use crate::store::{
    Change, LinuxFamily, Platform, Presence, Scope, StoreStatus, Trust, TrustError, TrustErrorKind,
    TrustStore, DEBIAN_ANCHOR_DIR, FEDORA_ANCHOR_DIR,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinuxStore(pub LinuxFamily);

static DEBIAN: Platform = Platform::Linux(LinuxFamily::Debian);
static FEDORA: Platform = Platform::Linux(LinuxFamily::Fedora);

const USER_SCOPE_MESSAGE: &str = "Linux has no per-user OS trust store; use --scope system";

/// `sudo` could not help, or there was no `sudo` prompt to answer.
const NEEDS_ROOT_MARKERS: [&str; 3] = ["Permission denied", "Operation not permitted", "sudo:"];

impl LinuxStore {
    /// `A`: the anchor file this store owns.
    fn anchor(&self) -> String {
        match self.0 {
            LinuxFamily::Debian => format!("{DEBIAN_ANCHOR_DIR}/aitmproxy-root-ca.crt"),
            LinuxFamily::Fedora => format!("{FEDORA_ANCHOR_DIR}/aitmproxy-root-ca.pem"),
        }
    }

    /// `B`: the bundle the refresh tool extracts from the anchors.
    fn bundle(&self) -> &'static str {
        match self.0 {
            LinuxFamily::Debian => "/etc/ssl/certs/ca-certificates.crt",
            LinuxFamily::Fedora => "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
        }
    }

    /// `R`: refresh after adding the anchor.
    fn refresh(&self) -> CmdLine {
        match self.0 {
            LinuxFamily::Debian => cmd("update-ca-certificates", &[], true),
            LinuxFamily::Fedora => cmd("update-ca-trust", &["extract"], true),
        }
    }

    /// `R_rm`: refresh after removing it. Debian gets `--fresh` so the
    /// `/etc/ssl/certs/<name>.pem` link cannot dangle (research Q6).
    fn refresh_after_remove(&self) -> CmdLine {
        match self.0 {
            LinuxFamily::Debian => cmd("update-ca-certificates", &["--fresh"], true),
            LinuxFamily::Fedora => self.refresh(),
        }
    }

    /// Reads `A` and `B`; never runs a subprocess.
    fn probe(&self, cert: &CaCert, exec: &dyn Executor) -> Probe {
        let anchor = self.anchor();
        let bundle = self.bundle();
        let mut detail = Vec::new();

        let (installed, anchor_fingerprint) = match exec.read_file(Path::new(&anchor)) {
            Ok(None) => (Presence::Absent, None),
            Ok(Some(bytes)) => match first_certificate_sha256(&bytes) {
                Some(sha) if sha == cert.sha256 => (Presence::Present, None),
                Some(sha) => (Presence::Stale, Some(colon_upper(&sha))),
                None => (Presence::Stale, None),
            },
            Err(e) => {
                detail.push(format!("anchor {anchor} not readable: {e:#}"));
                (Presence::Unknown, None)
            }
        };

        let trusted = match exec.read_file(Path::new(bundle)) {
            Ok(Some(bytes)) if bundle_contains(&bytes, &cert.sha256) => Trust::Yes,
            Ok(Some(_)) => Trust::No,
            Ok(None) => {
                detail.push(format!("bundle {bundle} not readable: no such file"));
                Trust::Unknown
            }
            Err(e) => {
                detail.push(format!("bundle {bundle} not readable: {e:#}"));
                Trust::Unknown
            }
        };

        Probe {
            installed,
            trusted,
            anchor_fingerprint,
            detail,
        }
    }

    /// One privileged step. A spawn failure of the refresh tool means the
    /// `ca-certificates` package is missing; a non-zero exit is classified
    /// by stderr.
    fn mutate(
        &self,
        exec: &dyn Executor,
        cmd: CmdLine,
        verb: &str,
        commands: &mut Vec<String>,
    ) -> Result<CmdOutput, TrustError> {
        let cmd = sudo_if_needed(cmd, exec);
        commands.push(cmd.render());
        let out = run(exec, &cmd).map_err(|e| {
            if e.kind == TrustErrorKind::ToolMissing && is_refresh(&cmd) {
                TrustError::new(
                    TrustErrorKind::ToolMissing,
                    format!(
                        "{} not found; install the ca-certificates package ({})",
                        refresh_program(&cmd),
                        e.message
                    ),
                )
            } else {
                e
            }
        })?;
        if out.success() {
            return Ok(out);
        }
        let text = failure_text(&cmd, &out);
        if NEEDS_ROOT_MARKERS.iter().any(|m| out.stderr.contains(m)) {
            return Err(TrustError::new(
                TrustErrorKind::NeedsRoot,
                format!(
                    "needs root: run aitm ca {verb} from a shell where sudo can prompt, or start \
                     the proxy as root ({text})"
                ),
            ));
        }
        Err(TrustError::new(TrustErrorKind::ToolFailed, text))
    }

    fn change(&self, changed: bool, commands: Vec<String>, detail: Vec<String>) -> Change {
        Change {
            changed,
            scope: Scope::System,
            location: self.anchor(),
            commands,
            detail,
        }
    }
}

/// What the two files say.
struct Probe {
    installed: Presence,
    trusted: Trust,
    /// The anchor's certificate when it is not ours (`Stale`), colon form.
    anchor_fingerprint: Option<String>,
    detail: Vec<String>,
}

/// `Err` unless `scope` is the one Linux has.
fn require_system(scope: Scope) -> Result<(), TrustError> {
    match scope {
        Scope::System => Ok(()),
        Scope::User => Err(TrustError::new(
            TrustErrorKind::UnsupportedScope,
            USER_SCOPE_MESSAGE,
        )),
    }
}

/// SHA-256 of the first `CERTIFICATE` block; `None` when there is none
/// or the file is not PEM.
fn first_certificate_sha256(bytes: &[u8]) -> Option<[u8; 32]> {
    Pem::iter_from_buffer(bytes)
        .filter_map(Result::ok)
        .find(|pem| pem.label == "CERTIFICATE")
        .map(|pem| sha256_of(&pem.contents))
}

/// Whether any `CERTIFICATE` block in the bundle has this digest.
fn bundle_contains(bytes: &[u8], sha256: &[u8; 32]) -> bool {
    Pem::iter_from_buffer(bytes)
        .filter_map(Result::ok)
        .any(|pem| pem.label == "CERTIFICATE" && sha256_of(&pem.contents) == *sha256)
}

fn colon_upper(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 3);
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 {
            s.push(':');
        }
        // Writing to a String cannot fail.
        let _ = write!(s, "{b:02X}");
    }
    s
}

/// The refresh tool's name, looking past a `sudo --` prefix.
fn refresh_program(cmd: &CmdLine) -> &str {
    if cmd.program == "sudo" {
        cmd.args.get(1).map_or("", String::as_str)
    } else {
        &cmd.program
    }
}

fn is_refresh(cmd: &CmdLine) -> bool {
    matches!(
        refresh_program(cmd),
        "update-ca-certificates" | "update-ca-trust"
    )
}

/// `update-ca-certificates` reports `<n> added, <m> removed; done.`; the
/// line is worth keeping in the change's detail.
fn refresh_detail(out: &CmdOutput) -> Option<String> {
    out.stdout
        .lines()
        .map(str::trim)
        .find(|l| l.contains("added") && l.contains("removed"))
        .map(|l| format!("update-ca-certificates: {l}"))
}

impl TrustStore for LinuxStore {
    fn platform(&self) -> &Platform {
        match self.0 {
            LinuxFamily::Debian => &DEBIAN,
            LinuxFamily::Fedora => &FEDORA,
        }
    }

    fn status(
        &self,
        cert: &CaCert,
        scope: Scope,
        exec: &dyn Executor,
    ) -> anyhow::Result<StoreStatus> {
        require_system(scope)?;
        let probe = self.probe(cert, exec);
        Ok(StoreStatus {
            scope,
            location: self.anchor(),
            installed: probe.installed,
            trusted: probe.trusted,
            detail: probe.detail,
        })
    }

    fn install(&self, cert: &CaCert, scope: Scope, exec: &dyn Executor) -> anyhow::Result<Change> {
        require_system(scope)?;
        let probe = self.probe(cert, exec);
        let anchor = self.anchor();
        let mut commands = Vec::new();
        let mut detail = Vec::new();

        match (probe.installed, probe.trusted) {
            (Presence::Present, Trust::Yes) => {
                detail.push(format!("{anchor} is in place and in the bundle"));
                return Ok(self.change(false, commands, detail));
            }
            // The anchor was dropped but never extracted into the bundle.
            (Presence::Present, _) => {
                detail.push(format!("{anchor} was in place but not in the bundle"));
            }
            _ => {
                let tee = CmdLine {
                    program: "tee".to_string(),
                    args: vec![anchor.clone()],
                    stdin: Some(cert.pem.as_bytes().to_vec()),
                    mutating: true,
                };
                self.mutate(exec, tee, "install", &mut commands)?;
                detail.push(format!("wrote {anchor}"));
            }
        }

        let out = self.mutate(exec, self.refresh(), "install", &mut commands)?;
        detail.extend(refresh_detail(&out));
        Ok(self.change(true, commands, detail))
    }

    fn uninstall(
        &self,
        cert: &CaCert,
        scope: Scope,
        exec: &dyn Executor,
    ) -> anyhow::Result<Change> {
        require_system(scope)?;
        let probe = self.probe(cert, exec);
        let anchor = self.anchor();
        let mut commands = Vec::new();
        let mut detail = Vec::new();

        if probe.installed == Presence::Absent {
            detail.push(format!("{anchor} is not present"));
            return Ok(self.change(false, commands, detail));
        }
        // Present or Stale: the file is ours by name either way.
        if probe.installed == Presence::Stale {
            detail.push(format!(
                "removed a stale aitmproxy anchor (fingerprint {})",
                probe.anchor_fingerprint.as_deref().unwrap_or("unparsable")
            ));
        }

        self.mutate(
            exec,
            cmd("rm", &["-f", &anchor], true),
            "uninstall",
            &mut commands,
        )?;
        let out = self.mutate(
            exec,
            self.refresh_after_remove(),
            "uninstall",
            &mut commands,
        )?;
        detail.push(format!("removed {anchor}"));
        detail.extend(refresh_detail(&out));
        Ok(self.change(true, commands, detail))
    }
}
