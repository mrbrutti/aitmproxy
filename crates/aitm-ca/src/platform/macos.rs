//! macOS: `security find-certificate` / `verify-cert` / `add-trusted-cert` /
//! `remove-trusted-cert` / `delete-certificate` against the login and System
//! keychains.
//!
//! Presence is what `find-certificate -a -Z` prints. Trust is one
//! `verify-cert -l -L -p basic` evaluation, run only when the certificate is
//! present (spec D17.3). The policy is `basic`, not `ssl`: `-p ssl` rejects
//! every CA certificate with "Invalid Extended Key Usage for policy", trusted
//! or not (the read-only probe recorded under "Task 32 result" in
//! `docs/superpowers/plans/2026-10-31-ca-trust-first-run-plan.md`); our
//! install sets both policies, so a `basic` verdict reflects HTTPS trust for
//! every path the app offers. Trust settings are per user and per certificate
//! hash, not per keychain, so both scopes report the same evaluation. Every
//! mutation is check-first, and `install` on a present certificate reads
//! trust back and replaces an untrusted copy (plan correction 8), which keeps
//! the design independent of what a duplicate `add-trusted-cert` does.

use crate::cert::CaCert;
use crate::exec::{CmdLine, CmdOutput, Executor};
use crate::platform::{
    cmd, failure_text, failure_text_with_tail, run, stderr_tail, sudo_if_needed, tail_of,
};
use crate::store::{
    Change, Platform, Presence, Scope, StoreStatus, Trust, TrustError, TrustErrorKind, TrustStore,
};
use tracing::debug;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MacOsStore;

static PLATFORM: Platform = Platform::MacOs;

const SYSTEM_KEYCHAIN: &str = "/Library/Keychains/System.keychain";
const LOGIN_KEYCHAIN: &str = "Library/Keychains/login.keychain-db";

/// Shown on every status answer: what ran for presence and what ran for trust.
const DETAIL: &str = "macOS: presence from `security find-certificate`; trust from `security \
                      verify-cert` (basic policy, local only; our install sets the ssl and \
                      basic policies together)";

/// `verify-cert`'s stdout contains this on exit 0 (the literal the probe
/// quoted; see the module docs).
const VERIFY_SUCCESS: &str = "certificate verification successful";

/// What `add-trusted-cert` says (case-insensitively) when the authentication
/// dialog was dismissed; Apple spells it "canceled".
const CANCEL_MARKER: &str = "cancel";

const CANCELLED_MESSAGE: &str = "ca.install cancelled: the macOS authentication dialog was \
                                 dismissed; the CA is not trusted";

const HEADLESS_HINT: &str = "macOS refused to change trust settings without a GUI session; run \
                             aitm ca install from a terminal in a logged-in desktop session";

/// What `add-trusted-cert` says (case-insensitively) when there is no
/// desktop session to show the authorization dialog in.
const HEADLESS_MARKERS: [&str; 3] = [
    "no user interaction was possible",
    "authorization was denied",
    "user interaction is not allowed",
];

/// Duplicate copies (research 07 §3.1): delete-and-requery this many times
/// before giving up with `CopiesRemain`.
const MAX_DELETE_PASSES: usize = 3;

/// One operation against one keychain: knows the scope's keychain path,
/// applies `sudo` to System-scope mutations, and keeps the rendered lines
/// for the [`Change`] report.
struct Op<'a> {
    cert: &'a CaCert,
    scope: Scope,
    keychain: String,
    exec: &'a dyn Executor,
    commands: Vec<String>,
}

impl<'a> Op<'a> {
    fn new(cert: &'a CaCert, scope: Scope, exec: &'a dyn Executor) -> Result<Self, TrustError> {
        let keychain = match scope {
            Scope::System => SYSTEM_KEYCHAIN.to_string(),
            Scope::User => exec
                .home_dir()
                .map(|home| home.join(LOGIN_KEYCHAIN).display().to_string())
                .ok_or_else(|| {
                    TrustError::new(
                        TrustErrorKind::ToolFailed,
                        "could not determine the home directory that holds the login keychain",
                    )
                })?,
        };
        Ok(Self {
            cert,
            scope,
            keychain,
            exec,
            commands: Vec::new(),
        })
    }

    fn run(&mut self, cmd: &CmdLine) -> Result<CmdOutput, TrustError> {
        self.commands.push(cmd.render());
        run(self.exec, cmd)
    }

    /// `security find-certificate -a -Z <K>`: never `sudo`, the System
    /// keychain is world-readable.
    fn query(&mut self) -> Result<(CmdLine, CmdOutput), TrustError> {
        let keychain = self.keychain.clone();
        let cmd = cmd(
            "security",
            &["find-certificate", "-a", "-Z", &keychain],
            false,
        );
        let out = self.run(&cmd)?;
        Ok((cmd, out))
    }

    /// `security verify-cert -c <cert> -l -L -p basic`, never `sudo`: `-l`
    /// marks the leaf as a CA, `-L` keeps the evaluation local. `Yes` on exit 0
    /// with [`VERIFY_SUCCESS`] in stdout; otherwise `No` with a detail line;
    /// `Err` only when the tool could not run (the caller reports `Unknown`).
    fn verify_trust(&mut self) -> Result<(Trust, Option<String>), TrustError> {
        let path = self.cert.path.display().to_string();
        let cmd = cmd(
            "security",
            &["verify-cert", "-c", &path, "-l", "-L", "-p", "basic"],
            false,
        );
        let out = self.run(&cmd)?;
        if !out.success() {
            return Ok((Trust::No, Some(verify_failure_text(&cmd, &out))));
        }
        if out.stdout.contains(VERIFY_SUCCESS) {
            return Ok((Trust::Yes, None));
        }
        Ok((
            Trust::No,
            Some(format!(
                "`{}` exited 0 without \"{VERIFY_SUCCESS}\" in its output",
                cmd.render()
            )),
        ))
    }

    /// Presence, or `ToolFailed` when the query itself failed: a mutation
    /// must not proceed on a guess.
    fn presence(&mut self) -> Result<Presence, TrustError> {
        let (cmd, out) = self.query()?;
        match parse_presence(&out, self.cert) {
            Presence::Unknown => Err(TrustError::new(
                TrustErrorKind::ToolFailed,
                failure_text(&cmd, &out),
            )),
            presence => Ok(presence),
        }
    }

    /// `[sudo] security <sub> [-d] <rest…>`: `sudo --` and `-d` (the admin
    /// trust domain) only for the System scope, and `-d` only where the
    /// subcommand takes it (`trust_domain`).
    fn mutate(
        &mut self,
        sub: &str,
        trust_domain: bool,
        rest: &[&str],
    ) -> Result<(CmdLine, CmdOutput), TrustError> {
        let system = self.scope == Scope::System;
        let mut args = vec![sub];
        if system && trust_domain {
            args.push("-d");
        }
        args.extend_from_slice(rest);
        let mut cmd = cmd("security", &args, true);
        if system {
            cmd = sudo_if_needed(cmd, self.exec);
        }
        let out = self.run(&cmd)?;
        Ok((cmd, out))
    }

    fn finish(self, changed: bool, detail: Vec<String>) -> Change {
        Change {
            changed,
            scope: self.scope,
            location: self.keychain,
            commands: self.commands,
            detail,
        }
    }
}

/// `find-certificate -a -Z` prints one block per certificate, each starting
/// with `SHA-256 hash:` and/or `SHA-1 hash:` (older macOS prints SHA-1
/// only). Ours is present if either hash matches.
fn parse_presence(out: &CmdOutput, cert: &CaCert) -> Presence {
    if !out.success() {
        return Presence::Unknown;
    }
    let sha256 = cert.sha256_hex();
    let sha1 = cert.sha1_hex_lower();
    for line in out.stdout.lines() {
        let line = line.trim();
        let matched = match (
            line.strip_prefix("SHA-256 hash:"),
            line.strip_prefix("SHA-1 hash:"),
        ) {
            (Some(hash), _) => hash.trim().eq_ignore_ascii_case(&sha256),
            (None, Some(hash)) => hash.trim().eq_ignore_ascii_case(&sha1),
            (None, None) => false,
        };
        if matched {
            return Presence::Present;
        }
    }
    Presence::Absent
}

fn is_headless(out: &CmdOutput) -> bool {
    let stderr = out.stderr.to_lowercase();
    HEADLESS_MARKERS.iter().any(|m| stderr.contains(m))
}

fn is_cancelled(out: &CmdOutput) -> bool {
    out.stderr.to_lowercase().contains(CANCEL_MARKER)
}

/// `verify-cert` prints its verdict (`Cert Verify Result: …`) on stdout, so a
/// failed evaluation's tail is taken from both streams, stdout first.
fn verify_failure_text(cmd: &CmdLine, out: &CmdOutput) -> String {
    let tail = tail_of(out.stdout.lines().chain(out.stderr.lines()));
    failure_text_with_tail(cmd, out, &tail)
}

impl TrustStore for MacOsStore {
    fn platform(&self) -> &Platform {
        &PLATFORM
    }

    fn status(
        &self,
        cert: &CaCert,
        scope: Scope,
        exec: &dyn Executor,
    ) -> anyhow::Result<StoreStatus> {
        let mut op = Op::new(cert, scope, exec)?;
        let (cmd, out) = op.query()?;
        let installed = parse_presence(&out, cert);
        let mut detail = vec![DETAIL.to_string()];
        let trusted = match installed {
            Presence::Present => match op.verify_trust() {
                Ok((trust, line)) => {
                    detail.extend(line);
                    trust
                }
                Err(e) => {
                    detail.push(e.to_string());
                    Trust::Unknown
                }
            },
            Presence::Unknown => {
                detail.push(failure_text(&cmd, &out));
                Trust::Unknown
            }
            Presence::Absent | Presence::Stale => Trust::No,
        };
        Ok(StoreStatus {
            scope,
            location: op.keychain,
            installed,
            trusted,
            detail,
        })
    }

    fn install(&self, cert: &CaCert, scope: Scope, exec: &dyn Executor) -> anyhow::Result<Change> {
        let mut op = Op::new(cert, scope, exec)?;
        let keychain = op.keychain.clone();
        let mut detail = Vec::new();
        if op.presence()? == Presence::Present {
            // Presence is not trust: a copy left by a dismissed dialog whose
            // rollback failed, or imported by hand, has no trust settings.
            match op.verify_trust() {
                Ok((Trust::Yes, _)) => {
                    return Ok(op.finish(
                        false,
                        vec![format!("already present and trusted in {keychain}")],
                    ));
                }
                Err(e) => {
                    return Ok(op.finish(
                        false,
                        vec![format!("already present in {keychain}"), e.to_string()],
                    ));
                }
                Ok(_) => {
                    let sha256 = cert.sha256_hex();
                    let (cmd, out) =
                        op.mutate("delete-certificate", false, &["-Z", &sha256, &keychain])?;
                    if !out.success() {
                        return Err(TrustError::new(
                            TrustErrorKind::ToolFailed,
                            format!(
                                "could not remove the untrusted copy from {keychain}: {}",
                                failure_text(&cmd, &out)
                            ),
                        )
                        .into());
                    }
                    detail.push(format!("replaced the untrusted copy in {keychain}"));
                }
            }
        }

        let path = cert.path.display().to_string();
        let (cmd, out) = op.mutate(
            "add-trusted-cert",
            true,
            &[
                "-r",
                "trustRoot",
                "-p",
                "ssl",
                "-p",
                "basic",
                "-k",
                &keychain,
                &path,
            ],
        )?;
        if out.success() {
            detail.push(format!(
                "added to {keychain} as a trusted root for ssl and basic"
            ));
            return Ok(op.finish(true, detail));
        }

        let (kind, mut message) = if is_headless(&out) {
            (
                TrustErrorKind::HeadlessAuth,
                format!("{HEADLESS_HINT} ({})", failure_text(&cmd, &out)),
            )
        } else if is_cancelled(&out) {
            debug!(
                target: "aitm_ca",
                stderr_tail = stderr_tail(&out).as_str(),
                "add-trusted-cert classified as cancelled"
            );
            (TrustErrorKind::Cancelled, CANCELLED_MESSAGE.to_string())
        } else {
            (TrustErrorKind::ToolFailed, failure_text(&cmd, &out))
        };

        // Rollback, best effort: a failed add-trusted-cert can leave the
        // certificate in the keychain without trust settings, where it
        // would make `status` say present. The original error is what the
        // caller sees either way.
        if let Ok((_, requery)) = op.query() {
            if parse_presence(&requery, cert) == Presence::Present {
                let sha256 = cert.sha256_hex();
                let rolled_back = op
                    .mutate("delete-certificate", false, &["-Z", &sha256, &keychain])
                    .map(|(_, out)| out.success())
                    .unwrap_or(false);
                message.push_str(if rolled_back {
                    "; removed the untrusted copy it left behind"
                } else {
                    "; an untrusted copy may remain in the keychain"
                });
            }
        }

        Err(TrustError::new(kind, message).into())
    }

    fn uninstall(
        &self,
        cert: &CaCert,
        scope: Scope,
        exec: &dyn Executor,
    ) -> anyhow::Result<Change> {
        let mut op = Op::new(cert, scope, exec)?;
        let keychain = op.keychain.clone();
        if op.presence()? == Presence::Absent {
            return Ok(op.finish(false, vec![format!("not present in {keychain}")]));
        }

        let mut detail = Vec::new();

        // A certificate without trust settings has nothing to remove here,
        // so a failure is recorded, not fatal.
        let path = cert.path.display().to_string();
        let (cmd, out) = op.mutate("remove-trusted-cert", true, &[&path])?;
        if !out.success() {
            detail.push(format!(
                "{} (no trust settings to remove)",
                failure_text(&cmd, &out)
            ));
        }

        let sha256 = cert.sha256_hex();
        let sha1 = cert.sha1_hex_lower();
        for pass in 1..=MAX_DELETE_PASSES {
            let (cmd, out) = op.mutate("delete-certificate", false, &["-Z", &sha256, &keychain])?;
            if !out.success() {
                // Older macOS keys the keychain on SHA-1.
                let (cmd1, out1) =
                    op.mutate("delete-certificate", false, &["-Z", &sha1, &keychain])?;
                if !out1.success() {
                    return Err(TrustError::new(
                        TrustErrorKind::ToolFailed,
                        format!(
                            "{}; {}",
                            failure_text(&cmd, &out),
                            failure_text(&cmd1, &out1)
                        ),
                    )
                    .into());
                }
            }
            if op.presence()? != Presence::Present {
                detail.push(format!("removed from {keychain}"));
                if pass > 1 {
                    detail.push(format!("{pass} copies were present"));
                }
                return Ok(op.finish(true, detail));
            }
        }

        Err(TrustError::new(
            TrustErrorKind::CopiesRemain,
            format!(
                "copies of the certificate remain in {keychain} after {MAX_DELETE_PASSES} delete \
                 passes; remove them in Keychain Access"
            ),
        )
        .into())
    }
}
