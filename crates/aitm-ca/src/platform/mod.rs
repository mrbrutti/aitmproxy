//! Per-platform `TrustStore` implementations. All three compile on every
//! host so each platform's command lines are unit-tested against canned
//! output wherever the suite runs; only `Platform::detect` consults the
//! target OS.
//!
//! The helpers here are what the three stores share: building a
//! [`CmdLine`], the `sudo --` prefix of the privilege model, mapping an
//! executor failure to a [`TrustError`], and quoting a failed command's
//! stderr in an error message.

pub mod linux;
pub mod macos;
pub mod windows;

use tracing::debug;

use crate::exec::{CmdLine, CmdOutput, Executor};
use crate::store::{TrustError, TrustErrorKind};

/// A command line with no stdin. `program` and `args` reach the OS as given.
pub(crate) fn cmd(program: &str, args: &[&str], mutating: bool) -> CmdLine {
    CmdLine {
        program: program.to_string(),
        args: args.iter().map(|a| a.to_string()).collect(),
        stdin: None,
        mutating,
    }
}

/// The privilege model: a privileged command is prefixed `sudo --` unless
/// the executor already is root. The process never escalates itself; the
/// user's own `sudo` prompts on the controlling terminal.
pub(crate) fn sudo_if_needed(mut cmd: CmdLine, exec: &dyn Executor) -> CmdLine {
    if exec.is_root() {
        return cmd;
    }
    let mut args = vec!["--".to_string(), std::mem::take(&mut cmd.program)];
    args.append(&mut cmd.args);
    cmd.program = "sudo".to_string();
    cmd.args = args;
    cmd
}

/// Run `cmd`, turning the executor's own failures into a [`TrustError`]:
/// a timeout is `Timeout`, anything else (the program could not be
/// started) is `ToolMissing`. A non-zero exit is still `Ok`. Every command
/// that ran is one `debug!` with its rendered line and exit code (spec §D8
/// Logging; `-1` when the child died on a signal).
pub(crate) fn run(exec: &dyn Executor, cmd: &CmdLine) -> Result<CmdOutput, TrustError> {
    let out = exec.run(cmd).map_err(|e| {
        let message = format!("{e:#}");
        // `RealExecutor` says "timed out" and nothing else does.
        let kind = if message.contains("timed out") {
            TrustErrorKind::Timeout
        } else {
            TrustErrorKind::ToolMissing
        };
        TrustError::new(kind, message)
    })?;
    debug!(
        target: "aitm_ca",
        command_line = cmd.render().as_str(),
        code = out.code.unwrap_or(-1),
        "ran trust-store command"
    );
    Ok(out)
}

/// The last five non-empty lines of `lines`, trimmed and joined with
/// `" | "` — enough to explain a failure without echoing a whole tool dump
/// into an error message.
pub(crate) fn tail_of<'a>(lines: impl Iterator<Item = &'a str>) -> String {
    let lines: Vec<&str> = lines.map(str::trim).filter(|l| !l.is_empty()).collect();
    let start = lines.len().saturating_sub(5);
    lines[start..].join(" | ")
}

/// [`tail_of`] over stderr alone.
pub(crate) fn stderr_tail(out: &CmdOutput) -> String {
    tail_of(out.stderr.lines())
}

/// `` `<rendered>` exited <code>: <tail> `` for a command that ran and
/// failed, with the caller's choice of tail; no colon when it is empty.
pub(crate) fn failure_text_with_tail(cmd: &CmdLine, out: &CmdOutput, tail: &str) -> String {
    let code = out
        .code
        .map_or_else(|| "on a signal".to_string(), |c| c.to_string());
    if tail.is_empty() {
        format!("`{}` exited {code}", cmd.render())
    } else {
        format!("`{}` exited {code}: {tail}", cmd.render())
    }
}

/// [`failure_text_with_tail`] with the stderr tail.
pub(crate) fn failure_text(cmd: &CmdLine, out: &CmdOutput) -> String {
    failure_text_with_tail(cmd, out, &stderr_tail(out))
}
