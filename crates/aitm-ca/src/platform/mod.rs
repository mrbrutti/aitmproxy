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
/// started) is `ToolMissing`. A non-zero exit is still `Ok`.
pub(crate) fn run(exec: &dyn Executor, cmd: &CmdLine) -> Result<CmdOutput, TrustError> {
    exec.run(cmd).map_err(|e| {
        let message = format!("{e:#}");
        // `RealExecutor` says "timed out" and nothing else does.
        let kind = if message.contains("timed out") {
            TrustErrorKind::Timeout
        } else {
            TrustErrorKind::ToolMissing
        };
        TrustError::new(kind, message)
    })
}

/// The last few non-empty lines of stderr, joined — enough to explain a
/// failure without echoing a whole tool dump into an error message.
pub(crate) fn stderr_tail(out: &CmdOutput) -> String {
    let lines: Vec<&str> = out
        .stderr
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    let start = lines.len().saturating_sub(5);
    lines[start..].join(" | ")
}

/// `` `<rendered>` exited <code>: <stderr tail> `` for a command that ran
/// and failed.
pub(crate) fn failure_text(cmd: &CmdLine, out: &CmdOutput) -> String {
    let code = out
        .code
        .map_or_else(|| "on a signal".to_string(), |c| c.to_string());
    let tail = stderr_tail(out);
    if tail.is_empty() {
        format!("`{}` exited {code}", cmd.render())
    } else {
        format!("`{}` exited {code}: {tail}", cmd.render())
    }
}
