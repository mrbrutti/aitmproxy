//! `ScriptError`: the one error type for the scripting tier, with the spec §8
//! pinned human-readable format (script, position, what, then the fix).

use std::path::PathBuf;
use std::time::Duration;

use aitm_core::GuardError;

/// Everything that can go wrong loading or running a script, carrying what a
/// human needs to fix it. `Display` renders the spec §8 pinned format:
///
/// ```text
/// error: <script>[:line[:col]] — <what>
///   reason: <typed cause, where one exists>
///   help: <the fix>
/// ```
#[derive(Debug, Clone, PartialEq)]
pub enum ScriptError {
    /// The file did not parse/compile; the proxy skips it (unless `strict`).
    Compile {
        script: String,
        path: PathBuf,
        line: usize,
        column: usize,
        message: String,
        hint: Option<String>,
    },
    /// A hook threw or hit a runtime fault; the flow proceeded unchanged.
    Runtime {
        script: String,
        hook: String,
        line: usize,
        message: String,
    },
    /// A hook ran past `hook_timeout` wall-clock and was aborted.
    Timeout {
        script: String,
        hook: String,
        elapsed: Duration,
    },
    /// A hook exceeded `max_operations` and was aborted.
    OpLimit {
        script: String,
        hook: String,
        operations: u64,
    },
    /// A guarded host call was refused by the scope/rate/SSRF guard.
    Denied {
        script: String,
        hook: String,
        capability: String,
        reason: GuardError,
    },
    /// The script's declared `API` is not one this build supports.
    ApiVersion {
        script: String,
        declared: String,
        supported: String,
    },
}

/// The help text shared by every "the hook was aborted" class.
const HELP_ABORTED: &str =
    "the flow was forwarded unchanged. Move long work to a command, or\n        \
                            reduce the loop; limits are set under `rhai:` in the config.";

const HELP_DENIED: &str = "scripts reach the network only through scope-approved hosts.\n        \
                           Add the host with `scope.add(...)` or the `scope:` config if it is in scope.";

const HELP_RUNTIME: &str = "the flow was forwarded unchanged. Fix the hook and reload the script.";

const HELP_API: &str = "set the script's `const API` to the supported version, or upgrade aitm.";

impl std::fmt::Display for ScriptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScriptError::Compile {
                script,
                line,
                column,
                message,
                hint,
                ..
            } => {
                write!(f, "error: {script}:{line}:{column} — {message}")?;
                if let Some(hint) = hint {
                    write!(f, "\n  help: {hint}")?;
                }
                Ok(())
            }
            ScriptError::Runtime {
                script,
                hook,
                line,
                message,
            } => write!(
                f,
                "error: {script}:{line} — hook '{hook}' failed: {message}\n  help: {HELP_RUNTIME}"
            ),
            ScriptError::Timeout {
                script,
                hook,
                elapsed,
            } => write!(
                f,
                "error: {script} — hook '{hook}' exceeded its {elapsed:?} time budget\n  help: {HELP_ABORTED}"
            ),
            ScriptError::OpLimit {
                script,
                hook,
                operations,
            } => write!(
                f,
                "error: {script} — hook '{hook}' exceeded its {operations} operation budget\n  help: {HELP_ABORTED}"
            ),
            ScriptError::Denied {
                script,
                hook,
                capability,
                reason,
            } => write!(
                f,
                "error: {script} — hook '{hook}' was denied capability '{capability}'\n  reason: {reason:?}\n  help: {HELP_DENIED}"
            ),
            ScriptError::ApiVersion {
                script,
                declared,
                supported,
            } => write!(
                f,
                "error: {script} — declares API '{declared}' but this build supports '{supported}'\n  help: {HELP_API}"
            ),
        }
    }
}

impl std::error::Error for ScriptError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ScriptError::Denied { reason, .. } => Some(reason),
            _ => None,
        }
    }
}
