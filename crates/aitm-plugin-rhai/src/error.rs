//! `ScriptError`: the one error type for the scripting tier, with the spec §8
//! pinned human-readable format (script, position, what, then the fix).

use std::path::PathBuf;
use std::time::Duration;

use aitm_core::GuardError;
use aitm_plugin::language::RegisterError;
use rhai::EvalAltResult;

use crate::engine::{AbortKind, Budget};
use crate::host_net::DeniedToken;

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
    /// A hook ran past `hook_timeout` wall-clock — or one of its `browser.*`
    /// calls past `browser_timeout` — and was aborted. `elapsed` is the budget
    /// that fired.
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
    /// The script declares an `API` older than a capability's `min_api`, so it
    /// is not loaded: deny-by-default never hands a lower-API script a namespace
    /// written for a newer contract.
    CapabilityDenied {
        script: String,
        declared: String,
        namespace: String,
        min_api: String,
    },
    /// Two seam protocol languages claimed the same `<namespace>.<name>` while
    /// the loader built its engine; registration never last-wins (Task 2 Review
    /// Focus, surfaced on the loader's build path by Task 7).
    LanguageCollision { namespace: String, name: String },
}

impl From<RegisterError> for ScriptError {
    fn from(err: RegisterError) -> Self {
        match err {
            RegisterError::Collision { namespace, name } => {
                ScriptError::LanguageCollision { namespace, name }
            }
        }
    }
}

impl ScriptError {
    /// The `ScriptError` a failed evaluation amounts to: which budget it
    /// blew (named with the configured figure), which capability refused it,
    /// or where it threw. One classifier for every entry point — hook, `load`,
    /// command, PoC step — so the pinned format is the same everywhere.
    pub fn from_eval(script: &str, hook: &str, err: &EvalAltResult, budget: &Budget) -> Self {
        let script = script.to_string();
        let hook = hook.to_string();
        let op_limit = |script, hook| ScriptError::OpLimit {
            script,
            hook,
            operations: budget.max_operations,
        };
        match err {
            EvalAltResult::ErrorTerminated(token, _) => {
                match token.clone().try_cast::<AbortKind>() {
                    Some(AbortKind::OpLimit) => return op_limit(script, hook),
                    Some(AbortKind::Timeout) => {
                        return ScriptError::Timeout {
                            script,
                            hook,
                            elapsed: budget.hook_timeout,
                        }
                    }
                    Some(AbortKind::BrowserTimeout) => {
                        return ScriptError::Timeout {
                            script,
                            hook,
                            elapsed: budget.browser_timeout,
                        }
                    }
                    None => {}
                }
            }
            // The engine's own hard cap, one operation above the token's
            // threshold (see `engine::harden`).
            EvalAltResult::ErrorTooManyOperations(_) => return op_limit(script, hook),
            _ => {}
        }
        // A throw inside the hook body arrives wrapped in `ErrorInFunctionCall`
        // (one layer per script function on the way out); the cause — and
        // the position worth reporting — is the innermost error.
        let cause = innermost(err);
        if let EvalAltResult::ErrorRuntime(value, _) = cause {
            if let Some(denied) = value.clone().try_cast::<DeniedToken>() {
                return ScriptError::Denied {
                    script,
                    hook,
                    capability: denied.capability,
                    reason: denied.reason,
                };
            }
        }
        ScriptError::Runtime {
            script,
            hook,
            line: cause.position().line().unwrap_or(0),
            message: describe(cause),
        }
    }
}

/// The error at the bottom of a chain of script function calls.
fn innermost(err: &EvalAltResult) -> &EvalAltResult {
    match err {
        EvalAltResult::ErrorInFunctionCall(_, _, inner, _) => innermost(inner),
        other => other,
    }
}

/// What went wrong, in one line without Rhai's own framing: a thrown value
/// reads as itself (a thrown denial as its message), anything else as Rhai
/// renders it minus the trailing position, which the pinned format already
/// carries.
pub fn describe(err: &EvalAltResult) -> String {
    if let EvalAltResult::ErrorRuntime(value, _) = err {
        if let Some(denied) = value.clone().try_cast::<DeniedToken>() {
            return denied.to_string();
        }
        if let Some(text) = value.read_lock::<rhai::ImmutableString>() {
            return text.to_string();
        }
    }
    let mut text = err.to_string();
    if let Some(i) = text.rfind(" (line ") {
        if text.ends_with(')') {
            text.truncate(i);
        }
    }
    text
}

/// The help text shared by every "the hook was aborted" class.
const HELP_ABORTED: &str =
    "the flow was forwarded unchanged. Move long work to a command, or\n        \
                            reduce the loop; limits are set under `rhai:` in the config.";

const HELP_DENIED: &str = "scripts reach the network only through scope-approved hosts.\n        \
                           Add the host with `scope.add(...)` or the `scope:` config if it is in scope.";

const HELP_RUNTIME: &str = "the flow was forwarded unchanged. Fix the hook and reload the script.";

const HELP_API: &str = "set the script's `const API` to the supported version, or upgrade aitm.";

const HELP_CAP: &str = "raise the script's `const API` to the capability's version once the script \
                        is written for that contract; a lower-API script is denied the namespace by \
                        default.";

const HELP_COLLISION: &str = "two protocol languages registered the same host function; each \
                              namespace must be owned by one language.";

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
            ScriptError::CapabilityDenied {
                script,
                declared,
                namespace,
                min_api,
            } => write!(
                f,
                "error: {script} — declares API '{declared}' but the '{namespace}' capability \
                 requires API '{min_api}' or newer\n  help: {HELP_CAP}"
            ),
            ScriptError::LanguageCollision { namespace, name } => write!(
                f,
                "error: host function '{namespace}.{name}' is registered by two protocol \
                 languages\n  help: {HELP_COLLISION}"
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
