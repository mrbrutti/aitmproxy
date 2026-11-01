//! Launch bookkeeping (spec D3, D7): the call waiting for its reply and the
//! UI-3 reason a launch is blocked. `WireConfirm` joins this module in Task 3.

use serde_json::Value;

/// A `scan.start` / `scan.map` / `scan.discover` call sent and not yet
/// answered.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PendingLaunch {
    /// The verb.
    pub call: String,
    /// The arguments as sent (re-issued with `_confirm` after a prompt).
    pub args: Value,
    /// The profile the launch named, for the toast.
    pub profile_name: Option<String>,
}

/// The launch state of the Scan view.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LaunchState {
    pub pending: Option<PendingLaunch>,
    /// The UI-3 reason the launch key is inert, recomputed whenever the
    /// draft, `app.l4.scope` or `app.tools` change; `None` means launchable.
    pub blocked: Option<String>,
}
