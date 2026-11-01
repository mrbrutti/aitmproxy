//! Per-platform mechanisms behind one trait. All of them compile on every
//! host so each mechanism's command lines are unit-tested against canned
//! output wherever the suite runs; only detection (`SystemProxy::detect_with`)
//! consults the target OS.

pub mod linux;
pub mod macos;
pub mod windows;

use aitm_ca::exec::{CmdLine, Executor};

use crate::state::Previous;
use crate::{Effective, Endpoint, Mechanism, ReadError, ServiceRow, WriteError};

/// The before-state a set records (§D7) and the services it must not write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Snapshot {
    /// What `restore` puts back; excludes `skipped`.
    pub previous: Previous,
    /// macOS services with `Authenticated Proxy Enabled: 1` (§D3): their
    /// password cannot be restored, so the engine leaves them alone and
    /// reports "skipped <svc>: authenticated proxy". Empty on Linux.
    pub skipped: Vec<String>,
}

/// One mechanism's reads and writes, each a sequence of [`CmdLine`]s run
/// through the executor. Returned `Vec<String>`s are the rendered lines, in
/// order, for the verb's `commands` field.
pub(crate) trait PlatformOps: Send + Sync {
    fn mechanism(&self) -> Mechanism;
    /// The effective view: `scutil --proxy` / six `gsettings get`.
    fn read_effective(&self, exec: &dyn Executor) -> Result<Effective, ReadError>;
    /// Per-service rows (macOS); Linux yields one synthetic row (two on KDE
    /// with gsettings mirrored).
    fn read_services(&self, exec: &dyn Executor) -> Result<Vec<ServiceRow>, ReadError>;
    /// The before-state for the state file, taken before the first mutating
    /// line. Runs reads only.
    fn snapshot(&self, exec: &dyn Executor) -> Result<Snapshot, ReadError>;
    /// Point every service in `previous` at `ours`, bypass = previous ∪
    /// default ∪ `bypass_extra`. Stops at the first failure and reports
    /// nothing about what was already written (the engine rolls back every
    /// service in `previous`, plan C7).
    fn write(
        &self,
        exec: &dyn Executor,
        previous: &Previous,
        ours: &Endpoint,
        bypass_extra: &[String],
    ) -> Result<Vec<String>, WriteError>;
    /// Restore the services named in `only` from `previous`.
    fn restore(
        &self,
        exec: &dyn Executor,
        previous: &Previous,
        only: &[String],
    ) -> Result<Vec<String>, WriteError>;
}

// "Does a live row still equal what we wrote" has one implementation,
// `crate::service_equals_wrote` (plan C3); the engine and the watchdog both
// judge a whole file against a live read through `watchdog::partition`, so
// the trait carries no per-mechanism equality hook.

/// The ops for a bare mechanism word: what the watchdog has (the state file
/// names the mechanism, nothing else) and what the public
/// `SystemProxy::with_mechanism` test constructor takes. `detect_with`
/// builds its ops from the full detection instead.
pub(crate) fn ops_for(mechanism: Mechanism) -> Box<dyn PlatformOps> {
    match mechanism {
        Mechanism::Networksetup => Box::new(macos::MacosOps),
        Mechanism::Gsettings => Box::new(linux::GsettingsOps),
        // A bare `Kde` cannot say which `kwriteconfig` major is on PATH nor
        // whether `gsettings` is present too, so both are resolved from this
        // host at runtime: a watchdog restore on a Plasma 5 host uses
        // `kwriteconfig5`, not an assumed 6 (the mirrored gsettings keys are
        // restored from the snapshot's content regardless of `gsettings_too`).
        Mechanism::Kde => Box::new(linux::kde_ops_from_host()),
        Mechanism::None => Box::new(windows::NoneOps),
    }
}

/// A command line with no stdin. `program` and `args` reach the OS as given;
/// quoting exists only in [`CmdLine::render`].
pub(crate) fn cmd(program: &str, args: &[&str], mutating: bool) -> CmdLine {
    CmdLine {
        program: program.to_string(),
        args: args.iter().map(|a| a.to_string()).collect(),
        stdin: None,
        mutating,
    }
}
