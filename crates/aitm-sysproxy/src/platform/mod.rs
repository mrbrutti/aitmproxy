//! Per-platform mechanisms behind one trait. All of them compile on every
//! host so each mechanism's command lines are unit-tested against canned
//! output wherever the suite runs; only detection (Task 6) consults the
//! target OS.

pub mod linux;
pub mod macos;
pub mod windows;

use aitm_ca::exec::{CmdLine, Executor};

use crate::state::Previous;
use crate::{
    service_equals_wrote, Effective, Endpoint, Mechanism, ReadError, ServiceRow, WriteError, Wrote,
};

/// One mechanism's reads and writes, each a sequence of [`CmdLine`]s run
/// through the executor. Returned `Vec<String>`s are the rendered lines, in
/// order, for the verb's `commands` field.
// `SystemProxy` (Task 6) is the first caller of this trait and the two
// helpers below; the allow goes with it.
#[allow(dead_code)]
pub(crate) trait PlatformOps: Send + Sync {
    fn mechanism(&self) -> Mechanism;
    /// The `detail` to report when the mechanism cannot manage anything
    /// (`None` for mechanisms that can).
    fn detail_when_unsupported(&self) -> Option<String>;
    /// The effective view: `scutil --proxy` / six `gsettings get`.
    fn read_effective(&self, exec: &dyn Executor) -> Result<Effective, ReadError>;
    /// Per-service rows (macOS); Linux yields one synthetic row.
    fn read_services(&self, exec: &dyn Executor) -> Result<Vec<ServiceRow>, ReadError>;
    /// Point every service at `ours`, bypass = previous ∪ default ∪ `bypass_extra`.
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
    /// Per service: does the live row still equal what we wrote (C3)?
    fn equals_wrote(&self, live: &[ServiceRow], wrote: &Wrote) -> Vec<(String, bool)> {
        live.iter()
            .map(|row| (row.service.clone(), service_equals_wrote(row, wrote)))
            .collect()
    }
}

/// The ops for a detected mechanism.
#[allow(dead_code)]
pub(crate) fn ops_for(mechanism: Mechanism) -> Box<dyn PlatformOps> {
    match mechanism {
        Mechanism::Networksetup => Box::new(macos::MacosOps),
        Mechanism::Gsettings => Box::new(linux::GsettingsOps),
        // PLAN GAP (plan Task 1, `ops_for` comment "Kde → linux::KdeOps"): a bare
        // `Mechanism::Kde` does not say which `kwriteconfig`/`kreadconfig` major
        // is on PATH nor whether `gsettings` is present too (§D4). The 6 variants
        // without gsettings are a placeholder until the Architect decides where
        // that probe lives (Task 3's `detect_mechanism` or Task 6's `with_mechanism`).
        Mechanism::Kde => Box::new(linux::KdeOps {
            kwrite: "kwriteconfig6",
            kread: "kreadconfig6",
            gsettings_too: false,
        }),
        Mechanism::None => Box::new(windows::NoneOps),
    }
}

/// A command line with no stdin. `program` and `args` reach the OS as given;
/// quoting exists only in [`CmdLine::render`].
#[allow(dead_code)]
pub(crate) fn cmd(program: &str, args: &[&str], mutating: bool) -> CmdLine {
    CmdLine {
        program: program.to_string(),
        args: args.iter().map(|a| a.to_string()).collect(),
        stdin: None,
        mutating,
    }
}
