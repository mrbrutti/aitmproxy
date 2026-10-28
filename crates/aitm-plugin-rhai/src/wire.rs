//! Wiring the tier into a host program (plan Task 15).
//!
//! A host (the `aitm` binary, or a test) needs four things out of one build of
//! the scripting tier, and they must all come from the **same** engine: the
//! plugins to register in the chain, the errors of whatever did not compile,
//! the executor the PoC runner dispatches `script` steps through, and the
//! error sink the chain is bound into once it exists. [`build`] returns all
//! four; [`load_scripts`] is the one-line form for a host that only wants
//! plugins, and [`executor`] builds the PoC-side half from a loader the caller
//! already has.
//!
//! Sharing the engine is not an optimization — it is what makes "one scripting
//! surface, reused" (spec Goals) true: a PoC `script` step sees exactly the
//! host functions, prelude, and limits a plugin hook sees, because it is the
//! same `Engine`.

use std::sync::Arc;

use crate::config::RhaiConfig;
use crate::error::ScriptError;
use crate::host_core::ScriptServices;
use crate::loader::RhaiLoader;
use crate::plugin::{ErrorSink, ScriptPlugin};
use crate::poc_step::RhaiScriptExecutor;

/// One built scripting tier, ready to wire.
pub struct ScriptTier {
    /// Compiled scripts, in declaration order — the order they take in the
    /// chain after the native plugins (spec §8).
    pub plugins: Vec<ScriptPlugin>,
    /// What did not compile. Non-empty is survivable unless the config is
    /// `strict`, which is the caller's call to make (spec §8).
    pub errors: Vec<ScriptError>,
    /// The PoC `script`-step executor over the same engine the plugins use.
    pub executor: Arc<RhaiScriptExecutor>,
    /// Bind the chain into this once it exists, so a failed hook's
    /// `Event::Error` reaches the bus instead of only the log.
    pub error_sink: Arc<ErrorSink>,
}

/// Build the whole tier: one engine, every declared script compiled on it, and
/// the PoC executor sharing it.
///
/// Fails only when the *engine* cannot be built (a limit so tight the bundled
/// prelude will not compile). A script that does not compile lands in
/// [`ScriptTier::errors`]; whether that is fatal is `cfg.strict`, which the
/// caller enforces because only it knows how to exit.
pub fn build(cfg: RhaiConfig, services: ScriptServices) -> Result<ScriptTier, ScriptError> {
    let loader = RhaiLoader::new(cfg, services)?;
    let (plugins, errors) = loader.load_all();
    Ok(ScriptTier {
        plugins,
        errors,
        executor: Arc::new(executor(&loader)),
        error_sink: loader.error_sink(),
    })
}

/// Compile every enabled script in `cfg` and report what did not, for a host
/// that wants plugins and nothing else. An engine that cannot be built is
/// reported as the single error.
pub fn load_scripts(
    cfg: RhaiConfig,
    services: ScriptServices,
) -> (Vec<ScriptPlugin>, Vec<ScriptError>) {
    match RhaiLoader::new(cfg, services) {
        Ok(loader) => loader.load_all(),
        Err(err) => (Vec::new(), vec![err]),
    }
}

/// The PoC `script`-step executor over `loader`'s engine and services.
pub fn executor(loader: &RhaiLoader) -> RhaiScriptExecutor {
    RhaiScriptExecutor::new(loader.engine(), loader.services().clone())
}
