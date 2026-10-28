//! `RhaiLoader`: builds the shared engine, compiles each script once, validates,
//! and yields one `ScriptPlugin` per script (plan Task 9).
//!
//! One hardened engine (Task 2) carries the whole host surface — the flow API
//! (Task 5), every `ScriptCapability` provider M3 ships (Tasks 6, 7) and the
//! bundled prelude (Task 11) — registered once in [`RhaiLoader::new`]. Each
//! `.rhai` file is then compiled once into an `AST`, its metadata read off the
//! AST without running it (`const NAME`, `const API`, the hooks it defines),
//! and wrapped as a [`ScriptPlugin`] that takes its own place in the chain.
//!
//! **Error policy (spec §8).** A script that does not compile is skipped with
//! a logged, positioned [`ScriptError::Compile`] and the rest still load, so a
//! typo never costs the engagement its proxy; `strict` flips that to
//! fail-fast — [`RhaiLoader::load_all`] then yields no plugins and every
//! error, so CI sees them all in one run. A missing or unsupported `API` is a
//! one-line warning, not a failure (spec §2 rule 1).
//!
//! **Ordering.** [`RhaiLoader::load_all`] keeps `cfg.scripts` order, which is
//! the chain order the wiring registers scripts in after the native plugins
//! (spec §8).

use std::fs;
use std::path::Path;
use std::sync::Arc;

use rhai::{Dynamic, Engine, ParseError, ParseErrorType, AST};

use crate::command::register_reg_api;
use crate::config::{RhaiConfig, ScriptEntry, ScriptMeta};
use crate::engine::{build_engine, Budget};
use crate::error::ScriptError;
use crate::flow_api::register_flow_api;
use crate::host_core::{
    FindingCapability, LogCapability, Options, ScriptCapability, ScriptServices,
};
use crate::host_net::{BrowserCapability, HttpCapability, ScopeCapability, StoreCapability};
use crate::plugin::{ErrorSink, ScriptPlugin};
use crate::poc_step::VarsCapability;
use crate::prelude::register_prelude;

/// The script `API` contract this build supports: M3's first and only one.
pub const SUPPORTED_API: &str = "1";

/// Every hook a script may define (spec §3), in the order a flow meets them,
/// with the parameters each is called with.
const HOOKS: [(&str, &[&str]); 10] = [
    ("load", &["reg"]),
    ("configure", &[]),
    ("on_request_headers", &["flow"]),
    ("on_request", &["flow"]),
    ("on_response_headers", &["flow"]),
    ("on_response", &["flow"]),
    ("on_ws_start", &["flow"]),
    ("on_ws_message", &["flow", "msg"]),
    ("on_ws_end", &["flow"]),
    ("on_error", &["flow", "err"]),
];

/// Log target for what the loader does and skips, so an operator can read
/// "what is loaded" off the log as well as off the config.
const LOADER_TARGET: &str = "aitm_plugin_rhai::loader";

/// The one sandboxed engine plus everything a compiled script needs to become
/// a plugin.
pub struct RhaiLoader {
    engine: Arc<Engine>,
    services: ScriptServices,
    cfg: RhaiConfig,
    /// Shared by every plugin this loader yields; the wiring binds the chain
    /// into it once the chain exists (see [`ErrorSink`]).
    errors: Arc<ErrorSink>,
}

impl RhaiLoader {
    /// Build the shared sandboxed engine and register the whole host surface:
    /// the flow API, each capability provider's namespace, then the prelude
    /// (compiled under the same limits, so a config that cannot run the
    /// prelude cannot run anything and is refused here).
    pub fn new(cfg: RhaiConfig, services: ScriptServices) -> Result<Self, ScriptError> {
        let mut engine = build_engine(&cfg.limits, cfg.hook_timeout);
        register_flow_api(&mut engine);
        // The `load(reg)` bridge: without it a script's `reg.add_command` is an
        // unknown function and no script could register anything (Task 10).
        register_reg_api(&mut engine);
        for capability in m3_capabilities(&cfg) {
            tracing::debug!(
                target: LOADER_TARGET,
                namespace = capability.namespace(),
                min_api = capability.min_api(),
                "registered script capability"
            );
            capability.register(&mut engine, &services);
        }
        register_prelude(&mut engine)?;
        Ok(Self {
            engine: Arc::new(engine),
            services,
            cfg,
            errors: Arc::default(),
        })
    }

    /// The shared engine, for the PoC step executor that runs on it too.
    pub fn engine(&self) -> Arc<Engine> {
        Arc::clone(&self.engine)
    }

    /// The sink every loaded plugin emits `Event::Error` through; the wiring
    /// binds the chain into it once built.
    pub fn error_sink(&self) -> Arc<ErrorSink> {
        Arc::clone(&self.errors)
    }

    /// The services the host surface was registered against, so the PoC step
    /// executor is built from the same handles as the plugins.
    pub fn services(&self) -> &ScriptServices {
        &self.services
    }

    /// The run budget the configuration gives every hook, step and command.
    pub fn budget(&self) -> Budget {
        Budget::of(&self.cfg)
    }

    /// Compile every enabled entry in `cfg.scripts`, in declaration order.
    /// Returns one plugin per script that compiled plus the errors of those
    /// that did not; with `strict`, any error means no plugins and every
    /// error, so the caller fails fast.
    pub fn load_all(&self) -> (Vec<ScriptPlugin>, Vec<ScriptError>) {
        let mut plugins = Vec::new();
        let mut errors = Vec::new();
        for entry in self.cfg.scripts.iter().filter(|entry| entry.enabled) {
            match self.load_one(entry) {
                Ok(plugin) => plugins.push(plugin),
                Err(err) => {
                    tracing::error!(target: LOADER_TARGET, path = %entry.path.display(), "{err}");
                    errors.push(err);
                }
            }
        }
        if self.cfg.strict && !errors.is_empty() {
            tracing::error!(
                target: LOADER_TARGET,
                failed = errors.len(),
                "strict: not loading any script while one fails"
            );
            return (Vec::new(), errors);
        }
        (plugins, errors)
    }

    /// Compile one file into a plugin over the shared engine, carrying the
    /// entry's options for `option(...)`.
    pub fn load_one(&self, entry: &ScriptEntry) -> Result<ScriptPlugin, ScriptError> {
        let (ast, meta) = self.compile(&entry.path)?;
        tracing::info!(
            target: LOADER_TARGET,
            script = %meta.name,
            path = %meta.path.display(),
            hooks = ?meta.hooks,
            "loaded script"
        );
        let options = Options::new(entry.options.clone());
        Ok(ScriptPlugin::new(
            meta,
            Arc::clone(&self.engine),
            ast,
            self.services.clone(),
            options,
            &self.cfg,
        )
        .with_error_sink(Arc::clone(&self.errors)))
    }

    /// Parse and compile only; no plugin is built and nothing is registered.
    /// Backs `script.validate`.
    pub fn validate(&self, path: &Path) -> Result<ScriptMeta, ScriptError> {
        self.compile(path).map(|(_, meta)| meta)
    }

    /// Read, compile, and describe one script. The AST is named after the
    /// script so host verbs can attribute what they record to it. Backs
    /// `script.reload`, which swaps the AST into the running plugin.
    pub fn compile(&self, path: &Path) -> Result<(AST, ScriptMeta), ScriptError> {
        let stem = file_stem(path);
        let src = fs::read_to_string(path).map_err(|err| ScriptError::Compile {
            script: stem.clone(),
            path: path.to_path_buf(),
            line: 0,
            column: 0,
            message: format!("cannot read {}: {err}", path.display()),
            hint: Some(
                "check the path under `scripts:` in the config (or the `--script` flag)".into(),
            ),
        })?;
        let mut ast = self
            .engine
            .compile(&src)
            .map_err(|err| compile_error(stem.clone(), path, &err))?;
        let meta = extract_meta(&ast, path, stem);
        ast.set_source(meta.name.as_str());
        Ok((ast, meta))
    }
}

/// The providers M3 ships (spec §6a). A namespace missing from this list does
/// not exist for scripts. `browser` decides SSRF under the host's policy and
/// `scope.add` is offered only when the config allows it.
///
/// `vars` is here rather than in the PoC executor because the engine is built
/// once and shared: its verbs must exist on the engine before any step runs,
/// even though the handle itself is pushed per step.
fn m3_capabilities(cfg: &RhaiConfig) -> [Arc<dyn ScriptCapability>; 7] {
    [
        Arc::new(LogCapability),
        Arc::new(FindingCapability),
        Arc::new(HttpCapability),
        Arc::new(BrowserCapability::new(cfg.ssrf.clone())),
        Arc::new(StoreCapability),
        Arc::new(ScopeCapability::new(cfg.allow_scope_add)),
        Arc::new(VarsCapability),
    ]
}

/// What the script is called when it declares no `NAME` (spec §2 rule 1).
fn file_stem(path: &Path) -> String {
    path.file_stem()
        .and_then(|stem| stem.to_str())
        .filter(|stem| !stem.is_empty())
        .unwrap_or("script")
        .to_string()
}

/// A parse failure in the pinned shape: the script, where, what, and — for
/// the classes with an obvious fix — how.
fn compile_error(script: String, path: &Path, err: &ParseError) -> ScriptError {
    let pos = err.position();
    ScriptError::Compile {
        script,
        path: path.to_path_buf(),
        line: pos.line().unwrap_or(0),
        column: pos.position().unwrap_or(0),
        message: err.err_type().to_string(),
        hint: hint_for(err.err_type()),
    }
}

fn hint_for(kind: &ParseErrorType) -> Option<String> {
    match kind {
        ParseErrorType::MissingToken(token, _) => Some(format!("add the missing '{token}'")),
        ParseErrorType::UnexpectedEOF => Some(
            "the file ends mid-statement; look for an unclosed brace, bracket, or string".into(),
        ),
        ParseErrorType::Reserved(word) => Some(format!(
            "'{word}' is a reserved word in Rhai and cannot be used as a name"
        )),
        _ => None,
    }
}

/// `NAME`, `API` and the hooks present, read off the AST's top-level literal
/// constants and function table without running the script. Anything odd
/// but survivable — no `API`, an unsupported one, a hook with the wrong
/// parameters, an `on_…` function that is not a hook — is a warning that
/// names the fix; the script still loads.
fn extract_meta(ast: &AST, path: &Path, stem: String) -> ScriptMeta {
    let mut name = None;
    let mut api = None;
    for (var, _, value) in ast.iter_literal_variables(true, false) {
        match var {
            "NAME" => name = string_const(&stem, var, value),
            "API" => api = string_const(&stem, var, value),
            _ => {}
        }
    }
    let name = name.unwrap_or(stem);

    let api = api.unwrap_or_else(|| {
        tracing::warn!(
            target: LOADER_TARGET,
            script = %name,
            "declares no `const API`; assuming the current version '{SUPPORTED_API}'"
        );
        SUPPORTED_API.to_string()
    });
    if api != SUPPORTED_API {
        let warning = ScriptError::ApiVersion {
            script: name.clone(),
            declared: api.clone(),
            supported: SUPPORTED_API.to_string(),
        };
        tracing::warn!(target: LOADER_TARGET, "{warning}");
    }

    let functions: Vec<(String, usize)> = ast
        .iter_functions()
        .map(|f| (f.name.to_string(), f.params.len()))
        .collect();
    warn_hook_shapes(&name, &functions);
    let hooks = HOOKS
        .iter()
        .filter(|(hook, _)| functions.iter().any(|(f, _)| f == hook))
        .map(|(hook, _)| hook.to_string())
        .collect();

    ScriptMeta {
        name,
        api,
        path: path.to_path_buf(),
        hooks,
    }
}

/// A declared `NAME`/`API` as a non-empty string, else a warning and the
/// default.
fn string_const(script: &str, var: &str, value: Dynamic) -> Option<String> {
    match value.into_immutable_string() {
        Ok(text) if !text.is_empty() => Some(text.to_string()),
        _ => {
            tracing::warn!(
                target: LOADER_TARGET,
                script,
                "`const {var}` must be a non-empty string; ignoring it"
            );
            None
        }
    }
}

/// The two hook mistakes a compile cannot catch (spec §2 rule 6: wrong
/// argument count, unknown hook name), each with the spelling that works.
fn warn_hook_shapes(script: &str, functions: &[(String, usize)]) {
    for (name, arity) in functions {
        match HOOKS.iter().find(|(hook, _)| hook == name) {
            Some((hook, params)) if params.len() != *arity => tracing::warn!(
                target: LOADER_TARGET,
                script,
                "hook '{hook}' is declared with {arity} parameter(s) but is called with {}; \
                 it will fail on every event. help: fn {hook}({})",
                params.len(),
                params.join(", ")
            ),
            None if name.starts_with("on_") => tracing::warn!(
                target: LOADER_TARGET,
                script,
                "'{name}' is not a hook and will never be called. help: the hooks are {}",
                HOOKS
                    .iter()
                    .map(|(hook, _)| *hook)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            _ => {}
        }
    }
}
