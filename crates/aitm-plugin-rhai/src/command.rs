//! Script-registered commands and options: `ScriptCommand` and the `load(reg)`
//! bridge (plan Task 10).
//!
//! A script's `fn load(reg) { … }` is the one hook that talks to the platform
//! `Registry` rather than to a flow. The `reg` it receives offers two verbs:
//!
//! - `reg.add_command(name, desc, fn)` — the function becomes a
//!   [`ScriptCommand`], a native `aitm_core::Command` with one free-form
//!   `args` object parameter and an `Any` result (spec §9), so MCP
//!   `tools/list` and the CLI pick it up with no special casing (AC-M3-3).
//! - `reg.add_option(name, default, desc)` — the default is recorded in the
//!   platform option store and in the script's [`Options`], where
//!   `option(name)` reads it.
//!
//! Rhai copies values and requires them to be `'static`, so the script cannot
//! hold the `&mut Registry` itself. [`ScriptRegHandle`] is the Rust side of
//! the bridge over that borrow: it hands the script a shared collector,
//! runs `load`, then installs what was collected. A `load` that throws installs
//! nothing (the collector is discarded), mirroring the effect model of hooks.

use std::sync::{Arc, Mutex, PoisonError};

use aitm_core::{
    CallerTrust, Command, CommandHost, ParamDef, ParamSchema, Params, Registry, TypeDesc, Value,
};
use rhai::{CallFnOptions, Dynamic, Engine, EvalAltResult, FnPtr, Position, Scope, AST};

use crate::engine::{begin_run, blocking, Budget, RunKind};
use crate::error::ScriptError;
use crate::host_core::Options;
use crate::host_registry::seed_call_context;
use crate::marshal::{dynamic_to_value, value_to_dynamic};

/// The hook this bridge drives.
const LOAD_HOOK: &str = "load";

/// The one parameter every script command declares.
const ARGS_PARAM: &str = "args";

/// A command a script registered, bridged onto the native trait. Invoking it
/// calls the script function with the arguments as one map, under the same
/// engine, AST, and options as the script's hooks.
pub struct ScriptCommand {
    name: String,
    desc: String,
    engine: Arc<Engine>,
    ast: Arc<AST>,
    func: FnPtr,
    /// Passed as the call's tag so `option(name)` works inside a command.
    options: Options,
    /// The run budget a command invocation gets (the script's hook budget).
    budget: Budget,
    /// The script that registered it, for error messages.
    script: String,
}

impl Command for ScriptCommand {
    fn name(&self) -> &str {
        &self.name
    }

    /// One optional `args` object, `Any` result (spec §9): a real MCP tool and
    /// CLI subcommand with no schema ceremony in the script.
    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: self.desc.clone(),
            params: vec![ParamDef {
                name: ARGS_PARAM.to_string(),
                ty: TypeDesc::Map(Box::new(TypeDesc::Any)),
                required: false,
                description: "arguments handed to the script as one object (`args.<key>`)"
                    .to_string(),
            }],
            result: TypeDesc::Any,
        }
    }

    /// The host services are not needed here: every verb the function may
    /// call was wired to the shared, guarded `ScriptServices` when the engine
    /// was built, so a command reaches the network only the way a hook does.
    /// The call runs as a `Command` run under the script's budget; a failure
    /// is reported in the pinned `ScriptError` format, naming the command.
    fn invoke(&self, args: Params, host: &CommandHost) -> anyhow::Result<Value> {
        let mut call_args = self.func.curry().to_vec();
        call_args.push(Dynamic::from_map(args_map(&args)));

        // Seed the per-eval caller trust from the invoking frontend before the
        // script function runs: a command body can reach a seam host fn, so this
        // boundary is gated on the live caller (`Agent` for an agent, `Operator`
        // for a human), never refused for a missing context and never widened to
        // operator (spec AC3). Held across the call under `block_in_place`.
        let caller = CallerTrust::from(host.frontend());
        // Thread the per-eval tag (the script's options, as a rhai-free `Value`)
        // and call source (the script name) through the seed, so the seam-migrated
        // `option`/`finding` read them off `HostCallCtx` (the old
        // `CallFnOptions::with_tag(Options)` custom-type tag could not cross the
        // rhai-free seam). Fail-closed when unseeded is preserved by the seam.
        let tag = self.options.to_value();
        let source = self.ast.source().map(str::to_string);
        let result = blocking(|| {
            let _run = begin_run(RunKind::Command, self.budget.hook_timeout);
            let _seed = seed_call_context(caller, Some(tag), source);
            self.engine.call_fn_with_options::<Dynamic>(
                CallFnOptions::new(),
                &mut Scope::new(),
                &self.ast,
                self.func.fn_name(),
                call_args,
            )
        })
        .map_err(|err| {
            anyhow::anyhow!(
                "command `{}` failed: {}",
                self.name,
                ScriptError::from_eval(&self.script, &self.name, &err, &self.budget)
            )
        })?;

        dynamic_to_value(&result).map_err(|err| {
            anyhow::anyhow!(
                "command `{}` (script `{}`) returned a value the bus cannot carry: {err}",
                self.name,
                self.script
            )
        })
    }
}

/// The Rust side of the `load(reg)` bridge: borrows the platform `Registry`,
/// runs a script's `load` over a collector, and installs what it registered.
pub struct ScriptRegHandle<'a> {
    reg: &'a mut Registry,
    options: Options,
    budget: Budget,
    caller: CallerTrust,
}

impl<'a> ScriptRegHandle<'a> {
    /// A handle over `reg` with no options set yet and the default budget.
    ///
    /// The caller trust defaults to the **least-privileged** [`CallerTrust::Agent`]
    /// (fail-closed, like `PocStepInputs::default`): a `load` evaluated through a
    /// handle whose trust was never set can only ever *under*-grant a seam verb,
    /// never silently widen an agent to operator. The production path sets the
    /// script's authoring trust explicitly via [`with_caller`](Self::with_caller).
    pub fn new(reg: &'a mut Registry) -> Self {
        Self {
            reg,
            options: Options::default(),
            budget: Budget::default(),
            caller: CallerTrust::Agent,
        }
    }

    /// Start from the script's configured options (the config entry's
    /// `options:`). A default a script then declares fills in only a key the
    /// config did not set, so the config overlay wins.
    pub fn with_options(mut self, options: Options) -> Self {
        self.options = options;
        self
    }

    /// The budget `load` runs under, and every command it registers.
    pub fn with_budget(mut self, budget: Budget) -> Self {
        self.budget = budget;
        self
    }

    /// The caller trust `load` evaluates under (the script's authoring trust),
    /// which [`run_load`](Self::run_load) seeds so a seam host fn `load` reaches
    /// (`option`, a guarded verb) is gated on the author — never left unseeded.
    /// The loader seeds the least-privilege [`CallerTrust::Agent`] for an
    /// unknown-provenance config-placed script; only an in-session `script.save`
    /// carries the saving frontend's true trust.
    pub fn with_caller(mut self, caller: CallerTrust) -> Self {
        self.caller = caller;
        self
    }

    /// Run the script's `load(reg)` if it defines one, then install every
    /// command and option it registered. A `load` that throws installs
    /// nothing and is reported as a `ScriptError` on hook `load`.
    ///
    /// `load` is called from `Proxy::build`, on the thread driving `main`'s
    /// future — inside the runtime. It crosses the same bridge as every other
    /// entry point (`engine::blocking`), so a guarded async verb in `load`
    /// works instead of panicking the proxy at startup, and it reads the
    /// configured options like a hook does.
    pub fn run_load(&mut self, engine: &Arc<Engine>, ast: &Arc<AST>) -> Result<(), ScriptError> {
        if !ast.iter_functions().any(|f| f.name == LOAD_HOOK) {
            return Ok(());
        }
        let script = ast.source().unwrap_or("script").to_string();
        let collector = RegCollector::default();

        // Seed the per-eval caller trust (the script's authoring trust) plus the
        // tag (the configured options, as a `Value`) and source (the script name)
        // so a seam host fn `load` reaches — `option(...)` today — is seeded and
        // gated, never fails closed for a missing context (spec AC3). This boundary
        // seeds internally so a direct `run_load` (the loader's `load` bridge, a
        // test) is covered, not only the plugin hook-dispatch path.
        let caller = self.caller;
        let tag = self.options.to_value();
        let source = ast.source().map(str::to_string);
        blocking(|| {
            let _run = begin_run(RunKind::Load, self.budget.hook_timeout);
            let _seed = seed_call_context(caller, Some(tag), source);
            engine.call_fn_with_options::<Dynamic>(
                CallFnOptions::new(),
                &mut Scope::new(),
                ast,
                LOAD_HOOK,
                (collector.clone(),),
            )
        })
        .map(drop)
        .map_err(|err| ScriptError::from_eval(&script, LOAD_HOOK, &err, &self.budget))?;

        let collected = collector.take();
        for (name, default, desc) in collected.options {
            self.reg.add_option(&name, default.clone(), &desc);
            if self.options.get(&name).is_none() {
                self.options.insert(name, default);
            }
        }
        for (name, desc, func) in collected.commands {
            self.reg.add_command(Arc::new(ScriptCommand {
                name,
                desc,
                engine: Arc::clone(engine),
                ast: Arc::clone(ast),
                func,
                options: self.options.clone(),
                budget: self.budget,
                script: script.clone(),
            }));
        }
        Ok(())
    }

    /// The script's options after `load`: config values plus declared defaults.
    pub fn options(&self) -> &Options {
        &self.options
    }

    /// Give the options back to the plugin that owns them for its hook runs.
    pub fn into_options(self) -> Options {
        self.options
    }
}

/// What a script's `load(reg)` holds: a `'static`, shared collector the
/// `reg.add_command` / `reg.add_option` verbs write into.
#[derive(Clone, Default)]
struct RegCollector(Arc<Mutex<Collected>>);

#[derive(Default)]
struct Collected {
    /// `(name, description, function)` in registration order.
    commands: Vec<(String, String, FnPtr)>,
    /// `(name, default, description)` in registration order.
    options: Vec<(String, Value, String)>,
}

impl RegCollector {
    fn lock(&self) -> std::sync::MutexGuard<'_, Collected> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Everything collected so far, leaving the collector empty.
    fn take(&self) -> Collected {
        std::mem::take(&mut *self.lock())
    }
}

/// Register the `reg` type and its two verbs on the shared engine. Called once
/// when the engine is built, beside the capability providers.
pub fn register_reg_api(engine: &mut Engine) {
    engine
        .register_type_with_name::<RegCollector>("reg")
        .register_fn(
            "add_command",
            |reg: &mut RegCollector,
             name: &str,
             desc: &str,
             func: FnPtr|
             -> Result<(), Box<EvalAltResult>> {
                if name.trim().is_empty() {
                    return Err(reg_error(
                        "reg.add_command(name, desc, fn) needs a non-empty name like \"demo.ping\"",
                    ));
                }
                reg.lock()
                    .commands
                    .push((name.to_string(), desc.to_string(), func));
                Ok(())
            },
        )
        .register_fn(
            "add_option",
            |reg: &mut RegCollector,
             name: &str,
             default: Dynamic,
             desc: &str|
             -> Result<(), Box<EvalAltResult>> {
                if name.trim().is_empty() {
                    return Err(reg_error(
                        "reg.add_option(name, default, desc) needs a non-empty name",
                    ));
                }
                let default = dynamic_to_value(&default)
                    .map_err(|err| reg_error(format!("reg.add_option(\"{name}\", …): {err}")))?;
                reg.lock()
                    .options
                    .push((name.to_string(), default, desc.to_string()));
                Ok(())
            },
        );
}

/// The map the script function receives: the object under `args` when the
/// frontend sent one, else the whole argument bag (so a bare call is `#{}`).
fn args_map(params: &Params) -> rhai::Map {
    let fields = match params.get(ARGS_PARAM) {
        Some(Value::Object(fields)) => fields.clone(),
        _ => params
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect(),
    };
    value_to_dynamic(&Value::Object(fields))
        .try_cast::<rhai::Map>()
        .unwrap_or_default()
}

/// A catchable runtime error; the engine fills in the call position.
fn reg_error(message: impl Into<String>) -> Box<EvalAltResult> {
    EvalAltResult::ErrorRuntime(Dynamic::from(message.into()), Position::NONE).into()
}
