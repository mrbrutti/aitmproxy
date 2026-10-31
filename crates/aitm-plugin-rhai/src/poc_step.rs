//! `RhaiScriptExecutor`: the PoC `script`-step implementation over the shared
//! engine, behind `aitm_poc::ScriptStepExecutor` (plan Task 14).
//!
//! One surface, reused (spec §10). The executor is handed the **same**
//! hardened `Arc<Engine>` the scripted plugins run on — every host namespace
//! (`log`, `finding`, `http`, `browser`, `store`, `scope`) and the prelude are
//! already registered on it, wired to the same `ScriptServices` and therefore
//! the same scope/rate/SSRF guards. A step adds exactly one thing a plugin hook
//! does not have: the per-step `vars` handle, pushed into the run's `Scope`.
//! Its `get`/`set` verbs are registered once at engine-build time by
//! [`VarsCapability`], through the §6a seam like every other namespace; the
//! handle itself is per run, so no global constant is set.
//!
//! The step body is a top-level block, not a function: it is compiled once per
//! distinct text (cached by content), then run with `eval_ast_with_scope`
//! as blocking work inside a `PocStep` run ([`crate::engine::begin_run`]),
//! under the configured operation and wall-clock budget — the run kind is
//! what keeps `scope.add` out of a step. The scope carries the constants
//! `pass` and `fail`; the
//! value the script returns — `return pass;`, `return fail;`, or a bare tail
//! expression — is the verdict, and anything else (falling off the end, `()`,
//! a stray number) is `Neutral` (Review Focus #5).
//!
//! A step is atomic, the way a hook is (spec §5, Task 8): `vars.set(...)`
//! writes land on a shared copy of the bindings and are copied back into
//! `ctx.vars` only when the step returns a value. A throw, a guard refusal the
//! script did not catch, a sandbox denial, or a budget abort leaves `ctx.vars`
//! exactly as it was and becomes a [`ScriptStepError`] carrying the
//! [`ScriptError`] text in the spec's pinned format.
//!
//! `browser.screenshot()` is the shared verb from `host_net`: it returns the
//! PNG bytes to the script and writes no file at this layer, so nothing is
//! appended to `ctx.artifacts` here.

use std::collections::HashMap;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};

use aitm_core::CallerTrust;
use aitm_poc::{
    ScriptStep, ScriptStepCtx, ScriptStepError, ScriptStepExecutor, ScriptVerdict, VarBindings,
};
use rhai::{Dynamic, Engine, EvalAltResult, Position, Scope, AST};

use crate::config::{DEFAULT_BROWSER_TIMEOUT, DEFAULT_HOOK_TIMEOUT};
use crate::engine::{begin_run, blocking, enter_constants, Budget, RunKind};
use crate::error::ScriptError;
use crate::host_core::{ScriptCapability, ScriptServices};
use crate::host_registry::seed_call_context;
use crate::marshal::{dynamic_to_value, value_to_dynamic};

/// Runs PoC `script` steps on the shared engine.
pub struct RhaiScriptExecutor {
    engine: Arc<Engine>,
    services: ScriptServices,
    /// The budget a step runs under; the figure its abort errors quote.
    budget: Budget,
    /// Compiled step bodies by content hash; a PoC's steps compile once per
    /// process, however often the PoC is run.
    cache: Mutex<HashMap<u64, Arc<AST>>>,
}

/// Entries kept before the compile cache is cleared; a long agent session runs
/// many distinct PoCs and must not grow without bound.
const CACHE_CAP: usize = 256;

/// The "hook" a step's `ScriptError` names, since a step is a body, not a hook.
const STEP_HOOK: &str = "script step";

/// The script name an unnamed step's errors carry.
const UNNAMED_STEP: &str = "script";

impl RhaiScriptExecutor {
    /// Run steps on `engine`, which must already carry the host surface and
    /// [`VarsCapability`]; `services` are the handles that surface is wired to.
    /// The budget defaults to the engine's operation cap and the default hook
    /// and browser timeouts; [`RhaiScriptExecutor::with_budget`] sets the
    /// configured one.
    pub fn new(engine: Arc<Engine>, services: ScriptServices) -> Self {
        let budget = Budget {
            // `engine::harden` sets the hard cap one above the configured
            // budget so the named token fires first.
            max_operations: engine.max_operations().saturating_sub(1),
            hook_timeout: DEFAULT_HOOK_TIMEOUT,
            browser_timeout: DEFAULT_BROWSER_TIMEOUT,
        };
        Self {
            engine,
            services,
            budget,
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// The budget every step runs under (the tier's configured one).
    pub fn with_budget(mut self, budget: Budget) -> Self {
        self.budget = budget;
        self
    }

    /// The services the shared engine's host verbs act through — the handles
    /// the binary builds a `CommandHost` from, so a run's two views agree.
    pub fn services(&self) -> &ScriptServices {
        &self.services
    }

    /// The compiled body, from the cache or freshly compiled and named after
    /// the step (so `finding(...)` attributes what it records).
    fn compile(&self, name: &str, step: &ScriptStep) -> Result<Arc<AST>, ScriptStepError> {
        let mut hasher = DefaultHasher::new();
        name.hash(&mut hasher);
        step.script.hash(&mut hasher);
        let key = hasher.finish();

        let mut cache = self.cache.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(ast) = cache.get(&key) {
            return Ok(Arc::clone(ast));
        }

        let mut ast = self.engine.compile(&step.script).map_err(|err| {
            let pos = err.position();
            ScriptStepError(
                ScriptError::Compile {
                    script: name.to_string(),
                    // A step is inline in its PoC; it has no file of its own.
                    path: PathBuf::new(),
                    line: pos.line().unwrap_or(0),
                    column: pos.position().unwrap_or(0),
                    message: err.to_string(),
                    hint: None,
                }
                .to_string(),
            )
        })?;
        ast.set_source(name);
        let ast = Arc::new(ast);

        if cache.len() >= CACHE_CAP {
            cache.clear();
        }
        cache.insert(key, Arc::clone(&ast));
        Ok(ast)
    }
}

impl ScriptStepExecutor for RhaiScriptExecutor {
    fn run_step(
        &self,
        step: &ScriptStep,
        ctx: &mut ScriptStepCtx<'_>,
    ) -> Result<ScriptVerdict, ScriptStepError> {
        let name = step.name.as_deref().unwrap_or(UNNAMED_STEP);
        let ast = self.compile(name, step)?;

        let vars = ScriptVars::new(ctx.vars.clone());
        let mut scope = Scope::new();
        scope
            .push_constant("pass", Verdict::Pass)
            .push_constant("fail", Verdict::Fail)
            // A variable, not a constant: Rhai refuses `&mut` method calls on a
            // constant, and `vars.set(...)` is one.
            .push("vars", vars.clone());

        // Seed the per-eval caller trust from the PoC run's frontend before the
        // step evaluates, so a seam host fn the step calls (`l4.*`, …) is gated on
        // the live caller — `Agent` for an agent-driven `poc.run`, `Operator` for
        // a human one — and never fails closed for a missing context (spec AC5
        // script face, AC3). The guard is held across the whole eval, so a seam
        // call nested in the step still observes it.
        let caller = CallerTrust::from(ctx.host.frontend());
        // A PoC `script:` step carries no options, so the per-eval tag stays `None`
        // (`option(...)` reads `()`); the call source is the step's name, which the
        // seam-migrated `finding(...)` records off `HostCallCtx::call_source()` —
        // identical to the pre-seam `NativeCallContext` AST source set at compile.
        let source = Some(name.to_string());
        let result = blocking(|| {
            let _run = begin_run(RunKind::PocStep, self.budget);
            let _seed = seed_call_context(caller, None, source);
            let _constants = enter_constants(&ast);
            self.engine.eval_ast_with_scope::<Dynamic>(&mut scope, &ast)
        });

        match result {
            Ok(value) => {
                *ctx.vars = vars.snapshot();
                Ok(verdict_of(value))
            }
            // `vars` is dropped unapplied: the bindings stay as they were.
            Err(err) => Err(ScriptStepError(
                ScriptError::from_eval(name, STEP_HOOK, &err, &self.budget).to_string(),
            )),
        }
    }
}

/// The value behind the scope constants `pass` and `fail`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict {
    Pass,
    Fail,
}

/// What the script's returned value says: a verdict, or nothing in particular.
fn verdict_of(value: Dynamic) -> ScriptVerdict {
    match value.try_cast::<Verdict>() {
        Some(Verdict::Pass) => ScriptVerdict::Pass,
        Some(Verdict::Fail) => ScriptVerdict::Fail,
        None => ScriptVerdict::Neutral,
    }
}

/// The step's `vars` handle: `vars.get(name)` / `vars.set(name, value)` over a
/// copy of the run's bindings that the executor copies back when the step
/// succeeds.
#[derive(Clone)]
pub struct ScriptVars(Arc<Mutex<VarBindings>>);

impl ScriptVars {
    pub fn new(vars: VarBindings) -> Self {
        Self(Arc::new(Mutex::new(vars)))
    }

    /// The bound value, or `()` when nothing is bound (option C: an unbound
    /// variable is an answer, not an error — `vars.get("csrf") == ()`).
    pub fn get(&self, name: &str) -> Dynamic {
        self.lock()
            .get(name)
            .map(value_to_dynamic)
            .unwrap_or(Dynamic::UNIT)
    }

    /// Bind `name`; a value with no `Value` counterpart is refused with what to
    /// use instead.
    pub fn set(&self, name: &str, value: Dynamic) -> Result<(), Box<EvalAltResult>> {
        let value = dynamic_to_value(&value).map_err(|_| {
            let message = format!(
                "vars.set(\"{name}\", …) cannot store a {}; use a string, number, bool, blob, array or map",
                value.type_name()
            );
            Box::new(EvalAltResult::ErrorRuntime(
                Dynamic::from(message),
                Position::NONE,
            ))
        })?;
        self.lock().insert(name, value);
        Ok(())
    }

    /// The bindings as they stand.
    pub fn snapshot(&self) -> VarBindings {
        self.lock().clone()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, VarBindings> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// The `vars` namespace of a PoC step (spec §10), as a [`ScriptCapability`]
/// provider: registers the handle type and its two verbs. The handle itself is
/// per step, pushed into the run's scope by the executor, so unlike the other
/// namespaces no global constant is set — a plugin hook has no `vars`.
#[derive(Debug, Clone, Copy, Default)]
pub struct VarsCapability;

impl ScriptCapability for VarsCapability {
    fn namespace(&self) -> &str {
        "vars"
    }

    fn min_api(&self) -> &str {
        "1"
    }

    fn register(&self, engine: &mut Engine, _services: &ScriptServices) {
        engine
            .register_type_with_name::<ScriptVars>("Vars")
            .register_fn("get", |vars: &mut ScriptVars, name: &str| vars.get(name))
            .register_fn(
                "set",
                |vars: &mut ScriptVars, name: &str, value: Dynamic| vars.set(name, value),
            );
    }
}
