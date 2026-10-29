//! The shared sandboxed engine: `build_engine`/`harden` apply `RhaiLimits`, the
//! operation/time budget via `on_progress`, disable `eval`, and route `print`
//! to tracing (plan Task 2). The run context ([`begin_run`]) tells the engine
//! and the host functions which kind of run is on this thread and when its
//! budget ends.
//!
//! **What a script can call.** The engine is built *raw* and given Rhai's
//! standard packages minus `BasicTimePackage` (`timestamp`/`elapsed`), and
//! `sleep` — which lives in the language-core package and cannot be left out
//! — is shadowed with a refusal. The resulting global function table is
//! pinned by `tests/engine.rs::allowed_global_functions_are_pinned`.
//!
//! **Stack depth.** Rhai's own data-size walk, clone and drop recurse once per
//! nesting level of an array/map, and no Rhai limit bounds nesting (the size
//! limits count elements). The marshalling layer caps the depth it will read
//! ([`crate::marshal::MAX_DEPTH`]); for Rhai's own recursion the bound is the
//! thread stack, so a host runs script evaluation on threads of at least
//! [`WORKER_STACK_SIZE`] (the `aitm` binary sizes its tokio workers so).

use std::cell::Cell;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use aitm_plugin::language::{ProtocolLanguage, RegisterError};
use rhai::module_resolvers::DummyModuleResolver;
use rhai::packages::{
    BasicArrayPackage, BasicBlobPackage, BasicMapPackage, BasicMathPackage, BitFieldPackage,
    CorePackage, LogicPackage, MoreStringPackage, Package,
};
use rhai::{Dynamic, Engine, EvalAltResult, Position};

use crate::config::{RhaiConfig, RhaiLimits};

/// Why `on_progress` terminated a hook. Carried as the termination token in
/// `EvalAltResult::ErrorTerminated` so the error can say which budget was
/// exceeded (spec §7, ergonomics rule 6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbortKind {
    /// The hook ran more than `max_operations` operations.
    OpLimit,
    /// The hook ran past `hook_timeout` wall-clock.
    Timeout,
}

/// Which entry point is evaluating on this thread. Host functions consult it:
/// `browser.*` is refused inside a flow hook (the navigation would pass back
/// through the chain this hook is holding) and `scope.add` is refused from a
/// PoC step (a shared artifact must not widen the engagement scope).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunKind {
    /// A flow hook (`on_request`, …) under the chain's plugin lock.
    Hook,
    /// A script's `load(reg)` at startup.
    Load,
    /// A script-registered command invoked from a frontend.
    Command,
    /// A PoC `script` step.
    PocStep,
}

/// The two budgets one run gets, as configured; the dispatchers hand it to
/// [`crate::error::ScriptError::from_eval`] so an abort names the right number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Budget {
    pub max_operations: u64,
    pub hook_timeout: Duration,
}

impl Budget {
    pub fn of(cfg: &RhaiConfig) -> Self {
        Self {
            max_operations: cfg.limits.max_operations,
            hook_timeout: cfg.hook_timeout,
        }
    }
}

impl Default for Budget {
    /// The shipped limits: what `RhaiConfig::default()` gives a run.
    fn default() -> Self {
        Self::of(&RhaiConfig::default())
    }
}

/// Run `f` — a script evaluation — as blocking work. On a multi-thread
/// runtime worker (or its `block_on` thread, where `Proxy::build` runs
/// `load`) this is `block_in_place`, which also leaves the runtime context so
/// the host verbs' `Handle::block_on` is legal; anywhere else `f` runs inline,
/// so a frontend invoking a command outside tokio does not panic. Every entry
/// point into the engine — hook, `load`, command, PoC step — goes through
/// here.
pub fn blocking<T>(f: impl FnOnce() -> T) -> T {
    match tokio::runtime::Handle::try_current() {
        Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
            tokio::task::block_in_place(f)
        }
        _ => f(),
    }
}

/// The stack a thread that evaluates scripts should have. Rhai recurses once
/// per nesting level of a value — on clone, on the data-size check, and on drop
/// — and no Rhai limit bounds that nesting, so the stack is the only backstop
/// against a deeply-nested value overflowing it and aborting the process. The
/// default operation budget ([`crate::config::MAX_OPERATIONS`]) is tuned so the
/// deepest nesting a run can build (~`MAX_OPERATIONS / 4` ≈ 16 000 levels)
/// stays well inside this stack, which overflows only past ~45 000 levels —
/// where a default 2 MiB worker stack overflows in the low thousands. Raise the
/// budget and this stack together, never one alone.
pub const WORKER_STACK_SIZE: usize = 64 * 1024 * 1024;

/// How many strings the engine interns; the figure `Engine::new` uses.
const MAX_STRINGS_INTERNED: usize = 1024;

/// The run on this thread: what kind, and when its wall-clock budget ends.
#[derive(Debug, Clone, Copy)]
struct Run {
    kind: RunKind,
    deadline: Instant,
}

thread_local! {
    /// The run the dispatcher opened on this thread (see [`begin_run`]).
    /// Hooks, steps and commands run synchronously on the thread that
    /// evaluates them, so each thread's cell belongs to exactly one run at a
    /// time; nested runs restore the outer one when they end.
    static RUN: Cell<Option<Run>> = const { Cell::new(None) };

    /// The clock of a *bare* evaluation — one no dispatcher opened, such as
    /// an `engine.run` in a test. Rhai restarts its operation counter for
    /// every top-level evaluation, so a count that does not increase marks a
    /// new one and re-arms the clock.
    static BARE_CLOCK: Cell<Option<(u64, Instant)>> = const { Cell::new(None) };
}

/// Opens a run on this thread for as long as the guard lives: `on_progress`
/// aborts the evaluation once `budget` has elapsed, and the host functions
/// read the kind and the remaining budget. Dropping the guard restores the
/// run that was open before (none, normally).
#[must_use = "the run ends when the guard drops"]
pub struct RunGuard {
    previous: Option<Run>,
}

/// Open a run of `kind` with `budget` of wall-clock from now. Every dispatcher
/// (hook, `load`, command, PoC step) calls this before evaluating.
pub fn begin_run(kind: RunKind, budget: Duration) -> RunGuard {
    let run = Run {
        kind,
        deadline: Instant::now() + budget,
    };
    let previous = RUN.with(|cell| cell.replace(Some(run)));
    RunGuard { previous }
}

impl Drop for RunGuard {
    fn drop(&mut self) {
        let previous = self.previous.take();
        RUN.with(|cell| cell.set(previous));
    }
}

/// The kind of run evaluating on this thread, if a dispatcher opened one.
pub fn current_run() -> Option<RunKind> {
    RUN.with(|cell| cell.get().map(|run| run.kind))
}

/// How much of the current run's wall-clock budget is left (zero once it has
/// passed), or `None` outside any run.
pub fn remaining_budget() -> Option<Duration> {
    RUN.with(|cell| {
        cell.get()
            .map(|run| run.deadline.saturating_duration_since(Instant::now()))
    })
}

/// A fresh engine with every sandbox limit applied; the one engine shared by
/// every script and PoC step.
pub fn build_engine(limits: &RhaiLimits, hook_timeout: Duration) -> Engine {
    let mut engine = Engine::new_raw();
    engine.set_max_strings_interned(MAX_STRINGS_INTERNED);
    // The standard packages, except `BasicTimePackage`: scripts get no clock.
    engine
        .register_global_module(CorePackage::new().as_shared_module())
        .register_global_module(BitFieldPackage::new().as_shared_module())
        .register_global_module(LogicPackage::new().as_shared_module())
        .register_global_module(BasicMathPackage::new().as_shared_module())
        .register_global_module(BasicArrayPackage::new().as_shared_module())
        .register_global_module(BasicBlobPackage::new().as_shared_module())
        .register_global_module(BasicMapPackage::new().as_shared_module())
        .register_global_module(MoreStringPackage::new().as_shared_module());
    harden(&mut engine, limits, hook_timeout);
    engine
}

/// A hardened engine (as [`build_engine`]) with each protocol language's
/// `<ns>.*` host fns installed through the [`crate::host_registry`] seam, so a
/// script can call `<ns>.fn(...)` with no per-protocol edit to this crate (plan
/// Task 2, AC1). Returns [`RegisterError::Collision`] if two languages claim the
/// same `<ns>.<name>` — registration never last-wins.
pub fn build_engine_with_languages(
    limits: &RhaiLimits,
    hook_timeout: Duration,
    languages: &[&dyn ProtocolLanguage],
) -> Result<Engine, RegisterError> {
    let mut engine = build_engine(limits, hook_timeout);
    crate::host_registry::install_languages(&mut engine, languages)?;
    Ok(engine)
}

/// Apply `RhaiLimits` and the budget to an engine (spec §7): size and depth
/// caps, imports capped and resolved by nothing, `eval` disabled, `sleep`
/// refused, `on_progress` enforcing both the operation and the wall-clock
/// budget, `print`/`debug` routed to tracing.
pub fn harden(engine: &mut Engine, limits: &RhaiLimits, hook_timeout: Duration) {
    // Rhai checks its own operation cap before it calls `on_progress`, so the
    // hard cap sits one operation above the token threshold: the token fires
    // first and names the budget; the cap is a backstop should the callback
    // ever be replaced. `0` is Rhai's "unlimited" and stays so.
    let hard_cap = match limits.max_operations {
        0 => 0,
        n => n.saturating_add(1),
    };
    engine
        .set_max_operations(hard_cap)
        .set_max_call_levels(limits.max_call_levels)
        .set_max_expr_depths(limits.max_expr_depth, limits.max_function_expr_depth)
        .set_max_string_size(limits.max_string_size)
        .set_max_array_size(limits.max_array_size)
        .set_max_map_size(limits.max_map_size)
        .set_max_modules(limits.max_modules)
        // `max_modules` is a count; this is what makes `import` touch no file
        // at any count — the resolver that resolves nothing.
        .set_module_resolver(DummyModuleResolver::new())
        .disable_symbol("eval");

    // `sleep` ships in the language-core package. An engine-registered
    // function takes precedence over a package one, so these overloads
    // shadow it with a catchable refusal: a native sleep ticks no operation,
    // so neither budget could end it.
    engine
        .register_fn("sleep", |_: i64| -> Result<(), Box<EvalAltResult>> {
            Err(no_sleep())
        })
        .register_fn("sleep", |_: f64| -> Result<(), Box<EvalAltResult>> {
            Err(no_sleep())
        });

    let max_operations = limits.max_operations;
    engine.on_progress(move |ops| {
        if max_operations > 0 && ops > max_operations {
            return Some(Dynamic::from(AbortKind::OpLimit));
        }
        let over_budget = match RUN.with(Cell::get) {
            Some(run) => Instant::now() > run.deadline,
            None => bare_elapsed(ops) > hook_timeout,
        };
        over_budget.then(|| Dynamic::from(AbortKind::Timeout))
    });

    engine.on_print(|text| tracing::info!(target: "aitm_plugin_rhai::script", "{text}"));
    engine.on_debug(|text, source, pos| {
        tracing::info!(
            target: "aitm_plugin_rhai::script",
            source = source.unwrap_or(""),
            %pos,
            "{text}"
        );
    });
}

/// Time since a bare evaluation (no open run) began, re-armed when Rhai's
/// operation counter restarts.
fn bare_elapsed(ops: u64) -> Duration {
    BARE_CLOCK.with(|clock| {
        let started = match clock.get() {
            Some((last_ops, started)) if ops > last_ops => started,
            _ => Instant::now(),
        };
        clock.set(Some((ops, started)));
        started.elapsed()
    })
}

fn no_sleep() -> Box<EvalAltResult> {
    EvalAltResult::ErrorRuntime(
        Dynamic::from(
            "sleep(...) is not available to scripts: a hook runs under a wall-clock budget \
             and must not park its worker; poll for state with store.query(...) instead"
                .to_string(),
        ),
        Position::NONE,
    )
    .into()
}

/// Test helper: a hardened engine (default limits, 2s budget) whose `print`
/// output is collected into the returned sink instead of tracing.
pub fn print_sink() -> (Engine, Arc<Mutex<Vec<String>>>) {
    let sink = Arc::new(Mutex::new(Vec::new()));
    let mut engine = build_engine(&RhaiLimits::default(), Duration::from_secs(2));
    let captured = Arc::clone(&sink);
    engine.on_print(move |text| {
        if let Ok(mut lines) = captured.lock() {
            lines.push(text.to_string());
        }
    });
    (engine, sink)
}
