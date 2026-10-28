//! The shared sandboxed engine: `build_engine`/`harden` apply `RhaiLimits`, the
//! operation/time budget via `on_progress`, disable `eval`, and route `print`
//! to tracing (plan Task 2).

use std::cell::Cell;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rhai::{Dynamic, Engine};

use crate::config::RhaiLimits;

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

thread_local! {
    /// The running hook's clock on this thread: the operation count last seen
    /// and when the current top-level evaluation began. Rhai restarts its
    /// operation counter for every top-level `run`/`call_fn`, so a count that
    /// does not increase marks the start of a new hook and re-arms the clock.
    /// Hooks run synchronously on the thread that evaluates them, so each
    /// thread's cell belongs to exactly one hook at a time.
    static HOOK_CLOCK: Cell<Option<(u64, Instant)>> = const { Cell::new(None) };
}

/// A fresh engine with every sandbox limit applied; the one engine shared by
/// every script and PoC step.
pub fn build_engine(limits: &RhaiLimits, hook_timeout: Duration) -> Engine {
    let mut engine = Engine::new();
    harden(&mut engine, limits, hook_timeout);
    engine
}

/// Apply `RhaiLimits` and the budget to an engine (spec §7): size and depth
/// caps, imports capped, `eval` disabled, `on_progress` enforcing both the
/// operation and the wall-clock budget, `print`/`debug` routed to tracing.
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
        .disable_symbol("eval");

    let max_operations = limits.max_operations;
    engine.on_progress(move |ops| {
        if max_operations > 0 && ops > max_operations {
            return Some(Dynamic::from(AbortKind::OpLimit));
        }
        let elapsed = HOOK_CLOCK.with(|clock| {
            let started = match clock.get() {
                Some((last_ops, started)) if ops > last_ops => started,
                _ => Instant::now(),
            };
            clock.set(Some((ops, started)));
            started.elapsed()
        });
        (elapsed > hook_timeout).then(|| Dynamic::from(AbortKind::Timeout))
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
