//! Task 2 — the sandboxed engine: operation/time budget abort distinctly
//! (Review Focus #4), `eval` is off, no ambient authority (no filesystem,
//! no modules, no clock, no sleep), the global function table is the audited
//! one, and `print` is captured.

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use aitm_plugin_rhai::config::RhaiLimits;
use aitm_plugin_rhai::engine::{
    begin_run, build_engine, current_run, enter_constants, print_sink, remaining_budget, AbortKind,
    Budget, RunKind,
};
use rhai::{EvalAltResult, OptimizationLevel, Scope, AST};

/// A run budget with `hook_timeout` of wall-clock and the shipped defaults
/// for the rest.
fn budget(hook_timeout: Duration) -> Budget {
    Budget {
        hook_timeout,
        ..Budget::default()
    }
}

/// A loop that never ends and does real work each turn, so the optimizer
/// cannot fold it away and every iteration costs operations.
const RUNAWAY: &str = "let n = 0; loop { n += 1; }";

/// Decode the `on_progress` termination token carried by an aborted run.
fn abort_kind(err: &EvalAltResult) -> Option<AbortKind> {
    match err {
        EvalAltResult::ErrorTerminated(token, _) => token.clone().try_cast::<AbortKind>(),
        _ => None,
    }
}

#[test]
fn timeout_and_oplimit_abort_distinctly() {
    // A busy hook: a small operation budget and a generous clock.
    let limits = RhaiLimits {
        max_operations: 10_000,
        ..RhaiLimits::default()
    };
    let engine = build_engine(&limits, Duration::from_secs(30));
    let err = engine.run(RUNAWAY).expect_err("a runaway loop must abort");
    assert_eq!(
        abort_kind(&err),
        Some(AbortKind::OpLimit),
        "expected an OpLimit token, got: {err}"
    );

    // A slow hook: an effectively unlimited operation budget and a 50ms clock.
    let limits = RhaiLimits {
        max_operations: 1_000_000_000_000,
        ..RhaiLimits::default()
    };
    let engine = build_engine(&limits, Duration::from_millis(50));
    let started = Instant::now();
    let err = engine.run(RUNAWAY).expect_err("a slow loop must abort");
    let elapsed = started.elapsed();
    assert_eq!(
        abort_kind(&err),
        Some(AbortKind::Timeout),
        "expected a Timeout token, got: {err}"
    );
    assert!(
        elapsed < Duration::from_secs(2),
        "timeout took too long to fire: {elapsed:?}"
    );
}

/// I14 (DoS): nothing in Rhai bounds value nesting, and its recursive
/// clone/size-check/drop overflow the worker stack — a Rust abort that kills the
/// whole process — before any Rhai limit trips. The operation budget is the
/// backstop: a script nests at ~4 operations per level, so the budget caps the
/// reachable depth. Here a small budget stops `a=[a]` gracefully (an `OpLimit`
/// abort, no crash) long before the depth could overflow even this thread; the
/// companion test pins that the *shipped* budget keeps that cap inside the real
/// worker stack.
#[test]
fn op_budget_stops_unbounded_value_nesting() {
    // ~8_000 ops → ~2_000 levels, far inside a modest stack (which overflows in
    // the low thousands only on a 2 MiB thread). A generous clock, so the
    // operation budget — not the timeout — is what fires.
    let limits = RhaiLimits {
        max_operations: 8_000,
        ..RhaiLimits::default()
    };
    let handle = std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(move || {
            let engine = build_engine(&limits, Duration::from_secs(30));
            let err = engine
                .run("let a = []; for i in 0..400000 { a = [a]; }")
                .expect_err("unbounded nesting must be refused, not run to a crash");
            assert_eq!(
                abort_kind(&err),
                Some(AbortKind::OpLimit),
                "the op budget must stop the nesting gracefully: {err}"
            );
        })
        .expect("spawns the test thread");
    handle
        .join()
        .expect("the nesting script did not abort the process");
}

/// I14 invariant: the *shipped* operation budget keeps the deepest value a run
/// can nest well inside the worker stack scripts actually run on, so the default
/// posture cannot overflow it. A regression that raised `max_operations` back
/// toward the old 2_000_000 (≈500_000 reachable levels) trips this.
#[test]
fn default_budget_keeps_nesting_within_the_worker_stack() {
    use aitm_plugin_rhai::engine::WORKER_STACK_SIZE;

    // Measured on this engine: ~4 operations build each `a=[a]` nesting level.
    const OPS_PER_LEVEL: u64 = 4;
    // Measured: recursive clone/size-check/drop overflow the 64 MiB worker stack
    // only past ~45_000 levels. Keep the reachable depth a wide margin below it.
    const STACK_OVERFLOW_DEPTH: u64 = 45_000;
    let reachable = RhaiLimits::default().max_operations / OPS_PER_LEVEL;
    assert!(
        reachable * 2 <= STACK_OVERFLOW_DEPTH,
        "the default op budget lets a script nest to {reachable} levels; the {}-byte worker \
         stack overflows past ~{STACK_OVERFLOW_DEPTH}. Lower max_operations or raise \
         WORKER_STACK_SIZE together.",
        WORKER_STACK_SIZE
    );
}

/// The wall-clock budget belongs to the run the caller opened, not to the
/// thread: a run whose budget is already spent is terminated, the next run on
/// the same thread starts its clock afresh and succeeds, and the deadline a
/// run opened is what host calls read back.
///
/// Deterministic by construction: the spent budget is `Duration::ZERO` (its
/// deadline has passed by the first `on_progress` tick, whatever the host is
/// doing), the live budget is 30 s against a few milliseconds of work, and
/// there is no sleep. The earlier form (a 60 ms loop under a 1.5 s budget)
/// flaked on a saturated host.
#[test]
fn each_run_gets_a_fresh_budget_and_exposes_its_deadline() {
    let limits = RhaiLimits {
        max_operations: 0,
        ..RhaiLimits::default()
    };
    // The engine-level budget is generous; the run's own budget is what counts.
    let engine = build_engine(&limits, Duration::from_secs(30));
    // Real work the optimizer cannot fold away: the sum 0 + 1 + … + 1999.
    let busy = "let t = 0; for i in 0..2000 { t += i; } t";
    const BUSY_RESULT: i64 = 1_999_000;
    let generous = budget(Duration::from_secs(30));

    // A run inside its budget completes with the right answer.
    {
        let _run = begin_run(RunKind::Hook, generous);
        let value = engine
            .eval::<i64>(busy)
            .unwrap_or_else(|err| panic!("a run inside its budget must succeed: {err}"));
        assert_eq!(value, BUSY_RESULT);
    }

    // A run whose budget is already spent is aborted with the Timeout token.
    {
        let _run = begin_run(RunKind::Hook, budget(Duration::ZERO));
        let err = engine
            .eval::<i64>(busy)
            .expect_err("an expired run must abort");
        assert_eq!(abort_kind(&err), Some(AbortKind::Timeout), "{err}");
    }

    // The next run on the same thread is not tainted by the spent one: its
    // budget is its own, opened afresh.
    {
        let _run = begin_run(RunKind::Hook, generous);
        let value = engine
            .eval::<i64>(busy)
            .unwrap_or_else(|err| panic!("a fresh run after a spent one must succeed: {err}"));
        assert_eq!(value, BUSY_RESULT);
    }

    // Outside a run nothing is active; inside, the kind and the remaining
    // budget are readable by the host functions.
    assert_eq!(current_run(), None);
    assert_eq!(remaining_budget(), None);
    {
        let _run = begin_run(RunKind::PocStep, budget(Duration::from_millis(500)));
        assert_eq!(current_run(), Some(RunKind::PocStep));
        let left = remaining_budget().expect("a run is active");
        assert!(left <= Duration::from_millis(500), "{left:?}");
        {
            let _inner = begin_run(RunKind::Command, budget(Duration::from_secs(1)));
            assert_eq!(current_run(), Some(RunKind::Command));
        }
        assert_eq!(current_run(), Some(RunKind::PocStep), "nesting restores");
    }
    assert_eq!(current_run(), None);
}

#[test]
fn eval_is_disabled() {
    let engine = build_engine(&RhaiLimits::default(), Duration::from_secs(2));
    let err = engine
        .eval::<i64>(r#"eval("1+1")"#)
        .expect_err("eval must be a disabled symbol");
    let text = err.to_string();
    assert!(text.contains("eval"), "error should name eval: {text}");
}

/// Spec §7: no filesystem, no modules, no clock, no sleep. Each probe is a
/// function Rhai's standard build *does* ship or a script author would try.
#[test]
fn no_ambient_authority() {
    let engine = build_engine(&RhaiLimits::default(), Duration::from_secs(2));

    // No filesystem: the core language has no such function and we register none.
    let err = engine
        .run(r#"open_file("x")"#)
        .expect_err("open_file must not exist");
    assert!(
        matches!(*err, EvalAltResult::ErrorFunctionNotFound(..)),
        "expected 'function not found', got: {err}"
    );

    // No clock: `timestamp()` (and with it `elapsed`) is not registered.
    let err = engine
        .run("timestamp()")
        .expect_err("timestamp must not exist");
    assert!(
        matches!(*err, EvalAltResult::ErrorFunctionNotFound(..)),
        "expected 'function not found', got: {err}"
    );

    // No sleeping: both overloads are refused with a catchable error and
    // return at once — a hook cannot park its worker past the budget.
    for src in [r#"sleep(5)"#, r#"sleep(5.0)"#] {
        let started = Instant::now();
        let err = engine.run(src).expect_err("sleep must be refused");
        assert!(
            started.elapsed() < Duration::from_millis(500),
            "{src} must not actually sleep"
        );
        assert!(
            matches!(*err, EvalAltResult::ErrorRuntime(..)),
            "{src}: expected a catchable runtime error, got: {err}"
        );
        assert!(err.to_string().contains("sleep"), "{src}: {err}");
    }
    let caught: String = engine
        .eval(r#"let r = "slept"; try { sleep(1); } catch(e) { r = "caught"; } r"#)
        .expect("the refusal is catchable");
    assert_eq!(caught, "caught");

    // No modules: imports are capped at zero …
    let err = engine
        .run(r#"import "m" as m;"#)
        .expect_err("import must be refused");
    assert!(
        matches!(*err, EvalAltResult::ErrorTooManyModules(..)),
        "expected the module cap to refuse the import, got: {err}"
    );
    // … and raising the cap in config still never reaches the filesystem:
    // the resolver installed is the one that resolves nothing.
    let limits = RhaiLimits {
        max_modules: 8,
        ..RhaiLimits::default()
    };
    let engine = build_engine(&limits, Duration::from_secs(2));
    let err = engine
        .run(r#"import "m" as m;"#)
        .expect_err("import must still be refused with max_modules > 0");
    assert!(
        matches!(*err, EvalAltResult::ErrorModuleNotFound(..)),
        "expected 'module not found' from the dummy resolver, got: {err}"
    );
}

/// The audit of the global function table (security review, M3): the exact
/// set of function names a script can call on a bare hardened engine. A Rhai
/// upgrade that adds a name fails here and is re-audited, not silently
/// shipped. `sleep` stays listed because it is shadowed with a refusal (see
/// `no_ambient_authority`); the names Rhai's standard build adds that are
/// absent here are the clock (`timestamp`, `elapsed`) and nothing else.
#[test]
fn allowed_global_functions_are_pinned() {
    let engine = build_engine(&RhaiLimits::default(), Duration::from_secs(2));
    let names: BTreeSet<String> = engine
        .gen_fn_signatures(true)
        .into_iter()
        .map(|sig| {
            sig.split('(')
                .next()
                .unwrap_or_default()
                .trim_start_matches("fn ")
                .to_string()
        })
        .filter(|name| !name.is_empty() && !name.starts_with("get$") && !name.starts_with("set$"))
        .collect();

    // (`exit` is present and fine: it ends the *script* with a termination
    // error, the way `return` would — it does not touch the process.)
    for forbidden in ["timestamp", "elapsed", "eval", "open_file", "spawn"] {
        assert!(
            !names.contains(forbidden),
            "`{forbidden}` must not be callable from a script"
        );
    }

    let expected: BTreeSet<String> = ALLOWED_FUNCTIONS.iter().map(|s| s.to_string()).collect();
    let added: Vec<_> = names.difference(&expected).collect();
    let removed: Vec<_> = expected.difference(&names).collect();
    assert!(
        added.is_empty() && removed.is_empty(),
        "the global function table changed; re-audit it.\n  added: {added:?}\n  removed: {removed:?}"
    );
}

/// Filled in from the audit run (rhai 1.27.0); every name here was checked to
/// touch nothing outside the engine: operators and arithmetic, strings,
/// arrays, blobs, maps, ranges and iterators, function-pointer introspection
/// (`name`, `is_anonymous`, `get_fn_metadata_list` — script functions only),
/// `tag`/`set_tag` on values, `print`/`debug` routed to tracing, `exit` (ends
/// the script), and `sleep` (shadowed with a refusal).
const ALLOWED_FUNCTIONS: &[&str] = &[
    "!",
    "!=",
    "%",
    "&",
    "*",
    "**",
    "+",
    "+=",
    "-",
    "/",
    "<",
    "<<",
    "<=",
    "==",
    ">",
    ">=",
    ">>",
    "E",
    "PI",
    "^",
    "abs",
    "acos",
    "acosh",
    "all",
    "append",
    "as_string",
    "asin",
    "asinh",
    "atan",
    "atanh",
    "bits",
    "blob",
    "bytes",
    "ceiling",
    "chars",
    "chop",
    "clear",
    "contains",
    "cos",
    "cosh",
    "crop",
    "debug",
    "dedup",
    "drain",
    "end",
    "ends_with",
    "exit",
    "exp",
    "extract",
    "fill_with",
    "filter",
    "find",
    "find_map",
    "floor",
    "for_each",
    "fraction",
    "get",
    "get_bit",
    "get_bits",
    "get_fn_metadata_list",
    "hypot",
    "index_of",
    "insert",
    "int",
    "is_anonymous",
    "is_empty",
    "is_even",
    "is_exclusive",
    "is_finite",
    "is_inclusive",
    "is_infinite",
    "is_nan",
    "is_odd",
    "is_zero",
    "keys",
    "len",
    "ln",
    "log",
    "make_lower",
    "make_upper",
    "map",
    "max",
    "min",
    "mixin",
    "name",
    "order",
    "order_by",
    "order_desc",
    "pad",
    "parse_be_float",
    "parse_be_int",
    "parse_float",
    "parse_int",
    "parse_json",
    "parse_le_float",
    "parse_le_int",
    "pop",
    "print",
    "push",
    "range",
    "reduce",
    "reduce_rev",
    "remove",
    "replace",
    "retain",
    "reverse",
    "round",
    "set",
    "set_bit",
    "set_bits",
    "set_tag",
    "shift",
    "sign",
    "sin",
    "sinh",
    "sleep",
    "some",
    "sort",
    "sort_by",
    "sort_desc",
    "splice",
    "split",
    "split_rev",
    "sqrt",
    "start",
    "starts_with",
    "sub_string",
    "tag",
    "take",
    "tan",
    "tanh",
    "to_array",
    "to_binary",
    "to_blob",
    "to_chars",
    "to_debug",
    "to_degrees",
    "to_float",
    "to_hex",
    "to_int",
    "to_json",
    "to_lower",
    "to_octal",
    "to_radians",
    "to_string",
    "to_upper",
    "trim",
    "truncate",
    "values",
    "write_ascii",
    "write_be",
    "write_le",
    "write_utf8",
    "zip",
    "|",
];

#[test]
fn print_is_captured() {
    let (engine, sink) = print_sink();
    engine.run(r#"print("hi")"#).expect("print must run");
    let lines = sink.lock().expect("sink lock");
    assert_eq!(lines.as_slice(), ["hi".to_string()]);
}

/// Every script compiles at one pinned level, so a debug and a release core
/// (and a future rhai default) compile it identically. The level is this
/// engine's promise, not rhai's default.
#[test]
fn optimization_level_is_pinned_to_simple() {
    let engine = build_engine(&RhaiLimits::default(), Duration::from_secs(2));
    assert_eq!(engine.optimization_level(), OptimizationLevel::Simple);
}

/// A script's top-level literal constants are visible inside its functions
/// (as plain values and as method receivers) only while `enter_constants`
/// holds them on the thread: the resolver behind `fn on_request(flow) { … TAG
/// … }` and `load(reg)` closures. A parameter of the same name still wins.
#[test]
fn script_constants_resolve_inside_functions_while_entered() {
    let engine = build_engine(&RhaiLimits::default(), Duration::from_secs(2));
    let ast = engine
        .compile(r#"const K = 7; const WORDS = ["a", "b"]; fn f(x) { K * x + WORDS.len() } fn g(K) { K }"#)
        .expect("compiles");

    let bare = engine.call_fn::<i64>(&mut Scope::new(), &ast, "f", (2_i64,));
    assert!(
        matches!(&bare, Err(e) if e.to_string().contains("Variable not found: K")),
        "{bare:?}"
    );

    let _constants = enter_constants(&ast);
    assert_eq!(
        engine
            .call_fn::<i64>(&mut Scope::new(), &ast, "f", (2_i64,))
            .expect("f runs"),
        16
    );
    assert_eq!(
        engine
            .call_fn::<i64>(&mut Scope::new(), &ast, "g", (3_i64,))
            .expect("g runs"),
        3
    );
}

/// `enter_constants` nests: an inner guard replaces the table and its drop
/// restores the one before it, so a run resumed after another script's run
/// sees its own constants again; once the last guard drops nothing is visible.
/// A map of literals is a constant too, usable as a receiver (`M.n`).
#[test]
fn enter_constants_nests_and_restores_the_previous_table() {
    let engine = build_engine(&RhaiLimits::default(), Duration::from_secs(2));
    let a = engine
        .compile(r#"const K = 1; const M = #{ n: 10 }; fn f() { K } fn m() { M.n }"#)
        .expect("a compiles");
    let b = engine
        .compile(r#"const K = 2; fn f() { K }"#)
        .expect("b compiles");
    let f = |ast: &AST| engine.call_fn::<i64>(&mut Scope::new(), ast, "f", ());

    let outer = enter_constants(&a);
    assert_eq!(f(&a).expect("a's f"), 1);
    assert_eq!(
        engine
            .call_fn::<i64>(&mut Scope::new(), &a, "m", ())
            .expect("a's m"),
        10,
        "a map literal is a constant and works as a receiver"
    );
    {
        let _inner = enter_constants(&b);
        assert_eq!(f(&b).expect("b's f"), 2);
    }
    assert_eq!(
        f(&a).expect("a's f after the inner guard dropped"),
        1,
        "dropping the inner guard restores the outer table"
    );
    drop(outer);
    let bare = f(&a);
    assert!(
        matches!(&bare, Err(e) if e.to_string().contains("Variable not found: K")),
        "no table is visible once the last guard drops: {bare:?}"
    );
}

/// A constant a function reaches through the resolver is still a constant:
/// Rhai refuses a mutating method on it and an assignment to it, exactly as it
/// does for a top-level `const`, and the next read sees the literal unchanged.
/// A script that wants to mutate copies into a local first.
#[test]
fn constants_reached_inside_functions_stay_constant() {
    let engine = build_engine(&RhaiLimits::default(), Duration::from_secs(2));
    let ast = engine
        .compile(
            r#"
            const PATHS = ["/a"];
            const N = 1;
            fn grow() { PATHS.push("/b"); PATHS.len() }
            fn reassign() { PATHS = []; PATHS.len() }
            fn bump() { N += 1; N }
            fn read() { PATHS.len() }
            fn local_copy() { let p = PATHS; p.push("/b"); `${p.len()}/${PATHS.len()}` }
            "#,
        )
        .expect("compiles");
    let _constants = enter_constants(&ast);
    let call = |name: &str| engine.call_fn::<i64>(&mut Scope::new(), &ast, name, ());

    let grow = call("grow");
    assert!(
        matches!(&grow, Err(e) if matches!(**e, EvalAltResult::ErrorNonPureMethodCallOnConstant(ref m, _) if m == "push")),
        "a mutating method on a constant is refused: {grow:?}"
    );
    let reassign = call("reassign");
    assert!(
        matches!(&reassign, Err(e) if matches!(**e, EvalAltResult::ErrorAssignmentToConstant(ref v, _) if v == "PATHS")),
        "assigning to a constant is refused: {reassign:?}"
    );
    let bump = call("bump");
    assert!(
        matches!(&bump, Err(e) if matches!(**e, EvalAltResult::ErrorAssignmentToConstant(ref v, _) if v == "N")),
        "compound-assigning to a constant is refused: {bump:?}"
    );
    assert_eq!(
        call("read").expect("read runs"),
        1,
        "the refused attempts left the constant as declared"
    );
    assert_eq!(
        engine
            .call_fn::<String>(&mut Scope::new(), &ast, "local_copy", ())
            .expect("local_copy runs"),
        "2/1",
        "a local copy may be mutated and the constant is untouched"
    );
}

/// A local or parameter a closure captures keeps shadowing a constant of the
/// same name: the closure body reads the captured name unindexed, and the
/// resolver defers to the live scope, where the capture is a parameter. An
/// uncaptured read of the constant from a closure still resolves.
#[test]
fn captured_locals_still_shadow_constants() {
    let engine = build_engine(&RhaiLimits::default(), Duration::from_secs(2));
    let ast = engine
        .compile(
            r#"
            const X = 1;
            fn via_closure() { let X = 5; let c = || X; c.call() }
            fn param_closure(X) { let c = || X; c.call() }
            fn unshadowed() { let c = || X; c.call() }
            "#,
        )
        .expect("compiles");
    let _constants = enter_constants(&ast);
    let call = |name: &str, args: Vec<rhai::Dynamic>| {
        engine
            .call_fn::<i64>(&mut Scope::new(), &ast, name, args)
            .expect(name)
    };
    assert_eq!(call("via_closure", vec![]), 5);
    assert_eq!(call("param_closure", vec![rhai::Dynamic::from(7_i64)]), 7);
    assert_eq!(call("unshadowed", vec![]), 1);
}
