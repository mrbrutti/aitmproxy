//! Task 2 — the sandboxed engine: operation/time budget abort distinctly
//! (Review Focus #4), `eval` is off, no ambient authority (no filesystem,
//! no modules, no clock, no sleep), the global function table is the audited
//! one, and `print` is captured.

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use aitm_plugin_rhai::config::RhaiLimits;
use aitm_plugin_rhai::engine::{
    begin_run, build_engine, current_run, print_sink, remaining_budget, AbortKind, RunKind,
};
use rhai::EvalAltResult;

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

/// The wall-clock budget belongs to the run the caller opened, not to the
/// thread: a second run on the same thread starts its clock afresh, and the
/// deadline it opened is what host calls read back.
#[test]
fn each_run_gets_a_fresh_budget_and_exposes_its_deadline() {
    let limits = RhaiLimits {
        max_operations: 0,
        ..RhaiLimits::default()
    };
    // The engine-level budget is generous; the run's own budget is what counts.
    let engine = build_engine(&limits, Duration::from_secs(30));
    // ~60ms of busy work per run.
    let busy = "let t = 0; for i in 0..400000 { t += i; } t";

    for _ in 0..2 {
        let _run = begin_run(RunKind::Hook, Duration::from_millis(1500));
        let started = Instant::now();
        engine
            .eval::<i64>(busy)
            .unwrap_or_else(|err| panic!("a run inside its budget must succeed: {err}"));
        assert!(started.elapsed() < Duration::from_millis(1500));
    }

    // A run whose budget is already spent is aborted with the Timeout token.
    {
        let _run = begin_run(RunKind::Hook, Duration::from_millis(20));
        std::thread::sleep(Duration::from_millis(40));
        let err = engine
            .eval::<i64>(busy)
            .expect_err("an expired run must abort");
        assert_eq!(abort_kind(&err), Some(AbortKind::Timeout), "{err}");
    }

    // Outside a run nothing is active; inside, the kind and the remaining
    // budget are readable by the host functions.
    assert_eq!(current_run(), None);
    assert_eq!(remaining_budget(), None);
    {
        let _run = begin_run(RunKind::PocStep, Duration::from_millis(500));
        assert_eq!(current_run(), Some(RunKind::PocStep));
        let left = remaining_budget().expect("a run is active");
        assert!(left <= Duration::from_millis(500), "{left:?}");
        {
            let _inner = begin_run(RunKind::Command, Duration::from_secs(1));
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
