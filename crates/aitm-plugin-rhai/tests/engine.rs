//! Task 2 — the sandboxed engine: operation/time budget abort distinctly
//! (Review Focus #4), `eval` is off, no ambient authority, `print` is captured.

use std::time::{Duration, Instant};

use aitm_plugin_rhai::config::RhaiLimits;
use aitm_plugin_rhai::engine::{build_engine, print_sink, AbortKind};
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

#[test]
fn eval_is_disabled() {
    let engine = build_engine(&RhaiLimits::default(), Duration::from_secs(2));
    let err = engine
        .eval::<i64>(r#"eval("1+1")"#)
        .expect_err("eval must be a disabled symbol");
    let text = err.to_string();
    assert!(text.contains("eval"), "error should name eval: {text}");
}

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

    // No modules: imports are capped at zero.
    let err = engine
        .run(r#"import "m" as m;"#)
        .expect_err("import must be refused");
    assert!(
        matches!(*err, EvalAltResult::ErrorTooManyModules(..)),
        "expected the module cap to refuse the import, got: {err}"
    );
}

#[test]
fn print_is_captured() {
    let (engine, sink) = print_sink();
    engine.run(r#"print("hi")"#).expect("print must run");
    let lines = sink.lock().expect("sink lock");
    assert_eq!(lines.as_slice(), ["hi".to_string()]);
}
