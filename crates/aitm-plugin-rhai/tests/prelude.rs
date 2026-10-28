//! Task 11 — the bundled prelude: compiles under the hardened engine and its
//! helpers (`ok`, `contains_ci`, `json`) are callable from any script.

use std::time::Duration;

use aitm_plugin_rhai::config::RhaiLimits;
use aitm_plugin_rhai::engine::build_engine;
use aitm_plugin_rhai::prelude::{load_prelude, register_prelude, PRELUDE_SRC};

#[test]
fn prelude_compiles_hardened() {
    let engine = build_engine(&RhaiLimits::default(), Duration::from_secs(2));
    load_prelude(&engine).expect("the bundled prelude must compile");
    assert!(
        !PRELUDE_SRC.trim().is_empty(),
        "the prelude source must be bundled"
    );
}

#[test]
fn helper_callable_from_script() {
    let mut engine = build_engine(&RhaiLimits::default(), Duration::from_secs(2));
    register_prelude(&mut engine).expect("the prelude must register");

    let hit = engine
        .eval::<bool>(r#"contains_ci("AbC", "abc")"#)
        .expect("contains_ci must be callable");
    assert!(hit, "contains_ci is case-insensitive");

    let miss = engine
        .eval::<bool>(r#"contains_ci("AbC", "xyz")"#)
        .expect("contains_ci must be callable");
    assert!(!miss, "contains_ci must still reject a real miss");

    let success = engine
        .eval::<bool>("ok(#{status: 204})")
        .expect("ok must be callable");
    assert!(success, "a 2xx status is ok");

    let failure = engine
        .eval::<bool>("ok(#{status: 500})")
        .expect("ok must be callable");
    assert!(!failure, "a 5xx status is not ok");

    let text = engine
        .eval::<String>("json(#{a: 1})")
        .expect("json must be callable");
    assert_eq!(text, r#"{"a":1}"#);
}
