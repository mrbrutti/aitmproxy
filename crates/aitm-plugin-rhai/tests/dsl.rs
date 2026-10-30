//! The `dsl` prelude helper namespace: each of the ten flat global functions
//! runs and returns its specified value (AC1–AC4), and the engine's registered
//! set equals the catalogue's `dsl[]` in both directions (AC5, the `dsl` slice
//! of the plugin-system drift guard).
//!
//! These register `register_dsl` onto a bare hardened `build_engine` — the pure
//! helpers need no store / client / guard — which is also why the bare-engine
//! audit (`tests/engine.rs`) does not see them.

use std::collections::BTreeSet;
use std::time::Duration;

use aitm_plugin_rhai::config::RhaiLimits;
use aitm_plugin_rhai::dsl::{register_dsl, DSL_FUNCTIONS};
use aitm_plugin_rhai::engine::build_engine;
use rhai::Engine;

/// A hardened engine with the `dsl` helpers registered, as a loaded script or a
/// PoC `script:` step would see them.
fn dsl_engine() -> Engine {
    let mut engine = build_engine(&RhaiLimits::default(), Duration::from_secs(2));
    register_dsl(&mut engine);
    engine
}

/// AC2 (encoding rows), AC3, AC8: base64 round-trips, `url_encode` matches
/// `aitm-poc`, `hex_encode` is lowercase hex of the input bytes.
#[test]
fn encoding_helpers_run() {
    let engine = dsl_engine();
    assert_eq!(
        engine.eval::<String>(r#"b64_encode("foobar")"#).unwrap(),
        "Zm9vYmFy"
    );
    assert_eq!(
        engine.eval::<String>(r#"b64_decode("Zm9vYmFy")"#).unwrap(),
        "foobar"
    );
    assert_eq!(
        engine.eval::<String>(r#"url_encode("a b/c")"#).unwrap(),
        "a%20b%2Fc"
    );
    assert_eq!(
        engine.eval::<String>(r#"hex_encode("AB")"#).unwrap(),
        "4142"
    );
}

/// AC4: a bad base64 input is a *catchable* `ErrorRuntime`, never a corrupted or
/// empty string that hides the bug.
#[test]
fn b64_decode_errors_are_catchable() {
    let engine = dsl_engine();
    assert!(
        engine.eval::<String>(r#"b64_decode("!!!")"#).is_err(),
        "invalid base64 must error"
    );
    assert_eq!(
        engine
            .eval::<String>(
                r#"let r = "no-error"; try { b64_decode("!!!"); } catch(e) { r = "caught"; } r"#
            )
            .unwrap(),
        "caught"
    );
}

/// AC2 (hashing rows): the published SHA-256 / MD5 digests of `"abc"`, rendered
/// as fixed-length lowercase hex.
#[test]
fn hashing_helpers_run() {
    let engine = dsl_engine();
    let sha = engine.eval::<String>(r#"sha256("abc")"#).unwrap();
    assert_eq!(
        sha,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(sha.len(), 64);
    assert!(sha
        .chars()
        .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));

    let md = engine.eval::<String>(r#"md5("abc")"#).unwrap();
    assert_eq!(md, "900150983cd24fb0d6963f7d28e17f72");
    assert_eq!(md.len(), 32);
    assert!(md
        .chars()
        .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
}

/// AC2 (random rows), AC4 (reversed range errors), AC8 (charset).
#[test]
fn random_helpers_run() {
    let engine = dsl_engine();
    let alpha = engine.eval::<String>(r#"rand_text_alpha(8)"#).unwrap();
    assert_eq!(alpha.chars().count(), 8);
    assert!(alpha.chars().all(|c| c.is_ascii_alphabetic()));

    assert_eq!(engine.eval::<i64>(r#"rand_int(5, 5)"#).unwrap(), 5);

    assert!(
        engine.eval::<i64>(r#"rand_int(5, 1)"#).is_err(),
        "a reversed range must error"
    );
    assert_eq!(
        engine
            .eval::<String>(
                r#"let r = "no-error"; try { rand_int(5, 1); } catch(e) { r = "caught"; } r"#
            )
            .unwrap(),
        "caught"
    );
}

/// AC2 (regex rows), AC4 (invalid pattern errors, out-of-range group is empty).
#[test]
fn regex_helpers_run() {
    let engine = dsl_engine();
    assert!(engine
        .eval::<bool>(r#"regex_match("^a.c$", "abc")"#)
        .unwrap());
    assert!(!engine
        .eval::<bool>(r#"regex_match("^a.c$", "xyz")"#)
        .unwrap());

    assert_eq!(
        engine
            .eval::<String>(r#"regex_extract("(\\d+)", "abc123", 1)"#)
            .unwrap(),
        "123"
    );
    // No match / absent / out-of-range group → "".
    assert_eq!(
        engine
            .eval::<String>(r#"regex_extract("z+", "abc", 0)"#)
            .unwrap(),
        ""
    );

    assert!(
        engine.eval::<bool>(r#"regex_match("(", "x")"#).is_err(),
        "an invalid pattern must error"
    );
    assert_eq!(
        engine
            .eval::<String>(
                r#"let r = "no-error"; try { regex_match("(", "x"); } catch(e) { r = "caught"; } r"#
            )
            .unwrap(),
        "caught"
    );
}

/// AC1 / AC3: all ten helpers are registered as flat global functions — one
/// script calls every one and returns a sentinel, so a missing registration
/// surfaces as `ErrorFunctionNotFound` rather than a silent gap.
#[test]
fn all_ten_dsl_helpers_are_callable() {
    let engine = dsl_engine();
    let script = r#"
        b64_encode("x");
        b64_decode("eA==");
        url_encode("x");
        hex_encode("x");
        sha256("x");
        md5("x");
        rand_text_alpha(1);
        rand_int(1, 2);
        regex_match("x", "x");
        regex_extract("x", "x", 0);
        "ok"
    "#;
    assert_eq!(engine.eval::<String>(script).unwrap(), "ok");
}

/// AC5: the drift guard — the engine's intended `dsl` set (`DSL_FUNCTIONS`)
/// equals the catalogue's `dsl[]` names in both directions. `rhai.api.json` is
/// valid YAML, so the existing `serde_yaml` dev-dependency parses it with no new
/// dev-dep.
#[test]
fn dsl_catalogue_matches_engine() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/design/languages/rhai.api.json"
    );
    let text = std::fs::read_to_string(path).expect("read rhai.api.json");
    let doc: serde_yaml::Value = serde_yaml::from_str(&text).expect("parse rhai.api.json");

    let catalogue: BTreeSet<String> = doc["dsl"]
        .as_sequence()
        .expect("dsl[] is a sequence")
        .iter()
        .map(|entry| {
            entry["name"]
                .as_str()
                .expect("each dsl entry has a string name")
                .to_string()
        })
        .collect();

    let engine: BTreeSet<String> = DSL_FUNCTIONS.iter().map(ToString::to_string).collect();

    assert_eq!(
        catalogue, engine,
        "catalogue dsl[] names must equal DSL_FUNCTIONS (both directions)"
    );
}
