//! The `dsl` prelude helper namespace: `DslCapability`'s identity (AC1) and each
//! of the ten flat global functions running and returning its specified value
//! (AC2–AC4). Engine ≡ catalogue (AC5) is the pre-existing
//! `tests/api_catalog.rs` bijection, not a bespoke test here.
//!
//! Most tests register `register_dsl` onto a bare hardened `build_engine` — the
//! pure helpers need no store / client / guard — which is also why the
//! bare-engine audit (`tests/engine.rs`) does not see them. One test
//! (`dsl_reachable_through_real_loader`, AC3) goes through the real `RhaiLoader`
//! engine built from `m3_capabilities()`, proving the helpers are wired in for
//! actual loaded scripts, not just via the free `register_dsl`.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use aitm_core::{HttpFlow, HttpRequest, MemFlowStore, ProxyClient, StdGuard};
use aitm_plugin_rhai::config::{RhaiConfig, RhaiLimits};
use aitm_plugin_rhai::dsl::{register_dsl, DslCapability};
use aitm_plugin_rhai::engine::build_engine;
use aitm_plugin_rhai::host_core::{MemoryFindingSink, ScriptCapability, ScriptServices};
use aitm_plugin_rhai::loader::RhaiLoader;
use rhai::Engine;

/// AC1: the capability advertises the `dsl` namespace at API 1.
#[test]
fn dsl_capability_identity() {
    let cap = DslCapability;
    assert_eq!(cap.namespace(), "dsl");
    assert_eq!(cap.min_api(), "1");
}

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
/// empty string that hides the bug — both the invalid-base64 branch and the
/// distinct valid-base64-but-non-UTF-8-bytes branch (`"/w=="` decodes to `0xFF`).
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

    // Valid base64 whose decoded bytes are not valid UTF-8 (0xFF): a distinct,
    // catchable error, never a lossy string.
    assert!(
        engine.eval::<String>(r#"b64_decode("/w==")"#).is_err(),
        "non-UTF-8 decoded bytes must error"
    );
    assert_eq!(
        engine
            .eval::<String>(
                r#"let r = "no-error"; try { b64_decode("/w=="); } catch(e) { r = "caught"; } r"#
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

/// `rand_text_alpha` is bounded at `MAX_RAND_TEXT_ALPHA` (4096): the cap length
/// still works, and any larger length is a *catchable* error — never a multi-GB
/// allocation or a capacity-overflow panic (the gating panel finding).
#[test]
fn rand_text_alpha_is_bounded() {
    let engine = dsl_engine();
    assert_eq!(
        engine
            .eval::<String>(r#"rand_text_alpha(4096)"#)
            .unwrap()
            .chars()
            .count(),
        4096
    );

    assert!(
        engine.eval::<String>(r#"rand_text_alpha(4097)"#).is_err(),
        "one over the cap must error"
    );
    assert!(
        engine
            .eval::<String>(r#"rand_text_alpha(2000000000)"#)
            .is_err(),
        "a huge length must error, not allocate"
    );
    assert_eq!(
        engine
            .eval::<String>(
                r#"let r = "no-error"; try { rand_text_alpha(2000000000); } catch(e) { r = "caught"; } r"#
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
    // Out-of-range group on a pattern that DID match → "".
    assert_eq!(
        engine
            .eval::<String>(r#"regex_extract("(a)(b)", "ab", 5)"#)
            .unwrap(),
        ""
    );
    // A negative group index → "".
    assert_eq!(
        engine
            .eval::<String>(r#"regex_extract("(a)", "a", -1)"#)
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

/// A client no test reaches — the `dsl` helpers are pure.
struct StubClient;

impl ProxyClient for StubClient {
    fn send(
        &self,
        _req: HttpRequest,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<HttpFlow>> + Send + '_>> {
        Box::pin(async { anyhow::bail!("stub client") })
    }
}

/// AC3: the helpers are reachable through the real `RhaiLoader` engine (built via
/// `m3_capabilities()`), not only through the free `register_dsl` — so an actual
/// loaded script / PoC `script:` step gets them. The loader's shared engine is
/// the same one every loaded script runs on.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dsl_reachable_through_real_loader() {
    let services = ScriptServices {
        store: Arc::new(MemFlowStore::new()),
        client: Arc::new(StubClient),
        browser: None,
        guard: Arc::new(StdGuard::default()),
        findings: Arc::new(MemoryFindingSink::new()),
        rt: tokio::runtime::Handle::current(),
    };
    let loader = RhaiLoader::new(RhaiConfig::default(), services).expect("the loader builds");
    let out = loader
        .engine()
        .eval::<String>(r#"b64_encode("foobar")"#)
        .expect("a dsl helper is callable on the loader's engine");
    assert_eq!(out, "Zm9vYmFy");
}
