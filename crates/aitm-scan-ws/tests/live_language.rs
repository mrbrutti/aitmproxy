//! Live proof of the `ws.*` Rhai namespace against the **real** seeded target
//! (T4 plan task 18, amended by call 35; spec AC T4-4).
//!
//! The engine is the real one `aitm-plugin-rhai` builds, the language is the
//! one `crates/aitm/src/main.rs` installs ([`aitm_scan_ws::language`]), the
//! dialer underneath is the production TCP transport, and the target is T10's
//! `aitm-testtarget-serve` spawned from `$AITM_TESTTARGET_BIN`. What the
//! script did is read back from the target's own control origin
//! (`GET /log/ws`, `GET /log/conns`), never from the scanner.
//!
//! Each test binds a loopback port, so each is `#[ignore]`d and run in the
//! Terminal:
//!
//! ```text
//! cargo test -p aitm-scan-ws --test live_lane --test live_language -- --ignored --nocapture
//! ```
//!
//! Without `AITM_TESTTARGET_BIN` the tests **panic**; a missing target must
//! read as a failure, never as a silent green.
//!
//! The scripts themselves run blocking on purpose — a seam host fn is a
//! synchronous closure and the language owns its own driver thread and
//! runtime — while the control origin is read through the live harness's one
//! async HTTP client, shared with `tests/live_lane.rs` (quality finding N3).

use std::sync::Arc;
use std::time::Duration;

use aitm_core::{CallerTrust, ScopeEntry, ScopeRateGuard, StdGuard};
use aitm_plugin_rhai::config::RhaiLimits;
use aitm_plugin_rhai::engine::build_engine_with_languages;
use aitm_plugin_rhai::host_registry::seed_call_context;
use rhai::{Dynamic, Engine};
use serde_json::Value;

mod common;

use common::live::{control_json, Target};

/// An address nothing listens on and the guard was never told about.
const OUT_OF_SCOPE_URL: &str = "ws://127.0.0.2:1/ws";

/// How long the engine may spend in one script.
const HOOK_TIMEOUT: Duration = Duration::from_secs(30);

/// How many rows `/log/conns` holds.
async fn conn_rows(control: &str) -> usize {
    control_json(control, "/log/conns").await["entries"]
        .as_array()
        .map_or(0, Vec::len)
}

/// Every accepted `/ws` handshake the target logged.
async fn accepted_handshakes(control: &str) -> Vec<Value> {
    control_json(control, "/log/ws").await["entries"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default()
        .iter()
        .filter(|entry| {
            entry["kind"] == Value::String("handshake".to_string())
                && entry["accepted"] == Value::Bool(true)
        })
        .cloned()
        .collect()
}

// --- the real engine ----------------------------------------------------------

/// A guard that holds exactly `authority`, as `LateHandles` would at runtime.
fn guard_for(authority: &str) -> Arc<dyn ScopeRateGuard> {
    let guard = StdGuard::default();
    guard.add_scope(ScopeEntry {
        host: authority.to_string(),
    });
    Arc::new(guard)
}

/// An engine with the production `ws.*` namespace installed.
///
/// Goes through [`aitm_scan_ws::language`], the exact entry point
/// `crates/aitm/src/main.rs` calls, so what is proved here is what ships.
fn engine_for(authority: &str) -> Engine {
    let language =
        aitm_scan_ws::language(guard_for(authority)).expect("the ws language slot is filled (D1)");
    build_engine_with_languages(&RhaiLimits::default(), HOOK_TIMEOUT, &[language.as_ref()])
        .expect("the ws namespace installs into a real engine")
}

/// The round-trip script against `authority`'s `/ws`.
fn round_trip_script(authority: &str) -> String {
    format!(
        r#"
        let h = ws.dial(#{{ url: "ws://{authority}/ws" }});
        ws.send(h, "{{\"type\":\"echo\",\"msg\":\"ping\"}}");
        let r = ws.recv(h, 1500);
        ws.close(h);
        r.frames.len()
    "#
    )
}

// --- the proofs ---------------------------------------------------------------

#[tokio::test]
#[ignore = "binds a loopback port; run in the Terminal"]
async fn script_round_trips_a_frame_to_the_real_target() {
    let target = Target::start("vulnerable");
    let authority = target.authority();
    let engine = engine_for(&authority);
    let _seed = seed_call_context(CallerTrust::Operator, None, None);

    let frames: i64 = engine
        .eval(&round_trip_script(&authority))
        .expect("the ws.* round trip evaluates against the real target");
    println!("round trip: {frames} frames came back from {authority}/ws");
    assert!(
        frames >= 2,
        "the seeded target answers with a hello frame and an echo frame, saw {frames}"
    );

    let handshakes = accepted_handshakes(&target.control).await;
    for entry in &handshakes {
        println!(
            "handshake: path={} key={} accepted={} status={}",
            entry["path"], entry["sec_websocket_key"], entry["accepted"], entry["status"]
        );
    }
    assert_eq!(
        handshakes.len(),
        1,
        "the target logged exactly the script's one accepted handshake"
    );
    assert_eq!(
        handshakes[0]["path"],
        Value::String("/ws".to_string()),
        "the script reached /ws"
    );
}

#[tokio::test]
#[ignore = "binds a loopback port; run in the Terminal"]
async fn out_of_scope_dial_is_refused_before_any_connection() {
    let target = Target::start("vulnerable");
    let authority = target.authority();
    let engine = engine_for(&authority);
    let _seed = seed_call_context(CallerTrust::Operator, None, None);

    // One in-scope dial first, so "no new row" is a change, not an emptiness.
    let frames: i64 = engine
        .eval(&round_trip_script(&authority))
        .expect("the in-scope round trip evaluates");
    assert!(frames >= 2, "the in-scope dial reached the target");
    let before = conn_rows(&target.control).await;

    let error = engine
        .eval::<Dynamic>(&format!(r#"ws.dial(#{{ url: "{OUT_OF_SCOPE_URL}" }})"#))
        .expect_err("an out-of-scope dial is refused");
    let text = error.to_string();
    println!("out of scope: {text}");
    assert!(
        text.contains("OutOfScope"),
        "the guard's refusal names OutOfScope; was {text}"
    );

    let after = conn_rows(&target.control).await;
    println!("conns: {before} rows before the refused dial, {after} after");
    assert_eq!(
        before, after,
        "a refused dial opens no connection, so the target's log gains no row"
    );
}

#[tokio::test]
#[ignore = "binds a loopback port; run in the Terminal"]
async fn fifth_concurrent_handle_is_refused() {
    let target = Target::start("vulnerable");
    let authority = target.authority();
    let engine = engine_for(&authority);
    let _seed = seed_call_context(CallerTrust::Operator, None, None);

    let error = engine
        .eval::<Dynamic>(&format!(
            r#"
            let last = 0;
            for i in 0..5 {{
                last = ws.dial(#{{ url: "ws://{authority}/ws" }});
            }}
            last
        "#
        ))
        .expect_err("the fifth concurrent handle is refused");
    let text = error.to_string();
    println!("handle bound: {text}");
    assert!(
        text.contains("4 handles already open"),
        "the fifth dial names the handle bound; was {text}"
    );

    let handshakes = accepted_handshakes(&target.control).await;
    println!(
        "handle bound: the target accepted {} upgrades",
        handshakes.len()
    );
    assert_eq!(
        handshakes.len(),
        4,
        "exactly four connections reached the target before the bound refused the fifth"
    );
}
