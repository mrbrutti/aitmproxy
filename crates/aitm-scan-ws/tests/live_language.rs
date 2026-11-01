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
//! Everything in this file is blocking on purpose: a seam host fn is a
//! synchronous closure, the language owns its own driver thread and runtime,
//! and the control origin speaks plain HTTP/1.1 — so the test needs no async
//! runtime of its own and no HTTP client dependency.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::process::{Child, ChildStdout, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use aitm_core::{CallerTrust, ScopeEntry, ScopeRateGuard, StdGuard};
use aitm_plugin_rhai::config::RhaiLimits;
use aitm_plugin_rhai::engine::build_engine_with_languages;
use aitm_plugin_rhai::host_registry::seed_call_context;
use rhai::{Dynamic, Engine};
use serde_json::Value;

/// What a run without `$AITM_TESTTARGET_BIN` panics with (plan call 35).
const SKIP: &str = "SKIP: set AITM_TESTTARGET_BIN to a serve binary that has /ws (T10 branch)";

/// An address nothing listens on and the guard was never told about.
const OUT_OF_SCOPE_URL: &str = "ws://127.0.0.2:1/ws";

/// How long the engine may spend in one script.
const HOOK_TIMEOUT: Duration = Duration::from_secs(30);

// --- the real target process -------------------------------------------------

/// T10's `aitm-testtarget-serve`, running with its control origin.
struct Target {
    child: Child,
    /// Keeps the stdout pipe open for the child's lifetime.
    _stdout: BufReader<ChildStdout>,
    /// `http://127.0.0.1:<port>` of the seeded origin.
    origin: String,
    /// `http://127.0.0.1:<port>` of the control origin.
    control: String,
}

impl Target {
    /// Spawn the binary in `mode` and read its listen lines up to `ready`.
    fn start(mode: &str) -> Self {
        let Ok(bin) = std::env::var("AITM_TESTTARGET_BIN") else {
            panic!("{SKIP}");
        };
        let mut child = Command::new(&bin)
            .args(["--mode", mode, "--port", "0", "--control-port", "0"])
            .stdout(Stdio::piped())
            .spawn()
            .unwrap_or_else(|err| panic!("{SKIP} (spawning {bin} failed: {err})"));
        let stdout = child.stdout.take().expect("the child's stdout is piped");
        let mut reader = BufReader::new(stdout);

        let mut origin = None;
        let mut control = None;
        let mut line = String::new();
        loop {
            line.clear();
            let read = reader
                .read_line(&mut line)
                .expect("read the target's stdout");
            assert!(
                read != 0,
                "{SKIP} (the target exited before `ready`; it reported {origin:?} / {control:?})"
            );
            let trimmed = line.trim();
            if let Some(rest) = trimmed.strip_prefix("listening ") {
                origin = Some(rest.to_string());
            } else if let Some(rest) = trimmed.strip_prefix("control ") {
                control = Some(rest.to_string());
            } else if trimmed == "ready" {
                break;
            }
        }

        let origin = origin.expect("the target printed a `listening` line");
        let control =
            control.expect("the target printed a `control` line (it needs --control-port)");
        println!("target[{mode}] origin={origin} control={control}");
        Self {
            child,
            _stdout: reader,
            origin,
            control,
        }
    }

    /// `127.0.0.1:<port>` of the seeded origin.
    fn authority(&self) -> String {
        strip_scheme(&self.origin).to_string()
    }
}

impl Drop for Target {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// `http://host:port` without its scheme.
fn strip_scheme(origin: &str) -> &str {
    origin.split_once("://").map_or(origin, |(_, rest)| rest)
}

/// `GET <path>` on the control origin, parsed as JSON.
fn control_json(control: &str, path: &str) -> Value {
    let authority = strip_scheme(control);
    let mut stream = TcpStream::connect(authority)
        .unwrap_or_else(|err| panic!("connect the control origin {authority}: {err}"));
    let request = format!("GET {path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n");
    stream
        .write_all(request.as_bytes())
        .unwrap_or_else(|err| panic!("send GET {path}: {err}"));
    let mut raw = Vec::new();
    stream
        .read_to_end(&mut raw)
        .unwrap_or_else(|err| panic!("read GET {path}: {err}"));
    let text = String::from_utf8_lossy(&raw).into_owned();
    let body = text
        .split_once("\r\n\r\n")
        .map_or("", |(_, body)| body)
        .to_string();
    serde_json::from_str(&body)
        .unwrap_or_else(|err| panic!("{path} is not JSON ({err}); response was {text:?}"))
}

/// How many rows `/log/conns` holds.
fn conn_rows(control: &str) -> usize {
    control_json(control, "/log/conns")["entries"]
        .as_array()
        .map_or(0, Vec::len)
}

/// Every accepted `/ws` handshake the target logged.
fn accepted_handshakes(control: &str) -> Vec<Value> {
    control_json(control, "/log/ws")["entries"]
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

#[test]
#[ignore = "binds a loopback port; run in the Terminal"]
fn script_round_trips_a_frame_to_the_real_target() {
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

    let handshakes = accepted_handshakes(&target.control);
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

#[test]
#[ignore = "binds a loopback port; run in the Terminal"]
fn out_of_scope_dial_is_refused_before_any_connection() {
    let target = Target::start("vulnerable");
    let authority = target.authority();
    let engine = engine_for(&authority);
    let _seed = seed_call_context(CallerTrust::Operator, None, None);

    // One in-scope dial first, so "no new row" is a change, not an emptiness.
    let frames: i64 = engine
        .eval(&round_trip_script(&authority))
        .expect("the in-scope round trip evaluates");
    assert!(frames >= 2, "the in-scope dial reached the target");
    let before = conn_rows(&target.control);

    let error = engine
        .eval::<Dynamic>(&format!(r#"ws.dial(#{{ url: "{OUT_OF_SCOPE_URL}" }})"#))
        .expect_err("an out-of-scope dial is refused");
    let text = error.to_string();
    println!("out of scope: {text}");
    assert!(
        text.contains("OutOfScope"),
        "the guard's refusal names OutOfScope; was {text}"
    );

    let after = conn_rows(&target.control);
    println!("conns: {before} rows before the refused dial, {after} after");
    assert_eq!(
        before, after,
        "a refused dial opens no connection, so the target's log gains no row"
    );
}

#[test]
#[ignore = "binds a loopback port; run in the Terminal"]
fn fifth_concurrent_handle_is_refused() {
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

    let handshakes = accepted_handshakes(&target.control);
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
