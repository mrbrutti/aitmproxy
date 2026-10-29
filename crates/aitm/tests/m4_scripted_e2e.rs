//! Task 17 — the deterministic scripted-driver e2e (spec §D7; AC-M4-13, AC-M4-14,
//! AC-M4-15b).
//!
//! A **non-LLM** generic MCP client ([`scripted_driver`]) drives the whole
//! find → reproduce → record → report loop against the hermetic multi-vuln
//! [`aitm-testtarget`](aitm_testtarget) over nothing but the public command
//! surface — the loopback-TCP bus with the agent token — proving the surface
//! suffices to run the thesis loop with no model in it. The driver crawls the
//! **vulnerable** origin through a real browser (obscura), enumerates candidate
//! abuse points from the observed `flow.detail`, confirms each with its own probe
//! via `request.send`, and reproduces it with `poc.build` + `poc.run` — a PoC that
//! passes on the vulnerable origin and fails on the **patched** control — then
//! `findings.record`s it and renders the report.
//!
//! The rig is shared with the Task 18 grader gate ([`rig`]). Gated on a real
//! browser: with `AITM_OBSCURA` unset the tests return early, so the default
//! `cargo test` stays hermetic (no browser, no port binding, no network). Run them
//! for real with:
//!
//! ```text
//! AITM_OBSCURA=1 AITM_OBSCURA_BIN=/path/to/obscura \
//!   cargo test -p aitm --test m4_scripted_e2e -- --nocapture
//! ```
//!
//! The findings-store commands (`findings.*`) are not yet wired into the `aitm`
//! binary (the M4 wiring gap other sessions flagged), so the rig registers
//! `FindingsPlugin` the way Task 16's validator does — the driver still reaches
//! them only over the bus.

#[path = "../../aitm-browser/tests/support/engines.rs"]
#[allow(dead_code)] // only `config_for` is used here; `engines` serves other suites
mod engines;
#[path = "support/rig.rs"]
mod rig;
#[path = "support/scripted_driver.rs"]
mod scripted_driver;

use aitm_core::{Flow, FlowId};
use aitm_findings::{render_index, render_report, DiskFindingStore, FindingFilter, FindingStore};

use rig::{obscura_enabled, obscura_lock, Rig, EXPECTED_CLASSES};

/// The eight-byte PNG signature a real screenshot artifact starts with.
const PNG_MAGIC: &[u8] = b"\x89PNG\r\n\x1a\n";

// ---- AC-M4-13 ---------------------------------------------------------------

/// The driver crawls the vulnerable target through a real browser and enumerates
/// its candidate abuse points **from the observed index flow** — each candidate's
/// path is present in the `flow.detail` body of the flow it was read from, and the
/// six vulnerable endpoints are all discovered. The crawl's flows also arrive as
/// F4 push notifications. Nothing here (or in the driver module) reads the
/// target's planted-vuln manifest.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn scripted_driver_finds_from_observation() {
    if !obscura_enabled() {
        return;
    }
    let _serial = obscura_lock().lock().await;
    let rig = Rig::start().await;
    let mut driver = rig.driver().await;

    let candidates = driver.discover().await.expect("discover candidates");

    // The six vulnerable endpoints are discovered from the crawl.
    for path in [
        "/search",
        "/comments",
        "/fetch",
        "/account/1",
        "/admin",
        "/redirect",
    ] {
        assert!(
            candidates.iter().any(|c| c.path == path),
            "endpoint {path} was not discovered from the crawl; got {:?}",
            candidates.iter().map(|c| &c.path).collect::<Vec<_>>()
        );
    }

    // Every candidate was derived from an observed flow: its path appears in the
    // `flow.detail` body of the source flow it was read out of.
    for candidate in &candidates {
        let detail = driver
            .client
            .tool_call(
                "flow.detail",
                serde_json::json!({"id": candidate.source_flow, "body": "inline"}),
            )
            .await
            .expect("flow.detail for the candidate's source flow");
        let body = response_body_text(&detail);
        assert!(
            body.contains(&candidate.path),
            "candidate {} was not present in its source flow's observed body",
            candidate.path
        );
    }

    // F4: the crawl's flows (captured after subscribing) pushed notifications.
    assert!(
        driver.client.flow_notifications() > 0,
        "no notifications/aitm/flow arrived during the crawl"
    );

    rig.finish().await;
}

// ---- AC-M4-14 ---------------------------------------------------------------

/// For each discovered vuln the driver builds and runs a PoC that passes on the
/// vulnerable origin and fails on the patched control, emitting the three
/// artifacts (a finding-capture flow in the store, a re-parsable PoC file, a PNG
/// screenshot).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn scripted_driver_reproduces_each() {
    if !obscura_enabled() {
        return;
    }
    let _serial = obscura_lock().lock().await;
    let rig = Rig::start().await;
    let mut driver = rig.driver().await;

    let candidates = driver.discover().await.expect("discover candidates");
    let findings = driver
        .reproduce_all(&candidates)
        .await
        .expect("reproduce the discovered vulns");

    let classes: Vec<&str> = findings.iter().map(|f| f.class.as_str()).collect();
    for class in EXPECTED_CLASSES {
        assert!(
            classes.contains(&class),
            "class {class} was not reproduced; got {classes:?}"
        );
    }

    for f in &findings {
        // The reproduction bar: passed on the vulnerable path, failed the control.
        assert!(
            f.passed,
            "[{}] PoC did not pass on the vulnerable origin",
            f.class
        );
        assert_eq!(
            f.control_passed,
            Some(false),
            "[{}] PoC did not fail on the patched control",
            f.class
        );

        // Artifact 1: the finding-capture flow is in the store.
        let fid: FlowId = f
            .finding_capture
            .parse()
            .unwrap_or_else(|e| panic!("[{}] bad finding_capture id: {e}", f.class));
        assert!(
            matches!(rig.store.get(fid), Some(Flow::Http(_))),
            "[{}] finding-capture flow is not in the store",
            f.class
        );

        // Artifact 2: the PoC file re-parses as a PoC.
        let poc_text = std::fs::read_to_string(&f.poc_path)
            .unwrap_or_else(|e| panic!("[{}] read PoC artifact: {e}", f.class));
        let _: aitm_poc::Poc = serde_yaml::from_str(&poc_text)
            .unwrap_or_else(|e| panic!("[{}] PoC artifact does not re-parse: {e}", f.class));

        // Artifact 3: the screenshot is a PNG.
        let png = std::fs::read(&f.screenshot_path)
            .unwrap_or_else(|e| panic!("[{}] read screenshot artifact: {e}", f.class));
        assert!(
            png.starts_with(PNG_MAGIC),
            "[{}] screenshot artifact is not a PNG ({} bytes)",
            f.class,
            png.len()
        );
    }

    rig.finish().await;
}

// ---- AC-M4-15b --------------------------------------------------------------

/// The driver records a `FindingRecord` per reproduced vuln (reachable again over
/// `findings.list`), and the aitm-findings renderer produces `report.md` +
/// `findings.index.json` from the persisted store — one report section and one
/// index entry per finding.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn scripted_driver_records_and_reports() {
    if !obscura_enabled() {
        return;
    }
    let _serial = obscura_lock().lock().await;
    let rig = Rig::start().await;
    let mut driver = rig.driver().await;

    let (findings, ids) = driver.run().await.expect("run the full driver loop");
    assert_eq!(ids.len(), findings.len(), "one recorded id per finding");
    assert!(
        findings.len() >= EXPECTED_CLASSES.len(),
        "expected at least {} findings, got {}",
        EXPECTED_CLASSES.len(),
        findings.len()
    );

    // The records are reachable again over the bus.
    let listed = driver
        .client
        .tool_call("findings.list", serde_json::json!({}))
        .await
        .expect("findings.list over MCP");
    assert_eq!(
        listed.as_array().map(Vec::len),
        Some(findings.len()),
        "findings.list did not return every recorded finding"
    );

    // Read the persisted records and render the report + index from them (D8a).
    let store = DiskFindingStore::new(&rig.findings_dir);
    let mut records = Vec::new();
    for id in &ids {
        records.push(
            store
                .get(id)
                .unwrap_or_else(|| panic!("recorded finding {id} is not in the store")),
        );
    }

    let report = render_report(&records);
    let sections = report.matches("\n## ").count();
    assert_eq!(
        sections,
        records.len(),
        "report must have one section per finding:\n{report}"
    );
    for f in &findings {
        assert!(
            report.contains(&f.target),
            "report missing endpoint {}",
            f.target
        );
    }

    let index = render_index(&records);
    assert_eq!(
        index.as_array().map(Vec::len),
        Some(records.len()),
        "the index must have one entry per finding"
    );

    // The deliverables land as files next to the store.
    let report_path = rig.findings_dir.join("report.md");
    let index_path = rig.findings_dir.join("findings.index.json");
    std::fs::write(&report_path, &report).expect("write report.md");
    std::fs::write(&index_path, serde_json::to_string_pretty(&index).unwrap())
        .expect("write findings.index.json");
    assert!(report_path.exists() && index_path.exists());

    // Sanity: the store's own filter path agrees with the rendered set.
    assert_eq!(
        store.list(&FindingFilter::default()).len(),
        records.len(),
        "the store lists every recorded finding"
    );

    rig.finish().await;
}

// ---- helpers ----------------------------------------------------------------

/// The base64-free body text of a `flow.detail` structured result.
fn response_body_text(detail: &serde_json::Value) -> String {
    // Request and response bodies are base64 (`Value::Bytes`); for discovery the
    // index is a request path echoed in the response body, so decode the response.
    match detail
        .get("response")
        .and_then(|r| r.get("body"))
        .and_then(serde_json::Value::as_str)
    {
        Some(b64) => String::from_utf8_lossy(&base64_decode(b64)).into_owned(),
        None => String::new(),
    }
}

/// Standard padded base64 decode (mirrors the driver's, for the test's own read).
fn base64_decode(s: &str) -> Vec<u8> {
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let mut acc = 0u32;
    let mut bits = 0u8;
    let mut out = Vec::new();
    for c in s.bytes() {
        let Some(v) = val(c) else { continue };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    out
}
