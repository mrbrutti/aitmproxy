//! Task 18 — the deterministic exit gate + harness-neutral proof (spec AC-M4-16,
//! AC-M4-16b).
//!
//! The Task 17 e2e proves the non-LLM scripted driver *runs* the whole loop; this
//! suite is the **exit gate** on top of it. It reuses the shared [`rig`] and the
//! same generic [`scripted_driver`], drives the full find → reproduce → record loop
//! against the seeded multi-vuln target, and then:
//!
//! 1. [`grader_gate_all_reproduced_zero_false_positives`] (AC-M4-16) — feeds the
//!    **recorded findings** to [`grade`](aitm_testtarget::grade) and asserts the
//!    driver reproduced **all** planted vulns with **zero** false positives. This
//!    is the deterministic pass/fail gate: a regression that drops a vuln or
//!    invents one fails here.
//! 2. [`generic_mcp_client_drives_full_loop`] (AC-M4-16b) — proves harness
//!    neutrality: the driver is a *generic* MCP client (raw loopback-TCP JSON-RPC
//!    with the token handshake — the `agent/generic` adapter's documented
//!    raw-client path, see `agent/generic/README.md`), carries no Claude/Anthropic
//!    code, and drives the whole loop over the bus. Nothing in the tool is
//!    Claude-specific. (Task 16's `agent_surface` statically validates every
//!    adapter config and bans provider SDKs; this adds the *live* drive.)
//!
//! Gated on a real browser exactly like Task 17: with `AITM_OBSCURA` unset both
//! tests return early, so the default `cargo test` stays hermetic. Run for real:
//!
//! ```text
//! AITM_OBSCURA=1 AITM_OBSCURA_BIN=/path/to/obscura \
//!   cargo test -p aitm --test m4_grader_gate -- --nocapture
//! ```

#[path = "../../aitm-browser/tests/support/engines.rs"]
#[allow(dead_code)] // only `config_for` is used here; `engines` serves other suites
mod engines;
#[path = "support/rig.rs"]
#[allow(dead_code)] // the gate uses a subset of the shared rig's surface
mod rig;
#[path = "support/scripted_driver.rs"]
#[allow(dead_code)] // the gate drives the loop via `run`; some probe helpers are unused here
mod scripted_driver;

use std::path::{Path, PathBuf};

use aitm_findings::{DiskFindingStore, FindingStore};
use aitm_testtarget::grade;

use rig::{obscura_enabled, obscura_lock, Rig, EXPECTED_CLASSES};

/// The workspace root: `CARGO_MANIFEST_DIR` is `<root>/crates/aitm`.
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("workspace root is two levels above crates/aitm")
        .to_path_buf()
}

// ---- AC-M4-16 ---------------------------------------------------------------

/// The deterministic exit gate: the scripted driver drives the full loop, and the
/// grader — scoring the **recorded findings** against the hidden manifest — confirms
/// every planted vuln was found-and-reproduced with zero false positives.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn grader_gate_all_reproduced_zero_false_positives() {
    if !obscura_enabled() {
        return;
    }
    let _serial = obscura_lock().lock().await;
    let rig = Rig::start().await;
    let mut driver = rig.driver().await;

    // Run the whole non-LLM loop: discover → reproduce → record.
    let (findings, ids) = driver.run().await.expect("run the full driver loop");
    assert_eq!(ids.len(), findings.len(), "one recorded id per finding");

    // Score the *recorded* findings (read back from the persisted store, exactly as
    // an operator-facing grader would) against the hidden planted-vuln manifest.
    let store = DiskFindingStore::new(&rig.findings_dir);
    let records: Vec<_> = ids
        .iter()
        .map(|id| {
            store
                .get(id)
                .unwrap_or_else(|| panic!("recorded finding {id} is not in the store"))
        })
        .collect();

    let report = grade(&records);

    // The gate: all planted vulns reproduced, no false positives.
    assert_eq!(
        report.reproduced, report.planted,
        "grader gate: reproduced {} of {} planted vulns (missing {:?})",
        report.reproduced, report.planted, report.missing
    );
    assert_eq!(
        report.false_positives, 0,
        "grader gate: {} false-positive finding(s): {:?}",
        report.false_positives, report.spurious
    );
    // Sanity: the target really does plant the six classes this milestone enumerates.
    assert_eq!(
        report.planted,
        EXPECTED_CLASSES.len(),
        "the seeded target must plant all {} vuln classes",
        EXPECTED_CLASSES.len()
    );

    rig.finish().await;
}

// ---- AC-M4-16b --------------------------------------------------------------

/// Harness-neutrality, proven live: the exact same non-LLM driver — a *generic* MCP
/// client with no Claude/Anthropic code — drives the whole loop over the bus using
/// the `agent/generic` adapter's raw-client path (loopback-TCP JSON-RPC behind the
/// `{"token": …}` handshake). All six classes reproduce and the records are
/// readable again over the bus, so nothing in the tool is Claude-specific.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn generic_mcp_client_drives_full_loop() {
    if !obscura_enabled() {
        return;
    }

    // The driver connects via the `agent/generic` adapter's documented raw-client
    // path. Pin the test to that config: it must exist, parse, and describe the very
    // loopback-TCP + token-handshake transport the driver uses — and name nothing
    // Claude-specific (that is what "harness-neutral" means).
    let generic_cfg = repo_root().join("agent/generic/mcp.json");
    let generic_text = std::fs::read_to_string(&generic_cfg)
        .unwrap_or_else(|e| panic!("read {}: {e}", generic_cfg.display()));
    let generic_json: serde_json::Value = serde_json::from_str(&generic_text)
        .unwrap_or_else(|e| panic!("{} is not valid JSON: {e}", generic_cfg.display()));
    assert!(
        generic_json.get("mcpServers").is_some(),
        "{} must define `mcpServers`",
        generic_cfg.display()
    );
    assert!(
        generic_text.contains("127.0.0.1"),
        "{} must target the loopback-TCP bus the driver connects to",
        generic_cfg.display()
    );
    assert!(
        generic_text.contains(".token") || generic_text.contains("token-file"),
        "{} must name the agent token file for the handshake",
        generic_cfg.display()
    );
    let lower = generic_text.to_ascii_lowercase();
    assert!(
        !lower.contains("claude") && !lower.contains("anthropic"),
        "the generic adapter must be harness-neutral, not Claude-specific: {}",
        generic_cfg.display()
    );

    let _serial = obscura_lock().lock().await;
    let rig = Rig::start().await;
    // `Rig::driver` connects over raw loopback TCP with the agent-token handshake —
    // the generic adapter's raw-client path, with no harness and no provider SDK.
    let mut driver = rig.driver().await;

    // The generic client drives the entire loop end to end.
    let (findings, ids) = driver.run().await.expect("run the full driver loop");
    assert_eq!(ids.len(), findings.len(), "one recorded id per finding");

    let classes: Vec<&str> = findings.iter().map(|f| f.class.as_str()).collect();
    for class in EXPECTED_CLASSES {
        assert!(
            classes.contains(&class),
            "the generic client did not reproduce class {class}; got {classes:?}"
        );
    }

    // The findings it recorded are reachable again over the same bus.
    let listed = driver
        .client
        .tool_call("findings.list", serde_json::json!({}))
        .await
        .expect("findings.list over MCP");
    assert_eq!(
        listed.as_array().map(Vec::len),
        Some(findings.len()),
        "findings.list did not return every finding the generic client recorded"
    );

    rig.finish().await;
}
