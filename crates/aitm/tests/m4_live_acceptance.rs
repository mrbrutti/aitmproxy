//! M4 follow-on — the live-acceptance harness, end to end (AC-M4-17 backbone).
//!
//! AC-M4-17 is the operator-run demo where a *live* model drives the whole
//! find → reproduce → report loop against a real, externally-running seeded target.
//! This suite is its deterministic backbone: it stands the exact same harness the
//! live run uses — the target as a **real external process** (the
//! `aitm-testtarget-serve` binary), the `aitm` proxy/bus, and an **out-of-process**
//! MCP client over loopback TCP — but drives it with the non-LLM
//! [`ScriptedDriver`](crate::scripted_driver) instead of a model. A green run proves
//! the harness itself works end to end; the live model later swaps in for the
//! scripted driver with no other change.
//!
//! The difference from the Task 17/18 suites is only *where the target runs*: those
//! serve it in-process, this spawns it as a separate OS process and points the same
//! shared [`rig`] at its base URLs via [`Rig::start_against`]. The driver, bus, and
//! grader are reused unchanged.
//!
//! Gated in addition to the browser gate: it needs a real browser (`AITM_OBSCURA`)
//! **and** opts into spawning external processes (`AITM_LIVE`). With either unset it
//! returns early, so the default `cargo test` stays hermetic. Run for real with:
//!
//! ```text
//! AITM_OBSCURA=1 AITM_OBSCURA_BIN=/path/to/obscura AITM_LIVE=1 \
//!   cargo test -p aitm --test m4_live_acceptance -- --nocapture
//! ```

#[path = "../../aitm-browser/tests/support/engines.rs"]
#[allow(dead_code)] // only `config_for` is used here; `engines` serves other suites
mod engines;
#[path = "support/rig.rs"]
#[allow(dead_code)] // this suite uses a subset of the shared rig's surface
mod rig;
#[path = "support/scripted_driver.rs"]
#[allow(dead_code)] // the driver's per-class probe helpers are reached via `run`
mod scripted_driver;

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use aitm_findings::{DiskFindingStore, FindingStore};
use aitm_testtarget::grade;

use rig::{live_enabled, obscura_enabled, obscura_lock, Rig, EXPECTED_CLASSES};

/// The workspace root: `CARGO_MANIFEST_DIR` is `<root>/crates/aitm`.
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("workspace root is two levels above crates/aitm")
        .to_path_buf()
}

/// The seed mode an external serve process is started in.
#[derive(Clone, Copy)]
enum Mode {
    Vulnerable,
    Patched,
}

impl Mode {
    fn arg(self) -> &'static str {
        match self {
            Mode::Vulnerable => "vulnerable",
            Mode::Patched => "patched",
        }
    }
}

/// An external `aitm-testtarget-serve` process plus the base URL it reported,
/// killed on drop so a panicking test never leaks a server.
struct ServeProcess {
    child: Child,
    base_url: String,
}

impl Drop for ServeProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Build the serve binary once (via cargo, same toolchain) and return its path,
/// read out of cargo's JSON artifact stream so the profile is always right.
fn build_serve_bin() -> PathBuf {
    let output = Command::new(env!("CARGO"))
        .current_dir(repo_root())
        .args([
            "build",
            "--message-format=json",
            "-p",
            "aitm-testtarget",
            "--bin",
            "aitm-testtarget-serve",
        ])
        .output()
        .expect("run cargo build for the serve bin");
    assert!(
        output.status.success(),
        "cargo build for aitm-testtarget-serve failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    for line in output.stdout.split(|&b| b == b'\n') {
        if line.is_empty() {
            continue;
        }
        let msg: serde_json::Value = match serde_json::from_slice(line) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let is_serve = msg.get("reason").and_then(|r| r.as_str()) == Some("compiler-artifact")
            && msg
                .get("target")
                .and_then(|t| t.get("name"))
                .and_then(|n| n.as_str())
                == Some("aitm-testtarget-serve");
        if is_serve {
            if let Some(exe) = msg.get("executable").and_then(|e| e.as_str()) {
                return PathBuf::from(exe);
            }
        }
    }
    panic!("cargo build did not report the aitm-testtarget-serve executable path");
}

/// Spawn the serve binary as an external process on an ephemeral loopback port and
/// return once it has printed its `listening <base_url>` line.
fn spawn_serve(bin: &Path, mode: Mode) -> ServeProcess {
    let mut child = Command::new(bin)
        .args(["--mode", mode.arg(), "--port", "0"])
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn aitm-testtarget-serve");
    let stdout = child.stdout.take().expect("serve bin stdout");
    let mut line = String::new();
    BufReader::new(stdout)
        .read_line(&mut line)
        .expect("read the serve bin listening line");
    let base_url = line
        .trim()
        .strip_prefix("listening ")
        .unwrap_or_else(|| panic!("unexpected first line from serve bin: {line:?}"))
        .to_string();
    assert!(
        base_url.starts_with("http://127.0.0.1:"),
        "serve bin must bind loopback only, got {base_url:?}"
    );
    ServeProcess { child, base_url }
}

// ---- AC-M4-17 backbone ------------------------------------------------------

/// The full live-acceptance harness: the seeded target runs as two **external
/// processes** (vulnerable + patched control), the `aitm` bus stands over them, and
/// the out-of-process scripted driver runs the whole find → reproduce → record loop
/// across the real loopback-TCP command surface. The grader then confirms every
/// planted vuln was reproduced with zero false positives — the deterministic
/// pass/fail gate the live model inherits.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn live_acceptance_harness_reproduces_all_zero_false_positives() {
    if !obscura_enabled() || !live_enabled() {
        return;
    }
    let _serial = obscura_lock().lock().await;

    // The target runs as real external processes, exactly as the live operator run
    // starts it — not the in-process `TestTarget` the Task 17/18 suites use.
    let bin = build_serve_bin();
    let vuln = spawn_serve(&bin, Mode::Vulnerable);
    let patched = spawn_serve(&bin, Mode::Patched);

    let rig = Rig::start_against(vuln.base_url.clone(), patched.base_url.clone()).await;
    let mut driver = rig.driver().await;

    // Drive the whole non-LLM loop over the bus: discover → reproduce → record.
    let (findings, ids) = driver
        .run()
        .await
        .expect("run the full driver loop against the external target");
    assert_eq!(ids.len(), findings.len(), "one recorded id per finding");

    // Score the recorded findings against the hidden manifest.
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

    // A one-line summary of the live-acceptance result (visible under --nocapture).
    let classes: Vec<&str> = findings.iter().map(|f| f.class.as_str()).collect();
    eprintln!(
        "AC-M4-17 live-acceptance: planted={} reproduced={} false_positives={} classes={:?}",
        report.planted, report.reproduced, report.false_positives, classes
    );

    assert_eq!(
        report.reproduced, report.planted,
        "live-acceptance gate: reproduced {} of {} planted vulns (missing {:?})",
        report.reproduced, report.planted, report.missing
    );
    assert_eq!(
        report.false_positives, 0,
        "live-acceptance gate: {} false-positive finding(s): {:?}",
        report.false_positives, report.spurious
    );
    assert_eq!(
        report.planted,
        EXPECTED_CLASSES.len(),
        "the seeded target must plant all {} vuln classes",
        EXPECTED_CLASSES.len()
    );

    rig.finish().await;
    // `vuln`/`patched` drop here, killing the external serve processes.
}
