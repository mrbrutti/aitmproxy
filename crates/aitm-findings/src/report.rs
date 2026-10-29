//! Task 15 — the report renderer (spec D8).
//!
//! Two **pure** functions over the recorded findings, the deliverable the scripted
//! driver (and an agent) assemble after reproduction:
//!
//! - [`render_report`] → `report.md`: human-friendly markdown, a title/summary then
//!   one section per finding carrying exactly the D8 field set.
//! - [`render_index`] → `findings.index.json`: the machine-readable list the grader
//!   consumes, so discovery is scored from recorded `passed`/`control_passed` rather
//!   than the agent self-asserting against the hidden manifest.
//!
//! No tool-generated prose beyond this structure: every value rendered comes
//! straight off a [`FindingRecord`] field. The report is a *rendering* of the
//! persistent findings store (D8a), not a separate source of truth.

use serde_json::{json, Value};

use crate::record::FindingRecord;

/// Render the human-friendly markdown report (`report.md`, spec D8): a title and a
/// one-line summary, then one `##` section per finding with `{title, severity,
/// class/CWE, affected endpoint, reproduction steps, PoC path, screenshot link,
/// finding-capture id}`.
pub fn render_report(findings: &[FindingRecord]) -> String {
    let mut out = String::new();
    out.push_str("# aitmproxy findings report\n\n");
    out.push_str(&summary_line(findings));
    out.push('\n');

    for f in findings {
        out.push_str("\n## ");
        out.push_str(&f.title);
        out.push_str("\n\n");

        out.push_str(&format!("- **Severity:** {}\n", severity_str(f)));
        out.push_str(&format!("- **Class / CWE:** {}\n", f.class));
        out.push_str(&format!("- **Affected endpoint:** {}\n", f.target));
        out.push_str(&format!("- **Reproduction:** {}\n", reproduction_steps(f)));
        out.push_str(&format!("- **PoC:** `{}`\n", f.artifacts.poc_path));
        out.push_str(&format!(
            "- **Screenshot:** [{0}]({0})\n",
            f.artifacts.screenshot_path
        ));
        out.push_str(&format!(
            "- **Finding capture:** `{}`\n",
            f.artifacts.finding_capture
        ));

        if let Some(notes) = &f.notes {
            out.push_str(&format!("\n{notes}\n"));
        }
    }

    out
}

/// Render the machine-readable index (`findings.index.json`, spec D8): a JSON array
/// of `{poc_path, target_path, class, passed, control_passed, finding_capture,
/// screenshot_path}`, in the order the findings are given.
pub fn render_index(findings: &[FindingRecord]) -> Value {
    Value::Array(
        findings
            .iter()
            .map(|f| {
                json!({
                    "poc_path": f.artifacts.poc_path,
                    "target_path": f.target,
                    "class": f.class,
                    "passed": f.reproduction.passed,
                    "control_passed": f.reproduction.control_passed,
                    "finding_capture": f.artifacts.finding_capture.to_string(),
                    "screenshot_path": f.artifacts.screenshot_path,
                })
            })
            .collect(),
    )
}

/// The one-line summary: how many findings, and how many were reproduced
/// (passed on the vulnerable path, control failed).
fn summary_line(findings: &[FindingRecord]) -> String {
    let reproduced = findings
        .iter()
        .filter(|f| f.reproduction.passed && f.reproduction.control_passed == Some(false))
        .count();
    let n = findings.len();
    let plural = if n == 1 { "finding" } else { "findings" };
    format!("{n} {plural}, {reproduced} reproduced against a patched control.\n")
}

/// The nuclei-vocabulary severity word (`info|low|medium|high|critical`), reusing
/// the `aitm-poc` serde form so the report matches the record on disk.
fn severity_str(f: &FindingRecord) -> String {
    serde_json::to_value(f.severity)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_else(|| "unknown".to_string())
}

/// The reproduction steps, derived from the recorded `poc.run` outcome: which PoC
/// reproduces it and what the vulnerable/control runs showed.
fn reproduction_steps(f: &FindingRecord) -> String {
    let vuln = if f.reproduction.passed {
        "passed against the vulnerable target"
    } else {
        "did not pass against the vulnerable target"
    };
    let control = match f.reproduction.control_passed {
        Some(false) => "; the patched control failed as expected",
        Some(true) => "; the patched control also passed (no control gap)",
        None => "; no patched control was run",
    };
    format!("run PoC `{}` (`poc.run`): {vuln}{control}", f.poc_ref)
}
