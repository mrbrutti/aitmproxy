//! Task 15: the pure report + index renderers over `FindingRecord`.

use std::time::{Duration, SystemTime};

use aitm_core::{FlowId, Frontend};
use aitm_findings::{render_index, render_report, FindingArtifacts, FindingRecord, Reproduction};
use aitm_poc::Severity;

fn at(secs: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
}

/// A finding whose every rendered field has a distinctive, searchable value.
fn finding(tag: &str, class: &str, control_passed: Option<bool>) -> FindingRecord {
    FindingRecord {
        id: format!("{class}-{tag}"),
        title: format!("{class} on /{tag}"),
        class: class.into(),
        severity: Severity::High,
        target: format!("http://localhost:9000/{tag}"),
        discovered_at: at(1_700_000_000),
        origin: Frontend::Mcp,
        client_label: Some("aitm-mac".into()),
        poc_ref: format!("{class}-{tag}"),
        reproduction: Reproduction {
            passed: true,
            control_passed,
            run_at: at(1_700_000_001),
        },
        artifacts: FindingArtifacts {
            finding_capture: FlowId::new(),
            poc_path: format!("/poc/{class}-{tag}.yaml"),
            screenshot_path: format!("/out/{tag}.png"),
        },
        flows: vec![FlowId::new()],
        notes: None,
    }
}

#[test]
fn report_has_one_section_per_finding() {
    let findings = vec![
        finding("search", "reflected-xss", Some(false)),
        finding("account", "idor", Some(false)),
        finding("fetch", "ssrf", Some(false)),
    ];

    let md = render_report(&findings);

    // One `## ` section per finding, and a single `# ` title above them.
    let sections = md.lines().filter(|l| l.starts_with("## ")).count();
    assert_eq!(sections, findings.len(), "one section per finding:\n{md}");
    assert_eq!(
        md.lines().filter(|l| l.starts_with("# ")).count(),
        1,
        "exactly one report title:\n{md}"
    );

    // Every finding's required fields appear in the report.
    for f in &findings {
        assert!(md.contains(&f.title), "title missing: {}\n{md}", f.title);
        assert!(
            md.contains(&f.target),
            "endpoint missing: {}\n{md}",
            f.target
        );
        assert!(
            md.contains(&f.artifacts.poc_path),
            "PoC path missing: {}\n{md}",
            f.artifacts.poc_path
        );
        assert!(
            md.contains(&f.artifacts.screenshot_path),
            "screenshot missing: {}\n{md}",
            f.artifacts.screenshot_path
        );
        assert!(
            md.contains(&f.artifacts.finding_capture.to_string()),
            "finding-capture id missing: {}\n{md}",
            f.artifacts.finding_capture
        );
        assert!(md.contains(&f.class), "class missing: {}\n{md}", f.class);
    }
    // Severity is rendered.
    assert!(
        md.to_lowercase().contains("high"),
        "severity missing:\n{md}"
    );
}

#[test]
fn index_matches_findings() {
    let findings = vec![
        finding("search", "reflected-xss", Some(false)),
        finding("redirect", "open-redirect", None),
    ];

    let index = render_index(&findings);
    let items = index.as_array().expect("index is a JSON array");
    assert_eq!(items.len(), findings.len());

    for (item, f) in items.iter().zip(&findings) {
        assert_eq!(item["poc_path"], f.artifacts.poc_path);
        assert_eq!(item["target_path"], f.target);
        assert_eq!(item["class"], f.class);
        assert_eq!(item["passed"], f.reproduction.passed);
        match f.reproduction.control_passed {
            Some(b) => assert_eq!(item["control_passed"], b),
            None => assert!(
                item["control_passed"].is_null(),
                "control_passed should be null: {item}"
            ),
        }
        assert_eq!(
            item["finding_capture"],
            f.artifacts.finding_capture.to_string()
        );
        assert_eq!(item["screenshot_path"], f.artifacts.screenshot_path);
    }
}
