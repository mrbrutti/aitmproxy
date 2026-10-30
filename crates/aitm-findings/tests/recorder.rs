//! Task 3 (dvwa-tool-fixes): `DiskFindingRecorder` implements the core
//! `FindingRecorder` seam and round-trips a draft through `DiskFindingStore`.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::SystemTime;

use aitm_core::{FindingDraft, FindingRecorder, FlowId, Frontend};
use aitm_findings::{DiskFindingRecorder, DiskFindingStore, FindingStore};
use aitm_poc::Severity;

fn unique_dir(tag: &str) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "aitm-recorder-{tag}-{}-{nanos}-{n}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn disk_recorder_round_trips() {
    let dir = unique_dir("rt");
    let capture = FlowId::new();
    let extra = FlowId::new();
    let draft = FindingDraft {
        title: "SQLi".into(),
        class: "sql-injection".into(),
        severity: "critical".into(),
        target: "http://localhost:4280/vulnerabilities/sqli/".into(),
        poc_ref: "dvwa-sqli-id".into(),
        passed: true,
        finding_capture: capture,
        flows: vec![capture, extra],
        poc_path: "/poc/dvwa-sqli-id.yaml".into(),
        screenshot_path: "/out/sqli.png".into(),
        origin: Frontend::Operator,
        client_label: Some("aitm-mac".into()),
    };

    let id = DiskFindingRecorder
        .record(&draft, &dir)
        .expect("record succeeds");
    assert!(!id.is_empty());

    let rec = DiskFindingStore::new(dir.clone())
        .get(&id)
        .expect("recorded finding is readable");
    assert_eq!(rec.id, id);
    assert_eq!(rec.title, "SQLi");
    assert_eq!(rec.class, "sql-injection");
    assert_eq!(rec.severity, Severity::Critical);
    assert_eq!(rec.target, "http://localhost:4280/vulnerabilities/sqli/");
    assert_eq!(rec.poc_ref, "dvwa-sqli-id");
    assert_eq!(rec.origin, Frontend::Operator);
    assert_eq!(rec.client_label.as_deref(), Some("aitm-mac"));
    assert!(rec.reproduction.passed);
    assert_eq!(rec.reproduction.control_passed, None);
    assert_eq!(rec.artifacts.finding_capture, capture);
    assert_eq!(rec.artifacts.poc_path, "/poc/dvwa-sqli-id.yaml");
    assert_eq!(rec.artifacts.screenshot_path, "/out/sqli.png");
    assert_eq!(rec.flows, vec![capture, extra]);
    assert_eq!(rec.notes, None);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn disk_recorder_rejects_unknown_severity() {
    let dir = unique_dir("sev");
    let draft = FindingDraft {
        title: "x".into(),
        class: "c".into(),
        severity: "catastrophic".into(),
        target: "t".into(),
        poc_ref: "p".into(),
        passed: true,
        finding_capture: FlowId::new(),
        flows: vec![],
        poc_path: String::new(),
        screenshot_path: String::new(),
        origin: Frontend::Mcp,
        client_label: None,
    };
    let err = DiskFindingRecorder
        .record(&draft, &dir)
        .expect_err("unknown severity is an error");
    assert!(
        err.to_string().contains("unknown severity `catastrophic`"),
        "got: {err}"
    );
    // Nothing was written.
    let yamls = std::fs::read_dir(&dir)
        .unwrap()
        .flatten()
        .filter(|e| e.path().extension().is_some_and(|x| x == "yaml"))
        .count();
    assert_eq!(yamls, 0);
    let _ = std::fs::remove_dir_all(&dir);
}
