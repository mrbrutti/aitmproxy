//! Task 9 skeleton tests: `CmdLine::render`, `CmdOutput::success`,
//! `AuditRecord` JSON shape, and the checked-in fixture CA.

use aitm_ca::audit::AuditRecord;
use aitm_ca::exec::{CmdLine, CmdOutput};

const FIXTURE: &str = include_str!("fixtures/ca.crt");

fn line(program: &str, args: &[&str]) -> CmdLine {
    CmdLine {
        program: program.to_string(),
        args: args.iter().map(|a| a.to_string()).collect(),
        stdin: None,
        mutating: false,
    }
}

#[test]
fn render_joins_with_single_spaces() {
    let cmd = line("security", &["find-certificate", "-a", "-Z", "/k"]);
    assert_eq!(cmd.render(), "security find-certificate -a -Z /k");
}

#[test]
fn render_quotes_whitespace() {
    let path = "/Users/t/Library/Application Support/x/ca.crt";
    let mut cmd = line("security", &["add-trusted-cert", path]);
    cmd.stdin = Some(b"STDIN-MUST-NOT-RENDER".to_vec());
    cmd.mutating = true;

    assert_eq!(
        cmd.render(),
        "security add-trusted-cert '/Users/t/Library/Application Support/x/ca.crt'"
    );
    assert!(!cmd.render().contains("STDIN-MUST-NOT-RENDER"));
    // The argument itself is stored unquoted; quoting is a rendering concern.
    assert_eq!(cmd.args[1], path);
}

#[test]
fn success_is_code_zero() {
    let out = |code: Option<i32>| CmdOutput {
        code,
        stdout: String::new(),
        stderr: String::new(),
    };
    assert!(out(Some(0)).success());
    assert!(!out(Some(1)).success());
    assert!(!out(None).success());
}

#[test]
fn audit_record_roundtrips_json() {
    let rec = AuditRecord {
        ts: "2026-10-27T21:03:14Z".to_string(),
        command: "ca.install",
        frontend: "cli",
        outcome: "ok",
        scope: Some("user".to_string()),
        platform: Some("macos".to_string()),
        fingerprint_sha256: None,
        detail: "changed=true".to_string(),
    };

    let json = serde_json::to_string(&rec).unwrap();
    let back: AuditRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(back, rec);

    let value: serde_json::Value = serde_json::from_str(&json).unwrap();
    let mut keys: Vec<&str> = value
        .as_object()
        .expect("record serializes to a JSON object")
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    let mut expected = vec![
        "ts",
        "command",
        "frontend",
        "outcome",
        "scope",
        "platform",
        "fingerprint_sha256",
        "detail",
    ];
    expected.sort_unstable();
    assert_eq!(keys, expected);
    assert_eq!(value["fingerprint_sha256"], serde_json::Value::Null);
}

#[test]
fn fixture_is_one_certificate() {
    assert_eq!(FIXTURE.matches("-----BEGIN CERTIFICATE-----").count(), 1);
    assert_eq!(FIXTURE.matches("-----END CERTIFICATE-----").count(), 1);
    assert!(!FIXTURE.contains("PRIVATE KEY"));
}
