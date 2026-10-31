//! Task 12 — `FileAuditLog`: an append-only JSON Lines file, created
//! `0600` in a `0700` parent, one record per line.

use std::fs;
use std::path::PathBuf;

use aitm_ca::audit::{now_rfc3339, AuditLog, AuditRecord, FileAuditLog};
use aitm_ca::testing::FIXTURE_FP256;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

/// A fresh, non-existent directory under the OS temp dir (`tempfile` is not
/// an allowed dependency).
fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("aitm-ca-audit-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    dir
}

fn record(detail: &str) -> AuditRecord {
    AuditRecord {
        ts: now_rfc3339(),
        command: "ca.install",
        frontend: "cli",
        outcome: "ok",
        scope: Some("user".to_string()),
        platform: Some("macos".to_string()),
        fingerprint_sha256: Some(FIXTURE_FP256.to_string()),
        detail: detail.to_string(),
    }
}

// CA-AC28 (file half).
#[test]
fn creates_0600_and_appends_lines() {
    let dir = scratch("creates");
    let path = dir.join("nested").join("ca-audit.jsonl");
    let parent = path.parent().unwrap();
    assert!(!parent.exists());

    let log = FileAuditLog::new(path.clone());
    log.open().unwrap();
    assert!(parent.is_dir());
    assert!(path.is_file());

    log.record(&record("changed=true")).unwrap();
    let after_first = fs::read_to_string(&path).unwrap();
    log.record(&record("changed=false")).unwrap();
    let after_second = fs::read_to_string(&path).unwrap();

    // Append-only: the first line is byte-identical after the second write.
    assert!(after_second.starts_with(&after_first));
    assert!(after_second.ends_with('\n'));
    let lines: Vec<&str> = after_second.lines().collect();
    assert_eq!(lines.len(), 2);
    for line in &lines {
        let value: serde_json::Value = serde_json::from_str(line).unwrap();
        let mut keys: Vec<&str> = value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "command",
                "detail",
                "fingerprint_sha256",
                "frontend",
                "outcome",
                "platform",
                "scope",
                "ts"
            ]
        );
        let back: AuditRecord = serde_json::from_str(line).unwrap();
        assert_eq!(back.command, "ca.install");
    }
    assert!(lines[0].contains("changed=true"));
    assert!(lines[1].contains("changed=false"));

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(parent).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }

    // Re-opening an existing log never truncates it.
    log.open().unwrap();
    assert_eq!(fs::read_to_string(&path).unwrap(), after_second);

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn open_fails_when_path_is_a_directory() {
    let dir = scratch("isdir");
    fs::create_dir_all(&dir).unwrap();

    let err = FileAuditLog::new(dir.clone()).open().unwrap_err();
    let text = err.to_string();
    assert!(text.contains(&dir.display().to_string()), "got: {text}");

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn rfc3339_parses() {
    let ts = now_rfc3339();
    let parsed = OffsetDateTime::parse(&ts, &Rfc3339).unwrap();

    // UTC, seconds precision: "2026-10-27T21:03:14Z".
    assert!(ts.ends_with('Z'), "{ts}");
    assert_eq!(ts.len(), "2026-10-27T21:03:14Z".len(), "{ts}");
    assert_eq!(parsed.nanosecond(), 0);
    assert!(parsed.year() >= 2026);
}

// ------------------------------------------------- F2 subset (M4 Task 8)

use aitm_ca::audit::entry_to_jsonl;
use aitm_core::{AuditEntry, AuditResult, AuditRing, AuditSink, Frontend};
use std::time::SystemTime;

/// A core F2 audit entry for a `ca.status` invocation.
fn ca_status_entry() -> AuditEntry {
    AuditEntry {
        at: SystemTime::now(),
        origin: Frontend::Mcp,
        client_label: Some("aitm-mac".to_string()),
        connection_id: None,
        command: "ca.status".to_string(),
        args_summary: "{}".to_string(),
        result: AuditResult::Ok,
    }
}

/// AC-M4-6b / spec D3a.2: a `ca.*` invocation appears in the always-on in-memory
/// ring and, with durable audit on, in the CA plugin's JSONL — routed through the
/// core `AuditSink`, so CA entries are a subset of **one** format, not a second
/// log shape.
#[test]
fn ca_audit_is_a_subset() {
    let entry = ca_status_entry();

    // In the always-on ring.
    let ring = AuditRing::default();
    ring.append(entry.clone());
    let recent = ring.recent(None, None);
    assert_eq!(recent.len(), 1);
    assert_eq!(recent[0].command, "ca.status");

    // And in the durable JSONL, via the CA's `FileAuditLog` as a core `AuditSink`.
    let dir = scratch("subset");
    let path = dir.join("audit.jsonl");
    let log = FileAuditLog::new(path.clone());
    AuditLog::open(&log).unwrap();
    AuditSink::append(&log, entry.clone());

    let contents = fs::read_to_string(&path).unwrap();
    assert!(contents.ends_with('\n'), "append-only JSONL line");
    let line = contents.lines().next().expect("one durable line");
    let value: serde_json::Value = serde_json::from_str(line).unwrap();
    assert_eq!(value["command"], "ca.status");
    assert_eq!(value["origin"], "mcp");
    assert_eq!(value["result"], "ok");
    assert_eq!(value["client_label"], "aitm-mac");

    // The durable line is exactly the one shared format (same renderer), so the
    // ring and the JSONL agree field for field.
    let expected: serde_json::Value = serde_json::from_str(&entry_to_jsonl(&entry)).unwrap();
    assert_eq!(value, expected);
}

/// AC17: the durable line and `AuditEntry::to_value` are one shape. The key set
/// of the JSONL object equals the key set of the ring's rendering (the seven keys
/// including `connection_id`), and the id survives as a string.
#[test]
fn durable_line_has_the_same_keys_as_to_value() {
    let e = AuditEntry {
        connection_id: Some("conn_ab-1".into()),
        ..ca_status_entry()
    };

    let durable: serde_json::Value = serde_json::from_str(&entry_to_jsonl(&e)).unwrap();
    let mut durable_keys: Vec<String> = durable.as_object().unwrap().keys().cloned().collect();
    durable_keys.sort_unstable();

    let aitm_core::Value::Object(rendered) = e.to_value() else {
        panic!("to_value must render an object");
    };
    let rendered_keys: Vec<String> = rendered.keys().cloned().collect();

    assert_eq!(durable_keys, rendered_keys);
    assert_eq!(
        durable_keys,
        [
            "args",
            "at",
            "client_label",
            "command",
            "connection_id",
            "origin",
            "result"
        ]
    );
    assert_eq!(durable["connection_id"], "conn_ab-1");

    // An entry with no streaming connection renders the key as null, not absent.
    let none: serde_json::Value =
        serde_json::from_str(&entry_to_jsonl(&ca_status_entry())).unwrap();
    assert!(none.as_object().unwrap().contains_key("connection_id"));
    assert_eq!(none["connection_id"], serde_json::Value::Null);
}
