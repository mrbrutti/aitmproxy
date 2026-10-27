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
