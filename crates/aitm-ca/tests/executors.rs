//! Task 11 — the `Executor` implementations: `RealExecutor` (bounded
//! subprocesses), `DryRunExecutor` (mutations recorded, not run), and the
//! test doubles `ScriptedExecutor` / `MemoryAuditLog`.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use aitm_ca::audit::{AuditLog, AuditRecord};
use aitm_ca::exec::{CmdLine, CmdOutput, DryRunExecutor, Executor, RealExecutor};
use aitm_ca::testing::{MemoryAuditLog, ScriptedExecutor, FIXTURE_FP256};

fn line(program: &str, args: &[&str], stdin: Option<&[u8]>, mutating: bool) -> CmdLine {
    CmdLine {
        program: program.to_string(),
        args: args.iter().map(|a| a.to_string()).collect(),
        stdin: stdin.map(<[u8]>::to_vec),
        mutating,
    }
}

// CA-AC26: every subprocess is bounded by a wall-clock timeout that depends
// on whether it mutates.
#[cfg(unix)]
#[test]
fn real_executor_times_out() {
    let exec = RealExecutor::with_timeouts(Duration::from_secs(15), Duration::from_millis(200));
    let cmd = line("sleep", &["5"], None, true);

    let start = Instant::now();
    let err = exec.run(&cmd).unwrap_err();
    let elapsed = start.elapsed();

    assert!(elapsed < Duration::from_secs(2), "took {elapsed:?}");
    let text = err.to_string();
    assert!(text.contains("timed out"), "got: {text}");
    assert!(text.contains("sleep 5"), "got: {text}");
}

#[cfg(unix)]
#[test]
fn real_executor_captures_output() {
    let exec = RealExecutor::new();
    let cmd = line("sh", &["-c", "echo out; echo err >&2; exit 3"], None, false);

    let out = exec.run(&cmd).unwrap();

    assert_eq!(out.code, Some(3));
    assert_eq!(out.stdout, "out\n");
    assert_eq!(out.stderr, "err\n");
    assert!(!out.success());
}

#[cfg(unix)]
#[test]
fn real_executor_pipes_stdin_and_reads_files() {
    let exec = RealExecutor::new();

    let cat = line("cat", &[], Some(b"from stdin"), false);
    assert_eq!(exec.run(&cat).unwrap().stdout, "from stdin");

    // A program that cannot be started is an `Err`, not a non-zero exit.
    let missing = line("/nonexistent/aitm-no-such-tool", &[], None, false);
    assert!(exec.run(&missing).is_err());

    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/ca.crt");
    let bytes = exec.read_file(&fixture).unwrap().expect("fixture exists");
    assert_eq!(bytes, include_bytes!("fixtures/ca.crt"));
    assert_eq!(
        exec.read_file(&fixture.with_file_name("ca.key")).unwrap(),
        None
    );
    assert!(exec.dir_exists(fixture.parent().unwrap()));
    assert!(!exec.dir_exists(&fixture));
}

// CA-AC21 (mechanics): a dry run passes queries and reads through and
// records what it would have run.
#[test]
fn dry_run_records_mutating_only() {
    let inner = ScriptedExecutor::new()
        .respond("security find-certificate -a", 0, "found", "")
        .file("/ca/ca.crt", b"pem");
    let dry = DryRunExecutor::new(&inner);

    let query = line("security", &["find-certificate", "-a"], None, false);
    let mutate = line("security", &["add-trusted-cert", "/ca/ca.crt"], None, true);

    let q = dry.run(&query).unwrap();
    assert_eq!(q.stdout, "found");

    let m = dry.run(&mutate).unwrap();
    assert_eq!(
        m,
        CmdOutput {
            code: Some(0),
            stdout: String::new(),
            stderr: String::new()
        }
    );

    assert_eq!(inner.runs(), vec![query.render()]);
    assert_eq!(dry.recorded(), vec![mutate.render()]);

    // Reads and host facts pass straight through.
    assert_eq!(
        dry.read_file(Path::new("/ca/ca.crt")).unwrap(),
        Some(b"pem".to_vec())
    );
    assert_eq!(inner.reads(), vec![PathBuf::from("/ca/ca.crt")]);
    assert_eq!(dry.home_dir(), Some(PathBuf::from("/Users/t")));
    assert!(!dry.is_root());
}

#[test]
fn scripted_records_runs_reads_and_stdin() {
    let anchor = "/usr/local/share/ca-certificates/aitmproxy-root-ca.crt";
    let exec = ScriptedExecutor::new()
        .file("/ca/ca.crt", b"cert bytes")
        .dir("/usr/local/share/ca-certificates")
        .respond(&format!("tee {anchor}"), 0, "pem", "");

    let tee = line("tee", &[anchor], Some(b"pem"), true);
    let out = exec.run(&tee).unwrap();
    assert_eq!(out.code, Some(0));
    assert_eq!(out.stdout, "pem");

    // An unlisted command gets the default response: exit 0, nothing printed.
    let id = line("id", &["-u"], None, false);
    assert_eq!(
        exec.run(&id).unwrap(),
        CmdOutput {
            code: Some(0),
            stdout: String::new(),
            stderr: String::new()
        }
    );

    assert_eq!(exec.runs(), vec![tee.render(), id.render()]);
    assert_eq!(exec.stdins(), vec![Some(b"pem".to_vec()), None]);

    assert_eq!(
        exec.read_file(Path::new("/ca/ca.crt")).unwrap(),
        Some(b"cert bytes".to_vec())
    );
    assert_eq!(exec.read_file(Path::new("/ca/ca.key")).unwrap(), None);
    assert_eq!(
        exec.reads(),
        vec![PathBuf::from("/ca/ca.crt"), PathBuf::from("/ca/ca.key")]
    );

    assert!(exec.dir_exists(Path::new("/usr/local/share/ca-certificates")));
    assert!(!exec.dir_exists(Path::new("/etc/pki/ca-trust/source/anchors")));
    assert_eq!(exec.home_dir(), Some(PathBuf::from("/Users/t")));
    assert!(!exec.is_root());
    assert!(ScriptedExecutor::new().root(true).is_root());
}

#[test]
fn scripted_with_real_fs_reads_disk_but_keeps_runs_scripted() {
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/ca.crt");
    let exec = ScriptedExecutor::new()
        .file("/ca/ca.crt", b"ignored once real")
        .with_real_fs();

    assert_eq!(
        exec.read_file(&fixture).unwrap(),
        Some(include_bytes!("fixtures/ca.crt").to_vec())
    );
    assert_eq!(exec.read_file(Path::new("/ca/ca.crt")).unwrap(), None);
    assert_eq!(
        exec.reads(),
        vec![fixture.clone(), PathBuf::from("/ca/ca.crt")]
    );
    assert!(exec.dir_exists(fixture.parent().unwrap()));

    // `run` never reaches the host.
    let rm = line("rm", &["-rf", "/"], None, true);
    assert_eq!(exec.run(&rm).unwrap().code, Some(0));
    assert_eq!(exec.runs(), vec![rm.render()]);
}

#[test]
fn memory_audit_failing_open() {
    let failing = MemoryAuditLog::failing();
    assert!(failing.open().is_err());

    let log = MemoryAuditLog::new();
    log.open().unwrap();
    assert!(log.records().is_empty());

    let rec = AuditRecord {
        ts: "2026-10-27T21:03:14Z".to_string(),
        command: "ca.install",
        frontend: "cli",
        outcome: "ok",
        scope: Some("user".to_string()),
        platform: Some("macos".to_string()),
        fingerprint_sha256: Some(FIXTURE_FP256.to_string()),
        detail: "changed=true".to_string(),
    };
    log.record(&rec).unwrap();
    log.record(&rec).unwrap();
    assert_eq!(log.records(), vec![rec.clone(), rec]);
    assert!(failing.records().is_empty());
}
