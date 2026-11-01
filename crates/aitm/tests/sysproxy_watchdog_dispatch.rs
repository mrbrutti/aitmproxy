//! Tester (stage 5), fix F3 of plan 2026-10-31-system-proxy-automation:
//! `main` dispatches the hidden `sysproxy-watchdog` subcommand before the
//! Tokio runtime, on the mode `parse_invocation` classified after the
//! global flags were split off. This runs the REAL binary to pin that a
//! leading `--config` (a spelling the spawner never emits; a hand launch
//! may) still reaches the watchdog and never the server path.
//!
//! The watchdog's contract (spec §D9 (b), plan C8): wait for stdin EOF,
//! load the state file, write one C8 line to `system-proxy-watchdog.log`
//! beside it, print nothing, exit 0 (`file-gone` when there is no file),
//! 2 on bad arguments. The server path would instead read the config,
//! bind ports and print; with a config path that does not exist it fails
//! loudly and non-zero. No port is bound here, so this runs in the sandbox.
//!
//! Spec: docs/superpowers/specs/2026-10-31-system-proxy-automation-design.md
//! Plan: docs/superpowers/plans/2026-10-31-system-proxy-automation-plan.md (Tasks 7, 10; F3)

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use aitm_sysproxy::{STATE_FILE_NAME, WATCHDOG_LOG_NAME};

fn temp_dir(tag: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let dir = std::env::temp_dir().join(format!("aitm-watchdog-dispatch-{tag}-{nanos}"));
    fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn pump(mut reader: impl Read + Send + 'static) -> JoinHandle<String> {
    thread::spawn(move || {
        let mut out = String::new();
        let _ = reader.read_to_string(&mut out);
        out
    })
}

/// Wait at most `timeout` for the child; a child still running then is
/// killed and the test fails with what it printed so far.
fn wait_bounded(child: &mut Child, timeout: Duration) -> Option<ExitStatus> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait().expect("try_wait") {
            return Some(status);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return None;
        }
        thread::sleep(Duration::from_millis(25));
    }
}

/// Run `aitm <args>` with a piped stdin that is closed at once (the core
/// "dies"), no inherited `AITM_CONFIG`/`RUST_LOG`. Returns the exit status
/// (None: did not exit within 30 s), stdout and stderr.
fn run_aitm(args: &[&str]) -> (Option<ExitStatus>, String, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_aitm"))
        .args(args)
        .env_remove("AITM_CONFIG")
        .env_remove("RUST_LOG")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn aitm");
    let stdout = pump(child.stdout.take().expect("piped stdout"));
    let stderr = pump(child.stderr.take().expect("piped stderr"));
    drop(child.stdin.take());
    let status = wait_bounded(&mut child, Duration::from_secs(30));
    let out = stdout.join().expect("stdout pump");
    let err = stderr.join().expect("stderr pump");
    (status, out, err)
}

fn log_lines(state: &Path) -> Vec<String> {
    let log = state.with_file_name(WATCHDOG_LOG_NAME);
    fs::read_to_string(&log)
        .unwrap_or_else(|e| panic!("read {}: {e}", log.display()))
        .lines()
        .map(str::to_string)
        .collect()
}

fn assert_c8_file_gone(line: &str) {
    let parts: Vec<&str> = line.split(' ').collect();
    assert_eq!(
        parts.len(),
        4,
        "<rfc3339> <decision> services=<n> ms=<n>: {line:?}"
    );
    assert!(
        parts[0].starts_with("20") && parts[0].contains('T'),
        "an RFC 3339 stamp: {line:?}"
    );
    assert_eq!(parts[1], "file-gone", "{line:?}");
    assert_eq!(parts[2], "services=0", "{line:?}");
    assert!(
        parts[3]
            .strip_prefix("ms=")
            .is_some_and(|n| n.parse::<u64>().is_ok()),
        "{line:?}"
    );
}

/// The watchdog behind `--config <p>`, `--config=<p>` and bare: every
/// spelling waits for EOF, finds no file, leaves exactly one C8 `file-gone`
/// line beside where the file would be (creating that directory), prints
/// nothing, exits 0, and never reads or creates the config path.
#[test]
fn watchdog_is_dispatched_regardless_of_a_leading_config_flag() {
    let dir = temp_dir("config-flag");
    let config = dir.join("does-not-exist").join("aitm.yaml");
    let config_s = config.to_string_lossy().into_owned();
    let config_eq = format!("--config={config_s}");
    for (tag, prefix) in [
        ("space", vec!["--config", config_s.as_str()]),
        ("equals", vec![config_eq.as_str()]),
        ("bare", vec![]),
    ] {
        let state = dir.join(tag).join(STATE_FILE_NAME);
        let state_s = state.to_string_lossy().into_owned();
        let mut argv = prefix.clone();
        argv.extend([
            "sysproxy-watchdog",
            "--pid",
            "1",
            "--state",
            state_s.as_str(),
        ]);

        let (status, out, err) = run_aitm(&argv);
        let status = status.unwrap_or_else(|| {
            panic!("{tag}: the process did not exit on stdin EOF; stdout={out:?} stderr={err:?}")
        });
        assert_eq!(
            status.code(),
            Some(0),
            "{tag}: stdout={out:?} stderr={err:?}"
        );
        assert_eq!(out, "", "{tag}: the watchdog never prints");
        assert_eq!(err, "", "{tag}: the watchdog never prints");
        assert!(!state.exists(), "{tag}: no state file was created");
        assert!(
            !config.exists() && !config.parent().unwrap().exists(),
            "{tag}: the config path was never touched"
        );
        let lines = log_lines(&state);
        assert_eq!(lines.len(), 1, "{tag}: {lines:?}");
        assert_c8_file_gone(&lines[0]);
    }
    fs::remove_dir_all(&dir).expect("remove temp dir");
}

/// Bad watchdog arguments behind a leading `--config` are the watchdog's
/// usage error (exit 2, the hidden usage line on stderr), not the server's
/// config error: the hidden subcommand owns its argv even then.
#[test]
fn watchdog_usage_error_behind_a_config_flag_is_exit_2_with_its_own_usage_line() {
    let dir = temp_dir("usage");
    let config = dir.join("does-not-exist").join("aitm.yaml");
    let config_s = config.to_string_lossy().into_owned();
    for argv in [
        vec![
            "--config",
            config_s.as_str(),
            "sysproxy-watchdog",
            "--pid",
            "1",
        ],
        vec![
            "--config",
            config_s.as_str(),
            "sysproxy-watchdog",
            "--pid",
            "1",
            "--state",
        ],
        vec![
            "--config",
            config_s.as_str(),
            "sysproxy-watchdog",
            "--pid",
            "nope",
            "--state",
            "/x",
        ],
    ] {
        let (status, out, err) = run_aitm(&argv);
        let status = status.unwrap_or_else(|| panic!("{argv:?}: did not exit; stderr={err:?}"));
        assert_eq!(
            status.code(),
            Some(2),
            "{argv:?}: stdout={out:?} stderr={err:?}"
        );
        assert_eq!(out, "", "{argv:?}");
        assert!(
            err.contains("usage: aitm sysproxy-watchdog --pid <pid> --state <file> [--no-pipe]"),
            "{argv:?}: {err:?}"
        );
        assert!(
            !err.contains("aitm.yaml") && !err.contains("No such file"),
            "{argv:?}: the server's config error leaked in: {err:?}"
        );
        assert!(
            !config.parent().unwrap().exists(),
            "{argv:?}: config untouched"
        );
    }
    fs::remove_dir_all(&dir).expect("remove temp dir");
}
