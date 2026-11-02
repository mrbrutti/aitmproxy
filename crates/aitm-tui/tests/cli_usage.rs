//! Tester (stage 5), spec 2026-10-31-remove-fake-data-ui-modes AC6, the
//! static half, proved on the built `aitm-tui` binary rather than on
//! `parse()` alone: the removed `--fixture` / `--snapshot` flags are unknown
//! arguments: stderr begins `unknown argument `<flag>`` followed by the
//! usage, exit status 2, nothing on stdout, no file written; with no `--bus`
//! and no `AITM_BUS` the usage is printed and the status is 2; and the kept
//! live arms of the transport match are still reached after the fixture arm
//! was removed. Every run here ends before a transport is chosen, or at the
//! token / loopback check that precedes a connect: nothing touches the
//! network, so this runs in the sandbox.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const BIN: &str = env!("CARGO_BIN_EXE_aitm-tui");

/// The first line of the usage `main.rs` prints.
const USAGE_HEAD: &str =
    "usage: aitm-tui --bus host:port (--token-file p | --token t (insecure: visible in ps))";

/// Run the binary with `args` in `cwd`, the bus environment cleared and
/// then `env` applied on top.
fn run_in(cwd: &Path, args: &[&str], env: &[(&str, &str)]) -> Output {
    let mut cmd = Command::new(BIN);
    cmd.args(args)
        .current_dir(cwd)
        .env_remove("AITM_BUS")
        .env_remove("AITM_BUS_TOKEN");
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.output().expect("aitm-tui runs")
}

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("aitm-tui-cli-usage-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn files_in(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

/// The usage must not advertise what it refuses: no line after the error
/// names a removed flag.
fn assert_usage_is_clean(stderr: &str) {
    for line in stderr.lines() {
        if line.starts_with("unknown argument") {
            continue;
        }
        for gone in ["--fixture", "--snapshot", "--cols", "--rows"] {
            assert!(!line.contains(gone), "the usage still names {gone}: {line}");
        }
    }
}

#[test]
fn the_removed_flags_are_unknown_arguments_with_the_usage_on_stderr_and_exit_2() {
    let dir = temp_dir("flags");
    for (args, flag) in [
        (&["--fixture"][..], "--fixture"),
        (&["--fixture", "bus-fixture.json"][..], "--fixture"),
        (&["--snapshot", "x.svg"][..], "--snapshot"),
        (&["--snapshot"][..], "--snapshot"),
        (&["--snapshot-core", "x.svg"][..], "--snapshot-core"),
        (&["--cols", "100"][..], "--cols"),
        (&["--rows", "50"][..], "--rows"),
        // After a valid bus and token the removed flag is still refused.
        (
            &["--bus", "127.0.0.1:9090", "--token", "t", "--fixture"][..],
            "--fixture",
        ),
    ] {
        let out = run_in(&dir, args, &[]);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(2), "{args:?}: {stderr}");
        assert!(
            out.stdout.is_empty(),
            "{args:?} wrote to stdout: {:?}",
            String::from_utf8_lossy(&out.stdout)
        );
        let want = format!("unknown argument `{flag}`\n{USAGE_HEAD}");
        assert!(stderr.starts_with(&want), "{args:?}:\n{stderr}");
        assert_usage_is_clean(&stderr);
    }
    // `--snapshot x.svg` named an output file: nothing was written.
    assert_eq!(files_in(&dir), Vec::<String>::new());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn no_arguments_and_no_bus_environment_print_the_usage_and_exit_2() {
    let dir = temp_dir("noargs");
    // Unset, and set-but-empty, both mean "no bus".
    for env in [&[][..], &[("AITM_BUS", ""), ("AITM_BUS_TOKEN", "")][..]] {
        let out = run_in(&dir, &[], env);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(2), "{env:?}: {stderr}");
        assert!(out.stdout.is_empty(), "{env:?}");
        assert!(stderr.starts_with(USAGE_HEAD), "{env:?}:\n{stderr}");
        assert!(stderr.contains("--poc-dir:"), "{stderr}");
        assert!(stderr.contains("--expect-role:"), "{stderr}");
        assert_usage_is_clean(&stderr);
    }
    // `--help` is the same usage, the same status.
    let out = run_in(&dir, &["--help"], &[]);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).starts_with(USAGE_HEAD));
    assert_eq!(files_in(&dir), Vec::<String>::new());
    let _ = std::fs::remove_dir_all(&dir);
}

/// The transport match lost its fixture arm; the two live arms (`--bus`,
/// `AITM_BUS`) and the S5 loopback refusal are still reached, each proved
/// at the check that comes *before* any connect, so no socket is opened.
#[test]
fn the_live_transport_arms_are_still_reached_and_refuse_before_connecting() {
    let dir = temp_dir("live-arms");
    // `--bus` without a token, and no AITM_BUS_TOKEN: refused by the token check.
    let out = run_in(&dir, &["--bus", "127.0.0.1:9090"], &[]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{stderr}");
    assert!(
        stderr.contains("--bus needs --token-file or --token (or AITM_BUS_TOKEN)"),
        "{stderr}"
    );
    // `AITM_BUS` set with an empty token: the env arm's own refusal.
    let out = run_in(
        &dir,
        &[],
        &[("AITM_BUS", "127.0.0.1:9090"), ("AITM_BUS_TOKEN", "")],
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{stderr}");
    assert!(
        stderr.contains("AITM_BUS is set but AITM_BUS_TOKEN is empty"),
        "{stderr}"
    );
    // A bus off loopback with a token: S5 refuses it before connecting.
    let out = run_in(&dir, &["--bus", "10.0.0.5:9090", "--token", "t"], &[]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{stderr}");
    assert!(
        stderr.contains("--bus 10.0.0.5:9090: refusing a bus that is not on loopback"),
        "{stderr}"
    );
    assert!(stderr.contains("--allow-remote-bus"), "{stderr}");
    // An unparsable bus address is refused the same way.
    let out = run_in(&dir, &["--bus", "not-an-address", "--token", "t"], &[]);
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty());
    assert_eq!(files_in(&dir), Vec::<String>::new());
    let _ = std::fs::remove_dir_all(&dir);
}
