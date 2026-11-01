//! Tester (stage 5), fix F4 of plan 2026-10-31-system-proxy-automation:
//! `main` dispatches `operator-token generate` beside the sysproxy watchdog,
//! before the config is assembled, before tracing and before the Tokio
//! runtime. This runs the REAL binary to pin the observable half of that:
//! the command works on a config file the server path would refuse (an
//! unknown top-level key fails `deny_unknown_fields`), behind `--config <p>`
//! and `--config=<p>`, prints exactly the confirmation line (never the
//! token), writes a 64-hex `operator_token` under `mcp:`, refuses to
//! overwrite without `--force`, rotates with it, and names a missing config
//! file. No port is bound, so this runs in the sandbox.
//!
//! Spec: docs/superpowers/specs/2026-10-31-system-proxy-automation-design.md
//! Plan: docs/superpowers/plans/2026-10-31-system-proxy-automation-plan.md (Task 10; F4)

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

fn temp_dir(tag: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let dir = std::env::temp_dir().join(format!("aitm-operator-token-dispatch-{tag}-{nanos}"));
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
/// killed (a server that started serving would never exit on its own).
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

/// Run `aitm <args>` with a closed stdin and no inherited `AITM_CONFIG` /
/// `RUST_LOG`. Returns the exit status (None: did not exit within 30 s),
/// stdout and stderr.
fn run_aitm(args: &[&str]) -> (Option<ExitStatus>, String, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_aitm"))
        .args(args)
        .env_remove("AITM_CONFIG")
        .env_remove("RUST_LOG")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn aitm");
    let stdout = pump(child.stdout.take().expect("piped stdout"));
    let stderr = pump(child.stderr.take().expect("piped stderr"));
    let status = wait_bounded(&mut child, Duration::from_secs(30));
    let out = stdout.join().expect("stdout pump");
    let err = stderr.join().expect("stderr pump");
    (status, out, err)
}

/// The `operator_token` value written under `mcp:`, if any.
fn token_in(config: &Path) -> Option<String> {
    let text = fs::read_to_string(config).expect("read config");
    text.lines()
        .map(str::trim)
        .find_map(|l| l.strip_prefix("operator_token:"))
        .map(|v| v.trim().to_string())
}

fn is_64_hex(s: &str) -> bool {
    s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// A config the server path would refuse (`deny_unknown_fields`), with an
/// `mcp:` block mapping for the editor to extend.
const REFUSED_BY_THE_SERVER: &str = "# operator config\nnot_a_knob: 1\nmcp:\n  enabled: true\n";

#[test]
fn operator_token_generate_runs_before_the_config_is_assembled() {
    let dir = temp_dir("generate");
    let config = dir.join("aitm.yaml");
    fs::write(&config, REFUSED_BY_THE_SERVER).expect("seed config");
    let config_s = config.to_string_lossy().into_owned();
    let expected_out = format!(
        "operator access enabled: wrote mcp.operator_token to {}\n\
         restart the proxy (and any `aitm web`/`aitm-tui --bus`/mac session) for it to take effect.\n",
        config.display()
    );

    // 1. `--config <p>`: exit 0, the confirmation line and nothing else.
    let (status, out, err) = run_aitm(&["--config", &config_s, "operator-token", "generate"]);
    let status = status.unwrap_or_else(|| panic!("did not exit; stdout={out:?} stderr={err:?}"));
    assert_eq!(status.code(), Some(0), "stdout={out:?} stderr={err:?}");
    assert_eq!(out, expected_out);
    assert_eq!(err, "", "nothing on stderr: no tracing, no config error");
    let first = token_in(&config).expect("operator_token written under mcp:");
    assert!(is_64_hex(&first), "a 64-hex CSPRNG token, got {first:?}");
    assert!(!out.contains(&first), "the token is never printed");
    let text = fs::read_to_string(&config).expect("read config");
    assert!(
        text.starts_with("# operator config\nnot_a_knob: 1\nmcp:\n"),
        "every other byte kept: {text:?}"
    );

    // 2. A second run without `--force` refuses, non-zero, file unchanged.
    let (status, out, err) = run_aitm(&["--config", &config_s, "operator-token", "generate"]);
    let status = status.unwrap_or_else(|| panic!("did not exit; stdout={out:?} stderr={err:?}"));
    assert_ne!(status.code(), Some(0), "stdout={out:?} stderr={err:?}");
    assert_eq!(out, "");
    assert!(
        err.contains("operator_token is already set; refusing to overwrite it"),
        "{err:?}"
    );
    assert!(!err.contains(&first), "the token is never printed");
    assert_eq!(fs::read_to_string(&config).expect("read config"), text);

    // 3. `--config=<p>` with `--force` rotates: exit 0, a different token.
    let config_eq = format!("--config={config_s}");
    let (status, out, err) = run_aitm(&[&config_eq, "operator-token", "generate", "--force"]);
    let status = status.unwrap_or_else(|| panic!("did not exit; stdout={out:?} stderr={err:?}"));
    assert_eq!(status.code(), Some(0), "stdout={out:?} stderr={err:?}");
    assert_eq!(out, expected_out);
    assert_eq!(err, "");
    let second = token_in(&config).expect("operator_token still under mcp:");
    assert!(is_64_hex(&second), "{second:?}");
    assert_ne!(second, first, "rotated");
    assert!(!out.contains(&second));

    fs::remove_dir_all(&dir).expect("remove temp dir");
}

/// A missing config file is the editor's own error, named with the path,
/// non-zero, nothing created — not the server's "could not read config".
#[test]
fn operator_token_generate_names_a_missing_config_and_creates_nothing() {
    let dir = temp_dir("missing");
    let config = dir.join("does-not-exist").join("aitm.yaml");
    let config_s = config.to_string_lossy().into_owned();

    let (status, out, err) = run_aitm(&["--config", &config_s, "operator-token", "generate"]);
    let status = status.unwrap_or_else(|| panic!("did not exit; stdout={out:?} stderr={err:?}"));
    assert_ne!(status.code(), Some(0), "stdout={out:?} stderr={err:?}");
    assert_eq!(out, "");
    assert!(
        err.contains(&format!(
            "config file {} does not exist; create a config before enabling operator access",
            config.display()
        )),
        "{err:?}"
    );
    assert!(!config.exists() && !config.parent().unwrap().exists());

    fs::remove_dir_all(&dir).expect("remove temp dir");
}
