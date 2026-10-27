//! Task 19: obscura discovery, probe, and the exact spawn command — hermetic.
//!
//! No real obscura is involved: the probe tests run the shell-script fixtures
//! in `tests/fixtures/`, and the command test only inspects the `Command` that
//! would be spawned. Nothing here starts a server (that is Task 20).

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use aitm_browser::obscura::{discover_binary, probe, SCRUBBED_ENV};
use aitm_browser::{BrowserConfig, ObscuraProcess};
use aitm_core::ObscuraConfig;

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

/// A fresh, empty directory under the OS temp dir (no `tempfile` crate in this
/// workspace); removed when the guard drops.
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let dir =
            std::env::temp_dir().join(format!("aitm-obscura-{tag}-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        Self(dir)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    /// Create an empty file at `name` and return its path.
    fn touch(&self, name: &str) -> PathBuf {
        let p = self.0.join(name);
        std::fs::write(&p, b"").expect("write temp file");
        p
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// M2-AC7, M2-AC16 — the spawned argv is exactly the spec's `serve …` line,
/// the CA is passed as the certificate *file* (never the directory or the key),
/// and every proxy/trust env var the operator's shell carries is removed.
#[test]
fn command_argv_and_env() {
    for var in SCRUBBED_ENV {
        std::env::set_var(var, "from-the-parent-shell");
    }

    let config = BrowserConfig {
        proxy_addr: "127.0.0.1:18081".parse().expect("socket addr"),
        ..BrowserConfig::default()
    };
    let ca_dir = Path::new("/var/aitm/ca");
    let ca_cert = ca_dir.join("ca.crt");
    let ready_file = Path::new("/tmp/aitm-ready-42");

    let cmd = ObscuraProcess::command(
        &config,
        Path::new("/opt/aitm/obscura"),
        &ca_cert,
        19222,
        ready_file,
    );
    let std_cmd = cmd.as_std();

    assert_eq!(std_cmd.get_program(), OsStr::new("/opt/aitm/obscura"));
    let args: Vec<&OsStr> = std_cmd.get_args().collect();
    assert_eq!(
        args,
        [
            "serve",
            "--host",
            "127.0.0.1",
            "--port",
            "19222",
            "--proxy",
            "http://127.0.0.1:18081",
            "--ca-cert",
            "/var/aitm/ca/ca.crt",
            "--allow-private-network",
            "--ready-file",
            "/tmp/aitm-ready-42",
        ]
        .map(OsStr::new)
    );

    // The certificate file is in argv; the directory alone and the key are not.
    assert!(args.contains(&OsStr::new("/var/aitm/ca/ca.crt")));
    assert!(!args.contains(&OsStr::new("/var/aitm/ca")));
    assert!(!args.iter().any(|a| a.to_string_lossy().contains("ca.key")));

    // Every scrubbed variable is registered as removed (`None` value).
    let envs: Vec<(&OsStr, Option<&OsStr>)> = std_cmd.get_envs().collect();
    for var in SCRUBBED_ENV {
        assert!(
            envs.contains(&(OsStr::new(var), None)),
            "{var} is not removed from the child env: {envs:?}"
        );
    }
    assert_eq!(SCRUBBED_ENV.len(), 11);

    for var in SCRUBBED_ENV {
        std::env::remove_var(var);
    }
}

/// M2-AC6 — a binary whose `--help` lacks `--ca-cert` is refused by name, and
/// nothing is dialled: the probe must not open any connection.
#[tokio::test]
async fn probe_refuses_unpatched() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback listener");

    let script = fixture("fake-obscura-unpatched.sh");
    let err = probe(&script)
        .await
        .expect_err("unpatched obscura must be refused");
    let text = format!("{err:#}");
    assert!(
        text.contains("--ca-cert"),
        "error does not name the flag: {text}"
    );
    assert!(
        text.contains(&script.display().to_string()),
        "error does not name the binary: {text}"
    );

    let dialled = tokio::time::timeout(Duration::from_millis(200), listener.accept()).await;
    assert!(dialled.is_err(), "the probe opened a connection");
}

/// The fork's `--help` lists `--ca-cert`; the probe accepts it and reports
/// the `--version` output.
#[tokio::test]
async fn probe_accepts_patched() {
    let info = probe(&fixture("fake-obscura-patched.sh"))
        .await
        .expect("patched obscura must be accepted");
    assert!(
        info.version.contains("0.2.5-aitm.test"),
        "version not reported: {:?}",
        info.version
    );
}

/// D3 — config → `AITM_OBSCURA_BIN` → `<exe_dir>/obscura` → `PATH`; the first
/// candidate that exists wins, and a configured path that does not exist is an
/// error, not a fall-through.
#[test]
fn discovery_order() {
    let cfg_dir = TempDir::new("cfg");
    let env_dir = TempDir::new("env");
    let exe_dir = TempDir::new("exe");
    let path_dir = TempDir::new("path");

    let cfg_bin = cfg_dir.touch("obscura-from-config");
    let env_bin = env_dir.touch("obscura-from-env");
    let exe_bin = exe_dir.touch("obscura");
    let path_bin = path_dir.touch("obscura");

    let lookup = |name: &str| -> Option<PathBuf> {
        assert_eq!(name, "obscura");
        Some(path_bin.clone())
    };
    let none_lookup = |_: &str| -> Option<PathBuf> { None };

    let configured = ObscuraConfig {
        binary: Some(cfg_bin.clone()),
        ..ObscuraConfig::default()
    };
    let unconfigured = ObscuraConfig::default();

    // Config wins over everything.
    assert_eq!(
        discover_binary(
            &configured,
            Some(env_bin.clone()),
            Some(exe_dir.path()),
            &lookup
        )
        .expect("configured binary"),
        cfg_bin
    );
    // Env wins over exe_dir.
    assert_eq!(
        discover_binary(
            &unconfigured,
            Some(env_bin.clone()),
            Some(exe_dir.path()),
            &lookup
        )
        .expect("env binary"),
        env_bin
    );
    // exe_dir wins over PATH.
    assert_eq!(
        discover_binary(&unconfigured, None, Some(exe_dir.path()), &lookup)
            .expect("bundled binary"),
        exe_bin
    );
    // PATH is last.
    assert_eq!(
        discover_binary(&unconfigured, None, None, &lookup).expect("PATH binary"),
        path_bin
    );
    // Nothing anywhere → an error.
    assert!(discover_binary(&unconfigured, None, None, &none_lookup).is_err());

    // A configured path that does not exist is reported, not skipped.
    let missing = cfg_dir.path().join("does-not-exist");
    let misconfigured = ObscuraConfig {
        binary: Some(missing.clone()),
        ..ObscuraConfig::default()
    };
    let err = discover_binary(
        &misconfigured,
        Some(env_bin.clone()),
        Some(exe_dir.path()),
        &lookup,
    )
    .expect_err("missing configured binary must be an error");
    let text = format!("{err:#}");
    assert!(
        text.contains(&missing.display().to_string()),
        "error does not name the configured path: {text}"
    );
}
