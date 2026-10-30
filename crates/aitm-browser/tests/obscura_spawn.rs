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
use aitm_core::{engine_may_reach_private, ObscuraConfig, ScopeEntry, SsrfPolicy};

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
///
/// Audit I15 — with `obscura.allow_private = false` (the default) the
/// `--allow-private-network` flag is **omitted**: the engine refuses private and
/// loopback targets on its own, mirroring the strict policy.
#[test]
fn command_argv_and_env() {
    for var in SCRUBBED_ENV {
        std::env::set_var(var, "from-the-parent-shell");
    }

    let config = BrowserConfig {
        proxy_addr: "127.0.0.1:18081".parse().expect("socket addr"),
        ..BrowserConfig::default()
    };
    assert!(
        !config.obscura.allow_private,
        "default must not pre-authorize private targets at the engine"
    );
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
            "--ready-file",
            "/tmp/aitm-ready-42",
        ]
        .map(OsStr::new)
    );
    assert!(
        !args.contains(&OsStr::new("--allow-private-network")),
        "strict policy must omit --allow-private-network: {args:?}"
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

/// The argv flag follows the derived `obscura.allow_private`: set it, and
/// `--allow-private-network` is passed, so the engine matches a launch site that
/// decided private targets are permitted.
#[test]
fn command_passes_allow_private_network_when_allowed() {
    let config = BrowserConfig {
        obscura: ObscuraConfig {
            allow_private: true,
            ..ObscuraConfig::default()
        },
        ..BrowserConfig::default()
    };

    assert!(
        allow_private_in_argv(&config),
        "allow_private = true must pass --allow-private-network"
    );
}

/// Audit I15 preserved, end to end at the argv level: under the strict default
/// policy, a **pure-public** scope leaves `obscura.allow_private` false, so the
/// flag is omitted — obscura refuses private/loopback targets on its own.
#[test]
fn command_omits_flag_for_pure_public_scope_under_strict_policy() {
    let strict = SsrfPolicy::default();
    let public_scope = [ScopeEntry {
        host: "example.com:443".into(),
    }];
    let config = BrowserConfig {
        ssrf: strict.clone(),
        obscura: ObscuraConfig {
            allow_private: engine_may_reach_private(&strict, &public_scope),
            ..ObscuraConfig::default()
        },
        ..BrowserConfig::default()
    };

    assert!(
        !allow_private_in_argv(&config),
        "strict policy + public-only scope must omit --allow-private-network"
    );
}

/// The real operator path, end to end at the argv level: under the strict
/// default policy, a **scoped loopback** target lifts `obscura.allow_private` via
/// policy ∪ scope, so the flag is passed — the engine can reach the scoped
/// loopback target without `block_private = false` (the removed PR #32 workaround).
#[test]
fn command_passes_flag_for_scoped_loopback_under_strict_policy() {
    let strict = SsrfPolicy::default();
    let loopback_scope = [ScopeEntry {
        host: "127.0.0.1:8085".into(),
    }];
    let config = BrowserConfig {
        ssrf: strict.clone(),
        obscura: ObscuraConfig {
            allow_private: engine_may_reach_private(&strict, &loopback_scope),
            ..ObscuraConfig::default()
        },
        ..BrowserConfig::default()
    };

    assert!(
        allow_private_in_argv(&config),
        "strict policy + scoped loopback must pass --allow-private-network"
    );
}

/// Whether the spawn command for `config` carries `--allow-private-network`.
fn allow_private_in_argv(config: &BrowserConfig) -> bool {
    let cmd = ObscuraProcess::command(
        config,
        Path::new("/opt/aitm/obscura"),
        Path::new("/var/aitm/ca/ca.crt"),
        19222,
        Path::new("/tmp/aitm-ready-42"),
    );
    cmd.as_std()
        .get_args()
        .any(|a| a == OsStr::new("--allow-private-network"))
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
    // Nothing anywhere → an actionable error that names the fixes (AC3): the
    // dev-fetch script, the AITM_OBSCURA_BIN override, and the config key.
    let not_found = discover_binary(&unconfigured, None, None, &none_lookup)
        .expect_err("no binary anywhere must be an error");
    let not_found = format!("{not_found:#}");
    for needle in [
        "scripts/fetch-obscura-dev.sh",
        "AITM_OBSCURA_BIN",
        "browser.obscura.binary",
    ] {
        assert!(
            not_found.contains(needle),
            "not-found error is not actionable (missing {needle:?}): {not_found}"
        );
    }

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
