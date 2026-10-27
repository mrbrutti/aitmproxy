//! The forked obscura engine as a managed child: finding the binary, probing
//! that it is the aitmproxy fork, and building the exact `serve` command.
//!
//! Spec §D3 (discovery, probe) and §D4 (argv, environment). Starting and
//! stopping the child, and the `BrowserDriver` over it, are Task 20.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use aitm_core::{BrowserConfig, ObscuraConfig};
use anyhow::Context as _;
use tokio::process::{Child, Command};

/// Environment variables removed from the child so its trust and routing are
/// exactly what aitmproxy passes as flags, whatever the operator's shell carries.
pub const SCRUBBED_ENV: [&str; 11] = [
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "OBSCURA_CA_CERT",
    "OBSCURA_PROXY",
    "OBSCURA_ALLOW_PRIVATE_NETWORK",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "no_proxy",
];

/// Bound on each probe invocation (`--help`, `--version`): every subprocess is
/// bounded, and a binary that hangs on `--help` is not one we want to serve.
const PROBE_TIMEOUT: Duration = Duration::from_secs(10);

/// What the probe learned about the binary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeInfo {
    /// The `--version` output, trimmed; informational, never a pin.
    pub version: String,
}

/// Find the obscura binary: `browser.obscura.binary` → `AITM_OBSCURA_BIN`
/// (`env_bin`) → `<exe_dir>/obscura` → `path_lookup("obscura")`. The first
/// candidate that exists is final; a configured path that does not exist is
/// an error, not a fall-through.
pub fn discover_binary(
    cfg: &ObscuraConfig,
    env_bin: Option<PathBuf>,
    exe_dir: Option<&Path>,
    path_lookup: &dyn Fn(&str) -> Option<PathBuf>,
) -> anyhow::Result<PathBuf> {
    if let Some(configured) = &cfg.binary {
        if configured.exists() {
            return Ok(configured.clone());
        }
        anyhow::bail!(
            "browser.obscura.binary {} does not exist",
            configured.display()
        );
    }

    let mut tried = Vec::new();
    let candidates = [
        env_bin,
        exe_dir.map(|dir| dir.join("obscura")),
        path_lookup("obscura"),
    ];
    for candidate in candidates.into_iter().flatten() {
        if candidate.exists() {
            return Ok(candidate);
        }
        tried.push(candidate.display().to_string());
    }
    anyhow::bail!(
        "no obscura binary found (tried: {}); install the bundled binary next to aitm, \
         set AITM_OBSCURA_BIN, or set browser.obscura.binary",
        if tried.is_empty() {
            "nothing".to_string()
        } else {
            tried.join(", ")
        }
    )
}

/// Check that `binary` is the aitmproxy fork — its `--help` must list
/// `--ca-cert` — then read its `--version`. No CDP connection is attempted.
pub async fn probe(binary: &Path) -> anyhow::Result<ProbeInfo> {
    let help = run_probe_flag(binary, "--help").await?;
    if !help.contains("--ca-cert") {
        anyhow::bail!(
            "{} is not the aitmproxy obscura fork: its --help does not list --ca-cert; \
             install the bundled binary or set browser.obscura.binary",
            binary.display()
        );
    }
    let version = run_probe_flag(binary, "--version").await?;
    Ok(ProbeInfo {
        version: version.trim().to_string(),
    })
}

/// Run `<binary> <flag>` with the scrubbed environment and return its combined
/// stdout and stderr, bounded by [`PROBE_TIMEOUT`].
async fn run_probe_flag(binary: &Path, flag: &str) -> anyhow::Result<String> {
    let mut cmd = Command::new(binary);
    cmd.arg(flag)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    scrub_env(&mut cmd);

    let output = tokio::time::timeout(PROBE_TIMEOUT, cmd.output())
        .await
        .map_err(|_| {
            anyhow::anyhow!(
                "{} {flag} did not finish within {PROBE_TIMEOUT:?}",
                binary.display()
            )
        })?
        .with_context(|| format!("running {} {flag}", binary.display()))?;

    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    Ok(text)
}

fn scrub_env(cmd: &mut Command) {
    for var in SCRUBBED_ENV {
        cmd.env_remove(var);
    }
}

/// A running `obscura serve` owned by one driver.
pub struct ObscuraProcess {
    // Populated by `start` (Task 20); `command` alone spawns nothing.
    #[allow(dead_code)]
    child: Child,
    #[allow(dead_code)]
    cdp_port: u16,
    #[allow(dead_code)]
    ready_file: PathBuf,
}

impl ObscuraProcess {
    /// The exact command that would be spawned (argv + env), for tests, logging,
    /// and `start`: the spec's `serve …` line, with the CA passed as the
    /// certificate **file**, the scrubbed environment, and `kill_on_drop`.
    pub fn command(
        config: &BrowserConfig,
        binary: &Path,
        ca_cert: &Path,
        cdp_port: u16,
        ready_file: &Path,
    ) -> Command {
        let mut cmd = Command::new(binary);
        cmd.arg("serve")
            .args(["--host", "127.0.0.1"])
            .args(["--port", &cdp_port.to_string()])
            .args([
                "--proxy",
                &format!("http://127.0.0.1:{}", config.proxy_addr.port()),
            ])
            .arg("--ca-cert")
            .arg(ca_cert)
            .arg("--allow-private-network")
            .arg("--ready-file")
            .arg(ready_file)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        scrub_env(&mut cmd);
        cmd
    }
}
