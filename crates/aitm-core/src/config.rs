//! The configuration model the `ProxyBuilder` consumes.
//!
//! These are plain data types. The `aitm` binary (Task 28) parses a YAML file
//! into them; serialization format is that task's concern. `BrowserConfig` and
//! `SsrfPolicy` live here — not in `aitm-browser` — because `Config` references
//! them and `aitm-core` cannot depend on `aitm-browser` without a cycle.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;

/// Top-level configuration.
#[derive(Debug, Clone)]
pub struct Config {
    pub listen: SocketAddr,
    pub scope: ScopeConfig,
    pub limits: LimitConfig,
    pub ca: CaConfig,
    pub mcp: McpConfig,
    pub browser: BrowserConfig,
    pub poc: PocConfig,
    /// Skip verification of upstream server certificates. **Off by default**:
    /// the proxy verifies upstream TLS against the platform roots. Turning this
    /// on (for a lab with self-signed targets) trusts any upstream certificate.
    pub ssl_insecure: bool,
    /// Flow-store capacity (0 = unbounded). The store evicts the oldest flow once
    /// over this, so a long run has bounded memory.
    pub max_flows: usize,
    /// Flow-store resident-byte budget (0 = unbounded). A second bound alongside
    /// `max_flows`, so a few very large captures cannot exhaust memory while under
    /// the flow-count cap.
    pub max_flow_bytes: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080),
            scope: ScopeConfig::default(),
            limits: LimitConfig::default(),
            ca: CaConfig::default(),
            mcp: McpConfig::default(),
            browser: BrowserConfig::default(),
            poc: PocConfig::default(),
            ssl_insecure: false,
            max_flows: crate::store::DEFAULT_MAX_FLOWS,
            max_flow_bytes: crate::store::DEFAULT_MAX_FLOW_BYTES,
        }
    }
}

/// PoC-engine configuration.
#[derive(Debug, Clone, Default)]
pub struct PocConfig {
    /// When set, `poc.run` only loads a PoC file that resolves (canonicalized)
    /// to a path under this directory. `None` (the default) imposes no
    /// confinement — a PoC may be loaded from any path, as before.
    pub dir: Option<PathBuf>,
}

/// Scope configuration. Deny-by-default: an empty list means nothing is active.
#[derive(Debug, Clone, Default)]
pub struct ScopeConfig {
    pub entries: Vec<ScopeEntry>,
}

/// One scope entry: a host, `host:port`, or `*.wildcard`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeEntry {
    pub host: String,
}

/// Rate/concurrency limits for active actions.
#[derive(Debug, Clone)]
pub struct LimitConfig {
    pub global_rps: u32,
    pub per_host_rps: u32,
    pub max_concurrency: u32,
    /// A host is disabled after this many errors.
    pub host_error_budget: u32,
    pub backoff: BackoffConfig,
    /// Cap on a single message body (request served, or captured response copy).
    /// Larger bodies are refused (requests) or truncated in the stored copy
    /// (responses) so a hostile peer cannot exhaust memory. Default 10 MiB.
    pub max_body_bytes: usize,
}

impl Default for LimitConfig {
    fn default() -> Self {
        Self {
            global_rps: 150,
            per_host_rps: 50,
            max_concurrency: 25,
            host_error_budget: 10,
            backoff: BackoffConfig::default(),
            max_body_bytes: 10 * 1024 * 1024,
        }
    }
}

/// Exponential backoff parameters for retrying a disabled host.
#[derive(Debug, Clone)]
pub struct BackoffConfig {
    pub base: Duration,
    pub max: Duration,
    pub factor: f64,
}

impl Default for BackoffConfig {
    fn default() -> Self {
        Self {
            base: Duration::from_millis(100),
            max: Duration::from_secs(30),
            factor: 2.0,
        }
    }
}

/// Certificate-authority configuration.
#[derive(Debug, Clone)]
pub struct CaConfig {
    /// Directory holding the root cert/key.
    pub dir: PathBuf,
    /// File mode for the private key (`0o600`).
    pub key_mode: u32,
    /// Let an agent frontend (MCP) run `ca.install`/`ca.uninstall`. **Off by
    /// default**: only the human CLI may change the OS trust store unless the
    /// operator opts in.
    pub allow_agent_install: bool,
    /// Append-only JSON Lines record of every `ca.*` change or export. A
    /// sibling of `dir`, never inside it, so the CA dir holds only key and cert.
    pub audit_log: PathBuf,
}

impl Default for CaConfig {
    fn default() -> Self {
        Self {
            dir: default_ca_dir(),
            key_mode: 0o600,
            allow_agent_install: false,
            audit_log: default_ca_audit_log(),
        }
    }
}

/// The per-user CA directory (`$XDG_CONFIG_HOME/aitmproxy/ca` or the platform
/// equivalent), so the key is not written into whatever directory the proxy was
/// launched from where another process could read or plant it. Falls back to
/// `$HOME/.aitm/ca` — never a CWD-relative path, which could be world-writable or
/// shared — and only to a local hidden dir when neither a config nor a home dir
/// is discoverable.
fn default_ca_dir() -> PathBuf {
    default_aitm_dir().join("ca")
}

/// The CA audit log, `<config_dir>/aitmproxy/ca-audit.jsonl`: a sibling of
/// [`default_ca_dir`] with the same fallbacks.
fn default_ca_audit_log() -> PathBuf {
    default_aitm_dir().join("ca-audit.jsonl")
}

/// The per-user aitmproxy directory the CA dir and audit log live under.
fn default_aitm_dir() -> PathBuf {
    dirs::config_dir()
        .map(|d| d.join("aitmproxy"))
        .or_else(|| dirs::home_dir().map(|h| h.join(".aitm")))
        .unwrap_or_else(|| PathBuf::from(".aitm"))
}

/// MCP transport selection.
#[derive(Debug, Clone)]
pub enum McpTransport {
    /// Serve over stdio.
    Stdio,
    /// Serve over loopback TCP (127.0.0.1 only); the token is required.
    LoopbackTcp { port: u16, token: String },
}

/// MCP frontend configuration.
#[derive(Debug, Clone)]
pub struct McpConfig {
    pub transport: McpTransport,
}

impl Default for McpConfig {
    fn default() -> Self {
        Self {
            transport: McpTransport::Stdio,
        }
    }
}

/// Which browser engine backs the `browser.*` tools. Declared here next to
/// `BrowserConfig`; `aitm-browser` selects the launcher from it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BrowserEngine {
    /// The bundled, forked obscura engine, which trusts the MITM CA via `--ca-cert`.
    #[default]
    Obscura,
    /// A system Chrome/Chromium (the M1 behaviour).
    Chrome,
    /// A system Firefox, launched with a throwaway profile whose proxy prefs
    /// point at aitmproxy and whose cert store trusts the MITM CA — the OS proxy
    /// and OS trust store are never touched (M4 Task 13, Review Focus #5).
    Firefox,
}

/// How to find and start the forked obscura.
#[derive(Debug, Clone)]
pub struct ObscuraConfig {
    /// The `obscura` binary; `None` runs the discovery order (bundled next to
    /// `aitm`, then `AITM_OBSCURA_BIN`, then `PATH`).
    pub binary: Option<PathBuf>,
    /// Spawn → CDP connected; default 15 s.
    pub start_timeout: Duration,
    /// Graceful stop → SIGKILL; default 5 s.
    pub stop_timeout: Duration,
}

impl Default for ObscuraConfig {
    fn default() -> Self {
        Self {
            binary: None,
            start_timeout: Duration::from_secs(15),
            stop_timeout: Duration::from_secs(5),
        }
    }
}

/// How to find and start a system Firefox (used when `engine` is `Firefox`).
///
/// Firefox is driven over its remote-debugging (CDP) endpoint. Unlike obscura,
/// trust and routing are configured per-profile (a throwaway profile), so this
/// carries no CA flag: the launcher writes the proxy prefs and trusts the CA
/// into that profile only.
#[derive(Debug, Clone)]
pub struct FirefoxConfig {
    /// The `firefox` binary; a bare name is resolved on `PATH`. Default `firefox`.
    pub binary: PathBuf,
    /// Spawn → CDP connected; default 20 s (a cold Firefox profile is slow).
    pub start_timeout: Duration,
    /// Per-operation bound on the `BrowserDriver` primitives; default 30 s.
    pub nav_timeout: Duration,
}

impl Default for FirefoxConfig {
    fn default() -> Self {
        Self {
            binary: PathBuf::from("firefox"),
            start_timeout: Duration::from_secs(20),
            nav_timeout: Duration::from_secs(30),
        }
    }
}

/// Embedded-browser configuration. Declared in `aitm-core` because `Config`
/// references it; `aitm-browser` implements the driver against this type.
#[derive(Debug, Clone)]
pub struct BrowserConfig {
    /// Engine selection; default obscura.
    pub engine: BrowserEngine,
    /// Obscura launcher settings (used when `engine` is `Obscura`).
    pub obscura: ObscuraConfig,
    /// Firefox launcher settings (used when `engine` is `Firefox`).
    pub firefox: FirefoxConfig,
    /// The proxy upstream (`--proxy-server`).
    pub proxy_addr: SocketAddr,
    /// Chrome only: obscura has no head.
    pub headless: bool,
    /// Chrome only: trust the proxy CA via CDP `Security.setIgnoreCertificateErrors`.
    pub ignore_cert_errors: bool,
    pub nav_timeout: Duration,
    pub ssrf: SsrfPolicy,
}

impl Default for BrowserConfig {
    fn default() -> Self {
        Self {
            engine: BrowserEngine::default(),
            obscura: ObscuraConfig::default(),
            firefox: FirefoxConfig::default(),
            // A dedicated loopback port, distinct from the main listener (8080):
            // the embedded browser dials this SSRF-filtered listener.
            proxy_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8081),
            headless: true,
            ignore_cert_errors: true,
            nav_timeout: Duration::from_secs(30),
            ssrf: SsrfPolicy::default(),
        }
    }
}

/// SSRF posture: block private and loopback unless the host is explicitly in
/// scope. Declared here so `BrowserConfig` (and thus `Config`) can reference it.
#[derive(Debug, Clone)]
pub struct SsrfPolicy {
    pub block_private: bool,
    pub block_loopback: bool,
    /// An explicit scope entry overrides the block.
    pub allow_if_in_scope: bool,
}

impl Default for SsrfPolicy {
    fn default() -> Self {
        Self {
            block_private: true,
            block_loopback: true,
            allow_if_in_scope: true,
        }
    }
}
