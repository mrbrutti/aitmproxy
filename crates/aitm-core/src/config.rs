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
        }
    }
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
}

impl Default for LimitConfig {
    fn default() -> Self {
        Self {
            global_rps: 150,
            per_host_rps: 50,
            max_concurrency: 25,
            host_error_budget: 10,
            backoff: BackoffConfig::default(),
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
}

impl Default for CaConfig {
    fn default() -> Self {
        Self {
            dir: PathBuf::from(".aitm/ca"),
            key_mode: 0o600,
        }
    }
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

/// Embedded-browser configuration. Declared in `aitm-core` because `Config`
/// references it; `aitm-browser` implements the driver against this type.
#[derive(Debug, Clone)]
pub struct BrowserConfig {
    /// The proxy upstream (`--proxy-server`).
    pub proxy_addr: SocketAddr,
    pub headless: bool,
    /// Trust the proxy CA via CDP `Security.setIgnoreCertificateErrors`.
    pub ignore_cert_errors: bool,
    pub nav_timeout: Duration,
    pub ssrf: SsrfPolicy,
}

impl Default for BrowserConfig {
    fn default() -> Self {
        Self {
            proxy_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080),
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
