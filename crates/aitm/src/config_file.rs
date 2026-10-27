//! The operator's YAML config file (spec §D10, M2-AC18).
//!
//! A serde mirror of [`Config`]: every field is optional and
//! `deny_unknown_fields` sits on every level, so a misspelled knob
//! (`browser.enigne`) is an error instead of a silently kept default. Values
//! are applied field by field over `Config::default()`, so a two-line file is
//! valid. `aitm_core::Config` stays a plain data type; the file format lives
//! here, in the binary's crate.
//!
//! Keys mirror the Rust field names. Durations are integer seconds.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::Context as _;
use serde::Deserialize;

use aitm_core::{
    BackoffConfig, BrowserConfig, BrowserEngine, CaConfig, Config, LimitConfig, McpConfig,
    McpTransport, ObscuraConfig, PocConfig, ScopeConfig, ScopeEntry, SsrfPolicy,
};

/// `<config_dir>/aitmproxy/config.yaml`: a sibling of the CA dir with the
/// same fallbacks, taken from the directory `CaConfig::default()` already
/// resolved rather than resolving it a second way.
pub fn default_config_path() -> PathBuf {
    CaConfig::default().audit_log.with_file_name("config.yaml")
}

/// Load the config file. `None` reads [`default_config_path`], where an absent
/// file means `Config::default()` (today's behaviour); `Some(p)` must exist,
/// and the error names `p`.
pub fn load(path: Option<&Path>) -> anyhow::Result<Config> {
    let Some(path) = path else {
        let path = default_config_path();
        return match std::fs::read_to_string(&path) {
            Ok(text) => parse(&text).with_context(|| format!("in config file {}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Config::default()),
            Err(e) => Err(e).with_context(|| format!("reading config file {}", path.display())),
        };
    };
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading config file {}", path.display()))?;
    parse(&text).with_context(|| format!("in config file {}", path.display()))
}

/// Parse YAML into a `Config`: unknown keys are errors; absent keys keep
/// their `Config::default()` value.
pub fn parse(yaml: &str) -> anyhow::Result<Config> {
    let file: ConfigFile = serde_yaml::from_str(yaml).context("parsing config YAML")?;
    let mut cfg = Config::default();
    file.apply(&mut cfg);
    Ok(cfg)
}

/// Overwrite `slot` only when the file set the key.
fn set<T>(slot: &mut T, value: Option<T>) {
    if let Some(v) = value {
        *slot = v;
    }
}

/// Durations in the file are integer seconds.
fn set_secs(slot: &mut Duration, secs: Option<u64>) {
    if let Some(s) = secs {
        *slot = Duration::from_secs(s);
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigFile {
    listen: Option<SocketAddr>,
    scope: Option<ScopeFile>,
    limits: Option<LimitsFile>,
    ca: Option<CaFile>,
    mcp: Option<McpFile>,
    browser: Option<BrowserFile>,
    poc: Option<PocFile>,
    ssl_insecure: Option<bool>,
    max_flows: Option<usize>,
    max_flow_bytes: Option<usize>,
}

impl ConfigFile {
    fn apply(self, c: &mut Config) {
        set(&mut c.listen, self.listen);
        if let Some(s) = self.scope {
            s.apply(&mut c.scope);
        }
        if let Some(l) = self.limits {
            l.apply(&mut c.limits);
        }
        if let Some(ca) = self.ca {
            ca.apply(&mut c.ca);
        }
        if let Some(m) = self.mcp {
            m.apply(&mut c.mcp);
        }
        if let Some(b) = self.browser {
            b.apply(&mut c.browser);
        }
        if let Some(p) = self.poc {
            p.apply(&mut c.poc);
        }
        set(&mut c.ssl_insecure, self.ssl_insecure);
        set(&mut c.max_flows, self.max_flows);
        set(&mut c.max_flow_bytes, self.max_flow_bytes);
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ScopeFile {
    /// `["host", "host:port", "*.wildcard"]`.
    entries: Option<Vec<String>>,
}

impl ScopeFile {
    fn apply(self, c: &mut ScopeConfig) {
        if let Some(hosts) = self.entries {
            c.entries = hosts.into_iter().map(|host| ScopeEntry { host }).collect();
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LimitsFile {
    global_rps: Option<u32>,
    per_host_rps: Option<u32>,
    max_concurrency: Option<u32>,
    host_error_budget: Option<u32>,
    backoff: Option<BackoffFile>,
    max_body_bytes: Option<usize>,
}

impl LimitsFile {
    fn apply(self, c: &mut LimitConfig) {
        set(&mut c.global_rps, self.global_rps);
        set(&mut c.per_host_rps, self.per_host_rps);
        set(&mut c.max_concurrency, self.max_concurrency);
        set(&mut c.host_error_budget, self.host_error_budget);
        if let Some(b) = self.backoff {
            b.apply(&mut c.backoff);
        }
        set(&mut c.max_body_bytes, self.max_body_bytes);
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BackoffFile {
    base: Option<u64>,
    max: Option<u64>,
    factor: Option<f64>,
}

impl BackoffFile {
    fn apply(self, c: &mut BackoffConfig) {
        set_secs(&mut c.base, self.base);
        set_secs(&mut c.max, self.max);
        set(&mut c.factor, self.factor);
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CaFile {
    dir: Option<PathBuf>,
    key_mode: Option<u32>,
    allow_agent_install: Option<bool>,
    audit_log: Option<PathBuf>,
}

impl CaFile {
    fn apply(self, c: &mut CaConfig) {
        set(&mut c.dir, self.dir);
        set(&mut c.key_mode, self.key_mode);
        set(&mut c.allow_agent_install, self.allow_agent_install);
        set(&mut c.audit_log, self.audit_log);
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct McpFile {
    transport: Option<TransportFile>,
}

impl McpFile {
    fn apply(self, c: &mut McpConfig) {
        if let Some(t) = self.transport {
            c.transport = t.into();
        }
    }
}

/// `transport: {stdio: {}}` or `transport: {loopback_tcp: {port, token}}`.
#[derive(Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
enum TransportFile {
    Stdio {},
    LoopbackTcp { port: u16, token: String },
}

impl From<TransportFile> for McpTransport {
    fn from(t: TransportFile) -> Self {
        match t {
            TransportFile::Stdio {} => McpTransport::Stdio,
            TransportFile::LoopbackTcp { port, token } => McpTransport::LoopbackTcp { port, token },
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BrowserFile {
    engine: Option<EngineFile>,
    obscura: Option<ObscuraFile>,
    proxy_addr: Option<SocketAddr>,
    headless: Option<bool>,
    ignore_cert_errors: Option<bool>,
    nav_timeout: Option<u64>,
    ssrf: Option<SsrfFile>,
}

impl BrowserFile {
    fn apply(self, c: &mut BrowserConfig) {
        set(&mut c.engine, self.engine.map(Into::into));
        if let Some(o) = self.obscura {
            o.apply(&mut c.obscura);
        }
        set(&mut c.proxy_addr, self.proxy_addr);
        set(&mut c.headless, self.headless);
        set(&mut c.ignore_cert_errors, self.ignore_cert_errors);
        set_secs(&mut c.nav_timeout, self.nav_timeout);
        if let Some(s) = self.ssrf {
            s.apply(&mut c.ssrf);
        }
    }
}

/// `engine: obscura | chrome`.
#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum EngineFile {
    Obscura,
    Chrome,
}

impl From<EngineFile> for BrowserEngine {
    fn from(e: EngineFile) -> Self {
        match e {
            EngineFile::Obscura => BrowserEngine::Obscura,
            EngineFile::Chrome => BrowserEngine::Chrome,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ObscuraFile {
    binary: Option<PathBuf>,
    start_timeout: Option<u64>,
    stop_timeout: Option<u64>,
}

impl ObscuraFile {
    fn apply(self, c: &mut ObscuraConfig) {
        if let Some(b) = self.binary {
            c.binary = Some(b);
        }
        set_secs(&mut c.start_timeout, self.start_timeout);
        set_secs(&mut c.stop_timeout, self.stop_timeout);
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SsrfFile {
    block_private: Option<bool>,
    block_loopback: Option<bool>,
    allow_if_in_scope: Option<bool>,
}

impl SsrfFile {
    fn apply(self, c: &mut SsrfPolicy) {
        set(&mut c.block_private, self.block_private);
        set(&mut c.block_loopback, self.block_loopback);
        set(&mut c.allow_if_in_scope, self.allow_if_in_scope);
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PocFile {
    dir: Option<PathBuf>,
}

impl PocFile {
    fn apply(self, c: &mut PocConfig) {
        if let Some(d) = self.dir {
            c.dir = Some(d);
        }
    }
}
