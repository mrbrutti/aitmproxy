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

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{bail, Context as _};
use serde::Deserialize;

use aitm_core::{
    BackoffConfig, BrowserConfig, BrowserEngine, CaConfig, Config, FindingsConfig, FirefoxConfig,
    Frontend, LimitConfig, MapsConfig, McpConfig, McpTransport, ObscuraConfig, PocConfig,
    ScopeConfig, ScopeEntry, SessionIoConfig, SsrfPolicy, TlsConfig, Value,
};
use aitm_plugin_rhai::{RhaiConfig, ScriptEntry};
use aitm_proto_l4::config::L4Config;

/// `<config_dir>/aitmproxy/config.yaml`: a sibling of the CA dir with the
/// same fallbacks, taken from the directory `CaConfig::default()` already
/// resolved rather than resolving it a second way.
pub fn default_config_path() -> PathBuf {
    CaConfig::default().audit_log.with_file_name("config.yaml")
}

/// Everything one config file configures: the proxy itself, the scripting tier,
/// and the L4 module. They are separate types — `aitm_core` knows nothing about
/// Rhai or L4 (no `aitm-core` edits, AC19) — but come from one file and one parse,
/// so a misspelled scripting or L4 knob is refused the same way a browser one is.
#[derive(Debug, Clone)]
pub struct Settings {
    pub core: Config,
    pub rhai: RhaiConfig,
    pub l4: L4Config,
}

/// Load the config file as the core [`Config`] only.
pub fn load(path: Option<&Path>) -> anyhow::Result<Config> {
    load_settings(path).map(|s| s.core)
}

/// Load the core [`Config`] and the L4 module [`L4Config`] (for callers that wire
/// L4). The L4 section lives outside `aitm-core`, so it rides alongside here rather
/// than inside `Config` (keeping `aitm-core` untouched, AC19).
pub fn load_full(path: Option<&Path>) -> anyhow::Result<(Config, L4Config)> {
    load_settings(path).map(|s| (s.core, s.l4))
}

/// [`load`], keeping the scripting-tier and L4 settings too. `None` reads
/// [`default_config_path`], where an absent file means defaults (L4 disabled);
/// `Some(p)` must exist, and the error names `p`.
pub fn load_settings(path: Option<&Path>) -> anyhow::Result<Settings> {
    let Some(path) = path else {
        let path = default_config_path();
        return match std::fs::read_to_string(&path) {
            Ok(text) => {
                parse_settings(&text).with_context(|| format!("in config file {}", path.display()))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Settings {
                core: Config::default(),
                rhai: RhaiConfig::default(),
                l4: L4Config::default(),
            }),
            Err(e) => Err(e).with_context(|| format!("reading config file {}", path.display())),
        };
    };
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading config file {}", path.display()))?;
    parse_settings(&text).with_context(|| format!("in config file {}", path.display()))
}

/// Parse YAML into the core [`Config`] only. See [`parse_full`] for the L4 variant.
pub fn parse(yaml: &str) -> anyhow::Result<Config> {
    parse_settings(yaml).map(|s| s.core)
}

/// Parse the core [`Config`] and the L4 module [`L4Config`].
pub fn parse_full(yaml: &str) -> anyhow::Result<(Config, L4Config)> {
    parse_settings(yaml).map(|s| (s.core, s.l4))
}

/// [`parse`], keeping the scripting-tier and L4 settings too: unknown keys are
/// errors (including under `l4`, which maps to `L4Config`'s own
/// `deny_unknown_fields`); absent keys keep their default value; an absent `l4`
/// section is `L4Config::default()` — disabled, fail-closed.
pub fn parse_settings(yaml: &str) -> anyhow::Result<Settings> {
    let file: ConfigFile = serde_yaml::from_str(yaml).context("parsing config YAML")?;
    let l4 = file.l4.clone().unwrap_or_default();
    let mut core = Config::default();
    let mut rhai = RhaiConfig::default();
    file.apply(&mut core, &mut rhai)?;
    append_scripts_dir_entries(&mut rhai);
    Ok(Settings { core, rhai, l4 })
}

/// The "next start" half of `script.save`: a script it wrote into
/// `rhai.scripts_dir` is not in `scripts:`, and the plugin chain is sealed once
/// built, so it can only join at startup. Append every `*.rhai` regular file in
/// the directory (name order) as an enabled entry, after the declared ones, and
/// skip any file a declared entry already names (compared canonicalized, so
/// `./a.rhai` and an absolute spelling are one script and the declared entry's
/// options and `enabled` win). A missing or unreadable directory adds nothing:
/// it is not fatal, and `script.save` creates it. Symlinks are not followed.
fn append_scripts_dir_entries(rhai: &mut RhaiConfig) {
    let Some(dir) = rhai.scripts_dir.clone() else {
        return;
    };
    let Ok(read) = std::fs::read_dir(&dir) else {
        return;
    };
    let canon = |p: &Path| p.canonicalize().unwrap_or_else(|_| p.to_path_buf());
    let mut declared: Vec<PathBuf> = rhai.scripts.iter().map(|e| canon(&e.path)).collect();
    let mut found: Vec<PathBuf> = read
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("rhai"))
        .collect();
    found.sort();
    for path in found {
        let resolved = canon(&path);
        if declared.contains(&resolved) {
            continue;
        }
        declared.push(resolved);
        rhai.scripts.push(ScriptEntry::new(path));
    }
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
    findings: Option<FindingsFile>,
    ssl_insecure: Option<bool>,
    max_flows: Option<usize>,
    max_flow_bytes: Option<usize>,
    /// The L4 (raw packet) module config. Maps directly to the crate's `L4Config`
    /// (its own `#[serde(default, deny_unknown_fields)]` applies), so missing keys
    /// take their fail-closed defaults and a misspelled `l4.*` key is an error.
    /// Lives outside `Config` to keep `aitm-core` untouched (AC19).
    l4: Option<L4Config>,
    /// The scripts to load, in chain order (M3 spec §8).
    scripts: Option<Vec<ScriptFile>>,
    /// The scripting sandbox: limits, the per-hook budget, the error policy.
    rhai: Option<RhaiFile>,
    /// Per-host TLS passthrough (M6 F11).
    tls: Option<TlsFile>,
    /// Map Local/Remote rules (M6).
    maps: Option<MapsFile>,
    /// Session/flow file I/O agent gate (M6 F10).
    session_io: Option<SessionIoFile>,
}

impl ConfigFile {
    fn apply(self, c: &mut Config, r: &mut RhaiConfig) -> anyhow::Result<()> {
        set(&mut c.listen, self.listen);
        if let Some(s) = self.scope {
            s.apply(&mut c.scope);
        }
        if let Some(l) = self.limits {
            l.apply(&mut c.limits);
        }
        if let Some(ca) = self.ca {
            ca.apply(&mut c.ca)?;
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
        if let Some(f) = self.findings {
            f.apply(&mut c.findings);
        }
        set(&mut c.ssl_insecure, self.ssl_insecure);
        set(&mut c.max_flows, self.max_flows);
        set(&mut c.max_flow_bytes, self.max_flow_bytes);
        if let Some(scripts) = self.scripts {
            r.scripts = scripts
                .into_iter()
                .map(ScriptFile::into_entry)
                .collect::<anyhow::Result<_>>()?;
        }
        if let Some(rhai) = self.rhai {
            rhai.apply(r);
        }
        if let Some(tls) = self.tls {
            tls.apply(&mut c.tls);
        }
        if let Some(maps) = self.maps {
            maps.apply(&mut c.maps);
        }
        if let Some(session_io) = self.session_io {
            session_io.apply(&mut c.session_io);
        }
        Ok(())
    }
}

/// The `tls:` section (M6 F11): the passthrough host list and the agent gate.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TlsFile {
    /// Hosts (or `*.wildcard`) tunnelled past MITM.
    passthrough: Option<Vec<String>>,
    /// Let an agent (MCP) frontend change the passthrough list. Off by default.
    allow_agent_passthrough: Option<bool>,
}

impl TlsFile {
    fn apply(self, c: &mut TlsConfig) {
        set(&mut c.passthrough, self.passthrough);
        set(&mut c.allow_agent_passthrough, self.allow_agent_passthrough);
    }
}

/// The `maps:` section (M6): the Map Local confinement root and the agent gate.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MapsFile {
    /// Directory Map Local files are confined to.
    root: Option<PathBuf>,
    /// Let an agent (MCP) frontend author map rules. Off by default.
    allow_agent_authoring: Option<bool>,
}

impl MapsFile {
    fn apply(self, c: &mut MapsConfig) {
        if let Some(root) = self.root {
            c.root = Some(root);
        }
        set(&mut c.allow_agent_authoring, self.allow_agent_authoring);
    }
}

/// The `session_io:` section (M6 F10): the agent file-I/O gate.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionIoFile {
    /// Let an agent (MCP) frontend read/write a host path via the session/flow I/O
    /// commands. Off by default.
    allow_agent_file_io: Option<bool>,
    /// Confine every path-bearing session/flow I/O call under this root. Unset
    /// imposes no confinement (the human CLI keeps full path access).
    root: Option<PathBuf>,
}

impl SessionIoFile {
    fn apply(self, c: &mut SessionIoConfig) {
        set(&mut c.allow_agent_file_io, self.allow_agent_file_io);
        if let Some(root) = self.root {
            c.root = Some(root);
        }
    }
}

/// One `scripts:` entry: `- path: addons/tagger.rhai` plus the options handed
/// to that script and whether it is loaded at all.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ScriptFile {
    path: PathBuf,
    options: Option<serde_yaml::Mapping>,
    enabled: Option<bool>,
}

impl ScriptFile {
    fn into_entry(self) -> anyhow::Result<ScriptEntry> {
        let mut options = BTreeMap::new();
        for (key, value) in self.options.unwrap_or_default() {
            let name = key.as_str().map(str::to_string).ok_or_else(|| {
                anyhow::anyhow!(
                    "script option names under `{}` must be strings",
                    self.path.display()
                )
            })?;
            let value = yaml_to_value(value).with_context(|| {
                format!(
                    "script option `{name}` of `{}` is not a value a script can read",
                    self.path.display()
                )
            })?;
            options.insert(name, value);
        }
        Ok(ScriptEntry {
            path: self.path,
            options,
            enabled: self.enabled.unwrap_or(true),
        })
    }
}

/// The `rhai:` section: the sandbox limits (spec §7), the per-hook wall-clock
/// budget, and the compile-error policy.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RhaiFile {
    /// Fail startup on a compile error instead of skipping the script.
    strict: Option<bool>,
    /// Let plugin scripts widen the scope with `scope.add(...)` (off by default).
    allow_scope_add: Option<bool>,
    /// The directory `script.save` writes `<name>.rhai` into, and whose `*.rhai`
    /// files load at startup. Unset refuses `script.save`.
    scripts_dir: Option<PathBuf>,
    /// Let an agent frontend (MCP) run `script.save`/`reload`/`enable`/`disable`
    /// (off by default; the human CLI and operator UI are never gated).
    allow_agent_authoring: Option<bool>,
    /// Seconds a single hook may run before it is aborted.
    hook_timeout: Option<u64>,
    /// Seconds a single `browser.*` host call may take (T9); a navigation
    /// legitimately outlives a hook, so it has its own budget.
    browser_timeout: Option<u64>,
    max_operations: Option<u64>,
    max_call_levels: Option<usize>,
    max_expr_depth: Option<usize>,
    max_function_expr_depth: Option<usize>,
    max_string_size: Option<usize>,
    max_array_size: Option<usize>,
    max_map_size: Option<usize>,
    max_modules: Option<usize>,
}

impl RhaiFile {
    fn apply(self, r: &mut RhaiConfig) {
        set(&mut r.strict, self.strict);
        set(&mut r.allow_scope_add, self.allow_scope_add);
        if let Some(dir) = self.scripts_dir {
            r.scripts_dir = Some(dir);
        }
        set(&mut r.allow_agent_authoring, self.allow_agent_authoring);
        set_secs(&mut r.hook_timeout, self.hook_timeout);
        set_secs(&mut r.browser_timeout, self.browser_timeout);
        let l = &mut r.limits;
        set(&mut l.max_operations, self.max_operations);
        set(&mut l.max_call_levels, self.max_call_levels);
        set(&mut l.max_expr_depth, self.max_expr_depth);
        set(&mut l.max_function_expr_depth, self.max_function_expr_depth);
        set(&mut l.max_string_size, self.max_string_size);
        set(&mut l.max_array_size, self.max_array_size);
        set(&mut l.max_map_size, self.max_map_size);
        set(&mut l.max_modules, self.max_modules);
    }
}

/// A script option as written in YAML, as the `Value` a script reads back
/// through `option(name)`. Anything without a `Value` counterpart (a YAML tag)
/// is refused rather than silently dropped.
fn yaml_to_value(y: serde_yaml::Value) -> anyhow::Result<Value> {
    Ok(match y {
        serde_yaml::Value::Null => Value::Null,
        serde_yaml::Value::Bool(b) => Value::Bool(b),
        serde_yaml::Value::Number(n) => match (n.as_i64(), n.as_f64()) {
            (Some(i), _) => Value::Int(i),
            (None, Some(f)) => Value::Float(f),
            (None, None) => bail!("`{n}` is not a number a script can read"),
        },
        serde_yaml::Value::String(s) => Value::Str(s),
        serde_yaml::Value::Sequence(items) => Value::Array(
            items
                .into_iter()
                .map(yaml_to_value)
                .collect::<anyhow::Result<_>>()?,
        ),
        serde_yaml::Value::Mapping(map) => {
            let mut out = BTreeMap::new();
            for (key, value) in map {
                let name = key
                    .as_str()
                    .map(str::to_string)
                    .ok_or_else(|| anyhow::anyhow!("map keys must be strings"))?;
                out.insert(name, yaml_to_value(value)?);
            }
            Value::Object(out)
        }
        serde_yaml::Value::Tagged(_) => bail!("tagged YAML values are not script options"),
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ScopeFile {
    /// `["host", "host:port", "*.wildcard"]`.
    entries: Option<Vec<String>>,
    /// Let an agent (MCP) frontend widen scope with `scope.add`. Off by default.
    allow_agent_widen: Option<bool>,
}

impl ScopeFile {
    fn apply(self, c: &mut ScopeConfig) {
        if let Some(hosts) = self.entries {
            c.entries = hosts.into_iter().map(|host| ScopeEntry { host }).collect();
        }
        set(&mut c.allow_agent_widen, self.allow_agent_widen);
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
    max_concurrent_streams: Option<u32>,
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
        set(&mut c.max_concurrent_streams, self.max_concurrent_streams);
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
    /// `key_mode` may only narrow the key's permissions: a mode with any
    /// group or other bit set is refused, so no config file can make the CA
    /// key readable beyond its owner.
    fn apply(self, c: &mut CaConfig) -> anyhow::Result<()> {
        if let Some(mode) = self.key_mode {
            if mode & 0o077 != 0 {
                bail!(
                    "ca.key_mode {mode:#o} grants group or other permissions on the CA key; use \
                     an owner-only mode such as 0o600"
                );
            }
        }
        set(&mut c.dir, self.dir);
        set(&mut c.key_mode, self.key_mode);
        set(&mut c.allow_agent_install, self.allow_agent_install);
        set(&mut c.audit_log, self.audit_log);
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct McpFile {
    /// `singleton_map`: the documented `{loopback_tcp: {…}}` map form. serde_yaml
    /// 0.9 otherwise reads an externally tagged enum only as a `!loopback_tcp`
    /// YAML tag. `default` keeps the key optional under `with`.
    #[serde(default, with = "serde_yaml::with::singleton_map")]
    transport: Option<TransportFile>,
    /// A second loopback-TCP token; a connection presenting it is a human
    /// operator ([`Frontend::Operator`]) rather than an agent.
    operator_token: Option<String>,
    /// The role a stdio connection speaks as (default `agent`).
    stdio_role: Option<RoleFile>,
}

impl McpFile {
    fn apply(self, c: &mut McpConfig) {
        if let Some(t) = self.transport {
            c.transport = t.into();
        }
        if self.operator_token.is_some() {
            c.operator_token = self.operator_token;
        }
        set(&mut c.stdio_role, self.stdio_role.map(Into::into));
    }
}

/// `stdio_role: agent | operator`.
#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum RoleFile {
    Agent,
    Operator,
}

impl From<RoleFile> for Frontend {
    fn from(r: RoleFile) -> Self {
        match r {
            RoleFile::Agent => Frontend::Mcp,
            RoleFile::Operator => Frontend::Operator,
        }
    }
}

/// `transport: {stdio: {}}` or
/// `transport: {loopback_tcp: {port, token, endpoint_file?}}`.
#[derive(Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
enum TransportFile {
    Stdio {},
    LoopbackTcp {
        port: u16,
        token: String,
        /// Optional rendezvous file for the bound bus `host:port` (no token).
        #[serde(default)]
        endpoint_file: Option<PathBuf>,
    },
}

impl From<TransportFile> for McpTransport {
    fn from(t: TransportFile) -> Self {
        match t {
            TransportFile::Stdio {} => McpTransport::Stdio,
            TransportFile::LoopbackTcp {
                port,
                token,
                endpoint_file,
            } => McpTransport::LoopbackTcp {
                port,
                token,
                endpoint_file,
            },
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BrowserFile {
    engine: Option<EngineFile>,
    obscura: Option<ObscuraFile>,
    firefox: Option<FirefoxFile>,
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
        if let Some(f) = self.firefox {
            f.apply(&mut c.firefox);
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

/// `engine: obscura | chrome | firefox`.
#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum EngineFile {
    Obscura,
    Chrome,
    Firefox,
}

impl From<EngineFile> for BrowserEngine {
    fn from(e: EngineFile) -> Self {
        match e {
            EngineFile::Obscura => BrowserEngine::Obscura,
            EngineFile::Chrome => BrowserEngine::Chrome,
            EngineFile::Firefox => BrowserEngine::Firefox,
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
struct FirefoxFile {
    binary: Option<PathBuf>,
    start_timeout: Option<u64>,
    nav_timeout: Option<u64>,
}

impl FirefoxFile {
    fn apply(self, c: &mut FirefoxConfig) {
        if let Some(b) = self.binary {
            c.binary = b;
        }
        set_secs(&mut c.start_timeout, self.start_timeout);
        set_secs(&mut c.nav_timeout, self.nav_timeout);
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
    /// Where `poc.run` writes artifacts and `poc.artifact` reads them from.
    out_dir: Option<PathBuf>,
    /// Let an agent (MCP) frontend run `poc.run` (default false). (T3)
    allow_agent_run: Option<bool>,
}

impl PocFile {
    fn apply(self, c: &mut PocConfig) {
        if let Some(d) = self.dir {
            c.dir = Some(d);
        }
        if let Some(d) = self.out_dir {
            c.out_dir = Some(d);
        }
        if let Some(v) = self.allow_agent_run {
            c.allow_agent_run = v;
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FindingsFile {
    /// Where the persistent findings store writes per-finding YAML + `runs.jsonl`.
    dir: Option<PathBuf>,
}

impl FindingsFile {
    fn apply(self, c: &mut FindingsConfig) {
        if let Some(d) = self.dir {
            c.dir = Some(d);
        }
    }
}
