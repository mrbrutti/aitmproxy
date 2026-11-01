//! System proxy automation (spec `docs/superpowers/specs/2026-10-31-system-proxy-automation-design.md`).
//!
//! The types and pure functions every other module shares: the status model
//! of §D6, the `classify` rule of §D3, the bypass union of §D5, the guidance
//! and remedy sentences of §D3/§D4; and the [`SystemProxy`] engine that the
//! three verbs, the startup recovery and the orderly exit call.

pub mod config;
pub mod platform;
pub mod plugin;
pub mod state;
pub mod watchdog;

use std::collections::BTreeMap;
use std::fmt;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use aitm_ca::exec::Executor;
use aitm_core::Value;

use platform::{ops_for, PlatformOps, Snapshot};
use state::StateFile;
use watchdog::{decide, Decision, WatchdogHandle};

pub use config::SystemProxyConfig;

/// How the system proxy is read and written on this host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mechanism {
    Networksetup,
    Gsettings,
    Kde,
    None,
}

impl Mechanism {
    /// The wire word: `networksetup | gsettings | kde | none`.
    pub fn as_str(&self) -> &'static str {
        match self {
            Mechanism::Networksetup => "networksetup",
            Mechanism::Gsettings => "gsettings",
            Mechanism::Kde => "kde",
            Mechanism::None => "none",
        }
    }
}

/// Where the effective system proxy points, relative to this core.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum State {
    Off,
    PointsAtUs,
    /// The effective HTTP endpoint, or the HTTPS one when HTTP is off.
    Other {
        host: String,
        port: u16,
    },
    Unsupported,
    NeedsPrivilege,
    Unknown,
}

impl State {
    /// The wire word: `off | points_at_us | other | unsupported | needs_privilege | unknown`.
    pub fn as_str(&self) -> &'static str {
        match self {
            State::Off => "off",
            State::PointsAtUs => "points_at_us",
            State::Other { .. } => "other",
            State::Unsupported => "unsupported",
            State::NeedsPrivilege => "needs_privilege",
            State::Unknown => "unknown",
        }
    }

    fn endpoint(&self) -> (Option<String>, Option<u16>) {
        match self {
            State::Other { host, port } => (Some(host.clone()), Some(*port)),
            _ => (None, None),
        }
    }
}

/// The host and port this core is reachable at for proxy-aware apps.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Endpoint {
    pub host: String,
    pub port: u16,
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.host, self.port)
    }
}

impl Endpoint {
    fn to_value(&self) -> Value {
        Value::Object(BTreeMap::from([
            ("host".to_string(), Value::Str(self.host.clone())),
            ("port".to_string(), Value::Int(i64::from(self.port))),
        ]))
    }
}

/// One protocol's proxy setting. An empty host is allowed (never configured).
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ProtocolProxy {
    pub enabled: bool,
    pub host: String,
    pub port: u16,
}

impl ProtocolProxy {
    fn to_value(&self) -> Value {
        Value::Object(BTreeMap::from([
            ("enabled".to_string(), Value::Bool(self.enabled)),
            ("host".to_string(), Value::Str(self.host.clone())),
            ("port".to_string(), Value::Int(i64::from(self.port))),
        ]))
    }
}

/// One macOS network service's proxy settings (Linux: one synthetic row).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ServiceRow {
    pub service: String,
    pub http: ProtocolProxy,
    pub https: ProtocolProxy,
    pub bypass: Vec<String>,
}

impl ServiceRow {
    fn to_value(&self) -> Value {
        Value::Object(BTreeMap::from([
            ("service".to_string(), Value::Str(self.service.clone())),
            ("http".to_string(), self.http.to_value()),
            ("https".to_string(), self.https.to_value()),
            ("bypass".to_string(), strings(&self.bypass)),
        ]))
    }
}

/// The effective system proxy as the OS resolves it (`scutil --proxy`, the
/// gsettings keys).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Effective {
    pub http: ProtocolProxy,
    pub https: ProtocolProxy,
    pub bypass: Vec<String>,
}

impl Effective {
    fn to_value(&self) -> Value {
        Value::Object(BTreeMap::from([
            ("http".to_string(), self.http.to_value()),
            ("https".to_string(), self.https.to_value()),
            ("bypass".to_string(), strings(&self.bypass)),
        ]))
    }
}

/// What a set wrote, as recorded in the state file.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Wrote {
    pub host: String,
    pub port: u16,
    pub bypass: Vec<String>,
}

/// `proxy.system.set` params.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SetRequest {
    pub bypass: Vec<String>,
}

/// The compact view `proxy.status` carries as `system_proxy` (§D6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Summary {
    pub state: State,
    pub host: Option<String>,
    pub port: Option<u16>,
    pub managed_by_us: bool,
    pub setting: bool,
    pub supported: bool,
    pub detail: String,
}

impl Summary {
    /// The §D6 `system_proxy` sub-object; `host`/`port` are explicit nulls.
    pub fn to_value(&self) -> Value {
        Value::Object(BTreeMap::from([
            (
                "state".to_string(),
                Value::Str(self.state.as_str().to_string()),
            ),
            ("host".to_string(), opt_str(&self.host)),
            ("port".to_string(), opt_port(self.port)),
            ("managed_by_us".to_string(), Value::Bool(self.managed_by_us)),
            ("setting".to_string(), Value::Bool(self.setting)),
            ("supported".to_string(), Value::Bool(self.supported)),
            ("detail".to_string(), Value::Str(self.detail.clone())),
        ]))
    }
}

/// The `proxy.system.status` result (§D6), as typed fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Status {
    pub state: State,
    pub detail: String,
    pub ours: Endpoint,
    pub mechanism: Mechanism,
    pub supported: bool,
    pub managed_by_us: bool,
    pub setting: bool,
    pub effective: Option<Effective>,
    pub services: Vec<ServiceRow>,
    pub bypass_default: Vec<String>,
    pub guidance: Option<String>,
    pub remedy: Option<String>,
    pub last_change_ms: Option<i64>,
    pub watchdog_pid: Option<u32>,
    pub state_file: PathBuf,
}

impl Status {
    /// The §D6 object. `host`/`port` are present only for `other`.
    pub fn to_value(&self) -> Value {
        let mut map = BTreeMap::from([
            (
                "state".to_string(),
                Value::Str(self.state.as_str().to_string()),
            ),
            ("detail".to_string(), Value::Str(self.detail.clone())),
            ("ours".to_string(), self.ours.to_value()),
            (
                "mechanism".to_string(),
                Value::Str(self.mechanism.as_str().to_string()),
            ),
            ("supported".to_string(), Value::Bool(self.supported)),
            ("managed_by_us".to_string(), Value::Bool(self.managed_by_us)),
            ("setting".to_string(), Value::Bool(self.setting)),
            (
                "effective".to_string(),
                self.effective
                    .as_ref()
                    .map_or(Value::Null, Effective::to_value),
            ),
            (
                "services".to_string(),
                Value::Array(self.services.iter().map(ServiceRow::to_value).collect()),
            ),
            ("bypass_default".to_string(), strings(&self.bypass_default)),
            ("guidance".to_string(), opt_str(&self.guidance)),
            ("remedy".to_string(), opt_str(&self.remedy)),
            (
                "last_change_ms".to_string(),
                self.last_change_ms.map_or(Value::Null, Value::Int),
            ),
            (
                "watchdog_pid".to_string(),
                self.watchdog_pid
                    .map_or(Value::Null, |pid| Value::Int(i64::from(pid))),
            ),
            (
                "state_file".to_string(),
                Value::Str(self.state_file.to_string_lossy().into_owned()),
            ),
        ]);
        if let State::Other { host, port } = &self.state {
            map.insert("host".to_string(), Value::Str(host.clone()));
            map.insert("port".to_string(), Value::Int(i64::from(*port)));
        }
        Value::Object(map)
    }

    /// The compact view of this status.
    pub fn summary(&self) -> Summary {
        let (host, port) = self.state.endpoint();
        Summary {
            state: self.state.clone(),
            host,
            port,
            managed_by_us: self.managed_by_us,
            setting: self.setting,
            supported: self.supported,
            detail: self.detail.clone(),
        }
    }
}

/// `proxy.system.unset`'s per-service outcome (§D6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsetOutcome {
    pub restored: Vec<String>,
    pub left_alone: Vec<String>,
    pub status: Status,
}

/// Why a read produced no `Effective`/rows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadError {
    /// The OS would not answer (sandbox, `AuthorizationCreate() failed`, an
    /// empty `scutil` dictionary): maps to `State::Unknown`, never `Off`.
    Unavailable(String),
    ToolMissing(String),
    Failed(String),
}

impl fmt::Display for ReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReadError::Unavailable(m) => write!(f, "system proxy unavailable: {m}"),
            ReadError::ToolMissing(m) => write!(f, "tool missing: {m}"),
            ReadError::Failed(m) => write!(f, "read failed: {m}"),
        }
    }
}

impl std::error::Error for ReadError {}

/// Why a write or restore stopped. `NeedsPrivilege` carries the remedy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WriteError {
    NeedsPrivilege(String),
    ToolMissing(String),
    Failed(String),
    /// The command outlived the mutate timeout; the message names the
    /// rendered line.
    Hung(String),
}

impl fmt::Display for WriteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WriteError::NeedsPrivilege(m) => write!(f, "needs privilege: {m}"),
            WriteError::ToolMissing(m) => write!(f, "tool missing: {m}"),
            WriteError::Failed(m) => write!(f, "write failed: {m}"),
            WriteError::Hung(m) => write!(f, "command hung: {m}"),
        }
    }
}

impl std::error::Error for WriteError {}

/// The default bypass list (§D5), always part of what a set writes.
pub const BYPASS_DEFAULT: [&str; 5] = ["localhost", "127.0.0.1", "::1", "*.local", "169.254/16"];
pub const STATE_FILE_NAME: &str = "system-proxy-state.json";
pub const WATCHDOG_LOG_NAME: &str = "system-proxy-watchdog.log";

/// The §D3 privilege sentence; `{ours}` is filled by [`remedy`].
pub const NEEDS_PRIVILEGE_REMEDY: &str = "macOS asks for an administrator to change network settings on this Mac (a standard user, or “Require an administrator password to access system-wide settings” is on under System Settings ▸ Privacy & Security ▸ Advanced). Turn that option off or sign in as an administrator, or set HTTP and HTTPS to {ours} under System Settings ▸ Network ▸ <service> ▸ Details ▸ Proxies.";

/// [`NEEDS_PRIVILEGE_REMEDY`] with the real host:port.
pub fn remedy(ours: &Endpoint) -> String {
    NEEDS_PRIVILEGE_REMEDY.replace("{ours}", &ours.to_string())
}

/// The §D4 env-var line shown (never run) when the mechanism is `none`.
pub fn guidance_line(ours: &Endpoint) -> String {
    format!(
        "export http_proxy=http://{ours} https_proxy=http://{ours} no_proxy=localhost,127.0.0.1,::1"
    )
}

/// The host we write (§D3): `127.0.0.1` when the listen address is loopback
/// or unspecified (`0.0.0.0`, `::`), otherwise the listen IP literal.
pub fn ours_from(listen: SocketAddr) -> Endpoint {
    let ip = listen.ip();
    let host = if ip.is_loopback() || ip.is_unspecified() {
        "127.0.0.1".to_string()
    } else {
        ip.to_string()
    };
    Endpoint {
        host,
        port: listen.port(),
    }
}

/// Hosts that count as "us" next to the literal we write (§D3).
fn is_our_host(host: &str, ours: &Endpoint) -> bool {
    matches!(host, "127.0.0.1" | "localhost" | "::1" | "[::1]") || host == ours.host
}

fn at_us(p: &ProtocolProxy, ours: &Endpoint) -> bool {
    p.enabled && p.port == ours.port && is_our_host(&p.host, ours)
}

fn arrow(p: &ProtocolProxy) -> String {
    if p.enabled {
        format!("→ {}:{}", p.host, p.port)
    } else {
        "off".to_string()
    }
}

/// The §D3 rule, with the `detail` the frontends show. `points_at_us` needs
/// both protocols enabled on our port at one of our hosts; a partial state
/// is `other` naming which protocol goes where (C4: both off is
/// "HTTP and HTTPS off").
pub fn classify(effective: &Effective, ours: &Endpoint) -> (State, String) {
    let http = &effective.http;
    let https = &effective.https;
    if !http.enabled && !https.enabled {
        return (State::Off, "HTTP and HTTPS off".to_string());
    }
    if at_us(http, ours) && at_us(https, ours) {
        return (
            State::PointsAtUs,
            format!("HTTP and HTTPS → {}:{} (this core)", http.host, http.port),
        );
    }
    let pointed = if http.enabled { http } else { https };
    let state = State::Other {
        host: pointed.host.clone(),
        port: pointed.port,
    };
    let same = http.enabled && https.enabled && http.host == https.host && http.port == https.port;
    let detail = if same {
        format!(
            "HTTP and HTTPS → {}:{} (not this core)",
            http.host, http.port
        )
    } else {
        format!("HTTP {}, HTTPS {}", arrow(http), arrow(https))
    };
    (state, detail)
}

/// C3: a service still equals what we wrote when both protocol endpoints
/// (`enabled`, `host`, `port`) match; the bypass list is not compared.
pub fn service_equals_wrote(row: &ServiceRow, wrote: &Wrote) -> bool {
    [&row.http, &row.https]
        .iter()
        .all(|p| p.enabled && p.host == wrote.host && p.port == wrote.port)
}

/// §D5: the ordered, de-duplicated union, `previous` first.
pub fn merge_bypass(previous: &[String], extra: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::with_capacity(previous.len() + extra.len());
    for host in previous.iter().chain(extra) {
        if !out.contains(host) {
            out.push(host.clone());
        }
    }
    out
}

fn strings(items: &[String]) -> Value {
    Value::Array(items.iter().map(|s| Value::Str(s.clone())).collect())
}

fn opt_str(s: &Option<String>) -> Value {
    s.as_ref().map_or(Value::Null, |s| Value::Str(s.clone()))
}

fn opt_port(p: Option<u16>) -> Value {
    p.map_or(Value::Null, |p| Value::Int(i64::from(p)))
}

// ---- the engine ---------------------------------------------------------------

/// How long a [`SystemProxy::summary`] is served from the cache (§D6).
pub const SUMMARY_TTL: Duration = Duration::from_secs(5);
/// `unset` with no state file (§D6).
pub const NOT_MANAGED_DETAIL: &str = "not managed by this core; nothing to restore";
/// A second `set`/`unset` while one is running (§D6).
pub const IN_FLIGHT_MSG: &str = "a system-proxy change is already in flight";
/// The `unsupported` detail on a Linux (or other non-Windows) host where
/// §D4's table matched nothing; `guidance` carries the env-var line.
pub const NO_MECHANISM_DETAIL: &str =
    "no supported system-proxy mechanism on this host (needs gsettings with a session bus, or KDE's kwriteconfig)";

/// What [`SystemProxy::recover_at_startup`] (§D9 (c)) and
/// [`SystemProxy::on_orderly_exit`] (§D9 (a)) did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Recovery {
    /// No file and `auto` off; or nothing of ours to restore at exit.
    Nothing,
    /// `auto` set the proxy (directly, or after a restore/forget of a
    /// leftover file); the status after the set (boxed: `Status` is large).
    Set(Box<Status>),
    /// A leftover file of this very endpoint was adopted: `pid` is the core
    /// pid now stamped in it, and a watchdog was spawned.
    Adopted { pid: u32 },
    /// The services still equal to `wrote` were restored from the file and
    /// the file removed; the rest were another tool's and left alone.
    Restored {
        restored: Vec<String>,
        left_alone: Vec<String>,
    },
    /// Another tool owns every service the file listed; the file was removed.
    Forgot,
    /// Something could not be done; the state file is kept whenever it
    /// still names a setting to restore.
    Failed(String),
}

/// The one implementation behind `proxy.system.*` (§D2). Reads and writes
/// go through the executor and the detected [`PlatformOps`]; the state file
/// is written before the first mutating command and removed after a
/// completed restore; the watchdog is spawned on every successful set.
pub struct SystemProxy {
    exec: Arc<dyn Executor>,
    ops: Box<dyn PlatformOps>,
    /// The `std::env::consts::OS` word detection ran with; picks the
    /// `unsupported` detail.
    target_os: String,
    state_file: PathBuf,
    ours: Endpoint,
    /// `system_proxy.bypass` from the config, merged into every set (§D5).
    config_bypass: Vec<String>,
    /// Our own executable, for `aitm sysproxy-watchdog`; `None` disables the
    /// watchdog (tests, and a core that cannot find itself).
    watchdog_exe: Option<PathBuf>,
    in_flight: AtomicBool,
    /// `NeedsPrivilege` is sticky until a later write succeeds (§D3).
    needs_privilege: AtomicBool,
    watchdog: Mutex<Option<WatchdogHandle>>,
    cache: Mutex<Option<(Instant, Summary)>>,
    last_change_ms: Mutex<Option<i64>>,
}

/// Lock a mutex that only guards bookkeeping; a poisoned one still holds
/// usable data, so recover it rather than panic.
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Clears `in_flight` when a `set`/`unset` returns, on every path.
struct InFlight<'a>(&'a AtomicBool);

impl Drop for InFlight<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

fn defaults() -> Vec<String> {
    BYPASS_DEFAULT.iter().map(|s| s.to_string()).collect()
}

fn elapsed_ms(started: Instant) -> i64 {
    i64::try_from(started.elapsed().as_millis()).unwrap_or(i64::MAX)
}

impl SystemProxy {
    /// Detection for this host: `std::env::consts::OS` and the real
    /// environment. Runs no command (plan C2).
    pub fn detect(
        exec: Arc<dyn Executor>,
        cfg: &SystemProxyConfig,
        ours: Endpoint,
        watchdog_exe: Option<PathBuf>,
    ) -> SystemProxy {
        Self::detect_with(
            exec,
            cfg,
            ours,
            watchdog_exe,
            std::env::consts::OS,
            &|name| std::env::var(name).ok(),
        )
    }

    /// The testable form: `macos` → `networksetup`; `linux` → the §D4 table
    /// over `env` and a `PATH` probe (`Path::is_file` on each `PATH` entry);
    /// anything else → `none`. Runs no command.
    pub fn detect_with(
        exec: Arc<dyn Executor>,
        cfg: &SystemProxyConfig,
        ours: Endpoint,
        watchdog_exe: Option<PathBuf>,
        target_os: &str,
        env: &dyn Fn(&str) -> Option<String>,
    ) -> SystemProxy {
        let ops: Box<dyn PlatformOps> = match target_os {
            "macos" => Box::new(platform::macos::MacosOps),
            "linux" => {
                let path = env("PATH").unwrap_or_default();
                let on_path = |tool: &str| {
                    std::env::split_paths(&path)
                        .any(|dir| !dir.as_os_str().is_empty() && dir.join(tool).is_file())
                };
                platform::linux::detect(target_os, env, &on_path)
                    .ops()
                    .unwrap_or_else(|| Box::new(platform::windows::NoneOps))
            }
            _ => Box::new(platform::windows::NoneOps),
        };
        Self::with_ops(exec, cfg, ours, watchdog_exe, target_os, ops)
    }

    /// A fixed mechanism on this host's OS word (plan C2): lets another
    /// crate's tests drive Linux ops on a macOS host. A bare `Kde` assumes
    /// the `kwriteconfig6` tools (see `platform::ops_for`).
    pub fn with_mechanism(
        exec: Arc<dyn Executor>,
        cfg: &SystemProxyConfig,
        ours: Endpoint,
        watchdog_exe: Option<PathBuf>,
        mechanism: Mechanism,
    ) -> SystemProxy {
        Self::with_ops(
            exec,
            cfg,
            ours,
            watchdog_exe,
            std::env::consts::OS,
            ops_for(mechanism),
        )
    }

    /// Exact ops and OS word; the constructor everything else goes through.
    pub(crate) fn with_ops(
        exec: Arc<dyn Executor>,
        cfg: &SystemProxyConfig,
        ours: Endpoint,
        watchdog_exe: Option<PathBuf>,
        target_os: &str,
        ops: Box<dyn PlatformOps>,
    ) -> SystemProxy {
        // `config_file::parse_settings` always fills `state_file` (plan C6);
        // a bare config falls back to the file name in the working directory.
        let state_file = cfg
            .state_file
            .clone()
            .unwrap_or_else(|| PathBuf::from(STATE_FILE_NAME));
        SystemProxy {
            exec,
            ops,
            target_os: target_os.to_string(),
            state_file,
            ours,
            config_bypass: cfg.bypass.clone(),
            watchdog_exe,
            in_flight: AtomicBool::new(false),
            needs_privilege: AtomicBool::new(false),
            watchdog: Mutex::new(None),
            cache: Mutex::new(None),
            last_change_ms: Mutex::new(None),
        }
    }

    pub fn mechanism(&self) -> Mechanism {
        self.ops.mechanism()
    }

    pub fn state_file(&self) -> &Path {
        &self.state_file
    }

    pub fn ours(&self) -> &Endpoint {
        &self.ours
    }

    /// A set or unset is running in this process (§D6 `setting`).
    pub fn is_setting(&self) -> bool {
        self.in_flight.load(Ordering::SeqCst)
    }

    fn supported(&self) -> bool {
        self.mechanism() != Mechanism::None
    }

    fn unsupported_detail(&self) -> String {
        if self.target_os == "windows" {
            platform::windows::NOT_MANAGED.to_string()
        } else {
            NO_MECHANISM_DETAIL.to_string()
        }
    }

    /// Every field but the ones the read fills.
    fn blank_status(&self, state: State, detail: String, setting: bool) -> Status {
        Status {
            state,
            detail,
            ours: self.ours.clone(),
            mechanism: self.mechanism(),
            supported: self.supported(),
            managed_by_us: false,
            setting,
            effective: None,
            services: Vec::new(),
            bypass_default: defaults(),
            guidance: None,
            remedy: None,
            last_change_ms: *lock(&self.last_change_ms),
            watchdog_pid: None,
            state_file: self.state_file.clone(),
        }
    }

    fn unsupported_status(&self, setting: bool) -> Status {
        let mut status = self.blank_status(State::Unsupported, self.unsupported_detail(), setting);
        status.guidance = Some(guidance_line(&self.ours));
        status
    }

    /// The state file, or `None` when absent or quarantined (a failed
    /// quarantine is logged and treated as absent here; the mutating verbs
    /// surface it as an error).
    fn load_file(&self) -> Option<StateFile> {
        match StateFile::load(&self.state_file) {
            Ok(file) => file,
            Err(e) => {
                tracing::warn!(target: "aitm_sysproxy", error = %e, "state file unreadable; treated as absent");
                None
            }
        }
    }

    /// The pid of a live watchdog from this process, if any.
    fn watchdog_pid(&self) -> Option<u32> {
        let mut guard = lock(&self.watchdog);
        let alive = guard.as_mut().is_some_and(WatchdogHandle::is_alive);
        if !alive {
            // A dead or exited watchdog is forgotten, so the next set spawns one.
            *guard = None;
        }
        guard.as_ref().map(WatchdogHandle::pid)
    }

    /// The §D3 sticky override: `needs_privilege` with the remedy sentence.
    fn apply_sticky(&self, status: &mut Status) {
        if self.needs_privilege.load(Ordering::SeqCst) {
            status.state = State::NeedsPrivilege;
            status.remedy = Some(remedy(&self.ours));
        }
    }

    /// `proxy.system.status`: a fresh read of the effective view and, where
    /// the mechanism has them, the per-service rows (§D6).
    pub fn status(&self) -> Status {
        self.read_status(self.is_setting())
    }

    fn read_status(&self, setting: bool) -> Status {
        if !self.supported() {
            return self.unsupported_status(setting);
        }
        let file = self.load_file();
        let mut status = match self.ops.read_effective(self.exec.as_ref()) {
            Ok(effective) => {
                let (state, detail) = classify(&effective, &self.ours);
                let mut status = self.blank_status(state, detail, setting);
                status.effective = Some(effective);
                // macOS rows are reported; Linux's synthetic rows only judge
                // `managed_by_us` (§D6: `services` is empty on Linux), so
                // they are read only when there is a file to judge against.
                let is_macos = self.mechanism() == Mechanism::Networksetup;
                if is_macos || file.is_some() {
                    if let Ok(live) = self.ops.read_services(self.exec.as_ref()) {
                        if let Some(file) = &file {
                            status.managed_by_us = all_still_ours(file, &live);
                        }
                        if is_macos {
                            status.services = live;
                        }
                    }
                }
                status
            }
            Err(e) => self.blank_status(State::Unknown, e.to_string(), setting),
        };
        if status.managed_by_us {
            status.watchdog_pid = self.watchdog_pid();
        }
        self.apply_sticky(&mut status);
        status
    }

    /// The compact view for `proxy.status` (§D6): served from the cache when
    /// it is at most [`SUMMARY_TTL`] old, else one `scutil --proxy` / six
    /// `gsettings get` and no per-service read. `set`/`unset`/recovery
    /// refresh it at once. `setting` is always live.
    pub fn summary(&self) -> Summary {
        let setting = self.is_setting();
        if let Some((at, cached)) = lock(&self.cache).as_ref() {
            if at.elapsed() <= SUMMARY_TTL {
                return Summary {
                    setting,
                    ..cached.clone()
                };
            }
        }
        let fresh = self.light_summary(setting);
        *lock(&self.cache) = Some((Instant::now(), fresh.clone()));
        fresh
    }

    fn light_summary(&self, setting: bool) -> Summary {
        if !self.supported() {
            return self.unsupported_status(setting).summary();
        }
        let mut status = match self.ops.read_effective(self.exec.as_ref()) {
            Ok(effective) => {
                let (state, detail) = classify(&effective, &self.ours);
                let mut status = self.blank_status(state, detail, setting);
                // Without per-service rows, "managed" is: a file exists and
                // the effective view still equals what it says we wrote.
                if let Some(file) = self.load_file() {
                    let row = ServiceRow {
                        service: String::new(),
                        http: effective.http.clone(),
                        https: effective.https.clone(),
                        bypass: Vec::new(),
                    };
                    status.managed_by_us = service_equals_wrote(&row, &file.wrote);
                }
                status
            }
            Err(e) => self.blank_status(State::Unknown, e.to_string(), setting),
        };
        self.apply_sticky(&mut status);
        status.summary()
    }

    fn refresh_cache(&self, status: &Status) {
        let mut summary = status.summary();
        summary.setting = false;
        *lock(&self.cache) = Some((Instant::now(), summary));
    }

    /// Take the in-flight flag or refuse (§D6).
    fn begin(&self) -> anyhow::Result<InFlight<'_>> {
        if self
            .in_flight
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            anyhow::bail!(IN_FLIGHT_MSG);
        }
        Ok(InFlight(&self.in_flight))
    }

    /// Spawn the watchdog (§D9 (b)) unless one from this process is alive
    /// or no executable was given. A spawn failure is logged, not fatal: the
    /// orderly exit and the next start still restore.
    fn ensure_watchdog(&self) {
        let Some(exe) = &self.watchdog_exe else {
            return;
        };
        let mut guard = lock(&self.watchdog);
        if guard.as_mut().is_some_and(WatchdogHandle::is_alive) {
            return;
        }
        match watchdog::spawn(exe, std::process::id(), &self.state_file) {
            Ok(handle) => {
                tracing::debug!(target: "aitm_sysproxy", pid = handle.pid(), "watchdog spawned");
                *guard = Some(handle);
            }
            Err(e) => {
                tracing::warn!(target: "aitm_sysproxy", error = %e, exe = %exe.display(), "could not spawn the system-proxy watchdog");
                *guard = None;
            }
        }
    }

    fn log_commands(lines: &[String]) {
        for line in lines {
            tracing::debug!(target: "aitm_sysproxy", command = %line);
        }
    }

    /// `proxy.system.set` (§D6). Returns the status after the write, whether
    /// anything was written, and the rendered lines that ran.
    ///
    /// Idempotent when the effective state already points at us and a state
    /// file exists. `needs_privilege` and `unsupported` are `Ok` with the
    /// state; a tool that cannot start or hangs, a change already in
    /// flight, and a rollback that failed are `Err`.
    pub fn set(&self, req: &SetRequest) -> anyhow::Result<(Status, bool, Vec<String>)> {
        let _guard = self.begin()?;
        if !self.supported() {
            let status = self.unsupported_status(false);
            self.refresh_cache(&status);
            return Ok((status, false, Vec::new()));
        }
        let existing = StateFile::load(&self.state_file)?;
        if existing.is_some() {
            let status = self.read_status(false);
            if status.state == State::PointsAtUs {
                self.refresh_cache(&status);
                return Ok((status, false, Vec::new()));
            }
        }

        let Snapshot { previous, skipped } = self
            .ops
            .snapshot(self.exec.as_ref())
            .map_err(|e| anyhow::anyhow!("cannot snapshot the current system proxy: {e}"))?;
        let extra = merge_bypass(&self.config_bypass, &req.bypass);
        let wrote = Wrote {
            host: self.ours.host.clone(),
            port: self.ours.port,
            bypass: merge_bypass(&defaults(), &extra),
        };
        let file = StateFile::new(self.mechanism(), std::process::id(), wrote, previous);
        // §D7: on disk before the first mutating command.
        file.save_atomic(&self.state_file)?;

        let started = Instant::now();
        match self
            .ops
            .write(self.exec.as_ref(), &file.previous, &self.ours, &extra)
        {
            Ok(lines) => {
                let ms = elapsed_ms(started);
                *lock(&self.last_change_ms) = Some(ms);
                self.needs_privilege.store(false, Ordering::SeqCst);
                Self::log_commands(&lines);
                self.ensure_watchdog();
                let mut status = self.read_status(false);
                for service in &skipped {
                    status.detail =
                        format!("{}; skipped {service}: authenticated proxy", status.detail);
                }
                tracing::info!(
                    target: "aitm_sysproxy",
                    outcome = "set",
                    ours = %self.ours,
                    services = file.service_names().len(),
                    skipped = skipped.len(),
                    ms,
                    "system proxy → {}",
                    self.ours
                );
                self.refresh_cache(&status);
                Ok((status, true, lines))
            }
            Err(WriteError::NeedsPrivilege(_)) => {
                // Nothing of ours is on the OS; the file must not claim otherwise.
                if let Err(e) = StateFile::remove(&self.state_file) {
                    tracing::warn!(target: "aitm_sysproxy", error = %e, "could not remove the state file after a privilege refusal");
                }
                self.needs_privilege.store(true, Ordering::SeqCst);
                let status = self.read_status(false);
                tracing::info!(target: "aitm_sysproxy", outcome = "needs_privilege", "system proxy not set: macOS asks for an administrator");
                self.refresh_cache(&status);
                Ok((status, false, Vec::new()))
            }
            Err(e) => self.roll_back(&file, e),
        }
    }

    /// Plan C7: `write` says nothing about how far it got, so every service
    /// in `previous` is restored (writing back an unchanged value is safe),
    /// then the file is removed. A rollback failure keeps the file and is
    /// an `Err` naming it.
    fn roll_back(
        &self,
        file: &StateFile,
        cause: WriteError,
    ) -> anyhow::Result<(Status, bool, Vec<String>)> {
        let names = file.service_names();
        let path = self.state_file.display();
        match self.ops.restore(self.exec.as_ref(), &file.previous, &names) {
            Ok(lines) => {
                Self::log_commands(&lines);
                StateFile::remove(&self.state_file).map_err(|e| {
                    anyhow::anyhow!(
                        "{cause}; rolled back, but the state file {path} could not be removed: {e}"
                    )
                })?;
                tracing::warn!(target: "aitm_sysproxy", outcome = "rolled_back", error = %cause, services = names.len(), "system proxy write failed; previous setting restored");
                match cause {
                    WriteError::Failed(message) => {
                        let mut status = self.read_status(false);
                        status.state = State::Unknown;
                        status.detail = message;
                        if matches!(self.mechanism(), Mechanism::Gsettings | Mechanism::Kde) {
                            // §D4: the env-var line is the fallback when the
                            // desktop keys cannot be relied on.
                            status.guidance = Some(guidance_line(&self.ours));
                        }
                        self.refresh_cache(&status);
                        Ok((status, false, lines))
                    }
                    other => Err(anyhow::anyhow!(
                        "{other}; the previous system proxy setting was restored"
                    )),
                }
            }
            Err(rollback) => {
                if matches!(rollback, WriteError::NeedsPrivilege(_)) {
                    self.needs_privilege.store(true, Ordering::SeqCst);
                }
                tracing::error!(target: "aitm_sysproxy", error = %cause, rollback_error = %rollback, file = %path, "system proxy write failed and the rollback failed; state file kept");
                Err(anyhow::anyhow!(
                    "{cause}; rolling back failed too ({rollback}); the previous setting is kept in {path}: run `aitm proxy system unset` to restore it"
                ))
            }
        }
    }

    /// `proxy.system.unset` (§D6): restore the services that still equal
    /// what we wrote, leave the rest (another tool took them over), remove
    /// the file. With no file: a no-op that says why in `detail`.
    pub fn unset(&self) -> anyhow::Result<(UnsetOutcome, bool, Vec<String>)> {
        let _guard = self.begin()?;
        let Some(file) = StateFile::load(&self.state_file)? else {
            let mut status = self.read_status(false);
            status.detail = NOT_MANAGED_DETAIL.to_string();
            self.refresh_cache(&status);
            return Ok((
                UnsetOutcome {
                    restored: Vec::new(),
                    left_alone: Vec::new(),
                    status,
                },
                false,
                Vec::new(),
            ));
        };
        let path = self.state_file.display();
        let live = self.ops.read_services(self.exec.as_ref()).map_err(|e| {
            anyhow::anyhow!(
                "cannot read the system proxy to judge what to restore: {e}; the state file {path} is kept"
            )
        })?;
        let (only, left_alone) = partition(&file, &live);
        let started = Instant::now();
        let lines = match self.ops.restore(self.exec.as_ref(), &file.previous, &only) {
            Ok(lines) => lines,
            Err(WriteError::NeedsPrivilege(_)) => {
                self.needs_privilege.store(true, Ordering::SeqCst);
                let status = self.read_status(false);
                tracing::info!(target: "aitm_sysproxy", outcome = "needs_privilege", "system proxy not restored: macOS asks for an administrator; state file kept");
                self.refresh_cache(&status);
                return Ok((
                    UnsetOutcome {
                        restored: Vec::new(),
                        left_alone: Vec::new(),
                        status,
                    },
                    false,
                    Vec::new(),
                ));
            }
            Err(e) => {
                anyhow::bail!("{e}; the state file {path} is kept so a later unset can retry")
            }
        };
        let ms = elapsed_ms(started);
        *lock(&self.last_change_ms) = Some(ms);
        self.needs_privilege.store(false, Ordering::SeqCst);
        Self::log_commands(&lines);
        StateFile::remove(&self.state_file)?;
        // The watchdog sees the file gone and exits on its own; closing our
        // end of its stdin wakes it now rather than at our exit.
        *lock(&self.watchdog) = None;
        tracing::info!(
            target: "aitm_sysproxy",
            outcome = "unset",
            restored = only.len(),
            left_alone = left_alone.len(),
            ms,
            "system proxy restored from {path}"
        );
        let status = self.read_status(false);
        self.refresh_cache(&status);
        let changed = !lines.is_empty();
        Ok((
            UnsetOutcome {
                restored: only,
                left_alone,
                status,
            },
            changed,
            lines,
        ))
    }

    /// §D9 (c), the next-start table, before serving:
    ///
    /// | File | Live vs `wrote` | `auto` | Action |
    /// |---|---|---|---|
    /// | absent | — | off | nothing |
    /// | absent | — | on | set |
    /// | present | equal, `wrote` endpoint == ours | on | adopt: keep the file, update `pid`, spawn a watchdog |
    /// | present | equal | off, or endpoint differs | restore, remove file; then set if `auto` |
    /// | present | not equal (another tool took over) | any | remove file; then set if `auto` |
    ///
    /// A file where only some services still equal `wrote` restores those
    /// and leaves the rest, as `unset` would. When `auto` makes a set
    /// follow a restore or a forget, the set's outcome is returned (the
    /// restore/forget is logged).
    pub fn recover_at_startup(&self, auto: bool) -> Recovery {
        let file = match StateFile::load(&self.state_file) {
            Ok(file) => file,
            Err(e) => return Recovery::Failed(e.to_string()),
        };
        let Some(file) = file else {
            return if auto {
                self.set_for_recovery()
            } else {
                Recovery::Nothing
            };
        };
        let path = self.state_file.display();
        if !self.supported() {
            return Recovery::Failed(format!(
                "state file {path} present but no mechanism can restore it on this host"
            ));
        }
        let live = match self.ops.read_services(self.exec.as_ref()) {
            Ok(live) => live,
            Err(e) => {
                return Recovery::Failed(format!(
                    "cannot read the system proxy to judge {path}: {e}; the file is kept"
                ))
            }
        };
        let (only, left_alone) = partition(&file, &live);
        let same_endpoint = file.wrote.host == self.ours.host && file.wrote.port == self.ours.port;
        if left_alone.is_empty() && auto && same_endpoint {
            let adopted = StateFile {
                pid: std::process::id(),
                ..file
            };
            if let Err(e) = adopted.save_atomic(&self.state_file) {
                return Recovery::Failed(format!("cannot adopt {path}: {e}"));
            }
            self.ensure_watchdog();
            tracing::info!(target: "aitm_sysproxy", outcome = "adopted", services = adopted.service_names().len(), "system proxy: adopted the setting in {path}");
            let status = self.read_status(false);
            self.refresh_cache(&status);
            return Recovery::Adopted { pid: adopted.pid };
        }
        if only.is_empty() {
            if let Err(e) = StateFile::remove(&self.state_file) {
                return Recovery::Failed(format!("cannot remove {path}: {e}"));
            }
            tracing::info!(target: "aitm_sysproxy", outcome = "forgot", left_alone = left_alone.len(), "system proxy: another tool owns the system proxy; forgot {path}");
            if auto {
                return self.set_for_recovery();
            }
            let status = self.read_status(false);
            self.refresh_cache(&status);
            return Recovery::Forgot;
        }
        let started = Instant::now();
        match self.ops.restore(self.exec.as_ref(), &file.previous, &only) {
            Ok(lines) => Self::log_commands(&lines),
            Err(e) => {
                if matches!(e, WriteError::NeedsPrivilege(_)) {
                    self.needs_privilege.store(true, Ordering::SeqCst);
                }
                return Recovery::Failed(format!("{e}; the state file {path} is kept"));
            }
        }
        let ms = elapsed_ms(started);
        *lock(&self.last_change_ms) = Some(ms);
        if let Err(e) = StateFile::remove(&self.state_file) {
            return Recovery::Failed(format!("restored, but cannot remove {path}: {e}"));
        }
        tracing::info!(
            target: "aitm_sysproxy",
            outcome = "restored",
            restored = only.len(),
            left_alone = left_alone.len(),
            ms,
            "system proxy: restored previous setting from {path}"
        );
        if auto {
            return self.set_for_recovery();
        }
        let status = self.read_status(false);
        self.refresh_cache(&status);
        Recovery::Restored {
            restored: only,
            left_alone,
        }
    }

    fn set_for_recovery(&self) -> Recovery {
        match self.set(&SetRequest::default()) {
            Ok((status, _, _)) => Recovery::Set(Box::new(status)),
            Err(e) => Recovery::Failed(e.to_string()),
        }
    }

    /// §D9 (a): on SIGINT/SIGTERM/stdin EOF, restore whatever the file says
    /// is ours and remove it, whether or not `auto` is on. No file: nothing.
    pub fn on_orderly_exit(&self) -> Recovery {
        match StateFile::load(&self.state_file) {
            Ok(None) => return Recovery::Nothing,
            Ok(Some(_)) => {}
            Err(e) => return Recovery::Failed(e.to_string()),
        }
        match self.unset() {
            Ok((outcome, _, _)) => {
                if outcome.status.state == State::NeedsPrivilege {
                    return Recovery::Failed(
                        outcome
                            .status
                            .remedy
                            .unwrap_or_else(|| "needs privilege".to_string()),
                    );
                }
                if outcome.restored.is_empty() && !outcome.left_alone.is_empty() {
                    return Recovery::Forgot;
                }
                Recovery::Restored {
                    restored: outcome.restored,
                    left_alone: outcome.left_alone,
                }
            }
            Err(e) => Recovery::Failed(e.to_string()),
        }
    }
}

/// The §D6 unset rule over a file and a live read: the services still equal
/// to `wrote` (to restore) and the rest (to leave alone). One implementation
/// with the watchdog's: [`watchdog::decide`].
fn partition(file: &StateFile, live: &[ServiceRow]) -> (Vec<String>, Vec<String>) {
    match decide(Some(file), live) {
        Decision::Restore { only, left_alone } => (only, left_alone),
        Decision::Exit0 => (Vec::new(), Vec::new()),
    }
}

/// `managed_by_us` (§D6): every service the file lists still equals `wrote`.
fn all_still_ours(file: &StateFile, live: &[ServiceRow]) -> bool {
    let (_, left_alone) = partition(file, live);
    left_alone.is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ours() -> Endpoint {
        Endpoint {
            host: "127.0.0.1".into(),
            port: 8080,
        }
    }

    fn on(host: &str, port: u16) -> ProtocolProxy {
        ProtocolProxy {
            enabled: true,
            host: host.into(),
            port,
        }
    }

    fn off() -> ProtocolProxy {
        ProtocolProxy {
            enabled: false,
            host: String::new(),
            port: 0,
        }
    }

    fn effective(http: ProtocolProxy, https: ProtocolProxy) -> Effective {
        Effective {
            http,
            https,
            bypass: vec!["*.local".into(), "169.254/16".into()],
        }
    }

    /// SP-AC4.
    #[test]
    fn classify_points_at_us_other_partial_off() {
        let ours = ours();

        let (state, detail) = classify(
            &effective(on("127.0.0.1", 8080), on("127.0.0.1", 8080)),
            &ours,
        );
        assert_eq!(state, State::PointsAtUs);
        assert_eq!(detail, "HTTP and HTTPS → 127.0.0.1:8080 (this core)");

        let (state, _) = classify(
            &effective(on("localhost", 8080), on("localhost", 8080)),
            &ours,
        );
        assert_eq!(state, State::PointsAtUs);

        let (state, detail) = classify(
            &effective(on("127.0.0.1", 9090), on("127.0.0.1", 9090)),
            &ours,
        );
        assert_eq!(
            state,
            State::Other {
                host: "127.0.0.1".into(),
                port: 9090
            }
        );
        assert_eq!(detail, "HTTP and HTTPS → 127.0.0.1:9090 (not this core)");

        let (state, detail) = classify(&effective(on("127.0.0.1", 8080), off()), &ours);
        assert_eq!(
            state,
            State::Other {
                host: "127.0.0.1".into(),
                port: 8080
            }
        );
        assert_eq!(detail, "HTTP → 127.0.0.1:8080, HTTPS off");

        let (state, detail) = classify(&effective(off(), off()), &ours);
        assert_eq!(state, State::Off);
        assert_eq!(detail, "HTTP and HTTPS off");
    }

    /// §D5: ordered, de-duplicated union, previous first.
    #[test]
    fn merge_bypass_is_an_ordered_deduplicated_union() {
        let previous: Vec<String> = vec!["*.local".into(), "169.254/16".into()];
        let extra: Vec<String> = [
            "localhost",
            "127.0.0.1",
            "::1",
            "*.local",
            "169.254/16",
            "corp.test",
        ]
        .into_iter()
        .map(String::from)
        .collect();
        assert_eq!(
            merge_bypass(&previous, &extra),
            vec![
                "*.local",
                "169.254/16",
                "localhost",
                "127.0.0.1",
                "::1",
                "corp.test"
            ]
        );
    }

    /// §D4 literal.
    #[test]
    fn guidance_line_is_the_spec_literal() {
        assert_eq!(
            guidance_line(&ours()),
            "export http_proxy=http://127.0.0.1:8080 https_proxy=http://127.0.0.1:8080 no_proxy=localhost,127.0.0.1,::1"
        );
    }

    /// §D3: loopback and unspecified become 127.0.0.1; anything else is the IP literal.
    #[test]
    fn ours_from_maps_loopback_and_unspecified_to_127() {
        let e = ours_from("0.0.0.0:8080".parse().unwrap());
        assert_eq!((e.host.as_str(), e.port), ("127.0.0.1", 8080));
        let e = ours_from("[::]:8080".parse().unwrap());
        assert_eq!((e.host.as_str(), e.port), ("127.0.0.1", 8080));
        let e = ours_from("127.0.0.1:8081".parse().unwrap());
        assert_eq!((e.host.as_str(), e.port), ("127.0.0.1", 8081));
        let e = ours_from("10.0.0.5:8080".parse().unwrap());
        assert_eq!((e.host.as_str(), e.port), ("10.0.0.5", 8080));
    }

    /// SP-AC19's crate half: unknown keys are refused; absent keys default.
    #[test]
    fn config_rejects_unknown_fields_and_defaults_the_rest() {
        assert!(serde_json::from_str::<SystemProxyConfig>(r#"{"nope":true}"#).is_err());
        let cfg: SystemProxyConfig = serde_json::from_str(r#"{"auto":true}"#).unwrap();
        assert_eq!(
            cfg,
            SystemProxyConfig {
                auto: true,
                bypass: vec![],
                state_file: None
            }
        );
        assert!(!SystemProxyConfig::default().auto);
        assert_eq!(
            SystemProxyConfig::default_state_file(std::path::Path::new(
                "/Users/me/Library/Application Support/aitmproxy/ca-audit.log"
            )),
            std::path::PathBuf::from(
                "/Users/me/Library/Application Support/aitmproxy/system-proxy-state.json"
            )
        );
    }

    fn status_with(state: State, detail: &str) -> Status {
        Status {
            state,
            detail: detail.into(),
            ours: ours(),
            mechanism: Mechanism::Networksetup,
            supported: true,
            managed_by_us: false,
            setting: false,
            effective: None,
            services: vec![],
            bypass_default: BYPASS_DEFAULT.iter().map(|s| s.to_string()).collect(),
            guidance: None,
            remedy: None,
            last_change_ms: None,
            watchdog_pid: None,
            state_file: std::path::PathBuf::from("/tmp/x/system-proxy-state.json"),
        }
    }

    /// §D6: `host`/`port` are present only for `other`.
    #[test]
    fn status_to_value_has_host_and_port_only_for_other() {
        use aitm_core::Value;

        let other = status_with(
            State::Other {
                host: "127.0.0.1".into(),
                port: 9090,
            },
            "HTTP and HTTPS → 127.0.0.1:9090 (not this core)",
        );
        let Value::Object(map) = other.to_value() else {
            panic!("status is an object");
        };
        assert_eq!(map.get("state"), Some(&Value::Str("other".into())));
        assert_eq!(map.get("host"), Some(&Value::Str("127.0.0.1".into())));
        assert_eq!(map.get("port"), Some(&Value::Int(9090)));
        assert_eq!(
            map.get("mechanism"),
            Some(&Value::Str("networksetup".into()))
        );
        assert_eq!(map.get("supported"), Some(&Value::Bool(true)));
        assert_eq!(map.get("effective"), Some(&Value::Null));
        assert_eq!(map.get("services"), Some(&Value::Array(vec![])));
        assert_eq!(
            map.get("bypass_default"),
            Some(&Value::Array(
                BYPASS_DEFAULT
                    .iter()
                    .map(|s| Value::Str(s.to_string()))
                    .collect()
            ))
        );
        assert_eq!(
            map.get("state_file"),
            Some(&Value::Str("/tmp/x/system-proxy-state.json".into()))
        );
        for key in [
            "detail",
            "ours",
            "managed_by_us",
            "setting",
            "guidance",
            "remedy",
            "last_change_ms",
            "watchdog_pid",
        ] {
            assert!(map.contains_key(key), "missing {key}");
        }

        let off = status_with(State::Off, "HTTP and HTTPS off");
        let Value::Object(map) = off.to_value() else {
            panic!("status is an object");
        };
        assert_eq!(map.get("state"), Some(&Value::Str("off".into())));
        assert!(!map.contains_key("host"));
        assert!(!map.contains_key("port"));

        // The compact view keeps the nulls explicit (§D6 `proxy.status` example).
        let Value::Object(summary) = off.summary().to_value() else {
            panic!("summary is an object");
        };
        assert_eq!(summary.get("host"), Some(&Value::Null));
        assert_eq!(summary.get("port"), Some(&Value::Null));
        assert_eq!(summary.get("state"), Some(&Value::Str("off".into())));
        assert_eq!(summary.len(), 7);
    }
}

#[cfg(test)]
mod engine_tests {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex};
    use std::time::{SystemTime, UNIX_EPOCH};

    use aitm_ca::exec::{CmdLine, CmdOutput, Executor};
    use aitm_ca::testing::ScriptedExecutor;

    use super::*;
    use crate::platform::windows::{NoneOps, NOT_MANAGED};
    use crate::state::{Previous, StateFile};

    const LIST: &str = "/usr/sbin/networksetup -listallnetworkservices";
    const LIST_OUT: &str = "An asterisk (*) denotes that a network service is disabled.\nDisplay Ethernet\n*Thunderbolt Bridge\nWi-Fi\n";
    const SCUTIL: &str = "/usr/sbin/scutil --proxy";
    const DE: &str = "'Display Ethernet'";
    const WIFI: &str = "Wi-Fi";
    const BYPASS_OUT: &str = "*.local\n169.254/16\n";

    fn ours() -> Endpoint {
        Endpoint {
            host: "127.0.0.1".into(),
            port: 8080,
        }
    }

    fn temp_dir(tag: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after 1970")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("aitm-sysproxy-engine-{tag}-{nanos}"));
        fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    fn strs(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    /// `-getwebproxy` / `-getsecurewebproxy` output; port 0 is "Enabled: No".
    fn proxy_out(host: &str, port: u16) -> String {
        if port == 0 {
            "Enabled: No\nServer: \nPort: 0\nAuthenticated Proxy Enabled: 0\n".to_string()
        } else {
            format!("Enabled: Yes\nServer: {host}\nPort: {port}\nAuthenticated Proxy Enabled: 0\n")
        }
    }

    /// `scutil --proxy` output; port 0 is both disabled.
    fn scutil_out(host: &str, port: u16) -> String {
        if port == 0 {
            return "<dictionary> {\n  HTTPEnable : 0\n  HTTPSEnable : 0\n}\n".to_string();
        }
        format!("<dictionary> {{\n  ExceptionsList : <array> {{\n    0 : *.local\n    1 : 169.254/16\n  }}\n  HTTPEnable : 1\n  HTTPPort : {port}\n  HTTPProxy : {host}\n  HTTPSEnable : 1\n  HTTPSPort : {port}\n  HTTPSProxy : {host}\n}}\n")
    }

    fn get_web(svc: &str) -> String {
        format!("/usr/sbin/networksetup -getwebproxy {svc}")
    }
    fn get_secure(svc: &str) -> String {
        format!("/usr/sbin/networksetup -getsecurewebproxy {svc}")
    }
    fn get_bypass(svc: &str) -> String {
        format!("/usr/sbin/networksetup -getproxybypassdomains {svc}")
    }

    /// The list read and the three `-get*` per service, as the engine runs them.
    fn read_round() -> Vec<String> {
        vec![
            LIST.to_string(),
            get_web(DE),
            get_secure(DE),
            get_bypass(DE),
            get_web(WIFI),
            get_secure(WIFI),
            get_bypass(WIFI),
        ]
    }

    /// Queue one round of answers: `Display Ethernet` at `de`, `Wi-Fi` at `wifi`.
    fn answer_round(
        exec: ScriptedExecutor,
        de: (&str, u16),
        wifi: (&str, u16),
    ) -> ScriptedExecutor {
        exec.respond(LIST, 0, LIST_OUT, "")
            .respond(&get_web(DE), 0, &proxy_out(de.0, de.1), "")
            .respond(&get_secure(DE), 0, &proxy_out(de.0, de.1), "")
            .respond(&get_bypass(DE), 0, BYPASS_OUT, "")
            .respond(&get_web(WIFI), 0, &proxy_out(wifi.0, wifi.1), "")
            .respond(&get_secure(WIFI), 0, &proxy_out(wifi.0, wifi.1), "")
            .respond(&get_bypass(WIFI), 0, BYPASS_OUT, "")
    }

    /// The §D7 before-state: `Display Ethernet` at `127.0.0.1:9090`, `Wi-Fi` off.
    fn before_round(exec: ScriptedExecutor) -> ScriptedExecutor {
        answer_round(exec, ("127.0.0.1", 9090), ("", 0))
    }

    fn at_us_round(exec: ScriptedExecutor) -> ScriptedExecutor {
        answer_round(exec, ("127.0.0.1", 8080), ("127.0.0.1", 8080))
    }

    /// The six mutating lines of a set over the §D7 before-state.
    fn set_lines(extra: &str) -> Vec<String> {
        vec![
            format!("/usr/sbin/networksetup -setwebproxy {DE} 127.0.0.1 8080"),
            format!("/usr/sbin/networksetup -setsecurewebproxy {DE} 127.0.0.1 8080"),
            format!("/usr/sbin/networksetup -setproxybypassdomains {DE} *.local 169.254/16 localhost 127.0.0.1 ::1{extra}"),
            format!("/usr/sbin/networksetup -setwebproxy {WIFI} 127.0.0.1 8080"),
            format!("/usr/sbin/networksetup -setsecurewebproxy {WIFI} 127.0.0.1 8080"),
            format!("/usr/sbin/networksetup -setproxybypassdomains {WIFI} *.local 169.254/16 localhost 127.0.0.1 ::1{extra}"),
        ]
    }

    /// SP-AC6: the restore lines for both §D7 services.
    fn restore_lines() -> Vec<String> {
        vec![
            format!("/usr/sbin/networksetup -setwebproxy {DE} 127.0.0.1 9090"),
            format!("/usr/sbin/networksetup -setwebproxystate {DE} on"),
            format!("/usr/sbin/networksetup -setsecurewebproxy {DE} 127.0.0.1 9090"),
            format!("/usr/sbin/networksetup -setsecurewebproxystate {DE} on"),
            format!("/usr/sbin/networksetup -setproxybypassdomains {DE} *.local 169.254/16"),
            format!("/usr/sbin/networksetup -setwebproxystate {WIFI} off"),
            format!("/usr/sbin/networksetup -setsecurewebproxystate {WIFI} off"),
            format!("/usr/sbin/networksetup -setproxybypassdomains {WIFI} *.local 169.254/16"),
        ]
    }

    fn row(service: &str, host: &str, port: u16) -> ServiceRow {
        let p = ProtocolProxy {
            enabled: port != 0,
            host: host.to_string(),
            port,
        };
        ServiceRow {
            service: service.to_string(),
            http: p.clone(),
            https: p,
            bypass: strs(&["*.local", "169.254/16"]),
        }
    }

    /// The §D7 document: both services, `wrote` 127.0.0.1:8080, pid 48213.
    fn d7_file() -> StateFile {
        StateFile::new(
            Mechanism::Networksetup,
            48213,
            Wrote {
                host: "127.0.0.1".into(),
                port: 8080,
                bypass: strs(&["localhost", "127.0.0.1", "::1", "*.local", "169.254/16"]),
            },
            Previous::Networksetup {
                services: vec![
                    row("Display Ethernet", "127.0.0.1", 9090),
                    row("Wi-Fi", "", 0),
                ],
            },
        )
    }

    /// Records `(rendered line, state file exists?)` on every `run` so a test
    /// can prove the file was on disk before the first mutating command.
    struct FileWatch {
        inner: ScriptedExecutor,
        state_file: PathBuf,
        seen: Mutex<Vec<(String, bool)>>,
    }

    impl FileWatch {
        fn seen(&self) -> Vec<(String, bool)> {
            self.seen.lock().unwrap_or_else(|p| p.into_inner()).clone()
        }
        fn runs(&self) -> Vec<String> {
            self.inner.runs()
        }
        fn mutating_runs(&self) -> Vec<String> {
            self.runs()
                .into_iter()
                .filter(|l| l.contains(" -set"))
                .collect()
        }
        fn count(&self, line: &str) -> usize {
            self.runs().iter().filter(|l| l.as_str() == line).count()
        }
    }

    impl Executor for FileWatch {
        fn run(&self, cmd: &CmdLine) -> anyhow::Result<CmdOutput> {
            self.seen
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .push((cmd.render(), self.state_file.exists()));
            self.inner.run(cmd)
        }
        fn read_file(&self, path: &Path) -> anyhow::Result<Option<Vec<u8>>> {
            self.inner.read_file(path)
        }
        fn dir_exists(&self, path: &Path) -> bool {
            self.inner.dir_exists(path)
        }
        fn home_dir(&self) -> Option<PathBuf> {
            self.inner.home_dir()
        }
        fn is_root(&self) -> bool {
            self.inner.is_root()
        }
    }

    struct Rig {
        exec: Arc<FileWatch>,
        sp: SystemProxy,
        dir: PathBuf,
        file: PathBuf,
    }

    impl Drop for Rig {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.dir);
        }
    }

    fn rig(tag: &str, exec: ScriptedExecutor, mechanism: Mechanism) -> Rig {
        let dir = temp_dir(tag);
        let file = dir.join(STATE_FILE_NAME);
        let exec = Arc::new(FileWatch {
            inner: exec.with_real_fs(),
            state_file: file.clone(),
            seen: Mutex::new(Vec::new()),
        });
        let cfg = SystemProxyConfig {
            auto: false,
            bypass: vec![],
            state_file: Some(file.clone()),
        };
        let as_exec: Arc<dyn Executor> = exec.clone();
        let sp = SystemProxy::with_mechanism(as_exec, &cfg, ours(), None, mechanism);
        Rig {
            exec,
            sp,
            dir,
            file,
        }
    }

    fn macos_rig(tag: &str, exec: ScriptedExecutor) -> Rig {
        rig(tag, exec, Mechanism::Networksetup)
    }

    /// SP-AC5: reads, then the six writes, then the verify reads; the file is
    /// on disk before the first `-set*` and round-trips to the §D7 document.
    #[test]
    fn set_runs_reads_then_writes_and_saves_the_file_first() {
        let exec = ScriptedExecutor::new().respond(SCUTIL, 0, &scutil_out("127.0.0.1", 8080), "");
        let exec = at_us_round(before_round(exec));
        let r = macos_rig("ac5", exec);

        let (status, changed, commands) =
            r.sp.set(&SetRequest {
                bypass: strs(&["corp.test"]),
            })
            .expect("set succeeds");

        let mut expected = read_round();
        expected.extend(set_lines(" corp.test"));
        expected.push(SCUTIL.to_string());
        expected.extend(read_round());
        assert_eq!(r.exec.runs(), expected);
        assert!(changed);
        assert_eq!(commands, set_lines(" corp.test"));
        assert_eq!(status.state, State::PointsAtUs);
        assert_eq!(status.detail, "HTTP and HTTPS → 127.0.0.1:8080 (this core)");
        assert!(status.managed_by_us);
        assert!(!status.setting);
        assert_eq!(status.services.len(), 2);
        assert!(status.last_change_ms.is_some());
        assert_eq!(status.state_file, r.file);

        // The file exists at the first `-set` and did not at the read before it.
        let seen = r.exec.seen();
        let first_set = seen
            .iter()
            .position(|(line, _)| line.contains(" -set"))
            .expect("a mutating line ran");
        assert!(seen[first_set].1, "state file exists at the first -set");
        assert!(
            !seen[first_set - 1].1,
            "state file absent at the last read before it: {:?}",
            seen[first_set - 1]
        );

        let file = StateFile::load(&r.file)
            .expect("load")
            .expect("state file present");
        assert_eq!(file.wrote.port, 8080);
        assert_eq!(file.wrote.host, "127.0.0.1");
        assert_eq!(file.pid, std::process::id());
        assert_eq!(file.mechanism, Mechanism::Networksetup);
        let Previous::Networksetup { services } = &file.previous else {
            panic!("networksetup previous, got {:?}", file.previous);
        };
        assert_eq!(services[1].http.host, "");
        assert_eq!(services[0].http.port, 9090);
        let json: serde_json::Value = serde_json::to_value(&file).expect("serialises");
        assert_eq!(json["previous"]["kind"], "networksetup");
        assert_eq!(json["previous"]["services"][1]["http"]["host"], "");
    }

    /// SP-AC7: pointing at us with a file → `changed: false`, zero `-set*` lines.
    #[test]
    fn set_is_idempotent_when_pointing_at_us_with_a_file() {
        let exec = ScriptedExecutor::new().respond(SCUTIL, 0, &scutil_out("127.0.0.1", 8080), "");
        let r = macos_rig("ac7", at_us_round(exec));
        d7_file().save_atomic(&r.file).expect("seed file");

        let (status, changed, commands) = r.sp.set(&SetRequest::default()).expect("set");
        assert!(!changed);
        assert!(commands.is_empty());
        assert_eq!(status.state, State::PointsAtUs);
        assert!(status.managed_by_us);
        assert!(r.exec.mutating_runs().is_empty(), "{:?}", r.exec.runs());
        assert!(r.file.exists());
    }

    /// Pointing at us with NO file (set by hand): snapshot and write anyway so
    /// a restore is possible.
    #[test]
    fn set_adopts_a_hand_set_proxy_without_a_file() {
        let exec = ScriptedExecutor::new().respond(SCUTIL, 0, &scutil_out("127.0.0.1", 8080), "");
        let r = macos_rig("hand-set", at_us_round(exec));

        let (status, changed, commands) = r.sp.set(&SetRequest::default()).expect("set");
        assert!(changed);
        assert_eq!(commands.len(), 6);
        assert_eq!(status.state, State::PointsAtUs);
        assert!(r.file.exists(), "a file exists afterwards");
        assert_eq!(r.exec.mutating_runs().len(), 6);
    }

    /// SP-AC8: partial takeover → only `Wi-Fi` restored, the file removed.
    #[test]
    fn unset_restores_only_the_services_still_ours() {
        let exec = ScriptedExecutor::new().respond(SCUTIL, 0, &scutil_out("10.0.0.5", 3128), "");
        let exec = answer_round(exec, ("10.0.0.5", 3128), ("127.0.0.1", 8080));
        let r = macos_rig("ac8", exec);
        d7_file().save_atomic(&r.file).expect("seed file");

        let (outcome, changed, commands) = r.sp.unset().expect("unset");
        assert_eq!(outcome.restored, vec!["Wi-Fi".to_string()]);
        assert_eq!(outcome.left_alone, vec!["Display Ethernet".to_string()]);
        assert!(changed);
        assert_eq!(commands, restore_lines()[5..].to_vec());
        assert!(
            !r.exec
                .mutating_runs()
                .iter()
                .any(|l| l.contains("Display Ethernet")),
            "{:?}",
            r.exec.mutating_runs()
        );
        assert_eq!(r.exec.mutating_runs(), restore_lines()[5..].to_vec());
        assert!(!r.file.exists(), "state file removed");
        assert!(!outcome.status.managed_by_us);
        assert!(outcome.status.last_change_ms.is_some());
    }

    /// No file: `unset` is a no-op that says why.
    #[test]
    fn unset_without_a_file_is_a_no_op() {
        let exec = ScriptedExecutor::new().respond(SCUTIL, 0, &scutil_out("127.0.0.1", 9090), "");
        let r = macos_rig("unset-nofile", before_round(exec));

        let (outcome, changed, commands) = r.sp.unset().expect("unset");
        assert!(!changed);
        assert!(commands.is_empty());
        assert!(outcome.restored.is_empty());
        assert!(outcome.left_alone.is_empty());
        assert_eq!(
            outcome.status.detail,
            "not managed by this core; nothing to restore"
        );
        assert_eq!(
            outcome.status.state,
            State::Other {
                host: "127.0.0.1".into(),
                port: 9090
            }
        );
        assert!(r.exec.mutating_runs().is_empty());
    }

    /// SP-AC9: the admin error is `Ok`, sticky, leaves no file and no further
    /// `-set*`; a later successful write clears it.
    #[test]
    fn needs_privilege_is_ok_sticky_and_leaves_no_file() {
        let first = format!("/usr/sbin/networksetup -setwebproxy {DE} 127.0.0.1 8080");
        let exec = ScriptedExecutor::new()
            .respond(SCUTIL, 0, &scutil_out("127.0.0.1", 9090), "")
            .respond(SCUTIL, 0, &scutil_out("127.0.0.1", 9090), "")
            .respond(SCUTIL, 0, &scutil_out("127.0.0.1", 8080), "")
            .respond(&first, 1, platform::macos::ADMIN_ERROR, "")
            .respond(&first, 0, "", "");
        let exec = before_round(before_round(before_round(exec)));
        let exec = at_us_round(exec);
        let r = macos_rig("ac9", exec);

        let (status, changed, commands) = r.sp.set(&SetRequest::default()).expect("Ok, not Err");
        assert_eq!(status.state, State::NeedsPrivilege);
        assert_eq!(status.remedy, Some(remedy(&ours())));
        assert!(status.remedy.as_deref().unwrap().contains("127.0.0.1:8080"));
        assert!(!changed);
        assert!(commands.is_empty());
        assert_eq!(r.exec.mutating_runs(), vec![first.clone()]);
        assert!(!r.file.exists(), "no state file left behind");

        // Sticky until a later write succeeds.
        let again = r.sp.status();
        assert_eq!(again.state, State::NeedsPrivilege);
        assert_eq!(again.remedy, Some(remedy(&ours())));
        assert_eq!(
            again.detail,
            "HTTP and HTTPS → 127.0.0.1:9090 (not this core)"
        );
        assert_eq!(r.sp.summary().state, State::NeedsPrivilege);

        let (status, changed, _) = r.sp.set(&SetRequest::default()).expect("second set");
        assert!(changed);
        assert_eq!(status.state, State::PointsAtUs);
        assert_eq!(status.remedy, None);
        assert!(r.file.exists());
    }

    /// SP-AC3 (engine half): the sandbox's empty dictionary is `unknown`, never `off`.
    #[test]
    fn scutil_empty_dictionary_is_unknown_not_off() {
        let exec = ScriptedExecutor::new().respond(SCUTIL, 0, "<dictionary> {\n}\n", "");
        let r = macos_rig("ac3", exec);
        let status = r.sp.status();
        assert_eq!(status.state, State::Unknown);
        assert!(
            status.detail.contains("empty dictionary"),
            "{}",
            status.detail
        );
        assert_eq!(status.effective, None);
        assert!(status.services.is_empty());
        assert!(!status.managed_by_us);
        assert_eq!(r.exec.runs(), vec![SCUTIL.to_string()]);
        assert_eq!(r.sp.summary().state, State::Unknown);
    }

    /// SP-AC10 (guidance half) and gap 3: `none` is `unsupported` with the
    /// env-var line and no shell-out; the Windows sentence only on Windows.
    #[test]
    fn unsupported_carries_guidance_and_runs_nothing() {
        let r = rig("ac10", ScriptedExecutor::new(), Mechanism::None);
        let status = r.sp.status();
        assert_eq!(status.state, State::Unsupported);
        assert_eq!(
            status.guidance.as_deref(),
            Some("export http_proxy=http://127.0.0.1:8080 https_proxy=http://127.0.0.1:8080 no_proxy=localhost,127.0.0.1,::1")
        );
        assert!(!status.supported);
        assert_eq!(status.mechanism, Mechanism::None);
        assert_eq!(status.remedy, None);
        assert!(r.exec.runs().is_empty());

        let summary = r.sp.summary();
        assert_eq!(summary.state, State::Unsupported);
        assert!(!summary.supported);
        let (set_status, changed, commands) = r.sp.set(&SetRequest::default()).expect("Ok");
        assert_eq!(set_status.state, State::Unsupported);
        assert!(!changed);
        assert!(commands.is_empty());
        let (outcome, changed, _) = r.sp.unset().expect("Ok");
        assert!(!changed);
        assert_eq!(outcome.status.state, State::Unsupported);
        assert!(
            r.exec.runs().is_empty(),
            "never a shell-out: {:?}",
            r.exec.runs()
        );
        assert!(!r.file.exists());

        // Linux with nothing detected: the guidance, not the Windows sentence.
        let dir = temp_dir("linux-none");
        let cfg = SystemProxyConfig {
            auto: false,
            bypass: vec![],
            state_file: Some(dir.join(STATE_FILE_NAME)),
        };
        let exec: Arc<dyn Executor> = Arc::new(ScriptedExecutor::new());
        let linux =
            SystemProxy::with_ops(exec.clone(), &cfg, ours(), None, "linux", Box::new(NoneOps));
        let status = linux.status();
        assert_eq!(status.state, State::Unsupported);
        assert_ne!(status.detail, NOT_MANAGED);
        assert!(status.detail.contains("gsettings"), "{}", status.detail);
        assert!(status.guidance.is_some());

        // Windows: the §D11 sentence.
        let windows = SystemProxy::detect_with(exec, &cfg, ours(), None, "windows", &|_| None);
        let status = windows.status();
        assert_eq!(status.state, State::Unsupported);
        assert_eq!(status.detail, "Windows system proxy is not managed yet");
        assert_eq!(status.mechanism, Mechanism::None);
        fs::remove_dir_all(&dir).expect("remove temp dir");
    }

    /// Gap 2: detection is pure over (`target_os`, env, a PATH probe) and runs
    /// no command.
    #[test]
    fn detect_with_picks_the_ops_from_os_env_and_path() {
        let dir = temp_dir("detect");
        let cfg = SystemProxyConfig {
            auto: false,
            bypass: vec![],
            state_file: Some(dir.join(STATE_FILE_NAME)),
        };
        let scripted = Arc::new(ScriptedExecutor::new());
        let exec: Arc<dyn Executor> = scripted.clone();

        let mac = SystemProxy::detect_with(exec.clone(), &cfg, ours(), None, "macos", &|_| None);
        assert_eq!(mac.mechanism(), Mechanism::Networksetup);

        // Linux: `gsettings` is a file on PATH and a display is set → gsettings.
        let bin = dir.join("bin");
        fs::create_dir_all(&bin).expect("bin dir");
        fs::write(bin.join("gsettings"), b"#!/bin/sh\n").expect("fake gsettings");
        let path = bin.to_string_lossy().into_owned();
        let env_with = move |k: &str| match k {
            "PATH" => Some(path.clone()),
            "DISPLAY" => Some(":0".to_string()),
            _ => None,
        };
        let linux = SystemProxy::detect_with(exec.clone(), &cfg, ours(), None, "linux", &env_with);
        assert_eq!(linux.mechanism(), Mechanism::Gsettings);

        // Same env, the tool is not on PATH → none.
        let env_without = |k: &str| match k {
            "PATH" => Some("/nonexistent-aitm".to_string()),
            "DISPLAY" => Some(":0".to_string()),
            _ => None,
        };
        let none =
            SystemProxy::detect_with(exec.clone(), &cfg, ours(), None, "linux", &env_without);
        assert_eq!(none.mechanism(), Mechanism::None);

        let other = SystemProxy::detect_with(exec, &cfg, ours(), None, "freebsd", &|_| None);
        assert_eq!(other.mechanism(), Mechanism::None);
        assert!(scripted.runs().is_empty(), "detection runs no command");
        assert_eq!(mac.state_file(), dir.join(STATE_FILE_NAME).as_path());
        fs::remove_dir_all(&dir).expect("remove temp dir");
    }

    fn gs_get(schema: &str, key: &str) -> String {
        CmdLine {
            program: "/usr/bin/gsettings".into(),
            args: strs(&["get", schema, key]),
            stdin: None,
            mutating: false,
        }
        .render()
    }

    /// SP-AC11 tail: the memory backend keeps `mode` at `'none'` → `unknown`,
    /// `did not persist`, no file, guidance filled, the rollback ran.
    #[test]
    fn gsettings_non_persisting_backend_is_unknown_and_leaves_no_file() {
        let exec = ScriptedExecutor::new()
            .respond(&gs_get("org.gnome.system.proxy", "mode"), 0, "'none'", "")
            .respond(&gs_get("org.gnome.system.proxy.http", "host"), 0, "''", "")
            .respond(
                &gs_get("org.gnome.system.proxy.http", "port"),
                0,
                "8080",
                "",
            )
            .respond(&gs_get("org.gnome.system.proxy.https", "host"), 0, "''", "")
            .respond(&gs_get("org.gnome.system.proxy.https", "port"), 0, "0", "")
            .respond(
                &gs_get("org.gnome.system.proxy", "ignore-hosts"),
                0,
                "['localhost', '127.0.0.0/8', '::1']",
                "",
            );
        let r = rig("ac11", exec, Mechanism::Gsettings);

        let (status, changed, _) = r.sp.set(&SetRequest::default()).expect("Ok, not Err");
        assert_eq!(status.state, State::Unknown);
        assert!(
            status.detail.contains("did not persist"),
            "{}",
            status.detail
        );
        assert!(status.guidance.is_some());
        assert!(!changed);
        assert!(!r.file.exists(), "no state file left");
        // The rollback wrote the previous values back, `mode` last.
        let runs = r.exec.runs();
        let manual = runs
            .iter()
            .position(|l| l.ends_with("mode 'manual'"))
            .expect("the manual switch ran");
        let back = runs
            .iter()
            .rposition(|l| l.ends_with("mode 'none'"))
            .expect("the rollback switch ran");
        assert!(back > manual, "rollback after the write: {runs:?}");
        assert!(
            status.services.is_empty(),
            "Linux rows stay out of `services`"
        );
    }

    /// SP-AC18 (engine half): `summary()` is cached ≤ 5 s and refreshed by `set`.
    #[test]
    fn summary_is_cached_five_seconds_and_refreshed_by_set() {
        let exec = ScriptedExecutor::new()
            .respond(SCUTIL, 0, &scutil_out("127.0.0.1", 9090), "")
            .respond(SCUTIL, 0, &scutil_out("127.0.0.1", 8080), "");
        let r = macos_rig("ac18", at_us_round(before_round(exec)));

        let first = r.sp.summary();
        let second = r.sp.summary();
        assert_eq!(first, second);
        assert_eq!(
            first.state,
            State::Other {
                host: "127.0.0.1".into(),
                port: 9090
            }
        );
        assert_eq!(first.host.as_deref(), Some("127.0.0.1"));
        assert_eq!(first.port, Some(9090));
        assert!(!first.managed_by_us);
        assert!(first.supported);
        assert_eq!(r.exec.count(SCUTIL), 1, "{:?}", r.exec.runs());
        assert_eq!(
            r.exec.runs(),
            vec![SCUTIL.to_string()],
            "no per-service reads"
        );

        r.sp.set(&SetRequest::default()).expect("set");
        let after_set = r.exec.count(SCUTIL);
        let summary = r.sp.summary();
        assert_eq!(summary.state, State::PointsAtUs);
        assert!(summary.managed_by_us);
        assert_eq!(summary.host, None);
        assert_eq!(r.exec.count(SCUTIL), after_set, "no new read after set");
    }

    /// SP-AC14: the five rows of the §D9 (c) table, plus the partial case.
    #[test]
    fn recover_follows_the_table() {
        // absent, auto off → nothing, no command at all.
        let r = macos_rig("rec-absent-off", ScriptedExecutor::new());
        assert_eq!(r.sp.recover_at_startup(false), Recovery::Nothing);
        assert!(r.exec.runs().is_empty());
        assert!(!r.file.exists());

        // absent, auto on → set.
        let exec = ScriptedExecutor::new().respond(SCUTIL, 0, &scutil_out("127.0.0.1", 8080), "");
        let r = macos_rig("rec-absent-on", at_us_round(before_round(exec)));
        let Recovery::Set(status) = r.sp.recover_at_startup(true) else {
            panic!("expected Set");
        };
        assert_eq!(status.state, State::PointsAtUs);
        assert_eq!(r.exec.mutating_runs(), set_lines(""));
        assert!(r.file.exists());

        // present, equal, same endpoint, auto on → adopt: file kept, new pid, no -set.
        let exec = ScriptedExecutor::new().respond(SCUTIL, 0, &scutil_out("127.0.0.1", 8080), "");
        let r = macos_rig("rec-adopt", at_us_round(exec));
        d7_file().save_atomic(&r.file).expect("seed");
        assert_eq!(
            r.sp.recover_at_startup(true),
            Recovery::Adopted {
                pid: std::process::id()
            }
        );
        assert!(r.exec.mutating_runs().is_empty(), "{:?}", r.exec.runs());
        let kept = StateFile::load(&r.file).expect("load").expect("kept");
        assert_eq!(kept.pid, std::process::id());
        assert_eq!(kept.previous, d7_file().previous);
        assert_eq!(kept.wrote, d7_file().wrote);
        assert!(r.sp.status().managed_by_us);

        // present, equal, auto off → restore, file gone.
        let exec = ScriptedExecutor::new().respond(SCUTIL, 0, &scutil_out("127.0.0.1", 8080), "");
        let r = macos_rig("rec-restore", at_us_round(exec));
        d7_file().save_atomic(&r.file).expect("seed");
        assert_eq!(
            r.sp.recover_at_startup(false),
            Recovery::Restored {
                restored: strs(&["Display Ethernet", "Wi-Fi"]),
                left_alone: vec![],
            }
        );
        assert_eq!(r.exec.mutating_runs(), restore_lines());
        assert!(!r.file.exists());

        // present, equal, endpoint differs (old core wrote 8081), auto on →
        // restore, then set. Live reads equal the OLD `wrote` (8081) first,
        // then the restored before-state, then the verify at 8080.
        let mut other_port = d7_file();
        other_port.wrote.port = 8081;
        let exec = ScriptedExecutor::new().respond(SCUTIL, 0, &scutil_out("127.0.0.1", 8080), "");
        let exec = at_us_round(before_round(answer_round(
            exec,
            ("127.0.0.1", 8081),
            ("127.0.0.1", 8081),
        )));
        let r = macos_rig("rec-restore-set", exec);
        other_port.save_atomic(&r.file).expect("seed");
        let Recovery::Set(status) = r.sp.recover_at_startup(true) else {
            panic!("expected Set after restore");
        };
        assert_eq!(status.state, State::PointsAtUs);
        let mut expected = restore_lines();
        expected.extend(set_lines(""));
        assert_eq!(r.exec.mutating_runs(), expected);
        assert!(r.file.exists(), "the new set's file");
        assert_eq!(
            StateFile::load(&r.file)
                .expect("load")
                .expect("file")
                .wrote
                .port,
            8080
        );

        // present, not equal (another tool took over), auto on → forget the
        // file, then set over the other tool's setting (its values become the
        // new `previous`).
        let exec = ScriptedExecutor::new().respond(SCUTIL, 0, &scutil_out("127.0.0.1", 8080), "");
        let exec = answer_round(exec, ("10.0.0.5", 3128), ("10.0.0.5", 3128));
        let exec = at_us_round(answer_round(exec, ("10.0.0.5", 3128), ("10.0.0.5", 3128)));
        let r = macos_rig("rec-forgot-on", exec);
        d7_file().save_atomic(&r.file).expect("seed");
        let Recovery::Set(status) = r.sp.recover_at_startup(true) else {
            panic!("expected Set after a forget");
        };
        assert_eq!(status.state, State::PointsAtUs);
        assert_eq!(r.exec.mutating_runs(), set_lines(""));
        let fresh = StateFile::load(&r.file).expect("load").expect("new file");
        let Previous::Networksetup { services } = &fresh.previous else {
            panic!("networksetup previous");
        };
        assert_eq!(
            services[0].http.port, 3128,
            "the other tool's setting is the new previous"
        );

        // present, not equal, auto off → forget, no -set, file gone.
        let exec = ScriptedExecutor::new().respond(SCUTIL, 0, &scutil_out("10.0.0.5", 3128), "");
        let r = macos_rig(
            "rec-forgot-off",
            answer_round(exec, ("10.0.0.5", 3128), ("10.0.0.5", 3128)),
        );
        d7_file().save_atomic(&r.file).expect("seed");
        assert_eq!(r.sp.recover_at_startup(false), Recovery::Forgot);
        assert!(r.exec.mutating_runs().is_empty(), "{:?}", r.exec.runs());
        assert!(!r.file.exists());

        // present, one service taken over, auto off → restore ours, leave the other.
        let exec = ScriptedExecutor::new().respond(SCUTIL, 0, &scutil_out("10.0.0.5", 3128), "");
        let r = macos_rig(
            "rec-partial",
            answer_round(exec, ("10.0.0.5", 3128), ("127.0.0.1", 8080)),
        );
        d7_file().save_atomic(&r.file).expect("seed");
        assert_eq!(
            r.sp.recover_at_startup(false),
            Recovery::Restored {
                restored: strs(&["Wi-Fi"]),
                left_alone: strs(&["Display Ethernet"]),
            }
        );
        assert_eq!(r.exec.mutating_runs(), restore_lines()[5..].to_vec());
        assert!(!r.file.exists());
    }

    /// §D9 (a): after a set, the orderly exit restores and forgets; a second
    /// call has nothing to do.
    #[test]
    fn on_orderly_exit_restores_when_managed() {
        let exec = ScriptedExecutor::new().respond(SCUTIL, 0, &scutil_out("127.0.0.1", 8080), "");
        let r = macos_rig("exit", at_us_round(before_round(exec)));
        assert_eq!(r.sp.on_orderly_exit(), Recovery::Nothing);
        assert!(r.exec.runs().is_empty(), "no file → no read");

        r.sp.set(&SetRequest::default()).expect("set");
        assert!(r.file.exists());
        assert_eq!(
            r.sp.on_orderly_exit(),
            Recovery::Restored {
                restored: strs(&["Display Ethernet", "Wi-Fi"]),
                left_alone: vec![],
            }
        );
        assert!(!r.file.exists());
        let mut expected = set_lines("");
        expected.extend(restore_lines());
        assert_eq!(r.exec.mutating_runs(), expected);
        assert_eq!(r.sp.on_orderly_exit(), Recovery::Nothing);
    }

    /// C7: a failure after the first service was written rolls back every
    /// service from `previous` and removes the file; a failed rollback keeps
    /// the file and is an `Err` naming it.
    #[test]
    fn set_rolls_back_every_service_on_a_mid_sequence_failure() {
        let wifi_set = format!("/usr/sbin/networksetup -setwebproxy {WIFI} 127.0.0.1 8080");
        let exec = ScriptedExecutor::new()
            .respond(SCUTIL, 0, &scutil_out("127.0.0.1", 9090), "")
            .respond(&wifi_set, 2, "", "boom");
        let r = macos_rig("c7", before_round(before_round(exec)));

        let (status, changed, commands) =
            r.sp.set(&SetRequest::default())
                .expect("Ok after a clean rollback");
        assert_eq!(status.state, State::Unknown);
        assert!(status.detail.contains("boom"), "{}", status.detail);
        assert!(!changed);
        assert_eq!(
            commands,
            restore_lines(),
            "the lines that ran after the failure"
        );
        let mut expected = set_lines("")[..4].to_vec();
        expected.extend(restore_lines());
        assert_eq!(r.exec.mutating_runs(), expected);
        assert!(!r.file.exists(), "file removed after the rollback");

        // The rollback itself fails → Err naming the file; the file is kept.
        let de_restore = format!("/usr/sbin/networksetup -setwebproxy {DE} 127.0.0.1 9090");
        let exec = ScriptedExecutor::new()
            .respond(SCUTIL, 0, &scutil_out("127.0.0.1", 9090), "")
            .respond(&wifi_set, 2, "", "boom")
            .respond(&de_restore, 1, "", "nope");
        let r = macos_rig("c7-rollback-fails", before_round(exec));
        let err =
            r.sp.set(&SetRequest::default())
                .expect_err("Err when the rollback fails");
        let msg = err.to_string();
        assert!(
            msg.contains(&r.file.to_string_lossy().into_owned()),
            "{msg}"
        );
        assert!(msg.contains("boom"), "{msg}");
        assert!(r.file.exists(), "file kept for a later unset");
        assert_eq!(
            r.exec.mutating_runs(),
            vec![
                set_lines("")[0].clone(),
                set_lines("")[1].clone(),
                set_lines("")[2].clone(),
                wifi_set,
                de_restore
            ]
        );
    }

    /// §D3: an authenticated service is not written, is named in `detail`,
    /// and is absent from the file's `previous`.
    #[test]
    fn set_skips_authenticated_services_and_names_them() {
        let auth = "Enabled: Yes\nServer: proxy.corp\nPort: 3128\nAuthenticated Proxy Enabled: 1\n";
        let exec = ScriptedExecutor::new()
            .respond(SCUTIL, 0, &scutil_out("127.0.0.1", 8080), "")
            .respond(LIST, 0, LIST_OUT, "")
            .respond(&get_web(DE), 0, &proxy_out("127.0.0.1", 9090), "")
            .respond(&get_web(DE), 0, &proxy_out("127.0.0.1", 8080), "")
            .respond(&get_secure(DE), 0, &proxy_out("127.0.0.1", 9090), "")
            .respond(&get_secure(DE), 0, &proxy_out("127.0.0.1", 8080), "")
            .respond(&get_bypass(DE), 0, BYPASS_OUT, "")
            .respond(&get_web(WIFI), 0, auth, "")
            .respond(&get_secure(WIFI), 0, &proxy_out("", 0), "")
            .respond(&get_bypass(WIFI), 0, BYPASS_OUT, "");
        let r = macos_rig("auth", exec);

        let (status, changed, commands) = r.sp.set(&SetRequest::default()).expect("set");
        assert!(changed);
        assert_eq!(commands, set_lines("")[..3].to_vec());
        assert_eq!(r.exec.mutating_runs(), set_lines("")[..3].to_vec());
        assert_eq!(
            status.detail,
            "HTTP and HTTPS → 127.0.0.1:8080 (this core); skipped Wi-Fi: authenticated proxy"
        );
        assert_eq!(status.state, State::PointsAtUs);
        let file = StateFile::load(&r.file).expect("load").expect("file");
        assert_eq!(file.service_names(), vec!["Display Ethernet".to_string()]);
    }

    /// A second change while one is in flight is refused.
    #[test]
    fn in_flight_flag_is_reported_and_guards_the_verbs() {
        let r = macos_rig("in-flight", ScriptedExecutor::new());
        assert!(!r.sp.is_setting());
        assert!(!r.sp.status().setting);
        let reads_so_far = r.exec.runs().len();
        r.sp.in_flight.store(true, Ordering::SeqCst);
        assert!(r.sp.is_setting());
        assert!(r.sp.status().setting);
        assert!(r.sp.summary().setting, "`setting` is live, not cached");
        let after_status = r.exec.runs().len();
        let err = r.sp.set(&SetRequest::default()).expect_err("refused");
        assert_eq!(
            err.to_string(),
            "a system-proxy change is already in flight"
        );
        let err = r.sp.unset().expect_err("refused");
        assert_eq!(
            err.to_string(),
            "a system-proxy change is already in flight"
        );
        assert_eq!(
            r.exec.runs().len(),
            after_status,
            "a refused call runs nothing"
        );
        assert!(after_status >= reads_so_far);
        r.sp.in_flight.store(false, Ordering::SeqCst);
        assert!(!r.sp.summary().setting);
    }

    #[test]
    fn engine_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<SystemProxy>();
    }
}
