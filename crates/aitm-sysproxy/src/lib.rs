//! System proxy automation (spec `docs/superpowers/specs/2026-10-31-system-proxy-automation-design.md`).
//!
//! The types and pure functions every other module shares: the status model
//! of §D6, the `classify` rule of §D3, the bypass union of §D5, the guidance
//! and remedy sentences of §D3/§D4. The `SystemProxy` engine is Task 6.

pub mod config;
pub mod platform;
pub mod plugin;
pub mod state;
pub mod watchdog;

use std::collections::BTreeMap;
use std::fmt;
use std::net::SocketAddr;
use std::path::PathBuf;

use aitm_core::Value;

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
