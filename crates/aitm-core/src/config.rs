//! The configuration model the `ProxyBuilder` consumes.
//!
//! These are plain data types. The `aitm` binary (Task 28) parses a YAML file
//! into them; serialization format is that task's concern. `BrowserConfig` and
//! `SsrfPolicy` live here — not in `aitm-browser` — because `Config` references
//! them and `aitm-core` cannot depend on `aitm-browser` without a cycle.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;

use crate::agent::AgentPolicy;
use crate::ctx::Frontend;

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
    pub findings: FindingsConfig,
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
    /// Per-host TLS passthrough pins (M6 F11). The list is empty and agent
    /// authoring is off by default. Decryption itself follows Scope (per-host
    /// decryption, 2026-10-31): a host is decrypted only while it is in Scope and
    /// not pinned here; everything else is tunnelled.
    pub tls: TlsConfig,
    /// Map Local/Remote rules (M6). Deny-by-default: no map root and agent
    /// authoring off, so Map Local is unusable and no agent may author maps until
    /// the operator opts in.
    pub maps: MapsConfig,
    /// Session/flow file I/O (M6 F10). Deny-by-default: an agent (MCP) frontend
    /// may not read or write a host path via `session.save`/`session.load`/
    /// `flow.export`/`flow.import` until the operator opts in.
    pub session_io: SessionIoConfig,
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
            findings: FindingsConfig::default(),
            ssl_insecure: false,
            max_flows: crate::store::DEFAULT_MAX_FLOWS,
            max_flow_bytes: crate::store::DEFAULT_MAX_FLOW_BYTES,
            tls: TlsConfig::default(),
            maps: MapsConfig::default(),
            session_io: SessionIoConfig::default(),
        }
    }
}

/// Per-host TLS passthrough configuration (M6 F11). A passthrough host is
/// tunnelled byte-for-byte without MITM, so the client speaks TLS to the real
/// upstream and the proxy records only a `CONNECT` row for it (`tunnel:
/// passthrough`, `tunnel_reason: pinned`), never a decrypted flow.
#[derive(Debug, Clone, Default)]
pub struct TlsConfig {
    /// Hosts (or `*.wildcard`) pinned out of MITM. **Empty by default.** Scope is
    /// the decryption list (per-host decryption, 2026-10-31): a host is decrypted
    /// only while it is in Scope **and** not pinned here; a host outside Scope is
    /// tunnelled regardless (`tunnel_reason: out_of_scope`). Pins win over Scope,
    /// so pinning an in-scope host stops its decryption without removing it from
    /// Scope.
    pub passthrough: Vec<String>,
    /// Let an agent frontend (MCP) change the passthrough list with
    /// `tls.passthrough.add`/`remove`. **Off by default**: pinning a host out of
    /// MITM is an authorisation decision, so only the human CLI may do it unless
    /// the operator opts in — mirrors [`ScopeConfig::allow_agent_widen`].
    pub allow_agent_passthrough: bool,
}

/// Map Local/Remote configuration (M6). Map rules rewrite or mock matching
/// requests; both the map root (confining Map Local file reads) and agent
/// authoring default to the deny-by-default posture.
#[derive(Debug, Clone, Default)]
pub struct MapsConfig {
    /// The directory Map Local files are confined to. **`None` by default**: with
    /// no root, a `map.add` for a local file is rejected (nothing to confine it
    /// to), so Map Local is unusable until the operator sets a root.
    pub root: Option<PathBuf>,
    /// Let an agent frontend (MCP) author map rules with `map.add`/`map.remove`.
    /// **Off by default**: a map rule redirects or mocks traffic, an
    /// authorisation decision, so only the human CLI may author one unless the
    /// operator opts in — mirrors [`ScopeConfig::allow_agent_widen`].
    pub allow_agent_authoring: bool,
}

/// Session/flow file-I/O configuration (M6 F10). `session.save`/`session.load`/
/// `flow.export`/`flow.import` can read or overwrite an arbitrary host path, so an
/// agent (MCP) frontend is refused a path-bearing call unless the operator opts in.
#[derive(Debug, Clone, Default)]
pub struct SessionIoConfig {
    /// Let an agent (MCP) frontend read/write a host path through the session/flow
    /// I/O commands. **Off by default**: reading or overwriting a host file is an
    /// authorisation decision, so only the human CLI may hand those commands a path
    /// unless the operator opts in — mirrors [`ScopeConfig::allow_agent_widen`]. An
    /// agent may still export to / import from in-memory `bytes` (no host path),
    /// which stays passive.
    pub allow_agent_file_io: bool,

    /// Confine every path-bearing session/flow I/O call under this root
    /// (traversal and absolute escapes are refused). `None` (the default) imposes
    /// no confinement, so the human CLI keeps full path access; set it to safely
    /// bound an agent frontend once [`Self::allow_agent_file_io`] is on.
    pub root: Option<PathBuf>,
}

/// PoC-engine configuration.
#[derive(Debug, Clone, Default)]
pub struct PocConfig {
    /// When set, `poc.run` only loads a PoC file that resolves (canonicalized)
    /// to a path under this directory. `None` (the default) imposes no
    /// confinement — a PoC may be loaded from any path, as before. `poc.list`
    /// and `poc.get` enumerate/read the PoC library under this directory.
    pub dir: Option<PathBuf>,
    /// Where `poc.run` writes its artifacts (the YAML copy and screenshot).
    /// `None` (the default) writes to the system temp directory as before.
    /// `poc.artifact` only serves files confined to this directory, so a
    /// remote/web surface can read run artifacts safely.
    pub out_dir: Option<PathBuf>,
    /// Let an agent frontend (`Frontend::Mcp`) run `poc.run`. **Off by default**:
    /// running a PoC is a sensitive action, so only the human CLI or a present
    /// operator may run it unless the operator opts in — mirrors
    /// [`ScopeConfig::allow_agent_widen`] / [`CaConfig::allow_agent_install`].
    /// `Frontend::Operator` and `Frontend::Cli` are never gated by it. (T3)
    pub allow_agent_run: bool,
}

/// Persistent findings / run-history store configuration (M4 Stream B).
#[derive(Debug, Clone, Default)]
pub struct FindingsConfig {
    /// Where the findings store writes one human-readable YAML per finding plus a
    /// `runs.jsonl` run-history log. `None` (the default) disables persistence:
    /// `findings.list`/`get` return nothing and `findings.record` errors. A
    /// sensible deployment points this at a sibling of `poc.dir`.
    pub dir: Option<PathBuf>,
}

/// Scope configuration. Deny-by-default: an empty list means nothing is active.
#[derive(Debug, Clone, Default)]
pub struct ScopeConfig {
    pub entries: Vec<ScopeEntry>,
    /// Let an agent frontend (MCP) widen scope with `scope.add`. **Off by
    /// default**: adding a host to scope is an authorisation decision, so only
    /// the human CLI may do it unless the operator opts in — mirrors
    /// [`CaConfig::allow_agent_install`]. `scope.remove` (which only narrows
    /// scope) is never gated.
    pub allow_agent_widen: bool,
}

/// The one sentence every surface prints, verbatim, when Scope is empty and so
/// nothing is decrypted (spec D8): `proxy.status.decrypt.advice`, the `Scope`
/// line of `aitm web`'s startup summary, and bare `aitm`'s one launch `info`
/// line. Frontends print it; they never compose their own.
pub const NOTHING_DECRYPTED_ADVICE: &str = "Nothing is decrypted until a host is in Scope.";

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
    /// `SETTINGS_MAX_CONCURRENT_STREAMS` advertised to an HTTP/2 client, bounding
    /// how many streams one connection may run in parallel so a hostile peer
    /// cannot open unbounded streams. Default 128.
    pub max_concurrent_streams: u32,
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
            max_concurrent_streams: 128,
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
    LoopbackTcp {
        port: u16,
        token: String,
        /// Where to publish the bound bus `host:port` (never the token) once the
        /// listener binds — the rendezvous file a parent process (the embedded-core
        /// manager) watches to learn the ephemeral port without parsing stdout.
        /// `None` writes nothing. Mirrors the obscura ready-file pattern.
        endpoint_file: Option<PathBuf>,
    },
    /// Serve over streamable HTTP (loopback by default); a non-empty Bearer
    /// `token` is required, cross-origin requests are gated by an exact
    /// `allowed_origins` allowlist (empty = none allowed), and requests are
    /// served at `path`. See [`McpTransport::streamable_http_default`].
    StreamableHttp {
        /// The interface/port to bind. Defaults to `127.0.0.1:8084`; binding a
        /// non-loopback interface is an explicit operator decision.
        bind: SocketAddr,
        /// The Bearer token required on every request. Must be non-empty.
        token: String,
        /// Exact `Origin` header allowlist. Empty means no cross-origin request
        /// is accepted (same-origin / no-Origin requests still work).
        allowed_origins: Vec<String>,
        /// The request path the endpoint is served at (e.g. `/mcp`).
        path: String,
    },
}

impl McpTransport {
    /// Build a [`McpTransport::StreamableHttp`] with the secure defaults: a
    /// loopback bind on `127.0.0.1:8084`, an empty `Origin` allowlist, and the
    /// `/mcp` path. The caller supplies the required non-empty Bearer `token`.
    pub fn streamable_http_default(token: String) -> Self {
        McpTransport::StreamableHttp {
            bind: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8084),
            token,
            allowed_origins: Vec::new(),
            path: "/mcp".into(),
        }
    }
}

/// MCP frontend configuration.
#[derive(Debug, Clone)]
pub struct McpConfig {
    pub transport: McpTransport,
    /// The token that marks a loopback-TCP connection as an autonomous agent
    /// ([`Frontend::Mcp`]). For the loopback transport the required token also
    /// lives on [`McpTransport::LoopbackTcp`]; this field is the canonical name
    /// so wiring and audit can speak of "the agent token" directly.
    pub agent_token: Option<String>,
    /// The token that marks a loopback-TCP connection as a human operator
    /// ([`Frontend::Operator`]). **Off by default**: without it, every
    /// loopback connection is an agent, matching the M1/M2 posture.
    pub operator_token: Option<String>,
    /// The agent policy the server starts under (enforced from Task 4). Default
    /// [`AgentPolicy::Auto`] per the milestone's adopted default.
    pub policy: AgentPolicy,
    /// The role a stdio connection is given (there is no token on stdio).
    /// Default [`Frontend::Mcp`] — stdio is the agent-attach transport; an
    /// operator attached over stdio sets this to [`Frontend::Operator`].
    pub stdio_role: Frontend,
    /// Where the durable audit log is written; see [`AuditLogSetting`]. The
    /// default is the per-user `audit.jsonl`.
    pub audit_log: AuditLogSetting,
}

impl Default for McpConfig {
    fn default() -> Self {
        Self {
            transport: McpTransport::Stdio,
            agent_token: None,
            operator_token: None,
            policy: AgentPolicy::Auto,
            stdio_role: Frontend::Mcp,
            audit_log: AuditLogSetting::Default,
        }
    }
}

/// Where the durable audit log (the JSONL file the `aitm` binary appends every
/// command invocation to) is written: the `mcp.audit_log` setting.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum AuditLogSetting {
    /// The operator said nothing: the per-user `audit.jsonl` beside the CA
    /// audit log, written on a best-effort basis.
    #[default]
    Default,
    /// The operator turned the file off.
    Off,
    /// An explicit path: the operator asked for this file, so a failure to use it
    /// is theirs to hear about (the spellings are in Design 2 of the durable
    /// audit spec).
    Path(PathBuf),
}

impl AuditLogSetting {
    /// The file to write, or `None` when the log is off. `Default` is
    /// `<config_dir>/aitmproxy/audit.jsonl`, a sibling of the CA audit log.
    pub fn resolved_path(&self) -> Option<PathBuf> {
        match self {
            Self::Default => Some(default_aitm_dir().join("audit.jsonl")),
            Self::Off => None,
            Self::Path(path) => Some(path.clone()),
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
    /// Pass obscura `--allow-private-network`, letting the engine reach
    /// private/loopback ranges (audit I15). **Derived, not configured:** the
    /// launch site computes it from the SSRF policy ∪ the seed scope via
    /// [`crate::engine_may_reach_private`] (so a scoped loopback target lifts it
    /// under the strict default), never from the config file. Off by default so a
    /// pure-public scope under strict policy keeps the engine as narrow as the
    /// policy; the proxy connector's SSRF check stays the authoritative per-host
    /// gate regardless.
    pub allow_private: bool,
}

impl Default for ObscuraConfig {
    fn default() -> Self {
        Self {
            binary: None,
            start_timeout: Duration::from_secs(15),
            stop_timeout: Duration::from_secs(5),
            allow_private: false,
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
    /// Start the browser-facing listener in scope-confined egress mode: refuse an
    /// out-of-scope PUBLIC host (scanner S2). **Off by default** — the general
    /// interception path must let an operator browse arbitrary public hosts. A
    /// scan campaign or agent crawl turns it on at runtime.
    pub confine_egress_to_scope: bool,
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
            // Off: free browsing is the general-interception default (spec AC8).
            confine_egress_to_scope: false,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn streamable_http_default_binds_loopback() {
        let transport = McpTransport::streamable_http_default("t".into());
        assert!(matches!(
            &transport,
            McpTransport::StreamableHttp { bind, .. }
                if bind.ip().is_loopback() && bind.port() == 8084
        ));
        match transport {
            McpTransport::StreamableHttp {
                token,
                allowed_origins,
                path,
                ..
            } => {
                assert_eq!(token, "t");
                assert!(allowed_origins.is_empty());
                assert_eq!(path, "/mcp");
            }
            other => panic!("expected StreamableHttp, got {other:?}"),
        }
    }
}
