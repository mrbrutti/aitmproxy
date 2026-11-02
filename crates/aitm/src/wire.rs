//! Assembling the proxy from `Config` (Task 28; M2 Task 21).
//!
//! [`assemble`] registers the protocol modules (`HttpModule`, then `WsModule`),
//! then the first-party plugins in chain order (capture, replay, intercept,
//! mutate, scope, rate-limit), then the command providers (browser, poc, ca),
//! and builds the [`Proxy`]. Each plugin's `load` registers its commands into
//! the one registry the chain and the frontends share. The [`CertAuthority`]
//! the HTTP module mints with comes back out in [`Assembled`], so the browser
//! launcher can hand its certificate file to the embedded engine (spec §D7).
//!
//! The feature set is data, not code: [`Features`] names which removable plugins
//! are registered. Dropping `mutate` there removes `flow.mutate`/`request.send`
//! with no `aitm-core` edit (AC-P3). The scope and rate limits come from `Config`,
//! so a config change moves the observed throttle threshold (AC-P4).

use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use aitm_browser::BrowserPlugin;
use aitm_ca::CaPlugin;
use aitm_core::{
    ActionPermit, AgentState, AuditRing, Config, GuardError, JobBus, Plugin, ProtocolModule, Proxy,
    Registry, ScopeEntry, ScopeRateGuard, SsrfPolicy,
};
use aitm_plugin_maprules::MapRulesPlugin;
use aitm_plugin_passthrough::{PassthroughList, PassthroughModule, PassthroughPlugin};
use aitm_plugin_scanner::jobs::{Engine as ScanEngine, ScanLate};
use aitm_plugin_scanner::{ScannerConfig, ScannerPlugin};
use aitm_plugin_sessionio::SessionIoPlugin;
use aitm_plugin_wsctl::WsCtlPlugin;
use aitm_plugins::{
    AgentPlugin, CapturePlugin, ControlPlugin, DetailPlugin, InterceptPlugin, MetaPlugin,
    MutatePlugin, RateLimitPlugin, ReplayPlugin, ScopePlugin, SubscriptionPlugin,
};
use aitm_proto_http::{CertAuthority, HttpModule};
use aitm_proto_l4::config::L4Config;
use aitm_proto_l4::flow::L4FlowStore;
use aitm_proto_l4::guard::L4Guard;
use aitm_proto_l4::{L4Module, L4Privilege};
use aitm_proto_ws::{InjectRegistry, WsModule};
use aitm_scan_model::CheckRegistry;
use aitm_scan_ws::types::TlsPolicy;
use aitm_sysproxy::plugin::SysProxyPlugin;
use aitm_sysproxy::{SystemProxy, SystemProxyConfig};
use tracing::{info, warn};

use crate::ingress::CoreIngress;
use crate::macos_capture::config::MacosCaptureConfig;
use crate::macos_capture::feeder::CaptureSession;
use crate::macos_capture::peer_auth::PeerVerifier;
use crate::macos_capture::status::{CaptureStatus, CaptureStatusPlugin, CaptureStatusWriter};

/// Which removable first-party feature plugins to register. Dropping one here is
/// the whole of AC-P3: the command disappears from the registry with no core edit.
#[derive(Clone)]
pub struct Features {
    /// The mutate plugin (`flow.mutate`, `request.send`).
    pub mutate: bool,
    /// The `ca.*` plugin to register. `None` builds `CaPlugin::new(cfg.ca)`
    /// (real executor, file audit log); `Some` registers the given plugin,
    /// which is how tests inject a scripted executor and an in-memory audit log.
    pub ca_plugin: Option<CaPlugin>,
    /// The L4 (raw packet) module config. Opt-in and fail-closed: `enabled` is
    /// false by default, so the default feature set registers no `l4.*` command.
    /// When enabled, the module is registered on the live core (M5-AC17).
    pub l4: L4Config,
    /// An explicit L4 capability-probe result. `None` (production default) runs the
    /// real cheap startup probe; tests force a known privilege state here.
    pub l4_privilege: Option<L4Privilege>,
    /// A pre-built, shared L4 guard + flow store the `l4.*` command module must act
    /// over. `None` (every caller using `..Features::default()`) ⇒ the module builds
    /// its own; `Some` ⇒ the binary already built the state and installed a live
    /// [`L4Language`](aitm_proto_l4::L4Language) over the **same** guard/store on the
    /// scripting engine, so a script's `l4.scope.add` and the bus see one state (no
    /// divergent L4 engagement state).
    pub l4_shared: Option<L4Shared>,
    /// The core's own listener ports **beyond** the proxy and browser-proxy ports
    /// `cfg` already names: the loopback bus, the web UI and the MCP streamable-HTTP
    /// port, each when the binary binds one. Assembly hands all of them to the L4
    /// module, so no capture ever records a loopback frame to or from the core
    /// itself — the bus's plaintext token line among it (L4PAR-AC34, spec §2.1).
    /// The binary refines the set with the bound ports after binding.
    pub l4_self_ports: Vec<u16>,
    /// The macOS NE live-capture feeder config. Opt-in and deny-by-default:
    /// `enabled` is false by default, so the default feature set never binds the
    /// capture listener. The feeder runs only when `enabled` and the build is macOS.
    pub macos_capture: MacosCaptureConfig,
    /// The system-proxy engine behind `proxy.system.*` and `proxy.status.system_proxy`
    /// (system-proxy spec §D8). `None` (production) detects this host's mechanism
    /// over a real executor from [`Features::system_proxy`]; `Some` injects a
    /// scripted engine (tests). Detection runs no command (plan C2).
    pub sysproxy: Option<Arc<SystemProxy>>,
    /// The `system_proxy:` config section (`auto`, `bypass`, `state_file`), read
    /// only when [`Features::sysproxy`] is `None`. The binary passes
    /// `Settings.system_proxy`, whose `state_file` is always `Some` (plan C6).
    pub system_proxy: SystemProxyConfig,
    /// The `scanner:` config section (spec D11): the scanner v2 engine's agent
    /// gates, job limits, ceilings and profile sources. It lives outside
    /// `aitm_core::Config` like the L4 config does, so `aitm-core` knows nothing
    /// about the scanner; the binary passes `Settings.scanner`. Assembly copies
    /// two values that are not `scanner:` keys onto the clone it hands the
    /// plugin: `cfg.findings.dir` (where job, issue and profile state is
    /// written) and `l4.allow_agent_inject` (so the `scan.start` L4 gate reads
    /// one struct). The default is [`ScannerConfig::default`] — deny-by-default
    /// agent gates, memory-only state.
    pub scanner: ScannerConfig,
}

/// A shared L4 guard + flow store, built once by the binary and threaded into both
/// the `l4.*` command module ([`Features::l4_shared`]) and the live
/// [`L4Language`](aitm_proto_l4::L4Language) on the scripting engine, so both faces
/// act over one L4 engagement state.
#[derive(Clone)]
pub struct L4Shared {
    pub guard: Arc<L4Guard>,
    pub store: Arc<dyn L4FlowStore>,
}

impl Default for Features {
    fn default() -> Self {
        Self {
            mutate: true,
            ca_plugin: None,
            l4: L4Config::default(),
            l4_privilege: None,
            l4_shared: None,
            l4_self_ports: Vec::new(),
            macos_capture: MacosCaptureConfig::default(),
            sysproxy: None,
            system_proxy: SystemProxyConfig::default(),
            scanner: ScannerConfig::default(),
        }
    }
}

/// Every scanner v2 lane the build has, in lane order (spec D1).
///
/// Each lane crate owns a `lane()` entry point returning `Option<Arc<dyn Lane>>`;
/// this is the one place that calls them, so a lane track lands by filling its own
/// crate and edits no shared file ("Registration without shared files"). A slot
/// that answers `None` — a track whose lane this build does not ship — is skipped,
/// and `scan.start` refuses that lane with `lane_unavailable`.
///
/// The two L4 slots are called with the shared guard and flow store from
/// [`Features::l4_shared`], so a scanner L4 case acts over the same L4 engagement
/// state the `l4.*` verbs and the scripting language do. When L4 is disabled `l4`
/// is `None` and both handles are passed as `None`; a landed L4 lane still returns
/// `Some` then, so the refusal is `refused_l4` rather than `lane_unavailable`
/// (spec D3's refusal order).
///
/// The WebSocket lane dials with [`TlsPolicy::Verify`] here; the binary selects
/// the operator's posture with [`collect_lanes_with`] and [`ws_tls_policy`].
#[must_use]
pub fn collect_lanes(l4: Option<&L4Shared>) -> Vec<Arc<dyn aitm_scan_model::Lane>> {
    collect_lanes_with(l4, TlsPolicy::Verify)
}

/// [`collect_lanes`], with the certificate policy the WebSocket lane dials with.
///
/// `aitm-scan-ws` verifies upstream certificates against the webpki roots by
/// default, so a self-signed `wss://` lab target answers `Inconclusive` (the
/// TLS handshake never completes) unless the operator's `ssl_insecure` is
/// passed down. This is the sibling that passes it: `collect_lanes` keeps its
/// one-argument signature (and its default-secure posture) for every caller
/// that has no `Config` to read, and assembly calls this one with
/// `ws_tls_policy(cfg)`. The other three slots take no TLS policy — the HTTP
/// lane dials through `aitm-proto-http`'s sender, which already reads
/// `cfg.ssl_insecure`, and the two L4 slots are below TLS.
#[must_use]
pub fn collect_lanes_with(
    l4: Option<&L4Shared>,
    ws_tls: TlsPolicy,
) -> Vec<Arc<dyn aitm_scan_model::Lane>> {
    let guard = l4.map(|shared| shared.guard.clone());
    let store = l4.map(|shared| shared.store.clone());
    [
        aitm_scan_http::lane(),
        aitm_scan_ws::lane::build_with(ws_tls),
        aitm_scan_l4_packet::lane(guard.clone(), store.clone()),
        aitm_scan_l4_stream::lane(guard, store),
    ]
    .into_iter()
    .flatten()
    .collect()
}

/// The certificate policy scanner v2's WebSocket lane and `ws.*` script
/// language dial with, for `cfg`.
///
/// `ssl_insecure: false` (the default) is [`TlsPolicy::Verify`]: the chain is
/// checked against the webpki roots, exactly the posture `HttpModule`'s
/// `with_insecure(cfg.ssl_insecure)` has. `ssl_insecure: true` is
/// [`TlsPolicy::AcceptAny`]: chain validation is skipped (the handshake
/// signature is still verified) so a lab of self-signed targets is reachable.
/// One switch, both faces — the lane ([`collect_lanes_with`]) and the `ws.*`
/// language (`main.rs`) — so a `wss://` target does not behave differently
/// depending on which one reached it.
#[must_use]
pub fn ws_tls_policy(cfg: &Config) -> TlsPolicy {
    if cfg.ssl_insecure {
        TlsPolicy::AcceptAny
    } else {
        TlsPolicy::Verify
    }
}

/// The native (compiled-in) scanner v2 checks this build ships (spec D1).
///
/// `aitm-scan-checks-http` contributes checks to the HTTP lane's catalogue rather
/// than a second lane, so its slot is `checks_with`, not `lane()`: the ten T3
/// natives (spec D8.2) — `sqli-boolean`, `sqli-time`, `cmdi-time`,
/// `xss-reflected`, `open-redirect` and the five observe-only `h2-*` checks.
/// The five h2 checks open one raw HTTP/2 connection per origin, outside the
/// job client, so they take the egress posture explicitly: `ssrf` is the
/// operator's `browser.ssrf` policy (the one [`SsrfPolicy`] in `Config`, the
/// same one the browser engine and `aitm browser confine` read) and `guard` is
/// the proxy's live scope guard, handed in as a [`LateGuard`] and bound right
/// after `Proxy::build` like Map Remote's. It is the crate's only slot: no
/// constructor omits the gate.
#[must_use]
pub fn collect_native_checks(
    ssrf: SsrfPolicy,
    guard: Arc<dyn ScopeRateGuard>,
) -> Vec<Arc<dyn aitm_scan_model::Check>> {
    aitm_scan_checks_http::checks_with(ssrf, guard)
}

/// A built proxy and the CA it serves with.
pub struct Assembled {
    pub proxy: Proxy,
    pub ca: Arc<CertAuthority>,
    /// Set `true` once the proxy is actually serving, so `proxy.status.listening`
    /// is honest (a one-shot `aitm proxy status` that never serves reports `false`).
    pub listening: Arc<std::sync::atomic::AtomicBool>,
    /// The agent policy state, seeded from `cfg.mcp.policy` and shared with the
    /// `AgentPlugin` already registered, so a server's policy gate reads the same
    /// policy `agent.set` writes. Apply it to both servers the bare-`aitm` server
    /// run builds (the primary and the `aitm web` bridge server). The `aitm tui`
    /// loopback agent server receives this same `Arc` through
    /// `Assembled::governance`, which `tui::build_servers` requires. The `Ask`
    /// approval hub is not shared; see `tui::with_shared_governance`.
    pub agent_state: Arc<AgentState>,
    /// The F4 push broadcast: the `SubscriptionPlugin` registered in the chain
    /// forwards lifecycle events to it; hand it to `McpServer::with_push` so the
    /// server's dispatcher fans `notifications/aitm/flow` to subscribers.
    pub push_tx: tokio::sync::broadcast::Sender<aitm_core::Event>,
    /// The F2 command-invocation audit ring, shared with the `AgentPlugin`
    /// already registered (which serves `agent.activity`/`agent.status` from it),
    /// so a server's `call_tool` records into the same ring. Apply it to both
    /// servers the bare-`aitm` server run builds (the primary and the `aitm web`
    /// bridge server). The `aitm tui` loopback agent server receives this same
    /// `Arc` through `Assembled::governance`, which `tui::build_servers`
    /// requires. The `Ask` approval hub is not shared; see
    /// `tui::with_shared_governance`.
    pub audit_ring: Arc<AuditRing>,
    /// The protocol-general capture/ingress boundary (L4OPS-AC17). Its stream/TCP half
    /// is wired for every build (from the live proxy's shared modules, store, chain,
    /// SSRF-guarded connector, and scope guard), so it is `Some` whenever assembly
    /// succeeds; the L4/UDP half is additionally bound to the live `L4Guard` + flow
    /// store when `l4.enabled`. It is the one seam a future capture backend (Phase 2's
    /// macOS Network/System Extension) feeds: an ingress-fed TCP flow is scope-gated,
    /// dispatched, and dialled exactly as a proxied one, and an ingress-fed L4 packet is
    /// guarded by the *same* `L4Guard` and lands in the *same* `L4FlowStore` the operator
    /// reads via `l4.flow.*`. The boundary assumes no single protocol or backend.
    pub l4_ingress: Option<CoreIngress>,
    /// The live L4 guard — a clone of the one the `l4.*` command module owns — `Some`
    /// iff `features.l4.enabled`, else `None`. The macOS capture feeder reads its scope
    /// (to build the provider's scope spec) from this exact guard, so the provider is
    /// pre-filtered by the same L4 engagement state the operator mutates, never a
    /// divergent copy. Read-only use: the feeder only lists scope here; every
    /// authorization still goes through the ingress's own `L4Guard::check`.
    pub l4_guard: Option<Arc<L4Guard>>,
    /// Write side of the `capture.status` handle; move it into
    /// [`build_capture_session`]. Dropping it unused leaves the verb reporting the
    /// constructor's `off` state.
    pub capture_status: CaptureStatusWriter,
    /// The system-proxy engine the `proxy.system.*` verbs and `proxy.status`
    /// act over (system-proxy spec §D8), so `main.rs` can call
    /// `recover_at_startup(auto)` before serving and `on_orderly_exit()` on the
    /// exit path. The injected one when [`Features::sysproxy`] was `Some`.
    pub sysproxy: Arc<SystemProxy>,
    /// The one job bus (spec D9.2): every long-running command publishes its
    /// progress on it and every `McpServer` this binary builds is handed this
    /// exact `Arc` (`McpServer::with_jobs`), so a `scan.start` over one surface
    /// reaches the subscribers of every other. Nothing subscribes until a
    /// server does; publishing with no subscriber is not an error.
    pub job_bus: Arc<JobBus>,
    /// The scanner's write-once handle cell (spec D5 "Owned handles", call B3).
    /// It comes out of assembly **unbound**: the engine's store, client, guard,
    /// browser and L4 handles are the proxy's own, which exist only after
    /// `build()`, so `main.rs` binds them beside `handles.bind_proxy(..)`. A
    /// `scan.*` verb on an unbound cell errors rather than running a job over
    /// handles that do not exist.
    pub scan_late: Arc<ScanLate>,
    /// The scanner engine the plugin's `load` assembled, in the cell handed out
    /// before the registry took the plugin by value
    /// (`ScannerPlugin::engine_cell`). It is the one way to read back the
    /// configuration, catalogue and registry the live `scan.*` verbs act over —
    /// what the wiring test asserts the `scanner:` section reached. Read-only:
    /// binding the engine's handles goes through [`Assembled::scan_late`].
    pub scanner_engine: Arc<OnceLock<Arc<ScanEngine>>>,
    /// The sealed [`Governance`] that [`Assembled::governance`] hands out;
    /// private so the `pub` fields above cannot substitute it.
    governance: Governance,
}

/// The core's own agent governance: the `AgentState` and `AuditRing` that the
/// registered `AgentPlugin` writes (`agent.set`) and reads (`agent.status`,
/// `agent.activity`), so a server built over them is gated by the policy the
/// operator sets and records into the trail the operator reads.
///
/// The type is sealed. It has no constructor and no accessor, and
/// `Assembled::governance` is its only public source. It is fixed when the
/// proxy is assembled, from the pair the `AgentPlugin` is registered over, and
/// `Assembled` keeps it in a private field, so no later write to the `pub`
/// `Assembled::agent_state` / `Assembled::audit_ring` fields can substitute a
/// fresh state. `tui::build_servers` and `tui::run` require one, so `aitm tui`
/// cannot be wired without one, and no outside code can substitute the pair an
/// assembly made. It is not tied to the `Proxy` in the `Services` passed beside
/// it: a `Governance` from a second `assemble()` would pass (in-process code
/// only; nothing on the network, in a plugin, or over MCP can reach that). It
/// carries no push sender.
///
/// A `Governance` cannot be built outside this crate:
///
/// ```compile_fail
/// use std::sync::Arc;
/// use aitm::tui::{build_servers, services, TuiLog};
/// use aitm::wire::{assemble, Governance};
/// use aitm_core::{AgentPolicy, AgentState, AuditRing, Config};
///
/// fn main() -> anyhow::Result<()> {
///     let agent_state = Arc::new(AgentState::new(AgentPolicy::Auto));
///     let audit_ring = Arc::new(AuditRing::default());
///     let cfg = Config::default();
///     let assembled = assemble(&cfg)?;
///     let governance: Governance = Governance { agent_state, audit_ring };
///     let services = services(
///         &assembled.proxy,
///         &cfg,
///         None,
///         TuiLog::Off,
///         Arc::clone(&assembled.job_bus),
///     );
///     let _servers = build_servers(&cfg, services, governance);
///     Ok(())
/// }
/// ```
///
/// With the same imports and the same two locals, the one that comes from
/// `Assembled::governance` compiles:
///
/// ```no_run
/// use std::sync::Arc;
/// use aitm::tui::{build_servers, services, TuiLog};
/// use aitm::wire::{assemble, Governance};
/// use aitm_core::{AgentPolicy, AgentState, AuditRing, Config};
///
/// fn main() -> anyhow::Result<()> {
///     let agent_state = Arc::new(AgentState::new(AgentPolicy::Auto));
///     let audit_ring = Arc::new(AuditRing::default());
///     let cfg = Config::default();
///     let assembled = assemble(&cfg)?;
///     drop((agent_state, audit_ring));
///     let governance: Governance = assembled.governance();
///     let services = services(
///         &assembled.proxy,
///         &cfg,
///         None,
///         TuiLog::Off,
///         Arc::clone(&assembled.job_bus),
///     );
///     let _servers = build_servers(&cfg, services, governance);
///     Ok(())
/// }
/// ```
#[derive(Clone)]
pub struct Governance {
    pub(crate) agent_state: Arc<AgentState>,
    pub(crate) audit_ring: Arc<AuditRing>,
}

impl Assembled {
    /// A clone of the [`Governance`] fixed at assembly; its only public source.
    pub fn governance(&self) -> Governance {
        self.governance.clone()
    }
}

/// The scripting tier, ready to take its place in the chain (M3 spec §8).
#[derive(Default)]
pub struct ScriptWiring {
    /// Plugins in declaration order. They are registered after the first-party
    /// feature plugins and before the command providers, so a script sees a
    /// flow once capture/scope/rate-limit/intercept/mutate have acted and its
    /// `halt()` short-circuits everything after it.
    pub plugins: Vec<Box<dyn Plugin>>,
    /// Runs a PoC's `script` steps. `None` leaves `poc.run` declarative-only,
    /// erroring on a `script` step rather than skipping it.
    pub executor: Option<Arc<dyn aitm_poc::ScriptStepExecutor>>,
    /// Native protocol `<ns>:` PoC-step handlers (e.g. `l4:`), built by the binary
    /// from the same live language instance that owns the shared guard + store.
    /// Threaded into `poc.run` alongside `executor`; empty leaves every protocol
    /// namespace step a runtime error ("no handler registered").
    pub poc_step_handlers: aitm_poc::step_registry::PocStepRegistry,
    /// Command-provider plugins registered after the first-party ones, in order.
    /// The binary fills this with the rhai tier's commands (`script.validate`,
    /// `script.reload`, `script.findings`) **and** the persistent findings store
    /// (`findings.record`/`get`/`remove`/`list`); each registers its own
    /// commands, so the slot holds as many providers as a deployment wires.
    pub commands: Vec<Box<dyn Plugin>>,
    /// The check registry the scripting tier fills from every `reg.add_check`
    /// (`ScriptTier::checks`, call B9). The scanner is registered over this
    /// exact registry, so a script's check joins the catalogue and gets its
    /// `check.<id>` manual command. `None` (every caller using
    /// `..ScriptWiring::default()`) is an empty registry: no scripted checks.
    ///
    /// It rides here rather than on `ScriptServices` because `ScriptServices`
    /// is constructed in seventeen files, two of them integration-shared.
    pub script_checks: Option<Arc<CheckRegistry>>,
}

/// Assemble the proxy from configuration with the default feature set.
pub fn assemble(cfg: &Config) -> anyhow::Result<Assembled> {
    assemble_with(cfg, &Features::default())
}

/// Assemble the proxy from configuration and an explicit feature set.
pub fn assemble_with(cfg: &Config, features: &Features) -> anyhow::Result<Assembled> {
    assemble_with_scripts(cfg, features, ScriptWiring::default())
}

/// Assemble the proxy with the scripting tier wired in.
pub fn assemble_with_scripts(
    cfg: &Config,
    features: &Features,
    scripts: ScriptWiring,
) -> anyhow::Result<Assembled> {
    // Refuse a PoC output dir that would expose the CA key: `poc.artifact` serves
    // files under `poc.out_dir`, so it must not equal or contain `ca.dir`.
    if let Some(out_dir) = &cfg.poc.out_dir {
        if cfg.ca.dir == *out_dir || cfg.ca.dir.starts_with(out_dir) {
            anyhow::bail!(
                "poc.out_dir ({}) must not equal or contain the CA directory ({}): \
                 poc.artifact would be able to read the CA key",
                out_dir.display(),
                cfg.ca.dir.display()
            );
        }
    }
    let ca = Arc::new(CertAuthority::load_or_generate(
        &cfg.ca.dir,
        cfg.ca.key_mode,
    )?);
    let http = HttpModule::with_ca(ca.clone())
        .with_insecure(cfg.ssl_insecure)
        .with_max_body_bytes(cfg.limits.max_body_bytes)
        .with_max_concurrent_streams(cfg.limits.max_concurrent_streams as usize);

    // The control plugin's `proxy.status` reports whether intercept is armed and
    // whether the proxy is serving, so it shares the intercept plugin's armed flag
    // and a listening flag `main` flips once it begins serving.
    let intercept = InterceptPlugin::new();
    let armed = intercept.armed_flag();
    let listening = Arc::new(std::sync::atomic::AtomicBool::new(false));

    // The system-proxy engine (system-proxy spec §D8): one instance shared by the
    // `proxy.system.*` verbs, `proxy.status.system_proxy`, and the binary's
    // startup-recovery / orderly-exit calls. Detection runs no command; the
    // real executor is the CA crate's (10 s per read, 30 s per write).
    let sysproxy = features.sysproxy.clone().unwrap_or_else(|| {
        Arc::new(SystemProxy::detect(
            Arc::new(aitm_ca::exec::RealExecutor::with_timeouts(
                Duration::from_secs(10),
                Duration::from_secs(30),
            )),
            &features.system_proxy,
            aitm_sysproxy::ours_from(cfg.listen),
            std::env::current_exe().ok(),
        ))
    });

    // The F4 push tap: a chain plugin forwards lifecycle events to this broadcast,
    // which the MCP server's dispatcher drains into per-connection push sinks.
    let (push_tx, _push_rx) = tokio::sync::broadcast::channel(aitm_mcp::DEFAULT_BROADCAST_CAPACITY);

    // M6 shared handles. The WS control plugin and the live WS module share one
    // inject registry so `ws.send` reaches a conversation's `select!` loop; the
    // passthrough plugin and its protocol module share one host list so a
    // `tls.passthrough.add` is seen by the next connection's module selection.
    let wsctl = WsCtlPlugin::new();
    let inject = wsctl.inject_registry();
    let passthrough =
        PassthroughPlugin::new(cfg.tls.passthrough.clone(), cfg.tls.allow_agent_passthrough);
    let passthrough_list = passthrough.list_handle();
    // Map Remote reaches the scope guard from `on_event`, where `FlowCtx` does not
    // carry it (Plan-level call 4). The guard is built inside `Proxy::build`, so
    // the plugin holds a late-bound handle wired to the proxy's real guard below —
    // the same `StdGuard` `scope.add` mutates, so Map Remote's pre-flight check
    // sees runtime scope changes. Until bound it denies (deny-by-default).
    let map_guard = Arc::new(LateGuard::default());
    let maprules = MapRulesPlugin::new(
        cfg.maps.root.clone().unwrap_or_default(),
        cfg.maps.allow_agent_authoring,
        map_guard.clone(),
    );
    // The passthrough module decides "pinned or not in Scope" per connection (spec
    // D1/D2) against the same live guard, through the same late-bound pattern:
    // bound to the proxy's real guard right after `build`, before anything is
    // served. Until bound it reports nothing in scope, so the module would tunnel
    // everything (deny-by-default) rather than decrypt it.
    let tunnel_guard = Arc::new(LateGuard::default());
    // The scope guard the T3 raw-h2 observe checks gate their one connection per
    // origin on; bound to the proxy's guard right after build, beside the others.
    let native_guard = Arc::new(LateGuard::default());

    // The one job bus (spec D9.2). Every long-running command publishes on it
    // and every server is handed this exact `Arc`, so progress from a job
    // started on one surface reaches the subscribers of every other.
    let job_bus = Arc::new(JobBus::default());

    // The scanner's configuration (spec D11, call D11): the operator's
    // `scanner:` section, plus the two values that are not `scanner:` keys —
    // `findings.dir`, which decides where job, issue and profile state is
    // written (and whether any is), and `l4.allow_agent_inject`, mirrored here
    // so the `scan.start` L4 gate reads one struct rather than two.
    let mut scanner_cfg = features.scanner.clone();
    scanner_cfg.findings_dir = cfg.findings.dir.clone();
    scanner_cfg.l4_allow_agent_inject = features.l4.allow_agent_inject;
    // Scanner v2 registration slots (spec D1, "Registration without shared
    // files"): the lanes each lane crate's `lane()` handed back, the native
    // checks from `aitm_scan_checks_http::checks_with(..)`, and the scripting tier's
    // check registry (call B9). `late` and `engine_cell` are taken before the
    // registry takes the plugin by value: `main.rs` binds the proxy's handles
    // into the first once the proxy exists, and the second is how the assembled
    // engine is read back.
    let scanner = ScannerPlugin::new(scanner_cfg)
        .with_lanes(collect_lanes_with(
            features.l4_shared.as_ref(),
            ws_tls_policy(cfg),
        ))
        .with_native_checks(collect_native_checks(
            cfg.browser.ssrf.clone(),
            native_guard.clone(),
        ))
        .with_script_checks(scripts.script_checks.clone().unwrap_or_default());
    let scan_late = scanner.late();
    let scanner_engine = scanner.engine_cell();

    // The peer resolver names the loopback client of every proxied connection
    // (spec 2026-11-01-proxied-client-attribution); `capture_interface` stays null
    // on this path.
    let mut builder = Proxy::builder()
        .with_config(cfg.clone())
        .with_peer_resolver(Arc::new(aitm_peer_process::ProcessResolver::new()));
    // Protocol modules, in registration order (first match claims the connection):
    // PassthroughModule before HttpModule so a pinned or out-of-scope host tunnels
    // past MITM.
    for module in ordered_modules(http, passthrough_list, inject, tunnel_guard.clone()) {
        builder = builder.register_module(module);
    }
    // The `capture.status` handle: the writer leaves in `Assembled` for the macOS
    // capture feeder (`build_capture_session`); the reader serves the bus verb.
    let (capture_status, capture_status_reader) =
        CaptureStatus::channel(features.macos_capture.enabled);
    builder = builder
        // First-party plugins, in chain order. Intercept precedes mutate so a
        // request is parked before mutate would act (data-flow 2).
        .register_plugin(Box::new(CapturePlugin::new()))
        // The subscription tap sits right after capture so it sees every captured
        // flow (the summary is rendered from the store at dispatch time).
        .register_plugin(Box::new(SubscriptionPlugin::new(push_tx.clone())))
        .register_plugin(Box::new(DetailPlugin::new()))
        .register_plugin(Box::new(MetaPlugin::new()))
        .register_plugin(Box::new(ReplayPlugin::new()))
        .register_plugin(Box::new(intercept))
        .register_plugin(Box::new(
            ControlPlugin::new(armed, listening.clone()).with_system_proxy(sysproxy.clone()),
        ))
        // The three `proxy.system.*` verbs over the same engine `proxy.status`
        // summarises; `listening` lets `set` refuse a one-shot process (§D10).
        .register_plugin(Box::new(SysProxyPlugin::new(
            sysproxy.clone(),
            listening.clone(),
        )))
        // The macOS NE capture feeder's read-only state (`capture.status`), beside
        // `proxy.status`: registered on every platform and for every `Features`, so
        // a client can always ask why nothing is captured (capture-status spec D8).
        .register_plugin(Box::new(CaptureStatusPlugin::new(capture_status_reader)));
    if features.mutate {
        builder = builder.register_plugin(Box::new(MutatePlugin::new()));
    }
    let ca_plugin = features
        .ca_plugin
        .clone()
        .unwrap_or_else(|| CaPlugin::new(cfg.ca.clone()));
    builder = builder
        .register_plugin(Box::new(ScopePlugin::new(cfg.scope.allow_agent_widen)))
        .register_plugin(Box::new(RateLimitPlugin::new(cfg.limits.per_host_rps)))
        // M6 feature plugins: WS frame control, session/HAR I/O, passthrough
        // commands, and Map Local/Remote. They take their chain positions after
        // the core feature plugins and before the scripts, so a script sees a
        // flow once map rewrites and WS parks have acted.
        .register_plugin(Box::new(wsctl))
        .register_plugin(Box::new(
            SessionIoPlugin::new(cfg.session_io.allow_agent_file_io)
                .with_session_root(cfg.session_io.root.clone()),
        ))
        .register_plugin(Box::new(passthrough))
        .register_plugin(Box::new(maprules));
    // Scripts take their chain positions here: after every native plugin that
    // acts on a flow, in the order the operator declared them (spec §8).
    for plugin in scripts.plugins {
        builder = builder.register_plugin(plugin);
    }
    // The agent policy state, shared between the `AgentPlugin` (agent.status/set)
    // and the MCP server's policy gate; seeded from config.
    let agent_state = Arc::new(AgentState::new(cfg.mcp.policy));
    // The F2 audit ring, shared between the `AgentPlugin` (agent.activity /
    // agent.status.actions_last_minute) and the MCP server's `call_tool`, which
    // appends one entry per invocation.
    let audit_ring = Arc::new(AuditRing::default());
    // The sealed `Governance`, fixed from the pair the `AgentPlugin` below is registered over.
    let governance = Governance {
        agent_state: Arc::clone(&agent_state),
        audit_ring: Arc::clone(&audit_ring),
    };
    builder = builder
        // Command providers: the browser, poc, ca and agent commands.
        .register_plugin(Box::new(BrowserPlugin::new(cfg.browser.ssrf.clone())))
        .register_plugin(Box::new(PocCommands {
            executor: scripts.executor,
            step_handlers: scripts.poc_step_handlers,
        }))
        .register_plugin(Box::new(ca_plugin))
        .register_plugin(Box::new(
            AgentPlugin::new(agent_state.clone()).with_audit_ring(audit_ring.clone()),
        ));
    for commands in scripts.commands {
        builder = builder.register_plugin(commands);
    }
    // The scanner, last (call B7): its `load` registers a `check.<id>` command
    // for every Rhai `add_check`, so the script tier must have loaded first.
    // The scanner registers no hooks, so chain order is unaffected.
    builder = builder.register_plugin(Box::new(scanner));

    // L4 (raw packet) module: opt-in and fail-closed (M5-AC17). When disabled, it is
    // not constructed and no `l4.*` command is registered. When enabled, it is always
    // registered — even without the capture/inject or in-path privilege — so the
    // operator who opted in sees an honest, drivable surface; the wire-touching verbs
    // then fail closed with the specific missing-capability reason, cached from a
    // cheap startup probe. The pure/read verbs work regardless. Registered before
    // `build()` (which consumes the builder).
    // Capture the L4 module's guard + store before `build()` consumes the module via
    // `register_plugin`; the L4/UDP half of the capture ingress is bound to them below.
    let mut l4_half = None;
    if features.l4.enabled {
        let privilege = features
            .l4_privilege
            .clone()
            .unwrap_or_else(L4Privilege::probe);
        match (&privilege.capture_inject, &privilege.intercept) {
            (None, None) => info!("L4 enabled; capture/inject and in-path privilege present"),
            (ci, ip) => warn!(
                capture_inject = ci.as_deref().unwrap_or("present"),
                in_path = ip.as_deref().unwrap_or("present"),
                "L4 enabled but some privilege is absent; affected l4.* commands will report \
                 L4Unavailable"
            ),
        }
        // When the binary pre-built the L4 state (so the scripting engine's live
        // `L4Language` shares it), build the module over that same guard + store;
        // otherwise the module owns its own. Either way the privilege gate stands.
        let module = match &features.l4_shared {
            Some(shared) => L4Module::with_shared(
                shared.guard.clone(),
                shared.store.clone(),
                features.l4.intercept.clone(),
                privilege,
            ),
            None => L4Module::with_privilege(&features.l4, privilege),
        };
        // Self-exclusion (L4PAR-AC34, spec §2.1): the core's own listener ports —
        // the proxy and browser-proxy ports from `cfg`, plus the bus / web UI / MCP
        // HTTP ports the binary knows — are handed to the module so no capture ever
        // records the core's own loopback traffic, whatever the scope says.
        let module = module.with_self_ports(
            [cfg.listen.port(), cfg.browser.proxy_addr.port()]
                .into_iter()
                .chain(features.l4_self_ports.iter().copied()),
        );
        l4_half = Some((module.guard(), module.store()));
        builder = builder.register_plugin(Box::new(module));
    }

    let proxy = builder.build()?;
    // Bind the late guards to the proxy's real guard before anything is served, so
    // Map Remote's `check_active` and the passthrough module's `in_scope` ride the
    // same scope/rate guard the client path and every other command enforce.
    map_guard.bind(proxy.guard());
    tunnel_guard.bind(proxy.guard());
    native_guard.bind(proxy.guard());

    // The protocol-general capture ingress (L4OPS-AC17). Its stream/TCP half is wired
    // for **every** build, from the live proxy's shared module list, flow store, event
    // chain, SSRF-guarded upstream connector, and scope guard — so a capture backend
    // (Phase 2's macOS Network/System Extension) can feed captured TCP whether or not
    // L4/UDP is enabled. The L4/UDP half is added only when L4 is enabled, bound to the
    // module's own guard + store so an ingress-fed packet is guarded identically to a
    // pcap-fed one and lands where `l4.flow.*` reads.
    let l4_guard = l4_half.as_ref().map(|(guard, _)| guard.clone());
    let ingress = match l4_half {
        Some((guard, store)) => CoreIngress::with_l4(guard, store),
        None => CoreIngress::empty(),
    };
    let l4_ingress = Some(ingress.with_stream(
        proxy.modules(),
        proxy.store(),
        proxy.event_sink(),
        proxy.upstream_connector(true),
        proxy.guard(),
    ));

    Ok(Assembled {
        proxy,
        ca,
        listening,
        agent_state,
        push_tx,
        audit_ring,
        l4_ingress,
        l4_guard,
        capture_status,
        sysproxy,
        job_bus,
        scan_late,
        scanner_engine,
        governance,
    })
}

/// Build the macOS NE live-capture session, or `None` when it is not switched on.
///
/// `Some` only when `features.macos_capture.enabled` — the deny-by-default
/// on-switch, which only the operator's config file can flip (there is no bus,
/// MCP, or script path to this function; see `no_agent_path_to_capture_session`).
/// Building is pure: nothing binds and no file is written until the caller drives
/// [`CaptureSession::run`], so the disabled path costs nothing and is testable in a
/// sandbox. `ingress`, `l7_guard` and `l4_guard` are the assembled proxy's own
/// ([`Assembled::l4_ingress`], `Proxy::guard`, [`Assembled::l4_guard`]), so a
/// captured flow is gated by exactly the guards a proxied one is. `status` is the
/// assembly's [`Assembled::capture_status`]; when the switch is off it is dropped
/// here, so the `capture.status` verb keeps reporting `off`.
#[must_use]
pub fn build_capture_session(
    features: &Features,
    ingress: CoreIngress,
    l7_guard: Arc<dyn ScopeRateGuard>,
    l4_guard: Option<Arc<L4Guard>>,
    verifier: Arc<dyn PeerVerifier>,
    socket_dir: PathBuf,
    status: CaptureStatusWriter,
) -> Option<CaptureSession> {
    features.macos_capture.enabled.then(|| {
        CaptureSession::new(
            Arc::new(ingress),
            l7_guard,
            l4_guard,
            verifier,
            socket_dir,
            status,
        )
    })
}

/// The protocol modules in registration order. [`PassthroughModule`] is **first**
/// so its tunnel-authority match wins over [`HttpModule`] for a pinned or
/// out-of-scope host (the acceptor picks the first module whose `matches` returns
/// true); then `HttpModule` (MITM for every in-scope host), then [`WsModule`]
/// (post-upgrade only), sharing the `inject` registry [`WsCtlPlugin`] holds so
/// `ws.send` reaches a live conversation. `scope` is the live scope guard the
/// passthrough module decides "in Scope" on (spec D1/D2). One source of module
/// order for [`assemble_with_scripts`] and the wiring test.
pub fn ordered_modules(
    http: HttpModule,
    passthrough: PassthroughList,
    inject: InjectRegistry,
    scope: Arc<dyn ScopeRateGuard>,
) -> Vec<Arc<dyn ProtocolModule>> {
    vec![
        Arc::new(PassthroughModule::new(passthrough).with_scope(scope)),
        Arc::new(http),
        Arc::new(WsModule::new().with_inject_registry(inject)),
    ]
}

/// A [`ScopeRateGuard`] handle Map Remote and the passthrough module can hold
/// before the proxy (and thus its guard) exists. The guard is created inside
/// `Proxy::build`; this forwards to it once [`bind`](LateGuard::bind) is called
/// (immediately after build, before serving). Unbound it refuses every active
/// check and reports nothing in scope — a guard that cannot check must not permit
/// (deny-by-default). Mirrors `scripts::LateHandles`' guard facet without pulling
/// in its store/client/browser facets.
#[derive(Default)]
struct LateGuard(OnceLock<Arc<dyn ScopeRateGuard>>);

impl LateGuard {
    /// Bind the proxy's real guard. Call once, before serving.
    fn bind(&self, guard: Arc<dyn ScopeRateGuard>) {
        let _ = self.0.set(guard);
    }
}

impl ScopeRateGuard for LateGuard {
    fn check_active(&self, host: &str) -> Result<ActionPermit, GuardError> {
        match self.0.get() {
            Some(guard) => guard.check_active(host),
            None => Err(GuardError::OutOfScope(host.to_string())),
        }
    }

    fn add_scope(&self, entry: ScopeEntry) {
        if let Some(guard) = self.0.get() {
            guard.add_scope(entry);
        }
    }

    fn remove_scope(&self, entry: &str) -> bool {
        self.0.get().map(|g| g.remove_scope(entry)).unwrap_or(false)
    }

    fn list_scope(&self) -> Vec<ScopeEntry> {
        self.0.get().map(|g| g.list_scope()).unwrap_or_default()
    }

    /// Forward to the bound guard; unbound keeps the trait's deny-by-default
    /// `false` (an unbound guard must not report a host in scope). The capture
    /// ingress scope-gates captured streams on this, so the delegation must be
    /// complete before a live feeder routes through it.
    fn in_scope(&self, host: &str) -> bool {
        self.0.get().map(|g| g.in_scope(host)).unwrap_or(false)
    }

    fn record_error(&self, host: &str) {
        if let Some(guard) = self.0.get() {
            guard.record_error(host);
        }
    }
}

/// Assemble the proxy from configuration with the default feature set.
pub fn build_proxy(cfg: &Config) -> anyhow::Result<Proxy> {
    Ok(assemble(cfg)?.proxy)
}

/// Assemble the proxy from configuration and an explicit feature set.
pub fn build_proxy_with(cfg: &Config, features: &Features) -> anyhow::Result<Proxy> {
    Ok(assemble_with(cfg, features)?.proxy)
}

/// A plugin that registers the `poc.build` and `poc.run` commands. The poc crate
/// exposes free `register` functions rather than a plugin; this adapts them into
/// the one `load`-driven registration path the builder uses.
///
/// With a script executor, `poc.run` dispatches `script` steps through the Rhai
/// tier; without one it is the declarative M1 command.
struct PocCommands {
    executor: Option<Arc<dyn aitm_poc::ScriptStepExecutor>>,
    /// Native protocol-namespace step handlers (`l4:`), threaded to `poc.run`
    /// together with the executor (the production path always supplies both).
    step_handlers: aitm_poc::step_registry::PocStepRegistry,
}

impl Plugin for PocCommands {
    fn name(&self) -> &str {
        "poc"
    }

    fn load(&mut self, reg: &mut Registry) {
        aitm_poc::builder::register(reg);
        match self.executor.clone() {
            Some(exec) => aitm_poc::runner::register_with_executor_and_steps(
                reg,
                exec,
                self.step_handlers.clone(),
            ),
            None => aitm_poc::runner::register(reg),
        }
        aitm_poc::library::register(reg);
    }
}

/// The request sender backing `flow.replay` / `request.send`: real HTTP/1.1 over
/// `aitm-proto-http`'s `Http1Machine` (chunked decode, clean framing) with TLS
/// for `https`. Re-exported from `aitm-proto-http`.
pub use aitm_proto_http::Http1Sender;

/// What the binary does with an agent transport's bound address, through
/// `McpServer::on_bound`: the same `FnOnce(SocketAddr)` that method takes.
pub type BoundHook = Box<dyn FnOnce(std::net::SocketAddr) + Send + 'static>;

/// The [`BoundHook`] that unions the agent transport's bound port into the live
/// L4 guard's self ports ([`L4Guard::add_self_ports`]), so a loopback capture
/// never records the bus's own frames — its plaintext `{"token": …}` first line
/// among them (L4PAR-AC34, spec §2.1). The bound port is the configured one or
/// the ephemeral port a `port: 0` resolved to, which only `on_bound` can know.
/// The one hook both the bare-`aitm` server path and `aitm tui` attach, so the
/// two cannot drift.
#[must_use]
pub fn self_port_hook(guard: Arc<L4Guard>) -> BoundHook {
    Box::new(move |addr: std::net::SocketAddr| {
        guard.add_self_ports([addr.port()]);
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::macos_capture::peer_auth::CodeSignatureVerifier;
    use crate::macos_capture::status::{FeederState, OffReason};
    use crate::macos_capture::test_support::{at, disabled_literal, s};
    use aitm_core::{CommandHost, Params, Value};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::SystemTime;

    /// A unique temp directory for a test's CA material (assembly generates a CA).
    fn temp_ca_dir(tag: &str) -> std::path::PathBuf {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let nanos = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("aitm-wire-{tag}-{nanos}-{n}"))
    }

    /// L4OPS-AC17 (wiring): the assembled ingress carries its stream half for every
    /// build (default features, L4 off), and deny-by-default holds — a captured TCP flow
    /// to an out-of-scope host (empty scope) is `Refused` before any module match or
    /// dial, so no network is reached.
    #[tokio::test]
    async fn assembled_ingress_dispatches_or_refuses_tcp() {
        let mut cfg = Config::default();
        cfg.ca.dir = temp_ca_dir("ingress-tcp");
        let assembled = assemble(&cfg).expect("assemble with default features");
        let ingress = assembled
            .l4_ingress
            .expect("the stream half of the capture ingress is wired for every build");

        let flow = crate::ingress::CapturedTcpFlow {
            stream: Box::pin(tokio::io::duplex(16).0),
            dst: "93.184.216.34:443".parse().unwrap(),
            sni: Some("example.com".to_string()),
            first_bytes: vec![0x16, 0x03, 0x01],
            peer_identity: None,
            interface: "test-if".to_string(),
        };
        assert_eq!(
            ingress.dispatch_tcp(flow).await,
            crate::ingress::StreamOutcome::Refused,
            "empty scope means out of scope: refused before any dial, no network"
        );
    }

    /// Features with only the `macos_capture` switch set.
    fn capture_features(enabled: bool) -> Features {
        Features {
            macos_capture: MacosCaptureConfig {
                enabled,
                ..MacosCaptureConfig::default()
            },
            ..Features::default()
        }
    }

    /// `build_capture_session` over inert parts and the given status writer: nothing
    /// here binds or runs, because building a session is pure and only `run` touches
    /// a socket.
    fn build_with_status(
        features: &Features,
        status: CaptureStatusWriter,
    ) -> Option<CaptureSession> {
        build_capture_session(
            features,
            crate::ingress::CoreIngress::empty(),
            Arc::new(LateGuard::default()),
            None,
            Arc::new(CodeSignatureVerifier::default()),
            std::path::PathBuf::from("/nonexistent-wire-test-dir"),
            status,
        )
    }

    /// [`build_with_status`] over a fresh handle nobody reads.
    fn build_with(features: &Features) -> Option<CaptureSession> {
        build_with_status(
            features,
            CaptureStatus::channel(features.macos_capture.enabled).0,
        )
    }

    /// CS-AC20: with the feature off, `build_capture_session` builds nothing and
    /// drops the writer, so the handle keeps reporting the constructor's disabled
    /// state, the D7 literal.
    #[test]
    fn disabled_capture_session_leaves_status_off() {
        let (w, r) = CaptureStatus::channel(false);
        assert!(build_with_status(&capture_features(false), w).is_none());
        assert_eq!(r.snapshot().to_value(), disabled_literal());
    }

    /// Building an enabled session is pure: until `run` binds, the handle reports
    /// `not started` on macOS and `not a macOS build` elsewhere.
    #[test]
    fn enabled_capture_session_is_not_started_until_run() {
        let (w, r) = CaptureStatus::channel(true);
        assert!(build_with_status(&capture_features(true), w).is_some());
        let expected = if cfg!(target_os = "macos") {
            OffReason::NotStarted
        } else {
            OffReason::NotMacos
        };
        assert_eq!(r.snapshot().feeder, FeederState::Off(expected));
    }

    /// LF-AC1: with `macos_capture.enabled = false` (the default) no capture session
    /// is built, so nothing can bind a listener or publish a rendezvous file.
    #[test]
    fn capture_session_absent_when_disabled() {
        assert!(build_with(&capture_features(false)).is_none());
        assert!(
            build_with(&Features::default()).is_none(),
            "the default feature set is deny-by-default"
        );
    }

    /// The config switch is the one thing that builds a session.
    #[test]
    fn capture_session_present_when_enabled() {
        assert!(build_with(&capture_features(true)).is_some());
    }

    /// Invoke the registered `capture.status` the way a frontend does: through the
    /// proxy's registry, over the service handles `main` shares with the frontends.
    fn invoke_capture_status(proxy: &Proxy, cfg: &Config) -> Value {
        let services = crate::tui::services(
            proxy,
            cfg,
            None,
            crate::tui::TuiLog::Off,
            Arc::new(JobBus::default()),
        );
        let host = CommandHost::new(&*services.store, &*services.client, &*services.guard, None);
        proxy
            .registry()
            .command("capture.status")
            .expect("registered")
            .invoke(Params::default(), &host)
            .expect("capture.status never errors")
    }

    /// **CS-AC3.** The default feature set and an explicit
    /// `macos_capture.enabled = false` both register a `capture.status` that
    /// returns exactly the D7 disabled literal.
    #[test]
    fn capture_status_verb_reports_the_disabled_literal() {
        let mut cfg = Config::default();
        cfg.ca.dir = temp_ca_dir("capture-status-default");
        let assembled = assemble(&cfg).expect("assemble with default features");
        assert_eq!(
            invoke_capture_status(&assembled.proxy, &cfg),
            disabled_literal(),
            "default features"
        );
        let _ = std::fs::remove_dir_all(&cfg.ca.dir);

        let mut cfg = Config::default();
        cfg.ca.dir = temp_ca_dir("capture-status-off");
        let assembled =
            assemble_with(&cfg, &capture_features(false)).expect("assemble, capture off");
        assert_eq!(
            invoke_capture_status(&assembled.proxy, &cfg),
            disabled_literal(),
            "capture_features(false)"
        );
        let _ = std::fs::remove_dir_all(&cfg.ca.dir);
    }

    /// **CS-AC20.** The registered verb reads the handle built from the `Features`
    /// passed to assembly: with the switch on it reports `enabled: true` and the
    /// constructor's platform-derived `off` reason.
    #[test]
    fn capture_status_verb_follows_the_feature_switch() {
        let mut cfg = Config::default();
        cfg.ca.dir = temp_ca_dir("capture-status-on");
        let assembled = assemble_with(&cfg, &capture_features(true)).expect("assemble, capture on");
        let status = invoke_capture_status(&assembled.proxy, &cfg);
        assert_eq!(at(&status, "enabled"), &Value::Bool(true));
        assert_eq!(at(&status, "capability"), &s("feeder_off"));
        let reason = if cfg!(target_os = "macos") {
            "not started"
        } else {
            "not a macOS build"
        };
        assert_eq!(at(at(&status, "feeder"), "reason"), &s(reason));
        let _ = std::fs::remove_dir_all(&cfg.ca.dir);
    }

    /// **CS-AC20.** `Assembled.capture_status` is the writer of the channel the
    /// registered verb reads: handing it to `build_capture_session` with the switch
    /// off builds nothing, drops the writer, and the verb keeps reporting the
    /// disabled literal.
    #[test]
    fn disabled_session_drops_the_writer_and_the_verb_stays_off() {
        let mut cfg = Config::default();
        cfg.ca.dir = temp_ca_dir("capture-status-dropped");
        let features = capture_features(false);
        let Assembled {
            proxy,
            l4_ingress,
            capture_status,
            ..
        } = assemble_with(&cfg, &features).expect("assemble, capture off");
        let session = build_capture_session(
            &features,
            l4_ingress.expect("the stream half of the capture ingress is wired for every build"),
            proxy.guard(),
            None,
            Arc::new(CodeSignatureVerifier::default()),
            PathBuf::from("/nonexistent-wire-test-dir"),
            capture_status,
        );
        assert!(session.is_none(), "the switch is off: no session");
        assert_eq!(invoke_capture_status(&proxy, &cfg), disabled_literal());
        let _ = std::fs::remove_dir_all(&cfg.ca.dir);
    }

    /// `Assembled.l4_guard` is `Some` exactly when L4 is enabled, and it is the
    /// module's own guard, not a fresh one: the feeder must scope the provider from
    /// the same L4 engagement state the operator mutates.
    #[test]
    fn l4_guard_tracks_l4_enabled() {
        let mut cfg = Config::default();
        cfg.ca.dir = temp_ca_dir("l4-guard-on");
        let shared = L4Shared {
            guard: Arc::new(L4Guard::new(&L4Config {
                enabled: true,
                ..L4Config::default()
            })),
            store: Arc::new(aitm_proto_l4::flow::InMemoryL4FlowStore::new()),
        };
        let enabled = Features {
            l4: L4Config {
                enabled: true,
                ..L4Config::default()
            },
            l4_privilege: Some(L4Privilege::available()),
            l4_shared: Some(shared.clone()),
            ..Features::default()
        };
        let assembled = assemble_with(&cfg, &enabled).expect("assemble with l4 enabled");
        let guard = assembled
            .l4_guard
            .expect("l4 enabled exposes the l4 guard for the capture feeder");
        assert!(
            Arc::ptr_eq(&guard, &shared.guard),
            "the exposed guard is the shared module guard, not a second instance"
        );

        let mut cfg = Config::default();
        cfg.ca.dir = temp_ca_dir("l4-guard-off");
        let disabled = assemble_with(&cfg, &Features::default()).expect("assemble, l4 disabled");
        assert!(disabled.l4_guard.is_none());
    }

    /// Task 11 / spec D1: the binary already calls every scanner v2 lane slot, and
    /// a skeleton slot returning `None` is skipped rather than collected. Three lanes
    /// have landed: T2 (`aitm-scan-http`), T4 (`aitm-scan-ws`) and T5
    /// (`aitm-scan-l4-packet`, which returns `Some` even without the L4 handles,
    /// call A18); the remaining slots are still skeletons, and with the L4 handles
    /// present the stream slot is still called and still contributes nothing. Each
    /// lane track's landing bumps these literals; that track re-pins this test.
    #[test]
    fn lane_slots_count_the_landed_lanes() {
        assert_eq!(collect_lanes(None).len(), 3);
        // T3 (`aitm-scan-checks-http`): the ten D8.2 natives, built through the
        // gated constructor with an unbound guard (deny-by-default until the
        // proxy binds it).
        let natives = collect_native_checks(SsrfPolicy::default(), Arc::new(LateGuard::default()));
        assert_eq!(natives.len(), 10);
        let mut ids: Vec<&str> = natives.iter().map(|c| c.meta().id.as_str()).collect();
        ids.sort_unstable();
        assert_eq!(
            ids,
            [
                "cmdi-time",
                "h2-cl-te-downgrade-indicator",
                "h2-header-crlf-tolerance",
                "h2-pseudo-header-validation",
                "h2-rapid-reset-mitigation",
                "h2-settings-observe",
                "open-redirect",
                "sqli-boolean",
                "sqli-time",
                "xss-reflected",
            ]
        );

        let shared = L4Shared {
            guard: Arc::new(L4Guard::new(&L4Config {
                enabled: true,
                ..L4Config::default()
            })),
            store: Arc::new(aitm_proto_l4::flow::InMemoryL4FlowStore::new()),
        };
        assert_eq!(collect_lanes(Some(&shared)).len(), 3);
    }

    /// Task 19 (T4 hand-off): the operator's `ssl_insecure` reaches the WS
    /// lane's dialer. The lane verifies upstream certificates by default, so a
    /// self-signed `wss://` lab target is Inconclusive unless the binary
    /// selects `TlsPolicy::AcceptAny`. `dyn Lane` exposes nothing about its
    /// transport (`TcpTransport::tls_policy` is `pub(crate)` in
    /// `aitm-scan-ws`), so the assertion is on the policy this module hands the
    /// builder, plus the fact that the insecure build is still the one `ws`
    /// lane.
    #[test]
    fn the_ws_lane_receives_ssl_insecure() {
        use aitm_scan_model::LaneKind;

        let mut cfg = Config::default();
        assert_eq!(
            ws_tls_policy(&cfg),
            TlsPolicy::Verify,
            "the default posture"
        );

        cfg.ssl_insecure = true;
        assert_eq!(
            ws_tls_policy(&cfg),
            TlsPolicy::AcceptAny,
            "ssl_insecure: true relaxes the WS lane's chain validation"
        );

        let lanes = collect_lanes_with(None, ws_tls_policy(&cfg));
        assert!(
            lanes.iter().any(|lane| lane.lane() == LaneKind::Ws),
            "the WS lane is among the collected lanes: {:?}",
            lanes.iter().map(|lane| lane.lane()).collect::<Vec<_>>()
        );
    }

    /// A check that sends nothing, standing in for one a Rhai `reg.add_check`
    /// declared. The model crate's `NullCheck` lives behind its `testing`
    /// feature, which this crate does not enable, so the wiring test carries its
    /// own two-line check rather than growing a dependency.
    struct WiredCheck(aitm_scan_model::CheckMeta);

    impl WiredCheck {
        fn new(id: &str) -> Self {
            Self(aitm_scan_model::CheckMeta {
                id: id.to_string(),
                name: id.to_string(),
                class: "none".to_string(),
                lanes: vec![aitm_scan_model::LaneKind::Http],
                kinds: vec![aitm_scan_model::InsertionKind::Query],
                intensity: aitm_scan_model::Intensity::Passive,
                cost: aitm_scan_model::CheckCost::Light,
                technique: aitm_scan_model::Technique::Observe,
                severity: aitm_poc::Severity::Info,
                confidence_max: aitm_scan_model::Confidence::Tentative,
                needs_baseline: false,
                wants_traits: None,
                targets_session: false,
                scope: aitm_scan_model::CheckScope::Point,
                cwe: None,
                description: "Concludes nothing.".to_string(),
                remediation: None,
                origin: aitm_scan_model::CheckOrigin::Custom {
                    path: "wired.rhai".to_string(),
                },
            })
        }
    }

    impl aitm_scan_model::Check for WiredCheck {
        fn meta(&self) -> &aitm_scan_model::CheckMeta {
            &self.0
        }

        fn run<'a>(
            &'a self,
            _point: &'a aitm_scan_model::InsertionPoint,
            _host: &'a dyn aitm_scan_model::ProbeHost,
        ) -> futures::future::BoxFuture<'a, aitm_scan_model::Verdict> {
            Box::pin(async {
                aitm_scan_model::Verdict {
                    outcome: aitm_scan_model::Outcome::Clean,
                    confidence: aitm_scan_model::Confidence::Tentative,
                    evidence: aitm_scan_model::Evidence::default(),
                    detail: "nothing to report".to_string(),
                    poc_hint: None,
                    location: None,
                    more: Vec::new(),
                }
            })
        }
    }

    /// A plugin that registers a check — not a command — while it loads, which
    /// is what the Rhai tier does for every `reg.add_check` in a script.
    struct CheckPusher {
        checks: Arc<aitm_scan_model::CheckRegistry>,
        id: &'static str,
    }

    impl Plugin for CheckPusher {
        fn name(&self) -> &str {
            "check-pusher"
        }

        fn load(&mut self, _reg: &mut Registry) {
            self.checks
                .add("test-script", Arc::new(WiredCheck::new(self.id)))
                .expect("the registry is empty, so the id is free");
        }
    }

    /// Spec D9.2 and D5 (call B3): assembly builds the one [`aitm_core::JobBus`]
    /// every server is handed and the write-once cell `main.rs` binds the
    /// scanner's owned handles into once the proxy exists. Straight out of
    /// assembly nobody subscribes to the bus and nothing is bound, so a `scan.*`
    /// verb that reached the engine before `bind_proxy` is told plainly that the
    /// services are missing instead of running a job over handles that do not
    /// exist yet.
    #[test]
    fn assembled_exposes_a_job_bus_and_an_unbound_scan_late() {
        let mut cfg = Config::default();
        cfg.ca.dir = temp_ca_dir("job-bus");
        let assembled = assemble(&cfg).expect("assemble");

        assert_eq!(assembled.job_bus.receiver_count(), 0);
        assert!(!assembled.scan_late.is_bound());
        let err = assembled
            .scan_late
            .get()
            .expect_err("the cell is unbound until main.rs binds it");
        assert!(
            err.to_string().contains("not bound"),
            "the unbound error names the condition: {err}"
        );

        let _ = std::fs::remove_dir_all(&cfg.ca.dir);
    }

    /// Task 15 and call B7: an ordinary assembly carries the whole scanner v2
    /// verb surface plus one `check.<id>` command per catalogue entry. Which
    /// entries exist depends on the lanes this build links, so the manual
    /// verbs are checked against the engine's own catalogue; the three shipped
    /// passive checks are engine-native (spec amendment 24) and are asserted
    /// unconditionally, the two legacy active ids only while the `http` lane
    /// is the interim one.
    #[test]
    fn scan_verbs_and_manual_checks_are_registered() {
        let mut cfg = Config::default();
        cfg.ca.dir = temp_ca_dir("scan-verbs");
        let assembled = assemble(&cfg).expect("assemble");
        let reg = assembled.proxy.registry();
        let engine = assembled
            .scanner_engine
            .get()
            .expect("the scanner plugin built its engine during assembly")
            .clone();
        let catalogue = engine.catalogue();
        let ids: Vec<String> = catalogue
            .all()
            .iter()
            .map(|c| c.meta().id.clone())
            .collect();
        assert!(!ids.is_empty(), "the catalogue is never empty");
        for id in &ids {
            assert!(
                reg.command(&format!("check.{id}")).is_some(),
                "check.{id} is registered for catalogue entry {id}"
            );
        }
        // Spec amendment 24 ("the passives stay"): the engine ships the three
        // passive checks whatever lane holds the http slot, so their manual
        // verbs are on every build.
        for id in ["reflection", "security-header", "cookie-flag"] {
            assert!(
                ids.iter().any(|have| have == id),
                "shipped passive check {id} is in the catalogue"
            );
            assert!(
                reg.command(&format!("check.{id}")).is_some(),
                "check.{id} is registered"
            );
        }
        let http_is_interim = engine.lane_entries().iter().any(|e| {
            e.lane == aitm_scan_model::LaneKind::Http
                && e.source == aitm_scan_model::LaneSource::Interim
        });
        if http_is_interim {
            for id in ["xss-reflected", "open-redirect"] {
                assert!(
                    ids.iter().any(|have| have == id),
                    "interim check {id} is in the catalogue"
                );
            }
        }

        for name in [
            "scan.start",
            "scan.map",
            "scan.status",
            "scan.list",
            "scan.cancel",
            "scan.issues",
            "scan.issue",
            "scan.issue.update",
            "scan.sitemap",
            "scan.checks",
            "scan.profile.list",
            "scan.profile.get",
            "scan.profile.save",
            "scan.profile.delete",
            "scan.session.preview",
            "scan.discover",
            "scan.passive",
            "scan.report",
        ] {
            assert!(reg.command(name).is_some(), "{name} is registered");
        }

        let _ = std::fs::remove_dir_all(&cfg.ca.dir);
    }

    /// Call B7: the scanner's `load` mints a `check.<id>` command for every
    /// check the scripting tier declared, so it has to be registered **after**
    /// the script tier — a plugin that adds a check while it loads (what a Rhai
    /// `reg.add_check` does) must be visible to the scanner, not half a chain
    /// too late.
    #[test]
    fn scanner_loads_after_the_script_tier() {
        let mut cfg = Config::default();
        cfg.ca.dir = temp_ca_dir("script-checks");
        let checks = Arc::new(aitm_scan_model::CheckRegistry::new());
        let assembled = assemble_with_scripts(
            &cfg,
            &Features::default(),
            ScriptWiring {
                plugins: vec![Box::new(CheckPusher {
                    checks: Arc::clone(&checks),
                    id: "wired-check",
                })],
                script_checks: Some(Arc::clone(&checks)),
                ..ScriptWiring::default()
            },
        )
        .expect("assemble with a scripting tier");

        assert_eq!(
            checks.len(),
            1,
            "the tier registered its check while loading"
        );
        assert!(
            assembled
                .proxy
                .registry()
                .command("check.wired-check")
                .is_some(),
            "the scanner loaded after the tier and saw its check"
        );

        let _ = std::fs::remove_dir_all(&cfg.ca.dir);
    }

    /// Spec D11 (call D11): the plugin runs on the `scanner:` section the config
    /// file parsed — never `ScannerConfig::default()` — and the binary copies the
    /// two values that are not `scanner:` keys onto it: `findings.dir`, where job,
    /// issue and profile state is written, and `l4.allow_agent_inject`, so the
    /// `scan.start` L4 gate reads one struct rather than two.
    #[test]
    fn scanner_config_reaches_the_plugin() {
        let mut cfg = Config::default();
        cfg.ca.dir = temp_ca_dir("scanner-cfg");
        cfg.findings.dir = Some(temp_ca_dir("scanner-findings"));
        let features = Features {
            scanner: aitm_plugin_scanner::ScannerConfig {
                max_jobs: 7,
                default_profile: "light-http".to_string(),
                ..aitm_plugin_scanner::ScannerConfig::default()
            },
            l4: L4Config {
                allow_agent_inject: true,
                ..L4Config::default()
            },
            ..Features::default()
        };

        let assembled = assemble_with(&cfg, &features).expect("assemble");
        let engine = assembled
            .scanner_engine
            .get()
            .expect("the plugin's `load` built the engine");
        assert_eq!(engine.cfg.max_jobs, 7);
        assert_eq!(engine.cfg.default_profile, "light-http");
        assert_eq!(engine.cfg.findings_dir, cfg.findings.dir);
        assert!(engine.cfg.l4_allow_agent_inject);

        let _ = std::fs::remove_dir_all(&cfg.ca.dir);
    }

    /// L4PAR-AC34 / spec §2.1: the hook both the server path and `aitm tui` hand
    /// the agent `McpServer`'s `on_bound` unions the bound port — the ephemeral
    /// one a `port: 0` resolved to included — into the live L4 guard's self ports,
    /// so a loopback capture never records the bus's plaintext token line. Port 0
    /// is never a bound listener and stays out.
    #[test]
    fn the_bound_port_hook_adds_the_agent_port_to_the_l4_guard() {
        let guard = Arc::new(L4Guard::new(&L4Config::default()));
        assert_eq!(guard.self_ports(), Vec::<u16>::new());

        let hook = self_port_hook(guard.clone());
        hook("127.0.0.1:41234".parse().expect("socket addr"));
        assert_eq!(guard.self_ports(), vec![41234]);

        // A second bind (a later run on the same guard) adds, never replaces.
        self_port_hook(guard.clone())("127.0.0.1:27431".parse().expect("socket addr"));
        assert_eq!(guard.self_ports(), vec![27431, 41234]);

        self_port_hook(guard.clone())("127.0.0.1:0".parse().expect("socket addr"));
        assert_eq!(guard.self_ports(), vec![27431, 41234], "port 0 is ignored");
    }

    /// L4PAR-AC34 (plan A10): assembly hands the L4 module the core's own
    /// listener ports — the proxy and browser-proxy ports from `cfg` plus
    /// `Features::l4_self_ports` (bus, web UI, MCP HTTP) — so no capture ever
    /// records them.
    #[test]
    fn l4_self_ports_cover_the_cores_listeners() {
        let mut cfg = Config::default();
        cfg.ca.dir = temp_ca_dir("l4-self-ports");
        cfg.listen = "127.0.0.1:28180".parse().unwrap();
        cfg.browser.proxy_addr = "127.0.0.1:28181".parse().unwrap();
        let shared = L4Shared {
            guard: Arc::new(L4Guard::new(&L4Config {
                enabled: true,
                ..L4Config::default()
            })),
            store: Arc::new(aitm_proto_l4::flow::InMemoryL4FlowStore::new()),
        };
        let features = Features {
            l4: L4Config {
                enabled: true,
                ..L4Config::default()
            },
            l4_privilege: Some(L4Privilege::available()),
            l4_shared: Some(shared.clone()),
            l4_self_ports: vec![28182, 27431],
            ..Features::default()
        };
        let assembled = assemble_with(&cfg, &features).expect("assemble with l4 enabled");
        let guard = assembled.l4_guard.expect("l4 enabled exposes the guard");
        assert_eq!(guard.self_ports(), vec![27431, 28180, 28181, 28182]);
        let _ = std::fs::remove_dir_all(&cfg.ca.dir);
    }

    /// `Assembled::governance` hands out the assembly's own `agent_state` and
    /// `audit_ring` `Arc`s, not copies, and `Clone` keeps that identity: a
    /// policy set through the `Governance` is the policy the core reads.
    #[test]
    fn governance_carries_the_assemblys_own_state_and_ring() {
        let mut cfg = Config::default();
        cfg.ca.dir = temp_ca_dir("governance-identity");
        let assembled = assemble(&cfg).expect("assemble with default features");
        let governance = assembled.governance();
        let cloned = governance.clone();
        for (what, held) in [("governance", &governance), ("its clone", &cloned)] {
            assert!(
                Arc::ptr_eq(&held.agent_state, &assembled.agent_state),
                "{what}: agent_state is a copy"
            );
            assert!(
                Arc::ptr_eq(&held.audit_ring, &assembled.audit_ring),
                "{what}: audit_ring is a copy"
            );
        }
        governance
            .agent_state
            .set_policy(aitm_core::AgentPolicy::Paused);
        assert_eq!(
            assembled.agent_state.policy(),
            aitm_core::AgentPolicy::Paused
        );
        let _ = std::fs::remove_dir_all(&cfg.ca.dir);
    }

    /// The `Governance` is fixed at assembly, from the pair the `AgentPlugin`
    /// was registered over. Overwriting the `pub` `agent_state` / `audit_ring`
    /// fields afterwards (which a caller outside the crate can do) does not
    /// change what `governance()` hands out, so the agent server built from it
    /// still reads the state `agent.set` writes.
    #[test]
    fn governance_is_fixed_at_assembly_not_read_from_the_public_fields() {
        let mut cfg = Config::default();
        cfg.ca.dir = temp_ca_dir("governance-fixed");
        let mut assembled = assemble(&cfg).expect("assemble with default features");
        let original_state = Arc::clone(&assembled.agent_state);
        let original_ring = Arc::clone(&assembled.audit_ring);

        assembled.agent_state = Arc::new(AgentState::new(aitm_core::AgentPolicy::Auto));
        assembled.audit_ring = Arc::new(AuditRing::default());

        let governance = assembled.governance();
        assert!(
            Arc::ptr_eq(&governance.agent_state, &original_state),
            "governance() read the substituted agent_state, not the assembly's own"
        );
        assert!(
            Arc::ptr_eq(&governance.audit_ring, &original_ring),
            "governance() read the substituted audit_ring, not the assembly's own"
        );
        let _ = std::fs::remove_dir_all(&cfg.ca.dir);
    }

    /// Every `*.rs` file under `dir`, recursively.
    fn rust_sources(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        for entry in std::fs::read_dir(dir).unwrap_or_else(|e| panic!("read {dir:?}: {e}")) {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                rust_sources(&path, out);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                out.push(path);
            }
        }
    }

    /// LF-AC12 (structural): the capture feeder has no agent path. The only way to
    /// build or start a `CaptureSession` is the config-driven startup in `main.rs`
    /// (through `wire.rs`); no bus, MCP, CLI, session, or script command source in
    /// the workspace names either symbol. A tripwire, like
    /// `one_choke_point_survives_ingress`, over the type-level fact that no other
    /// crate depends on `aitm`.
    #[test]
    fn no_agent_path_to_capture_session() {
        let crates = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("crates dir");
        let aitm_src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut sources = Vec::new();
        for krate in std::fs::read_dir(crates).expect("read crates dir") {
            let src = krate.expect("crate entry").path().join("src");
            if src.is_dir() {
                rust_sources(&src, &mut sources);
            }
        }

        // The tripwire must actually be looking at the agent-reachable surfaces.
        for must_scan in [
            "aitm-mcp/src/server.rs",
            "aitm-plugins/src/scope.rs",
            "aitm-plugin-sessionio/src/lib.rs",
            "aitm-cli/src/dispatch.rs",
            "aitm/src/web/bridge.rs",
            "aitm/src/tui.rs",
        ] {
            assert!(
                sources.iter().any(|p| p.ends_with(must_scan)),
                "{must_scan} must be among the scanned sources"
            );
        }

        let mut offenders = Vec::new();
        for path in &sources {
            let allowed = path == &aitm_src.join("main.rs")
                || path == &aitm_src.join("wire.rs")
                || path.starts_with(aitm_src.join("macos_capture"));
            if allowed {
                continue;
            }
            let text = std::fs::read_to_string(path)
                .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
            for symbol in ["build_capture_session(", "CaptureSession::"] {
                if text.contains(symbol) {
                    offenders.push(format!("{} names `{symbol}`", path.display()));
                }
            }
        }
        assert_eq!(
            offenders,
            Vec::<String>::new(),
            "only the config-driven startup may build or run the capture session"
        );
    }
}

/// System-proxy wiring (plan 2026-10-31-system-proxy-automation, Task 9).
#[cfg(test)]
mod sysproxy_tests {
    use super::*;
    use aitm_ca::exec::Executor;
    use aitm_ca::testing::ScriptedExecutor;
    use aitm_core::{CommandHost, Frontend, Params, TypeDesc, Value};
    use aitm_sysproxy::{Endpoint, Mechanism, SystemProxy, SystemProxyConfig, STATE_FILE_NAME};
    use std::sync::atomic::Ordering;

    const LIST: &str = "/usr/sbin/networksetup -listallnetworkservices";
    const LIST_OUT: &str = "An asterisk (*) denotes that a network service is disabled.\nDisplay Ethernet\n*Thunderbolt Bridge\nWi-Fi\n";
    const SCUTIL: &str = "/usr/sbin/scutil --proxy";
    const DE: &str = "'Display Ethernet'";
    const WIFI: &str = "Wi-Fi";
    const BYPASS_OUT: &str = "*.local\n169.254/16\n";

    /// A unique temp directory for the CA and the state file.
    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!("aitm-wire-sysproxy-{tag}-{nanos}"));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    /// `-getwebproxy` / `-getsecurewebproxy` output; port 0 is "Enabled: No".
    fn proxy_out(host: &str, port: u16) -> String {
        if port == 0 {
            "Enabled: No\nServer: \nPort: 0\nAuthenticated Proxy Enabled: 0\n".to_string()
        } else {
            format!("Enabled: Yes\nServer: {host}\nPort: {port}\nAuthenticated Proxy Enabled: 0\n")
        }
    }

    /// `scutil --proxy` output with both protocols at `host:port`.
    fn scutil_out(host: &str, port: u16) -> String {
        format!("<dictionary> {{\n  ExceptionsList : <array> {{\n    0 : *.local\n    1 : 169.254/16\n  }}\n  HTTPEnable : 1\n  HTTPPort : {port}\n  HTTPProxy : {host}\n  HTTPSEnable : 1\n  HTTPSPort : {port}\n  HTTPSProxy : {host}\n}}\n")
    }

    /// Queue one per-service round: `Display Ethernet` at `de`, `Wi-Fi` at `wifi`.
    fn answer_round(
        exec: ScriptedExecutor,
        de: (&str, u16),
        wifi: (&str, u16),
    ) -> ScriptedExecutor {
        let get = |verb: &str, svc: &str| format!("/usr/sbin/networksetup {verb} {svc}");
        exec.respond(LIST, 0, LIST_OUT, "")
            .respond(&get("-getwebproxy", DE), 0, &proxy_out(de.0, de.1), "")
            .respond(
                &get("-getsecurewebproxy", DE),
                0,
                &proxy_out(de.0, de.1),
                "",
            )
            .respond(&get("-getproxybypassdomains", DE), 0, BYPASS_OUT, "")
            .respond(
                &get("-getwebproxy", WIFI),
                0,
                &proxy_out(wifi.0, wifi.1),
                "",
            )
            .respond(
                &get("-getsecurewebproxy", WIFI),
                0,
                &proxy_out(wifi.0, wifi.1),
                "",
            )
            .respond(&get("-getproxybypassdomains", WIFI), 0, BYPASS_OUT, "")
    }

    /// A scripted engine over `exec` with the given mechanism, its state file in `dir`.
    fn scripted(
        exec: ScriptedExecutor,
        dir: &std::path::Path,
        mechanism: Mechanism,
    ) -> (Arc<ScriptedExecutor>, Arc<SystemProxy>) {
        let exec = Arc::new(exec.with_real_fs());
        let cfg = SystemProxyConfig {
            auto: false,
            bypass: vec![],
            state_file: Some(dir.join(STATE_FILE_NAME)),
        };
        let as_exec: Arc<dyn Executor> = exec.clone();
        let ours = Endpoint {
            host: "127.0.0.1".into(),
            port: 8080,
        };
        let sp = Arc::new(SystemProxy::with_mechanism(
            as_exec, &cfg, ours, None, mechanism,
        ));
        (exec, sp)
    }

    /// Assemble over an injected scripted engine; the CA lives in `dir` too.
    fn assemble_over(dir: &std::path::Path, sp: Arc<SystemProxy>) -> (Config, Assembled) {
        let mut cfg = Config::default();
        cfg.ca.dir = dir.join("ca");
        let assembled = assemble_with(
            &cfg,
            &Features {
                sysproxy: Some(sp),
                ..Features::default()
            },
        )
        .expect("assemble with a scripted system proxy");
        (cfg, assembled)
    }

    /// Invoke a registered command the way a frontend does, as `frontend`.
    fn invoke(proxy: &Proxy, cfg: &Config, name: &str, frontend: Frontend) -> Value {
        let services = crate::tui::services(
            proxy,
            cfg,
            None,
            crate::tui::TuiLog::Off,
            Arc::new(JobBus::default()),
        );
        let host = CommandHost::new(&*services.store, &*services.client, &*services.guard, None)
            .with_frontend(frontend);
        proxy
            .registry()
            .command(name)
            .unwrap_or_else(|| panic!("{name} registered"))
            .invoke(Params::default(), &host)
            .unwrap_or_else(|e| panic!("{name} succeeds: {e}"))
    }

    fn field<'a>(v: &'a Value, name: &str) -> &'a Value {
        match v {
            Value::Object(map) => map
                .get(name)
                .unwrap_or_else(|| panic!("field `{name}` in {v:?}")),
            other => panic!("expected an object, got {other:?}"),
        }
    }

    fn scutil_runs(exec: &ScriptedExecutor) -> usize {
        exec.runs().iter().filter(|l| *l == SCUTIL).count()
    }

    /// D8 + SP-AC17 (registered-schema half): assembly over an injected engine
    /// registers the three `proxy.system.*` verbs, and `set` takes exactly one
    /// optional `bypass: Array(Str)`.
    #[test]
    fn sysproxy_verbs_are_registered_with_control() {
        let dir = temp_dir("registered");
        let (_exec, sp) = scripted(ScriptedExecutor::new(), &dir, Mechanism::Networksetup);
        let (_cfg, assembled) = assemble_over(&dir, sp.clone());
        let reg = assembled.proxy.registry();
        for name in [
            "proxy.system.status",
            "proxy.system.set",
            "proxy.system.unset",
        ] {
            assert!(reg.command(name).is_some(), "{name} is registered");
        }
        let schema = reg.command("proxy.system.set").expect("set").schema();
        assert_eq!(schema.params.len(), 1);
        assert_eq!(schema.params[0].name, "bypass");
        assert!(!schema.params[0].required);
        assert!(
            matches!(&schema.params[0].ty, TypeDesc::Array(inner) if matches!(**inner, TypeDesc::Str)),
            "ty: {:?}",
            schema.params[0].ty
        );
        assert!(
            Arc::ptr_eq(&assembled.sysproxy, &sp),
            "Assembled.sysproxy is the injected engine"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// SP-AC18: `proxy.status.system_proxy` is the §D6 compact object, served
    /// from a ≤ 5 s cache (two calls, one `scutil --proxy`) and refreshed at
    /// once by a `set` (the next call flips to `points_at_us` with no new read).
    #[test]
    fn proxy_status_carries_system_proxy_cached_and_refreshed() {
        let dir = temp_dir("cached");
        let exec = ScriptedExecutor::new()
            .respond(SCUTIL, 0, &scutil_out("127.0.0.1", 9090), "")
            .respond(SCUTIL, 0, &scutil_out("127.0.0.1", 8080), "");
        let exec = answer_round(exec, ("127.0.0.1", 9090), ("", 0));
        let exec = answer_round(exec, ("127.0.0.1", 8080), ("127.0.0.1", 8080));
        let (exec, sp) = scripted(exec, &dir, Mechanism::Networksetup);
        let (cfg, assembled) = assemble_over(&dir, sp);
        assembled.listening.store(true, Ordering::SeqCst);

        let first = invoke(&assembled.proxy, &cfg, "proxy.status", Frontend::Cli);
        let sys = field(&first, "system_proxy");
        assert_eq!(field(sys, "state"), &Value::Str("other".into()));
        assert_eq!(field(sys, "host"), &Value::Str("127.0.0.1".into()));
        assert_eq!(field(sys, "port"), &Value::Int(9090));
        assert_eq!(field(sys, "managed_by_us"), &Value::Bool(false));
        assert_eq!(field(sys, "setting"), &Value::Bool(false));
        assert_eq!(field(sys, "supported"), &Value::Bool(true));
        assert_eq!(
            field(sys, "detail"),
            &Value::Str("HTTP and HTTPS → 127.0.0.1:9090 (not this core)".into())
        );
        let second = invoke(&assembled.proxy, &cfg, "proxy.status", Frontend::Cli);
        assert_eq!(field(&second, "system_proxy"), sys);
        assert_eq!(scutil_runs(&exec), 1, "two calls within 5 s read once");

        let set = invoke(
            &assembled.proxy,
            &cfg,
            "proxy.system.set",
            Frontend::Operator,
        );
        assert_eq!(field(&set, "changed"), &Value::Bool(true));
        let after_set = scutil_runs(&exec);

        let third = invoke(&assembled.proxy, &cfg, "proxy.status", Frontend::Cli);
        let sys = field(&third, "system_proxy");
        assert_eq!(field(sys, "state"), &Value::Str("points_at_us".into()));
        assert_eq!(field(sys, "host"), &Value::Null);
        assert_eq!(field(sys, "port"), &Value::Null);
        assert_eq!(field(sys, "managed_by_us"), &Value::Bool(true));
        assert_eq!(scutil_runs(&exec), after_set, "set refreshed the cache");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// §D6: with no mechanism the sub-object is present as `unsupported` and
    /// nothing is ever run.
    #[test]
    fn unsupported_mechanism_reports_without_a_shell_out() {
        let dir = temp_dir("unsupported");
        let (exec, sp) = scripted(ScriptedExecutor::new(), &dir, Mechanism::None);
        let (cfg, assembled) = assemble_over(&dir, sp);
        let status = invoke(&assembled.proxy, &cfg, "proxy.status", Frontend::Cli);
        let sys = field(&status, "system_proxy");
        assert_eq!(field(sys, "state"), &Value::Str("unsupported".into()));
        assert_eq!(field(sys, "supported"), &Value::Bool(false));
        assert!(exec.runs().is_empty(), "ran: {:?}", exec.runs());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
