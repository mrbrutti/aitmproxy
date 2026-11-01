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
    ActionPermit, AgentState, AuditRing, Config, GuardError, Plugin, ProtocolModule, Proxy,
    Registry, ScopeEntry, ScopeRateGuard,
};
use aitm_plugin_maprules::MapRulesPlugin;
use aitm_plugin_passthrough::{PassthroughList, PassthroughModule, PassthroughPlugin};
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
        }
    }
}

/// Every scanner v2 lane the build has, in lane order (spec D1).
///
/// Each lane crate owns a `lane()` entry point returning `Option<Arc<dyn Lane>>`;
/// this is the one place that calls them, so a lane track lands by filling its own
/// crate and edits no shared file ("Registration without shared files"). A slot
/// that answers `None` — every slot while its track is unimplemented — is skipped,
/// and `scan.start` refuses that lane with `lane_unavailable`.
///
/// The two L4 slots are called with the shared guard and flow store from
/// [`Features::l4_shared`], so a scanner L4 case acts over the same L4 engagement
/// state the `l4.*` verbs and the scripting language do. When L4 is disabled `l4`
/// is `None` and both handles are passed as `None`; a landed L4 lane still returns
/// `Some` then, so the refusal is `refused_l4` rather than `lane_unavailable`
/// (spec D3's refusal order).
#[must_use]
pub fn collect_lanes(l4: Option<&L4Shared>) -> Vec<Arc<dyn aitm_scan_model::Lane>> {
    let guard = l4.map(|shared| shared.guard.clone());
    let store = l4.map(|shared| shared.store.clone());
    [
        aitm_scan_http::lane(),
        aitm_scan_ws::lane(),
        aitm_scan_l4_packet::lane(guard.clone(), store.clone()),
        aitm_scan_l4_stream::lane(guard, store),
    ]
    .into_iter()
    .flatten()
    .collect()
}

/// The native (compiled-in) scanner v2 checks this build ships (spec D1).
///
/// `aitm-scan-checks-http` contributes checks to the HTTP lane's catalogue rather
/// than a second lane, so its slot is `checks()`, not `lane()`. Empty until track
/// T3 lands.
#[must_use]
pub fn collect_native_checks() -> Vec<Arc<dyn aitm_scan_model::Check>> {
    aitm_scan_checks_http::checks()
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
///     let services = services(&assembled.proxy, &cfg, None, TuiLog::Off);
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
///     let services = services(&assembled.proxy, &cfg, None, TuiLog::Off);
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

    let mut builder = Proxy::builder().with_config(cfg.clone());
    // Protocol modules, in registration order (first match claims the connection):
    // PassthroughModule before HttpModule so a pinned host tunnels past MITM.
    for module in ordered_modules(http, passthrough_list, inject) {
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
        // The deterministic scanner's command set (scan.discover): a command-only
        // provider that observes no events. Stage 1 uses the default budgets.
        // Scanner v2 lane slots, spec D1: the lanes and native checks this build
        // has are collected here and handed over. The shipped engine ignores
        // them; the v2 engine (track T1b) consumes them.
        .register_plugin(Box::new(
            aitm_plugin_scanner::ScannerPlugin::new(aitm_plugin_scanner::ScannerConfig::default())
                .with_lanes(collect_lanes(features.l4_shared.as_ref()))
                .with_native_checks(collect_native_checks()),
        ))
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
    // Bind the late guard to the proxy's real guard before anything is served, so
    // Map Remote's `check_active` rides the same scope/rate guard the client path
    // and every other command enforce.
    map_guard.bind(proxy.guard());

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
/// so its SNI/CONNECT-authority match wins over [`HttpModule`] for a pinned host
/// (the acceptor picks the first module whose `matches` returns true); then
/// `HttpModule` (MITM for every other host), then [`WsModule`] (post-upgrade
/// only), sharing the `inject` registry [`WsCtlPlugin`] holds so `ws.send` reaches
/// a live conversation. One source of module order for [`assemble_with_scripts`]
/// and the wiring test.
pub fn ordered_modules(
    http: HttpModule,
    passthrough: PassthroughList,
    inject: InjectRegistry,
) -> Vec<Arc<dyn ProtocolModule>> {
    vec![
        Arc::new(PassthroughModule::new(passthrough)),
        Arc::new(http),
        Arc::new(WsModule::new().with_inject_registry(inject)),
    ]
}

/// A [`ScopeRateGuard`] handle Map Remote can hold before the proxy (and thus its
/// guard) exists. The guard is created inside `Proxy::build`; this forwards to it
/// once [`bind`](LateGuard::bind) is called (immediately after build, before
/// serving). Unbound it refuses every active check — a guard that cannot check
/// must not permit (deny-by-default). Mirrors `scripts::LateHandles`' guard facet
/// without pulling in its store/client/browser facets.
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
        let services = crate::tui::services(proxy, cfg, None, crate::tui::TuiLog::Off);
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
    /// the T6 L4 stream lane (`aitm_scan_l4_stream::lane`) returns `Some` with or
    /// without the L4 handles (it refuses at discovery when they are absent), and
    /// the HTTP, WS and L4 packet slots are still skeletons returning `None`. A
    /// `None` slot is skipped rather than collected. A lane track's landing flips
    /// these literals; that track re-pins this test.
    #[test]
    fn lane_slots_match_the_landed_lanes() {
        assert_eq!(collect_lanes(None).len(), 1);
        assert_eq!(collect_native_checks().len(), 0);

        let shared = L4Shared {
            guard: Arc::new(L4Guard::new(&L4Config {
                enabled: true,
                ..L4Config::default()
            })),
            store: Arc::new(aitm_proto_l4::flow::InMemoryL4FlowStore::new()),
        };
        assert_eq!(collect_lanes(Some(&shared)).len(), 1);
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
        let services = crate::tui::services(proxy, cfg, None, crate::tui::TuiLog::Off);
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
