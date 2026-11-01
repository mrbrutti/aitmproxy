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
    /// The macOS NE live-capture feeder config. Opt-in and deny-by-default:
    /// `enabled` is false by default, so the default feature set never binds the
    /// capture listener. The feeder runs only when `enabled` and the build is macOS.
    pub macos_capture: MacosCaptureConfig,
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
            macos_capture: MacosCaptureConfig::default(),
        }
    }
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
        .register_plugin(Box::new(aitm_plugin_scanner::ScannerPlugin::new(
            aitm_plugin_scanner::ScannerConfig::default(),
        )))
        .register_plugin(Box::new(ReplayPlugin::new()))
        .register_plugin(Box::new(intercept))
        .register_plugin(Box::new(ControlPlugin::new(armed, listening.clone())))
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
