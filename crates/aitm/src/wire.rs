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
use aitm_proto_l4::{L4Module, L4Privilege};
use aitm_proto_ws::{InjectRegistry, WsModule};
use tracing::{info, warn};

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
}

impl Default for Features {
    fn default() -> Self {
        Self {
            mutate: true,
            ca_plugin: None,
            l4: L4Config::default(),
            l4_privilege: None,
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
    /// `AgentPlugin` already registered; hand it to `McpServer::with_agent_state`
    /// so the server's policy gate reads the same policy `agent.set` writes.
    pub agent_state: Arc<AgentState>,
    /// The F4 push broadcast: the `SubscriptionPlugin` registered in the chain
    /// forwards lifecycle events to it; hand it to `McpServer::with_push` so the
    /// server's dispatcher fans `notifications/aitm/flow` to subscribers.
    pub push_tx: tokio::sync::broadcast::Sender<aitm_core::Event>,
    /// The F2 command-invocation audit ring, shared with the `AgentPlugin`
    /// already registered (which serves `agent.activity`/`agent.status` from it);
    /// hand it to `McpServer::with_audit_ring` so the server's `call_tool` records
    /// into the same ring.
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
    pub l4_ingress: Option<crate::ingress::CoreIngress>,
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
        .register_plugin(Box::new(ControlPlugin::new(armed, listening.clone())));
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
    builder = builder
        // Command providers: the browser, poc, ca and agent commands.
        .register_plugin(Box::new(BrowserPlugin::new(cfg.browser.ssrf.clone())))
        .register_plugin(Box::new(PocCommands {
            executor: scripts.executor,
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
        let module = L4Module::with_privilege(&features.l4, privilege);
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
    let ingress = match l4_half {
        Some((guard, store)) => crate::ingress::CoreIngress::with_l4(guard, store),
        None => crate::ingress::CoreIngress::empty(),
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
}

impl Plugin for PocCommands {
    fn name(&self) -> &str {
        "poc"
    }

    fn load(&mut self, reg: &mut Registry) {
        aitm_poc::builder::register(reg);
        match self.executor.clone() {
            Some(exec) => aitm_poc::runner::register_with_executor(reg, exec),
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
        };
        assert_eq!(
            ingress.dispatch_tcp(flow).await,
            crate::ingress::StreamOutcome::Refused,
            "empty scope means out of scope: refused before any dial, no network"
        );
    }
}
