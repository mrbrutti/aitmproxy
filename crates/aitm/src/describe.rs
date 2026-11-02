//! The schema-only command registry that help and the registry pins read
//! (spec D15 bullet 1, realised as plan C28).
//!
//! **Source of truth: `wire::assemble_with_scripts`.** [`registry`] constructs
//! the same plugins in the same order, over inert handles — a `LateHandles`
//! that is never bound, a `StdGuard::default()` for the map guard, a
//! `SystemProxy` fixed to `Mechanism::None`, a `PrivilegeState` nothing reports
//! on (so no probe runs), a `CaPlugin` whose audit log opens nothing until a write — and
//! registers them into a bare `aitm_core::Registry`: no `Proxy`, no
//! `CertAuthority`, nothing bound, nothing written (plan rule 12). The Rhai
//! tier is composed as `main.rs`'s `run()` composes it (plan C29: config
//! entries, `AITM_SCRIPTS`, `--script` entries, then the bundled catalogue
//! deduped against them; the `ws` language and, with `l4.enabled`, the
//! `L4Language` installed before compile) on a private current-thread runtime
//! the [`Described`] value owns, so a script registered by the operator's own
//! `load(reg)` appears in help too. Compile errors are collected, not fatal:
//! `strict` is a boot concern.
//!
//! **Guard.** The plugin list, and [`PocProvider`] (the twin of the frozen
//! file's private `PocCommands`), are duplicated from `wire.rs` on purpose —
//! that file is frozen until #267 — and `tests/describe_registry.rs` pins the
//! command names, registration order and schema fingerprints against the live
//! assembly for the default features, for `l4.enabled`, and with the bundled
//! catalogue. **Follow-up** (plan follow-up 1): once #267 lands, `wire.rs` and
//! this module share one plugin-list builder, and `run()`'s tier composition
//! moves into `scripts.rs` for both.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use aitm_browser::BrowserPlugin;
use aitm_ca::CaPlugin;
use aitm_cli::dispatch::{group_of, type_hint};
use aitm_core::{AgentState, AuditRing, Command, ParamSchema, Plugin, Registry, StdGuard};
use aitm_findings::FindingsPlugin;
use aitm_plugin::language::ProtocolLanguage;
use aitm_plugin_maprules::MapRulesPlugin;
use aitm_plugin_passthrough::PassthroughPlugin;
use aitm_plugin_rhai::wire::build_with_languages;
use aitm_plugin_rhai::{MemoryFindingSink, ScriptEntry, ScriptServices};
use aitm_plugin_scanner::ScannerPlugin;
use aitm_plugin_sessionio::SessionIoPlugin;
use aitm_plugin_wsctl::WsCtlPlugin;
use aitm_plugins::{
    AgentPlugin, CapturePlugin, ControlPlugin, DetailPlugin, InterceptPlugin, MetaPlugin,
    MutatePlugin, RateLimitPlugin, ReplayPlugin, ScopePlugin, SubscriptionPlugin,
};
use aitm_poc::step_registry::PocStepRegistry;
use aitm_proto_l4::flow::InMemoryL4FlowStore;
use aitm_proto_l4::guard::L4Guard;
use aitm_proto_l4::privilege::state::{PrivilegeConfig, ProcessLifetime};
use aitm_proto_l4::{L4Language, L4Module, PrivilegePlugin, PrivilegeState};
use aitm_sysproxy::plugin::SysProxyPlugin;
use aitm_sysproxy::{Mechanism, SystemProxy};

use crate::config_file::Settings;
use crate::macos_capture::status::{CaptureStatus, CaptureStatusPlugin};
use crate::scripts::LateHandles;
use crate::wire::{collect_lanes_with, collect_native_checks, ws_tls_policy, L4Shared};
use crate::{bundled, env};

/// What the schema-only registry is built from: the operator's settings (the
/// config file as the caller read it, or defaults), the `--script` paths, and
/// an environment lookup — injected, so tests never touch the process env and
/// the help path reads exactly the keys `run()` reads.
pub struct DescribeInputs<'a> {
    pub settings: &'a Settings,
    pub script_args: &'a [PathBuf],
    pub env: &'a dyn Fn(&str) -> Option<String>,
}

/// The built registry, what did not compile, and the runtime it was built on.
pub struct Described {
    /// Every command the binary would register for these inputs, in
    /// registration order, with its schema; no command here can be invoked
    /// against anything real (the handles are unbound).
    pub registry: Arc<Registry>,
    /// The Rhai tier's compile errors, one line each. Help does not fail on
    /// them (`strict` is a boot concern, plan C29); the pins assert the bundled
    /// catalogue produces none.
    pub script_errors: Vec<String>,
    /// The private current-thread runtime whose `Handle` the tier's host verbs
    /// hold. Owned here so the handle outlives the registry; never driven,
    /// because nothing on the help path invokes a command.
    _runtime: tokio::runtime::Runtime,
}

/// Build the schema-only registry: the Rhai tier as `run()` composes it, then
/// the plugins of `wire::assemble_with_scripts` in its order, into a bare
/// [`Registry`]. Reads the environment through `inputs.env` and the script
/// files named by the config, the env and `inputs.script_args`; creates no
/// file or directory, opens no log, spawns nothing, binds nothing (plan rule
/// 12). Fails only when the scripting *engine* cannot be built or the runtime
/// cannot be created.
pub fn registry(inputs: &DescribeInputs) -> anyhow::Result<Described> {
    let settings = inputs.settings;
    let lookup = inputs.env;

    // The three config layers `run()` applies the env over, in its order.
    let mut core = settings.core.clone();
    let mut rhai = settings.rhai.clone();
    let mut l4 = settings.l4.clone();
    env::apply(&mut core, lookup);
    env::apply_rhai(&mut rhai, lookup);
    env::apply_l4(&mut l4, lookup);
    // A script's `browser.navigate` decides SSRF under the command's policy.
    rhai.ssrf = core.browser.ssrf.clone();
    // `--script` entries after the config's; the bundled catalogue last and
    // deduped by path, so an operator entry naming a bundled file wins.
    rhai.scripts
        .extend(inputs.script_args.iter().cloned().map(ScriptEntry::new));
    bundled::apply(&mut rhai, lookup);

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let handles = LateHandles::new();
    let services = ScriptServices {
        store: handles.clone(),
        client: handles.clone(),
        browser: Some(handles.clone()),
        guard: handles.clone(),
        findings: Arc::new(MemoryFindingSink::new()),
        rt: runtime.handle().clone(),
    };
    // The L4 state the module and the live `L4Language` share (one engagement
    // state), built only when `l4.enabled`, as `run()` does.
    let l4_shared = l4.enabled.then(|| L4Shared {
        guard: Arc::new(L4Guard::new(&l4)),
        store: Arc::new(InMemoryL4FlowStore::new()),
    });
    // The one privilege state `run()` builds (p1b, privilege spec §2.1): the
    // language's wire verbs, the `l4.*` module and the `l4.privilege` verbs all
    // read it. Building it probes nothing; nothing here calls `report()`.
    let privilege_state = Arc::new(PrivilegeState::new(&PrivilegeConfig {
        enabled: l4.enabled,
        l4: l4.privilege.clone(),
        lifetime: ProcessLifetime::Serving,
    }));
    let l4_language = l4_shared.as_ref().map(|shared| {
        L4Language::new(
            shared.guard.clone(),
            privilege_state.backend(),
            shared.store.clone(),
        )
    });
    // Under the same certificate policy as `run()` builds it and the WS lane
    // dials with (`ws_tls_policy`), so this tier matches the live one.
    let ws_language = aitm_scan_ws::language::build_with(handles.clone(), ws_tls_policy(&core));
    let mut languages: Vec<&dyn ProtocolLanguage> = Vec::new();
    if let Some(lang) = &l4_language {
        languages.push(lang);
    }
    if let Some(lang) = &ws_language {
        languages.push(lang.as_ref());
    }
    let tier = build_with_languages(rhai, services, &languages)?;
    let script_checks = tier.checks.clone();
    let script_errors: Vec<String> = tier.errors.iter().map(ToString::to_string).collect();
    // The `l4:` / `ws:` PoC-step handlers from the same language instances the
    // engine installed, as `run()` builds them.
    let mut step_handlers = PocStepRegistry::new();
    if let Some(handler) = l4_language.as_ref().and_then(ProtocolLanguage::poc_step) {
        step_handlers.register(Arc::from(handler));
    }
    if let Some(handler) = ws_language.as_deref().and_then(ProtocolLanguage::poc_step) {
        step_handlers.register(Arc::from(handler));
    }

    // Inert handles for the plugins that take one in `wire.rs`.
    let intercept = InterceptPlugin::new();
    let armed = intercept.armed_flag();
    let listening = Arc::new(AtomicBool::new(false));
    let sysproxy = Arc::new(SystemProxy::with_mechanism(
        Arc::new(aitm_ca::exec::RealExecutor::new()),
        &settings.system_proxy,
        aitm_sysproxy::ours_from(core.listen),
        None,
        Mechanism::None,
    ));
    let (push_tx, _push_rx) = tokio::sync::broadcast::channel(aitm_mcp::DEFAULT_BROADCAST_CAPACITY);
    let (_capture_status, capture_status_reader) =
        CaptureStatus::channel(settings.macos_capture.enabled);
    let agent_state = Arc::new(AgentState::new(core.mcp.policy));

    // `wire::assemble_with_scripts`'s plugin list, in its order.
    let mut reg = Registry::new();
    reg.add_plugin(Box::new(CapturePlugin::new()));
    reg.add_plugin(Box::new(SubscriptionPlugin::new(push_tx)));
    reg.add_plugin(Box::new(DetailPlugin::new()));
    reg.add_plugin(Box::new(MetaPlugin::new()));
    reg.add_plugin(Box::new(ReplayPlugin::new()));
    reg.add_plugin(Box::new(intercept));
    reg.add_plugin(Box::new(
        ControlPlugin::new(armed, listening.clone()).with_system_proxy(sysproxy.clone()),
    ));
    reg.add_plugin(Box::new(SysProxyPlugin::new(sysproxy, listening)));
    reg.add_plugin(Box::new(CaptureStatusPlugin::new(capture_status_reader)));
    // `Features::default().mutate` is true: the binary always registers it.
    reg.add_plugin(Box::new(MutatePlugin::new()));
    reg.add_plugin(Box::new(ScopePlugin::new(core.scope.allow_agent_widen)));
    reg.add_plugin(Box::new(RateLimitPlugin::new(core.limits.per_host_rps)));
    reg.add_plugin(Box::new(WsCtlPlugin::new()));
    reg.add_plugin(Box::new(
        SessionIoPlugin::new(core.session_io.allow_agent_file_io)
            .with_session_root(core.session_io.root.clone()),
    ));
    reg.add_plugin(Box::new(PassthroughPlugin::new(
        core.tls.passthrough.clone(),
        core.tls.allow_agent_passthrough,
    )));
    reg.add_plugin(Box::new(MapRulesPlugin::new(
        core.maps.root.clone().unwrap_or_default(),
        core.maps.allow_agent_authoring,
        Arc::new(StdGuard::default()),
    )));
    reg.add_plugin(Box::new(
        tier.host.with_max_body(core.limits.max_body_bytes),
    ));
    reg.add_plugin(Box::new(BrowserPlugin::new(core.browser.ssrf.clone())));
    reg.add_plugin(Box::new(PocProvider {
        executor: Some(tier.executor.clone()),
        step_handlers,
    }));
    reg.add_plugin(Box::new(CaPlugin::new(core.ca.clone())));
    reg.add_plugin(Box::new(
        AgentPlugin::new(agent_state).with_audit_ring(Arc::new(AuditRing::default())),
    ));
    reg.add_plugin(Box::new(tier.commands));
    reg.add_plugin(Box::new(FindingsPlugin::new()));
    // The scanner, last of the first-party plugins as `wire.rs` registers it:
    // the operator's `scanner:` section plus the two values that are not its
    // keys, the lanes, the native checks over the inert `StdGuard` (as the map
    // rules above; nothing is bound, so the h2 observe checks could open
    // nothing), and the Rhai tier's check registry (call B9).
    let mut scanner_cfg = settings.scanner.clone();
    scanner_cfg.findings_dir = core.findings.dir.clone();
    scanner_cfg.l4_allow_agent_inject = l4.allow_agent_inject;
    reg.add_plugin(Box::new(
        ScannerPlugin::new(scanner_cfg)
            .with_lanes(collect_lanes_with(l4_shared.as_ref(), ws_tls_policy(&core)))
            .with_native_checks(collect_native_checks(
                core.browser.ssrf.clone(),
                Arc::new(StdGuard::default()),
            ))
            .with_script_checks(script_checks),
    ));
    // The privilege verbs register on every core (p1b #267), after the scanner
    // as `wire.rs` orders them; the module itself stays opt-in, over the same
    // state, and `log_l4_startup` (which reports, hence probes) is `run()`'s.
    reg.add_plugin(Box::new(PrivilegePlugin::new(Arc::clone(&privilege_state))));
    if let Some(shared) = l4_shared {
        reg.add_plugin(Box::new(L4Module::with_shared_state(
            shared.guard,
            shared.store,
            l4.intercept.clone(),
            Arc::clone(&privilege_state),
        )));
    }

    Ok(Described {
        registry: Arc::new(reg),
        script_errors,
        _runtime: runtime,
    })
}

/// The commands by group (`aitm_cli::dispatch::group_of`: the first dotted
/// segment of the name) with the groups in alphabetical order and each
/// group's verbs in registration order (plan C50: the order `wire.rs`
/// registers them).
pub fn groups(registry: &Registry) -> Vec<(String, Vec<Arc<dyn Command>>)> {
    let mut by_group: BTreeMap<String, Vec<Arc<dyn Command>>> = BTreeMap::new();
    for cmd in registry.commands() {
        by_group
            .entry(group_of(cmd.name()).to_string())
            .or_default()
            .push(Arc::clone(cmd));
    }
    by_group.into_iter().collect()
}

/// Whether `name` is the group (first dotted segment) of at least one
/// registered command: `is_group(reg, "scope")`, not `"scope.add"`.
pub fn is_group(registry: &Registry, name: &str) -> bool {
    registry.commands().any(|cmd| group_of(cmd.name()) == name)
}

/// A schema's identity for the registry pins:
/// `"{description}|{name}:{type_hint}:{required};…|{result type_hint}"`, the
/// params `;`-joined in schema order, with the same type words the CLI prints
/// (`aitm_cli::dispatch::type_hint`). Two schemas that differ in a parameter's
/// type or requiredness, in the parameter list, in the description or in the
/// result type have different fingerprints.
pub fn fingerprint(schema: &ParamSchema) -> String {
    let params: Vec<String> = schema
        .params
        .iter()
        .map(|p| format!("{}:{}:{}", p.name, type_hint(&p.ty), p.required))
        .collect();
    format!(
        "{}|{}|{}",
        schema.description,
        params.join(";"),
        type_hint(&schema.result)
    )
}

/// The twin of the frozen `wire.rs`'s private `PocCommands` (plan Task 9's
/// shared-worktree rule): registers `poc.build`, `poc.run` and the library
/// verbs through the same three calls in the same order as
/// `wire::PocCommands::load`. With an executor, `poc.run` is the script-capable
/// form; without one, the declarative form. The registry pin guards the
/// duplication; plan follow-up 1 removes it with the shared builder.
struct PocProvider {
    executor: Option<Arc<dyn aitm_poc::ScriptStepExecutor>>,
    /// Native protocol-namespace step handlers (`l4:`, `ws:`), threaded to
    /// `poc.run` together with the executor.
    step_handlers: PocStepRegistry,
}

impl Plugin for PocProvider {
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
