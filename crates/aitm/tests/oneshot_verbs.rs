//! R14 Task 4 (AC-R14-22, spec D6): every verb the binary registers has a
//! one-shot placement decided in `EXPECTED`, `placement` agrees with it, the
//! long-lane lists name real verbs (natives registered, bundled script verbs
//! not), and no command claims the one-shot's own flag names.
//!
//! The `m4_sensitivity.rs` pattern over the full assembly: names come from
//! `support::built_in_groups` (the EMPTY Rhai tier plus the `FindingsPlugin`,
//! exactly as `main` wires it) for `Features::default()` and for the
//! `synopsis_groups_l4.rs` feature set that registers the native `l4.*` verbs.
//! The params scan mirrors that assembly to reach the commands themselves and
//! cross-checks its name set against `built_in_groups` so the two cannot drift.

use std::collections::BTreeSet;
use std::sync::Arc;

use aitm::oneshot::verbs::{
    placement, Placement, LOCAL_VERBS, LONG_RUNNING_PREFIXES, LONG_RUNNING_SCRIPT_VERBS,
    LONG_RUNNING_VERBS, ONE_SHOT_FLAG_NAMES,
};
use aitm::scripts::LateHandles;
use aitm::wire::{assemble_with_scripts, Features, ScriptWiring};
use aitm_core::{Config, Plugin, Registry};
use aitm_findings::FindingsPlugin;
use aitm_plugin_rhai::wire::build_with_languages;
use aitm_plugin_rhai::{MemoryFindingSink, RhaiConfig, ScriptServices};
use aitm_poc::step_registry::PocStepRegistry;
use aitm_proto_l4::config::L4Config;
use aitm_proto_l4::L4Privilege;

mod support;

use Placement::{Live, Local};

/// Every built-in verb and where a one-shot runs it (spec D6, the table
/// expanded): the 111 of the default registry (73 before main's #232 added the
/// fifteen scan-job verbs and the 23 native `check.*`), then the 22 native
/// `l4.*` verbs `l4.enabled` adds. Enumerated from the tree, in registration order.
const EXPECTED: &[(&str, Placement)] = &[
    // flow.* — the core's flow store.
    ("flow.list", Live),
    ("flow.get", Live),
    ("flow.table", Live),
    ("flow.subscribe", Live),
    ("flow.unsubscribe", Live),
    ("flow.detail", Live),
    ("flow.mark", Live),
    ("flow.comment", Live),
    // scan.* — discover/passive drive the core's client; report renders the
    // findings directory on this machine.
    ("scan.discover", Live),
    ("scan.passive", Live),
    ("scan.report", Local),
    // scan.* job verbs (main's scanner v2 rewrite, #232): every one acts on the
    // core's job table, profiles, sessions and catalogue; `start` and `map`
    // return a job id at once, so they stay on the 30 s lane.
    ("scan.start", Live),
    ("scan.map", Live),
    ("scan.status", Live),
    ("scan.list", Live),
    ("scan.cancel", Live),
    ("scan.issues", Live),
    ("scan.issue", Live),
    ("scan.issue.update", Live),
    ("scan.sitemap", Live),
    ("scan.checks", Live),
    ("scan.profile.list", Live),
    ("scan.profile.get", Live),
    ("scan.profile.save", Live),
    ("scan.profile.delete", Live),
    ("scan.session.preview", Live),
    // check.<id> — one check by hand on the core (natives since #232; the
    // `check.` prefix puts them on the long lane).
    ("check.cmdi-time", Live),
    ("check.cookie-flag", Live),
    ("check.cswsh", Live),
    ("check.h2-cl-te-downgrade-indicator", Live),
    ("check.h2-header-crlf-tolerance", Live),
    ("check.h2-pseudo-header-validation", Live),
    ("check.h2-rapid-reset-mitigation", Live),
    ("check.h2-settings-observe", Live),
    ("check.l4-packet-crash", Live),
    ("check.l4-packet-reaction", Live),
    ("check.open-redirect", Live),
    ("check.reflection", Live),
    ("check.security-header", Live),
    ("check.sqli-boolean", Live),
    ("check.sqli-time", Live),
    ("check.ws-auth-bypass-handshake", Live),
    ("check.ws-cmdi-echo", Live),
    ("check.ws-input-reflection", Live),
    ("check.ws-oversize-frame", Live),
    ("check.ws-sql-error", Live),
    ("check.ws-ssti", Live),
    ("check.ws-subprotocol-observe", Live),
    ("check.xss-reflected", Live),
    ("flow.replay", Live),
    ("flow.intercept", Live),
    ("flow.resume", Live),
    ("flow.kill", Live),
    // proxy.* — the running proxy; `system.unset` is the recovery for a dead
    // proxy left as the OS proxy, so it stays local.
    ("proxy.status", Live),
    ("proxy.pause", Live),
    ("proxy.resume", Live),
    ("flow.clear", Live),
    ("config.get", Live),
    ("proxy.system.status", Live),
    ("proxy.system.set", Live),
    ("proxy.system.unset", Local),
    ("capture.status", Live),
    ("flow.mutate", Live),
    ("request.send", Live),
    ("scope.add", Live),
    ("scope.remove", Live),
    ("scope.list", Live),
    ("ws.intercept", Live),
    ("ws.frame", Live),
    ("ws.send", Live),
    ("session.save", Live),
    ("session.load", Live),
    ("flow.export", Live),
    ("flow.import", Live),
    ("tls.passthrough.list", Live),
    ("tls.passthrough.add", Live),
    ("tls.passthrough.remove", Live),
    ("map.add", Live),
    ("map.list", Live),
    ("map.remove", Live),
    // browser.* — the core's browser.
    ("browser.navigate", Live),
    ("browser.click", Live),
    ("browser.type", Live),
    ("browser.screenshot", Live),
    ("browser.eval", Live),
    ("browser.get_dom", Live),
    ("browser.confine", Live),
    // poc.* — build/run use the core's client, guard and store; the rest read
    // the PoC directory on this machine.
    ("poc.build", Live),
    ("poc.run", Live),
    ("poc.list", Local),
    ("poc.get", Local),
    ("poc.artifact", Local),
    // ca.* — the CA files and the trust store on this machine.
    ("ca.export", Local),
    ("ca.status", Local),
    ("ca.install", Local),
    ("ca.uninstall", Local),
    // agent.* — the core's agent policy.
    ("agent.status", Live),
    ("agent.set", Live),
    ("agent.activity", Live),
    ("agent.approve", Live),
    // script.* — a static compile is local; everything else is the core's
    // script host.
    ("script.validate", Local),
    ("script.reload", Live),
    ("script.findings", Live),
    ("script.list", Live),
    ("script.enable", Live),
    ("script.disable", Live),
    ("script.save", Live),
    // findings.* — the findings directory on this machine; `record` names
    // the core's flow and uses its store.
    ("findings.list", Local),
    ("findings.get", Local),
    ("findings.record", Live),
    ("findings.remove", Local),
    // l4.* natives (`l4.enabled`) — the core's capture feeder and L4 state.
    ("l4.interfaces", Live),
    ("l4.scope.add", Live),
    ("l4.scope.remove", Live),
    ("l4.scope.list", Live),
    ("l4.flow.list", Live),
    ("l4.flow.get", Live),
    ("l4.craft", Live),
    ("l4.capture.start", Live),
    ("l4.capture.stop", Live),
    ("l4.inject", Live),
    ("l4.send_recv", Live),
    ("l4.capture.status", Live),
    ("l4.intercept.start", Live),
    ("l4.intercept.stop", Live),
    ("l4.intercept.list", Live),
    ("l4.intercept.mutate", Live),
    ("l4.intercept.revert", Live),
    ("l4.intercept.forward", Live),
    ("l4.intercept.drop", Live),
    ("l4.intercept.status", Live),
    ("l4.agent.status", Live),
    ("l4.agent.set", Live),
];

/// `l4.enabled` with the privilege pre-answered, exactly as
/// `tests/synopsis_groups_l4.rs` enables the native `l4.*` verbs: no startup
/// probe touches the host.
fn l4_features() -> Features {
    Features {
        l4: L4Config {
            enabled: true,
            ..L4Config::default()
        },
        l4_privilege: Some(L4Privilege::available()),
        ..Features::default()
    }
}

/// `main.rs`'s script services: late-bound handles the proxy fills in once
/// built (mirrors `support::startup_services`, which is private there).
fn startup_services() -> ScriptServices {
    let handles = LateHandles::new();
    ScriptServices {
        store: handles.clone(),
        client: handles.clone(),
        browser: Some(handles.clone()),
        guard: handles.clone(),
        findings: Arc::new(MemoryFindingSink::new()),
        rt: tokio::runtime::Handle::current(),
    }
}

/// The registry `support::built_in_groups` enumerates, kept alive (with the
/// runtime the script tier needs) so the test can read each command's schema.
fn full_registry(features: &Features) -> (tokio::runtime::Runtime, Arc<Registry>) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a current-thread runtime for the script tier");
    let dir = support::temp_ca_dir("oneshot-verbs");
    let mut cfg = Config::default();
    cfg.ca.dir = dir.clone();
    let registry = rt.block_on(async {
        let tier = build_with_languages(RhaiConfig::default(), startup_services(), &[])
            .expect("the empty rhai tier builds");
        assert!(
            tier.errors.is_empty(),
            "empty tier errors: {:?}",
            tier.errors
        );
        let assembled = assemble_with_scripts(
            &cfg,
            features,
            ScriptWiring {
                plugins: vec![
                    Box::new(tier.host.with_max_body(cfg.limits.max_body_bytes)) as Box<dyn Plugin>
                ],
                executor: Some(tier.executor.clone()),
                poc_step_handlers: PocStepRegistry::new(),
                commands: vec![Box::new(tier.commands), Box::new(FindingsPlugin::new())],
                script_checks: Some(tier.checks.clone()),
            },
        )
        .expect("the proxy assembles in a temp CA dir");
        assembled.proxy.registry_arc()
    });
    let _ = std::fs::remove_dir_all(&dir);
    (rt, registry)
}

#[test]
fn every_registered_verb_is_classified() {
    // The authoritative name set: the default assembly plus the l4 natives.
    let (_, default_names) = support::built_in_groups(&Features::default());
    let (_, l4_names) = support::built_in_groups(&l4_features());
    let registered: BTreeSet<&str> = default_names
        .iter()
        .chain(l4_names.iter())
        .map(String::as_str)
        .collect();

    let expected: BTreeSet<&str> = EXPECTED.iter().map(|(name, _)| *name).collect();
    assert_eq!(
        expected.len(),
        EXPECTED.len(),
        "EXPECTED lists a verb twice"
    );
    for name in &registered {
        assert!(
            expected.contains(name),
            "unclassified verb {name}: add it to EXPECTED and, if local, to LOCAL_VERBS"
        );
    }
    for name in &expected {
        assert!(
            registered.contains(name),
            "EXPECTED lists {name}, which the registry no longer registers"
        );
    }

    // The table decides; `placement` must agree with every row.
    for (name, want) in EXPECTED {
        assert_eq!(placement(name), *want, "placement({name:?})");
    }

    // Every exact-name entry of the local and native long-running lists is a
    // verb the registry knows; the bundled script verbs are, by definition,
    // absent from the native registry (research F13).
    for name in LOCAL_VERBS {
        assert!(
            registered.contains(name),
            "{name} in LOCAL_VERBS is not a registered verb"
        );
    }
    for name in LONG_RUNNING_VERBS {
        assert!(
            registered.contains(name),
            "{name} in LONG_RUNNING_VERBS is not a registered verb"
        );
    }
    for name in LONG_RUNNING_SCRIPT_VERBS {
        assert!(
            !registered.contains(name),
            "{name} is now a native verb: move it to LONG_RUNNING_VERBS"
        );
    }
    for prefix in LONG_RUNNING_PREFIXES {
        assert!(
            prefix.ends_with('.'),
            "LONG_RUNNING_PREFIXES entry {prefix:?} must end with a dot"
        );
    }

    // No registered command declares a param that collides with the
    // one-shot's own flags (`--bus`, `--token-file`; spec D7).
    let (_rt, registry) = full_registry(&l4_features());
    let scanned: BTreeSet<&str> = registry.commands().map(|c| c.name()).collect();
    assert_eq!(
        scanned, registered,
        "the params scan must walk the same registry built_in_groups enumerates"
    );
    for cmd in registry.commands() {
        for param in cmd.schema().params {
            assert!(
                !ONE_SHOT_FLAG_NAMES.contains(&param.name.as_str()),
                "{} declares a param named {:?}, which is a one-shot flag",
                cmd.name(),
                param.name
            );
        }
    }
}

#[test]
fn local_set_is_exactly_the_spec_list() {
    assert_eq!(LOCAL_VERBS.len(), 13, "spec D6 names thirteen local verbs");
    for name in [
        "ca.status",
        "ca.export",
        "ca.install",
        "ca.uninstall",
        "findings.list",
        "findings.get",
        "findings.remove",
        "poc.list",
        "poc.get",
        "poc.artifact",
        "scan.report",
        "script.validate",
        "proxy.system.unset",
    ] {
        assert!(
            LOCAL_VERBS.contains(&name),
            "{name} is local in spec D6 but missing from LOCAL_VERBS"
        );
    }
}
