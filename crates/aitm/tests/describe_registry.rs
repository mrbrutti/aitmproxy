//! The schema-only registry `aitm::describe::registry` builds for help (spec
//! D15 bullet 1, AC-W2-6; plan C28–C30) is a hand-kept copy of the plugin list
//! in the frozen `wire::assemble_with_scripts`. These pins compare it with the
//! binary's live assembly — command names, registration order and schema
//! fingerprints — for the default features, for `l4.enabled`, and with the
//! bundled catalogue, and assert that the help path created nothing (plan rule
//! 12): the CA directory it is pointed at does not exist afterwards. Plain
//! `#[test]`s: `describe::registry` owns its own runtime and `live_commands`
//! builds one, so neither may run inside another.

use std::collections::BTreeMap;
use std::path::Path;

use aitm::config_file::Settings;
use aitm::describe::{self, DescribeInputs, Described};
use aitm::macos_capture::config::MacosCaptureConfig;
use aitm::wire::Features;
use aitm_core::{Config, ParamDef, ParamSchema, Registry, TypeDesc};
use aitm_plugin_rhai::RhaiConfig;
use aitm_plugin_scanner::ScannerConfig;
use aitm_proto_l4::config::L4Config;
use aitm_proto_l4::L4Privilege;
use aitm_sysproxy::SystemProxyConfig;

mod support;

/// The shipped catalogue, reached through the injected env (plan rule 13).
const BUNDLED: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../scripts/bundled");

/// The 18 built-in groups (catalogue off, `l4.enabled` off; `check` is
/// native since the scanner v2 engine, main #232).
const BUILT_IN_GROUPS: [&str; 18] = [
    "agent", "browser", "ca", "capture", "check", "config", "findings", "flow", "map", "poc",
    "proxy", "request", "scan", "scope", "script", "session", "tls", "ws",
];

/// The 19 groups of plan mock-up M-W2-1 (catalogue on, `l4.enabled` off).
const CATALOGUE_GROUPS: [&str; 19] = [
    "agent", "browser", "ca", "capture", "check", "config", "findings", "flow", "l4", "map", "poc",
    "proxy", "request", "scan", "scope", "script", "session", "tls", "ws",
];

/// `Settings` defaults with the CA pointed at a throwaway directory that must
/// never come into existence.
fn settings(tag: &str) -> Settings {
    let mut core = Config::default();
    core.ca.dir = support::temp_ca_dir(tag);
    Settings {
        core,
        rhai: RhaiConfig::default(),
        l4: L4Config::default(),
        macos_capture: MacosCaptureConfig::default(),
        system_proxy: SystemProxyConfig::default(),
        scanner: ScannerConfig::default(),
    }
}

fn env(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn describe(settings: &Settings, env: &BTreeMap<String, String>) -> Described {
    let lookup = |key: &str| env.get(key).cloned();
    describe::registry(&DescribeInputs {
        settings,
        script_args: &[],
        env: &lookup,
    })
    .expect("the schema-only registry builds")
}

fn names_and_fingerprints(registry: &Registry) -> Vec<(String, String)> {
    registry
        .commands()
        .map(|cmd| (cmd.name().to_string(), describe::fingerprint(&cmd.schema())))
        .collect()
}

fn group_names(registry: &Registry) -> Vec<String> {
    describe::groups(registry)
        .into_iter()
        .map(|(group, _)| group)
        .collect()
}

fn verbs_of(registry: &Registry, group: &str) -> Vec<String> {
    describe::groups(registry)
        .into_iter()
        .find(|(name, _)| name == group)
        .map(|(_, verbs)| verbs.iter().map(|cmd| cmd.name().to_string()).collect())
        .unwrap_or_else(|| panic!("group `{group}` is registered"))
}

#[test]
fn describe_matches_the_live_registry_with_the_default_features() {
    let settings = settings("describe");
    let env = env(&[("AITM_NO_BUNDLED_SCRIPTS", "1")]);

    let described = describe(&settings, &env);
    let ours = names_and_fingerprints(&described.registry);
    let live = support::live_commands(&Features::default(), RhaiConfig::default());

    assert!(
        !ours.is_empty(),
        "the schema-only registry registers commands"
    );
    assert_eq!(
        ours, live,
        "describe::registry drifted from wire::assemble_with_scripts (names, order or schemas)"
    );
    assert_eq!(group_names(&described.registry), BUILT_IN_GROUPS);
    assert!(
        !settings.core.ca.dir.exists(),
        "help must never create the CA directory (plan rule 12): {}",
        settings.core.ca.dir.display()
    );
}

#[test]
fn describe_matches_the_live_registry_with_l4_enabled() {
    let mut settings = settings("describe-l4");
    settings.l4.enabled = true;
    let env = env(&[("AITM_NO_BUNDLED_SCRIPTS", "1")]);

    let described = describe(&settings, &env);
    let ours = names_and_fingerprints(&described.registry);
    let features = Features {
        l4: L4Config {
            enabled: true,
            ..L4Config::default()
        },
        l4_privilege: Some(L4Privilege::available()),
        ..Features::default()
    };
    let live = support::live_commands(&features, RhaiConfig::default());

    assert_eq!(
        ours, live,
        "with l4.enabled describe::registry drifted from the live assembly"
    );
    let groups = group_names(&described.registry);
    assert!(groups.iter().any(|g| g == "l4"), "groups: {groups:?}");
    assert!(describe::is_group(&described.registry, "l4"));
    assert!(describe::is_group(&described.registry, "scope"));
    assert!(!describe::is_group(&described.registry, "l4.recon"));
    assert!(!describe::is_group(&described.registry, "nope"));
    assert!(
        !settings.core.ca.dir.exists(),
        "help must never create the CA directory (plan rule 12)"
    );
}

#[test]
fn describe_with_the_bundled_catalogue_lists_check_and_l4_scripts() {
    assert!(
        Path::new(BUNDLED).is_dir(),
        "the bundled catalogue is at {BUNDLED}"
    );
    let settings = settings("describe-catalogue");
    let env = env(&[("AITM_BUNDLED_SCRIPTS", BUNDLED)]);

    let described = describe(&settings, &env);
    assert!(
        described.script_errors.is_empty(),
        "the catalogue compiles for help: {:?}",
        described.script_errors
    );
    let ours = names_and_fingerprints(&described.registry);
    let mut rhai = RhaiConfig::default();
    aitm::bundled::append(&mut rhai, Path::new(BUNDLED));
    let live = support::live_commands(&Features::default(), rhai);

    assert_eq!(
        ours, live,
        "with the catalogue describe::registry drifted from the live assembly"
    );
    assert_eq!(group_names(&described.registry), CATALOGUE_GROUPS);
    let check = verbs_of(&described.registry, "check");
    // 26 natives since the scanner v2 track (main #232, #301) plus the 15
    // bundled Rhai checks, all under one `check` group.
    assert_eq!(check.len(), 41, "check verbs: {check:?}");
    assert!(check.iter().all(|v| v.starts_with("check.")));
    assert_eq!(
        verbs_of(&described.registry, "l4"),
        ["l4.recon", "l4.tcp_probe", "l4.udp_probe"]
    );
    assert!(
        !settings.core.ca.dir.exists(),
        "help must never create the CA directory (plan rule 12)"
    );
}

#[test]
fn fingerprint_distinguishes_type_and_required() {
    fn schema(ty: TypeDesc, required: bool) -> ParamSchema {
        ParamSchema {
            description: "Add a host to Scope.".into(),
            params: vec![ParamDef {
                name: "host".into(),
                ty,
                required,
                description: "The host.".into(),
            }],
            result: TypeDesc::Bool,
        }
    }
    let base = schema(TypeDesc::Str, true);

    assert_eq!(
        describe::fingerprint(&base),
        "Add a host to Scope.|host:string:true|true|false"
    );
    assert_eq!(
        describe::fingerprint(&base),
        describe::fingerprint(&schema(TypeDesc::Str, true))
    );
    assert_ne!(
        describe::fingerprint(&base),
        describe::fingerprint(&schema(TypeDesc::Str, false)),
        "required must be part of the fingerprint"
    );
    assert_ne!(
        describe::fingerprint(&base),
        describe::fingerprint(&schema(TypeDesc::Int, true)),
        "the type must be part of the fingerprint"
    );

    let two = ParamSchema {
        description: "Get a flow.".into(),
        params: vec![
            ParamDef {
                name: "id".into(),
                ty: TypeDesc::FlowId,
                required: true,
                description: String::new(),
            },
            ParamDef {
                name: "offset".into(),
                ty: TypeDesc::Int,
                required: false,
                description: String::new(),
            },
        ],
        result: TypeDesc::Str,
    };
    assert_eq!(
        describe::fingerprint(&two),
        "Get a flow.|id:flow-id:true;offset:int:false|string"
    );
}

#[test]
fn groups_are_alphabetical_with_verbs_in_registration_order() {
    let settings = settings("describe-groups");
    let env = env(&[("AITM_BUNDLED_SCRIPTS", BUNDLED)]);
    let described = describe(&settings, &env);

    let groups = describe::groups(&described.registry);
    let names: Vec<&str> = groups.iter().map(|(g, _)| g.as_str()).collect();
    let mut sorted = names.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(names, sorted, "groups are alphabetical and distinct");
    assert_eq!(names.first(), Some(&"agent"));
    assert_eq!(names.last(), Some(&"ws"));
    assert_eq!(
        verbs_of(&described.registry, "scope"),
        ["scope.add", "scope.remove", "scope.list"],
        "verbs keep registration order (plan C50)"
    );
}

// ---- tester, wave-2 pass 1 (AC-W2-6; plan C28–C30, rule 12) ----

/// The widest set help can show — the catalogue and `l4.enabled` together —
/// pinned against the live assembly like the other three: 113 commands, 19
/// groups, and the `l4` group is the three bundled scripts first (the tier's
/// commands register before the module) then the module's 22 natives.
#[test]
fn describe_matches_the_live_registry_with_the_catalogue_and_l4_enabled() {
    let mut settings = settings("describe-catalogue-l4");
    settings.l4.enabled = true;
    let env = env(&[("AITM_BUNDLED_SCRIPTS", BUNDLED)]);

    let described = describe(&settings, &env);
    assert!(
        described.script_errors.is_empty(),
        "the catalogue compiles for help: {:?}",
        described.script_errors
    );
    let ours = names_and_fingerprints(&described.registry);
    let features = Features {
        l4: L4Config {
            enabled: true,
            ..L4Config::default()
        },
        l4_privilege: Some(L4Privilege::available()),
        ..Features::default()
    };
    let mut rhai = RhaiConfig::default();
    aitm::bundled::append(&mut rhai, Path::new(BUNDLED));
    let live = support::live_commands(&features, rhai);

    assert_eq!(
        ours, live,
        "with the catalogue and l4.enabled describe::registry drifted from the live assembly"
    );
    // Plan Task 10 counted 113 before main's scanner track registered the
    // fifteen `scan.*` job verbs and 26 native `check.*` (2026-11-02).
    assert_eq!(ours.len(), 154, "plan Task 10's command count");
    assert_eq!(group_names(&described.registry), CATALOGUE_GROUPS);
    let l4 = verbs_of(&described.registry, "l4");
    assert_eq!(l4.len(), 25, "{l4:?}");
    assert_eq!(&l4[..3], ["l4.recon", "l4.tcp_probe", "l4.udp_probe"]);
    assert!(l4.iter().all(|v| v.starts_with("l4.")), "{l4:?}");
    let mut distinct = l4.clone();
    distinct.sort();
    distinct.dedup();
    assert_eq!(distinct.len(), l4.len(), "no verb twice: {l4:?}");
    assert!(
        !settings.core.ca.dir.exists(),
        "help must never create the CA directory (plan rule 12)"
    );
}

/// Plan C29: a `--script` that does not compile and one that does not exist
/// are reported in `script_errors` and never fail help; the built-in commands
/// are all still there, in the same order with the same schemas.
#[test]
fn describe_reports_broken_or_missing_scripts_without_failing() {
    let dir = std::env::temp_dir().join(format!(
        "aitm-describe-broken-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let broken = dir.join("broken.rhai");
    std::fs::write(&broken, "fn on_request(f) { this is not rhai").expect("write");
    let missing = dir.join("missing.rhai");
    let settings = settings("describe-broken");
    let env = env(&[("AITM_NO_BUNDLED_SCRIPTS", "1")]);
    let lookup = |key: &str| env.get(key).cloned();
    let described = describe::registry(&DescribeInputs {
        settings: &settings,
        script_args: &[broken.clone(), missing.clone()],
        env: &lookup,
    });
    let _ = std::fs::remove_dir_all(&dir);
    let described = described.expect("help never fails on a script");
    assert_eq!(
        described.script_errors.len(),
        2,
        "one error per bad script: {:?}",
        described.script_errors
    );
    let baseline = describe(&settings, &env);
    assert_eq!(
        names_and_fingerprints(&described.registry),
        names_and_fingerprints(&baseline.registry)
    );
    assert!(
        !settings.core.ca.dir.exists(),
        "help must never create the CA directory (plan rule 12)"
    );
}
