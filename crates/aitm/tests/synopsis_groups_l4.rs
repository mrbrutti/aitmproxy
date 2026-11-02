//! Tester (whole-branch pass): the static `Groups:` list leaves `l4` out on
//! purpose (plan C19): the `L4Module`'s verbs register only when
//! `l4.enabled`, so the binary's own assembly with L4 switched on is exactly
//! `GROUPS` plus `l4`. This proves the exclusion is deliberate and that the
//! `synopsis_groups` pin is sensitive to the feature set it assembles with
//! (`Features::default()` there; `l4.enabled` here). Same empty Rhai tier,
//! same `FindingsPlugin`, same `assemble_with_scripts` as `main` and as
//! `tests/synopsis_groups.rs`, through the one `support::built_in_groups`.

use std::collections::BTreeSet;

use aitm::startup::GROUPS;
use aitm::wire::Features;
use aitm_proto_l4::config::L4Config;
use aitm_proto_l4::L4Privilege;

mod support;

#[test]
fn l4_enabled_adds_exactly_the_l4_group_to_the_built_in_registry() {
    // `l4.enabled` with the privilege pre-answered, so no startup probe
    // touches the host (the module registers either way; its wire-touching
    // verbs fail closed without privilege).
    let features = Features {
        l4: L4Config {
            enabled: true,
            ..L4Config::default()
        },
        l4_privilege: Some(L4Privilege::available()),
        ..Features::default()
    };
    let (groups, names) = support::built_in_groups(&features);
    let l4_verbs: Vec<&String> = names.iter().filter(|n| n.starts_with("l4.")).collect();

    let mut expected: BTreeSet<String> = GROUPS.iter().map(|g| g.to_string()).collect();
    assert!(
        !expected.contains("l4"),
        "the static synopsis must not list the conditional `l4` group (plan C19)"
    );
    expected.insert("l4".to_string());
    assert_eq!(
        groups, expected,
        "with l4.enabled the registry is GROUPS plus `l4` and nothing else; l4 verbs: {l4_verbs:?}"
    );
    assert!(
        !l4_verbs.is_empty(),
        "l4.enabled registers at least one `l4.*` verb"
    );
}
