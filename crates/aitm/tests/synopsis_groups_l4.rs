//! Tester (whole-branch pass), amended for the L4 capture-privilege core: the
//! static `Groups:` list includes `l4` because `l4.privilege` and
//! `l4.privilege.request` register on every core (spec
//! `2026-10-31-l4-capture-privilege-design` §2.2). Switching `l4.enabled` on
//! therefore adds no group, only the `L4Module`'s other `l4.*` verbs. This
//! proves the `synopsis_groups` pin is sensitive to the feature set it
//! assembles with (`Features::default()` there; `l4.enabled` here). Same empty
//! Rhai tier, same `FindingsPlugin`, same `assemble_with_scripts` as `main` and
//! as `tests/synopsis_groups.rs`, through the one `support::built_in_groups`.

use std::collections::BTreeSet;

use aitm::startup::GROUPS;
use aitm::wire::Features;
use aitm_proto_l4::config::L4Config;
use aitm_proto_l4::L4Privilege;

mod support;

#[test]
fn l4_enabled_adds_no_group_but_the_modules_l4_verbs() {
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

    let expected: BTreeSet<String> = GROUPS.iter().map(|g| g.to_string()).collect();
    assert!(
        expected.contains("l4"),
        "the static synopsis lists `l4`: the privilege verbs are always registered (spec §2.2)"
    );
    assert_eq!(
        groups, expected,
        "with l4.enabled the registry's groups are exactly GROUPS; l4 verbs: {l4_verbs:?}"
    );
    assert!(
        l4_verbs.len() > 2,
        "l4.enabled registers the module's verbs beyond the two privilege verbs: {l4_verbs:?}"
    );
    for v in [
        "l4.privilege",
        "l4.privilege.request",
        "l4.capture.status",
        "l4.scope.list",
    ] {
        assert!(
            names.iter().any(|n| n == v),
            "{v} is registered with l4.enabled; registry names: {names:?}"
        );
    }
}
