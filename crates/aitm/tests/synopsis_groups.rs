//! The static `aitm --help` synopsis names the built-in command groups (spec
//! D8, AC-W1-2; plan C19). The registry cannot be built without minting a CA,
//! so `--help` prints a constant; this pin keeps the constant honest against
//! the binary's own assembly (`support::built_in_groups`): an EMPTY Rhai tier
//! (no bundled catalogue, so no `l4.*` script commands; `check.*` is native since #232; `l4.enabled`
//! off, so the `l4` group is only the two always-on privilege verbs) plus the `FindingsPlugin`, through `assemble_with_scripts` exactly as
//! `main` wires it. Bare `build_proxy_with` would miss `script.*` and
//! `findings.*`.

use std::collections::BTreeSet;

use aitm::startup::GROUPS;
use aitm::wire::Features;

mod support;

#[test]
fn synopsis_groups_match_the_built_in_registry() {
    let (groups, names) = support::built_in_groups(&Features::default());

    let expected: BTreeSet<String> = GROUPS.iter().map(|g| g.to_string()).collect();
    // 18 since the merge of main's scanner-v2 engine (#232, 2026-11-02): its native
    // `check` group registers without the bundled catalogue; 19 since the L4
    // capture-privilege core (spec 2026-10-31-l4-capture-privilege-design §2.2):
    // `l4.privilege` and `l4.privilege.request` register whether or not
    // `l4.enabled`, so `l4` is a built-in group.
    assert_eq!(expected.len(), 19, "GROUPS must name 19 groups");
    assert_eq!(
        groups, expected,
        "the synopsis Groups block drifted from the built-in registry; registry names: {names:?}"
    );
    // With `l4.enabled` off the `l4` group holds exactly the two always-on
    // privilege verbs (the module's other verbs need `l4.enabled`).
    let mut l4_names: Vec<&String> = names.iter().filter(|n| n.starts_with("l4.")).collect();
    l4_names.sort();
    assert_eq!(
        l4_names,
        vec![&"l4.privilege".to_string(), &"l4.privilege.request".to_string()],
        "the default assembly's l4 group is the two privilege verbs only; registry names: {names:?}"
    );
    for absent in ["demo", "egress"] {
        assert!(
            !groups.contains(absent),
            "`{absent}` is not a built-in group (catalogue or test-only); registry names: {names:?}"
        );
    }
}
