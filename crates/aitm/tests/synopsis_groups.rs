//! The static `aitm --help` synopsis names the built-in command groups (spec
//! D8, AC-W1-2; plan C19). The registry cannot be built without minting a CA,
//! so `--help` prints a constant; this pin keeps the constant honest against
//! the binary's own assembly (`support::built_in_groups`): an EMPTY Rhai tier
//! (no bundled catalogue, so no `l4.*` script commands; `check.*` is native since #232; `l4.enabled`
//! off) plus the `FindingsPlugin`, through `assemble_with_scripts` exactly as
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
    // `check` group registers without the bundled catalogue.
    assert_eq!(expected.len(), 18, "GROUPS must name 18 groups");
    assert_eq!(
        groups, expected,
        "the synopsis Groups block drifted from the built-in registry; registry names: {names:?}"
    );
    for absent in ["l4", "demo", "egress"] {
        assert!(
            !groups.contains(absent),
            "`{absent}` is not a built-in group (catalogue or test-only); registry names: {names:?}"
        );
    }
}
