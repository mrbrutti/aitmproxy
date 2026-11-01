//! The catalogue slot agrees with the design (spec D1, D6, D8.2; T3 plan task 10).
//!
//! These tests read the two catalogue slots the way the binary does —
//! `crates/aitm/src/wire.rs::collect_native_checks` calls one of them once at
//! startup and hands the result to the HTTP lane — and pin what the engine
//! depends on: the ids, the metadata shape every scheduler field is read from,
//! and the `class` tokens D6's dedupe groups issues by. No check body runs and
//! no socket is opened; building the lists is all these tests do.
//!
//! There are two slots because five of the ten checks dial raw:
//! [`aitm_scan_checks_http::checks_with`] takes the live SSRF policy and scope
//! guard and returns all ten, and [`aitm_scan_checks_http::checks`] returns
//! only the five that probe through the lane's own guarded client. An ungated
//! raw-h2 probe therefore cannot be constructed through the slot at all
//! (coordinator decision of 2026-11-01, option A).

use std::collections::BTreeSet;
use std::sync::Arc;

use aitm_core::{ScopeRateGuard, SsrfPolicy, StdGuard};
use aitm_scan_checks_http::{checks, checks_with};
use aitm_scan_model::{Check, CheckOrigin, Intensity, LaneKind};
use regex::Regex;

/// The gated slot, built the way `wire.rs` builds it: the job's SSRF policy
/// and the engine's scope guard, which every raw h2 probe is checked against.
fn gated() -> Vec<Arc<dyn Check>> {
    checks_with(SsrfPolicy::default(), guard())
}

fn guard() -> Arc<dyn ScopeRateGuard> {
    Arc::new(StdGuard::default())
}

/// The five checks `checks()` returns: every native check that probes through
/// the lane's own guarded client and dials nothing itself.
const GATE_FREE_IDS: [&str; 5] = [
    "cmdi-time",
    "open-redirect",
    "sqli-boolean",
    "sqli-time",
    "xss-reflected",
];

/// The ten native ids, in the sorted order the plan's task 10 enumerates them.
const NATIVE_IDS: [&str; 10] = [
    "cmdi-time",
    "h2-cl-te-downgrade-indicator",
    "h2-header-crlf-tolerance",
    "h2-pseudo-header-validation",
    "h2-rapid-reset-mitigation",
    "h2-settings-observe",
    "open-redirect",
    "sqli-boolean",
    "sqli-time",
    "xss-reflected",
];

/// The `class` of the check with `id`, or a panic naming the missing id.
fn class_of(id: &str) -> String {
    gated()
        .into_iter()
        .find(|check| check.meta().id == id)
        .unwrap_or_else(|| panic!("checks() has no check with id {id}"))
        .meta()
        .class
        .clone()
}

#[test]
fn checks_with_returns_every_native_id() {
    let built = gated();
    assert_eq!(
        built.len(),
        10,
        "checks_with() must return ten native checks"
    );

    let mut ids: Vec<String> = built.iter().map(|check| check.meta().id.clone()).collect();
    ids.sort();
    assert_eq!(ids, NATIVE_IDS, "the sorted native ids");
}

/// The ungated slot returns only the checks that need no gate. The five h2
/// checks dial a raw socket, so they exist only where a policy and a guard
/// were supplied: a caller that forgot cannot get one by accident.
#[test]
fn checks_returns_only_the_gate_free_five() {
    let ids: Vec<String> = checks()
        .iter()
        .map(|check| check.meta().id.clone())
        .collect();

    assert_eq!(ids, GATE_FREE_IDS);
    for id in &ids {
        assert!(!id.starts_with("h2-"), "{id} dials raw and needs a gate");
    }
}

/// Together they are the whole catalogue, with nothing in `checks()` that
/// `checks_with()` does not also build.
#[test]
fn the_gated_slot_is_a_superset_of_the_ungated_one() {
    let gate_free: BTreeSet<String> = checks().iter().map(|c| c.meta().id.clone()).collect();
    let all: BTreeSet<String> = gated().iter().map(|c| c.meta().id.clone()).collect();

    assert!(gate_free.is_subset(&all));
    let only_gated: Vec<&String> = all.difference(&gate_free).collect();
    assert_eq!(only_gated.len(), 5, "the five h2 checks");
    for id in only_gated {
        assert!(id.starts_with("h2-"), "{id}");
    }
}

#[test]
fn every_meta_is_well_formed() {
    let built = gated();
    // Guard against a vacuous pass: an empty catalogue satisfies every `for`
    // body below, so the count is part of the assertion.
    assert_eq!(built.len(), NATIVE_IDS.len(), "checks examined");

    for check in built {
        let meta = check.meta();
        let id = &meta.id;
        assert_eq!(meta.origin, CheckOrigin::Native, "{id}: origin");
        assert_eq!(meta.lanes, vec![LaneKind::Http], "{id}: lanes");
        assert!(!meta.kinds.is_empty(), "{id}: kinds must not be empty");
        assert!(!meta.name.is_empty(), "{id}: name must not be empty");
        assert!(
            !meta.description.is_empty(),
            "{id}: description must not be empty"
        );
        assert!(!meta.class.is_empty(), "{id}: class must not be empty");
        assert!(
            meta.intensity <= Intensity::Medium,
            "{id}: intensity {:?} is above Medium",
            meta.intensity
        );
        assert!(
            !meta.targets_session,
            "{id}: no v2 check may target session points"
        );
    }
}

#[test]
fn every_class_is_unique_per_h2_check() {
    let expected = [
        ("h2-cl-te-downgrade-indicator", "h2-smuggling-indicator"),
        ("h2-header-crlf-tolerance", "h2-header-crlf"),
        ("h2-pseudo-header-validation", "h2-pseudo-header"),
        ("h2-rapid-reset-mitigation", "h2-rapid-reset"),
        ("h2-settings-observe", "h2-settings"),
    ];
    for (id, class) in expected {
        assert_eq!(class_of(id), class, "{id}: class");
    }

    // Pairwise distinct, so D6's dedupe never merges two different h2
    // observations into one issue.
    let distinct: BTreeSet<&str> = expected.iter().map(|(_, class)| *class).collect();
    assert_eq!(distinct.len(), 5, "the five h2 class tokens must differ");
}

#[test]
fn the_shared_classes_match_the_taxonomy() {
    // Both SQL-injection techniques share one class, so a target found by the
    // boolean differential and by the timing oracle yields one issue, not two.
    assert_eq!(class_of("sqli-boolean"), "sqli");
    assert_eq!(class_of("sqli-time"), "sqli");
    // D6's spelling, which the engine's interim lane emits; dedupe is by
    // class, so the native check and the lane must agree on the token.
    assert_eq!(class_of("xss-reflected"), "reflected-xss");
    assert_eq!(class_of("open-redirect"), "open-redirect");
}

#[test]
fn ids_are_verb_safe() {
    let verb_safe = Regex::new("^[a-z0-9][a-z0-9-]*$").expect("the id pattern compiles");
    let built = gated();
    assert_eq!(built.len(), NATIVE_IDS.len(), "ids examined");

    for check in built {
        let id = &check.meta().id;
        assert!(
            verb_safe.is_match(id),
            "{id} is not a legal `check.<id>` verb suffix"
        );
    }
}

/// Both slots promise the list **in id order**, and `wire.rs` hands it
/// straight to the catalogue. Sorting a copy before comparing (as
/// `checks_returns_every_native_id` must, to name the ids) would hide both a
/// lost sort and a duplicate id, so this reads the list as it comes back:
/// strictly ascending is sorted and unique in one assertion.
#[test]
fn checks_come_back_sorted_and_unique() {
    let ids: Vec<String> = gated()
        .iter()
        .map(|check| check.meta().id.clone())
        .collect();

    assert!(
        ids.windows(2).all(|pair| pair[0] < pair[1]),
        "checks() is not strictly ascending by id: {ids:?}"
    );
    let distinct: BTreeSet<&String> = ids.iter().collect();
    assert_eq!(distinct.len(), ids.len(), "duplicate check id in {ids:?}");
}

/// Every call builds fresh checks. The h2 checks keep per-instance state (the
/// once-per-authority guard), so two catalogues sharing one instance would make
/// the second catalogue silently skip an origin the first had already seen.
#[test]
fn each_call_builds_fresh_check_instances() {
    let first = gated();
    let second = gated();

    assert_eq!(first.len(), second.len());
    for (a, b) in first.iter().zip(second.iter()) {
        assert_eq!(a.meta().id, b.meta().id);
        assert!(
            !std::ptr::addr_eq(std::sync::Arc::as_ptr(a), std::sync::Arc::as_ptr(b)),
            "{} is shared between two catalogues",
            a.meta().id
        );
    }
}

/// Every id is a legal `check.<id>` verb *and* distinct from every other verb
/// suffix once lower-cased, and no id collides with a bus namespace separator.
/// D4 gives each catalogue entry a manual command, so an id with a dot or an
/// upper-case letter would mint a verb the contract lists cannot express.
#[test]
fn no_id_carries_a_verb_separator() {
    for check in gated() {
        let id = &check.meta().id;
        assert!(!id.contains('.'), "{id} would split the verb namespace");
        assert!(!id.contains('_'), "{id} is not kebab-case");
        assert_eq!(id.to_lowercase(), *id, "{id} is not lower-case");
        assert!(id.len() <= 64, "{id} is too long for a verb suffix");
    }
}
