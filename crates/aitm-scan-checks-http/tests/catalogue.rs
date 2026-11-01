//! The catalogue slot agrees with the design (spec D1, D6, D8.2; T3 plan task 10).
//!
//! These tests read [`aitm_scan_checks_http::checks`] the way the binary does —
//! `crates/aitm/src/wire.rs::collect_native_checks` calls it once at startup and
//! hands the result to the HTTP lane — and pin what the engine depends on: the
//! ten ids, the metadata shape every scheduler field is read from, and the
//! `class` tokens D6's dedupe groups issues by. No check body runs and no socket
//! is opened; building the list is all these tests do.

use std::collections::BTreeSet;

use aitm_scan_checks_http::checks;
use aitm_scan_model::{CheckOrigin, Intensity, LaneKind};
use regex::Regex;

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
    checks()
        .into_iter()
        .find(|check| check.meta().id == id)
        .unwrap_or_else(|| panic!("checks() has no check with id {id}"))
        .meta()
        .class
        .clone()
}

#[test]
fn checks_returns_every_native_id() {
    let built = checks();
    assert_eq!(built.len(), 10, "checks() must return ten native checks");

    let mut ids: Vec<String> = built.iter().map(|check| check.meta().id.clone()).collect();
    ids.sort();
    assert_eq!(ids, NATIVE_IDS, "the sorted native ids");
}

#[test]
fn every_meta_is_well_formed() {
    let built = checks();
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
    assert_eq!(class_of("xss-reflected"), "xss");
    assert_eq!(class_of("open-redirect"), "open-redirect");
}

#[test]
fn ids_are_verb_safe() {
    let verb_safe = Regex::new("^[a-z0-9][a-z0-9-]*$").expect("the id pattern compiles");
    let built = checks();
    assert_eq!(built.len(), NATIVE_IDS.len(), "ids examined");

    for check in built {
        let id = &check.meta().id;
        assert!(
            verb_safe.is_match(id),
            "{id} is not a legal `check.<id>` verb suffix"
        );
    }
}

/// `checks()` promises the list **in id order**, and `wire.rs` hands it
/// straight to the catalogue. Sorting a copy before comparing (as
/// `checks_returns_every_native_id` must, to name the ids) would hide both a
/// lost sort and a duplicate id, so this reads the list as it comes back:
/// strictly ascending is sorted and unique in one assertion.
#[test]
fn checks_come_back_sorted_and_unique() {
    let ids: Vec<String> = checks()
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
    let first = checks();
    let second = checks();

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
    for check in checks() {
        let id = &check.meta().id;
        assert!(!id.contains('.'), "{id} would split the verb namespace");
        assert!(!id.contains('_'), "{id} is not kebab-case");
        assert_eq!(id.to_lowercase(), *id, "{id} is not lower-case");
        assert!(id.len() <= 64, "{id} is too long for a verb suffix");
    }
}
