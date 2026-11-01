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
//! guard and returns all ten, and [`aitm_scan_checks_http::checks`] — the one
//! the binary calls today — returns **nothing** in this PR: the binary
//! collects the catalogue through `checks_with(policy, guard)` in a follow-up
//! once the engine lands, and until then no native check is reachable from
//! it (coordinator decision of 2026-11-01, option A, and the split-PR call
//! of the final F6 pass). An ungated raw-h2 probe therefore cannot be
//! constructed through a slot at all.

use std::collections::BTreeSet;
use std::sync::Arc;

use aitm_core::{ScopeRateGuard, SsrfPolicy, StdGuard};
use aitm_scan_checks_http::checks_with;
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

/// The five gate-free checks among the ten: every native check that probes
/// through the lane's own guarded client and dials nothing itself.
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
        .unwrap_or_else(|| panic!("checks_with() has no check with id {id}"))
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

/// `checks_with` returns the ten: the five h2 checks exist only where a
/// policy and a guard were supplied, and the five gate-free ones ride along
/// with them. There is no other slot (T3 PR 2a), so nothing the binary can
/// reach omits the gate.
#[test]
fn the_gated_slot_returns_the_ten() {
    let all: BTreeSet<String> = gated().iter().map(|c| c.meta().id.clone()).collect();
    assert_eq!(all, NATIVE_IDS.iter().map(|s| (*s).to_string()).collect());

    let h2: Vec<&String> = all.iter().filter(|id| id.starts_with("h2-")).collect();
    assert_eq!(h2.len(), 5, "the five h2 checks: {h2:?}");
    let gate_free: Vec<&str> = all
        .iter()
        .filter(|id| !id.starts_with("h2-"))
        .map(String::as_str)
        .collect();
    assert_eq!(gate_free, GATE_FREE_IDS);
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
        "checks_with() is not strictly ascending by id: {ids:?}"
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

/// Option A's whole point is that **no code path builds a raw h2 runner
/// without the SSRF policy and the scope guard**. The type system cannot say
/// "this struct has exactly one constructor", so the source is pinned the way
/// `native_timing.rs` pins the absence of `sleep`: the accept-any client is
/// constructed exactly once in the crate, on the line that gates it, there is
/// no other `pub fn` on the runner, and the five h2 checks are built only
/// inside `checks_with`.
#[test]
fn no_source_path_builds_an_ungated_raw_h2_runner() {
    let h2 = include_str!("../src/h2_observe.rs");
    let catalogue = include_str!("../src/catalogue.rs");
    let lib = include_str!("../src/lib.rs");

    let constructions: Vec<&str> = h2
        .lines()
        .filter(|line| line.contains("RawH2Client::new("))
        .collect();
    assert_eq!(
        constructions.len(),
        1,
        "the raw client is built in exactly one place: {constructions:?}"
    );
    assert!(
        constructions[0].contains(".with_ssrf(ssrf, guard)"),
        "the one construction must be gated on the same line: {}",
        constructions[0]
    );
    let accept_any_in_code = h2
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .filter(|line| line.contains("TlsVerify::AcceptAny"))
        .count();
    assert_eq!(
        accept_any_in_code, 1,
        "accept-any appears on exactly one non-comment line (the rest is documentation)"
    );
    assert!(
        !h2.contains("pub fn new(") && !h2.contains("impl Default for RealRawH2Runner"),
        "RealRawH2Runner must have no constructor besides with_ssrf"
    );

    // The h2 checks are built only by the gated slot.
    let callers: Vec<&str> = catalogue
        .lines()
        .filter(|line| line.contains("h2_checks(") && !line.trim_start().starts_with("//"))
        .collect();
    assert_eq!(callers.len(), 1, "{callers:?}");
    assert!(callers[0].contains("h2_checks(runner)"), "{}", callers[0]);
    assert!(
        !lib.contains("h2_checks("),
        "lib.rs must not build h2 checks itself"
    );
}

/// `RealRawH2Runner` is public (the h2 tests build it to prove it refuses
/// session material), so its doc must say exactly what the gate it carries
/// does: refuse private, loopback and metadata addresses, **not** confine to
/// scope (`confine_to_scope = false`, as the reissue path), with condition 1
/// — target is a profile origin — enforced by `H2Check::run` and not by the
/// runner. `h2_checks` is public for the same reason (the tests script a fake
/// runner through it) and must carry that contract too (final security
/// review FS-3).
#[test]
fn the_raw_runner_and_h2_checks_document_their_gate_contract() {
    let h2 = include_str!("../src/h2_observe.rs");

    let doc_of = |item: &str| -> String {
        let at = h2.find(item).unwrap_or_else(|| panic!("{item} not found"));
        // The doc comment block immediately above the item.
        h2[..at]
            .lines()
            .rev()
            .take_while(|line| {
                line.trim_start().starts_with("///") || line.trim_start().starts_with('#')
            })
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect::<Vec<_>>()
            .join("\n")
    };

    let runner = doc_of("pub struct RealRawH2Runner {");
    for phrase in [
        "confine_to_scope = false",
        "private, loopback and metadata",
        "H2Check::run",
    ] {
        assert!(
            runner.contains(phrase),
            "RealRawH2Runner doc lacks {phrase:?}:\n{runner}"
        );
    }

    let checks = doc_of("pub fn h2_checks(");
    for phrase in ["profile origin", "H2Check::run", "scope"] {
        assert!(
            checks.contains(phrase),
            "h2_checks doc lacks {phrase:?}:\n{checks}"
        );
    }
}

/// What the crate exposes is the one slot, the check modules, and
/// `timing` — the latter because the plan's D4 contract offers
/// `timing::{fit, correlated}` to the Rhai bridge. `matching` is the checks'
/// own toolbox and stays crate-private, so no second scrub entry point exists
/// to keep in step with the core's (final quality review FQ-3, spec
/// re-review SP2-1).
#[test]
fn the_public_modules_are_the_checks_and_timing() {
    let lib = include_str!("../src/lib.rs");
    let public: BTreeSet<&str> = lib
        .lines()
        .filter_map(|line| line.strip_prefix("pub mod "))
        .map(|rest| rest.trim_end_matches(';'))
        .collect();
    assert_eq!(
        public,
        BTreeSet::from([
            "blind_timing",
            "h2_observe",
            "redirect",
            "sqli_boolean",
            "timing",
            "xss",
        ])
    );
    assert!(
        lib.contains("\nmod matching;\n"),
        "matching must be crate-private"
    );
}

/// The five gate-free checks `checks_with` returns carry exactly the metadata
/// their modules declare: the gated slot does not re-shape them, it only adds
/// the h2 five. (The comparison is against the modules' own constructors.)
#[test]
fn the_gated_slot_leaves_the_gate_free_five_untouched() {
    let declared: Vec<Arc<dyn Check>> = vec![
        aitm_scan_checks_http::blind_timing::cmdi_time(),
        aitm_scan_checks_http::blind_timing::sqli_time(),
        aitm_scan_checks_http::redirect::check(),
        aitm_scan_checks_http::sqli_boolean::check(),
        aitm_scan_checks_http::xss::check(),
    ];
    let all = gated();
    assert_eq!(declared.len(), GATE_FREE_IDS.len());
    for check in &declared {
        let twin = all
            .iter()
            .find(|c| c.meta().id == check.meta().id)
            .unwrap_or_else(|| panic!("{} missing from checks_with", check.meta().id));
        assert_eq!(twin.meta(), check.meta(), "{}", check.meta().id);
    }
}

/// Coordinator decision 3 (2026-11-01): the five observe-only h2 checks are
/// properties of an origin and run once per origin; the other five run per
/// insertion point.
#[test]
fn the_h2_five_are_origin_scoped_and_the_rest_point_scoped() {
    use aitm_scan_model::CheckScope;
    for check in gated() {
        let meta = check.meta();
        let expected = if meta.id.starts_with("h2-") {
            CheckScope::Origin
        } else {
            CheckScope::Point
        };
        assert_eq!(meta.scope, expected, "{}", meta.id);
    }
}
