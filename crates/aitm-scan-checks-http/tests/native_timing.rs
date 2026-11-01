//! The two native blind-timing checks: `sqli-time` and `cmdi-time`
//! (spec D8.2, D4 "Timing without `sleep`"; T3 plan task 8, AC T3-4).
//!
//! A time-based check asks the target to pause for a known number of seconds
//! and then reads the `elapsed_ms` the lane measured. So the whole check is
//! testable with no clock and no socket: the scripted host answers instantly
//! and *reports* a delay, and the check must reach its verdict from the report.
//! Two of these tests are specifically about that — one measures the wall time
//! of a run whose host claims three seconds per probe, and one pins that the
//! source never names a sleep call at all (AC T3-4, "the scripts never call
//! `sleep`").
//!
//! The rest pin the contract AC T3-4 states: a correlated alternating series is
//! `firm` with `r >= 0.85`, a flat target is clean, and no point ever costs more
//! than eight probes.

mod support;

use std::time::{Duration, Instant};

use aitm_scan_model::{
    Check, CheckCost, CheckOrigin, Confidence, InsertionKind, Intensity, LaneKind, Outcome,
    ProbeHost, ProbeResponse, Speed, Technique, Timing, Verdict,
};

use support::{html, point, ScriptedHost, TARGET_URL};

/// A `200 text/html` response that reports `ms` milliseconds on the wire.
///
/// The host returns it immediately; only the number is delayed, which is the
/// whole point of a timing oracle that never waits.
fn timed(ms: u32) -> ProbeResponse {
    ProbeResponse {
        elapsed_ms: ms,
        ..html(200, "ok")
    }
}

/// The query point every test probes.
fn q() -> aitm_scan_model::InsertionPoint {
    point(InsertionKind::Query, "q", TARGET_URL)
}

fn timing_of(verdict: &Verdict) -> &Timing {
    verdict
        .evidence
        .timing
        .as_ref()
        .expect("a timing verdict must carry its regression as evidence")
}

// ---------------------------------------------------------------------------
// sqli-time
// ---------------------------------------------------------------------------

/// The headline case: the target obeys `SLEEP(n)`, so the observed delay tracks
/// the requested one across the alternating schedule. Four probes, one family,
/// a `firm` verdict carrying the fit an operator (and AC T3-4's live cell) reads
/// `correlated` from.
#[tokio::test]
async fn sqli_time_is_firm_when_the_delays_correlate() {
    let host = ScriptedHost::new()
        .with_baseline(timed(40))
        .on("SLEEP(1)", timed(1040))
        .on("SLEEP(3)", timed(3060))
        .with_fallback(timed(45));

    let verdict = sqli_check().run(&q(), &host).await;

    assert_eq!(verdict.outcome, Outcome::Vulnerable);
    assert_eq!(verdict.confidence, Confidence::Firm);

    let t = timing_of(&verdict);
    assert_eq!(t.requested_s, vec![1.0, 3.0, 1.0, 3.0]);
    assert_eq!(t.observed_ms, vec![1040, 3060, 1040, 3060]);
    assert!(t.r >= 0.85, "r was {}", t.r);
    assert!((950.0..=1050.0).contains(&t.slope), "slope was {}", t.slope);
    assert!(
        t.correlated,
        "the check judged the fit correlated and the evidence says so (AC T3-4)"
    );

    // The payload an operator re-sends by hand is the longest delay of the
    // family that fired, and the detail names the family and the fit.
    assert_eq!(
        verdict.evidence.payload.as_deref(),
        Some("' AND SLEEP(3)-- ")
    );
    assert!(
        verdict
            .detail
            .starts_with("mysql: observed delay tracks the requested delay (r="),
        "{}",
        verdict.detail
    );
    assert!(verdict.detail.contains("ms/s)"), "{}", verdict.detail);

    // A blind differential has no stable response assertion, so no PoC hint.
    assert!(verdict.poc_hint.is_none());

    // Exactly one family's worth of probes: the check stops at the first hit.
    assert_eq!(host.sent().len(), 4);
    assert_eq!(
        host.sent(),
        vec![
            "' AND SLEEP(1)-- ".to_string(),
            "' AND SLEEP(3)-- ".to_string(),
            "' AND SLEEP(1)-- ".to_string(),
            "' AND SLEEP(3)-- ".to_string(),
        ]
    );
    assert_eq!(host.baseline_calls(), 1);
}

/// A target that answers in the same 45 ms whatever it is asked to wait for is
/// not injectable: there is no variance to regress, so the oracle refuses and
/// the check is clean rather than guessing.
#[tokio::test]
async fn sqli_time_is_clean_on_a_flat_target() {
    let host = ScriptedHost::new()
        .with_baseline(timed(40))
        .with_fallback(timed(45));

    let verdict = sqli_check().run(&q(), &host).await;

    assert_eq!(verdict.outcome, Outcome::Clean);
    assert_eq!(verdict.confidence, Confidence::Tentative);
    assert!(host.sent().len() <= 8, "sent {}", host.sent().len());
}

/// `thorough` trades time for separation: the schedule moves to 2 s and 5 s,
/// still alternating, still four probes.
#[tokio::test]
async fn thorough_speed_asks_for_two_and_five_seconds() {
    let host = ScriptedHost::new()
        .with_speed(Speed::Thorough)
        .with_baseline(timed(40))
        .on("SLEEP(2)", timed(2040))
        .on("SLEEP(5)", timed(5050))
        .with_fallback(timed(45));

    let verdict = sqli_check().run(&q(), &host).await;

    assert_eq!(verdict.outcome, Outcome::Vulnerable);
    assert_eq!(
        host.sent(),
        vec![
            "' AND SLEEP(2)-- ".to_string(),
            "' AND SLEEP(5)-- ".to_string(),
            "' AND SLEEP(2)-- ".to_string(),
            "' AND SLEEP(5)-- ".to_string(),
        ]
    );
    assert_eq!(timing_of(&verdict).requested_s, vec![2.0, 5.0, 2.0, 5.0]);
}

/// The baseline only re-centres the series; it moves neither slope nor `r`
/// (`timing::fit`'s documented invariant). A point whose baseline the lane could
/// not fetch is therefore still decidable, and the evidence says plainly that no
/// baseline was collected.
#[tokio::test]
async fn a_failed_baseline_does_not_stop_the_check() {
    let host = ScriptedHost::new()
        .with_baseline_fails(true)
        .on("SLEEP(1)", timed(1040))
        .on("SLEEP(3)", timed(3060))
        .with_fallback(timed(45));

    let verdict = sqli_check().run(&q(), &host).await;

    assert_eq!(verdict.outcome, Outcome::Vulnerable);
    assert!(timing_of(&verdict).baseline_ms.is_empty());
    assert_eq!(host.sent().len(), 4);
}

/// AC T3-4's `r >= 0.85` boundary, end to end, on a series that *jitters*: the
/// two one-second probes and the two three-second probes each come back
/// differently, as a real target under load does. The payload-keyed script
/// cannot express that — both `SLEEP(1)` probes would get the same answer — so
/// the host answers the first and second call of each delay separately.
///
/// The two series differ by 40 ms on two probes and nothing else. One fits at
/// `r = 0.856` and is reported; the other at `r = 0.849` and is not. Both have
/// the same slope, inside the band, so only the correlation half of ZAP's rule
/// can decide between them.
#[tokio::test]
async fn a_jittered_series_decides_at_the_correlation_boundary() {
    let reported = ScriptedHost::new()
        .with_baseline(timed(40))
        .on_nth("SLEEP(1)", 1, timed(800))
        .on_nth("SLEEP(3)", 1, timed(2600))
        .on_nth("SLEEP(1)", 2, timed(1735))
        .on_nth("SLEEP(3)", 2, timed(4130))
        .with_fallback(timed(45));

    let verdict = sqli_check().run(&q(), &reported).await;

    assert_eq!(verdict.outcome, Outcome::Vulnerable);
    assert_eq!(verdict.confidence, Confidence::Firm);
    let t = timing_of(&verdict);
    assert_eq!(t.observed_ms, vec![800, 2600, 1735, 4130]);
    assert!((0.855..0.86).contains(&t.r), "r was {}", t.r);
    assert_eq!(reported.sent().len(), 4, "one family, four probes");

    // 40 ms more jitter on the same two probes, and the fit falls below the
    // acceptance threshold: the second family is flat, so the run is clean.
    let not_reported = ScriptedHost::new()
        .with_baseline(timed(40))
        .on_nth("SLEEP(1)", 1, timed(800))
        .on_nth("SLEEP(3)", 1, timed(2600))
        .on_nth("SLEEP(1)", 2, timed(1775))
        .on_nth("SLEEP(3)", 2, timed(4170))
        .with_fallback(timed(45));

    let verdict = sqli_check().run(&q(), &not_reported).await;

    assert_eq!(verdict.outcome, Outcome::Clean, "{}", verdict.detail);
    assert_eq!(not_reported.sent().len(), 8, "both families were tried");
}

// ---------------------------------------------------------------------------
// cmdi-time
// ---------------------------------------------------------------------------

/// The shell family: `; sleep n` appended to a parameter the target hands to a
/// shell. Same oracle, same verdict shape, a different class and CWE.
#[tokio::test]
async fn cmdi_time_is_firm_on_the_sh_family() {
    let host = ScriptedHost::new()
        .with_baseline(timed(40))
        .on("; sleep 1", timed(1050))
        .on("; sleep 3", timed(3070))
        .with_fallback(timed(45));

    let verdict = cmdi_check().run(&q(), &host).await;

    assert_eq!(verdict.outcome, Outcome::Vulnerable);
    assert_eq!(verdict.confidence, Confidence::Firm);
    assert!(verdict.detail.contains("sh:"), "{}", verdict.detail);
    assert!(timing_of(&verdict).r >= 0.85);
    assert_eq!(
        host.sent(),
        vec![
            "; sleep 1".to_string(),
            "; sleep 3".to_string(),
            "; sleep 1".to_string(),
            "; sleep 3".to_string(),
        ]
    );
}

// ---------------------------------------------------------------------------
// The budget and the clock
// ---------------------------------------------------------------------------

/// AC T3-4's hard number. Four probes per family and eight per point means at
/// most two families are ever tried, whatever the target does — here the first
/// family is anticorrelated (the right magnitude, the wrong direction) and the
/// second is flat.
#[tokio::test]
async fn the_check_never_exceeds_eight_probes_per_point() {
    let host = ScriptedHost::new()
        .with_baseline(timed(40))
        .on("SLEEP(1)", timed(3000))
        .on("SLEEP(3)", timed(1000))
        .with_fallback(timed(60));

    let verdict = sqli_check().run(&q(), &host).await;

    assert_eq!(verdict.outcome, Outcome::Clean);
    assert_eq!(host.sent().len(), 8);

    // The second family is PostgreSQL, rendered as the canonical payload.
    assert_eq!(
        &host.sent()[4..],
        &[
            "'||pg_sleep(1)--".to_string(),
            "'||pg_sleep(3)--".to_string(),
            "'||pg_sleep(1)--".to_string(),
            "'||pg_sleep(3)--".to_string(),
        ]
    );
}

/// The check reads `elapsed_ms`; it never waits. A host that claims three
/// seconds per probe and answers instantly must produce a verdict in
/// milliseconds, or some code path is sleeping for real.
#[tokio::test]
async fn the_check_never_sleeps() {
    let host = ScriptedHost::new()
        .with_baseline(timed(3000))
        .with_fallback(timed(3000));

    let started = Instant::now();
    let verdict = sqli_check().run(&q(), &host).await;
    let wall = started.elapsed();

    assert_eq!(verdict.outcome, Outcome::Clean);
    assert_eq!(host.sent().len(), 8);
    // Two seconds, not a tight bound: the assertion is "it did not wait for
    // the three seconds it asked for", and a loaded CI box must not be able
    // to turn that into a flake.
    assert!(
        wall < Duration::from_secs(2),
        "the run took {wall:?}; a timing check must never wait"
    );
}

/// The source pin behind AC T3-4's "the scripts never call `sleep`". The AC's
/// subject is the **scanner's own** behaviour: this check must never wait, so
/// its source may not call a sleep. It may perfectly well *spell* one, because
/// `'||pg_sleep(n)--` is a payload asking the target to wait, and hiding that
/// payload behind a constant to satisfy a substring search made the code less
/// readable without making the scanner any less patient (review finding C4).
#[test]
fn no_sleep_call_in_the_source() {
    let src = include_str!("../src/blind_timing.rs");
    for call in [
        "tokio::time::sleep(",
        "thread::sleep(",
        "std::thread::sleep",
        // And the imports that would let a sleep be spelled without its path:
        // `use std::thread::{sleep, ..}` or `use tokio::time::sleep`.
        "std::thread",
        "tokio::time",
        "futures_timer",
    ] {
        assert!(
            !src.contains(call),
            "blind_timing.rs must never call {call}: the check reads elapsed_ms"
        );
    }
    // And the payload is spelled in the source, not hidden behind a constant
    // or assembled from pieces: an operator reading the module sees what goes
    // on the wire. (The rendered series itself is pinned by the probe test;
    // this does not pin the `format!` spelling, Q2-6.)
    assert!(
        src.contains("pg_sleep("),
        "the postgres payload must be written inline"
    );
}

/// `Check::run`'s contract: stop when the job is cancelled. Nothing is sent
/// after the cancellation is observed, and a check that sent nothing concluded
/// nothing.
#[tokio::test]
async fn a_cancelled_job_stops_after_the_current_probe() {
    let host = ScriptedHost::new()
        .with_cancelled(true)
        .with_baseline(timed(40))
        .on("SLEEP(1)", timed(1040))
        .on("SLEEP(3)", timed(3060));

    let verdict = sqli_check().run(&q(), &host).await;

    assert_eq!(verdict.outcome, Outcome::Inconclusive);
    assert!(host.sent().len() <= 1, "sent {}", host.sent().len());
}

/// A job whose budget runs out mid-family stops there and says so, rather than
/// regressing a truncated series into a verdict.
#[tokio::test]
async fn an_exhausted_budget_stops_the_run() {
    let host = ScriptedHost::new()
        .with_budget(3)
        .with_baseline(timed(40))
        .on("SLEEP(1)", timed(1040))
        .on("SLEEP(3)", timed(3060));

    let verdict = sqli_check().run(&q(), &host).await;

    assert_eq!(verdict.outcome, Outcome::Inconclusive);
    assert!(host.sent().len() <= 2, "sent {}", host.sent().len());
}

/// One refused probe costs its family the complete series, and a family that
/// could not be fitted is **not** evidence that the target was quiet. Here the
/// third mysql probe is refused and the postgres family is flat: the run has
/// sent every probe it planned, so the old epilogue called it `Clean` and said
/// the response time did not track the delay over eight probes — a sentence
/// that misstates what happened for four of them. It is `Inconclusive`, and
/// the detail says how many families were abandoned.
#[tokio::test]
async fn a_family_abandoned_for_a_refused_probe_is_inconclusive_not_clean() {
    let host = ScriptedHost::new()
        .with_baseline(timed(40))
        .with_probe_refused_at(3)
        .on("SLEEP(1)", timed(1040))
        .on("SLEEP(3)", timed(3060))
        .with_fallback(timed(45));

    let verdict = sqli_check().run(&q(), &host).await;

    assert_eq!(verdict.outcome, Outcome::Inconclusive, "{}", verdict.detail);
    assert_eq!(
        verdict.detail,
        "1 of 2 payload families was abandoned: a probe was refused part-way \
         through its schedule, so the series could not be fitted"
    );
    assert_eq!(host.sent().len(), 8);
}

/// Every probe refused is an error, not a clean bill of health.
#[tokio::test]
async fn a_host_that_refuses_every_probe_is_an_error() {
    let host = ScriptedHost::new()
        .with_baseline(timed(40))
        .with_probes_failing(true);

    let verdict = sqli_check().run(&q(), &host).await;

    assert_eq!(verdict.outcome, Outcome::Error);
}

// ---------------------------------------------------------------------------
// Catalogue metadata
// ---------------------------------------------------------------------------

/// The catalogue entries Task 10 lists and the scheduler reasons over. Both
/// checks are `medium` intensity, `timing` technique and capped at `firm`:
/// a blind differential is never `certain`.
#[test]
fn the_two_checks_carry_their_catalogue_meta() {
    let sqli = sqli_check();
    let m = sqli.meta();
    assert_eq!(m.id, "sqli-time");
    assert_eq!(m.class, "sqli");
    assert_eq!(m.lanes, vec![LaneKind::Http]);
    assert_eq!(
        m.kinds,
        vec![
            InsertionKind::Query,
            InsertionKind::BodyParam,
            InsertionKind::JsonValue,
            InsertionKind::XmlValue,
            InsertionKind::MultipartValue,
            InsertionKind::Header,
            InsertionKind::Cookie,
            InsertionKind::PathSegment,
        ]
    );
    assert_eq!(m.intensity, Intensity::Medium);
    assert_eq!(m.cost, CheckCost::Medium);
    assert_eq!(m.technique, Technique::Timing);
    assert_eq!(m.severity, aitm_poc::Severity::Critical);
    assert_eq!(m.confidence_max, Confidence::Firm);
    assert!(m.needs_baseline);
    assert!(!m.targets_session);
    assert_eq!(m.cwe, Some(89));
    assert_eq!(m.origin, CheckOrigin::Native);

    let cmdi = cmdi_check();
    let m = cmdi.meta();
    assert_eq!(m.id, "cmdi-time");
    assert_eq!(m.class, "cmdi");
    assert_eq!(m.cwe, Some(78));
    assert_eq!(m.technique, Technique::Timing);
    assert_eq!(m.severity, aitm_poc::Severity::Critical);
    assert_eq!(m.confidence_max, Confidence::Firm);
    assert!(m.needs_baseline);
    assert_eq!(m.kinds, sqli.meta().kinds);
}

// ---------------------------------------------------------------------------

fn sqli_check() -> std::sync::Arc<dyn Check> {
    aitm_scan_checks_http::blind_timing::sqli_time()
}

fn cmdi_check() -> std::sync::Arc<dyn Check> {
    aitm_scan_checks_http::blind_timing::cmdi_time()
}

// ---------------------------------------------------------------------------
// Tester pass over fix round F3: abandoned families at their edges
// ---------------------------------------------------------------------------

/// A refused probe in the *first* family does not hide a finding in the
/// second: mysql loses a probe and is abandoned, postgres correlates, and the
/// run reports postgres. A dropped request must never cost the point a real
/// finding.
#[tokio::test]
async fn a_refused_probe_in_one_family_does_not_hide_a_hit_in_the_next() {
    let host = ScriptedHost::new()
        .with_baseline(timed(40))
        .with_probe_refused_at(1)
        .on("pg_sleep(1)", timed(1040))
        .on("pg_sleep(3)", timed(3060))
        .with_fallback(timed(45));

    let verdict = sqli_check().run(&q(), &host).await;

    assert_eq!(verdict.outcome, Outcome::Vulnerable, "{}", verdict.detail);
    assert!(
        verdict
            .detail
            .starts_with("postgres: observed delay tracks the requested delay"),
        "{}",
        verdict.detail
    );
    assert_eq!(
        verdict.evidence.payload.as_deref(),
        Some("'||pg_sleep(3)--")
    );
    assert_eq!(host.sent().len(), 8);
}

/// The abandoned-family rule applies to the second family as much as the
/// first (postgres loses its last probe, mysql is flat), and when *both*
/// families lose a probe the detail counts both, in the plural.
#[tokio::test]
async fn abandoned_families_are_counted_wherever_they_fall() {
    let second_only = ScriptedHost::new()
        .with_baseline(timed(40))
        .with_probe_refused_at(8)
        .with_fallback(timed(45));
    let verdict = sqli_check().run(&q(), &second_only).await;
    assert_eq!(verdict.outcome, Outcome::Inconclusive, "{}", verdict.detail);
    assert_eq!(
        verdict.detail,
        "1 of 2 payload families was abandoned: a probe was refused part-way \
         through its schedule, so the series could not be fitted"
    );
    assert_eq!(second_only.sent().len(), 8);

    let both = ScriptedHost::new()
        .with_baseline(timed(40))
        .with_probe_refused_at(2)
        .with_probe_refused_at(7)
        .with_fallback(timed(45));
    let verdict = sqli_check().run(&q(), &both).await;
    assert_eq!(verdict.outcome, Outcome::Inconclusive, "{}", verdict.detail);
    assert_eq!(
        verdict.detail,
        "2 of 2 payload families were abandoned: a probe was refused part-way \
         through its schedule, so the series could not be fitted"
    );
    assert_eq!(both.sent().len(), 8);
    assert_eq!(
        verdict.evidence.timing, None,
        "an abandoned family is never fitted"
    );
}

/// The same rule for `cmdi-time`, whose families differ but whose loop is the
/// one `sqli-time` runs: a refused `; sleep` probe abandons the `sh` family.
#[tokio::test]
async fn cmdi_time_abandons_a_family_for_a_refused_probe_too() {
    let host = ScriptedHost::new()
        .with_baseline(timed(40))
        .with_probe_refused_at(4)
        .with_fallback(timed(45));

    let verdict = cmdi_check().run(&q(), &host).await;

    assert_eq!(verdict.outcome, Outcome::Inconclusive, "{}", verdict.detail);
    assert!(
        verdict
            .detail
            .starts_with("1 of 2 payload families was abandoned"),
        "{}",
        verdict.detail
    );
    assert_eq!(host.sent().len(), 8);
    assert!(host.sent()[0].starts_with("; sleep "), "{:?}", host.sent());
}

/// A refused probe *and* a stop in the same run: the stop is the scanner's
/// own doing and wins — the verdict says the run stopped early, not that a
/// family was abandoned, so the per-host error ladder is never fed by a
/// cancellation.
#[tokio::test]
async fn a_stop_after_a_refused_probe_is_reported_as_the_stop() {
    let host = ScriptedHost::new()
        .with_baseline(timed(40))
        .with_probe_refused_at(2)
        .with_cancel_after(5)
        .with_fallback(timed(45));

    let verdict = sqli_check().run(&q(), &host).await;

    assert_eq!(verdict.outcome, Outcome::Inconclusive);
    assert!(
        verdict
            .detail
            .starts_with("stopped after 5 of 8 delay probes"),
        "{}",
        verdict.detail
    );
    assert_eq!(host.sent().len(), 5);
}

/// The stop gate counts the budget *before* the baseline, and the per-probe
/// gate counts it before every delay probe: with exactly one family's worth
/// of budget after the baseline, the first family completes (and, flat, does
/// not correlate), the second never starts, and the run says so.
#[tokio::test]
async fn a_budget_for_exactly_one_family_runs_that_family_and_stops() {
    let host = ScriptedHost::new()
        .with_budget(5)
        .with_baseline(timed(40))
        .with_fallback(timed(45));

    let verdict = sqli_check().run(&q(), &host).await;

    assert_eq!(verdict.outcome, Outcome::Inconclusive);
    assert!(
        verdict
            .detail
            .starts_with("stopped after 4 of 8 delay probes"),
        "{}",
        verdict.detail
    );
    assert_eq!(host.sent().len(), 4);
    assert_eq!(host.budget_left(), 0);
}
