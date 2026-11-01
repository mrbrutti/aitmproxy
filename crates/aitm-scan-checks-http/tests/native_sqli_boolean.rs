//! The native `sqli-boolean` check (spec D8.2, D2; T3 plan task 7).
//!
//! The check is ZAP's `SqlInjectionScanRule` boolean half: re-send the point's
//! own value as a control, then send an always-true and an always-false
//! condition and compare the three response lengths. Nothing here touches a
//! socket — every response comes from the scripted host, and every body is
//! `"x".repeat(n)` so the lengths the check compares are exact and the
//! assertions can be literal.
//!
//! What these tests pin, in order of how much they matter:
//!
//! 1. the differential itself (true arm matches the baseline, false arm
//!    diverges from both) and the `Diff` evidence it produces;
//! 2. that an unstable page is `inconclusive` rather than a finding — the
//!    control re-send exists to make a flaky page cost two probes, not ten;
//! 3. the `Speed` and `Accuracy` dials of spec D2, counted in probes;
//! 4. the stop contract: the ten-probe cap, the budget, cancellation.

mod support;

use aitm_poc::Severity;
use aitm_scan_model::{
    Accuracy, Check, CheckCost, CheckOrigin, Confidence, Diff, InsertionKind, Intensity, LaneKind,
    Outcome, PayloadMode, Speed, Technique,
};

use support::{html, point, ScriptedHost, TARGET_URL};

/// The hard per-point cap the plan names (`MAX_BOOLEAN_PROBES`).
const MAX_BOOLEAN_PROBES: usize = 10;

/// The first pair the check tries, in order.
const TRUE_ARM: &str = " AND 1=1";
const FALSE_ARM: &str = " AND 1=2";

/// The example value `support::point` gives every point; the control re-sends
/// exactly this.
const EXAMPLE: &str = "seed";

/// A body of exactly `n` bytes.
fn body(n: usize) -> String {
    "x".repeat(n)
}

/// A host whose first pair is a textbook boolean hit: the baseline, the control
/// and the true arm are all 600 bytes, the false arm is 120.
fn vulnerable_host() -> ScriptedHost {
    ScriptedHost::new()
        .with_baseline(html(200, &body(600)))
        .on(EXAMPLE, html(200, &body(600)))
        .on("1=1", html(200, &body(600)))
        .on("1=2", html(200, &body(120)))
        .with_fallback(html(200, &body(600)))
}

fn sqli() -> std::sync::Arc<dyn Check> {
    aitm_scan_checks_http::sqli_boolean::check()
}

/// How many stimuli carried the always-false condition of the first pair.
fn false_arms(host: &ScriptedHost) -> usize {
    host.sent().iter().filter(|p| p.contains("1=2")).count()
}

// ---------------------------------------------------------------------------
// The differential
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_true_matching_and_false_diverging_pair_is_firm() {
    let host = vulnerable_host();
    let point = point(InsertionKind::Query, "id", TARGET_URL);

    let verdict = sqli().run(&point, &host).await;

    assert_eq!(verdict.outcome, Outcome::Vulnerable);
    assert_eq!(
        verdict.confidence,
        Confidence::Firm,
        "a blind differential is never `certain`"
    );
    assert_eq!(
        verdict.evidence.diff,
        Some(Diff {
            baseline_len: 600,
            true_len: 600,
            false_len: 120,
        }),
        "the three lengths are the whole proof"
    );
    assert_eq!(
        verdict.evidence.payload,
        Some(FALSE_ARM.to_string()),
        "the payload that produced the reaction is the diverging arm"
    );
    assert_eq!(
        verdict.evidence.matched, None,
        "a blind technique matched no text"
    );
    assert!(
        verdict.poc_hint.is_none(),
        "a boolean differential has no stable response assertion, so no hint"
    );
}

/// The exact stimuli, in order: the control re-send, then the first pair, then
/// the one repeat `Accuracy::Normal` asks for. The control is a `replace` of
/// the point's own value; a condition is a `suffix` on it.
#[tokio::test]
async fn the_probe_sequence_is_control_then_the_pair_then_its_repeat() {
    let host = vulnerable_host();
    let point = point(InsertionKind::Query, "id", TARGET_URL);

    let _ = sqli().run(&point, &host).await;

    assert_eq!(
        host.sent(),
        vec![
            EXAMPLE.to_string(),
            TRUE_ARM.to_string(),
            FALSE_ARM.to_string(),
            TRUE_ARM.to_string(),
            FALSE_ARM.to_string(),
        ]
    );
    let modes: Vec<PayloadMode> = host.sent_probes().into_iter().map(|s| s.mode).collect();
    assert_eq!(
        modes,
        vec![
            PayloadMode::Replace,
            PayloadMode::Suffix,
            PayloadMode::Suffix,
            PayloadMode::Suffix,
            PayloadMode::Suffix,
        ]
    );
    assert_eq!(host.baseline_calls(), 1, "the baseline is fetched once");
}

/// The detail names the pair and the three lengths, and quotes no response
/// text: a body excerpt in a boolean detail would be pure noise and a
/// redaction hazard (spec D8.2, "Redaction").
#[tokio::test]
async fn the_detail_names_the_pair_and_the_three_lengths() {
    let host = vulnerable_host();
    let point = point(InsertionKind::Query, "id", TARGET_URL);

    let verdict = sqli().run(&point, &host).await;

    for needle in [TRUE_ARM, FALSE_ARM, "600", "120", "id"] {
        assert!(
            verdict.detail.contains(needle),
            "detail {:?} is missing {needle:?}",
            verdict.detail
        );
    }
    assert!(
        !verdict.detail.contains("xxx"),
        "detail quoted the response body: {:?}",
        verdict.detail
    );
}

#[tokio::test]
async fn a_pair_that_does_not_diverge_is_clean() {
    // Every response, control and both arms alike, is 600 bytes.
    let host = ScriptedHost::new()
        .with_baseline(html(200, &body(600)))
        .with_fallback(html(200, &body(600)));
    let point = point(InsertionKind::Query, "id", TARGET_URL);

    let verdict = sqli().run(&point, &host).await;

    assert_eq!(verdict.outcome, Outcome::Clean);
    assert_eq!(verdict.confidence, Confidence::Tentative);
    assert_eq!(verdict.evidence.diff, None);
    // Control plus the four pairs `Speed::Normal` allows, both arms each.
    assert_eq!(host.sent().len(), 9);
}

/// A false arm that diverges from the baseline but not from the true arm is a
/// page that reacts to any suffix, not to the condition. That is not a hit.
#[tokio::test]
async fn a_false_arm_that_matches_the_true_arm_is_clean() {
    let host = ScriptedHost::new()
        .with_baseline(html(200, &body(600)))
        .on(EXAMPLE, html(200, &body(600)))
        .with_fallback(html(200, &body(120)));
    let point = point(InsertionKind::Query, "id", TARGET_URL);

    let verdict = sqli().run(&point, &host).await;

    assert_eq!(verdict.outcome, Outcome::Clean);
}

// ---------------------------------------------------------------------------
// The control re-send
// ---------------------------------------------------------------------------

/// ZAP re-sends the original because a payload may have changed state. If that
/// re-send does not reproduce the baseline, no length comparison downstream
/// means anything, so the check stops after two stimuli.
#[tokio::test]
async fn an_unstable_page_is_inconclusive() {
    let host = ScriptedHost::new()
        .with_baseline(html(200, &body(600)))
        .on(EXAMPLE, html(200, &body(300)))
        .with_fallback(html(200, &body(600)));
    let point = point(InsertionKind::Query, "id", TARGET_URL);

    let verdict = sqli().run(&point, &host).await;

    assert_eq!(verdict.outcome, Outcome::Inconclusive);
    assert_eq!(verdict.confidence, Confidence::Tentative);
    // Two stimuli in total: the baseline and the control. The scripted host
    // records the baseline separately from `sent`.
    assert_eq!(host.baseline_calls(), 1);
    assert_eq!(host.sent(), vec![EXAMPLE.to_string()]);
}

#[tokio::test]
async fn a_baseline_that_cannot_be_fetched_is_an_error() {
    let host = ScriptedHost::new().with_baseline_fails(true);
    let point = point(InsertionKind::Query, "id", TARGET_URL);

    let verdict = sqli().run(&point, &host).await;

    assert_eq!(verdict.outcome, Outcome::Error);
    assert!(host.sent().is_empty(), "no probe follows a failed baseline");
}

#[tokio::test]
async fn a_control_that_cannot_be_sent_is_an_error() {
    let host = ScriptedHost::new()
        .with_baseline(html(200, &body(600)))
        .with_probes_failing(true);
    let point = point(InsertionKind::Query, "id", TARGET_URL);

    let verdict = sqli().run(&point, &host).await;

    assert_eq!(verdict.outcome, Outcome::Error);
    assert_eq!(host.sent().len(), 1, "the check gives up after the control");
}

// ---------------------------------------------------------------------------
// The Speed and Accuracy dials (spec D2)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn speed_fast_tries_two_pairs_and_thorough_eight() {
    let stable = || {
        ScriptedHost::new()
            .with_baseline(html(200, &body(600)))
            .with_fallback(html(200, &body(600)))
            .with_budget(64)
    };
    let point = point(InsertionKind::Query, "id", TARGET_URL);

    let fast = stable().with_speed(Speed::Fast);
    assert_eq!(sqli().run(&point, &fast).await.outcome, Outcome::Clean);
    assert_eq!(fast.sent().len(), 1 + 2 * 2);

    let thorough = stable().with_speed(Speed::Thorough);
    // Eight pairs would be seventeen stimuli; the cap stops it at nine, so a
    // thorough run that found nothing is inconclusive, not clean.
    let verdict = sqli().run(&point, &thorough).await;
    assert_eq!(verdict.outcome, Outcome::Inconclusive);
    assert_eq!(thorough.sent().len(), 9);
}

#[tokio::test]
async fn accuracy_normal_repeats_the_hit_once() {
    let host = vulnerable_host().with_accuracy(Accuracy::Normal);
    let point = point(InsertionKind::Query, "id", TARGET_URL);

    let verdict = sqli().run(&point, &host).await;

    assert_eq!(verdict.outcome, Outcome::Vulnerable);
    assert_eq!(false_arms(&host), 2);
}

#[tokio::test]
async fn accuracy_fewer_false_negatives_does_not_repeat_the_hit() {
    let host = vulnerable_host().with_accuracy(Accuracy::FewerFalseNegatives);
    let point = point(InsertionKind::Query, "id", TARGET_URL);

    let verdict = sqli().run(&point, &host).await;

    assert_eq!(verdict.outcome, Outcome::Vulnerable);
    assert_eq!(false_arms(&host), 1);
}

#[tokio::test]
async fn accuracy_fewer_false_positives_repeats_the_hit_twice() {
    let host = vulnerable_host().with_accuracy(Accuracy::FewerFalsePositives);
    let point = point(InsertionKind::Query, "id", TARGET_URL);

    let verdict = sqli().run(&point, &host).await;

    assert_eq!(verdict.outcome, Outcome::Vulnerable);
    assert_eq!(false_arms(&host), 3);
}

/// A pair that hits once and misses on its repeat is noise, not a finding.
/// `Accuracy::Normal` wants two agreeing runs, so the second run of the first
/// pair is scripted to come back the baseline's length: the differential
/// disappears and the check must not report it, however convincing the first
/// run was.
#[tokio::test]
async fn a_hit_that_does_not_reproduce_on_its_repeat_is_not_reported() {
    let host = vulnerable_host()
        .with_accuracy(Accuracy::Normal)
        // Two pairs, so the run is exactly the first pair, its repeat, and one
        // more pair that never diverges.
        .with_speed(Speed::Fast)
        // The repeat's false arm answers like the baseline: no divergence.
        .on_nth(" AND 1=2", 2, html(200, &body(600)));
    let point = point(InsertionKind::Query, "id", TARGET_URL);

    let verdict = sqli().run(&point, &host).await;

    assert_eq!(
        verdict.outcome,
        Outcome::Clean,
        "an unreproduced difference was reported: {}",
        verdict.detail
    );
    assert_eq!(
        host.sent().iter().filter(|p| *p == FALSE_ARM).count(),
        2,
        "the first pair was run exactly twice: {:?}",
        host.sent()
    );
}

/// A repeat that could not be **sent** is not the same as a repeat that
/// disagreed. The first says nothing about the target; the second says the
/// difference was noise. Reporting the first as `Clean` would bury a candidate
/// SQL injection behind a refused request, so it is `Inconclusive` and the
/// detail names the pair that was left unconfirmed.
#[tokio::test]
async fn a_refused_repeat_after_a_hit_is_inconclusive_not_clean() {
    let host = vulnerable_host()
        .with_accuracy(Accuracy::Normal)
        .with_speed(Speed::Fast)
        // Control, true arm, false arm go through; the repeat is refused.
        .with_probes_failing_after(3);
    let point = point(InsertionKind::Query, "id", TARGET_URL);

    let verdict = sqli().run(&point, &host).await;

    assert_eq!(verdict.outcome, Outcome::Inconclusive);
    assert_eq!(
        verdict.detail,
        "the pair \" AND 1=1\" / \" AND 1=2\" differed once but a repeat could not be sent"
    );
    assert_eq!(
        verdict.evidence.diff, None,
        "an unconfirmed pair is not evidence"
    );
}

/// The control re-send is the point's **own observed value**. A point that
/// carries none cannot be re-sent, and sending an empty value instead is a
/// different request: it would compare the page's answer to "" against the
/// baseline and call a stable page unstable. The check says what is missing
/// and sends nothing (review findings Q-M4 and SEC-C4).
#[tokio::test]
async fn a_point_with_no_example_is_inconclusive_and_sends_no_control() {
    let host = vulnerable_host();
    let mut point = point(InsertionKind::Query, "id", TARGET_URL);
    point.example = None;

    let verdict = sqli().run(&point, &host).await;

    assert_eq!(verdict.outcome, Outcome::Inconclusive);
    assert_eq!(
        verdict.detail,
        "the point carries no observed value to re-send as a control, so the boolean \
         differential has nothing stable to compare against"
    );
    assert!(host.sent().is_empty(), "sent {:?}", host.sent());
}

// ---------------------------------------------------------------------------
// The stop contract
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_check_never_exceeds_ten_probes() {
    // Every arm diverges from the 600-byte baseline, so no pair ever hits and
    // the check runs until something stops it.
    let host = ScriptedHost::new()
        .with_speed(Speed::Thorough)
        .with_baseline(html(200, &body(600)))
        .on(EXAMPLE, html(200, &body(600)))
        .with_fallback(html(200, &body(120)))
        .with_budget(64);
    let point = point(InsertionKind::Query, "id", TARGET_URL);

    let verdict = sqli().run(&point, &host).await;

    assert!(
        host.sent().len() <= MAX_BOOLEAN_PROBES,
        "sent {} probes",
        host.sent().len()
    );
    // A pair is atomic, so the cap lands on the control plus four whole pairs.
    assert_eq!(host.sent().len(), 9);
    assert_eq!(verdict.outcome, Outcome::Inconclusive);
}

#[tokio::test]
async fn the_check_stops_when_the_budget_is_gone() {
    let host = vulnerable_host().with_budget(1);
    let point = point(InsertionKind::Query, "id", TARGET_URL);

    let verdict = sqli().run(&point, &host).await;

    // The one unit left pays for the baseline; the control cannot be sent.
    assert!(host.sent().len() <= 1, "sent {:?}", host.sent());
    assert_eq!(verdict.outcome, Outcome::Inconclusive);
}

#[tokio::test]
async fn a_cancelled_job_sends_nothing_at_all() {
    let host = vulnerable_host().with_cancelled(true);
    let point = point(InsertionKind::Query, "id", TARGET_URL);

    let verdict = sqli().run(&point, &host).await;

    assert_eq!(verdict.outcome, Outcome::Inconclusive);
    assert!(host.sent().is_empty());
    assert_eq!(host.baseline_calls(), 0, "not even a baseline");
}

#[tokio::test]
async fn a_passed_deadline_stops_the_run() {
    let host = vulnerable_host()
        .with_deadline(std::time::Instant::now() - std::time::Duration::from_secs(1));
    let point = point(InsertionKind::Query, "id", TARGET_URL);

    let verdict = sqli().run(&point, &host).await;

    assert_eq!(verdict.outcome, Outcome::Inconclusive);
    assert!(host.sent().is_empty());
}

// ---------------------------------------------------------------------------
// Meta
// ---------------------------------------------------------------------------

/// Session call S3 and the plan's task 7 row, field for field. The scheduler
/// reads every one of these, so a drift here silently re-aims the check.
#[tokio::test]
async fn sqli_boolean_meta_is_the_task_7_entry() {
    let check = sqli();
    let meta = check.meta();

    assert_eq!(meta.id, "sqli-boolean");
    assert_eq!(meta.class, "sqli");
    assert_eq!(meta.lanes, vec![LaneKind::Http]);
    assert_eq!(
        meta.kinds,
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
    assert_eq!(meta.intensity, Intensity::Medium);
    assert_eq!(meta.cost, CheckCost::Medium);
    assert_eq!(meta.technique, Technique::Boolean);
    assert_eq!(meta.severity, Severity::Critical);
    assert_eq!(meta.confidence_max, Confidence::Firm);
    assert!(meta.needs_baseline);
    assert_eq!(meta.wants_traits, None);
    assert!(!meta.targets_session);
    assert_eq!(meta.cwe, Some(89));
    assert_eq!(meta.origin, CheckOrigin::Native);
    assert!(meta.remediation.is_some());
}

// ---------------------------------------------------------------------------
// Tester pass over fix round F3: the confirmation loop's other exits
// ---------------------------------------------------------------------------

/// The refused-repeat rule holds on the *second* repeat too, not only the
/// first: `Accuracy::FewerFalsePositives` wants three agreeing runs, the
/// first two agree and the third cannot be sent. Still `Inconclusive`, still
/// naming the pair, still no `Diff`.
#[tokio::test]
async fn a_refused_second_repeat_is_inconclusive_too() {
    let host = vulnerable_host()
        .with_accuracy(Accuracy::FewerFalsePositives)
        .with_speed(Speed::Fast)
        // Control, pair, first repeat go through (five stimuli); the second
        // repeat's true arm is refused.
        .with_probes_failing_after(5);
    let point = point(InsertionKind::Query, "id", TARGET_URL);

    let verdict = sqli().run(&point, &host).await;

    assert_eq!(verdict.outcome, Outcome::Inconclusive, "{}", verdict.detail);
    assert_eq!(
        verdict.detail,
        "the pair \" AND 1=1\" / \" AND 1=2\" differed once but a repeat could not be sent"
    );
    assert_eq!(verdict.evidence.diff, None);
    assert_eq!(host.sent().len(), 6, "it stopped at the refused arm");
}

/// A refusal during a pair that had *not* hit is not the same thing: the
/// check moves on, and a later pair that hits and reproduces is still the
/// finding. A single dropped request must not cost the point its verdict.
#[tokio::test]
async fn a_refused_first_pair_does_not_hide_a_later_hit() {
    let host = ScriptedHost::new()
        .with_baseline(html(200, &body(600)))
        .on(EXAMPLE, html(200, &body(600)))
        // The second pair (single-quoted) is the real hit.
        .on("'1'='1", html(200, &body(600)))
        .on("'1'='2", html(200, &body(120)))
        .with_fallback(html(200, &body(600)))
        // The first pair's true arm (stimulus 2) is refused.
        .with_probe_refused_at(2);
    let point = point(InsertionKind::Query, "id", TARGET_URL);

    let verdict = sqli().run(&point, &host).await;

    assert_eq!(verdict.outcome, Outcome::Vulnerable, "{}", verdict.detail);
    assert_eq!(verdict.confidence, Confidence::Firm);
    assert_eq!(
        verdict.evidence.payload.as_deref(),
        Some("' AND '1'='2"),
        "the finding is the pair that hit, not the one that was refused"
    );
    assert_eq!(
        verdict.evidence.diff,
        Some(Diff {
            baseline_len: 600,
            true_len: 600,
            false_len: 120,
        })
    );
    // Control, the refused true arm (the false arm is never sent once its
    // partner failed), then the second pair twice.
    assert_eq!(
        host.sent(),
        vec![
            EXAMPLE.to_string(),
            " AND 1=1".to_string(),
            "' AND '1'='1".to_string(),
            "' AND '1'='2".to_string(),
            "' AND '1'='1".to_string(),
            "' AND '1'='2".to_string(),
        ]
    );
}

/// A hit that does not reproduce is dropped — and the loop goes on. The next
/// pair, which does reproduce, is reported, so a flaky first pair does not
/// end the run `Clean` over a real finding further down the list.
#[tokio::test]
async fn an_unreproduced_hit_is_dropped_and_a_later_reproducing_pair_is_reported() {
    let host = vulnerable_host()
        .with_accuracy(Accuracy::Normal)
        // The first pair's repeat does not diverge.
        .on_nth(" AND 1=2", 2, html(200, &body(600)))
        // The second pair hits every time.
        .on("'1'='1", html(200, &body(600)))
        .on("'1'='2", html(200, &body(120)));
    let point = point(InsertionKind::Query, "id", TARGET_URL);

    let verdict = sqli().run(&point, &host).await;

    assert_eq!(verdict.outcome, Outcome::Vulnerable, "{}", verdict.detail);
    assert_eq!(verdict.evidence.payload.as_deref(), Some("' AND '1'='2"));
    assert!(
        verdict.detail.contains("reproduced 2 time(s)"),
        "{}",
        verdict.detail
    );
    // Control + first pair twice + second pair twice = 9, inside the cap.
    assert_eq!(host.sent().len(), 9);
}

/// The cap counts stimuli, not pairs, and the baseline is the lane's and is
/// not one of them: a `thorough` run with a hit on the fourth pair at
/// `Accuracy::Normal` needs a control plus four pairs plus one repeat, which
/// is eleven — over the cap — so the repeat is refused and the run says the
/// cap stopped it. Ten is the number the scheduler was promised.
#[tokio::test]
async fn the_cap_refuses_the_repeat_that_would_be_the_eleventh_probe() {
    let host = ScriptedHost::new()
        .with_speed(Speed::Thorough)
        .with_accuracy(Accuracy::Normal)
        .with_baseline(html(200, &body(600)))
        .on(EXAMPLE, html(200, &body(600)))
        // Only the fourth pair (the OR form) diverges.
        .on(" OR 1=2", html(200, &body(120)))
        .with_fallback(html(200, &body(600)))
        .with_budget(64);
    let point = point(InsertionKind::Query, "id", TARGET_URL);

    let verdict = sqli().run(&point, &host).await;

    assert_eq!(verdict.outcome, Outcome::Inconclusive, "{}", verdict.detail);
    assert!(
        verdict
            .detail
            .contains("differed once but the job stopped before it could be confirmed"),
        "{}",
        verdict.detail
    );
    assert_eq!(
        host.sent().len(),
        9,
        "control plus four whole pairs; no eleventh"
    );
    assert!(host.sent().len() <= MAX_BOOLEAN_PROBES);
}
