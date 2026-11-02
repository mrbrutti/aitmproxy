//! The native `sqli-boolean` check (spec D8.2). Implemented by T3 task 7.
//!
//! This is ZAP's `SqlInjectionScanRule` boolean half (research 17 §3.6),
//! expressed in the catalogue's vocabulary. The question it asks is the oldest
//! one in blind SQL injection: **does the page change when the condition
//! appended to the value changes, and only then?**
//!
//! The answer takes three responses per attempt:
//!
//! 1. the **baseline**, the point's request with nothing added;
//! 2. the **true arm**, the value with an always-true condition appended
//!    (` AND 1=1`). If the value lands inside a SQL statement, the statement's
//!    result set is unchanged, so the page must still look like the baseline;
//! 3. the **false arm**, the same shape with an always-false condition
//!    (` AND 1=2`). Now the result set is empty, so the page must look like
//!    neither the baseline nor the true arm.
//!
//! A page that reacts that way is reacting to SQL semantics, not to the bytes:
//! both arms are the same length and the same shape, and only the digit
//! differs. That asymmetry is why the technique is worth `firm` on a response
//! length alone.
//!
//! Two guards keep it honest:
//!
//! - **The control re-send.** Before any condition is sent, the point's own
//!   observed value goes back out and must reproduce the baseline. ZAP re-sends
//!   the original for a specific reason — an earlier payload "may have actually
//!   succeeded in modifying the database" — and the same re-send doubles as a
//!   stability test. A page that does not reproduce itself cannot be read by
//!   response length, so the check stops there with `inconclusive` rather than
//!   spending ten more probes to produce a guess.
//! - **Repeats.** `Accuracy` decides how many times a candidate pair must
//!   reproduce before it is reported (one, two or three agreeing runs, spec
//!   D2). A pair that hits once and not again is noise and is dropped.
//!
//! Everything sent is a read-only condition: `1=1`, `1=2` and quote/paren
//! variants of them. Nothing here stacks a statement, ends one, or asks the
//! database for data; the finding is the length difference, not an extraction
//! (spec anti-goals, plan "Shared facts").
//!
//! There is deliberately **no [`PocHint`](aitm_scan_model::PocHint)**: D6's
//! must-hint list names the Rhai `sqli` error technique, whose proof is a
//! matchable error string. A blind differential has no stable response
//! assertion — the proof is a comparison between three responses, which the PoC
//! matcher vocabulary cannot express — so a boolean issue never becomes a
//! `FindingRecord`.

use std::sync::Arc;

use aitm_poc::Severity;
use aitm_scan_model::{
    Accuracy, Check, CheckCost, CheckMeta, CheckOrigin, Confidence, Diff, Evidence, InsertionKind,
    InsertionPoint, Intensity, LaneKind, Outcome, Payload, PayloadMode, ProbeHost, ProbeResponse,
    Speed, Technique, Verdict,
};
use futures::future::BoxFuture;

use crate::gate::{self, no_finding, point_label, ProbeTally, STOPPED};
use crate::matching::{body_text, length_differs};

/// The hard ceiling on stimuli this check spends on one insertion point,
/// counting the control re-send and every repeat: **ten**, which is what
/// `cost: Medium` promises the scheduler.
///
/// `Speed::Thorough` would otherwise ask for seventeen (a control plus eight
/// pairs), and a confirmed hit late in the list can ask for more again. A pair
/// is atomic, so the cap lands on a control plus four whole pairs. It is the
/// check's own promise, independent of whatever budget the job still has.
const MAX_BOOLEAN_PROBES: u32 = 10;

/// The condition pairs, in the order they are tried, before the parenthesised
/// variants are appended.
///
/// The order is cheapest-first by how often it works: a bare numeric context,
/// then single- and double-quoted string contexts, then the `OR` form that
/// catches a value filtered into a `WHERE` clause the `AND` form cannot reach.
/// Both arms of a pair are the same length and differ in one digit, so a page
/// that reacts to one and not the other is reacting to the condition.
const BASE_PAIRS: [(&str, &str); 4] = [
    (" AND 1=1", " AND 1=2"),
    ("' AND '1'='1", "' AND '1'='2"),
    ("\" AND \"1\"=\"1", "\" AND \"1\"=\"2"),
    (" OR 1=1", " OR 1=2"),
];

/// Every pair, in order: the four base forms, then the same four with a leading
/// `)` for a value interpolated inside a parenthesised condition.
fn condition_pairs() -> Vec<(String, String)> {
    BASE_PAIRS
        .iter()
        .map(|(t, f)| ((*t).to_string(), (*f).to_string()))
        .chain(
            BASE_PAIRS
                .iter()
                .map(|(t, f)| (format!("){t}"), format!("){f}"))),
        )
        .collect()
}

/// How many pairs the profile's `Speed` allows (spec D2: 2 / 4 / 8).
fn pairs_allowed(speed: Speed) -> usize {
    match speed {
        Speed::Fast => 2,
        Speed::Normal => 4,
        Speed::Thorough => 8,
    }
}

/// How many agreeing runs of a pair the profile's `Accuracy` demands before the
/// check reports it (spec D2: 1 / 2 / 3). The first run counts as one.
fn confirmations(accuracy: Accuracy) -> u32 {
    match accuracy {
        Accuracy::FewerFalseNegatives => 1,
        Accuracy::Normal => 2,
        Accuracy::FewerFalsePositives => 3,
    }
}

/// The matched length of a response body: bounded by
/// [`crate::matching::body_text`], so a hostile target cannot make the
/// comparison arbitrarily expensive.
fn body_len(resp: &ProbeResponse) -> usize {
    body_text(resp).len()
}

/// Whether the three lengths are the boolean signature.
///
/// All three clauses must hold: the true arm reproduces the baseline, the false
/// arm diverges from the baseline, **and** the false arm diverges from the true
/// arm. The third is what rules out a page that simply reacts to any appended
/// text — there both arms move together and nothing is proven.
fn is_hit(baseline_len: usize, true_len: usize, false_len: usize) -> bool {
    !length_differs(true_len, baseline_len, baseline_len)
        && length_differs(false_len, baseline_len, baseline_len)
        && length_differs(false_len, true_len, baseline_len)
}

/// The catalogue entry for the boolean SQL-injection check (session call S3).
#[must_use]
pub fn check() -> Arc<dyn Check> {
    Arc::new(SqliBoolean::new())
}

/// Blind SQL injection by boolean response differential.
struct SqliBoolean {
    meta: CheckMeta,
}

impl SqliBoolean {
    fn new() -> Self {
        Self {
            meta: CheckMeta {
                id: "sqli-boolean".to_string(),
                name: "SQL injection (boolean differential)".to_string(),
                class: "sqli".to_string(),
                lanes: vec![LaneKind::Http],
                kinds: vec![
                    InsertionKind::Query,
                    InsertionKind::BodyParam,
                    InsertionKind::JsonValue,
                    InsertionKind::XmlValue,
                    InsertionKind::MultipartValue,
                    InsertionKind::Header,
                    InsertionKind::Cookie,
                    InsertionKind::PathSegment,
                ],
                intensity: Intensity::Medium,
                cost: CheckCost::Medium,
                technique: Technique::Boolean,
                severity: Severity::Critical,
                confidence_max: Confidence::Firm,
                needs_baseline: true,
                wants_traits: None,
                targets_session: false,
                scope: aitm_scan_model::CheckScope::Point,
                cwe: Some(89),
                description: "Re-sends the point's own value as a control, then appends an \
                              always-true and an always-false SQL condition and compares the \
                              three response lengths. Reports when the true arm reproduces the \
                              baseline and the false arm diverges from both, repeated as many \
                              times as the profile's accuracy demands."
                    .to_string(),
                remediation: Some(
                    "Pass the value to the database as a bound parameter of a prepared \
                     statement rather than concatenating it into SQL, and give the \
                     application's database account only the privileges it needs."
                        .to_string(),
                ),
                origin: CheckOrigin::Native,
            },
        }
    }
}

/// Whether the check may spend `need` more stimuli right now.
///
/// Four reasons to stop, and the check owns all four: the shared gate's three
/// (the job was cancelled, it is out of budget, it is past its deadline) plus
/// this check's own — the point has had its share, [`MAX_BOOLEAN_PROBES`].
/// `need` is 2 for a pair, because half a pair proves nothing and must never
/// be sent.
fn may_send(host: &dyn ProbeHost, spent: u32, need: u32) -> bool {
    gate::may_send(host, need) && spent.saturating_add(need) <= MAX_BOOLEAN_PROBES
}

/// The lengths of one run of a pair, kept so the reported evidence is the run
/// that was actually observed rather than a recomputed guess.
struct PairRun {
    true_len: usize,
    false_len: usize,
    true_flow: Option<aitm_scan_model::FlowRef>,
    false_flow: Option<aitm_scan_model::FlowRef>,
}

/// What one attempt at a pair concluded.
enum PairOutcome {
    /// The three lengths are the boolean signature.
    Hit(PairRun),
    /// The pair ran and did not show the signature.
    Miss,
    /// One of the two arms was refused; nothing was learned.
    Failed,
}

impl SqliBoolean {
    /// Send both arms of one pair once and classify the result.
    async fn run_pair(
        host: &dyn ProbeHost,
        true_arm: &str,
        false_arm: &str,
        baseline_len: usize,
    ) -> PairOutcome {
        let Some(t) = send_condition(host, true_arm).await else {
            return PairOutcome::Failed;
        };
        let Some(f) = send_condition(host, false_arm).await else {
            return PairOutcome::Failed;
        };
        let run = PairRun {
            true_len: body_len(&t),
            false_len: body_len(&f),
            true_flow: t.flow,
            false_flow: f.flow,
        };
        if is_hit(baseline_len, run.true_len, run.false_len) {
            PairOutcome::Hit(run)
        } else {
            PairOutcome::Miss
        }
    }
}

/// Append `condition` to the point's value and return the response, or `None`
/// if the host refused the probe.
async fn send_condition(host: &dyn ProbeHost, condition: &str) -> Option<ProbeResponse> {
    let payload = Payload {
        value: condition.to_string(),
        mode: PayloadMode::Suffix,
        bytes: None,
    };
    host.probe(&payload).await.ok()
}

/// The verdict for a pair that hit and reproduced.
fn confirmed(
    point: &InsertionPoint,
    true_arm: &str,
    false_arm: &str,
    baseline_len: usize,
    run: &PairRun,
    baseline_flow: Option<aitm_scan_model::FlowRef>,
    runs: u32,
) -> Verdict {
    let to_u32 = |n: usize| u32::try_from(n).unwrap_or(u32::MAX);
    Verdict {
        outcome: Outcome::Vulnerable,
        confidence: Confidence::Firm,
        evidence: Evidence {
            payload: Some(false_arm.to_string()),
            matched: None,
            probe_flows: run
                .true_flow
                .into_iter()
                .chain(run.false_flow)
                .collect::<Vec<_>>(),
            baseline_flow,
            diff: Some(Diff {
                baseline_len: to_u32(baseline_len),
                true_len: to_u32(run.true_len),
                false_len: to_u32(run.false_len),
            }),
            ..Evidence::default()
        },
        detail: format!(
            "the {kind:?} point \"{name}\" answered the always-true condition \"{true_arm}\" \
             with {true_len} bytes, matching its {baseline_len}-byte baseline, and the \
             always-false \"{false_arm}\" with {false_len} bytes; the pair reproduced {runs} \
             time(s), so the value is being evaluated as SQL",
            kind = point.kind,
            name = point_label(point),
            true_len = run.true_len,
            false_len = run.false_len,
        ),
        poc_hint: None,
        location: None,
        more: Vec::new(),
    }
}

impl Check for SqliBoolean {
    fn meta(&self) -> &CheckMeta {
        &self.meta
    }

    fn run<'a>(
        &'a self,
        point: &'a InsertionPoint,
        host: &'a dyn ProbeHost,
    ) -> BoxFuture<'a, Verdict> {
        Box::pin(async move {
            let mut spent = 0u32;

            // Nothing at all, not even a baseline, once the job has stopped.
            if !may_send(host, spent, 1) {
                return no_finding(
                    Outcome::Inconclusive,
                    format!("{STOPPED} before the baseline"),
                );
            }

            let Ok(baseline) = host.baseline().await else {
                return no_finding(
                    Outcome::Error,
                    "the point's baseline could not be fetched, so there is nothing to \
                     compare against",
                );
            };
            let baseline_len = body_len(&baseline);

            // Step 2: the control re-send. The point's own value goes back out
            // and must reproduce the baseline.
            if !may_send(host, spent, 1) {
                return no_finding(
                    Outcome::Inconclusive,
                    "the job stopped before the control re-send",
                );
            }
            // The control is the point's *own observed value*. With none to
            // re-send there is no stability test, and an empty value is a
            // different request whose answer says nothing about this one
            // (review findings Q-M4, SEC-C4).
            let Some(example) = point.example.clone() else {
                return no_finding(
                    Outcome::Inconclusive,
                    "the point carries no observed value to re-send as a control, so the \
                     boolean differential has nothing stable to compare against",
                );
            };
            spent += 1;
            let control_payload = Payload {
                value: example,
                mode: PayloadMode::Replace,
                bytes: None,
            };
            let Ok(control) = host.probe(&control_payload).await else {
                return no_finding(
                    Outcome::Error,
                    "the control re-send of the point's own value was refused",
                );
            };
            if length_differs(body_len(&control), baseline_len, baseline_len) {
                return no_finding(
                    Outcome::Inconclusive,
                    format!(
                        "the page is not stable enough for a boolean differential: re-sending \
                         the point's own value answered {} bytes against a {baseline_len}-byte \
                         baseline",
                        body_len(&control),
                    ),
                );
            }

            // Step 3: the pairs, in order, as many as `Speed` allows.
            let pairs = condition_pairs();
            let planned = pairs_allowed(host.profile().speed).min(pairs.len());
            let wanted = confirmations(host.profile().accuracy);
            let mut tally = ProbeTally::new("condition pairs", planned).also_stopped_by(format!(
                "this point had spent its {MAX_BOOLEAN_PROBES} probes"
            ));

            for (true_arm, false_arm) in pairs.iter().take(planned) {
                if !may_send(host, spent, 2) {
                    break;
                }
                spent += 2;
                tally.attempted();
                let first =
                    match SqliBoolean::run_pair(host, true_arm, false_arm, baseline_len).await {
                        PairOutcome::Hit(run) => run,
                        PairOutcome::Miss => continue,
                        PairOutcome::Failed => {
                            // One refused arm is not a verdict; try the next pair.
                            tally.refused();
                            continue;
                        }
                    };

                // Step 4: repeat the candidate until `Accuracy` is satisfied.
                // Every repeat must agree; one disagreement makes it noise.
                let mut agreed = 1u32;
                let mut stopped_early = false;
                while agreed < wanted {
                    if !may_send(host, spent, 2) {
                        stopped_early = true;
                        break;
                    }
                    spent += 2;
                    match SqliBoolean::run_pair(host, true_arm, false_arm, baseline_len).await {
                        PairOutcome::Hit(_) => agreed += 1,
                        // A repeat that *disagreed* says the difference was
                        // noise: drop the candidate and try the next pair.
                        PairOutcome::Miss => break,
                        // A repeat that could not be *sent* says nothing at
                        // all. Treating it as a miss would let a refused
                        // request end the run `Clean` over a candidate SQL
                        // injection, so the run stops here and says so.
                        PairOutcome::Failed => {
                            return no_finding(
                                Outcome::Inconclusive,
                                format!(
                                    "the pair \"{true_arm}\" / \"{false_arm}\" differed once \
                                     but a repeat could not be sent"
                                ),
                            )
                        }
                    }
                }

                if agreed >= wanted {
                    return confirmed(
                        point,
                        true_arm,
                        false_arm,
                        baseline_len,
                        &first,
                        baseline.flow,
                        agreed,
                    );
                }
                if stopped_early {
                    return no_finding(
                        Outcome::Inconclusive,
                        format!(
                            "the pair \"{true_arm}\" / \"{false_arm}\" differed once but the \
                             job stopped before it could be confirmed {wanted} time(s)"
                        ),
                    );
                }
                // The repeat disagreed: noise, not a finding. Next pair.
            }

            tally.conclude(format!(
                "no always-true/always-false pair changed the response length after \
                 {planned} pairs against a {baseline_len}-byte baseline"
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use aitm_scan_model::{Accuracy, Speed};

    use super::{
        condition_pairs, confirmations, is_hit, length_differs, pairs_allowed, MAX_BOOLEAN_PROBES,
    };

    /// The order is the plan's: four base pairs, then the same four with a
    /// leading `)`. Both arms of every pair are the same length, which is what
    /// makes a length difference mean the condition and not the bytes.
    #[test]
    fn the_eight_pairs_are_in_the_plans_order_and_balanced() {
        let pairs = condition_pairs();
        assert_eq!(pairs.len(), 8);
        assert_eq!(pairs[0], (" AND 1=1".to_string(), " AND 1=2".to_string()));
        assert_eq!(pairs[3], (" OR 1=1".to_string(), " OR 1=2".to_string()));
        assert_eq!(pairs[4], (") AND 1=1".to_string(), ") AND 1=2".to_string()));
        assert_eq!(pairs[7], (") OR 1=1".to_string(), ") OR 1=2".to_string()));
        for (t, f) in &pairs {
            assert_eq!(t.len(), f.len(), "{t} and {f} are not the same length");
        }
    }

    /// Nothing sent may end a statement, stack another, comment the rest of one
    /// out, or ask the database for data. These are read-only conditions.
    #[test]
    fn no_pair_contains_a_destructive_or_extracting_construct() {
        for (t, f) in condition_pairs() {
            for arm in [t, f] {
                let lowered = arm.to_ascii_lowercase();
                for banned in [
                    ";",
                    "--",
                    "/*",
                    "#",
                    "union",
                    "select",
                    "drop",
                    "delete",
                    "insert",
                    "update",
                    "sleep",
                    "waitfor",
                    "benchmark",
                    "load_file",
                    "xp_",
                ] {
                    assert!(!lowered.contains(banned), "{arm} contains {banned}");
                }
            }
        }
    }

    #[test]
    fn speed_and_accuracy_map_to_the_spec_d2_counts() {
        assert_eq!(pairs_allowed(Speed::Fast), 2);
        assert_eq!(pairs_allowed(Speed::Normal), 4);
        assert_eq!(pairs_allowed(Speed::Thorough), 8);

        assert_eq!(confirmations(Accuracy::FewerFalseNegatives), 1);
        assert_eq!(confirmations(Accuracy::Normal), 2);
        assert_eq!(confirmations(Accuracy::FewerFalsePositives), 3);
    }

    /// All three clauses of the signature, each failed in turn. The third one —
    /// the false arm must differ from the true arm too — is the clause that
    /// rules out a page reacting to any appended text.
    #[test]
    fn a_hit_needs_all_three_length_clauses() {
        assert!(is_hit(600, 600, 120), "the textbook case");

        assert!(
            !is_hit(600, 120, 60),
            "the true arm did not reproduce the baseline"
        );
        assert!(
            !is_hit(600, 600, 600),
            "the false arm did not diverge from the baseline"
        );
        assert!(
            !is_hit(600, 120, 120),
            "both arms moved together: the page reacts to any suffix"
        );
        // The third clause on its own. Above, the first clause already refuses
        // (120 is nothing like the 600-byte baseline), so the case says nothing
        // about the third. Here the true arm *does* reproduce the baseline
        // (40 bytes is exactly the noise floor) and the false arm *does*
        // diverge from it (60 bytes), and the pair is still not a hit, because
        // the two arms are only 20 bytes apart: the page drifted, it did not
        // answer the condition.
        assert!(!length_differs(640, 600, 600), "clause 1 holds");
        assert!(length_differs(660, 600, 600), "clause 2 holds");
        assert!(
            !is_hit(600, 640, 660),
            "the false arm must diverge from the true arm too"
        );
        assert!(is_hit(600, 640, 681), "41 bytes apart is a divergence");

        // The threshold is `matching::length_differs`, so a difference inside
        // the noise floor is not a difference.
        assert!(
            !is_hit(600, 600, 570),
            "30 bytes is below the 40-byte floor"
        );
        assert!(is_hit(600, 600, 559), "41 bytes is above it");
    }

    /// A thorough run asks for a control plus eight pairs, which is seventeen
    /// stimuli; the cap must be what actually stops it.
    #[test]
    fn the_cap_is_below_what_a_thorough_run_would_ask_for() {
        let thorough = 1 + 2 * pairs_allowed(Speed::Thorough);
        assert!(u32::try_from(thorough).is_ok_and(|n| n > MAX_BOOLEAN_PROBES));
        assert_eq!(MAX_BOOLEAN_PROBES, 10);
    }
}
