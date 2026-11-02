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

use crate::gate::is_server_error;
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

/// Condition pairs answered 5xx on both arms before the point is given up as
/// error-based territory (F8c; panel review of PR 2a).
const MAX_ERRORED_PAIRS: usize = 2;

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

/// How a pair's responses are compared against the baseline.
///
/// Decided once per point, at the control re-send: a page that answers the
/// same request with the same bytes is compared by **content**, a page that
/// does not (a nonce, a timestamp, a rotating advert) by **length**. The
/// live run of 2026-11-01 is why both exist: the seeded `/items` answers
/// `<p>items: 1</p>` to the true arm and `<p>items: 0</p>` to the false one,
/// the same fifteen bytes, and the length rule alone could never see it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Signature {
    /// Byte-for-byte, with every echo of the sent value scrubbed out first
    /// so a page that merely reflects the parameter is not different from
    /// itself.
    Content,
    /// ZAP's rule: lengths, with the shipped tolerance
    /// ([`crate::matching::length_differs`]).
    Length,
}

/// The baseline a pair is compared against: its length, and its body with
/// the point's own value scrubbed out.
struct Baseline {
    len: usize,
    body: String,
    flow: Option<aitm_scan_model::FlowRef>,
}

/// The marker every echo of the sent value becomes before two bodies are
/// compared. A control character no HTML page carries.
const ECHO_MARK: &str = "\u{1}";

/// The longest sent value whose echoes are scrubbed. A parameter value longer
/// than this is not something a page echoes back as a unit, and the forms of
/// an unbounded value would be the one target-controlled cost in this path
/// (security review of PR 2a).
const MAX_ECHO_FORM: usize = 4096;

/// The forms a page may print `value` in: raw, percent-encoded (upper- and
/// lower-case hex, and `+` for a space), and HTML-escaped with the
/// apostrophe as `&#x27;` (the project's own escaper and OWASP's), `&#39;`
/// or `&apos;`. Empty when `value` is empty or over [`MAX_ECHO_FORM`].
fn echo_forms(value: &str) -> Vec<String> {
    if value.is_empty() || value.len() > MAX_ECHO_FORM {
        return Vec::new();
    }
    let upper = aitm_poc::dsl::url_encode(value);
    let escaped = aitm_poc::dsl::html_escape(value);
    vec![
        value.to_string(),
        upper.replace("%20", "+"),
        upper.to_ascii_lowercase(),
        upper,
        escaped.replace("&#x27;", "&#39;"),
        escaped.replace("&#x27;", "&apos;"),
        escaped,
    ]
}

/// A response body with every echo of each of `sent` (in every form of
/// [`echo_forms`]) replaced by [`ECHO_MARK`], bounded like [`body_len`] is.
///
/// Every body of one point is scrubbed of the point's own value, and an arm's
/// body of the whole value it sent as well, so the three bodies are scrubbed
/// alike: a page that echoes the parameter compares equal to itself, and a
/// value as short as `1` that also happens to appear in the page's content
/// (`items: 1`, the live seed) is scrubbed out of the baseline and the arms
/// the same way rather than out of the baseline alone.
fn normalized(resp: &ProbeResponse, sent: &[&str]) -> String {
    let mut text = body_text(resp).into_owned();
    let mut forms: Vec<String> = sent
        .iter()
        .flat_map(|value| echo_forms(value))
        .filter(|form| form.len() <= text.len())
        .collect();
    // Longest first, so a form that contains another is replaced whole; equal
    // lengths in lexical order, so `dedup` sees every duplicate adjacent.
    forms.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
    forms.dedup();
    for form in forms {
        text = text.replace(&form, ECHO_MARK);
    }
    text
}

/// Where two bodies first part, for the evidence of a content hit: a bounded
/// slice of each from the first differing byte, so the reader sees the digit
/// that moved and not two identical lengths. The caller hands in bodies that
/// are already echo-scrubbed *and* credential-scrubbed, so the byte offset
/// counts in the scrubbed text and nothing cut here escapes the scrub.
fn divergence(baseline: &str, other: &str) -> String {
    let common = baseline
        .bytes()
        .zip(other.bytes())
        .take_while(|(a, b)| a == b)
        .count();
    let cut = |text: &str| {
        let mut from = common.min(text.len());
        while !text.is_char_boundary(from) {
            from -= 1;
        }
        let mut to = (from + 48).min(text.len());
        while !text.is_char_boundary(to) {
            to -= 1;
        }
        text[from..to].replace(ECHO_MARK, "<value>")
    };
    let (ours, theirs) = (cut(baseline), cut(other));
    if ours.is_empty() && theirs.is_empty() {
        // The scrub collapsed the only difference: say that rather than quote
        // two empty windows.
        return format!(
            "true arm reproduced the baseline; false arm differed only in scrubbed text \
             ({} vs {} bytes)",
            baseline.len(),
            other.len()
        );
    }
    format!(
        "true arm reproduced the baseline; false arm differed at byte {common} of the scrubbed \
         body: baseline \"{ours}\" vs \"{theirs}\""
    )
}

/// Whether a pair's run is the boolean signature under `signature`.
///
/// Content: the true arm reproduces the baseline body and the false arm does
/// not (so the two arms differ from each other too). Length: all three
/// clauses must hold — the true arm reproduces the baseline, the false arm
/// diverges from the baseline, **and** the false arm diverges from the true
/// arm. The third is what rules out a page that simply reacts to any
/// appended text — there both arms move together and nothing is proven.
fn is_hit(signature: Signature, baseline: &Baseline, run: &PairRun) -> bool {
    match signature {
        Signature::Content => run.true_body == baseline.body && run.false_body != baseline.body,
        Signature::Length => {
            !length_differs(run.true_len, baseline.len, baseline.len)
                && length_differs(run.false_len, baseline.len, baseline.len)
                && length_differs(run.false_len, run.true_len, baseline.len)
        }
    }
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
                              three responses: by content on a page that answers the control \
                              byte for byte, by length otherwise. Reports when the true arm \
                              reproduces the baseline and the false arm diverges from both, \
                              repeated as many times as the profile's accuracy demands."
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

/// One run of a pair — the lengths and the scrubbed bodies of both arms —
/// kept so the reported evidence is the run that was actually observed
/// rather than a recomputed guess.
struct PairRun {
    true_len: usize,
    false_len: usize,
    true_body: String,
    false_body: String,
    true_flow: Option<aitm_scan_model::FlowRef>,
    false_flow: Option<aitm_scan_model::FlowRef>,
}

/// What one attempt at a pair concluded.
enum PairOutcome {
    /// The run is the boolean signature.
    Hit(PairRun),
    /// The pair ran and did not show the signature.
    Miss,
    /// One of the two arms was refused; nothing was learned.
    Failed,
    /// Both arms were answered with a 5xx: the payload breaks the query
    /// rather than being evaluated as a condition. That is the error-based
    /// check's finding, not a boolean differential, and every further pair
    /// would be one more server error for a host whose error ladder the job
    /// shares with every other check (live run 2026-11-01: the seeded
    /// error-based `/products` tripped the per-host ladder for the whole job).
    Errored,
}

impl SqliBoolean {
    /// Send both arms of one pair once and classify the result. `example` is
    /// the point's own value the arms are appended to, so the bodies are
    /// scrubbed of exactly what was sent.
    async fn run_pair(
        host: &dyn ProbeHost,
        example: &str,
        true_arm: &str,
        false_arm: &str,
        baseline: &Baseline,
        signature: Signature,
    ) -> PairOutcome {
        let Some(t) = send_condition(host, true_arm).await else {
            return PairOutcome::Failed;
        };
        let Some(f) = send_condition(host, false_arm).await else {
            return PairOutcome::Failed;
        };
        if is_server_error(&t) && is_server_error(&f) {
            return PairOutcome::Errored;
        }
        let run = PairRun {
            true_len: body_len(&t),
            false_len: body_len(&f),
            true_body: normalized(&t, &[example, &format!("{example}{true_arm}")]),
            false_body: normalized(&f, &[example, &format!("{example}{false_arm}")]),
            true_flow: t.flow,
            false_flow: f.flow,
        };
        if is_hit(signature, baseline, &run) {
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

/// One confirmed pair: the run that hit, how many runs agreed and the
/// signature it was read with.
struct Hit<'a> {
    run: &'a PairRun,
    runs: u32,
    signature: Signature,
}

/// The verdict for a pair that hit and reproduced.
fn confirmed(
    point: &InsertionPoint,
    (true_arm, false_arm): (&str, &str),
    baseline: &Baseline,
    hit: Hit<'_>,
) -> Verdict {
    let to_u32 = |n: usize| u32::try_from(n).unwrap_or(u32::MAX);
    let run = hit.run;
    let baseline_len = baseline.len;
    let compared = match hit.signature {
        Signature::Content => format!(
            "with a body identical to its {baseline_len}-byte baseline (the sent value \
             scrubbed out), and the always-false \"{false_arm}\" with a different body of \
             {false_len} bytes",
            false_len = run.false_len,
        ),
        Signature::Length => format!(
            "with {true_len} bytes, matching its {baseline_len}-byte baseline, and the \
             always-false \"{false_arm}\" with {false_len} bytes",
            true_len = run.true_len,
            false_len = run.false_len,
        ),
    };
    Verdict {
        outcome: Outcome::Vulnerable,
        confidence: Confidence::Firm,
        evidence: Evidence {
            payload: Some(false_arm.to_string()),
            // A content hit's lengths can be identical (the live seed's were),
            // so the evidence names where the bodies parted; a length hit's
            // `Diff` is its whole proof.
            matched: match hit.signature {
                // Scrub first, then cut (the `matching::excerpt_around` order):
                // a credential whose key fell outside the window would
                // otherwise pass the key-framed scrub unseen (security
                // re-review of PR 2a). Two linear scrubs, on a confirmed hit
                // only.
                Signature::Content => Some(Evidence::excerpt(&divergence(
                    &crate::matching::scrub(&baseline.body),
                    &crate::matching::scrub(&run.false_body),
                ))),
                Signature::Length => None,
            },
            probe_flows: run
                .true_flow
                .into_iter()
                .chain(run.false_flow)
                .collect::<Vec<_>>(),
            baseline_flow: baseline.flow,
            diff: Some(Diff {
                baseline_len: to_u32(baseline_len),
                true_len: to_u32(run.true_len),
                false_len: to_u32(run.false_len),
            }),
            ..Evidence::default()
        },
        detail: format!(
            "the {kind:?} point \"{name}\" answered the always-true condition \"{true_arm}\" \
             {compared}; the pair reproduced {runs} time(s), so the value is being \
             evaluated as SQL",
            kind = point.kind,
            name = point_label(point),
            runs = hit.runs,
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

            let Ok(baseline_resp) = host.baseline().await else {
                return no_finding(
                    Outcome::Error,
                    "the point's baseline could not be fetched, so there is nothing to \
                     compare against",
                );
            };
            let baseline_len = body_len(&baseline_resp);

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
                value: example.clone(),
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
            // The signature this point is read with: content when the control
            // reproduced the baseline byte for byte (the sent value scrubbed
            // out of both), length when the page varies between identical
            // requests but stays within the tolerance.
            let baseline = Baseline {
                len: baseline_len,
                body: normalized(&baseline_resp, &[&example]),
                flow: baseline_resp.flow,
            };
            // A value over `MAX_ECHO_FORM` has no echo forms, so a page that
            // echoes it could never compare equal to its baseline under the
            // content rule: that point is read by length, which the scrub
            // does not touch.
            let signature = if echo_forms(&example).is_empty() {
                Signature::Length
            } else if normalized(&control, &[&example]) == baseline.body {
                Signature::Content
            } else {
                Signature::Length
            };

            // Step 3: the pairs, in order, as many as `Speed` allows.
            let pairs = condition_pairs();
            let planned = pairs_allowed(host.profile().speed).min(pairs.len());
            let wanted = confirmations(host.profile().accuracy);
            let mut tally = ProbeTally::new("condition pairs", planned).also_stopped_by(format!(
                "this point had spent its {MAX_BOOLEAN_PROBES} probes"
            ));
            // Pairs the server answered 5xx on both arms. One is a syntax
            // family that breaks this point's query (a quoted pair on a
            // numeric parameter, say); the next family may still show the
            // differential, so the pair is dropped and the run goes on. Two
            // are the point erroring on the technique, and every further pair
            // would be two more 5xx for the host's error ladder (F8c, panel
            // review of PR 2a).
            let mut errored_pairs = 0usize;

            for (true_arm, false_arm) in pairs.iter().take(planned) {
                if !may_send(host, spent, 2) {
                    break;
                }
                spent += 2;
                tally.attempted();
                let first = match SqliBoolean::run_pair(
                    host, &example, true_arm, false_arm, &baseline, signature,
                )
                .await
                {
                    PairOutcome::Hit(run) => run,
                    PairOutcome::Miss => continue,
                    PairOutcome::Failed => {
                        // One refused arm is not a verdict; try the next pair.
                        tally.refused();
                        continue;
                    }
                    PairOutcome::Errored => {
                        errored_pairs += 1;
                        if errored_pairs >= MAX_ERRORED_PAIRS {
                            return no_finding(
                                Outcome::Inconclusive,
                                format!(
                                    "the point answered 5xx to both arms of {errored_pairs} \
                                     condition pairs, the last \"{true_arm}\" / \
                                     \"{false_arm}\": the payloads break the query rather than \
                                     being evaluated as a condition, which is the error-based \
                                     check's territory, not a boolean differential"
                                ),
                            );
                        }
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
                    match SqliBoolean::run_pair(
                        host, &example, true_arm, false_arm, &baseline, signature,
                    )
                    .await
                    {
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
                        // A repeat answered 5xx on both arms: the page that
                        // differed once now errors on the same payloads, so
                        // the candidate is neither confirmed nor noise.
                        PairOutcome::Errored => {
                            return no_finding(
                                Outcome::Inconclusive,
                                format!(
                                    "the pair \"{true_arm}\" / \"{false_arm}\" differed once \
                                     but a repeat was answered 5xx on both arms"
                                ),
                            )
                        }
                    }
                }

                if agreed >= wanted {
                    return confirmed(
                        point,
                        (true_arm, false_arm),
                        &baseline,
                        Hit {
                            run: &first,
                            runs: agreed,
                            signature,
                        },
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

            // A run the job cut short says so first, whatever else it saw.
            if let Some(unfinished) = tally.unfinished() {
                return unfinished;
            }
            if errored_pairs > 0 {
                return no_finding(
                    Outcome::Inconclusive,
                    format!(
                        "{errored_pairs} of {planned} condition pairs {was} answered 5xx on both \
                         arms (error-based territory) and the rest showed no differential \
                         against the {baseline_len}-byte baseline",
                        was = if errored_pairs == 1 { "was" } else { "were" },
                    ),
                );
            }
            tally.conclude(format!(
                "no always-true/always-false pair changed the response {compared} after \
                 {planned} pairs against a {baseline_len}-byte baseline",
                compared = match signature {
                    Signature::Content => "content",
                    Signature::Length => "length",
                },
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use aitm_scan_model::{Accuracy, Speed};

    use super::{
        condition_pairs, confirmations, is_hit, length_differs, normalized, pairs_allowed,
        Baseline, PairRun, Signature, MAX_BOOLEAN_PROBES,
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

    /// A run of a pair under the length signature, from its three lengths.
    fn hit_by_length(baseline: usize, true_len: usize, false_len: usize) -> bool {
        let base = Baseline {
            len: baseline,
            body: String::new(),
            flow: None,
        };
        let run = PairRun {
            true_len,
            false_len,
            true_body: String::new(),
            false_body: String::new(),
            true_flow: None,
            false_flow: None,
        };
        is_hit(Signature::Length, &base, &run)
    }

    /// A run of a pair under the content signature, from the scrubbed bodies.
    fn hit_by_content(baseline: &str, true_body: &str, false_body: &str) -> bool {
        let base = Baseline {
            len: baseline.len(),
            body: baseline.to_string(),
            flow: None,
        };
        let run = PairRun {
            true_len: true_body.len(),
            false_len: false_body.len(),
            true_body: true_body.to_string(),
            false_body: false_body.to_string(),
            true_flow: None,
            false_flow: None,
        };
        is_hit(Signature::Content, &base, &run)
    }

    /// The content signature: the true arm reproduces the baseline body and the
    /// false arm does not — however small the difference, and whatever the
    /// lengths (the live seed answers `items: 1` / `items: 0`, fifteen bytes
    /// either way).
    #[test]
    fn a_content_hit_is_a_reproduced_true_arm_and_a_changed_false_arm() {
        assert!(hit_by_content(
            "<p>items: 1</p>",
            "<p>items: 1</p>",
            "<p>items: 0</p>"
        ));
        assert!(
            !hit_by_content("<p>items: 1</p>", "<p>items: 2</p>", "<p>items: 0</p>"),
            "the true arm changed the page: a reaction to any suffix"
        );
        assert!(
            !hit_by_content("<p>items: 1</p>", "<p>items: 1</p>", "<p>items: 1</p>"),
            "the false arm changed nothing"
        );
    }

    /// Every echo of the sent value — raw, percent-encoded with `%20` or `+`,
    /// HTML-escaped — becomes one marker, so an echoing page compares equal to
    /// itself; the rest of the body is untouched.
    #[test]
    fn normalized_scrubs_every_form_of_the_echo() {
        use aitm_scan_model::ProbeResponse;
        let resp = |body: &str| ProbeResponse {
            status: Some(200),
            headers: Vec::new(),
            body: body.as_bytes().to_vec(),
            elapsed_ms: 1,
            flow: None,
            l4: None,
            ws_frames: None,
        };
        let sent = "1' AND '1'='1";
        assert_eq!(
            normalized(&resp("<p>1' AND '1'='1</p>"), &[sent]),
            "<p>\u{1}</p>",
            "raw"
        );
        assert_eq!(
            normalized(&resp("<p>1%27%20AND%20%271%27%3D%271</p>"), &[sent]),
            "<p>\u{1}</p>",
            "percent-encoded"
        );
        assert_eq!(
            normalized(&resp("<p>1%27+AND+%271%27%3D%271</p>"), &[sent]),
            "<p>\u{1}</p>",
            "form-encoded"
        );
        assert_eq!(
            normalized(&resp("<p>1&#39; AND &#39;1&#39;=&#39;1</p>"), &[sent]),
            "<p>\u{1}</p>",
            "html-escaped"
        );
        assert_eq!(
            normalized(&resp("<p>items: 1</p>"), &[sent]),
            "<p>items: 1</p>"
        );
        assert_eq!(
            normalized(&resp("<p>x</p>"), &[""]),
            "<p>x</p>",
            "an empty value scrubs nothing"
        );
        // The live seed's shape: the point's value `1` also appears in the page's
        // content, and an arm's body is scrubbed of the bare value too, so the
        // baseline and the true arm compare equal.
        assert_eq!(
            normalized(&resp("<p>items: 1</p>"), &["1"]),
            "<p>items: \u{1}</p>"
        );
        assert_eq!(
            normalized(&resp("<p>items: 1</p>"), &["1", "1 AND 1=1"]),
            "<p>items: \u{1}</p>"
        );
        assert_eq!(
            normalized(
                &resp("<p>you sent 1 AND 1=1</p><p>items: 1</p>"),
                &["1", "1 AND 1=1"]
            ),
            "<p>you sent \u{1}</p><p>items: \u{1}</p>"
        );
    }

    /// All three clauses of the signature, each failed in turn. The third one —
    /// the false arm must differ from the true arm too — is the clause that
    /// rules out a page reacting to any appended text.
    #[test]
    fn a_hit_needs_all_three_length_clauses() {
        assert!(hit_by_length(600, 600, 120), "the textbook case");

        assert!(
            !hit_by_length(600, 120, 60),
            "the true arm did not reproduce the baseline"
        );
        assert!(
            !hit_by_length(600, 600, 600),
            "the false arm did not diverge from the baseline"
        );
        assert!(
            !hit_by_length(600, 120, 120),
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
            !hit_by_length(600, 640, 660),
            "the false arm must diverge from the true arm too"
        );
        assert!(
            hit_by_length(600, 640, 681),
            "41 bytes apart is a divergence"
        );

        // The threshold is `matching::length_differs`, so a difference inside
        // the noise floor is not a difference.
        assert!(
            !hit_by_length(600, 600, 570),
            "30 bytes is below the 40-byte floor"
        );
        assert!(hit_by_length(600, 600, 559), "41 bytes is above it");
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
