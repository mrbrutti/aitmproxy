//! Cross-check hardening: what every native HTTP check must survive
//! (tester pass over T3 plan tasks 2, 5, 7, 8, 9b, 10).
//!
//! The per-technique suites (`native_reflection.rs`, `native_sqli_boolean.rs`,
//! `native_timing.rs`, `native_h2_observe.rs`) pin each check's own algorithm.
//! This file pins the properties that are the *same* for all of them, and that
//! a change to one check could silently break in another:
//!
//! 1. **Nothing a target sends becomes unbounded output.** A megabyte of body
//!    must not become a megabyte of evidence, and a reflection past the
//!    matching cap must not be matched at all (spec D8.2, "Redaction", and
//!    `aitm_scan_model::{MAX_MATCH_BODY, MAX_EXCERPT_BYTES}`).
//! 2. **Nothing secret a *point* carries is quoted back.** A point's `example`
//!    may be a session value; it goes on the wire as the control re-send and
//!    nowhere else — not into `detail`, not into `Evidence`, not into the
//!    `Debug` of a verdict that ends up in a log line.
//! 3. **Every check spends exactly the budget it reports and stops when told.**
//!    No probe is ever attempted that the budget cannot pay for, a deadline in
//!    the past means no stimulus at all, and a cancellation that lands *during*
//!    a run stops it after the probe in flight.
//! 4. **Malformed and empty responses conclude nothing**, rather than being
//!    read as a finding or panicking.
//!
//! No socket is opened: every response comes from `support::ScriptedHost`.

mod support;

use std::sync::Arc;
use std::time::{Duration, Instant};

use aitm_scan_model::{
    Check, Confidence, InsertionKind, InsertionPoint, Outcome, ProbeHost, ProbeResponse, RawProbe,
    Speed, Verdict, MAX_EXCERPT_BYTES, MAX_MATCH_BODY,
};

use support::{html, point, redirect, response, ScriptedHost, TARGET_URL};

/// The job marker every test gives the host, so the XSS canary tag is
/// `aitmabcd` and the first context probe is [`FIRST_XSS_PROBE`].
const MARKER: &str = "abcd";
const FIRST_XSS_PROBE: &str = "<aitmabcd>x</aitmabcd>";
const CANARY: &str = "https://aitm-redirect.invalid/";

/// A credential shaped like one a real target leaks into a page: a `key=value`
/// pair whose key `aitm_core::redact::is_secret_key` recognises.
const SECRET: &str = "SESSIONID=super-secret-value";

/// The five checks that drive `ProbeHost::probe` (the h2 five drive the raw
/// runner instead and are covered by `native_h2_observe.rs`).
fn value_checks() -> Vec<Arc<dyn Check>> {
    vec![
        aitm_scan_checks_http::xss::check(),
        aitm_scan_checks_http::redirect::check(),
        aitm_scan_checks_http::sqli_boolean::check(),
        aitm_scan_checks_http::blind_timing::sqli_time(),
        aitm_scan_checks_http::blind_timing::cmdi_time(),
    ]
}

fn q() -> InsertionPoint {
    point(InsertionKind::Query, "q", TARGET_URL)
}

/// A body of exactly `n` bytes.
fn body(n: usize) -> String {
    "x".repeat(n)
}

/// A `200 text/html` response reporting `ms` on the wire.
fn timed(ms: u32) -> ProbeResponse {
    ProbeResponse {
        elapsed_ms: ms,
        ..html(200, "ok")
    }
}

// ---------------------------------------------------------------------------
// 1. Bounds: a hostile response cannot grow an issue
// ---------------------------------------------------------------------------

/// A reflection inside a megabyte of padding is still a finding, but the
/// evidence it produces is a 256-byte window, not the page.
#[tokio::test]
async fn an_xss_excerpt_stays_bounded_on_a_megabyte_response() {
    let huge = format!("{}{FIRST_XSS_PROBE}{}", body(4096), body(2 * 1024 * 1024));
    let host = ScriptedHost::new()
        .with_marker(MARKER)
        .on(FIRST_XSS_PROBE, html(200, &huge));

    let verdict = aitm_scan_checks_http::xss::check().run(&q(), &host).await;

    assert_eq!(verdict.outcome, Outcome::Vulnerable);
    let matched = verdict
        .evidence
        .matched
        .expect("the hit quotes its context");
    assert!(
        matched.len() <= MAX_EXCERPT_BYTES,
        "the evidence was {} bytes",
        matched.len()
    );
    assert!(matched.contains(FIRST_XSS_PROBE), "{matched}");
    assert!(
        verdict.detail.len() < 1024,
        "the detail grew with the response: {} bytes",
        verdict.detail.len()
    );
}

/// `matching::body_text` caps what a check reads at [`MAX_MATCH_BODY`]. A
/// reflection past that cap is therefore **not** reported — the bound is real,
/// not advisory, and a check that quietly read the whole body would turn this
/// into a `Vulnerable`.
#[tokio::test]
async fn a_reflection_past_the_match_cap_is_not_matched() {
    let past_the_cap = format!("{}{FIRST_XSS_PROBE}", body(MAX_MATCH_BODY));
    let host = ScriptedHost::new()
        .with_marker(MARKER)
        .with_fallback(html(200, &past_the_cap));

    let verdict = aitm_scan_checks_http::xss::check().run(&q(), &host).await;

    assert_eq!(verdict.outcome, Outcome::Clean);
    assert_eq!(verdict.evidence.matched, None);
}

/// The boolean differential compares *bounded* lengths. A two-megabyte false
/// arm is read as exactly [`MAX_MATCH_BODY`] bytes, so the `Diff` an operator
/// reads is the matched length and never the target's own number.
#[tokio::test]
async fn the_boolean_differential_compares_capped_body_lengths() {
    let host = ScriptedHost::new()
        .with_baseline(html(200, &body(600)))
        .on("seed", html(200, &body(600)))
        .on("1=1", html(200, &body(600)))
        .on("1=2", html(200, &body(2 * 1024 * 1024)))
        .with_fallback(html(200, &body(600)));

    let verdict = aitm_scan_checks_http::sqli_boolean::check()
        .run(&q(), &host)
        .await;

    assert_eq!(verdict.outcome, Outcome::Vulnerable);
    let diff = verdict
        .evidence
        .diff
        .expect("a boolean hit carries its diff");
    assert_eq!(diff.baseline_len, 600);
    assert_eq!(diff.true_len, 600);
    assert_eq!(
        usize::try_from(diff.false_len).unwrap(),
        MAX_MATCH_BODY,
        "the false arm's length must be the capped one"
    );
}

// ---------------------------------------------------------------------------
// 2. Malformed and empty responses
// ---------------------------------------------------------------------------

/// A response with no status, no headers and no body is what a half-broken
/// upstream produces. No check may read one as a finding, and none may panic.
#[tokio::test]
async fn an_empty_response_concludes_nothing_for_any_check() {
    let empty = ProbeResponse {
        status: None,
        headers: Vec::new(),
        body: Vec::new(),
        elapsed_ms: 0,
        flow: None,
        ws_frames: None,
        l4: None,
    };
    for check in value_checks() {
        let host = ScriptedHost::new()
            .with_marker(MARKER)
            .with_baseline(empty.clone())
            .with_fallback(empty.clone())
            .with_budget(64);

        let verdict = check.run(&q(), &host).await;

        assert_ne!(
            verdict.outcome,
            Outcome::Vulnerable,
            "{} reported on an empty response: {}",
            check.meta().id,
            verdict.detail
        );
        assert!(verdict.poc_hint.is_none(), "{}", check.meta().id);
    }
}

/// A verbatim reflection into a body whose status line could not be read is not
/// reportable: the PoC hint asserts a status, so a hit with no status would
/// produce a hint that can never reproduce.
#[tokio::test]
async fn a_reflection_without_a_status_is_not_reported() {
    let reflected = ProbeResponse {
        status: None,
        ..html(200, &format!("<div>{FIRST_XSS_PROBE}</div>"))
    };
    let host = ScriptedHost::new()
        .with_marker(MARKER)
        .with_fallback(reflected);

    let verdict = aitm_scan_checks_http::xss::check().run(&q(), &host).await;

    assert_eq!(verdict.outcome, Outcome::Clean);
    assert!(verdict.poc_hint.is_none());
}

/// A body that is not valid UTF-8 must still be matched (lossily) rather than
/// dropped: a reflection in a mislabelled page is still a reflection.
#[tokio::test]
async fn a_reflection_in_an_invalid_utf8_body_is_still_matched() {
    let mut mangled = html(200, "");
    mangled.body = [&[0xff, 0xfe, 0xff][..], FIRST_XSS_PROBE.as_bytes()].concat();
    let host = ScriptedHost::new()
        .with_marker(MARKER)
        .with_fallback(mangled);

    let verdict = aitm_scan_checks_http::xss::check().run(&q(), &host).await;

    assert_eq!(verdict.outcome, Outcome::Vulnerable);
    assert!(verdict
        .evidence
        .matched
        .as_deref()
        .is_some_and(|m| m.contains(FIRST_XSS_PROBE)));
}

/// A `Location` that is empty, blank or a bare scheme has no authority, so it
/// is not a redirect to the canary however the check is asked.
#[tokio::test]
async fn a_malformed_location_is_never_read_as_the_canary() {
    for location in ["", "   ", "https://", "//", "/\\", "?next=1", "\u{0}"] {
        let host = ScriptedHost::new()
            .with_marker(MARKER)
            .with_fallback(redirect(302, location));

        let verdict = aitm_scan_checks_http::redirect::check()
            .run(&q(), &host)
            .await;

        assert_eq!(
            verdict.outcome,
            Outcome::Clean,
            "location {location:?} was read as a redirect to the canary"
        );
    }
}

// ---------------------------------------------------------------------------
// 3. Secrets a point carries
// ---------------------------------------------------------------------------

/// A point's `example` is the value observed on the wire, so it can be a
/// session token. The control re-send has to put it back on the wire — that is
/// the technique — but it must reach nothing else: not the detail, not the
/// evidence, and not the `Debug` rendering a log line or a bus frame carries.
#[tokio::test]
async fn a_session_value_in_the_point_example_reaches_the_wire_and_nothing_else() {
    for check in value_checks() {
        let id = check.meta().id.clone();
        let mut p = q();
        p.example = Some(SECRET.to_string());
        let host = ScriptedHost::new()
            .with_marker(MARKER)
            .with_baseline(html(200, &body(600)))
            .on(SECRET, html(200, &body(600)))
            .on("1=1", html(200, &body(600)))
            .on("1=2", html(200, &body(120)))
            .on("SLEEP(1)", timed(1040))
            .on("SLEEP(3)", timed(3060))
            .on("; sleep 1", timed(1040))
            .on("; sleep 3", timed(3060))
            .with_fallback(html(200, &body(600)))
            .with_budget(64);

        let verdict = check.run(&p, &host).await;

        assert!(
            !verdict.detail.contains(SECRET),
            "{id}: the detail quoted the point's example: {}",
            verdict.detail
        );
        assert_ne!(verdict.evidence.payload.as_deref(), Some(SECRET), "{id}");
        assert!(
            !format!("{verdict:?}").contains(SECRET),
            "{id}: the verdict's Debug carries the point's example",
        );
    }
}

/// The same for a secret the *target* puts in the response: a check's `detail`
/// is a sentence about the point, never a quotation of the page.
#[tokio::test]
async fn no_detail_quotes_a_secret_the_target_returned() {
    let leaky = format!("<div>{SECRET}</div><p>{FIRST_XSS_PROBE}</p>");
    let cases: Vec<(Arc<dyn Check>, ScriptedHost)> = vec![
        (
            aitm_scan_checks_http::xss::check(),
            ScriptedHost::new()
                .with_marker(MARKER)
                .on(FIRST_XSS_PROBE, html(200, &leaky)),
        ),
        (
            aitm_scan_checks_http::redirect::check(),
            ScriptedHost::new()
                .with_marker(MARKER)
                .on(CANARY, redirect(302, &format!("{CANARY}?{SECRET}"))),
        ),
        (
            aitm_scan_checks_http::sqli_boolean::check(),
            ScriptedHost::new()
                .with_baseline(html(200, &body(600)))
                .on("seed", html(200, &body(600)))
                .on("1=1", html(200, &body(600)))
                .on("1=2", html(200, &format!("{SECRET}{}", body(60))))
                .with_fallback(html(200, &body(600))),
        ),
    ];

    for (check, host) in cases {
        let verdict = check.run(&q(), &host).await;

        assert_eq!(
            verdict.outcome,
            Outcome::Vulnerable,
            "{}: the case must actually fire",
            check.meta().id
        );
        assert!(
            !verdict.detail.contains("super-secret-value"),
            "{}: detail quoted the response: {}",
            check.meta().id,
            verdict.detail
        );
    }
}

/// Spec D8.1: "every `example` and every excerpt in `Evidence.matched` passes
/// `aitm_core::redact`". A credential sitting next to the canary in the body,
/// or in the `Location` the target answered with, must not reach the issue
/// store, the push stream or the UIs. The assertion is the scrub's own fixed
/// point: an excerpt that still carries credential material is not what
/// `aitm_core::redact::scrub_text` would have produced.
#[tokio::test]
async fn evidence_excerpts_are_scrubbed_with_the_core_vocabulary() {
    let leaky = format!("<div>{SECRET}</div><p>{FIRST_XSS_PROBE}</p>");
    let xss_host = ScriptedHost::new()
        .with_marker(MARKER)
        .on(FIRST_XSS_PROBE, html(200, &leaky));
    let redirect_host = ScriptedHost::new()
        .with_marker(MARKER)
        .on(CANARY, redirect(302, &format!("{CANARY}?{SECRET}")));

    for (check, host) in [
        (aitm_scan_checks_http::xss::check(), xss_host),
        (aitm_scan_checks_http::redirect::check(), redirect_host),
    ] {
        let verdict = check.run(&q(), &host).await;
        let matched = verdict
            .evidence
            .matched
            .expect("the hit quotes what it matched");

        assert_eq!(
            matched,
            aitm_core::redact::scrub_text(&matched),
            "{}: the excerpt still carries unscrubbed credential material",
            check.meta().id
        );
    }
}

/// The same rule stated as the literal an operator would recognise: the session
/// value the *target* returned, and the one the *point* carried as its
/// `example`, appear in neither `Evidence.matched` nor `Evidence.payload` of
/// any of the five value checks. `scrub_text`'s fixed point above says the
/// excerpt is shaped like scrubbed text; this says the secret itself is gone.
#[tokio::test]
async fn no_evidence_field_carries_a_session_value_from_the_body_or_the_point() {
    const SESSION_VALUE: &str = "super-secret-value";

    let leaky_body = format!("<div>{SECRET}</div><p>{FIRST_XSS_PROBE}</p>");
    let mut secret_point = q();
    secret_point.example = Some(SECRET.to_string());

    for check in value_checks() {
        let id = check.meta().id.clone();
        let host = ScriptedHost::new()
            .with_marker(MARKER)
            .with_baseline(html(200, &leaky_body))
            .on(FIRST_XSS_PROBE, html(200, &leaky_body))
            .on(CANARY, redirect(302, &format!("{CANARY}?{SECRET}")))
            .with_fallback(html(200, &leaky_body));

        let verdict = check.run(&secret_point, &host).await;

        for (field, text) in [
            ("matched", verdict.evidence.matched.clone()),
            ("payload", verdict.evidence.payload.clone()),
        ] {
            let Some(text) = text else { continue };
            assert!(
                !text.contains(SESSION_VALUE),
                "{id}: evidence.{field} carried the session value: {text}"
            );
        }
        assert!(
            !verdict.detail.contains(SESSION_VALUE),
            "{id}: the detail carried the session value: {}",
            verdict.detail
        );
    }
}

// ---------------------------------------------------------------------------
// 4. Budget, deadline, cancellation
// ---------------------------------------------------------------------------

/// A check may never place a payload the job cannot pay for, and running out
/// must never be reported as a target `Error` — that would feed the per-host
/// error ladder (spec D5) with the scanner's own accounting. The budget is
/// swept from nothing to more than a thorough run needs, and the host's ledger
/// must balance at each step: every unit missing from `budget_left` is a
/// stimulus the host recorded.
///
/// Every check consults the gate before its baseline, so all five are held to
/// the stricter rule: baseline included, nothing is attempted past the budget.
#[tokio::test]
async fn no_check_asks_for_a_probe_the_budget_cannot_pay_for() {
    for check in value_checks() {
        let id = check.meta().id.clone();
        for budget in 0u32..=6 {
            let host = ScriptedHost::new()
                .with_marker(MARKER)
                .with_speed(Speed::Thorough)
                .with_baseline(html(200, &body(600)))
                .with_fallback(html(200, &body(600)))
                .with_budget(budget);

            let verdict = check.run(&q(), &host).await;

            let payloads = host.sent().len();
            assert!(
                payloads <= usize::try_from(budget).unwrap(),
                "{id}: placed {payloads} payloads on a budget of {budget}"
            );
            let served = usize::try_from(budget - host.budget_left()).unwrap();
            assert!(
                served <= host.sent().len() + host.baseline_calls(),
                "{id}: the host spent {served} units on {} recorded stimuli",
                host.sent().len() + host.baseline_calls()
            );
            let asked = host.sent().len() + host.baseline_calls();
            assert!(
                asked <= usize::try_from(budget).unwrap(),
                "{id}: asked for {asked} stimuli on a budget of {budget}"
            );
            assert_ne!(
                verdict.outcome,
                Outcome::Error,
                "{id}: running out of budget is not a target error ({budget}): {}",
                verdict.detail
            );
        }
    }
}

/// A deadline already in the past means the check sends nothing at all. It is
/// the same contract as cancellation, and the engine relies on it to stop a job
/// within its `time_s` rather than one check later (spec D5).
#[tokio::test]
async fn a_deadline_already_passed_sends_no_payload() {
    for check in value_checks() {
        let host = ScriptedHost::new()
            .with_marker(MARKER)
            .with_deadline(Instant::now() - Duration::from_secs(1));

        let verdict = check.run(&q(), &host).await;

        assert!(
            host.sent().is_empty(),
            "{} sent {:?} after its deadline",
            check.meta().id,
            host.sent()
        );
        assert_eq!(
            verdict.outcome,
            Outcome::Inconclusive,
            "{}: a check that sent nothing concluded nothing",
            check.meta().id
        );
        assert_eq!(verdict.confidence, Confidence::Tentative);
    }
}

/// Every check consults the cancel/budget/deadline gate *before* it asks for a
/// baseline, the timing pair included: a cancelled job, an expired job and a
/// job with no budget left are not asked for a single request.
/// `sqli_boolean.rs` says why — "Nothing at all, not even a baseline, once the
/// job has stopped."
#[tokio::test]
async fn a_stopped_timing_check_does_not_even_take_a_baseline() {
    for check in [
        aitm_scan_checks_http::blind_timing::sqli_time(),
        aitm_scan_checks_http::blind_timing::cmdi_time(),
    ] {
        for host in [
            ScriptedHost::new().with_cancelled(true),
            ScriptedHost::new().with_deadline(Instant::now() - Duration::from_secs(1)),
            ScriptedHost::new().with_budget(0),
        ] {
            let verdict = check.run(&q(), &host).await;

            assert_eq!(verdict.outcome, Outcome::Inconclusive);
            assert_eq!(
                host.baseline_calls(),
                0,
                "{}: a stopped job must not be asked for a baseline",
                check.meta().id
            );
        }
    }
}

/// "Every probe was refused" is only a target `Error` when every probe the
/// plan asked for was actually attempted. Here the first probe is refused and
/// the job is cancelled immediately after it: one refused probe out of three
/// says nothing about the target, and calling it `Error` would feed the
/// per-host error ladder (spec D5) with the scanner's own stop.
#[tokio::test]
async fn a_single_refused_probe_before_a_cancellation_is_inconclusive_not_an_error() {
    for check in value_checks() {
        let id = check.meta().id.clone();
        if id == "sqli-boolean" {
            // Its first stimulus is the control re-send, whose refusal is its
            // own verdict (`native_sqli_boolean.rs` pins it).
            continue;
        }
        let host = ScriptedHost::new()
            .with_marker(MARKER)
            .with_probe_refused_at(1)
            .with_cancel_after(1);

        let verdict = check.run(&q(), &host).await;

        assert_eq!(host.sent().len(), 1, "{id}");
        assert_eq!(
            verdict.outcome,
            Outcome::Inconclusive,
            "{id}: {}",
            verdict.detail
        );
    }
}

/// Cancellation that lands *during* a run: the check finishes the probe in
/// flight and stops, rather than running its schedule out. The host reports the
/// job cancelled from the moment the first stimulus has been sent.
#[tokio::test]
async fn a_cancellation_mid_run_stops_after_the_probe_in_flight() {
    // (check, stimuli before the cancellation, stimuli expected in total)
    let cases: Vec<(Arc<dyn Check>, usize, usize)> = vec![
        // Three context probes; cancelled after the first.
        (aitm_scan_checks_http::xss::check(), 1, 1),
        // Three canary forms; cancelled after the first.
        (aitm_scan_checks_http::redirect::check(), 1, 1),
        // The control re-send, then the pairs: cancelled after the control.
        (aitm_scan_checks_http::sqli_boolean::check(), 1, 1),
        // Four delays per family; cancelled after the second.
        (aitm_scan_checks_http::blind_timing::sqli_time(), 2, 2),
    ];

    for (check, cancel_after, expected) in cases {
        let id = check.meta().id.clone();
        let host = ScriptedHost::new()
            .with_marker(MARKER)
            .with_speed(Speed::Thorough)
            .with_baseline(html(200, &body(600)))
            .with_fallback(html(200, &body(600)))
            .with_budget(64)
            .with_cancel_after(cancel_after);

        let verdict = check.run(&q(), &host).await;

        assert_eq!(
            host.sent().len(),
            expected,
            "{id}: sent {:?} after the cancellation",
            host.sent()
        );
        assert_eq!(
            verdict.outcome,
            Outcome::Inconclusive,
            "{id}: a half-run schedule proves nothing: {}",
            verdict.detail
        );
    }
}

/// A pair is atomic: half of a boolean differential proves nothing, so a
/// cancellation between the two arms must not leave a one-armed "hit", and a
/// budget with room for one arm must not start the pair at all.
#[tokio::test]
async fn half_a_boolean_pair_is_never_a_finding() {
    let host = ScriptedHost::new()
        .with_baseline(html(200, &body(600)))
        .on("seed", html(200, &body(600)))
        .on("1=1", html(200, &body(600)))
        .on("1=2", html(200, &body(120)))
        .with_fallback(html(200, &body(600)))
        // The baseline and the control, then room for one arm only.
        .with_budget(3);

    let verdict = aitm_scan_checks_http::sqli_boolean::check()
        .run(&q(), &host)
        .await;

    assert_eq!(verdict.outcome, Outcome::Inconclusive);
    assert_eq!(
        host.sent(),
        vec!["seed".to_string()],
        "no arm of a pair may be sent without room for the other"
    );
    assert_eq!(verdict.evidence.diff, None);
}

// ---------------------------------------------------------------------------
// 5. Every declared kind, and the decision boundaries
// ---------------------------------------------------------------------------

/// A check is scheduled against every `InsertionKind` its meta declares, so it
/// must reach the same verdict for each one and name the kind it was aimed at.
#[tokio::test]
async fn xss_reflected_fires_on_every_kind_it_declares() {
    let check = aitm_scan_checks_http::xss::check();
    let kinds = check.meta().kinds.clone();
    assert_eq!(kinds.len(), 8, "the declared kinds");

    for kind in kinds {
        let host = ScriptedHost::new().with_marker(MARKER).on(
            FIRST_XSS_PROBE,
            html(200, &format!("<p>{FIRST_XSS_PROBE}</p>")),
        );
        let p = point(kind, "field", TARGET_URL);

        let verdict = check.run(&p, &host).await;

        assert_eq!(verdict.outcome, Outcome::Vulnerable, "{kind:?}");
        assert_eq!(verdict.confidence, Confidence::Certain, "{kind:?}");
        assert!(
            verdict.detail.contains(&format!("{kind:?}")),
            "{kind:?}: the detail does not name the kind: {}",
            verdict.detail
        );
        assert!(verdict.poc_hint.is_some(), "{kind:?}");
    }
}

#[tokio::test]
async fn open_redirect_fires_on_every_kind_it_declares() {
    let check = aitm_scan_checks_http::redirect::check();
    let kinds = check.meta().kinds.clone();
    assert_eq!(kinds.len(), 4, "the declared kinds");

    for kind in kinds {
        let host = ScriptedHost::new()
            .with_marker(MARKER)
            .on(CANARY, redirect(302, CANARY));
        let p = point(kind, "next", TARGET_URL);

        let verdict = check.run(&p, &host).await;

        assert_eq!(verdict.outcome, Outcome::Vulnerable, "{kind:?}");
        assert!(
            verdict.detail.contains(&format!("{kind:?}")),
            "{kind:?}: {}",
            verdict.detail
        );
    }
}

/// The boolean threshold end to end, at the byte. `max(baseline / 20, 40)` with
/// a **strict** comparison: against a 600-byte baseline a 40-byte difference is
/// noise and a 41-byte one is the finding. One byte of drift here moves every
/// boolean verdict the scanner will ever make.
#[tokio::test]
async fn the_boolean_length_threshold_is_strict_at_the_byte_end_to_end() {
    for (false_len, expected) in [(560usize, Outcome::Clean), (559, Outcome::Vulnerable)] {
        let host = ScriptedHost::new()
            .with_baseline(html(200, &body(600)))
            .on("seed", html(200, &body(600)))
            .on("1=1", html(200, &body(600)))
            .on("1=2", html(200, &body(false_len)))
            .with_fallback(html(200, &body(600)))
            .with_budget(64);

        let verdict = aitm_scan_checks_http::sqli_boolean::check()
            .run(&q(), &host)
            .await;

        assert_eq!(
            verdict.outcome, expected,
            "a false arm of {false_len} bytes against a 600-byte baseline \
             (threshold is exactly 40 bytes, strictly exceeded)"
        );
    }
}

/// The slope half of ZAP's acceptance rule, end to end. A target that answers
/// 1290 ms per second requested is inside the 30 % band and is reported; one
/// that answers 1310 ms per second is outside it and is not, however perfect
/// its correlation. Both series here correlate at `r == 1.0`, so only the slope
/// can decide — which is the point of having two halves to the rule.
#[tokio::test]
async fn the_timing_slope_band_decides_at_thirty_percent_end_to_end() {
    for (long_ms, expected, slope) in [
        (3620u32, Outcome::Vulnerable, 1290.0_f32),
        (3660, Outcome::Clean, 1310.0),
    ] {
        let host = ScriptedHost::new()
            .with_baseline(timed(40))
            .on("SLEEP(1)", timed(1040))
            .on("SLEEP(3)", timed(long_ms))
            // The second family is flat, so only the first can decide.
            .with_fallback(timed(45))
            .with_budget(64);

        let verdict = aitm_scan_checks_http::blind_timing::sqli_time()
            .run(&q(), &host)
            .await;

        assert_eq!(
            verdict.outcome, expected,
            "a {long_ms} ms answer to a 3 s request is a slope of {slope} ms/s"
        );
        if expected == Outcome::Vulnerable {
            let t = verdict
                .evidence
                .timing
                .as_ref()
                .expect("a timing hit carries its fit");
            assert!((t.slope - slope).abs() < 1.0, "slope was {}", t.slope);
            assert!(t.r >= 0.85, "r was {}", t.r);
        }
    }
}

/// A target that honours only a third of the requested delay — a shared cache,
/// a proxy timeout, a coincidence — correlates perfectly and is still not a
/// finding.
#[tokio::test]
async fn a_partially_honoured_delay_is_not_a_finding() {
    let host = ScriptedHost::new()
        .with_baseline(timed(40))
        .on("SLEEP(1)", timed(380))
        .on("SLEEP(3)", timed(1080))
        .with_fallback(timed(45))
        .with_budget(64);

    let verdict = aitm_scan_checks_http::blind_timing::sqli_time()
        .run(&q(), &host)
        .await;

    assert_eq!(verdict.outcome, Outcome::Clean);
    assert!(verdict.evidence.timing.is_none());
}

/// A 200 that carries the canary in a header other than `Location` is a target
/// echoing input, not redirecting: the rule is a 3xx **and** a `Location`
/// authority, and neither half may be dropped.
#[tokio::test]
async fn a_canary_echoed_in_another_header_is_not_a_redirect() {
    let host = ScriptedHost::new()
        .with_marker(MARKER)
        .with_fallback(response(
            302,
            &[
                ("Location", "/home"),
                ("X-Echo", CANARY),
                ("Content-Type", "text/html"),
            ],
            "",
        ));

    let verdict: Verdict = aitm_scan_checks_http::redirect::check()
        .run(&q(), &host)
        .await;

    assert_eq!(verdict.outcome, Outcome::Clean);
}

/// The third clause of the boolean signature, end to end: the false arm must
/// diverge from the **true arm** as well as from the baseline. Here the true
/// arm reproduces the baseline (40 bytes apart, exactly the noise floor) and
/// the false arm is 60 bytes off the baseline but only 20 bytes off the true
/// arm — a page drifting, not a database answering a condition. Dropping that
/// clause turns every slightly unstable page into a `Critical` SQL-injection
/// issue, which is why it is worth its own end-to-end case.
#[tokio::test]
async fn a_false_arm_that_tracks_the_true_arm_is_not_a_hit() {
    let host = ScriptedHost::new()
        .with_baseline(html(200, &body(600)))
        .on("seed", html(200, &body(600)))
        .on("1=1", html(200, &body(640)))
        .on("1=2", html(200, &body(660)))
        .with_fallback(html(200, &body(600)))
        .with_budget(64);

    let verdict = aitm_scan_checks_http::sqli_boolean::check()
        .run(&q(), &host)
        .await;

    assert_eq!(verdict.outcome, Outcome::Clean, "{}", verdict.detail);
    assert_eq!(verdict.evidence.diff, None);
}

// ---------------------------------------------------------------------------
// 6. Tester pass over fix round F3: redaction at the match, and the gate at
//    the byte
// ---------------------------------------------------------------------------

/// The scrub must never cost a finding. When the reflected canary sits
/// *inside* credential-shaped text — the value of a `sid=` pair, the tail of
/// an `Authorization:` line — the scrub swallows the canary out of the
/// excerpt, and that is correct for the evidence; but the verdict is decided
/// on the unscrubbed body, so the reflection is still reported, still
/// `certain`, and still carries a reproducible hint.
#[tokio::test]
async fn a_reflection_inside_credential_shaped_text_is_still_reported_and_its_excerpt_is_clean() {
    for (label, body_text) in [
        (
            "inside a sid= value",
            format!("<p>sid={FIRST_XSS_PROBE} other=1</p>"),
        ),
        (
            "after a bearer token on the same line",
            format!("Authorization: Bearer abc.def.ghi {FIRST_XSS_PROBE}"),
        ),
        (
            "as a JSON-quoted secret in an HTML page",
            format!("<div>{{\"password\":\"{FIRST_XSS_PROBE}\"}}</div>"),
        ),
    ] {
        let host = ScriptedHost::new()
            .with_marker(MARKER)
            .on(FIRST_XSS_PROBE, html(200, &body_text));

        let verdict = aitm_scan_checks_http::xss::check().run(&q(), &host).await;

        assert_eq!(
            verdict.outcome,
            Outcome::Vulnerable,
            "{label}: {}",
            verdict.detail
        );
        assert_eq!(verdict.confidence, Confidence::Certain, "{label}");
        assert!(verdict.poc_hint.is_some(), "{label}");
        let matched = verdict
            .evidence
            .matched
            .expect("the hit quotes its context");
        assert_eq!(
            matched,
            aitm_core::redact::scrub_text(&matched),
            "{label}: the excerpt carries unscrubbed material: {matched}"
        );
        assert!(!matched.contains("abc.def.ghi"), "{label}: {matched}");
        assert!(matched.len() <= MAX_EXCERPT_BYTES, "{label}");
    }
}

/// The scrub as the literal an operator sees: a `Location` to the canary that
/// carries a token in its query is reported, and the evidence quotes the
/// `Location` with the token replaced by `[redacted]` and nothing else
/// changed — the host, the path and the other parameter survive.
#[tokio::test]
async fn a_canary_location_with_a_token_is_quoted_with_the_token_redacted() {
    let location = format!("{CANARY}cb?token=abc123&page=2");
    let host = ScriptedHost::new()
        .with_marker(MARKER)
        .on(CANARY, redirect(302, &location));

    let verdict = aitm_scan_checks_http::redirect::check()
        .run(&q(), &host)
        .await;

    assert_eq!(verdict.outcome, Outcome::Vulnerable);
    assert_eq!(verdict.confidence, Confidence::Certain);
    assert_eq!(
        verdict.evidence.matched.as_deref(),
        Some("https://aitm-redirect.invalid/cb?token=[redacted]&page=2")
    );
    assert!(verdict.poc_hint.is_some());
}

/// An oversized `Location` — a hostile target can send one of any length —
/// is still judged (the authority is the canary) and is quoted bounded.
#[tokio::test]
async fn an_oversized_location_is_judged_and_quoted_bounded() {
    let location = format!("{CANARY}{}", "p".repeat(512 * 1024));
    let host = ScriptedHost::new()
        .with_marker(MARKER)
        .on(CANARY, redirect(302, &location));

    let verdict = aitm_scan_checks_http::redirect::check()
        .run(&q(), &host)
        .await;

    assert_eq!(verdict.outcome, Outcome::Vulnerable);
    let matched = verdict
        .evidence
        .matched
        .expect("the hit quotes the Location");
    assert!(
        matched.len() <= MAX_EXCERPT_BYTES,
        "len was {}",
        matched.len()
    );
    assert!(matched.starts_with(CANARY), "{matched}");
    assert!(verdict.detail.len() < 1024, "{}", verdict.detail.len());
}

/// A response whose body is a megabyte of `key=value` credential pairs around
/// the canary: the scrub is linear and the excerpt is bounded, so the check
/// returns promptly with a 256-byte, fully scrubbed excerpt.
#[tokio::test]
async fn a_megabyte_of_credential_pairs_around_the_match_is_scrubbed_and_bounded() {
    let pairs = "sid=s3cr3t&token=t0k3n&".repeat(20_000);
    let huge = format!("{pairs}{FIRST_XSS_PROBE}{pairs}");
    assert!(
        huge.len() < MAX_MATCH_BODY,
        "the canary must be inside the match cap"
    );
    let host = ScriptedHost::new()
        .with_marker(MARKER)
        .on(FIRST_XSS_PROBE, html(200, &huge));

    let started = Instant::now();
    let verdict = aitm_scan_checks_http::xss::check().run(&q(), &host).await;
    let wall = started.elapsed();

    assert_eq!(verdict.outcome, Outcome::Vulnerable);
    let matched = verdict.evidence.matched.expect("quoted");
    assert!(
        matched.len() <= MAX_EXCERPT_BYTES,
        "len was {}",
        matched.len()
    );
    assert!(
        !matched.contains("s3cr3t") && !matched.contains("t0k3n"),
        "{matched}"
    );
    assert!(
        wall < Duration::from_secs(10),
        "scrubbing a megabyte took {wall:?}"
    );
}

/// The budget gate is exact, not merely safe: a check with budget for exactly
/// its plan runs the whole plan and concludes, and one unit short stops it one
/// stimulus early with `Inconclusive`. `no_check_asks_for_a_probe_the_budget_
/// cannot_pay_for` proves `<=`; this proves `==`, so an over-cautious gate
/// that left budget unspent is caught too.
#[tokio::test]
async fn the_budget_gate_spends_exactly_the_plan_when_the_budget_allows_it() {
    // xss-reflected: three probes, no baseline.
    let exact = ScriptedHost::new()
        .with_marker(MARKER)
        .with_fallback(html(200, "nothing"))
        .with_budget(3);
    let v = aitm_scan_checks_http::xss::check().run(&q(), &exact).await;
    assert_eq!(v.outcome, Outcome::Clean, "{}", v.detail);
    assert_eq!(exact.sent().len(), 3);
    assert_eq!(exact.budget_left(), 0);

    let short = ScriptedHost::new()
        .with_marker(MARKER)
        .with_fallback(html(200, "nothing"))
        .with_budget(2);
    let v = aitm_scan_checks_http::xss::check().run(&q(), &short).await;
    assert_eq!(v.outcome, Outcome::Inconclusive, "{}", v.detail);
    assert_eq!(short.sent().len(), 2);
    assert!(
        v.detail
            .starts_with("stopped after 2 of 3 reflection probes"),
        "{}",
        v.detail
    );

    // open-redirect: the same three-probe shape.
    let exact = ScriptedHost::new()
        .with_marker(MARKER)
        .with_fallback(html(200, "nothing"))
        .with_budget(3);
    let v = aitm_scan_checks_http::redirect::check()
        .run(&q(), &exact)
        .await;
    assert_eq!(v.outcome, Outcome::Clean, "{}", v.detail);
    assert_eq!(exact.sent().len(), 3);

    // sqli-time: a baseline plus two families of four.
    let exact = ScriptedHost::new()
        .with_baseline(timed(40))
        .with_fallback(timed(45))
        .with_budget(9);
    let v = aitm_scan_checks_http::blind_timing::sqli_time()
        .run(&q(), &exact)
        .await;
    assert_eq!(v.outcome, Outcome::Clean, "{}", v.detail);
    assert_eq!(exact.sent().len(), 8);
    assert_eq!(exact.budget_left(), 0);

    // sqli-boolean at normal speed on a stable page: baseline, control, four pairs.
    let exact = ScriptedHost::new()
        .with_baseline(html(200, &body(600)))
        .with_fallback(html(200, &body(600)))
        .with_budget(10);
    let v = aitm_scan_checks_http::sqli_boolean::check()
        .run(&q(), &exact)
        .await;
    assert_eq!(v.outcome, Outcome::Clean, "{}", v.detail);
    assert_eq!(exact.sent().len(), 9);
    assert_eq!(exact.budget_left(), 0);
}

/// A deadline that passes *during* a run stops it after the probe in flight,
/// exactly as a cancellation does: the host reports the deadline as passed
/// from the moment `n` stimuli have been sent, and the check may send nothing
/// after that — no second context probe, no second canary form, no next
/// delay, and never the next boolean pair.
#[tokio::test]
async fn a_deadline_that_passes_mid_run_stops_after_the_probe_in_flight() {
    let cases: Vec<(Arc<dyn Check>, usize)> = vec![
        (aitm_scan_checks_http::xss::check(), 1),
        (aitm_scan_checks_http::redirect::check(), 2),
        // The control, then the deadline passes before the first pair.
        (aitm_scan_checks_http::sqli_boolean::check(), 1),
        (aitm_scan_checks_http::blind_timing::sqli_time(), 3),
        (aitm_scan_checks_http::blind_timing::cmdi_time(), 5),
    ];

    for (check, after) in cases {
        let id = check.meta().id.clone();
        let host = ScriptedHost::new()
            .with_marker(MARKER)
            .with_baseline(html(200, &body(600)))
            .with_fallback(html(200, &body(600)))
            .with_budget(64)
            .with_deadline_after(after);

        let verdict = check.run(&q(), &host).await;

        assert_eq!(
            host.sent().len(),
            after,
            "{id}: sent {:?} after the deadline passed",
            host.sent()
        );
        assert_eq!(
            verdict.outcome,
            Outcome::Inconclusive,
            "{id}: a run cut by its deadline proves nothing: {}",
            verdict.detail
        );
        assert_eq!(verdict.confidence, Confidence::Tentative, "{id}");
        assert!(verdict.poc_hint.is_none(), "{id}");
    }
}

/// The scripted host's refusal script is one script for both kinds of
/// stimulus (quality re-review Q2-5): the n-th probe is refused whether a
/// check sends it shaped (`probe`) or raw (`probe_raw`), and "fail after n"
/// counts both too. A harness that refused only shaped probes would let a
/// raw-probing check pass a mid-series refusal test it should fail.
#[tokio::test]
async fn the_scripted_host_refuses_a_raw_probe_by_the_same_script() {
    fn raw(path: &str) -> RawProbe {
        RawProbe {
            method: "GET".to_string(),
            url: format!("http://127.0.0.1:8099{path}"),
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    let host = ScriptedHost::new().with_probe_refused_at(2);
    assert!(
        host.probe_raw(raw("/a")).await.is_ok(),
        "the first is answered"
    );
    assert!(
        host.probe_raw(raw("/b")).await.is_err(),
        "the second raw probe is the refused one"
    );
    assert!(
        host.probe_raw(raw("/c")).await.is_ok(),
        "the third is answered"
    );
    assert_eq!(host.sent_targets().len(), 3, "every attempt is recorded");

    // Shaped and raw stimuli share one count: the refused "second" may be a
    // raw probe after a shaped one.
    let host = ScriptedHost::new().with_probe_refused_at(2);
    let shaped = aitm_scan_model::Payload {
        value: "x".to_string(),
        mode: aitm_scan_model::PayloadMode::Replace,
        bytes: None,
    };
    assert!(host.probe(&shaped).await.is_ok());
    assert!(host.probe_raw(raw("/b")).await.is_err());

    let host = ScriptedHost::new().with_probes_failing_after(1);
    assert!(host.probe_raw(raw("/a")).await.is_ok());
    assert!(
        host.probe_raw(raw("/b")).await.is_err(),
        "raw probes past the failure point are refused"
    );
}
