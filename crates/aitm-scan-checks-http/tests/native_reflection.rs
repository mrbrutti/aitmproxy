//! The two native reflection checks: `xss-reflected` and `open-redirect`
//! (spec D8.2, D6; T3 plan task 5).
//!
//! Both are "send a marker, see whether it comes back somewhere that matters"
//! checks, and both are required by D6 to supply a [`PocHint`], so these tests
//! assert three things for each: the verdict, the evidence, and that the hint
//! the check hands the PoC builder actually *evaluates true* against the very
//! response that proved the finding. The last one is the point — a hint that
//! cannot reproduce the issue silently costs a `FindingRecord`.
//!
//! Nothing here touches a socket. The canary host `aitm-redirect.invalid` is an
//! RFC 2606 reserved name that resolves nowhere, and the tests pin that no
//! stimulus is ever addressed to it.

mod support;

use aitm_poc::{evaluate, Assertion, MatchContext, MatchPart, Severity};
use aitm_scan_model::{
    CheckCost, CheckOrigin, Confidence, InsertionKind, Intensity, LaneKind, Outcome, PointTrait,
    Technique, Verdict,
};

use support::{html, json, point, redirect, response, ScriptedHost, TARGET_URL};

/// The job marker every test gives the host, so the canary tag is `aitmabcd`.
const MARKER: &str = "abcd";
/// The first context probe `xss-reflected` sends for that marker.
const FIRST_XSS_PROBE: &str = "<aitmabcd>x</aitmabcd>";
/// The JavaScript-string probe `xss-reflected` sends third. It carries no
/// angle bracket, so a verbatim echo of it is evidence only inside a script.
const JS_XSS_PROBE: &str = "';aitmabcd//";
/// The absolute canary form `open-redirect` sends first.
const CANARY: &str = "https://aitm-redirect.invalid/";

/// Build a matcher context from the response a scripted host returned, the way
/// the PoC runner builds one from a real reproduction response.
fn ctx_from(status: u16, headers: &[(&str, &str)], body: &str) -> MatchContext {
    let mut ctx = MatchContext::new(status, body);
    for (name, value) in headers {
        ctx = ctx.with_header(*name, *value);
    }
    ctx
}

fn hint_of(verdict: &Verdict) -> &aitm_scan_model::PocHint {
    verdict
        .poc_hint
        .as_ref()
        .expect("a D6 reflection check must supply a PoC hint")
}

// ---------------------------------------------------------------------------
// xss-reflected
// ---------------------------------------------------------------------------

#[tokio::test]
async fn xss_reflected_is_certain_when_the_marker_survives_in_html() {
    let body = format!("<div>you searched for {FIRST_XSS_PROBE}</div>");
    let host = ScriptedHost::new()
        .with_marker(MARKER)
        .on(FIRST_XSS_PROBE, html(200, &body))
        .with_fallback(html(200, "nothing here"));
    let point = point(InsertionKind::Query, "q", TARGET_URL);

    let verdict = aitm_scan_checks_http::xss::check().run(&point, &host).await;

    assert_eq!(verdict.outcome, Outcome::Vulnerable);
    assert_eq!(verdict.confidence, Confidence::Certain);
    assert_eq!(
        verdict.evidence.payload,
        Some(FIRST_XSS_PROBE.to_string()),
        "the evidence names the probe that survived"
    );
    assert!(
        verdict
            .evidence
            .matched
            .as_deref()
            .is_some_and(|m| m.contains(FIRST_XSS_PROBE)),
        "matched excerpt was {:?}",
        verdict.evidence.matched
    );

    let hint = hint_of(&verdict);
    assert_eq!(hint.assertions[0], Assertion::Status(200));
    assert_eq!(
        hint.assertions[1],
        Assertion::Word {
            word: FIRST_XSS_PROBE.to_string(),
            part: MatchPart::Body,
        }
    );

    // It stopped at the probe that hit: one probe, not three.
    assert_eq!(host.sent(), vec![FIRST_XSS_PROBE.to_string()]);
}

#[tokio::test]
async fn xss_reflected_is_clean_when_the_marker_is_entity_encoded() {
    let host = ScriptedHost::new()
        .with_marker(MARKER)
        .with_fallback(html(200, "<div>you searched for &lt;aitmabcd&gt;</div>"));
    let point = point(InsertionKind::Query, "q", TARGET_URL);

    let verdict = aitm_scan_checks_http::xss::check().run(&point, &host).await;

    assert_eq!(verdict.outcome, Outcome::Clean);
    assert_eq!(verdict.poc_hint, None);
    assert_eq!(verdict.evidence.payload, None);
}

#[tokio::test]
async fn xss_reflected_is_clean_on_a_json_content_type() {
    let body = format!("{{\"q\":\"{FIRST_XSS_PROBE}\"}}");
    let host = ScriptedHost::new()
        .with_marker(MARKER)
        .with_fallback(json(200, &body));
    let point = point(InsertionKind::Query, "q", TARGET_URL);

    let verdict = aitm_scan_checks_http::xss::check().run(&point, &host).await;

    assert_eq!(
        verdict.outcome,
        Outcome::Clean,
        "verbatim reflection into JSON is not an HTML execution context"
    );
    assert_eq!(verdict.poc_hint, None);
}

/// The JavaScript-string probe has no angle bracket in it, so its bytes
/// coming back verbatim prove nothing on their own: `';aitmabcd//` in a
/// paragraph is text. It is a finding only when the echo sits inside a
/// `<script>` element, where a closed quote and a comment reach the
/// interpreter (final quality review FQ-1).
#[tokio::test]
async fn xss_reflected_is_clean_when_the_js_probe_is_echoed_outside_a_script() {
    let host = ScriptedHost::new()
        .with_marker(MARKER)
        .with_fallback(html(200, "<p>you searched for ';aitmabcd//</p>"));
    let point = point(InsertionKind::Query, "q", TARGET_URL);

    let verdict = aitm_scan_checks_http::xss::check().run(&point, &host).await;

    assert_eq!(
        verdict.outcome,
        Outcome::Clean,
        "a verbatim JS-string probe outside any script element is not a finding: {}",
        verdict.detail
    );
    assert_eq!(verdict.poc_hint, None);
    assert_eq!(verdict.evidence.payload, None);
    assert_eq!(host.sent().len(), 3, "all three contexts were tried");
}

/// A literal `<script>` the tokenizer never reads as a tag — inside an HTML
/// comment, or in the RCDATA body of a `<title>` — opens no script context, so
/// a text echo after it is still text, even with a real script element later
/// on the page (F7-2).
#[tokio::test]
async fn xss_reflected_is_clean_when_the_only_script_before_the_echo_is_a_decoy() {
    for body in [
        "<title><script></title><p>you searched for ';aitmabcd//</p><script>init()</script>",
        "<!-- <script> --><p>';aitmabcd//</p><script>x()</script>",
    ] {
        let host = ScriptedHost::new()
            .with_marker(MARKER)
            .with_fallback(html(200, body));
        let point = point(InsertionKind::Query, "q", TARGET_URL);

        let verdict = aitm_scan_checks_http::xss::check().run(&point, &host).await;

        assert_eq!(
            verdict.outcome,
            Outcome::Clean,
            "a <script> in a comment or RCDATA body is text, not an element: {body}: {}",
            verdict.detail
        );
        assert_eq!(verdict.poc_hint, None);
        assert_eq!(verdict.evidence.payload, None);
        assert_eq!(host.sent().len(), 3, "all three contexts were tried");
    }
}

#[tokio::test]
async fn xss_reflected_is_certain_when_the_js_probe_is_echoed_inside_a_script() {
    let body = "<html><body><script>var q='';aitmabcd//';</script></body></html>";
    let host = ScriptedHost::new()
        .with_marker(MARKER)
        .on(JS_XSS_PROBE, html(200, body))
        .with_fallback(html(200, "<p>nothing here</p>"));
    let point = point(InsertionKind::Query, "q", TARGET_URL);

    let verdict = aitm_scan_checks_http::xss::check().run(&point, &host).await;

    assert_eq!(verdict.outcome, Outcome::Vulnerable, "{}", verdict.detail);
    assert_eq!(verdict.confidence, Confidence::Certain);
    assert_eq!(verdict.evidence.payload, Some(JS_XSS_PROBE.to_string()));
    assert_eq!(
        verdict.detail,
        "the Query point \"q\" reflected an unencoded canary into an HTML 200 response: the \
         quote, semicolon and comment survived inside a <script> block"
    );
    assert_eq!(
        host.sent(),
        vec![
            FIRST_XSS_PROBE.to_string(),
            "\"><aitmabcd>".to_string(),
            JS_XSS_PROBE.to_string(),
        ],
        "the first two contexts missed and the run stopped on the third"
    );
}

/// The detail names the context whose evidence actually came back, so an
/// operator reading "angle brackets survived" is never reading it about a
/// probe that had none (FQ-1).
#[tokio::test]
async fn xss_reflected_detail_names_the_context_that_hit() {
    let element = format!("<div>{FIRST_XSS_PROBE}</div>");
    let host = ScriptedHost::new()
        .with_marker(MARKER)
        .on(FIRST_XSS_PROBE, html(200, &element));
    let point = point(InsertionKind::Query, "q", TARGET_URL);
    let verdict = aitm_scan_checks_http::xss::check().run(&point, &host).await;
    assert_eq!(
        verdict.detail,
        "the Query point \"q\" reflected an unencoded canary into an HTML 200 response: the \
         tag survived byte for byte"
    );

    let attribute = "<input value=\"\"><aitmabcd>\">";
    let host = ScriptedHost::new()
        .with_marker(MARKER)
        .on("\"><aitmabcd>", html(200, attribute))
        .with_fallback(html(200, "<p>nothing here</p>"));
    let verdict = aitm_scan_checks_http::xss::check().run(&point, &host).await;
    assert_eq!(verdict.outcome, Outcome::Vulnerable, "{}", verdict.detail);
    assert_eq!(
        verdict.detail,
        "the Query point \"q\" reflected an unencoded canary into an HTML 200 response: the \
         quote and the tag survived"
    );
}

#[tokio::test]
async fn xss_reflected_sends_at_most_three_probes() {
    let host = ScriptedHost::new()
        .with_marker(MARKER)
        .with_fallback(html(200, "no reflection at all"));
    let point = point(InsertionKind::Query, "q", TARGET_URL);

    let verdict = aitm_scan_checks_http::xss::check().run(&point, &host).await;

    assert_eq!(verdict.outcome, Outcome::Clean);
    assert_eq!(host.sent().len(), 3);
    assert_eq!(
        host.sent(),
        vec![
            "<aitmabcd>x</aitmabcd>".to_string(),
            "\"><aitmabcd>".to_string(),
            "';aitmabcd//".to_string(),
        ],
        "the three contexts are element, attribute break-out and JS string"
    );
    assert_eq!(
        host.baseline_calls(),
        0,
        "the check declares needs_baseline: false, so it must not take one"
    );
}

#[tokio::test]
async fn xss_reflected_meta_is_the_session_call_s3_entry() {
    let check = aitm_scan_checks_http::xss::check();
    let meta = check.meta();

    assert_eq!(meta.id, "xss-reflected");
    assert_eq!(meta.class, "reflected-xss");
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
            InsertionKind::PathSegment,
            InsertionKind::ParamNameQuery,
        ]
    );
    assert_eq!(meta.intensity, Intensity::Light);
    assert_eq!(meta.cost, CheckCost::Light);
    assert_eq!(meta.technique, Technique::Reflected);
    assert_eq!(meta.severity, Severity::High);
    assert_eq!(meta.confidence_max, Confidence::Certain);
    assert!(!meta.needs_baseline);
    assert_eq!(meta.wants_traits, None);
    assert!(!meta.targets_session);
    assert_eq!(meta.cwe, Some(79));
    assert_eq!(meta.origin, CheckOrigin::Native);
}

/// The hint is only worth having if it reproduces: the assertions must hold
/// against the proving response and the control's expectations must hold
/// against a response where the marker was *not* echoed as markup.
#[tokio::test]
async fn xss_reflected_poc_hint_reproduces_and_its_control_does_not() {
    let body = format!("<div>you searched for {FIRST_XSS_PROBE}</div>");
    let host = ScriptedHost::new()
        .with_marker(MARKER)
        .on(FIRST_XSS_PROBE, html(200, &body));
    let point = point(InsertionKind::Query, "q", TARGET_URL);

    let verdict = aitm_scan_checks_http::xss::check().run(&point, &host).await;
    let hint = hint_of(&verdict);

    let proving = ctx_from(200, &[("Content-Type", "text/html; charset=utf-8")], &body);
    for assertion in &hint.assertions {
        assert!(evaluate(assertion, &proving), "failed: {assertion:?}");
    }

    let control = hint.control.as_ref().expect("the hint carries a control");
    assert_eq!(
        control.payload, "aitmabcd",
        "the control is the bare marker, with no markup at all"
    );
    let control_response = ctx_from(
        200,
        &[("Content-Type", "text/html; charset=utf-8")],
        "<div>you searched for aitmabcd</div>",
    );
    for assertion in &control.expect {
        assert!(
            evaluate(assertion, &control_response),
            "control expectation failed: {assertion:?}"
        );
        assert!(
            !evaluate(assertion, &proving),
            "a control expectation that also holds on the proving response proves nothing: {assertion:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// open-redirect
// ---------------------------------------------------------------------------

#[tokio::test]
async fn open_redirect_is_certain_on_a_302_to_the_canary() {
    let host = ScriptedHost::new()
        .with_marker(MARKER)
        .on(CANARY, redirect(302, CANARY))
        .with_fallback(html(200, "no redirect"));
    let point = point(InsertionKind::Query, "next", TARGET_URL);

    let verdict = aitm_scan_checks_http::redirect::check()
        .run(&point, &host)
        .await;

    assert_eq!(verdict.outcome, Outcome::Vulnerable);
    assert_eq!(verdict.confidence, Confidence::Certain);
    assert_eq!(verdict.evidence.payload, Some(CANARY.to_string()));
    assert_eq!(
        verdict.evidence.matched.as_deref(),
        Some(CANARY),
        "the evidence quotes the Location the target sent"
    );
    assert_eq!(host.sent(), vec![CANARY.to_string()]);
}

#[tokio::test]
async fn open_redirect_is_clean_when_location_stays_on_the_origin() {
    let host = ScriptedHost::new()
        .with_marker(MARKER)
        .with_fallback(redirect(302, "/home"));
    let point = point(InsertionKind::Query, "next", TARGET_URL);

    let verdict = aitm_scan_checks_http::redirect::check()
        .run(&point, &host)
        .await;

    assert_eq!(verdict.outcome, Outcome::Clean);
    assert_eq!(verdict.poc_hint, None);
}

/// A `Location` that merely *mentions* the canary — carried back as a query
/// parameter of a same-origin URL — is not an open redirect. The check reads
/// the authority, not the string.
#[tokio::test]
async fn open_redirect_is_clean_when_the_canary_is_only_inside_the_location() {
    let host = ScriptedHost::new()
        .with_marker(MARKER)
        .with_fallback(redirect(
            302,
            "https://127.0.0.1:8099/login?next=https://aitm-redirect.invalid/",
        ));
    let point = point(InsertionKind::Query, "next", TARGET_URL);

    let verdict = aitm_scan_checks_http::redirect::check()
        .run(&point, &host)
        .await;

    assert_eq!(verdict.outcome, Outcome::Clean);
}

/// A `200 OK` whose body happens to contain the canary is not a redirect
/// either: the rule is a 3xx *and* a `Location` authority.
#[tokio::test]
async fn open_redirect_is_clean_on_a_200_that_echoes_the_canary() {
    let host = ScriptedHost::new()
        .with_marker(MARKER)
        .with_fallback(response(
            200,
            &[("Content-Type", "text/html"), ("Location", CANARY)],
            CANARY,
        ));
    let point = point(InsertionKind::Query, "next", TARGET_URL);

    let verdict = aitm_scan_checks_http::redirect::check()
        .run(&point, &host)
        .await;

    assert_eq!(verdict.outcome, Outcome::Clean);
}

/// The scheme-relative and backslash forms are what actually gets past a naive
/// "starts with http" filter, so each must be tried and each must be judged by
/// the same authority rule.
#[tokio::test]
async fn open_redirect_sends_three_forms_and_catches_the_scheme_relative_one() {
    // Table order matters: the absolute form contains the scheme-relative one
    // as a substring, so the "filtered" rule for it has to come first — which
    // is exactly the server behaviour being modelled.
    let host = ScriptedHost::new()
        .with_marker(MARKER)
        .on(CANARY, html(200, "filtered"))
        .on(
            "//aitm-redirect.invalid/",
            redirect(302, "//aitm-redirect.invalid/"),
        )
        .with_fallback(html(200, "filtered"));
    let point = point(InsertionKind::Query, "next", TARGET_URL);

    let verdict = aitm_scan_checks_http::redirect::check()
        .run(&point, &host)
        .await;

    assert_eq!(verdict.outcome, Outcome::Vulnerable);
    assert_eq!(
        verdict.evidence.payload,
        Some("//aitm-redirect.invalid/".to_string())
    );
    assert_eq!(
        host.sent(),
        vec![
            "https://aitm-redirect.invalid/".to_string(),
            "//aitm-redirect.invalid/".to_string(),
        ],
        "the absolute form is tried first and the run stops on the hit"
    );
}

#[tokio::test]
async fn open_redirect_sends_at_most_three_probes() {
    let host = ScriptedHost::new()
        .with_marker(MARKER)
        .with_fallback(html(200, "no redirect"));
    let point = point(InsertionKind::Query, "next", TARGET_URL);

    let verdict = aitm_scan_checks_http::redirect::check()
        .run(&point, &host)
        .await;

    assert_eq!(verdict.outcome, Outcome::Clean);
    assert_eq!(
        host.sent(),
        vec![
            "https://aitm-redirect.invalid/".to_string(),
            "//aitm-redirect.invalid/".to_string(),
            "/\\aitm-redirect.invalid/".to_string(),
        ]
    );
}

#[tokio::test]
async fn open_redirect_wants_the_url_trait() {
    let check = aitm_scan_checks_http::redirect::check();
    let meta = check.meta();

    assert_eq!(meta.wants_traits, Some(vec![PointTrait::Url]));
    assert_eq!(meta.id, "open-redirect");
    assert_eq!(meta.class, "open-redirect");
    assert_eq!(meta.lanes, vec![LaneKind::Http]);
    assert_eq!(
        meta.kinds,
        vec![
            InsertionKind::Query,
            InsertionKind::BodyParam,
            InsertionKind::JsonValue,
            InsertionKind::Header,
        ]
    );
    assert_eq!(meta.intensity, Intensity::Light);
    assert_eq!(meta.cost, CheckCost::Light);
    assert_eq!(meta.technique, Technique::Reflected);
    assert_eq!(meta.severity, Severity::Medium);
    assert_eq!(meta.confidence_max, Confidence::Certain);
    assert!(!meta.needs_baseline);
    assert_eq!(meta.cwe, Some(601));
    assert_eq!(meta.origin, CheckOrigin::Native);
}

/// The hint's header regex must match a real response, where `Location` is the
/// fourth header rather than the first — the PoC runner joins the headers with
/// newlines and evaluates the pattern against the whole block.
#[tokio::test]
async fn open_redirect_poc_hint_reproduces_against_a_realistic_header_block() {
    let host = ScriptedHost::new()
        .with_marker(MARKER)
        .on(CANARY, redirect(302, CANARY));
    let point = point(InsertionKind::Query, "next", TARGET_URL);

    let verdict = aitm_scan_checks_http::redirect::check()
        .run(&point, &host)
        .await;
    let hint = hint_of(&verdict);

    assert_eq!(hint.assertions[0], Assertion::Status(302));
    assert_eq!(
        hint.assertions[1],
        Assertion::Regex {
            regex: r"(?im)^location:\s*.*aitm-redirect\.invalid".to_string(),
            part: MatchPart::Header,
        }
    );

    let proving = ctx_from(
        302,
        &[
            ("Date", "Sat, 01 Nov 2026 00:00:00 GMT"),
            ("Server", "aitm-testtarget"),
            ("Content-Type", "text/html; charset=utf-8"),
            ("Location", CANARY),
            ("Content-Length", "0"),
        ],
        "",
    );
    for assertion in &hint.assertions {
        assert!(evaluate(assertion, &proving), "failed: {assertion:?}");
    }

    let control = hint.control.as_ref().expect("the hint carries a control");
    let control_response = ctx_from(
        302,
        &[("Date", "Sat, 01 Nov 2026 00:00:00 GMT"), ("Location", "/")],
        "",
    );
    for assertion in &control.expect {
        assert!(
            evaluate(assertion, &control_response),
            "control expectation failed: {assertion:?}"
        );
        assert!(
            !evaluate(assertion, &proving),
            "the control expectation must separate the two responses: {assertion:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// Shared contract
// ---------------------------------------------------------------------------

/// The canary is a name, not a destination. Neither check may address a request
/// to it: the payload is a *value placed at the point*, and the request still
/// goes to the target the point names.
#[tokio::test]
async fn neither_check_sends_a_request_to_the_canary_host() {
    let xss_host = ScriptedHost::new().with_marker(MARKER);
    let redirect_host = ScriptedHost::new().with_marker(MARKER);
    let point = point(InsertionKind::Query, "next", TARGET_URL);

    let _ = aitm_scan_checks_http::xss::check()
        .run(&point, &xss_host)
        .await;
    let _ = aitm_scan_checks_http::redirect::check()
        .run(&point, &redirect_host)
        .await;

    let mut targets = xss_host.sent_targets();
    targets.extend(redirect_host.sent_targets());
    assert_eq!(targets.len(), 6, "three probes from each check");
    for target in &targets {
        assert_eq!(target, TARGET_URL);
        assert!(
            !target.contains("aitm-redirect.invalid"),
            "a request was addressed to the canary: {target}"
        );
    }
}

/// `Check::run`'s contract: stop early when the job was cancelled. Neither
/// check may send anything at all in that case.
#[tokio::test]
async fn neither_check_sends_anything_when_the_job_is_cancelled() {
    let point = point(InsertionKind::Query, "next", TARGET_URL);

    for check in [
        aitm_scan_checks_http::xss::check(),
        aitm_scan_checks_http::redirect::check(),
    ] {
        let host = ScriptedHost::new().with_marker(MARKER).with_cancelled(true);
        let verdict = check.run(&point, &host).await;

        assert_eq!(
            verdict.outcome,
            Outcome::Inconclusive,
            "{} concluded on a cancelled job",
            check.meta().id
        );
        assert!(
            host.sent().is_empty(),
            "{} sent on a cancelled job",
            check.meta().id
        );
        assert_eq!(verdict.poc_hint, None);
    }
}

/// With no budget left a check must send nothing and must not call a target it
/// never probed clean.
#[tokio::test]
async fn neither_check_sends_when_the_budget_is_gone() {
    let point = point(InsertionKind::Query, "next", TARGET_URL);

    for check in [
        aitm_scan_checks_http::xss::check(),
        aitm_scan_checks_http::redirect::check(),
    ] {
        let host = ScriptedHost::new().with_marker(MARKER).with_budget(0);
        let verdict = check.run(&point, &host).await;

        assert_eq!(
            verdict.outcome,
            Outcome::Inconclusive,
            "{} overspent or concluded on nothing",
            check.meta().id
        );
        assert!(
            host.sent().is_empty(),
            "{} sent with no budget",
            check.meta().id
        );
        assert_eq!(verdict.poc_hint, None);
    }
}

/// When every probe is refused the check has learned nothing. Reporting that
/// as `clean` would be a false negative dressed as a result.
#[tokio::test]
async fn neither_check_reports_clean_when_every_probe_fails() {
    let point = point(InsertionKind::Query, "next", TARGET_URL);

    for check in [
        aitm_scan_checks_http::xss::check(),
        aitm_scan_checks_http::redirect::check(),
    ] {
        let host = ScriptedHost::new()
            .with_marker(MARKER)
            .with_probes_failing(true);
        let verdict = check.run(&point, &host).await;

        assert_eq!(
            verdict.outcome,
            Outcome::Error,
            "{} must not call a target it could not reach clean",
            check.meta().id
        );
        assert_eq!(host.sent().len(), 3, "{}", check.meta().id);
        assert_eq!(verdict.poc_hint, None);
    }
}

/// A point's name is observed on the wire too — a parameter can be named
/// after the credential it carries, or be as long as the target likes — so the
/// `detail` that names it is bounded and scrubbed like `matched` (final
/// security review FS-1).
#[tokio::test]
async fn details_scrub_and_bound_a_credential_shaped_point_name() {
    let secret_name = format!("token={}", "A".repeat(2048));

    let body = format!("<div>{FIRST_XSS_PROBE}</div>");
    let host = ScriptedHost::new()
        .with_marker(MARKER)
        .on(FIRST_XSS_PROBE, html(200, &body));
    let secret_point = point(InsertionKind::Query, &secret_name, TARGET_URL);
    let verdict = aitm_scan_checks_http::xss::check()
        .run(&secret_point, &host)
        .await;
    assert_eq!(verdict.outcome, Outcome::Vulnerable, "{}", verdict.detail);
    assert!(
        verdict.detail.contains("\"token=[redacted]\""),
        "{}",
        verdict.detail
    );
    assert!(!verdict.detail.contains("AAAA"), "{}", verdict.detail);
    assert!(verdict.detail.len() <= 300, "{}", verdict.detail.len());

    let host = ScriptedHost::new()
        .with_marker(MARKER)
        .on(CANARY, redirect(302, CANARY));
    let verdict = aitm_scan_checks_http::redirect::check()
        .run(&secret_point, &host)
        .await;
    assert_eq!(verdict.outcome, Outcome::Vulnerable, "{}", verdict.detail);
    assert!(
        verdict.detail.contains("\"token=[redacted]\""),
        "{}",
        verdict.detail
    );
    assert!(!verdict.detail.contains("AAAA"), "{}", verdict.detail);
    assert!(verdict.detail.len() <= 300, "{}", verdict.detail.len());
}

/// Nothing a check writes may echo a value a target or an operator supplied
/// beyond the bounded `Evidence` fields: a `detail` names the point, never the
/// response.
#[tokio::test]
async fn details_name_the_point_and_quote_no_response_text() {
    let secret = "SESSIONID=super-secret-value";
    let body = format!("<div>{secret} {FIRST_XSS_PROBE}</div>");
    let host = ScriptedHost::new()
        .with_marker(MARKER)
        .on(FIRST_XSS_PROBE, html(200, &body));
    let point = point(InsertionKind::Query, "q", TARGET_URL);

    let verdict = aitm_scan_checks_http::xss::check().run(&point, &host).await;

    assert_eq!(verdict.outcome, Outcome::Vulnerable);
    assert!(verdict.detail.contains('q'), "{}", verdict.detail);
    assert!(
        !verdict.detail.contains(secret),
        "the detail quoted the response: {}",
        verdict.detail
    );
}
