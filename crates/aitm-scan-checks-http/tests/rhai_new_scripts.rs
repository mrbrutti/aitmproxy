//! T3 plan Task 11 — the two checks the v2 catalogue adds in Rhai
//! (`nosqli-json`, `header-reflection`), the two it retires, and the bridge
//! contract they rely on, all exercised through the **real** engine: the
//! shipped file, the real `RhaiLoader`, the real `reg.add_check`, the real
//! `probe.*`, answered by the model's `RecordingHost` (decision D-2b-1).
//!
//! These are inner-loop tests over canned replies. The acceptance evidence for
//! both checks is Task 17: a real scan over the real bus against the project's
//! own test target.

mod rhai_harness;

use aitm_core::redact::scrub_text_wide;
use aitm_scan_model::check::VerdictLocation;
use aitm_scan_model::vocab::{Confidence, InsertionKind, Outcome, PointTrait};

use rhai_harness::{active_path, point, run, Loaded, Replies};

/// The marker `RecordingHost` hands every check, and therefore the marker both
/// scripts build their payload from here.
const MARKER: &str = "aitm7f3a";

/// What `check-header-reflection.rhai` places in the header: markup-significant
/// characters plus the marker, so only an **unencoded** echo matches (T4's live
/// finding; switchover item 8).
const REFLECTION_PAYLOAD: &str = "\"><aitm7f3a";

/// A meta map with every required key, so one test can drop exactly one.
fn meta_without(dropped: &str) -> String {
    [
        ("id", "\"fixture-check\""),
        ("name", "\"Fixture\""),
        ("class", "\"demo\""),
        ("lanes", "[\"http\"]"),
        ("kinds", "[\"query\"]"),
        ("intensity", "\"light\""),
        ("cost", "\"light\""),
        ("technique", "\"reflected\""),
        ("severity", "\"low\""),
        ("confidence_max", "\"certain\""),
        ("description", "\"d\""),
    ]
    .iter()
    .filter(|(key, _)| *key != dropped)
    .map(|(key, value)| format!("{key}: {value}"))
    .collect::<Vec<_>>()
    .join(", ")
}

/// A fixture script whose `load(reg)` registers one check with `body`.
fn fixture(meta: &str, body: &str) -> String {
    format!("fn load(reg) {{\n    reg.add_check(#{{ {meta} }}, |point| {body});\n}}\n")
}

/// A body of exactly `len` bytes, so a length differential is a literal.
fn body_of(len: usize) -> String {
    "x".repeat(len)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_two_new_scripts_declare_one_check_each_with_valid_meta() {
    let nosqli = Loaded::load("check-nosqli-json.rhai").expect("the shipped script loads");
    let check = nosqli.single().expect("exactly one check");
    let meta = check.meta();
    assert_eq!(meta.id, "nosqli-json");
    assert_eq!(meta.class, "nosqli");
    assert_eq!(
        meta.kinds,
        vec![InsertionKind::JsonValue, InsertionKind::EntireBody]
    );
    assert_eq!(meta.cwe, Some(943));
    assert_eq!(
        nosqli.command_names(),
        Vec::<String>::new(),
        "an active check script registers no command any more"
    );

    let reflection =
        Loaded::load("check-header-reflection.rhai").expect("the shipped script loads");
    let check = reflection.single().expect("exactly one check");
    let meta = check.meta();
    assert_eq!(meta.id, "header-reflection");
    assert_eq!(
        meta.class, "reflected-xss",
        "the class token the engine pins, single-sourced with the native check"
    );
    assert_eq!(
        meta.kinds,
        vec![InsertionKind::Header, InsertionKind::Cookie]
    );
    assert_eq!(meta.cwe, Some(79));
    assert_eq!(reflection.command_names(), Vec::<String>::new());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_meta_missing_kinds_fails_naming_kinds() {
    let err = Loaded::load_source(
        "no-kinds",
        &fixture(&meta_without("kinds"), "\"nothing found\""),
    )
    .expect_err("a check the catalogue cannot classify is a load error");

    let message = err.to_string();
    assert!(
        message.contains("kinds"),
        "the error must name the missing key, got: {message}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_new_scripts_find_their_vulnerable_shape_and_clear_the_patched_one() {
    // --- nosqli-json: a query operator in a JSON value widens the result set.
    let check = Loaded::load("check-nosqli-json.rhai")
        .expect("loads")
        .single()
        .expect("exactly one check");
    let json_point = point(
        InsertionKind::JsonValue,
        "username",
        "http://127.0.0.1:8080/api/login",
        Some("alice"),
        &[],
    );

    let widened = Replies::plain(200, &body_of(120))
        .when("$ne", 200, &body_of(900))
        .build();
    let verdict = run(&check, &json_point, &widened).await;
    assert_eq!(verdict.outcome, Outcome::Vulnerable);
    assert_eq!(verdict.confidence, Confidence::Firm);
    assert_eq!(
        verdict.evidence.payload.as_deref(),
        Some("{\"$ne\": null}"),
        "the operator document the store accepted"
    );
    assert_eq!(
        verdict.evidence.matched.as_deref(),
        Some("result set 120 -> 900 bytes")
    );
    assert_eq!(
        widened.payloads(),
        vec!["{\"$ne\": null}".to_string()],
        "the first operator concluded it; the second is never sent"
    );

    // Patched: the operator document is treated as the string it was declared
    // to be, so the result set does not move.
    let patched = Replies::plain(200, &body_of(120)).build();
    let verdict = run(&check, &json_point, &patched).await;
    assert_eq!(verdict.outcome, Outcome::Clean);
    assert_eq!(
        verdict.detail,
        "A query operator in this JSON value did not change the result set."
    );
    assert_eq!(
        patched.payloads(),
        vec!["{\"$ne\": null}".to_string(), "{\"$gt\": \"\"}".to_string()],
        "both operators are tried before the point is cleared"
    );

    // --- header-reflection: only the UNENCODED echo in HTML is a finding.
    let check = Loaded::load("check-header-reflection.rhai")
        .expect("loads")
        .single()
        .expect("exactly one check");
    let header_point = point(
        InsertionKind::Header,
        "X-Forwarded-Host",
        "http://127.0.0.1:8080/",
        Some("shop.test"),
        &[],
    );

    let html_unencoded = Replies::plain(200, "no echo")
        .when_headers(
            MARKER,
            200,
            &[("content-type", "text/html; charset=utf-8")],
            &format!("<p>Host: {REFLECTION_PAYLOAD}</p>"),
        )
        .build();
    let verdict = run(&check, &header_point, &html_unencoded).await;
    assert_eq!(verdict.outcome, Outcome::Vulnerable);
    assert_eq!(verdict.confidence, Confidence::Certain);
    assert_eq!(
        verdict.evidence.payload.as_deref(),
        Some(REFLECTION_PAYLOAD)
    );
    assert_eq!(
        html_unencoded.payloads(),
        vec![REFLECTION_PAYLOAD.to_string()],
        "the payload carries markup-significant characters, not the bare marker"
    );
    let matchers =
        rhai_harness::matchers_parse(&verdict).expect("a vulnerable verdict hints a PoC");
    assert_eq!(
        matchers,
        vec![aitm_poc::Assertion::All(vec![aitm_poc::Assertion::Word {
            word: REFLECTION_PAYLOAD.to_string(),
            part: aitm_poc::MatchPart::Body,
        }])]
    );
    let (payload, expect) = rhai_harness::control_parse(&verdict)
        .expect("a hint is present")
        .expect("the hint names a control arm");
    assert_eq!(
        payload, "shop.test",
        "the control re-sends the point's own value"
    );
    assert_eq!(
        expect,
        vec![aitm_poc::Assertion::All(vec![aitm_poc::Assertion::Not(
            Box::new(aitm_poc::Assertion::Word {
                word: REFLECTION_PAYLOAD.to_string(),
                part: aitm_poc::MatchPart::Body,
            })
        )])]
    );

    // Patched: the page HTML-escapes what it prints, so the markup is inert.
    let html_escaped = Replies::plain(200, "no echo")
        .when_headers(
            MARKER,
            200,
            &[("content-type", "text/html; charset=utf-8")],
            &format!("<p>Host: &quot;&gt;&lt;{MARKER}</p>"),
        )
        .build();
    let verdict = run(&check, &header_point, &html_escaped).await;
    assert_eq!(verdict.outcome, Outcome::Clean);
    assert_eq!(
        verdict.detail,
        "The marker came back HTML-encoded, which is what a page that escapes its output does."
    );

    // A JSON API that echoes the header verbatim is not a browser injection.
    let json_echo = Replies::plain(200, "no echo")
        .when_headers(
            MARKER,
            200,
            &[("content-type", "application/json")],
            &format!("{{\"host\":\"{REFLECTION_PAYLOAD}\"}}"),
        )
        .build();
    let verdict = run(&check, &header_point, &json_echo).await;
    assert_eq!(verdict.outcome, Outcome::Clean);
    assert_eq!(
        verdict.detail,
        "The marker came back, but not in an HTML body: a non-HTML response is not a browser injection."
    );

    // The payload back verbatim in a RESPONSE HEADER: firm, and the detail
    // names the header it came back in.
    let header_echo = Replies::plain(200, "no echo")
        .when_headers(
            MARKER,
            200,
            &[
                ("content-type", "text/plain"),
                ("x-forwarded-host", REFLECTION_PAYLOAD),
            ],
            "no echo in the body",
        )
        .build();
    let verdict = run(&check, &header_point, &header_echo).await;
    assert_eq!(verdict.outcome, Outcome::Vulnerable);
    assert_eq!(verdict.confidence, Confidence::Firm);
    assert!(
        verdict.detail.contains("x-forwarded-host"),
        "the detail must name the response header, got: {}",
        verdict.detail
    );
}

// --- nosqli-json, the `entire_body` shape: a whole JSON body, one operator
// document per string field, each signal controlled by a string at the same
// field (plan Task 11, spec amendment 65).

/// The body the document branch is shown: a point's example as the HTTP lane
/// hands it over, already scrubbed, so `password` reads `[redacted]`.
const LOGIN_BODY: &str = r#"{"username":"alice","password":"[redacted]"}"#;

/// A document with its spaces removed. Rhai's `to_json` is compact on the
/// engine the scanner ships, but the spacing is not a contract across builds,
/// while the key order is (a Rhai map is a `BTreeMap`, so `to_json` emits its
/// keys sorted). No value in these documents holds a space.
fn compact(text: &str) -> String {
    text.replace(' ', "")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nosqli_json_places_an_operator_document_at_each_string_field_of_the_body() {
    let check = Loaded::load("check-nosqli-json.rhai")
        .expect("loads")
        .single()
        .expect("exactly one check");
    let body_point = point(
        InsertionKind::EntireBody,
        "body",
        "http://127.0.0.1:8080/api/login",
        Some(LOGIN_BODY),
        &[PointTrait::Json, PointTrait::Structured],
    );

    // The login route compares the document it was handed: `{"$ne": null}` at
    // `password` logs in, the same operator at `username` does not, and the
    // string control — the marker as a plain string — is refused like any
    // wrong password. `[redacted]` answers every document that still carries
    // the password *string*, which is every document whose operator sits at
    // `username`.
    let widened = Replies::plain(401, r#"{"ok":false}"#)
        .when("[redacted]", 401, r#"{"ok":false}"#)
        .when("aitm", 401, r#"{"ok":false}"#)
        .when("$ne", 200, r#"{"ok":true,"marker":"m"}"#)
        .build();
    let verdict = run(&check, &body_point, &widened).await;

    assert_eq!(verdict.outcome, Outcome::Vulnerable);
    assert_eq!(verdict.confidence, Confidence::Firm);
    assert_eq!(
        verdict.location,
        Some(VerdictLocation {
            path: None,
            name: Some("password".to_string()),
        }),
        "the issue is located at the field the operator sat in"
    );
    assert_eq!(
        verdict.evidence.matched.as_deref(),
        Some(
            "status 401 -> 200 with an operator at \"password\"; \
             the string control answered 401"
        )
    );
    // The evidence payload is the operator document the probe sent, through
    // the bridge's mandatory `Verdict::scrubbed()` (amendment 85): the
    // scrubber masks the value of the `password` pair, so the stored document
    // is present, carries the mask, and never carries the raw operator at the
    // secret field. The exact scrubbed spelling is the scrubber's business (a
    // JSON-aware mask is a scheduled follow-up), so it is not pinned here; the
    // document **on the wire** is asserted below, where nothing scrubbed it.
    let stored = verdict
        .evidence
        .payload
        .as_deref()
        .map(compact)
        .expect("the vulnerable verdict stores the operator document");
    assert!(stored.contains("[redacted]"), "stored: {stored}");
    assert!(
        !stored.contains(r#""password":{"$ne""#),
        "the raw operator at the secret field must not survive the scrub: {stored}"
    );
    assert!(stored.contains(r#""username":"alice""#), "stored: {stored}");

    assert_eq!(
        widened
            .payloads()
            .iter()
            .map(|sent| compact(sent))
            .collect::<Vec<String>>(),
        vec![
            compact(r#"{"password":{"$ne":null},"username":"alice"}"#),
            compact(&format!(
                r#"{{"password":"aitm{MARKER}","username":"alice"}}"#
            )),
        ],
        "the first string field answered the operator, so the control went to \
         the same field and no second operator and no second field were spent"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nosqli_json_is_clean_when_the_operator_is_refused() {
    let check = Loaded::load("check-nosqli-json.rhai")
        .expect("loads")
        .single()
        .expect("exactly one check");
    let body_point = point(
        InsertionKind::EntireBody,
        "body",
        "http://127.0.0.1:8080/api/login",
        Some(LOGIN_BODY),
        &[PointTrait::Json, PointTrait::Structured],
    );

    // A route that validates its body against a schema: an object where a
    // string was declared is a 400, and the string control is the ordinary
    // 401.
    let refused = Replies::plain(401, r#"{"ok":false}"#)
        .when("aitm", 401, r#"{"ok":false}"#)
        .when("$ne", 400, r#"{"error":"password must be a string"}"#)
        .when("$gt", 400, r#"{"error":"password must be a string"}"#)
        .build();
    let verdict = run(&check, &body_point, &refused).await;

    assert_eq!(verdict.outcome, Outcome::Clean);
    assert_eq!(
        verdict.detail,
        "A query-operator document at any string field of this JSON body did not change the answer."
    );
    assert_eq!(
        refused
            .payloads()
            .iter()
            .map(|sent| compact(sent))
            .collect::<Vec<String>>(),
        vec![
            compact(r#"{"password":{"$ne":null},"username":"alice"}"#),
            compact(r#"{"password":{"$gt":""},"username":"alice"}"#),
            compact(r#"{"password":"[redacted]","username":{"$ne":null}}"#),
            compact(r#"{"password":"[redacted]","username":{"$gt":""}}"#),
        ],
        "both operators are tried at both string fields, and no control is \
         spent where no operator moved the answer"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nosqli_json_is_inconclusive_when_the_example_is_not_the_document() {
    let check = Loaded::load("check-nosqli-json.rhai")
        .expect("loads")
        .single()
        .expect("exactly one check");
    // The example is cut: the lane shows a point's value up to a cap, and a
    // document-level operator needs the document, not a prefix of it.
    let cut_point = point(
        InsertionKind::EntireBody,
        "body",
        "http://127.0.0.1:8080/api/login",
        Some(r#"{"username":"alice","password":"[redac"#),
        &[PointTrait::Json, PointTrait::Structured],
    );

    let host = Replies::plain(401, r#"{"ok":false}"#).build();
    let verdict = run(&check, &cut_point, &host).await;

    assert_eq!(verdict.outcome, Outcome::Inconclusive);
    assert_eq!(verdict.confidence, Confidence::Tentative);
    assert_eq!(
        verdict.detail,
        "the JSON document is longer than the point's example; document-level operators need the whole body"
    );
    assert_eq!(verdict.evidence.payload, None);
    assert_eq!(verdict.evidence.matched, None);
    assert_eq!(
        host.payloads(),
        Vec::<String>::new(),
        "no probe is spent on a document the check cannot rebuild"
    );

    // A cut that lands on the closing brace of a nested object still ends
    // with `}`, so the whole document — not just its last character — has to
    // be read before it is parsed.
    let cut_at_a_brace = point(
        InsertionKind::EntireBody,
        "body",
        "http://127.0.0.1:8080/api/login",
        Some(r#"{"username":"alice","profile":{"city":"lisbon"}"#),
        &[PointTrait::Json, PointTrait::Structured],
    );
    let host = Replies::plain(401, r#"{"ok":false}"#).build();
    let verdict = run(&check, &cut_at_a_brace, &host).await;

    assert_eq!(verdict.outcome, Outcome::Inconclusive);
    assert_eq!(
        verdict.detail,
        "the JSON document is longer than the point's example; document-level operators need the whole body"
    );
    assert_eq!(host.payloads(), Vec::<String>::new());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nosqli_json_visits_at_most_eight_string_fields_of_a_wide_body() {
    let check = Loaded::load("check-nosqli-json.rhai")
        .expect("loads")
        .single()
        .expect("exactly one check");
    // Ten string fields, in the key order a Rhai map keeps them in (sorted).
    let wide = format!(
        "{{{}}}",
        (1..=10)
            .map(|n| format!(r#""f{n:02}":"v""#))
            .collect::<Vec<String>>()
            .join(",")
    );
    let wide_point = point(
        InsertionKind::EntireBody,
        "body",
        "http://127.0.0.1:8080/api/search",
        Some(&wide),
        &[PointTrait::Json, PointTrait::Structured],
    );

    // Nothing moves, so every operator document is spent and none is
    // controlled.
    let host = Replies::plain(401, r#"{"ok":false}"#).build();
    let verdict = run(&check, &wide_point, &host).await;

    assert_eq!(verdict.outcome, Outcome::Clean);
    assert_eq!(
        host.payloads().len(),
        16,
        "two operators at each of the first eight string fields, and no ninth \
         field: an unbounded pass would have spent the job's whole probe budget"
    );
    assert!(
        host.payloads()
            .iter()
            .all(|sent| !sent.contains(r#""f09":{"#) && !sent.contains(r#""f10":{"#)),
        "no operator document sits at the ninth or tenth field, got {:?}",
        host.payloads()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nosqli_json_meta_declares_both_kinds_and_wants_json() {
    let check = Loaded::load("check-nosqli-json.rhai")
        .expect("loads")
        .single()
        .expect("exactly one check");
    let meta = check.meta();

    assert_eq!(
        meta.kinds,
        vec![InsertionKind::JsonValue, InsertionKind::EntireBody],
        "the value shape and the document shape (spec amendment 65)"
    );
    assert_eq!(
        meta.wants_traits,
        Some(vec![PointTrait::Json]),
        "no probe is spent on a body that is not JSON"
    );
    assert!(
        meta.needs_baseline,
        "both shapes read the point's own baseline"
    );
}

/// The document branch's **other** oracle (call C12): no status flip, but the
/// operator widened the result set materially while a plain string at the same
/// field left it where the baseline was. The status-flip arm above and this one
/// are the only two ways the check reports a finding.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nosqli_json_reports_a_widened_result_set_when_the_string_control_does_not() {
    let check = Loaded::load("check-nosqli-json.rhai")
        .expect("loads")
        .single()
        .expect("exactly one check");
    let body_point = point(
        InsertionKind::EntireBody,
        "body",
        "http://127.0.0.1:8080/api/search",
        Some(LOGIN_BODY),
        &[PointTrait::Json, PointTrait::Structured],
    );

    // A route that answers 200 to everything: one record for the baseline and
    // for the string control, the whole table for the operator document.
    let one_record = "b".repeat(100);
    let whole_table = "b".repeat(400);
    let widened = Replies::plain(200, &one_record)
        .when("$ne", 200, &whole_table)
        .when("aitm", 200, &one_record)
        .build();
    let verdict = run(&check, &body_point, &widened).await;

    assert_eq!(verdict.outcome, Outcome::Vulnerable);
    assert_eq!(verdict.confidence, Confidence::Firm);
    assert_eq!(
        verdict.location,
        Some(VerdictLocation {
            path: None,
            name: Some("password".to_string()),
        })
    );
    assert_eq!(
        verdict.evidence.matched.as_deref(),
        Some(
            "result set 100 -> 400 bytes with an operator at \"password\"; \
             the string control answered 100 bytes"
        ),
        "the size rule names both the operator's answer and the control's"
    );
    assert_eq!(
        widened
            .payloads()
            .iter()
            .map(|sent| compact(sent))
            .collect::<Vec<String>>(),
        vec![
            compact(r#"{"password":{"$ne":null},"username":"alice"}"#),
            compact(&format!(
                r#"{{"password":"aitm{MARKER}","username":"alice"}}"#
            )),
        ],
        "one operator and its control; the second operator and the second \
         field are not spent once the first field is a finding"
    );
}

/// The control is what makes the size rule a finding rather than noise: a route
/// whose answer grows for *any* value it has not seen grows for the string
/// control too, and then nothing is reported. Every operator is still tried, at
/// every string field, each with its own control.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nosqli_json_reports_nothing_when_the_string_control_moved_too() {
    let check = Loaded::load("check-nosqli-json.rhai")
        .expect("loads")
        .single()
        .expect("exactly one check");
    let body_point = point(
        InsertionKind::EntireBody,
        "body",
        "http://127.0.0.1:8080/api/search",
        Some(LOGIN_BODY),
        &[PointTrait::Json, PointTrait::Structured],
    );

    let one_record = "b".repeat(100);
    let whole_table = "b".repeat(400);
    let noisy = Replies::plain(200, &one_record)
        .when("$ne", 200, &whole_table)
        .when("$gt", 200, &whole_table)
        .when("aitm", 200, &whole_table)
        .build();
    let verdict = run(&check, &body_point, &noisy).await;

    assert_eq!(
        verdict.outcome,
        Outcome::Clean,
        "a route that answers anything unfamiliar the same way is not a finding"
    );
    assert_eq!(
        verdict.detail,
        "A query-operator document at any string field of this JSON body did not change the answer."
    );
    assert_eq!(
        noisy
            .payloads()
            .iter()
            .map(|sent| compact(sent))
            .collect::<Vec<String>>(),
        vec![
            compact(r#"{"password":{"$ne":null},"username":"alice"}"#),
            compact(&format!(
                r#"{{"password":"aitm{MARKER}","username":"alice"}}"#
            )),
            compact(r#"{"password":{"$gt":""},"username":"alice"}"#),
            compact(&format!(
                r#"{{"password":"aitm{MARKER}","username":"alice"}}"#
            )),
            compact(r#"{"password":"[redacted]","username":{"$ne":null}}"#),
            compact(&format!(
                r#"{{"password":"[redacted]","username":"aitm{MARKER}"}}"#
            )),
            compact(r#"{"password":"[redacted]","username":{"$gt":""}}"#),
            compact(&format!(
                r#"{{"password":"[redacted]","username":"aitm{MARKER}"}}"#
            )),
        ],
        "operator then control at each field in turn, and the field is put \
         back before the next one — no document ever carries two operators"
    );
}

/// The budget arm: a body wide enough that the operators and their controls
/// outrun the probes the job has left stops where the budget stops and says so.
/// A `clean` there would be a claim about fields that were never tried.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nosqli_json_is_inconclusive_when_the_budget_runs_out_mid_document() {
    let check = Loaded::load("check-nosqli-json.rhai")
        .expect("loads")
        .single()
        .expect("exactly one check");
    // Five string fields; every operator moves the answer and so costs a
    // control as well — four probes a field, against the sixteen the host
    // lends, so the fifth field is never reached.
    let wide_point = point(
        InsertionKind::EntireBody,
        "body",
        "http://127.0.0.1:8080/api/search",
        Some(r#"{"f1":"v","f2":"v","f3":"v","f4":"v","f5":"v"}"#),
        &[PointTrait::Json, PointTrait::Structured],
    );

    let one_record = "b".repeat(100);
    let whole_table = "b".repeat(400);
    let noisy = Replies::plain(200, &one_record)
        .when("$", 200, &whole_table)
        .when("aitm", 200, &whole_table)
        .build();
    let verdict = run(&check, &wide_point, &noisy).await;

    assert_eq!(verdict.outcome, Outcome::Inconclusive);
    assert_eq!(verdict.confidence, Confidence::Tentative);
    assert_eq!(
        verdict.detail,
        "the probe budget ran out before every string field of this JSON body had been tried"
    );
    assert_eq!(
        noisy.payloads().len(),
        16,
        "it stops at the budget, it does not keep sending: {:?}",
        noisy.payloads()
    );
    assert_eq!(
        verdict.evidence.payload.as_deref().map(compact),
        Some(compact(
            r#"{"f1":"v","f2":"v","f3":"v","f4":{"$gt":""},"f5":"v"}"#
        )),
        "the evidence is the last document it managed to send"
    );
}

/// The completeness guard reads the document, not its last character: a string
/// value holding braces, brackets and escaped quotes is a *whole* document and
/// the check proceeds to probe it (and, in doing so, keeps those escapes intact
/// in the document it rebuilds).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nosqli_json_takes_a_document_whose_strings_hold_braces_and_escaped_quotes() {
    let check = Loaded::load("check-nosqli-json.rhai")
        .expect("loads")
        .single()
        .expect("exactly one check");
    let tricky = point(
        InsertionKind::EntireBody,
        "body",
        "http://127.0.0.1:8080/api/search",
        Some(r#"{"q":"he said \"hi\" } ] {","user":"alice"}"#),
        &[PointTrait::Json, PointTrait::Structured],
    );

    let host = Replies::plain(401, r#"{"ok":false}"#).build();
    let verdict = run(&check, &tricky, &host).await;

    assert_eq!(
        verdict.outcome,
        Outcome::Clean,
        "the document is whole, so it is probed and decided, not refused"
    );
    assert_eq!(
        host.payloads().len(),
        4,
        "two operators at each of the two string fields: {:?}",
        host.payloads()
    );
    // Keys come back in a Rhai map's sorted order, so the operator visits `q`
    // first; the tricky value is then the *other* field, and it must survive
    // the rebuild byte for byte, escapes and all.
    assert!(
        host.payloads()[0].contains(r#""$ne""#) && host.payloads()[0].contains(r#""user":"alice""#),
        "the first operator document sits at `q`: {:?}",
        host.payloads()[0]
    );
    assert!(
        host.payloads()[2].contains(r#""user":{"$ne":null}"#)
            && host.payloads()[2].contains(r#"he said \"hi\" } ] {"#),
        "the operator document keeps the other field's escapes: {:?}",
        host.payloads()[2]
    );
}

/// Everything the document branch refuses rather than guesses at, in one place:
/// a top-level array, a bare scalar, a document with one brace too many, and a
/// point with no example at all. Each is the `inconclusive` of
/// [`nosqli_json_is_inconclusive_when_the_example_is_not_the_document`], and
/// none of them spends a probe.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nosqli_json_refuses_a_body_that_is_not_one_whole_json_object() {
    let check = Loaded::load("check-nosqli-json.rhai")
        .expect("loads")
        .single()
        .expect("exactly one check");
    let examples: Vec<Option<&str>> = vec![
        Some(r#"[{"username":"alice"}]"#),
        Some(r#""just a string""#),
        Some("42"),
        Some(r#"{"username":"alice"}}"#),
        Some(""),
        None,
    ];

    for example in examples {
        let body_point = point(
            InsertionKind::EntireBody,
            "body",
            "http://127.0.0.1:8080/api/login",
            example,
            &[PointTrait::Json, PointTrait::Structured],
        );
        let host = Replies::plain(401, r#"{"ok":false}"#).build();
        let verdict = run(&check, &body_point, &host).await;

        assert_eq!(
            verdict.outcome,
            Outcome::Inconclusive,
            "{example:?} is not a whole JSON object: {verdict:?}"
        );
        assert_eq!(
            verdict.detail,
            "the JSON document is longer than the point's example; document-level operators need the whole body",
            "{example:?}"
        );
        assert_eq!(
            host.payloads(),
            Vec::<String>::new(),
            "{example:?} spent a probe"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_plain_string_return_is_read_as_inconclusive() {
    let check = Loaded::load_source(
        "plain-string",
        &fixture(&meta_without(""), "\"nothing found\""),
    )
    .expect("the fixture loads")
    .single()
    .expect("exactly one check");

    let host = Replies::plain(200, "body").build();
    let verdict = run(
        &check,
        &point(
            InsertionKind::Query,
            "q",
            "http://127.0.0.1:8080/search",
            None,
            &[],
        ),
        &host,
    )
    .await;

    assert_eq!(verdict.outcome, Outcome::Inconclusive);
    assert_eq!(verdict.detail, "nothing found");
    assert_eq!(host.payloads(), Vec::<String>::new());
}

#[test]
fn the_retired_scripts_are_gone() {
    // `xss-reflected` and `open-redirect` are native checks now, and a class is
    // single-sourced: the Rhai copies would be a second owner of the same
    // class. Their manual verbs are `check.xss-reflected` / `check.open-redirect`.
    assert!(
        !active_path("check-xss.rhai").exists(),
        "check-xss.rhai is retired"
    );
    assert!(
        !active_path("check-open-redirect.rhai").exists(),
        "check-open-redirect.rhai is retired"
    );
}

/// A JSON body whose fields are all numbers, booleans or nulls: the document
/// branch has nowhere to put an operator, so it sends nothing at all — and
/// says so. `Outcome::Clean` is reserved for "operators were tried and nothing
/// moved" (`aitm-scan-model` vocab); a body no operator was ever placed in is
/// `inconclusive`, the same answer the cut example gets.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nosqli_json_is_inconclusive_when_the_body_has_no_string_field() {
    let check = Loaded::load("check-nosqli-json.rhai")
        .expect("loads")
        .single()
        .expect("exactly one check");
    let body_point = point(
        InsertionKind::EntireBody,
        "body",
        "http://127.0.0.1:8080/api/search",
        Some(r#"{"active":true,"id":7,"page":null}"#),
        &[PointTrait::Json, PointTrait::Structured],
    );

    let host = Replies::plain(401, r#"{"ok":false}"#).build();
    let verdict = run(&check, &body_point, &host).await;

    assert_eq!(
        host.payloads(),
        Vec::<String>::new(),
        "no string field, so no operator document was ever built"
    );
    assert_eq!(verdict.outcome, Outcome::Inconclusive, "{verdict:?}");
    assert_eq!(verdict.confidence, Confidence::Tentative);
    assert_eq!(
        verdict.detail,
        "this JSON body has no string field to place an operator document at"
    );
    assert_eq!(verdict.evidence.payload, None);
    assert_eq!(verdict.evidence.matched, None);
}

/// The lane's `entire_body` example is **scrubbed** before the check sees it
/// (`aitm-scan-http::redact::example`), and a secret-named field whose value is
/// not quoted — a number, an object, `true`, `null` — is replaced value and
/// quotes alike: `{"user":"a","api_key":12345}` reaches the script as
/// `{"user":"a","api_key":[redacted]}`, pinned by
/// `redact::tests::an_entire_body_example_with_an_unquoted_secret_value_is_no_longer_json`.
///
/// Its braces and brackets balance and no quote is left open, so completeness
/// alone would hand it to `parse_json`, which fails uncatchably and ends the
/// whole check as an `error`. A mask standing where a value should be says the
/// example is not the document the store saw: the check answers `inconclusive`
/// with a detail of its own, because the cause is the scrub and not a cut. A
/// mask *inside* a quoted string is still a whole document and is still probed.
///
/// Every masked example here is built by running the **real** scrubber
/// ([`aitm_core::redact::scrub_text_wide`], the one
/// `aitm-scan-http::redact::example` applies) over a plain body, so the shapes
/// under test are the shapes the lane really produces and nothing is
/// hand-written. That is also what pins the mask token across the two crates:
/// reword `aitm_core::redact::MASK` and this test goes red, rather than every
/// masked body silently becoming an uncatchable `parse_json` error verdict.
/// The third body is the nested secret-named object, whose scrub takes the
/// `{` with the value — `{"user":"a","auth":[redacted]"token":"[redacted]"}}` —
/// so its braces do **not** balance: completeness alone would call it a cut
/// example, and only the bare-mask reading says what really happened.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nosqli_json_is_inconclusive_when_the_scrub_masked_an_unquoted_value() {
    let check = Loaded::load("check-nosqli-json.rhai")
        .expect("loads")
        .single()
        .expect("exactly one check");

    for plain in [
        r#"{"user":"a","api_key":12345}"#,
        r#"{"user":"a","token":true,"page":2}"#,
        r#"{"user":"a","auth":{"token":"t"}}"#,
    ] {
        let example = scrub_text_wide(plain);
        assert!(
            example.contains("[redacted]"),
            "the scrubber masks this body: {plain} -> {example}"
        );
        let body_point = point(
            InsertionKind::EntireBody,
            "body",
            "http://127.0.0.1:8080/api/login",
            Some(example.as_str()),
            &[PointTrait::Json, PointTrait::Structured],
        );

        let host = Replies::plain(401, r#"{"ok":false}"#).build();
        let verdict = run(&check, &body_point, &host).await;

        assert_eq!(
            verdict.outcome,
            Outcome::Inconclusive,
            "{example}: {verdict:?}"
        );
        assert_eq!(verdict.confidence, Confidence::Tentative, "{example}");
        assert_eq!(
            verdict.detail,
            "a secret in this JSON body was masked before the check saw it; \
             document-level operators need the whole body",
            "{example}: the scrub case says why, and says something other than \
             the cut case"
        );
        assert_eq!(verdict.evidence.payload, None, "{example}");
        assert_eq!(verdict.evidence.matched, None, "{example}");
        assert_eq!(
            host.payloads(),
            Vec::<String>::new(),
            "{example}: no probe is spent on a document the check cannot rebuild"
        );
    }

    // The masked value the lane leaves *quoted* — the ordinary case — is a
    // whole document still, and every string field of it is probed. The
    // scrubber really does produce exactly this body, which is what makes
    // `LOGIN_BODY` a capture and not a guess.
    assert_eq!(
        scrub_text_wide(r#"{"username":"alice","password":"hunter2"}"#),
        LOGIN_BODY,
        "the quoted-mask body every other test uses is the scrubber's own output"
    );
    let quoted = point(
        InsertionKind::EntireBody,
        "body",
        "http://127.0.0.1:8080/api/login",
        Some(LOGIN_BODY),
        &[PointTrait::Json, PointTrait::Structured],
    );
    let host = Replies::plain(401, r#"{"ok":false}"#).build();
    let verdict = run(&check, &quoted, &host).await;

    assert_eq!(verdict.outcome, Outcome::Clean, "{verdict:?}");
    assert_eq!(
        host.payloads().len(),
        4,
        "both operators at both string fields: {:?}",
        host.payloads()
    );
}
