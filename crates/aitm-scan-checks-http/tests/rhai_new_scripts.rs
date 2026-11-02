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

use aitm_scan_model::vocab::{Confidence, InsertionKind, Outcome};

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
    assert_eq!(meta.kinds, vec![InsertionKind::JsonValue]);
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
