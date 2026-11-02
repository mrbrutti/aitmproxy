//! T3 plan Task 14 — the three converted scripts that put protocol or query
//! metacharacters in a value: `crlf`, `nosqli`, `ldapi`.
//!
//! Each is the shipped `scripts/bundled/active/*.rhai` file, compiled by the
//! real `RhaiLoader`, registered through the real `reg.add_check`, and probed
//! through the real `probe.*` against the model's `RecordingHost` (decision
//! D-2b-1). Nothing here is a stand-in for the engine.
//!
//! These are inner-loop tests over canned replies: they say each script is
//! well-formed and decides correctly on the shapes it is shown. The acceptance
//! evidence is Task 17, a real scan over the real bus against the project's own
//! test target.

mod rhai_harness;

use aitm_poc::{Assertion, MatchPart, Severity};
use aitm_scan_model::vocab::{
    CheckCost, CheckOrigin, CheckScope, Confidence, InsertionKind, Intensity, LaneKind, Outcome,
    Technique,
};

use rhai_harness::{control_parse, matchers_parse, point, run, Loaded, Replies};

/// The marker `RecordingHost` hands every check — `ProbeHost::marker()` on the
/// recorder is this literal — and therefore the canary `check-crlf-injection`
/// builds its header out of here.
const MARKER: &str = "aitm7f3a";

/// The response header the CRLF canary is written into, lower-cased the way a
/// probe response's `headers` map carries it.
const CANARY_HEADER: &str = "x-aitm-crlf";

/// A result listing of `rows` entries, 18 bytes a row — the body a differential
/// check measures. Six rows (108 bytes) is the honest answer; fifty (900 bytes)
/// is what comes back when a query operator has widened the result set.
fn listing(rows: usize) -> String {
    (0..rows)
        .map(|i| format!("<li>user{i:04}</li>\n"))
        .collect()
}

/// The point `crlf` is run against: a redirect target in the query string.
fn crlf_point() -> aitm_scan_model::point::InsertionPoint {
    point(
        InsertionKind::Query,
        "next",
        "http://127.0.0.1:8080/login",
        Some("/home"),
        &[],
    )
}

/// The point `nosqli` is run against: a user name in the query string.
fn nosqli_point() -> aitm_scan_model::point::InsertionPoint {
    point(
        InsertionKind::Query,
        "user",
        "http://127.0.0.1:8080/users",
        Some("alice"),
        &[],
    )
}

/// The point `ldapi` is run against: a common name in the query string.
fn ldapi_point() -> aitm_scan_model::point::InsertionPoint {
    point(
        InsertionKind::Query,
        "cn",
        "http://127.0.0.1:8080/directory",
        Some("alice"),
        &[],
    )
}

// ---------------------------------------------------------------------------
// crlf
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn crlf_declares_one_check_with_valid_meta() {
    let loaded = Loaded::load("check-crlf-injection.rhai").expect("the shipped script loads");
    let check = loaded.single().expect("exactly one check");
    let meta = check.meta();

    assert_eq!(meta.id, "crlf");
    assert_eq!(meta.class, "crlf");
    assert_eq!(meta.lanes, vec![LaneKind::Http]);
    assert_eq!(
        meta.kinds,
        vec![
            InsertionKind::Query,
            InsertionKind::BodyParam,
            InsertionKind::Header
        ]
    );
    assert_eq!(meta.technique, Technique::Reflected);
    assert_eq!(meta.confidence_max, Confidence::Firm);
    assert_eq!(meta.severity, Severity::High);
    assert_eq!(meta.intensity, Intensity::Medium);
    assert_eq!(meta.cost, CheckCost::Light);
    assert_eq!(meta.cwe, Some(113));
    assert_eq!(meta.wants_traits, None);
    assert_eq!(meta.scope, CheckScope::Point);
    assert!(!meta.needs_baseline);

    match &meta.origin {
        CheckOrigin::Bundled { path } => assert!(
            path.ends_with("check-crlf-injection.rhai"),
            "the bundled origin must name the file, got: {path}"
        ),
        other => panic!("a shipped script is a bundled origin, got {other:?}"),
    }
    assert_eq!(
        loaded.command_names(),
        Vec::<String>::new(),
        "an active check script registers no command any more"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn crlf_is_vulnerable_against_its_vulnerable_shape() {
    let check = Loaded::load("check-crlf-injection.rhai")
        .expect("loads")
        .single()
        .expect("exactly one check");

    // A front end that percent-decodes the break writes the canary header the
    // value carried into the reply's own header block.
    let split = Replies::plain(200, "Redirecting")
        .when_headers(
            "%0d%0aX-Aitm-Crlf:%20aitm7f3a",
            200,
            &[(CANARY_HEADER, MARKER)],
            "Redirecting",
        )
        .build();

    let verdict = run(&check, &crlf_point(), &split).await;
    assert_eq!(verdict.outcome, Outcome::Vulnerable);
    assert_eq!(verdict.confidence, Confidence::Firm);
    assert_eq!(
        verdict.evidence.payload.as_deref(),
        Some("/home%0d%0aX-Aitm-Crlf:%20aitm7f3a")
    );
    assert_eq!(
        verdict.evidence.matched.as_deref(),
        Some("x-aitm-crlf: aitm7f3a")
    );
    assert_eq!(
        split.payloads(),
        vec!["/home%0d%0aX-Aitm-Crlf:%20aitm7f3a".to_string()],
        "the first encoding concluded it; the other two are never sent"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn crlf_is_clean_against_its_patched_shape() {
    let check = Loaded::load("check-crlf-injection.rhai")
        .expect("loads")
        .single()
        .expect("exactly one check");

    // A front end that decodes nothing into the header block: the reply carries
    // the canary nowhere, whichever encoding was sent.
    let patched = Replies::plain(200, "Redirecting").build();

    let verdict = run(&check, &crlf_point(), &patched).await;
    assert_eq!(verdict.outcome, Outcome::Clean);
    assert_eq!(verdict.confidence, Confidence::Firm);
    assert_eq!(
        verdict.detail,
        "No encoding of a line break in this value reached the response header block."
    );
    assert_eq!(
        patched.payloads(),
        vec![
            "/home%0d%0aX-Aitm-Crlf:%20aitm7f3a".to_string(),
            "/home%0d%0aX-Aitm-Crlf:aitm7f3a".to_string(),
            "/home%E5%98%8D%E5%98%8AX-Aitm-Crlf:aitm7f3a".to_string(),
        ],
        "all three encodings are tried before the point is cleared"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn crlf_supplies_a_parsable_poc_hint() {
    let check = Loaded::load("check-crlf-injection.rhai")
        .expect("loads")
        .single()
        .expect("exactly one check");
    let split = Replies::plain(200, "Redirecting")
        .when_headers(
            "%0d%0aX-Aitm-Crlf:%20aitm7f3a",
            200,
            &[(CANARY_HEADER, MARKER)],
            "Redirecting",
        )
        .build();

    let verdict = run(&check, &crlf_point(), &split).await;
    let matchers = matchers_parse(&verdict).expect("a vulnerable crlf verdict hints a PoC");
    assert_eq!(
        matchers,
        vec![Assertion::All(vec![Assertion::Word {
            word: MARKER.to_string(),
            part: MatchPart::Header,
        }])],
        "the reproduction looks for the canary among the response headers"
    );

    let (payload, expect) = control_parse(&verdict)
        .expect("a hint is present")
        .expect("the hint names a control arm");
    assert_eq!(
        payload, "/home",
        "the control re-sends the value the request already carried"
    );
    assert_eq!(
        expect,
        vec![Assertion::All(vec![Assertion::Not(Box::new(
            Assertion::Word {
                word: MARKER.to_string(),
                part: MatchPart::Header,
            }
        ))])],
        "and must NOT see the canary without the line break"
    );
}

// ---------------------------------------------------------------------------
// nosqli
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nosqli_declares_one_check_with_valid_meta() {
    let loaded = Loaded::load("check-nosql-injection.rhai").expect("the shipped script loads");
    let check = loaded.single().expect("exactly one check");
    let meta = check.meta();

    assert_eq!(meta.id, "nosqli");
    assert_eq!(meta.class, "nosqli");
    assert_eq!(meta.lanes, vec![LaneKind::Http]);
    assert_eq!(
        meta.kinds,
        vec![InsertionKind::Query, InsertionKind::BodyParam]
    );
    assert_eq!(meta.technique, Technique::Boolean);
    assert_eq!(meta.confidence_max, Confidence::Firm);
    assert_eq!(meta.severity, Severity::High);
    assert_eq!(meta.intensity, Intensity::Medium);
    assert_eq!(meta.cost, CheckCost::Light);
    assert_eq!(meta.cwe, Some(943));
    assert_eq!(meta.wants_traits, None);
    assert_eq!(meta.scope, CheckScope::Point);
    assert!(
        meta.needs_baseline,
        "the differential half measures against the point's own baseline"
    );

    match &meta.origin {
        CheckOrigin::Bundled { path } => assert!(
            path.ends_with("check-nosql-injection.rhai"),
            "the bundled origin must name the file, got: {path}"
        ),
        other => panic!("a shipped script is a bundled origin, got {other:?}"),
    }
    assert_eq!(loaded.command_names(), Vec::<String>::new());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nosqli_is_vulnerable_against_its_vulnerable_shape() {
    let check = Loaded::load("check-nosql-injection.rhai")
        .expect("loads")
        .single()
        .expect("exactly one check");

    // The store compares the document instead of the string: "not equal to a
    // name nobody holds" returns every row the honest query narrowed away.
    let widened = Replies::plain(200, &listing(6))
        .when("{\"$ne\": \"aliceaitmX\"}", 200, &listing(50))
        .build();

    let verdict = run(&check, &nosqli_point(), &widened).await;
    assert_eq!(verdict.outcome, Outcome::Vulnerable);
    assert_eq!(verdict.confidence, Confidence::Firm);
    assert_eq!(
        verdict.evidence.payload.as_deref(),
        Some("{\"$ne\": \"aliceaitmX\"}")
    );
    assert_eq!(
        verdict.evidence.matched.as_deref(),
        Some("result set 108 -> 900 bytes")
    );
    assert_eq!(
        widened.payloads(),
        vec![
            "{\"$ne\": null}".to_string(),
            "{\"$ne\": \"aliceaitmX\"}".to_string(),
        ],
        "the error probe first, then the inverted comparison"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nosqli_is_clean_against_its_patched_shape() {
    let check = Loaded::load("check-nosql-injection.rhai")
        .expect("loads")
        .single()
        .expect("exactly one check");

    // The operator document is coerced to the string it was declared to be:
    // same six rows, no parser error.
    let patched = Replies::plain(200, &listing(6)).build();

    let verdict = run(&check, &nosqli_point(), &patched).await;
    assert_eq!(verdict.outcome, Outcome::Clean);
    assert_eq!(verdict.confidence, Confidence::Firm);
    assert_eq!(
        verdict.detail,
        "A query operator in this value produced neither a database error nor a different result set."
    );
    assert_eq!(
        patched.payloads(),
        vec![
            "{\"$ne\": null}".to_string(),
            "{\"$ne\": \"aliceaitmX\"}".to_string(),
        ],
        "both techniques are tried before the point is cleared"
    );
}

// ---------------------------------------------------------------------------
// ldapi
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ldapi_declares_one_check_with_valid_meta() {
    let loaded = Loaded::load("check-ldap-injection.rhai").expect("the shipped script loads");
    let check = loaded.single().expect("exactly one check");
    let meta = check.meta();

    assert_eq!(meta.id, "ldapi");
    assert_eq!(meta.class, "ldapi");
    assert_eq!(meta.lanes, vec![LaneKind::Http]);
    assert_eq!(
        meta.kinds,
        vec![InsertionKind::Query, InsertionKind::BodyParam]
    );
    assert_eq!(meta.technique, Technique::Boolean);
    assert_eq!(meta.confidence_max, Confidence::Firm);
    assert_eq!(meta.severity, Severity::High);
    assert_eq!(meta.intensity, Intensity::Medium);
    assert_eq!(meta.cost, CheckCost::Light);
    assert_eq!(meta.cwe, Some(90));
    assert_eq!(meta.wants_traits, None);
    assert_eq!(meta.scope, CheckScope::Point);
    assert!(
        meta.needs_baseline,
        "the always-true filter is measured against the point's own baseline"
    );

    match &meta.origin {
        CheckOrigin::Bundled { path } => assert!(
            path.ends_with("check-ldap-injection.rhai"),
            "the bundled origin must name the file, got: {path}"
        ),
        other => panic!("a shipped script is a bundled origin, got {other:?}"),
    }
    assert_eq!(loaded.command_names(), Vec::<String>::new());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ldapi_is_vulnerable_against_its_vulnerable_shape() {
    let check = Loaded::load("check-ldap-injection.rhai")
        .expect("loads")
        .single()
        .expect("exactly one check");

    // The metacharacters reach the search filter: an always-true filter returns
    // the whole directory instead of the one entry asked for.
    let widened = Replies::plain(200, &listing(6))
        .when("*)(cn=*))%00", 200, &listing(50))
        .build();

    let verdict = run(&check, &ldapi_point(), &widened).await;
    assert_eq!(verdict.outcome, Outcome::Vulnerable);
    assert_eq!(verdict.confidence, Confidence::Firm);
    assert_eq!(verdict.evidence.payload.as_deref(), Some("*)(cn=*))%00"));
    assert_eq!(
        verdict.evidence.matched.as_deref(),
        Some("result set 108 -> 900 bytes")
    );
    assert_eq!(
        widened.payloads(),
        vec!["alice)(|(cn=*".to_string(), "*)(cn=*))%00".to_string()],
        "the unbalanced parenthesis first, then the always-true filter"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ldapi_is_clean_against_its_patched_shape() {
    let check = Loaded::load("check-ldap-injection.rhai")
        .expect("loads")
        .single()
        .expect("exactly one check");

    // The filter metacharacters are escaped: the directory neither complains
    // nor returns more than it did.
    let patched = Replies::plain(200, &listing(6)).build();

    let verdict = run(&check, &ldapi_point(), &patched).await;
    assert_eq!(verdict.outcome, Outcome::Clean);
    assert_eq!(verdict.confidence, Confidence::Firm);
    assert_eq!(
        verdict.detail,
        "Filter metacharacters in this value produced neither a directory error nor a different result set."
    );
    assert_eq!(
        patched.payloads(),
        vec!["alice)(|(cn=*".to_string(), "*)(cn=*))%00".to_string()],
        "both techniques are tried before the point is cleared"
    );
}

// ---------------------------------------------------------------------------
// The operator checks' second technique
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_operator_checks_also_report_a_database_error_signature() {
    // The differential is one half of `nosqli` and `ldapi`; the other half is
    // the error the query parser itself emits, which concludes on probe one.
    let nosqli = Loaded::load("check-nosql-injection.rhai")
        .expect("loads")
        .single()
        .expect("exactly one check");
    let mongo = Replies::plain(200, &listing(6))
        .when(
            "{\"$ne\": null}",
            500,
            "MongoError: unexpected token in filter",
        )
        .build();
    let verdict = run(&nosqli, &nosqli_point(), &mongo).await;
    assert_eq!(verdict.outcome, Outcome::Vulnerable);
    assert_eq!(verdict.confidence, Confidence::Firm);
    assert_eq!(verdict.evidence.payload.as_deref(), Some("{\"$ne\": null}"));
    assert_eq!(
        verdict.evidence.matched.as_deref(),
        Some("NoSQL database error signature")
    );
    assert_eq!(
        verdict.detail,
        "A query operator in \"user\" produced a database error, so the value is parsed as part of the query document."
    );
    assert_eq!(
        mongo.payloads(),
        vec!["{\"$ne\": null}".to_string()],
        "the parser error concluded it; the differential is never sent"
    );

    let ldapi = Loaded::load("check-ldap-injection.rhai")
        .expect("loads")
        .single()
        .expect("exactly one check");
    let jndi = Replies::plain(200, &listing(6))
        .when(
            ")(|(cn=*",
            500,
            "javax.naming.directory.InvalidSearchFilterException: bad search filter",
        )
        .build();
    let verdict = run(&ldapi, &ldapi_point(), &jndi).await;
    assert_eq!(verdict.outcome, Outcome::Vulnerable);
    assert_eq!(verdict.confidence, Confidence::Firm);
    assert_eq!(verdict.evidence.payload.as_deref(), Some("alice)(|(cn=*"));
    assert_eq!(
        verdict.evidence.matched.as_deref(),
        Some("LDAP directory error signature")
    );
    assert_eq!(
        verdict.detail,
        "A filter metacharacter in \"cn\" produced an LDAP error, so the value reaches the search filter unescaped."
    );
    assert_eq!(
        jndi.payloads(),
        vec!["alice)(|(cn=*".to_string()],
        "the directory error concluded it; the always-true filter is never sent"
    );
}

// ---------------------------------------------------------------------------
// House rules, on the shipped source of all three
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_three_scripts_never_call_sleep() {
    for file in [
        "check-crlf-injection.rhai",
        "check-nosql-injection.rhai",
        "check-ldap-injection.rhai",
    ] {
        let loaded = Loaded::load(file).expect("the shipped script loads");
        assert!(
            !loaded.source().contains("sleep("),
            "{file} blocks the engine with a sleep"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_three_scripts_use_probe_send_not_a_handbuilt_query() {
    for file in [
        "check-crlf-injection.rhai",
        "check-nosql-injection.rhai",
        "check-ldap-injection.rhai",
    ] {
        let loaded = Loaded::load(file).expect("the shipped script loads");
        let source = loaded.source();
        assert!(
            source.contains("probe.send"),
            "{file} must payload the point through the host"
        );
        assert!(
            !source.contains("http.send"),
            "{file} composes its own request instead of probing the point"
        );
        assert!(
            !source.contains("url_encode(param)"),
            "{file} hand-builds a query string"
        );
        assert!(
            !source.contains("add_command"),
            "{file} is an active check, not a manual verb"
        );
    }
}
