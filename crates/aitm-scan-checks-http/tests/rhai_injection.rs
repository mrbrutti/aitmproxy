//! T3 plan Task 12 — the three converted injection checks (`sqli`, `ssti`,
//! `cmdi`) on the **real** bridge: the shipped `scripts/bundled/active/*.rhai`
//! file, the real `RhaiLoader`, the real `reg.add_check`, the real `probe.*`,
//! every reply from the model's own `RecordingHost` (decision D-2b-1).
//!
//! These are inner-loop tests over canned replies: they say the script is
//! well-formed and decides correctly on the two shapes it is shown, and
//! nothing about the scanner in the field. The acceptance evidence is Task 17,
//! a real scan against the project's own test target.
//!
//! Every oracle here is an echo oracle. Nothing in these three scripts reads,
//! writes or runs anything on the far side: `sqli` makes a parser complain
//! about an unbalanced quote, `ssti` asks a template engine to multiply two
//! primes, `cmdi` asks for a benign echo of a marker split in two halves.

mod rhai_harness;

use aitm_poc::{Assertion, MatchPart, Severity};
use aitm_scan_model::vocab::{
    CheckCost, CheckOrigin, CheckScope, Confidence, InsertionKind, Intensity, LaneKind, Outcome,
    Technique,
};

use rhai_harness::{control_parse, matchers_parse, point, run, Loaded, Replies};

/// The marker `RecordingHost` hands every check. `ssti` and `cmdi` build their
/// canary from `probe.marker()` rather than from random text, because a reply
/// table cannot know what `rand_text_alpha` minted (T3 PR 2b, the real
/// bridge's randomness is real).
const MARKER: &str = "aitm7f3a";

/// The database-error signature `check-sqli.rhai` carries, as the PoC engine
/// will receive it. The Rhai source writes `\\[` for this string's `\[`.
const SQL_ERR: &str = r"(?i)(SQL syntax.*MySQL|ORA-[0-9]{5}|PostgreSQL.*ERROR|SQLSTATE\[|SQLiteException|Unclosed quotation mark|SqlException|psycopg2\.|sqlalchemy\.exc\.|Warning.*mysqli?_|quoted string not properly terminated)";

/// What a MySQL server says when a quote lands in an unparameterised query.
const MYSQL_ERROR: &str = "You have an error in your SQL syntax; check the manual that \
     corresponds to your MySQL server version near \"''\" at line 1";

/// `ssti`'s evaluated product next to the job marker: 73 * 79 = 5767.
const SSTI_RENDERED: &str = "aitm7f3a5767";

/// `cmdi`'s marker as only a shell rejoins it, and the literal command text a
/// mere reflection shows instead.
const CMDI_JOINED: &str = "AITM7F3A";
const CMDI_LITERAL: &str = "echo AITM";

/// A `word` matcher against the body, the way the bridge parsed it.
fn word(text: &str) -> Assertion {
    Assertion::Word {
        word: text.to_string(),
        part: MatchPart::Body,
    }
}

/// A `regex` matcher against the body, the way the bridge parsed it.
fn regex(pattern: &str) -> Assertion {
    Assertion::Regex {
        regex: pattern.to_string(),
        part: MatchPart::Body,
    }
}

/// `not: { .. }` around one matcher.
fn not(inner: Assertion) -> Assertion {
    Assertion::Not(Box::new(inner))
}

/// The bridge wraps a `matchers: [..]` list in one `all`, however long it is.
fn all(list: Vec<Assertion>) -> Vec<Assertion> {
    vec![Assertion::All(list)]
}

/// The shipped file this check came from, which is what the catalogue shows.
fn origin_file(origin: &CheckOrigin) -> String {
    match origin {
        CheckOrigin::Bundled { path } => path
            .rsplit(std::path::MAIN_SEPARATOR)
            .next()
            .unwrap_or_default()
            .to_string(),
        other => panic!("a shipped active check is Bundled, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// sqli — error technique
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sqli_declares_one_check_with_valid_meta() {
    let loaded = Loaded::load("check-sqli.rhai").expect("the shipped script loads");
    let check = loaded.single().expect("exactly one check");
    let meta = check.meta();

    assert_eq!(meta.id, "sqli");
    assert_eq!(meta.name, "SQL injection (error-based)");
    assert_eq!(meta.class, "sqli");
    assert_eq!(meta.lanes, vec![LaneKind::Http]);
    assert_eq!(
        meta.kinds,
        vec![
            InsertionKind::Query,
            InsertionKind::BodyParam,
            InsertionKind::JsonValue,
            InsertionKind::Cookie,
        ]
    );
    assert_eq!(
        meta.technique,
        Technique::Error,
        "native `sqli-boolean` owns the boolean technique; this script owns `error` only"
    );
    assert_eq!(meta.confidence_max, Confidence::Firm);
    assert_eq!(meta.severity, Severity::Critical);
    assert_eq!(meta.intensity, Intensity::Medium);
    assert_eq!(meta.cost, CheckCost::Light);
    assert_eq!(meta.cwe, Some(89));
    assert_eq!(meta.wants_traits, None);
    assert_eq!(meta.scope, CheckScope::Point);
    assert!(!meta.needs_baseline);
    assert_eq!(origin_file(&meta.origin), "check-sqli.rhai");
    assert_eq!(loaded.command_names(), Vec::<String>::new());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sqli_is_vulnerable_against_its_vulnerable_shape() {
    let check = Loaded::load("check-sqli.rhai")
        .expect("loads")
        .single()
        .expect("exactly one check");
    let host = Replies::plain(200, "Item 1")
        .when("1'", 500, MYSQL_ERROR)
        .build();

    let verdict = run(&check, &sqli_point(), &host).await;

    assert_eq!(verdict.outcome, Outcome::Vulnerable);
    assert_eq!(verdict.confidence, Confidence::Firm);
    assert_eq!(verdict.evidence.payload.as_deref(), Some("1'"));
    assert_eq!(
        verdict.evidence.matched.as_deref(),
        Some("database error signature")
    );
    assert_eq!(
        verdict.detail,
        "A single quote in \"id\" provoked a database error, so the value reaches the query \
         unparameterised."
    );
    assert_eq!(
        host.payloads(),
        vec!["1'".to_string()],
        "the quote is appended to the value the application already accepts"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sqli_is_clean_against_its_patched_shape() {
    let check = Loaded::load("check-sqli.rhai")
        .expect("loads")
        .single()
        .expect("exactly one check");
    // A parameterised query rejects the value instead of letting it reach the
    // parser: a 400 with no error signature in it.
    let host = Replies::plain(200, "Item 1")
        .when("1'", 400, "Invalid item id.")
        .build();

    let verdict = run(&check, &sqli_point(), &host).await;

    assert_eq!(verdict.outcome, Outcome::Clean);
    assert_eq!(verdict.confidence, Confidence::Firm);
    assert_eq!(verdict.evidence.payload.as_deref(), Some("1'"));
    assert_eq!(verdict.evidence.matched, None);
    assert_eq!(
        verdict.detail,
        "A quote in this value produced no database error signature."
    );
    assert!(verdict.poc_hint.is_none(), "a clean verdict hints no PoC");
    assert_eq!(host.payloads(), vec!["1'".to_string()]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sqli_supplies_a_parsable_poc_hint() {
    let check = Loaded::load("check-sqli.rhai")
        .expect("loads")
        .single()
        .expect("exactly one check");
    let host = Replies::plain(200, "Item 1")
        .when("1'", 500, MYSQL_ERROR)
        .build();

    let verdict = run(&check, &sqli_point(), &host).await;

    assert_eq!(
        matchers_parse(&verdict).expect("a hint"),
        all(vec![regex(SQL_ERR)])
    );
    let (payload, expect) = control_parse(&verdict)
        .expect("a hint")
        .expect("the hint names a control arm");
    assert_eq!(
        payload, "1",
        "the control re-sends the point's own value, unquoted"
    );
    assert_eq!(expect, all(vec![not(regex(SQL_ERR))]));

    // The signature the hint carries is a real regex, and it is the one that
    // decided this verdict.
    let compiled = regex::Regex::new(SQL_ERR).expect("the hinted signature compiles");
    assert!(compiled.is_match(MYSQL_ERROR));
    assert!(!compiled.is_match("Invalid item id."));
}

fn sqli_point() -> aitm_scan_model::point::InsertionPoint {
    point(
        InsertionKind::Query,
        "id",
        "http://127.0.0.1:8080/item",
        Some("1"),
        &[],
    )
}

// ---------------------------------------------------------------------------
// ssti — arithmetic marker
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ssti_declares_one_check_with_valid_meta() {
    let loaded = Loaded::load("check-ssti.rhai").expect("the shipped script loads");
    let check = loaded.single().expect("exactly one check");
    let meta = check.meta();

    assert_eq!(meta.id, "ssti");
    assert_eq!(meta.name, "Server-side template injection");
    assert_eq!(meta.class, "ssti");
    assert_eq!(meta.lanes, vec![LaneKind::Http]);
    assert_eq!(
        meta.kinds,
        vec![
            InsertionKind::Query,
            InsertionKind::BodyParam,
            InsertionKind::JsonValue,
        ]
    );
    assert_eq!(meta.technique, Technique::Reflected);
    assert_eq!(meta.confidence_max, Confidence::Certain);
    assert_eq!(meta.severity, Severity::Critical);
    assert_eq!(meta.intensity, Intensity::Medium);
    assert_eq!(meta.cost, CheckCost::Medium);
    assert_eq!(meta.cwe, Some(1336));
    assert_eq!(meta.wants_traits, None);
    assert_eq!(meta.scope, CheckScope::Point);
    assert!(!meta.needs_baseline);
    assert_eq!(origin_file(&meta.origin), "check-ssti.rhai");
    assert_eq!(loaded.command_names(), Vec::<String>::new());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ssti_is_vulnerable_against_its_vulnerable_shape() {
    let check = Loaded::load("check-ssti.rhai")
        .expect("loads")
        .single()
        .expect("exactly one check");
    // A Jinja/Twig page renders the expression, so the product comes back
    // next to the job marker instead of the expression text.
    let host = Replies::plain(200, "Hello world!")
        .when(
            "{{73*79}}",
            200,
            &format!("<h1>Hello {SSTI_RENDERED}!</h1>"),
        )
        .build();

    let verdict = run(&check, &ssti_point(), &host).await;

    assert_eq!(verdict.outcome, Outcome::Vulnerable);
    assert_eq!(verdict.confidence, Confidence::Certain);
    assert_eq!(
        verdict.evidence.payload.as_deref(),
        Some("aitm7f3a{{73*79}}")
    );
    assert_eq!(verdict.evidence.matched.as_deref(), Some(SSTI_RENDERED));
    assert_eq!(
        verdict.detail,
        "\"name\" evaluated a template expression: 73*79 came back rendered as aitm7f3a5767. \
         Template injection usually reaches remote code execution."
    );
    assert_eq!(
        host.payloads(),
        vec!["aitm7f3a{{73*79}}".to_string()],
        "the first syntax concluded it; the other three are never sent"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ssti_is_clean_against_its_patched_shape() {
    let check = Loaded::load("check-ssti.rhai")
        .expect("loads")
        .single()
        .expect("exactly one check");
    // The page prints the value instead of rendering it: the expression text
    // comes back verbatim, which is a reflection and not an evaluation.
    let host = Replies::plain(200, "Hello world!")
        .when(
            "{{73*79}}",
            200,
            &format!("<h1>Hello {MARKER}{{{{73*79}}}}!</h1>"),
        )
        .build();

    let verdict = run(&check, &ssti_point(), &host).await;

    assert_eq!(verdict.outcome, Outcome::Clean);
    assert_eq!(verdict.confidence, Confidence::Firm);
    assert_eq!(
        verdict.evidence.payload.as_deref(),
        Some("aitm7f3a{{73*79}}")
    );
    assert_eq!(verdict.evidence.matched, None);
    assert_eq!(
        verdict.detail,
        "No template syntax was evaluated: the arithmetic marker never came back as its product."
    );
    assert!(verdict.poc_hint.is_none());
    assert_eq!(
        host.payloads(),
        vec![
            "aitm7f3a{{73*79}}".to_string(),
            "aitm7f3a${73*79}".to_string(),
            "aitm7f3a#{73*79}".to_string(),
            "aitm7f3a<%= 73*79 %>".to_string(),
        ],
        "all four engine syntaxes are tried before the point is cleared"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ssti_supplies_a_parsable_poc_hint() {
    let check = Loaded::load("check-ssti.rhai")
        .expect("loads")
        .single()
        .expect("exactly one check");
    let host = Replies::plain(200, "Hello world!")
        .when(
            "{{73*79}}",
            200,
            &format!("<h1>Hello {SSTI_RENDERED}!</h1>"),
        )
        .build();

    let verdict = run(&check, &ssti_point(), &host).await;

    assert_eq!(
        matchers_parse(&verdict).expect("a hint"),
        all(vec![word(SSTI_RENDERED)])
    );
    let (payload, expect) = control_parse(&verdict)
        .expect("a hint")
        .expect("the hint names a control arm");
    assert_eq!(
        payload, MARKER,
        "the control sends the bare marker: it must come back without the product"
    );
    assert_eq!(expect, all(vec![not(word(SSTI_RENDERED))]));
}

fn ssti_point() -> aitm_scan_model::point::InsertionPoint {
    point(
        InsertionKind::Query,
        "name",
        "http://127.0.0.1:8080/greet",
        Some("world"),
        &[],
    )
}

// ---------------------------------------------------------------------------
// cmdi — split echo marker
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cmdi_declares_one_check_with_valid_meta() {
    let loaded = Loaded::load("check-command-injection.rhai").expect("the shipped script loads");
    let check = loaded.single().expect("exactly one check");
    let meta = check.meta();

    assert_eq!(meta.id, "cmdi");
    assert_eq!(meta.name, "OS command injection");
    assert_eq!(meta.class, "cmdi");
    assert_eq!(meta.lanes, vec![LaneKind::Http]);
    assert_eq!(
        meta.kinds,
        vec![
            InsertionKind::Query,
            InsertionKind::BodyParam,
            InsertionKind::JsonValue,
        ]
    );
    assert_eq!(
        meta.technique,
        Technique::Reflected,
        "the echo marker only; native `cmdi-time` owns the timing technique"
    );
    assert_eq!(meta.confidence_max, Confidence::Certain);
    assert_eq!(meta.severity, Severity::Critical);
    assert_eq!(meta.intensity, Intensity::Medium);
    assert_eq!(meta.cost, CheckCost::Medium);
    assert_eq!(meta.cwe, Some(78));
    assert_eq!(meta.wants_traits, None);
    assert_eq!(meta.scope, CheckScope::Point);
    assert!(!meta.needs_baseline);
    assert_eq!(origin_file(&meta.origin), "check-command-injection.rhai");
    assert_eq!(loaded.command_names(), Vec::<String>::new());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cmdi_is_vulnerable_against_its_vulnerable_shape() {
    let check = Loaded::load("check-command-injection.rhai")
        .expect("loads")
        .single()
        .expect("exactly one check");
    // A shell ran the separator's right-hand side: the two halves come back
    // joined and the command word is gone.
    let host = Replies::plain(200, "ping: 1 is unreachable")
        .when(
            CMDI_LITERAL,
            200,
            &format!("PING 1 ... 0 received\n{CMDI_JOINED}\n"),
        )
        .build();

    let verdict = run(&check, &cmdi_point(), &host).await;

    assert_eq!(verdict.outcome, Outcome::Vulnerable);
    assert_eq!(verdict.confidence, Confidence::Certain);
    assert_eq!(verdict.evidence.payload.as_deref(), Some("1;echo AITM7F3A"));
    assert_eq!(verdict.evidence.matched.as_deref(), Some(CMDI_JOINED));
    assert_eq!(
        verdict.detail,
        "\"host\" ran an injected shell command: the split echo marker came back joined as \
         AITM7F3A with the command text gone. This is remote command execution."
    );
    assert_eq!(
        host.payloads(),
        vec!["1;echo AITM7F3A".to_string()],
        "the first separator concluded it; the other five are never sent"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cmdi_is_clean_against_its_patched_shape() {
    let check = Loaded::load("check-command-injection.rhai")
        .expect("loads")
        .single()
        .expect("exactly one check");
    // The value never reaches a shell; the page reflects it verbatim, so the
    // joined marker is there but so is the literal command text. A reflection
    // must not be read as execution.
    let host = Replies::plain(200, "ping: 1 is unreachable")
        .when(CMDI_LITERAL, 200, "ping: unknown host \"1;echo AITM7F3A\"")
        .build();

    let verdict = run(&check, &cmdi_point(), &host).await;

    assert_eq!(verdict.outcome, Outcome::Clean);
    assert_eq!(verdict.confidence, Confidence::Firm);
    assert_eq!(verdict.evidence.payload.as_deref(), Some("1;echo AITM7F3A"));
    assert_eq!(verdict.evidence.matched, None);
    assert_eq!(
        verdict.detail,
        "No separator reassembled the echo marker, so nothing reached a shell."
    );
    assert!(verdict.poc_hint.is_none());
    assert_eq!(
        host.payloads(),
        vec![
            "1;echo AITM7F3A".to_string(),
            "1|echo AITM7F3A".to_string(),
            "1&&echo AITM7F3A".to_string(),
            "1$(echo AITM)7F3A".to_string(),
            "1`echo AITM`7F3A".to_string(),
            "1&echo AITM7F3A".to_string(),
        ],
        "all six separators are tried, and each one carries the marker split in two"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cmdi_supplies_a_parsable_poc_hint() {
    let check = Loaded::load("check-command-injection.rhai")
        .expect("loads")
        .single()
        .expect("exactly one check");
    let host = Replies::plain(200, "ping: 1 is unreachable")
        .when(
            CMDI_LITERAL,
            200,
            &format!("PING 1 ... 0 received\n{CMDI_JOINED}\n"),
        )
        .build();

    let verdict = run(&check, &cmdi_point(), &host).await;

    assert_eq!(
        matchers_parse(&verdict).expect("a hint"),
        all(vec![word(CMDI_JOINED), not(word(CMDI_LITERAL))]),
        "the PoC must see the joined marker AND not the literal command text"
    );
    let (payload, expect) = control_parse(&verdict)
        .expect("a hint")
        .expect("the hint names a control arm");
    assert_eq!(payload, "1", "the control re-sends the point's own value");
    assert_eq!(expect, all(vec![not(word(CMDI_JOINED))]));
}

fn cmdi_point() -> aitm_scan_model::point::InsertionPoint {
    point(
        InsertionKind::Query,
        "host",
        "http://127.0.0.1:8080/ping",
        Some("1"),
        &[],
    )
}

// ---------------------------------------------------------------------------
// Source rules every converted active check obeys (spec D4)
// ---------------------------------------------------------------------------

/// A check never sleeps: a timing technique belongs to a native check that
/// can fit a distribution, not to a script that blocks a worker (spec D4).
fn assert_never_sleeps(file: &str, source: &str) {
    assert!(
        !source.contains("sleep("),
        "{file} must not sleep: the timing techniques are native checks"
    );
}

/// A check payloads the point through `probe.send`, which lets the lane place
/// and encode the value; it never composes the request itself.
fn assert_uses_probe_send(file: &str, source: &str) {
    assert!(
        source.contains("probe.send("),
        "{file} must payload the point through the probe host"
    );
    assert!(
        !source.contains("http.send"),
        "{file} must not compose its own request"
    );
    assert!(
        !source.contains("url_encode("),
        "{file} must not encode the payload itself: the lane owns the encoding"
    );
    assert!(
        !source.contains("add_command"),
        "{file} is an active check, not a manual verb"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sqli_never_calls_sleep() {
    let loaded = Loaded::load("check-sqli.rhai").expect("loads");
    assert_never_sleeps("check-sqli.rhai", loaded.source());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sqli_uses_probe_send_not_a_handbuilt_query() {
    let loaded = Loaded::load("check-sqli.rhai").expect("loads");
    assert_uses_probe_send("check-sqli.rhai", loaded.source());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ssti_never_calls_sleep() {
    let loaded = Loaded::load("check-ssti.rhai").expect("loads");
    assert_never_sleeps("check-ssti.rhai", loaded.source());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ssti_uses_probe_send_not_a_handbuilt_query() {
    let loaded = Loaded::load("check-ssti.rhai").expect("loads");
    assert_uses_probe_send("check-ssti.rhai", loaded.source());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cmdi_never_calls_sleep() {
    let loaded = Loaded::load("check-command-injection.rhai").expect("loads");
    assert_never_sleeps("check-command-injection.rhai", loaded.source());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cmdi_uses_probe_send_not_a_handbuilt_query() {
    let loaded = Loaded::load("check-command-injection.rhai").expect("loads");
    assert_uses_probe_send("check-command-injection.rhai", loaded.source());
}
