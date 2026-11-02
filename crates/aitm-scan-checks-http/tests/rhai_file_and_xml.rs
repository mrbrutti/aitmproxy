//! T3 plan Task 13 — the three converted file-and-document checks
//! (`check-path-traversal.rhai`, `check-xxe.rhai`, `check-ssrf.rhai`) through
//! the **real** T1b bridge: the shipped file, the real `RhaiLoader`, the real
//! `reg.add_check`, the real `probe.*`, answered by the model's own
//! `RecordingHost` (decision D-2b-1).
//!
//! These three share a shape: the payload names something the *server* reads —
//! a file path, an XML entity, a URL the server fetches — and the oracle is a
//! signature of what came back, never a timer. That is why each has a
//! vulnerable shape and a patched shape here and nothing in between.
//!
//! Inner-loop only, over canned replies and no network. The acceptance
//! evidence is Task 17: a real scan over the real bus against the project's own
//! test target.

mod rhai_harness;

use aitm_poc::{Assertion, MatchPart, Severity};
use aitm_scan_model::vocab::{
    CheckCost, CheckOrigin, CheckScope, Confidence, InsertionKind, Intensity, LaneKind, Outcome,
    PointTrait, Technique,
};

use rhai_harness::{control_parse, matchers_parse, point, run, Loaded, Replies};

/// The marker `RecordingHost` hands every check, and so the XML element name
/// `check-xxe.rhai` builds its document around here.
const MARKER: &str = "aitm7f3a";

/// The POSIX account-file signature both the traversal and the XXE check match
/// on, and carry into their PoC hint.
const NIX_SIG: &str = "root:.*:0:0:";

/// A `/etc/passwd` body that signature matches.
const PASSWD: &str = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin\n";

/// The six traversal payloads `check-path-traversal.rhai` spends, in order.
fn traversal_payloads() -> Vec<String> {
    [
        "../../../../../../../../etc/passwd",
        "..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
        "....//....//....//....//etc/passwd",
        "/etc/passwd",
        "..\\..\\..\\..\\..\\windows\\win.ini",
        "../../../../../../windows/win.ini",
    ]
    .iter()
    .map(|p| (*p).to_string())
    .collect()
}

/// The XXE document the check builds once its element name is the job marker.
fn xxe_document() -> String {
    format!(
        "<?xml version=\"1.0\"?>\
         <!DOCTYPE {MARKER} [<!ENTITY {MARKER} SYSTEM \"file:///etc/passwd\">]>\
         <{MARKER}>&{MARKER};</{MARKER}>"
    )
}

/// The benign control document: the same element, no DOCTYPE, no entity.
fn xxe_control() -> String {
    format!("<?xml version=\"1.0\"?><{MARKER}>1</{MARKER}>")
}

/// The four addresses `check-ssrf.rhai` points the value at, in order.
fn ssrf_targets() -> Vec<String> {
    [
        "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        "http://127.0.0.1/",
    ]
    .iter()
    .map(|t| (*t).to_string())
    .collect()
}

/// The point `check-path-traversal.rhai` is scheduled on: a filename-shaped
/// query value.
fn traversal_point() -> aitm_scan_model::point::InsertionPoint {
    point(
        InsertionKind::Query,
        "file",
        "http://127.0.0.1:8080/download",
        Some("readme.txt"),
        &[PointTrait::Filename],
    )
}

/// The point `check-xxe.rhai` is scheduled on: a whole XML body.
fn xxe_point() -> aitm_scan_model::point::InsertionPoint {
    point(
        InsertionKind::EntireBody,
        "body",
        "http://127.0.0.1:8080/api/orders",
        Some("<order><id>1</id></order>"),
        &[],
    )
}

/// The point `check-ssrf.rhai` is scheduled on: a URL-shaped query value.
fn ssrf_point() -> aitm_scan_model::point::InsertionPoint {
    point(
        InsertionKind::Query,
        "next",
        "http://127.0.0.1:8080/fetch",
        Some("http://example.test/logo.png"),
        &[PointTrait::Url],
    )
}

// ---------------------------------------------------------------------------
// check-path-traversal.rhai
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn path_traversal_declares_one_check_with_valid_meta() {
    let loaded = Loaded::load("check-path-traversal.rhai").expect("the shipped script loads");
    let check = loaded.single().expect("exactly one check");
    let meta = check.meta();

    assert_eq!(meta.id, "path_traversal");
    assert_eq!(meta.name, "Path traversal / local file inclusion");
    assert_eq!(meta.class, "path-traversal");
    assert_eq!(meta.lanes, vec![LaneKind::Http]);
    assert_eq!(
        meta.kinds,
        vec![
            InsertionKind::Query,
            InsertionKind::BodyParam,
            InsertionKind::JsonValue,
            InsertionKind::PathFilename,
            InsertionKind::MultipartFilename,
        ]
    );
    assert_eq!(meta.technique, Technique::Reflected);
    assert_eq!(meta.confidence_max, Confidence::Firm);
    assert_eq!(meta.severity, Severity::Critical);
    assert_eq!(meta.intensity, Intensity::Medium);
    assert_eq!(meta.cost, CheckCost::Medium);
    assert_eq!(meta.cwe, Some(22));
    assert_eq!(meta.wants_traits, Some(vec![PointTrait::Filename]));
    assert_eq!(meta.scope, CheckScope::Point);
    assert!(!meta.needs_baseline);
    match &meta.origin {
        CheckOrigin::Bundled { path } => assert!(
            path.ends_with("check-path-traversal.rhai"),
            "the bundled origin names the shipped file, got: {path}"
        ),
        other => panic!("a shipped script is a bundled origin, got {other:?}"),
    }
    assert_eq!(loaded.command_names(), Vec::<String>::new());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn path_traversal_is_vulnerable_against_its_vulnerable_shape() {
    let check = Loaded::load("check-path-traversal.rhai")
        .expect("loads")
        .single()
        .expect("exactly one check");

    // The document root is walked out of: the account file comes back.
    let host = Replies::plain(404, "File not found")
        .when("etc/passwd", 200, PASSWD)
        .build();
    let verdict = run(&check, &traversal_point(), &host).await;

    assert_eq!(verdict.outcome, Outcome::Vulnerable);
    assert_eq!(verdict.confidence, Confidence::Firm);
    assert_eq!(
        verdict.evidence.payload.as_deref(),
        Some("../../../../../../../../etc/passwd")
    );
    assert_eq!(
        verdict.evidence.matched.as_deref(),
        Some("system file signature")
    );
    assert_eq!(
        verdict.detail,
        "\"file\" returned the contents of a system file for traversal payload \
         ../../../../../../../../etc/passwd."
    );
    assert_eq!(
        host.payloads(),
        vec!["../../../../../../../../etc/passwd".to_string()],
        "the first encoding concluded it; the other five are never spent"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn path_traversal_is_clean_against_its_patched_shape() {
    let check = Loaded::load("check-path-traversal.rhai")
        .expect("loads")
        .single()
        .expect("exactly one check");

    // Every encoding is resolved back inside the document root.
    let host = Replies::plain(404, "File not found").build();
    let verdict = run(&check, &traversal_point(), &host).await;

    assert_eq!(verdict.outcome, Outcome::Clean);
    assert_eq!(verdict.confidence, Confidence::Firm);
    assert_eq!(
        verdict.detail,
        "No traversal encoding reached a file outside the document root."
    );
    assert_eq!(
        verdict.evidence.payload.as_deref(),
        Some("../../../../../../../../etc/passwd")
    );
    assert_eq!(verdict.evidence.matched, None);
    assert_eq!(verdict.poc_hint, None, "a clean verdict hints no PoC");
    assert_eq!(
        host.payloads(),
        traversal_payloads(),
        "all six encodings are tried before the point is cleared"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn path_traversal_supplies_a_parsable_poc_hint() {
    let check = Loaded::load("check-path-traversal.rhai")
        .expect("loads")
        .single()
        .expect("exactly one check");

    let host = Replies::plain(404, "File not found")
        .when("etc/passwd", 200, PASSWD)
        .build();
    let verdict = run(&check, &traversal_point(), &host).await;

    let matchers = matchers_parse(&verdict).expect("spec D6: path-traversal must hint a PoC");
    assert_eq!(
        matchers,
        vec![Assertion::All(vec![Assertion::Regex {
            regex: NIX_SIG.to_string(),
            part: MatchPart::Body,
        }])]
    );

    let (payload, expect) = control_parse(&verdict)
        .expect("a hint is present")
        .expect("the hint names a control arm");
    assert_eq!(
        payload, "readme.txt",
        "the control re-sends the point's own filename"
    );
    assert_eq!(
        expect,
        vec![Assertion::All(vec![Assertion::Not(Box::new(
            Assertion::Regex {
                regex: NIX_SIG.to_string(),
                part: MatchPart::Body,
            }
        ))])]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn path_traversal_never_calls_sleep() {
    let loaded = Loaded::load("check-path-traversal.rhai").expect("loads");
    assert!(
        !loaded.source().contains("sleep("),
        "a check never blocks the engine on a clock"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn path_traversal_uses_probe_send_not_a_handbuilt_query() {
    let loaded = Loaded::load("check-path-traversal.rhai").expect("loads");
    let source = loaded.source();
    assert!(source.contains("probe."), "the check probes its own point");
    assert!(!source.contains("http.send"));
    assert!(
        !source.contains("url_encode("),
        "the lane owns the encoding, not the check"
    );
    assert!(!source.contains("add_command"));
}

// ---------------------------------------------------------------------------
// check-xxe.rhai
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn xxe_declares_one_check_with_valid_meta() {
    let loaded = Loaded::load("check-xxe.rhai").expect("the shipped script loads");
    let check = loaded.single().expect("exactly one check");
    let meta = check.meta();

    assert_eq!(meta.id, "xxe");
    assert_eq!(meta.name, "XML external entity (XXE) injection");
    assert_eq!(meta.class, "xxe");
    assert_eq!(meta.lanes, vec![LaneKind::Http]);
    assert_eq!(meta.kinds, vec![InsertionKind::EntireBody]);
    assert_eq!(meta.technique, Technique::Reflected);
    assert_eq!(meta.confidence_max, Confidence::Firm);
    assert_eq!(meta.severity, Severity::Critical);
    assert_eq!(meta.intensity, Intensity::Medium);
    assert_eq!(meta.cost, CheckCost::Light);
    assert_eq!(meta.cwe, Some(611));
    assert_eq!(meta.wants_traits, None);
    assert_eq!(meta.scope, CheckScope::Point);
    assert!(!meta.needs_baseline);
    match &meta.origin {
        CheckOrigin::Bundled { path } => assert!(
            path.ends_with("check-xxe.rhai"),
            "the bundled origin names the shipped file, got: {path}"
        ),
        other => panic!("a shipped script is a bundled origin, got {other:?}"),
    }
    assert_eq!(loaded.command_names(), Vec::<String>::new());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn xxe_is_vulnerable_against_its_vulnerable_shape() {
    let check = Loaded::load("check-xxe.rhai")
        .expect("loads")
        .single()
        .expect("exactly one check");

    // The parser resolves the one external entity and prints the file.
    let host = Replies::plain(200, "<ok/>")
        .when(
            "file:///etc/passwd",
            200,
            &format!("<{MARKER}>root:x:0:0:root:/root:/bin/bash</{MARKER}>"),
        )
        .build();
    let verdict = run(&check, &xxe_point(), &host).await;

    assert_eq!(verdict.outcome, Outcome::Vulnerable);
    assert_eq!(verdict.confidence, Confidence::Firm);
    assert_eq!(verdict.evidence.payload.as_deref(), Some(&*xxe_document()));
    assert_eq!(
        verdict.evidence.matched.as_deref(),
        Some("system file signature")
    );
    assert_eq!(
        verdict.detail,
        "The XML endpoint resolved an external entity and returned local file contents. \
         XXE gives file disclosure and often server-side request forgery too."
    );
    assert_eq!(
        host.payloads(),
        vec![xxe_document()],
        "one document, one entity: no amplification and no second probe"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn xxe_is_clean_against_its_patched_shape() {
    let check = Loaded::load("check-xxe.rhai")
        .expect("loads")
        .single()
        .expect("exactly one check");

    // The parser refuses the DOCTYPE outright.
    let host = Replies::plain(200, "<ok/>")
        .when(
            "file:///etc/passwd",
            400,
            "<error>DOCTYPE is disallowed</error>",
        )
        .build();
    let verdict = run(&check, &xxe_point(), &host).await;

    assert_eq!(verdict.outcome, Outcome::Clean);
    assert_eq!(verdict.confidence, Confidence::Firm);
    assert_eq!(
        verdict.detail,
        "The endpoint returned no file contents: it either rejects a DOCTYPE or does not \
         parse XML here."
    );
    assert_eq!(verdict.evidence.payload.as_deref(), Some(&*xxe_document()));
    assert_eq!(verdict.evidence.matched, None);
    assert_eq!(verdict.poc_hint, None, "a clean verdict hints no PoC");
    assert_eq!(host.payloads(), vec![xxe_document()]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn xxe_supplies_a_parsable_poc_hint() {
    let check = Loaded::load("check-xxe.rhai")
        .expect("loads")
        .single()
        .expect("exactly one check");

    let host = Replies::plain(200, "<ok/>")
        .when(
            "file:///etc/passwd",
            200,
            &format!("<{MARKER}>root:x:0:0:root:/root:/bin/bash</{MARKER}>"),
        )
        .build();
    let verdict = run(&check, &xxe_point(), &host).await;

    let matchers = matchers_parse(&verdict).expect("spec D6: xxe must hint a PoC");
    assert_eq!(
        matchers,
        vec![Assertion::All(vec![Assertion::Regex {
            regex: NIX_SIG.to_string(),
            part: MatchPart::Body,
        }])]
    );

    let (payload, expect) = control_parse(&verdict)
        .expect("a hint is present")
        .expect("the hint names a control arm");
    assert_eq!(
        payload,
        xxe_control(),
        "the control is the same document with no DOCTYPE and no entity"
    );
    assert_eq!(
        expect,
        vec![Assertion::All(vec![Assertion::Not(Box::new(
            Assertion::Regex {
                regex: NIX_SIG.to_string(),
                part: MatchPart::Body,
            }
        ))])]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn xxe_never_calls_sleep() {
    let loaded = Loaded::load("check-xxe.rhai").expect("loads");
    assert!(
        !loaded.source().contains("sleep("),
        "a check never blocks the engine on a clock"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn xxe_uses_probe_send_not_a_handbuilt_query() {
    let loaded = Loaded::load("check-xxe.rhai").expect("loads");
    let source = loaded.source();
    assert!(source.contains("probe."), "the check probes its own point");
    assert!(!source.contains("http.send"));
    assert!(
        !source.contains("url_encode("),
        "the lane owns the encoding, not the check"
    );
    assert!(!source.contains("add_command"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn xxe_declares_one_entity_that_resolves_once() {
    // The benign-probe rule for this class: one entity, named once, pointing at
    // one file. A document that referenced its own entity would be a
    // billion-laughs amplification against the target, which this check must
    // never send. Asserted on the document the host was really handed, not on
    // a copy of it.
    let check = Loaded::load("check-xxe.rhai")
        .expect("loads")
        .single()
        .expect("exactly one check");
    let host = Replies::plain(200, "<ok/>").build();
    run(&check, &xxe_point(), &host).await;
    let document = host
        .payloads()
        .first()
        .cloned()
        .expect("one probe was sent");

    assert_eq!(
        document.matches("<!ENTITY").count(),
        1,
        "exactly one entity declaration"
    );
    assert_eq!(
        document.matches(&format!("&{MARKER};")).count(),
        1,
        "the entity is referenced exactly once"
    );
    assert!(!document.contains("SYSTEM \"http"), "no outbound fetch");

    let loaded = Loaded::load("check-xxe.rhai").expect("loads");
    assert!(
        loaded.source().contains("probe.marker()"),
        "the element name is the job's collision-resistant marker, so the \
         document a finding carries is the document that was sent"
    );
}

// ---------------------------------------------------------------------------
// check-ssrf.rhai
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ssrf_declares_one_check_with_valid_meta() {
    let loaded = Loaded::load("check-ssrf.rhai").expect("the shipped script loads");
    let check = loaded.single().expect("exactly one check");
    let meta = check.meta();

    assert_eq!(meta.id, "ssrf");
    assert_eq!(meta.name, "Server-side request forgery");
    assert_eq!(meta.class, "ssrf");
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
    assert_eq!(meta.confidence_max, Confidence::Firm);
    assert_eq!(meta.severity, Severity::Critical);
    assert_eq!(meta.intensity, Intensity::Medium);
    assert_eq!(meta.cost, CheckCost::Medium);
    assert_eq!(meta.cwe, Some(918));
    assert_eq!(meta.wants_traits, Some(vec![PointTrait::Url]));
    assert_eq!(meta.scope, CheckScope::Point);
    assert!(!meta.needs_baseline);
    match &meta.origin {
        CheckOrigin::Bundled { path } => assert!(
            path.ends_with("check-ssrf.rhai"),
            "the bundled origin names the shipped file, got: {path}"
        ),
        other => panic!("a shipped script is a bundled origin, got {other:?}"),
    }
    assert_eq!(loaded.command_names(), Vec::<String>::new());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ssrf_is_vulnerable_against_its_vulnerable_shape() {
    let check = Loaded::load("check-ssrf.rhai")
        .expect("loads")
        .single()
        .expect("exactly one check");

    // The server fetches the instance-metadata service and hands back its page.
    let host = Replies::plain(200, "fetch failed")
        .when(
            "169.254.169.254/latest/meta-data",
            200,
            "ami-id\ninstance-id\nhostname\npublic-keys/",
        )
        .build();
    let verdict = run(&check, &ssrf_point(), &host).await;

    assert_eq!(verdict.outcome, Outcome::Vulnerable);
    assert_eq!(verdict.confidence, Confidence::Firm);
    assert_eq!(
        verdict.evidence.payload.as_deref(),
        Some("http://169.254.169.254/latest/meta-data/")
    );
    assert_eq!(
        verdict.evidence.matched.as_deref(),
        Some("internal service response signature")
    );
    assert_eq!(
        verdict.detail,
        "\"next\" fetched http://169.254.169.254/latest/meta-data/ and returned its \
         response. Cloud-metadata forgery leaks instance credentials."
    );
    assert_eq!(
        host.payloads(),
        vec!["http://169.254.169.254/latest/meta-data/".to_string()],
        "the scanner never dials the internal address itself: it rides inside \
         the in-scope parameter, and the first one concluded it"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ssrf_is_clean_against_its_patched_shape() {
    let check = Loaded::load("check-ssrf.rhai")
        .expect("loads")
        .single()
        .expect("exactly one check");

    // The fetcher allow-lists its destinations, so every address is refused.
    let host = Replies::plain(502, "fetch failed: destination refused").build();
    let verdict = run(&check, &ssrf_point(), &host).await;

    assert_eq!(verdict.outcome, Outcome::Clean);
    assert_eq!(verdict.confidence, Confidence::Firm);
    assert_eq!(
        verdict.detail,
        "No internal or metadata address was fetched on this value."
    );
    assert_eq!(
        verdict.evidence.payload.as_deref(),
        Some("http://169.254.169.254/latest/meta-data/")
    );
    assert_eq!(verdict.evidence.matched, None);
    assert_eq!(
        host.payloads(),
        ssrf_targets(),
        "all four addresses are tried before the point is cleared"
    );
    assert_eq!(
        host.raw_urls(),
        Vec::<String>::new(),
        "a per-point check composes no request of its own"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ssrf_supplies_no_poc_hint() {
    // Spec D6 does not list `ssrf` among the classes that must hint a PoC, and
    // an in-band metadata signature is not reliably reproducible from another
    // network position — so this check deliberately carries none, and the
    // assertion is that it stays that way.
    let check = Loaded::load("check-ssrf.rhai")
        .expect("loads")
        .single()
        .expect("exactly one check");

    let host = Replies::plain(200, "fetch failed")
        .when(
            "169.254.169.254/latest/meta-data",
            200,
            "ami-id\ninstance-id\nhostname\npublic-keys/",
        )
        .build();
    let verdict = run(&check, &ssrf_point(), &host).await;

    assert_eq!(verdict.outcome, Outcome::Vulnerable);
    assert_eq!(verdict.poc_hint, None);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ssrf_never_calls_sleep() {
    let loaded = Loaded::load("check-ssrf.rhai").expect("loads");
    assert!(
        !loaded.source().contains("sleep("),
        "a check never blocks the engine on a clock"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ssrf_uses_probe_send_not_a_handbuilt_query() {
    let loaded = Loaded::load("check-ssrf.rhai").expect("loads");
    let source = loaded.source();
    assert!(source.contains("probe."), "the check probes its own point");
    assert!(!source.contains("http.send"));
    assert!(
        !source.contains("url_encode("),
        "the lane owns the encoding, not the check"
    );
    assert!(!source.contains("add_command"));
}
