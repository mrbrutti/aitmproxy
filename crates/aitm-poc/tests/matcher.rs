//! Task 22: matcher evaluation (AC-L5) and extractor binding (AC-L6).

use aitm_core::Value;
use aitm_poc::extract::{run_extractors, Extractor, ExtractorKind};
use aitm_poc::matcher::{evaluate, MatchContext};
use aitm_poc::{Assertion, MatchPart};

/// AC-L5: status/word/regex/browser-eval matchers evaluate to the expected boolean.
#[test]
fn status_word_regex_browser() {
    let ctx = MatchContext::new(200, "window.__aitm='ABC'")
        .with_browser("window.__aitm", Value::Str("ABC".into()));

    assert!(evaluate(&Assertion::Status(200), &ctx));
    assert!(!evaluate(&Assertion::Status(404), &ctx));

    assert!(evaluate(&Assertion::word("window.__aitm='ABC'"), &ctx));
    assert!(!evaluate(&Assertion::word("not present"), &ctx));

    assert!(evaluate(&Assertion::regex("__aitm='[A-Z]+'"), &ctx));
    assert!(!evaluate(&Assertion::regex("__aitm='[0-9]+'"), &ctx));

    assert!(evaluate(
        &Assertion::BrowserEval {
            expr: "window.__aitm".into(),
            equals: Value::Str("ABC".into()),
        },
        &ctx
    ));
    assert!(!evaluate(
        &Assertion::BrowserEval {
            expr: "window.__aitm".into(),
            equals: Value::Str("XYZ".into()),
        },
        &ctx
    ));
}

/// AC-L5: `negative` (→ Not), and `all`/`any` combine as specified.
#[test]
fn negative_and_or() {
    let ctx = MatchContext::new(200, "clean reflected body");

    // Negative matcher: true when the word is absent.
    assert!(evaluate(
        &Assertion::Not(Box::new(Assertion::word("patched"))),
        &ctx
    ));
    assert!(!evaluate(
        &Assertion::Not(Box::new(Assertion::word("reflected"))),
        &ctx
    ));

    let hit = Assertion::Status(200);
    let miss = Assertion::Status(500);

    // All: every child must hold.
    assert!(evaluate(
        &Assertion::All(vec![hit.clone(), Assertion::word("body")]),
        &ctx
    ));
    assert!(!evaluate(
        &Assertion::All(vec![hit.clone(), miss.clone()]),
        &ctx
    ));

    // Any: at least one child must hold.
    assert!(evaluate(
        &Assertion::Any(vec![miss.clone(), hit.clone()]),
        &ctx
    ));
    assert!(!evaluate(
        &Assertion::Any(vec![miss.clone(), Assertion::word("absent")]),
        &ctx
    ));
}

/// AC-L5 (R2): a `word`/`regex` matcher with `part: header` tests the response
/// headers, not the body.
#[test]
fn matcher_part_header() {
    let ctx = MatchContext::new(200, "body has no marker")
        .with_header("X-Powered-By", "Express")
        .with_header("Set-Cookie", "sid=abc; HttpOnly");

    // Body part (default) does not see the header value.
    assert!(!evaluate(&Assertion::word("Express"), &ctx));
    // Header part does.
    assert!(evaluate(
        &Assertion::Word {
            word: "Express".into(),
            part: MatchPart::Header,
        },
        &ctx
    ));
    assert!(evaluate(
        &Assertion::Regex {
            regex: "sid=[a-z0-9]+".into(),
            part: MatchPart::Header,
        },
        &ctx
    ));
    // `all` sees both body and headers.
    assert!(evaluate(
        &Assertion::Word {
            word: "body has no marker".into(),
            part: MatchPart::All,
        },
        &ctx
    ));
    assert!(evaluate(
        &Assertion::Word {
            word: "Express".into(),
            part: MatchPart::All,
        },
        &ctx
    ));
}

/// AC-L6: a named regex extractor binds a variable; `internal` keeps it out of output.
#[test]
fn regex_binds_later_var() {
    let ctx = MatchContext::new(200, r#"<input name="csrf" value="abc123">"#);

    let internal = Extractor {
        name: "csrf".into(),
        kind: ExtractorKind::Regex {
            pattern: r#"name="csrf" value="([a-f0-9]+)""#.into(),
            group: 1,
        },
        internal: true,
    };
    let out = run_extractors(std::slice::from_ref(&internal), &ctx);
    assert_eq!(out.bound.get("csrf"), Some(&Value::Str("abc123".into())));
    assert!(
        out.printed.is_empty(),
        "internal: true must keep the binding out of the printed output set"
    );

    // A non-internal extractor appears in both bound and printed.
    let public = Extractor {
        internal: false,
        ..internal
    };
    let out = run_extractors(std::slice::from_ref(&public), &ctx);
    assert_eq!(out.bound.get("csrf"), Some(&Value::Str("abc123".into())));
    assert_eq!(out.printed.get("csrf"), Some(&Value::Str("abc123".into())));
}
