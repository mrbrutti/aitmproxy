//! Task 22: matcher evaluation (AC-L5) and extractor binding (AC-L6).

use aitm_core::Value;
use aitm_poc::extract::{run_extractors, Extractor, ExtractorKind};
use aitm_poc::matcher::{evaluate, MatchContext};
use aitm_poc::Assertion;

/// AC-L5: status/word/regex/browser-eval matchers evaluate to the expected boolean.
#[test]
fn status_word_regex_browser() {
    let ctx = MatchContext::new(200, "window.__aitm='ABC'")
        .with_browser("window.__aitm", Value::Str("ABC".into()));

    assert!(evaluate(&Assertion::Status(200), &ctx));
    assert!(!evaluate(&Assertion::Status(404), &ctx));

    assert!(evaluate(
        &Assertion::Word("window.__aitm='ABC'".into()),
        &ctx
    ));
    assert!(!evaluate(&Assertion::Word("not present".into()), &ctx));

    assert!(evaluate(&Assertion::Regex("__aitm='[A-Z]+'".into()), &ctx));
    assert!(!evaluate(&Assertion::Regex("__aitm='[0-9]+'".into()), &ctx));

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
        &Assertion::Not(Box::new(Assertion::Word("patched".into()))),
        &ctx
    ));
    assert!(!evaluate(
        &Assertion::Not(Box::new(Assertion::Word("reflected".into()))),
        &ctx
    ));

    let hit = Assertion::Status(200);
    let miss = Assertion::Status(500);

    // All: every child must hold.
    assert!(evaluate(
        &Assertion::All(vec![hit.clone(), Assertion::Word("body".into())]),
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
        &Assertion::Any(vec![miss.clone(), Assertion::Word("absent".into())]),
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
