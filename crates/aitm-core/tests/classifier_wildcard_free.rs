//! AC4 (compile-time forcing): the three classifiers that decide what a `Frontend`
//! or a `CallerTrust` may do must stay wildcard-free `match`es.
//!
//! `CallerTrust::from`, `CallerTrust::is_trusted_control` and `audit::origin_label`
//! are the only places a new variant is forced to be classified. A `_ =>` arm (or a
//! catch-all binding such as `other =>`) in any of them would let a new variant
//! compile unclassified and silently fall into whatever the arm returns, which is
//! exactly the fail-open the single predicate exists to prevent. The `aitm-core`
//! unit tests (`ctx::trust_tests`) are wildcard-free too, but they pin the tests'
//! own tables, not these bodies; this reads the bodies themselves.

use std::fs;
use std::path::Path;

use regex::Regex;

fn read_src(rel: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(rel);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// `src` without `//` comments (line, doc and inner doc). The classifier bodies
/// hold no string containing `//`, so a plain cut is exact here.
fn strip_line_comments(src: &str) -> String {
    src.lines()
        .map(|line| line.find("//").map_or(line, |at| &line[..at]))
        .collect::<Vec<_>>()
        .join("\n")
}

/// The brace-delimited body of the first item whose text starts at `anchor`
/// (searching from `from` in `code`): everything between its outer `{` and the
/// matching `}`. Panics with the anchor named if it is not found, so a renamed
/// classifier fails loudly instead of the check passing on nothing.
fn body_of(code: &str, from: usize, anchor: &str) -> String {
    let start = code[from..]
        .find(anchor)
        .unwrap_or_else(|| panic!("classifier `{anchor}` not found; was it renamed?"))
        + from;
    let open = code[start..]
        .find('{')
        .unwrap_or_else(|| panic!("`{anchor}` has no body"))
        + start;
    let mut depth = 0usize;
    for (offset, byte) in code.as_bytes()[open..].iter().enumerate() {
        match byte {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return code[open + 1..open + offset].to_string();
                }
            }
            _ => {}
        }
    }
    panic!("`{anchor}` body never closes");
}

/// The match arms of `body` that are catch-alls: a wildcard (`_ =>`, `_ if g =>`)
/// or a bare binding (`other =>`, `mut x =>`, `ref x if g =>`), as the
/// whitespace-normalised text of each.
fn catch_all_arms(body: &str) -> Vec<String> {
    // A pattern that is a lone lowercase identifier or `_` (optionally `ref`/`mut`),
    // optionally guarded, then `=>`. A path or tuple-struct pattern
    // (`Frontend::Cli`, `Some(x)`) never matches this, so only genuine catch-alls
    // are reported.
    //
    // The guard is lazy so it stops at its own `=>` (a guard may itself hold `=`:
    // `_ if n == 1 =>`, `_ if n <= 1 =>`) and a catch-all after it is still seen,
    // and `(?s)` lets it span lines, so a guard rustfmt broke across lines is read.
    let catch_all =
        Regex::new(r"(?ms)(?:^|[{,|])\s*(?:ref\s+)?(?:mut\s+)?([a-z_][a-z0-9_]*)\s*(?:if\s.*?)?=>")
            .expect("static regex compiles");
    catch_all
        .captures_iter(body)
        .map(|c| {
            c[0].trim()
                .trim_start_matches([',', '{', '|'])
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
        })
        .collect()
}

#[test]
fn catch_all_detector_flags_wildcards_and_bindings_only() {
    // Each of these has catch-all arms: the check must report exactly these, in order,
    // whitespace-normalised.
    let flagged: &[(&str, &[&str])] = &[
        ("match x { A => 1, _ => 2 }", &["_ =>"]),
        ("match x { A => 1, other => 2 }", &["other =>"]),
        ("match x { A => 1,\n    _ if g => 2 }", &["_ if g =>"]),
        ("match x {\n    A => 1,\n    _ => 2,\n}", &["_ =>"]),
        ("match x { A | B => 1, rest => 2 }", &["rest =>"]),
        // A guard that itself contains `=`: `==`, `!=`, `<=`, `>=`.
        ("match x { A => 1, _ if n == 1 => 2 }", &["_ if n == 1 =>"]),
        (
            "match x { A => 1, other if n != 1 => 2 }",
            &["other if n != 1 =>"],
        ),
        ("match x { A => 1, _ if n <= 1 => 2 }", &["_ if n <= 1 =>"]),
        ("match x { A => 1, _ if n >= 1 => 2 }", &["_ if n >= 1 =>"]),
        // rustfmt may break a long guard across lines.
        (
            "match x {\n    A => 1,\n    _ if n\n        == 1 => 2,\n}",
            &["_ if n == 1 =>"],
        ),
        // A lazy guard stops at its own `=>`, so a catch-all after it is still seen.
        (
            "match x { A => 1, _ if g == 1 => 2, other => 3 }",
            &["_ if g == 1 =>", "other =>"],
        ),
        // Binding catch-alls: `mut x`, `ref x`, `ref mut x`, with or without a guard.
        ("match x { A => 1, mut y => 2 }", &["mut y =>"]),
        ("match x { A => 1, ref y => 2 }", &["ref y =>"]),
        ("match x { A => 1, ref mut y => 2 }", &["ref mut y =>"]),
        (
            "match x { A => 1, mut y if y == 1 => 2 }",
            &["mut y if y == 1 =>"],
        ),
        ("match x {\n    A => 1,\n    ref y => 2,\n}", &["ref y =>"]),
        ("match x { A | mut y => 1 }", &["mut y =>"]),
        // A guarded named arm is skipped, the catch-all after it is not.
        ("match x { A if n == 1 => 1, _ => 2 }", &["_ =>"]),
        (
            "match x { A => 1, b if c => 2, D => 3, _ => 4 }",
            &["b if c =>", "_ =>"],
        ),
    ];
    for (input, arms) in flagged {
        assert_eq!(
            catch_all_arms(input),
            arms.iter().map(|a| a.to_string()).collect::<Vec<_>>(),
            "wrong catch-all arms in {input:?}"
        );
    }
    // None of these does.
    for clean in [
        "match x { A => 1, B => 2 }",
        "match x { A | B => 1, C => 2 }",
        "match x { Frontend::Cli | Frontend::Operator => CallerTrust::Operator, Frontend::Mcp => CallerTrust::Agent }",
        "match x {\n    CallerTrust::Operator => true,\n    CallerTrust::Agent => false,\n}",
        // A guarded named arm is not a catch-all, whatever the guard holds.
        "match x { A if n == 1 => 1, B => 2 }",
        "match x { Frontend::Cli if n <= 1 => 1, Frontend::Mcp => 2, Frontend::Operator => 3 }",
        // Lowercase text inside an arm body is not an arm pattern.
        "match x { A => { let y = 1; y }, B => 2 }",
        "match x { A => { if a == 1 { 1 } else { 2 } }, B => 3 }",
        "match x { A => foo(a, b), B => 2 }",
    ] {
        assert_eq!(
            catch_all_arms(clean),
            Vec::<String>::new(),
            "expected no catch-all in {clean:?}"
        );
    }
}

/// One classifier to check: where it lives and what its body must name.
struct Classifier {
    /// File under the crate dir.
    file: &'static str,
    /// Text that precedes the function in that file (its `impl` header), so a
    /// same-named method elsewhere in the file is not picked up by mistake.
    scope: &'static str,
    /// The function's signature, from which its body is read.
    anchor: &'static str,
    /// Every variant the body must name (non-vacuity: proves the right body was read).
    variants: &'static [&'static str],
}

const CLASSIFIERS: &[Classifier] = &[
    Classifier {
        file: "src/ctx.rs",
        scope: "impl From<Frontend> for CallerTrust {",
        anchor: "fn from(frontend: Frontend)",
        variants: &["Frontend::Mcp", "Frontend::Cli", "Frontend::Operator"],
    },
    Classifier {
        // The `CallerTrust` impl, not `Frontend::is_trusted_control`, which
        // delegates and has no `match`.
        file: "src/ctx.rs",
        scope: "impl CallerTrust {",
        anchor: "is_trusted_control(self) -> bool",
        variants: &["CallerTrust::Operator", "CallerTrust::Agent"],
    },
    Classifier {
        file: "src/audit.rs",
        scope: "pub fn origin_label(",
        anchor: "pub fn origin_label(frontend: Frontend)",
        variants: &["Frontend::Cli", "Frontend::Mcp", "Frontend::Operator"],
    },
];

#[test]
fn the_three_classifiers_have_no_catch_all_arm() {
    for Classifier {
        file,
        scope,
        anchor,
        variants,
    } in CLASSIFIERS
    {
        let code = strip_line_comments(&read_src(file));
        let from = code
            .find(scope)
            .unwrap_or_else(|| panic!("`{scope}` not found in {file}"));
        let body = body_of(&code, from, anchor);

        // Non-vacuity: the body read is the real classifier, so it names every
        // variant it classifies.
        for variant in *variants {
            assert!(
                body.contains(variant),
                "`{anchor}` in {file} does not name {variant}; body read was:\n{body}"
            );
        }
        assert!(
            body.contains("match"),
            "`{anchor}` in {file} is not a `match`; body read was:\n{body}"
        );

        assert_eq!(
            catch_all_arms(&body),
            Vec::<String>::new(),
            "`{anchor}` in {file} has a catch-all arm. A wildcard here removes the \
             compile-time forcing function: a new variant would compile unclassified."
        );
    }
}

/// The same read-the-body pipeline the real check uses, run over source text that
/// does carry a wildcard (the way `CallerTrust::from` would look if someone added
/// `_ => CallerTrust::Operator`), proving the pipeline reports it, and stays quiet on
/// the wildcard-free twin. The real check reads files; a mutation of production code
/// is not needed to know it can fail.
#[test]
fn pipeline_reports_a_wildcard_planted_in_a_classifier_body() {
    let scope = "impl From<Frontend> for CallerTrust {";
    let anchor = "fn from(frontend: Frontend)";
    let with_wildcard = "impl From<Frontend> for CallerTrust {\n\
        fn from(frontend: Frontend) -> Self {\n\
            match frontend {\n\
                Frontend::Mcp => CallerTrust::Agent,\n\
                _ => CallerTrust::Operator,\n\
            }\n\
        }\n\
    }\n\
    impl Other { fn from(x: u8) -> u8 { match x { _ => 0 } } }\n";
    let clean = "impl From<Frontend> for CallerTrust {\n\
        fn from(frontend: Frontend) -> Self {\n\
            match frontend {\n\
                Frontend::Mcp => CallerTrust::Agent,\n\
                Frontend::Cli | Frontend::Operator => CallerTrust::Operator,\n\
            }\n\
        }\n\
    }\n\
    impl Other { fn from(x: u8) -> u8 { match x { _ => 0 } } }\n";

    for (code, expected) in [
        (with_wildcard, vec!["_ =>".to_string()]),
        // The wildcard in the unrelated `impl Other` is outside the body read.
        (clean, Vec::<String>::new()),
    ] {
        let from = code.find(scope).expect("scope present");
        let body = body_of(code, from, anchor);
        assert_eq!(catch_all_arms(&body), expected, "body read was:\n{body}");
    }
}

/// Whether `body` classifies variants itself: it holds a `match` (which also covers
/// `matches!`) or a `=>` arm. A body that only delegates holds neither.
fn classifies_variants(body: &str) -> bool {
    body.contains("match") || body.contains("=>")
}

#[test]
fn classification_detector_flags_match_and_arms_only() {
    for classifying in [
        "match self { Frontend::Mcp => false, _ => true }",
        "matches!(self, Frontend::Cli | Frontend::Operator)",
        "match self {\n    Frontend::Mcp => false,\n    Frontend::Cli | Frontend::Operator => true,\n}",
    ] {
        assert!(
            classifies_variants(classifying),
            "expected {classifying:?} to count as classifying"
        );
    }
    for delegating in [
        "CallerTrust::from(self).is_trusted_control()",
        "\n        CallerTrust::from(self)\n            .is_trusted_control()\n    ",
    ] {
        assert!(
            !classifies_variants(delegating),
            "expected {delegating:?} to count as delegating"
        );
    }
}

/// `Frontend::is_trusted_control` must delegate, not classify: it holds no `match`
/// and no `=>` arm of its own, so the answer for every variant is decided in exactly
/// one place. What it answers is pinned in `ctx::trust_tests`, not here.
#[test]
fn frontend_predicate_delegates_and_does_not_classify() {
    let code = strip_line_comments(&read_src("src/ctx.rs"));
    let from = code
        .find("impl Frontend {")
        .expect("`impl Frontend {` in ctx.rs");
    let body = body_of(&code, from, "is_trusted_control(self) -> bool");
    // Non-vacuity: a real body was read, not an empty one.
    assert!(
        !body.trim().is_empty(),
        "`Frontend::is_trusted_control` has an empty body"
    );
    assert!(
        !classifies_variants(&body),
        "`Frontend::is_trusted_control` must delegate to `CallerTrust`, not classify \
         variants itself (no `match`, no `=>`); body read was:\n{body}"
    );
}
