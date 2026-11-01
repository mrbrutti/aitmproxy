//! Behaviour of the shared matcher. AC-R1/AC-R2 cover wildcard/regex URL
//! matching (against the full URL and the path; the per-case contract lives in
//! `url_match_cases.rs`) and invalid-regex rejection; the remaining tests pin
//! every other branch F3/F9/Map depend on (host, phase, method, ws_dir, enabled,
//! protocol).

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::SystemTime;

use aitm_core::{
    Body, ConnInfo, Flow, FlowId, FlowMeta, HeaderMap, HttpFlow, HttpRequest, HttpVersion,
    InterceptState, WsDir, WsFlow,
};
use aitm_rules::{
    check_rule_count, compile, HostMatch, MatchCondition, Phase, Rule, RuleError, UrlMatch,
};

fn conn() -> ConnInfo {
    ConnInfo {
        peer: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
        sni: None,
        alpn: None,
        tls: false,
        established: SystemTime::now(),
    }
}

/// An HTTP flow with the given method, authority and request path over `https`.
fn http_flow_full(method: &str, authority: &str, path: &str) -> Flow {
    http_flow_scheme("https", method, authority, path)
}

/// An HTTP flow with every URL-bearing request field chosen by the caller.
fn http_flow_scheme(scheme: &str, method: &str, authority: &str, path: &str) -> Flow {
    Flow::Http(HttpFlow {
        id: FlowId::new(),
        request: HttpRequest {
            method: method.into(),
            scheme: scheme.into(),
            authority: authority.into(),
            path: path.into(),
            version: HttpVersion::Http11,
            headers: HeaderMap::new(),
            body: Body::Empty,
            timestamp: SystemTime::now(),
        },
        response: None,
        client_conn: conn(),
        server_conn: None,
        metadata: FlowMeta::default(),
        intercept: InterceptState::Observed,
    })
}

/// An HTTP flow at `path` with a `GET`/`ex.test:443` default request.
fn http_flow(path: &str) -> Flow {
    http_flow_full("GET", "ex.test:443", path)
}

/// A WebSocket flow (its `dir` is supplied to `matches`, not read off the flow).
fn ws_flow() -> Flow {
    Flow::WebSocket(WsFlow {
        id: FlowId::new(),
        handshake: FlowId::new(),
        messages: Vec::new(),
        client_conn: conn(),
        server_conn: None,
        metadata: FlowMeta::default(),
        intercept: InterceptState::Observed,
    })
}

/// A default "match anything" condition at `Phase::Request`.
fn cond() -> MatchCondition {
    MatchCondition {
        url: None,
        method: None,
        host: None,
        phase: Phase::Request,
        ws_dir: None,
    }
}

fn rule_with(condition: MatchCondition) -> Rule {
    Rule {
        id: "r1".into(),
        name: None,
        enabled: true,
        condition,
    }
}

fn rule(url: UrlMatch) -> Rule {
    rule_with(MatchCondition {
        url: Some(url),
        ..cond()
    })
}

// --- AC-R1 / AC-R2: URL matching (full URL or path) + invalid regex ---------

#[test]
fn wildcard_login_matches() {
    let compiled = compile(rule(UrlMatch::Wildcard("*/login".into()))).expect("valid wildcard");
    assert!(compiled.matches(&http_flow("/api/login"), Phase::Request, None));
    assert!(!compiled.matches(&http_flow("/api/logout"), Phase::Request, None));
}

#[test]
fn regex_users_matches() {
    let compiled = compile(rule(UrlMatch::Regex("^/v[0-9]+/users$".into()))).expect("valid regex");
    assert!(compiled.matches(&http_flow("/v2/users"), Phase::Request, None));
    assert!(!compiled.matches(&http_flow("/v2/users/1"), Phase::Request, None));
}

#[test]
fn invalid_regex_rejected() {
    let err = compile(rule(UrlMatch::Regex("[unterminated".into())))
        .expect_err("invalid regex must be rejected, not panic");
    assert!(matches!(err, RuleError::BadRegex { .. }));
}

#[test]
fn oversized_regex_rejected() {
    // AC10: a bounded repetition that compiles to well past the 1 MiB cap. URL
    // regexes compile case-insensitively, so this exercises the cap on the
    // folded program.
    let err = compile(rule(UrlMatch::Regex("a{1000}{1000}{100}".into())))
        .expect_err("a pattern over the size cap must be rejected, not balloon");
    assert!(matches!(err, RuleError::BadRegex { .. }));
    // The pattern is valid syntax, so the rejection must come from the cap, not
    // the parser; a `BadRegex` alone would also pass for a syntax error.
    assert!(
        err.to_string().contains("size limit"),
        "rejection must name the size cap: {err}"
    );
}

#[test]
fn oversized_wildcards_rejected_under_size_cap() {
    // Spec Constraints: agent-supplied patterns are rejected, never panic, never
    // balloon. A wildcard is compiled through the same capped builder, so a
    // pathological one that fits under the byte cap is still rejected like a
    // regex: a run of stars compiles to a `.*` program per star, and 4096 of
    // them blow the 1 MiB cap. Anything longer never reaches the builder
    // (`PatternTooLong`, pinned in `patterns_over_4096_bytes_are_rejected`).
    let stars = "*".repeat(4096);
    let err = compile(rule(UrlMatch::Wildcard(stars)))
        .expect_err("a 4096-star wildcard must be rejected under the size cap");
    assert!(matches!(err, RuleError::BadRegex { .. }));
    assert!(
        err.to_string().contains("size limit"),
        "rejection must name the size cap: {}",
        err.to_string().chars().take(120).collect::<String>()
    );

    // A long-but-realistic pattern (a 4 KiB literal path) still compiles and
    // matches: `*` plus a 4095-byte path is exactly 4096 bytes.
    let long_path = format!("/{}", "x".repeat(4094));
    let pattern = format!("*{long_path}");
    assert_eq!(pattern.len(), 4096);
    let compiled = compile(rule(UrlMatch::Wildcard(pattern))).expect("4096-byte wildcard compiles");
    assert!(compiled.matches(&http_flow(&long_path), Phase::Request, None));
    assert!(!compiled.matches(&http_flow("/x"), Phase::Request, None));
}

#[test]
fn patterns_over_4096_bytes_are_rejected() {
    // AC18. The byte cap runs before the regex builder, so an over-long pattern
    // that is also invalid regex syntax reports its length, not the syntax
    // error, and a 256 KiB literal is turned away without being walked.
    let at_cap = "a".repeat(4096);
    compile(rule(UrlMatch::Wildcard(at_cap.clone()))).expect("a 4096-byte wildcard compiles");
    compile(rule(UrlMatch::Regex(at_cap.clone()))).expect("a 4096-byte regex compiles");
    compile(rule_with(MatchCondition {
        host: Some(HostMatch::Wildcard(at_cap)),
        ..cond()
    }))
    .expect("a 4096-byte host wildcard compiles");

    let over = format!("[{}", "a".repeat(4096)); // 4097 bytes, and unterminated
    for (what, r) in [
        ("url wildcard", rule(UrlMatch::Wildcard(over.clone()))),
        ("url regex", rule(UrlMatch::Regex(over.clone()))),
        (
            "host wildcard",
            rule_with(MatchCondition {
                host: Some(HostMatch::Wildcard(over.clone())),
                ..cond()
            }),
        ),
    ] {
        let err = compile(r).expect_err(what);
        assert_eq!(
            err,
            RuleError::PatternTooLong {
                len: 4097,
                max: 4096
            },
            "{what}"
        );
        assert_eq!(
            err.to_string(),
            "pattern is 4097 bytes; the limit is 4096",
            "{what}"
        );
    }

    for huge in ["*".repeat(50_000), "a".repeat(256 * 1024)] {
        let len = huge.len();
        let err = compile(rule(UrlMatch::Wildcard(huge))).expect_err("over the byte cap");
        assert_eq!(err, RuleError::PatternTooLong { len, max: 4096 });
    }
}

#[test]
fn pattern_cap_counts_bytes_not_chars() {
    // AC18 edge: `MAX_PATTERN_BYTES` is a byte cap, not a character cap, so a
    // multibyte pattern reaches it long before 4096 characters. U+1F600 is four
    // bytes in UTF-8: 1024 of them are exactly 4096 bytes and compile on every
    // pattern surface; 1025 (4100 bytes, far fewer than 4096 characters) are
    // turned away with the byte length in the error.
    let at_cap = "\u{1F600}".repeat(1024);
    assert_eq!(at_cap.len(), 4096);
    assert_eq!(at_cap.chars().count(), 1024);
    let compiled = compile(rule(UrlMatch::Wildcard(at_cap.clone())))
        .expect("a 4096-byte multibyte wildcard compiles");
    // Star-less, so a substring of the path: a path carrying the same run matches.
    assert!(compiled.matches(&http_flow(&format!("/{at_cap}")), Phase::Request, None));
    assert!(!compiled.matches(&http_flow("/"), Phase::Request, None));
    compile(rule(UrlMatch::Regex(at_cap.clone()))).expect("a 4096-byte multibyte regex compiles");
    compile(rule_with(MatchCondition {
        host: Some(HostMatch::Wildcard(at_cap)),
        ..cond()
    }))
    .expect("a 4096-byte multibyte host wildcard compiles");

    let over = "\u{1F600}".repeat(1025);
    assert_eq!(over.len(), 4100);
    for (what, r) in [
        ("url wildcard", rule(UrlMatch::Wildcard(over.clone()))),
        ("url regex", rule(UrlMatch::Regex(over.clone()))),
        (
            "host wildcard",
            rule_with(MatchCondition {
                host: Some(HostMatch::Wildcard(over.clone())),
                ..cond()
            }),
        ),
    ] {
        let err = compile(r).expect_err(what);
        assert_eq!(
            err,
            RuleError::PatternTooLong {
                len: 4100,
                max: 4096
            },
            "{what}: 1025 characters is under 4096, so a character cap would have accepted this"
        );
    }
}

#[test]
fn more_than_256_rules_per_call_are_rejected() {
    // AC18: the count check `flow.intercept` and `ws.intercept` both run before
    // compiling anything, so a rejected call leaves the active rules alone.
    check_rule_count(0).expect("no rules is fine");
    check_rule_count(256).expect("256 rules is the cap, inclusive");
    let err = check_rule_count(257).expect_err("257 rules is over the cap");
    assert_eq!(
        err,
        RuleError::TooManyRules {
            count: 257,
            max: 256
        }
    );
    assert_eq!(
        err.to_string(),
        "257 rules supplied; the limit is 256 per call"
    );
}

#[test]
fn empty_url_patterns_are_rejected() {
    // AC19: `bus.rs` accepts `url: ""` (a bare string is a wildcard) and
    // `{regex: ""}`, and an empty pattern is a substring of every subject, so
    // it would arm a match-everything rule by accident. The core refuses it, as
    // the macOS form already does ("Enter a URL pattern"); omit `url` to match
    // any URL.
    for clause in [
        UrlMatch::Wildcard(String::new()),
        UrlMatch::Regex(String::new()),
    ] {
        let err = compile(rule(clause)).expect_err("an empty url pattern is rejected");
        assert_eq!(err, RuleError::EmptyPattern);
        assert_eq!(
            err.to_string(),
            "empty url pattern; omit `url` to match any URL"
        );
    }
}

#[test]
fn anchored_empty_regex_matches_only_an_empty_path() {
    // `^$` can never match the full URL (it always has a scheme), so it fires
    // only through the second subject, and only when the path is empty.
    let compiled = compile(rule(UrlMatch::Regex("^$".into()))).expect("valid regex");
    assert!(compiled.matches(
        &http_flow_scheme("https", "GET", "h.test:443", ""),
        Phase::Request,
        None
    ));
    assert!(!compiled.matches(
        &http_flow_scheme("https", "GET", "h.test:443", "/"),
        Phase::Request,
        None
    ));
}

#[test]
fn url_wildcard_case_folds_beyond_ascii() {
    // Case-insensitivity is the regex crate's Unicode fold, not an ASCII
    // lowercase, so a non-ASCII letter in a path folds too (the subject is what
    // the client sent; a raw UTF-8 path is legal on the wire).
    let compiled = compile(rule(UrlMatch::Wildcard("*/caf\u{c9}*".into()))).expect("valid");
    assert!(compiled.matches(&http_flow("/caf\u{e9}/menu"), Phase::Request, None));
    assert!(!compiled.matches(&http_flow("/cafe/menu"), Phase::Request, None));
}

#[test]
fn host_and_url_clauses_combine() {
    // AC9: both clauses must hold.
    let compiled = compile(rule_with(MatchCondition {
        host: Some(HostMatch::Exact("httpbin.org".into())),
        url: Some(UrlMatch::Wildcard("*/get".into())),
        ..cond()
    }))
    .expect("valid");
    assert!(compiled.matches(
        &http_flow_scheme("http", "GET", "httpbin.org", "/get"),
        Phase::Request,
        None
    ));
    assert!(!compiled.matches(
        &http_flow_scheme("http", "GET", "httpbin.org", "/post"),
        Phase::Request,
        None
    ));
    // The url clause alone would match any host's /get; the host clause narrows it.
    assert!(!compiled.matches(
        &http_flow_scheme("http", "GET", "example.com", "/get"),
        Phase::Request,
        None
    ));
}

// --- Host matching ----------------------------------------------------------

#[test]
fn host_exact_matches() {
    let compiled = compile(rule_with(MatchCondition {
        host: Some(HostMatch::Exact("api.example.com".into())),
        ..cond()
    }))
    .expect("valid host");
    assert!(compiled.matches(
        &http_flow_full("GET", "api.example.com:443", "/"),
        Phase::Request,
        None
    ));
    assert!(!compiled.matches(
        &http_flow_full("GET", "www.example.com:443", "/"),
        Phase::Request,
        None
    ));
}

#[test]
fn host_wildcard_matches() {
    let compiled = compile(rule_with(MatchCondition {
        host: Some(HostMatch::Wildcard("*.example.com".into())),
        ..cond()
    }))
    .expect("valid host wildcard");
    assert!(compiled.matches(
        &http_flow_full("GET", "foo.example.com:443", "/"),
        Phase::Request,
        None
    ));
    assert!(!compiled.matches(
        &http_flow_full("GET", "example.net:443", "/"),
        Phase::Request,
        None
    ));
}

#[test]
fn host_wildcard_without_star_stays_exact() {
    // The url wildcard's star-less substring rule does not leak into `host`:
    // a star-less host wildcard is still the whole host.
    let compiled = compile(rule_with(MatchCondition {
        host: Some(HostMatch::Wildcard("example.com".into())),
        ..cond()
    }))
    .expect("valid host wildcard");
    assert!(compiled.matches(
        &http_flow_full("GET", "example.com:443", "/"),
        Phase::Request,
        None
    ));
    assert!(!compiled.matches(
        &http_flow_full("GET", "api.example.com:443", "/"),
        Phase::Request,
        None
    ));
}

#[test]
fn host_wildcard_is_case_insensitive() {
    // A mixed-case host pattern must still match the lowercased authority.
    let compiled = compile(rule_with(MatchCondition {
        host: Some(HostMatch::Wildcard("*.API.Example.com".into())),
        ..cond()
    }))
    .expect("valid host wildcard");
    assert!(compiled.matches(
        &http_flow_full("GET", "foo.api.example.com:443", "/"),
        Phase::Request,
        None
    ));
}

// --- Phase gating -----------------------------------------------------------

#[test]
fn phase_any_fires_at_response() {
    let compiled = compile(rule_with(MatchCondition {
        phase: Phase::Any,
        ..cond()
    }))
    .expect("valid");
    assert!(compiled.matches(&http_flow("/"), Phase::Response, None));
}

#[test]
fn request_rule_does_not_fire_at_response() {
    let compiled = compile(rule_with(cond())).expect("valid"); // phase == Request
    assert!(!compiled.matches(&http_flow("/"), Phase::Response, None));
}

// --- Method -----------------------------------------------------------------

#[test]
fn method_match_is_case_insensitive() {
    let compiled = compile(rule_with(MatchCondition {
        method: Some("post".into()),
        ..cond()
    }))
    .expect("valid");
    assert!(compiled.matches(
        &http_flow_full("POST", "ex.test:443", "/"),
        Phase::Request,
        None
    ));
    assert!(!compiled.matches(
        &http_flow_full("GET", "ex.test:443", "/"),
        Phase::Request,
        None
    ));
}

// --- WebSocket direction ----------------------------------------------------

#[test]
fn ws_dir_match_and_non_match() {
    let compiled = compile(rule_with(MatchCondition {
        phase: Phase::WsFrame,
        ws_dir: Some(WsDir::ClientToServer),
        ..cond()
    }))
    .expect("valid");
    assert!(compiled.matches(&ws_flow(), Phase::WsFrame, Some(WsDir::ClientToServer)));
    assert!(!compiled.matches(&ws_flow(), Phase::WsFrame, Some(WsDir::ServerToClient)));
}

#[test]
fn ws_flow_cannot_match_url_or_host_clause() {
    // HTTP-only clauses can't be evaluated against a WS flow → no match.
    let url_rule = compile(rule(UrlMatch::Wildcard("*".into()))).expect("valid");
    assert!(!url_rule.matches(&ws_flow(), Phase::Request, None));

    let host_rule = compile(rule_with(MatchCondition {
        host: Some(HostMatch::Exact("ex.test".into())),
        ..cond()
    }))
    .expect("valid");
    assert!(!host_rule.matches(&ws_flow(), Phase::Request, None));
}

// --- Enabled flag -----------------------------------------------------------

#[test]
fn disabled_rule_never_matches() {
    let mut r = rule(UrlMatch::Wildcard("*".into()));
    r.enabled = false;
    let compiled = compile(r).expect("valid");
    assert!(!compiled.matches(&http_flow("/anything"), Phase::Request, None));
}

// --- authority_host via host-exact behaviour (port stripped, IPv6) ----------

#[test]
fn host_exact_strips_port() {
    let compiled = compile(rule_with(MatchCondition {
        host: Some(HostMatch::Exact("ex.test".into())),
        ..cond()
    }))
    .expect("valid");
    // authority carries a port; the exact host clause (portless) must still match.
    assert!(compiled.matches(
        &http_flow_full("GET", "ex.test:8443", "/"),
        Phase::Request,
        None
    ));
}

#[test]
fn host_exact_ipv6_literal_strips_port() {
    let compiled = compile(rule_with(MatchCondition {
        host: Some(HostMatch::Exact("[::1]".into())),
        ..cond()
    }))
    .expect("valid");
    assert!(compiled.matches(
        &http_flow_full("GET", "[::1]:443", "/"),
        Phase::Request,
        None
    ));
}
