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
use aitm_rules::{compile, HostMatch, MatchCondition, Phase, Rule, RuleError, UrlMatch};

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
    // Tester: the pattern is valid syntax, so the rejection must come from the
    // cap, not the parser; a `BadRegex` alone would also pass for a syntax error.
    assert!(
        err.to_string().contains("size limit"),
        "rejection must name the size cap: {err}"
    );
}

#[test]
fn oversized_wildcards_rejected_under_size_cap() {
    // Tester (spec Constraints: agent-supplied patterns are rejected, never
    // panic, never balloon). A wildcard is compiled through the same capped
    // builder, so a pathological one is rejected like a regex. A run of stars
    // compiles to a `.*` program per star; a huge star-less literal compiles to
    // one case-folded instruction per character. Both blow the 1 MiB cap.
    let stars = "*".repeat(50_000);
    let err = compile(rule(UrlMatch::Wildcard(stars)))
        .expect_err("a 50k-star wildcard must be rejected under the size cap");
    assert!(matches!(err, RuleError::BadRegex { .. }));
    assert!(
        err.to_string().contains("size limit"),
        "rejection must name the size cap: {}",
        err.to_string().chars().take(120).collect::<String>()
    );

    let literal = "a".repeat(256 * 1024);
    let err = compile(rule(UrlMatch::Wildcard(literal)))
        .expect_err("a 256 KiB star-less wildcard must be rejected under the size cap");
    assert!(matches!(err, RuleError::BadRegex { .. }));
    assert!(
        err.to_string().contains("size limit"),
        "rejection must name the size cap: {}",
        err.to_string().chars().take(120).collect::<String>()
    );

    // A long-but-realistic pattern (a 4 KiB path) still compiles and matches.
    let long_path = format!("/{}", "x".repeat(4096));
    let compiled = compile(rule(UrlMatch::Wildcard(format!("*{long_path}"))))
        .expect("4 KiB wildcard compiles");
    assert!(compiled.matches(&http_flow(&long_path), Phase::Request, None));
    assert!(!compiled.matches(&http_flow("/x"), Phase::Request, None));
}

#[test]
fn empty_url_patterns_match_every_http_flow() {
    // Tester: the degenerate end of the substring rule. `bus.rs` accepts
    // `url: ""` (a bare string is a wildcard) and `{regex: ""}`, and an empty
    // pattern is a substring of every subject, so both arm a match-everything
    // rule on an HTTP flow, the same as omitting `url`. The macOS form refuses
    // an empty pattern ("Enter a URL pattern") before it reaches the bus; the
    // core does not. Pinned so a change here is deliberate.
    let wildcard =
        compile(rule(UrlMatch::Wildcard(String::new()))).expect("empty wildcard compiles");
    assert!(wildcard.matches(&http_flow("/get"), Phase::Request, None));
    assert!(wildcard.matches(
        &http_flow_scheme("https", "GET", "h.test:443", ""),
        Phase::Request,
        None
    ));
    // Still an HTTP-only clause: a WebSocket flow has no URL to be a substring of.
    assert!(!wildcard.matches(&ws_flow(), Phase::Request, None));

    let regex = compile(rule(UrlMatch::Regex(String::new()))).expect("empty regex compiles");
    assert!(regex.matches(&http_flow("/get"), Phase::Request, None));
    assert!(!regex.matches(&ws_flow(), Phase::Request, None));
}

#[test]
fn anchored_empty_regex_matches_only_an_empty_path() {
    // Tester: `^$` can never match the full URL (it always has a scheme), so it
    // fires only through the second subject, and only when the path is empty.
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
    // Tester: case-insensitivity is the regex crate's Unicode fold, not an ASCII
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
