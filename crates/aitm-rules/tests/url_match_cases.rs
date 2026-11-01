//! Every case in the URL-clause case table `cases/url-match-cases.json` must get
//! the answer the table expects from `CompiledRule::matches`. The macOS Kit
//! preview (`BreakpointRuleCasesTests.swift`) reads the same file, so a preview
//! that disagrees with the core fails a test on its own side.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::SystemTime;

use aitm_core::{
    Body, ConnInfo, Flow, FlowId, FlowMeta, HeaderMap, HttpFlow, HttpRequest, HttpVersion,
    InterceptState,
};
use aitm_rules::{compile, MatchCondition, Phase, Rule, UrlMatch};
use serde_json::Value;

const CASES: &str = include_str!("cases/url-match-cases.json");

fn conn() -> ConnInfo {
    ConnInfo {
        peer: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
        sni: None,
        alpn: None,
        tls: false,
        established: SystemTime::now(),
    }
}

/// A `GET` flow with the given scheme, authority and request target (path plus
/// any query, as `HttpRequest.path` carries it).
fn get_flow(scheme: &str, authority: &str, target: &str) -> Flow {
    Flow::Http(HttpFlow {
        id: FlowId::new(),
        request: HttpRequest {
            method: "GET".into(),
            scheme: scheme.into(),
            authority: authority.into(),
            path: target.into(),
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

fn url_rule(url: UrlMatch) -> Rule {
    Rule {
        id: "case".into(),
        name: None,
        enabled: true,
        condition: MatchCondition {
            url: Some(url),
            method: None,
            host: None,
            phase: Phase::Request,
            ws_dir: None,
        },
    }
}

fn str_field<'a>(case: &'a Value, key: &str) -> &'a str {
    case.get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("case {case} lacks string field {key:?}"))
}

#[test]
fn every_case_agrees_with_the_core() {
    let doc: Value = serde_json::from_str(CASES).expect("case table is valid JSON");
    let cases = doc
        .get("cases")
        .and_then(Value::as_array)
        .expect("case table has a `cases` array");
    assert!(!cases.is_empty(), "case table `cases` must not be empty");

    let mut failures = Vec::new();
    for case in cases {
        let ac = str_field(case, "ac");
        let kind = str_field(case, "kind");
        let pattern = str_field(case, "pattern");
        let scheme = str_field(case, "scheme");
        let authority = str_field(case, "authority");
        let path = str_field(case, "path");
        let query = case.get("query").and_then(Value::as_str);
        let expect = case
            .get("expect")
            .and_then(Value::as_bool)
            .unwrap_or_else(|| panic!("case {case} lacks bool field `expect`"));

        let target = match query {
            Some(q) => format!("{path}?{q}"),
            None => path.to_string(),
        };
        let url = format!("{scheme}://{authority}{target}");

        let clause = match kind {
            "wildcard" => UrlMatch::Wildcard(pattern.into()),
            "regex" => UrlMatch::Regex(pattern.into()),
            other => panic!("case {ac} has unknown kind {other:?}"),
        };
        let compiled = compile(url_rule(clause))
            .unwrap_or_else(|e| panic!("{ac} {kind} {pattern:?} must compile: {e}"));

        let got = compiled.matches(&get_flow(scheme, authority, &target), Phase::Request, None);
        if got != expect {
            failures.push(format!(
                "{ac} {kind} {pattern:?} vs {url}: expected {expect}, got {got}"
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "{} of {} cases disagree with the core:\n  {}",
        failures.len(),
        cases.len(),
        failures.join("\n  ")
    );
}
