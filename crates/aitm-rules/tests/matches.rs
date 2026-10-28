//! AC-R1 / AC-R2: the shared matcher does wildcard and regex URL matching and
//! rejects an invalid regex at compile time (never panics at match time).

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::SystemTime;

use aitm_core::{
    Body, ConnInfo, Flow, FlowId, FlowMeta, HeaderMap, HttpFlow, HttpRequest, HttpVersion,
    InterceptState,
};
use aitm_rules::{compile, MatchCondition, Phase, Rule, RuleError, UrlMatch};

/// An HTTP flow with the given request path (everything else is a fixed stub).
fn http_flow(path: &str) -> Flow {
    Flow::Http(HttpFlow {
        id: FlowId::new(),
        request: HttpRequest {
            method: "GET".into(),
            scheme: "https".into(),
            authority: "ex.test:443".into(),
            path: path.into(),
            version: HttpVersion::Http11,
            headers: HeaderMap::new(),
            body: Body::Empty,
            timestamp: SystemTime::now(),
        },
        response: None,
        client_conn: ConnInfo {
            peer: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
            sni: None,
            alpn: None,
            tls: false,
            established: SystemTime::now(),
        },
        server_conn: None,
        metadata: FlowMeta::default(),
        intercept: InterceptState::Observed,
    })
}

fn rule(url: UrlMatch) -> Rule {
    Rule {
        id: "r1".into(),
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
