//! Passive checks: deterministic heuristics over one already-captured flow's
//! response. Issues **no** new traffic — every check reads only the `flow`
//! it is handed.
//!
//! Three checks, each naming a class:
//!
//! - **reflection** — a request parameter (from [`crate::discover::enumerate`])
//!   whose value appears verbatim in the response body.
//! - **security-header** — a missing `Content-Security-Policy`,
//!   `X-Content-Type-Options`, or `Strict-Transport-Security` response header.
//! - **cookie-flag** — a `Set-Cookie` missing `Secure` or `HttpOnly`.
//!
//! Redaction is load-bearing here: [`PassiveFinding::evidence`] never carries a
//! param *value* (only the param/header *name*, already available on the
//! finding, and a fixed description of the class). A reflected secret (a
//! session id, a token echoed by a broken error page) must not be re-leaked
//! through this read-only surface.

use aitm_poc::matcher::{evaluate, MatchContext};
use aitm_poc::{Assertion, MatchPart, Severity};

use crate::discover::{enumerate, Location, REDACTED};

/// One passive finding over a single captured flow.
#[derive(Debug, Clone, PartialEq)]
pub struct PassiveFinding {
    pub class: String,
    pub flow: aitm_core::FlowId,
    pub location: Option<Location>,
    pub name: Option<String>,
    /// A description of the class/location — **never** a param or header
    /// *value* (see module docs).
    pub evidence: String,
    pub severity: Severity,
}

/// Response headers whose absence is a `security-header` finding.
const SECURITY_HEADERS: &[&str] = &[
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "Strict-Transport-Security",
];

/// Evaluate the three passive checks over `flow`. Reads only `flow`; no new
/// traffic is issued.
pub fn passive_checks(flow: &aitm_core::HttpFlow) -> Vec<PassiveFinding> {
    let mut findings = Vec::new();
    let Some(response) = &flow.response else {
        return findings;
    };

    reflection_checks(flow, response, &mut findings);
    security_header_checks(flow, response, &mut findings);
    cookie_flag_checks(flow, response, &mut findings);

    findings
}

fn reflection_checks(
    flow: &aitm_core::HttpFlow,
    response: &aitm_core::HttpResponse,
    findings: &mut Vec<PassiveFinding>,
) {
    let body = body_text(&response.body);
    let ctx = MatchContext::new(response.status, body);

    for point in enumerate(flow) {
        // A redacted or empty example carries no value to test for reflection
        // (an empty `word` would trivially "match" any non-empty body).
        if point.example == REDACTED || point.example.is_empty() {
            continue;
        }
        let assertion = Assertion::Word {
            word: point.example.clone(),
            part: MatchPart::Body,
        };
        if evaluate(&assertion, &ctx) {
            findings.push(PassiveFinding {
                class: "reflection".into(),
                flow: flow.id,
                location: Some(point.location.clone()),
                name: Some(point.name.clone()),
                evidence: "request parameter value reflected in response body".into(),
                severity: Severity::Low,
            });
        }
    }
}

fn security_header_checks(
    flow: &aitm_core::HttpFlow,
    response: &aitm_core::HttpResponse,
    findings: &mut Vec<PassiveFinding>,
) {
    for header in SECURITY_HEADERS {
        if response.headers.get(header).is_none() {
            findings.push(PassiveFinding {
                class: "security-header".into(),
                flow: flow.id,
                location: None,
                name: Some((*header).to_string()),
                evidence: format!("{header} is absent from the response"),
                severity: Severity::Info,
            });
        }
    }
}

fn cookie_flag_checks(
    flow: &aitm_core::HttpFlow,
    response: &aitm_core::HttpResponse,
    findings: &mut Vec<PassiveFinding>,
) {
    for (name, value) in response.headers.iter() {
        if !name.eq_ignore_ascii_case("set-cookie") {
            continue;
        }
        let has_secure = value
            .split(';')
            .any(|attr| attr.trim().eq_ignore_ascii_case("secure"));
        let has_http_only = value
            .split(';')
            .any(|attr| attr.trim().eq_ignore_ascii_case("httponly"));
        if has_secure && has_http_only {
            continue;
        }
        // The cookie *name* (never its value) names the finding.
        let cookie_name = value
            .split(';')
            .next()
            .and_then(|kv| kv.split_once('='))
            .map(|(k, _)| k.trim().to_string())
            .unwrap_or_default();
        findings.push(PassiveFinding {
            class: "cookie-flag".into(),
            flow: flow.id,
            location: Some(Location::Cookie),
            name: Some(cookie_name),
            evidence: "Set-Cookie missing Secure/HttpOnly".into(),
            severity: Severity::Low,
        });
    }
}

/// Read a response body as text the same way `discover.rs` reads a request
/// body: a buffered body yields its bytes (lossily decoded), a still-streaming
/// body yields nothing.
fn body_text(body: &aitm_core::Body) -> String {
    match body {
        aitm_core::Body::Bytes(b) => String::from_utf8_lossy(b).into_owned(),
        aitm_core::Body::Empty => String::new(),
        aitm_core::Body::Streamed(_) => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aitm_core::{
        Body, ConnInfo, FlowId, FlowMeta, HeaderMap, HttpFlow, HttpRequest, HttpResponse,
        HttpVersion, InterceptState,
    };
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::time::SystemTime;

    fn conn() -> ConnInfo {
        ConnInfo {
            peer: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
            sni: None,
            alpn: None,
            tls: false,
            established: SystemTime::now(),
        }
    }

    fn flow_with(
        path: &str,
        req_headers: HeaderMap,
        status: u16,
        resp_headers: HeaderMap,
        body: &str,
    ) -> HttpFlow {
        HttpFlow {
            id: FlowId::new(),
            request: HttpRequest {
                method: "GET".into(),
                scheme: "http".into(),
                authority: "target.test".into(),
                path: path.into(),
                version: HttpVersion::Http11,
                headers: req_headers,
                body: Body::Empty,
                timestamp: SystemTime::now(),
            },
            response: Some(HttpResponse {
                status,
                version: HttpVersion::Http11,
                headers: resp_headers,
                body: Body::Bytes(body.as_bytes().to_vec()),
                timestamp: SystemTime::now(),
            }),
            client_conn: conn(),
            server_conn: None,
            metadata: FlowMeta::default(),
            intercept: InterceptState::Observed,
        }
    }

    #[test]
    fn passive_flags_reflection() {
        let flow = flow_with(
            "/search?q=HELLOMARKER",
            HeaderMap::new(),
            200,
            HeaderMap::new(),
            "results for HELLOMARKER: none",
        );

        let findings = passive_checks(&flow);

        let hit = findings
            .iter()
            .find(|f| f.class == "reflection")
            .expect("a reflection finding");
        assert_eq!(hit.name, Some("q".to_string()));
    }

    #[test]
    fn passive_flags_missing_csp() {
        let flow = flow_with("/", HeaderMap::new(), 200, HeaderMap::new(), "hello");

        let findings = passive_checks(&flow);

        assert!(
            findings.iter().any(|f| f.class == "security-header"
                && f.name.as_deref() == Some("Content-Security-Policy")),
            "expected a security-header finding for the missing CSP: {findings:?}"
        );
    }

    #[test]
    fn passive_flags_insecure_cookie() {
        let mut resp_headers = HeaderMap::new();
        resp_headers.set("Set-Cookie", "sid=1");
        let flow = flow_with("/", HeaderMap::new(), 200, resp_headers, "hello");

        let findings = passive_checks(&flow);

        assert!(
            findings.iter().any(|f| f.class == "cookie-flag"),
            "expected a cookie-flag finding: {findings:?}"
        );
    }

    #[test]
    fn passive_evidence_has_no_value() {
        let flow = flow_with(
            "/search?q=abc123",
            HeaderMap::new(),
            200,
            HeaderMap::new(),
            "echo: abc123",
        );

        let findings = passive_checks(&flow);

        assert!(
            findings.iter().any(|f| f.class == "reflection"),
            "expected a reflection finding: {findings:?}"
        );
        for f in &findings {
            assert!(
                !f.evidence.contains("abc123"),
                "evidence leaked the param value: {f:?}"
            );
        }
    }
}
