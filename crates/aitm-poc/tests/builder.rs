//! Task 23: `PocBuilder` parameterizes a captured flow (AC13 build side).

use std::time::SystemTime;

use aitm_core::{
    Body, ConnInfo, FlowId, FlowMeta, HeaderMap, HttpFlow, HttpRequest, HttpResponse, HttpVersion,
    InterceptState, Value,
};
use aitm_poc::builder::{PocBuilder, PocSpec, StdPocBuilder};
use aitm_poc::{Assertion, PocInfo, Severity, Step, Variable};

fn conn() -> ConnInfo {
    ConnInfo {
        peer: "127.0.0.1:0".parse().unwrap(),
        sni: None,
        alpn: None,
        tls: false,
        established: SystemTime::now(),
    }
}

/// A captured reflected-XSS flow against `http://vuln.test/search?q=<payload>`.
fn xss_flow() -> HttpFlow {
    let mut headers = HeaderMap::new();
    headers.set("Host", "vuln.test");
    HttpFlow {
        id: FlowId::new(),
        request: HttpRequest {
            method: "GET".into(),
            scheme: "http".into(),
            authority: "vuln.test".into(),
            path: "/search?q=<script>alert(1)</script>".into(),
            version: HttpVersion::Http11,
            headers,
            body: Body::Empty,
            timestamp: SystemTime::now(),
        },
        response: Some(HttpResponse {
            status: 200,
            version: HttpVersion::Http11,
            headers: HeaderMap::new(),
            body: Body::Bytes(b"<html><script>alert(1)</script></html>".to_vec()),
            timestamp: SystemTime::now(),
        }),
        client_conn: conn(),
        server_conn: None,
        metadata: FlowMeta::default(),
        intercept: InterceptState::Observed,
    }
}

/// AC13 (build): the builder replaces the concrete host/param with `{{var}}`
/// placeholders and carries the chosen `success` assertion through.
#[test]
fn build_parameterizes_flow() {
    let success = Assertion::BrowserEval {
        expr: "window.__aitm".into(),
        equals: Value::Str("MARKER".into()),
    };
    let spec = PocSpec {
        info: PocInfo {
            name: "Reflected XSS in search q".into(),
            severity: Severity::High,
            references: vec![],
            tags: vec!["xss".into()],
            cwe: Some("CWE-79".into()),
        },
        variables: vec![
            Variable {
                name: "target".into(),
                default: None,
                description: "Base URL".into(),
                required: true,
            },
            Variable {
                name: "param".into(),
                default: Some(Value::Str("q".into())),
                description: "Reflected parameter".into(),
                required: false,
            },
            Variable {
                name: "payload".into(),
                default: Some(Value::Str("<script>alert(1)</script>".into())),
                description: "XSS payload".into(),
                required: false,
            },
        ],
        success: success.clone(),
    };

    let poc = StdPocBuilder
        .build(&xss_flow(), spec)
        .expect("build succeeds");

    let Step::Http(step) = &poc.steps[0] else {
        panic!("first step must be an http step");
    };
    assert!(
        step.url.contains("{{target}}"),
        "url must be parameterized by target, got {}",
        step.url
    );
    assert!(
        step.url.contains("{{param}}"),
        "url must be parameterized by param, got {}",
        step.url
    );
    assert!(
        !step.url.contains("vuln.test"),
        "the literal host must not survive into the PoC, got {}",
        step.url
    );
    assert_eq!(
        poc.success, success,
        "the chosen success assertion is carried through"
    );
}

/// Credential headers are redacted to `{{var}}` placeholders and become required
/// variables, so a built PoC never carries a session cookie or bearer token.
#[test]
fn build_redacts_credential_headers() {
    let mut flow = xss_flow();
    flow.request.headers.set("Cookie", "sid=supersecret");
    flow.request
        .headers
        .set("Authorization", "Bearer tok-abc123");
    flow.request.headers.set("X-Trace", "keepme");

    let spec = PocSpec {
        info: PocInfo {
            name: "cred finding".into(),
            severity: Severity::Medium,
            references: vec![],
            tags: vec![],
            cwe: None,
        },
        variables: vec![],
        success: Assertion::Status(200),
    };
    let poc = StdPocBuilder.build(&flow, spec).expect("build succeeds");
    let Step::Http(step) = &poc.steps[0] else {
        panic!("http step");
    };

    let header = |name: &str| {
        step.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.clone())
    };
    assert_eq!(header("Cookie").as_deref(), Some("{{cookie}}"));
    assert_eq!(
        header("Authorization").as_deref(),
        Some("{{authorization}}")
    );
    assert_eq!(header("X-Trace").as_deref(), Some("keepme"));

    // The secret becomes a required variable with no default (must be supplied).
    for name in ["cookie", "authorization"] {
        let var = poc
            .variables
            .iter()
            .find(|v| v.name == name)
            .unwrap_or_else(|| panic!("variable {name} must be declared"));
        assert!(var.required && var.default.is_none());
    }
    // No secret value survives anywhere in the serialized PoC.
    let yaml = serde_yaml::to_string(&poc).unwrap();
    assert!(!yaml.contains("supersecret") && !yaml.contains("tok-abc123"));
}
