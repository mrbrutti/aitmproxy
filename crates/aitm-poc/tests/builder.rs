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
            trailers: HeaderMap::new(),
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
            description: None,
            author: None,
            metadata: None,
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
            description: None,
            author: None,
            metadata: None,
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

// --- credential scrubbing: mask real credentials WITHOUT destroying the
// injection payload or corrupting a JSON body (regression for the #123 scrubber
// over-scrubbing reported against the scanner) ---------------------------------

/// A captured flow against `path`, with an optional request body.
fn flow_with(path: &str, body: Body) -> HttpFlow {
    let mut headers = HeaderMap::new();
    headers.set("Host", "vuln.test");
    HttpFlow {
        id: FlowId::new(),
        request: HttpRequest {
            method: "POST".into(),
            scheme: "http".into(),
            authority: "vuln.test".into(),
            path: path.into(),
            version: HttpVersion::Http11,
            headers,
            body,
            timestamp: SystemTime::now(),
        },
        response: Some(HttpResponse {
            status: 200,
            version: HttpVersion::Http11,
            headers: HeaderMap::new(),
            trailers: HeaderMap::new(),
            body: Body::Empty,
            timestamp: SystemTime::now(),
        }),
        client_conn: conn(),
        server_conn: None,
        metadata: FlowMeta::default(),
        intercept: InterceptState::Observed,
    }
}

/// `target` + `param=q` only — the injection point is at some *other* key, as when
/// the agent calls `poc.build` without naming the real injection parameter.
fn basic_spec() -> PocSpec {
    PocSpec {
        info: PocInfo {
            name: "scan finding".into(),
            severity: Severity::High,
            references: vec![],
            tags: vec![],
            cwe: None,
            description: None,
            author: None,
            metadata: None,
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
                description: "injection parameter".into(),
                required: false,
            },
        ],
        success: Assertion::Status(200),
    }
}

fn http_step(poc: &aitm_poc::Poc) -> &aitm_poc::HttpStep {
    match &poc.steps[0] {
        Step::Http(s) => s,
        _ => panic!("http step"),
    }
}

fn var(name: &str, default: Option<&str>, required: bool) -> Variable {
    Variable {
        name: name.into(),
        default: default.map(|d| Value::Str(d.into())),
        description: String::new(),
        required,
    }
}

/// Redaction is BY KEY, not value shape: a credential at a secret-named key is
/// masked even when it carries metacharacters (security review: a value-shape
/// heuristic leaked `password=P@ss/w0rd!` and base64-with-`/`).
#[test]
fn build_redacts_special_char_credential_at_secret_key() {
    for (q, secret) in [
        ("/login?password=P@ss/w0rd!&q=hi", "P@ss/w0rd!"),
        ("/api?api_key=AbC/dEf+gh12&q=hi", "AbC/dEf+gh12"),
    ] {
        let poc = StdPocBuilder
            .build(&flow_with(q, Body::Empty), basic_spec())
            .expect("build");
        let url = &http_step(&poc).url;
        assert!(url.contains("[redacted]"), "secret not masked: {url}");
        assert!(!url.contains(secret), "credential leaked: {url}");
    }
}

/// A real credential at a secret-named query key is masked (keep #123).
#[test]
fn build_redacts_real_credential_in_query() {
    let flow = flow_with("/api?access_token=sk-realtoken123&q=hi", Body::Empty);
    let poc = StdPocBuilder.build(&flow, basic_spec()).expect("build");
    let url = &http_step(&poc).url;
    assert!(!url.contains("sk-realtoken123"), "credential leaked: {url}");
    assert!(
        url.contains("access_token=[redacted]"),
        "credential not masked: {url}"
    );
}

/// The declared injection point survives: parameterized to `{{payload}}` at a
/// secret-named key, it is exempt from redaction so the PoC still reproduces (this
/// is how a payload at a secret point is kept — not by guessing value shape).
#[test]
fn build_preserves_declared_payload_placeholder() {
    let spec = PocSpec {
        info: basic_spec().info,
        variables: vec![
            var("target", None, true),
            var("param", Some("return_token"), false),
            var("payload", Some("https://sentinel.invalid/"), false),
        ],
        success: Assertion::Status(200),
    };
    let flow = flow_with("/cb?return_token=https://sentinel.invalid/", Body::Empty);
    let url = http_step(&StdPocBuilder.build(&flow, spec).expect("build"))
        .url
        .clone();
    assert!(
        url.contains("{{payload}}"),
        "declared payload dropped: {url}"
    );
    assert!(
        !url.contains("[redacted]"),
        "declared payload redacted: {url}"
    );
}

/// A credential embedded in a non-secret URL-valued parameter is masked (spec
/// review Critical: `next=…?access_token=…` must not leak), while the redirect
/// target itself survives.
#[test]
fn build_redacts_embedded_credential_in_url_valued_param() {
    let flow = flow_with(
        "/go?next=https://app.example/cb?access_token=LEAKME99&q=hi",
        Body::Empty,
    );
    let url = http_step(&StdPocBuilder.build(&flow, basic_spec()).expect("build"))
        .url
        .clone();
    assert!(
        !url.contains("LEAKME99"),
        "embedded credential leaked: {url}"
    );
    assert!(
        url.contains("next=https://app.example/cb"),
        "the redirect target must survive: {url}"
    );
}

/// A form-encoded `password=` body is masked, the non-secret field is kept (#123).
#[test]
fn build_redacts_form_body_password() {
    let flow = flow_with(
        "/login",
        Body::Bytes(b"user=admin&password=hunter2".to_vec()),
    );
    let out = http_step(&StdPocBuilder.build(&flow, basic_spec()).expect("build"))
        .body
        .clone()
        .expect("a body");
    assert_eq!(out, "user=admin&password=[redacted]", "got {out}");
}

/// A JSON body stays valid; string, numeric, nested, and embedded-bearer secrets are
/// masked; a non-secret field and a payload at a non-secret key survive. This is the
/// #123 JSON-corruption fix (a secret value no longer eats the surrounding `"}`).
#[test]
fn build_scrubs_json_body_keeping_it_valid() {
    let body = Body::Bytes(
        br#"{"user":"admin","password":"P@ss w0rd","token":1234,"nested":{"api_key":"JSONKEY2"},"note":"Bearer JSONBEARER3","q":"<script>alert(1)</script>"}"#
            .to_vec(),
    );
    let out = http_step(
        &StdPocBuilder
            .build(&flow_with("/submit", body), basic_spec())
            .expect("build"),
    )
    .body
    .clone()
    .expect("a body");
    let p: serde_json::Value =
        serde_json::from_str(&out).unwrap_or_else(|e| panic!("not valid JSON: {e}: {out}"));
    assert_eq!(p["user"], serde_json::json!("admin"), "non-secret survives");
    assert_eq!(
        p["password"],
        serde_json::json!("[redacted]"),
        "special-char password masked"
    );
    assert_eq!(
        p["token"],
        serde_json::json!("[redacted]"),
        "numeric secret masked"
    );
    assert_eq!(
        p["nested"]["api_key"],
        serde_json::json!("[redacted]"),
        "nested secret masked"
    );
    assert_eq!(
        p["q"],
        serde_json::json!("<script>alert(1)</script>"),
        "payload at a non-secret key survives"
    );
    assert!(
        p["note"].as_str().unwrap().contains("[redacted]"),
        "embedded bearer masked: {out}"
    );
    assert!(
        !out.contains("JSONKEY2") && !out.contains("JSONBEARER3") && !out.contains("P@ss w0rd"),
        "a credential leaked: {out}"
    );
}

/// A declared payload placeholder at a secret JSON key survives, document valid.
#[test]
fn build_json_preserves_declared_payload_placeholder() {
    let flow = flow_with(
        "/login",
        Body::Bytes(br#"{"password":"{{payload}}"}"#.to_vec()),
    );
    let out = http_step(&StdPocBuilder.build(&flow, basic_spec()).expect("build"))
        .body
        .clone()
        .expect("a body");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&out).unwrap()["password"],
        serde_json::json!("{{payload}}")
    );
}

/// A credential embedded in a kept (non-secret) header is scrubbed (#123 Referer).
#[test]
fn build_scrubs_credential_in_referer_header() {
    let mut flow = flow_with("/go?q=hi", Body::Empty);
    flow.request
        .headers
        .set("Referer", "http://target.test/app?access_token=REFSECRET1");
    let poc = StdPocBuilder.build(&flow, basic_spec()).expect("build");
    let referer = http_step(&poc)
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("referer"))
        .map(|(_, v)| v.clone())
        .unwrap_or_default();
    assert!(
        !referer.contains("REFSECRET1"),
        "referer credential leaked: {referer}"
    );
}

/// A secret under a secret-named key must not escape via a non-secret sub-key or an
/// array element: the whole subtree is secret (security re-review).
#[test]
fn build_redacts_nested_secret_under_secret_key() {
    let body = Body::Bytes(
        br#"{"token":{"v":"sk-REALSECRET"},"api_keys":["sk-AAAA","sk-BBBB"],"ok":{"n":1}}"#
            .to_vec(),
    );
    let out = http_step(
        &StdPocBuilder
            .build(&flow_with("/submit", body), basic_spec())
            .expect("build"),
    )
    .body
    .clone()
    .expect("a body");
    let p: serde_json::Value =
        serde_json::from_str(&out).unwrap_or_else(|e| panic!("not valid JSON: {e}: {out}"));
    assert_eq!(
        p["token"]["v"],
        serde_json::json!("[redacted]"),
        "nested secret masked"
    );
    assert_eq!(p["api_keys"][0], serde_json::json!("[redacted]"));
    assert_eq!(p["api_keys"][1], serde_json::json!("[redacted]"));
    assert_eq!(
        p["ok"]["n"],
        serde_json::json!(1),
        "non-secret subtree untouched"
    );
    assert!(
        !out.contains("sk-REALSECRET") && !out.contains("sk-AAAA") && !out.contains("sk-BBBB"),
        "a nested credential leaked: {out}"
    );
}

/// The session / jwt / csrf family is masked even on a directly-captured flow
/// (poc.build runs on any stored flow), while a key that merely *contains* a needle
/// as a substring (`inside` ⊃ `sid`) is not over-matched.
#[test]
fn build_redacts_session_family_keys() {
    let url = http_step(
        &StdPocBuilder
            .build(
                &flow_with("/cb?sid=SESSION123&q=hi", Body::Empty),
                basic_spec(),
            )
            .expect("build"),
    )
    .url
    .clone();
    assert!(!url.contains("SESSION123"), "sid leaked: {url}");
    assert!(url.contains("sid=[redacted]"), "sid not masked: {url}");

    let out = http_step(
        &StdPocBuilder
            .build(
                &flow_with(
                    "/x",
                    Body::Bytes(br#"{"jwt":"realjwt","inside":"keep"}"#.to_vec()),
                ),
                basic_spec(),
            )
            .expect("build"),
    )
    .body
    .clone()
    .expect("a body");
    let p: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(p["jwt"], serde_json::json!("[redacted]"), "jwt masked");
    assert_eq!(
        p["inside"],
        serde_json::json!("keep"),
        "`inside` must not match the `sid` needle"
    );
}

/// A credential header not in the fixed SECRET_HEADERS list (X-Auth-Token) is still
/// placeholdered via the widened key check.
#[test]
fn build_redacts_non_listed_credential_header() {
    let mut flow = flow_with("/x?q=hi", Body::Empty);
    flow.request.headers.set("X-Auth-Token", "sk-headersecret");
    let poc = StdPocBuilder.build(&flow, basic_spec()).expect("build");
    let header = http_step(&poc)
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("x-auth-token"))
        .map(|(_, v)| v.clone());
    assert_eq!(
        header.as_deref(),
        Some("{{x_auth_token}}"),
        "X-Auth-Token not placeholdered"
    );
    assert!(!serde_yaml::to_string(&poc)
        .unwrap()
        .contains("sk-headersecret"));
}

/// A declared `{{payload}}` placeholder at a secret-named QUERY key is preserved
/// (the URL placeholder-exemption branch).
#[test]
fn build_preserves_placeholder_at_secret_query_key() {
    let spec = PocSpec {
        info: basic_spec().info,
        variables: vec![
            var("target", None, true),
            var("payload", Some("PAYLOAD_VAL"), false),
        ],
        success: Assertion::Status(200),
    };
    // parameterize_url rewrites the literal `PAYLOAD_VAL` to `{{payload}}`, so the
    // secret-named `token` key then carries a placeholder, which must survive.
    let flow = flow_with("/cb?token=PAYLOAD_VAL", Body::Empty);
    let url = http_step(&StdPocBuilder.build(&flow, spec).expect("build"))
        .url
        .clone();
    assert!(
        url.contains("token={{payload}}"),
        "placeholder at a secret key dropped: {url}"
    );
    assert!(
        !url.contains("[redacted]"),
        "placeholder at a secret key redacted: {url}"
    );
}

/// A JSON-shaped body that fails to parse (a truncated capture, a trailing comma)
/// must still have its credentials masked — never emitted verbatim. The structural
/// path only fires for VALID JSON, so a broken body used to fall through unscrubbed
/// and re-leak a #123-class credential (security re-review Important).
#[test]
fn build_scrubs_credential_in_unparseable_json_body() {
    for body in [
        &br#"{"password":"hunter2",}"#[..], // trailing comma -> invalid JSON
        &br#"{"api_key":"sk-SECRET","x":"#[..], // truncated capture
    ] {
        assert!(
            serde_json::from_slice::<serde_json::Value>(body).is_err(),
            "test body must be invalid JSON to exercise the fallback"
        );
        let out = http_step(
            &StdPocBuilder
                .build(
                    &flow_with("/submit", Body::Bytes(body.to_vec())),
                    basic_spec(),
                )
                .expect("build"),
        )
        .body
        .clone()
        .expect("a body");
        assert!(out.contains("[redacted]"), "nothing masked: {out}");
        assert!(
            !out.contains("hunter2") && !out.contains("sk-SECRET"),
            "credential leaked from unparseable JSON: {out}"
        );
    }
}

/// A body that starts with `[` reads as JSON-shaped, which blocks the form branch; if
/// it is really form data it must still be scrubbed, not returned verbatim (security
/// re-review: `[x]=1&password=…` leaked).
#[test]
fn build_scrubs_credential_in_bracket_prefixed_body() {
    let flow = flow_with("/x", Body::Bytes(b"[x]=1&password=hunter2".to_vec()));
    let out = http_step(&StdPocBuilder.build(&flow, basic_spec()).expect("build"))
        .body
        .clone()
        .expect("a body");
    assert!(!out.contains("hunter2"), "credential leaked: {out}");
    assert!(out.contains("[redacted]"), "not masked: {out}");
}

/// An opaque (non-JSON, non-form) body runs through the free-text safety net, so an
/// embedded credential is masked — while a credential-free attack payload, carrying no
/// `key=`/`Bearer`/`Authorization` framing, is left intact.
#[test]
fn build_scrubs_embedded_credential_in_opaque_body() {
    let flow = flow_with(
        "/x",
        Body::Bytes(b"raw blob Authorization: Bearer sk-OPAQUE1 end".to_vec()),
    );
    let out = http_step(&StdPocBuilder.build(&flow, basic_spec()).expect("build"))
        .body
        .clone()
        .expect("a body");
    assert!(
        !out.contains("sk-OPAQUE1"),
        "embedded credential leaked: {out}"
    );

    let payload = "<svg/onload=xss(1)>";
    let flow = flow_with("/y", Body::Bytes(payload.as_bytes().to_vec()));
    let out = http_step(&StdPocBuilder.build(&flow, basic_spec()).expect("build"))
        .body
        .clone()
        .expect("a body");
    assert_eq!(out, payload, "credential-free payload must survive: {out}");
}

/// A JWT / session id embedded in a kept (non-secret) `Referer` header is masked with
/// the builder's WIDER vocabulary — the shared `scrub_text` set lacks jwt/sid, and the
/// task anti-goal names Referer JWTs as must-redact (security re-review).
#[test]
fn build_scrubs_jwt_and_sid_in_referer_header() {
    let mut flow = flow_with("/go?q=hi", Body::Empty);
    flow.request.headers.set(
        "Referer",
        "http://app.test/cb?jwt=eyJLEAK.aaa.bbb&sid=SIDLEAK&ok=1",
    );
    let poc = StdPocBuilder.build(&flow, basic_spec()).expect("build");
    let referer = http_step(&poc)
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("referer"))
        .map(|(_, v)| v.clone())
        .unwrap_or_default();
    assert!(
        !referer.contains("eyJLEAK") && !referer.contains("SIDLEAK"),
        "referer jwt/sid leaked: {referer}"
    );
    assert!(
        referer.contains("ok=1"),
        "non-secret param must survive: {referer}"
    );
}

/// A JWT embedded in a `next=` redirect param (a non-secret query key) is masked with
/// the wider vocabulary, while the redirect target survives.
#[test]
fn build_scrubs_jwt_in_next_param() {
    let flow = flow_with(
        "/go?next=https://app.test/cb?jwt=eyJLEAK.aaa.bbb&q=hi",
        Body::Empty,
    );
    let url = http_step(&StdPocBuilder.build(&flow, basic_spec()).expect("build"))
        .url
        .clone();
    assert!(!url.contains("eyJLEAK"), "embedded jwt leaked: {url}");
    assert!(
        url.contains("next=https://app.test/cb"),
        "redirect target must survive: {url}"
    );
}

/// A concatenated session-cookie key name (`PHPSESSID`, `JSESSIONID`) is a single
/// token the SEGMENT match misses; the substring rule still masks it, in a URL query
/// and in a JSON body (security re-review Minor).
#[test]
fn build_redacts_concatenated_session_cookie_name() {
    let url = http_step(
        &StdPocBuilder
            .build(
                &flow_with("/a?PHPSESSID=SESSSECRET&q=hi", Body::Empty),
                basic_spec(),
            )
            .expect("build"),
    )
    .url
    .clone();
    assert!(!url.contains("SESSSECRET"), "PHPSESSID leaked: {url}");
    assert!(
        url.contains("PHPSESSID=[redacted]"),
        "PHPSESSID not masked: {url}"
    );

    let out = http_step(
        &StdPocBuilder
            .build(
                &flow_with("/b", Body::Bytes(br#"{"JSESSIONID":"JSECRET"}"#.to_vec())),
                basic_spec(),
            )
            .expect("build"),
    )
    .body
    .clone()
    .expect("a body");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&out).unwrap()["JSESSIONID"],
        serde_json::json!("[redacted]"),
        "JSESSIONID not masked: {out}"
    );
}

/// The csrf / auth needles (mirrored from the scanner's Scrubber vocabulary the builder
/// matches) are masked: a `csrf` value and a bare `auth` value do not ride into a PoC.
/// `auth` earns its own needle — the shared `token` needle would not catch a bare `auth`.
#[test]
fn build_redacts_csrf_and_auth_keys() {
    let out = http_step(
        &StdPocBuilder
            .build(
                &flow_with(
                    "/x",
                    Body::Bytes(
                        br#"{"csrf":"CSRFSECRET","auth":"AUTHSECRET","keep":"ok"}"#.to_vec(),
                    ),
                ),
                basic_spec(),
            )
            .expect("build"),
    )
    .body
    .clone()
    .expect("a body");
    let p: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(
        p["csrf"],
        serde_json::json!("[redacted]"),
        "csrf masked: {out}"
    );
    assert_eq!(
        p["auth"],
        serde_json::json!("[redacted]"),
        "auth masked: {out}"
    );
    assert_eq!(p["keep"], serde_json::json!("ok"), "non-secret survives");
    assert!(
        !out.contains("CSRFSECRET") && !out.contains("AUTHSECRET"),
        "a credential leaked: {out}"
    );
}

/// A declared payload placeholder at a secret key INSIDE an embedded redirect URL is
/// preserved, not eaten by the free-text pass (security re-review: `next=…?token={{payload}}`
/// used to become `token=[redacted]}}`).
#[test]
fn build_preserves_placeholder_in_embedded_url() {
    let spec = PocSpec {
        info: basic_spec().info,
        variables: vec![
            var("target", None, true),
            var("payload", Some("https://evil.test/x"), false),
        ],
        success: Assertion::Status(200),
    };
    // parameterize_url rewrites the payload literal to {{payload}} wherever it appears,
    // including inside the embedded `next=` URL's secret-named `token` param.
    let flow = flow_with(
        "/go?next=https://app.test/cb?token=https://evil.test/x",
        Body::Empty,
    );
    let url = http_step(&StdPocBuilder.build(&flow, spec).expect("build"))
        .url
        .clone();
    assert!(
        url.contains("token={{payload}}"),
        "embedded placeholder dropped: {url}"
    );
    assert!(
        !url.contains("[redacted]"),
        "embedded placeholder redacted: {url}"
    );
}

/// A credential hidden in a shadowed DUPLICATE JSON key does not ride into the PoC: the
/// structural scrub reserializes the parsed (deduplicated) document, dropping the shadow.
/// (Security re-review: a raw-bytes "nothing redacted" shortcut re-leaked it, because the
/// parse keeps only the last `note` and so never saw the credential in the first.)
#[test]
fn build_drops_credential_in_duplicate_json_key() {
    let flow = flow_with(
        "/x",
        Body::Bytes(br#"{"note":"Bearer sk-SHADOWSECRET","note":"ok"}"#.to_vec()),
    );
    let out = http_step(&StdPocBuilder.build(&flow, basic_spec()).expect("build"))
        .body
        .clone()
        .expect("a body");
    assert!(
        !out.contains("sk-SHADOWSECRET"),
        "shadowed credential leaked: {out}"
    );
    // The surviving (last-wins) value is kept, and the body stays valid JSON.
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&out).unwrap()["note"],
        serde_json::json!("ok")
    );
}

/// A credential nested under a secret parent (`auth:`, a line break, then `password: v`) is
/// masked on every surface the builder scrubs: the url, a JSON body (an object value and an
/// array element), a form body and a text body. Each surface is its own flow, and the canary
/// of each is absent from the serialized PoC.
#[test]
fn build_masks_a_credential_nested_under_a_secret_parent_on_every_surface() {
    let body_of = |poc: &aitm_poc::Poc| http_step(poc).body.clone().expect("a body");

    // url: the path carries a real line break.
    let poc = StdPocBuilder
        .build(
            &flow_with("/go?q=hello&note=auth:\n  password: URLPW1", Body::Empty),
            basic_spec(),
        )
        .expect("build");
    assert_eq!(
        http_step(&poc).url,
        "{{target}}/go?{{param}}=hello&note=auth:\n  [redacted] [redacted]"
    );
    assert!(
        !serde_json::to_string(&poc).unwrap().contains("URLPW1"),
        "url canary leaked"
    );

    // JSON: the escapes are JSON text, decoded by the parse.
    let json_body =
        r#"{"note":"auth:\n  password: JSONPW2","list":["credentials:\r\n\tsecret: JSONSEC9"]}"#;
    let poc = StdPocBuilder
        .build(
            &flow_with("/x", Body::Bytes(json_body.as_bytes().to_vec())),
            basic_spec(),
        )
        .expect("build");
    let out = body_of(&poc);
    let parsed: serde_json::Value =
        serde_json::from_str(&out).unwrap_or_else(|e| panic!("not valid JSON: {e}: {out}"));
    assert_eq!(
        parsed,
        serde_json::json!({
            "note": "auth:\n  [redacted] [redacted]",
            "list": ["credentials:\r\n\t[redacted] [redacted]"]
        }),
        "json body: {out}"
    );
    let serialized = serde_json::to_string(&poc).unwrap();
    assert!(
        !serialized.contains("JSONPW2") && !serialized.contains("JSONSEC9"),
        "json canary leaked"
    );

    // form
    let poc = StdPocBuilder
        .build(
            &flow_with(
                "/x",
                Body::Bytes(b"note=auth:\n  password: FORMPW3&page=2".to_vec()),
            ),
            basic_spec(),
        )
        .expect("build");
    assert_eq!(
        body_of(&poc),
        "note=auth:\n  [redacted] [redacted]&page=2",
        "form body"
    );
    assert!(
        !serde_json::to_string(&poc).unwrap().contains("FORMPW3"),
        "form canary leaked"
    );

    // text
    let poc = StdPocBuilder
        .build(
            &flow_with("/x", Body::Bytes(b"auth:\n  password: RAWPW4".to_vec())),
            basic_spec(),
        )
        .expect("build");
    assert_eq!(body_of(&poc), "auth:\n  [redacted] [redacted]", "text body");
    assert!(
        !serde_json::to_string(&poc).unwrap().contains("RAWPW4"),
        "text canary leaked"
    );
}

/// A nested credential in a header the builder keeps (its name is not a secret), on one line
/// and across a tab and a no-break space (a header value cannot hold a line break:
/// `HeaderMap::set` drops it); in a query value, where the pair has no blank to read across;
/// and in a body a connection dropped mid-stream, cut at every byte (a multi-byte character
/// split included). No canary survives in any of them.
#[test]
fn build_masks_a_nested_credential_in_a_header_a_query_value_and_a_body_cut_at_every_byte() {
    // Headers: the value is content-scrubbed as free text.
    let mut flow = flow_with("/go?q=hello", Body::Empty);
    flow.request.headers.set("X-Note", "auth: password: HDRPW5");
    flow.request
        .headers
        .set("X-Trace", "auth:\t\u{a0}password: HDRPW6");
    let poc = StdPocBuilder.build(&flow, basic_spec()).expect("build");
    let step = http_step(&poc);
    let header = |name: &str| {
        step.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    };
    assert_eq!(header("X-Note"), Some("auth: [redacted] [redacted]"));
    assert_eq!(
        header("X-Trace"),
        Some("auth:\t\u{a0}[redacted] [redacted]")
    );
    let serialized = serde_json::to_string(&poc).unwrap();
    assert!(
        !serialized.contains("HDRPW5") && !serialized.contains("HDRPW6"),
        "header canary leaked"
    );

    // A query value with the blanks percent-encoded is one token, masked whole.
    let poc = StdPocBuilder
        .build(
            &flow_with(
                "/go?q=hello&note=auth:%0A%20%20password:%20QRYPW7",
                Body::Empty,
            ),
            basic_spec(),
        )
        .expect("build");
    assert_eq!(
        http_step(&poc).url,
        "{{target}}/go?{{param}}=hello&note=auth:[redacted]"
    );
    assert!(
        !serde_json::to_string(&poc).unwrap().contains("QRYPW7"),
        "query canary leaked"
    );

    // The body, cut at every byte. `\u{e9}` is two bytes and `\u{1f600}` four, so some
    // cuts split a character and the lossy decode puts U+FFFD there.
    let body = "auth:\n  password: \u{e9}QQQQ\u{1f600}".as_bytes();
    let mut cuts = 0;
    let mut leaks: Vec<(usize, String)> = Vec::new();
    for cut in 0..=body.len() {
        let poc = StdPocBuilder
            .build(
                &flow_with("/x", Body::Bytes(body[..cut].to_vec())),
                basic_spec(),
            )
            .expect("build");
        let text = http_step(&poc).body.clone().unwrap_or_default();
        cuts += 1;
        if text.contains('Q') {
            leaks.push((cut, text));
        }
    }
    assert!(cuts >= 25, "the body is too short: {cuts} cuts");
    assert!(leaks.is_empty(), "a credential survived a cut: {leaks:#?}");
    let poc = StdPocBuilder
        .build(&flow_with("/x", Body::Bytes(body.to_vec())), basic_spec())
        .expect("build");
    assert_eq!(
        http_step(&poc).body.as_deref(),
        Some("auth:\n  [redacted] [redacted]")
    );
}

/// An opaque body of a mebibyte or more with a nested pair on every other line: the scrub
/// finishes, masks every canary and keeps the line structure. The count is clamped to a body of
/// at most two mebibytes before the repeat.
#[test]
fn build_masks_a_nested_credential_in_an_oversized_opaque_body() {
    const UNIT: &str = "auth:\n  password: BIGPW8\n";
    const FLOOR: usize = 1 << 20;
    const CEILING: usize = 1 << 21;
    let copies = (FLOOR / UNIT.len() + 1).min(CEILING / UNIT.len());
    let body = UNIT.repeat(copies);
    assert!(body.len() >= FLOOR && body.len() <= CEILING);

    let poc = StdPocBuilder
        .build(
            &flow_with("/x", Body::Bytes(body.into_bytes())),
            basic_spec(),
        )
        .expect("build");
    let text = http_step(&poc).body.clone().expect("a body");
    assert!(
        !text.contains("BIGPW8"),
        "a canary of the large body leaked"
    );
    assert!(
        text == "auth:\n  [redacted] [redacted]\n".repeat(copies),
        "the large body was not masked line by line"
    );
}
