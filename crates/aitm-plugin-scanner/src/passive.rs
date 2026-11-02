//! Passive checks: deterministic heuristics over one already-captured flow's
//! response. Issues **no** new traffic — every check reads only the `flow`
//! it is handed.
//!
//! Three checks, each naming a class:
//!
//! - **reflection** — a query or body parameter (from [`crate::discover::enumerate`])
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

use std::borrow::Cow;

use aitm_poc::Severity;

use crate::discover::{body_bytes, enumerate, Location, REDACTED};

/// Finding class for a request parameter value reflected in the response body.
pub(crate) const CLASS_REFLECTION: &str = "reflection";
/// Finding class for a missing security response header.
pub(crate) const CLASS_SECURITY_HEADER: &str = "security-header";
/// Finding class for a `Set-Cookie` missing `Secure` and/or `HttpOnly`.
pub(crate) const CLASS_COOKIE_FLAG: &str = "cookie-flag";

/// A request value shorter than this many characters is never tested for
/// reflection: `1`, `2`, `en` appear in nearly every body and say nothing.
const REFLECTION_MIN_LEN: usize = 4;

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

/// Which responses a security header is expected on.
#[derive(Debug, Clone, Copy)]
enum AppliesTo {
    /// An HTML document response (`Content-Type` contains `text/html`).
    HtmlDocument,
    /// Any response to an `https` request (RFC 6797: a user agent ignores HSTS
    /// delivered over plain http).
    Https,
}

/// Response headers whose absence is a `security-header` finding, and the
/// responses each one is expected on.
const SECURITY_HEADERS: &[(&str, AppliesTo)] = &[
    ("Content-Security-Policy", AppliesTo::HtmlDocument),
    ("X-Content-Type-Options", AppliesTo::HtmlDocument),
    ("Strict-Transport-Security", AppliesTo::Https),
];

/// Evaluate the three passive checks over `flow`. Reads only `flow`; no new
/// traffic is issued.
pub fn passive_checks(flow: &aitm_core::HttpFlow) -> Vec<PassiveFinding> {
    let Some(response) = &flow.response else {
        return Vec::new();
    };

    let mut findings = reflection_checks(flow, response);
    findings.extend(security_header_checks(flow, response));
    findings.extend(cookie_flag_checks(flow, response));
    findings
}

fn reflection_checks(
    flow: &aitm_core::HttpFlow,
    response: &aitm_core::HttpResponse,
) -> Vec<PassiveFinding> {
    // Read the body once; every point is tested against the same text.
    let body = body_text(&response.body);
    let mut findings = Vec::new();

    for point in enumerate(flow) {
        // Reflection is scoped to user-controllable request parameters — the
        // same locations the active reflected-XSS check injects into. A path
        // segment (whose "name" is its value, so it could leak) and a request
        // header (`Connection`, `Accept-Language`, ... coincidentally echo in
        // bodies) are not free-form app input here, so they stay out of scope
        // and quiet.
        if !matches!(point.location, Location::Query | Location::BodyParam) {
            continue;
        }
        // A redacted example carries no value to test; a value under the floor
        // (which includes an empty one, trivially "contained" in any body) is
        // boilerplate noise.
        if point.example == REDACTED || point.example.chars().count() < REFLECTION_MIN_LEN {
            continue;
        }
        if body.contains(point.example.as_str()) {
            findings.push(PassiveFinding {
                class: CLASS_REFLECTION.into(),
                flow: flow.id,
                location: Some(point.location),
                name: Some(point.name),
                evidence: "request parameter value reflected in response body".into(),
                severity: Severity::Low,
            });
        }
    }
    findings
}

fn security_header_checks(
    flow: &aitm_core::HttpFlow,
    response: &aitm_core::HttpResponse,
) -> Vec<PassiveFinding> {
    let is_https = flow.request.scheme.eq_ignore_ascii_case("https");
    let is_html = response
        .headers
        .get("Content-Type")
        .is_some_and(|ct| ct.to_ascii_lowercase().contains("text/html"));

    SECURITY_HEADERS
        .iter()
        .filter(|(_, applies_to)| match applies_to {
            AppliesTo::HtmlDocument => is_html,
            AppliesTo::Https => is_https,
        })
        .filter(|(header, _)| !response.headers.has(header))
        .map(|(header, _)| PassiveFinding {
            class: CLASS_SECURITY_HEADER.into(),
            flow: flow.id,
            location: None,
            name: Some((*header).to_string()),
            evidence: format!("{header} is absent from the response"),
            severity: Severity::Info,
        })
        .collect()
}

fn cookie_flag_checks(
    flow: &aitm_core::HttpFlow,
    response: &aitm_core::HttpResponse,
) -> Vec<PassiveFinding> {
    let mut findings = Vec::new();
    for (name, value) in response.headers.iter() {
        if !name.eq_ignore_ascii_case("set-cookie") {
            continue;
        }
        let mut parts = value.split(';');
        // RFC 6265 5.2: a `Set-Cookie` whose name-value pair has no `=` is
        // ignored by the user agent, so its flags are moot.
        let Some((cookie_name, _value)) = parts.next().and_then(|pair| pair.split_once('=')) else {
            continue;
        };
        let has_attr = |wanted: &str| {
            value
                .split(';')
                .skip(1)
                .any(|attr| attr.trim().eq_ignore_ascii_case(wanted))
        };
        let missing = match (has_attr("secure"), has_attr("httponly")) {
            (true, true) => continue,
            (true, false) => "HttpOnly",
            (false, true) => "Secure",
            (false, false) => "Secure and HttpOnly",
        };
        // The cookie *name* (never its value) names the finding; an empty name
        // is no name at all.
        let cookie_name = cookie_name.trim();
        findings.push(PassiveFinding {
            class: CLASS_COOKIE_FLAG.into(),
            flow: flow.id,
            location: Some(Location::Cookie),
            name: (!cookie_name.is_empty()).then(|| cookie_name.to_string()),
            evidence: format!("Set-Cookie missing {missing}"),
            severity: Severity::Low,
        });
    }
    findings
}

/// Read a response body as text through the same helper `discover.rs` reads a
/// request body with: a buffered body yields its bytes (lossily decoded,
/// borrowed when already valid UTF-8), a still-streaming body yields nothing.
fn body_text(body: &aitm_core::Body) -> Cow<'_, str> {
    body_bytes(body)
        .map(String::from_utf8_lossy)
        .unwrap_or_default()
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
                trailers: HeaderMap::new(),
                body: Body::Bytes(body.as_bytes().to_vec()),
                timestamp: SystemTime::now(),
                peer: None,
            }),
            client_conn: conn(),
            server_conn: None,
            metadata: FlowMeta::default(),
            intercept: InterceptState::Observed,
        }
    }

    /// Build a header map from literal pairs (a repeated name is kept twice).
    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.set(name, value);
        }
        map
    }

    /// The findings of one class, in emission order.
    fn of_class<'a>(findings: &'a [PassiveFinding], class: &str) -> Vec<&'a PassiveFinding> {
        findings.iter().filter(|f| f.class == class).collect()
    }

    /// The `name` of every finding of one class.
    fn names_of(findings: &[PassiveFinding], class: &str) -> Vec<Option<String>> {
        of_class(findings, class)
            .iter()
            .map(|f| f.name.clone())
            .collect()
    }

    // ----- reflection ------------------------------------------------------

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

        let hits = of_class(&findings, CLASS_REFLECTION);
        assert_eq!(
            hits.len(),
            1,
            "exactly one reflection finding: {findings:?}"
        );
        assert_eq!(hits[0].name, Some("q".to_string()));
        assert_eq!(hits[0].location, Some(Location::Query));
    }

    #[test]
    fn reflection_flags_a_real_reflected_value() {
        let flow = flow_with(
            "/search?q=searchtermxyz",
            HeaderMap::new(),
            200,
            HeaderMap::new(),
            "<p>you searched for searchtermxyz</p>",
        );

        let findings = passive_checks(&flow);

        assert_eq!(
            names_of(&findings, CLASS_REFLECTION),
            vec![Some("q".to_string())],
            "exactly one reflection finding, named q: {findings:?}"
        );
    }

    /// The quality reviewer's probe: a short query value (`page=1`), an empty
    /// one (`q=`), a numeric path segment (`2`), and request headers are all
    /// quiet — including the `keep-alive` header value echoed verbatim in the
    /// body, because request headers are out of reflection's scope (only query
    /// and body parameters are user-controllable app input here).
    #[test]
    fn reflection_is_not_noisy() {
        let flow = flow_with(
            "/products/2/items?page=1&q=",
            headers(&[
                ("Upgrade-Insecure-Requests", "1"),
                ("Connection", "keep-alive"),
            ]),
            200,
            HeaderMap::new(),
            "page 1 of 12, 2 items; keep-alive docs",
        );

        let findings = passive_checks(&flow);

        assert_eq!(
            of_class(&findings, CLASS_REFLECTION),
            Vec::<&PassiveFinding>::new(),
            "no reflection findings expected: {findings:?}"
        );
    }

    #[test]
    fn reflection_ignores_values_below_the_floor() {
        // `abc` is one char under REFLECTION_MIN_LEN; `abcd` is exactly on it.
        let below = flow_with(
            "/s?q=abc",
            HeaderMap::new(),
            200,
            HeaderMap::new(),
            "echo abc",
        );
        let on_floor = flow_with(
            "/s?q=abcd",
            HeaderMap::new(),
            200,
            HeaderMap::new(),
            "echo abcd",
        );

        assert_eq!(REFLECTION_MIN_LEN, 4);
        assert!(
            of_class(&passive_checks(&below), CLASS_REFLECTION).is_empty(),
            "a 3-char value is below the floor"
        );
        assert_eq!(
            names_of(&passive_checks(&on_floor), CLASS_REFLECTION),
            vec![Some("q".to_string())],
            "a 4-char value is on the floor and is flagged"
        );
    }

    #[test]
    fn reflection_skips_numeric_path_segments() {
        let flow = flow_with(
            "/reset/482913",
            HeaderMap::new(),
            200,
            HeaderMap::new(),
            "resetting account 482913",
        );

        let findings = passive_checks(&flow);

        assert!(
            of_class(&findings, CLASS_REFLECTION).is_empty(),
            "a numeric path id is not user-controlled free text: {findings:?}"
        );
    }

    #[test]
    fn reflection_ignores_a_param_that_is_not_reflected() {
        let flow = flow_with(
            "/search?q=searchtermxyz",
            HeaderMap::new(),
            200,
            HeaderMap::new(),
            "no results",
        );

        let findings = passive_checks(&flow);

        assert!(
            of_class(&findings, CLASS_REFLECTION).is_empty(),
            "the value is absent from the body: {findings:?}"
        );
    }

    #[test]
    fn reflection_ignores_an_empty_param_value() {
        let flow = flow_with(
            "/search?q=",
            HeaderMap::new(),
            200,
            HeaderMap::new(),
            "a non-empty body",
        );

        let findings = passive_checks(&flow);

        assert!(
            of_class(&findings, CLASS_REFLECTION).is_empty(),
            "an empty value trivially matches any body and must be skipped: {findings:?}"
        );
    }

    /// A secret-named param arrives as the `<redacted>` placeholder; even a body
    /// that literally contains that placeholder must not look like a reflection.
    #[test]
    fn reflection_skips_a_redacted_example() {
        let flow = flow_with(
            "/s?session=reflectedvalue123",
            HeaderMap::new(),
            200,
            HeaderMap::new(),
            "echo reflectedvalue123 and <redacted>",
        );

        let findings = passive_checks(&flow);

        assert!(
            of_class(&findings, CLASS_REFLECTION).is_empty(),
            "a redacted example must never be tested for reflection: {findings:?}"
        );
    }

    // ----- security headers --------------------------------------------------

    /// An HTML response over https: every security header applies.
    fn https_html_flow(resp_headers: &[(&str, &str)]) -> HttpFlow {
        let mut all = vec![("Content-Type", "text/html; charset=utf-8")];
        all.extend_from_slice(resp_headers);
        let mut flow = flow_with("/", HeaderMap::new(), 200, headers(&all), "hello");
        flow.request.scheme = "https".into();
        flow
    }

    #[test]
    fn passive_flags_missing_csp() {
        let flow = https_html_flow(&[]);

        let findings = passive_checks(&flow);

        assert_eq!(
            names_of(&findings, CLASS_SECURITY_HEADER),
            vec![
                Some("Content-Security-Policy".to_string()),
                Some("X-Content-Type-Options".to_string()),
                Some("Strict-Transport-Security".to_string()),
            ],
            "all three security headers are missing on an https HTML response: {findings:?}"
        );
    }

    #[test]
    fn security_headers_present_yield_no_finding() {
        // Lower-case names: header lookup is case-insensitive.
        let flow = https_html_flow(&[
            ("content-security-policy", "default-src 'self'"),
            ("x-content-type-options", "nosniff"),
            ("strict-transport-security", "max-age=31536000"),
        ]);

        let findings = passive_checks(&flow);

        assert!(
            of_class(&findings, CLASS_SECURITY_HEADER).is_empty(),
            "all three headers are present: {findings:?}"
        );
    }

    #[test]
    fn security_headers_flag_only_the_missing_one() {
        let flow = https_html_flow(&[
            ("Content-Security-Policy", "default-src 'self'"),
            ("Strict-Transport-Security", "max-age=31536000"),
        ]);

        let findings = passive_checks(&flow);

        assert_eq!(
            names_of(&findings, CLASS_SECURITY_HEADER),
            vec![Some("X-Content-Type-Options".to_string())],
            "exactly the absent header is flagged: {findings:?}"
        );
    }

    /// RFC 6797: a user agent ignores HSTS delivered over plain http, so its
    /// absence there is not a finding.
    #[test]
    fn hsts_is_not_flagged_over_http() {
        let mut flow = https_html_flow(&[]);
        flow.request.scheme = "http".into();

        let findings = passive_checks(&flow);

        assert_eq!(
            names_of(&findings, CLASS_SECURITY_HEADER),
            vec![
                Some("Content-Security-Policy".to_string()),
                Some("X-Content-Type-Options".to_string()),
            ],
            "no HSTS finding for an http flow: {findings:?}"
        );
    }

    /// CSP and nosniff are about documents; a JSON (or typeless) response does
    /// not owe them.
    #[test]
    fn csp_and_nosniff_are_not_flagged_on_a_non_html_response() {
        for content_type in [Some("application/json"), None] {
            let resp_headers: Vec<(&str, &str)> = content_type
                .map(|ct| vec![("Content-Type", ct)])
                .unwrap_or_default();
            let mut flow = flow_with("/", HeaderMap::new(), 200, headers(&resp_headers), "{}");
            flow.request.scheme = "https".into();

            let findings = passive_checks(&flow);

            assert_eq!(
                names_of(&findings, CLASS_SECURITY_HEADER),
                vec![Some("Strict-Transport-Security".to_string())],
                "only HSTS applies to a non-HTML https response ({content_type:?}): {findings:?}"
            );
        }
    }

    // ----- cookie flags ------------------------------------------------------

    fn cookie_findings(set_cookie: &[&str]) -> Vec<PassiveFinding> {
        let pairs: Vec<(&str, &str)> = set_cookie.iter().map(|v| ("Set-Cookie", *v)).collect();
        let flow = flow_with("/", HeaderMap::new(), 200, headers(&pairs), "hello");
        passive_checks(&flow)
            .into_iter()
            .filter(|f| f.class == CLASS_COOKIE_FLAG)
            .collect()
    }

    #[test]
    fn passive_flags_insecure_cookie() {
        let findings = cookie_findings(&["sid=1"]);

        assert_eq!(findings.len(), 1, "one cookie finding: {findings:?}");
        assert_eq!(findings[0].name, Some("sid".to_string()));
        assert_eq!(findings[0].location, Some(Location::Cookie));
        assert_eq!(
            findings[0].evidence,
            "Set-Cookie missing Secure and HttpOnly"
        );
    }

    #[test]
    fn cookie_with_both_flags_yields_no_finding() {
        for cookie in ["sid=1; Secure; HttpOnly", "sid=1; secure; httponly"] {
            let findings = cookie_findings(&[cookie]);

            assert!(
                findings.is_empty(),
                "`{cookie}` carries both flags (case-insensitive): {findings:?}"
            );
        }
    }

    #[test]
    fn cookie_finding_names_the_missing_flag() {
        let no_http_only = cookie_findings(&["sid=1; Secure"]);
        let no_secure = cookie_findings(&["sid=1; HttpOnly; Path=/"]);

        assert_eq!(no_http_only.len(), 1, "{no_http_only:?}");
        assert_eq!(no_http_only[0].evidence, "Set-Cookie missing HttpOnly");
        assert_eq!(no_secure.len(), 1, "{no_secure:?}");
        assert_eq!(no_secure[0].evidence, "Set-Cookie missing Secure");
    }

    #[test]
    fn each_set_cookie_header_is_judged_on_its_own() {
        let findings = cookie_findings(&["a=1; Secure; HttpOnly", "b=2", "c=3; Secure"]);

        assert_eq!(
            findings.iter().map(|f| f.name.clone()).collect::<Vec<_>>(),
            vec![Some("b".to_string()), Some("c".to_string())],
            "{findings:?}"
        );
    }

    #[test]
    fn malformed_set_cookie_never_yields_an_empty_name() {
        // No `=`: a user agent ignores the header, so it is not a finding.
        let no_equals = cookie_findings(&["justaflag; Secure"]);
        // An empty name keeps the finding but carries no name.
        let empty_name = cookie_findings(&["=v; Secure"]);

        assert!(no_equals.is_empty(), "{no_equals:?}");
        assert_eq!(empty_name.len(), 1, "{empty_name:?}");
        assert_eq!(empty_name[0].name, None);
    }

    // ----- shape + redaction ---------------------------------------------------

    #[test]
    fn no_response_yields_no_findings() {
        let mut flow = flow_with(
            "/search?q=HELLOMARKER",
            HeaderMap::new(),
            200,
            HeaderMap::new(),
            "",
        );
        flow.response = None;

        assert_eq!(passive_checks(&flow), Vec::<PassiveFinding>::new());
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

        assert_eq!(
            of_class(&findings, CLASS_REFLECTION).len(),
            1,
            "expected one reflection finding: {findings:?}"
        );
        for f in &findings {
            assert!(
                !f.evidence.contains("abc123"),
                "evidence leaked the param value: {f:?}"
            );
        }
    }

    /// AC3: no secret value reaches any field of any finding.
    #[test]
    fn passive_leaks_no_secret() {
        let mut flow = flow_with(
            "/reset/482913?access_token=abc123secret&note=plainvalue",
            headers(&[
                ("Cookie", "PHPSESSID=abc123secret"),
                ("Authorization", "Bearer tok_abc123secret"),
            ]),
            200,
            headers(&[
                ("Content-Type", "text/html"),
                ("Set-Cookie", "PHPSESSID=abc123secret"),
            ]),
            "token abc123secret, account 482913, plainvalue, auth Bearer tok_abc123secret",
        );
        flow.request.scheme = "https".into();

        let findings = passive_checks(&flow);

        // Not vacuous: every check class fired on this flow, and each names its
        // subject (a param, a header, a cookie) without carrying a value.
        assert_eq!(
            names_of(&findings, CLASS_REFLECTION),
            vec![Some("note".to_string())],
            "{findings:?}"
        );
        assert_eq!(
            names_of(&findings, CLASS_COOKIE_FLAG),
            vec![Some("PHPSESSID".to_string())],
            "{findings:?}"
        );
        assert_eq!(
            of_class(&findings, CLASS_SECURITY_HEADER).len(),
            3,
            "{findings:?}"
        );
        let dump = format!("{findings:?}");
        for secret in ["abc123secret", "482913"] {
            assert!(
                !dump.contains(secret),
                "`{secret}` leaked into the findings: {dump}"
            );
        }
    }
}
