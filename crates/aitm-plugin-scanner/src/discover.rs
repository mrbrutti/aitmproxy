//! Injection-point discovery: given one captured HTTP flow, enumerate the
//! candidate injection points from the request shape alone.
//!
//! This reads ONLY the passed flow — never a test-target manifest or any other
//! out-of-band source. The same request shape a client could observe is all the
//! scanner is allowed to see.
//!
//! Credentials never leave here. **Every** cookie point carries [`REDACTED`] as
//! its example — a cookie value is session or credential material whatever its
//! name (`PHPSESSID`, `sid`, `JSESSIONID`), so no name list is trusted to spot
//! it. A header, query or body point whose *name* reads as a secret
//! ([`aitm_core::redact::is_secret_key`] — `Authorization`, `token`, `api-key`,
//! `password`, … — widened locally by [`is_secret_name`] with the common auth
//! parameter names) is redacted the same way. So an auth header or session
//! cookie seen in captured traffic cannot reach a structured `scan.*` result.

use std::collections::HashSet;

use aitm_core::redact::is_secret_key;
use aitm_core::Body;

/// The example value a secret-named injection point carries.
pub const REDACTED: &str = "<redacted>";

/// Auth-parameter name fragments the shared vocabulary in `aitm_core::redact`
/// does not carry, matched the same way (case-insensitive substring). They
/// over-match on purpose (`sid` catches `subsidiary`): a redacted example costs
/// nothing, a leaked session id does. `pub(crate)` so `reproduce`'s embedded-value
/// scrub is built from this very slice rather than a second copy of the list.
pub(crate) const EXTRA_SECRET_NEEDLES: &[&str] = &["sid", "jwt", "csrf", "session", "auth"];

/// Whether a header / query / body parameter name reads as a secret: the shared
/// vocabulary plus [`EXTRA_SECRET_NEEDLES`]. `pub(crate)` so `reproduce`'s PoC
/// scrubber masks exactly the names `enumerate` redacts here — one vocabulary.
pub(crate) fn is_secret_name(name: &str) -> bool {
    if is_secret_key(name) {
        return true;
    }
    let lower = name.to_ascii_lowercase();
    EXTRA_SECRET_NEEDLES
        .iter()
        .any(|needle| lower.contains(needle))
}

/// Upper bound on the injection points enumerated from one flow. A hostile
/// client can POST a multi-megabyte body of distinct parameters; past this many
/// points the rest are dropped rather than enumerated.
const MAX_POINTS_PER_FLOW: usize = 1024;

/// Where a candidate injection point lives in the request.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Location {
    /// A `?k=v` query-string parameter.
    Query,
    /// A top-level key in a form-urlencoded or JSON object body.
    BodyParam,
    /// A request header (other than `Cookie`).
    Header,
    /// A single cookie parsed from the `Cookie` header.
    Cookie,
    /// A numeric object-id path segment.
    PathSegment,
    /// A query or body parameter whose value is a URL (open-redirect candidate).
    Redirect,
}

impl Location {
    /// The lowercase wire token for this location.
    pub fn as_str(&self) -> &'static str {
        match self {
            Location::Query => "query",
            Location::BodyParam => "body_param",
            Location::Header => "header",
            Location::Cookie => "cookie",
            Location::PathSegment => "path_segment",
            Location::Redirect => "redirect",
        }
    }
}

/// One candidate injection point discovered in a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InjectionPoint {
    /// The flow this point was discovered in.
    pub flow: aitm_core::FlowId,
    /// Where the point lives.
    pub location: Location,
    /// The parameter / header / segment name.
    pub name: String,
    /// The observed value (or segment) at that point, or [`REDACTED`] for every
    /// cookie and for any other point whose name reads as a secret.
    pub example: String,
}

/// Enumerate candidate injection points from the request shape of `flow`.
///
/// Reads ONLY the passed flow. Never calls any `aitm_testtarget` API. At most
/// [`MAX_POINTS_PER_FLOW`] points are returned, deduplicated on
/// `(location, name)`; every cookie's example, and the example of any other
/// secret-named point, is [`REDACTED`].
pub fn enumerate(flow: &aitm_core::HttpFlow) -> Vec<InjectionPoint> {
    let id = flow.id;
    let req = &flow.request;
    let mut points: Vec<InjectionPoint> = Vec::new();
    // O(1) dedupe: a linear scan per point is quadratic in the parameter count,
    // which a single large captured body controls.
    let mut seen: HashSet<(Location, String)> = HashSet::new();
    let mut push = |location: Location, name: String, example: String| {
        if points.len() >= MAX_POINTS_PER_FLOW {
            return;
        }
        if !seen.insert((location.clone(), name.clone())) {
            return;
        }
        // A cookie is credential material regardless of its name; everything
        // else is redacted when its name says so.
        let example = if location == Location::Cookie || is_secret_name(&name) {
            REDACTED.to_string()
        } else {
            example
        };
        points.push(InjectionPoint {
            flow: id,
            location,
            name,
            example,
        });
    };

    // Split the path into the raw path and its query string.
    let (raw_path, query) = match req.path.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (req.path.as_str(), None),
    };

    // Query parameters, percent-decoded: a browser-encoded
    // `next=https%3A%2F%2Fevil.test` is an open-redirect candidate, not a plain
    // query parameter.
    if let Some(query) = query {
        for (name, value) in form_pairs(query) {
            push(classify(&value, Location::Query), name, value);
        }
    }

    // Numeric object-id path segments.
    for segment in raw_path.split('/').filter(|s| !s.is_empty()) {
        if segment.bytes().all(|b| b.is_ascii_digit()) {
            push(
                Location::PathSegment,
                segment.to_string(),
                segment.to_string(),
            );
        }
    }

    // Body parameters (form-urlencoded, or the top-level keys of a JSON object).
    if let Some(bytes) = body_bytes(&req.body) {
        let ctype = req.headers.get("content-type").unwrap_or("");
        if ctype.contains("application/x-www-form-urlencoded") {
            if let Ok(text) = std::str::from_utf8(bytes) {
                for (name, value) in form_pairs(text) {
                    push(classify(&value, Location::BodyParam), name, value);
                }
            }
        } else if ctype.contains("application/json") {
            for (name, value) in json_pairs(bytes) {
                push(classify(&value, Location::BodyParam), name, value);
            }
        }
    }

    // Cookies and other headers.
    for (name, value) in req.headers.iter() {
        if name.eq_ignore_ascii_case("cookie") {
            for (cname, cvalue) in cookie_pairs(value) {
                push(Location::Cookie, cname, cvalue);
            }
        } else if name.eq_ignore_ascii_case("host") {
            // A pseudo/host header the client does not control; skip it.
            continue;
        } else {
            push(Location::Header, name.to_string(), value.to_string());
        }
    }

    points
}

/// A URL-valued parameter is an open-redirect candidate wherever it was found;
/// anything else keeps its own location.
fn classify(value: &str, default: Location) -> Location {
    if is_url(value) {
        Location::Redirect
    } else {
        default
    }
}

/// Whether `value` looks like a URL for open-redirect purposes.
fn is_url(value: &str) -> bool {
    value.starts_with("http://") || value.starts_with("https://") || value.starts_with("//")
}

/// Read body bytes the way `detail.rs` does: buffered bodies yield their bytes,
/// a still-streaming body yields nothing. Shared with `passive.rs` so request
/// and response bodies are read identically.
pub(crate) fn body_bytes(body: &Body) -> Option<&[u8]> {
    match body {
        Body::Bytes(b) => Some(b.as_slice()),
        Body::Empty => Some(&[]),
        Body::Streamed(_) => None,
    }
}

/// Parse an `application/x-www-form-urlencoded` string (a query string or a form
/// body) into decoded `name`/`value` pairs, the way a browser encodes one: `%xx`
/// is decoded and `+` is a space. Empty names are skipped and the count is
/// capped at [`MAX_POINTS_PER_FLOW`].
fn form_pairs(input: &str) -> Vec<(String, String)> {
    url::form_urlencoded::parse(input.as_bytes())
        .filter(|(name, _)| !name.is_empty())
        .take(MAX_POINTS_PER_FLOW)
        .map(|(name, value)| (name.into_owned(), value.into_owned()))
        .collect()
}

/// Split a `Cookie` header into its `name=value` pairs. Cookie values are not
/// form-encoded, so they are taken verbatim; entries without a `=`, and empty
/// names, are skipped.
fn cookie_pairs(input: &str) -> Vec<(String, String)> {
    input
        .split(';')
        .filter_map(|pair| {
            let (k, v) = pair.trim().split_once('=')?;
            let k = k.trim();
            if k.is_empty() {
                return None;
            }
            Some((k.to_string(), v.trim().to_string()))
        })
        .take(MAX_POINTS_PER_FLOW)
        .collect()
}

/// The **top-level** keys of a JSON object body, with scalar values rendered as
/// text and nested values as their compact JSON. Anything that is not a JSON
/// object (an array, a scalar, malformed bytes) yields nothing; a nested key is
/// never reported as a top-level parameter.
fn json_pairs(bytes: &[u8]) -> Vec<(String, String)> {
    let Ok(serde_json::Value::Object(map)) = serde_json::from_slice::<serde_json::Value>(bytes)
    else {
        return Vec::new();
    };
    map.into_iter()
        .take(MAX_POINTS_PER_FLOW)
        .map(|(name, value)| {
            let text = match value {
                serde_json::Value::String(s) => s,
                other => other.to_string(),
            };
            (name, text)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use aitm_core::{
        Body, ConnInfo, FlowId, FlowMeta, HeaderMap, HttpFlow, HttpRequest, HttpVersion,
        InterceptState,
    };
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::time::{Instant, SystemTime};

    fn conn() -> ConnInfo {
        ConnInfo {
            peer: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
            sni: None,
            alpn: None,
            tls: false,
            established: SystemTime::now(),
        }
    }

    fn captured(path: &str, headers: HeaderMap) -> HttpFlow {
        captured_body(path, headers, Body::Empty)
    }

    fn captured_body(path: &str, headers: HeaderMap, body: Body) -> HttpFlow {
        HttpFlow {
            id: FlowId::new(),
            request: HttpRequest {
                method: "GET".into(),
                scheme: "http".into(),
                authority: "ex.test".into(),
                path: path.into(),
                version: HttpVersion::Http11,
                headers,
                body,
                timestamp: SystemTime::now(),
            },
            response: None,
            client_conn: conn(),
            server_conn: None,
            metadata: FlowMeta::default(),
            intercept: InterceptState::Observed,
        }
    }

    fn has(points: &[InjectionPoint], location: Location, name: &str) -> bool {
        points
            .iter()
            .any(|p| p.location == location && p.name == name)
    }

    fn example_of(points: &[InjectionPoint], location: Location, name: &str) -> String {
        points
            .iter()
            .find(|p| p.location == location && p.name == name)
            .map(|p| p.example.clone())
            .unwrap_or_else(|| panic!("no {location:?} point named {name}: {points:?}"))
    }

    #[test]
    fn enumerate_finds_query_body_cookie_path() {
        let mut headers = HeaderMap::new();
        headers.set("Cookie", "sid=abc");
        let flow = captured("/account/2/profile?q=1&next=http://x", headers);

        let points = enumerate(&flow);

        assert_eq!(points.len(), 4, "exactly four points: {points:?}");
        assert!(has(&points, Location::Query, "q"), "query q present");
        assert!(
            has(&points, Location::Redirect, "next"),
            "redirect next present"
        );
        assert!(
            has(&points, Location::PathSegment, "2"),
            "numeric path segment 2 present"
        );
        assert!(has(&points, Location::Cookie, "sid"), "cookie sid present");
        assert!(
            !has(&points, Location::PathSegment, "account"),
            "non-numeric segment account absent"
        );
        assert!(
            !has(&points, Location::PathSegment, "profile"),
            "non-numeric segment profile absent"
        );
        assert!(
            !has(&points, Location::Header, "Cookie"),
            "the Cookie header is not also emitted as a Header point"
        );
    }

    /// A browser percent-encodes a URL-valued parameter; the open-redirect
    /// candidate must survive the encoding.
    #[test]
    fn enumerate_classifies_encoded_url_value_as_redirect() {
        let flow = captured("/go?next=https%3A%2F%2Fevil.test%2Fpwn", HeaderMap::new());

        let points = enumerate(&flow);

        assert_eq!(points.len(), 1, "one point: {points:?}");
        assert!(
            has(&points, Location::Redirect, "next"),
            "the decoded value is a URL, so the point is a redirect: {points:?}"
        );
        assert_eq!(
            example_of(&points, Location::Redirect, "next"),
            "https://evil.test/pwn",
            "the example is the decoded value"
        );
    }

    #[test]
    fn enumerate_finds_form_body_params() {
        let mut headers = HeaderMap::new();
        headers.set("Content-Type", "application/x-www-form-urlencoded");
        let flow = captured_body(
            "/login",
            headers,
            Body::Bytes(b"user=alice&where=http%3A%2F%2Fx.test%2F&note=a+b".to_vec()),
        );

        let points = enumerate(&flow);

        assert_eq!(points.len(), 4, "three body params + content-type header");
        assert_eq!(example_of(&points, Location::BodyParam, "user"), "alice");
        assert_eq!(example_of(&points, Location::BodyParam, "note"), "a b");
        assert_eq!(
            example_of(&points, Location::Redirect, "where"),
            "http://x.test/"
        );
        assert!(
            has(&points, Location::Header, "Content-Type"),
            "the content-type header is a point too: {points:?}"
        );
    }

    /// Only the top-level keys of a JSON object are parameters; a nested
    /// object's keys are not.
    #[test]
    fn enumerate_reads_only_top_level_json_keys() {
        let mut headers = HeaderMap::new();
        headers.set("Content-Type", "application/json");
        let flow = captured_body(
            "/api",
            headers,
            Body::Bytes(
                br#"{"user":{"id":1,"role":"admin"},"q":"a","n":3,"to":"https://x.test/"}"#
                    .to_vec(),
            ),
        );

        let points = enumerate(&flow);

        assert!(has(&points, Location::BodyParam, "user"));
        assert!(has(&points, Location::BodyParam, "q"));
        assert!(has(&points, Location::BodyParam, "n"));
        assert!(has(&points, Location::Redirect, "to"));
        assert!(
            !has(&points, Location::BodyParam, "role"),
            "a nested key is not a top-level parameter: {points:?}"
        );
        assert!(
            !has(&points, Location::BodyParam, "id"),
            "a nested key is not a top-level parameter: {points:?}"
        );
        assert_eq!(example_of(&points, Location::BodyParam, "q"), "a");
        assert_eq!(example_of(&points, Location::BodyParam, "n"), "3");
        assert_eq!(
            example_of(&points, Location::BodyParam, "user"),
            r#"{"id":1,"role":"admin"}"#
        );
    }

    #[test]
    fn enumerate_ignores_a_malformed_json_body() {
        let mut headers = HeaderMap::new();
        headers.set("Content-Type", "application/json");
        let flow = captured_body("/api", headers, Body::Bytes(b"{not json".to_vec()));

        let points = enumerate(&flow);

        assert!(
            !points.iter().any(|p| p.location == Location::BodyParam),
            "a malformed body yields no body params: {points:?}"
        );
    }

    /// The anti-goal: an auth header must never come back as an example value.
    #[test]
    fn enumerate_redacts_secret_header() {
        let mut headers = HeaderMap::new();
        headers.set("Authorization", "Bearer abc123");
        headers.set("X-Api-Key", "abc123");
        headers.set("Accept", "text/html");
        let flow = captured("/x", headers);

        let points = enumerate(&flow);

        assert_eq!(
            example_of(&points, Location::Header, "Authorization"),
            REDACTED
        );
        assert_eq!(example_of(&points, Location::Header, "X-Api-Key"), REDACTED);
        assert_eq!(
            example_of(&points, Location::Header, "Accept"),
            "text/html",
            "a non-secret header keeps its observed value"
        );
        assert!(
            !points.iter().any(|p| p.example.contains("abc123")),
            "the token leaked: {points:?}"
        );
    }

    #[test]
    fn enumerate_redacts_secret_cookie() {
        let mut headers = HeaderMap::new();
        headers.set("Cookie", "session_token=abc123; theme=dark");
        let flow = captured("/x?access_token=abc123", headers);

        let points = enumerate(&flow);

        assert_eq!(
            example_of(&points, Location::Cookie, "session_token"),
            REDACTED
        );
        assert_eq!(
            example_of(&points, Location::Cookie, "theme"),
            REDACTED,
            "even an innocently named cookie is credential material"
        );
        assert_eq!(
            example_of(&points, Location::Query, "access_token"),
            REDACTED
        );
        assert!(
            !points.iter().any(|p| p.example.contains("abc123")),
            "the session value leaked: {points:?}"
        );
    }

    /// A session cookie's name need not contain a secret keyword
    /// (`PHPSESSID`, `sid`): every cookie value is redacted, unconditionally.
    #[test]
    fn enumerate_redacts_cookie_by_value_regardless_of_name() {
        let mut headers = HeaderMap::new();
        headers.set(
            "Cookie",
            "PHPSESSID=secretvalue; sid=abc; JSESSIONID=jsv; lang=en",
        );
        let flow = captured("/x", headers);

        let points = enumerate(&flow);

        for name in ["PHPSESSID", "sid", "JSESSIONID", "lang"] {
            assert_eq!(
                example_of(&points, Location::Cookie, name),
                REDACTED,
                "cookie {name} must be redacted"
            );
        }
        for leaked in ["secretvalue", "abc", "jsv"] {
            assert!(
                !points.iter().any(|p| p.example.contains(leaked)),
                "cookie value {leaked} leaked: {points:?}"
            );
        }
        assert_eq!(points.len(), 4, "the cookie *names* survive: {points:?}");
    }

    /// Common auth parameter names outside the shared vocabulary are caught
    /// for headers, query and body parameters too.
    #[test]
    fn enumerate_redacts_common_auth_parameter_names() {
        let mut headers = HeaderMap::new();
        headers.set("X-CSRF-Token", "csrfv");
        headers.set("X-Auth", "authv");
        headers.set("Accept", "text/html");
        let flow = captured("/x?sid=sidv&jwt=jwtv&session=sessv&page=2", headers);

        let points = enumerate(&flow);

        for name in ["sid", "jwt", "session"] {
            assert_eq!(
                example_of(&points, Location::Query, name),
                REDACTED,
                "query {name} must be redacted"
            );
        }
        assert_eq!(
            example_of(&points, Location::Header, "X-CSRF-Token"),
            REDACTED
        );
        assert_eq!(example_of(&points, Location::Header, "X-Auth"), REDACTED);
        assert_eq!(
            example_of(&points, Location::Query, "page"),
            "2",
            "a plain parameter keeps its value"
        );
        assert_eq!(
            example_of(&points, Location::Header, "Accept"),
            "text/html",
            "a plain header keeps its value"
        );
        for leaked in ["sidv", "jwtv", "sessv", "csrfv", "authv"] {
            assert!(
                !points.iter().any(|p| p.example.contains(leaked)),
                "{leaked} leaked: {points:?}"
            );
        }
    }

    /// A hostile body of a million parameters must be capped, and the dedupe
    /// must not be quadratic.
    #[test]
    fn enumerate_caps_points_from_a_huge_body() {
        let mut headers = HeaderMap::new();
        headers.set("Content-Type", "application/x-www-form-urlencoded");
        let mut body = String::new();
        for i in 0..50_000 {
            body.push_str(&format!("k{i}=v&"));
        }
        let flow = captured_body("/bulk", headers, Body::Bytes(body.into_bytes()));

        let started = Instant::now();
        let points = enumerate(&flow);
        let elapsed = started.elapsed();

        assert!(
            points.len() <= MAX_POINTS_PER_FLOW,
            "capped at {MAX_POINTS_PER_FLOW}, got {}",
            points.len()
        );
        assert!(
            elapsed < std::time::Duration::from_secs(5),
            "enumerate took {elapsed:?} on 50k params"
        );
    }

    #[test]
    fn enumerate_deduplicates_repeated_names() {
        let flow = captured("/x?q=1&q=2&q=3", HeaderMap::new());

        let points = enumerate(&flow);

        assert_eq!(
            points.len(),
            1,
            "one point per (location, name): {points:?}"
        );
        assert_eq!(
            example_of(&points, Location::Query, "q"),
            "1",
            "the first observed value is kept"
        );
    }

    #[test]
    fn location_tokens_are_stable() {
        assert_eq!(Location::Query.as_str(), "query");
        assert_eq!(Location::BodyParam.as_str(), "body_param");
        assert_eq!(Location::Header.as_str(), "header");
        assert_eq!(Location::Cookie.as_str(), "cookie");
        assert_eq!(Location::PathSegment.as_str(), "path_segment");
        assert_eq!(Location::Redirect.as_str(), "redirect");
    }

    #[test]
    fn enumerate_reads_no_manifest() {
        // `enumerate` takes only `&HttpFlow` by construction (this compiles).
        fn _takes_only_flow(f: &HttpFlow) -> Vec<InjectionPoint> {
            enumerate(f)
        }

        // The crate must not depend on `aitm-testtarget` outside dev-dependencies.
        let manifest = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"))
            .expect("read Cargo.toml");
        let deps = manifest
            .split("[dev-dependencies]")
            .next()
            .expect("manifest has a prefix before dev-dependencies");
        assert!(
            !deps.contains("aitm-testtarget"),
            "aitm-testtarget must not be a non-dev dependency"
        );
    }
}
