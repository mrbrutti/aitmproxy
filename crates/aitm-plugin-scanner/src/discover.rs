//! Injection-point discovery: given one captured HTTP flow, enumerate the
//! candidate injection points from the request shape alone.
//!
//! This reads ONLY the passed flow — never a test-target manifest or any other
//! out-of-band source. The same request shape a client could observe is all the
//! scanner is allowed to see.

use aitm_core::Body;

/// Where a candidate injection point lives in the request.
#[derive(Debug, Clone, PartialEq, Eq)]
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

/// One candidate injection point discovered in a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InjectionPoint {
    /// The flow this point was discovered in.
    pub flow: aitm_core::FlowId,
    /// Where the point lives.
    pub location: Location,
    /// The parameter / header / segment name.
    pub name: String,
    /// The observed value (or segment) at that point.
    pub example: String,
}

/// Enumerate candidate injection points from the request shape of `flow`.
///
/// Reads ONLY the passed flow. Never calls any `aitm_testtarget` API.
pub fn enumerate(flow: &aitm_core::HttpFlow) -> Vec<InjectionPoint> {
    let id = flow.id;
    let req = &flow.request;
    let mut points: Vec<InjectionPoint> = Vec::new();
    let mut push = |location: Location, name: String, example: String| {
        if !points
            .iter()
            .any(|p| p.location == location && p.name == name)
        {
            points.push(InjectionPoint {
                flow: id,
                location,
                name,
                example,
            });
        }
    };

    // Split the path into the raw path and its query string.
    let (raw_path, query) = match req.path.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (req.path.as_str(), None),
    };

    // Query parameters.
    if let Some(query) = query {
        for (name, value) in parse_pairs(query, '&') {
            let location = if is_url(&value) {
                Location::Redirect
            } else {
                Location::Query
            };
            push(location, name, value);
        }
    }

    // Numeric object-id path segments.
    for segment in raw_path.split('/').filter(|s| !s.is_empty()) {
        if !segment.is_empty() && segment.bytes().all(|b| b.is_ascii_digit()) {
            push(
                Location::PathSegment,
                segment.to_string(),
                segment.to_string(),
            );
        }
    }

    // Body parameters (form-urlencoded or a flat JSON object).
    if let Some(bytes) = body_bytes(&req.body) {
        let ctype = req.headers.get("content-type").unwrap_or("");
        if ctype.contains("application/x-www-form-urlencoded") {
            if let Ok(text) = std::str::from_utf8(bytes) {
                for (name, value) in parse_pairs(text, '&') {
                    let location = if is_url(&value) {
                        Location::Redirect
                    } else {
                        Location::BodyParam
                    };
                    push(location, name, value);
                }
            }
        } else if ctype.contains("application/json") {
            if let Ok(text) = std::str::from_utf8(bytes) {
                for (name, value) in parse_json_object(text) {
                    let location = if is_url(&value) {
                        Location::Redirect
                    } else {
                        Location::BodyParam
                    };
                    push(location, name, value);
                }
            }
        }
    }

    // Cookies and other headers.
    for (name, value) in req.headers.iter() {
        if name.eq_ignore_ascii_case("cookie") {
            for (cname, cvalue) in parse_pairs(value, ';') {
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

/// Whether `value` looks like a URL for open-redirect purposes.
fn is_url(value: &str) -> bool {
    value.starts_with("http://") || value.starts_with("https://") || value.starts_with("//")
}

/// Read body bytes the way `detail.rs` does: buffered bodies yield their bytes,
/// a still-streaming body yields nothing.
fn body_bytes(body: &Body) -> Option<&[u8]> {
    match body {
        Body::Bytes(b) => Some(b.as_slice()),
        Body::Empty => Some(&[]),
        Body::Streamed(_) => None,
    }
}

/// Split `input` on `sep`, trim each entry, and parse `k=v` pairs. Entries
/// without a `=` are skipped; empty keys are skipped.
fn parse_pairs(input: &str, sep: char) -> Vec<(String, String)> {
    input
        .split(sep)
        .filter_map(|pair| {
            let pair = pair.trim();
            let (k, v) = pair.split_once('=')?;
            let k = k.trim();
            if k.is_empty() {
                return None;
            }
            Some((k.to_string(), v.trim().to_string()))
        })
        .collect()
}

/// Extract the top-level string-valued keys from a flat JSON object. Values that
/// are strings are returned unquoted; other scalar values are returned as their
/// raw token. Returns nothing for anything that is not a `{ ... }` object.
fn parse_json_object(text: &str) -> Vec<(String, String)> {
    let text = text.trim();
    let inner = match text.strip_prefix('{').and_then(|t| t.strip_suffix('}')) {
        Some(inner) => inner,
        None => return Vec::new(),
    };

    let mut out = Vec::new();
    let bytes = inner.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        // Skip whitespace and separators.
        while i < bytes.len() && (bytes[i].is_ascii_whitespace() || bytes[i] == b',') {
            i += 1;
        }
        if i >= bytes.len() || bytes[i] != b'"' {
            break;
        }
        // Parse the quoted key.
        let (key, next) = match parse_json_string(bytes, i) {
            Some(res) => res,
            None => break,
        };
        i = next;
        // Expect a colon.
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= bytes.len() || bytes[i] != b':' {
            break;
        }
        i += 1;
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }
        // Parse the value.
        let (value, next) = if bytes[i] == b'"' {
            match parse_json_string(bytes, i) {
                Some(res) => res,
                None => break,
            }
        } else {
            // A scalar token up to the next comma / brace / whitespace.
            let start = i;
            while i < bytes.len() && bytes[i] != b',' {
                i += 1;
            }
            (inner[start..i].trim().to_string(), i)
        };
        i = next;
        out.push((key, value));
    }
    out
}

/// Parse a JSON string literal starting at `start` (which must be `"`). Returns
/// the unescaped content and the index just past the closing quote.
fn parse_json_string(bytes: &[u8], start: usize) -> Option<(String, usize)> {
    debug_assert_eq!(bytes[start], b'"');
    let mut i = start + 1;
    let mut s = String::new();
    while i < bytes.len() {
        match bytes[i] {
            b'"' => return Some((s, i + 1)),
            b'\\' if i + 1 < bytes.len() => {
                let esc = bytes[i + 1];
                match esc {
                    b'"' => s.push('"'),
                    b'\\' => s.push('\\'),
                    b'/' => s.push('/'),
                    b'n' => s.push('\n'),
                    b't' => s.push('\t'),
                    b'r' => s.push('\r'),
                    other => s.push(other as char),
                }
                i += 2;
            }
            other => {
                s.push(other as char);
                i += 1;
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use aitm_core::{
        Body, ConnInfo, FlowId, FlowMeta, HeaderMap, HttpFlow, HttpRequest, HttpVersion,
        InterceptState,
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

    fn captured(path: &str, headers: HeaderMap) -> HttpFlow {
        HttpFlow {
            id: FlowId::new(),
            request: HttpRequest {
                method: "GET".into(),
                scheme: "http".into(),
                authority: "ex.test".into(),
                path: path.into(),
                version: HttpVersion::Http11,
                headers,
                body: Body::Empty,
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
