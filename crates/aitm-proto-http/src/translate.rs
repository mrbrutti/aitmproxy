//! Pure, I/O-free translation between the `http` crate's h2 head types and the
//! `aitm-core` flow model, plus the connection-specific headers that are illegal
//! in HTTP/2 and must be dropped on encode (RFC 9113 §8.2.2).
//!
//! The `serve_h2` driver (Task 2) consumes these; they carry no async and touch
//! no sockets, so they are unit-tested in isolation.

use std::time::SystemTime;

use aitm_core::{Body, HeaderMap, HttpRequest, HttpResponse, HttpVersion};

/// Connection-specific header names that are legal in HTTP/1.1 but illegal in
/// HTTP/2 (RFC 9113 §8.2.2). Carrying any of these into an h2 frame makes the
/// `h2` encoder emit a `PROTOCOL_ERROR` and drop the stream, so they are stripped
/// on encode. All entries are lowercase for case-insensitive matching.
pub(crate) const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-connection",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// An h2 inbound request head → the core model. The pseudo-headers carried on the
/// `http::Uri` (`:scheme`, `:authority`, `:path`) are read from there, falling back
/// to the connection's scheme/authority when a pseudo-header is absent. `version`
/// is always `H2`; the body is filled in by the caller as it drains the stream.
pub(crate) fn request_from_h2(
    head: &http::request::Parts,
    conn_scheme: &str,
    conn_authority: &str,
) -> HttpRequest {
    let scheme = head
        .uri
        .scheme_str()
        .map(str::to_string)
        .unwrap_or_else(|| conn_scheme.to_string());
    let authority = head
        .uri
        .authority()
        .map(|a| a.as_str().to_string())
        .unwrap_or_else(|| conn_authority.to_string());
    let path = head
        .uri
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());

    HttpRequest {
        method: head.method.as_str().to_string(),
        scheme,
        authority,
        path,
        version: HttpVersion::H2,
        headers: headers_from_h2(&head.headers),
        body: Body::Empty,
        timestamp: SystemTime::now(),
    }
}

/// The core model → an h2 outbound request head. Strips the h1-only hop-by-hop
/// headers ([`HOP_BY_HOP`]) and lowercases every name, as HTTP/2 requires.
pub(crate) fn h2_request_from(req: &HttpRequest) -> http::Request<()> {
    let mut out = http::Request::new(());
    *out.method_mut() =
        http::Method::from_bytes(req.method.as_bytes()).unwrap_or(http::Method::GET);
    *out.uri_mut() = build_uri(&req.scheme, &req.authority, &req.path);
    *out.version_mut() = http::Version::HTTP_2;
    encode_headers(&req.headers, out.headers_mut());
    out
}

/// An h2 inbound response head → the core model (`version` is always `H2`).
pub(crate) fn response_from_h2(head: &http::response::Parts) -> HttpResponse {
    HttpResponse {
        status: head.status.as_u16(),
        version: HttpVersion::H2,
        headers: headers_from_h2(&head.headers),
        trailers: HeaderMap::new(),
        body: Body::Empty,
        timestamp: SystemTime::now(),
    }
}

/// The core model → an h2 outbound response head. Strips hop-by-hop headers and
/// lowercases names, as HTTP/2 requires. An out-of-range status falls back to 200.
pub(crate) fn h2_response_from(resp: &HttpResponse) -> http::Response<()> {
    let mut out = http::Response::new(());
    *out.status_mut() = http::StatusCode::from_u16(resp.status).unwrap_or(http::StatusCode::OK);
    *out.version_mut() = http::Version::HTTP_2;
    encode_headers(&resp.headers, out.headers_mut());
    out
}

/// Build an h2 request-target URI from the model's scheme/authority/path. An empty
/// path becomes `/`; a URI that cannot be assembled degrades to `/` rather than
/// panicking (the encoder is infallible by contract).
fn build_uri(scheme: &str, authority: &str, path: &str) -> http::Uri {
    let path = if path.is_empty() { "/" } else { path };
    http::uri::Builder::new()
        .scheme(scheme)
        .authority(authority)
        .path_and_query(path)
        .build()
        .unwrap_or_else(|_| http::Uri::from_static("/"))
}

/// Copy an h2 header map into the ordered core [`HeaderMap`], preserving insertion
/// order and duplicates. Non-UTF-8 values (which the model cannot represent) are
/// dropped.
fn headers_from_h2(src: &http::HeaderMap) -> HeaderMap {
    let mut out = HeaderMap::new();
    for (name, value) in src.iter() {
        if let Ok(v) = value.to_str() {
            out.set(name.as_str(), v);
        }
    }
    out
}

/// Encode the core [`HeaderMap`] into an h2 header map: lowercase every name, drop
/// the hop-by-hop set, and skip any name/value the `http` types reject (the core
/// map already forbids CRLF, so this only guards against the few bytes `http` is
/// stricter about). Duplicates and order are preserved via `append`.
fn encode_headers(src: &HeaderMap, dst: &mut http::HeaderMap) {
    for (name, value) in src.iter() {
        let lower = name.to_ascii_lowercase();
        if HOP_BY_HOP.contains(&lower.as_str()) {
            continue;
        }
        if let (Ok(n), Ok(v)) = (
            http::header::HeaderName::from_bytes(lower.as_bytes()),
            http::header::HeaderValue::from_str(value),
        ) {
            dst.append(n, v);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aitm_core::{Body, HeaderMap, HttpRequest, HttpResponse, HttpVersion};
    use std::time::SystemTime;

    fn req_with_headers(headers: HeaderMap) -> HttpRequest {
        HttpRequest {
            method: "GET".to_string(),
            scheme: "https".to_string(),
            authority: "ex.com".to_string(),
            path: "/".to_string(),
            version: HttpVersion::H2,
            headers,
            body: Body::Empty,
            timestamp: SystemTime::now(),
        }
    }

    #[test]
    fn request_from_h2_maps_pseudo_headers() {
        let (parts, _) = http::Request::builder()
            .method("POST")
            .uri("https://ex.com/v1/x")
            .body(())
            .unwrap()
            .into_parts();

        let req = request_from_h2(&parts, "https", "ex.com:443");

        assert_eq!(req.method, "POST");
        assert_eq!(req.scheme, "https");
        assert!(req.authority == "ex.com" || req.authority == "ex.com:443");
        assert_eq!(req.path, "/v1/x");
        assert_eq!(req.version, HttpVersion::H2);
    }

    #[test]
    fn encode_strips_hop_by_hop() {
        let mut headers = HeaderMap::new();
        headers.set("Connection", "keep-alive");
        headers.set("Transfer-Encoding", "chunked");
        headers.set("X-Keep", "1");

        let out = h2_request_from(&req_with_headers(headers));

        assert!(out.headers().contains_key("x-keep"));
        assert!(!out.headers().contains_key("connection"));
        assert!(!out.headers().contains_key("transfer-encoding"));
    }

    #[test]
    fn response_status_round_trips() {
        let (parts, _) = http::Response::builder()
            .status(418)
            .body(())
            .unwrap()
            .into_parts();

        let resp = response_from_h2(&parts);
        assert_eq!(resp.status, 418);
        assert_eq!(resp.version, HttpVersion::H2);

        let model = HttpResponse {
            status: 418,
            version: HttpVersion::H2,
            headers: HeaderMap::new(),
            trailers: HeaderMap::new(),
            body: Body::Empty,
            timestamp: SystemTime::now(),
        };
        assert_eq!(
            h2_response_from(&model).status(),
            http::StatusCode::IM_A_TEAPOT
        );
    }

    #[test]
    fn a_translated_h2_response_has_no_trailers() {
        let (parts, _) = http::Response::builder()
            .status(200)
            .body(())
            .unwrap()
            .into_parts();

        assert!(response_from_h2(&parts).trailers.is_empty());
    }

    #[test]
    fn h2_response_from_ignores_trailers() {
        let mut trailers = HeaderMap::new();
        trailers.set("X-Sum", "abc");
        let model = HttpResponse {
            status: 200,
            version: HttpVersion::H2,
            headers: HeaderMap::new(),
            trailers,
            body: Body::Empty,
            timestamp: SystemTime::now(),
        };

        assert!(!h2_response_from(&model).headers().contains_key("x-sum"));
    }
}
