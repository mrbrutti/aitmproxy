//! URL normalisation, origin and scope keys (task 3).

use aitm_core::HttpRequest;
use url::Url;

/// Characters whose presence in a fragment marks it as a client-side route
/// rather than an in-page anchor: a path, a query, or the WHATWG host
/// terminator `\`. A fragment carrying any of these is kept; every other
/// fragment is dropped (Burp's "fragments for routing" default).
const ROUTING_FRAGMENT_CHARS: [char; 5] = ['/', '\\', '?', '=', '&'];

/// Parse an absolute `http(s)` URL (a crawl seed or a captured request URL).
///
/// Trims the input, accepts only `http`/`https` with a non-empty host and no
/// userinfo, and routes the fragment through [`route_fragment`]. A URL that
/// carries credentials is refused outright: `http://target.test@evil.com/`
/// reads as the target to a human while the client connects to `evil.com`.
pub(crate) fn parse_absolute(s: &str) -> Option<Url> {
    Url::parse(s.trim()).ok().and_then(normalise)
}

/// Resolve `href` against `base` (a link harvested from a page), then apply the
/// same normalisation and scheme/host/userinfo checks as [`parse_absolute`].
///
/// Non-http schemes (`javascript:`, `mailto:`, `data:`, `tel:`, …) resolve to
/// `None`.
pub(crate) fn resolve(base: &Url, href: &str) -> Option<Url> {
    base.join(href).ok().and_then(normalise)
}

/// The shared post-parse checks and normalisation for a parsed or joined URL:
/// `http(s)` only, a non-empty host, no userinfo, and the routing-fragment
/// rule.
fn normalise(mut url: Url) -> Option<Url> {
    if !matches!(url.scheme(), "http" | "https") {
        return None;
    }
    match url.host_str() {
        Some(host) if !host.is_empty() => {}
        _ => return None,
    }
    if !url.username().is_empty() || url.password().is_some() {
        return None;
    }
    route_fragment(&mut url);
    Some(url)
}

/// Keep a fragment that looks like a client-side route (it contains any of
/// `/ \ ? = &`) verbatim; drop every other fragment.
pub(crate) fn route_fragment(url: &mut Url) {
    let keeps = url
        .fragment()
        .is_some_and(|f| f.contains(ROUTING_FRAGMENT_CHARS));
    if !keeps {
        url.set_fragment(None);
    }
}

/// `scheme://host[:port]`, the port shown only when it is not the scheme
/// default (the url crate elides a default port at parse time, so
/// [`Url::port`] already reports `None` for it).
pub(crate) fn origin_key(url: &Url) -> String {
    let scheme = url.scheme();
    let host = url.host_str().unwrap_or_default();
    match url.port() {
        Some(port) => format!("{scheme}://{host}:{port}"),
        None => format!("{scheme}://{host}"),
    }
}

/// The `host:port` the scope guard is asked about, always with an explicit
/// port (the scheme's default when the URL elides it) so an explicit
/// `target.test:443` scope entry matches a portless `https://target.test/`.
/// Same shape as the legacy `guard_authority`.
pub(crate) fn guard_authority(url: &Url) -> String {
    let host = url.host_str().unwrap_or_default();
    let port = url.port_or_known_default().unwrap_or(0);
    format!("{host}:{port}")
}

/// Whether two URLs share a WHATWG origin (scheme, host and port).
pub(crate) fn same_origin(a: &Url, b: &Url) -> bool {
    a.origin() == b.origin()
}

/// The request's URL rebuilt from its parts (`path` already carries the
/// query), run through [`parse_absolute`] so it is normalised and credential-
/// free like every other URL the lane handles.
///
/// A captured authority is `host[:port]` only. It is checked before anything
/// is composed: an empty one would read as `http:///a`, which the url crate
/// parses as host `a` (a bogus host that would silently get a site-map node),
/// and a `/ ? # @` or whitespace inside it would let the path, query or
/// userinfo masquerade as the host. Either shape yields `None`.
pub(crate) fn request_url(req: &HttpRequest) -> Option<Url> {
    if !is_plain_authority(&req.authority) {
        return None;
    }
    parse_absolute(&format!("{}://{}{}", req.scheme, req.authority, req.path))
}

/// Whether `authority` is a bare `host[:port]`: non-empty after trimming and
/// free of the URL delimiters and whitespace that would end or re-shape it.
fn is_plain_authority(authority: &str) -> bool {
    !authority.trim().is_empty()
        && !authority
            .chars()
            .any(|c| matches!(c, '/' | '?' | '#' | '@') || c.is_whitespace())
}

/// The visited-set key for a page: its normalised serialisation.
pub(crate) fn page_key(url: &Url) -> String {
    url.as_str().to_string()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use aitm_core::{Body, HeaderMap, HttpRequest, HttpVersion};
    use std::time::SystemTime;

    #[test]
    fn resolve_pins() {
        let base = parse_absolute("http://t/a/").expect("base parses");

        // A routing-less fragment is dropped.
        assert_eq!(resolve(&base, "b#top").unwrap().as_str(), "http://t/a/b");
        // A fragment that routes (contains `/ \ ? = &`) is kept verbatim.
        assert_eq!(
            resolve(&base, "b#/route?x=1").unwrap().as_str(),
            "http://t/a/b#/route?x=1"
        );
        // Non-http schemes resolve to nothing.
        assert_eq!(resolve(&base, "javascript:void(0)"), None);
        assert_eq!(resolve(&base, "mailto:a@b"), None);

        // Protocol-relative crosses origin.
        let proto_rel = resolve(&base, "//evil.test/x").expect("protocol-relative resolves");
        assert_eq!(proto_rel.as_str(), "http://evil.test/x");
        assert!(!same_origin(&base, &proto_rel));

        // Scheme and host lowercased, default port elided.
        assert_eq!(
            resolve(&base, "HTTP://T:80/x").unwrap().as_str(),
            "http://t/x"
        );
        // Userinfo is refused outright.
        assert_eq!(resolve(&base, "http://u:p@t/x"), None);

        // The backslash-host scope bypass stays rejected: the url crate reads
        // `\\evil.test\x` as `//evil.test/x`, so the host is `evil.test`.
        let backslash =
            resolve(&base, "\\\\evil.test\\x").expect("backslash host maps to evil.test");
        assert_eq!(backslash.as_str(), "http://evil.test/x");
        assert!(!same_origin(&base, &backslash));
    }

    #[test]
    fn keys() {
        let g1 = parse_absolute("https://t/x").unwrap();
        assert_eq!(guard_authority(&g1), "t:443");
        let g2 = parse_absolute("http://t:8080/").unwrap();
        assert_eq!(guard_authority(&g2), "t:8080");

        let o1 = parse_absolute("http://t:8080/x?y").unwrap();
        assert_eq!(origin_key(&o1), "http://t:8080");
        let o2 = parse_absolute("https://t/").unwrap();
        assert_eq!(origin_key(&o2), "https://t");
    }

    #[test]
    fn request_url_builds_from_parts() {
        assert_eq!(
            request_url(&req("http", "t:8080", "/a?b=1"))
                .unwrap()
                .as_str(),
            "http://t:8080/a?b=1"
        );
    }

    /// A captured authority is `host[:port]` only. An empty one would compose
    /// to `http:///a`, which the url crate reads as host `a` (a bogus site-map
    /// node); a delimiter inside it would let the path or query masquerade as
    /// the host. Both are refused before anything is composed.
    #[test]
    fn request_url_refuses_malformed_authority() {
        assert!(request_url(&req("http", "", "/a")).is_none());
        assert!(request_url(&req("http", "   ", "/a")).is_none());
        assert!(request_url(&req("http", "a/b", "/x")).is_none());
        assert!(request_url(&req("http", "t?x=1", "/")).is_none());
        assert!(request_url(&req("http", "t#f", "/")).is_none());
        assert!(request_url(&req("http", "u@t", "/")).is_none());
        assert!(request_url(&req("http", "t 8080", "/")).is_none());
        // The well-formed shapes still resolve.
        assert_eq!(
            request_url(&req("https", "t", "/")).unwrap().as_str(),
            "https://t/"
        );
        assert_eq!(
            request_url(&req("http", "t:8080", "/")).unwrap().as_str(),
            "http://t:8080/"
        );
    }

    fn req(scheme: &str, authority: &str, path: &str) -> HttpRequest {
        HttpRequest {
            method: "GET".into(),
            scheme: scheme.into(),
            authority: authority.into(),
            path: path.into(),
            version: HttpVersion::Http11,
            headers: HeaderMap::new(),
            body: Body::Empty,
            timestamp: SystemTime::now(),
        }
    }
}
