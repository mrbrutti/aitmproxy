//! Breadth-first crawl of an in-scope target through the embedded browser.
//!
//! Read-only link discovery: every page is reached by a plain navigation, its
//! DOM is scanned for `href` and form `action` attributes, and only links that
//! are same-origin with the target **and** in the guard's scope are followed.
//! Off-origin or out-of-scope links are dropped without being fetched or
//! recorded. The crawl is bounded by `max_pages`, `max_depth` and
//! `time_budget` from [`ScannerConfig`].

use std::collections::{HashSet, VecDeque};
use std::fmt;
use std::time::Instant;

use aitm_core::{CommandHost, Flow, GuardError};

use crate::ScannerConfig;

/// What a crawl reached and why it stopped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrawlOutcome {
    /// Normalized in-scope URLs reached, in crawl order, deduplicated.
    pub endpoints: Vec<String>,
    /// Pages successfully navigated.
    pub pages_crawled: usize,
    /// `"max_pages"`, `"max_depth"`, `"time_budget"`, `"no_browser"`, or
    /// `None` when the reachable graph was exhausted.
    pub stopped_reason: Option<String>,
}

/// Crawl breadth-first from `target`, following only same-origin, in-scope links.
///
/// The target itself must be an absolute `http(s)` URL whose host the guard has
/// in scope; otherwise this returns [`GuardError::OutOfScope`] (deny-by-default)
/// and navigates nothing. Without a browser on the host the crawl falls back
/// to listing the distinct same-origin, in-scope request URLs already captured
/// in the flow store and reports `stopped_reason = Some("no_browser")`.
pub async fn crawl(
    host: &CommandHost<'_>,
    target: &str,
    cfg: &ScannerConfig,
) -> anyhow::Result<CrawlOutcome> {
    let seed = Url::parse(target)
        .ok_or_else(|| anyhow::anyhow!("target is not an absolute http(s) URL: {target:?}"))?;
    let authority = seed.authority();
    if !host.guard().in_scope(&authority) {
        return Err(GuardError::OutOfScope(authority).into());
    }
    let origin = seed.origin();
    let Some(browser) = host.browser() else {
        return Ok(stored_endpoints(host, &seed));
    };

    let started = Instant::now();
    let mut queue: VecDeque<(Url, usize)> = VecDeque::from([(seed.clone(), 0)]);
    let mut visited: HashSet<String> = HashSet::from([seed.to_string()]);
    let mut endpoints: Vec<String> = Vec::new();
    let mut pages_crawled = 0usize;
    let mut depth_hit = false;
    let mut stopped: Option<&str> = None;

    while let Some((url, depth)) = queue.pop_front() {
        if started.elapsed() >= cfg.time_budget {
            stopped = Some("time_budget");
            break;
        }
        if pages_crawled >= cfg.max_pages {
            stopped = Some("max_pages");
            break;
        }
        let Ok(nav) = browser.navigate(&url.to_string()).await else {
            // An unreachable page is skipped; the crawl is best-effort.
            continue;
        };
        pages_crawled += 1;
        // A redirect may have landed somewhere else. Only a same-origin,
        // in-scope landing page is recorded and harvested.
        let Some(page) = Url::parse(&nav.final_url)
            .filter(|u| u.origin() == origin && host.guard().in_scope(&u.authority()))
        else {
            continue;
        };
        let page_key = page.to_string();
        visited.insert(page_key.clone());
        if !endpoints.contains(&page_key) {
            endpoints.push(page_key);
        }
        let Ok(dom) = browser.get_dom().await else {
            continue;
        };
        for link in harvest_links(&dom) {
            let Some(resolved) = page.resolve(&link) else {
                continue;
            };
            if resolved.origin() != origin || !host.guard().in_scope(&resolved.authority()) {
                continue;
            }
            let key = resolved.to_string();
            if visited.contains(&key) {
                continue;
            }
            if depth + 1 > cfg.max_depth {
                depth_hit = true;
                continue;
            }
            visited.insert(key);
            queue.push_back((resolved, depth + 1));
        }
    }

    let stopped_reason = stopped
        .or(if depth_hit { Some("max_depth") } else { None })
        .map(str::to_string);
    Ok(CrawlOutcome {
        endpoints,
        pages_crawled,
        stopped_reason,
    })
}

/// The no-browser fallback: distinct same-origin, in-scope request URLs already
/// in the store, in insertion order.
fn stored_endpoints(host: &CommandHost<'_>, seed: &Url) -> CrawlOutcome {
    let origin = seed.origin();
    let mut seen: HashSet<String> = HashSet::new();
    let mut endpoints = Vec::new();
    for id in host.store().list() {
        let Some(Flow::Http(flow)) = host.store().get(id) else {
            continue;
        };
        let req = &flow.request;
        let Some(url) = Url::parse(&format!("{}://{}{}", req.scheme, req.authority, req.path))
        else {
            continue;
        };
        if url.origin() != origin || !host.guard().in_scope(&url.authority()) {
            continue;
        }
        let key = url.to_string();
        if seen.insert(key.clone()) {
            endpoints.push(key);
        }
    }
    CrawlOutcome {
        endpoints,
        pages_crawled: 0,
        stopped_reason: Some("no_browser".to_string()),
    }
}

/// A parsed, normalized absolute `http(s)` URL: lowercase scheme and host,
/// default port elided, dot-segments removed, fragment dropped, query kept.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Url {
    scheme: String,
    host: String,
    /// Only an explicit, non-default port.
    port: Option<u16>,
    path: String,
    query: Option<String>,
}

impl Url {
    /// Parse an absolute URL. Only `http` and `https` are accepted; anything
    /// without a scheme and host, or with an unparseable port, is `None`.
    fn parse(s: &str) -> Option<Url> {
        let s = s.trim();
        let (scheme, rest) = s.split_once("://")?;
        let scheme = scheme.to_ascii_lowercase();
        let default_port = match scheme.as_str() {
            "http" => 80,
            "https" => 443,
            _ => return None,
        };
        let auth_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let (authority, tail) = rest.split_at(auth_end);
        // Drop any userinfo; a crawl never carries credentials in a URL.
        let authority = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
        let (host, port) = split_host_port(authority)?;
        if host.is_empty() {
            return None;
        }
        let host = host.to_ascii_lowercase();
        let port = match port {
            Some(p) => {
                let p: u16 = p.parse().ok()?;
                (p != default_port).then_some(p)
            }
            None => None,
        };
        let (path, query) = split_path_query(tail);
        Some(Url {
            scheme,
            host,
            port,
            path: remove_dot_segments(path),
            query,
        })
    }

    /// `scheme://host[:port]` — what same-origin comparison uses.
    fn origin(&self) -> String {
        format!("{}://{}", self.scheme, self.authority())
    }

    /// `host[:port]` — what the scope guard is asked about.
    fn authority(&self) -> String {
        match self.port {
            Some(p) => format!("{}:{p}", self.host),
            None => self.host.clone(),
        }
    }

    /// Resolve an `href`/`action` value against this page (RFC 3986 §5.2,
    /// the subset HTML links use). Non-navigational schemes (`javascript:`,
    /// `mailto:`, `data:`, …) resolve to `None`; a fragment-only reference
    /// resolves to this page.
    fn resolve(&self, reference: &str) -> Option<Url> {
        let reference = reference.trim();
        let reference = reference.split('#').next().unwrap_or("");
        if reference.is_empty() {
            return Some(self.clone());
        }
        if has_scheme(reference) {
            return Url::parse(reference);
        }
        if let Some(rest) = reference.strip_prefix("//") {
            return Url::parse(&format!("{}://{rest}", self.scheme));
        }
        let (path, query) = if reference.starts_with('/') {
            split_path_query(reference)
        } else if let Some(q) = reference.strip_prefix('?') {
            (self.path.as_str(), Some(q.to_string()))
        } else {
            let dir_end = self.path.rfind('/').map_or(0, |i| i + 1);
            let merged = format!("{}{reference}", &self.path[..dir_end]);
            let (p, q) = split_path_query(&merged);
            return Some(Url {
                path: remove_dot_segments(p),
                query: q,
                ..self.clone()
            });
        };
        Some(Url {
            path: remove_dot_segments(path),
            query,
            ..self.clone()
        })
    }
}

impl fmt::Display for Url {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}{}", self.origin(), self.path)?;
        if let Some(q) = &self.query {
            write!(f, "?{q}")?;
        }
        Ok(())
    }
}

/// Split `host[:port]`, keeping an IPv6 literal's brackets with the host.
fn split_host_port(authority: &str) -> Option<(&str, Option<&str>)> {
    if authority.starts_with('[') {
        let close = authority.find(']')?;
        let host = &authority[..=close];
        let rest = &authority[close + 1..];
        if rest.is_empty() {
            return Some((host, None));
        }
        return rest.strip_prefix(':').map(|p| (host, Some(p)));
    }
    Some(match authority.rsplit_once(':') {
        Some((h, p)) => (h, Some(p)),
        None => (authority, None),
    })
}

/// Split `path[?query][#fragment]` into the path (never empty) and the query;
/// the fragment is dropped.
fn split_path_query(tail: &str) -> (&str, Option<String>) {
    let tail = tail.split('#').next().unwrap_or("");
    let (path, query) = match tail.split_once('?') {
        Some((p, q)) => (p, Some(q.to_string())),
        None => (tail, None),
    };
    let path = if path.is_empty() { "/" } else { path };
    (path, query)
}

/// RFC 3986 §5.2.4 on an absolute path; a trailing `.`/`..` keeps the slash.
fn remove_dot_segments(path: &str) -> String {
    let segments: Vec<&str> = path.split('/').collect();
    let last = segments.len().saturating_sub(1);
    let mut out: Vec<&str> = Vec::new();
    for (i, seg) in segments.iter().enumerate().skip(1) {
        match *seg {
            "." => {
                if i == last {
                    out.push("");
                }
            }
            ".." => {
                out.pop();
                if i == last {
                    out.push("");
                }
            }
            s => out.push(s),
        }
    }
    format!("/{}", out.join("/"))
}

/// Whether `reference` starts with a URI scheme (`alpha *(alnum / + / - / .) :`)
/// before any path or query delimiter.
fn has_scheme(reference: &str) -> bool {
    let Some(colon) = reference.find(':') else {
        return false;
    };
    let scheme = &reference[..colon];
    let mut chars = scheme.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    first.is_ascii_alphabetic()
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
        && !reference[..colon].contains(['/', '?'])
}

/// Every `href` and form `action` attribute value in `html`, in document
/// order, with the common HTML entities decoded. Plain string scanning —
/// case-insensitive attribute names, single/double/unquoted values.
fn harvest_links(html: &str) -> Vec<String> {
    let lower = html.to_ascii_lowercase();
    let bytes = lower.as_bytes();
    let mut links = Vec::new();
    for attr in ["href", "action"] {
        let mut from = 0;
        while let Some(found) = lower[from..].find(attr) {
            let start = from + found;
            let end = start + attr.len();
            from = end;
            // Must be a whole attribute name: preceded by whitespace or a
            // quote-less tag boundary, not part of a longer word.
            let preceded_ok = start > 0 && !bytes[start - 1].is_ascii_alphanumeric();
            if !preceded_ok {
                continue;
            }
            let Some(value) = attribute_value(html, &lower, end) else {
                continue;
            };
            links.push(decode_entities(value));
        }
    }
    links
}

/// The value of the attribute whose name ends at `after_name`, if what follows
/// is `[ws] = [ws] value`.
fn attribute_value<'a>(html: &'a str, lower: &str, after_name: usize) -> Option<&'a str> {
    let bytes = lower.as_bytes();
    let mut i = after_name;
    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    if i >= bytes.len() || bytes[i] != b'=' {
        return None;
    }
    i += 1;
    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    if i >= bytes.len() {
        return None;
    }
    match bytes[i] {
        quote @ (b'"' | b'\'') => {
            let start = i + 1;
            let len = lower[start..].find(quote as char)?;
            Some(&html[start..start + len])
        }
        b'>' => None,
        _ => {
            let start = i;
            let len = lower[start..]
                .find(|c: char| c.is_ascii_whitespace() || c == '>')
                .unwrap_or(lower.len() - start);
            Some(&html[start..start + len])
        }
    }
}

/// Decode the entities an attribute value commonly carries.
fn decode_entities(value: &str) -> String {
    if !value.contains('&') {
        return value.to_string();
    }
    value
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&#39;", "'")
        .replace("&#x27;", "'")
}

#[cfg(test)]
mod tests {
    use super::*;
    use aitm_core::{
        Body, ClickTarget, ConnInfo, Flow, FlowId, FlowMeta, FlowStore, HeaderMap, HttpFlow,
        HttpRequest, HttpVersion, InterceptState, MemFlowStore, NavOutcome, ProxyClient,
        ScopeEntry, ScopeRateGuard, StdGuard, Value,
    };
    use futures::executor::block_on;
    use futures::future::BoxFuture;
    use std::collections::BTreeMap;
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::sync::Mutex;
    use std::time::{Duration, SystemTime};

    const TARGET: &str = "http://target.test/";

    fn conn() -> ConnInfo {
        ConnInfo {
            peer: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
            sni: None,
            alpn: None,
            tls: false,
            established: SystemTime::now(),
        }
    }

    fn captured(scheme: &str, authority: &str, path: &str) -> Flow {
        Flow::Http(HttpFlow {
            id: FlowId::new(),
            request: HttpRequest {
                method: "GET".into(),
                scheme: scheme.into(),
                authority: authority.into(),
                path: path.into(),
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

    /// A `ProxyClient` the crawler must never use: it panics if reached.
    struct NoSendClient;

    impl ProxyClient for NoSendClient {
        fn send(&self, req: HttpRequest) -> BoxFuture<'_, anyhow::Result<HttpFlow>> {
            panic!("the crawler must not send requests through the proxy client: {req:?}");
        }
    }

    /// A browser that serves crafted HTML per normalized URL (falling back to
    /// `default_html`) and records every navigation it is asked for.
    struct StubBrowser {
        pages: BTreeMap<String, String>,
        default_html: String,
        current: Mutex<Option<String>>,
        navigated: Mutex<Vec<String>>,
    }

    impl StubBrowser {
        fn new(default_html: &str) -> Self {
            Self {
                pages: BTreeMap::new(),
                default_html: default_html.to_string(),
                current: Mutex::new(None),
                navigated: Mutex::new(Vec::new()),
            }
        }

        fn page(mut self, url: &str, html: &str) -> Self {
            self.pages.insert(url.to_string(), html.to_string());
            self
        }

        fn navigated(&self) -> Vec<String> {
            self.navigated.lock().expect("navigated lock").clone()
        }
    }

    impl aitm_core::BrowserDriver for StubBrowser {
        fn navigate(&self, url: &str) -> BoxFuture<'_, anyhow::Result<NavOutcome>> {
            let url = url.to_string();
            Box::pin(async move {
                self.navigated
                    .lock()
                    .expect("navigated lock")
                    .push(url.clone());
                *self.current.lock().expect("current lock") = Some(url.clone());
                Ok(NavOutcome {
                    final_url: url,
                    status: Some(200),
                })
            })
        }

        fn click(&self, _target: ClickTarget) -> BoxFuture<'_, anyhow::Result<()>> {
            Box::pin(async { unimplemented!("the crawler never clicks") })
        }

        fn type_text(&self, _selector: &str, _text: &str) -> BoxFuture<'_, anyhow::Result<()>> {
            Box::pin(async { unimplemented!("the crawler never types") })
        }

        fn screenshot(&self) -> BoxFuture<'_, anyhow::Result<Vec<u8>>> {
            Box::pin(async { unimplemented!("the crawler never screenshots") })
        }

        fn eval(&self, _expr: &str) -> BoxFuture<'_, anyhow::Result<Value>> {
            Box::pin(async { unimplemented!("the crawler never evals") })
        }

        fn get_dom(&self) -> BoxFuture<'_, anyhow::Result<String>> {
            Box::pin(async move {
                let current = self.current.lock().expect("current lock").clone();
                let html = current
                    .and_then(|u| self.pages.get(&u).cloned())
                    .unwrap_or_else(|| self.default_html.clone());
                Ok(html)
            })
        }
    }

    fn scoped_guard(host: &str) -> StdGuard {
        let guard = StdGuard::default();
        guard.add_scope(ScopeEntry { host: host.into() });
        guard
    }

    fn cfg(max_pages: usize, max_depth: usize) -> ScannerConfig {
        ScannerConfig {
            max_pages,
            max_depth,
            ..ScannerConfig::default()
        }
    }

    #[test]
    fn crawl_respects_max_pages() {
        let html = r#"<html><body>
            <a href="/a">a</a> <a href="/b">b</a> <a href="/c">c</a>
            <a href="/d">d</a> <a href="/e">e</a>
        </body></html>"#;
        let browser = StubBrowser::new(html);
        let store = MemFlowStore::new();
        let guard = scoped_guard("target.test");
        let client = NoSendClient;
        let host = CommandHost::new(&store, &client, &guard, Some(&browser));

        let out = block_on(crawl(&host, TARGET, &cfg(2, 3))).expect("crawl succeeds");

        assert_eq!(out.stopped_reason, Some("max_pages".into()));
        assert_eq!(out.pages_crawled, 2);
        assert_eq!(
            out.endpoints,
            vec![
                "http://target.test/".to_string(),
                "http://target.test/a".to_string()
            ]
        );
        assert_eq!(
            browser.navigated(),
            out.endpoints,
            "every navigation is a recorded endpoint"
        );
    }

    #[test]
    fn crawl_skips_out_of_scope() {
        let html = r#"<html><body>
            <a href="/ok">same origin</a>
            <a href="http://evil.example/x">off origin</a>
            <a href="//evil.example/y">scheme-relative off origin</a>
            <form action="http://target.test:8080/other-port"></form>
            <form action="/submit"></form>
        </body></html>"#;
        let browser = StubBrowser::new(html);
        let store = MemFlowStore::new();
        let guard = scoped_guard("target.test");
        let client = NoSendClient;
        let host = CommandHost::new(&store, &client, &guard, Some(&browser));

        let out =
            block_on(crawl(&host, TARGET, &ScannerConfig::default())).expect("crawl succeeds");

        assert_eq!(
            out.endpoints,
            vec![
                "http://target.test/".to_string(),
                "http://target.test/ok".to_string(),
                "http://target.test/submit".to_string(),
            ]
        );
        assert_eq!(out.pages_crawled, 3);
        assert_eq!(out.stopped_reason, None);
        for url in browser.navigated() {
            assert!(
                url.starts_with("http://target.test/"),
                "navigated off-origin: {url}"
            );
        }
        assert!(
            !out.endpoints.iter().any(|u| u.contains("evil.example")),
            "off-origin URL leaked into endpoints: {:?}",
            out.endpoints
        );
    }

    #[test]
    fn crawl_skips_same_origin_links_the_guard_rejects() {
        // Same origin as the target, but the guard has no entry for the host:
        // deny-by-default means not even the seed is navigated.
        let browser = StubBrowser::new(r#"<a href="/a">a</a>"#);
        let store = MemFlowStore::new();
        let guard = StdGuard::default(); // empty scope
        let client = NoSendClient;
        let host = CommandHost::new(&store, &client, &guard, Some(&browser));

        let err = block_on(crawl(&host, TARGET, &ScannerConfig::default()))
            .expect_err("an out-of-scope target is refused");
        assert_eq!(
            err.downcast_ref::<aitm_core::GuardError>(),
            Some(&aitm_core::GuardError::OutOfScope("target.test".into()))
        );
        assert!(browser.navigated().is_empty(), "nothing was navigated");
    }

    #[test]
    fn crawl_stops_at_max_depth() {
        let browser = StubBrowser::new("<p>leaf</p>")
            .page(TARGET, r#"<a href="/l1">l1</a>"#)
            .page("http://target.test/l1", r#"<a href="/l2">l2</a>"#)
            .page("http://target.test/l2", r#"<a href="/l3">l3</a>"#);
        let store = MemFlowStore::new();
        let guard = scoped_guard("target.test");
        let client = NoSendClient;
        let host = CommandHost::new(&store, &client, &guard, Some(&browser));

        let out = block_on(crawl(&host, TARGET, &cfg(50, 1))).expect("crawl succeeds");

        assert_eq!(
            out.endpoints,
            vec![
                "http://target.test/".to_string(),
                "http://target.test/l1".to_string()
            ]
        );
        assert_eq!(out.pages_crawled, 2);
        assert_eq!(out.stopped_reason, Some("max_depth".into()));
    }

    #[test]
    fn crawl_exhausts_graph_with_no_stop_reason() {
        let browser = StubBrowser::new("<p>leaf</p>").page(
            TARGET,
            r##"<a href="/a#frag">a</a> <a href="a">a again</a> <a href="./b?x=1&amp;y=2">b</a>
               <a href="javascript:void(0)">js</a> <a href="mailto:x@y">mail</a> <a href="#top">frag</a>
               <A HREF='/c'>upper</A>"##,
        );
        let store = MemFlowStore::new();
        let guard = scoped_guard("target.test");
        let client = NoSendClient;
        let host = CommandHost::new(&store, &client, &guard, Some(&browser));

        let out =
            block_on(crawl(&host, TARGET, &ScannerConfig::default())).expect("crawl succeeds");

        assert_eq!(
            out.endpoints,
            vec![
                "http://target.test/".to_string(),
                "http://target.test/a".to_string(),
                "http://target.test/b?x=1&y=2".to_string(),
                "http://target.test/c".to_string(),
            ]
        );
        assert_eq!(out.pages_crawled, 4);
        assert_eq!(out.stopped_reason, None);
    }

    #[test]
    fn crawl_stops_on_time_budget() {
        let browser = StubBrowser::new(r#"<a href="/a">a</a> <a href="/b">b</a>"#);
        let store = MemFlowStore::new();
        let guard = scoped_guard("target.test");
        let client = NoSendClient;
        let host = CommandHost::new(&store, &client, &guard, Some(&browser));
        let cfg = ScannerConfig {
            time_budget: Duration::ZERO,
            ..ScannerConfig::default()
        };

        let out = block_on(crawl(&host, TARGET, &cfg)).expect("crawl succeeds");

        assert_eq!(out.stopped_reason, Some("time_budget".into()));
        assert_eq!(out.pages_crawled, 0);
        assert!(browser.navigated().is_empty());
    }

    #[test]
    fn crawl_without_browser_lists_stored_in_scope_urls() {
        let store = MemFlowStore::new();
        store.insert(captured("http", "target.test", "/one?q=1"));
        store.insert(captured("http", "target.test", "/one?q=1")); // duplicate
        store.insert(captured("http", "target.test", "/two#frag"));
        store.insert(captured("http", "evil.example", "/x")); // off origin
        store.insert(captured("https", "target.test", "/tls")); // other origin
        let guard = scoped_guard("target.test");
        let client = NoSendClient;
        let host = CommandHost::new(&store, &client, &guard, None);

        let out =
            block_on(crawl(&host, TARGET, &ScannerConfig::default())).expect("crawl succeeds");

        assert_eq!(out.stopped_reason, Some("no_browser".into()));
        assert_eq!(out.pages_crawled, 0);
        assert_eq!(
            out.endpoints,
            vec![
                "http://target.test/one?q=1".to_string(),
                "http://target.test/two".to_string(),
            ]
        );
    }

    #[test]
    fn crawl_rejects_unparseable_target() {
        let store = MemFlowStore::new();
        let guard = scoped_guard("target.test");
        let client = NoSendClient;
        let host = CommandHost::new(&store, &client, &guard, None);

        let err = block_on(crawl(&host, "not a url", &ScannerConfig::default()))
            .expect_err("a target without scheme://host is refused");
        assert!(
            err.to_string().contains("not a url"),
            "names the input: {err}"
        );
    }
}
