//! Breadth-first crawl of an in-scope target through the embedded browser.
//!
//! Read-only link discovery: every page is reached by a plain navigation, its
//! DOM is scanned for anchor `href` and form `action` attributes, and only links
//! that are same-origin with the target **and** in the guard's scope are
//! followed. Off-origin or out-of-scope links are dropped without being fetched
//! or recorded. Every navigation takes an [`aitm_core::ActionPermit`] from
//! `check_active`, so the scan is rate-, concurrency- and error-budget-bound the
//! same way `browser.navigate` is, and it is capped by `max_pages`, `max_depth`
//! and `time_budget` from [`ScannerConfig`].
//!
//! URLs are parsed with the `url` crate — the same WHATWG parser the browser
//! resolves a link with — so the host the scope check is made about is exactly
//! the host the browser would connect to (`http://evil.com\.target.test/` has
//! host `evil.com`, not `evil.com\.target.test`).

use std::collections::{HashSet, VecDeque};
use std::time::{Duration, Instant};

use aitm_core::{CommandHost, Flow, GuardError};
use url::Url;

use crate::ScannerConfig;

/// Links harvested from one page. A hostile page with a million anchors cannot
/// grow the frontier past this per visit.
const MAX_LINKS_PER_PAGE: usize = 512;

/// Hard ceiling on the pending frontier, independent of `max_pages`: the queue
/// and the visited set cannot grow without bound on a page that links to a
/// combinatorial URL space.
const MAX_FRONTIER: usize = 4096;

/// Bytes of a page's DOM that are scanned for links. The rest is ignored.
const MAX_DOM_BYTES: usize = 2 * 1024 * 1024;

/// What a crawl reached and why it stopped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrawlOutcome {
    /// Normalized in-scope URLs reached, in crawl order, deduplicated. A
    /// request that redirected within scope is recorded as well as the page it
    /// landed on (requested first).
    pub endpoints: Vec<String>,
    /// Pages successfully navigated. Failed navigations are **not** counted
    /// here, but they do count against `max_pages` (see [`crawl`]).
    pub pages_crawled: usize,
    /// `"max_pages"`, `"max_depth"`, `"time_budget"`, `"no_browser"`,
    /// `"left_scope"` (a navigation landed off-origin or out of scope — a
    /// redirect — and the crawl aborted there),
    /// `"navigation_failed"` (the browser was there but every navigation
    /// failed), `"guard_refused"` (the guard refused every enqueued link), or
    /// `None` when the reachable graph was exhausted.
    pub stopped_reason: Option<String>,
}

/// Crawl breadth-first from `target`, following only same-origin, in-scope links.
///
/// The target itself must be an absolute, credential-free `http(s)` URL whose
/// host the guard has in scope; otherwise this returns [`GuardError::OutOfScope`]
/// (deny-by-default) and navigates nothing. Without a browser on the host the
/// crawl falls back to listing the distinct same-origin, in-scope request URLs
/// already captured in the flow store and reports
/// `stopped_reason = Some("no_browser")`.
///
/// Every navigation is gated: `check_active` is called for the page's authority
/// and its permit is held across the navigation, so each page consumes a rate
/// token and a concurrency slot. A navigation that fails records an error
/// against the host (feeding the guard's back-off) and counts against
/// `max_pages`, so a target that refuses connections cannot be retried
/// unboundedly under the time budget alone. A guard refusal on the seed is
/// propagated; a refusal on an enqueued link skips that link.
pub async fn crawl(
    host: &CommandHost<'_>,
    target: &str,
    cfg: &ScannerConfig,
) -> anyhow::Result<CrawlOutcome> {
    let seed = parse_target(target).ok_or_else(|| {
        anyhow::anyhow!(
            "target is not an absolute, credential-free http(s) URL: {}",
            safe_target(target)
        )
    })?;
    let authority = guard_authority(&seed);
    if !host.guard().in_scope(&authority) {
        return Err(GuardError::OutOfScope(authority).into());
    }
    let origin = seed.origin();
    let Some(browser) = host.browser() else {
        // Nothing is fetched on this path, but the host must still be one the
        // guard would let us act on (not disabled, not rate-exhausted). This is
        // the command's single gate check for a store-only discovery.
        drop(host.guard().check_active(&authority)?);
        return Ok(stored_endpoints(host, &seed, cfg));
    };

    let started = Instant::now();
    let mut queue: VecDeque<(Url, usize)> = VecDeque::from([(seed.clone(), 0)]);
    let mut visited: HashSet<String> = HashSet::from([seed.as_str().to_string()]);
    let mut endpoints: Vec<String> = Vec::new();
    let mut seen_endpoints: HashSet<String> = HashSet::new();
    // Navigations attempted, successful or not — what `max_pages` bounds, so a
    // target that refuses every connection cannot be retried unboundedly.
    let mut attempts = 0usize;
    let mut pages_crawled = 0usize;
    let mut nav_failures = 0usize;
    let mut guard_refusals = 0usize;
    let mut depth_hit = false;
    let mut stopped: Option<&str> = None;
    let mut is_seed = true;

    while let Some((url, depth)) = queue.pop_front() {
        let Some(remaining) = remaining_budget(cfg.time_budget, started) else {
            stopped = Some("time_budget");
            break;
        };
        if attempts >= cfg.max_pages {
            stopped = Some("max_pages");
            break;
        }

        let page_authority = guard_authority(&url);
        // Per-navigation gate: scope, rate, concurrency and the host's error
        // budget, exactly as `browser.navigate` does for a single call. The
        // permit is held until this page is done and released by `drop`.
        let permit = match host.guard().check_active(&page_authority) {
            Ok(permit) => permit,
            // Deny-by-default on the seed is the caller's answer; a refusal on
            // a link found mid-crawl only drops that link.
            Err(err) if is_seed => return Err(err.into()),
            Err(_) => {
                guard_refusals += 1;
                continue;
            }
        };
        is_seed = false;

        attempts += 1;
        let nav = match tokio::time::timeout(remaining, browser.navigate(url.as_str())).await {
            Ok(Ok(nav)) => nav,
            Ok(Err(_err)) => {
                // Best-effort: an unreachable page is skipped, but it is counted
                // and reported to the guard so a refusing host backs off.
                nav_failures += 1;
                host.guard().record_error(&page_authority);
                drop(permit);
                continue;
            }
            Err(_elapsed) => {
                drop(permit);
                stopped = Some("time_budget");
                break;
            }
        };
        pages_crawled += 1;

        // A redirect or meta-refresh may have taken the browser somewhere else.
        // A landing page that is off-origin or out of scope ends the crawl on
        // the spot (`left_scope`): neither it nor the requested URL is recorded,
        // nothing is harvested, and no further page is navigated. Silently
        // continuing would let a target walk the browser around other hosts
        // one redirect at a time.
        let Some(page) = parse_target(&nav.final_url)
            .filter(|u| u.origin() == origin && host.guard().in_scope(&guard_authority(u)))
        else {
            drop(permit);
            stopped = Some("left_scope");
            break;
        };
        // The requested URL passed the enqueue filter and this page's gate, so
        // a request that redirected within scope is a reachable endpoint in its
        // own right (its parameters are the redirector's attack surface), not
        // only the page it landed on. Record it first.
        let page_key = page.as_str().to_string();
        visited.insert(page_key.clone());
        for key in [url.as_str().to_string(), page_key] {
            if seen_endpoints.insert(key.clone()) {
                endpoints.push(key);
            }
        }

        let Some(remaining) = remaining_budget(cfg.time_budget, started) else {
            drop(permit);
            stopped = Some("time_budget");
            break;
        };
        let dom = match tokio::time::timeout(remaining, browser.get_dom()).await {
            Ok(Ok(dom)) => dom,
            Ok(Err(_err)) => {
                host.guard().record_error(&page_authority);
                drop(permit);
                continue;
            }
            Err(_elapsed) => {
                drop(permit);
                stopped = Some("time_budget");
                break;
            }
        };
        drop(permit);

        for link in harvest_links(crate::util::truncate_on_char_boundary(&dom, MAX_DOM_BYTES)) {
            let Ok(resolved) = page.join(&link) else {
                continue;
            };
            let Some(resolved) = normalize(resolved) else {
                continue;
            };
            // Re-checked per link, not only per origin: scope can be revoked
            // mid-crawl (`remove_scope`), and the crawl must honour that.
            if resolved.origin() != origin || !host.guard().in_scope(&guard_authority(&resolved)) {
                continue;
            }
            let key = resolved.as_str().to_string();
            if visited.contains(&key) {
                continue;
            }
            if depth + 1 > cfg.max_depth {
                depth_hit = true;
                continue;
            }
            if queue.len() >= MAX_FRONTIER {
                continue;
            }
            visited.insert(key);
            queue.push_back((resolved, depth + 1));
        }
    }

    let stopped_reason = stopped
        .or(depth_hit.then_some("max_depth"))
        // A crawl that reached nothing must not look like an exhausted graph.
        .or((pages_crawled == 0 && nav_failures > 0).then_some("navigation_failed"))
        .or((pages_crawled == 0 && guard_refusals > 0).then_some("guard_refused"))
        .map(str::to_string);
    Ok(CrawlOutcome {
        endpoints,
        pages_crawled,
        stopped_reason,
    })
}

/// Normalize an absolute `http(s)` URL to the same canonical form the crawl
/// records its endpoints in (WHATWG normalization: lowercase scheme and host,
/// default port elided, dot-segments removed, fragment dropped, query kept).
/// Returns `None` for anything that is not an absolute, credential-free
/// `http(s)` URL.
///
/// `scan.discover` uses this to match a captured flow's request URL against the
/// crawl's endpoint set, so the two are compared in one normal form.
pub(crate) fn normalize_url(s: &str) -> Option<String> {
    parse_target(s).map(|u| u.as_str().to_string())
}

/// A target string that is safe to put in an error message: userinfo removed,
/// embedded credential material scrubbed, and length-capped.
///
/// A target that does not parse as a URL has no structure to rely on, so its
/// userinfo is stripped textually ([`strip_unparsed_userinfo`]) rather than the
/// string being echoed verbatim.
pub(crate) fn safe_target(target: &str) -> String {
    let bare = match Url::parse(target.trim()) {
        Ok(mut url) => {
            let _ = url.set_username("");
            let _ = url.set_password(None);
            url.set_fragment(None);
            url.to_string()
        }
        Err(_) => strip_unparsed_userinfo(target),
    };
    let scrubbed = aitm_core::redact::scrub_text(&bare);
    crate::util::truncate_on_char_boundary(&scrubbed, 256).to_string()
}

/// Bytes that can never appear raw inside a URL's userinfo once it is
/// percent-encoded the WHATWG way, and so end an authority in free text:
/// whitespace, the path/query/fragment delimiters, and quoting characters.
/// Sub-delimiters (`&`, `;`, `,`, `'`) are *not* here — they are legal raw in a
/// password, and treating one as the end of the authority would leave the rest
/// of that password in the output.
fn ends_authority(b: u8) -> bool {
    b.is_ascii_whitespace()
        || matches!(
            b,
            b'/' | b'?' | b'#' | b'\\' | b'"' | b'<' | b'>' | b'`' | b'{' | b'}'
        )
}

/// Remove URL userinfo from free text: for every `//authority` in `text`,
/// everything up to the *last* `@` of that authority is dropped
/// (`http://user:pw@host/x` → `http://host/x`). The last `@` wins because an
/// unencoded `@` inside a password is still credential. An `@` after the
/// authority has ended (path, query) is left alone.
///
/// One linear pass: each authority is scanned once and the scan resumes where it
/// ended, so a hostile body cannot make this quadratic.
pub(crate) fn strip_userinfo(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    // Start of the text not yet copied into `out`.
    let mut copied = 0;
    let mut i = 0;
    while i + 1 < bytes.len() {
        if bytes[i] != b'/' || bytes[i + 1] != b'/' {
            i += 1;
            continue;
        }
        let start = i + 2;
        let mut end = start;
        let mut last_at = None;
        while end < bytes.len() && !ends_authority(bytes[end]) {
            if bytes[end] == b'@' {
                last_at = Some(end);
            }
            end += 1;
        }
        if let Some(at) = last_at {
            // Every index here follows an ASCII byte (`/` or `@`), so it is a
            // char boundary.
            out.push_str(&text[copied..start]);
            copied = at + 1;
        }
        i = end;
    }
    out.push_str(&text[copied..]);
    out
}

/// Strip userinfo from a target that did not parse as a URL: every
/// `//authority@` ([`strip_userinfo`]), then — for a scheme-less `user@host/…`,
/// which has no `//` to anchor on — everything up to the last `@` that precedes
/// the first `/`. Over-strips on garbage input rather than leaving a credential.
fn strip_unparsed_userinfo(target: &str) -> String {
    let stripped = strip_userinfo(target);
    let head_end = stripped.find('/').unwrap_or(stripped.len());
    match stripped[..head_end].rfind('@') {
        Some(at) => stripped[at + 1..].to_string(),
        None => stripped,
    }
}

/// Parse an absolute `http(s)` URL the way the browser does, with the fragment
/// dropped. A URL that carries userinfo is refused outright: a crawl never
/// carries credentials, and `http://target.test@evil.com/` reads as the target
/// to a human while the browser connects to `evil.com`.
fn parse_target(s: &str) -> Option<Url> {
    Url::parse(s.trim()).ok().and_then(normalize)
}

/// The shared post-parse checks and normalization for a parsed URL.
fn normalize(mut url: Url) -> Option<Url> {
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
    url.set_fragment(None);
    Some(url)
}

/// The `host[:port]` the scope guard is asked about, always with an explicit
/// port (the scheme's default when the URL elides it) so an explicit
/// `target.test:443` scope entry matches a portless `https://target.test/`.
/// A portless scope entry still covers every port of its host.
fn guard_authority(url: &Url) -> String {
    let host = url.host_str().unwrap_or_default();
    let authority = match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    };
    crate::util::guard_authority(url.scheme(), &authority)
}

/// The guard `host:port` for a bare target string: [`parse_target`] then
/// [`guard_authority`], so a target is parsed, refused (userinfo, non-`http(s)`
/// scheme, no host) and folded to an authority exactly the way the crawl's own
/// seed is. The one entry point other engines (`inject`) use, so they cannot
/// grow a second, laxer parser.
pub(crate) fn guard_authority_for(target: &str) -> Option<String> {
    parse_target(target).map(|url| guard_authority(&url))
}

/// The time left in the budget, or `None` when it is spent.
fn remaining_budget(budget: Duration, started: Instant) -> Option<Duration> {
    budget
        .checked_sub(started.elapsed())
        .filter(|left| !left.is_zero())
}

/// Bridge a `crawl` future from a synchronous command.
///
/// On a multi-thread runtime, block in place so the blocking call cannot starve
/// the reactor (the browser's CDP futures need the reactor turning, which a bare
/// `futures::executor` would not do). With no runtime at all, drive the future on
/// a private current-thread runtime **with timers enabled** — the crawl arms a
/// `tokio::time::timeout` on every navigation and there would otherwise be no
/// timer to fire it.
///
/// Calling this from inside a *current-thread* runtime is not supported: tokio
/// refuses to block a runtime thread. The binary always runs multi-threaded and
/// invokes commands through `spawn_blocking`.
pub(crate) fn block_on<F: std::future::Future>(fut: F) -> F::Output {
    use tokio::runtime::{Builder, Handle, RuntimeFlavor};
    if let Ok(handle) = Handle::try_current() {
        if matches!(handle.runtime_flavor(), RuntimeFlavor::MultiThread) {
            return tokio::task::block_in_place(|| handle.block_on(fut));
        }
    }
    match Builder::new_current_thread().enable_time().build() {
        Ok(rt) => rt.block_on(fut),
        // No OS resources for a runtime: fall back to a bare executor. Timers
        // never fire there, so the per-page budget checks are the only bound.
        Err(_) => futures::executor::block_on(fut),
    }
}

/// The no-browser fallback: distinct same-origin, in-scope request URLs already
/// in the store, in insertion order, capped at `max_pages`.
fn stored_endpoints(host: &CommandHost<'_>, seed: &Url, cfg: &ScannerConfig) -> CrawlOutcome {
    let origin = seed.origin();
    let mut seen: HashSet<String> = HashSet::new();
    let mut endpoints = Vec::new();
    for id in host.store().list() {
        if endpoints.len() >= cfg.max_pages {
            break;
        }
        let Some(Flow::Http(flow)) = host.store().get(id) else {
            continue;
        };
        let req = &flow.request;
        let Some(url) = parse_target(&format!("{}://{}{}", req.scheme, req.authority, req.path))
        else {
            continue;
        };
        if url.origin() != origin || !host.guard().in_scope(&guard_authority(&url)) {
            continue;
        }
        let key = url.as_str().to_string();
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

/// Every `<a href=…>`, `<area href=…>` and `<form action=…>` value in `html`, in
/// document order, with the common HTML entities decoded.
///
/// Tag-aware by construction: the scan walks tag openings and reads the
/// attribute only from an anchor or a form, so `data-href`, `<link href>`,
/// `<base href>`, `<script>` contents and HTML comments are never harvested. At
/// most [`MAX_LINKS_PER_PAGE`] links are returned.
fn harvest_links(html: &str) -> Vec<String> {
    let bytes = html.as_bytes();
    let mut links = Vec::new();
    let mut i = 0;
    while i < bytes.len() && links.len() < MAX_LINKS_PER_PAGE {
        if bytes[i] != b'<' {
            i += 1;
            continue;
        }
        // A comment is not markup: a commented-out anchor is not a link.
        if html[i..].starts_with("<!--") {
            i = html[i..].find("-->").map_or(bytes.len(), |off| i + off + 3);
            continue;
        }
        let name_start = i + 1;
        let mut j = name_start;
        while j < bytes.len() && bytes[j].is_ascii_alphanumeric() {
            j += 1;
        }
        if j == name_start {
            i += 1;
            continue;
        }
        let tag = html[name_start..j].to_ascii_lowercase();
        // Raw-text elements: their content is script or CSS, not markup, so
        // `var action = "/api/delete"` inside one is not a link.
        if tag == "script" || tag == "style" {
            i = crate::util::find_close_tag(html, &tag, j, bytes.len()).unwrap_or(bytes.len());
            continue;
        }
        let wanted = match tag.as_str() {
            "a" | "area" => "href",
            "form" => "action",
            _ => {
                i = j;
                continue;
            }
        };
        let (after_tag, value) = tag_attribute(html, j, wanted);
        if let Some(value) = value {
            links.push(crate::util::decode_entities(value));
        }
        i = after_tag;
    }
    links
}

/// Walk the attributes of the tag whose name ends at `from`, returning the index
/// just past the tag's `>` and the first value of the `wanted` attribute.
/// Attribute names are matched whole, so `data-href` is not `href`.
fn tag_attribute<'a>(html: &'a str, from: usize, wanted: &str) -> (usize, Option<&'a str>) {
    let bytes = html.as_bytes();
    let mut i = from;
    let mut found: Option<&'a str> = None;
    while i < bytes.len() {
        if bytes[i] == b'>' {
            return (i + 1, found);
        }
        if bytes[i].is_ascii_whitespace() || bytes[i] == b'/' {
            i += 1;
            continue;
        }
        // An attribute name runs to whitespace, `=`, `/` or `>`.
        let name_start = i;
        while i < bytes.len() && !bytes[i].is_ascii_whitespace() && !matches!(bytes[i], b'=' | b'>')
        {
            i += 1;
        }
        let name = &html[name_start..i];
        let mut k = i;
        while k < bytes.len() && bytes[k].is_ascii_whitespace() {
            k += 1;
        }
        if k >= bytes.len() {
            return (bytes.len(), found);
        }
        if bytes[k] != b'=' {
            // A valueless attribute; `i` already points past its name.
            continue;
        }
        k += 1;
        while k < bytes.len() && bytes[k].is_ascii_whitespace() {
            k += 1;
        }
        if k >= bytes.len() {
            return (bytes.len(), found);
        }
        let (value, next) = match bytes[k] {
            quote @ (b'"' | b'\'') => {
                let start = k + 1;
                match html[start..].find(quote as char) {
                    Some(len) => (&html[start..start + len], start + len + 1),
                    None => return (bytes.len(), found),
                }
            }
            b'>' => {
                i = k;
                continue;
            }
            _ => {
                let start = k;
                let len = html[start..]
                    .find(|c: char| c.is_ascii_whitespace() || c == '>')
                    .unwrap_or(html.len() - start);
                (&html[start..start + len], start + len)
            }
        };
        if found.is_none() && name.eq_ignore_ascii_case(wanted) {
            found = Some(value);
        }
        i = next;
    }
    (bytes.len(), found)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aitm_core::{
        ActionPermit, Body, ClickTarget, ConnInfo, Flow, FlowId, FlowMeta, FlowStore, HeaderMap,
        HttpFlow, HttpRequest, HttpVersion, InterceptState, MemFlowStore, NavOutcome, ProxyClient,
        ScopeEntry, ScopeRateGuard, StdGuard, Value,
    };
    use futures::future::BoxFuture;
    use std::collections::BTreeMap;
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;
    use std::time::SystemTime;

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
    /// `default_html`) and records every navigation it is asked for. With
    /// `fail_after(n)` set, every navigation from the `n`th on fails.
    struct StubBrowser {
        pages: BTreeMap<String, String>,
        /// Navigated URL → the `final_url` the browser reports (a redirect).
        redirects: BTreeMap<String, String>,
        default_html: String,
        fail_after: usize,
        current: Mutex<Option<String>>,
        navigated: Mutex<Vec<String>>,
    }

    impl StubBrowser {
        fn new(default_html: &str) -> Self {
            Self {
                pages: BTreeMap::new(),
                redirects: BTreeMap::new(),
                default_html: default_html.to_string(),
                fail_after: usize::MAX,
                current: Mutex::new(None),
                navigated: Mutex::new(Vec::new()),
            }
        }

        fn page(mut self, url: &str, html: &str) -> Self {
            self.pages.insert(url.to_string(), html.to_string());
            self
        }

        fn fail_after(mut self, n: usize) -> Self {
            self.fail_after = n;
            self
        }

        /// Navigating `url` lands on `final_url`, as after a server redirect.
        fn redirect(mut self, url: &str, final_url: &str) -> Self {
            self.redirects
                .insert(url.to_string(), final_url.to_string());
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
                let nth = {
                    let mut log = self.navigated.lock().expect("navigated lock");
                    log.push(url.clone());
                    log.len() - 1
                };
                if nth >= self.fail_after {
                    anyhow::bail!("stub navigation refused: {url}");
                }
                let final_url = self.redirects.get(&url).cloned().unwrap_or(url);
                *self.current.lock().expect("current lock") = Some(final_url.clone());
                Ok(NavOutcome {
                    final_url,
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

    /// A guard that grants the first `allow` `check_active` calls and refuses
    /// every later one, counting the calls and the errors recorded.
    struct CountingGuard {
        inner: StdGuard,
        allow: usize,
        checks: AtomicUsize,
        errors: Mutex<Vec<String>>,
    }

    impl CountingGuard {
        fn new(host: &str, allow: usize) -> Self {
            let inner = StdGuard::default();
            inner.add_scope(ScopeEntry { host: host.into() });
            Self {
                inner,
                allow,
                checks: AtomicUsize::new(0),
                errors: Mutex::new(Vec::new()),
            }
        }

        fn checks(&self) -> usize {
            self.checks.load(Ordering::SeqCst)
        }

        fn errors(&self) -> Vec<String> {
            self.errors.lock().expect("errors lock").clone()
        }
    }

    impl ScopeRateGuard for CountingGuard {
        fn check_active(&self, host: &str) -> Result<ActionPermit, GuardError> {
            let n = self.checks.fetch_add(1, Ordering::SeqCst);
            if n >= self.allow {
                return Err(GuardError::RateLimited {
                    retry_after: Duration::from_secs(1),
                });
            }
            self.inner.check_active(host)
        }

        fn add_scope(&self, entry: ScopeEntry) {
            self.inner.add_scope(entry);
        }

        fn remove_scope(&self, entry: &str) -> bool {
            self.inner.remove_scope(entry)
        }

        fn list_scope(&self) -> Vec<ScopeEntry> {
            self.inner.list_scope()
        }

        fn in_scope(&self, host: &str) -> bool {
            self.inner.in_scope(host)
        }

        fn record_error(&self, host: &str) {
            self.errors
                .lock()
                .expect("errors lock")
                .push(host.to_string());
            self.inner.record_error(host);
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

    #[tokio::test]
    async fn crawl_respects_max_pages() {
        let html = r#"<html><body>
            <a href="/a">a</a> <a href="/b">b</a> <a href="/c">c</a>
            <a href="/d">d</a> <a href="/e">e</a>
        </body></html>"#;
        let browser = StubBrowser::new(html);
        let store = MemFlowStore::new();
        let guard = scoped_guard("target.test");
        let client = NoSendClient;
        let host = CommandHost::new(&store, &client, &guard, Some(&browser));

        let out = crawl(&host, TARGET, &cfg(2, 3))
            .await
            .expect("crawl succeeds");

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

    #[tokio::test]
    async fn crawl_skips_out_of_scope() {
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

        let out = crawl(&host, TARGET, &ScannerConfig::default())
            .await
            .expect("crawl succeeds");

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

    /// A navigation whose landing page is off-origin or out of scope (a server
    /// redirect) aborts the crawl: the landing page is not recorded, nothing
    /// is harvested from it, and no further page is navigated.
    #[tokio::test]
    async fn crawl_aborts_on_off_scope_landing() {
        let browser = StubBrowser::new(r#"<a href="/after">after</a>"#)
            .page(TARGET, r#"<a href="/go">go</a> <a href="/stay">stay</a>"#)
            // The in-scope link `/go` is navigated, but the server sends the
            // browser to another host.
            .redirect("http://target.test/go", "http://evil.example/landing");
        let store = MemFlowStore::new();
        let guard = scoped_guard("target.test");
        let client = NoSendClient;
        let host = CommandHost::new(&store, &client, &guard, Some(&browser));

        let out = crawl(&host, TARGET, &ScannerConfig::default())
            .await
            .expect("leaving scope is an outcome, not an error");

        assert_eq!(out.stopped_reason, Some("left_scope".into()));
        assert_eq!(
            out.endpoints,
            vec!["http://target.test/".to_string()],
            "the off-scope landing page is not recorded"
        );
        assert_eq!(
            browser.navigated(),
            vec![
                "http://target.test/".to_string(),
                "http://target.test/go".to_string()
            ],
            "the crawl stopped at the redirect: `/stay` was never navigated"
        );
        assert!(
            !out.endpoints.iter().any(|u| u.contains("evil.example")),
            "off-scope URL leaked into endpoints: {:?}",
            out.endpoints
        );
    }

    /// `guard_authority_for` is the one place a bare target string becomes the
    /// `host:port` the guard is asked about, shared with `inject`: it folds the
    /// default port in, and refuses what `parse_target` refuses (userinfo, a
    /// non-http scheme, no host).
    #[test]
    fn guard_authority_for_folds_port_and_rejects_userinfo() {
        assert_eq!(
            guard_authority_for("http://target.test/"),
            Some("target.test:80".to_string())
        );
        assert_eq!(
            guard_authority_for(" https://Target.Test/a/b?q=1 "),
            Some("target.test:443".to_string())
        );
        assert_eq!(
            guard_authority_for("http://target.test:8080/"),
            Some("target.test:8080".to_string())
        );
        // `http://target.test@evil.com/` reads as the target to a human while the
        // client connects to `evil.com`: refused outright, as are credentials.
        assert_eq!(guard_authority_for("http://user:pw@target.test/"), None);
        assert_eq!(guard_authority_for("http://target.test@evil.com/"), None);
        assert_eq!(guard_authority_for("ftp://target.test/"), None);
        assert_eq!(guard_authority_for("not a url"), None);
    }

    /// A same-origin, in-scope redirect is a reachable endpoint in its own
    /// right: the requested URL is recorded as well as the page it landed on,
    /// and the crawl carries on past it.
    #[tokio::test]
    async fn crawl_records_a_same_origin_redirect_request_as_an_endpoint() {
        let browser = StubBrowser::new("<p>leaf</p>")
            .page(TARGET, r#"<a href="/go">go</a> <a href="/other">other</a>"#)
            .redirect("http://target.test/go", "http://target.test/landing");
        let store = MemFlowStore::new();
        let guard = scoped_guard("target.test");
        let client = NoSendClient;
        let host = CommandHost::new(&store, &client, &guard, Some(&browser));

        let out = crawl(&host, TARGET, &ScannerConfig::default())
            .await
            .expect("crawl succeeds");

        assert_eq!(
            out.endpoints,
            vec![
                "http://target.test/".to_string(),
                "http://target.test/go".to_string(),
                "http://target.test/landing".to_string(),
                "http://target.test/other".to_string(),
            ],
            "the redirecting request and its landing page are both recorded, requested first"
        );
        assert_eq!(out.pages_crawled, 3);
        assert_eq!(out.stopped_reason, None);
        assert_eq!(
            browser.navigated(),
            vec![
                "http://target.test/".to_string(),
                "http://target.test/go".to_string(),
                "http://target.test/other".to_string(),
            ],
            "the crawl continued past the in-scope redirect"
        );
    }

    /// A redirect that lands on a page already recorded (here the seed) adds
    /// only the requested URL; the landing page is not duplicated.
    #[tokio::test]
    async fn crawl_dedups_a_redirect_that_lands_on_an_already_recorded_page() {
        let browser = StubBrowser::new("<p>leaf</p>")
            .page(TARGET, r#"<a href="/go">go</a>"#)
            .redirect("http://target.test/go", TARGET);
        let store = MemFlowStore::new();
        let guard = scoped_guard("target.test");
        let client = NoSendClient;
        let host = CommandHost::new(&store, &client, &guard, Some(&browser));

        let out = crawl(&host, TARGET, &ScannerConfig::default())
            .await
            .expect("crawl succeeds");

        assert_eq!(
            out.endpoints,
            vec![
                "http://target.test/".to_string(),
                "http://target.test/go".to_string(),
            ],
            "the seed is recorded once even though `/go` lands on it"
        );
        assert_eq!(out.pages_crawled, 2);
        assert_eq!(out.stopped_reason, None);
        assert_eq!(
            browser.navigated(),
            vec![
                "http://target.test/".to_string(),
                "http://target.test/go".to_string(),
            ]
        );
    }

    /// `\` is a path separator to a WHATWG browser, so the host of
    /// `http://evil.com\.target.test/` is `evil.com` — it must not pass a
    /// `*.target.test` scope entry by looking like a subdomain.
    #[tokio::test]
    async fn crawl_rejects_backslash_host_scope_bypass() {
        let hostile = "http://evil.com\\.target.test/";
        assert_eq!(
            parse_target(hostile)
                .map(|u| guard_authority(&u))
                .expect("the URL parses"),
            "evil.com:80",
            "the backslash ends the host, as the browser reads it"
        );

        let browser = StubBrowser::new(&format!(r#"<a href="{hostile}">bypass</a>"#));
        let store = MemFlowStore::new();
        let guard = scoped_guard("*.target.test");
        let client = NoSendClient;
        let host = CommandHost::new(&store, &client, &guard, Some(&browser));

        // As a seed: refused outright, nothing is navigated.
        let err = crawl(&host, hostile, &ScannerConfig::default())
            .await
            .expect_err("the real host evil.com is out of scope");
        assert_eq!(
            err.downcast_ref::<GuardError>(),
            Some(&GuardError::OutOfScope("evil.com:80".into()))
        );
        assert!(browser.navigated().is_empty(), "nothing was navigated");

        // As a link on an in-scope page: dropped before any navigation.
        let out = crawl(&host, "http://app.target.test/", &ScannerConfig::default())
            .await
            .expect("the in-scope seed crawls");
        assert_eq!(out.endpoints, vec!["http://app.target.test/".to_string()]);
        for url in browser.navigated() {
            assert!(
                !url.contains("evil.com"),
                "the crawler navigated the real host of the bypass URL: {url}"
            );
        }
    }

    #[tokio::test]
    async fn crawl_skips_same_origin_links_the_guard_rejects() {
        // Same origin as the target, but the guard has no entry for the host:
        // deny-by-default means not even the seed is navigated.
        let browser = StubBrowser::new(r#"<a href="/a">a</a>"#);
        let store = MemFlowStore::new();
        let guard = StdGuard::default(); // empty scope
        let client = NoSendClient;
        let host = CommandHost::new(&store, &client, &guard, Some(&browser));

        let err = crawl(&host, TARGET, &ScannerConfig::default())
            .await
            .expect_err("an out-of-scope target is refused");
        assert_eq!(
            err.downcast_ref::<GuardError>(),
            Some(&GuardError::OutOfScope("target.test:80".into()))
        );
        assert!(browser.navigated().is_empty(), "nothing was navigated");
    }

    /// Every navigation takes a permit: a guard that stops granting them stops
    /// the crawl's navigations, and the seed's refusal is propagated.
    #[tokio::test]
    async fn crawl_gates_every_navigation_on_check_active() {
        let browser = StubBrowser::new("<p>leaf</p>").page(
            TARGET,
            r#"<a href="/a">a</a> <a href="/b">b</a> <a href="/c">c</a>"#,
        );
        let store = MemFlowStore::new();
        // Two permits: the seed and one link. The rest are refused.
        let guard = CountingGuard::new("target.test", 2);
        let client = NoSendClient;
        let host = CommandHost::new(&store, &client, &guard, Some(&browser));

        let out = crawl(&host, TARGET, &ScannerConfig::default())
            .await
            .expect("a refusal on a link is not a crawl failure");

        assert_eq!(
            browser.navigated(),
            vec![
                "http://target.test/".to_string(),
                "http://target.test/a".to_string()
            ],
            "only the permitted navigations ran"
        );
        assert_eq!(out.pages_crawled, 2);
        assert_eq!(
            guard.checks(),
            4,
            "one check per dequeued page: seed, /a, /b, /c"
        );

        // The seed's own refusal is the caller's answer.
        let browser = StubBrowser::new("<p>leaf</p>");
        let guard = CountingGuard::new("target.test", 0);
        let host = CommandHost::new(&store, &client, &guard, Some(&browser));
        let err = crawl(&host, TARGET, &ScannerConfig::default())
            .await
            .expect_err("a refused seed fails the command");
        assert_eq!(
            err.downcast_ref::<GuardError>(),
            Some(&GuardError::RateLimited {
                retry_after: Duration::from_secs(1)
            })
        );
        assert!(browser.navigated().is_empty());
    }

    /// A target that refuses every connection is bounded by `max_pages`, not by
    /// the time budget alone, and each failure is reported to the guard.
    #[tokio::test]
    async fn crawl_counts_failed_navigations_toward_max_pages() {
        let browser = StubBrowser::new("<p>leaf</p>")
            .page(
                TARGET,
                r#"<a href="/a">a</a> <a href="/b">b</a> <a href="/c">c</a>
                   <a href="/d">d</a> <a href="/e">e</a>"#,
            )
            // The seed loads; every later navigation fails.
            .fail_after(1);
        let store = MemFlowStore::new();
        let guard = CountingGuard::new("target.test", usize::MAX);
        let client = NoSendClient;
        let host = CommandHost::new(&store, &client, &guard, Some(&browser));

        let out = crawl(&host, TARGET, &cfg(3, 5))
            .await
            .expect("a failed navigation is not a crawl failure");

        assert_eq!(
            browser.navigated(),
            vec![
                "http://target.test/".to_string(),
                "http://target.test/a".to_string(),
                "http://target.test/b".to_string(),
            ],
            "failed attempts count against max_pages"
        );
        assert_eq!(out.pages_crawled, 1);
        assert_eq!(out.endpoints, vec!["http://target.test/".to_string()]);
        assert_eq!(out.stopped_reason, Some("max_pages".into()));
        assert_eq!(
            guard.errors(),
            vec!["target.test:80".to_string(), "target.test:80".to_string()],
            "each failure is recorded against the host's error budget"
        );
    }

    /// A crawl that navigated nothing successfully says so, instead of looking
    /// like an exhausted graph.
    #[tokio::test]
    async fn crawl_reports_navigation_failed_when_nothing_loaded() {
        let browser = StubBrowser::new(r#"<a href="/a">a</a>"#).fail_after(0);
        let store = MemFlowStore::new();
        let guard = scoped_guard("target.test");
        let client = NoSendClient;
        let host = CommandHost::new(&store, &client, &guard, Some(&browser));

        let out = crawl(&host, TARGET, &ScannerConfig::default())
            .await
            .expect("a failed navigation is not a crawl failure");

        assert_eq!(browser.navigated(), vec!["http://target.test/".to_string()]);
        assert_eq!(out.pages_crawled, 0);
        assert!(out.endpoints.is_empty());
        assert_eq!(out.stopped_reason, Some("navigation_failed".into()));
    }

    #[tokio::test]
    async fn crawl_stops_at_max_depth() {
        let browser = StubBrowser::new("<p>leaf</p>")
            .page(TARGET, r#"<a href="/l1">l1</a>"#)
            .page("http://target.test/l1", r#"<a href="/l2">l2</a>"#)
            .page("http://target.test/l2", r#"<a href="/l3">l3</a>"#);
        let store = MemFlowStore::new();
        let guard = scoped_guard("target.test");
        let client = NoSendClient;
        let host = CommandHost::new(&store, &client, &guard, Some(&browser));

        let out = crawl(&host, TARGET, &cfg(50, 1))
            .await
            .expect("crawl succeeds");

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

    #[tokio::test]
    async fn crawl_exhausts_graph_with_no_stop_reason() {
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

        let out = crawl(&host, TARGET, &ScannerConfig::default())
            .await
            .expect("crawl succeeds");

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

    #[tokio::test]
    async fn crawl_stops_on_time_budget() {
        let browser = StubBrowser::new(r#"<a href="/a">a</a> <a href="/b">b</a>"#);
        let store = MemFlowStore::new();
        let guard = scoped_guard("target.test");
        let client = NoSendClient;
        let host = CommandHost::new(&store, &client, &guard, Some(&browser));
        let cfg = ScannerConfig {
            time_budget: Duration::ZERO,
            ..ScannerConfig::default()
        };

        let out = crawl(&host, TARGET, &cfg).await.expect("crawl succeeds");

        assert_eq!(out.stopped_reason, Some("time_budget".into()));
        assert_eq!(out.pages_crawled, 0);
        assert!(browser.navigated().is_empty());
    }

    /// A navigation that never completes is cut off at the remaining budget
    /// instead of blocking the command forever.
    #[tokio::test]
    async fn crawl_times_out_a_hung_navigation() {
        /// A browser whose navigation never resolves.
        struct HungBrowser;

        impl aitm_core::BrowserDriver for HungBrowser {
            fn navigate(&self, _url: &str) -> BoxFuture<'_, anyhow::Result<NavOutcome>> {
                Box::pin(std::future::pending())
            }

            fn click(&self, _target: ClickTarget) -> BoxFuture<'_, anyhow::Result<()>> {
                Box::pin(async { unimplemented!() })
            }

            fn type_text(&self, _selector: &str, _text: &str) -> BoxFuture<'_, anyhow::Result<()>> {
                Box::pin(async { unimplemented!() })
            }

            fn screenshot(&self) -> BoxFuture<'_, anyhow::Result<Vec<u8>>> {
                Box::pin(async { unimplemented!() })
            }

            fn eval(&self, _expr: &str) -> BoxFuture<'_, anyhow::Result<Value>> {
                Box::pin(async { unimplemented!() })
            }

            fn get_dom(&self) -> BoxFuture<'_, anyhow::Result<String>> {
                Box::pin(std::future::pending())
            }
        }

        let browser = HungBrowser;
        let store = MemFlowStore::new();
        let guard = scoped_guard("target.test");
        let client = NoSendClient;
        let host = CommandHost::new(&store, &client, &guard, Some(&browser));
        let cfg = ScannerConfig {
            time_budget: Duration::from_millis(50),
            ..ScannerConfig::default()
        };

        let started = Instant::now();
        let out = crawl(&host, TARGET, &cfg).await.expect("crawl succeeds");

        assert_eq!(out.stopped_reason, Some("time_budget".into()));
        assert_eq!(out.pages_crawled, 0);
        assert!(out.endpoints.is_empty());
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the hung navigation was cut off at the budget, not waited out"
        );
    }

    #[tokio::test]
    async fn crawl_without_browser_lists_stored_in_scope_urls() {
        let store = MemFlowStore::new();
        store.insert(captured("http", "target.test", "/one?q=1"));
        store.insert(captured("http", "target.test", "/one?q=1")); // duplicate
        store.insert(captured("http", "target.test", "/two#frag"));
        store.insert(captured("http", "evil.example", "/x")); // off origin
        store.insert(captured("https", "target.test", "/tls")); // other origin
        let guard = scoped_guard("target.test");
        let client = NoSendClient;
        let host = CommandHost::new(&store, &client, &guard, None);

        let out = crawl(&host, TARGET, &ScannerConfig::default())
            .await
            .expect("crawl succeeds");

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

    #[tokio::test]
    async fn crawl_rejects_unparseable_target() {
        let store = MemFlowStore::new();
        let guard = scoped_guard("target.test");
        let client = NoSendClient;
        let host = CommandHost::new(&store, &client, &guard, None);

        let err = crawl(&host, "not a url", &ScannerConfig::default())
            .await
            .expect_err("a target without scheme://host is refused");
        assert!(
            err.to_string().contains("not a url"),
            "names the input: {err}"
        );
    }

    /// A credentialed target is refused, and the refusal does not echo the
    /// credential back to the caller.
    #[tokio::test]
    async fn crawl_refuses_credentials_in_the_target_without_echoing_them() {
        let store = MemFlowStore::new();
        let guard = scoped_guard("target.test");
        let client = NoSendClient;
        let host = CommandHost::new(&store, &client, &guard, None);

        let err = crawl(
            &host,
            "http://admin:hunter2@target.test/",
            &ScannerConfig::default(),
        )
        .await
        .expect_err("a target carrying userinfo is refused");
        let text = err.to_string();
        assert!(!text.contains("hunter2"), "password echoed back: {text}");
        assert!(!text.contains("admin"), "username echoed back: {text}");
        assert!(text.contains("target.test"), "names the host: {text}");
    }

    /// Only real anchor and form targets are links: `data-href`, `<link>`,
    /// `<base>`, script bodies, comments and prose are not.
    #[test]
    fn harvest_links_is_tag_aware() {
        let html = r#"<html><head>
            <base href="/base">
            <link rel="stylesheet" href="/style.css">
            <script>var action = "/api/delete-all"; var href = "/js-href";</script>
          </head><body>
            <div data-href="/data-href" data-action="/data-action">the form's action = "/prose"</div>
            <!-- <a href="/commented">old</a> -->
            <a href="/real">real</a>
            <A HREF='/upper'>upper</A>
            <a class="x" href=/unquoted >unquoted</a>
            <area href="/area">
            <form method="post" action="/submit"></form>
            <a name="anchor-only">no href</a>
            <a href="/amp?x=1&amp;y=2">amp</a>
          </body></html>"#;

        assert_eq!(
            harvest_links(html),
            vec![
                "/real".to_string(),
                "/upper".to_string(),
                "/unquoted".to_string(),
                "/area".to_string(),
                "/submit".to_string(),
                "/amp?x=1&y=2".to_string(),
            ]
        );
    }

    /// `http://user:pw@host:99999/` has an out-of-range port, so `Url::parse`
    /// fails; the fallback arm used to echo the target verbatim, userinfo and all.
    #[test]
    fn safe_target_strips_userinfo_when_the_target_does_not_parse() {
        assert_eq!(
            safe_target("http://user:pw@host:99999/"),
            "http://host:99999/"
        );
        // Another parse failure (bad IPv6 literal): userinfo gone, and the
        // credential-material mask still applies to the rest.
        assert_eq!(
            safe_target("http://u:p@[::1/?access_token=T1"),
            "http://[::1/?access_token=[redacted]"
        );
        // Scheme-relative and scheme-less forms both fail to parse too.
        assert_eq!(safe_target("//user:pw@host/x"), "//host/x");
        assert_eq!(safe_target("user@host:99999/x"), "host:99999/x");
        // The crawl's own refusal message must not echo the credential either.
        assert!(!safe_target("http://user:hunter2@host:99999/").contains("hunter2"));
        // A target that parses keeps the existing behavior.
        assert_eq!(
            safe_target("http://user:pw@target.test/p#frag"),
            "http://target.test/p"
        );
    }

    #[test]
    fn strip_userinfo_drops_credentials_before_the_last_at_of_each_authority() {
        assert_eq!(
            strip_userinfo("see http://user:pw@host:8080/p?x=1 now"),
            "see http://host:8080/p?x=1 now"
        );
        // The last `@` wins: an unencoded `@` inside the password is credential.
        assert_eq!(strip_userinfo("//u:p@ss@host/x"), "//host/x");
        // Every authority in the text, not just the first.
        assert_eq!(
            strip_userinfo("a=//u1:p1@h1/x&b=//u2@h2"),
            "a=//h1/x&b=//h2"
        );
        // An `@` after the authority ends is path or query, not userinfo.
        assert_eq!(
            strip_userinfo("http://host/a@b?e=me@x.com"),
            "http://host/a@b?e=me@x.com"
        );
        assert_eq!(strip_userinfo("no urls here"), "no urls here");
        assert_eq!(strip_userinfo(""), "");
        // Non-ASCII text around the authority is preserved intact.
        assert_eq!(
            strip_userinfo("h\u{e9}llo //u\u{e9}:p@h\u{f6}st/\u{fc}"),
            "h\u{e9}llo //h\u{f6}st/\u{fc}"
        );
    }

    #[test]
    fn decode_entities_does_not_double_decode() {
        use crate::util::decode_entities;
        assert_eq!(decode_entities("&amp;lt;"), "&lt;");
        assert_eq!(decode_entities("a&amp;b"), "a&b");
        assert_eq!(decode_entities("&lt;tag&gt;"), "<tag>");
    }

    /// A page of a hundred thousand `<script></script>` pairs is scanned in one
    /// linear pass: the close-tag search must not copy the remaining DOM per
    /// tag, because this runs synchronously where the time budget cannot
    /// interrupt it.
    #[test]
    fn harvest_links_is_linear_on_many_script_tags() {
        let mut html = String::from(r#"<a href="/first">first</a>"#);
        for _ in 0..100_000 {
            html.push_str("<script></script>");
        }
        html.push_str(r#"<SCRIPT>var href = "/not-a-link";</SCRIPT><a href="/last">last</a>"#);
        assert!(html.len() > 1_700_000, "a realistically large page");

        let started = Instant::now();
        let links = harvest_links(&html);
        let elapsed = started.elapsed();

        assert_eq!(links, vec!["/first".to_string(), "/last".to_string()]);
        assert!(
            elapsed < Duration::from_secs(2),
            "harvest took {elapsed:?} on 100k script tags"
        );
    }

    /// A page with far more links than the per-page cap cannot grow the
    /// frontier without bound.
    #[test]
    fn harvest_links_caps_a_hostile_page() {
        let mut html = String::new();
        for i in 0..(MAX_LINKS_PER_PAGE * 3) {
            html.push_str(&format!("<a href=\"/p{i}\">x</a>"));
        }
        assert_eq!(harvest_links(&html).len(), MAX_LINKS_PER_PAGE);
    }
}
