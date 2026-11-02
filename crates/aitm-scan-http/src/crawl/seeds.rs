//! `robots.txt` and `sitemap.xml` seed discovery (task 15).
//!
//! Before the crawler walks a target it asks the two files the target itself
//! publishes for paths it would otherwise have to guess (spec D8.1, "both
//! honour `robots` and `sitemap` options"). Only the operator's own options
//! turn either read on, and every URL either file offers is resolved against
//! the origin and kept only when it is **same-origin**: a `robots.txt` or a
//! sitemap is attacker-controlled input, and a crawler that followed a `<loc>`
//! or a `Sitemap:` line off the origin would walk out of the operator's scope
//! on the target's say-so. `Disallow` lines are read as a *map of interesting
//! paths*, not as permission: this is an authorised scan of the operator's own
//! target, where the whole point is to reach what a crawler would not.
//!
//! Every GET here goes through the job's client with the options the lane
//! hands it (the job mark `scan:<job>` alone, spec D5: a seed fetch is not a
//! crawled page, so the lane gives it no `crawl` mark and the engine's page
//! count is untouched; and `RecordPolicy::Never`, amendment 79: a seed is
//! parsed in memory and never stored, so it leaves no scan-marked store row
//! without an `issue:<id>`), carries the session, is bounded by
//! `min(deadline - now, MAX_AWAIT)` and parses at most `MAX_BODY_PARSE_BYTES`.
//! A failure is logged at debug through [`redact::safe_url`] and skipped: a
//! target without a `robots.txt` is the normal case, not an error.
//!
//! **Plan note.** The plan's `fetch_seeds_requests` reuses the `robots_pins`
//! text, whose `Sitemap: http://t/sm.xml` is port 80 while the test origin is
//! `http://t:8080`; following it would contradict the same task's
//! "robots-listed **same-origin** sitemaps". The normative rule wins: the
//! served fixture names `http://t:8080/sm.xml`, and a cross-origin `Sitemap:`
//! line is pinned as *not* fetched.

use std::collections::HashSet;
use std::time::Instant;

use aitm_core::{ProxyClient, SendOptions};
use aitm_scan_model::{CrawlOptions, SessionMaterial};
use url::Url;

use crate::crawl::client::crawl_get;
use crate::limits::{
    MAX_AWAIT, MAX_BODY_PARSE_BYTES, MAX_SEED_URLS, MAX_SITEMAPS_FOLLOWED, MAX_SITEMAP_URLS,
};
use crate::{params, redact, session, url_norm};

/// What a seed read says it accepts: the two files are text and XML, never a
/// page.
const ACCEPT_SEEDS: &str = "text/plain,application/xml,text/xml,*/*;q=0.8";

/// What a `robots.txt` offered: paths worth crawling and sitemaps worth reading.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct RobotsSeeds {
    /// Every `Allow:`/`Disallow:` value, in file order, as written.
    pub paths: Vec<String>,
    /// Every `Sitemap:` value, in file order, as written.
    pub sitemaps: Vec<String>,
}

/// Read `robots.txt` as a list of candidate paths and sitemap URLs.
///
/// Keys are matched case-insensitively and groups are ignored: `Allow` and
/// `Disallow` are both just evidence that a path exists. A value is trimmed and
/// cut at its first `*` or `$` (a wildcard pattern is not a URL; its literal
/// prefix is the useful part), then dropped when it is empty or exactly `/`,
/// which carry no information the origin root does not already give. A `#`
/// starts a comment (RFC 9309) and is cut with the rest of the line. Both lists
/// are capped at [`MAX_SEED_URLS`] so a hostile `robots.txt` cannot grow the
/// process.
pub(crate) fn parse_robots(text: &str) -> RobotsSeeds {
    let mut seeds = RobotsSeeds::default();

    for raw in text.lines() {
        let line = match raw.split_once('#') {
            Some((head, _)) => head,
            None => raw,
        };
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim();

        if key.eq_ignore_ascii_case("sitemap") {
            if !value.is_empty() && seeds.sitemaps.len() < MAX_SEED_URLS {
                seeds.sitemaps.push(value.to_string());
            }
            continue;
        }
        if !key.eq_ignore_ascii_case("allow") && !key.eq_ignore_ascii_case("disallow") {
            continue;
        }

        // `find` returns a char boundary, so the slice cannot panic.
        let cut = value.find(['*', '$']).unwrap_or(value.len());
        let path = value[..cut].trim_end();
        if path.is_empty() || path == "/" {
            continue;
        }
        if seeds.paths.len() < MAX_SEED_URLS {
            seeds.paths.push(path.to_string());
        }
    }

    seeds
}

/// Every `<loc>` text of a sitemap document, trimmed, in document order.
///
/// A plain forward scan, not [`crate::xml`]: a sitemap is read for one element
/// and nothing here needs offsets or mutation, and a scan cannot recurse on a
/// nested document. `<urlset>` and `<sitemapindex>` are the same shape, so both
/// fall out of the same loop. `<location>` and friends do not match: the
/// character after `<loc` must end the tag or open its attributes. Capped at
/// [`MAX_SITEMAP_URLS`].
pub(crate) fn parse_sitemap(xml: &str) -> Vec<String> {
    let mut locs = Vec::new();
    let mut rest = xml;

    while locs.len() < MAX_SITEMAP_URLS {
        let Some(open) = rest.find("<loc") else {
            break;
        };
        let after = &rest[open + "<loc".len()..];
        let Some(tag_end) = after.find('>') else {
            break;
        };
        let (attrs, body) = after.split_at(tag_end);
        let body = &body["<".len()..];

        // `<location>`: the tag name continues, so this is not a `<loc>`.
        if !attrs.chars().all(char::is_whitespace) {
            rest = body;
            continue;
        }
        let Some(close) = body.find("</loc>") else {
            break;
        };
        let text = body[..close].trim();
        if !text.is_empty() {
            locs.push(text.to_string());
        }
        rest = &body[close + "</loc>".len()..];
    }

    locs
}

/// Fetch and parse the origin's `robots.txt` and `sitemap.xml`, returning the
/// same-origin seed URLs they offer.
///
/// `opts.robots` and `opts.sitemap` each gate their own fetch; with both off
/// this sends nothing. Robots-listed sitemaps are followed only when they are
/// same-origin and only up to [`MAX_SITEMAPS_FOLLOWED`] of them. The result is
/// deduped, in discovery order, and capped at [`MAX_SEED_URLS`].
pub(crate) async fn fetch_seeds(
    client: &dyn ProxyClient,
    origin: &Url,
    opts: &CrawlOptions,
    material: Option<&SessionMaterial>,
    send: SendOptions,
    deadline: Instant,
) -> Vec<Url> {
    let mut seeds: Vec<Url> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut robots = RobotsSeeds::default();

    if opts.robots {
        if let Some(url) = url_norm::resolve(origin, "/robots.txt") {
            if let Some(text) = fetch(client, &url, material, &send, deadline).await {
                robots = parse_robots(&text);
                for path in &robots.paths {
                    push_seed(origin, path, &mut seeds, &mut seen);
                }
            }
        }
    }

    if opts.sitemap {
        for document in sitemap_documents(origin, &robots) {
            let Some(xml) = fetch(client, &document, material, &send, deadline).await else {
                continue;
            };
            for loc in parse_sitemap(&xml) {
                push_seed(origin, &loc, &mut seeds, &mut seen);
            }
        }
    }

    seeds
}

/// The sitemap documents to read: the origin's own `/sitemap.xml` first, then
/// up to [`MAX_SITEMAPS_FOLLOWED`] distinct same-origin ones `robots.txt`
/// listed. A cross-origin or unparseable entry is logged at debug and dropped.
fn sitemap_documents(origin: &Url, robots: &RobotsSeeds) -> Vec<Url> {
    let mut documents: Vec<Url> = Vec::new();
    let mut keys: HashSet<String> = HashSet::new();

    if let Some(url) = url_norm::resolve(origin, "/sitemap.xml") {
        keys.insert(url.as_str().to_string());
        documents.push(url);
    }

    let mut followed = 0;
    for raw in &robots.sitemaps {
        if followed >= MAX_SITEMAPS_FOLLOWED {
            break;
        }
        let Some(url) = url_norm::resolve(origin, raw) else {
            tracing::debug!(
                sitemap = %redact::safe_url(raw),
                "scan: seeds: robots.txt listed an unusable sitemap URL"
            );
            continue;
        };
        if !url_norm::same_origin(origin, &url) {
            tracing::debug!(
                sitemap = %redact::safe_url(url.as_str()),
                "scan: seeds: skipping a sitemap outside the origin"
            );
            continue;
        }
        if !keys.insert(url.as_str().to_string()) {
            continue;
        }
        documents.push(url);
        followed += 1;
    }

    documents
}

/// Resolve `reference` against `origin` and add it as a seed when it is
/// same-origin, new and there is room under [`MAX_SEED_URLS`].
fn push_seed(origin: &Url, reference: &str, seeds: &mut Vec<Url>, seen: &mut HashSet<String>) {
    if seeds.len() >= MAX_SEED_URLS {
        return;
    }
    let Some(url) = url_norm::resolve(origin, reference) else {
        return;
    };
    if !url_norm::same_origin(origin, &url) {
        tracing::debug!(
            seed = %redact::safe_url(url.as_str()),
            "scan: seeds: dropping a seed outside the origin"
        );
        return;
    }
    if seen.insert(url.as_str().to_string()) {
        seeds.push(url);
    }
}

/// `GET url` with the session applied, bounded by the job's remaining time, and
/// return at most [`MAX_BODY_PARSE_BYTES`] of a `2xx` body as text.
///
/// Every other outcome — past deadline, timeout, transport error, non-`2xx`, a
/// body still streaming — answers `None` after a debug line naming the URL
/// through [`redact::safe_url`]. The client's error is never logged: it can
/// carry the request it failed on, and this module puts no header, cookie or
/// body in a line.
async fn fetch(
    client: &dyn ProxyClient,
    url: &Url,
    material: Option<&SessionMaterial>,
    send: &SendOptions,
    deadline: Instant,
) -> Option<String> {
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        tracing::debug!(
            seed = %redact::safe_url(url.as_str()),
            "scan: seeds: out of time before the fetch"
        );
        return None;
    }

    let mut req = crawl_get(url, ACCEPT_SEEDS)?;
    if let Some(material) = material {
        session::apply_session(&mut req, material);
    }

    let flow = match tokio::time::timeout(left.min(MAX_AWAIT), client.send_opts(req, send.clone()))
        .await
    {
        Ok(Ok(flow)) => flow,
        Ok(Err(_)) | Err(_) => {
            tracing::debug!(
                seed = %redact::safe_url(url.as_str()),
                "scan: seeds: fetch failed"
            );
            return None;
        }
    };

    let response = flow.response?;
    if response.status / 100 != 2 {
        tracing::debug!(
            seed = %redact::safe_url(url.as_str()),
            status = response.status,
            "scan: seeds: fetch did not answer 2xx"
        );
        return None;
    }

    let bytes = params::body_bytes(&response.body)?;
    let end = bytes.len().min(MAX_BODY_PARSE_BYTES);
    Some(String::from_utf8_lossy(&bytes[..end]).into_owned())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::limits::USER_AGENT;
    use crate::testutil::{response, ScriptedClient, JOB_ID};
    use aitm_core::{HttpRequest, RecordPolicy, VersionPolicy};
    use std::time::Duration;

    /// The `robots.txt` of the plan's `robots_pins`, verbatim.
    const ROBOTS: &str = "User-agent: *\nDisallow: /admin/\nAllow: /public\ndisallow: /tmp/*\nSitemap: http://t/sm.xml\nDisallow: /\nDisallow:\n";

    #[test]
    fn robots_pins() {
        let seeds = parse_robots(ROBOTS);
        assert_eq!(seeds.paths, vec!["/admin/", "/public", "/tmp/"]);
        assert_eq!(seeds.sitemaps, vec!["http://t/sm.xml"]);
    }

    #[test]
    fn sitemap_pins() {
        assert_eq!(
            parse_sitemap(
                "<urlset><url><loc>http://t/a</loc></url><url><loc> http://t/b </loc></url></urlset>"
            ),
            vec!["http://t/a", "http://t/b"]
        );
        assert_eq!(
            parse_sitemap(
                "<sitemapindex><sitemap><loc>http://t/s1.xml</loc></sitemap><sitemap><loc>http://t/s2.xml</loc></sitemap></sitemapindex>"
            ),
            vec!["http://t/s1.xml", "http://t/s2.xml"]
        );
        // A longer tag name is not a `<loc>`; a `<loc>` with whitespace is.
        assert!(parse_sitemap("<location>http://t/a</location>").is_empty());
        assert_eq!(parse_sitemap("<loc >http://t/a</loc>"), vec!["http://t/a"]);
        assert!(parse_sitemap("<urlset><url><loc></loc></url></urlset>").is_empty());
    }

    /// The served `robots.txt`: the pinned text with its `Sitemap:` on the
    /// origin's own port (see the module note on the plan's fixture), plus a
    /// cross-origin sitemap that must never be fetched.
    const ROBOTS_SERVED: &str = "User-agent: *\nDisallow: /admin/\nAllow: /public\ndisallow: /tmp/*\nSitemap: http://t:8080/sm.xml\nSitemap: http://evil.test/sm.xml\nDisallow: /\nDisallow:\n";

    /// `/robots.txt`, `/sitemap.xml` and `/sm.xml`; everything else 404s.
    ///
    /// `/sitemap.xml` carries one same-origin absolute `<loc>` and one
    /// cross-origin one; `/sm.xml` carries a relative `<loc>`, so the test
    /// pins both "resolved against `origin`" and "same-origin only".
    fn seed_site() -> ScriptedClient {
        ScriptedClient::new(|req: &HttpRequest| {
            let (content_type, body) = match req.path.as_str() {
                "/robots.txt" => ("text/plain", ROBOTS_SERVED),
                "/sitemap.xml" => (
                    "application/xml",
                    "<urlset><url><loc>http://t:8080/a</loc></url><url><loc>http://evil.test/x</loc></url></urlset>",
                ),
                "/sm.xml" => (
                    "application/xml",
                    "<urlset><url><loc>/b</loc></url></urlset>",
                ),
                _ => return Ok(response(404, &[("content-type", "text/plain")], b"")),
            };
            Ok(response(
                200,
                &[("content-type", content_type)],
                body.as_bytes(),
            ))
        })
    }

    /// The options the lane passes: `record: Never` (amendment 79) and the
    /// job mark only (plan call A2; the lane test
    /// `seed_sends_carry_the_job_mark_only_and_are_never_recorded` owns both
    /// choices).
    fn send_options() -> SendOptions {
        SendOptions {
            record: RecordPolicy::Never,
            marks: vec![format!("scan:{JOB_ID}")],
            version: VersionPolicy::H1,
        }
    }

    fn origin() -> Url {
        Url::parse("http://t:8080/").expect("the test origin parses")
    }

    fn session() -> SessionMaterial {
        SessionMaterial {
            cookies: vec![("sid".to_string(), "S3".to_string())],
            headers: Vec::new(),
        }
    }

    #[tokio::test]
    async fn fetch_seeds_requests() {
        let client = seed_site();
        let material = session();
        let opts = CrawlOptions {
            robots: true,
            sitemap: true,
            ..CrawlOptions::default()
        };

        let seeds = fetch_seeds(
            &client,
            &origin(),
            &opts,
            Some(&material),
            send_options(),
            Instant::now() + Duration::from_secs(60),
        )
        .await;

        // robots first, then the origin sitemap, then the robots-listed
        // same-origin one; the cross-origin sitemap is never fetched.
        assert_eq!(
            client.sent_paths(),
            vec!["/robots.txt", "/sitemap.xml", "/sm.xml"]
        );
        // The caller's marks go out on every seed send unchanged.
        for marks in client.sent_marks() {
            assert_eq!(marks, vec!["scan:scan-1a2b3c4d".to_string()]);
        }
        for (req, opts) in client.sent.lock().unwrap().iter() {
            assert_eq!(req.method, "GET");
            assert_eq!(req.headers.get("cookie"), Some("sid=S3"));
            assert_eq!(req.headers.get("user-agent"), Some(USER_AGENT));
            assert_eq!(req.headers.get("accept"), Some(ACCEPT_SEEDS));
            assert_eq!(req.headers.get("host"), Some("t:8080"));
            // Amendment 79: the caller's `Never` goes out unchanged on every
            // seed send; `fetch_seeds` never promotes a seed to a recorded flow.
            assert_eq!(opts.record, RecordPolicy::Never);
            // Sp2: the caller's version policy goes out on every seed send.
            assert_eq!(opts.version, VersionPolicy::H1);
        }

        let urls: Vec<String> = seeds.iter().map(|url| url.as_str().to_string()).collect();
        assert!(urls.contains(&"http://t:8080/admin/".to_string()));
        assert!(urls.contains(&"http://t:8080/public".to_string()));
        assert!(urls.contains(&"http://t:8080/tmp/".to_string()));
        assert!(urls.contains(&"http://t:8080/a".to_string()));
        assert!(urls.contains(&"http://t:8080/b".to_string()));
        // Same-origin only: the cross-origin <loc> never becomes a seed.
        assert!(!urls.iter().any(|url| url.contains("evil.test")));
        // Deduped.
        let mut sorted = urls.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), urls.len());
    }

    #[tokio::test]
    async fn fetch_seeds_sends_nothing_when_both_options_are_off() {
        let client = seed_site();
        let opts = CrawlOptions {
            robots: false,
            sitemap: false,
            ..CrawlOptions::default()
        };

        let seeds = fetch_seeds(
            &client,
            &origin(),
            &opts,
            None,
            send_options(),
            Instant::now() + Duration::from_secs(60),
        )
        .await;

        assert_eq!(client.sent.lock().unwrap().len(), 0);
        assert!(seeds.is_empty());
    }

    #[tokio::test]
    async fn fetch_seeds_sends_nothing_past_the_deadline() {
        let client = seed_site();

        let seeds = fetch_seeds(
            &client,
            &origin(),
            &CrawlOptions::default(),
            None,
            send_options(),
            Instant::now() - Duration::from_secs(1),
        )
        .await;

        assert_eq!(client.sent.lock().unwrap().len(), 0);
        assert!(seeds.is_empty());
    }
}
