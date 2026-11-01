//! The `Crawler` trait, the shared frontier, crawl limits and reports (task 16).
//!
//! Both crawl engines (the browser engine and the client engine, tasks 17 and
//! 18) are the same loop over the same [`Frontier`] under the same [`Limits`],
//! so everything they share about *when to stop* lives here: the strategy
//! limits, the visited and fingerprint sets, the frontier ceiling, the page
//! fingerprint that keeps volatile content from looping, the deadline bound on
//! every await, and the report shape the lane reads back (spec D8.1).

use std::collections::{HashSet, VecDeque};
use std::fmt;
use std::time::{Duration, Instant};

use aitm_core::{Body, HttpFlow};
use aitm_scan_model::{CrawlOptions, CrawlStrategy, JobCtx};
use futures::future::BoxFuture;
use url::Url;

use crate::hash::fnv1a64;
use crate::limits::{
    CLICKS_PER_PAGE_NORMAL, CLICKS_PER_PAGE_THOROUGH, FORMS_PER_PAGE_NORMAL,
    FORMS_PER_PAGE_THOROUGH, MAX_AWAIT, MAX_FRONTIER,
};
use crate::url_norm::page_key;

/// What one crawl run may spend, resolved from the profile's [`CrawlOptions`]
/// and its [`CrawlStrategy`] once, before the run starts.
///
/// Every engine reads these and never re-reads the profile, so a reviewer sees
/// the whole budget of a crawl in one value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Limits {
    /// How many links deep from a seed the crawler follows.
    pub max_depth: u32,
    /// How many pages the crawler attempts. `0` disables crawling.
    pub max_pages: u32,
    /// Clicks spent on one page.
    pub clicks_per_page: u32,
    /// Form submissions spent on one page.
    pub forms_per_page: u32,
    /// Whether non-document links (`img`, `script`, `link`, …) are followed.
    pub follow_resources: bool,
    /// Whether the crawler submits forms it judges safe.
    pub submit_forms: bool,
    /// Whether the crawler clicks event handlers.
    pub click_handlers: bool,
}

/// Resolve the crawl limits for `opts`.
///
/// `Fast` is links-only and one level deep: it lowers the profile's depth to at
/// most 1 (never raises it) and forces clicks, form submissions and resource
/// links off. `Normal` is the profile's depth and pages with the normal
/// per-page click and form allowances. `Thorough` raises those allowances and
/// follows resource links as well. The two operator switches
/// (`submit_forms`, `click_handlers`) can only ever turn behaviour *off*.
pub(crate) fn limits_for(opts: &CrawlOptions) -> Limits {
    let (max_depth, clicks_per_page, forms_per_page, follow_resources, interactive) =
        match opts.strategy {
            CrawlStrategy::Fast => (opts.max_depth.min(1), 0, 0, false, false),
            CrawlStrategy::Normal => (
                opts.max_depth,
                CLICKS_PER_PAGE_NORMAL,
                FORMS_PER_PAGE_NORMAL,
                false,
                true,
            ),
            CrawlStrategy::Thorough => (
                opts.max_depth,
                CLICKS_PER_PAGE_THOROUGH,
                FORMS_PER_PAGE_THOROUGH,
                true,
                true,
            ),
        };
    Limits {
        max_depth,
        max_pages: opts.max_pages,
        clicks_per_page,
        forms_per_page,
        follow_resources,
        submit_forms: interactive && opts.submit_forms,
        click_handlers: interactive && opts.click_handlers,
    }
}

/// The work queue and the memory of one crawl run.
///
/// The frontier owns three things an engine must not keep for itself: the FIFO
/// of URLs still to visit with their depth, the visited set (so a page is
/// fetched once), and the set of page fingerprints (so two URLs rendering the
/// same page are extracted from once). It also records *why* work was refused,
/// which the engine turns into a stop reason.
#[derive(Default)]
pub(crate) struct Frontier {
    queue: VecDeque<(Url, u32)>,
    visited: HashSet<String>,
    fingerprints: HashSet<u64>,
    /// Whether a URL was ever refused for being deeper than `max_depth`.
    pub depth_hit: bool,
    /// How many URLs were dropped because the frontier was full.
    pub dropped_full: u32,
}

impl Frontier {
    /// An empty frontier.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Queue `url` at `depth`, and report whether it was taken.
    ///
    /// A URL is refused when it is deeper than `limits.max_depth` (which sets
    /// [`Frontier::depth_hit`]), when it was already visited, or when the
    /// frontier already holds [`MAX_FRONTIER`] URLs (which counts
    /// [`Frontier::dropped_full`]). An accepted URL is marked visited there and
    /// then, so the same link found on ten pages is queued once.
    pub(crate) fn push(&mut self, url: Url, depth: u32, limits: &Limits) -> bool {
        if depth > limits.max_depth {
            self.depth_hit = true;
            return false;
        }
        if self.is_visited(&url) {
            return false;
        }
        if self.queue.len() >= MAX_FRONTIER {
            self.dropped_full = self.dropped_full.saturating_add(1);
            return false;
        }
        self.visited.insert(page_key(&url));
        self.queue.push_back((url, depth));
        true
    }

    /// Take the next URL and its depth, oldest first.
    pub(crate) fn pop(&mut self) -> Option<(Url, u32)> {
        self.queue.pop_front()
    }

    /// Mark `url` visited without queueing it, and report whether that was new.
    ///
    /// Used for a URL an engine reached without going through the queue (the
    /// origin root, a redirect target it followed itself).
    pub(crate) fn mark_visited(&mut self, url: &Url) -> bool {
        self.visited.insert(page_key(url))
    }

    /// Whether `url` was queued or visited already.
    pub(crate) fn is_visited(&self, url: &Url) -> bool {
        self.visited.contains(&page_key(url))
    }

    /// Record a page fingerprint, and report whether the page is new.
    ///
    /// A `false` means this page has been seen under another URL (or another
    /// render of the same volatile page): the engine counts the fetch but does
    /// not extract links from it again.
    pub(crate) fn note_fingerprint(&mut self, fp: u64) -> bool {
        self.fingerprints.insert(fp)
    }

    /// How many URLs are waiting.
    ///
    /// Test-only: an engine drains the queue with [`Frontier::pop`] and never
    /// asks for its size (Q8). `is_empty` is its conventional partner
    /// (`clippy::len_without_is_empty`).
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.queue.len()
    }

    /// Whether no URL is waiting.
    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }
}

/// Counts only: a queued or visited URL may be a stored seed carrying its
/// captured query string, and this type is one `tracing::debug!` away from a
/// log line (spec D8.1 redaction rules, S-M3).
impl fmt::Debug for Frontier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Frontier")
            .field("queued", &self.queue.len())
            .field("visited", &self.visited.len())
            .field("fingerprints", &self.fingerprints.len())
            .field("depth_hit", &self.depth_hit)
            .field("dropped_full", &self.dropped_full)
            .finish()
    }
}

/// The fingerprint of a page body: a hash of the page with its volatile parts
/// normalised away.
///
/// `<script>`, `<style>` and comment elements are dropped whole (an
/// unterminated one swallows the rest of the input rather than leaking it),
/// the result is lowercased, every run of digits becomes a single `0`, every
/// run of whitespace becomes a single space, and the ends are trimmed. Two
/// renders of one page that differ only in a timestamp, a counter, a CSRF
/// token inside a script or the layout of the markup fingerprint the same, so
/// the crawler stops looping on volatile content (spec D8.1). The hash is
/// [`fnv1a64`]: fast, stable, and never a security decision.
pub(crate) fn fingerprint(body: &str) -> u64 {
    let lower = body.to_ascii_lowercase();
    let bytes = lower.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0usize;

    while i < bytes.len() {
        if bytes[i] == b'<' {
            if let Some(end) = skip_element(bytes, i) {
                i = end;
                continue;
            }
        }
        if bytes[i].is_ascii_digit() {
            out.push(b'0');
            while i < bytes.len() && bytes[i].is_ascii_digit() {
                i += 1;
            }
            continue;
        }
        if bytes[i].is_ascii_whitespace() {
            out.push(b' ');
            while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }

    let trimmed = trim_spaces(&out);
    fnv1a64(trimmed)
}

/// If `bytes[at..]` opens a comment, a `<script>` or a `<style>`, the index
/// just past that whole element (its end, or the end of the input when it is
/// unterminated). `None` for any other `<`.
fn skip_element(bytes: &[u8], at: usize) -> Option<usize> {
    for (open, close) in [
        (&b"<!--"[..], &b"-->"[..]),
        (&b"<script"[..], &b"</script>"[..]),
        (&b"<style"[..], &b"</style>"[..]),
    ] {
        if bytes[at..].starts_with(open) {
            let from = at + open.len();
            let end = find(bytes, close, from).map_or(bytes.len(), |hit| hit + close.len());
            return Some(end);
        }
    }
    None
}

/// The index of the first `needle` in `haystack` at or after `from`.
fn find(haystack: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if from >= haystack.len() || needle.is_empty() {
        return None;
    }
    haystack[from..]
        .windows(needle.len())
        .position(|window| window == needle)
        .map(|offset| from + offset)
}

/// `bytes` without its leading and trailing spaces.
fn trim_spaces(bytes: &[u8]) -> &[u8] {
    let mut start = 0usize;
    let mut end = bytes.len();
    while start < end && bytes[start] == b' ' {
        start += 1;
    }
    while end > start && bytes[end - 1] == b' ' {
        end -= 1;
    }
    bytes.get(start..end).unwrap_or(&[])
}

/// Why a crawl stopped before its frontier ran dry (spec D8.1).
///
/// [`StopReason::as_str`] is the literal the lane logs and the engine's
/// report carries: `max_pages`, `max_depth`, `time`, `budget`, `cancelled`,
/// `left_scope`, `navigation_failed`, `guard_refused`, `no_browser`.
///
/// `NoBrowser` is lane-only: the lane logs it when the profile demands a
/// browser the job does not have and no engine runs at all, so no engine ever
/// sets it on a [`CrawlReport`] (`stopped_reason` is never `NoBrowser`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StopReason {
    /// `max_pages` attempts were spent.
    MaxPages,
    /// The frontier ran dry only because links deeper than `max_depth` were
    /// refused.
    MaxDepth,
    /// The job's deadline passed.
    Time,
    /// The job's budget refused a charge.
    Budget,
    /// The job was cancelled.
    Cancelled,
    /// The browser landed outside the engagement.
    LeftScope,
    /// Nothing loaded at all.
    NavigationFailed,
    /// The frontier ran dry only because the scope guard refused pages.
    GuardRefused,
    /// The profile demanded a browser the job does not have. Logged by the
    /// lane before any engine runs; never set on a report.
    NoBrowser,
}

impl StopReason {
    /// The documented literal for this reason.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::MaxPages => "max_pages",
            Self::MaxDepth => "max_depth",
            Self::Time => "time",
            Self::Budget => "budget",
            Self::Cancelled => "cancelled",
            Self::LeftScope => "left_scope",
            Self::NavigationFailed => "navigation_failed",
            Self::GuardRefused => "guard_refused",
            Self::NoBrowser => "no_browser",
        }
    }
}

impl fmt::Display for StopReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What one crawl run did.
///
/// `stopped_reason` is `None` when the crawl ran out of frontier on its own.
#[derive(Default)]
pub(crate) struct CrawlReport {
    /// Pages that loaded (a `2xx` or `3xx` response, or a browser navigation).
    pub pages: u32,
    /// Pages the crawler attempted, loaded or not; charged against `max_pages`.
    pub attempts: u32,
    /// Forms the crawler submitted.
    pub forms_submitted: u32,
    /// Forms the browser engine refused to submit because the live form was
    /// not the form the page markup declared (S-I2).
    pub forms_skipped: u32,
    /// Elements the crawler clicked.
    pub clicks: u32,
    /// The flows the crawl produced, for the lane to turn into site-map nodes.
    pub flows: Vec<HttpFlow>,
    /// Why the crawl stopped early, or `None` when it finished the frontier.
    pub stopped_reason: Option<StopReason>,
    /// The deepest level the crawl actually reached.
    pub depth_reached: u32,
}

/// Counts only: a report never prints a flow, which would carry headers,
/// cookies and bodies into a log line (spec D8.1 redaction rules).
impl fmt::Debug for CrawlReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CrawlReport")
            .field("pages", &self.pages)
            .field("attempts", &self.attempts)
            .field("forms_submitted", &self.forms_submitted)
            .field("forms_skipped", &self.forms_skipped)
            .field("clicks", &self.clicks)
            .field("flows", &self.flows.len())
            .field("stopped_reason", &self.stopped_reason)
            .field("depth_reached", &self.depth_reached)
            .finish()
    }
}

/// The flow as a [`CrawlReport`] keeps it: the response body dropped, so a
/// crawl of a few hundred large pages cannot grow the job's memory for the
/// life of discovery (S-I3, R-M3).
///
/// Both engines hold their produced flows through this one function. The
/// stored flow (recorded by the client, or captured through the proxy) is
/// untouched; this copy only feeds the site-map builder, which reads the
/// request alone, so nothing is lost by holding no body at all. The response
/// status and headers stay.
pub(crate) fn held_copy(mut flow: HttpFlow) -> HttpFlow {
    if let Some(response) = flow.response.as_mut() {
        response.body = Body::Empty;
    }
    flow
}

/// One crawl engine.
///
/// The lane picks an engine from `use_browser` and the job's browser, then
/// drives it through this one object-safe seam, so neither the lane nor the
/// site-map builder knows which engine produced a flow (spec D8.1).
pub(crate) trait Crawler: Send + Sync {
    /// Crawl `origin` from `seeds` under `limits` until a stop reason applies.
    fn crawl<'a>(
        &'a self,
        origin: &'a Url,
        seeds: Vec<Url>,
        job: &'a dyn JobCtx,
        limits: &'a Limits,
    ) -> BoxFuture<'a, anyhow::Result<CrawlReport>>;
}

/// How long the lane may wait on the network or the browser right now:
/// `min(job.deadline() - now, MAX_AWAIT)`, or `None` once the deadline has
/// passed.
///
/// Every await in the lane is bounded by this, so a job cannot outlive its
/// deadline because one request hung, and no single await can outlive
/// [`MAX_AWAIT`] even when the deadline is hours out.
pub(crate) fn remaining(job: &dyn JobCtx) -> Option<Duration> {
    let left = job.deadline().checked_duration_since(Instant::now())?;
    if left.is_zero() {
        return None;
    }
    Some(left.min(MAX_AWAIT))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::testutil::{response, FakeJob, ScriptedClient};
    use crate::url_norm::parse_absolute;
    use aitm_scan_model::{CrawlOptions, CrawlStrategy, JobCtx, ScanProfile};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    fn url(s: &str) -> Url {
        parse_absolute(s).expect("test url parses")
    }

    #[test]
    fn limits_pins() {
        let normal = limits_for(&CrawlOptions::default());
        assert_eq!(normal.max_depth, 3);
        assert_eq!(normal.max_pages, 200);
        assert_eq!(normal.clicks_per_page, 8);
        assert_eq!(normal.forms_per_page, 8);
        assert!(!normal.follow_resources);
        assert!(normal.submit_forms);
        assert!(normal.click_handlers);

        let fast = limits_for(&CrawlOptions {
            strategy: CrawlStrategy::Fast,
            ..CrawlOptions::default()
        });
        assert_eq!(fast.max_depth, 1);
        assert_eq!(fast.max_pages, 200);
        assert_eq!(fast.clicks_per_page, 0);
        assert_eq!(fast.forms_per_page, 0);
        assert!(!fast.follow_resources);
        assert!(!fast.submit_forms);
        assert!(!fast.click_handlers);

        let thorough = limits_for(&CrawlOptions {
            strategy: CrawlStrategy::Thorough,
            ..CrawlOptions::default()
        });
        assert_eq!(thorough.max_depth, 3);
        assert_eq!(thorough.clicks_per_page, 32);
        assert_eq!(thorough.forms_per_page, 32);
        assert!(thorough.follow_resources);

        // A profile that turns the two switches off keeps them off at every
        // strategy.
        let quiet = limits_for(&CrawlOptions {
            strategy: CrawlStrategy::Thorough,
            submit_forms: false,
            click_handlers: false,
            ..CrawlOptions::default()
        });
        assert!(!quiet.submit_forms);
        assert!(!quiet.click_handlers);

        // `Fast` only ever lowers the profile's depth.
        let shallow = limits_for(&CrawlOptions {
            strategy: CrawlStrategy::Fast,
            max_depth: 0,
            ..CrawlOptions::default()
        });
        assert_eq!(shallow.max_depth, 0);
    }

    #[test]
    fn frontier_rules() {
        let limits = limits_for(&CrawlOptions::default());
        let mut frontier = Frontier::new();

        assert!(frontier.push(url("http://t/a"), 0, &limits));
        // The same URL is refused the second time, and the frontier did not grow.
        assert!(!frontier.push(url("http://t/a"), 0, &limits));
        assert_eq!(frontier.len(), 1);
        assert!(frontier.is_visited(&url("http://t/a")));

        // A depth above `max_depth` is refused and recorded.
        assert!(!frontier.depth_hit);
        assert!(!frontier.push(url("http://t/deep"), 4, &limits));
        assert!(frontier.depth_hit);
        assert!(!frontier.is_visited(&url("http://t/deep")));
        // `max_depth` itself is still accepted.
        assert!(frontier.push(url("http://t/edge"), 3, &limits));

        // FIFO.
        assert_eq!(
            frontier.pop().map(|(u, d)| (u.as_str().to_string(), d)),
            Some(("http://t/a".to_string(), 0))
        );
        assert_eq!(
            frontier.pop().map(|(u, d)| (u.as_str().to_string(), d)),
            Some(("http://t/edge".to_string(), 3))
        );
        assert_eq!(frontier.pop(), None);
        assert_eq!(frontier.len(), 0);
        assert!(frontier.is_empty());

        // A full frontier refuses and counts.
        let mut full = Frontier::new();
        for i in 0..4096 {
            assert!(
                full.push(url(&format!("http://t/p{i}")), 0, &limits),
                "url {i} accepted"
            );
        }
        assert_eq!(full.len(), 4096);
        assert!(!full.push(url("http://t/one-too-many"), 0, &limits));
        assert_eq!(full.dropped_full, 1);
        assert!(!full.is_visited(&url("http://t/one-too-many")));

        // `mark_visited` and `note_fingerprint` report novelty.
        let mut f = Frontier::new();
        assert!(f.mark_visited(&url("http://t/x")));
        assert!(!f.mark_visited(&url("http://t/x")));
        assert!(!f.push(url("http://t/x"), 0, &limits));
        assert!(f.note_fingerprint(7));
        assert!(!f.note_fingerprint(7));
        assert!(f.note_fingerprint(8));
    }

    /// Q2: the stop reasons are one enum whose `as_str` is the documented
    /// literal the lane logs and the engine's report carries.
    #[test]
    fn stop_reason_literals_pin() {
        let all = [
            (StopReason::MaxPages, "max_pages"),
            (StopReason::MaxDepth, "max_depth"),
            (StopReason::Time, "time"),
            (StopReason::Budget, "budget"),
            (StopReason::Cancelled, "cancelled"),
            (StopReason::LeftScope, "left_scope"),
            (StopReason::NavigationFailed, "navigation_failed"),
            (StopReason::GuardRefused, "guard_refused"),
            (StopReason::NoBrowser, "no_browser"),
        ];
        for (reason, literal) in all {
            assert_eq!(reason.as_str(), literal);
            assert_eq!(reason.to_string(), literal);
        }
    }

    /// S-M3: a frontier holds queued and visited URLs, and a stored seed
    /// carries its captured query string; `Debug` prints counts only.
    #[test]
    fn frontier_debug_prints_counts_only() {
        let limits = limits_for(&CrawlOptions::default());
        let mut frontier = Frontier::new();
        frontier.push(url("http://t/a?token=abc"), 0, &limits);
        frontier.mark_visited(&url("http://t/cb?sid=S3"));
        frontier.note_fingerprint(7);

        let text = format!("{frontier:?}");

        assert!(!text.contains("abc"), "{text}");
        assert!(!text.contains("S3"), "{text}");
        assert!(!text.contains("http"), "{text}");
        assert_eq!(
            text,
            "Frontier { queued: 1, visited: 2, fingerprints: 1, depth_hit: false, dropped_full: 0 }"
        );
    }

    #[test]
    fn fingerprint_pins() {
        // Digit runs and whitespace runs do not change a page.
        assert_eq!(
            fingerprint("<p>Time 12:30</p>"),
            fingerprint("<p>time  09:15</p>")
        );
        // Script bodies are dropped.
        assert_eq!(
            fingerprint("<p>a</p><script>x=1</script>"),
            fingerprint("<p>a</p><script>y=2</script>")
        );
        // Style bodies and comments are dropped too.
        assert_eq!(
            fingerprint("<p>a</p><style>.x{color:red}</style><!-- build 991 -->"),
            fingerprint("<p>a</p><STYLE>.y{color:blue}</STYLE><!-- build 7 -->")
        );
        // Real text is not.
        assert_ne!(fingerprint("<p>a</p>"), fingerprint("<p>b</p>"));
        // An unterminated script swallows the rest of the page rather than
        // panicking or leaking the script text.
        assert_eq!(
            fingerprint("<p>a</p><script>x=1"),
            fingerprint("<p>a</p><script>y=2")
        );
    }

    #[test]
    fn remaining_is_bounded_and_runs_out() {
        let mut job = FakeJob::new(
            ScanProfile::default(),
            Arc::new(ScriptedClient::new(|_| Ok(response(200, &[], b"")))),
        );
        // A deadline a minute out is clamped to `MAX_AWAIT`.
        assert_eq!(remaining(&job), Some(MAX_AWAIT));

        // A near deadline is the bound itself.
        job.deadline = Instant::now() + Duration::from_secs(5);
        let left = remaining(&job).expect("time left");
        assert!(
            left <= Duration::from_secs(5) && left > Duration::from_secs(4),
            "{left:?}"
        );

        // A passed deadline is `None`.
        job.deadline = Instant::now() - Duration::from_secs(1);
        assert_eq!(remaining(&job), None);
    }

    struct CountingCrawler;

    impl Crawler for CountingCrawler {
        fn crawl<'a>(
            &'a self,
            origin: &'a Url,
            seeds: Vec<Url>,
            job: &'a dyn JobCtx,
            limits: &'a Limits,
        ) -> BoxFuture<'a, anyhow::Result<CrawlReport>> {
            Box::pin(async move {
                let _ = (origin, job);
                Ok(CrawlReport {
                    pages: seeds.len() as u32,
                    depth_reached: limits.max_depth,
                    stopped_reason: Some(StopReason::MaxPages),
                    ..CrawlReport::default()
                })
            })
        }
    }

    #[tokio::test]
    async fn crawler_trait_is_object_safe() {
        let job = FakeJob::new(
            ScanProfile::default(),
            Arc::new(ScriptedClient::new(|_| Ok(response(200, &[], b"")))),
        );
        let limits = limits_for(&CrawlOptions::default());
        let engine: Box<dyn Crawler> = Box::new(CountingCrawler);

        let report = engine
            .crawl(&url("http://t/"), vec![url("http://t/a")], &job, &limits)
            .await
            .expect("the crawl succeeds");

        assert_eq!(report.pages, 1);
        assert_eq!(report.depth_reached, 3);
        assert_eq!(report.stopped_reason, Some(StopReason::MaxPages));
        assert_eq!(report.attempts, 0);
        assert_eq!(report.forms_submitted, 0);
        assert_eq!(report.clicks, 0);
        assert!(report.flows.is_empty());
        // The report never prints a flow's bytes.
        assert_eq!(
            format!("{report:?}"),
            "CrawlReport { pages: 1, attempts: 0, forms_submitted: 0, forms_skipped: 0, clicks: 0, flows: 0, stopped_reason: Some(MaxPages), depth_reached: 3 }"
        );
    }
}
