//! Every bound the HTTP lane enforces, as a named constant.
//!
//! The crate rule (spec D8.1) is that no limit is written inline at its use
//! site: a reviewer reads this one file to see every ceiling the lane applies
//! to a page, a body, the frontier, the browser budget or an await.

use std::time::Duration;

/// Links taken from one HTML page.
pub(crate) const MAX_LINKS_PER_PAGE: usize = 512;

/// Forms taken from one HTML page.
pub(crate) const MAX_FORMS_PER_PAGE: usize = 64;

/// Fields read from one form.
pub(crate) const MAX_FIELDS_PER_FORM: usize = 256;

/// Options read from one `<select>`.
pub(crate) const MAX_OPTIONS_PER_SELECT: usize = 128;

/// URLs held in the crawl frontier at once.
pub(crate) const MAX_FRONTIER: usize = 4096;

/// Serialised DOM bytes accepted from the browser for one page.
pub(crate) const MAX_DOM_BYTES: usize = 2 * 1024 * 1024;

/// Body bytes parsed for insertion points.
pub(crate) const MAX_BODY_PARSE_BYTES: usize = 2 * 1024 * 1024;

/// Seed URLs taken from `robots.txt` and `sitemap.xml` together.
pub(crate) const MAX_SEED_URLS: usize = 256;

/// URLs taken from all sitemaps of one origin.
pub(crate) const MAX_SITEMAP_URLS: usize = 1024;

/// Nested sitemap documents followed from one sitemap index.
pub(crate) const MAX_SITEMAPS_FOLLOWED: usize = 4;

/// Clickable elements listed for one page.
pub(crate) const MAX_CLICKABLES_LISTED: usize = 32;

/// Clicks spent on one page at crawl strength `normal`.
pub(crate) const CLICKS_PER_PAGE_NORMAL: u32 = 8;

/// Clicks spent on one page at crawl strength `thorough`.
pub(crate) const CLICKS_PER_PAGE_THOROUGH: u32 = 32;

/// Form submissions spent on one page at crawl strength `normal`.
pub(crate) const FORMS_PER_PAGE_NORMAL: u32 = 8;

/// Form submissions spent on one page at crawl strength `thorough`.
pub(crate) const FORMS_PER_PAGE_THOROUGH: u32 = 32;

/// Interval between polls while waiting for a page to settle.
pub(crate) const SETTLE_POLL_MS: u64 = 200;

/// Longest wait for a page to settle before the crawler moves on.
pub(crate) const SETTLE_MAX_MS: u64 = 3000;

/// Name/value pairs parsed from one form, cookie header or query string.
pub(crate) const MAX_PAIRS: usize = 4096;

/// Nesting depth walked in a JSON body.
pub(crate) const MAX_JSON_DEPTH: usize = 32;

/// Insertion slots recorded in one XML body.
pub(crate) const MAX_XML_SLOTS: usize = 1024;

/// Element nesting depth walked in an XML body.
pub(crate) const MAX_XML_DEPTH: usize = 64;

/// Parts parsed from one multipart body.
pub(crate) const MAX_MULTIPART_PARTS: usize = 256;

/// Characters kept in an `InsertionPoint.example`.
pub(crate) const MAX_EXAMPLE_CHARS: usize = 64;

/// Characters kept in a URL that reaches a log line or an error message.
pub(crate) const MAX_SAFE_URL_CHARS: usize = 256;

/// Flows held in memory for one probe before the oldest is dropped.
pub(crate) const MAX_HELD_FLOWS: usize = 16;

/// Ceiling on any single await on the network or the browser; the real bound
/// is `min(job.deadline() - now, MAX_AWAIT)`.
pub(crate) const MAX_AWAIT: Duration = Duration::from_secs(30);

/// Probes between two session-canary checks.
pub(crate) const CANARY_EVERY: u32 = 25;

/// Session monitors held for one job.
pub(crate) const MAX_SESSION_MONITORS: usize = 16;

/// Evicted-lost job ids the monitor registry remembers, so a rebuilt monitor
/// for one of them starts lost (S-M5).
pub(crate) const MAX_LOST_MONITOR_IDS: usize = 256;

/// Captured same-origin flows the stored pass of one origin enumerates, newest
/// first; older captures are left to the crawl to rediscover. Also the most
/// flows a browser crawl's report holds, oldest dropped (R-M3).
pub(crate) const MAX_STORED_FLOWS: usize = 2048;

/// The mark put on every request the crawler makes (spec D5, "crawl marks").
pub(crate) const MARK_CRAWL: &str = "crawl";

/// The prefix of the job mark: every flow a job produces carries
/// `scan:<job id>` (spec D5, AC T1-9).
pub(crate) const JOB_MARK_PREFIX: &str = "scan:";

/// The job mark for `job_id`, built here and nowhere else so the lane, the two
/// crawl engines and the probe host cannot drift on its shape.
pub(crate) fn job_mark(job_id: &str) -> String {
    format!("{JOB_MARK_PREFIX}{job_id}")
}

/// The `User-Agent` every request the lane makes itself carries — a crawl page
/// fetch, a form submission, a `robots.txt` or `sitemap.xml` read.
///
/// Honest on purpose: an operator reading the target's access log sees the
/// scanner, not a spoofed browser (call **A13**). One constant, so the crawl
/// engine and the seed reader cannot drift apart.
pub(crate) const USER_AGENT: &str = "aitm-scan";

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{
        job_mark, CANARY_EVERY, JOB_MARK_PREFIX, MAX_AWAIT, MAX_DOM_BYTES, MAX_FRONTIER,
        MAX_HELD_FLOWS, MAX_LINKS_PER_PAGE, MAX_LOST_MONITOR_IDS, MAX_SESSION_MONITORS,
    };
    use std::time::Duration;

    #[test]
    fn limits_match_the_plan() {
        assert_eq!(MAX_LINKS_PER_PAGE, 512);
        assert_eq!(MAX_FRONTIER, 4096);
        assert_eq!(MAX_DOM_BYTES, 2_097_152);
        assert_eq!(MAX_HELD_FLOWS, 16);
        assert_eq!(CANARY_EVERY, 25);
        assert_eq!(MAX_AWAIT, Duration::from_secs(30));
        assert_eq!(MAX_SESSION_MONITORS, 16);
        assert_eq!(MAX_LOST_MONITOR_IDS, 256);
    }

    /// The job mark is built in one place (Q1): the literal every other crate
    /// and every test asserts against is `scan:<job id>`.
    #[test]
    fn job_mark_pins() {
        assert_eq!(JOB_MARK_PREFIX, "scan:");
        assert_eq!(job_mark("scan-1a2b3c4d"), "scan:scan-1a2b3c4d");
        assert_eq!(job_mark(""), "scan:");
    }
}
