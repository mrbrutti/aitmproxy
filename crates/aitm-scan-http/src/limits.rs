//! Every bound the HTTP lane enforces, as a named constant.
//!
//! The crate rule (spec D8.1) is that no limit is written inline at its use
//! site: a reviewer reads this one file to see every ceiling the lane applies
//! to a page, a body, the frontier, the browser budget or an await.

// Removed by the tasks that fill the modules consuming these constants.
#![allow(dead_code)]

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

/// Response body bytes held from one crawl fetch.
pub(crate) const MAX_HELD_CRAWL_BODY: usize = 64 * 1024;

/// The mark put on every request the crawler makes (spec D5, "crawl marks").
pub(crate) const MARK_CRAWL: &str = "crawl";

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{
        CANARY_EVERY, MAX_AWAIT, MAX_DOM_BYTES, MAX_FRONTIER, MAX_HELD_FLOWS, MAX_LINKS_PER_PAGE,
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
    }
}
