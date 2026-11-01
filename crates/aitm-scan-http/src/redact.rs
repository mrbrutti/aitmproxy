//! The one redaction indirection of the HTTP lane (spec D8.1, AC T2-6).
//!
//! Two rules hold the lane to the spec, and both are enforced here rather than
//! at each call site:
//!
//! - Every `InsertionPoint.example` is built by [`example`], so a cookie value
//!   or any value under a secret-looking name is the literal [`REDACTED`] and
//!   everything else is scrubbed and cut to a bounded length.
//! - Every URL that reaches a `tracing` line or an `anyhow!`/`bail!` message is
//!   built by [`safe_url`] or [`safe_request_url`], so no credential in a
//!   userinfo section or a query parameter ever lands in a log or an error. The
//!   `log_sites_route_urls_through_safe_url` test below is a lint over the
//!   lane's five network-facing modules that fails the build when a later task
//!   logs a raw URL.
//!
//! The secret vocabulary itself is never defined here: [`scrub`] and
//! [`is_secret_name`] are one-line indirections to `aitm_core::redact`, which is
//! the single source of truth shared with the audit log, the findings store and
//! the PoC builder. They are the only two call sites of that module in this
//! crate, so widening the vocabulary (PR #199's `_wide` pair, task 22) is a
//! two-line edit in this file.

use aitm_core::flow::HttpRequest;
use aitm_scan_model::InsertionKind;

use crate::limits::{MAX_EXAMPLE_CHARS, MAX_SAFE_URL_CHARS};

/// What the lane shows instead of a value it must never reveal.
///
/// Distinct on purpose from `aitm_core::redact`'s own `[redacted]` token: this
/// one means "the whole value was withheld", the core's means "a credential was
/// masked inside this text".
pub(crate) const REDACTED: &str = "<redacted>";

/// Mask credential material embedded inside `text` (`password=…`, `Bearer …`,
/// `"sid":"…"`), using the shared vocabulary.
///
/// Task 22 flips this to `scrub_text_wide` once PR #199 is on `origin/main`.
pub(crate) fn scrub(text: &str) -> String {
    aitm_core::redact::scrub_text(text)
}

/// Whether a parameter, header or cookie name reads as a secret, using the
/// shared vocabulary.
///
/// Task 22 flips this to `is_secret_key_wide` once PR #199 is on `origin/main`.
pub(crate) fn is_secret_name(name: &str) -> bool {
    aitm_core::redact::is_secret_key(name)
}

/// The `example` an `InsertionPoint` may carry for `(kind, name, value)`.
///
/// [`REDACTED`] when the point is a cookie (every cookie value is session
/// material, whatever it is called) or when the name reads as a secret;
/// otherwise the scrubbed value cut to [`MAX_EXAMPLE_CHARS`] characters on a
/// char boundary, with no ellipsis (an ellipsis would be indistinguishable from
/// one in the value itself).
pub(crate) fn example(kind: InsertionKind, name: &str, value: &str) -> String {
    if kind == InsertionKind::Cookie || is_secret_name(name) {
        return REDACTED.to_string();
    }
    cut_chars(&scrub(value), MAX_EXAMPLE_CHARS)
}

/// `url` with every credential removed, safe for a log line or an error message.
///
/// When it parses as a URL: the userinfo is dropped, the fragment is dropped,
/// and the query is rebuilt pair by pair: a pair whose key [`is_secret_name`]
/// has its value replaced by [`REDACTED`], every other pair keeps its key and
/// has its value passed through [`scrub`], with no re-encoding. When it does
/// not parse (a relative reference, a malformed
/// authority), everything up to and including the last `@` of the
/// authority-looking head is dropped — that is where a `user:password@` sits —
/// and the rest is scrubbed. Either way the result is cut to
/// [`MAX_SAFE_URL_CHARS`] characters on a char boundary.
pub(crate) fn safe_url(url: &str) -> String {
    let cleaned = match url::Url::parse(url) {
        Ok(parsed) => rebuild(&parsed),
        Err(_) => scrub(&drop_userinfo(url)),
    };
    cut_chars(&cleaned, MAX_SAFE_URL_CHARS)
}

/// [`safe_url`] of the absolute URL a request addresses.
pub(crate) fn safe_request_url(req: &HttpRequest) -> String {
    safe_url(&format!("{}://{}{}", req.scheme, req.authority, req.path))
}

/// A parsed URL without its userinfo or fragment, with secret query values
/// replaced. The query is rebuilt from the raw text, never re-encoded, so the
/// logged URL still reads like the one on the wire.
fn rebuild(parsed: &url::Url) -> String {
    let mut out = String::new();
    out.push_str(parsed.scheme());
    match parsed.host_str() {
        Some(host) => {
            out.push_str("://");
            out.push_str(host);
            if let Some(port) = parsed.port() {
                out.push(':');
                out.push_str(&port.to_string());
            }
        }
        None => out.push(':'),
    }
    out.push_str(parsed.path());
    if let Some(query) = parsed.query() {
        out.push('?');
        out.push_str(&safe_query(query));
    }
    out
}

/// A raw query string with the value of every pair whose key [`is_secret_name`]
/// replaced by [`REDACTED`], and the value of every other pair passed through
/// [`scrub`], so a credential nested inside a non-secret parameter (an
/// unencoded `next=/cb?sid=abc`) is masked too. Pairs are split on `&` and the
/// first `=` only; a fragment with no `=` is scrubbed whole.
fn safe_query(query: &str) -> String {
    let mut out = String::new();
    for (index, pair) in query.split('&').enumerate() {
        if index > 0 {
            out.push('&');
        }
        match pair.split_once('=') {
            Some((key, _)) if is_secret_name(key) => {
                out.push_str(key);
                out.push('=');
                out.push_str(REDACTED);
            }
            Some((key, value)) => {
                out.push_str(key);
                out.push('=');
                out.push_str(&scrub(value));
            }
            None => out.push_str(&scrub(pair)),
        }
    }
    out
}

/// `url` with everything up to and including the last `@` of its
/// authority-looking head removed; `url` unchanged when that head holds no `@`.
///
/// Used only when the URL does not parse, where there is no structure to trust:
/// dropping the head is the conservative reading, because a `user:password@` can
/// only sit before the first `/`, `?` or `#`.
fn drop_userinfo(url: &str) -> String {
    let after_scheme = url.find("://").map_or(0, |index| index + 3);
    let Some(rest) = url.get(after_scheme..) else {
        return url.to_string();
    };
    let head_len = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let head = rest.get(..head_len).unwrap_or(rest);
    match head.rfind('@') {
        Some(at) => rest.get(at + 1..).unwrap_or(rest).to_string(),
        None => url.to_string(),
    }
}

/// The first `max` characters of `text`, cut on a char boundary.
fn cut_chars(text: &str, max: usize) -> String {
    match text.char_indices().nth(max) {
        Some((end, _)) => text.get(..end).unwrap_or(text).to_string(),
        None => text.to_string(),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{example, safe_url};
    use crate::limits::{MAX_EXAMPLE_CHARS, MAX_SAFE_URL_CHARS};
    use aitm_scan_model::InsertionKind;
    use regex::Regex;

    #[test]
    fn example_rules() {
        assert_eq!(example(InsertionKind::Query, "q", "hello"), "hello");
        assert_eq!(
            example(InsertionKind::Cookie, "theme", "dark"),
            "<redacted>"
        );
        assert_eq!(
            example(InsertionKind::Header, "Authorization", "Bearer abc"),
            "<redacted>"
        );
        assert_eq!(
            example(InsertionKind::Query, "next", "/cb?sid=abc"),
            "/cb?sid=[redacted]"
        );
        assert_eq!(
            example(InsertionKind::Query, "q", &"a".repeat(100))
                .chars()
                .count(),
            MAX_EXAMPLE_CHARS
        );
        assert_eq!(
            example(InsertionKind::Query, "q", &"é".repeat(100))
                .chars()
                .count(),
            MAX_EXAMPLE_CHARS
        );
    }

    #[test]
    fn safe_url_pins() {
        assert_eq!(
            safe_url("http://t/x?sid=abc&q=1"),
            "http://t/x?sid=<redacted>&q=1"
        );
        assert_eq!(safe_url("http://u:p@t/x#frag"), "http://t/x");
        assert_eq!(
            safe_url("https://t:8443/a?token=abc&b=2&Authorization=xyz"),
            "https://t:8443/a?token=<redacted>&b=2&Authorization=<redacted>"
        );
        assert!(!safe_url("nope://u:hunter2@h/?password=hunter2").contains("hunter2"));
        assert_eq!(
            safe_url(&format!("http://t/{}", "a".repeat(400)))
                .chars()
                .count(),
            MAX_SAFE_URL_CHARS
        );
    }

    #[test]
    fn safe_url_scrubs_kept_query_values() {
        assert_eq!(
            safe_url("http://t/x?next=/cb?sid=abc&q=1"),
            "http://t/x?next=/cb?sid=[redacted]&q=1"
        );
    }

    /// The macro invocations this lint inspects: every line that opens a
    /// `tracing` log line or an `anyhow`/`bail` error.
    const LOG_OPENERS: &[&str] = &[
        "tracing::",
        "warn!(",
        "info!(",
        "debug!(",
        "trace!(",
        "error!(",
        "anyhow!(",
        "bail!(",
    ];

    /// At most this many lines of one invocation are read.
    const MAX_INVOCATION_LINES: usize = 8;

    /// Every log or error invocation in `source`, as `(1-based line, text)`.
    fn log_invocations(source: &str) -> Vec<(usize, String)> {
        let lines: Vec<&str> = source.lines().collect();
        let mut found = Vec::new();
        for (index, line) in lines.iter().enumerate() {
            if !LOG_OPENERS.iter().any(|opener| line.contains(opener)) {
                continue;
            }
            let mut text = String::new();
            for taken in lines.iter().skip(index).take(MAX_INVOCATION_LINES) {
                text.push_str(taken);
                text.push('\n');
                if taken.trim_end().ends_with(");") {
                    break;
                }
            }
            found.push((index + 1, text));
        }
        found
    }

    /// Whether `text` names the identifier `url` as a whole word (so `safe_url`,
    /// `url_norm` and `request_url` do not count), case-insensitively.
    fn mentions_url(text: &str) -> bool {
        #[allow(clippy::unwrap_used)]
        let re = Regex::new(r"(?i)\burl\b").unwrap();
        re.is_match(text)
    }

    /// Whether `text` routes through this module's scrubbers.
    fn mentions_safe_url(text: &str) -> bool {
        text.contains("safe_url(") || text.contains("safe_request_url(")
    }

    #[test]
    fn log_sites_route_urls_through_safe_url() {
        for (file, source) in [
            ("host.rs", include_str!("host.rs")),
            ("crawl/browser.rs", include_str!("crawl/browser.rs")),
            ("crawl/client.rs", include_str!("crawl/client.rs")),
            ("session.rs", include_str!("session.rs")),
            ("lane.rs", include_str!("lane.rs")),
        ] {
            for (line, text) in log_invocations(source) {
                if !mentions_url(&text) {
                    continue;
                }
                assert!(
                    mentions_safe_url(&text),
                    "{file}:{line}: this log or error invocation names a URL but does not \
                     route it through redact::safe_url / redact::safe_request_url:\n{text}"
                );
            }
        }
    }

    #[test]
    fn log_lint_catches_a_raw_url_and_accepts_a_scrubbed_one() {
        let raw = "    tracing::warn!(target: \"scan\", url = %url, \"probe failed\");\n";
        let invocations = log_invocations(raw);
        assert_eq!(invocations.len(), 1);
        assert!(mentions_url(&invocations[0].1));
        assert!(!mentions_safe_url(&invocations[0].1));

        let scrubbed =
            "    tracing::warn!(target: \"scan\", url = %safe_url(&url), \"probe failed\");\n";
        let invocations = log_invocations(scrubbed);
        assert_eq!(invocations.len(), 1);
        assert!(mentions_safe_url(&invocations[0].1));
    }
}
