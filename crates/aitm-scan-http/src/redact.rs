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

/// A foreign error's text, flattened with its context chain and scrubbed, for a
/// log line or an `anyhow!` message.
///
/// The lane cannot know what a browser driver, a transport or a body parser
/// puts in an error: a driver may echo the URL it failed on (`?token=…`) or the
/// `document.cookie = "sid=…"` statement it rejected, a parser the element name
/// it choked on. Every such error goes through here before it is logged or
/// propagated, so the scrub happens once and at the boundary.
pub(crate) fn scrub_error(err: &anyhow::Error) -> String {
    scrub(&format!("{err:#}"))
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
/// first `=` only; a fragment with no `=` is scrubbed whole. The key is
/// percent-decoded before the secret check, so `s%65ssion` cannot escape the
/// rule, while the raw key is emitted unchanged (S-M4).
fn safe_query(query: &str) -> String {
    let mut out = String::new();
    for (index, pair) in query.split('&').enumerate() {
        if index > 0 {
            out.push('&');
        }
        match pair.split_once('=') {
            Some((key, _)) if is_secret_name(&decode_key(key)) => {
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

/// A query key with its percent-encoding decoded, so the secret-key check sees
/// `session` rather than `s%65ssion` (S-M4). `+` is treated as a space, as in a
/// form-encoded key. On the rare malformed key the raw text is returned.
fn decode_key(key: &str) -> String {
    url::form_urlencoded::parse(key.as_bytes())
        .next()
        .map_or_else(|| key.to_string(), |(decoded, _)| decoded.into_owned())
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

/// Test support: capture the `tracing` events this thread emits, so a test can
/// assert on what a real log site wrote.
///
/// One process-wide subscriber is installed on first use; it enables every
/// callsite and hands each event to the *emitting thread's* sink, which
/// [`install`] sets for the life of the returned guard. A `current_thread`
/// tokio test runs its futures on the test thread, so the lane's lines land in
/// that test's `Lines` and nowhere else. (A scoped `set_default` subscriber is
/// not enough: while exactly one is alive, another test thread's first hit on a
/// callsite caches that callsite's interest as `never` against the no-op global
/// default, and the capturing thread then loses the event.) Each line is the
/// event's fields as `name=value ` pairs followed by the message.
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
pub(crate) mod capture {
    use std::cell::RefCell;
    use std::fmt::{self, Write as _};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex, Once};

    use tracing::field::{Field, Visit};
    use tracing::span::{Attributes, Id, Record};
    use tracing::{Event, Metadata, Subscriber};

    /// The lines an [`install`]ed capture recorded so far.
    #[derive(Clone, Default)]
    pub(crate) struct Lines(Arc<Mutex<Vec<String>>>);

    impl Lines {
        /// Every recorded line, in order.
        pub(crate) fn all(&self) -> Vec<String> {
            self.0.lock().unwrap().clone()
        }

        /// The lines whose text contains `needle`.
        pub(crate) fn containing(&self, needle: &str) -> Vec<String> {
            self.all()
                .into_iter()
                .filter(|line| line.contains(needle))
                .collect()
        }
    }

    thread_local! {
        /// Where this thread's events go while a capture is installed.
        static SINK: RefCell<Option<Lines>> = const { RefCell::new(None) };
    }

    static INSTALL: Once = Once::new();

    struct FanOut {
        next_span: AtomicU64,
    }

    struct LineVisitor(String);

    impl Visit for LineVisitor {
        fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
            let _ = write!(self.0, "{}={:?} ", field.name(), value);
        }
    }

    impl Subscriber for FanOut {
        fn enabled(&self, _: &Metadata<'_>) -> bool {
            true
        }

        fn new_span(&self, _: &Attributes<'_>) -> Id {
            Id::from_u64(self.next_span.fetch_add(1, Ordering::SeqCst) + 1)
        }

        fn record(&self, _: &Id, _: &Record<'_>) {}

        fn record_follows_from(&self, _: &Id, _: &Id) {}

        fn event(&self, event: &Event<'_>) {
            let mut visitor = LineVisitor(String::new());
            event.record(&mut visitor);
            SINK.with(|sink| {
                if let Some(lines) = sink.borrow().as_ref() {
                    lines.0.lock().unwrap().push(visitor.0);
                }
            });
        }

        fn enter(&self, _: &Id) {}

        fn exit(&self, _: &Id) {}
    }

    /// Clears this thread's sink when dropped.
    pub(crate) struct Guard;

    impl Drop for Guard {
        fn drop(&mut self) {
            SINK.with(|sink| sink.borrow_mut().take());
        }
    }

    /// Start capturing this thread's `tracing` events until the guard drops.
    pub(crate) fn install() -> (Guard, Lines) {
        INSTALL.call_once(|| {
            // Another global (none in this crate) would mean every capture test
            // fails loudly on its first assertion, which is the right outcome.
            let _ = tracing::subscriber::set_global_default(FanOut {
                next_span: AtomicU64::new(0),
            });
        });
        let lines = Lines::default();
        SINK.with(|sink| *sink.borrow_mut() = Some(lines.clone()));
        (Guard, lines)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{example, safe_url, scrub_error};
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

    /// A foreign error (a browser driver's, a body parser's) is flattened to one
    /// line and scrubbed before it can reach a log or an `anyhow` message
    /// (stage-5 F1/F3).
    #[test]
    fn scrub_error_masks_credentials_in_a_foreign_error() {
        let err = anyhow::anyhow!(
            "navigation to http://t:8080/cb?token=abc failed after document.cookie = \"sid=S3\""
        )
        .context("crawl step");
        let text = scrub_error(&err);
        assert!(!text.contains("abc"), "{text}");
        assert!(!text.contains("S3"), "{text}");
        assert!(text.contains("crawl step"), "{text}");
        assert!(
            text.contains("navigation to http://t:8080/cb?token="),
            "{text}"
        );
    }

    /// A percent-encoded query key must not escape the secret-key rule: the key
    /// is decoded before [`super::is_secret_name`] sees it, while the raw key is
    /// emitted unchanged (S-M4).
    #[test]
    fn safe_url_decodes_query_key_for_the_secret_check() {
        assert_eq!(
            safe_url("http://t/x?s%65ssion=abc"),
            "http://t/x?s%65ssion=<redacted>"
        );
    }

    /// S-M4 (tester): the decoded-key rule holds for upper-case hex, for a key
    /// whose first byte is encoded, for `+` as a segment separator, and in the
    /// middle of other pairs; a non-secret encoded key keeps its value, and a
    /// malformed escape neither panics nor hides a plain secret next to it.
    #[test]
    fn safe_url_decoded_key_check_pins_variants() {
        assert_eq!(
            safe_url("http://t/x?S%45SSION=abc"),
            "http://t/x?S%45SSION=<redacted>"
        );
        assert_eq!(
            safe_url("http://t/x?%74oken=abc"),
            "http://t/x?%74oken=<redacted>"
        );
        assert_eq!(
            safe_url("http://t/x?x+session=abc"),
            "http://t/x?x+session=<redacted>"
        );
        assert_eq!(
            safe_url("http://t/x?a=1&p%61ssword=hunter2&n%61me=bob"),
            "http://t/x?a=1&p%61ssword=<redacted>&n%61me=bob"
        );
        assert_eq!(
            safe_url("http://t/x?%zz=1&token=abc"),
            "http://t/x?%zz=1&token=<redacted>"
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
            // A `use tracing::{..};` line names the crate, not a log site.
            if line.trim_start().starts_with("use ") {
                continue;
            }
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
        static RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
        RE.get_or_init(|| Regex::new(r"(?i)\burl\b").expect("a valid regex literal"))
            .is_match(text)
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
            ("crawl/seeds.rs", include_str!("crawl/seeds.rs")),
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

        // An import block is not a log site: a `use tracing::{..};` line followed
        // by `use url::Url;` must not be read as an invocation naming a URL (R1),
        // while the real warn! that follows it is still caught.
        let imports_then_raw = concat!(
            "use tracing::{debug, warn};\n",
            "use url::Url;\n",
            "\n",
            "fn f(url: &Url) {\n",
            "    warn!(url = %url, \"probe failed\");\n",
            "}\n",
        );
        let invocations = log_invocations(imports_then_raw);
        assert_eq!(
            invocations
                .iter()
                .map(|(line, _)| *line)
                .collect::<Vec<_>>(),
            vec![5],
            "{invocations:?}"
        );
        assert!(mentions_url(&invocations[0].1));
        assert!(!mentions_safe_url(&invocations[0].1));
    }

    // --- tester additions (stage 5, whole branch) ----------------------------

    /// The scrubbers survive empty, relative, malformed and IPv6 input without
    /// losing the credential-free parts or keeping a credential.
    #[test]
    fn safe_url_survives_empty_and_odd_input() {
        assert_eq!(safe_url(""), "");
        assert_eq!(safe_url("http://t/x?a"), "http://t/x?a");
        assert_eq!(
            safe_url("http://[::1]:8080/x?a=1"),
            "http://[::1]:8080/x?a=1"
        );
        assert_eq!(
            safe_url("/relative?token=abc"),
            "/relative?token=[redacted]"
        );
        let garbage = safe_url("not a url sid=abc password=hunter2");
        assert!(
            !garbage.contains("abc") && !garbage.contains("hunter2"),
            "{garbage}"
        );
        // An out-of-range port makes the URL unparseable; the userinfo still goes.
        let unparseable = safe_url("http://user:hunter2@h:99999/x?q=1");
        assert!(!unparseable.contains("hunter2"), "{unparseable}");
        assert!(unparseable.contains("h:99999/x?q=1"), "{unparseable}");
        assert_eq!(example(InsertionKind::Query, "q", ""), "");
    }
}
