//! Bounded response matching shared by the native HTTP checks.
//!
//! Everything a check reads out of a response passes through here, and
//! everything here is bounded. A response body is matched at most
//! [`MAX_MATCH_BODY`] bytes deep and every excerpt a check quotes into an
//! [`Evidence`] is cut by [`Evidence::excerpt`], so a hostile target cannot grow
//! an issue, a log line or a bus message without limit (spec D8.2, "Redaction").
//!
//! These helpers are deliberately dumb: they answer "what does the response
//! say", never "is this a vulnerability". The verdict is the check's.

use std::borrow::Cow;

use aitm_scan_model::{Evidence, ProbeResponse, MAX_EXCERPT_BYTES, MAX_MATCH_BODY};

/// The smallest response-length difference that counts as a difference, however
/// small the baseline. Below it, compression, a timestamp or a request id is a
/// likelier explanation than the payload.
const MIN_LENGTH_DELTA: usize = 40;

/// The fraction of the baseline above which a difference counts; the shipped
/// `check-sqli.rhai` threshold, kept so a converted script and its native
/// successor read the same response the same way.
const LENGTH_DELTA_DIVISOR: usize = 20;

/// The response body as text for matching: lossy UTF-8, never more than
/// [`MAX_MATCH_BODY`] bytes.
///
/// The lane already bounds `ProbeResponse::body`; this enforces the same bound
/// again rather than trusting it, because a check is the last place a body's
/// size is still the target's choice. Invalid bytes become `U+FFFD` instead of
/// an error: a check that cannot read the body cannot report on it, and a
/// mangled encoding is not a reason to drop a finding.
///
/// Borrowing when it can, so the common (valid UTF-8, under the cap) case does
/// not copy a megabyte per match.
#[must_use]
pub fn body_text(resp: &ProbeResponse) -> Cow<'_, str> {
    let capped = &resp.body[..resp.body.len().min(MAX_MATCH_BODY)];
    match String::from_utf8_lossy(capped) {
        // The slice was already cut to the cap, so a borrow is within it.
        Cow::Borrowed(text) => Cow::Borrowed(text),
        // Each invalid byte expands to a three-byte replacement character, so a
        // lossy conversion can cross the cap the slice respected. Cut it back.
        Cow::Owned(mut text) => {
            if text.len() > MAX_MATCH_BODY {
                let mut end = MAX_MATCH_BODY;
                while end > 0 && !text.is_char_boundary(end) {
                    end -= 1;
                }
                text.truncate(end);
            }
            Cow::Owned(text)
        }
    }
}

/// The first value of `name`, matched ASCII case-insensitively.
///
/// First match, not last and not joined: a check reports what a client would
/// act on, and duplicate headers are themselves a finding for another check.
#[must_use]
pub fn header<'a>(resp: &'a ProbeResponse, name: &str) -> Option<&'a str> {
    resp.headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

/// Whether the response claims to be HTML.
///
/// Substring, not equality, so `text/html; charset=utf-8` and
/// `application/xhtml+xml` both count. A reflection check uses this to decide
/// whether a reflected payload is in a context that could execute.
#[must_use]
pub fn is_html(resp: &ProbeResponse) -> bool {
    header(resp, "content-type").is_some_and(|v| v.to_ascii_lowercase().contains("html"))
}

/// Whether two response lengths differ by enough to mean something, given the
/// baseline they are measured against.
///
/// The threshold is `max(baseline / 20, 40)` bytes — five percent of the
/// baseline, never less than forty — and the comparison is strict, matching the
/// shipped `check-sqli.rhai` rule exactly so the native and scripted boolean
/// techniques never disagree on the same pair of responses.
#[must_use]
pub fn length_differs(a: usize, b: usize, baseline: usize) -> bool {
    let threshold = (baseline / LENGTH_DELTA_DIVISOR).max(MIN_LENGTH_DELTA);
    a.abs_diff(b) > threshold
}

/// A bounded window of `hay` around the first occurrence of `needle`, for an
/// [`Evidence::matched`] field.
///
/// The window is centred on the match and cut to [`MAX_EXCERPT_BYTES`] on
/// character boundaries, so the evidence shows the context that makes the match
/// meaningful rather than a naked prefix. When `needle` does not occur, the
/// leading bytes of `hay` come back instead — a check that quotes a response it
/// did not match still quotes a bounded amount of it.
///
/// This is a **bound, not a scrub**: the caller passes text that has already
/// been through `aitm_core::redact`.
#[must_use]
pub fn excerpt_around(hay: &str, needle: &str) -> String {
    let Some(at) = hay.find(needle) else {
        return Evidence::excerpt(hay);
    };

    let lead = MAX_EXCERPT_BYTES.saturating_sub(needle.len()) / 2;
    let mut start = at.saturating_sub(lead);
    while start < hay.len() && !hay.is_char_boundary(start) {
        start += 1;
    }
    let mut end = start.saturating_add(MAX_EXCERPT_BYTES).min(hay.len());
    while end > start && !hay.is_char_boundary(end) {
        end -= 1;
    }
    Evidence::excerpt(&hay[start..end])
}

#[cfg(test)]
mod tests {
    use aitm_scan_model::{ProbeResponse, MAX_EXCERPT_BYTES, MAX_MATCH_BODY};

    use super::{body_text, excerpt_around, header, is_html, length_differs};

    fn resp(content_type: &str, body: Vec<u8>) -> ProbeResponse {
        ProbeResponse {
            status: Some(200),
            headers: vec![("Content-Type".to_string(), content_type.to_string())],
            body,
            elapsed_ms: 7,
            flow: None,
            ws_frames: None,
            l4: None,
        }
    }

    #[test]
    fn body_text_is_capped_at_max_match_body() {
        let r = resp("text/plain", vec![b'a'; 2 * 1024 * 1024]);
        assert_eq!(body_text(&r).len(), MAX_MATCH_BODY);
    }

    #[test]
    fn length_differs_uses_the_shipped_threshold() {
        assert!(!length_differs(600, 600, 600));
        assert!(length_differs(600, 120, 600));
        assert!(!length_differs(100, 130, 100));
        assert!(length_differs(100, 180, 100));
    }

    /// The rule is `max(baseline / 20, 40)` and the comparison is **strict**, so
    /// a difference of exactly the threshold is not a difference. Both halves of
    /// the `max` and both sides of the boundary are pinned here: the native and
    /// the scripted boolean techniques must not drift apart by a byte.
    #[test]
    fn length_differs_is_strict_at_both_halves_of_the_threshold() {
        // Small baseline: the floor of 40 applies (2000 / 20 = 100 > 40 does not).
        assert!(
            !length_differs(100, 140, 100),
            "exactly 40 is not a difference"
        );
        assert!(length_differs(100, 141, 100));

        // Large baseline: five percent applies, 100 bytes here.
        assert!(
            !length_differs(2000, 2100, 2000),
            "exactly 100 is not a difference"
        );
        assert!(length_differs(2000, 2101, 2000));

        // The order of the two lengths does not matter.
        assert!(length_differs(2101, 2000, 2000));
    }

    #[test]
    fn is_html_matches_a_charset_suffix() {
        assert!(is_html(&resp("text/html; charset=utf-8", Vec::new())));
        assert!(!is_html(&resp("application/json", Vec::new())));
    }

    /// A body that is not valid UTF-8 must still be matchable, and the lossy
    /// replacement characters must not push the result past the cap — three
    /// bytes out for every one in is how a 1 MiB cap becomes a 3 MiB string.
    #[test]
    fn body_text_is_lossy_and_still_capped_on_invalid_utf8() {
        let short = resp("text/plain", vec![b'h', b'i', 0xff]);
        assert_eq!(body_text(&short), "hi\u{fffd}");

        let long = resp("text/plain", vec![0xff; 2 * 1024 * 1024]);
        let text = body_text(&long);
        assert!(text.len() <= MAX_MATCH_BODY, "len was {}", text.len());
        assert!(text.starts_with('\u{fffd}'));
    }

    #[test]
    fn header_is_ascii_case_insensitive_and_takes_the_first() {
        let mut r = resp("text/html", Vec::new());
        r.headers
            .push(("X-Frame-Options".to_string(), "DENY".to_string()));
        r.headers
            .push(("x-frame-options".to_string(), "SAMEORIGIN".to_string()));

        assert_eq!(header(&r, "X-FRAME-OPTIONS"), Some("DENY"));
        assert_eq!(header(&r, "content-type"), Some("text/html"));
        assert_eq!(header(&r, "location"), None);
    }

    /// The window is centred on the match and bounded, and a needle that is not
    /// there still yields a bounded prefix rather than the whole body.
    #[test]
    fn excerpt_around_centres_a_bounded_window_on_the_match() {
        let hay = format!("{}<marker>{}", "a".repeat(500), "b".repeat(500));
        let out = excerpt_around(&hay, "<marker>");
        assert!(out.len() <= MAX_EXCERPT_BYTES, "len was {}", out.len());
        assert!(out.contains("<marker>"), "{out}");
        assert!(out.starts_with('a') && out.ends_with('b'), "{out}");

        let missing = excerpt_around(&hay, "<absent>");
        assert_eq!(missing.len(), MAX_EXCERPT_BYTES);
        assert!(hay.starts_with(&missing));

        // Multi-byte text must never be cut mid-character.
        let wide = format!("{}<marker>{}", "é".repeat(400), "€".repeat(400));
        let cut = excerpt_around(&wide, "<marker>");
        assert!(cut.len() <= MAX_EXCERPT_BYTES);
        assert!(cut.contains("<marker>"), "{cut}");
    }
}
