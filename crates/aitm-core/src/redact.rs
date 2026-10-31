//! The one shared secret vocabulary and credential scrubbers.
//!
//! Every surface that must keep credentials out of durable or pushed output used
//! to carry its own list, and they diverged (the audit redaction knew `cookie`
//! and `credential`; the findings store knew `pwd`; the PoC builder knew `sid`
//! and `jwt`). This module is the single source of truth, used by both:
//!
//! - [`is_secret_key`] — key-level: when an argument *key* names a secret, the
//!   whole value is dropped (the F2 audit `args_summary`, the PoC builder).
//! - [`scrub_text`] — content-level: mask credential material embedded *inside* a
//!   value or free text — a query string (`?access_token=…`), a form body
//!   (`password=…`), a JSON body (`"sid":"…"`), an `Authorization:` line, a
//!   `Bearer <token>` — regardless of the key it sits under. This catches the
//!   secrets a key-only pass misses.
//!
//! There is one vocabulary: the pair pass of [`scrub_text`] decides whether a key
//! is secret by calling [`is_secret_key`], so the two cannot diverge.

use std::sync::OnceLock;

use regex::Regex;

/// Substrings that mark an argument *key* as carrying a secret (matched
/// case-insensitively, as a substring, so `X-Api-Key`, `access_token`,
/// `set-cookie`, `JSESSIONID`, and `ASP.NET_SessionId` are all caught). These are
/// long, distinctive words that are safe to match anywhere inside a key; the short
/// words that would also hit innocent keys live in [`SECRET_KEY_SEGMENTS`].
const SECRET_KEY_NEEDLES: &[&str] = &[
    "authorization",
    "token",
    "password",
    "passwd",
    "pwd",
    "secret",
    "cookie",
    "api_key",
    "apikey",
    "api-key",
    "bearer",
    "credential",
    "sessionid",
    "phpsessid",
];

/// Short words that mark a key as secret only when they are a *whole segment* of
/// it, where segments are the runs of ASCII alphanumerics between every other
/// character (`x-auth`, `connect.sid`, and `_csrf` match; `author`, `authority`,
/// `inside`, `side`, and `sessions` do not). Matched case-insensitively.
const SECRET_KEY_SEGMENTS: &[&str] = &["sid", "jwt", "csrf", "session", "auth"];

/// Whether an argument key names a secret whose value must never be recorded:
/// true when the ASCII-lowercased key contains any `SECRET_KEY_NEEDLES` entry, or
/// when any whole segment of it equals a `SECRET_KEY_SEGMENTS` entry.
pub fn is_secret_key(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    SECRET_KEY_NEEDLES
        .iter()
        .any(|needle| lower.contains(needle))
        || lower
            .split(|c: char| !c.is_ascii_alphanumeric())
            .any(|segment| SECRET_KEY_SEGMENTS.contains(&segment))
}

/// The compiled regex passes of [`scrub_text`], applied in order. The `key=value`
/// pair pass is [`mask_secret_pairs`], not a regex, because it must call
/// [`is_secret_key`] and handle quoted values.
fn patterns() -> &'static [(Regex, &'static str)] {
    static PATTERNS: OnceLock<Vec<(Regex, &'static str)>> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        vec![
            // An `Authorization` header/line: the value is the whole credential,
            // so redact to the end of the line (applied first, before the generic
            // `key=value` pass could stop at the space in `Bearer <token>`).
            (
                Regex::new(r"(?i)(authorization\s*[:=]\s*).+").unwrap(),
                "${1}[redacted]",
            ),
            // A standalone `Bearer <token>` with no `Authorization` prefix.
            (Regex::new(r"(?i)(bearer\s+)\S+").unwrap(), "${1}[redacted]"),
        ]
    })
}

/// Mask credential material embedded anywhere in `text` by *content* (not by the
/// key it is stored under): an `Authorization:` line, a `Bearer <token>`, and
/// every `key=value` / `key: value` pair whose key [`is_secret_key`] — both
/// unquoted (query strings, form bodies, header lines) and JSON-quoted
/// (`"key":"value"`). Redacted values become `[redacted]`.
///
/// A quoted value is masked whole, up to its matching unescaped quote, so a value
/// holding spaces or an escaped quote leaks nothing. A quote that follows `=` or
/// `:` (blanks aside) and has a value character after it is the opener of the next
/// value, not the closer of this one, so an unclosed quote does not swallow the
/// next pair's key and leave its value in the clear while that pair's opening
/// quote is present (`password='a b token='S3'` masks through `S3`); a padded
/// value (`"token":"YWJj=","user":"bob"`) still closes, because a delimiter
/// follows its quote. A next key with only a closing quote is a residual: in
/// `password='x password'=S3CR3T` the first value closes at that quote and
/// `S3CR3T` is left in the clear. An unquoted value, or one whose opening
/// quote never closes, runs to the first whitespace, `&`, `;`, `,`, quote, or `}`.
/// Whitespace is Unicode whitespace (`char::is_whitespace`), as the regex `\s`
/// this replaces was. An empty value is left alone. A pair nested inside a
/// non-secret value (`next=/cb?sid=…`) is still found.
///
/// A `host:port` is not a credential: a dotted key directly followed by `:` and
/// one to five digits ending at `/`, `?`, `#`, a delimiter, or the end of the text
/// (`auth.example.com:8443`) is left alone. A quoted key, a key with no dot, and
/// `=` are never exempt.
///
/// Conservative by design: it over-redacts (any pair whose key reads as secret)
/// rather than risk letting a secret through. Residual limit: a bare credential
/// with no recognisable `key=` or `Bearer`/`Authorization` framing cannot be
/// detected. Work is linear in the length of `text`.
pub fn scrub_text(text: &str) -> String {
    let mut out = text.to_string();
    for (re, rep) in patterns() {
        out = re.replace_all(&out, *rep).into_owned();
    }
    mask_secret_pairs(&out)
}

/// Whether the ASCII byte `b` can be part of a key run: an ASCII alphanumeric,
/// `_`, `.`, or `-`. A non-ASCII character is part of a key run too, unless it is
/// whitespace (see [`run_end`]), so a key with non-ASCII letters is one run.
fn is_key_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-')
}

/// The index where the run of characters starting at `from` ends: at the first
/// ASCII byte for which `ascii_continues` is false, at the first whitespace
/// character (see [`blank_len`]), or at the end of `text`. Any other non-ASCII
/// character continues the run. `from` itself is returned when nothing continues
/// the run there. A char is read once, and `from` must be on a char boundary.
fn run_end(text: &str, from: usize, ascii_continues: fn(u8) -> bool) -> usize {
    let bytes = text.as_bytes();
    let mut end = from;
    while end < bytes.len() {
        let b = bytes[end];
        if b < 0x80 {
            if !ascii_continues(b) {
                break;
            }
            end += 1;
        } else {
            match text.get(end..).and_then(|rest| rest.chars().next()) {
                Some(c) if !c.is_whitespace() => end += c.len_utf8(),
                _ => break,
            }
        }
    }
    end
}

/// Whether `b` is ASCII whitespace as [`char::is_whitespace`] reads it: space,
/// tab, newline, vertical tab, form feed, and carriage return. (`u8`'s own
/// `is_ascii_whitespace` leaves out the vertical tab.)
fn is_ascii_blank(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | 0x0B | 0x0C | b'\r')
}

/// The byte length of the whitespace character at `i` (as [`char::is_whitespace`]
/// reads it, so a no-break space or U+2028 counts), or 0 when the character there
/// is not whitespace, `i` is the end of `text`, or `i` is not on a char boundary.
/// ASCII is decided on the byte; only a non-ASCII lead byte is decoded.
fn blank_len(text: &str, i: usize) -> usize {
    match text.as_bytes().get(i) {
        None => 0,
        Some(&b) if b < 0x80 => usize::from(is_ascii_blank(b)),
        Some(_) => text
            .get(i..)
            .and_then(|rest| rest.chars().next())
            .filter(|c| c.is_whitespace())
            .map_or(0, char::len_utf8),
    }
}

/// The index of the first byte at or after `i` that does not start a whitespace
/// character (see [`blank_len`]).
fn skip_blanks(text: &str, mut i: usize) -> usize {
    loop {
        match blank_len(text, i) {
            0 => return i,
            n => i += n,
        }
    }
}

/// Whether `b` ends an unquoted value: ASCII whitespace or a pair, list, quote,
/// or JSON delimiter. A non-ASCII byte never does here (the caller decodes it to
/// find Unicode whitespace), so a value is over- rather than under-redacted.
// The scanner's copy (`ends_value` in `crates/aitm-plugin-scanner/src/reproduce.rs`)
// is not in step: it deliberately reads ASCII whitespace only (no vertical tab, no
// Unicode whitespace). It stays until the scanner vocabulary consolidation
// follow-up removes it.
fn ends_value(b: u8) -> bool {
    is_ascii_blank(b) || matches!(b, b'&' | b';' | b',' | b'"' | b'\'' | b'}')
}

/// The index where an unquoted value starting at `from` ends: its first ASCII
/// byte for which [`ends_value`] holds, its first whitespace character, or the end
/// of `text`.
fn unquoted_value_end(text: &str, from: usize) -> usize {
    run_end(text, from, |b| !ends_value(b))
}

/// Whether the unescaped `quote` byte at `quote_at` reads as the *opening* quote
/// of a value rather than the closing quote of the one being searched: the last
/// character before it that is not whitespace is `=` or `:`, and the character
/// after it does not end a value (the text's end, whitespace, `&`, `;`, `,`, `}`,
/// `]`). A padded value (`"token":"YWJj=","user":"bob"`) ends in `=` too, but a
/// delimiter follows its closing quote, so it still closes.
fn is_opening_quote(text: &str, quote_at: usize) -> bool {
    // `quote_at` indexes an ASCII byte, so both slices are on char boundaries.
    let after_separator = matches!(
        text[..quote_at]
            .trim_end_matches(char::is_whitespace)
            .chars()
            .next_back(),
        Some('=' | ':')
    );
    after_separator
        && text[quote_at + 1..]
            .chars()
            .next()
            .is_some_and(|c| !(c.is_whitespace() || matches!(c, '&' | ';' | ',' | '}' | ']')))
}

/// The index of the unescaped `quote` byte that closes a quoted value starting at
/// `from`, or `None` if it never closes. A backslash skips the next byte, and a
/// quote that [`is_opening_quote`] does not close the value: it is the opener of
/// the next pair, and closing there would swallow that pair's key and leave its
/// value in the clear.
// The scanner's copy (`closing_quote` in `crates/aitm-plugin-scanner/src/reproduce.rs`)
// is not in step: it deliberately lacks the opener-shaped rule and so closes at the
// next pair's opening quote. It stays until the scanner vocabulary consolidation
// follow-up removes it.
fn closing_quote(text: &str, from: usize, quote: u8) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut k = from;
    while k < bytes.len() {
        match bytes[k] {
            b'\\' => k += 2,
            b if b == quote && !is_opening_quote(text, k) => return Some(k),
            _ => k += 1,
        }
    }
    None
}

/// Whether a key run is the host of a `host:port` rather than a credential key:
/// `run` contains a `.`, `after` (the bytes straight after the run) opens with
/// `:`, and one to five ASCII digits follow that colon, then `/`, `?`, `#`, a
/// value delimiter, or the end. Reads at most seven bytes of `after`. Only an ASCII
/// terminator exempts a host:port: a non-ASCII whitespace terminator (a no-break
/// space after `auth.example.com:8443`) does not, so the pair is masked, which
/// over-redacts, the safe direction.
fn is_host_port(run: &[u8], after: &[u8]) -> bool {
    if !run.contains(&b'.') || after.first() != Some(&b':') {
        return false;
    }
    let digits = after[1..]
        .iter()
        .take(6)
        .take_while(|b| b.is_ascii_digit())
        .count();
    (1..=5).contains(&digits)
        && after
            .get(1 + digits)
            .is_none_or(|&b| matches!(b, b'/' | b'?' | b'#') || ends_value(b))
}

/// Replace the value of every `key=value` / `key: value` pair in `text` whose key
/// run satisfies [`is_secret_key`] with `[redacted]`.
///
/// One linear scan. A key run is followed by an optional closing quote,
/// whitespace (newlines included, so a value on the next line is still masked; see
/// [`blank_len`] for what counts), `=` or `:`, whitespace, an optional opening
/// quote, and the value (see [`scrub_text`] for the value rule). After a masked
/// pair the scan resumes after the value; after any other key run it resumes right
/// after the run, not after the value, so a pair nested in a non-secret value is
/// still seen.
///
/// Each byte is read a constant number of times. A successful search for a closing
/// quote ends where the scan resumes, so successful searches never overlap. A
/// failed search for a quote character reads to the end of the text once, and is
/// remembered: a later search for the same character starts further on and so
/// considers a subset of the candidates, and a candidate is judged on its
/// neighbouring characters alone, so it would fail too and is not run. That holds
/// because every later search starts just after an opening quote that the failed
/// search already passed as a non-closing candidate, so from there the two scans
/// coincide; [`is_opening_quote`] must therefore stay a pure function of the text
/// around the quote. The vocabulary is consulted only for a key run that is
/// followed by a separator, so no allocation is spent on the rest of the text.
fn mask_secret_pairs(text: &str) -> String {
    let bytes = text.as_bytes();
    let len = bytes.len();
    let mut out = String::with_capacity(len);
    // Start of the text not yet copied into `out`.
    let mut copied = 0;
    // Whether a search for a closing `"` (index 0) or `'` (index 1) has failed.
    let mut quote_unclosed = [false; 2];
    let mut i = 0;
    while i < len {
        let key_start = i;
        let key_end = run_end(text, key_start, is_key_byte);
        if key_end == key_start {
            // A delimiter or a whitespace char: step over the whole char.
            i += blank_len(text, i).max(1);
            continue;
        }
        i = key_end;

        // Key run, optional closing quote, whitespace, then `=` or `:`.
        let mut j = key_end;
        if j < len && matches!(bytes[j], b'"' | b'\'') {
            j += 1;
        }
        j = skip_blanks(text, j);
        if j >= len || !matches!(bytes[j], b'=' | b':') {
            continue;
        }
        let separator = bytes[j];
        j += 1;

        // The scan only ever stops on char boundaries and `run_end` steps whole
        // chars, so `key_start..key_end` is on char boundaries.
        let key = &text[key_start..key_end];
        if !is_secret_key(key) {
            continue;
        }
        if separator == b':' && is_host_port(key.as_bytes(), &bytes[key_end..]) {
            continue;
        }

        // Whitespace, an optional opening quote, then the value.
        j = skip_blanks(text, j);
        let quote = match bytes.get(j) {
            Some(&q) if matches!(q, b'"' | b'\'') => {
                j += 1;
                Some(q)
            }
            _ => None,
        };
        let value_start = j;
        let closer = quote.and_then(|q| {
            let unclosed = &mut quote_unclosed[usize::from(q == b'\'')];
            if *unclosed {
                return None;
            }
            let found = closing_quote(text, value_start, q);
            *unclosed = found.is_none();
            found
        });
        let value_end = match closer {
            Some(end) => end,
            // Unquoted, or an opening quote that never closes: the plain rule.
            None => unquoted_value_end(text, value_start),
        };
        if value_end == value_start {
            continue;
        }
        // `value_start` follows an ASCII byte or a whole whitespace char and
        // `value_end` is a quote, a delimiter, a whitespace char, or the end of the
        // text, so both are char boundaries.
        out.push_str(&text[copied..value_start]);
        out.push_str("[redacted]");
        copied = value_end;
        i = value_end;
    }
    out.push_str(&text[copied..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Run [`scrub_text`] over every `(input, expected)` row and return the rows
    /// that came out different, as `(input, expected, actual)`, so one failure
    /// shows every bad row instead of the first.
    fn mismatches<'a>(rows: &[(&'a str, &'a str)]) -> Vec<(&'a str, &'a str, String)> {
        rows.iter()
            .filter_map(|&(input, expected)| {
                let actual = scrub_text(input);
                (actual != expected).then_some((input, expected, actual))
            })
            .collect()
    }

    #[test]
    fn secret_keys_matched_as_substring_case_insensitively() {
        for key in [
            "Authorization",
            "X-Api-Key",
            "access_token",
            "Set-Cookie",
            "db_password",
            "clientSecret",
            "CREDENTIAL",
        ] {
            assert!(is_secret_key(key), "`{key}` should be a secret key");
        }
        for key in ["authority", "path", "body", "note", "method"] {
            assert!(!is_secret_key(key), "`{key}` is not a secret key");
        }
    }

    #[test]
    fn scrubs_token_in_query_string() {
        // The query-string case the audit redaction used to miss.
        let out = scrub_text("/v1/users?access_token=sk-9f8a7b6c5d4e&page=2");
        assert!(!out.contains("sk-9f8a7b6c5d4e"), "token leaked: {out}");
        assert!(out.contains("access_token=[redacted]"), "{out}");
        // Surrounding, non-secret structure survives.
        assert!(out.contains("page=2"), "{out}");
    }

    #[test]
    fn scrubs_credential_in_form_body() {
        let out = scrub_text("user=admin&password=hunter2");
        assert!(!out.contains("hunter2"), "password leaked: {out}");
        assert!(
            out.contains("user=admin"),
            "non-secret field survives: {out}"
        );
        assert!(out.contains("password=[redacted]"), "{out}");
    }

    #[test]
    fn scrubs_secret_in_json_body() {
        // A JSON-encoded request body: the `"` between key and `:` used to break
        // the `key=value` framing, so the value reached the audit log verbatim.
        assert_eq!(
            scrub_text(r#"{"password":"hunter2"}"#),
            r#"{"password":"[redacted]"}"#
        );
        // A space after the colon and a different secret key, same result.
        assert_eq!(
            scrub_text(r#"{"api_key": "sk-9f8a7b6c5d4e"}"#),
            r#"{"api_key": "[redacted]"}"#
        );
        // A non-secret JSON key is untouched, even beside a redacted one.
        assert_eq!(
            scrub_text(r#"{"user":"admin","password":"hunter2"}"#),
            r#"{"user":"admin","password":"[redacted]"}"#
        );
    }

    #[test]
    fn scrubs_authorization_and_bearer_in_free_text() {
        let out = scrub_text("send Authorization: Bearer sk-9f8a7b6c5d4e, then retry");
        assert!(!out.contains("sk-9f8a7b6c5d4e"), "secret leaked: {out}");
        assert!(out.contains("[redacted]"), "{out}");

        let out = scrub_text("got token via Bearer abc.def.ghi here");
        assert!(!out.contains("abc.def.ghi"), "bearer token leaked: {out}");
    }

    #[test]
    fn leaves_innocuous_text_untouched() {
        let text = "GET /search?q=hello&page=2";
        assert_eq!(scrub_text(text), text);
    }

    #[test]
    fn is_secret_key_covers_the_session_and_auth_family() {
        let bad: Vec<&str> = [
            "sid",
            "SID",
            "jwt",
            "csrf",
            "_csrf",
            "session",
            "auth",
            "x-auth",
            "connect.sid",
            "sessionId",
            "JSESSIONID",
            "PHPSESSID",
            "ASP.NET_SessionId",
        ]
        .into_iter()
        .filter(|key| !is_secret_key(key))
        .collect();
        assert!(bad.is_empty(), "should be secret keys: {bad:#?}");
    }

    #[test]
    fn is_secret_key_leaves_lookalikes_alone() {
        let bad: Vec<&str> = [
            "author",
            "authority",
            "authenticated",
            "inside",
            "side",
            "sidebar",
            "subsidiary",
            "sessions",
            "path",
            "host",
            "body",
            "note",
            "method",
        ]
        .into_iter()
        .filter(|key| is_secret_key(key))
        .collect();
        assert!(bad.is_empty(), "should not be secret keys: {bad:#?}");
    }

    #[test]
    fn scrub_text_masks_unframed_session_credentials() {
        let bad = mismatches(&[
            ("sid=abc123", "sid=[redacted]"),
            (
                "/cb?next=/home&sid=S1&page=2",
                "/cb?next=/home&sid=[redacted]&page=2",
            ),
            ("session=abc; theme=dark", "session=[redacted]; theme=dark"),
            ("auth=xyz", "auth=[redacted]"),
            ("jwt=eyJa.b.c", "jwt=[redacted]"),
            ("csrf=c1", "csrf=[redacted]"),
            ("PHPSESSID=p1", "PHPSESSID=[redacted]"),
            ("connect.sid=s%3Aabc", "connect.sid=[redacted]"),
            ("x-auth: v1", "x-auth: [redacted]"),
            (r#"{"sid":"S1","n":1}"#, r#"{"sid":"[redacted]","n":1}"#),
        ]);
        assert!(bad.is_empty(), "wrong output: {bad:#?}");
    }

    #[test]
    fn scrub_text_leaves_lookalike_pairs_alone() {
        let rows: Vec<(&str, &str)> = [
            "author=bob",
            "authority=example.com",
            "inside=1",
            "side=left",
            "sidebar=1",
            "authenticated=true",
            "subsidiary=acme",
            "page=2&q=hello",
            "sid=&x=1",
        ]
        .into_iter()
        .map(|text| (text, text))
        .collect();
        let bad = mismatches(&rows);
        assert!(bad.is_empty(), "should be unchanged: {bad:#?}");
    }

    #[test]
    fn scrub_text_masks_quoted_values_whole() {
        let bad = mismatches(&[
            (r#"{"password":"hunter 2"}"#, r#"{"password":"[redacted]"}"#),
            (r#"{"sid":"a\"b c","n":1}"#, r#"{"sid":"[redacted]","n":1}"#),
            ("{'jwt' : 'a b','n':1}", "{'jwt' : '[redacted]','n':1}"),
            (r#"sid="abc&x=1"#, r#"sid="[redacted]&x=1"#),
            (r#"{"sid":"","n":1}"#, r#"{"sid":"","n":1}"#),
        ]);
        assert!(bad.is_empty(), "wrong output: {bad:#?}");
    }

    #[test]
    fn scrub_text_sees_pairs_nested_in_a_non_secret_value() {
        assert_eq!(scrub_text("next=/cb?sid=S1"), "next=/cb?sid=[redacted]");
    }

    #[test]
    fn scrub_text_masks_a_value_on_the_next_line() {
        // The old pair regex used `\s*` around the separator, so a value on the
        // line after its key was masked; the scan must not be weaker.
        let bad = mismatches(&[
            ("password:\n  hunter2", "password:\n  [redacted]"),
            ("token=\r\nabc123", "token=\r\n[redacted]"),
        ]);
        assert!(bad.is_empty(), "wrong output: {bad:#?}");
    }

    #[test]
    fn scrub_text_does_not_mask_a_host_port() {
        let unchanged: Vec<(&str, &str)> = [
            "https://auth.example.com:8443/login",
            "auth.example.com:8443",
            "token.example.com:8443/x",
        ]
        .into_iter()
        .map(|text| (text, text))
        .collect();
        let mut bad = mismatches(&unchanged);
        bad.extend(mismatches(&[
            ("sid:12345", "sid:[redacted]"),
            ("auth=1", "auth=[redacted]"),
            (r#"{"sid":12345}"#, r#"{"sid":[redacted]}"#),
        ]));
        assert!(bad.is_empty(), "wrong output: {bad:#?}");
    }

    #[test]
    fn scrub_text_and_is_secret_key_share_one_vocabulary() {
        let disagree: Vec<&str> = [
            // The session and auth family, and the look-alikes beside it.
            "sid",
            "SID",
            "jwt",
            "csrf",
            "_csrf",
            "session",
            "auth",
            "x-auth",
            "connect.sid",
            "sessionId",
            "JSESSIONID",
            "PHPSESSID",
            "ASP.NET_SessionId",
            "author",
            "authority",
            "authenticated",
            "inside",
            "side",
            "sidebar",
            "subsidiary",
            "sessions",
            "path",
            "host",
            "body",
            "note",
            "method",
            // The substring needles.
            "authorization",
            "token",
            "password",
            "passwd",
            "pwd",
            "secret",
            "cookie",
            "api_key",
            "apikey",
            "api-key",
            "bearer",
            "credential",
        ]
        .into_iter()
        .filter(|key| {
            let text = format!("{key}=VALUE9");
            is_secret_key(key) != (scrub_text(&text) != text)
        })
        .collect();
        assert!(
            disagree.is_empty(),
            "is_secret_key and scrub_text disagree on: {disagree:#?}"
        );
    }

    #[test]
    fn scrub_text_survives_hostile_inputs() {
        // `assert!` on `==`, not `assert_eq!`: a failure must not print megabytes.

        // The whole remainder is one unquoted value.
        assert!(
            scrub_text(&"sid=".repeat(1 << 20)) == "sid=[redacted]",
            "4 MiB of `sid=` is one value"
        );

        // No pair anywhere: the text comes back byte for byte.
        let a = "a".repeat(4 << 20);
        assert!(scrub_text(&a) == a, "4 MiB of `a` is unchanged");
        let quotes = "\"".repeat(2 << 20);
        assert!(
            scrub_text(&quotes) == quotes,
            "2 MiB of quotes is unchanged"
        );
        let slashes = "\\".repeat(2 << 20);
        assert!(
            scrub_text(&slashes) == slashes,
            "2 MiB of backslashes is unchanged"
        );

        // Quotes that open but never close are in
        // `scrub_text_stays_linear_when_quotes_open_but_never_close`.
    }

    #[test]
    fn scrub_text_masks_a_quoted_secret_after_an_unclosed_quote() {
        // An opening quote that never closes by itself, or whose closer is
        // escaped, used to run on to the NEXT pair's opening quote: that swallowed
        // the next key and left its quoted value in the clear.
        let bad = mismatches(&[
            (
                r#"password='abc def token='S3CR3T'"#,
                r#"password='[redacted]'"#,
            ),
            (
                r#"x-api-key="oops see sessionid="S3CR3T" end"#,
                r#"x-api-key="[redacted]" end"#,
            ),
            ("token: \"a b\nsession: \"S3CR3T\"", "token: \"[redacted]\""),
            (
                r#"password="C:\dir\" token="S3""#,
                r#"password="[redacted]""#,
            ),
            // A failed search for one quote character says nothing about the other:
            // the `'` pair after an unclosed `"` still closes at its own quote.
            (
                r#"a_token="x b_token='y z' c"#,
                r#"a_token="[redacted] b_token='[redacted]' c"#,
            ),
            (
                r#"a_token='x b_token="y z" c"#,
                r#"a_token='[redacted] b_token="[redacted]" c"#,
            ),
        ]);
        assert!(bad.is_empty(), "wrong output: {bad:#?}");
    }

    #[test]
    fn scrub_text_never_leaves_a_credential_after_an_unclosed_quote() {
        // (input, credential text that must not survive scrubbing)
        let rows = [
            (r#"password='abc def token='S3CR3T'"#, "S3CR3T"),
            (r#"x-api-key="oops see sessionid="S3CR3T" end"#, "S3CR3T"),
            ("token: \"a b\nsession: \"S3CR3T\"", "S3CR3T"),
            (r#"password="C:\dir\" token="S3""#, "S3"),
            (r#"api_key="x y secret='S3CR3T' z"#, "S3CR3T"),
            ("password: 'abc\nsecret: 'S3CR3T'", "S3CR3T"),
            (
                r#"a_token="1 b_token="2 c_token="3 d_token="S3CR3T" tail"#,
                "S3CR3T",
            ),
            ("data-sid='x y data-token='S3CR3T' z='1'", "S3CR3T"),
            ("token='abc def sid='S3CR3T", "S3CR3T"),
            (r#"secret="a b\" sid="S3CR3T""#, "S3CR3T"),
            (
                r#"{"a":"x","password":"hunter 2","token":"S3CR3T"}"#,
                "S3CR3T",
            ),
        ];
        let bad: Vec<(&str, String)> = rows
            .iter()
            .filter_map(|&(input, secret)| {
                let out = scrub_text(input);
                out.contains(secret).then_some((input, out))
            })
            .collect();
        assert!(
            bad.is_empty(),
            "a credential was left in the clear: {bad:#?}"
        );
    }

    #[test]
    fn scrub_text_closes_a_padded_value_at_its_own_quote() {
        // A value that ends in `=` (base64 padding) or `:` is closed by its own
        // quote when a delimiter follows it, even though a quote after `=` or `:`
        // otherwise reads as the opening quote of the next value.
        let bad = mismatches(&[
            (
                r#"{"token":"YWJj=","user":"bob"}"#,
                r#"{"token":"[redacted]","user":"bob"}"#,
            ),
            (
                r#"token="YWJj=" user=bob"#,
                r#"token="[redacted]" user=bob"#,
            ),
            (
                r#"?token="YWJj="&user=bob"#,
                r#"?token="[redacted]"&user=bob"#,
            ),
            (r#"token="YWJj=""#, r#"token="[redacted]""#),
            (r#"{"token":"YWJj==" }"#, r#"{"token":"[redacted]" }"#),
            (r#"{"token":"YWJj="}"#, r#"{"token":"[redacted]"}"#),
            (
                r#"{"token":"a:","user":"bob"}"#,
                r#"{"token":"[redacted]","user":"bob"}"#,
            ),
            (
                "token=\"YWJj=\"\u{a0}user=bob",
                "token=\"[redacted]\"\u{a0}user=bob",
            ),
            // Each delimiter that can follow the closing quote, with a quoted
            // pair after it: a delimiter wrongly read as a value character would
            // run this value on to that pair's quote and swallow its key.
            (r#"token="YWJj=";x="y""#, r#"token="[redacted]";x="y""#),
            (r#"?token="YWJj="&x="y""#, r#"?token="[redacted]"&x="y""#),
            (
                r#"{"o":{"token":"YWJj="},"b":"c"}"#,
                r#"{"o":{"token":"[redacted]"},"b":"c"}"#,
            ),
            (r#"[token="YWJj="] x="y""#, r#"[token="[redacted]"] x="y""#),
            (
                "token=\"YWJj=\"\u{a0}x=\"y\"",
                "token=\"[redacted]\"\u{a0}x=\"y\"",
            ),
        ]);
        assert!(bad.is_empty(), "wrong output: {bad:#?}");
    }

    #[test]
    fn scrub_text_stays_linear_when_quotes_open_but_never_close() {
        // `assert!` on `==`, not `assert_eq!`: a failure must not print megabytes.

        // Every quote after `=` reads as an opener except the last, which ends
        // the text: one value, one search.
        let n = (1 << 20) / 5;
        assert!(
            scrub_text(&"sid=\"".repeat(n)) == "sid=\"[redacted]\"",
            "1 MiB of `sid=\"` is one value"
        );

        // No quote closes: each search fails, and a failed search for a quote
        // character is not repeated, so every byte is read a constant number of
        // times.
        assert!(
            scrub_text(&"sid=\"x ".repeat(150_000)) == "sid=\"[redacted] ".repeat(150_000),
            "1 MiB of `sid=\"x ` masks every value"
        );
        assert!(
            scrub_text(&"sid='x ".repeat(150_000)) == "sid='[redacted] ".repeat(150_000),
            "1 MiB of `sid='x ` masks every value"
        );
        assert!(
            scrub_text(&"sid=\"x sid='x ".repeat(75_000))
                == "sid=\"[redacted] sid='[redacted] ".repeat(75_000),
            "1 MiB of alternating quote characters masks every value"
        );
    }

    #[test]
    fn scrub_text_reads_unicode_whitespace_as_blank() {
        // The old pair regex used the Unicode `\s`; the scan must not be weaker.
        let bad = mismatches(&[
            ("password\u{b}=hunter2", "password\u{b}=[redacted]"),
            (
                "credentials=\u{a0}\"CNRY0\"",
                "credentials=\u{a0}\"[redacted]\"",
            ),
            (
                "api_key=\u{b}CNRY0\u{2028}z+?secret='X'",
                "api_key=\u{b}[redacted]\u{2028}z+?secret='[redacted]'",
            ),
            ("token=abc\u{3000}x", "token=[redacted]\u{3000}x"),
            (
                "password\u{2003}:\u{2003}hunter2",
                "password\u{2003}:\u{2003}[redacted]",
            ),
            // A Unicode blank ends a key run, as it did for the old regex's key
            // class: `token` here is not a pair (a quote, not a separator, follows
            // the blank), so the pair after it is found; and `password` after
            // `secret\u{2028}é\n=` is a key, not the tail of that pair's value.
            (
                "token\u{a0}'\n:\n]xapi_key:\u{b}S3CR3T",
                "token\u{a0}'\n:\n]xapi_key:\u{b}[redacted]",
            ),
            (
                "secret\u{2028}é\n=password\u{2028}=S3CR3T",
                "secret\u{2028}é\n=password\u{2028}=[redacted]",
            ),
        ]);
        assert!(bad.is_empty(), "wrong output: {bad:#?}");
    }
}
