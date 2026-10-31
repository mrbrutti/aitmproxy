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
/// true when the ASCII-lowercased key contains any [`SECRET_KEY_NEEDLES`] entry,
/// or when any whole segment of it equals a [`SECRET_KEY_SEGMENTS`] entry.
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
/// holding spaces or an escaped quote leaks nothing; an unquoted value, or one
/// whose opening quote never closes, runs to the first whitespace, `&`, `;`, `,`,
/// quote, or `}`. An empty value is left alone. A pair nested inside a non-secret
/// value (`next=/cb?sid=…`) is still found.
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

/// Whether `b` can be part of a key run: an ASCII alphanumeric, `_`, `.`, `-`, or
/// any non-ASCII byte (so a key with non-ASCII letters is one run).
fn is_key_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-') || b >= 0x80
}

/// Whether `b` ends an unquoted value: ASCII whitespace or a pair, list, quote,
/// or JSON delimiter. A non-ASCII byte never does, so a value is over- rather
/// than under-redacted.
fn ends_value(b: u8) -> bool {
    b.is_ascii_whitespace() || matches!(b, b'&' | b';' | b',' | b'"' | b'\'' | b'}')
}

/// The index of the unescaped `quote` byte that closes a quoted value starting at
/// `from`, or `None` if it never closes. A backslash skips the next byte.
fn closing_quote(bytes: &[u8], from: usize, quote: u8) -> Option<usize> {
    let mut k = from;
    while k < bytes.len() {
        match bytes[k] {
            b'\\' => k += 2,
            b if b == quote => return Some(k),
            _ => k += 1,
        }
    }
    None
}

/// Whether a key run is the host of a `host:port` rather than a credential key:
/// `run` contains a `.`, `after` (the bytes straight after the run) opens with
/// `:`, and one to five ASCII digits follow that colon, then `/`, `?`, `#`, a
/// value delimiter, or the end. Reads at most seven bytes of `after`.
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
/// One linear scan. A key run is followed by an optional closing quote, ASCII
/// whitespace (newlines included, so a value on the next line is still masked),
/// `=` or `:`, ASCII whitespace, an optional opening quote, and the value (see
/// [`scrub_text`] for the value rule). After a masked pair the scan resumes after
/// the value; after any other key run it resumes right after the run, not after
/// the value, so a pair nested in a non-secret value is still seen. Each byte is
/// read a constant number of times: a failed search for a closing quote can
/// happen at most once per quote character, because any later opening quote of
/// the same character would have closed it. The vocabulary is consulted only for
/// a key run that is followed by a separator, so no allocation is spent on the
/// rest of the text.
fn mask_secret_pairs(text: &str) -> String {
    let bytes = text.as_bytes();
    let len = bytes.len();
    let mut out = String::with_capacity(len);
    // Start of the text not yet copied into `out`.
    let mut copied = 0;
    let mut i = 0;
    while i < len {
        if !is_key_byte(bytes[i]) {
            i += 1;
            continue;
        }
        let key_start = i;
        while i < len && is_key_byte(bytes[i]) {
            i += 1;
        }
        let key_end = i;

        // Key run, optional closing quote, whitespace, then `=` or `:`.
        let mut j = key_end;
        if j < len && matches!(bytes[j], b'"' | b'\'') {
            j += 1;
        }
        while j < len && bytes[j].is_ascii_whitespace() {
            j += 1;
        }
        if j >= len || !matches!(bytes[j], b'=' | b':') {
            continue;
        }
        let separator = bytes[j];
        j += 1;

        // A run starts after an ASCII byte and ends before one (or the text's
        // end), so `key_start..key_end` is on char boundaries.
        let key = &text[key_start..key_end];
        if !is_secret_key(key) {
            continue;
        }
        if separator == b':' && is_host_port(key.as_bytes(), &bytes[key_end..]) {
            continue;
        }

        // Whitespace, an optional opening quote, then the value.
        while j < len && bytes[j].is_ascii_whitespace() {
            j += 1;
        }
        let quote = match bytes.get(j) {
            Some(&q) if matches!(q, b'"' | b'\'') => {
                j += 1;
                Some(q)
            }
            _ => None,
        };
        let value_start = j;
        let value_end = match quote.and_then(|q| closing_quote(bytes, value_start, q)) {
            Some(end) => end,
            // Unquoted, or an opening quote that never closes: the plain rule.
            None => {
                let mut end = value_start;
                while end < len && !ends_value(bytes[end]) {
                    end += 1;
                }
                end
            }
        };
        if value_end == value_start {
            continue;
        }
        // `value_start` follows an ASCII byte and `value_end` precedes one (or is
        // the end of the text), so both are char boundaries.
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
        for key in [
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
        ] {
            assert!(is_secret_key(key), "`{key}` should be a secret key");
        }
    }

    #[test]
    fn is_secret_key_leaves_lookalikes_alone() {
        for key in [
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
        ] {
            assert!(!is_secret_key(key), "`{key}` is not a secret key");
        }
    }

    #[test]
    fn scrub_text_masks_unframed_session_credentials() {
        for (input, expected) in [
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
        ] {
            assert_eq!(scrub_text(input), expected, "input: {input}");
        }
    }

    #[test]
    fn scrub_text_leaves_lookalike_pairs_alone() {
        for text in [
            "author=bob",
            "authority=example.com",
            "inside=1",
            "side=left",
            "sidebar=1",
            "authenticated=true",
            "subsidiary=acme",
            "page=2&q=hello",
            "sid=&x=1",
        ] {
            assert_eq!(scrub_text(text), text, "input: {text}");
        }
    }

    #[test]
    fn scrub_text_masks_quoted_values_whole() {
        for (input, expected) in [
            (r#"{"password":"hunter 2"}"#, r#"{"password":"[redacted]"}"#),
            (r#"{"sid":"a\"b c","n":1}"#, r#"{"sid":"[redacted]","n":1}"#),
            ("{'jwt' : 'a b','n':1}", "{'jwt' : '[redacted]','n':1}"),
            (r#"sid="abc&x=1"#, r#"sid="[redacted]&x=1"#),
            (r#"{"sid":"","n":1}"#, r#"{"sid":"","n":1}"#),
        ] {
            assert_eq!(scrub_text(input), expected, "input: {input}");
        }
    }

    #[test]
    fn scrub_text_sees_pairs_nested_in_a_non_secret_value() {
        assert_eq!(scrub_text("next=/cb?sid=S1"), "next=/cb?sid=[redacted]");
    }

    #[test]
    fn scrub_text_masks_a_value_on_the_next_line() {
        // The old pair regex used `\s*` around the separator, so a value on the
        // line after its key was masked; the scan must not be weaker.
        for (input, expected) in [
            ("password:\n  hunter2", "password:\n  [redacted]"),
            ("token=\r\nabc123", "token=\r\n[redacted]"),
        ] {
            assert_eq!(scrub_text(input), expected, "input: {input:?}");
        }
    }

    #[test]
    fn scrub_text_does_not_mask_a_host_port() {
        for text in [
            "https://auth.example.com:8443/login",
            "auth.example.com:8443",
            "token.example.com:8443/x",
        ] {
            assert_eq!(scrub_text(text), text, "input: {text}");
        }
        for (input, expected) in [
            ("sid:12345", "sid:[redacted]"),
            ("auth=1", "auth=[redacted]"),
            (r#"{"sid":12345}"#, r#"{"sid":[redacted]}"#),
        ] {
            assert_eq!(scrub_text(input), expected, "input: {input}");
        }
    }

    #[test]
    fn scrub_text_and_is_secret_key_share_one_vocabulary() {
        for key in [
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
        ] {
            let text = format!("{key}=VALUE9");
            assert_eq!(
                is_secret_key(key),
                scrub_text(&text) != text,
                "`{key}`: is_secret_key and scrub_text disagree"
            );
        }
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

        // Each opening quote is closed by the next repeat's quote, so the
        // pairs mask in twos and every byte is read a constant number of times.
        assert!(
            scrub_text(&"sid='x ".repeat(150_000)) == "sid='[redacted]'x ".repeat(75_000),
            "1 MiB of `sid='x ` masks in pairs"
        );
    }
}
