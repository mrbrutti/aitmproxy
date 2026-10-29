//! The one shared secret vocabulary and credential scrubbers.
//!
//! Every surface that must keep credentials out of durable or pushed output used
//! to carry its own list, and they diverged (the audit redaction knew `cookie`
//! and `credential`; the findings store knew `pwd`). This module is the single
//! source of truth, used by both:
//!
//! - [`is_secret_key`] — key-level: when an argument *key* names a secret, the
//!   whole value is dropped (the F2 audit `args_summary`).
//! - [`scrub_text`] — content-level: mask credential material embedded *inside* a
//!   value or free text — a query string (`?access_token=…`), a form body
//!   (`password=…`), an `Authorization:` line, a `Bearer <token>` — regardless of
//!   the key it sits under. This catches the secrets a key-only pass misses.

use std::sync::OnceLock;

use regex::Regex;

/// Substrings that mark an argument *key* as carrying a secret (matched
/// case-insensitively, as a substring, so `X-Api-Key`, `access_token`, and
/// `set-cookie` are all caught). The content scrubber's `key=value` pass below
/// is built from the same vocabulary.
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
];

/// Whether an argument key names a secret whose value must never be recorded.
/// Matched case-insensitively as a substring against [`SECRET_KEY_NEEDLES`].
pub fn is_secret_key(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    SECRET_KEY_NEEDLES
        .iter()
        .any(|needle| lower.contains(needle))
}

/// The compiled content-scrubber passes, applied in order.
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
            // A `key = value` / `key: value` pair whose key *contains* a secret
            // needle — including a prefixed key (`access_token`, `refresh_token`,
            // `x-api-key`). The value runs to the next separator (`&`/`;`/`,`/
            // whitespace), so a credential in a query string or form body is
            // masked while the surrounding structure survives.
            (
                Regex::new(
                    r"(?i)([\w.\-]*(?:api[_-]?key|apikey|token|secret|password|passwd|pwd|credential|cookie)[\w.\-]*\s*[:=]\s*)[^\s&;,]+",
                )
                .unwrap(),
                "${1}[redacted]",
            ),
        ]
    })
}

/// Mask credential material embedded anywhere in `text` by *content* (not by the
/// key it is stored under): an `Authorization:` line, a `Bearer <token>`, and
/// `…token`/`…api_key`/`secret`/`password`/`cookie`/`credential` `key=value` pairs
/// in query strings, bodies, or free text. Redacted values become `[redacted]`.
///
/// Conservative by design: it over-redacts (any key *containing* a needle) rather
/// than risk letting a secret through. Residual limit: a bare credential with no
/// recognisable `key=` or `Bearer`/`Authorization` framing cannot be detected.
pub fn scrub_text(text: &str) -> String {
    let mut out = text.to_string();
    for (re, rep) in patterns() {
        out = re.replace_all(&out, *rep).into_owned();
    }
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
}
