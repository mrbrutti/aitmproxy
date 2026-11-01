//! The known-secret registry (spec Design 14.4): the set of secrets the audit
//! writer masks in every string field **by exact value**, whatever frames them
//! (a `key=`, a `Bearer` prefix, a header name) and whichever encoding they
//! arrive in. The replacement is always `[redacted]`.
//!
//! A secret is stored raw and, when different, in its JSON-escaped form (the
//! way `serde_json` writes a string body), its percent-encoded form with
//! upper-case hex and, when different again, with lower-case hex. How a stored
//! form is matched depends on the secret's length in bytes, because masking a
//! short secret as a substring would corrupt every word that holds it:
//!
//! | bytes | tier | masked |
//! |---|---|---|
//! | 8 or more | [`Registration::Substring`] | anywhere |
//! | 4 to 7 | [`Registration::WholeToken`] | only as a whole token |
//! | fewer than 4, or empty | [`Registration::Ignored`] | never by value |
//!
//! An empty secret, or one that is a substring of the mask literals, is
//! ignored as well, which is what makes masking idempotent.
//!
//! The set is a copy-on-write snapshot behind a lock. `register` builds a new
//! snapshot and swaps it; `mask` clones the current one and works on it
//! without any lock held, so a registration made while a writer thread runs
//! is seen by the next field that thread masks.
//!
//! Nothing here can carry a secret out: `Debug` prints a count, there is no
//! `Display`, the one warning names a source label and a threshold, and no
//! error or panic message is built from a value.

use std::fmt;
use std::sync::{Arc, PoisonError, RwLock};

use tracing::warn;

/// What replaces a registered secret.
const MASK: &str = "[redacted]";

/// The literals the redaction passes write. A secret that is a substring of
/// one of them is ignored: masking it would rewrite the replacement itself.
const MASK_LITERALS: [&str; 3] = ["redacted", "[redacted]", "<redacted>"];

/// Fewer bytes than this and a secret is not masked by value at all.
const WHOLE_TOKEN_MIN_BYTES: usize = 4;

/// This many bytes or more and a secret is masked as a substring anywhere.
/// The warning says `shorter than 8`: keep the two in step.
const SUBSTRING_MIN_BYTES: usize = 8;

/// The ending of a text must be at least this many bytes of a secret for
/// [`SecretRegistry::mask_trailing_fragment`] to take it for one cut in half.
const FRAGMENT_MIN_BYTES: usize = 6;

/// The marker a producer's cap puts after the text it cut: the ring's own, which
/// the writer's caps use too (see `pipeline`).
pub(super) const CUT_MARK: &str = "\u{2026}";

/// How a secret was taken in. It carries no value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Registration {
    /// 8 bytes or more: masked as a substring, anywhere.
    Substring,
    /// 4 to 7 bytes: masked only as a whole token.
    WholeToken,
    /// Fewer than 4 bytes, empty, or a substring of the mask literals: not
    /// stored, never masked by value.
    Ignored,
}

/// The known-secret registry. Shared as an `Arc`; every method takes `&self`.
///
/// `Debug` prints `SecretRegistry { secrets: N }` and nothing else, and there
/// is deliberately no `Display`.
pub struct SecretRegistry {
    snapshot: RwLock<Arc<Snapshot>>,
}

/// One immutable state of the registry. Never `Debug`: it holds the values.
#[derive(Clone, Default)]
struct Snapshot {
    /// Every distinct stored secret in its raw form (what `len` counts).
    secrets: Vec<String>,
    /// Every form of every `Substring` secret, distinct.
    substrings: Vec<String>,
    /// Every form of every `WholeToken` secret, distinct.
    whole_tokens: Vec<String>,
}

impl fmt::Debug for SecretRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretRegistry")
            .field("secrets", &self.len())
            .finish()
    }
}

impl Default for SecretRegistry {
    fn default() -> Self {
        SecretRegistry::new()
    }
}

impl SecretRegistry {
    /// An empty registry: `mask` returns every text unchanged.
    pub fn new() -> SecretRegistry {
        SecretRegistry {
            snapshot: RwLock::new(Arc::new(Snapshot::default())),
        }
    }

    /// Takes `secret` in, and says how it will be masked.
    ///
    /// `source` is a label for the place the secret came from (never a value);
    /// it is the only thing the warning for a short secret names. Registering
    /// the same secret again stores nothing more but warns again, once per
    /// registration, because each source is told separately.
    pub fn register(&self, source: &str, secret: &str) -> Registration {
        let tier = tier_of(secret);
        self.store(secret, tier);
        if (1..SUBSTRING_MIN_BYTES).contains(&secret.len()) {
            // The source label and the threshold: never the value, never its
            // length. Logged after the lock was released.
            warn!(
                target: "aitm::audit",
                source = ?source,
                "a secret registered from this source is shorter than 8 characters and is only partly covered by value masking"
            );
        }
        tier
    }

    /// `text` with every registered secret, in every stored form, replaced by
    /// `[redacted]`.
    ///
    /// Every occurrence of every form is found in `text` as it was given, and
    /// overlapping occurrences (two forms of one secret, a form inside a
    /// longer one, two secrets that overlap) become one replaced span, so the
    /// longest form wins and nothing of a shorter one is left beside it. No
    /// lock is held while this runs.
    pub fn mask(&self, text: &str) -> String {
        self.current().mask(text)
    }

    /// `text` with a registered secret that a cut left at its end masked: when
    /// `text` (ignoring one trailing `…`, the marker a producer's cap puts after
    /// a cut) ends with a prefix of 6 bytes or more of a secret of 8 bytes or
    /// more, in any stored form, that fragment becomes `[redacted]` and the
    /// marker is put back. The longest such ending wins. A whole secret is
    /// masked by [`mask`](Self::mask); this is for the part of one that a cap
    /// kept. A fragment shorter than 6 bytes is not masked: it is too common to
    /// tell from text (Design 14.4, Residual risks). No lock is held while this
    /// runs.
    pub(crate) fn mask_trailing_fragment(&self, text: &str) -> String {
        self.current().mask_trailing_fragment(text)
    }

    /// How many distinct secrets are stored (ignored ones are not).
    pub fn len(&self) -> usize {
        self.current().secrets.len()
    }

    /// Whether no secret is stored.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The snapshot in force now; the lock is released before this returns.
    fn current(&self) -> Arc<Snapshot> {
        let held = self.snapshot.read().unwrap_or_else(PoisonError::into_inner);
        Arc::clone(&held)
    }

    /// Builds the next snapshot and swaps it in. The write lock covers both
    /// steps so that two registrations cannot overwrite each other.
    fn store(&self, secret: &str, tier: Registration) {
        if tier == Registration::Ignored {
            return;
        }
        let mut held = self
            .snapshot
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        if held.secrets.iter().any(|known| known == secret) {
            return;
        }
        let next = held.with(secret, tier);
        *held = Arc::new(next);
    }
}

impl Snapshot {
    /// This snapshot plus `secret` (of the given, non-ignored tier).
    fn with(&self, secret: &str, tier: Registration) -> Snapshot {
        let mut next = self.clone();
        let forms = match tier {
            Registration::Substring => &mut next.substrings,
            Registration::WholeToken => &mut next.whole_tokens,
            Registration::Ignored => return next,
        };
        for form in forms_of(secret) {
            if !forms.contains(&form) {
                forms.push(form);
            }
        }
        next.secrets.push(secret.to_string());
        next
    }

    /// See [`SecretRegistry::mask`].
    fn mask(&self, text: &str) -> String {
        let mut spans: Vec<(usize, usize)> = Vec::new();
        for form in &self.substrings {
            collect_spans(text, form, false, &mut spans);
        }
        for form in &self.whole_tokens {
            collect_spans(text, form, true, &mut spans);
        }
        if spans.is_empty() {
            return text.to_string();
        }

        // One span for every run of overlapping occurrences. Spans that only
        // touch stay apart, as two replacements would.
        spans.sort_unstable();
        let mut merged: Vec<(usize, usize)> = Vec::with_capacity(spans.len());
        for (start, end) in spans {
            match merged.last_mut() {
                Some(last) if start < last.1 => last.1 = last.1.max(end),
                _ => merged.push((start, end)),
            }
        }

        let mut out = String::with_capacity(text.len());
        let mut copied = 0;
        for (start, end) in merged {
            // Every span edge is a character boundary of `text` (a match of
            // valid UTF-8); a failed `get` would drop text, never keep it.
            out.push_str(text.get(copied..start).unwrap_or_default());
            out.push_str(MASK);
            copied = end;
        }
        out.push_str(text.get(copied..).unwrap_or_default());
        out
    }

    /// See [`SecretRegistry::mask_trailing_fragment`].
    fn mask_trailing_fragment(&self, text: &str) -> String {
        let (body, marker) = match text.strip_suffix(CUT_MARK) {
            Some(body) => (body, CUT_MARK),
            None => (text, ""),
        };
        let Some(start) = self.fragment_start(body) else {
            return text.to_string();
        };
        let mut out = String::with_capacity(start + MASK.len() + marker.len());
        // `start` is a character boundary of `body`; a failed `get` would drop
        // text, never keep it.
        out.push_str(body.get(..start).unwrap_or_default());
        out.push_str(MASK);
        out.push_str(marker);
        out
    }

    /// Where the longest ending of `body` that is a prefix of a stored form
    /// begins, when that ending is [`FRAGMENT_MIN_BYTES`] bytes or more. Only
    /// the forms of `Substring` secrets are looked at: a `WholeToken` secret is
    /// shorter than 8 bytes. The scan is bounded by the length of `body` and of
    /// the longest form, and tries the earliest start first, so the first match
    /// is the longest ending.
    fn fragment_start(&self, body: &str) -> Option<usize> {
        let longest = self.substrings.iter().map(String::len).max()?;
        let earliest = body.len().saturating_sub(longest);
        let latest = body.len().checked_sub(FRAGMENT_MIN_BYTES)?;
        (earliest..=latest)
            .filter(|at| body.is_char_boundary(*at))
            .find(|at| {
                let ending = body.get(*at..).unwrap_or_default();
                self.substrings.iter().any(|form| form.starts_with(ending))
            })
    }
}

/// The tier a secret falls in, by its length in bytes.
fn tier_of(secret: &str) -> Registration {
    if secret.len() < WHOLE_TOKEN_MIN_BYTES
        || MASK_LITERALS.iter().any(|literal| literal.contains(secret))
    {
        Registration::Ignored
    } else if secret.len() < SUBSTRING_MIN_BYTES {
        Registration::WholeToken
    } else {
        Registration::Substring
    }
}

/// The forms a secret is looked for in: raw, JSON-escaped, percent-encoded in
/// upper-case hex and in lower-case hex, each kept once.
fn forms_of(secret: &str) -> Vec<String> {
    let mut forms = vec![secret.to_string()];
    let candidates = [
        json_body(secret),
        Some(percent_encode(secret, HEX_UPPER)),
        Some(percent_encode(secret, HEX_LOWER)),
    ];
    for form in candidates.into_iter().flatten() {
        if !forms.contains(&form) {
            forms.push(form);
        }
    }
    forms
}

/// `secret` as `serde_json` writes the inside of a string: quotes, backslashes
/// and control characters escaped, everything else as is.
fn json_body(secret: &str) -> Option<String> {
    let quoted = serde_json::to_string(secret).ok()?;
    let body = quoted.strip_prefix('"')?.strip_suffix('"')?;
    Some(body.to_string())
}

const HEX_UPPER: &[u8; 16] = b"0123456789ABCDEF";
const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";

/// Percent encoding: ASCII letters, digits, `-`, `.`, `_` and `~` are kept,
/// every other byte (each byte of a multi-byte character) becomes `%XX`.
fn percent_encode(text: &str, digits: &[u8; 16]) -> String {
    let mut out = String::with_capacity(text.len());
    for &byte in text.as_bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(byte));
        } else {
            out.push('%');
            out.push(char::from(digits[usize::from(byte >> 4)]));
            out.push(char::from(digits[usize::from(byte & 0x0f)]));
        }
    }
    out
}

/// Appends the byte span of every occurrence of `form` in `text`, overlapping
/// ones included. With `whole_token` set, an occurrence counts only when it is
/// a whole token (see [`is_whole_token`]).
fn collect_spans(text: &str, form: &str, whole_token: bool, spans: &mut Vec<(usize, usize)>) {
    if form.is_empty() {
        return;
    }
    let mut from = 0;
    while let Some(rest) = text.get(from..) {
        let Some(found) = rest.find(form) else { break };
        let start = from + found;
        let end = start + form.len();
        if !whole_token || is_whole_token(text, start, end) {
            spans.push((start, end));
        }
        // One character past the start, so that an occurrence overlapping this
        // one is found too.
        let step = rest
            .get(found..)
            .and_then(|tail| tail.chars().next())
            .map_or(1, char::len_utf8);
        from = start + step;
    }
}

/// Whether the text at `start..end` is bounded on both sides by a character
/// that is not an ASCII alphanumeric, `_`, `-` or `.`, or by the edge of the
/// field.
fn is_whole_token(text: &str, start: usize, end: usize) -> bool {
    let before = text.get(..start).and_then(|head| head.chars().next_back());
    let after = text.get(end..).and_then(|tail| tail.chars().next());
    !before.is_some_and(is_token_char) && !after.is_some_and(is_token_char)
}

/// A character that continues a token.
fn is_token_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.')
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io;
    use std::sync::{Arc, Mutex, PoisonError};
    use std::thread;

    use serde_json::Value;

    /// What a test subscriber wrote, shared with the test.
    #[derive(Clone, Default)]
    struct LogCapture(Arc<Mutex<Vec<u8>>>);

    impl LogCapture {
        fn text(&self) -> String {
            let bytes = self.0.lock().unwrap_or_else(PoisonError::into_inner);
            String::from_utf8_lossy(&bytes).into_owned()
        }
    }

    impl io::Write for LogCapture {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            let mut held = self.0.lock().unwrap_or_else(PoisonError::into_inner);
            held.extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// Runs `run` under a subscriber that captures everything it logs.
    fn logged<T>(run: impl FnOnce() -> T) -> (T, String) {
        let capture = LogCapture::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer({
                let capture = capture.clone();
                move || capture.clone()
            })
            .with_ansi(false)
            .without_time()
            .finish();
        let out = tracing::subscriber::with_default(subscriber, run);
        (out, capture.text())
    }

    /// Registers each `(source, secret)` pair under a capturing subscriber and
    /// returns what it logged.
    ///
    /// `tracing` caches per callsite whether anyone wants it, and a callsite
    /// reached for the first time in the process just as another test thread
    /// installs its own subscriber can be cached as "no one". Installing a
    /// subscriber rebuilds that cache, so one more attempt sees the event. An
    /// attempt that logged nothing at the warning level is that race (the
    /// callers below all expect at least one warning); anything else is judged.
    fn register_logged(
        registry: &SecretRegistry,
        pairs: &[(&str, &str)],
    ) -> (Vec<Registration>, String) {
        let register_all = || {
            pairs
                .iter()
                .map(|(source, secret)| registry.register(source, secret))
                .collect::<Vec<_>>()
        };
        let mut attempt = logged(register_all);
        for _ in 0..4 {
            if attempt.1.contains("WARN") {
                break;
            }
            attempt = logged(register_all);
        }
        attempt
    }

    /// The rows whose masked text is not the wanted text, one message each, so
    /// that a failing run lists every wrong row at once.
    fn failing_rows(registry: &SecretRegistry, rows: &[(&str, &str, &str)]) -> Vec<String> {
        rows.iter()
            .filter_map(|(name, text, want)| {
                let got = registry.mask(text);
                (got != *want).then(|| format!("{name}: {text:?} gave {got:?}, wanted {want:?}"))
            })
            .collect()
    }

    /// The registration of one secret under a fresh registry, no log wanted.
    fn tier_of_alone(secret: &str) -> Registration {
        SecretRegistry::new().register("test.tier", secret)
    }

    /// Exactly one warning, naming the source and the threshold, and nothing
    /// of the value or of its length: with the threshold's own digit set
    /// aside, the log holds no digit at all.
    fn assert_one_clean_warning(log: &str, source: &str, secret: &str) {
        let warnings: Vec<&str> = log.lines().filter(|l| l.contains("WARN")).collect();
        assert_eq!(
            warnings.len(),
            1,
            "one warning per short registration: {log}"
        );
        assert!(log.contains("aitm::audit"), "the audit target: {log}");
        assert!(log.contains(source), "the source label: {log}");
        assert!(log.contains("shorter than 8"), "the threshold: {log}");
        assert!(
            !log.contains(secret),
            "the value must never be logged: {log}"
        );
        let without_threshold = log.replace("shorter than 8", "");
        assert!(
            !without_threshold.chars().any(|c| c.is_ascii_digit()),
            "the length must never be logged: {log}"
        );
    }

    /// AC48: the three tiers, their boundary rule, and the ignored secrets.
    #[test]
    fn registry_tiers() {
        // Eight bytes or more: masked anywhere.
        let registry = SecretRegistry::new();
        assert_eq!(
            registry.register("mcp.operator_token", "ABCD1234EFGH"),
            Registration::Substring
        );
        assert_eq!(registry.mask("x ABCD1234EFGH y"), "x [redacted] y");
        assert_eq!(
            registry.mask("prefixABCD1234EFGHsuffix"),
            "prefix[redacted]suffix"
        );

        // Four to seven bytes: masked only as a whole token.
        let registry = SecretRegistry::new();
        let (registrations, log) = register_logged(&registry, &[("mcp.operator_token", "wxyz")]);
        assert_eq!(registrations, [Registration::WholeToken]);
        assert_one_clean_warning(&log, "mcp.operator_token", "wxyz");
        let failures = failing_rows(
            &registry,
            &[
                ("spaces", "a wxyz b", "a [redacted] b"),
                ("parentheses", "(wxyz)", "([redacted])"),
                ("letters around", "awxyzb", "awxyzb"),
                ("hyphen before", "a-wxyz", "a-wxyz"),
            ],
        );
        assert!(failures.is_empty(), "{}", failures.join("\n"));

        // Fewer than four bytes: never literal-masked.
        let registry = SecretRegistry::new();
        let (registrations, log) = register_logged(&registry, &[("mcp.agent_token", "abc")]);
        assert_eq!(registrations, [Registration::Ignored]);
        assert_one_clean_warning(&log, "mcp.agent_token", "abc");
        assert_eq!(registry.mask("abc abcd"), "abc abcd");
        assert_eq!(registry.len(), 0, "an ignored secret is not stored");

        // A secret that is a substring of the mask literals is ignored, so
        // masking can run twice over the same text.
        let registry = SecretRegistry::new();
        assert_eq!(
            registry.register("test.literal", "redacted"),
            Registration::Ignored
        );
        assert_eq!(registry.mask("[redacted]"), "[redacted]");
    }

    /// The tier follows the byte length, at both boundaries and for text that
    /// is wider than its character count.
    #[test]
    fn registry_tier_follows_the_byte_length() {
        let rows = [
            ("", Registration::Ignored),
            ("123", Registration::Ignored),
            ("1234", Registration::WholeToken),
            ("1234567", Registration::WholeToken),
            ("12345678", Registration::Substring),
            // Two bytes each: 2, 4, 6 and 8 bytes from 1 to 4 characters.
            ("\u{e9}", Registration::Ignored),
            ("\u{e9}\u{e9}", Registration::WholeToken),
            ("\u{e9}\u{e9}\u{e9}", Registration::WholeToken),
            ("\u{e9}\u{e9}\u{e9}\u{e9}", Registration::Substring),
        ];
        let wrong: Vec<String> = rows
            .iter()
            .filter(|(secret, want)| tier_of_alone(secret) != *want)
            .map(|(secret, want)| format!("{} bytes: wanted {want:?}", secret.len()))
            .collect();
        assert!(wrong.is_empty(), "{}", wrong.join("\n"));
    }

    /// A whole token ends at any character that is not an ASCII alphanumeric,
    /// `_`, `-` or `.`, or at the edge of the field.
    #[test]
    fn registry_whole_token_bounds() {
        let registry = SecretRegistry::new();
        assert_eq!(
            registry.register("test.short", "wxyz"),
            Registration::WholeToken
        );
        let rows = [
            ("the whole field", "wxyz", "[redacted]"),
            ("an equals and an ampersand", "k=wxyz&m", "k=[redacted]&m"),
            ("two tokens", "wxyz,wxyz", "[redacted],[redacted]"),
            ("a quote", "\"wxyz\"", "\"[redacted]\""),
            (
                "a non-ASCII letter before",
                "\u{e9}wxyz",
                "\u{e9}[redacted]",
            ),
            ("a letter pair", "wxyzwxyz", "wxyzwxyz"),
            ("an underscore before", "_wxyz", "_wxyz"),
            ("an underscore after", "wxyz_", "wxyz_"),
            ("a hyphen after", "wxyz-", "wxyz-"),
            ("a dot before", ".wxyz", ".wxyz"),
            ("a dot after", "wxyz.", "wxyz."),
            ("a digit before", "1wxyz", "1wxyz"),
            ("a digit after", "wxyz9", "wxyz9"),
            ("another case", "WXYZ", "WXYZ"),
            ("a longer word", "wxyzs", "wxyzs"),
        ];
        let failures = failing_rows(&registry, &rows);
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }

    /// AC49: raw, JSON-escaped, percent-encoded in both cases, in a URL and
    /// inside JSON text that must still parse.
    #[test]
    fn registry_masks_every_encoding() {
        let plus = "Zm9v+YmFy/Ymf=ZZ99";
        let quoted = "ab\"cd\\ef12345";
        let registry = SecretRegistry::new();
        assert_eq!(
            registry.register("test.plus", plus),
            Registration::Substring
        );
        assert_eq!(
            registry.register("test.quoted", quoted),
            Registration::Substring
        );

        let rows = [
            ("plus raw", plus, "[redacted]"),
            (
                "plus percent upper",
                "Zm9v%2BYmFy%2FYmf%3DZZ99",
                "[redacted]",
            ),
            (
                "plus percent lower",
                "Zm9v%2bYmFy%2fYmf%3dZZ99",
                "[redacted]",
            ),
            ("quoted raw", quoted, "[redacted]"),
            ("quoted json", "ab\\\"cd\\\\ef12345", "[redacted]"),
            ("quoted percent upper", "ab%22cd%5Cef12345", "[redacted]"),
            ("quoted percent lower", "ab%22cd%5cef12345", "[redacted]"),
            (
                "a url fragment",
                "http://127.0.0.1:8082/#t=Zm9v+YmFy/Ymf=ZZ99",
                "http://127.0.0.1:8082/#t=[redacted]",
            ),
            (
                "a percent form in a query",
                "x?next=Zm9v%2BYmFy%2FYmf%3DZZ99&y=1",
                "x?next=[redacted]&y=1",
            ),
        ];
        let failures = failing_rows(&registry, &rows);
        assert!(failures.is_empty(), "{}", failures.join("\n"));

        // JSON text: the replacement sits inside the string literal, so the
        // text still parses and reads as the source wrote it, masked.
        for (text, want) in [
            (
                r#"{"u":"x?next=Zm9v%2BYmFy%2FYmf%3DZZ99"}"#,
                r#"{"u":"x?next=[redacted]"}"#,
            ),
            (r#"{"a":"ab\"cd\\ef12345"}"#, r#"{"a":"[redacted]"}"#),
        ] {
            let masked = registry.mask(text);
            assert_eq!(masked, want);
            let parsed: Result<Value, _> = serde_json::from_str(&masked);
            assert!(parsed.is_ok(), "the masked text must parse: {masked}");
        }
    }

    /// Percent encoding keeps ASCII letters, digits, `-`, `.`, `_` and `~`,
    /// writes every other byte (each byte of a multi-byte character) as `%XX`,
    /// and the lower-case hex form is masked as well.
    #[test]
    fn registry_percent_forms_keep_only_the_unreserved_set() {
        let secret = "Ab-._~ 09\u{e9}+";
        let registry = SecretRegistry::new();
        assert_eq!(
            registry.register("test.unreserved", secret),
            Registration::Substring
        );
        let rows = [
            ("raw", secret, "[redacted]"),
            ("upper", "Ab-._~%2009%C3%A9%2B", "[redacted]"),
            ("lower", "Ab-._~%2009%c3%a9%2b", "[redacted]"),
        ];
        let failures = failing_rows(&registry, &rows);
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }

    /// Two forms that overlap, or two secrets that do, are one span: the
    /// longest form wins and nothing of a shorter one is left beside it. A
    /// raw form that stopped short of its JSON form would leave a lone
    /// backslash and break the text.
    #[test]
    fn registry_masks_overlapping_forms_as_one_span() {
        let registry = SecretRegistry::new();
        assert_eq!(
            registry.register("test.slash", "abcdefgh\\"),
            Registration::Substring
        );
        let json = r#"{"k":"abcdefgh\\"}"#;
        let masked = registry.mask(json);
        assert_eq!(masked, r#"{"k":"[redacted]"}"#);
        let parsed: Result<Value, _> = serde_json::from_str(&masked);
        assert!(parsed.is_ok(), "the masked text must parse: {masked}");

        let registry = SecretRegistry::new();
        registry.register("test.one", "ABCDEFGH");
        registry.register("test.two", "EFGHIJKL");
        registry.register("test.long", "CDEFGHIJ");
        assert_eq!(registry.mask("xABCDEFGHIJKLy"), "x[redacted]y");
        assert_eq!(registry.mask("ABCDEFGH EFGHIJKL"), "[redacted] [redacted]");
    }

    /// A registration is seen by the next mask, and a registry with nothing in
    /// it changes nothing.
    #[test]
    fn registry_sees_a_registration_made_after_a_mask() {
        let registry = SecretRegistry::new();
        assert!(registry.is_empty());
        let text = "a LATE50TOKENVALUE b [redacted] <redacted>";
        assert_eq!(registry.mask(text), text);
        assert_eq!(
            registry.register("test.late", "LATE50TOKENVALUE"),
            Registration::Substring
        );
        assert_eq!(registry.mask(text), "a [redacted] b [redacted] <redacted>");
        assert!(!registry.is_empty());
    }

    /// Registrations from several threads are all kept while others mask.
    #[test]
    fn registry_keeps_every_concurrent_registration() {
        let registry = SecretRegistry::new();
        let secrets: Vec<String> = (0..16u32)
            .map(|i| format!("CNRYconc{i:02}x{:08x}", i * 7919 + 1))
            .collect();
        thread::scope(|scope| {
            for secret in &secrets {
                let registry = &registry;
                scope.spawn(move || {
                    registry.register("test.concurrent", secret);
                });
            }
            for _ in 0..4 {
                let registry = &registry;
                scope.spawn(move || {
                    for _ in 0..200 {
                        let _ = registry.mask("noise CNRYconc03x00001f0f noise");
                    }
                });
            }
        });
        assert_eq!(registry.len(), 16);
        let failures: Vec<String> = secrets
            .iter()
            .filter(|secret| registry.mask(&format!("a {secret} b")) != "a [redacted] b")
            .map(|_| "a registered secret was not masked".to_string())
            .collect();
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }

    /// Warnings: one per registration of a secret of 1 to 7 bytes, none for an
    /// empty one or for one of 8 or more, whatever it is.
    #[test]
    fn registry_warns_only_for_secrets_shorter_than_eight() {
        let registry = SecretRegistry::new();
        let (_, log) = register_logged(
            &registry,
            &[
                ("test.long", "ABCD1234EFGH"),
                ("test.empty", ""),
                ("test.literal", "redacted"),
                ("test.tiny", "qzx"),
            ],
        );
        assert_one_clean_warning(&log, "test.tiny", "qzx");
        assert!(!log.contains("test.long"), "{log}");
        assert!(!log.contains("test.empty"), "{log}");
        assert!(!log.contains("test.literal"), "{log}");
    }

    /// Registering the same secret twice stores it once and keeps its tier.
    #[test]
    fn registry_counts_each_secret_once() {
        let registry = SecretRegistry::new();
        assert_eq!(
            registry.register("test.first", "ABCD1234EFGH"),
            Registration::Substring
        );
        assert_eq!(
            registry.register("test.second", "ABCD1234EFGH"),
            Registration::Substring
        );
        assert_eq!(registry.len(), 1);
    }

    /// `Debug` prints a count and nothing else.
    #[test]
    fn registry_debug_prints_only_a_count() {
        let registry = SecretRegistry::new();
        assert_eq!(format!("{registry:?}"), "SecretRegistry { secrets: 0 }");
        registry.register("test.one", "CNRYdbg1x00000001");
        registry.register("test.two", "CNRYdbg2x00000002");
        registry.register("test.ignored", "redacted");
        assert_eq!(format!("{registry:?}"), "SecretRegistry { secrets: 2 }");
        assert_eq!(format!("{registry:#?}").matches("CNRY").count(), 0);
        assert_eq!(format!("{:?}", Registration::Substring), "Substring");
        assert_eq!(format!("{:?}", Registration::WholeToken), "WholeToken");
        assert_eq!(format!("{:?}", Registration::Ignored), "Ignored");
    }

    /// The rows whose trailing-fragment mask is not the wanted text.
    fn failing_fragment_rows(
        registry: &SecretRegistry,
        rows: &[(&str, &str, &str)],
    ) -> Vec<String> {
        rows.iter()
            .filter_map(|(name, text, want)| {
                let got = registry.mask_trailing_fragment(text);
                (got != *want).then(|| format!("{name}: {text:?} gave {got:?}, wanted {want:?}"))
            })
            .collect()
    }

    /// Design 14.4, cut secrets: a text that ends with a prefix of 6 bytes or
    /// more of a registered secret loses that fragment, the producer's `…`
    /// marker is set aside and put back, and the longest fragment wins.
    #[test]
    fn a_trailing_fragment_of_a_registered_secret_is_masked() {
        let registry = SecretRegistry::new();
        registry.register("test.cut", "CUT12SECRETVALUE0123456789");
        registry.register("test.overlap", "ABABABABCD");
        let failures = failing_fragment_rows(
            &registry,
            &[
                ("ten bytes", "see CUT12SECRE", "see [redacted]"),
                (
                    "ten bytes and the marker",
                    "see CUT12SECRE…",
                    "see [redacted]…",
                ),
                ("exactly six bytes", "x CUT12S", "x [redacted]"),
                ("five bytes stay", "x CUT12", "x CUT12"),
                ("the whole text is the fragment", "CUT12SECRE", "[redacted]"),
                (
                    "the whole secret at the end",
                    "x CUT12SECRETVALUE0123456789",
                    "x [redacted]",
                ),
                (
                    "not at the end",
                    "CUT12SECRE and more",
                    "CUT12SECRE and more",
                ),
                (
                    "one marker is set aside, not two",
                    "x CUT12SECRE……",
                    "x CUT12SECRE……",
                ),
                (
                    "a two-byte character before the fragment",
                    "é CUT12SECRE",
                    "é [redacted]",
                ),
                ("shorter than six", "CUT1", "CUT1"),
                ("empty", "", ""),
                ("only the marker", "…", "…"),
                ("no fragment, a marker", "plain text…", "plain text…"),
                // `ABABAB` and `ABABABAB` both end the text and both start the
                // secret: the longer one is masked, not the shorter.
                ("the longest fragment wins", "xABABABABAB", "xAB[redacted]"),
            ],
        );
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }

    /// Every stored form of a secret is a form a cut can leave: the raw one, the
    /// JSON-escaped one and the percent-encoded ones in both cases of hex.
    #[test]
    fn a_trailing_fragment_is_found_in_every_stored_form() {
        let registry = SecretRegistry::new();
        registry.register("test.base64", "Zm9v+YmFy/Ymf=ZZ99");
        registry.register("test.json", "ab\"cd\\ef12345");
        registry.register("test.utf8", "héllo-wörld-12345");
        let failures = failing_fragment_rows(
            &registry,
            &[
                ("raw", "next=Zm9v+YmFy/Y", "next=[redacted]"),
                (
                    "percent, upper-case hex",
                    "u?next=Zm9v%2BYmFy%2",
                    "u?next=[redacted]",
                ),
                (
                    "percent, lower-case hex",
                    "u?next=Zm9v%2bYmFy%2f",
                    "u?next=[redacted]",
                ),
                ("JSON-escaped", r#"x ab\"cd\\ef1"#, "x [redacted]"),
                ("raw with the quote", "x ab\"cd\\ef1", "x [redacted]"),
                ("multi-byte, raw", "x héllo-w", "x [redacted]"),
                (
                    "multi-byte, percent",
                    "x h%C3%A9llo-w%C3%B6",
                    "x [redacted]",
                ),
            ],
        );
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }

    /// Only a secret of 8 bytes or more is cut-masked: a short secret is masked
    /// as a whole token and a fragment of it is not a secret. An empty registry
    /// changes nothing.
    #[test]
    fn only_a_secret_of_eight_bytes_or_more_is_cut_masked() {
        let registry = SecretRegistry::new();
        // A long secret too, so that the scan runs and a short one could be taken.
        registry.register("test.long", "CUT12SECRETVALUE0123456789");
        registry.register("test.short", "abcdefg");
        registry.register("test.tiny", "qzx");
        let failures = failing_fragment_rows(
            &registry,
            &[
                ("a fragment of a 7-byte secret", "x abcdef", "x abcdef"),
                ("a fragment of an ignored one", "x qzx", "x qzx"),
            ],
        );
        assert!(failures.is_empty(), "{}", failures.join("\n"));

        let empty = SecretRegistry::new();
        let failures = failing_fragment_rows(
            &empty,
            &[("an empty registry", "see CUT12SECRE…", "see CUT12SECRE…")],
        );
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }
}
