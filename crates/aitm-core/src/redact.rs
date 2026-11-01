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
//! There is one list of secret words, read two ways. The standard reading is
//! [`is_secret_key`] and [`scrub_text`]: the short words match only as a whole
//! segment of a key. The wide reading is [`is_secret_key_wide`] and
//! [`scrub_text_wide`]: the same short words also match as substrings (`author`,
//! `sidebar`), for decisions where a false positive costs nothing and a miss
//! leaks.
//!
//! [`scrub_text_wide`] is two scans of one private pair scanner, over the output
//! of the regex passes. The first judges a key run by the standard reading,
//! except a run that begins inside a value it has just masked, which it judges by
//! the wide one; the second judges every key run by the wide reading. So it masks
//! everything [`scrub_text`] masks on well-formed input, and then more. A scan
//! judges each key *run* by the predicate of its reading; a string that the
//! predicate accepts can be several runs (`user[sid]` is two), so a scrubber and
//! its predicate can differ on text that is not one run. The two scans share every
//! blank rule, value rule and quote rule: every whitespace character is a blank
//! beside a separator, a line break included, so `sid:\nabc` takes `abc` in both.
//! They differ in the key test, in the host:port exemption (the second scan has
//! none), and in the key test inside a masked value.
//!
//! A secret pair that begins inside a value a scan has just masked is read too:
//! `auth:\n  password: hunter2` masks `hunter2`, not only the `password:` that is
//! the value of `auth:`.

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
/// `inside`, `side`, and `sessions` do not). Matched case-insensitively. The same
/// words are what [`is_secret_key_wide`] matches as substrings, so one list serves
/// both readings and a word added here widens both.
const SECRET_KEY_SEGMENTS: &[&str] = &["sid", "jwt", "csrf", "session", "auth"];

/// Whether an argument key names a secret whose value must never be recorded:
/// true when the ASCII-lowercased key contains any `SECRET_KEY_NEEDLES` entry, or
/// when any whole segment of it equals a `SECRET_KEY_SEGMENTS` entry.
pub fn is_secret_key(key: &str) -> bool {
    is_secret_lower(&key.to_ascii_lowercase())
}

/// The wide reading of the key vocabulary: true when [`is_secret_key`] is, or when
/// the ASCII-lowercased key contains any `SECRET_KEY_SEGMENTS` word as a
/// substring, whole segment or not (`author`, `authority`, `sidebar`,
/// `subsidiary`, `inside`, `sessions`, and `userSession` all read as secret).
/// `is_secret_key(k)` implies `is_secret_key_wide(k)`.
///
/// For decisions where a false positive costs nothing and a miss leaks: a PoC
/// meant to be shared, an example value shown beside a parameter name. Never use
/// it for MCP argument keys, audit summaries, or text a human reads, because
/// `authority` is a real argument key.
pub fn is_secret_key_wide(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    is_secret_lower(&lower) || contains_segment_word(&lower)
}

/// [`is_secret_key`] on a key that is already ASCII-lowercased.
fn is_secret_lower(lower: &str) -> bool {
    SECRET_KEY_NEEDLES
        .iter()
        .any(|needle| lower.contains(needle))
        || lower
            .split(|c: char| !c.is_ascii_alphanumeric())
            .any(|segment| SECRET_KEY_SEGMENTS.contains(&segment))
}

/// Whether an already ASCII-lowercased key contains any `SECRET_KEY_SEGMENTS` word
/// as a substring, whole segment or not.
fn contains_segment_word(lower: &str) -> bool {
    SECRET_KEY_SEGMENTS.iter().any(|word| lower.contains(word))
}

/// The compiled regex passes that [`apply_patterns`] runs, in order, for
/// [`scrub_text`] and [`scrub_text_wide`] alike. The `key=value` pair pass is
/// [`mask_secret_pairs`], not a regex, because it must judge each key by the
/// predicate of the reading it runs under ([`is_secret_key`] or
/// [`is_secret_key_wide`]) and handle quoted values.
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

/// Run the regex passes of [`patterns`] over `text`, in order. Both scrubs start
/// here, before their pair scan.
fn apply_patterns(text: &str) -> String {
    let mut out = text.to_string();
    for (re, rep) in patterns() {
        out = re.replace_all(&out, *rep).into_owned();
    }
    out
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
/// A secret pair that begins inside a value just masked is read too: in
/// `auth:\n  password: hunter2` the value of `auth:` is the token `password:`, and
/// the pair `password: hunter2` inside it masks `hunter2`, so the output is
/// `auth:\n  [redacted] [redacted]`. What the nested pair does not read stays as it
/// was. A nested key that is not secret keeps its value (`auth:\n  user: bob` keeps
/// `bob`). A value that looks like a pair stays masked whole
/// (`token:\n  AApwdBB==` masks all of `AApwdBB==`), because a pair whose value
/// would start inside the masked text, its closing quote included, is left alone.
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
///
/// For the over-matching reading, which also masks keys that merely contain a
/// short secret word (`author`, `sidebar`), see [`scrub_text_wide`].
pub fn scrub_text(text: &str) -> String {
    mask_secret_pairs(&apply_patterns(text), Reading::Standard)
}

/// [`scrub_text`] with a wider key test. It masks everything [`scrub_text`] masks on
/// well-formed input, and then every pair whose key reads as secret under
/// [`is_secret_key_wide`], so it also masks keys that merely contain a short secret
/// word (`author`, `sidebar`).
///
/// After the regex passes of [`scrub_text`] it runs two scans of one private pair
/// scanner. The first judges a key run by [`is_secret_key`], except a run that
/// begins inside a value it has just masked, which it judges by
/// [`is_secret_key_wide`]; the second judges every key run by
/// [`is_secret_key_wide`]. The wide test inside a masked value is what masks the
/// value of a wide-only key nested under a standard-secret pair
/// (`Credentials:\n\tjwt:\n\tsidebar :  "Q"` masks `Q`): judged by the standard test,
/// that key would be the masked value of the `jwt:` above it and the second scan
/// could no longer see it.
///
/// The two scans share every blank rule, value rule and quote rule, so a line break
/// beside a separator is skipped like any other whitespace and the wide scan reads
/// across it. A credential on the line after a wide-only key is masked
/// (`userSession:\n  S3SS10N9`, `sidebar:\nS3SS10N9`), and so is the first word of
/// prose there (`author:\nJohn` becomes `author:\n[redacted]`). A secret pair that
/// begins inside a masked value is read, whatever the key above it
/// (`authentication:\n  password: hunter2` becomes
/// `authentication:\n  [redacted] [redacted]`). The scans differ in the key test and
/// in the host:port exemption: the second scan exempts nothing, so
/// `auth.example.com:8443` and `token.example.com:8443` are masked.
///
/// It over-redacts by design: use it where a masked innocent value costs nothing
/// and a missed credential leaks (a PoC meant to be shared), never on text that
/// goes to an agent, an audit record, or a finding, where `authority=` and
/// `author=3` are ordinary. Its running time is linear: each doubling of the input
/// costs at most 3.0 times the time, measured out of tree at 1 to 8 MiB.
///
/// A residual, on malformed quotes: a quote that is unmatched, unescaped, or shaped
/// like an opener (after `=` or `:`, with a value character behind it) can make a
/// scan pair the quotes inside a masked value differently from the way it pairs
/// them outside one, and so leave a quoted value in the clear in a rare malformed
/// input. A well-formed JSON body, form or query has no such quote.
pub fn scrub_text_wide(text: &str) -> String {
    mask_secret_pairs(
        &mask_secret_pairs(&apply_patterns(text), Reading::FirstOfWide),
        Reading::Wide,
    )
}

/// Which reading of the vocabulary a scan applies. See [`mask_secret_pairs`]. The
/// three variants differ in the key test and the host:port exemption only; all
/// three skip every whitespace character beside a separator, a line break
/// included, and share every value rule and quote rule.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Reading {
    /// [`is_secret_key`] for every key run, and a host:port is exempt. The one scan
    /// of [`scrub_text`].
    Standard,
    /// [`is_secret_key_wide`] for every key run, and nothing is exempt. The second
    /// scan of [`scrub_text_wide`].
    Wide,
    /// [`is_secret_key_wide`] for a key run that begins inside a value the scan has
    /// just masked, [`is_secret_key`] for every other key run, and a host:port is
    /// exempt as for `Standard`. The first scan of [`scrub_text_wide`].
    FirstOfWide,
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
/// run is secret under `reading` with `[redacted]`.
///
/// `reading` is consulted in exactly two places: the secret test of a key run, and
/// the host:port exemption. The secret test is [`is_secret_key`] for
/// [`Reading::Standard`] and [`is_secret_key_wide`] for [`Reading::Wide`]; for
/// [`Reading::FirstOfWide`] it is [`is_secret_key_wide`] when the key run begins
/// inside the text this scan has already masked, and [`is_secret_key`] elsewhere.
/// The exemption is applied for `Standard` and `FirstOfWide`, never for `Wide`. It
/// is read nowhere that decides where a key run, a blank, a separator, a value, or a
/// closing quote starts or ends, so a pair that two readings both call secret is
/// scanned identically by them, host:port aside.
///
/// One linear scan. A key run is followed by an optional closing quote, blanks
/// (every whitespace character, a line break included, so a value on the next line
/// is still masked), `=` or `:`, blanks, an optional opening quote, and the value
/// (see [`scrub_text`] for the value rule). After any key run that is not a masked
/// pair the scan resumes right after the run, not after the value, so a pair nested
/// in a non-secret value is still seen. After a masked pair it resumes at the
/// value's start, not its end, so a secret pair that begins inside the masked value
/// is read too: such a pair is called nested.
///
/// Two guards keep a nested pair from reading text that is already masked, and so
/// from reading it twice. The exact guard: after the blanks that follow the
/// separator, a pair whose value would start before the first index the masked text
/// does not cover (its closing quote included) is left alone, as a pair with a
/// non-secret key is, with no value and no closing-quote search. Without it
/// `token="sid:" tail="x"` would read the closing quote of the masked value as the
/// opener of a value for the nested `sid:`, and swallow ` tail="x`. The early guard:
/// a pair whose separator ends inside the masked text is skipped right after the
/// separator is found, before the vocabulary is consulted. The exact guard implies
/// it, so it changes no output; it only keeps a long masked value full of nested
/// keys from costing one lowercase allocation for each.
///
/// The work is linear. The scan index strictly increases: after a masked pair it is
/// the value's start, which is past the pair's key end. So key starts strictly
/// increase too, and a pair reaches a closing-quote search only when its value
/// starts at or after the end of the masked text, which is at or after `copied`.
/// Searches therefore start at strictly increasing positions, and successful ones
/// never overlap: each starts after the previous masked text. A failed search for a
/// quote character reads to the end of the text once, and is remembered: a later
/// search for the same character starts further on and so considers a subset of the
/// candidates, and a candidate is judged on its neighbouring characters alone, so it
/// would fail too and is not run. [`is_opening_quote`] must therefore stay a pure
/// function of the text around the quote. A byte is read once to find the end of a
/// value and once more when the scan walks the masked value; masked values are
/// disjoint and increasing, so a byte lies in at most one. Blank runs are read by
/// the lookahead after a key run and by the loop's own steps. The slice
/// `text[copied..value_start]` needs `value_start >= copied`, which the exact guard
/// gives. The vocabulary is consulted only for a key run whose separator follows it
/// and does not end inside the masked text, so no allocation is spent on the rest
/// of the text.
fn mask_secret_pairs(text: &str, reading: Reading) -> String {
    let bytes = text.as_bytes();
    let len = bytes.len();
    let mut out = String::with_capacity(len);
    // Start of the text not yet copied into `out`.
    let mut copied = 0;
    // The first index the masked text does not cover: the end of the last masked
    // value, and one more when its closing quote is part of the masked text.
    let mut masked_to = 0;
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
        // A pair whose separator ends inside the masked text: the guard after the
        // blank skip below would leave it alone as well. This one is the cheap
        // form of it, taken before the vocabulary costs an allocation for each
        // key of a long masked value. It changes no output.
        if j < copied {
            continue;
        }

        // The scan only ever stops on char boundaries and `run_end` steps whole
        // chars, so `key_start..key_end` is on char boundaries.
        let key = &text[key_start..key_end];
        let secret = match reading {
            Reading::Standard => is_secret_key(key),
            Reading::Wide => is_secret_key_wide(key),
            Reading::FirstOfWide => {
                if key_start < copied {
                    is_secret_key_wide(key)
                } else {
                    is_secret_key(key)
                }
            }
        };
        if !secret {
            continue;
        }
        if reading != Reading::Wide
            && separator == b':'
            && is_host_port(key.as_bytes(), &bytes[key_end..])
        {
            continue;
        }

        // Whitespace, an optional opening quote, then the value.
        j = skip_blanks(text, j);
        // A value that would start inside the masked text is no value: it is part
        // of the parent's own value, or its closing quote. Leave the pair alone, as
        // for a key that is not secret, so no closing-quote search starts there.
        if j < masked_to {
            continue;
        }
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
        masked_to = value_end + usize::from(closer.is_some());
        // Resume inside the masked value, so a secret pair that begins there is
        // read too. The key runs before `value_start` were passed already.
        i = value_start;
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

    // ---- Stage 5 tester additions: each one kills a mutant of the vocabulary or
    // the pair scan that the tests above let survive. ----

    #[test]
    fn is_secret_key_names_every_substring_needle() {
        // Spelled out, not read from the const: a needle dropped from the list must
        // fail here (the vocabulary-consistency test cannot see it, because
        // `is_secret_key` and `scrub_text` would both stop knowing it).
        let mut bad: Vec<String> = Vec::new();
        for needle in [
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
        ] {
            for key in [
                needle.to_string(),
                needle.to_ascii_uppercase(),
                format!("x-{needle}-y"),
                format!("my{needle}2"),
            ] {
                if !is_secret_key(&key) {
                    bad.push(format!("is_secret_key({key:?}) is false"));
                }
            }
            let pair = format!("{needle}=VALUE9");
            if !scrub_text(&pair).contains("[redacted]") {
                bad.push(format!("scrub_text({pair:?}) kept the value"));
            }
        }
        assert!(bad.is_empty(), "the vocabulary lost a needle: {bad:#?}");
    }

    #[test]
    fn is_secret_key_segments_are_whole_alphanumeric_runs_digits_included() {
        for key in [
            "auth2", "sid1", "jwt0", "x-csrf9", "session2", "2sid", "sid2x",
        ] {
            assert!(
                !is_secret_key(key),
                "`{key}` is one segment, not `sid`/`auth`"
            );
        }
        for key in ["sid-2", "auth_2", "x.sid.2", "1-jwt", "session.9"] {
            assert!(is_secret_key(key), "`{key}` has a whole secret segment");
        }
    }

    #[test]
    fn scrub_text_masks_an_authorization_line_in_any_case() {
        // The regex pass has to be case-insensitive: the pair pass alone would mask
        // only the scheme (`Basic`) and leave the credential after it.
        let bad = mismatches(&[
            (
                "AUTHORIZATION: Basic dXNlcjpwYXNz",
                "AUTHORIZATION: [redacted]",
            ),
            (
                "authorization: basic dXNlcjpwYXNz",
                "authorization: [redacted]",
            ),
            ("Authorization=Digest a=b c=d", "Authorization=[redacted]"),
            (
                "x: 1\nAuthorization:  Basic dXNlcjpwYXNz tail\ny: 2",
                "x: 1\nAuthorization:  [redacted]\ny: 2",
            ),
        ]);
        assert!(bad.is_empty(), "wrong output: {bad:#?}");
    }

    #[test]
    fn scrub_text_masks_a_bearer_token_in_any_spacing_and_case() {
        let bad = mismatches(&[
            ("Bearer  tok3n", "Bearer  [redacted]"),
            ("Bearer\ttok3n", "Bearer\t[redacted]"),
            ("BEARER tok3n", "BEARER [redacted]"),
            ("bearer\ntok3n", "bearer\n[redacted]"),
            ("see Bearer tok3n here", "see Bearer [redacted] here"),
        ]);
        assert!(bad.is_empty(), "wrong output: {bad:#?}");
    }

    #[test]
    fn scrub_text_masks_a_bearer_credential_given_as_a_pair_value() {
        // The `Bearer` pass runs before the pair pass: the pair pass alone would
        // mask the scheme word and leave the token behind it.
        let out = scrub_text("token=Bearer abc123");
        assert!(!out.contains("abc123"), "the bearer token leaked: {out}");
        assert_eq!(out, "token=[redacted] [redacted]");
    }

    #[test]
    fn scrub_text_masks_a_dotted_key_whose_secret_word_is_not_last() {
        // The key run keeps its dots, so the whole run is judged, not its last part.
        let bad = mismatches(&[
            ("password.hash=S3CR3T", "password.hash=[redacted]"),
            ("x.api_key.v1=K1&n=2", "x.api_key.v1=[redacted]&n=2"),
            ("connect.sid.v2=abc; a=b", "connect.sid.v2=[redacted]; a=b"),
            ("a-token-b=T1", "a-token-b=[redacted]"),
        ]);
        assert!(bad.is_empty(), "wrong output: {bad:#?}");
    }

    #[test]
    fn scrub_text_treats_non_ascii_letters_as_part_of_a_key() {
        let bad = mismatches(&[
            ("token_é=S3CR3T", "token_é=[redacted]"),
            ("passwordé: S3CR3T", "passwordé: [redacted]"),
            ("日本_secret=XYZ", "日本_secret=[redacted]"),
            ("é-sid=ABC", "é-sid=[redacted]"),
            // A non-secret key with non-ASCII letters is left alone.
            ("café=latte", "café=latte"),
        ]);
        assert!(bad.is_empty(), "wrong output: {bad:#?}");
    }

    #[test]
    fn scrub_text_reads_every_ascii_whitespace_as_blank() {
        // Space, tab, newline, vertical tab, form feed and carriage return: each
        // may pad the separator and each ends an unquoted value.
        let mut bad: Vec<(char, String)> = Vec::new();
        for c in [' ', '\t', '\n', '\u{b}', '\u{c}', '\r'] {
            let input = format!("password{c}={c}hunter2{c}tail");
            let want = format!("password{c}={c}[redacted]{c}tail");
            let got = scrub_text(&input);
            if got != want {
                bad.push((c, got));
            }
        }
        assert!(bad.is_empty(), "wrong output for these blanks: {bad:#?}");
    }

    #[test]
    fn scrub_text_ends_an_unquoted_value_at_a_comma_or_a_stray_quote() {
        let bad = mismatches(&[
            ("token=abc,user=bob", "token=[redacted],user=bob"),
            ("token=abc\"def", "token=[redacted]\"def"),
            ("token=abc'def", "token=[redacted]'def"),
        ]);
        assert!(bad.is_empty(), "wrong output: {bad:#?}");
    }

    #[test]
    fn scrub_text_stays_linear_on_oversized_inputs_of_other_shapes() {
        // A quadratic scan turns each of these (1 to 4 MiB) into a hang, so the
        // test finishing is the check. `assert!` on `==`, not `assert_eq!`: a
        // failure must not print megabytes.
        let unchanged = [
            ("secret keys with no separator", "password ".repeat(200_000)),
            ("separators with no key", "=".repeat(2 << 20)),
            ("colons with no key", ":".repeat(2 << 20)),
            ("multi-byte letters", "é".repeat(1 << 20)),
            ("no-break spaces", "\u{a0}".repeat(1 << 20)),
            (
                "a secret key then only blanks",
                format!("token={}", " ".repeat(2 << 20)),
            ),
            ("dotted non-secret keys", "a.b:".repeat(500_000)),
            ("host:port after host:port", "auth.x:1 ".repeat(300_000)),
            ("empty quoted values", "x=\"\" ".repeat(400_000)),
        ];
        for (what, text) in &unchanged {
            assert!(scrub_text(text) == *text, "{what} came back changed");
        }
        // These do hold a secret pair per repeat, each of which is masked.
        assert!(
            scrub_text(&"sid:1 ".repeat(300_000)) == "sid:[redacted] ".repeat(300_000),
            "300k short pairs are each masked"
        );
        assert!(
            scrub_text(&"token=\"a\" ".repeat(200_000)) == "token=\"[redacted]\" ".repeat(200_000),
            "200k quoted pairs are each masked"
        );
        assert!(
            scrub_text(&"Bearer x ".repeat(300_000)) == "Bearer [redacted] ".repeat(300_000),
            "300k bearer tokens are each masked"
        );
    }

    #[test]
    fn scrub_text_exempts_only_a_dotted_key_with_a_one_to_five_digit_port() {
        // Left alone: a host with a port of one to five digits and a terminator.
        let mut bad = mismatches(
            &[
                "auth.example.com:1",
                "auth.example.com:65535",
                "auth.example.com:8443?x=1",
                "auth.example.com:8443#frag",
                "auth.example.com:8443&x=1",
                "auth.example.com:8443;x=1",
                "auth.example.com:8443,next",
                "connect to auth.example.com:8443 now",
            ]
            .map(|text| (text, text)),
        );
        // Masked: everything that is not exactly that shape, or that uses `=`.
        bad.extend(mismatches(&[
            ("auth.example.com:123456", "auth.example.com:[redacted]"),
            ("auth.example.com: x", "auth.example.com: [redacted]"),
            ("auth.example.com:/x", "auth.example.com:[redacted]"),
            ("auth.example.com:8443abc", "auth.example.com:[redacted]"),
            ("auth.example.com=8443", "auth.example.com=[redacted]"),
            ("db.password=1234", "db.password=[redacted]"),
        ]));
        assert!(bad.is_empty(), "wrong output: {bad:#?}");
    }

    // Recorded outputs of `scrub_text`, taken by running it at commit 15009b2 (a
    // throwaway test printed each row, and no output below was written by hand).
    // Each row is `(input, recorded_output, reading_agnostic)`.
    //
    // `reading_agnostic` is `true` unless the input holds a key that contains one of
    // the `SECRET_KEY_SEGMENTS` words without being a whole-segment or needle secret
    // (`author`, `sidebar`, `xsid\u{e9}y`), or a dotted key directly before `:` and a
    // digit (`auth.example.com:8443`). Those are the rows that a wider key reading,
    // or a reading with no host:port exemption, could answer differently. The test
    // below reads the first two columns only.
    const RECORDED_SCRUB_TEXT: &[(&str, &str, bool)] = &[
        ("author=v", "author=v", false),
        ("author: v", "author: v", false),
        ("\"author\":\"v\"", "\"author\":\"v\"", false),
        ("author:\nJohn", "author:\nJohn", false),
        ("author\u{a0}:\u{a0}v", "author\u{a0}:\u{a0}v", false),
        ("author='a b'", "author='a b'", false),
        ("authority=v", "authority=v", false),
        ("authority: v", "authority: v", false),
        ("\"authority\":\"v\"", "\"authority\":\"v\"", false),
        ("authority:\nJohn", "authority:\nJohn", false),
        ("authority\u{a0}:\u{a0}v", "authority\u{a0}:\u{a0}v", false),
        ("authority='a b'", "authority='a b'", false),
        ("authenticated=v", "authenticated=v", false),
        ("authenticated: v", "authenticated: v", false),
        ("\"authenticated\":\"v\"", "\"authenticated\":\"v\"", false),
        ("authenticated:\nJohn", "authenticated:\nJohn", false),
        (
            "authenticated\u{a0}:\u{a0}v",
            "authenticated\u{a0}:\u{a0}v",
            false,
        ),
        ("authenticated='a b'", "authenticated='a b'", false),
        ("inside=v", "inside=v", false),
        ("inside: v", "inside: v", false),
        ("\"inside\":\"v\"", "\"inside\":\"v\"", false),
        ("inside:\nJohn", "inside:\nJohn", false),
        ("inside\u{a0}:\u{a0}v", "inside\u{a0}:\u{a0}v", false),
        ("inside='a b'", "inside='a b'", false),
        ("side=v", "side=v", false),
        ("side: v", "side: v", false),
        ("\"side\":\"v\"", "\"side\":\"v\"", false),
        ("side:\nJohn", "side:\nJohn", false),
        ("side\u{a0}:\u{a0}v", "side\u{a0}:\u{a0}v", false),
        ("side='a b'", "side='a b'", false),
        ("sidebar=v", "sidebar=v", false),
        ("sidebar: v", "sidebar: v", false),
        ("\"sidebar\":\"v\"", "\"sidebar\":\"v\"", false),
        ("sidebar:\nJohn", "sidebar:\nJohn", false),
        ("sidebar\u{a0}:\u{a0}v", "sidebar\u{a0}:\u{a0}v", false),
        ("sidebar='a b'", "sidebar='a b'", false),
        ("subsidiary=v", "subsidiary=v", false),
        ("subsidiary: v", "subsidiary: v", false),
        ("\"subsidiary\":\"v\"", "\"subsidiary\":\"v\"", false),
        ("subsidiary:\nJohn", "subsidiary:\nJohn", false),
        (
            "subsidiary\u{a0}:\u{a0}v",
            "subsidiary\u{a0}:\u{a0}v",
            false,
        ),
        ("subsidiary='a b'", "subsidiary='a b'", false),
        ("sessions=v", "sessions=v", false),
        ("sessions: v", "sessions: v", false),
        ("\"sessions\":\"v\"", "\"sessions\":\"v\"", false),
        ("sessions:\nJohn", "sessions:\nJohn", false),
        ("sessions\u{a0}:\u{a0}v", "sessions\u{a0}:\u{a0}v", false),
        ("sessions='a b'", "sessions='a b'", false),
        ("userSession=v", "userSession=v", false),
        ("userSession: v", "userSession: v", false),
        ("\"userSession\":\"v\"", "\"userSession\":\"v\"", false),
        ("userSession:\nJohn", "userSession:\nJohn", false),
        (
            "userSession\u{a0}:\u{a0}v",
            "userSession\u{a0}:\u{a0}v",
            false,
        ),
        ("userSession='a b'", "userSession='a b'", false),
        ("X-Authority=v", "X-Authority=v", false),
        ("X-Authority: v", "X-Authority: v", false),
        ("\"X-Authority\":\"v\"", "\"X-Authority\":\"v\"", false),
        ("X-Authority:\nJohn", "X-Authority:\nJohn", false),
        (
            "X-Authority\u{a0}:\u{a0}v",
            "X-Authority\u{a0}:\u{a0}v",
            false,
        ),
        ("X-Authority='a b'", "X-Authority='a b'", false),
        ("author=bob&page=2", "author=bob&page=2", false),
        (
            "{\"subsidiary\":\"a b\",\"n\":1}",
            "{\"subsidiary\":\"a b\",\"n\":1}",
            false,
        ),
        ("sidebar='x y' z=1", "sidebar='x y' z=1", false),
        ("author:\n  John", "author:\n  John", false),
        ("sidebar=abc\u{a0}def", "sidebar=abc\u{a0}def", false),
        ("sidebar=abc\u{b}def", "sidebar=abc\u{b}def", false),
        (
            "sidebar='abc def token='S3'",
            "sidebar='abc def token='[redacted]'",
            false,
        ),
        (
            "sidebar='abc def token='S3",
            "sidebar='abc def token='[redacted]",
            false,
        ),
        (
            "{\"sidebar\":\"YWJj=\",\"user\":\"bob\"}",
            "{\"sidebar\":\"YWJj=\",\"user\":\"bob\"}",
            false,
        ),
        ("next=/cb?sidebar=S1", "next=/cb?sidebar=S1", false),
        ("sidebar=&x=1", "sidebar=&x=1", false),
        ("sid=1&sidebar=2", "sid=[redacted]&sidebar=2", false),
        ("password=x&author=y", "password=[redacted]&author=y", false),
        ("sid=abc\u{b}def", "sid=[redacted]\u{b}def", true),
        ("sid=abc\u{a0}def", "sid=[redacted]\u{a0}def", true),
        ("password=abc\u{b}def", "password=[redacted]\u{b}def", true),
        (
            "password=abc\u{a0}def",
            "password=[redacted]\u{a0}def",
            true,
        ),
        ("token=abc\u{b}def", "token=[redacted]\u{b}def", true),
        ("token=abc\u{a0}def", "token=[redacted]\u{a0}def", true),
        ("sid: abc\u{a0}def", "sid: [redacted]\u{a0}def", true),
        ("sid=abc\u{2028}def", "sid=[redacted]\u{2028}def", true),
        (
            "password=abc\u{3000}def",
            "password=[redacted]\u{3000}def",
            true,
        ),
        ("token=\u{a0}abc", "token=\u{a0}[redacted]", true),
        ("sid=abc\u{c}def", "sid=[redacted]\u{c}def", true),
        ("sid=abc\u{1680}def", "sid=[redacted]\u{1680}def", true),
        ("sid='abc def token='S3'", "sid='[redacted]'", true),
        (
            "password='abc def token='S3'",
            "password='[redacted]'",
            true,
        ),
        (
            "sid='abc def token='S3",
            "sid='[redacted] def token='[redacted]",
            true,
        ),
        (
            "password='abc def token='S3",
            "password='[redacted] def token='[redacted]",
            true,
        ),
        ("sid=\"abc def token=\"S3\"", "sid=\"[redacted]\"", true),
        ("token='a b token='S3'", "token='[redacted]'", true),
        ("auth.example.com:1", "auth.example.com:1", false),
        ("auth.example.com:65535", "auth.example.com:65535", false),
        (
            "auth.example.com:8443?x=1",
            "auth.example.com:8443?x=1",
            false,
        ),
        (
            "auth.example.com:8443#frag",
            "auth.example.com:8443#frag",
            false,
        ),
        (
            "auth.example.com:8443&x=1",
            "auth.example.com:8443&x=1",
            false,
        ),
        (
            "auth.example.com:8443;x=1",
            "auth.example.com:8443;x=1",
            false,
        ),
        (
            "auth.example.com:8443,next",
            "auth.example.com:8443,next",
            false,
        ),
        (
            "connect to auth.example.com:8443 now",
            "connect to auth.example.com:8443 now",
            false,
        ),
        (
            "auth.example.com:123456",
            "auth.example.com:[redacted]",
            false,
        ),
        (
            "auth.example.com:8443abc",
            "auth.example.com:[redacted]",
            false,
        ),
        (
            "auth.example.com:8443\u{a0}x",
            "auth.example.com:[redacted]\u{a0}x",
            false,
        ),
        (
            "token.example.com:8443/x",
            "token.example.com:8443/x",
            false,
        ),
        (
            "https://auth.example.com:8443/login",
            "https://auth.example.com:8443/login",
            false,
        ),
        ("connect.sid:12345", "connect.sid:12345", false),
        ("sid.example.com:80", "sid.example.com:80", false),
        ("jwt.x:443", "jwt.x:443", false),
        ("session.host:8080/path", "session.host:8080/path", false),
        (
            "Host: auth.example.com:8443",
            "Host: auth.example.com:8443",
            false,
        ),
        ("auth.example.com: x", "auth.example.com: [redacted]", true),
        ("auth.example.com:/x", "auth.example.com:[redacted]", true),
        ("auth.example.com=8443", "auth.example.com=[redacted]", true),
        (
            "auth.example.com\u{a0}:8443",
            "auth.example.com\u{a0}:[redacted]",
            true,
        ),
        ("db.password=1234", "db.password=[redacted]", true),
        ("sid:12345", "sid:[redacted]", true),
        ("token:8443", "token:[redacted]", true),
        ("xsid\u{e9}y=v", "xsid\u{e9}y=v", false),
        ("sid\u{e9}bar=x", "sid\u{e9}bar=[redacted]", true),
        ("\u{e9}-sid=ABC", "\u{e9}-sid=[redacted]", true),
        ("caf\u{e9}=latte", "caf\u{e9}=latte", true),
        ("sid\u{e9}=x", "sid\u{e9}=[redacted]", true),
        ("\u{e9}auth=x", "\u{e9}auth=[redacted]", true),
        ("xauth\u{e9}=v", "xauth\u{e9}=v", false),
        ("\u{e9}sid\u{e9}=ABC", "\u{e9}sid\u{e9}=[redacted]", true),
        ("m\u{e9}sidence=x", "m\u{e9}sidence=x", false),
        ("na\u{ef}ve=1", "na\u{ef}ve=1", true),
        ("token\u{e9}=abc", "token\u{e9}=[redacted]", true),
        ("jwt\u{f1}=x", "jwt\u{f1}=[redacted]", true),
        ("s\u{e9}same=open", "s\u{e9}same=open", true),
        ("caf\u{e9}:latte", "caf\u{e9}:latte", true),
        (
            "\u{dc}n\u{ef}code_token=x",
            "\u{dc}n\u{ef}code_token=[redacted]",
            true,
        ),
        (
            "sid=\u{65e5}\u{672c}\u{8a9e}&x=1",
            "sid=[redacted]&x=1",
            true,
        ),
        (
            "password: \u{201c}quoted\u{201d}",
            "password: [redacted]",
            true,
        ),
        (
            "Authorization: Bearer abc.def.ghi",
            "Authorization: [redacted]",
            true,
        ),
        (
            "authorization=Basic dXNlcjpwYXNz",
            "authorization=[redacted]",
            true,
        ),
        (
            "Authorization:Bearer tok123",
            "Authorization:[redacted]",
            true,
        ),
        (
            "send Authorization: Bearer sk-9f8a7b6c5d4e, then retry",
            "send Authorization: [redacted]",
            true,
        ),
        (
            "got token via Bearer abc.def.ghi here",
            "got token via Bearer [redacted] here",
            true,
        ),
        ("Bearer abcdef", "Bearer [redacted]", true),
        ("bearer   x y", "bearer   [redacted] y", true),
        (
            "Proxy-Authorization: Basic Zm9vOmJhcg==",
            "Proxy-Authorization: [redacted]",
            true,
        ),
        (
            "Authorization:\nBearer abc",
            "Authorization:\n[redacted]",
            true,
        ),
        ("Authorization: ", "Authorization:[redacted]", true),
        ("", "", true),
        ("=", "=", true),
        (":", ":", true),
        ("'", "'", true),
        ("\"", "\"", true),
        ("\\", "\\", true),
        ("sid=", "sid=", true),
        ("sid='", "sid='", true),
        ("sid=\"\\", "sid=\"[redacted]", true),
        ("\u{a0}", "\u{a0}", true),
        ("==", "==", true),
        ("::", "::", true),
        ("sid=''", "sid=''", true),
        ("sid=\"\"", "sid=\"\"", true),
        ("sid=\\", "sid=[redacted]", true),
        ("password:", "password:", true),
        ("sid='\\", "sid='[redacted]", true),
        ("token=\u{a0}", "token=\u{a0}", true),
        ("sid= ", "sid= ", true),
        ("sid\n=\nx", "sid\n=\n[redacted]", true),
        ("'sid'=x", "'sid'=[redacted]", true),
        ("\"sid\"=\"x", "\"sid\"=\"[redacted]", true),
        (
            "/v1/users?access_token=sk-9f8a7b6c5d4e&page=2",
            "/v1/users?access_token=[redacted]&page=2",
            true,
        ),
        (
            "user=admin&password=hunter2",
            "user=admin&password=[redacted]",
            true,
        ),
        (
            "{\"password\":\"hunter2\"}",
            "{\"password\":\"[redacted]\"}",
            true,
        ),
        (
            "{\"api_key\": \"sk-9f8a7b6c5d4e\"}",
            "{\"api_key\": \"[redacted]\"}",
            true,
        ),
        (
            "{\"user\":\"admin\",\"password\":\"hunter2\"}",
            "{\"user\":\"admin\",\"password\":\"[redacted]\"}",
            true,
        ),
        (
            "GET /search?q=hello&page=2",
            "GET /search?q=hello&page=2",
            true,
        ),
        ("next=/cb?sid=S1", "next=/cb?sid=[redacted]", true),
        (
            "{\"token\":\"YWJj=\",\"user\":\"bob\"}",
            "{\"token\":\"[redacted]\",\"user\":\"bob\"}",
            true,
        ),
        ("password='a b token='S3'", "password='[redacted]'", true),
        // rows in this group record a tail the shared value rule leaves beside the mask; they pin the unchanged behaviour of the standard scan, they are not requirements
        (
            "Set-Cookie: sid=abc123; Path=/; HttpOnly",
            "Set-Cookie: [redacted]; Path=/; HttpOnly",
            true,
        ),
        ("Cookie: a=1; b=2", "Cookie: [redacted]; b=2", true),
        ("X-CSRF-Token: abc", "X-CSRF-Token: [redacted]", true),
        ("_csrf=abc&x=1", "_csrf=[redacted]&x=1", true),
        ("jwt=aaa.bbb.ccc", "jwt=[redacted]", true),
        ("connect.sid=s%3Aabc.def", "connect.sid=[redacted]", true),
        (
            "JSESSIONID=ABC123; Path=/",
            "JSESSIONID=[redacted]; Path=/",
            true,
        ),
        ("q=hello world&page=2", "q=hello world&page=2", true),
        (
            "http://user:pw@host/p?x=1",
            "http://user:pw@host/p?x=1",
            true,
        ),
    ];

    #[test]
    fn scrub_text_is_unchanged_on_the_recorded_corpus() {
        assert!(
            RECORDED_SCRUB_TEXT.len() >= 60,
            "the recorded corpus shrank to {} rows",
            RECORDED_SCRUB_TEXT.len()
        );
        let rows: Vec<(&str, &str)> = RECORDED_SCRUB_TEXT
            .iter()
            .map(|&(input, output, _)| (input, output))
            .collect();
        let bad = mismatches(&rows);
        assert!(
            bad.is_empty(),
            "scrub_text changed on {} recorded rows: {bad:#?}",
            bad.len()
        );
    }

    /// Run [`scrub_text_wide`] over every `(input, expected)` row and return the
    /// rows that came out different, as [`mismatches`] does for [`scrub_text`].
    fn mismatches_wide<'a>(rows: &[(&'a str, &'a str)]) -> Vec<(&'a str, &'a str, String)> {
        rows.iter()
            .filter_map(|&(input, expected)| {
                let actual = scrub_text_wide(input);
                (actual != expected).then_some((input, expected, actual))
            })
            .collect()
    }

    #[test]
    fn is_secret_key_wide_reads_the_segment_words_as_substrings() {
        // `(key, (is_secret_key, is_secret_key_wide))`.
        let wide_only = [
            "author",
            "authority",
            "authenticated",
            "inside",
            "side",
            "sidebar",
            "subsidiary",
            "sessions",
            "Author",
            "X-Authority",
            "rhai.allow_agent_authoring",
            "userSession",
        ]
        .map(|key| (key, (false, true)));
        let both = ["sid", "X-CSRF", "connect.sid", "PHPSESSID", "Authorization"]
            .map(|key| (key, (true, true)));
        let neither = [
            "path",
            "host",
            "body",
            "note",
            "method",
            "page",
            "q",
            "username",
            "next",
            "Content-Type",
            "Referer",
        ]
        .map(|key| (key, (false, false)));
        let bad: Vec<String> = wide_only
            .into_iter()
            .chain(both)
            .chain(neither)
            .filter_map(|(key, expected)| {
                let actual = (is_secret_key(key), is_secret_key_wide(key));
                (actual != expected).then(|| {
                    format!("{key}: expected (standard, wide) {expected:?}, got {actual:?}")
                })
            })
            .collect();
        assert!(bad.is_empty(), "wrong key decisions: {bad:#?}");
    }

    #[test]
    fn is_secret_key_wide_is_a_superset_of_is_secret_key() {
        let keys = [
            // is_secret_key_covers_the_session_and_auth_family
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
            // is_secret_key_leaves_lookalikes_alone
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
            // secret_keys_matched_as_substring_case_insensitively
            "Authorization",
            "X-Api-Key",
            "access_token",
            "Set-Cookie",
            "db_password",
            "clientSecret",
            "CREDENTIAL",
            // every substring needle, spelled out
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
            // the keys neither reading names
            "page",
            "q",
            "username",
            "next",
            "Content-Type",
            "Referer",
        ];
        let standard = keys.iter().filter(|key| is_secret_key(key)).count();
        assert!(
            standard >= 34,
            "only {standard} keys are secret under is_secret_key: the table lost its secret keys"
        );
        let bad: Vec<&str> = keys
            .into_iter()
            .filter(|key| is_secret_key(key) && !is_secret_key_wide(key))
            .collect();
        assert!(
            bad.is_empty(),
            "is_secret_key but not is_secret_key_wide: {bad:#?}"
        );
    }

    #[test]
    fn is_secret_key_wide_names_every_segment_word() {
        // Spelled out, not read from `SECRET_KEY_SEGMENTS`: a dropped word must fail.
        let bad: Vec<String> = ["sid", "jwt", "csrf", "session", "auth"]
            .into_iter()
            .flat_map(|word| {
                [
                    word.to_string(),
                    word.to_ascii_uppercase(),
                    format!("x-{word}-y"),
                    format!("my{word}2"),
                ]
            })
            .filter(|key| !is_secret_key_wide(key))
            .collect();
        assert!(bad.is_empty(), "should be wide secret keys: {bad:#?}");
    }

    #[test]
    fn scrub_text_wide_and_is_secret_key_wide_share_one_vocabulary() {
        let secret = [
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
            // The wide-only keys that the table above does not already hold.
            "Author",
            "X-Authority",
            "rhai.allow_agent_authoring",
            "userSession",
        ];
        let plain = ["path", "host", "body", "note", "method"];
        // `(key, expected)` where both the predicate and the scrub must say `expected`.
        let disagree: Vec<(&str, bool)> = secret
            .into_iter()
            .map(|key| (key, true))
            .chain(plain.into_iter().map(|key| (key, false)))
            .filter(|&(key, expected)| {
                let text = format!("{key}=VALUE9");
                is_secret_key_wide(key) != expected || (scrub_text_wide(&text) != text) != expected
            })
            .collect();
        assert!(
            disagree.is_empty(),
            "is_secret_key_wide and scrub_text_wide disagree with the table on: {disagree:#?}"
        );
    }

    #[test]
    fn scrub_text_wide_masks_a_wide_only_pair_as_a_standard_pair() {
        let bad = mismatches_wide(&[
            ("author=bob&page=2", "author=[redacted]&page=2"),
            (
                r#"{"subsidiary":"a b","n":1}"#,
                r#"{"subsidiary":"[redacted]","n":1}"#,
            ),
            ("sidebar='x y' z=1", "sidebar='[redacted]' z=1"),
            ("author:\u{a0}John", "author:\u{a0}[redacted]"),
            ("sidebar=abc\u{a0}def", "sidebar=[redacted]\u{a0}def"),
            ("sidebar='abc def token='S3'", "sidebar='[redacted]'"),
            (
                r#"{"sidebar":"YWJj=","user":"bob"}"#,
                r#"{"sidebar":"[redacted]","user":"bob"}"#,
            ),
            ("next=/cb?sidebar=S1", "next=/cb?sidebar=[redacted]"),
            ("sidebar=&x=1", "sidebar=&x=1"),
        ]);
        assert!(bad.is_empty(), "wrong output: {bad:#?}");
    }

    #[test]
    fn scrub_text_wide_does_not_exempt_a_host_port() {
        // The paired guard is `scrub_text_does_not_mask_a_host_port`: the standard
        // reading still leaves the first three alone.
        let bad = mismatches_wide(&[
            ("auth.example.com:8443", "auth.example.com:[redacted]"),
            (
                "https://auth.example.com:8443/login",
                "https://auth.example.com:[redacted]",
            ),
            ("token.example.com:8443/x", "token.example.com:[redacted]"),
            ("sid:12345", "sid:[redacted]"),
        ]);
        assert!(bad.is_empty(), "wrong output: {bad:#?}");
    }

    #[test]
    fn scrub_text_wide_survives_hostile_inputs_and_stays_linear() {
        // `assert!` on `==`, not `assert_eq!`: a failure must not print megabytes.
        let input = "sidebar=".repeat(1 << 19);
        assert!(
            scrub_text_wide(&input) == "sidebar=[redacted]",
            "an unquoted value that holds the key again is masked whole"
        );

        let input = "sidebar=\"x ".repeat(150_000);
        assert!(
            scrub_text_wide(&input) == "sidebar=\"[redacted] ".repeat(150_000),
            "an opening quote that never closes must still mask every value"
        );

        let input = "sidebar='x sidebar=\"x ".repeat(75_000);
        assert!(
            scrub_text_wide(&input) == "sidebar='[redacted] sidebar=\"[redacted] ".repeat(75_000),
            "two kinds of unclosed quote must still mask every value"
        );

        let input = "author.x:1 ".repeat(300_000);
        assert!(
            scrub_text_wide(&input) == "author.x:[redacted] ".repeat(300_000),
            "a dotted key before a port is masked, with no exemption"
        );

        // A megabyte of one non-ASCII character, as a key run and as a blank run,
        // holds no pair and comes back as it went in.
        let input = "\u{e9}".repeat(1 << 19);
        assert!(scrub_text_wide(&input) == input, "a run of e-acute changed");
        let input = "\u{a0}".repeat(1 << 19);
        assert!(scrub_text_wide(&input) == input, "a run of nbsp changed");

        let input = "sid\u{e9}bar=x ".repeat(100_000);
        assert!(
            scrub_text_wide(&input) == "sid\u{e9}bar=[redacted] ".repeat(100_000),
            "a key glued to a non-ASCII letter is one run and is masked"
        );
    }

    #[test]
    fn scrub_text_wide_agrees_with_scrub_text_when_nothing_wide_applies() {
        let mut checked = 0;
        let mut bad: Vec<(&str, String, String)> = Vec::new();
        for &(input, _, agnostic) in RECORDED_SCRUB_TEXT {
            if !agnostic {
                continue;
            }
            checked += 1;
            let standard = scrub_text(input);
            let wide = scrub_text_wide(input);
            if standard != wide {
                bad.push((input, standard, wide));
            }
        }
        assert!(
            checked >= 25,
            "only {checked} recorded rows are reading-agnostic"
        );
        assert!(
            bad.is_empty(),
            "(input, scrub_text, scrub_text_wide) disagree on {} of {checked} rows: {bad:#?}",
            bad.len()
        );
    }

    // ---- Edges of the wide reading: the ends of the text, non-ASCII boundaries,
    // ---- a text cut short, and oversized runs.

    /// The two ends of the text and the places a non-ASCII character can sit, read
    /// the wide way. Each row follows from the scan's rules (a key run, blanks, a
    /// separator, a value), not from a recording.
    #[test]
    fn scrub_text_wide_reads_the_edges_of_the_text() {
        let bad = mismatches_wide(&[
            // Nothing at all, and a key the text ends on or just after.
            ("", ""),
            ("sidebar", "sidebar"),
            ("sidebar=", "sidebar="),
            ("sidebar:", "sidebar:"),
            ("sidebar='", "sidebar='"),
            ("author: ", "author: "),
            ("author:\n", "author:\n"),
            ("author:\u{2028}", "author:\u{2028}"),
            ("sidebar=\u{a0}", "sidebar=\u{a0}"),
            ("sidebar\u{a0}", "sidebar\u{a0}"),
            ("sidebar\u{e9}", "sidebar\u{e9}"),
            // A one-character value is the last thing in the text.
            ("sidebar=v", "sidebar=[redacted]"),
            ("x=1&sidebar=v", "x=1&sidebar=[redacted]"),
            ("author:v", "author:[redacted]"),
            // A value that is one non-ASCII character (two and four bytes), a NUL,
            // and a value that a non-ASCII blank ends.
            ("sidebar=\u{e9}", "sidebar=[redacted]"),
            ("sidebar=\u{1f600}", "sidebar=[redacted]"),
            ("sidebar=\0", "sidebar=[redacted]"),
            ("sidebar=v\u{a0}", "sidebar=[redacted]\u{a0}"),
            ("sidebar=\u{e9}\u{a0}x", "sidebar=[redacted]\u{a0}x"),
            // A key glued to a non-ASCII character on either side is one run, and
            // a word that a non-ASCII character splits is not the word.
            ("\u{e9}author=v", "\u{e9}author=[redacted]"),
            ("author\u{e9}=v", "author\u{e9}=[redacted]"),
            ("\u{1f600}sid=v", "\u{1f600}sid=[redacted]"),
            ("si\u{e9}d=v", "si\u{e9}d=v"),
            // A blank is not part of a key run, so a leading no-break space is
            // stepped over whole and the key behind it is still found.
            ("\u{a0}sidebar=v", "\u{a0}sidebar=[redacted]"),
            (
                "author\u{2028}:\u{2028}v",
                "author\u{2028}:\u{2028}[redacted]",
            ),
            // A non-secret non-ASCII key beside a secret one swallows nothing.
            (
                "\u{4e2d}\u{6587}=v&sidebar=1",
                "\u{4e2d}\u{6587}=v&sidebar=[redacted]",
            ),
        ]);
        assert!(bad.is_empty(), "wrong output: {bad:#?}");
    }

    /// A connection that drops mid-stream hands over a prefix of the text. Cut at
    /// every char boundary, the wide scrub never panics and leaves no character of
    /// a credential behind: every value is a run of `Q` (or of `8`, as a port), and
    /// neither character appears anywhere else in the text.
    #[test]
    fn scrub_text_wide_masks_every_prefix_of_a_credential_bearing_text() {
        let doc = "GET /x?author=QQQQ&sidebar=QQQQ HTTP/1.1\r\n\
                   X-Authority: QQQQ\r\n\r\n\
                   {\"subsidiary\":\"QQQQ\",\"n\":1}&next=/cb?sessions=QQQQ\
                   &u=auth.example.com:8888 \u{e9}\u{a0}sid:QQQQ\u{2028}tail";
        let mut cuts = 0;
        let mut bad: Vec<(usize, String)> = Vec::new();
        for prefix in prefixes(doc) {
            cuts += 1;
            let out = scrub_text_wide(prefix);
            if out.contains('Q') || out.contains('8') {
                bad.push((prefix.len(), out));
            }
        }
        assert!(cuts >= 150, "the document is too short: {cuts} cuts");
        assert!(
            bad.is_empty(),
            "a credential survived in a prefix: {bad:#?}"
        );

        let whole = "GET /x?author=[redacted]&sidebar=[redacted] HTTP/1.1\r\n\
                     X-Authority: [redacted]\r\n\r\n\
                     {\"subsidiary\":\"[redacted]\",\"n\":1}&next=/cb?sessions=[redacted]\
                     &u=auth.example.com:[redacted] \u{e9}\u{a0}sid:[redacted]\u{2028}tail";
        assert!(
            scrub_text_wide(doc) == whole,
            "the whole text came out wrong: {:?}",
            scrub_text_wide(doc)
        );
    }

    /// Keys with nothing to match, and keys far too long to be real, are decided
    /// without a panic. Case folding is ASCII only, so a non-ASCII letter never
    /// reads as an ASCII one.
    #[test]
    fn is_secret_key_wide_survives_degenerate_and_oversized_keys() {
        assert!(!is_secret_key_wide(""));
        assert!(!is_secret_key_wide(" \t\u{a0}\n"));
        assert!(!is_secret_key_wide("\u{e9}\u{4e2d}\u{1f600}"));
        assert!(is_secret_key_wide("\u{e9}AUTH\u{e9}"));
        assert!(!is_secret_key_wide("s\u{131}d"), "dotless i is not an i");
        assert!(!is_secret_key_wide("S\u{130}D"), "dotted I is not an i");

        let long = "a".repeat(1 << 20);
        assert!(!is_secret_key_wide(&long));
        assert!(is_secret_key_wide(&format!("{long}sid")));
        assert!(is_secret_key_wide(&format!("sid{long}")));
        let multibyte = "\u{e9}".repeat(1 << 19);
        assert!(!is_secret_key_wide(&multibyte));
        assert!(is_secret_key_wide(&format!("{multibyte}Auth")));
    }

    /// One run of a megabyte, in each place the scan reads a run, stays linear and
    /// is read the same way as a short one.
    #[test]
    fn scrub_text_wide_stays_linear_on_one_oversized_run() {
        let run = "x".repeat(1 << 20);
        let blanks = " ".repeat(1 << 20);

        // A key run holding the word at its end is masked; one holding no word is not.
        let input = format!("{run}author=v");
        assert!(
            scrub_text_wide(&input) == format!("{run}author=[redacted]"),
            "a megabyte-long key that ends in `author` was not masked"
        );
        let input = format!("{run}=v");
        assert!(scrub_text_wide(&input) == input, "a plain long key changed");

        // Blanks between the key and the separator, and between it and the value.
        let input = format!("author{blanks}=v");
        assert!(
            scrub_text_wide(&input) == format!("author{blanks}=[redacted]"),
            "blanks before the separator were not skipped"
        );
        let input = format!("author={blanks}v");
        assert!(
            scrub_text_wide(&input) == format!("author={blanks}[redacted]"),
            "blanks after the separator were not skipped"
        );

        // A value of a megabyte, and a megabyte of nothing but separators.
        let input = format!("author={run}");
        assert!(
            scrub_text_wide(&input) == "author=[redacted]",
            "a long value"
        );
        for separators in [":".repeat(1 << 20), "=".repeat(1 << 20)] {
            assert!(
                scrub_text_wide(&separators) == separators,
                "a run of separators changed"
            );
        }
    }

    // ---- The wide scrub reads a pair that begins inside a masked value.

    /// A standard-secret pair nested under a wide-only key. In rows 1 to 4 the pair
    /// is on the line after the key: the parent takes the child's label as its
    /// value and the child masks its own, so both come out `[redacted]`. Rows 5 to
    /// 9 are one-line shapes, and the rule leaves their outputs as they were.
    const NESTED_UNDER_A_WIDE_ONLY_KEY: &[(&str, &str)] = &[
        (
            "authentication:\n  password: hunter2",
            "authentication:\n  [redacted] [redacted]",
        ),
        (
            "author:\n  token: abc123",
            "author:\n  [redacted] [redacted]",
        ),
        ("sessions:\n  jwt: J1", "sessions:\n  [redacted] [redacted]"),
        (
            "sidebar:\n    api_key: K1",
            "sidebar:\n    [redacted] [redacted]",
        ),
        (
            "authentication: {password: hunter2}",
            "authentication: [redacted] [redacted]}",
        ),
        ("sidebar=sid=\"C1\"", "sidebar=[redacted]\"[redacted]\""),
        ("author=password='C2'", "author=[redacted]'[redacted]'"),
        ("inside=x?sid\t=\tC9", "inside=[redacted]\t=\t[redacted]"),
        ("Auths:Pwd: C", "Auths:[redacted] [redacted]"),
    ];

    /// Shapes with a line break beside a separator, as the wide scrub reads them:
    /// it reads across the line break and a pair that begins inside a masked
    /// value, so a wide-only key takes the next line's token as its value and a
    /// key on that line is masked as well.
    const PAIR_ACROSS_A_LINE_BREAK: &[(&str, &str)] = &[
        ("side:\nSid2':C", "side:\n[redacted]':[redacted]"),
        (
            "authentication:\n  sessionKey: abc123",
            "authentication:\n  [redacted] [redacted]",
        ),
        ("bsid:\rSIDE:'C", "bsid:\r[redacted]'[redacted]"),
        ("author:\nJohn", "author:\n[redacted]"),
        ("sidebar:\r\nv", "sidebar:\r\n[redacted]"),
        ("sidebar\n:v", "sidebar\n:[redacted]"),
        ("sidebar=\u{c}v", "sidebar=\u{c}[redacted]"),
        // A standard key still reads across a line break.
        ("sid:\nabc", "sid:\n[redacted]"),
    ];

    /// The maximal runs of two or more ASCII alphanumerics in `text`.
    fn alnum_runs(text: &str) -> Vec<&str> {
        text.split(|c: char| !c.is_ascii_alphanumeric())
            .filter(|run| run.len() >= 2)
            .collect()
    }

    /// Every prefix of `text` that ends on a char boundary, the empty one and
    /// `text` itself included: what a connection that drops mid-stream hands over.
    fn prefixes(text: &str) -> impl Iterator<Item = &str> {
        text.char_indices()
            .map(|(at, _)| at)
            .chain(std::iter::once(text.len()))
            .map(move |cut| &text[..cut])
    }

    /// The superset check on one text. The first value is how many runs (see
    /// [`alnum_runs`]) [`scrub_text`] removes from it, `redacted` aside; the second
    /// is those of them that are still in the output of [`scrub_text_wide`]. The
    /// second is empty when the wide scrub masks everything the standard one does.
    fn runs_left_by_wide(text: &str) -> (usize, Vec<&str>) {
        let standard = scrub_text(text);
        let wide = scrub_text_wide(text);
        let masked: Vec<&str> = alnum_runs(text)
            .into_iter()
            .filter(|run| !"redacted".contains(run) && !standard.contains(run))
            .collect();
        let left = masked
            .iter()
            .copied()
            .filter(|run| wide.contains(run))
            .collect();
        (masked.len(), left)
    }

    #[test]
    fn scrub_text_wide_masks_a_standard_pair_nested_under_a_wide_only_key() {
        let bad = mismatches_wide(NESTED_UNDER_A_WIDE_ONLY_KEY);
        assert!(bad.is_empty(), "wrong output: {bad:#?}");
    }

    #[test]
    fn scrub_text_wide_masks_everything_scrub_text_masks() {
        let inputs = corpus_inputs();
        let mut with_a_masked_run = 0;
        let mut bad: Vec<(&str, Vec<&str>, String)> = Vec::new();
        for &input in &inputs {
            let (masked, left) = runs_left_by_wide(input);
            if masked > 0 {
                with_a_masked_run += 1;
            }
            if !left.is_empty() {
                bad.push((input, left, scrub_text_wide(input)));
            }
        }
        assert!(
            inputs.len() >= 100,
            "only {} inputs are checked",
            inputs.len()
        );
        assert!(
            with_a_masked_run >= 20,
            "only {with_a_masked_run} inputs have a run that scrub_text masks: the test is vacuous"
        );
        assert!(
            bad.is_empty(),
            "(input, runs scrub_text masks but scrub_text_wide leaves, scrub_text_wide) on {} inputs: {bad:#?}",
            bad.len()
        );
    }

    #[test]
    fn scrub_text_wide_reads_a_pair_across_a_line_break() {
        let bad = mismatches_wide(PAIR_ACROSS_A_LINE_BREAK);
        assert!(bad.is_empty(), "wrong output: {bad:#?}");
    }

    // ---- Edges of the blank rule and of the two scans: a pair read across a
    // ---- line break beside non-ASCII spaces, a text cut short, and oversized
    // ---- runs of line breaks.

    /// Every input of the three corpora above, the recorded ones and the two
    /// tables of the line-break and nesting shapes.
    fn corpus_inputs() -> Vec<&'static str> {
        RECORDED_SCRUB_TEXT
            .iter()
            .map(|&(input, _, _)| input)
            .chain(NESTED_UNDER_A_WIDE_ONLY_KEY.iter().map(|&(input, _)| input))
            .chain(PAIR_ACROSS_A_LINE_BREAK.iter().map(|&(input, _)| input))
            .collect()
    }

    /// The wide scan reads a pair across a line break, with a non-ASCII space
    /// before or after the line break as much as without one, and the standard
    /// scan still reads a standard key across the line break. The expected texts
    /// follow from the scan's rules (a wide-only key takes the next line's token
    /// as its value, and a key inside that value is read as a key), not from a
    /// recording.
    #[test]
    fn scrub_text_wide_reads_a_pair_across_a_line_break_beside_non_ascii_spaces() {
        let bad = mismatches_wide(&[
            // A wide-only key: the value is found across a line break, and a
            // non-ASCII space before or after it does not stop the scan.
            ("sidebar:\u{a0}\nJohn", "sidebar:\u{a0}\n[redacted]"),
            ("author\u{a0}\n:John", "author\u{a0}\n:[redacted]"),
            ("author\u{c}=John", "author\u{c}=[redacted]"),
            // A key on the next line, after a non-ASCII space, is masked as the
            // value of the wide-only key above it, and its own value with it.
            (
                "sidebar:\n\u{a0}sessionKey: abc123",
                "sidebar:\n\u{a0}[redacted] [redacted]",
            ),
            (
                "authentication:\u{2009}\r\n\u{2009}jwt:\u{a0}J1",
                "authentication:\u{2009}\r\n\u{2009}[redacted]\u{a0}[redacted]",
            ),
            // The standard scan reads a standard key across a line break, with a
            // non-ASCII space on either side of it.
            (
                "sid\u{a0}\n\u{a0}:\u{a0}\n\u{a0}abc",
                "sid\u{a0}\n\u{a0}:\u{a0}\n\u{a0}[redacted]",
            ),
            ("jwt:\u{2028}\u{c}J1", "jwt:\u{2028}\u{c}[redacted]"),
            ("sid\u{c}=abc", "sid\u{c}=[redacted]"),
            // Windows line endings: a nested standard pair and a header block.
            (
                "authentication:\r\n  password: hunter2",
                "authentication:\r\n  [redacted] [redacted]",
            ),
            (
                "X-Authority: example.com\r\nX-Sid: S1\r\n",
                "X-Authority: [redacted]\r\nX-Sid: [redacted]\r\n",
            ),
        ]);
        assert!(bad.is_empty(), "wrong output: {bad:#?}");

        // A nested standard pair under a wide-only key, inside JSON text where the
        // line break is the two characters `\n`: no credential survives.
        let json = r#"{"authentication":"x","note":"authentication:\n  password: hunter2"}"#;
        let out = scrub_text_wide(json);
        assert!(
            !out.contains("hunter2"),
            "a nested credential leaked: {out}"
        );
        assert!(out.contains("password: [redacted]"), "{out}");
    }

    /// A connection that drops mid-stream hands over a prefix of the text. The
    /// superset property of `scrub_text_wide_masks_everything_scrub_text_masks`
    /// holds on every char-boundary prefix of every corpus input, nested shapes and
    /// line breaks included, and no cut makes the scrub panic.
    #[test]
    fn scrub_text_wide_masks_everything_scrub_text_masks_on_every_prefix() {
        let mut checked = 0;
        let mut with_a_masked_run = 0;
        let mut bad: Vec<(&str, Vec<&str>, String)> = Vec::new();
        for input in corpus_inputs() {
            for prefix in prefixes(input) {
                checked += 1;
                let (masked, left) = runs_left_by_wide(prefix);
                if masked > 0 {
                    with_a_masked_run += 1;
                }
                if !left.is_empty() {
                    bad.push((prefix, left, scrub_text_wide(prefix)));
                }
            }
        }
        assert!(checked >= 3000, "only {checked} prefixes are checked");
        assert!(
            with_a_masked_run >= 300,
            "only {with_a_masked_run} prefixes have a run that scrub_text masks: the test is vacuous"
        );
        assert!(
            bad.is_empty(),
            "(prefix, runs scrub_text masks but scrub_text_wide leaves, scrub_text_wide) on {} prefixes: {bad:#?}",
            bad.len()
        );
    }

    /// Hostile text that gives both scans work: standard keys with a quote that
    /// never closes, and a standard key beside a wide-only one. The standard scan
    /// masks the first, and the wide scan reads the masked output. Each family
    /// finishes, and each comes out as the scan's rules say.
    #[test]
    fn scrub_text_wide_stays_linear_when_both_scans_have_work() {
        let input = "sid=\"x ".repeat(150_000);
        assert!(
            scrub_text_wide(&input) == "sid=\"[redacted] ".repeat(150_000),
            "an opening quote that never closes was not masked in every unit"
        );

        let input = "sid='x sid=\"x ".repeat(75_000);
        assert!(
            scrub_text_wide(&input) == "sid='[redacted] sid=\"[redacted] ".repeat(75_000),
            "two kinds of unclosed quote on a standard key were not masked in every unit"
        );

        let input = "sid='x sidebar=\"y ".repeat(75_000);
        assert!(
            scrub_text_wide(&input) == "sid='[redacted] sidebar=\"[redacted] ".repeat(75_000),
            "a standard key beside a wide-only key was not masked in every unit"
        );
    }

    /// Each of the five short words, read as a substring inside a key that is no
    /// whole segment (`mysid2`, `SIDX`, `asid`): the wide scrub masks the value and
    /// the standard scrub leaves the pair alone. The words are spelled out, not
    /// read from the list, so a word dropped from the wide reading fails here.
    #[test]
    fn scrub_text_wide_masks_a_key_that_merely_contains_each_segment_word() {
        let mut bad: Vec<(String, String, String)> = Vec::new();
        for word in ["sid", "jwt", "csrf", "session", "auth"] {
            let upper = word.to_ascii_uppercase();
            for key in [
                format!("my{word}2"),
                format!("{upper}X"),
                format!("a{word}"),
            ] {
                let input = format!("{key}=VALUE9&page=2");
                let wide = scrub_text_wide(&input);
                let standard = scrub_text(&input);
                if wide != format!("{key}=[redacted]&page=2") || standard != input {
                    bad.push((input, wide, standard));
                }
            }
        }
        assert!(
            bad.is_empty(),
            "(input, scrub_text_wide, scrub_text) is wrong: {bad:#?}"
        );
    }

    /// Oversized runs of line breaks and of line-ended pairs: the scan reads each
    /// byte a constant number of times, so these finish, and each comes out as the
    /// scan's rules say.
    #[test]
    fn scrub_text_wide_stays_linear_on_line_break_shapes() {
        // A wide-only key whose separator ends its line, over a hundred thousand
        // times: the first line keeps its key and every later line is the value of
        // the key above it.
        let input = "author:\n".repeat(1 << 17);
        assert!(
            scrub_text_wide(&input)
                == "author:\n".to_string() + &"[redacted]\n".repeat((1 << 17) - 1),
            "a line after a wide-only key at a line end was not masked as its value"
        );

        // A wide-only parent over a wide-only child, and over a standard child: the
        // parent takes the child's label as its value and the child masks its own.
        let input = "authentication:\n  sessionKey: x\n".repeat(50_000);
        assert!(
            scrub_text_wide(&input) == "authentication:\n  [redacted] [redacted]\n".repeat(50_000),
            "a wide-only child on the next line, with its parent, was not masked"
        );
        let input = "authentication:\n  password: x\n".repeat(50_000);
        assert!(
            scrub_text_wide(&input) == "authentication:\n  [redacted] [redacted]\n".repeat(50_000),
            "a standard child on the next line, with its parent, was not masked"
        );

        // A standard key reads across the line break, so a value is the next
        // line's first token; the scan resumes inside it, so every line after the
        // first is masked.
        let input = "sid:\n".repeat(100_000);
        assert!(
            scrub_text_wide(&input) == "sid:\n".to_string() + &"[redacted]\n".repeat(99_999),
            "standard keys on consecutive lines were not each masked"
        );

        // Half a million line breaks between a key and its separator: a wide-only
        // key and a standard key both read through all of them to the value.
        let breaks = "\n".repeat(1 << 19);
        let input = format!("sidebar{breaks}=v");
        assert!(
            scrub_text_wide(&input) == format!("sidebar{breaks}=[redacted]"),
            "a wide-only key was not masked across half a million line breaks"
        );
        let input = format!("sid{breaks}=v");
        assert!(
            scrub_text_wide(&input) == format!("sid{breaks}=[redacted]"),
            "a standard key was not masked across half a million line breaks"
        );
    }

    /// Five thousand `(parent, credential)` pairs from a seeded xorshift64
    /// generator, so every run sees the same ones. A credential is 4 to 43
    /// characters of `A-Za-z0-9` followed by `=` or `==`, the shape of padded
    /// base64; the parent is a standard secret key.
    fn padded_credentials() -> Vec<(&'static str, String)> {
        const PARENTS: [&str; 6] = ["token", "password", "secret", "session", "auth", "api_key"];
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        (0..5_000)
            .map(|_| {
                let parent = PARENTS[(next() % PARENTS.len() as u64) as usize];
                let len = 4 + (next() % 40) as usize;
                let mut credential: String = (0..len)
                    .map(|_| ALPHABET[(next() % ALPHABET.len() as u64) as usize] as char)
                    .collect();
                credential.push_str(if next() % 2 == 0 { "=" } else { "==" });
                (parent, credential)
            })
            .collect()
    }

    /// After a secret key the first token is the value, even on the next line,
    /// and it is masked whole. A secret pair that starts after that token is
    /// masked as a pair; none of these rows has one that starts inside it.
    #[test]
    fn scrub_text_keeps_the_output_it_had_when_no_secret_pair_starts_inside_a_masked_value() {
        let rows = [
            ("auth:\n  password=hunter2", "auth:\n  [redacted]"),
            ("auth=\n  password=hunter2", "auth=\n  [redacted]"),
            (
                "auth:\n  creds:\n    password: hunter2",
                "auth:\n  [redacted]\n    password: [redacted]",
            ),
            ("auth:\n  user: bob", "auth:\n  [redacted] bob"),
            ("token:\n  author: bob", "token:\n  [redacted] bob"),
            (
                "auth:\n  authority: example.com",
                "auth:\n  [redacted] example.com",
            ),
            (
                "auth:\n  user: bob\n  password: hunter2",
                "auth:\n  [redacted] bob\n  password: [redacted]",
            ),
            (
                "auth:\n  # note\n  password: hunter2",
                "auth:\n  [redacted] note\n  password: [redacted]",
            ),
            (
                "credentials:\n  - password: hunter2",
                "credentials:\n  [redacted] password: [redacted]",
            ),
            (
                "auth: x\n  password: hunter2",
                "auth: [redacted]\n  password: [redacted]",
            ),
            ("auth:\n", "auth:\n"),
            ("auth:\n  sessionKey: abc123", "auth:\n  [redacted] abc123"),
            (
                "Authorization:\n  password: hunter2",
                "Authorization:\n  [redacted]",
            ),
            ("password:\n  hunter2", "password:\n  [redacted]"),
        ];
        let bad = mismatches(&rows);
        assert!(
            bad.is_empty(),
            "(input, expected, actual) is wrong: {bad:#?}"
        );
    }

    /// A value that reads like a pair (`YWJj=`, `s3cr:et`, `user:pass`) on the
    /// line after a standard secret key is that key's value and is masked whole,
    /// whatever separator or secret-looking word it contains.
    #[test]
    fn scrub_text_masks_a_value_that_looks_like_a_pair_under_a_secret_parent() {
        let rows = [
            ("token:\n  YWJj=", "token:\n  [redacted]"),
            ("token:\n  YWJj==", "token:\n  [redacted]"),
            ("password:\n  s3cr:et", "password:\n  [redacted]"),
            ("token:\n  dXNlcjpwYXNz", "token:\n  [redacted]"),
            ("password:\n  user:pass", "password:\n  [redacted]"),
            ("token:\n  AApwdBB=", "token:\n  [redacted]"),
            (
                "token:\n  AApwdBB==\n  other: 1",
                "token:\n  [redacted]\n  other: 1",
            ),
            ("password:\n  sid:abc", "password:\n  [redacted]"),
            ("password:\n  auth=xyz", "password:\n  [redacted]"),
            ("secret:\n  a=b", "secret:\n  [redacted]"),
            ("auth:\n  user:pass", "auth:\n  [redacted]"),
            ("token:\r\n  YWJj=\r\n", "token:\r\n  [redacted]\r\n"),
            (
                "session:\n\tQWxhZGRpbjpvcGVuIHNlc2FtZQ==",
                "session:\n\t[redacted]",
            ),
            (
                "password:\n  jwt=eyJhbGciOi.eyJzdWIi.sig=",
                "password:\n  [redacted]",
            ),
            ("api_key:\n  Key=AAA=:", "api_key:\n  [redacted]"),
        ];
        let bad = mismatches(&rows);
        assert!(
            bad.is_empty(),
            "(input, expected, actual) is wrong: {bad:#?}"
        );
    }

    /// A padded base64 credential on the line after a standard secret key is the
    /// key's value, whatever its length and whichever key: the whole credential
    /// is masked and nothing of it is left in the clear.
    #[test]
    fn scrub_text_masks_a_padded_base64_credential_on_the_next_line() {
        let mut checked = 0;
        for (parent, credential) in padded_credentials() {
            let input = format!("{parent}:\n  {credential}");
            let expected = format!("{parent}:\n  [redacted]");
            let actual = scrub_text(&input);
            assert!(
                actual == expected,
                "a padded credential was not masked whole: {input:?} gave {actual:?}"
            );
            checked += 1;
        }
        assert_eq!(checked, 5_000, "the generator changed its count");
    }

    /// The closing quote of a masked quoted value is not an opening quote: the
    /// text that follows it is scanned as it always was, so a `sid:` inside the
    /// quotes is part of the masked value and the quote after it ends that value.
    #[test]
    fn scrub_text_does_not_read_the_closing_quote_of_a_masked_value_as_an_opener() {
        let rows = [
            (
                "token=\"sid: \" tail=\"x\"",
                "token=\"[redacted]\" tail=\"x\"",
            ),
            (
                "token=\"sid:\" tail=\"x\"",
                "token=\"[redacted]\" tail=\"x\"",
            ),
            (
                "token=\"a sid:\" tail=\"x\"",
                "token=\"[redacted]\" tail=\"x\"",
            ),
            (
                "x=1&token='auth='&y=\"z\"",
                "x=1&token='[redacted]'&y=\"z\"",
            ),
            ("x=1&token=\"sid:\t\"\ny=2", "x=1&token=\"[redacted]\"\ny=2"),
        ];
        let bad = mismatches(&rows);
        assert!(
            bad.is_empty(),
            "(input, expected, actual) is wrong: {bad:#?}"
        );
    }

    /// A secret key whose value is another secret key's label, with the child's
    /// own value after it: the parent masks the label and the child masks its
    /// value, whichever parent and whichever blank layout lies between them.
    #[test]
    fn scrub_text_masks_a_credential_nested_under_a_secret_parent() {
        const PARENTS: [&str; 11] = [
            "auth",
            "credentials",
            "secret",
            "token",
            "session",
            "cookie",
            "password",
            "sid",
            "jwt",
            "csrf",
            "api_key",
        ];
        const LAYOUTS: [&str; 6] = ["\n  ", "\r\n  ", "\n\t", "\r  ", "\u{c}  ", "\n    "];
        let mut owned: Vec<(String, String)> = Vec::new();
        for parent in PARENTS {
            for layout in LAYOUTS {
                owned.push((
                    format!("{parent}:{layout}password: hunter2"),
                    format!("{parent}:{layout}[redacted] [redacted]"),
                ));
            }
        }
        owned.push((
            "token:\r\n\tsid: S1".to_string(),
            "token:\r\n\t[redacted] [redacted]".to_string(),
        ));
        owned.push((
            "session:\n  csrf: C9".to_string(),
            "session:\n  [redacted] [redacted]".to_string(),
        ));
        assert!(owned.len() >= 68, "the table lost rows: {}", owned.len());
        let rows: Vec<(&str, &str)> = owned
            .iter()
            .map(|(input, expected)| (input.as_str(), expected.as_str()))
            .collect();
        let bad = mismatches(&rows);
        assert!(
            bad.is_empty(),
            "(input, expected, actual) is wrong: {bad:#?}"
        );
    }

    /// The nested credential is masked in every form a pair takes: quoted keys,
    /// a separator with blanks before it, a value on its own line, a quoted
    /// value, and a run of empty lines between the parent and the child.
    #[test]
    fn scrub_text_masks_a_nested_credential_in_every_separator_and_quote_form() {
        let rows = [
            (
                "\"auth\":\n  \"password\": \"x\"",
                "\"auth\":\n  \"[redacted]\": \"[redacted]\"",
            ),
            (
                "'auth':\n  'password' : 'x y'",
                "'auth':\n  '[redacted]' : '[redacted]'",
            ),
            ("auth: password: hunter2", "auth: [redacted] [redacted]"),
            (
                "auth:\n  password :   hunter2",
                "auth:\n  [redacted] :   [redacted]",
            ),
            (
                "auth:\n  password:\n    hunter2",
                "auth:\n  [redacted]\n    [redacted]",
            ),
            (
                "auth:\n  password: 'hunter2'",
                "auth:\n  [redacted] '[redacted]'",
            ),
            (
                "auth:\n\n\n\n\n  password: x",
                "auth:\n\n\n\n\n  [redacted] [redacted]",
            ),
        ];
        let bad = mismatches(&rows);
        assert!(
            bad.is_empty(),
            "(input, expected, actual) is wrong: {bad:#?}"
        );
    }

    /// A chain of secret keys, each the value of the one before it: every pair
    /// of the chain is read, so the last key in it masks its own value too.
    #[test]
    fn scrub_text_reads_every_pair_of_a_chain_of_secret_keys() {
        let rows = [
            (
                "token:\n  sid:\n  password: hunter2",
                "token:\n  [redacted]\n  [redacted] [redacted]",
            ),
            (
                "auth:\n  secret:\n    password: hunter2",
                "auth:\n  [redacted]\n    [redacted] [redacted]",
            ),
            (
                "auth:\n  token:\n    secret:\n      password: hunter2",
                "auth:\n  [redacted]\n    [redacted]\n      [redacted] [redacted]",
            ),
            (
                "auth:\n  password:\n  sid=abc",
                "auth:\n  [redacted]\n  [redacted]",
            ),
            (
                "auth:\n  secret:\n    \"password\": \"x\"",
                "auth:\n  [redacted]\n    \"[redacted]\": \"[redacted]\"",
            ),
            ("sid:\nsid:\nsid:\n", "sid:\n[redacted]\n[redacted]\n"),
        ];
        let bad = mismatches(&rows);
        assert!(
            bad.is_empty(),
            "(input, expected, actual) is wrong: {bad:#?}"
        );
    }

    /// A padded base64 credential on the line after a nested pair's key is that
    /// key's value, whatever its length: it is masked whole and nothing of it is
    /// left in the clear.
    #[test]
    fn scrub_text_masks_a_padded_base64_credential_under_a_nested_pair() {
        let mut checked = 0;
        for (_, credential) in padded_credentials() {
            let input = format!("auth:\n  password:\n    {credential}");
            let expected = "auth:\n  [redacted]\n    [redacted]";
            let actual = scrub_text(&input);
            assert!(
                actual == expected,
                "a padded credential under a nested pair was not masked whole: {input:?} gave {actual:?}"
            );
            checked += 1;
        }
        assert_eq!(checked, 5_000, "the generator changed its count");
    }

    /// Nested pairs over inputs of a megabyte and more: the scan reads each byte
    /// a constant number of times, so these finish, and each comes out as the
    /// scan's rules say.
    #[test]
    fn scrub_text_stays_linear_on_nested_pair_shapes() {
        // A parent and a child on every other line.
        let input = "auth:\n  password: x\n".repeat(50_000);
        assert!(
            scrub_text(&input) == "auth:\n  [redacted] [redacted]\n".repeat(50_000),
            "nested pairs on consecutive lines were not masked"
        );

        // A bare secret key on every line: each is the value of the one before.
        let input = "sid:\n".repeat(100_000);
        assert!(
            scrub_text(&input) == "sid:\n".to_string() + &"[redacted]\n".repeat(99_999),
            "a column of bare secret keys was not masked line by line"
        );

        let input = "password:\n password:\n".repeat(50_000);
        assert!(
            scrub_text(&input)
                == "password:\n [redacted]\n".to_string()
                    + &"[redacted]\n [redacted]\n".repeat(49_999),
            "a column of indented secret keys was not masked line by line"
        );

        // Half a million empty lines between a parent and its child.
        let breaks = "\n".repeat(1 << 19);
        let input = format!("auth:{breaks}  password: x");
        assert!(
            scrub_text(&input) == format!("auth:{breaks}  [redacted] [redacted]"),
            "a child after half a million empty lines was not masked"
        );

        // A quoted value that holds a million key-like words and no closing quote
        // until the end.
        let input = format!("token=\"{}\"", "a=".repeat(1 << 20));
        assert!(
            scrub_text(&input) == "token=\"[redacted]\"",
            "a quoted value full of key-like words was not masked whole"
        );

        // Two hundred thousand openers of a quoted value, one closing quote.
        let input = format!("{}x\"", "sid:\"".repeat(200_000));
        assert!(
            scrub_text(&input) == "sid:\"[redacted]\"",
            "a run of quoted-value openers was not masked as one value"
        );

        // A masked quoted value with a secret-looking word inside, repeated.
        let input = "token=\"sid: \" tail=\"x\" ".repeat(100_000);
        assert!(
            scrub_text(&input) == "token=\"[redacted]\" tail=\"x\" ".repeat(100_000),
            "repeated quoted values with a key-like word inside were not masked"
        );
    }

    /// Under the wide reading the first token after a secret key is its value on
    /// the next line too, so a wide-only key masks the line after it.
    #[test]
    fn scrub_text_wide_masks_a_next_line_credential_under_a_wide_only_parent() {
        let rows = [
            ("userSession:\n  S3SS10N9", "userSession:\n  [redacted]"),
            ("sidebar:\nS3SS10N9", "sidebar:\n[redacted]"),
            ("author:\nJohn", "author:\n[redacted]"),
            ("sessionKey:\n  abc123", "sessionKey:\n  [redacted]"),
            ("userSession:\r\n\tS3SS10N9", "userSession:\r\n\t[redacted]"),
            ("sidebar=\u{c}v", "sidebar=\u{c}[redacted]"),
            ("sidebar\n:v", "sidebar\n:[redacted]"),
        ];
        let bad = mismatches_wide(&rows);
        assert!(
            bad.is_empty(),
            "(input, expected, actual) is wrong: {bad:#?}"
        );
    }

    /// Under the wide reading a wide-only key nested under a standard secret key
    /// is read as a pair too: the parent takes its label and it masks its value.
    #[test]
    fn scrub_text_wide_masks_a_wide_only_pair_nested_under_a_standard_parent() {
        let rows = [
            (
                "auth:\n  sessionKey: abc123",
                "auth:\n  [redacted] [redacted]",
            ),
            ("auth: sessionKey: abc123", "auth: [redacted] [redacted]"),
            (
                "jwt:\n\tsidebar :  \"Q\"",
                "jwt:\n\t[redacted] :  \"[redacted]\"",
            ),
            (
                "Credentials:\n\tjwt:\n\tsidebar :  \"Q\"",
                "Credentials:\n\t[redacted]\n\t[redacted] :  \"[redacted]\"",
            ),
        ];
        let bad = mismatches_wide(&rows);
        assert!(
            bad.is_empty(),
            "(input, expected, actual) is wrong: {bad:#?}"
        );
    }

    // ---- Tester additions: the edges a pair that begins inside a masked value has
    // ---- to survive. A text cut short, a text of a mebibyte and more, a value or a
    // ---- key that is not ASCII, and a quote at the end of the text.

    /// How many copies of `unit` make a text of at least one mebibyte and at most
    /// two (`1 << 21` bytes). The count is clamped here, before any `repeat`, so no
    /// hostile family is smaller than the size at which a quadratic scan shows and
    /// none is larger than the bound these tests keep.
    fn mebibyte_copies(unit: &str) -> usize {
        const FLOOR: usize = 1 << 20;
        const CEILING: usize = 1 << 21;
        assert!(
            !unit.is_empty() && unit.len() <= FLOOR,
            "a unit of {} bytes is out of range",
            unit.len()
        );
        (FLOOR / unit.len() + 1).min(CEILING / unit.len())
    }

    /// A connection that drops mid-stream hands over a prefix of the text. Cut at
    /// every char boundary, a text with a nested secret pair never makes either
    /// scrub panic and never leaves a character of the credential behind: every
    /// credential is a run of `Q`, and `Q` is nowhere else in a text. The whole text
    /// comes out as the rule says. The wide scrub also masks every run of a prefix
    /// that the standard scrub masks: the first scan of the wide scrub is not the
    /// standard scrub, so this is checked here and not implied.
    #[test]
    fn scrub_text_masks_a_nested_credential_on_every_prefix_of_the_text() {
        // Standard keys: both scrubs read these the same way.
        let standard: &[(&str, &str)] = &[
            ("auth:\n  password: QQQQ", "auth:\n  [redacted] [redacted]"),
            (
                "credentials:\r\n\tsecret: QQQQ",
                "credentials:\r\n\t[redacted] [redacted]",
            ),
            (
                "\"auth\":\n  \"password\": \"QQQQ\"",
                "\"auth\":\n  \"[redacted]\": \"[redacted]\"",
            ),
            (
                "auth:\n  password :   QQQQ",
                "auth:\n  [redacted] :   [redacted]",
            ),
            (
                "auth:\n  password:\n    QQQQ",
                "auth:\n  [redacted]\n    [redacted]",
            ),
            (
                "auth:\n  token:\n    secret:\n      password: QQQQ",
                "auth:\n  [redacted]\n    [redacted]\n      [redacted] [redacted]",
            ),
            ("auth: password: QQQQ", "auth: [redacted] [redacted]"),
            (
                "token=\"sid: QQQQ\" tail=\"x\"",
                "token=\"[redacted]\" tail=\"x\"",
            ),
            (
                "auth:\n  password: \u{e9}QQQQ\u{1f600}",
                "auth:\n  [redacted] [redacted]",
            ),
        ];
        // Wide-only keys: only the wide scrub reads these.
        let wide: &[(&str, &str)] = &[
            ("userSession:\n  QQQQ", "userSession:\n  [redacted]"),
            ("sidebar:\nQQQQ", "sidebar:\n[redacted]"),
            (
                "auth:\n  sessionKey: QQQQ",
                "auth:\n  [redacted] [redacted]",
            ),
            (
                "Credentials:\n\tjwt:\n\tsidebar :  \"QQQQ\"",
                "Credentials:\n\t[redacted]\n\t[redacted] :  \"[redacted]\"",
            ),
            (
                "authentication:\u{2009}\r\n\u{2009}jwt:\u{a0}QQQQ",
                "authentication:\u{2009}\r\n\u{2009}[redacted]\u{a0}[redacted]",
            ),
        ];

        let mut cuts = 0;
        let mut leaks: Vec<(usize, String)> = Vec::new();
        let mut not_a_superset: Vec<(String, Vec<&str>)> = Vec::new();
        for &(doc, whole) in standard {
            assert!(scrub_text(doc) == whole, "standard whole text: {doc:?}");
            assert!(scrub_text_wide(doc) == whole, "wide whole text: {doc:?}");
            for prefix in prefixes(doc) {
                cuts += 1;
                for out in [scrub_text(prefix), scrub_text_wide(prefix)] {
                    if out.contains('Q') {
                        leaks.push((prefix.len(), out));
                    }
                }
                let (_, left) = runs_left_by_wide(prefix);
                if !left.is_empty() {
                    not_a_superset.push((prefix.to_string(), left));
                }
            }
        }
        for &(doc, whole) in wide {
            assert!(scrub_text_wide(doc) == whole, "wide whole text: {doc:?}");
            for prefix in prefixes(doc) {
                cuts += 1;
                let out = scrub_text_wide(prefix);
                if out.contains('Q') {
                    leaks.push((prefix.len(), out));
                }
            }
        }
        assert!(cuts >= 300, "the documents are too short: {cuts} cuts");
        assert!(leaks.is_empty(), "a credential survived a cut: {leaks:#?}");
        assert!(
            not_a_superset.is_empty(),
            "(prefix, runs scrub_text masks that scrub_text_wide leaves): {not_a_superset:#?}"
        );
    }

    /// The two ends of the text, an empty value, and the places a non-ASCII
    /// character can sit beside a nested pair, read the standard way and the wide
    /// way alike. Each row follows from the scan's rules (a masked value, a pair
    /// that begins inside it, a value that would start inside the masked text or at
    /// its closing quote is no value), not from a recording.
    #[test]
    fn scrub_text_reads_the_edges_of_a_nested_pair() {
        let rows: &[(&str, &str)] = &[
            // Nothing at all, and a key the text ends on or just after.
            ("", ""),
            ("auth:", "auth:"),
            ("auth:\n  password", "auth:\n  [redacted]"),
            ("auth:\n  password:", "auth:\n  [redacted]"),
            ("auth:\n  password: ", "auth:\n  [redacted] "),
            ("auth:\n  password:\n", "auth:\n  [redacted]\n"),
            ("auth:\n  password: x", "auth:\n  [redacted] [redacted]"),
            // A nested value that is one non-ASCII character of two and four
            // bytes, and one that mixes them.
            (
                "auth:\n  password: \u{e9}t\u{e9}",
                "auth:\n  [redacted] [redacted]",
            ),
            (
                "auth:\n  password: \u{1f600}",
                "auth:\n  [redacted] [redacted]",
            ),
            // Non-ASCII blanks between the parent and the child, and in front of
            // the child's key, and a non-ASCII letter in the child's key.
            (
                "auth:\n\u{a0}password:\u{a0}hunter2",
                "auth:\n\u{a0}[redacted]\u{a0}[redacted]",
            ),
            (
                "auth:\u{2028}password: x",
                "auth:\u{2028}[redacted] [redacted]",
            ),
            (
                "auth:\n  \u{e9}password: x",
                "auth:\n  [redacted] [redacted]",
            ),
            // The closing quote of a masked value is not read as an opener when a
            // blank or the end of the text follows it.
            ("token=\"sid:\"", "token=\"[redacted]\""),
            ("token=\"sid:\" ", "token=\"[redacted]\" "),
            // A quote that a value character follows is shaped like an opener (the
            // malformed-quote residual of the spec), so the value of the pair before
            // it ends there and the nested `sid:` takes the next token as its own.
            // ASCII or not, one more token is masked, none is exposed, and the text
            // is cut on char boundaries.
            ("token=\"sid:\"x", "token=\"[redacted]\"[redacted]"),
            ("token=\"sid:\"\u{e9}", "token=\"[redacted]\"[redacted]"),
            ("token=\"sid:\"\u{1f600}", "token=\"[redacted]\"[redacted]"),
            // A quote that never closes: the plain value rule, and the nested key
            // inside it finds no value after it.
            ("token=\"sid:", "token=\"[redacted]"),
            ("token=\"", "token=\""),
            ("token=\"sid: x", "token=\"[redacted] [redacted]"),
            // A run of openers with one closing quote is one masked value.
            ("sid:\"sid:\"sid:\"x\"", "sid:\"[redacted]\""),
        ];
        let bad = mismatches(rows);
        assert!(
            bad.is_empty(),
            "(input, expected, actual) is wrong: {bad:#?}"
        );
        // None of these rows has a wide-only key, so the wide scrub reads them the
        // same way.
        let bad = mismatches_wide(rows);
        assert!(
            bad.is_empty(),
            "wide: (input, expected, actual) is wrong: {bad:#?}"
        );
    }

    /// A quote that is unmatched, or that closes with the other quote character,
    /// around a nested credential: the credential is still masked, and neither scrub
    /// panics, whichever cut the text takes.
    #[test]
    fn scrub_text_masks_a_nested_credential_after_a_malformed_quote() {
        let docs = [
            "auth:\n  password: \"QQQQ",
            "auth:\n  password: 'QQQQ\" x",
            "auth:\n  password: QQQQ\0",
            "\"auth:\n  password: QQQQ",
        ];
        let mut cuts = 0;
        let mut leaks: Vec<(usize, String)> = Vec::new();
        for doc in docs {
            for prefix in prefixes(doc) {
                cuts += 1;
                for out in [scrub_text(prefix), scrub_text_wide(prefix)] {
                    if out.contains('Q') {
                        leaks.push((prefix.len(), out));
                    }
                }
            }
        }
        assert!(cuts >= 80, "the documents are too short: {cuts} cuts");
        assert!(leaks.is_empty(), "a credential survived: {leaks:#?}");
    }

    /// The families of `scrub_text_stays_linear_on_nested_pair_shapes` that come
    /// out under a mebibyte (the spec asks for one or more), at a mebibyte or more
    /// and never more than two, through both scrubs, with the exact output the rule
    /// gives. A scan that reads a masked value again for each nested key does not
    /// finish.
    #[test]
    fn scrub_text_stays_linear_on_nested_pair_shapes_of_a_mebibyte_or_more() {
        // A parent and a child on every other line.
        let unit = "auth:\n  password: x\n";
        let n = mebibyte_copies(unit);
        let input = unit.repeat(n);
        let expected = "auth:\n  [redacted] [redacted]\n".repeat(n);
        assert!(input.len() >= 1 << 20 && input.len() <= 1 << 21);
        assert!(
            scrub_text(&input) == expected,
            "a nested pair on every other line was not masked"
        );
        assert!(
            scrub_text_wide(&input) == expected,
            "wide: a nested pair on every other line was not masked"
        );

        // A bare secret key on every line: each is the value of the one before.
        let unit = "sid:\n";
        let n = mebibyte_copies(unit);
        let input = unit.repeat(n);
        let expected = "sid:\n".to_string() + &"[redacted]\n".repeat(n - 1);
        assert!(input.len() >= 1 << 20 && input.len() <= 1 << 21);
        assert!(
            scrub_text(&input) == expected,
            "a column of bare secret keys was not masked line by line"
        );
        assert!(
            scrub_text_wide(&input) == expected,
            "wide: a column of bare secret keys was not masked line by line"
        );

        let unit = "password:\n password:\n";
        let n = mebibyte_copies(unit);
        let input = unit.repeat(n);
        let expected =
            "password:\n [redacted]\n".to_string() + &"[redacted]\n [redacted]\n".repeat(n - 1);
        assert!(input.len() >= 1 << 20 && input.len() <= 1 << 21);
        assert!(
            scrub_text(&input) == expected,
            "a column of indented secret keys was not masked line by line"
        );

        // A mebibyte of empty lines between a parent and its child.
        let breaks = "\n".repeat(1 << 20);
        let input = format!("auth:{breaks}  password: x");
        assert!(
            scrub_text(&input) == format!("auth:{breaks}  [redacted] [redacted]"),
            "a child after a mebibyte of empty lines was not masked"
        );
        assert!(
            scrub_text_wide(&input) == format!("auth:{breaks}  [redacted] [redacted]"),
            "wide: a child after a mebibyte of empty lines was not masked"
        );

        // A quoted value that holds half a million key-like words, then one that
        // holds a secret-looking word, repeated.
        let words = "a=".repeat(mebibyte_copies("a="));
        let input = format!("token=\"{words}\"");
        assert!(
            scrub_text(&input) == "token=\"[redacted]\"",
            "a quoted value full of key-like words was not masked whole"
        );
        assert!(
            scrub_text_wide(&input) == "token=\"[redacted]\"",
            "wide: a quoted value full of key-like words was not masked whole"
        );
        let unit = "token=\"sid: \" tail=\"x\" ";
        let n = mebibyte_copies(unit);
        let input = unit.repeat(n);
        assert!(
            scrub_text(&input) == "token=\"[redacted]\" tail=\"x\" ".repeat(n),
            "repeated quoted values with a key-like word inside were not masked"
        );

        // Openers of a quoted value, then one closing quote.
        let unit = "sid:\"";
        let n = mebibyte_copies(unit);
        let input = format!("{}x\"", unit.repeat(n));
        assert!(
            scrub_text(&input) == "sid:\"[redacted]\"",
            "a run of quoted-value openers was not masked as one value"
        );
        assert!(
            scrub_text_wide(&input) == "sid:\"[redacted]\"",
            "wide: a run of quoted-value openers was not masked as one value"
        );
    }

    /// One nested key, and one blank run between a nested key and its separator,
    /// of a mebibyte each: the scan reads each once, and the credential after the
    /// key is masked as the rule says. The long key is ASCII once and non-ASCII
    /// once.
    #[test]
    fn scrub_text_reads_an_oversized_nested_key_and_blank_run() {
        let ascii = "k".repeat(1 << 20);
        let input = format!("auth:\n  {ascii}password: x");
        assert!(
            scrub_text(&input) == "auth:\n  [redacted] [redacted]",
            "a nested key of a mebibyte was not read"
        );
        assert!(
            scrub_text_wide(&input) == "auth:\n  [redacted] [redacted]",
            "wide: a nested key of a mebibyte was not read"
        );

        // `\u{e9}` is two bytes: this key is a mebibyte as well.
        let non_ascii = "\u{e9}".repeat(1 << 19);
        let input = format!("auth:\n  {non_ascii}password: x");
        assert!(
            scrub_text(&input) == "auth:\n  [redacted] [redacted]",
            "a non-ASCII nested key of a mebibyte was not read"
        );
        assert!(
            scrub_text_wide(&input) == "auth:\n  [redacted] [redacted]",
            "wide: a non-ASCII nested key of a mebibyte was not read"
        );

        // The parent's value is `password`; the child is that same key with a
        // mebibyte of blanks before its separator.
        let blanks = " ".repeat(1 << 20);
        let input = format!("auth:\n  password{blanks}: x");
        let expected = format!("auth:\n  [redacted]{blanks}: [redacted]");
        assert!(
            scrub_text(&input) == expected,
            "a nested key with a mebibyte of blanks before its separator was not read"
        );
        assert!(
            scrub_text_wide(&input) == expected,
            "wide: a nested key with a mebibyte of blanks before its separator was not read"
        );
    }
}
