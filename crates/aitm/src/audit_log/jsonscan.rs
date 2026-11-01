//! The writer's pass over `args` (spec Design 14.5), the one field that is JSON
//! text.
//!
//! `args` reaches the writer as the text the source rendered, cut at 512 bytes,
//! or as whatever a caller of the ring hook wrote. A plain-text scrubber must
//! never run over it: a line break is the two characters `\r\n` there and a value
//! is followed by `"}`, so the scrubber reads a mask such as
//! `Authorization: [redacted]` to the end of the text and rewrites honest
//! entries (Design 14.0). So the pass has three steps, by what the text is:
//!
//! 1. **It parses as JSON**: the source's own function, [`redact_value`] (rules
//!    S and D and the leaf text pass), and the result is rendered. The file can
//!    never be less strict than the ring.
//! 2. **It does not parse**, because the cap cut it or because it is not complete
//!    JSON: the tolerant scan below.
//! 3. **The scan gives up**, because something other than JSON structure is
//!    outside a string literal: the whole text is plain text and goes through
//!    `scrub_strict`, which is right for ` password=x`.
//!
//! # The tolerant scan
//!
//! It walks the text byte by byte, once, with a loop and no recursion (hostile
//! nesting cannot reach the stack, and the work is linear). Outside a string
//! literal it accepts only the JSON structure characters `{ } [ ] , :`, JSON
//! blanks, number characters (digits and `+ - . e E`) and the words `true`,
//! `false` and `null`; none of these is ever changed, so what parsed before the
//! scan still parses. Anything else gives up.
//!
//! Inside a literal the content is decoded (`\" \\ \/ \b \f \n \r \t`, `\uXXXX`
//! and surrogate pairs), passed through `scrub_strict` and written back with the
//! escaping `serde_json` uses, so a literal `serde_json` wrote comes back byte
//! for byte. A literal cut off by the end of the text is decoded as far as it
//! goes, and an escape the end of the text cut in half is dropped. A closed
//! literal followed (after blanks) by `:` is a key; when the strict vocabulary
//! names it, the literal that follows the colon is replaced by `"<redacted>"` (a
//! cut one by `"<redacted>`, with no closing quote). A number, a word or a
//! container under a secret key is not masked, and the literal after it is not
//! touched: Residual risks 17 says so.
//!
//! **The cap marker.** The source cuts at 512 bytes and appends `…` after the
//! cut. When the cut falls in a literal the marker is that literal's last
//! character, but when it falls after a `,`, in a number or in a word the marker
//! sits outside every literal, and the letter of the scan above would give up
//! and run the plain-text pass over JSON text, which is the defect this module
//! exists to avoid. So one trailing `…` is set aside before the scan and put
//! back after, as the registry's fragment mask sets it aside (plan Ambiguity 15),
//! and a word that is the start of `true`, `false` or `null` and runs to the end
//! of the text is the word the cut interrupted.

use aitm_core::redact_strict::{is_secret_key_strict, scrub_strict};
use aitm_mcp::redact_args::redact_value;
use serde_json::Value;

use super::registry::CUT_MARK;

/// What replaces the value of a secret-named key: the literal the source writes
/// for it (`aitm_mcp::redact_args` keeps its own copy private; a test compares
/// the two).
const KEY_REDACTED: &str = "<redacted>";

/// The words a JSON text may hold outside a string literal.
const WORDS: [&str; 3] = ["true", "false", "null"];

/// The `args` text of an entry as the file keeps it: the pass of the module
/// documentation, parse first, then the tolerant scan, then plain text.
pub(crate) fn redact_args_text(text: &str) -> String {
    if let Ok(value) = serde_json::from_str::<Value>(text) {
        return redact_value(&value).to_string();
    }
    scan_json_text(text).unwrap_or_else(|| scrub_strict(text))
}

/// Where the scan is in a `"key": "value"` pair.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Pair {
    /// Not after a secret key.
    Idle,
    /// A secret key's literal was just read: a colon makes the next literal its
    /// value.
    Named,
    /// The colon of a secret key was read: the next literal is its value and is
    /// hidden. Anything else that comes first (a number, a word, a container, a
    /// comma) ends it.
    Hide,
}

/// The tolerant scan of the module documentation, or `None` when the text holds
/// something other than JSON structure outside a string literal (the caller then
/// treats the whole text as plain).
fn scan_json_text(text: &str) -> Option<String> {
    let (body, marker) = match text.strip_suffix(CUT_MARK) {
        Some(body) => (body, CUT_MARK),
        None => (text, ""),
    };
    let bytes = body.as_bytes();
    let mut out = String::with_capacity(body.len() + body.len() / 8 + marker.len());
    let mut pair = Pair::Idle;
    let mut at = 0;
    while let Some(&byte) = bytes.get(at) {
        match byte {
            b' ' | b'\t' | b'\n' | b'\r' => {
                out.push(char::from(byte));
                at += 1;
            }
            b'{' | b'[' | b',' | b'}' | b']' => {
                out.push(char::from(byte));
                at += 1;
                pair = Pair::Idle;
            }
            b':' => {
                out.push(':');
                at += 1;
                pair = if pair == Pair::Named {
                    Pair::Hide
                } else {
                    Pair::Idle
                };
            }
            b'"' => at = literal(body, at, &mut pair, &mut out),
            b'0'..=b'9' | b'+' | b'-' | b'.' | b'e' | b'E' => {
                let end = run_end(bytes, at, is_number_byte);
                out.push_str(body.get(at..end)?);
                at = end;
                pair = Pair::Idle;
            }
            b'a'..=b'z' | b'A'..=b'Z' => {
                let end = run_end(bytes, at, |b| b.is_ascii_alphabetic());
                let word = body.get(at..end)?;
                if !is_json_word(word, end == bytes.len()) {
                    return None;
                }
                out.push_str(word);
                at = end;
                pair = Pair::Idle;
            }
            _ => return None,
        }
    }
    out.push_str(marker);
    Some(out)
}

/// The index after the run of bytes from `from` that satisfy `keep`.
fn run_end(bytes: &[u8], from: usize, keep: fn(u8) -> bool) -> usize {
    let rest = bytes.get(from..).unwrap_or_default();
    from + rest.iter().take_while(|b| keep(**b)).count()
}

fn is_number_byte(byte: u8) -> bool {
    byte.is_ascii_digit() || matches!(byte, b'+' | b'-' | b'.' | b'e' | b'E')
}

/// Whether `word` is `true`, `false` or `null`, or, at the end of the text, the
/// start of one: the word a cut interrupted.
fn is_json_word(word: &str, at_end: bool) -> bool {
    WORDS
        .iter()
        .any(|known| *known == word || (at_end && known.starts_with(word)))
}

/// Reads the string literal that opens at `start` (a quote), appends it to `out`
/// as the pass keeps it, updates `pair`, and returns the index after it.
fn literal(body: &str, start: usize, pair: &mut Pair, out: &mut String) -> usize {
    let (content, closed, next) = decode_literal(body, start);
    out.push('"');
    if *pair == Pair::Hide {
        out.push_str(KEY_REDACTED);
        *pair = Pair::Idle;
    } else {
        push_encoded(out, &scrub_strict(&content));
        *pair = if closed && colon_follows(body.as_bytes(), next) && is_secret_key_strict(&content)
        {
            Pair::Named
        } else {
            Pair::Idle
        };
    }
    if closed {
        out.push('"');
    }
    next
}

/// Whether the next byte that is not a JSON blank, from `from` on, is a colon.
fn colon_follows(bytes: &[u8], from: usize) -> bool {
    let blanks = run_end(bytes, from, |b| matches!(b, b' ' | b'\t' | b'\n' | b'\r'));
    bytes.get(blanks) == Some(&b':')
}

/// `text` written the way `serde_json` writes the inside of a string.
fn push_encoded(out: &mut String, text: &str) {
    // `to_string` cannot fail for a `str`; were it to, the content is dropped,
    // which hides text and never shows it.
    let encoded = serde_json::to_string(text).unwrap_or_default();
    let inside = encoded
        .strip_prefix('"')
        .and_then(|rest| rest.strip_suffix('"'));
    out.push_str(inside.unwrap_or_default());
}

/// The decoded content of the literal that opens at `start`, whether its closing
/// quote was found, and the index after it (or the end of the text).
fn decode_literal(body: &str, start: usize) -> (String, bool, usize) {
    let bytes = body.as_bytes();
    let mut content = String::new();
    let mut at = start + 1;
    loop {
        // A run with no quote and no backslash is copied whole. Both ends of the
        // run are ASCII bytes or the ends of the text, so the slice is valid.
        let run = bytes.get(at..).unwrap_or_default();
        let len = run
            .iter()
            .position(|b| *b == b'"' || *b == b'\\')
            .unwrap_or(run.len());
        content.push_str(body.get(at..at + len).unwrap_or_default());
        at += len;
        match bytes.get(at) {
            None => return (content, false, at),
            Some(b'"') => return (content, true, at + 1),
            Some(_) => {}
        }
        match escape(bytes, at) {
            Escape::Char(c, used) => {
                content.push(c);
                at += used;
            }
            Escape::Raw(used) => {
                content.push_str(body.get(at..at + used).unwrap_or_default());
                at += used;
            }
            Escape::Cut => return (content, false, bytes.len()),
        }
    }
}

/// What a backslash in a literal stands for.
enum Escape {
    /// The character, and how many bytes the escape took.
    Char(char, usize),
    /// Not an escape: the next `n` bytes (the backslash, and a `\u` with the
    /// hex digits before the bad one) are kept as the text they are.
    Raw(usize),
    /// The end of the text cut the escape in half: it is dropped.
    Cut,
}

/// The escape that starts with the backslash at `at`.
fn escape(bytes: &[u8], at: usize) -> Escape {
    let one = |c: char| Escape::Char(c, 2);
    match bytes.get(at + 1) {
        None => Escape::Cut,
        Some(b'"') => one('"'),
        Some(b'\\') => one('\\'),
        Some(b'/') => one('/'),
        Some(b'b') => one('\u{8}'),
        Some(b'f') => one('\u{c}'),
        Some(b'n') => one('\n'),
        Some(b'r') => one('\r'),
        Some(b't') => one('\t'),
        Some(b'u') => unicode_escape(bytes, at),
        Some(_) => Escape::Raw(1),
    }
}

/// Four hex digits read from `from`.
enum Hex {
    Value(u32),
    /// The text ended first.
    Short,
    /// A byte that is not a hex digit came after this many that were.
    Bad(usize),
}

fn hex4(bytes: &[u8], from: usize) -> Hex {
    let mut value = 0;
    for offset in 0..4 {
        let Some(&byte) = bytes.get(from + offset) else {
            return Hex::Short;
        };
        let Some(digit) = char::from(byte).to_digit(16) else {
            return Hex::Bad(offset);
        };
        value = value * 16 + digit;
    }
    Hex::Value(value)
}

/// The `\uXXXX` escape that starts at `at`. A surrogate pair is one character; a
/// surrogate with no partner becomes U+FFFD.
fn unicode_escape(bytes: &[u8], at: usize) -> Escape {
    match hex4(bytes, at + 2) {
        Hex::Short => Escape::Cut,
        Hex::Bad(good) => Escape::Raw(2 + good),
        Hex::Value(unit @ 0xd800..=0xdbff) => match low_surrogate(bytes, at + 6) {
            Some(low) => {
                let code = 0x10000 + ((unit - 0xd800) << 10) + (low - 0xdc00);
                Escape::Char(char::from_u32(code).unwrap_or('\u{fffd}'), 12)
            }
            None => Escape::Char('\u{fffd}', 6),
        },
        Hex::Value(0xdc00..=0xdfff) => Escape::Char('\u{fffd}', 6),
        Hex::Value(unit) => Escape::Char(char::from_u32(unit).unwrap_or('\u{fffd}'), 6),
    }
}

/// The low surrogate of a `\uXXXX` escape that starts at `from`, if one does.
fn low_surrogate(bytes: &[u8], from: usize) -> Option<u32> {
    if bytes.get(from) != Some(&b'\\') || bytes.get(from + 1) != Some(&b'u') {
        return None;
    }
    match hex4(bytes, from + 2) {
        Hex::Value(unit @ 0xdc00..=0xdfff) => Some(unit),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::time::{Duration, Instant};

    use aitm_core::redact_strict::scrub_strict;
    use aitm_mcp::redact_args::redact_value;
    use serde_json::{json, Value};

    /// Everything of `text` except the content of its string literals: the
    /// quotes stay, so a closed literal is `""` and a cut one is `"`. Two texts
    /// that agree here differ only inside literals, which is the promise of the
    /// scan: structure characters, blanks, numbers and words are never touched.
    fn outside_literals(text: &str) -> String {
        let mut out = String::new();
        let mut inside = false;
        let mut escaped = false;
        for c in text.chars() {
            if !inside {
                out.push(c);
                inside = c == '"';
            } else if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                out.push(c);
                inside = false;
            }
        }
        out
    }

    /// One failure line when `got` is not `want`.
    fn differ(row: &str, got: &str, want: &str) -> Option<String> {
        (got != want).then(|| format!("{row}: left: {got:?}, right: {want:?}"))
    }

    /// Fails with every collected row, so one run shows every defect.
    fn assert_no_failures(failures: Vec<String>) {
        assert!(
            failures.is_empty(),
            "{} row(s) failed:\n{}",
            failures.len(),
            failures.join("\n")
        );
    }

    /// The plan's extra test: over a list of cut and odd texts, a scan that gives a
    /// result changed only literal contents, and a text with something else
    /// outside a literal is given up (`None`, plain text for the caller).
    #[test]
    fn tolerant_scan_never_changes_structure() {
        let mut failures = Vec::new();
        for (row, text, scans) in [
            ("a cut string", r#"{"a":"abc"#, true),
            ("a cut key", r#"{"ab"#, true),
            ("a cut escape", r#"{"a":"x\u00"#, true),
            ("a lone backslash at the end", r#"{"a":"x\"#, true),
            ("nested arrays cut mid-element", r#"[[1,2],[3,"x"#, true),
            ("blanks everywhere", "[ 1 ,\n\t2 ,\r\n 3 ,", true),
            (
                "numbers and words",
                r#"{"a":1,"b":[true,false,null],"c":{"d":-1.5e3,"e":+2"#,
                true,
            ),
            ("a cut word, nothing after it", r#"{"a":tru"#, true),
            ("only structure", "[[[{{{", true),
            ("an empty text", "", true),
            ("an unquoted word gives up", r#"{"a": hello}"#, false),
            ("a word that is not a keyword", r#"[nul, 1]"#, false),
            ("a cut word followed by more", r#"{"a":tru,"b":1"#, false),
            ("text after a complete value", r#"{"a":1} trailing"#, false),
            (
                "a non-ASCII byte outside a literal",
                "{\"a\":1}\u{e9}",
                false,
            ),
            ("a control byte outside a literal", "{\"a\":1}\u{1}", false),
            ("plain text", "password=P1 x", false),
        ] {
            match (scan_json_text(text), scans) {
                (Some(out), true) => {
                    let (kept, was) = (outside_literals(&out), outside_literals(text));
                    if kept != was {
                        failures.push(format!("{row}: structure changed: {out:?} for {text:?}"));
                    }
                }
                (None, false) => {}
                (got, _) => failures.push(format!("{row}: expected scans={scans}, got {got:?}")),
            }
        }
        assert_eq!(
            redact_args_text("{\"a\": hello password=P1}"),
            "{\"a\": hello password=[redacted]}",
            "text the scan gives up on is plain text"
        );
        assert_no_failures(failures);
    }

    /// Design 14.5: a literal is decoded, passed through the strict text pass and
    /// encoded the way `serde_json` encodes, so what `serde_json` wrote comes
    /// back byte for byte, and what it did not write comes back in its form.
    #[test]
    fn a_literal_is_encoded_the_way_serde_json_encodes_it() {
        let mut failures = Vec::new();
        // Contents `serde_json` itself writes: every one must come back as it was.
        for content in [
            "plain",
            "say \"hi\" and \\ back",
            "line\nbreak and\ttab and\r\n",
            "bell \u{7} and unit separator \u{1f} and NUL \u{0}",
            "héllo wörld, 日本語, \u{1f600}",
            "DEL \u{7f} and CSI \u{9b} and \u{2028}",
            "slash / and <angle> & amp",
            "",
        ] {
            let encoded = serde_json::to_string(content).unwrap_or_default();
            let cut = format!("{{\"a\":{encoded},\"b\":\"cut");
            if let Some(line) = differ(
                &format!("serde_json wrote {content:?}"),
                &redact_args_text(&cut),
                &cut,
            ) {
                failures.push(line);
            }
        }
        // Texts `serde_json` did not write: decoded, then written its way.
        for (row, text, want) in [
            (
                "escaped e-acute",
                r#"{"a":"\u00e9","b":"cut"#,
                "{\"a\":\"é\",\"b\":\"cut",
            ),
            (
                "escaped slash",
                r#"{"a":"a\/b","b":"cut"#,
                r#"{"a":"a/b","b":"cut"#,
            ),
            (
                "a surrogate pair",
                r#"{"a":"\ud83d\ude00","b":"cut"#,
                "{\"a\":\"\u{1f600}\",\"b\":\"cut",
            ),
            (
                "backspace and form feed",
                r#"{"a":"\b\f","b":"cut"#,
                r#"{"a":"\b\f","b":"cut"#,
            ),
            (
                "a lone high surrogate",
                r#"{"a":"x\ud83dy","b":"cut"#,
                "{\"a\":\"x\u{fffd}y\",\"b\":\"cut",
            ),
            (
                "a lone low surrogate",
                r#"{"a":"x\ude00y","b":"cut"#,
                "{\"a\":\"x\u{fffd}y\",\"b\":\"cut",
            ),
            (
                "an invalid escape keeps its backslash",
                r#"{"a":"x\qy","b":"cut"#,
                r#"{"a":"x\\qy","b":"cut"#,
            ),
            (
                "a bad unicode escape keeps its text",
                r#"{"a":"x\u12G4y","b":"cut"#,
                r#"{"a":"x\\u12G4y","b":"cut"#,
            ),
            (
                "an escape cut by the end of the text is dropped",
                r#"{"a":"x\u00"#,
                r#"{"a":"x"#,
            ),
            (
                "a high surrogate then half an escape",
                r#"{"a":"x\ud83d\ude"#,
                "{\"a\":\"x\u{fffd}",
            ),
            ("a lone backslash at the end", r#"{"a":"x\"#, r#"{"a":"x"#),
            (
                "a raw line break inside a literal is encoded",
                "{\"a\":\"x\ny\",\"b\":\"cut",
                r#"{"a":"x\ny","b":"cut"#,
            ),
        ] {
            if let Some(line) = differ(row, &redact_args_text(text), want) {
                failures.push(line);
            }
        }
        assert_no_failures(failures);
    }

    /// Design 14.5: a closed literal followed by a colon is a key, and when the
    /// strict vocabulary names it the literal that follows is hidden (a cut one
    /// as `"<redacted>` with no closing quote). Only that literal: a number, a
    /// word or a container under a secret key is not masked (Residual risks 17),
    /// and the literal after it is not touched.
    #[test]
    fn a_secret_key_hides_the_literal_that_follows_it() {
        let mut failures = Vec::new();
        for (row, text, want) in [
            (
                "the plan's row",
                r#"{"password":"SECRET54c","n":1"#,
                r#"{"password":"<redacted>","n":1"#,
            ),
            ("a cut value", r#"{"token":"abc"#, r#"{"token":"<redacted>"#),
            (
                "blanks around the colon stay",
                r#"{"Authorization" : "Bearer abc", "x":"y"#,
                r#"{"Authorization" : "<redacted>", "x":"y"#,
            ),
            (
                "a name only the strict vocabulary knows",
                r#"{"user":"u","pw":"x","other":"y"#,
                r#"{"user":"u","pw":"<redacted>","other":"y"#,
            ),
            (
                "a key written with an escape is decoded first",
                r#"{"pass\u0077ord":"v","k":"cut"#,
                r#"{"password":"<redacted>","k":"cut"#,
            ),
            (
                "a secret key in a nested object",
                r#"{"a":{"b":{"api_key":"K1","c":"keep"#,
                r#"{"a":{"b":{"api_key":"<redacted>","c":"keep"#,
            ),
            (
                "a number under a secret key is not masked",
                r#"{"password":1,"x":"keep"#,
                r#"{"password":1,"x":"keep"#,
            ),
            (
                "nor is a word",
                r#"{"password":true,"x":"keep"#,
                r#"{"password":true,"x":"keep"#,
            ),
            (
                "a number ends the pending hide, even with no comma after it",
                r#"{"password":1 "x":"keep"#,
                r#"{"password":1 "x":"keep"#,
            ),
            (
                "and so does a word",
                r#"{"password":true "x":"keep"#,
                r#"{"password":true "x":"keep"#,
            ),
            (
                "nor a container, and the next literal is not hidden",
                r#"{"password":{"a":"keep"#,
                r#"{"password":{"a":"keep"#,
            ),
            (
                "a secret word that is not a key",
                r#"["password","keep"#,
                r#"["password","keep"#,
            ),
            (
                "a secret word as a value",
                r#"{"note":"password","x":"keep"#,
                r#"{"note":"password","x":"keep"#,
            ),
            (
                "a secret key with nothing after it",
                r#"{"a":"b","password":"#,
                r#"{"a":"b","password":"#,
            ),
            (
                "a secret key cut before its colon",
                r#"{"a":"b","password""#,
                r#"{"a":"b","password""#,
            ),
            (
                "the key text is scrubbed too",
                r#"{"ghp_abcdefghijklmnopqrstuvwxyz0123456789":"v","k":"cut"#,
                r#"{"[redacted]":"v","k":"cut"#,
            ),
        ] {
            let got = redact_args_text(text);
            if let Some(line) = differ(row, &got, want) {
                failures.push(line);
            }
            if let Some(line) = differ(
                &format!("{row} (second pass)"),
                &redact_args_text(&got),
                &got,
            ) {
                failures.push(line);
            }
        }
        assert_no_failures(failures);
    }

    /// The source's cap marker (`…`, after the cut) is set aside before the scan
    /// and put back, so a text the cap cut outside a literal (after a comma, in a
    /// number, in a word) still scans, and the plain-text pass never runs over
    /// JSON text. Without this an honest entry the source cut after a `,` and
    /// that holds a mask such as `Authorization: [redacted]` would be rewritten:
    /// the plain-text pass reads the mask's line to the end of the text.
    #[test]
    fn a_text_cut_outside_a_literal_is_still_scanned() {
        let mut failures = Vec::new();
        let pad = "x".repeat(40);
        let mask = r#"{"a":"Authorization: [redacted]","b":""#;
        for (row, text) in [
            ("after a comma", format!("{mask}{pad}\",\u{2026}")),
            ("after a colon", format!("{mask}{pad}\":\u{2026}")),
            (
                "after an open brace",
                format!("{mask}{pad}\",\"c\":{{\u{2026}"),
            ),
            ("in a number", format!("{mask}{pad}\",\"c\":-12.5e\u{2026}")),
            ("in a word", format!("{mask}{pad}\",\"c\":fal\u{2026}")),
            ("inside a literal", format!("{mask}{pad}\u{2026}")),
            ("after a closed value", format!("{mask}{pad}\"\u{2026}")),
        ] {
            if let Some(line) = differ(row, &redact_args_text(&text), &text) {
                failures.push(line);
            }
        }
        for (row, text, scans) in [
            ("a marker after structure", "{\"a\":1,\u{2026}", true),
            ("a marker inside a cut literal", "{\"a\":\"x\u{2026}", true),
            ("a marker after a cut word", "{\"a\":tru\u{2026}", true),
            (
                "a marker that is not the last character",
                "{\"a\":1\u{2026},",
                false,
            ),
            ("a marker on plain text", "foo\u{2026}", false),
            (
                "two markers: only one is the cut",
                "{\"a\":1,\u{2026}\u{2026}",
                false,
            ),
        ] {
            let got = scan_json_text(text);
            if got.is_some() != scans {
                failures.push(format!("{row}: expected scans={scans}, got {got:?}"));
            }
        }
        assert_no_failures(failures);
    }

    /// Design 14.5: text that parses is handled by the source's own function,
    /// rules S and D included, and rendered as `serde_json` renders it.
    #[test]
    fn text_that_parses_goes_through_the_source_function() {
        let mut failures = Vec::new();
        for (row, text, want) in [
            (
                "rule D: an innocuous header name hides its value",
                r#"{"headers":{"X-Custom":"SECRET54e"}}"#,
                Some(r#"{"headers":{"X-Custom":"<redacted>"}}"#),
            ),
            (
                "the secret-key rule",
                r#"{"password":"SECRET54c","n":1}"#,
                Some(r#"{"n":1,"password":"<redacted>"}"#),
            ),
            (
                "rule S, a header pair",
                r#"{"h":["Cookie","foo=C"]}"#,
                Some(r#"{"h":["Cookie","<redacted>"]}"#),
            ),
            (
                "a text with nothing to hide",
                r#"{"a":[1,2,{"b":null}]}"#,
                None,
            ),
        ] {
            let got = redact_args_text(text);
            let parsed: Value = serde_json::from_str(text).unwrap_or(Value::Null);
            let source = redact_value(&parsed).to_string();
            // The source function is the one the call path ran, so the writer can
            // never be less strict than the ring.
            if let Some(line) = differ(&format!("{row}: the source function"), &got, &source) {
                failures.push(line);
            }
            if let Some(want) = want {
                // Compared as values: a build with `preserve_order` writes the
                // members in input order, one without in sorted order.
                let got: Value = serde_json::from_str(&got).unwrap_or(Value::Null);
                let want: Value = serde_json::from_str(want).unwrap_or(Value::Null);
                if got != want {
                    failures.push(format!("{row}: left: {got}, right: {want}"));
                }
            }
            if serde_json::from_str::<Value>(&got).is_err() {
                failures.push(format!("{row}: the result is not JSON: {got}"));
            }
        }
        assert_no_failures(failures);
    }

    /// Design 14.0, the defect that made the first version of the spec wrong: the
    /// plain-text scrubber over JSON text is not idempotent (the `Authorization`
    /// pass runs to a real line end, and JSON text has none). Honest text the
    /// source wrote, whole or cut, must come back unchanged, on the parse path
    /// and on the scan path alike.
    #[test]
    fn no_plain_text_pass_runs_over_json_text() {
        let mut failures = Vec::new();
        for (row, text) in [
            (
                "AC47 shape 1, whole",
                r#"{"note":"Authorization: [redacted]"}"#,
            ),
            (
                "AC47 shape 2, whole",
                r#"{"raw":"GET /\r\nCookie: [redacted]\r\nHost: x"}"#,
            ),
            (
                "shape 1 with a cut after it",
                r#"{"note":"Authorization: [redacted]","k":"v"#,
            ),
            (
                "shape 2 with a cut after it",
                r#"{"raw":"GET /\r\nCookie: [redacted]\r\nHost: x","k":1,"#,
            ),
            (
                "a Bearer mask in a cut text",
                r#"{"note":"Bearer [redacted] was refused","k":"#,
            ),
            (
                "a key mask in a cut text",
                r#"{"token":"<redacted>","other":"v"#,
            ),
        ] {
            if let Some(line) = differ(row, &redact_args_text(text), text) {
                failures.push(line);
            }
        }
        assert_no_failures(failures);
    }

    /// Design 14.5, AC47's writer half: what the source wrote for a call is a
    /// fixed point of the writer's pass. The list is local (the corpus does not
    /// exist for this task; its own test repeats this over its values). Each value
    /// is put through the source function, and the writer's pass must give that
    /// text back, whole, and cut at the source's cap after every character.
    #[test]
    fn what_the_source_wrote_is_a_fixed_point_of_the_writer_pass() {
        let long_note = "word ".repeat(150);
        let values = [
            json!({"policy": "auto"}),
            json!({}),
            json!({"note": "Authorization: Bearer SECRET47"}),
            json!({"raw": "GET /\r\nCookie: a=b; z=SECRET47\r\nHost: x"}),
            json!({"headers": {"Authorization": "Bearer C", "Accept": "text/html", "X-Custom": "C"}}),
            json!({"headers": [["Cookie", "foo=C"], ["Accept", "text/html"], ["X-Zed", "z"]]}),
            json!({"headers": [{"name": "Cookie", "value": "C"}, {"name": "Accept", "value": "text/html"}]}),
            json!({"pairs": [{"name": "Authorization", "value": "C"}], "entries": [["Set-Cookie", "C=1"]]}),
            json!({"a": {"b": {"request_headers": {"X-Zed": "C", "Host": "h.test"}}}}),
            json!({"edits": {"headers": {"X-Forwarded-Host": "evil.test", "X-Debug": "C"}}}),
            json!({"headers": {"Referer": "https://x.test/cb?token=C"}}),
            json!({"headers": {"X-N": 5}}),
            json!({"selector": "#password", "text": "C"}),
            json!({"selector": "#q", "text": "hello"}),
            json!({"vars": {"admin_pass": "C", "pw": "C", "target": "http://t.test", "user": "admin"}}),
            json!({"body": "{\"user\":\"u\",\"password\":\"C\"}"}),
            json!({"url": "https://user:C@host.test/p?access_token=C&page=2"}),
            json!({"note": "héllo wörld 日本語 \u{1f600} ✓", "n": [1, 2.5, -3, true, null]}),
            json!({"text": long_note}),
        ];
        let mut failures = Vec::new();
        for value in &values {
            let written = redact_value(value).to_string();
            if let Some(line) = differ(
                &format!("{value}: whole"),
                &redact_args_text(&written),
                &written,
            ) {
                failures.push(line);
            }
            if let Some(line) = differ(
                &format!("{value}: second source pass"),
                &redact_value(&serde_json::from_str(&written).unwrap_or(Value::Null)).to_string(),
                &written,
            ) {
                failures.push(line);
            }
        }
        assert_no_failures(failures);
    }

    /// The source cuts at 512 bytes and appends `…`. For a text with no mask at
    /// the cut (a mask cut in half is completed by the plain-text pass over its
    /// literal, which is the one way an honest cut text changes) the writer's
    /// pass gives the cut text back, wherever the cut falls: in a literal, in a
    /// number, in a word, after any structure character.
    #[test]
    fn a_text_cut_anywhere_by_the_cap_comes_back_unchanged() {
        let honest = json!({
            "a": 1,
            "b": [true, false, null, -1.5e3, {"c": "héllo wörld", "d": []}],
            "e": {"f": "x \"quoted\" y \\ z", "g": 12345},
            "h": "日本語 and \u{1f600}",
        })
        .to_string();
        let mut failures = Vec::new();
        for at in (1..honest.len()).filter(|at| honest.is_char_boundary(*at)) {
            let cut = format!("{}\u{2026}", honest.get(..at).unwrap_or_default());
            // A cut that falls inside an escape drops the half escape: the one
            // difference, and only where the previous byte is a backslash that
            // opens one.
            let inside_escape = honest.get(..at).is_some_and(|head| {
                let slashes = head.bytes().rev().take_while(|b| *b == b'\\').count();
                slashes % 2 == 1
            });
            let got = redact_args_text(&cut);
            if inside_escape {
                let want = format!("{}\u{2026}", honest.get(..at - 1).unwrap_or_default());
                if let Some(line) = differ(&format!("cut {at} inside an escape"), &got, &want) {
                    failures.push(line);
                }
            } else if let Some(line) = differ(&format!("cut at {at}"), &got, &cut) {
                failures.push(line);
            }
        }
        assert_no_failures(failures);
    }

    /// The hostile nesting shapes: far deeper than `serde_json` accepts.
    fn deep_texts() -> Vec<(&'static str, String)> {
        vec![
            ("open brackets", "[".repeat(200_000)),
            ("open objects", "{\"a\":".repeat(100_000)),
            (
                "nested then closed",
                format!("{}1{}", "[".repeat(100_000), "]".repeat(100_000)),
            ),
            (
                "a secret key at every level",
                "{\"password\":".repeat(50_000),
            ),
        ]
    }

    /// Hostile nesting must not exhaust the stack (plan ambiguity 22): the scan
    /// holds no stack of its own. It runs here on a thread with 128 KiB of stack,
    /// which a recursive scan of 100 000 levels cannot survive, and must give each
    /// text back as it was (nothing in it is a literal).
    #[test]
    fn deeply_nested_text_is_scanned_without_recursion() {
        let handle = std::thread::Builder::new()
            .name("deep-nesting".to_string())
            .stack_size(128 * 1024)
            .spawn(|| {
                let mut failures = Vec::new();
                for (row, text) in deep_texts() {
                    let got = scan_json_text(&text);
                    if got.as_deref() != Some(text.as_str()) {
                        failures.push(format!("{row}: the scan changed or refused the text"));
                    }
                }
                failures
            });
        let failures = match handle {
            Ok(handle) => handle
                .join()
                .unwrap_or_else(|_| vec!["the scan panicked".to_string()]),
            Err(error) => vec![format!("could not start the thread: {error}")],
        };
        assert_no_failures(failures);
    }

    /// The whole pass over the same texts: `serde_json` refuses them at its depth
    /// limit (128) instead of recursing without end, and the scan takes over. A
    /// writer thread has the default stack (2 MiB), which this thread has too.
    #[test]
    fn deeply_nested_text_goes_through_the_whole_pass() {
        let mut failures = Vec::new();
        for (row, text) in deep_texts() {
            if redact_args_text(&text) != text {
                failures.push(format!("{row}: the text changed"));
            }
        }
        assert_no_failures(failures);
    }

    /// Design 14.5, the bound: hostile shapes finish at once and do not grow. The
    /// pipeline cuts a field to 64 KiB before the pass, so the shapes that cost a
    /// strict text pass per literal are exactly that size, the worst the writer is
    /// ever given, and the cheap ones (no literal to pass) are 512 KiB: a scan that
    /// re-read a run of blanks for every byte of it would need minutes on them. The
    /// generous bound (20 s, the plan's guard for hostile input) is for a loaded
    /// debug build; the work takes milliseconds in release.
    #[test]
    fn hostile_texts_are_scanned_in_linear_time() {
        let mega = 512 * 1024;
        let large = 64 * 1024;
        let mut failures = Vec::new();
        for (row, text) in [
            (
                "one huge literal",
                format!("{{\"a\":\"{}", "x".repeat(large)),
            ),
            (
                "one huge escaped literal",
                format!("{{\"a\":\"{}", "\\\\".repeat(large / 2)),
            ),
            (
                "a huge literal of escapes",
                format!("[\"{}", "\\u00e9".repeat(large / 6)),
            ),
            ("tiny literals", "\"a\",".repeat(large / 4)),
            ("tiny keys", "{\"a\":1,".repeat(large / 7)),
            ("tiny secret keys", "{\"pw\":\"v\",".repeat(large / 12)),
            ("blanks", " ".repeat(mega)),
            ("only colons and commas", ":,".repeat(mega / 2)),
            (
                "a huge secret key",
                format!("{{\"{}password\":\"v\"", "k".repeat(large)),
            ),
            ("numbers", "1234567890.5e-3".repeat(mega / 15)),
            (
                "blanks before a colon",
                format!("{{\"a\"{}:\"v\"", " ".repeat(mega)),
            ),
        ] {
            let started = Instant::now();
            let got = redact_args_text(&text);
            let took = started.elapsed();
            if took > Duration::from_secs(20) {
                failures.push(format!("{row}: took {took:?}"));
            }
            if got.len() > text.len() * 2 + 64 {
                failures.push(format!(
                    "{row}: grew from {} to {} bytes",
                    text.len(),
                    got.len()
                ));
            }
        }
        assert_no_failures(failures);
    }

    /// A small deterministic generator: a fixed seed, so a failure reproduces.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            // xorshift64*
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
        }

        fn below(&mut self, n: usize) -> usize {
            (self.next() % n as u64) as usize
        }

        fn pick<'a>(&mut self, items: &[&'a str]) -> &'a str {
            items[self.below(items.len())]
        }
    }

    /// Text the scan reads from a generated JSON text: whole values, so that the
    /// text parses, and what a cap makes of them.
    fn generated_value(rng: &mut Rng, depth: usize) -> Value {
        const KEYS: [&str; 10] = [
            "a",
            "note",
            "password",
            "token",
            "X-Api-Key",
            "headers",
            "pw",
            "Cookie",
            "k\u{e9}y",
            "sel\"ector",
        ];
        const TEXTS: [&str; 12] = [
            "plain",
            "password=CNRYF1x2y3z4",
            "Authorization: Bearer CNRYF5x6y7z8",
            "GET /\r\nCookie: a=b; z=CNRYF9x8y7z6\r\nHost: x",
            "https://host.test/p?x=1&y=2",
            "say \"hi\" \\ back\tnow",
            "h\u{e9}llo w\u{f6}rld \u{65e5}\u{672c}",
            "\u{1f600} and \u{9b} and \u{7f}",
            "[redacted] and <redacted>",
            "token=abc&x=1",
            "",
            "Bearer CNRYF4a5b6c7d",
        ];
        let kind = if depth >= 4 {
            rng.below(4)
        } else {
            rng.below(6)
        };
        match kind {
            0 => json!(rng.below(1000) as i64 - 500),
            1 => Value::Bool(rng.below(2) == 0),
            2 => Value::Null,
            3 => Value::String(rng.pick(&TEXTS).to_string()),
            4 => Value::Array(
                (0..rng.below(4))
                    .map(|_| generated_value(rng, depth + 1))
                    .collect(),
            ),
            _ => Value::Object(
                (0..rng.below(4))
                    .map(|_| {
                        let key = rng.pick(&KEYS).to_string();
                        let value = match key.as_str() {
                            "password" | "token" | "pw" | "X-Api-Key" if rng.below(2) == 0 => {
                                Value::String("CNRYK1a2b3c4".to_string())
                            }
                            _ => generated_value(rng, depth + 1),
                        };
                        (key, value)
                    })
                    .collect(),
            ),
        }
    }

    /// Generated texts, whole and cut at every kind of place: the scan never
    /// panics, is idempotent, keeps what is outside literals, hides a framed
    /// secret and the value of a secret key wherever the text is cut, and turns
    /// text that parses into text that parses.
    #[test]
    fn generated_texts_hold_every_property_of_the_pass() {
        const CASES: usize = 600;
        let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
        let mut failures = Vec::new();
        for case in 0..CASES {
            let value = generated_value(&mut rng, 0);
            let whole = value.to_string();
            let mut texts = vec![whole.clone()];
            for _ in 0..6 {
                let mut at = rng.below(whole.len() + 1);
                while !whole.is_char_boundary(at) {
                    at -= 1;
                }
                let head = whole.get(..at).unwrap_or_default();
                texts.push(head.to_string());
                texts.push(format!("{head}\u{2026}"));
            }
            for text in texts {
                let once = redact_args_text(&text);
                let twice = redact_args_text(&once);
                if twice != once {
                    failures.push(format!(
                        "case {case}: not idempotent for {text:?}: {once:?} then {twice:?}"
                    ));
                }
                if let Some(scanned) = scan_json_text(&text) {
                    if outside_literals(&scanned) != outside_literals(&text) {
                        failures.push(format!(
                            "case {case}: structure changed for {text:?}: {scanned:?}"
                        ));
                    }
                }
                for canary in ["CNRYF", "CNRYK"] {
                    if once.contains(canary) {
                        failures.push(format!(
                            "case {case}: {canary} survived in {once:?} from {text:?}"
                        ));
                    }
                }
                if serde_json::from_str::<Value>(&text).is_ok()
                    && serde_json::from_str::<Value>(&once).is_err()
                {
                    failures.push(format!(
                        "case {case}: JSON became text that does not parse: {once:?}"
                    ));
                }
            }
            if failures.len() > 20 {
                break;
            }
        }
        assert_no_failures(failures);
    }

    /// The literal the scan writes for a hidden value is the one the source writes
    /// for a secret-named key, so a file never shows two spellings of "hidden".
    #[test]
    fn the_hidden_value_is_what_the_source_writes() {
        let hidden = redact_value(&json!({"password": "x"}));
        assert_eq!(hidden["password"], json!(KEY_REDACTED));
        assert_eq!(
            redact_args_text(r#"{"password":"x","k":"cut"#),
            r#"{"password":"<redacted>","k":"cut"#
        );
    }

    /// `scrub_strict` is what a literal's content goes through: the same function
    /// the source runs over a leaf, not a copy of it.
    #[test]
    fn a_literal_content_gets_the_strict_text_pass() {
        let text = r#"{"note":"build pw=CNRYS1a2b3 ok","k":"cut"#;
        let want = format!(
            "{{\"note\":\"{}\",\"k\":\"cut",
            scrub_strict("build pw=CNRYS1a2b3 ok")
        );
        assert_eq!(redact_args_text(text), want);
        assert!(!want.contains("CNRYS1a2b3"), "{want}");
    }
}
