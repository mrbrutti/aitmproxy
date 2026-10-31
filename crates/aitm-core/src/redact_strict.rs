//! Audit-only strict redaction, beside the untouched [`crate::redact`] module.
//!
//! [`crate::redact::scrub_text`] and [`crate::redact::is_secret_key`] are shared by
//! the scanner, the findings store and the PoC builder, so they are not edited for
//! the audit log. This module calls them and adds to them, for the audit path only:
//!
//! - [`scrub_strict`]: `scrub_text` first, then the strict text passes. This task
//!   holds P2 (header lines) and P3 (Basic, Negotiate and NTLM credentials).
//! - [`is_secret_key_strict`]: the shared vocabulary plus a few extra key words.
//! - [`is_benign_header`]: the header names whose value is evidence, not a
//!   credential (the default-deny list of header collections).
//!
//! Every pass runs on **plain decoded text** (a string leaf, an error reason, a
//! label), never on JSON text. Every pass is linear in the length of the text,
//! changes no character outside the span it masks, replaces with the literal
//! `[redacted]`, and is idempotent: `scrub_strict(scrub_strict(x)) ==
//! scrub_strict(x)`.

use crate::redact::{is_secret_key, scrub_text};

/// The literal every pass writes over a credential.
const REDACTED: &str = "[redacted]";

/// Needles that mark a key as secret beyond [`is_secret_key`], matched as a
/// substring of the ASCII-lowercased key.
const EXTRA_KEY_NEEDLES: &[&str] = &[
    "passphrase",
    "private_key",
    "private-key",
    "privatekey",
    "access_key",
    "access-key",
    "accesskey",
    "signing_key",
    "signing-key",
];

/// Short words that mark a key as secret beyond [`is_secret_key`] only when they
/// are a whole segment of it (the runs of ASCII alphanumerics between every other
/// character), so `bypass`, `passed`, `compass` and `power` are not hit.
const EXTRA_KEY_SEGMENTS: &[&str] = &["pass", "pw", "otp", "totp"];

/// Header names whose value is the credential itself. P2 masks the rest of the
/// line after one of these anywhere in the text, not only at the start of a line.
const CREDENTIAL_HEADERS: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "cookie",
    "cookie2",
    "set-cookie",
];

/// The header names that carry routing, negotiation or injection evidence rather
/// than a credential (ASCII case-insensitive, exact).
const BENIGN_HEADERS: &[&str] = &[
    "accept",
    "accept-charset",
    "accept-encoding",
    "accept-language",
    "accept-ranges",
    "access-control-request-headers",
    "access-control-request-method",
    "cache-control",
    "connection",
    "content-disposition",
    "content-encoding",
    "content-language",
    "content-length",
    "content-type",
    "date",
    "dnt",
    "expect",
    "forwarded",
    "host",
    "if-modified-since",
    "if-unmodified-since",
    "origin",
    "pragma",
    "range",
    "referer",
    "sec-websocket-extensions",
    "sec-websocket-protocol",
    "sec-websocket-version",
    "te",
    "transfer-encoding",
    "upgrade",
    "upgrade-insecure-requests",
    "user-agent",
    "via",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-port",
    "x-forwarded-proto",
    "x-http-method-override",
    "x-original-url",
    "x-real-ip",
    "x-requested-with",
    "x-rewrite-url",
];

/// Prefixes of benign header families (`Sec-Fetch-Mode`, `Sec-CH-UA`).
const BENIGN_HEADER_PREFIXES: &[&str] = &["sec-fetch-", "sec-ch-"];

/// Whether an argument key or header name names a secret under the audit log's
/// stricter vocabulary: everything [`is_secret_key`] says, plus the needles
/// `passphrase`, `private_key`, `private-key`, `privatekey`, `access_key`,
/// `access-key`, `accesskey`, `signing_key` and `signing-key`, plus the whole
/// segments `pass`, `pw`, `otp` and `totp` (segments split on every character that
/// is not an ASCII alphanumeric). Matched case-insensitively.
///
/// The extras are deliberately not added to the shared `is_secret_key`: that would
/// change the scanner's, the findings store's and the PoC builder's output.
pub fn is_secret_key_strict(key: &str) -> bool {
    if is_secret_key(key) {
        return true;
    }
    let lower = key.to_ascii_lowercase();
    EXTRA_KEY_NEEDLES
        .iter()
        .any(|needle| lower.contains(needle))
        || lower
            .split(|c: char| !c.is_ascii_alphanumeric())
            .any(|segment| EXTRA_KEY_SEGMENTS.contains(&segment))
}

/// Whether `name` is on the benign header list: an ASCII-case-insensitive exact
/// match against the routing and override headers an injection test sends, or a
/// name that starts with `sec-fetch-` or `sec-ch-`.
///
/// This alone says only "on the list". A caller that decides whether a header's
/// value is kept combines it with [`is_secret_key_strict`] (a benign name that is
/// also a strict secret key is not kept).
pub fn is_benign_header(name: &str) -> bool {
    BENIGN_HEADERS
        .iter()
        .any(|benign| name.eq_ignore_ascii_case(benign))
        || BENIGN_HEADER_PREFIXES.iter().any(|prefix| {
            name.as_bytes()
                .get(..prefix.len())
                .is_some_and(|head| head.eq_ignore_ascii_case(prefix.as_bytes()))
        })
}

/// Mask credential material in plain text: [`scrub_text`] first (unchanged), then
/// the strict passes in order: P2 header lines, P3 Basic, Negotiate and NTLM
/// credentials.
///
/// - **P2.** The name `authorization`, `proxy-authorization`, `cookie`, `cookie2`
///   or `set-cookie` (ASCII case-insensitive, a whole name: not preceded by an
///   ASCII alphanumeric, `_`, `.` or `-`) followed by optional blanks and `:`
///   masks the rest of the line (to a real CR or LF, or the end of the text),
///   keeping the name, the colon and one blank: `Cookie: [redacted]`. At the start
///   of a line any name that [`is_secret_key_strict`] does the same, except that a
///   `host:port` (`auth.example.com:8443`) is a host, not a header. Prose without
///   a `:` is untouched, and so is a header with an empty value.
/// - **P3.** `basic` followed by blanks and a base64-alphabet token of at least 8
///   characters masks the token only when it decodes (leniently, padding not
///   required) to bytes that contain `:`, the `user:pass` shape. `negotiate` or
///   `ntlm` followed by blanks and a token of 16 or more such characters masks the
///   token.
///
/// Plain text only: never call this over JSON text, where a line break is the two
/// characters `\r\n` and a value is followed by `"}`. Linear in the length of
/// `text`, and idempotent.
pub fn scrub_strict(text: &str) -> String {
    let scrubbed = scrub_text(text);
    let headers_masked = mask_header_lines(&scrubbed);
    mask_basic_credentials(&headers_masked)
}

/// Whether `b` can be part of a header name run: an ASCII alphanumeric, `_`, `.`
/// or `-`. Every other byte, a non-ASCII one included, ends a run.
fn is_name_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-')
}

/// A blank between a keyword and its token (P3): a space or a tab.
fn is_blank(b: u8) -> bool {
    matches!(b, b' ' | b'\t')
}

/// ASCII whitespace of any kind, the vertical tab and form feed included.
fn is_ascii_space(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\r' | b'\n' | 0x0B | 0x0C)
}

/// The index of the first byte at or after `from` for which `keep` is false, or
/// the end of `bytes`.
fn skip_while(bytes: &[u8], from: usize, keep: fn(u8) -> bool) -> usize {
    bytes
        .get(from..)
        .and_then(|rest| rest.iter().position(|&b| !keep(b)))
        .map_or(bytes.len(), |offset| from + offset)
}

/// The index of the first character at or after `from` that is not a blank inside
/// a line (P2): any Unicode whitespace except a CR or a LF, as `scrub_text` reads
/// whitespace. Reading only a space and a tab would let a header whose value is
/// whitespace alone (`Authorization:` then U+2028) be rewritten here, and the CR
/// after it then be eaten by a second `scrub_text` (its `.+` matches a CR), which
/// breaks idempotence. `from` not on a char boundary, or past the end, is returned
/// unchanged.
fn skip_line_blanks(text: &str, from: usize) -> usize {
    let Some(rest) = text.get(from..) else {
        return from;
    };
    let blanks: usize = rest
        .chars()
        .take_while(|&c| c.is_whitespace() && !matches!(c, '\r' | '\n'))
        .map(char::len_utf8)
        .sum();
    from + blanks
}

/// Whether the name run `bytes[start..end]` is the host of a `host:port` rather
/// than a header name: the run contains a `.`, the very next byte is `:`, and one
/// to five ASCII digits follow it and then `/`, `?`, `#`, a blank or the end of
/// the text. Reads at most seven bytes past the run.
fn is_host_port(bytes: &[u8], start: usize, end: usize) -> bool {
    if !bytes[start..end].contains(&b'.') || bytes.get(end) != Some(&b':') {
        return false;
    }
    let digits_start = end + 1;
    let digits = bytes
        .get(digits_start..)
        .unwrap_or_default()
        .iter()
        .take(6)
        .take_while(|b| b.is_ascii_digit())
        .count();
    (1..=5).contains(&digits)
        && bytes
            .get(digits_start + digits)
            .is_none_or(|&b| matches!(b, b'/' | b'?' | b'#') || is_ascii_space(b))
}

/// P2. See [`scrub_strict`]. One left-to-right scan: each name run is read once,
/// and a masked line is skipped whole, so the work is linear.
fn mask_header_lines(text: &str) -> String {
    let bytes = text.as_bytes();
    let len = bytes.len();
    let mut out = String::with_capacity(len);
    // Start of the text not yet copied into `out`.
    let mut copied = 0;
    let mut i = 0;
    while i < len {
        if !is_name_byte(bytes[i]) {
            i += 1;
            continue;
        }
        // `i` starts a maximal name run: the byte before it is not a name byte, so
        // the "not preceded by an alphanumeric, `_`, `.` or `-`" rule holds.
        let start = i;
        let end = skip_while(bytes, start, is_name_byte);
        i = end;

        // Optional blanks, then the colon. The vocabulary is consulted only for a
        // run that is followed by one.
        let colon = skip_line_blanks(text, end);
        if bytes.get(colon) != Some(&b':') {
            continue;
        }
        // A name run is ASCII, so `start..end` is on char boundaries.
        let name = &text[start..end];
        let at_line_start = start == 0 || matches!(bytes[start - 1], b'\r' | b'\n');
        let masks = CREDENTIAL_HEADERS
            .iter()
            .any(|header| name.eq_ignore_ascii_case(header))
            || (at_line_start && is_secret_key_strict(name) && !is_host_port(bytes, start, end));
        if !masks {
            continue;
        }

        // The rest of the line after the colon and its blanks. An empty value is
        // left alone, as `scrub_text` leaves one.
        let value_start = skip_line_blanks(text, colon + 1);
        let line_end = skip_while(bytes, value_start, |b| !matches!(b, b'\r' | b'\n'));
        if line_end == value_start {
            continue;
        }
        // `colon` is an ASCII byte and `line_end` is a CR, a LF or the end of the
        // text, so both slice points are char boundaries.
        out.push_str(&text[copied..=colon]);
        out.push(' ');
        out.push_str(REDACTED);
        copied = line_end;
        i = line_end;
    }
    out.push_str(&text[copied..]);
    out
}

/// The value of a base64 or base64url alphabet byte, `None` for any other byte
/// (the `=` padding included).
fn base64_value(b: u8) -> Option<u32> {
    match b {
        b'A'..=b'Z' => Some(u32::from(b - b'A')),
        b'a'..=b'z' => Some(u32::from(b - b'a') + 26),
        b'0'..=b'9' => Some(u32::from(b - b'0') + 52),
        b'+' | b'-' => Some(62),
        b'/' | b'_' => Some(63),
        _ => None,
    }
}

/// Whether `b` can be part of a base64 token: the standard and URL-safe alphabets
/// and the `=` padding.
fn is_base64_token_byte(b: u8) -> bool {
    base64_value(b).is_some() || b == b'='
}

/// Whether `token` decodes, leniently, to bytes that contain `:`. Both alphabets
/// are accepted, padding is not required, a `=` ends the data, and trailing bits
/// that do not make a whole byte are dropped. No allocation, one pass.
fn decodes_with_colon(token: &[u8]) -> bool {
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for &b in token {
        let Some(value) = base64_value(b) else { break };
        acc = (acc << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            if (acc >> bits) & 0xFF == u32::from(b':') {
                return true;
            }
            // Keep only the bits not yet emitted, so `acc` never overflows.
            acc &= (1 << bits) - 1;
        }
    }
    false
}

/// The length of the scheme keyword that `bytes[at..]` starts with, and the
/// minimum token length it needs, or `None`. Matched ASCII case-insensitively.
fn scheme_at(bytes: &[u8], at: usize) -> Option<(usize, usize, bool)> {
    let rest = bytes.get(at..)?;
    let starts = |word: &str| {
        rest.get(..word.len())
            .is_some_and(|head| head.eq_ignore_ascii_case(word.as_bytes()))
    };
    // (keyword length, minimum token length, the token must decode to `user:pass`)
    if starts("basic") {
        Some((5, 8, true))
    } else if starts("negotiate") {
        Some((9, 16, false))
    } else if starts("ntlm") {
        Some((4, 16, false))
    } else {
        None
    }
}

/// P3. See [`scrub_strict`]. One left-to-right scan. A keyword's token is read once
/// and the scan resumes after it when it is masked; otherwise the scan moves on a
/// byte, and a keyword inside a token it just read is followed by token bytes, not
/// blanks, so it fails at once. The work is linear.
fn mask_basic_credentials(text: &str) -> String {
    let bytes = text.as_bytes();
    let len = bytes.len();
    let mut out = String::with_capacity(len);
    // Start of the text not yet copied into `out`.
    let mut copied = 0;
    let mut i = 0;
    while i < len {
        let Some((keyword_len, min_token, must_decode)) = scheme_at(bytes, i) else {
            i += 1;
            continue;
        };
        let after_keyword = i + keyword_len;
        let token_start = skip_while(bytes, after_keyword, is_blank);
        if token_start == after_keyword {
            // No blank after the keyword (`basicbasicbasic...`): not a credential
            // header, and the token run is not read, so a long run of keywords
            // costs a constant each.
            i += 1;
            continue;
        }
        let token_end = skip_while(bytes, token_start, is_base64_token_byte);
        let token = &bytes[token_start..token_end];
        if token.len() >= min_token && (!must_decode || decodes_with_colon(token)) {
            // The token is ASCII and starts after a blank, so both slice points
            // are on char boundaries.
            out.push_str(&text[copied..token_start]);
            out.push_str(REDACTED);
            copied = token_end;
            i = token_end;
        } else {
            i += 1;
        }
    }
    out.push_str(&text[copied..]);
    out
}
