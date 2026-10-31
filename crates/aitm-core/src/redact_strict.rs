//! Audit-only strict redaction, beside the untouched [`crate::redact`] module.
//!
//! [`crate::redact::scrub_text`] and [`crate::redact::is_secret_key`] are shared by
//! the scanner, the findings store and the PoC builder, so they are not edited for
//! the audit log. This module calls them and adds to them, for the audit path only:
//!
//! - [`scrub_strict`]: `scrub_text` first, then the strict text passes: P2 (header
//!   lines), P3 (Basic, Negotiate and NTLM credentials), P4 (URL userinfo), P5
//!   (credential shapes with a distinctive prefix) and P6 (the extra key words as
//!   `key=value` pairs).
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
    is_secret_key(key) || has_extra_vocabulary(key)
}

/// Whether `key` carries one of the audit-only extra words, whatever the shared
/// vocabulary says. P6 masks the pairs of exactly these keys: `scrub_text` has
/// already masked the rest.
fn has_extra_vocabulary(key: &str) -> bool {
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
/// credentials, P4 URL userinfo, P5 credential shapes, P6 the extra key words.
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
/// - **P4.** In `scheme://userinfo@host` (the userinfo is the text up to the first
///   `@`, with no `/`, `?`, `#`, blank or quote in it): with a `:` the part after
///   the first `:` is masked and the user name stays
///   (`https://user:[redacted]@host`); with no `:` the whole userinfo is masked
///   only when it is 20 or more bytes long or holds a P5 shape (`ssh://git@host`
///   stays).
/// - **P5.** A credential with a distinctive prefix, a fixed alphabet and a minimum
///   length: a JWT, a PEM private key block, an AWS access key id, GitHub, GitLab,
///   Slack, Stripe, `sk-` and Google API keys. It must start at a boundary, a byte
///   that is not an ASCII alphanumeric (`_` included, so `KEY_ghp_...` is still
///   masked, and `task-<uuid>` is not an `sk-` key). A run shape ends at a boundary
///   by construction; an exact-length one (AWS, Google) must be followed by one,
///   unless an alphanumeric that opens another credential follows it.
/// - **P6.** A `key=value`, `key: value` or `"key":"value"` pair whose key carries
///   one of the audit-only extra words (and no shared one) is masked with the value
///   rule of `scrub_text`. P2 has already taken a `pass: value` that starts a line.
///
/// Plain text only: never call this over JSON text, where a line break is the two
/// characters `\r\n` and a value is followed by `"}`. Linear in the length of
/// `text`.
///
/// Idempotent: a second call over the output changes nothing, for every row of the
/// tests and for all but a handful of the dense, hostile strings a fuzz produced
/// (23 distinct shapes in 30 million). The exceptions are all of one kind, one mask
/// changing how a neighbour reads, and the second call masks more, never less:
///
/// - A value that ends in a backslash before a quote (`otp=\"`): masking it takes the
///   backslash, so the quote is no longer escaped. `scrub_text` does the same, so it
///   is not idempotent there on its own.
/// - A mask that takes away what made an earlier pass hold back: the `.` that made
///   `scrub_text` read `a.b_c:8443` as a host and a port, a `/` or a blank that ended
///   a P4 userinfo, the delimiter between a P4 password and the rest of a value.
pub fn scrub_strict(text: &str) -> String {
    let scrubbed = scrub_text(text);
    let headers_masked = mask_header_lines(&scrubbed);
    let basic_masked = mask_basic_credentials(&headers_masked);
    let userinfo_masked = mask_url_userinfo(&basic_masked);
    let shapes_masked = mask_credential_shapes(&userinfo_masked);
    mask_extra_pairs(&shapes_masked)
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

/// Whether `b` can end the scheme in front of `://`: an ASCII alphanumeric, `+`,
/// `.` or `-`.
fn is_scheme_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'+' | b'.' | b'-')
}

/// The index of the `@` that ends the userinfo of an authority starting at `from`,
/// or `None` when a `/`, `?`, `#`, quote or whitespace character, or the end of the
/// text, comes first. Reads no further than that character. Whitespace is Unicode
/// whitespace, as `scrub_text` reads it: it ends the value of a `key:value` pair
/// there, so a pass that masked across one (a no-break space inside a "password")
/// would let the next call read that value further than this one did.
fn userinfo_end(text: &str, from: usize) -> Option<usize> {
    for (offset, c) in text.get(from..)?.char_indices() {
        match c {
            '@' => return Some(from + offset),
            '/' | '?' | '#' | '"' | '\'' => return None,
            c if c.is_whitespace() => return None,
            _ => {}
        }
    }
    None
}

/// P4. See [`scrub_strict`]. The text is searched for `://` once, left to right.
/// The userinfo scan after a `://` stops at the first `/` at the latest, and a later
/// `://` has a `/` in it, so two scans never overlap and the work is linear.
fn mask_url_userinfo(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    // Start of the text not yet copied into `out`.
    let mut copied = 0;
    let mut search_from = 0;
    while let Some(found) = text.get(search_from..).and_then(|rest| rest.find("://")) {
        let separator = search_from + found;
        let authority = separator + 3;
        // `authority` follows ASCII, so it is a char boundary.
        search_from = authority;
        if separator == 0 || !is_scheme_byte(bytes[separator - 1]) {
            continue;
        }
        let Some(at) = userinfo_end(text, authority) else {
            continue;
        };
        // `authority` and `at` (an ASCII `@`) are char boundaries.
        let userinfo = &text[authority..at];
        let mask_from = match userinfo.find(':') {
            // The part after the first colon; an empty one is no secret.
            Some(colon) => (colon + 1 < userinfo.len()).then_some(authority + colon + 1),
            None => (userinfo.len() >= 20 || contains_shape(userinfo)).then_some(authority),
        };
        if let Some(from) = mask_from {
            out.push_str(&text[copied..from]);
            out.push_str(REDACTED);
            copied = at;
        }
    }
    out.push_str(&text[copied..]);
    out
}

/// A P5 credential made of a distinctive prefix and a body of bytes of one alphabet.
struct Shape {
    prefixes: &'static [&'static str],
    body: fn(u8) -> bool,
    /// The shortest body, or the exact body length when `exact`.
    min: usize,
    /// The body is exactly `min` bytes and the next byte is not an ASCII
    /// alphanumeric, unless it starts another credential (see [`starts_shape`]).
    /// (Every other body alphabet holds all ASCII alphanumerics, so a maximal run
    /// ends at a boundary by construction.)
    exact: bool,
}

fn body_alnum(b: u8) -> bool {
    b.is_ascii_alphanumeric()
}

fn body_alnum_underscore(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn body_alnum_dash(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'-'
}

/// The base64url alphabet without padding.
fn body_base64url(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-')
}

fn body_upper_digit(b: u8) -> bool {
    b.is_ascii_uppercase() || b.is_ascii_digit()
}

/// The prefix-and-body shapes of P5. The JWT and the PEM block have their own scans.
const SHAPES: &[Shape] = &[
    // AWS access key id.
    Shape {
        prefixes: &["AKIA", "ASIA", "AGPA", "AIDA", "AROA", "ANPA", "ANVA"],
        body: body_upper_digit,
        min: 16,
        exact: true,
    },
    // GitHub tokens.
    Shape {
        prefixes: &["ghp_", "gho_", "ghu_", "ghs_", "ghr_"],
        body: body_alnum,
        min: 36,
        exact: false,
    },
    Shape {
        prefixes: &["github_pat_"],
        body: body_alnum_underscore,
        min: 22,
        exact: false,
    },
    // GitLab personal access token.
    Shape {
        prefixes: &["glpat-"],
        body: body_base64url,
        min: 20,
        exact: false,
    },
    // Slack tokens.
    Shape {
        prefixes: &["xoxa-", "xoxb-", "xoxp-", "xoxr-", "xoxs-"],
        body: body_alnum_dash,
        min: 10,
        exact: false,
    },
    // Stripe keys.
    Shape {
        prefixes: &["sk_live_", "sk_test_", "rk_live_", "rk_test_"],
        body: body_alnum,
        min: 16,
        exact: false,
    },
    // `sk-` API keys (`sk-proj-`, `sk-ant-`).
    Shape {
        prefixes: &["sk-"],
        body: body_base64url,
        min: 32,
        exact: false,
    },
    // Google API key.
    Shape {
        prefixes: &["AIza"],
        body: body_base64url,
        min: 35,
        exact: true,
    },
];

/// Whether the prefix of a [`SHAPES`] credential or of a JWT starts at `at`. An
/// exact-length shape is not held back by a following alphanumeric that opens one:
/// that neighbour is masked in the same scan, and a boundary that waited for it
/// would be met by the second call and not by the first.
fn starts_shape(bytes: &[u8], at: usize) -> bool {
    let rest = bytes.get(at..).unwrap_or_default();
    rest.starts_with(b"eyJ")
        || SHAPES.iter().any(|shape| {
            shape
                .prefixes
                .iter()
                .any(|prefix| rest.starts_with(prefix.as_bytes()))
        })
}

/// The end of the [`SHAPES`] credential starting at `at`, or `None`.
///
/// A body shorter than `min` is read to its end, which is under `min` bytes away
/// (a longer one is a match, and the scan resumes after it), so a failed attempt
/// costs a constant.
fn table_shape_end(bytes: &[u8], at: usize) -> Option<usize> {
    let rest = bytes.get(at..)?;
    SHAPES.iter().find_map(|shape| {
        let prefix = shape
            .prefixes
            .iter()
            .find(|prefix| rest.starts_with(prefix.as_bytes()))?;
        let body_start = at + prefix.len();
        let limit = if shape.exact { shape.min } else { usize::MAX };
        let run = bytes
            .get(body_start..)?
            .iter()
            .take(limit)
            .take_while(|&&b| (shape.body)(b))
            .count();
        if run < shape.min {
            return None;
        }
        let end = body_start + run;
        let glued = bytes.get(end).is_some_and(u8::is_ascii_alphanumeric);
        if shape.exact && glued && !starts_shape(bytes, end) {
            return None;
        }
        Some(end)
    })
}

/// The end of the JWT starting at `at` (on `eyJ`, at a boundary), or `None`: a
/// first segment of at least 8 base64url characters (the `eyJ` included), a dot, a
/// second segment of at least 8, a dot, and a third segment of any length, the
/// signature, which an unsecured token leaves empty.
///
/// A failed attempt reads the first segment to its end, `first_end`, and the
/// verdict of any attempt that starts inside that segment is the same (it ends at
/// the same dot and meets the same second segment, with a shorter first one), so
/// `dead_until` is set and those attempts are skipped: without that, `eyJ-eyJ-...`
/// would cost a pass over the rest of the text at every `eyJ`.
fn jwt_end(bytes: &[u8], at: usize, dead_until: &mut usize) -> Option<usize> {
    if at < *dead_until {
        return None;
    }
    let first_end = skip_while(bytes, at, body_base64url);
    let end = jwt_after_first(bytes, at, first_end);
    if end.is_none() {
        *dead_until = first_end;
    }
    end
}

/// The rest of [`jwt_end`], given the end of the first segment.
fn jwt_after_first(bytes: &[u8], at: usize, first_end: usize) -> Option<usize> {
    if first_end - at < 8 || bytes.get(first_end) != Some(&b'.') {
        return None;
    }
    let second_start = first_end + 1;
    let second_end = skip_while(bytes, second_start, body_base64url);
    if second_end - second_start < 8 || bytes.get(second_end) != Some(&b'.') {
        return None;
    }
    Some(skip_while(bytes, second_end + 1, body_base64url))
}

/// The most label bytes a PEM private key marker line may carry between the
/// keyword and the closing dashes (`RSA PRIVATE KEY` is 15).
const PEM_LABEL_MAX: usize = 48;

/// If a PEM marker line starts at `at` with `keyword` (`-----BEGIN ` or
/// `-----END `), a label of capital letters, digits and spaces that ends in
/// `PRIVATE KEY`, and the closing dashes, the index just past those dashes.
fn pem_marker_end(bytes: &[u8], at: usize, keyword: &str) -> Option<usize> {
    let rest = bytes.get(at..)?;
    if !rest.starts_with(keyword.as_bytes()) {
        return None;
    }
    let label_start = at + keyword.len();
    let after_keyword = bytes.get(label_start..)?;
    let label_len = after_keyword
        .iter()
        .take(PEM_LABEL_MAX + 1)
        .take_while(|&&b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b' ')
        .count();
    if label_len > PEM_LABEL_MAX || !after_keyword[..label_len].ends_with(b"PRIVATE KEY") {
        return None;
    }
    let dashes = label_start + label_len;
    bytes
        .get(dashes..)?
        .starts_with(b"-----")
        .then_some(dashes + 5)
}

/// The end of the PEM private key block that starts at `at`, or `None` when no
/// `-----BEGIN ... PRIVATE KEY-----` line starts there. The block runs through the
/// first `-----END ... PRIVATE KEY-----` line after it, or to the end of the text
/// when there is none, so an unterminated block masks everything after its header.
/// Each marker candidate costs a bounded read and the search resumes after it.
///
/// A name byte glued to the end of the closing line belongs to the block. P2 reads a
/// header name as a whole run of name bytes, and the closing dashes are name bytes:
/// `-----END PRIVATE KEY-----cookie: x` is one run to it, not a header. Masking only
/// up to the dashes would leave `[redacted]cookie: x`, where `cookie` starts a run
/// and is one, so a second call would mask what the first left.
fn pem_block_end(text: &str, at: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    let header_end = pem_marker_end(bytes, at, "-----BEGIN ")?;
    let mut from = header_end;
    while let Some(found) = text.get(from..).and_then(|rest| rest.find("-----END ")) {
        let marker = from + found;
        if let Some(end) = pem_marker_end(bytes, marker, "-----END ") {
            return Some(skip_while(bytes, end, is_name_byte));
        }
        from = marker + 1;
    }
    Some(text.len())
}

/// The end of the P5 credential that starts at `at`, or `None`. `from` is where the
/// scan started: the start of the text, or the end of the credential masked just
/// before, whose last byte the candidate at `from` is glued to. `jwt_dead_until` is
/// the JWT scan's memory (see [`jwt_end`]).
fn shape_end_at(text: &str, at: usize, from: usize, jwt_dead_until: &mut usize) -> Option<usize> {
    let bytes = text.as_bytes();
    match bytes[at] {
        // A PEM block needs no boundary: its header is distinctive.
        b'-' => pem_block_end(text, at),
        // First bytes of the other shapes. The previous byte must not be an ASCII
        // alphanumeric, so a prefix in the middle of a word (`task-` for `sk-`) is
        // not one. At `from` the previous byte is the end of a credential that is
        // masked by then, and `]` is a boundary: judging the candidate by the byte
        // that stood there would leave it for the next call.
        b'e' | b'A' | b'g' | b'x' | b's' | b'r' => {
            if at > from && bytes[at - 1].is_ascii_alphanumeric() {
                return None;
            }
            if bytes[at..].starts_with(b"eyJ") {
                jwt_end(bytes, at, jwt_dead_until)
            } else {
                table_shape_end(bytes, at)
            }
        }
        _ => None,
    }
}

/// The first P5 credential at or after `from`, as `(start, end)`.
fn next_shape(text: &str, from: usize, jwt_dead_until: &mut usize) -> Option<(usize, usize)> {
    (from..text.len())
        .find_map(|at| shape_end_at(text, at, from, jwt_dead_until).map(|end| (at, end)))
}

/// Whether `text` holds a P5 credential anywhere.
fn contains_shape(text: &str) -> bool {
    next_shape(text, 0, &mut 0).is_some()
}

/// P5. See [`scrub_strict`]. One left-to-right scan: a credential is masked whole
/// and the scan resumes after it.
fn mask_credential_shapes(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    // Start of the text not yet copied into `out`.
    let mut copied = 0;
    let mut jwt_dead_until = 0;
    while let Some((start, end)) = next_shape(text, copied, &mut jwt_dead_until) {
        // A shape starts on an ASCII byte and ends on one or at the end of the
        // text, so both slice points are char boundaries.
        out.push_str(&text[copied..start]);
        out.push_str(REDACTED);
        copied = end;
    }
    out.push_str(&text[copied..]);
    out
}

// P6 reads a pair the way `scrub_text` does, so that a value is masked to the same
// end. `redact.rs` keeps its scanner private and is not edited for the audit log,
// so the helpers below are copies of its own: `run_end`, `blank_len`,
// `skip_blanks`, `ends_value`, `unquoted_value_end`, `is_opening_quote` and
// `closing_quote`. A change to the value rule there is a change here.

/// The index where the run of characters starting at `from` ends: at the first
/// ASCII byte for which `ascii_continues` is false, at the first whitespace
/// character, or at the end of `text`. Any other non-ASCII character continues the
/// run. `from` must be on a char boundary.
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

/// The byte length of the whitespace character at `i` (as [`char::is_whitespace`]
/// reads it), or 0 when the character there is not whitespace, `i` is the end of
/// `text`, or `i` is not on a char boundary.
fn blank_len(text: &str, i: usize) -> usize {
    match text.as_bytes().get(i) {
        None => 0,
        Some(&b) if b < 0x80 => usize::from(is_ascii_space(b)),
        Some(_) => text
            .get(i..)
            .and_then(|rest| rest.chars().next())
            .filter(|c| c.is_whitespace())
            .map_or(0, char::len_utf8),
    }
}

/// The index of the first byte at or after `i` that does not start a whitespace
/// character.
fn skip_blanks(text: &str, mut i: usize) -> usize {
    loop {
        match blank_len(text, i) {
            0 => return i,
            n => i += n,
        }
    }
}

/// Whether `b` ends an unquoted value: ASCII whitespace or a pair, list, quote or
/// JSON delimiter.
fn ends_value(b: u8) -> bool {
    is_ascii_space(b) || matches!(b, b'&' | b';' | b',' | b'"' | b'\'' | b'}')
}

/// The index where an unquoted value starting at `from` ends.
fn unquoted_value_end(text: &str, from: usize) -> usize {
    run_end(text, from, |b| !ends_value(b))
}

/// Whether the unescaped quote at `quote_at` reads as the opening quote of a value
/// rather than the closing quote of the one being searched: the last character
/// before it that is not whitespace is `=` or `:`, and the character after it does
/// not end a value.
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
/// `from`, or `None` if it never closes.
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

/// P6. See [`scrub_strict`]. One linear scan, structured as the pair pass of
/// `scrub_text`: a key run is followed by an optional closing quote, whitespace and
/// `=` or `:`; after a masked pair the scan resumes after the value, after any
/// other key run right after the run, so a pair nested in a value is still seen.
///
/// A failed search for a closing quote reads to the end of the text, and a later
/// search for the same quote character would fail too (a candidate is judged on
/// the characters around it alone), so it is not run: the cost is one pass per
/// quote character, not one per pair.
fn mask_extra_pairs(text: &str) -> String {
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
        let key_end = run_end(text, key_start, is_name_byte);
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

        // The scan only stops on char boundaries and `run_end` steps whole chars,
        // so `key_start..key_end` is on char boundaries.
        let key = &text[key_start..key_end];
        if is_secret_key(key) || !has_extra_vocabulary(key) {
            continue;
        }
        if separator == b':' && is_host_port(bytes, key_start, key_end) {
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
        out.push_str(REDACTED);
        copied = value_end;
        i = value_end;
    }
    out.push_str(&text[copied..]);
    out
}
