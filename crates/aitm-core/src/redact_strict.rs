//! Audit-only strict redaction, beside the untouched [`crate::redact`] module.
//!
//! `crate::redact::scrub_text` and `crate::redact::is_secret_key` are shared by the
//! scanner, the findings store and the PoC builder, so they are not edited for the
//! audit log. This module calls them and adds to them, for the audit path only:
//!
//! - [`scrub_strict`]: one round is the PEM pre-pass, the frames pre-pass, P1
//!   (`scrub_text` itself, unchanged), then the strict passes P2 (header lines), P3
//!   (Basic, Negotiate and NTLM credentials), P4 (URL userinfo), P5 (credential
//!   shapes with a distinctive prefix) and P6 (pairs of the extra key words, and
//!   form fields written with bracket groups). The round is repeated until its
//!   output stops changing, at most `MAX_ROUNDS` times.
//! - [`scrub_strict_bounded`]: `scrub_strict` over a text cut to a byte bound.
//! - [`is_secret_key_strict`]: the shared vocabulary plus a few extra key words,
//!   read in camelCase too.
//! - [`is_benign_header`]: the header names whose value is evidence, not a
//!   credential (the default-deny list of header collections).
//!
//! Every pass runs on **plain decoded text** (a string leaf, an error reason, a
//! label), never on JSON text. Every pass is linear in the length of the text and
//! replaces with the literal `[redacted]`.
//!
//! What is guaranteed: a mask can change how a neighbour reads, so one round does not
//! always settle a text, and the rounds are repeated until a round leaves its input as
//! it was. The result is therefore always one of two things: a text a round leaves
//! alone (a second call over it changes nothing), or, when `MAX_ROUNDS` rounds were not
//! enough, the whole text replaced by `[redacted]` (itself a fixed point). The last
//! round's output is never returned unsettled, because it may still hold what a later
//! round would mask, and a person who controls the text can make the rounds needed grow
//! without bound (each `"D "c ` segment of the `layered` shape in the tests costs two).
//! An ordinary text settles in one or two rounds, and the shapes a fuzz run found that
//! need more (`FUZZ_FOUND_SHAPES` in the tests) settle well inside the cap.
//!
//! Accepted residuals, which no pass reads: a credential with no key, frame or known
//! shape around it; percent-encoded frames and SQL (`SET PASSWORD = 'x'`); an XML
//! attribute that holds a `<` (`<password a="x<y">C</password>`) and an element whose
//! content starts with a comment or a child (`<password><!-- c -->C</password>`); and a
//! URL in quotes whose password holds the quote that opens it (`'https://u:O'C@h/x'`:
//! the authority ends at that quote).
//!
//! Accepted over-redaction, in the safe direction: `-u` and `-U` mask the part after the
//! first colon of the next word, so `docker run -u 1000:1000 img` becomes `-u
//! 1000:[redacted]` and `date -u +%H:%M` loses its minutes; and an unquoted value that
//! runs across a quote takes the text up to the next delimiter with it.

use std::borrow::Cow;

use crate::redact::{is_secret_key, scrub_text};

/// The literal every pass writes over a credential.
const REDACTED: &str = "[redacted]";

/// Needles that mark a key as secret beyond `is_secret_key`, matched as a substring
/// of the ASCII-lowercased key.
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

/// Short words that mark a key as secret beyond `is_secret_key` only when they are
/// a whole segment of it (the runs of ASCII alphanumerics between every other
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
/// than a credential (ASCII case-insensitive, exact). `sec-websocket-protocol` is
/// not here: its list of subprotocols carries bearer tokens
/// (`base64url.bearer.authorization.k8s.io.<token>`).
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
/// stricter vocabulary: everything `is_secret_key` says, plus the needles
/// `passphrase`, `private_key`, `private-key`, `privatekey`, `access_key`,
/// `access-key`, `accesskey`, `signing_key` and `signing-key`, plus the whole
/// segments `pass`, `pw`, `otp` and `totp` (segments split on every character that
/// is not an ASCII alphanumeric). Matched case-insensitively.
///
/// A key is also read in camelCase: with an `_` put wherever a lower-case letter or
/// a digit is followed by a capital, before it is lower-cased, so `userPass`,
/// `adminPw`, `totpCode`, `authKey` and `sessionKey` are secret keys, while
/// `bypass`, `compass`, `Passed`, `author` and `authority`, which have no such
/// boundary, are not.
///
/// The extras are deliberately not added to the shared `is_secret_key`: that would
/// change the scanner's, the findings store's and the PoC builder's output.
pub fn is_secret_key_strict(key: &str) -> bool {
    is_secret_key(key)
        || has_extra_vocabulary(key)
        || split_camel_case(key)
            .is_some_and(|split| is_secret_key(&split) || has_extra_vocabulary(&split))
}

/// Whether `key` carries one of the audit-only extra words, whatever the shared
/// vocabulary says.
fn has_extra_vocabulary(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    EXTRA_KEY_NEEDLES
        .iter()
        .any(|needle| lower.contains(needle))
        || lower
            .split(|c: char| !c.is_ascii_alphanumeric())
            .any(|segment| EXTRA_KEY_SEGMENTS.contains(&segment))
}

/// Whether a key read in camelCase is split between `previous` and `next`: a
/// lower-case letter or a digit followed by a capital.
fn is_camel_boundary(previous: char, next: char) -> bool {
    (previous.is_ascii_lowercase() || previous.is_ascii_digit()) && next.is_ascii_uppercase()
}

/// `key` with an `_` inserted at every [`is_camel_boundary`], or `None` when there is
/// none. Case is kept: the vocabulary lower-cases afterwards.
fn split_camel_case(key: &str) -> Option<String> {
    let mut pairs = key.chars().zip(key.chars().skip(1));
    if !pairs.any(|(previous, next)| is_camel_boundary(previous, next)) {
        return None;
    }
    let mut split = String::with_capacity(key.len() + 4);
    let mut previous: Option<char> = None;
    for c in key.chars() {
        if previous.is_some_and(|p| is_camel_boundary(p, c)) {
            split.push('_');
        }
        split.push(c);
        previous = Some(c);
    }
    Some(split)
}

/// Whether `key` is a strict secret key that `scrub_text` does not already mask: an
/// extra word or a camelCase name. P6 masks the pairs of exactly these keys; for a
/// shared key `scrub_text` has already decided, and decided the host-and-port
/// exemption by its own, wider, rule.
fn is_extra_secret_key(key: &str) -> bool {
    is_secret_key_strict(key) && !is_secret_key(key)
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

/// Mask credential material in plain text. One round is the PEM pre-pass, the frames
/// pre-pass, P1 (`scrub_text`, unchanged), then the strict passes in order: P2 header
/// lines, P3 Basic, Negotiate and NTLM credentials, P4 URL userinfo, P5 credential
/// shapes, P6 pairs of the extra key words and form fields written with bracket
/// groups. The round is repeated until it changes nothing (see below).
///
/// - **PEM pre-pass.** A private key block, from `-----BEGIN ... PRIVATE KEY-----`
///   (or the PGP `... PRIVATE KEY BLOCK-----`) through the matching `-----END ...`
///   line, or to the end of the text when there is none, becomes `[redacted]`, and
///   what came before it stays (`private_key: [redacted]`). It runs first because
///   every other pass reads text line by line: a key name in front of a block
///   (`password: -----BEGIN ...`) would have its own mask take the header line and
///   leave a key body that nothing after that can tell from prose.
/// - **Frames pre-pass.** Values that `scrub_text` cuts in the wrong place, and
///   frames it does not read, before it can mangle them. Under a secret key (the
///   strict vocabulary, camelCase included): a Rust `Debug` wrapper (`Str("x")`,
///   `Some(Str("x"))`, `Bytes([1, 2])`, nested, over several lines), a value in
///   escaped quotes (`{\"password\":\"x\"}`, one level or two, to the quote with
///   the same run of backslashes) and a `[..]` or `{..}` group (`"tokens":["x"]`,
///   strings in either quote read, a group that is cut running to the end) are
///   masked whole. A plain value that runs across a quote is masked whole too: an
///   unquoted value goes on across a quote that something follows (`password=O'Brien`,
///   `api_key=ab"cd`) and ends at one followed by whitespace, `&`, `;`, `,`, `}`, `]` or
///   the end of the text, where `scrub_text` would end it at the first quote and keep
///   the tail. Also an XML or HTML element with a secret name
///   (`<password>x</password>`, CDATA included; the start tag is scanned for frames
///   too), a multipart field (`name="password"`, then the part headers, a blank
///   line and the value, which runs to the boundary line), a command-line flag
///   (`--password x`, `--token 'a b'`; `--key=x` is a pair) and the password of a
///   `user:password` flag (`-u`, `-U`, `--user`, `--proxy-user`: what follows the
///   first colon of the word).
/// - **P2.** The name `authorization`, `proxy-authorization`, `cookie`, `cookie2`
///   or `set-cookie` (ASCII case-insensitive, a whole name: not preceded by an
///   ASCII alphanumeric, `_`, `.` or `-`) followed by optional blanks and `:`
///   masks the rest of the line (to a real CR or LF, or the end of the text) and
///   every folded line after it (a line that starts with a space or a tab),
///   keeping the name, the colon and one blank: `Cookie: [redacted]`. The blanks
///   include the zero-width characters U+200B to U+200D, U+2060 and U+FEFF. At the
///   start of a line any name that `is_secret_key_strict` does the same, except
///   that a `host:port` (`auth.example.com:8443`) is a host, not a header. Prose
///   without a `:` is untouched, and so is a header with an empty value and no
///   folded line.
/// - **P3.** `basic` followed by blanks and a base64-alphabet token of at least 8
///   characters masks the token only when it decodes (leniently, padding not
///   required) to bytes that contain `:`, the `user:pass` shape. `negotiate` or
///   `ntlm` followed by blanks and a token of 16 or more such characters masks the
///   token.
/// - **P4.** In `scheme://userinfo@host`, the authority ends at the first `/`, `?`,
///   `#` or whitespace, and at the quote that stands in front of the scheme when the
///   URL is in a quoted string (`'https://h'`); any other quote is part of the
///   password (`O'Brien`). The userinfo is the text up to the last `@` of the
///   authority, as a browser reads it. With a `:` the part after the first `:` is
///   masked and the user name stays (`https://user:[redacted]@host`); with no `:`
///   the whole userinfo is masked only when it is 20 or more bytes long or holds a
///   P5 shape (`ssh://git@host` stays). A userinfo with no scheme in front of it
///   (`//user:pw@host`) is not read.
/// - **P5.** A credential with a distinctive prefix, a fixed alphabet and a minimum
///   length: a JWT or compact JWE, an AWS access key id, GitHub, GitLab, Slack,
///   Stripe, `sk-` and Google API keys. It must start at a boundary, a byte that is
///   not an ASCII alphanumeric (`_` included, so `KEY_ghp_...` is still masked, and
///   `task-<uuid>` is not an `sk-` key). A run shape ends at a boundary by
///   construction; an exact-length one (AWS, Google) must be followed by one,
///   unless an alphanumeric that opens another credential follows it. A JWE is a
///   header and four more segments, to its tag.
/// - **P6.** A `key=value`, `key: value` or `"key":"value"` pair whose key is a
///   strict secret key that `scrub_text` does not know (an extra word, a camelCase
///   name) is masked with the value rule of `scrub_text`, an unquoted value running
///   across a quote as in the frames pre-pass. A form field name written
///   with bracket groups (`user[password]=x`, `password[]=x`, `a[b][token]=x`) is
///   read as a pair under the whole vocabulary, shared words included, because
///   `scrub_text` never read it. P2 has already taken a `pass: value` that starts a
///   line.
///
/// Plain text only: never call this over JSON text, where a line break is the two
/// characters `\r\n` and a value is followed by `"}`.
///
/// The round is repeated until its output equals its input, at most `MAX_ROUNDS`
/// times. One round does not always settle a text, because a mask can change how a
/// neighbour reads: masking a value that ends in a backslash un-escapes the quote after
/// it, and masking a span can remove the `.` that made `scrub_text` read a host and a
/// port, or a `/` that ended a P4 authority. A text the round leaves alone costs one
/// round, and the work is at most `MAX_ROUNDS` passes, each linear in the length of
/// `text`.
///
/// **Fail closed.** A text for which no round, within `MAX_ROUNDS`, left its input as it
/// was has not been shown to be a fixed point, and the last round's output may still
/// hold a credential a later round would mask. The result is then the literal
/// `[redacted]` for the whole text, never that output. Every result is therefore a
/// fixed point: a second call over it changes nothing.
pub fn scrub_strict(text: &str) -> String {
    converge(text, scrub_round)
}

/// [`scrub_strict`] over `text` cut to at most `max_bytes` bytes, on a char
/// boundary. When the text is cut a `…` is appended, so what remains of a credential
/// the cut fell in reads as an unquoted value and is masked with it (`password=CN…`
/// gives `password=[redacted]`). A text that fits is not cut. The bound limits the
/// work, not the length of the result: a mask can make a short value longer
/// (`pw=a` becomes `pw=[redacted]`), so a caller that needs a length cap cuts the
/// result itself, as the audit reason does. A text that does not settle is replaced
/// whole by `[redacted]`, as [`scrub_strict`] does.
pub fn scrub_strict_bounded(text: &str, max_bytes: usize) -> String {
    if text.len() <= max_bytes {
        return scrub_strict(text);
    }
    let mut cut = max_bytes;
    while !text.is_char_boundary(cut) {
        cut -= 1;
    }
    let mut bounded = String::with_capacity(cut + '…'.len_utf8());
    bounded.push_str(&text[..cut]);
    bounded.push('…');
    scrub_strict(&bounded)
}

/// The most rounds [`scrub_strict`] runs over one text. The call that shows a text
/// settled (output equal to input) counts: a text that needs this many calls, the
/// last of them changing nothing, still settles.
const MAX_ROUNDS: usize = 8;

/// Run `round` over `text` until its output equals its input, at most
/// [`MAX_ROUNDS`] times, and return that output. A text the round leaves alone costs
/// one round. When the last round allowed still changed its input, the text never
/// settled and the result is [`REDACTED`], not that round's output: it is not known to
/// be a fixed point and may still hold what a further round would mask.
fn converge(text: &str, round: impl Fn(&str) -> String) -> String {
    let mut current = round(text);
    if current == text {
        return current;
    }
    for _ in 1..MAX_ROUNDS {
        let next = round(&current);
        if next == current {
            return next;
        }
        current = next;
    }
    REDACTED.to_string()
}

/// One round of [`scrub_strict`]: the PEM pre-pass, the frames pre-pass,
/// `scrub_text`, then P2 to P6.
fn scrub_round(text: &str) -> String {
    let blocks_masked = mask_pem_blocks(text);
    let frames_masked = mask_value_frames(&blocks_masked);
    let scrubbed = scrub_text(&frames_masked);
    let headers_masked = mask_header_lines(&scrubbed);
    let basic_masked = mask_basic_credentials(&headers_masked);
    let userinfo_masked = mask_url_userinfo(&basic_masked);
    let shapes_masked = mask_credential_shapes(&userinfo_masked);
    mask_extra_pairs(&shapes_masked)
}

// ---- Shared helpers

/// Whether `b` can be part of a name run: an ASCII alphanumeric, `_`, `.` or `-`.
/// Every other byte, a non-ASCII one included, ends a run. P2 reads header names as
/// whole runs of these, and the frames pre-pass and P6 read key runs with them.
fn is_name_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-')
}

/// An ASCII alphanumeric or `_`: a word of an identifier (`Some`, `Str`), and the body
/// alphabet of a `github_pat_` token.
fn is_word_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// A space or a tab: the blank between a keyword and its token (P3), and the first
/// byte of a folded header line (P2).
fn is_space_or_tab(b: u8) -> bool {
    matches!(b, b' ' | b'\t')
}

/// ASCII whitespace of any kind, the vertical tab and form feed included.
fn is_ascii_ws(b: u8) -> bool {
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

/// A zero-width character a header parser would not see between a name and its
/// colon: U+200B to U+200D, the word joiner U+2060 and the byte order mark U+FEFF.
fn is_zero_width(c: char) -> bool {
    matches!(c, '\u{200b}'..='\u{200d}' | '\u{2060}' | '\u{feff}')
}

/// The index of the first character at or after `from` that is not a blank inside
/// a line (P2): any Unicode whitespace except a CR or a LF, as `scrub_text` reads
/// whitespace, and the zero-width characters. Reading only a space and a tab would
/// let a header whose value is whitespace alone (`Authorization:` then U+2028) be
/// rewritten here, and the CR after it then be eaten by a second `scrub_text` (its
/// `.+` matches a CR), which breaks idempotence. `from` not on a char boundary, or
/// past the end, is returned unchanged.
fn skip_blanks_in_line(text: &str, from: usize) -> usize {
    let Some(rest) = text.get(from..) else {
        return from;
    };
    let blanks: usize = rest
        .chars()
        .take_while(|&c| (c.is_whitespace() && !matches!(c, '\r' | '\n')) || is_zero_width(c))
        .map(char::len_utf8)
        .sum();
    from + blanks
}

/// Whether the name run `bytes[start..end]` is the host of a `host:port` rather
/// than a header name: the run contains a `.`, the very next byte is `:`, and one
/// to five ASCII digits follow it and then `/`, `?`, `#`, a byte for which
/// `ends_port` holds or the end of the text. Reads at most seven bytes past the run.
/// P2 and P6 end a port at whitespace; the frames pre-pass, which stands in front of
/// `scrub_text`, ends it where `scrub_text` does (`ends_value`).
fn is_host_port(bytes: &[u8], start: usize, end: usize, ends_port: fn(u8) -> bool) -> bool {
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
            .is_none_or(|&b| matches!(b, b'/' | b'?' | b'#') || ends_port(b))
}

// What `scrub_text` does to a pair is private to `redact.rs`, which is not edited
// for the audit log, so the frames pre-pass (`mask_value_frames`) and P6
// (`mask_extra_pairs`) read a pair with copies of its helpers: `is_name_byte` (its
// `is_key_byte`), `is_ascii_ws` (its `is_ascii_blank`), `run_end`, `blank_len`,
// `skip_blanks_and_breaks` (its `skip_blanks`), `ends_value`, `unquoted_value_end`,
// `is_opening_quote` and `closing_quote`, and `is_host_port`, which P2 and P6 end at
// `/`, `?`, `#` or whitespace and not at the other value delimiters `scrub_text` also
// accepts (P6 uses it only for keys `scrub_text` does not know, so the narrower
// exemption masks more). They must end a value where `scrub_text` ends it, and the
// test `the_pair_value_rule_matches_scrub_text` holds the two together. A change to
// the value rule there is a change here, with one deliberate difference: an unquoted
// value runs across a quote that something follows (`unquoted_value_end_across_quotes`).

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
        Some(&b) if b < 0x80 => usize::from(is_ascii_ws(b)),
        Some(_) => text
            .get(i..)
            .and_then(|rest| rest.chars().next())
            .filter(|c| c.is_whitespace())
            .map_or(0, char::len_utf8),
    }
}

/// The index of the first byte at or after `i` that does not start a whitespace
/// character of any kind, a line break included.
fn skip_blanks_and_breaks(text: &str, mut i: usize) -> usize {
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
    is_ascii_ws(b) || matches!(b, b'&' | b';' | b',' | b'"' | b'\'' | b'}')
}

/// The index where an unquoted value starting at `from` ends.
fn unquoted_value_end(text: &str, from: usize) -> usize {
    run_end(text, from, |b| !ends_value(b))
}

/// Whether a quote followed by the text at `after` is part of an unquoted value rather
/// than its end: something follows, and it is not whitespace, `&`, `;`, `,`, `}` or `]`
/// (`O'Brien`, `ab"cd`). `scrub_text` ends an unquoted value at any quote, which keeps
/// the tail of a password with an apostrophe in it.
fn quote_continues_value(text: &str, after: usize) -> bool {
    // `after` follows an ASCII quote, so it is a char boundary.
    text[after..]
        .chars()
        .next()
        .is_some_and(|c| !(c.is_whitespace() || matches!(c, '&' | ';' | ',' | '}' | ']')))
}

/// Where an unquoted value that starts at `from` ends, and whether it ran across a
/// quote: the rule of `scrub_text` (`unquoted_value_end`) except that a quote for which
/// [`quote_continues_value`] holds is part of the value. Each step consumes the quote
/// it crosses, so the work is linear.
fn unquoted_value_end_across_quotes(text: &str, from: usize) -> (usize, bool) {
    let bytes = text.as_bytes();
    let mut end = from;
    let mut across = false;
    loop {
        end = unquoted_value_end(text, end);
        match bytes.get(end) {
            Some(b'"' | b'\'') if quote_continues_value(text, end + 1) => {
                across = true;
                end += 1;
            }
            _ => return (end, across),
        }
    }
}

/// Where the value of a pair starts, given the index just after its separator: after
/// whitespace and an optional opening quote. With the end of the quoted value when that
/// quote closes (the quoted rule of `scrub_text`, which is not changed). A failed search
/// for a closing quote reads to the end of the text, and a later search for the same
/// quote character would fail too (a candidate is judged on the characters around it
/// alone), so `quote_unclosed` remembers it and the search is not run again.
fn pair_value_start(
    text: &str,
    after_separator: usize,
    quote_unclosed: &mut [bool; 2],
) -> (usize, Option<usize>) {
    let bytes = text.as_bytes();
    let mut j = skip_blanks_and_breaks(text, after_separator);
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
    (value_start, closer)
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

/// The text with spans replaced by `[redacted]`, built only when a span is masked:
/// the unchanged text is borrowed back. Spans must be masked in order and must not
/// overlap, and both ends must be char boundaries.
struct Masks<'a> {
    text: &'a str,
    out: String,
    /// Start of the text not yet copied into `out`.
    copied: usize,
    masked: bool,
}

impl<'a> Masks<'a> {
    fn new(text: &'a str) -> Self {
        Self {
            text,
            out: String::new(),
            copied: 0,
            masked: false,
        }
    }

    fn mask(&mut self, start: usize, end: usize) {
        self.out.push_str(&self.text[self.copied..start]);
        self.out.push_str(REDACTED);
        self.copied = end;
        self.masked = true;
    }

    fn finish(mut self) -> Cow<'a, str> {
        if !self.masked {
            return Cow::Borrowed(self.text);
        }
        self.out.push_str(&self.text[self.copied..]);
        Cow::Owned(self.out)
    }
}

// ---- PEM pre-pass

/// The most label bytes a PEM private key marker line may carry between the
/// keyword and the closing dashes (`PGP PRIVATE KEY BLOCK` is 21).
const PEM_LABEL_MAX: usize = 48;

/// How a label of a private key marker line ends: `PRIVATE KEY` for PEM
/// (`RSA PRIVATE KEY`, `ENCRYPTED PRIVATE KEY`) and `PRIVATE KEY BLOCK` for the
/// PGP armor.
const PEM_LABEL_ENDS: [&[u8]; 2] = [b"PRIVATE KEY", b"PRIVATE KEY BLOCK"];

const PEM_BEGIN: &str = "-----BEGIN ";
const PEM_END: &str = "-----END ";

/// If a PEM marker line starts at `at` with `keyword` (`-----BEGIN ` or
/// `-----END `), a label of capital letters, digits and spaces that ends as
/// [`PEM_LABEL_ENDS`] says, and the closing dashes, the index just past those
/// dashes.
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
    if label_len > PEM_LABEL_MAX {
        return None;
    }
    let label = &after_keyword[..label_len];
    if !PEM_LABEL_ENDS.iter().any(|end| label.ends_with(end)) {
        return None;
    }
    let dashes = label_start + label_len;
    bytes
        .get(dashes..)?
        .starts_with(b"-----")
        .then_some(dashes + 5)
}

/// The end of the private key block that starts at `at`, or `None` when no
/// `-----BEGIN ... PRIVATE KEY-----` (or `... PRIVATE KEY BLOCK-----`) line starts
/// there. The block runs through the first matching `-----END ...` line after it, or
/// to the end of the text when there is none, so an unterminated block masks
/// everything after its header. Each marker candidate costs a bounded read and the
/// search resumes after it.
fn pem_block_end(text: &str, at: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    let header_end = pem_marker_end(bytes, at, PEM_BEGIN)?;
    let mut from = header_end;
    while let Some(found) = text.get(from..).and_then(|rest| rest.find(PEM_END)) {
        let marker = from + found;
        if let Some(end) = pem_marker_end(bytes, marker, PEM_END) {
            return Some(end);
        }
        from = marker + 1;
    }
    Some(text.len())
}

/// The PEM pre-pass: mask every private key block, header to closing line, before
/// any other pass runs. The other passes read a block line by line, and a key name
/// in front of it (`password: -----BEGIN ...`) would have its own mask take the
/// header line and leave the key body, which nothing after that can tell from text.
/// What came before the block stays: `private_key: [redacted]`. The text is borrowed
/// back when it holds no block. One left-to-right search: a header costs a bounded
/// read, and a block that is masked is skipped whole.
fn mask_pem_blocks(text: &str) -> Cow<'_, str> {
    let mut masks = Masks::new(text);
    let mut from = 0;
    while let Some(found) = text.get(from..).and_then(|rest| rest.find(PEM_BEGIN)) {
        let start = from + found;
        match pem_block_end(text, start) {
            Some(end) => {
                // A block starts on an ASCII `-` and ends on an ASCII `-` or at the
                // end of the text, so both slice points are char boundaries.
                masks.mask(start, end);
                from = end;
            }
            None => from = start + 1,
        }
    }
    masks.finish()
}

// ---- Frames pre-pass

/// The most bytes of a multipart field name that are read after a `name="`, and the
/// most bytes of part headers searched for the blank line that ends them (these
/// bound the work per field).
const MULTIPART_FIELD_MAX: usize = 128;
const MULTIPART_HEADER_WINDOW: usize = 512;

fn is_ident_start(b: u8) -> bool {
    b.is_ascii_alphabetic() || b == b'_'
}

fn is_xml_name_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-' | b':')
}

/// The index just past the quoted string that opens at `open` (a quote byte), where
/// a backslash escapes the next byte, or the end of the text when it never closes.
fn quoted_end(bytes: &[u8], open: usize) -> usize {
    let quote = bytes[open];
    let mut k = open + 1;
    while k < bytes.len() {
        match bytes[k] {
            b'\\' => k += 2,
            b if b == quote => return k + 1,
            _ => k += 1,
        }
    }
    bytes.len()
}

/// The index just past the bracketed group that opens at `open` (a `[` or a `{`):
/// `[` and `{` are counted against `]` and `}`, strings in either quote are skipped
/// whole, and a group that never closes runs to the end of the text, so a mask over it
/// fails closed. A parenthesis is not counted: in a flow list an unmatched one is text
/// (`[a), b]`), and in `Debug` output, where parentheses balance, counting them would
/// change nothing.
fn bracket_end(bytes: &[u8], open: usize) -> usize {
    let mut depth = 0usize;
    let mut k = open;
    while k < bytes.len() {
        match bytes[k] {
            b'"' | b'\'' => {
                k = quoted_end(bytes, k);
                continue;
            }
            b'[' | b'{' => depth += 1,
            b']' | b'}' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return k + 1;
                }
            }
            _ => {}
        }
        k += 1;
    }
    bytes.len()
}

/// The end of a value in escaped quotes that starts at `value`: a run of one or more
/// backslashes and a quote, the body, and the first quote of the same kind after a
/// run of exactly as many backslashes (a quote inside the body is escaped one level
/// deeper, with more). The whole frame, backslashes and quotes included, is the
/// value. A frame that never closes (a text cut by a cap) runs to the end of the
/// text. `None` when `value` does not start one.
fn escaped_frame_end(bytes: &[u8], value: usize) -> Option<usize> {
    let slashes_end = skip_while(bytes, value, |b| b == b'\\');
    let run = slashes_end - value;
    let quote = *bytes
        .get(slashes_end)
        .filter(|b| matches!(b, b'"' | b'\''))?;
    if run == 0 {
        return None;
    }
    let mut backslashes = 0usize;
    for (offset, &b) in bytes[slashes_end + 1..].iter().enumerate() {
        match b {
            b'\\' => backslashes += 1,
            b if b == quote => {
                if backslashes == run {
                    return Some(slashes_end + 1 + offset + 1);
                }
                backslashes = 0;
            }
            _ => backslashes = 0,
        }
    }
    Some(bytes.len())
}

/// The end of a Rust `Debug` wrapper that starts at `value`: `Ident(` and, after
/// optional whitespace, a string, a `[..]` or a `{..}` group, or another `Ident(`
/// (`Str("x")`, `Some(Str("x"))`, `Bytes([1, 2])`), then the closing parentheses of
/// the wrappers. The `{:#?}` form puts whitespace and a comma before each closer.
/// `None` when `value` is not a wrapper around a string or a group (`Some(5)` is
/// left to the pair rule).
fn wrapper_frame_end(text: &str, value: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut at = value;
    let mut depth = 0usize;
    let core = loop {
        let ident_end = skip_while(bytes, at, is_word_byte);
        if !bytes.get(at).copied().is_some_and(is_ident_start)
            || bytes.get(ident_end) != Some(&b'(')
        {
            return None;
        }
        depth += 1;
        at = skip_blanks_and_breaks(text, ident_end + 1);
        match bytes.get(at) {
            Some(b'"' | b'[' | b'{') => break at,
            Some(&b) if is_ident_start(b) => {}
            _ => return None,
        }
    };
    let mut end = if bytes[core] == b'"' {
        quoted_end(bytes, core)
    } else {
        bracket_end(bytes, core)
    };
    for _ in 0..depth {
        let closer = skip_while(bytes, end, |b| is_ascii_ws(b) || b == b',');
        if bytes.get(closer) != Some(&b')') {
            break;
        }
        end = closer + 1;
    }
    Some(end)
}

/// After the key run ending at `key_end`: an optional closing quote (with a run of
/// backslashes before it, for a key in escaped quotes), whitespace, then `=` or `:`.
/// The index of that separator.
fn separator_after_key(text: &str, key_end: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    let slashes_end = skip_while(bytes, key_end, |b| b == b'\\');
    let mut at = key_end;
    if matches!(bytes.get(slashes_end), Some(b'"' | b'\'')) {
        at = slashes_end + 1;
    }
    at = skip_blanks_and_breaks(text, at);
    matches!(bytes.get(at), Some(b'=' | b':')).then_some(at)
}

/// Whether `value` starts the shape of a frame that [`pair_frame`] reads: a `[` or a
/// `{`, a run of backslashes and a quote, or `Ident(`. A cheap look, with no scan to a
/// closer, so the key is not consulted for a value that is none of them.
fn starts_frame(bytes: &[u8], value: usize) -> bool {
    if matches!(bytes.get(value), Some(b'[' | b'{')) {
        return true;
    }
    let slashes_end = skip_while(bytes, value, |b| b == b'\\');
    if slashes_end > value {
        return matches!(bytes.get(slashes_end), Some(b'"' | b'\''));
    }
    let ident_end = skip_while(bytes, value, is_word_byte);
    bytes.get(value).copied().is_some_and(is_ident_start) && bytes.get(ident_end) == Some(&b'(')
}

/// What the frames pre-pass does with the value of a pair under a secret key.
enum Pair {
    /// Mask this span.
    Mask(usize, usize),
    /// Leave the value to the passes after: `scrub_text` or P6 mask it, and the scan
    /// resumes at this index, as theirs do.
    Skip(usize),
}

/// The value of a pair under a secret key, for the frames pre-pass: a frame that
/// `scrub_text` reads wrongly (a value in escaped quotes, a Rust `Debug` wrapper, a
/// `[..]` or `{..}` group, which it would cut after its opening bracket), or a plain
/// value that runs across a quote (`password=O'Brien`, which it would cut at the
/// apostrophe). A plain value that does not is left to the passes after, and the scan
/// goes on after it, as theirs does: a secret key's value is masked whole, and a scan
/// of it for every key inside it would be a pass per key. The exceptions are a host and
/// port (`auth.example.com:8443`), whose value is not masked, and an empty value.
///
/// The key is judged first, since every key with a separator is now read; the frame
/// shapes are cheap to see, a closer is scanned for only after, and a frame that is not
/// closed runs to the end of the text, so a failed scan is never repeated either.
fn pair_frame(
    text: &str,
    key_start: usize,
    key_end: usize,
    quote_unclosed: &mut [bool; 2],
) -> Option<Pair> {
    let bytes = text.as_bytes();
    let separator = separator_after_key(text, key_end)?;
    if !is_secret_key_strict(&text[key_start..key_end]) {
        return None;
    }
    let value = skip_blanks_and_breaks(text, separator + 1);
    if starts_frame(bytes, value) {
        let frame = escaped_frame_end(bytes, value)
            .or_else(|| wrapper_frame_end(text, value))
            .or_else(|| matches!(bytes[value], b'[' | b'{').then(|| bracket_end(bytes, value)));
        if let Some(end) = frame {
            return Some(Pair::Mask(value, end));
        }
    }
    if bytes[separator] == b':' && is_host_port(bytes, key_start, key_end, ends_value) {
        return None;
    }
    let (value_start, closer) = pair_value_start(text, separator + 1, quote_unclosed);
    if let Some(closer) = closer {
        return Some(Pair::Skip(closer));
    }
    let (value_end, across) = unquoted_value_end_across_quotes(text, value_start);
    if value_end == value_start {
        return None;
    }
    Some(if across {
        Pair::Mask(value_start, value_end)
    } else {
        Pair::Skip(value_end)
    })
}

/// The index of the `>` that closes the tag whose name ends at `from`, or `None`
/// when a `<` comes first. A quoted attribute value is skipped whole, so it may hold
/// a `>`, but it may not hold a `<`. The scan never reaches the next `<`, so the
/// scans of two tags do not overlap.
fn tag_close(bytes: &[u8], from: usize) -> Option<usize> {
    let mut k = from;
    while k < bytes.len() {
        match bytes[k] {
            b'>' => return Some(k),
            b'<' => return None,
            quote @ (b'"' | b'\'') => {
                let rel = bytes[k + 1..]
                    .iter()
                    .position(|&b| b == quote || b == b'<')?;
                if bytes[k + 1 + rel] == b'<' {
                    return None;
                }
                k += rel + 2;
                continue;
            }
            _ => {}
        }
        k += 1;
    }
    None
}

/// The content span of the XML or HTML element that opens at `lt` (a `<`) when its
/// name is a secret key: from the `>` of the start tag to the next `<` (the closing
/// tag, or a child), or through the `]]>` of a CDATA section, to the end of the text
/// when the element is cut. `None` for a closing tag, a self-closing tag, an empty or
/// blank content and any other name.
fn xml_content(text: &str, lt: usize) -> Option<(usize, usize)> {
    let bytes = text.as_bytes();
    let name_start = lt + 1;
    if !bytes.get(name_start).copied().is_some_and(is_ident_start) {
        return None;
    }
    let name_end = skip_while(bytes, name_start, is_xml_name_byte);
    let close = tag_close(bytes, name_end)?;
    if bytes[close - 1] == b'/' || !is_secret_key_strict(&text[name_start..name_end]) {
        return None;
    }
    let start = close + 1;
    let end = if bytes[start..].starts_with(b"<![CDATA[") {
        text[start..]
            .find("]]>")
            .map_or(text.len(), |at| start + at + 3)
    } else {
        bytes[start..]
            .iter()
            .position(|&b| b == b'<')
            .map_or(bytes.len(), |at| start + at)
    };
    (!text[start..end].trim().is_empty()).then_some((start, end))
}

/// The index just past the first empty line in `window` (a line break followed at
/// once by another), or `None` when there is none.
fn empty_line_end(window: &[u8]) -> Option<usize> {
    window.iter().enumerate().find_map(|(k, &b)| {
        if b != b'\n' {
            return None;
        }
        let rest = &window[k + 1..];
        if rest.starts_with(b"\r\n") {
            Some(k + 3)
        } else if rest.starts_with(b"\n") {
            Some(k + 2)
        } else {
            None
        }
    })
}

/// The index of the first line break at or after `from` that is followed by a
/// boundary line (one that starts with `--`), or the end of the text.
fn boundary_or_end(bytes: &[u8], from: usize) -> usize {
    let mut k = from;
    while k < bytes.len() {
        if matches!(bytes[k], b'\r' | b'\n') {
            let after = if bytes[k] == b'\r' && bytes.get(k + 1) == Some(&b'\n') {
                k + 2
            } else {
                k + 1
            };
            if bytes[after..].starts_with(b"--") {
                return k;
            }
        }
        k += 1;
    }
    bytes.len()
}

/// The value of a multipart field named by a secret key: `name="password"`, the rest
/// of that line and any further part header lines, an empty line, then the value up to
/// the boundary line, or to the end of the text when there is none (a value may run
/// over several lines, and the first line is not all of it).
///
/// The cost is bounded for every field. The name is read within
/// [`MULTIPART_FIELD_MAX`] bytes and judged first, so a field that is not secret costs
/// that read and nothing else, however long the text after it. A secret field's blank
/// line is looked for within [`MULTIPART_HEADER_WINDOW`] bytes, and its value, which
/// can be as long as the text, is consumed by the mask, so no byte is scanned twice.
/// `None` for an empty value.
fn multipart_value(text: &str, key_start: usize, key_end: usize) -> Option<(usize, usize)> {
    let bytes = text.as_bytes();
    if !text[key_start..key_end].eq_ignore_ascii_case("name") || bytes.get(key_end) != Some(&b'=') {
        return None;
    }
    let quote = *bytes
        .get(key_end + 1)
        .filter(|b| matches!(b, b'"' | b'\''))?;
    let field_start = key_end + 2;
    let field_len = bytes[field_start..]
        .iter()
        .take(MULTIPART_FIELD_MAX + 1)
        .position(|&b| b == quote || matches!(b, b'\r' | b'\n'))?;
    if bytes[field_start + field_len] != quote {
        return None;
    }
    // The field is judged before anything after it is read: the scan to the boundary
    // line is as long as the value, and for a field that is not secret it would be
    // thrown away, once for every such field.
    if !is_secret_key_strict(&text[field_start..field_start + field_len]) {
        return None;
    }
    let after_name = field_start + field_len + 1;
    let window = &bytes[after_name..bytes.len().min(after_name + MULTIPART_HEADER_WINDOW)];
    let value_start = after_name + empty_line_end(window)?;
    let value_end = boundary_or_end(bytes, value_start);
    (value_end > value_start).then_some((value_start, value_end))
}

/// The word after a command-line flag whose name is a secret key: `--password x`,
/// `--token 'a b'`. The word is a quoted string, or runs to the next whitespace
/// (a password may hold `&` or `;`). `--key=value` is a pair and is not read here.
/// `None` for a flag with no word after it on its line.
fn cli_value(text: &str, key_start: usize, key_end: usize) -> Option<(usize, usize)> {
    let bytes = text.as_bytes();
    if key_end - key_start <= 2 || !bytes[key_start..].starts_with(b"--") {
        return None;
    }
    let value = skip_while(bytes, key_end, is_space_or_tab);
    let first = *bytes.get(value)?;
    if value == key_end || matches!(first, b'\r' | b'\n') {
        return None;
    }
    if !is_secret_key_strict(&text[key_start + 2..key_end]) {
        return None;
    }
    let end = if matches!(first, b'"' | b'\'') {
        quoted_end(bytes, value)
    } else {
        run_end(text, value, |b| !is_ascii_ws(b))
    };
    (end > value).then_some((value, end))
}

/// The flags whose word is `user:password` (curl's `-u`, `--user`, and the proxy's
/// `-U`, `--proxy-user`).
const USERPASS_FLAGS: &[&str] = &["-u", "-U", "--user", "--proxy-user"];

/// The password of the word after a `user:password` flag: `-u admin:secret`,
/// `--proxy-user 'u:p w'`. The span is what follows the first colon of the word, and
/// the closing quote stays. A word with no colon, or nothing after it, has no password
/// (the tool asks for one). `None` for any other flag.
fn userpass_value(text: &str, key_start: usize, key_end: usize) -> Option<(usize, usize)> {
    let bytes = text.as_bytes();
    if !USERPASS_FLAGS.contains(&&text[key_start..key_end]) {
        return None;
    }
    let value = skip_while(bytes, key_end, is_space_or_tab);
    let first = *bytes.get(value)?;
    if value == key_end || matches!(first, b'\r' | b'\n') {
        return None;
    }
    let (word_start, word_end) = if matches!(first, b'"' | b'\'') {
        let end = quoted_end(bytes, value);
        let closed = end > value + 1 && bytes[end - 1] == first;
        (value + 1, if closed { end - 1 } else { end })
    } else {
        (value, run_end(text, value, |b| !is_ascii_ws(b)))
    };
    let colon = word_start + text[word_start..word_end].find(':')?;
    (colon + 1 < word_end).then_some((colon + 1, word_end))
}

/// The frames pre-pass. Run before `scrub_text`, because `scrub_text` would cut
/// these values in the wrong place (`Str("x")` after a key becomes
/// `[redacted]"x")`, and `token=\"x\"` becomes `token=[redacted]"x\"`), and for
/// frames it does not read at all. See [`scrub_strict`] for what is masked.
///
/// One left-to-right scan: an element opens at a `<`, anything else is read as a
/// run of name bytes, and each rule looks at what follows the run. The multipart,
/// flag and `user:password` rules look at the shape first and the key after; the pair
/// rule judges the key as soon as a separator follows it. A masked span is skipped
/// whole, a value that the passes after will mask is skipped too (see [`Pair`]), a
/// frame that never closes runs to the end of the text, and the multipart and element
/// scans are bounded, so the work is linear.
///
/// A secret-named element's content is masked when the scan reaches it (`pending`),
/// not when the element is found, so that the scan first reads the start tag, whose
/// interior is where a name and a frame can sit (`<otp: Some("x")>`).
fn mask_value_frames(text: &str) -> Cow<'_, str> {
    let bytes = text.as_bytes();
    let len = bytes.len();
    let mut masks = Masks::new(text);
    // The content of an element whose start tag is being scanned: masked once the
    // scan reaches it, unless a frame in the tag has covered it. The content starts
    // after the `>` that ends the tag, and the scan steps over that byte one at a time,
    // so it always reaches the start before the end of the text, or a frame has
    // covered the content; nothing is left pending when the loop ends.
    let mut pending: Option<(usize, usize)> = None;
    // Whether a search for a closing `"` (index 0) or `'` (index 1) has failed.
    let mut quote_unclosed = [false; 2];
    let mut i = 0;
    while i < len {
        if let Some((start, end)) = pending.filter(|&(start, _)| i >= start) {
            pending = None;
            if start >= masks.copied {
                masks.mask(start, end);
                i = i.max(end);
                continue;
            }
        }
        if bytes[i] == b'<' {
            // The start tag is scanned too, for frames of its own (`<otp: Some("x")>`):
            // the scan goes on at the name, and the content is masked when it is reached.
            match xml_content(text, i) {
                Some(content) => {
                    pending = Some(content);
                    i += 1;
                }
                None => i += 1,
            }
            continue;
        }
        let key_start = i;
        let key_end = run_end(text, key_start, is_name_byte);
        if key_end == key_start {
            // A delimiter or a whitespace char: step over the whole char.
            i += blank_len(text, i).max(1);
            continue;
        }
        i = key_end;
        let found = multipart_value(text, key_start, key_end)
            .or_else(|| cli_value(text, key_start, key_end))
            .or_else(|| userpass_value(text, key_start, key_end))
            .map(|(start, end)| Pair::Mask(start, end))
            .or_else(|| pair_frame(text, key_start, key_end, &mut quote_unclosed));
        match found {
            Some(Pair::Mask(start, end)) => {
                masks.mask(start, end);
                i = end;
            }
            Some(Pair::Skip(to)) => i = to,
            None => {}
        }
    }
    masks.finish()
}

// ---- P2: header lines

/// The end of a header value whose first line ends at `line_end` (a CR, a LF or the
/// end of the text): the value goes on through every following line that starts with
/// a space or a tab (a folded line, RFC 9112 section 5.2).
fn folded_end(bytes: &[u8], mut line_end: usize) -> usize {
    loop {
        let next = match bytes.get(line_end) {
            Some(b'\r') if bytes.get(line_end + 1) == Some(&b'\n') => line_end + 2,
            Some(b'\r' | b'\n') => line_end + 1,
            _ => return line_end,
        };
        if !bytes.get(next).copied().is_some_and(is_space_or_tab) {
            return line_end;
        }
        line_end = skip_while(bytes, next, |b| !matches!(b, b'\r' | b'\n'));
    }
}

/// P2. See [`scrub_strict`]. One left-to-right scan: each name run is read once,
/// and a masked line, folded lines included, is skipped whole, so the work is
/// linear.
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
        let colon = skip_blanks_in_line(text, end);
        if bytes.get(colon) != Some(&b':') {
            continue;
        }
        // A name run is ASCII, so `start..end` is on char boundaries.
        let name = &text[start..end];
        let at_line_start = start == 0 || matches!(bytes[start - 1], b'\r' | b'\n');
        let masks = CREDENTIAL_HEADERS
            .iter()
            .any(|header| name.eq_ignore_ascii_case(header))
            || (at_line_start
                && is_secret_key_strict(name)
                && !is_host_port(bytes, start, end, is_ascii_ws));
        if !masks {
            continue;
        }

        // The rest of the line after the colon and its blanks, and the folded lines
        // after it. An empty value with no folded line is left alone, as
        // `scrub_text` leaves one.
        let value_start = skip_blanks_in_line(text, colon + 1);
        let first_end = skip_while(bytes, value_start, |b| !matches!(b, b'\r' | b'\n'));
        let value_end = folded_end(bytes, first_end);
        if value_end == value_start {
            continue;
        }
        // `colon` is an ASCII byte and `value_end` is a CR, a LF or the end of the
        // text, so both slice points are char boundaries.
        out.push_str(&text[copied..=colon]);
        out.push(' ');
        out.push_str(REDACTED);
        copied = value_end;
        i = value_end;
    }
    out.push_str(&text[copied..]);
    out
}

// ---- P3: Basic, Negotiate and NTLM credentials

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

/// The fewest characters of a Basic token that P3 reads: `user:pass` is 6 bytes, which
/// is 8 characters of base64.
const BASIC_TOKEN_MIN: usize = 8;

/// The fewest characters of a Negotiate or NTLM token that P3 reads: such a token is a
/// binary message, much longer than a word.
const NEGOTIATE_TOKEN_MIN: usize = 16;

/// A credential scheme keyword that P3 reads, and what its token must be.
struct Scheme {
    /// The keyword, matched ASCII case-insensitively.
    keyword: &'static str,
    /// The fewest token characters that make a credential.
    min_token: usize,
    /// The token must decode to the `user:pass` shape (only Basic has one).
    must_decode: bool,
}

const SCHEMES: &[Scheme] = &[
    Scheme {
        keyword: "basic",
        min_token: BASIC_TOKEN_MIN,
        must_decode: true,
    },
    Scheme {
        keyword: "negotiate",
        min_token: NEGOTIATE_TOKEN_MIN,
        must_decode: false,
    },
    Scheme {
        keyword: "ntlm",
        min_token: NEGOTIATE_TOKEN_MIN,
        must_decode: false,
    },
];

/// The scheme whose keyword `bytes[at..]` starts with, or `None`.
fn scheme_at(bytes: &[u8], at: usize) -> Option<&'static Scheme> {
    let rest = bytes.get(at..)?;
    SCHEMES.iter().find(|scheme| {
        rest.get(..scheme.keyword.len())
            .is_some_and(|head| head.eq_ignore_ascii_case(scheme.keyword.as_bytes()))
    })
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
        let Some(scheme) = scheme_at(bytes, i) else {
            i += 1;
            continue;
        };
        let after_keyword = i + scheme.keyword.len();
        let token_start = skip_while(bytes, after_keyword, is_space_or_tab);
        if token_start == after_keyword {
            // No blank after the keyword (`basicbasicbasic...`): not a credential
            // header, and the token run is not read, so a long run of keywords
            // costs a constant each.
            i += 1;
            continue;
        }
        let token_end = skip_while(bytes, token_start, is_base64_token_byte);
        let token = &bytes[token_start..token_end];
        if token.len() >= scheme.min_token && (!scheme.must_decode || decodes_with_colon(token)) {
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

// ---- P4: URL userinfo

/// A userinfo with no password part (no colon) is masked when it is this long: a user
/// name is a word, a longer one is a token (`ssh://git@host` stays).
const USERINFO_NAME_ONLY_MIN: usize = 20;

/// Whether `b` can end the scheme in front of `://`: an ASCII alphanumeric, `+`,
/// `.` or `-`.
fn is_scheme_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'+' | b'.' | b'-')
}

/// The index of the last `@` of the authority that starts at `from`, which ends its
/// userinfo, or `None` when the authority has none. The authority ends at the first
/// `/`, `?`, `#` or whitespace character, at the end of the text, or at `opening_quote`
/// when the URL stood in a quoted string (the quote in front of its scheme); any other
/// quote belongs to the password (`O'Brien`). A browser takes the host after the last
/// `@`, so a password holding a raw `@` is all userinfo. Whitespace is Unicode
/// whitespace, as `scrub_text` reads it: it ends the value of a `key:value` pair
/// there, so a pass that masked across one (a no-break space inside a "password")
/// would let the next call read that value further than this one did.
fn userinfo_end(text: &str, from: usize, opening_quote: Option<char>) -> Option<usize> {
    let mut last_at = None;
    for (offset, c) in text.get(from..)?.char_indices() {
        match c {
            '@' => last_at = Some(from + offset),
            '/' | '?' | '#' => break,
            c if c.is_whitespace() || Some(c) == opening_quote => break,
            _ => {}
        }
    }
    last_at
}

/// P4. See [`scrub_strict`]. The text is searched for `://` once, left to right.
/// The authority scan after a `://` stops at the first `/` at the latest, and a later
/// `://` has a `/` in it, so two scans never overlap and the work is linear (so do the
/// look back over the scheme, which no other scheme's look back shares).
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
        // The quote in front of the scheme, if the URL stands in a quoted string.
        let scheme_start = bytes[..separator]
            .iter()
            .rposition(|&b| !is_scheme_byte(b))
            .map_or(0, |at| at + 1);
        let opening_quote = scheme_start
            .checked_sub(1)
            .map(|at| char::from(bytes[at]))
            .filter(|c| matches!(c, '"' | '\''));
        let Some(at) = userinfo_end(text, authority, opening_quote) else {
            continue;
        };
        // `authority` and `at` (an ASCII `@`) are char boundaries.
        let userinfo = &text[authority..at];
        let mask_from = match userinfo.find(':') {
            // The part after the first colon; an empty one is no secret.
            Some(colon) => (colon + 1 < userinfo.len()).then_some(authority + colon + 1),
            None => (userinfo.len() >= USERINFO_NAME_ONLY_MIN || contains_shape(userinfo))
                .then_some(authority),
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

// ---- P5: credential shapes

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

/// The prefix-and-body shapes of P5. The JWT and JWE have their own scan.
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
        body: is_word_byte,
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

/// The prefix of a JWT or JWE header: `{"` in base64url.
const JWT_PREFIX: &[u8] = b"eyJ";

/// The bytes a P5 credential can start with: the first byte of every prefix of
/// [`SHAPES`] and of [`JWT_PREFIX`], built from the tables so that a prefix added to
/// one cannot be left out of the scan.
static FIRST_BYTES: [bool; 256] = first_bytes();

const fn first_bytes() -> [bool; 256] {
    let mut table = [false; 256];
    table[JWT_PREFIX[0] as usize] = true;
    let mut shape = 0;
    while shape < SHAPES.len() {
        let prefixes = SHAPES[shape].prefixes;
        let mut prefix = 0;
        while prefix < prefixes.len() {
            table[prefixes[prefix].as_bytes()[0] as usize] = true;
            prefix += 1;
        }
        shape += 1;
    }
    table
}

/// Whether the prefix of a [`SHAPES`] credential or of a JWT starts at `at`. An
/// exact-length shape is not held back by a following alphanumeric that opens one:
/// that neighbour is masked in the same scan, and a boundary that waited for it
/// would be met by the second call and not by the first.
fn starts_shape(bytes: &[u8], at: usize) -> bool {
    let rest = bytes.get(at..).unwrap_or_default();
    rest.starts_with(JWT_PREFIX)
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

/// The fewest characters of the first and the second segment of a JWT (the header and
/// the payload, which a JSON object makes at least this long in base64url).
const JWT_SEGMENT_MIN: usize = 8;

/// How many dot-separated segments a compact JWE has: the header, the encrypted
/// key, the initialisation vector, the ciphertext and the tag.
const JWE_SEGMENTS: usize = 5;

/// The end of the JWT or compact JWE starting at `at` (on `eyJ`, at a boundary), or
/// `None`. A JWT is a first segment of at least 8 base64url characters (the `eyJ`
/// included), a dot, a second segment of at least 8, a dot, and a third segment of
/// any length, the signature, which an unsecured token leaves empty. A compact JWE
/// is the first segment and four more: the encrypted key, the vector and the
/// ciphertext may be empty (`dir` has no key), the tag may not.
///
/// A failed attempt reads the first segment to its end, `first_end`, and the
/// verdict of any attempt that starts inside that segment is the same (it ends at
/// the same dot and meets the same later segments, with a shorter first one), so
/// `dead_until` is set and those attempts are skipped: without that, `eyJ-eyJ-...`
/// would cost a pass over the rest of the text at every `eyJ`. An attempt reads at
/// most four segments past the first, so each run of base64url characters is read a
/// constant number of times.
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
    if first_end - at < JWT_SEGMENT_MIN || bytes.get(first_end) != Some(&b'.') {
        return None;
    }
    // `ends[k]` is the end of segment `k`; each later one follows a dot.
    let mut ends = [first_end; JWE_SEGMENTS];
    let mut count = 1;
    while count < JWE_SEGMENTS && bytes.get(ends[count - 1]) == Some(&b'.') {
        ends[count] = skip_while(bytes, ends[count - 1] + 1, body_base64url);
        count += 1;
    }
    let tag_is_empty = ends[JWE_SEGMENTS - 1] == ends[JWE_SEGMENTS - 2] + 1;
    if count == JWE_SEGMENTS && !tag_is_empty {
        return Some(ends[JWE_SEGMENTS - 1]);
    }
    // A JWT: the second segment is at least 8, and a dot and a third segment follow.
    (count >= 3 && ends[1] - (first_end + 1) >= JWT_SEGMENT_MIN).then_some(ends[2])
}

/// The end of the P5 credential that starts at `at`, or `None`. `from` is where the
/// scan started: the start of the text, or the end of the credential masked just
/// before, whose last byte the candidate at `from` is glued to. `jwt_dead_until` is
/// the JWT scan's memory (see [`jwt_end`]).
fn shape_end_at(text: &str, at: usize, from: usize, jwt_dead_until: &mut usize) -> Option<usize> {
    let bytes = text.as_bytes();
    if !FIRST_BYTES[usize::from(bytes[at])] {
        return None;
    }
    // The previous byte must not be an ASCII alphanumeric, so a prefix in the middle
    // of a word (`task-` for `sk-`) is not one. At `from` the previous byte is the
    // end of a credential that is masked by then, and `]` is a boundary: judging the
    // candidate by the byte that stood there would leave it for the next call.
    if at > from && bytes[at - 1].is_ascii_alphanumeric() {
        return None;
    }
    if bytes[at..].starts_with(JWT_PREFIX) {
        jwt_end(bytes, at, jwt_dead_until)
    } else {
        table_shape_end(bytes, at)
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

// ---- P6: pairs of the extra key words

/// The index just past the bracket groups that follow a key run ending at `from`:
/// any number of `[` and a name and `]` (`user[password]`, `a[b][c]`, `password[]`).
/// `from` itself when there is none. A `[` that does not open such a group ends it.
fn bracket_groups_end(bytes: &[u8], from: usize) -> usize {
    let mut end = from;
    while bytes.get(end) == Some(&b'[') {
        let name_end = skip_while(bytes, end + 1, is_name_byte);
        if bytes.get(name_end) != Some(&b']') {
            break;
        }
        end = name_end + 1;
    }
    end
}

/// P6. See [`scrub_strict`]. One linear scan, structured as the pair pass of
/// `scrub_text` and reading a value with copies of its helpers (see the note above
/// `run_end`): a key run is followed by an optional closing quote, whitespace and
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

        // Bracket groups after the run belong to the key (`user[password]`).
        let groups_end = bracket_groups_end(bytes, key_end);
        let bracketed = groups_end > key_end;

        // Key run and groups, optional closing quote, whitespace, then `=` or `:`.
        let mut j = groups_end;
        if j < len && matches!(bytes[j], b'"' | b'\'') {
            j += 1;
        }
        j = skip_blanks_and_breaks(text, j);
        if j >= len || !matches!(bytes[j], b'=' | b':') {
            continue;
        }
        let separator = bytes[j];
        j += 1;

        // The scan only stops on char boundaries and `run_end` steps whole chars,
        // so `key_start..groups_end` is on char boundaries. A key with groups is a
        // form field name that `scrub_text` never read as a pair, so the whole
        // vocabulary applies; one without is read as `scrub_text` read it, and only
        // what `scrub_text` does not know is masked here.
        // The whole text is judged, brackets included: every group is a segment of it
        // and every needle a substring, so a word in the run or in any group is found.
        let secret = if bracketed {
            is_secret_key_strict(&text[key_start..groups_end])
        } else {
            is_extra_secret_key(&text[key_start..key_end])
        };
        if !secret {
            continue;
        }
        if !bracketed && separator == b':' && is_host_port(bytes, key_start, key_end, is_ascii_ws) {
            continue;
        }

        // Whitespace, an optional opening quote, then the value: the quoted rule of
        // `scrub_text`, or the unquoted one, which runs across a quote that something
        // follows.
        let (value_start, closer) = pair_value_start(text, j, &mut quote_unclosed);
        let value_end = match closer {
            Some(end) => end,
            // Unquoted, or an opening quote that never closes: the plain rule.
            None => unquoted_value_end_across_quotes(text, value_start).0,
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

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::{converge, scrub_round, scrub_strict, MAX_ROUNDS, SHAPES};

    /// `converge` over `round`, and how many times it called it.
    fn run(text: &str, round: impl Fn(&str) -> String) -> (String, usize) {
        let calls = Cell::new(0);
        let out = converge(text, |t| {
            calls.set(calls.get() + 1);
            round(t)
        });
        (out, calls.get())
    }

    #[test]
    fn every_entry_of_the_shape_table_fires_at_its_minimum_and_not_below() {
        // `A` is in every body alphabet of the table. For each prefix: the shortest
        // body is masked whole, one byte less is not a credential, and the prefix
        // glued to the end of a word is not the start of one.
        let mut failures = Vec::new();
        for shape in SHAPES {
            assert!(
                (shape.body)(b'A'),
                "`A` must be in the body alphabet of {:?}",
                shape.prefixes
            );
            for prefix in shape.prefixes {
                let full = format!("{prefix}{}", "A".repeat(shape.min));
                let short = format!("{prefix}{}", "A".repeat(shape.min - 1));
                let glued = format!("x{full}");
                for (label, input, want) in [
                    ("shortest body", &full, "[redacted]"),
                    ("one byte short", &short, short.as_str()),
                    ("glued to a word", &glued, glued.as_str()),
                ] {
                    let got = scrub_strict(input);
                    if got != want {
                        failures.push(format!("{prefix} {label}: {input:?} gives {got:?}"));
                    }
                }
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }

    #[test]
    fn an_unchanged_text_costs_exactly_one_round() {
        assert_eq!(run("abc", str::to_string), ("abc".to_string(), 1));
    }

    #[test]
    fn rounds_repeat_until_the_output_equals_the_input() {
        // Each round drops one trailing `x`: `abxx` -> `abx` -> `ab`, and the third
        // round leaves `ab` as it was, which is the proof of a fixed point.
        let drop_one = |t: &str| t.strip_suffix('x').unwrap_or(t).to_string();
        assert_eq!(run("abxx", drop_one), ("ab".to_string(), 3));
    }

    #[test]
    fn a_text_that_never_settles_is_replaced_whole_after_max_rounds() {
        // A round that never settles is cut off after MAX_ROUNDS calls. The last output
        // (one more `x` per round) is not the result, because it was never seen to be
        // a fixed point: it may still hold what a later round would have masked, so the
        // text is replaced whole.
        assert_eq!(
            run("", |t| format!("{t}x")),
            ("[redacted]".to_string(), MAX_ROUNDS)
        );
    }

    #[test]
    fn a_text_that_settles_on_the_last_allowed_round_is_kept() {
        // Each round drops one trailing `x`, and the call that leaves the text as it
        // was proves it settled. `MAX_ROUNDS - 1` copies of `x` need exactly MAX_ROUNDS
        // calls, so the proof arrives on the last call allowed; one more `x` needs a
        // call beyond the cap.
        let drop_one = |t: &str| t.strip_suffix('x').unwrap_or(t).to_string();
        assert_eq!(
            run(&"x".repeat(MAX_ROUNDS - 1), drop_one),
            (String::new(), MAX_ROUNDS)
        );
        assert_eq!(
            run(&"x".repeat(MAX_ROUNDS), drop_one),
            ("[redacted]".to_string(), MAX_ROUNDS)
        );
    }

    #[test]
    fn a_shape_that_needs_seven_calls_settles_within_the_cap() {
        // Found by fuzzing. Each round re-pairs the quotes and masks one more segment
        // (`"otp:(": ` first, then the next quote-delimited run, and so on). The text
        // after the sixth call is the fixed point, and the seventh call proves it, one
        // more than an earlier, smaller cap of `converge` allowed.
        let shape = "-u\t\"otp:(\": \"h\u{3000}\"#&\"D \"c ";
        let (out, calls) = run(shape, scrub_round);
        assert_eq!(out, "-u\t\"otp:[redacted]");
        assert_eq!(calls, 7);
        assert!(calls <= MAX_ROUNDS, "{calls} calls, cap {MAX_ROUNDS}");
    }

    #[test]
    fn the_replacement_is_itself_a_fixed_point() {
        // `scrub_strict` is idempotent over what the fail-closed path returns.
        assert_eq!(scrub_strict("[redacted]"), "[redacted]");
        let (out, calls) = run("[redacted]", scrub_round);
        assert_eq!((out.as_str(), calls), ("[redacted]", 1));
    }
}
