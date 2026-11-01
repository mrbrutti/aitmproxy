//! Offset-recording multipart part parser, splicing and filename escaping (task 7).
//!
//! `multipart/form-data` bodies (RFC 2046 / RFC 7578) parsed once into byte
//! spans: `points.rs` names an insertion point from a span and `mutate.rs`
//! splices one payload into it, so every byte the scanner did not target
//! survives the round trip unchanged — including file-part bytes, which are
//! never copied out of the body.
//!
//! The parser is hand-rolled on purpose (plan decision 3) and strictly CRLF
//! (plan call A7): an LF-only body is an `Err`, not a guess, because guessing
//! would shift every span by one byte per line. Every read is a bounds-checked
//! slice, malformed input is an `Err` naming a byte offset rather than a panic,
//! and no error message or `Debug` line carries header or body content.

use std::fmt;
use std::ops::Range;

use anyhow::{anyhow, bail, Result};

use crate::limits::MAX_MULTIPART_PARTS;

/// One parsed part: who it is, and where its mutable bytes live.
///
/// Spans are byte offsets into the body passed to [`parse`], never copies of
/// the part content.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Part {
    /// `Content-Disposition` `name=` parameter, if the part has one.
    pub name: Option<String>,
    /// `Content-Disposition` `filename=` parameter, if the part has one.
    pub filename: Option<String>,
    /// The filename bytes in the body (between the quotes when quoted), so a
    /// `multipart_filename` point can be spliced without rewriting the header.
    pub filename_span: Option<Range<usize>>,
    /// The part's own `Content-Type` header value, trimmed.
    pub content_type: Option<String>,
    /// The part content: the bytes between the blank line that ends the part
    /// headers and the CRLF that introduces the next delimiter.
    pub value_span: Range<usize>,
}

/// Structure only. The filename is a header value, so it is printed as a
/// length and never as text (crate redaction rules, spec D8.1).
impl fmt::Debug for Part {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Part")
            .field("name", &self.name)
            .field("filename_len", &self.filename.as_ref().map(String::len))
            .field("filename_span", &self.filename_span)
            .field("content_type", &self.content_type)
            .field("value_span", &self.value_span)
            .finish()
    }
}

/// The `boundary` parameter of a `multipart/*` content type.
///
/// `None` when the media type is not `multipart/*`, when there is no
/// `boundary` parameter, or when the boundary is empty or carries a line
/// break (which no delimiter can contain).
///
/// The one reading of the header the lane has: `params::body_format` resolves
/// the boundary here before it hands one to [`parse`].
pub(crate) fn boundary_of(content_type: &str) -> Option<String> {
    let (media, rest) = content_type.split_once(';')?;
    if !media.trim().to_ascii_lowercase().starts_with("multipart/") {
        return None;
    }
    let (_, value, _) = params(rest)
        .into_iter()
        .find(|(key, _, _)| key == "boundary")?;
    if value.is_empty() || value.bytes().any(|b| b == b'\r' || b == b'\n') {
        return None;
    }
    Some(value)
}

/// Parses a multipart body into its parts, recording spans.
///
/// Errors (never panics) when the body has no opening delimiter, no closing
/// `--boundary--`, a delimiter not followed by CRLF (an LF-only body), part
/// headers that no blank line terminates, or a header that is not UTF-8. At
/// most [`MAX_MULTIPART_PARTS`] parts are returned; the rest are ignored.
pub(crate) fn parse(bytes: &[u8], boundary: &str) -> Result<Vec<Part>> {
    if boundary.is_empty() {
        bail!("multipart boundary is empty");
    }
    if boundary.bytes().any(|b| b == b'\r' || b == b'\n') {
        bail!("multipart boundary contains a line break");
    }
    let dash_boundary = format!("--{boundary}");
    let delim = dash_boundary.as_bytes();
    let crlf_delim = [b"\r\n".as_slice(), delim].concat();

    let mut pos = first_delimiter(bytes, delim)
        .ok_or_else(|| anyhow!("multipart body has no opening boundary delimiter"))?;
    let mut parts: Vec<Part> = Vec::new();

    loop {
        let after = pos + delim.len();

        // `--boundary--` closes the body; anything after it is the epilogue.
        if bytes.get(after..after.saturating_add(2)) == Some(b"--".as_slice()) {
            return Ok(parts);
        }

        let headers_start = crlf_after_padding(bytes, after).ok_or_else(|| {
            anyhow!(
                "multipart delimiter at offset {pos} is not followed by CRLF \
                 (RFC 2046 requires CRLF line endings)"
            )
        })?;

        if parts.len() >= MAX_MULTIPART_PARTS {
            tracing::debug!(
                cap = MAX_MULTIPART_PARTS,
                "multipart part cap reached; later parts ignored"
            );
            return Ok(parts);
        }

        // Where the part headers stop and the content starts. A part with no
        // headers at all opens with the blank line.
        let no_headers =
            bytes.get(headers_start..headers_start.saturating_add(2)) == Some(b"\r\n".as_slice());
        let (header_block, value_start) = if no_headers {
            (headers_start..headers_start, headers_start + 2)
        } else {
            let term = find(bytes, b"\r\n\r\n", headers_start)
                .ok_or_else(|| unterminated_headers(headers_start))?;
            (headers_start..term + 2, term + 4)
        };

        // The blank line must come before the next delimiter, or these are not
        // this part's headers at all.
        let next = find(bytes, &crlf_delim, headers_start).ok_or_else(|| {
            anyhow!(
                "multipart part at offset {headers_start} has no terminating boundary delimiter"
            )
        })?;
        if next + 2 < value_start {
            return Err(unterminated_headers(headers_start));
        }

        let headers = read_headers(bytes, header_block)?;
        parts.push(Part {
            name: headers.name,
            filename: headers.filename,
            filename_span: headers.filename_span,
            content_type: headers.content_type,
            value_span: value_start..next,
        });

        pos = next + 2;
    }
}

/// Replaces `span` with `replacement`, copying every other byte verbatim.
///
/// A span that is inverted or runs past the end of `bytes` leaves the body
/// unchanged rather than panicking.
pub(crate) fn splice(bytes: &[u8], span: Range<usize>, replacement: &[u8]) -> Vec<u8> {
    if span.start > span.end || span.end > bytes.len() {
        return bytes.to_vec();
    }
    let kept = bytes.len() - (span.end - span.start);
    let mut out = Vec::with_capacity(kept + replacement.len());
    out.extend_from_slice(bytes.get(..span.start).unwrap_or_default());
    out.extend_from_slice(replacement);
    out.extend_from_slice(bytes.get(span.end..).unwrap_or_default());
    out
}

/// Percent-escapes the four characters that would break a quoted `filename=`.
///
/// Everything else is left alone: the point of a `multipart_filename` payload
/// is to reach the application intact (`../`, nul-ish text and Unicode all
/// survive); only the characters that would end the quoted string or split the
/// header are encoded.
pub(crate) fn escape_filename(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("%22"),
            '\r' => out.push_str("%0D"),
            '\n' => out.push_str("%0A"),
            '\\' => out.push_str("%5C"),
            other => out.push(other),
        }
    }
    out
}

/// The one error two places in [`parse`] raise, kept in one spelling.
fn unterminated_headers(offset: usize) -> anyhow::Error {
    anyhow!("multipart part headers at offset {offset} are not terminated by a blank line")
}

/// The part headers this module reads; every other header is ignored.
struct Headers {
    name: Option<String>,
    filename: Option<String>,
    filename_span: Option<Range<usize>>,
    content_type: Option<String>,
}

/// Reads `Content-Disposition` and `Content-Type` out of one part's header
/// block (`block` ends after the CRLF of the last header line).
fn read_headers(bytes: &[u8], block: Range<usize>) -> Result<Headers> {
    let mut out = Headers {
        name: None,
        filename: None,
        filename_span: None,
        content_type: None,
    };

    let mut i = block.start;
    while i < block.end {
        let line_end = find(bytes, b"\r\n", i)
            .filter(|end| *end < block.end)
            .ok_or_else(|| anyhow!("multipart header at offset {i} is not CRLF terminated"))?;
        let raw = bytes.get(i..line_end).unwrap_or_default();
        if raw.contains(&b'\n') {
            bail!(
                "multipart header at offset {i} uses a bare LF \
                 (RFC 2046 requires CRLF line endings)"
            );
        }
        let line = std::str::from_utf8(raw)
            .map_err(|_| anyhow!("multipart header at offset {i} is not valid UTF-8"))?;

        if let Some((header, value)) = line.split_once(':') {
            let value_at = i + header.len() + 1;
            match header.trim().to_ascii_lowercase().as_str() {
                "content-disposition" => {
                    for (key, text, span) in params(value) {
                        match key.as_str() {
                            "name" if out.name.is_none() => out.name = Some(text),
                            "filename" if out.filename.is_none() => {
                                out.filename_span =
                                    Some(value_at + span.start..value_at + span.end);
                                out.filename = Some(text);
                            }
                            _ => {}
                        }
                    }
                }
                "content-type" if out.content_type.is_none() => {
                    out.content_type = Some(value.trim().to_string());
                }
                _ => {}
            }
        }

        i = line_end + 2;
    }

    Ok(out)
}

/// Splits a `;`-separated parameter list into
/// `(lowercased key, raw value, span of the value within `s`)`.
///
/// The value is the raw text: quoted values lose only the quotes, so the span
/// always addresses exactly the bytes the value was read from. Quoted values
/// are read to the next `"` with no backslash unescaping (RFC 7578 §2 tells
/// senders not to put quotes in a filename, and [`escape_filename`] percent-
/// escapes them on the way back out).
fn params(s: &str) -> Vec<(String, String, Range<usize>)> {
    let bytes = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0usize;

    while i < bytes.len() {
        while matches!(bytes.get(i), Some(b) if *b == b';' || b.is_ascii_whitespace()) {
            i += 1;
        }
        let key_start = i;
        while matches!(bytes.get(i), Some(b) if *b != b'=' && *b != b';') {
            i += 1;
        }
        let key = s
            .get(key_start..i)
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase();

        if bytes.get(i) != Some(&b'=') {
            if !key.is_empty() {
                out.push((key, String::new(), i..i));
            }
            continue;
        }
        i += 1; // the `=`

        while matches!(bytes.get(i), Some(b' ' | b'\t')) {
            i += 1;
        }

        let (value, span) = if bytes.get(i) == Some(&b'"') {
            i += 1;
            let start = i;
            while matches!(bytes.get(i), Some(b) if *b != b'"') {
                i += 1;
            }
            let end = i;
            if bytes.get(i) == Some(&b'"') {
                i += 1;
            }
            (
                s.get(start..end).unwrap_or_default().to_string(),
                start..end,
            )
        } else {
            let start = i;
            while matches!(bytes.get(i), Some(b) if *b != b';') {
                i += 1;
            }
            let text = s.get(start..i).unwrap_or_default().trim_end();
            (text.to_string(), start..start + text.len())
        };

        out.push((key, value, span));
    }

    out
}

/// The first `--boundary` that starts a line (offset 0 or after a CRLF), so a
/// preamble that mentions the boundary cannot be mistaken for a delimiter.
fn first_delimiter(bytes: &[u8], delim: &[u8]) -> Option<usize> {
    let mut from = 0usize;
    while let Some(at) = find(bytes, delim, from) {
        if at == 0 || (at >= 2 && bytes.get(at - 2..at) == Some(b"\r\n".as_slice())) {
            return Some(at);
        }
        from = at + 1;
    }
    None
}

/// Offset just past the CRLF that ends the delimiter line, skipping the
/// transport padding RFC 2046 allows; `None` when no CRLF follows.
fn crlf_after_padding(bytes: &[u8], mut i: usize) -> Option<usize> {
    while matches!(bytes.get(i), Some(b' ' | b'\t')) {
        i += 1;
    }
    if bytes.get(i..i.saturating_add(2)) == Some(b"\r\n".as_slice()) {
        Some(i + 2)
    } else {
        None
    }
}

/// First offset at or after `from` where `needle` occurs in `hay`.
fn find(hay: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if needle.is_empty() || from > hay.len() {
        return None;
    }
    hay.get(from..)?
        .windows(needle.len())
        .position(|window| window == needle)
        .map(|at| at + from)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{boundary_of, escape_filename, parse, splice};
    use crate::limits::MAX_MULTIPART_PARTS;
    use std::ops::Range;

    /// The body pinned by the plan (boundary `XyZ`), CRLF throughout.
    const BODY: &[u8] = b"--XyZ\r\nContent-Disposition: form-data; name=\"title\"\r\n\r\nhello\r\n--XyZ\r\nContent-Disposition: form-data; name=\"doc\"; filename=\"a.txt\"\r\nContent-Type: text/plain\r\n\r\nfile-bytes\r\n--XyZ--\r\n";

    #[test]
    fn parse_pins() {
        let parts = parse(BODY, "XyZ").unwrap();
        assert_eq!(parts.len(), 2);

        assert_eq!(parts[0].name.as_deref(), Some("title"));
        assert_eq!(parts[0].filename, None);
        assert_eq!(parts[0].filename_span, None);
        assert_eq!(parts[0].content_type, None);
        assert_eq!(parts[0].value_span, 55..60);
        assert_eq!(&BODY[parts[0].value_span.clone()], b"hello");

        assert_eq!(parts[1].name.as_deref(), Some("doc"));
        assert_eq!(parts[1].filename.as_deref(), Some("a.txt"));
        assert_eq!(parts[1].filename_span, Some(123..128));
        assert_eq!(&BODY[parts[1].filename_span.clone().unwrap()], b"a.txt");
        assert_eq!(parts[1].content_type.as_deref(), Some("text/plain"));
        assert_eq!(parts[1].value_span, 159..169);
        assert_eq!(&BODY[parts[1].value_span.clone()], b"file-bytes");
    }

    #[test]
    fn parse_reads_bare_and_empty_parts() {
        let body =
            b"--b\r\nContent-Disposition: form-data; name=doc; filename=a.txt\r\n\r\n\r\n--b--\r\n";
        let parts = parse(body, "b").unwrap();
        assert_eq!(parts.len(), 1);
        assert_eq!(parts[0].name.as_deref(), Some("doc"));
        assert_eq!(parts[0].filename.as_deref(), Some("a.txt"));
        assert_eq!(&body[parts[0].filename_span.clone().unwrap()], b"a.txt");
        assert_eq!(&body[parts[0].value_span.clone()], b"");
    }

    #[test]
    fn splice_value() {
        let parts = parse(BODY, "XyZ").unwrap();
        let out = splice(BODY, parts[0].value_span.clone(), b"<x>");
        assert!(out.ends_with(b"--XyZ--\r\n"));

        let again = parse(&out, "XyZ").unwrap();
        assert_eq!(again.len(), 2);
        assert_eq!(&out[again[0].value_span.clone()], b"<x>");
        assert_eq!(&out[again[1].value_span.clone()], b"file-bytes");
    }

    #[test]
    fn splice_filename() {
        assert_eq!(escape_filename("../x\"y.txt"), "../x%22y.txt");
        assert_eq!(escape_filename("a\r\nb\\c"), "a%0D%0Ab%5Cc");
        assert_eq!(escape_filename("plain.txt"), "plain.txt");

        let parts = parse(BODY, "XyZ").unwrap();
        let span = parts[1].filename_span.clone().unwrap();
        let out = splice(BODY, span, escape_filename("../x\"y.txt").as_bytes());

        let again = parse(&out, "XyZ").unwrap();
        assert_eq!(again.len(), 2);
        assert_eq!(again[1].name.as_deref(), Some("doc"));
        assert_eq!(again[1].filename.as_deref(), Some("../x%22y.txt"));
        assert_eq!(&out[again[1].value_span.clone()], b"file-bytes");
    }

    #[test]
    fn splice_is_bounds_checked() {
        // Past the end, and inverted (built field-wise: `2..1` as a literal is
        // a clippy error). Both leave the body untouched instead of panicking.
        let inverted = Range { start: 2, end: 1 };
        assert_eq!(splice(b"abc", 9..12, b"z"), b"abc".to_vec());
        assert_eq!(splice(b"abc", inverted, b"z"), b"abc".to_vec());
        assert_eq!(splice(b"abc", 1..2, b"zz"), b"azzc".to_vec());
    }

    #[test]
    fn boundary_pins() {
        assert_eq!(
            boundary_of("multipart/form-data; boundary=\"XyZ\""),
            Some("XyZ".to_string())
        );
        assert_eq!(
            boundary_of("multipart/form-data; boundary=XyZ; charset=utf-8"),
            Some("XyZ".to_string())
        );
        assert_eq!(
            boundary_of("MULTIPART/FORM-DATA; BOUNDARY=XyZ"),
            Some("XyZ".to_string())
        );
        assert_eq!(boundary_of("application/json"), None);
        assert_eq!(boundary_of("multipart/form-data"), None);
        assert_eq!(boundary_of("multipart/form-data; boundary="), None);
        assert_eq!(boundary_of("application/json; boundary=XyZ"), None);
    }

    #[test]
    fn parse_errors() {
        // No closing `--XyZ--`.
        let open = b"--XyZ\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nhello\r\n";
        assert!(parse(open, "XyZ").is_err());

        // LF-only line endings (RFC 2046 requires CRLF; plan call A7).
        let lf = b"--XyZ\nContent-Disposition: form-data; name=\"a\"\n\nhello\n--XyZ--\n";
        let err = parse(lf, "XyZ").unwrap_err().to_string();
        assert!(err.contains("offset"), "message was {err:?}");
        assert!(!err.contains("hello"), "message was {err:?}");

        // No delimiter at all, and an empty boundary.
        assert!(parse(b"hello", "XyZ").is_err());
        assert!(parse(BODY, "").is_err());

        // Headers never terminated by a blank line.
        let unterminated = b"--XyZ\r\nContent-Disposition: form-data; name=\"a\"\r\n--XyZ--\r\n";
        assert!(parse(unterminated, "XyZ").is_err());
    }

    #[test]
    fn parse_caps_parts() {
        let mut body = Vec::new();
        for i in 0..(MAX_MULTIPART_PARTS + 44) {
            body.extend_from_slice(
                format!("--b\r\nContent-Disposition: form-data; name=\"f{i}\"\r\n\r\nv\r\n")
                    .as_bytes(),
            );
        }
        body.extend_from_slice(b"--b--\r\n");

        let parts = parse(&body, "b").unwrap();
        assert_eq!(parts.len(), 256);
        assert_eq!(parts.len(), MAX_MULTIPART_PARTS);
        assert_eq!(parts[255].name.as_deref(), Some("f255"));
    }
}
