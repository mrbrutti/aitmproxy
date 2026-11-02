//! Offset-recording XML tokenizer, escaping and splicing (task 6).
//!
//! The lane needs XML insertion points (spec D8.1: the `xml_value` and
//! `xml_attr` kinds) and it needs to put a payload back into a captured body
//! without rewriting the rest of it. A full XML object model would do neither
//! well: re-serialising a parsed tree reformats bytes the target may be
//! sensitive to, and no XML crate is in the workspace (none may be added).
//!
//! So this is a hand-rolled single forward pass that records **byte offsets**.
//! [`scan`] returns one [`XmlSlot`] per mutable position, each carrying the
//! span of the raw bytes that hold the value; [`splice`] replaces exactly that
//! span and copies everything else through untouched. Mutation is therefore
//! byte-exact: declaration, comments, `DOCTYPE`, whitespace, attribute order
//! and quoting style all survive a probe.
//!
//! Security properties this file is responsible for:
//!
//! - **No entity expansion, ever.** The internal subset of a `DOCTYPE` is
//!   skipped as opaque bytes and an `&name;` reference is left literal, so a
//!   body the scanner reads can never pull in a file or a URL (the XXE and
//!   billion-laughs classes are structurally absent, not defended against).
//!   Only the five predefined entities and decimal `&#NN;` references are
//!   decoded, and only into the slot's `value`, never back into the document.
//! - **No panics on hostile input.** Every read is bounds-checked, every slice
//!   goes through `get`, malformed markup is an `Err` naming the byte offset,
//!   and the pass is guarded against standing still.
//! - **Bounded work.** Element nesting is capped by
//!   [`MAX_XML_DEPTH`](crate::limits::MAX_XML_DEPTH) and the number of slots by
//!   [`MAX_XML_SLOTS`](crate::limits::MAX_XML_SLOTS); past the slot cap the pass
//!   keeps validating the document but stops recording.
//! - **No value in `Debug`.** [`XmlSlot`] prints the length of its value, never
//!   the value, because a slot holds body content (crate redaction rule, D8.1).

use std::fmt;
use std::ops::Range;

use anyhow::{anyhow, bail, Result};

use crate::limits::{MAX_XML_DEPTH, MAX_XML_SLOTS};

/// What kind of position in the document a slot is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum XmlSlotKind {
    /// The character data of an element with no element children.
    Text,
    /// The value of an attribute, between its quotes.
    Attr,
}

/// One mutable position in an XML document.
///
/// `span` indexes the bytes handed to [`scan`] and covers the **raw** value:
/// the text between an element's tags, the bytes between an attribute's quotes
/// or the content of a `CDATA` section. `value` is the decoded reading of those
/// bytes (see the entity rules above) and is what a point's `example` is built
/// from; it is never written back to the document.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct XmlSlot {
    pub kind: XmlSlotKind,
    /// Dotted element path from the root, with `@attr` appended for an
    /// attribute: `order.item`, `order.item@sku`.
    pub path: String,
    /// Local name of the element or attribute, namespace prefix stripped.
    pub name: String,
    /// Byte range of the raw value inside the scanned document.
    pub span: Range<usize>,
    /// Decoded value. Body content: never logged, never in `Debug`.
    pub value: String,
    /// Whether the span is the content of a `CDATA` section.
    pub cdata: bool,
}

impl fmt::Debug for XmlSlot {
    /// Structure only. A slot's value is body content and never reaches a log
    /// line, an error or a `Debug` rendering (crate redaction rule, D8.1).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("XmlSlot")
            .field("kind", &self.kind)
            .field("path", &self.path)
            .field("name", &self.name)
            .field("span", &self.span)
            .field("cdata", &self.cdata)
            .field("value_len", &self.value.len())
            .finish()
    }
}

/// Record every mutable position in `bytes`, in document order.
///
/// Attributes are recorded as their start tag is read, an element's text when
/// its end tag is read, so the order is the order the values appear.
///
/// # Errors
///
/// Returns `Err` naming the byte offset when the document is not valid UTF-8,
/// when markup is unterminated (tag, comment, `CDATA`, attribute value), when
/// tags are unbalanced, when character data sits outside the root element, or
/// when nesting passes [`MAX_XML_DEPTH`](crate::limits::MAX_XML_DEPTH). A
/// document with no root element is an error too, so a caller that guessed the
/// body format wrong gets a refusal rather than an empty slot list.
pub(crate) fn scan(bytes: &[u8]) -> Result<Vec<XmlSlot>> {
    if let Err(err) = std::str::from_utf8(bytes) {
        bail!(
            "xml: document is not valid UTF-8 at offset {}",
            err.valid_up_to()
        );
    }
    Scanner {
        bytes,
        pos: 0,
        stack: Vec::new(),
        slots: Vec::new(),
        saw_root: false,
    }
    .run()
}

/// Escape `text` so it is safe as element content or as a quoted attribute
/// value: `& < > " '` become `&amp; &lt; &gt; &quot; &apos;`.
///
/// Both quote styles are escaped, so one escaped string can be spliced into a
/// `"`-quoted or a `'`-quoted attribute without unbalancing it.
pub(crate) fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(ch),
        }
    }
    out
}

/// Replace `span` in `bytes` with `replacement`, copying the rest through.
///
/// The caller is expected to pass a span from [`scan`] and an already escaped
/// replacement (see [`escape`]). An out-of-range or inverted span is clamped
/// into the document rather than panicking, so a stale span from an earlier
/// body can never bring a probe down.
pub(crate) fn splice(bytes: &[u8], span: Range<usize>, replacement: &[u8]) -> Vec<u8> {
    let start = span.start.min(bytes.len());
    let end = span.end.clamp(start, bytes.len());
    let kept = bytes.len() - (end - start);
    let mut out = Vec::with_capacity(kept + replacement.len());
    out.extend_from_slice(bytes.get(..start).unwrap_or_default());
    out.extend_from_slice(replacement);
    out.extend_from_slice(bytes.get(end..).unwrap_or_default());
    out
}

/// One open element while the pass walks the document.
struct Frame {
    /// Name as written, prefix included; an end tag must match it exactly.
    qname: String,
    /// Local name, prefix stripped.
    name: String,
    /// Dotted path from the root, this element included.
    path: String,
    /// Offset of this element's `<`, for the unclosed-element error.
    open_offset: usize,
    /// Set once a child element opens: such an element gets no text slot.
    has_child_element: bool,
    /// First non-blank text run: raw span and decoded value.
    text: Option<(Range<usize>, String)>,
    /// First `CDATA` section: raw span and literal value.
    cdata: Option<(Range<usize>, String)>,
}

/// The single forward pass.
struct Scanner<'a> {
    bytes: &'a [u8],
    pos: usize,
    stack: Vec<Frame>,
    slots: Vec<XmlSlot>,
    saw_root: bool,
}

impl Scanner<'_> {
    fn run(mut self) -> Result<Vec<XmlSlot>> {
        while self.pos < self.bytes.len() {
            let before = self.pos;
            if starts_with(self.bytes, self.pos, CDATA_OPEN) {
                self.read_cdata()?;
            } else if starts_with(self.bytes, self.pos, b"<!--") {
                self.skip_comment()?;
            } else if starts_with(self.bytes, self.pos, b"<!") {
                self.skip_markup_declaration()?;
            } else if starts_with(self.bytes, self.pos, b"<?") {
                self.skip_processing_instruction()?;
            } else if starts_with(self.bytes, self.pos, b"</") {
                self.close_element()?;
            } else if byte_at(self.bytes, self.pos) == Some(b'<') {
                self.open_element()?;
            } else {
                self.read_text()?;
            }
            // Belt and braces: no input may make the pass stand still.
            if self.pos <= before {
                bail!("xml: tokenizer made no progress at offset {before}");
            }
        }
        if let Some(frame) = self.stack.last() {
            bail!(
                "xml: unclosed element <{}> opened at offset {}",
                frame.qname,
                frame.open_offset
            );
        }
        if !self.saw_root {
            bail!("xml: document has no root element");
        }
        Ok(self.slots)
    }

    /// Record a slot, or drop it once the document has filled the slot cap.
    fn push_slot(&mut self, slot: XmlSlot) {
        if self.slots.len() < MAX_XML_SLOTS {
            self.slots.push(slot);
        }
    }

    /// `<!-- ... -->`, skipped whole.
    fn skip_comment(&mut self) -> Result<()> {
        let start = self.pos;
        let end = find_from(self.bytes, start + 4, b"-->")
            .ok_or_else(|| anyhow!("xml: unterminated comment at offset {start}"))?;
        self.pos = end + 3;
        Ok(())
    }

    /// `<? ... ?>`: the XML declaration and any processing instruction.
    fn skip_processing_instruction(&mut self) -> Result<()> {
        let start = self.pos;
        let end = find_from(self.bytes, start + 2, b"?>")
            .ok_or_else(|| anyhow!("xml: unterminated processing instruction at offset {start}"))?;
        self.pos = end + 2;
        Ok(())
    }

    /// `<!DOCTYPE ...>` and any other `<! ... >` declaration, skipped whole.
    ///
    /// The internal subset in `[ ... ]` is opaque: its `>` characters, its
    /// quoted strings and above all its `<!ENTITY>` declarations are stepped
    /// over without being read, which is what makes entity expansion
    /// impossible here rather than merely disabled.
    fn skip_markup_declaration(&mut self) -> Result<()> {
        let bytes = self.bytes;
        let start = self.pos;
        let mut i = start + 2;
        let mut quote: Option<u8> = None;
        let mut subset_depth = 0usize;
        while let Some(b) = byte_at(bytes, i) {
            match quote {
                Some(q) => {
                    if b == q {
                        quote = None;
                    }
                }
                None => match b {
                    b'"' | b'\'' => quote = Some(b),
                    b'[' => subset_depth += 1,
                    b']' => subset_depth = subset_depth.saturating_sub(1),
                    b'>' if subset_depth == 0 => {
                        self.pos = i + 1;
                        return Ok(());
                    }
                    _ => {}
                },
            }
            i += 1;
        }
        bail!("xml: unterminated markup declaration at offset {start}")
    }

    /// `<![CDATA[ ... ]]>`: literal content, recorded as a text slot on the
    /// enclosing element with `cdata: true` and never entity-decoded.
    fn read_cdata(&mut self) -> Result<()> {
        let bytes = self.bytes;
        let start = self.pos;
        let content_start = start + CDATA_OPEN.len();
        let content_end = find_from(bytes, content_start, CDATA_CLOSE)
            .ok_or_else(|| anyhow!("xml: unterminated CDATA section at offset {start}"))?;
        let raw = str_at(bytes, content_start..content_end)?.to_owned();
        match self.stack.last_mut() {
            Some(frame) => {
                if frame.cdata.is_none() {
                    frame.cdata = Some((content_start..content_end, raw));
                }
            }
            None => bail!("xml: CDATA section outside the root element at offset {start}"),
        }
        self.pos = content_end + CDATA_CLOSE.len();
        Ok(())
    }

    /// Character data up to the next `<`.
    fn read_text(&mut self) -> Result<()> {
        let bytes = self.bytes;
        let start = self.pos;
        let end = find_byte(bytes, start, b'<').unwrap_or(bytes.len());
        let raw = str_at(bytes, start..end)?;
        let blank = raw.trim().is_empty();
        match self.stack.last_mut() {
            Some(frame) => {
                if !blank && frame.text.is_none() {
                    frame.text = Some((start..end, decode(raw)));
                }
            }
            None => {
                if !blank {
                    bail!("xml: character data outside the root element at offset {start}");
                }
            }
        }
        self.pos = end;
        Ok(())
    }

    /// A start tag: records a slot per attribute, then opens a frame unless
    /// the tag closes itself.
    fn open_element(&mut self) -> Result<()> {
        let bytes = self.bytes;
        let start = self.pos;
        let name_start = start + 1;
        let name_end = scan_name_end(bytes, name_start);
        if name_end == name_start {
            bail!("xml: malformed start tag at offset {start}");
        }
        let qname = str_at(bytes, name_start..name_end)?.to_owned();
        if self.saw_root && self.stack.is_empty() {
            bail!("xml: a second root element <{qname}> at offset {start}");
        }
        if self.stack.len() >= MAX_XML_DEPTH {
            bail!("xml: element nesting deeper than {MAX_XML_DEPTH} at offset {start}");
        }
        let name = local_name(&qname).to_owned();
        let path = match self.stack.last() {
            Some(parent) => format!("{}.{name}", parent.path),
            None => name.clone(),
        };

        let mut i = name_end;
        let self_closing;
        loop {
            i = skip_space(bytes, i);
            match byte_at(bytes, i) {
                None => bail!("xml: unterminated start tag at offset {start}"),
                Some(b'>') => {
                    self_closing = false;
                    i += 1;
                    break;
                }
                Some(b'/') if byte_at(bytes, i + 1) == Some(b'>') => {
                    self_closing = true;
                    i += 2;
                    break;
                }
                Some(b'/') => bail!("xml: malformed start tag at offset {i}"),
                Some(_) => i = self.read_attribute(&path, i)?,
            }
        }

        if let Some(parent) = self.stack.last_mut() {
            parent.has_child_element = true;
        }
        self.saw_root = true;
        if !self_closing {
            self.stack.push(Frame {
                qname,
                name,
                path,
                open_offset: start,
                has_child_element: false,
                text: None,
                cdata: None,
            });
        }
        self.pos = i;
        Ok(())
    }

    /// One `name="value"` inside a start tag; returns the offset just past it.
    fn read_attribute(&mut self, element_path: &str, from: usize) -> Result<usize> {
        let bytes = self.bytes;
        let name_end = scan_name_end(bytes, from);
        if name_end == from {
            bail!("xml: malformed attribute at offset {from}");
        }
        let name = local_name(str_at(bytes, from..name_end)?).to_owned();
        let mut i = skip_space(bytes, name_end);
        if byte_at(bytes, i) != Some(b'=') {
            bail!("xml: attribute `{name}` has no value at offset {from}");
        }
        i = skip_space(bytes, i + 1);
        let quote = match byte_at(bytes, i) {
            Some(q @ (b'"' | b'\'')) => q,
            _ => bail!("xml: attribute `{name}` value is not quoted at offset {i}"),
        };
        let value_start = i + 1;
        let value_end = find_byte(bytes, value_start, quote)
            .ok_or_else(|| anyhow!("xml: unterminated attribute value at offset {value_start}"))?;
        let value = decode(str_at(bytes, value_start..value_end)?);
        self.push_slot(XmlSlot {
            kind: XmlSlotKind::Attr,
            path: format!("{element_path}@{name}"),
            name,
            span: value_start..value_end,
            value,
            cdata: false,
        });
        Ok(value_end + 1)
    }

    /// An end tag: closes the open element and emits its text slot, if it has
    /// one (text-only content, not all whitespace).
    fn close_element(&mut self) -> Result<()> {
        let bytes = self.bytes;
        let start = self.pos;
        let name_start = start + 2;
        let name_end = scan_name_end(bytes, name_start);
        if name_end == name_start {
            bail!("xml: malformed end tag at offset {start}");
        }
        let qname = str_at(bytes, name_start..name_end)?;
        let close = skip_space(bytes, name_end);
        if byte_at(bytes, close) != Some(b'>') {
            bail!("xml: unterminated end tag at offset {start}");
        }
        let Some(frame) = self.stack.pop() else {
            bail!("xml: unexpected end tag </{qname}> at offset {start}");
        };
        if frame.qname != qname {
            bail!(
                "xml: end tag </{qname}> does not close <{}> at offset {start}",
                frame.qname
            );
        }
        if !frame.has_child_element {
            if let Some((span, value)) = frame.cdata {
                self.push_slot(XmlSlot {
                    kind: XmlSlotKind::Text,
                    path: frame.path,
                    name: frame.name,
                    span,
                    value,
                    cdata: true,
                });
            } else if let Some((span, value)) = frame.text {
                self.push_slot(XmlSlot {
                    kind: XmlSlotKind::Text,
                    path: frame.path,
                    name: frame.name,
                    span,
                    value,
                    cdata: false,
                });
            }
        }
        self.pos = close + 1;
        Ok(())
    }
}

/// Opening delimiter of a `CDATA` section.
const CDATA_OPEN: &[u8] = b"<![CDATA[";

/// Closing delimiter of a `CDATA` section.
const CDATA_CLOSE: &[u8] = b"]]>";

/// The byte at `i`, or `None` past the end. The only way this file reads one.
fn byte_at(bytes: &[u8], i: usize) -> Option<u8> {
    bytes.get(i).copied()
}

/// Whether `needle` sits at `at`.
fn starts_with(bytes: &[u8], at: usize, needle: &[u8]) -> bool {
    match at.checked_add(needle.len()) {
        Some(end) => bytes.get(at..end) == Some(needle),
        None => false,
    }
}

/// Offset of the next `needle` at or after `from`.
fn find_from(bytes: &[u8], from: usize, needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return None;
    }
    let hay = bytes.get(from..)?;
    hay.windows(needle.len())
        .position(|w| w == needle)
        .map(|at| from + at)
}

/// Offset of the next `needle` byte at or after `from`.
fn find_byte(bytes: &[u8], from: usize, needle: u8) -> Option<usize> {
    let hay = bytes.get(from..)?;
    hay.iter().position(|&b| b == needle).map(|at| from + at)
}

/// XML whitespace (production S).
fn is_space(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\r' | b'\n')
}

/// First offset at or after `from` that is not whitespace.
fn skip_space(bytes: &[u8], from: usize) -> usize {
    let mut i = from;
    while byte_at(bytes, i).is_some_and(is_space) {
        i += 1;
    }
    i
}

/// End of the element or attribute name starting at `from`.
fn scan_name_end(bytes: &[u8], from: usize) -> usize {
    let mut i = from;
    while let Some(b) = byte_at(bytes, i) {
        if is_space(b) || matches!(b, b'/' | b'>' | b'<' | b'=' | b'"' | b'\'') {
            break;
        }
        i += 1;
    }
    i
}

/// `ns:item` -> `item`. A name without a prefix is returned unchanged.
fn local_name(qname: &str) -> &str {
    qname.rsplit_once(':').map_or(qname, |(_, local)| local)
}

/// The bytes of `span` as `&str`.
fn str_at(bytes: &[u8], span: Range<usize>) -> Result<&str> {
    let start = span.start;
    let slice = bytes
        .get(span)
        .ok_or_else(|| anyhow!("xml: span out of range at offset {start}"))?;
    std::str::from_utf8(slice)
        .map_err(|_| anyhow!("xml: text is not valid UTF-8 at offset {start}"))
}

/// Decode the five predefined entities and decimal `&#NN;` character
/// references in `raw`.
///
/// Everything else — `&name;` from a DTD, hexadecimal `&#xNN;`, a bare `&` —
/// is copied through literally. Nothing here can read a file, open a URL or
/// grow the input, which is the point: the decoded value is only ever shown as
/// a point's example, never written back into a document.
fn decode(raw: &str) -> String {
    if !raw.contains('&') {
        return raw.to_owned();
    }
    let bytes = raw.as_bytes();
    let mut out = String::with_capacity(raw.len());
    let mut copied = 0usize;
    let mut i = 0usize;
    while i < bytes.len() {
        if byte_at(bytes, i) == Some(b'&') {
            if let Some((ch, len)) = decode_entity(bytes, i) {
                out.push_str(slice_str(raw, copied, i));
                out.push(ch);
                i += len;
                copied = i;
                continue;
            }
        }
        i += 1;
    }
    out.push_str(slice_str(raw, copied, raw.len()));
    out
}

/// The five predefined XML entities. No others exist without a DTD, and this
/// tokenizer never reads one.
const PREDEFINED: [(&[u8], char); 5] = [
    (b"&amp;", '&'),
    (b"&lt;", '<'),
    (b"&gt;", '>'),
    (b"&quot;", '"'),
    (b"&apos;", '\''),
];

/// Decode the reference starting at `at` (which must be `&`), returning the
/// character and the number of bytes it occupied.
fn decode_entity(bytes: &[u8], at: usize) -> Option<(char, usize)> {
    for (pattern, ch) in PREDEFINED {
        if starts_with(bytes, at, pattern) {
            return Some((ch, pattern.len()));
        }
    }
    if !starts_with(bytes, at, b"&#") {
        return None;
    }
    let mut i = at + 2;
    let mut code: u32 = 0;
    let mut digits = 0usize;
    while let Some(b) = byte_at(bytes, i) {
        if !b.is_ascii_digit() {
            break;
        }
        // Checked, so a long run of digits is a literal, never an overflow.
        code = code.checked_mul(10)?.checked_add(u32::from(b - b'0'))?;
        digits += 1;
        i += 1;
    }
    if digits == 0 || byte_at(bytes, i) != Some(b';') {
        return None;
    }
    Some((char::from_u32(code)?, i + 1 - at))
}

/// `s[start..end]`, or `""` if those are not byte offsets into `s`. Callers
/// cut at ASCII delimiters, so the fallback is unreachable in practice and
/// exists so no path can panic.
fn slice_str(s: &str, start: usize, end: usize) -> &str {
    s.get(start..end).unwrap_or_default()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{escape, scan, splice, XmlSlotKind};
    use crate::limits::{MAX_XML_DEPTH, MAX_XML_SLOTS};

    /// The pinned document of the plan's task 6 test table.
    const DOC: &str = concat!(
        r#"<?xml version="1.0"?>"#,
        r#"<order id="7">"#,
        r#"<item sku="A1">Widget</item>"#,
        r#"<note><![CDATA[x<y]]></note>"#,
        r#"<empty/>"#,
        r#"</order>"#,
    );

    #[test]
    fn scan_pins() {
        let bytes = DOC.as_bytes();
        let slots = scan(bytes).unwrap();
        assert_eq!(slots.len(), 4);

        assert_eq!(slots[0].kind, XmlSlotKind::Attr);
        assert_eq!(slots[0].path, "order@id");
        assert_eq!(slots[0].name, "id");
        assert_eq!(slots[0].value, "7");
        assert!(!slots[0].cdata);
        assert_eq!(&bytes[slots[0].span.clone()], b"7");

        assert_eq!(slots[1].kind, XmlSlotKind::Attr);
        assert_eq!(slots[1].path, "order.item@sku");
        assert_eq!(slots[1].name, "sku");
        assert_eq!(slots[1].value, "A1");
        assert!(!slots[1].cdata);
        assert_eq!(&bytes[slots[1].span.clone()], b"A1");

        assert_eq!(slots[2].kind, XmlSlotKind::Text);
        assert_eq!(slots[2].path, "order.item");
        assert_eq!(slots[2].name, "item");
        assert_eq!(slots[2].value, "Widget");
        assert!(!slots[2].cdata);
        assert_eq!(&bytes[slots[2].span.clone()], b"Widget");

        assert_eq!(slots[3].kind, XmlSlotKind::Text);
        assert_eq!(slots[3].path, "order.note");
        assert_eq!(slots[3].name, "note");
        assert_eq!(slots[3].value, "x<y");
        assert!(slots[3].cdata);
        assert_eq!(&bytes[slots[3].span.clone()], b"x<y");
    }

    #[test]
    fn splice_escapes() {
        let bytes = DOC.as_bytes();
        let slots = scan(bytes).unwrap();

        let text = splice(bytes, slots[2].span.clone(), escape("<b>&\"").as_bytes());
        assert_eq!(
            String::from_utf8(text).unwrap(),
            DOC.replace("Widget", "&lt;b&gt;&amp;&quot;")
        );

        let attr = splice(bytes, slots[1].span.clone(), escape("a\"b").as_bytes());
        let attr = String::from_utf8(attr).unwrap();
        assert!(attr.contains(r#"sku="a&quot;b""#), "{attr}");

        // The spliced document still parses and the value round-trips.
        let again = scan(attr.as_bytes()).unwrap();
        assert_eq!(again[1].path, "order.item@sku");
        assert_eq!(again[1].value, "a\"b");
    }

    #[test]
    fn scan_errors_name_offset() {
        let err = scan(b"<a><b>").unwrap_err().to_string();
        assert!(err.contains("offset"), "{err}");
        assert!(err.contains("offset 3"), "{err}");
    }

    #[test]
    fn scan_skips_doctype_entities() {
        let doc = r#"<!DOCTYPE x [<!ENTITY e "boom">]><a>&e;</a>"#;
        let slots = scan(doc.as_bytes()).unwrap();
        assert_eq!(slots.len(), 1);
        assert_eq!(slots[0].kind, XmlSlotKind::Text);
        assert_eq!(slots[0].path, "a");
        assert_eq!(slots[0].name, "a");
        assert_eq!(slots[0].value, "&e;");
        assert!(!slots[0].value.contains("boom"));
    }

    #[test]
    fn scan_caps() {
        let mut doc = String::from("<a");
        for i in 0..2000 {
            doc.push_str(&format!(" a{i}=\"{i}\""));
        }
        doc.push_str("/>");
        let slots = scan(doc.as_bytes()).unwrap();
        assert_eq!(MAX_XML_SLOTS, 1024);
        assert_eq!(slots.len(), 1024);
    }

    #[test]
    fn escape_pins() {
        assert_eq!(escape("a&b<c>d\"e'f"), "a&amp;b&lt;c&gt;d&quot;e&apos;f");
        assert_eq!(escape("plain"), "plain");
        assert_eq!(escape(""), "");
    }

    #[test]
    fn decodes_the_five_entities_and_decimal_refs() {
        let doc =
            r#"<a t="&lt;&amp;&gt;&quot;&apos;&#65;">&lt;tag&gt; &#8364; &unknown; &#xFF;</a>"#;
        let slots = scan(doc.as_bytes()).unwrap();
        assert_eq!(slots.len(), 2);
        assert_eq!(slots[0].value, "<&>\"'A");
        // Unknown entities and hex character references are left literal: the
        // tokenizer never expands anything a DTD could define.
        assert_eq!(slots[1].value, "<tag> \u{20ac} &unknown; &#xFF;");
    }

    #[test]
    fn strips_namespace_prefixes() {
        let doc = r#"<ns:order xmlns:ns="urn:x"><ns:item ns:sku="A1">W</ns:item></ns:order>"#;
        let slots = scan(doc.as_bytes()).unwrap();
        assert_eq!(slots.len(), 3);
        // Namespace declarations are recorded like any other attribute; the
        // ignore rules of `points.rs` decide what is worth mutating.
        assert_eq!(slots[0].path, "order@ns");
        assert_eq!(slots[0].name, "ns");
        assert_eq!(slots[1].path, "order.item@sku");
        assert_eq!(slots[1].name, "sku");
        assert_eq!(slots[2].path, "order.item");
        assert_eq!(slots[2].name, "item");
        assert_eq!(slots[2].value, "W");
    }

    #[test]
    fn skips_whitespace_only_text_and_elements_with_children() {
        let doc = "<a>\n  <b>   </b>\n  <c>v</c>\n</a>";
        let slots = scan(doc.as_bytes()).unwrap();
        assert_eq!(slots.len(), 1);
        assert_eq!(slots[0].path, "a.c");
        assert_eq!(slots[0].value, "v");
    }

    #[test]
    fn skips_comments_and_processing_instructions() {
        let doc = r#"<?xml version="1.0"?><!-- <b>no</b> --><a><?php echo 1;?>v</a>"#;
        let bytes = doc.as_bytes();
        let slots = scan(bytes).unwrap();
        assert_eq!(slots.len(), 1);
        assert_eq!(slots[0].path, "a");
        assert_eq!(slots[0].value, "v");
        assert_eq!(&bytes[slots[0].span.clone()], b"v");
    }

    #[test]
    fn rejects_unbalanced_and_unterminated_markup() {
        for doc in [
            &b"<a></b>"[..],
            &b"</a>"[..],
            &b""[..],
            &b"<a>"[..],
            &b"<a"[..],
            &b"<a><!-- x</a>"[..],
            &b"<a><![CDATA[x</a>"[..],
            &b"<a b=\"x></a>"[..],
            &b"<a b=x></a>"[..],
            &b"<a><b></b>"[..],
            &b"<a/><b/>"[..],
        ] {
            let got = scan(doc);
            assert!(
                got.is_err(),
                "expected Err for {:?}",
                String::from_utf8_lossy(doc)
            );
        }
    }

    #[test]
    fn rejects_invalid_utf8() {
        let err = scan(&[b'<', b'a', b'>', 0xff, b'<', b'/', b'a', b'>'])
            .unwrap_err()
            .to_string();
        assert!(err.contains("UTF-8"), "{err}");
        assert!(err.contains("offset 3"), "{err}");
    }

    #[test]
    fn rejects_nesting_past_the_depth_cap() {
        let mut doc = String::new();
        for _ in 0..=MAX_XML_DEPTH {
            doc.push_str("<a>");
        }
        let err = scan(doc.as_bytes()).unwrap_err().to_string();
        assert!(err.contains("offset"), "{err}");
        assert!(err.contains("64"), "{err}");
    }

    #[test]
    fn splice_clamps_out_of_range_spans() {
        assert_eq!(splice(b"abc", 1..2, b"XY"), b"aXYc".to_vec());
        assert_eq!(splice(b"abc", 9..12, b"XY"), b"abcXY".to_vec());
        // Built from values so this stays an inverted span at run time
        // rather than a literal clippy rejects at compile time.
        let (start, end) = (2usize, 1usize);
        assert_eq!(splice(b"abc", start..end, b"XY"), b"abXYc".to_vec());
        assert_eq!(splice(b"", 0..0, b"XY"), b"XY".to_vec());
    }
}
