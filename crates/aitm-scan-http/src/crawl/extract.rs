//! HTML link and form extraction (task 4).
//!
//! One hand-rolled, tag-aware tokenizer (spec D8.1, client engine "HTML
//! link/form extractor"); the crate takes no HTML dependency. The scan walks
//! tag openings and reads attributes only from the elements it cares about, so
//! `data-href`, prose, HTML comments and the contents of `<script>`/`<style>`
//! are never harvested — a commented-out anchor is not a link and
//! `var action = "/api/delete-all"` is not a form.
//!
//! The pass is linear in the page: the raw-text skip compares bytes in place
//! instead of lowercasing or copying the rest of the DOM per tag, because this
//! runs synchronously between awaits where the job's time budget cannot
//! interrupt it. Every output is capped by a named constant from
//! [`crate::limits`]; the caller truncates the page to `MAX_DOM_BYTES` on a
//! char boundary before calling [`extract`].
//!
//! Nothing here resolves, filters or scopes a URL: values come out exactly as
//! the page wrote them (entities decoded, surrounding whitespace trimmed), and
//! `crawl::frontier` decides what is in scope and what a relative reference
//! means against `Extracted::base`.

use std::fmt;

use crate::limits::{
    MAX_FIELDS_PER_FORM, MAX_FORMS_PER_PAGE, MAX_LINKS_PER_PAGE, MAX_OPTIONS_PER_SELECT,
};

/// Everything one HTML page offers the crawler.
#[derive(Default, Clone, PartialEq, Eq)]
pub(crate) struct Extracted {
    /// The first `<base href>` of the page, if it has one.
    pub base: Option<String>,
    /// Navigable references, in document order: `a[href]`, `area[href]`,
    /// `iframe[src]`, `frame[src]`, the target of a `meta[http-equiv=refresh]`
    /// and `button[formaction]` (plan call A6: a plain link, not a form).
    pub links: Vec<String>,
    /// Sub-resources, in document order: `link[href]` and `script[src]`.
    pub resources: Vec<String>,
    /// Every `<form>` of the page, in document order.
    pub forms: Vec<FormSpec>,
}

/// One `<form>` and the controls the crawler may submit.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct FormSpec {
    /// The form's position in the page, counted over every `<form>` seen
    /// (including ones dropped by [`MAX_FORMS_PER_PAGE`]), so the index stays
    /// stable when the cap bites.
    pub index: usize,
    /// The raw `action`, unresolved; `None` means "this page's URL".
    pub action: Option<String>,
    /// The method, upper-cased; `GET` when the form does not say.
    pub method: String,
    /// The `enctype`, trimmed and lower-cased.
    pub enctype: Option<String>,
    /// The named controls of the form, in document order.
    pub fields: Vec<FieldSpec>,
}

/// One named control of a form.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct FieldSpec {
    /// The control's `name`; nameless controls are not fields.
    pub name: String,
    /// What the control is, which decides how a value is generated for it.
    pub kind: FieldKind,
    /// The control's default value: the `value` attribute, the text of a
    /// `<textarea>`, or the literal `on` for a checkbox or radio that gives no
    /// value (the browser default).
    pub value: Option<String>,
    /// A `<select>`'s options in order: each `option[value]`, or the option's
    /// text when it has no `value` attribute.
    pub options: Vec<String>,
    /// Whether a checkbox or radio is `checked`.
    pub checked: bool,
}

/// The control types the lane distinguishes.
///
/// The named variants are the `input` types whose value shape the generator and
/// the insertion-point traits care about; anything else keeps its literal
/// lower-cased type in [`FieldKind::Other`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum FieldKind {
    Text,
    Email,
    Number,
    Url,
    Password,
    Tel,
    Date,
    Checkbox,
    Radio,
    Select,
    Textarea,
    Hidden,
    File,
    Other(String),
}

// `Debug` never prints a value or a URL taken from the page: a hidden field
// carries CSRF tokens and a query string carries credentials, and this type is
// one `tracing::debug!` away from a log line (spec D8.1 redaction rules). Shape
// only — names and counts.
impl fmt::Debug for Extracted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Extracted")
            .field("has_base", &self.base.is_some())
            .field("links", &self.links.len())
            .field("resources", &self.resources.len())
            .field("forms", &self.forms)
            .finish()
    }
}

impl FormSpec {
    /// A form from its raw attributes, normalised the one way the crawler reads
    /// a form (R-M6): `action` trimmed with an empty one read as "this page",
    /// `method` trimmed and upper-cased with `GET` when absent or blank,
    /// `enctype` trimmed and lower-cased, and no fields yet. The extractor
    /// builds every `<form>` through here and the browser engine reads a live
    /// form back through it, so [`crate::crawl::values::form_action`] judges
    /// both by the same shape.
    pub(crate) fn from_attrs(
        index: usize,
        action: Option<&str>,
        method: Option<&str>,
        enctype: Option<&str>,
    ) -> Self {
        Self {
            index,
            action: trimmed(action),
            method: trimmed(method)
                .map(|method| method.to_ascii_uppercase())
                .unwrap_or_else(|| "GET".to_string()),
            enctype: trimmed(enctype).map(|enctype| enctype.to_ascii_lowercase()),
            fields: Vec::new(),
        }
    }
}

impl fmt::Debug for FormSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FormSpec")
            .field("index", &self.index)
            .field("has_action", &self.action.is_some())
            .field("method", &self.method)
            .field("enctype", &self.enctype)
            .field("fields", &self.fields)
            .finish()
    }
}

impl fmt::Debug for FieldSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FieldSpec")
            .field("name", &self.name)
            .field("kind", &self.kind)
            .field("has_value", &self.value.is_some())
            .field("options", &self.options.len())
            .field("checked", &self.checked)
            .finish()
    }
}

/// One attribute of one tag: the name lower-cased, the value decoded.
///
/// `value` is `None` for a valueless attribute such as `checked`.
struct Attr {
    name: String,
    value: Option<String>,
}

/// Read the links, resources and forms of `html`.
///
/// Never panics and never loops: unterminated markup, a quote that is never
/// closed and `<a href=<<<>>>>` are ordinary page input, and the walk always
/// advances.
pub(crate) fn extract(html: &str) -> Extracted {
    let bytes = html.as_bytes();
    let mut walk = Walk::new(html);
    let mut i = 0usize;

    while i < bytes.len() {
        if bytes[i] != b'<' {
            i += 1;
            continue;
        }
        // A comment is not markup: a commented-out anchor is not a link.
        let rest = html.get(i..).unwrap_or_default();
        if rest.starts_with("<!--") {
            i = rest.find("-->").map_or(bytes.len(), |off| i + off + 3);
            continue;
        }
        let closing = bytes.get(i + 1) == Some(&b'/');
        let name_start = if closing { i + 2 } else { i + 1 };
        let mut j = name_start;
        while j < bytes.len() && bytes[j].is_ascii_alphanumeric() {
            j += 1;
        }
        if j == name_start {
            // A `<` that opens no tag is text, including a bare `<` or `</`.
            i += 1;
            continue;
        }
        let tag = html
            .get(name_start..j)
            .unwrap_or_default()
            .to_ascii_lowercase();

        if closing {
            walk.close(&tag);
            i = scan_tag(html, j, None);
            continue;
        }
        // Raw-text elements: their content is script, CSS or plain text, not
        // markup, so `var action = "/api/delete-all"` inside one is not a form
        // and a `<form>` written inside a `<title>`, `<noscript>`, `<xmp>`,
        // `<noembed>`, `<noframes>` or `<plaintext>` is not one either; the
        // live DOM has no such form, and counting one would put every later
        // form's index off by one (S-I2, R-M2). `<script>` and `<iframe>` still
        // have their `src` read and `<textarea>` its name, so those three go
        // through `Walk::open`, which skips their bodies the same way.
        if is_raw_text_element(&tag) {
            i = raw_text_end(html, &tag, scan_tag(html, j, None));
            continue;
        }
        if !is_element_of_interest(&tag) {
            i = scan_tag(html, j, None);
            continue;
        }
        let mut attrs: Vec<Attr> = Vec::new();
        i = scan_tag(html, j, Some(&mut attrs));
        i = walk.open(&tag, &attrs, i);
    }

    walk.finish()
}

/// Whether the element's body is text the tokenizer never reads as markup
/// (besides `<script>`, `<iframe>` and `<textarea>`, which carry an attribute
/// the walk wants and are handled in [`Walk::open`]). `<plaintext>` has no end
/// tag, so it swallows the rest of the document, as it does in a browser.
fn is_raw_text_element(tag: &str) -> bool {
    matches!(
        tag,
        "style" | "title" | "noscript" | "xmp" | "noembed" | "noframes" | "plaintext"
    )
}

/// Whether the tokenizer reads this element's attributes at all; every other
/// element is skipped without allocating.
fn is_element_of_interest(tag: &str) -> bool {
    matches!(
        tag,
        "a" | "area"
            | "base"
            | "button"
            | "form"
            | "iframe"
            | "frame"
            | "input"
            | "link"
            | "meta"
            | "option"
            | "script"
            | "select"
            | "textarea"
    )
}

/// The walk's state: what the page has given so far, plus the `<form>` and the
/// `<select>` currently open.
struct Walk<'a> {
    html: &'a str,
    out: Extracted,
    form: Option<FormSpec>,
    select: Option<FieldSpec>,
    /// Every `<form>` started, including ones the page cap dropped.
    forms_seen: usize,
}

impl<'a> Walk<'a> {
    fn new(html: &'a str) -> Self {
        Self {
            html,
            out: Extracted::default(),
            form: None,
            select: None,
            forms_seen: 0,
        }
    }

    /// Everything the page gave; a form the page never closed still counts.
    fn finish(mut self) -> Extracted {
        self.close_select();
        self.close_form();
        self.out
    }

    /// Take an opening tag whose attributes end at `after`, and return the
    /// index the walk continues from.
    fn open(&mut self, tag: &str, attrs: &[Attr], after: usize) -> usize {
        match tag {
            "script" => {
                push_capped(&mut self.out.resources, attr(attrs, "src"));
                return raw_text_end(self.html, "script", after);
            }
            "base" => {
                if self.out.base.is_none() {
                    if let Some(href) = trimmed(attr(attrs, "href")) {
                        self.out.base = Some(href);
                    }
                }
            }
            "a" | "area" => push_capped(&mut self.out.links, attr(attrs, "href")),
            // An iframe's content is fallback text to the parser, never markup
            // of this page (R-M2): its `src` is the link, its body is skipped.
            "iframe" => {
                push_capped(&mut self.out.links, attr(attrs, "src"));
                return raw_text_end(self.html, "iframe", after);
            }
            "frame" => push_capped(&mut self.out.links, attr(attrs, "src")),
            "button" => push_capped(&mut self.out.links, attr(attrs, "formaction")),
            "link" => push_capped(&mut self.out.resources, attr(attrs, "href")),
            "meta" => self.meta_refresh(attrs),
            "form" => self.open_form(attrs),
            "input" if self.form.is_some() => {
                self.close_select();
                if let Some(field) = input_field(attrs) {
                    self.push_field(field);
                }
            }
            "select" if self.form.is_some() => {
                self.close_select();
                self.select = trimmed(attr(attrs, "name")).map(|name| FieldSpec {
                    name,
                    kind: FieldKind::Select,
                    value: None,
                    options: Vec::new(),
                    checked: false,
                });
            }
            "textarea" if self.form.is_some() => return self.open_textarea(attrs, after),
            // Outside a form its text is still text, never markup.
            "textarea" => return raw_text_end(self.html, "textarea", after),
            "option" => self.open_option(attrs, after),
            _ => {}
        }
        after
    }

    /// Take a closing tag; only `</select>` and `</form>` end anything.
    fn close(&mut self, tag: &str) {
        match tag {
            // The select first: `</form>` with a select still open must not
            // lose the select's field.
            "select" => self.close_select(),
            "form" => {
                self.close_select();
                self.close_form();
            }
            _ => {}
        }
    }

    /// The target of a `meta[http-equiv=refresh]`, as a plain link.
    fn meta_refresh(&mut self, attrs: &[Attr]) {
        if !attr(attrs, "http-equiv").is_some_and(|v| v.trim().eq_ignore_ascii_case("refresh")) {
            return;
        }
        if let Some(target) = attr(attrs, "content").and_then(refresh_target) {
            push_capped(&mut self.out.links, Some(target.as_str()));
        }
    }

    /// Start a form; an unclosed one ends where the next one starts.
    fn open_form(&mut self, attrs: &[Attr]) {
        self.close_select();
        self.close_form();
        self.form = Some(FormSpec::from_attrs(
            self.forms_seen,
            attr(attrs, "action"),
            attr(attrs, "method"),
            attr(attrs, "enctype"),
        ));
        self.forms_seen += 1;
    }

    /// A `<textarea>`'s default value is its text, not an attribute; the walk
    /// resumes on its closing tag.
    fn open_textarea(&mut self, attrs: &[Attr], after: usize) -> usize {
        self.close_select();
        let end = raw_text_end(self.html, "textarea", after);
        if let Some(name) = trimmed(attr(attrs, "name")) {
            self.push_field(FieldSpec {
                name,
                kind: FieldKind::Textarea,
                value: Some(decode_entities(
                    self.html.get(after..end).unwrap_or_default(),
                )),
                options: Vec::new(),
                checked: false,
            });
        }
        end
    }

    /// One `<option>` of the open `<select>`: its `value`, or its text when it
    /// has none. Options outside a select are not markup the lane needs.
    fn open_option(&mut self, attrs: &[Attr], after: usize) {
        let text = || {
            let rest = self.html.get(after..).unwrap_or_default();
            rest.find('<')
                .and_then(|end| rest.get(..end))
                .unwrap_or(rest)
                .trim()
                .to_string()
        };
        if let Some(open) = self.select.as_mut() {
            if open.options.len() < MAX_OPTIONS_PER_SELECT {
                let value = attr(attrs, "value").map_or_else(text, ToString::to_string);
                open.options.push(value);
            }
        }
    }

    /// Add `field` to the open form, up to [`MAX_FIELDS_PER_FORM`].
    fn push_field(&mut self, field: FieldSpec) {
        if let Some(form) = self.form.as_mut() {
            if form.fields.len() < MAX_FIELDS_PER_FORM {
                form.fields.push(field);
            }
        }
    }

    /// Hand the open `<select>`, if any, to the open form as a field.
    fn close_select(&mut self) {
        if let Some(field) = self.select.take() {
            self.push_field(field);
        }
    }

    /// Hand the open `<form>`, if any, to the page, up to
    /// [`MAX_FORMS_PER_PAGE`].
    fn close_form(&mut self) {
        if let Some(form) = self.form.take() {
            if self.out.forms.len() < MAX_FORMS_PER_PAGE {
                self.out.forms.push(form);
            }
        }
    }
}

/// The `FieldSpec` an `<input>` contributes, if it contributes one.
///
/// Nameless controls and the buttons (`submit`, `button`, `image`, `reset`) are
/// not fields: they carry no operator-supplied value to mutate.
fn input_field(attrs: &[Attr]) -> Option<FieldSpec> {
    let name = trimmed(attr(attrs, "name"))?;
    let kind = attr(attrs, "type").map_or("text".to_string(), |t| t.trim().to_ascii_lowercase());
    let kind = match kind.as_str() {
        "submit" | "button" | "image" | "reset" => return None,
        "" | "text" => FieldKind::Text,
        "email" => FieldKind::Email,
        "number" | "range" => FieldKind::Number,
        "url" => FieldKind::Url,
        "password" => FieldKind::Password,
        "tel" => FieldKind::Tel,
        "date" | "datetime-local" | "month" | "week" | "time" => FieldKind::Date,
        "checkbox" => FieldKind::Checkbox,
        "radio" => FieldKind::Radio,
        "hidden" => FieldKind::Hidden,
        "file" => FieldKind::File,
        other => FieldKind::Other(other.to_string()),
    };
    let toggle = matches!(kind, FieldKind::Checkbox | FieldKind::Radio);
    Some(FieldSpec {
        name,
        value: match attr(attrs, "value") {
            Some(value) => Some(value.to_string()),
            // The browser submits `on` for a checked toggle with no value.
            None if toggle => Some("on".to_string()),
            None => None,
        },
        options: Vec::new(),
        checked: toggle && has_attr(attrs, "checked"),
        kind,
    })
}

/// Push a trimmed, non-empty `value` while `list` is under
/// [`MAX_LINKS_PER_PAGE`]; the links and the resources are capped separately.
fn push_capped(list: &mut Vec<String>, value: Option<&str>) {
    if let Some(value) = trimmed(value) {
        if list.len() < MAX_LINKS_PER_PAGE {
            list.push(value);
        }
    }
}

/// `value` trimmed, or `None` when it is absent or blank.
fn trimmed(value: Option<&str>) -> Option<String> {
    let value = value?.trim();
    (!value.is_empty()).then(|| value.to_string())
}

/// The first value of `name` among `attrs` (first occurrence wins, as a browser
/// does); attribute names were lower-cased when they were read.
fn attr<'a>(attrs: &'a [Attr], name: &str) -> Option<&'a str> {
    attrs
        .iter()
        .find(|a| a.name == name)
        .and_then(|a| a.value.as_deref())
}

/// Whether `attrs` carries `name` at all, with or without a value.
fn has_attr(attrs: &[Attr], name: &str) -> bool {
    attrs.iter().any(|a| a.name == name)
}

/// The URL a `meta[http-equiv=refresh]`'s `content` points at.
///
/// `content="0;url=/next"`, `content="0; URL='/next'"` and `content="url=/next"`
/// all give `/next`; a plain delay gives nothing.
///
/// Page text is sliced with `get`, never by index: `content="0;éé"` puts a
/// multi-byte char across byte 3, and an indexed `rest[..3]` panics the whole
/// extraction (C1).
fn refresh_target(content: &str) -> Option<String> {
    let rest = content.split_once(';').map_or(content, |(_, r)| r).trim();
    let (keyword, after) = (rest.get(..3)?, rest.get(3..)?);
    if !keyword.eq_ignore_ascii_case("url") {
        return None;
    }
    let target = after
        .trim_start()
        .strip_prefix('=')?
        .trim()
        .trim_matches(['"', '\''])
        .trim();
    (!target.is_empty()).then(|| target.to_string())
}

/// Walk the attributes of the tag whose name ends at `from`, returning the index
/// just past the tag's `>`; when `sink` is given, each attribute is recorded
/// with its name lower-cased and its value entity-decoded.
///
/// Attribute names are matched whole by the caller, so `data-href` is not
/// `href`. An unterminated tag consumes the rest of the page rather than
/// rewinding, which is what keeps the walk finite.
fn scan_tag(html: &str, from: usize, mut sink: Option<&mut Vec<Attr>>) -> usize {
    let bytes = html.as_bytes();
    let mut i = from;
    while i < bytes.len() {
        if bytes[i] == b'>' {
            return i + 1;
        }
        if bytes[i].is_ascii_whitespace() || bytes[i] == b'/' {
            i += 1;
            continue;
        }
        // An attribute name runs to whitespace, `=` or `>`.
        let name_start = i;
        while i < bytes.len() && !bytes[i].is_ascii_whitespace() && !matches!(bytes[i], b'=' | b'>')
        {
            i += 1;
        }
        let name = html.get(name_start..i).unwrap_or_default();
        let mut k = i;
        while k < bytes.len() && bytes[k].is_ascii_whitespace() {
            k += 1;
        }
        if k >= bytes.len() {
            return bytes.len();
        }
        if bytes[k] != b'=' {
            // A valueless attribute such as `checked`; `i` is past its name.
            record(&mut sink, name, None);
            continue;
        }
        k += 1;
        while k < bytes.len() && bytes[k].is_ascii_whitespace() {
            k += 1;
        }
        if k >= bytes.len() {
            return bytes.len();
        }
        let (value, next) = match bytes[k] {
            quote @ (b'"' | b'\'') => {
                let start = k + 1;
                let rest = html.get(start..).unwrap_or_default();
                match rest
                    .find(quote as char)
                    .and_then(|len| Some((rest.get(..len)?, len)))
                {
                    Some((value, len)) => (value, start + len + 1),
                    // An unterminated quote swallows the rest of the page.
                    None => return bytes.len(),
                }
            }
            b'>' => {
                // `name=` with nothing after it: the tag ends here.
                record(&mut sink, name, None);
                i = k;
                continue;
            }
            _ => {
                let start = k;
                let rest = html.get(start..).unwrap_or_default();
                let len = rest
                    .find(|c: char| c.is_ascii_whitespace() || c == '>')
                    .unwrap_or(rest.len());
                (rest.get(..len).unwrap_or_default(), start + len)
            }
        };
        record(&mut sink, name, Some(value));
        i = next;
    }
    bytes.len()
}

/// Record one attribute in `sink`, if the caller asked for the attributes.
fn record(sink: &mut Option<&mut Vec<Attr>>, name: &str, value: Option<&str>) {
    if name.is_empty() {
        return;
    }
    if let Some(sink) = sink.as_mut() {
        sink.push(Attr {
            name: name.to_ascii_lowercase(),
            value: value.map(decode_entities),
        });
    }
}

/// The index of the `<` of the next `</tag`, searched case-insensitively from
/// `from`, or the end of the page when there is none.
///
/// A single forward pass comparing bytes in place: nothing is allocated or
/// lowercased per call, so a page of a hundred thousand empty
/// `<script></script>` pairs costs one linear scan in total, not one copy of the
/// remaining DOM per tag.
fn raw_text_end(html: &str, tag: &str, from: usize) -> usize {
    let start = from.min(html.len());
    let hay = &html.as_bytes()[start..];
    let tag = tag.as_bytes();
    let needle_len = tag.len() + 2;
    if hay.len() < needle_len {
        return html.len();
    }
    (0..=hay.len() - needle_len)
        .find(|&i| {
            hay[i] == b'<'
                && hay[i + 1] == b'/'
                && hay[i + 2..i + needle_len].eq_ignore_ascii_case(tag)
        })
        .map_or(html.len(), |i| start + i)
}

/// Decode the entities an attribute value or an option's text commonly carries.
///
/// One left-to-right pass, so output is never re-scanned and a decoded `&` is
/// never decoded again: `&amp;lt;` is the text `&lt;` and never `<`. An
/// unknown or unterminated entity is left exactly as written.
fn decode_entities(value: &str) -> String {
    if !value.contains('&') {
        return value.to_string();
    }
    let mut out = String::with_capacity(value.len());
    let mut rest = value;
    while let Some(amp) = rest.find('&') {
        out.push_str(rest.get(..amp).unwrap_or_default());
        let tail = rest.get(amp..).unwrap_or_default();
        match decode_one(tail) {
            Some((decoded, len)) => {
                out.push(decoded);
                rest = tail.get(len..).unwrap_or_default();
            }
            None => {
                out.push('&');
                rest = tail.get(1..).unwrap_or_default();
            }
        }
    }
    out.push_str(rest);
    out
}

/// The named entities a page actually uses in an attribute value.
const NAMED_ENTITIES: [(&str, char); 5] = [
    ("&lt;", '<'),
    ("&gt;", '>'),
    ("&quot;", '"'),
    ("&apos;", '\''),
    ("&amp;", '&'),
];

/// Longest `&#...;` body accepted, enough for any code point.
const MAX_NUMERIC_ENTITY: usize = 8;

/// The character the entity at the start of `tail` denotes, with its length in
/// bytes; `None` when `tail` does not start with one this decoder knows.
fn decode_one(tail: &str) -> Option<(char, usize)> {
    for (entity, decoded) in NAMED_ENTITIES {
        if tail.starts_with(entity) {
            return Some((decoded, entity.len()));
        }
    }
    let body = tail.strip_prefix("&#")?;
    let (digits, radix) = match body.strip_prefix(['x', 'X']) {
        Some(hex) => (hex, 16),
        None => (body, 10),
    };
    let end = digits.find(';')?;
    if end == 0 || end > MAX_NUMERIC_ENTITY {
        return None;
    }
    let code = u32::from_str_radix(digits.get(..end)?, radix).ok()?;
    let decoded = char::from_u32(code)?;
    Some((decoded, tail.len() - digits.len() + end + 1))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{extract, refresh_target, FieldKind, FormSpec};
    use crate::limits::{
        MAX_FIELDS_PER_FORM, MAX_FORMS_PER_PAGE, MAX_LINKS_PER_PAGE, MAX_OPTIONS_PER_SELECT,
    };

    /// The pinned page of the plan's task 4: one literal page exercising every
    /// link source, every resource source, the comment and raw-text skips, the
    /// entity decode and the whole form shape in one pass.
    #[test]
    fn extract_pins() {
        let html = r#"<base href="/app/"><a href="/one">1</a><!-- <a href="/hidden">h</a> --><script>var s="<a href='/js'>";</script><form action="/search" method="get"><input name="q"><select name="s"><option value="a">A</option><option value="b">B</option></select><input type="hidden" name="h" value="1"><input type="radio" name="r" value="x" checked><input type="radio" name="r" value="y"><input type="submit"></form><meta http-equiv="refresh" content="0;url=/next"><iframe src="/frame"></iframe><link href="/s.css" rel="stylesheet"><script src="/app.js"></script><button formaction="/alt">b</button><a href="/amp?a=1&amp;b=2">x</a>"#;

        let out = extract(html);

        assert_eq!(out.base.as_deref(), Some("/app/"));
        assert_eq!(
            out.links,
            ["/one", "/next", "/frame", "/alt", "/amp?a=1&b=2"]
        );
        assert_eq!(out.resources, ["/s.css", "/app.js"]);
        assert_eq!(out.forms.len(), 1);

        let form = &out.forms[0];
        assert_eq!(form.index, 0);
        assert_eq!(form.method, "GET");
        assert_eq!(form.action.as_deref(), Some("/search"));

        let names: Vec<&str> = form.fields.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, ["q", "s", "h", "r", "r"]);
        let kinds: Vec<FieldKind> = form.fields.iter().map(|f| f.kind.clone()).collect();
        assert_eq!(
            kinds,
            [
                FieldKind::Text,
                FieldKind::Select,
                FieldKind::Hidden,
                FieldKind::Radio,
                FieldKind::Radio
            ]
        );
        assert_eq!(form.fields[1].options, ["a", "b"]);
        assert_eq!(form.fields[2].value.as_deref(), Some("1"));
        assert!(form.fields[3].checked);
        assert!(!form.fields[4].checked);
    }

    /// A hostile page cannot grow the frontier without bound.
    #[test]
    fn extract_caps_links() {
        let mut html = String::new();
        for i in 0..600 {
            html.push_str(&format!("<a href=\"/p{i}\">x</a>"));
        }

        let out = extract(&html);

        assert_eq!(out.links.len(), MAX_LINKS_PER_PAGE);
        assert_eq!(out.links[0], "/p0");
        assert_eq!(out.links[MAX_LINKS_PER_PAGE - 1], "/p511");
    }

    /// Unterminated markup is page input, not a bug report: the extractor
    /// returns what it could read and never panics or spins.
    #[test]
    fn extract_survives_garbage() {
        let out = extract("<a href=<<<>>>><form><input");

        assert_eq!(out.links, ["<<<"]);
        assert_eq!(out.forms.len(), 1);
        assert!(out.forms[0].fields.is_empty());

        // C1: a refresh whose target is multi-byte text where the `url` keyword
        // would be must not slice inside a char. Neither is a link.
        let out = extract(
            r#"<meta http-equiv="refresh" content="0;éé"><meta http-equiv="refresh" content="0;é日"><a href="/after">x</a>"#,
        );
        assert_eq!(out.links, ["/after"]);
        // The same shapes without a delay, and a bare multi-byte keyword.
        let out = extract(
            r#"<meta http-equiv="refresh" content="éé"><meta http-equiv="refresh" content="日本語=/x"><meta http-equiv="refresh" content="0; URL=/ok">"#,
        );
        assert_eq!(out.links, ["/ok"]);
    }

    /// C1 (tester): `refresh_target` is the function that panicked. Pinned
    /// directly on the shapes that put a char boundary inside byte 3 and on the
    /// shapes that must still resolve, so the `get` cannot quietly become an
    /// index again.
    #[test]
    fn refresh_target_pins_multibyte_and_keyword_shapes() {
        assert_eq!(refresh_target("0;éé"), None);
        assert_eq!(refresh_target("0;é日"), None);
        assert_eq!(refresh_target("éé"), None);
        assert_eq!(refresh_target("日本語=/x"), None);
        assert_eq!(refresh_target("uré=/x"), None);
        assert_eq!(refresh_target("ur"), None);
        assert_eq!(refresh_target(""), None);
        assert_eq!(refresh_target("5"), None);
        assert_eq!(refresh_target("0;url"), None);
        assert_eq!(refresh_target("0;url="), None);
        assert_eq!(refresh_target("0;url=/é"), Some("/é".to_string()));
        assert_eq!(refresh_target("0; URL='/ok'"), Some("/ok".to_string()));
        assert_eq!(refresh_target("url=/next"), Some("/next".to_string()));
    }

    /// C1 (tester): every indexed slice of page text in this module became a
    /// `get`. A 2-, 3- and 4-byte char dropped at every char boundary of a
    /// page that reaches each of them (comment, tag name, quoted and bare
    /// attribute values, textarea, option, entities, meta refresh, raw text)
    /// must never panic. A 2-byte char at offset 2 of `url` is the exact C1
    /// shape (`ur` + `é` puts byte 3 inside the char).
    #[test]
    fn extract_never_panics_with_a_multibyte_char_anywhere() {
        const PAGE: &str = concat!(
            r#"<!-- <a href="/c"> --><meta http-equiv="refresh" content="0;url=/r">"#,
            r#"<a href=/bare title='q'>x</a><base href="/b/"><form action="/f" method=post>"#,
            r#"<textarea name="t">body &amp; &#233; &#xe9; &bogus; &#99999999;</textarea>"#,
            r#"<select name="s"><option>one<option value="2">two</select>"#,
            r#"<input name="r" type=radio checked><input name=unq value=v></form>"#,
            r#"<style>a{}</style><title><a href="/t"></title><script src="/s.js"></script>"#,
            r#"<a href="/unterminated"#,
        );
        let boundaries = PAGE
            .char_indices()
            .map(|(at, _)| at)
            .chain(std::iter::once(PAGE.len()));
        for at in boundaries {
            for insert in ["é", "日", "\u{10348}"] {
                let mut page = String::with_capacity(PAGE.len() + insert.len());
                page.push_str(&PAGE[..at]);
                page.push_str(insert);
                page.push_str(&PAGE[at..]);
                // Only the absence of a panic is asserted: what the page means
                // with a stray char in it is not this test's question.
                let _ = extract(&page);
            }
        }
    }

    /// S-I2: the bodies of `textarea`, `title`, `noscript` and `xmp` are text,
    /// never markup, in or out of a form, so a `<form>` written inside one is
    /// not a form the crawler would submit (the live DOM has no such form, and
    /// the index of every later form would otherwise be off by one).
    #[test]
    fn extract_treats_raw_text_bodies_as_text() {
        let out = extract(r#"<textarea><form action="/x"><input name="q"></textarea>"#);
        assert!(out.forms.is_empty(), "{out:?}");
        assert!(out.links.is_empty());

        let out = extract(concat!(
            r#"<title><form action="/t"><a href="/t"></title>"#,
            r#"<noscript><form action="/n"><input name="n"></noscript>"#,
            r#"<xmp><a href="/x"><form action="/x"></xmp>"#,
            r#"<TEXTAREA name="free"><form action="/ta"></TEXTAREA>"#,
            r#"<form action="/real"><textarea name="c"><input name="not-a-field"></textarea></form>"#,
        ));
        assert!(out.links.is_empty(), "{:?}", out.links);
        assert_eq!(out.forms.len(), 1);
        assert_eq!(out.forms[0].index, 0);
        assert_eq!(out.forms[0].action.as_deref(), Some("/real"));
        let names: Vec<&str> = out.forms[0]
            .fields
            .iter()
            .map(|f| f.name.as_str())
            .collect();
        assert_eq!(names, ["c"]);
    }

    /// The remaining raw-text bodies (R-M2): an `<iframe>`'s fallback content,
    /// `<noembed>`, `<noframes>` and `<plaintext>` are text to the parser, so a
    /// form written inside one is not a form and does not consume an index
    /// (`FormSpec::index` counts forms the walk *started*; a form inside a
    /// raw-text body is never started), while the `<iframe src>` is still a
    /// link.
    #[test]
    fn extract_treats_iframe_noembed_noframes_and_plaintext_bodies_as_text() {
        let out = extract(concat!(
            r#"<iframe src="/f"><form action="/x"><input name="q"></form></iframe>"#,
            r#"<form action="/real"><input name="a"></form>"#,
        ));
        assert_eq!(out.links, vec!["/f".to_string()]);
        assert!(out.resources.is_empty(), "{:?}", out.resources);
        assert_eq!(out.forms.len(), 1, "{out:?}");
        assert_eq!(out.forms[0].index, 0);
        assert_eq!(out.forms[0].action.as_deref(), Some("/real"));
        let names: Vec<&str> = out.forms[0]
            .fields
            .iter()
            .map(|f| f.name.as_str())
            .collect();
        assert_eq!(names, ["a"]);

        let out = extract(concat!(
            r#"<noembed><form action="/ne"><a href="/ne"></noembed>"#,
            r#"<NOFRAMES><form action="/nf"><input name="nf"></NOFRAMES>"#,
            r#"<form action="/real"><input name="b"></form>"#,
            r#"<plaintext><form action="/pt"><a href="/pt">"#,
        ));
        assert!(out.links.is_empty(), "{:?}", out.links);
        assert_eq!(out.forms.len(), 1, "{out:?}");
        assert_eq!(out.forms[0].index, 0);
        assert_eq!(out.forms[0].action.as_deref(), Some("/real"));
    }

    /// The one normalisation of a form's attributes (R-M6), shared by the
    /// extractor and the browser engine's live-form read: `action` trimmed
    /// (empty is none), `method` trimmed and upper-cased with `GET` when absent
    /// or blank, `enctype` trimmed and lower-cased, no fields.
    #[test]
    fn form_spec_from_attrs_pins() {
        let spec = FormSpec::from_attrs(
            3,
            Some("  /search "),
            Some(" post "),
            Some(" MULTIPART/Form-Data "),
        );
        assert_eq!(spec.index, 3);
        assert_eq!(spec.action.as_deref(), Some("/search"));
        assert_eq!(spec.method, "POST");
        assert_eq!(spec.enctype.as_deref(), Some("multipart/form-data"));
        assert!(spec.fields.is_empty());

        let bare = FormSpec::from_attrs(0, None, None, None);
        assert_eq!(bare.action, None);
        assert_eq!(bare.method, "GET");
        assert_eq!(bare.enctype, None);

        let blank = FormSpec::from_attrs(1, Some("  "), Some(""), Some(" "));
        assert_eq!(blank.action, None);
        assert_eq!(blank.method, "GET");
        assert_eq!(blank.enctype, None);

        // The extractor builds its forms through the same function.
        let out = extract(r#"<form action=" /x " method="PoSt" enctype=" A/B "></form>"#);
        assert_eq!(
            out.forms,
            vec![FormSpec::from_attrs(
                0,
                Some("/x"),
                Some("post"),
                Some("a/b")
            )]
        );
    }

    /// Controls the plan excludes stay out; the ones it keeps carry their
    /// documented defaults.
    #[test]
    fn extract_reads_control_defaults_and_drops_non_fields() {
        let html = r#"<form enctype="MULTIPART/Form-Data"><textarea name="c">hi &amp; bye</textarea><select name="s"><option>Plain</option><option value="">empty</option></select><input type="checkbox" name="ok"><input type="submit" name="go"><input type="image" name="img"><input type="button" name="b"><input type="reset" name="rst"><input type="weird" name="w"><input value="nameless"></form>"#;

        let out = extract(html);

        assert_eq!(out.forms.len(), 1);
        let form = &out.forms[0];
        assert_eq!(form.method, "GET");
        assert_eq!(form.action, None);
        assert_eq!(form.enctype.as_deref(), Some("multipart/form-data"));

        let names: Vec<&str> = form.fields.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, ["c", "s", "ok", "w"]);
        assert_eq!(form.fields[0].kind, FieldKind::Textarea);
        assert_eq!(form.fields[0].value.as_deref(), Some("hi & bye"));
        assert_eq!(form.fields[1].options, ["Plain", ""]);
        assert_eq!(form.fields[2].kind, FieldKind::Checkbox);
        assert_eq!(form.fields[2].value.as_deref(), Some("on"));
        assert_eq!(form.fields[3].kind, FieldKind::Other("weird".to_string()));
    }

    /// Entity decoding is one left-to-right pass, so a decoded `&` is never
    /// decoded again: `&amp;lt;` is the text `&lt;`, never `<`.
    #[test]
    fn extract_decodes_entities_once() {
        let out = extract(
            r#"<a href="/x?a=&amp;lt;&b=&lt;&quot;&gt;&#39;&#x27;&apos;">x</a><a href="/y?n=&#65;&#x42;">y</a>"#,
        );

        assert_eq!(out.links, ["/x?a=&lt;&b=<\">'''", "/y?n=AB"]);
    }

    /// Per-form and per-select ceilings hold on a hostile page.
    #[test]
    fn extract_caps_forms_fields_and_options() {
        let mut many = String::new();
        for _ in 0..(MAX_FORMS_PER_PAGE * 2) {
            many.push_str("<form action=\"/f\"><input name=\"a\"></form>");
        }
        assert_eq!(extract(&many).forms.len(), MAX_FORMS_PER_PAGE);

        let mut big = String::from("<form><select name=\"s\">");
        for i in 0..(MAX_OPTIONS_PER_SELECT + 10) {
            big.push_str(&format!("<option value=\"o{i}\">"));
        }
        big.push_str("</select>");
        for i in 0..(MAX_FIELDS_PER_FORM + 10) {
            big.push_str(&format!("<input name=\"f{i}\">"));
        }
        big.push_str("</form>");

        let out = extract(&big);

        assert_eq!(out.forms.len(), 1);
        assert_eq!(out.forms[0].fields.len(), MAX_FIELDS_PER_FORM);
        assert_eq!(out.forms[0].fields[0].options.len(), MAX_OPTIONS_PER_SELECT);
    }

    /// The raw-text skip must not copy the rest of the DOM per tag: this runs
    /// synchronously between awaits, where the budget cannot interrupt it.
    #[test]
    fn extract_is_linear_on_many_script_tags() {
        let mut html = String::from("<a href=\"/first\">first</a>");
        for _ in 0..100_000 {
            html.push_str("<script></script>");
        }
        html.push_str("<SCRIPT>var href = \"/not-a-link\";</SCRIPT><a href=\"/last\">last</a>");

        let started = std::time::Instant::now();
        let out = extract(&html);
        let elapsed = started.elapsed();

        assert_eq!(out.links, ["/first", "/last"]);
        assert!(
            elapsed < std::time::Duration::from_secs(10),
            "extract took {elapsed:?} on 100k script tags"
        );
    }
}
