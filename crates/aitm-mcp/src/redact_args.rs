//! The structural half of audit redaction: what a call's arguments look like in
//! the audit entry (the ring, the pushed `notifications/aitm/agent` line,
//! `agent.activity`, and the durable file).
//!
//! [`redact_value`] walks a `serde_json::Value` and applies, in this order of
//! precedence, to every object member:
//!
//! 1. **Secret key.** A member whose key names a secret (the strict vocabulary of
//!    `aitm_core::redact_strict::is_secret_key_strict`, plus the reserved
//!    `_confirm` acknowledgment) has its value replaced by `"<redacted>"`, whatever
//!    its type.
//! 2. **Rule S** (structural, container-agnostic, anywhere in the arguments). An
//!    array of exactly two strings whose first element is a strict secret key has
//!    its second element replaced (`["Cookie","x"]` becomes `["Cookie",
//!    "<redacted>"]`). An object with a string member among `name`, `key`,
//!    `header`, `field`, `selector` or `label` whose value is a strict secret key
//!    has its value members replaced: `value`, `values`, `val`, `text`, `data`,
//!    `content`, `input`, `keys`, `string`, and any key that ends in `value` or
//!    `values` (`cookie_value`). An object whose `header_name` member names a header
//!    that does not keep its value (a secret, or any name off the benign list) has
//!    its `header_value` member replaced. Names and every other member stay.
//! 3. **Rule D** (default-deny, inside a header collection only). A header
//!    collection is what sits under a key whose ASCII-lowercased name contains
//!    `header` or `hdr`, or is `trailer` or `trailers` (`headers`, `extra_headers`,
//!    `custom_headers`, `hdrs`, `req_hdrs`, `trailers`, ...), at any depth. Everything
//!    below such a key keeps the header context: an array of arrays, an array of
//!    maps, a map of maps. A boolean, a number or a string with no header shape under
//!    such a key (`include_headers: true`, `header_name: "X-Foo"`) is left as it is.
//!    Inside a collection, a header's value is kept only when its name is on the
//!    benign list and is not a strict secret key; every other value is replaced by
//!    `"<redacted>"` whatever its type. A value that is kept (the value of a **kept**
//!    name) must be a string or a number, boolean or null: an object is replaced, and
//!    so is a container nested in a list of values (a list of scalars and strings is
//!    the multi-value form of the header and stays). The names stay, but each name
//!    inside a collection (a map key, a pair name, a `name`/`key`/`header` member, the
//!    keys of a header object) passes the strict text pass and is cut at 256 bytes.
//!    The shapes a header takes:
//!    - a plain map (an object with no name member) in an array, or a map under a
//!      collection key: each member is a header, rule D by key;
//!    - an array of two or more elements whose first element is a string, **whatever
//!      the types of the rest** (`["X-N", 5]`, `["X-Zed", "a", "b"]`): the first
//!      element is the name and rule D decides **every** later element by it. It is
//!      also read when it is the whole value of the key (`"headers": ["X-Debug",
//!      "v"]`) and its first element, as the text pass leaves it, holds no `:`
//!      (`["My Cookie", "v"]`, `["X-Api Key", "a", "b"]`, of any length: a name that is
//!      not a token is never benign, so every value is hidden). A first element with
//!      a `:` makes it a list of lines, below (`["Cookie: a=b", "X-Debug: c"]`); a bare
//!      list of two header names reads as a name and its value, an accepted
//!      over-redaction. In that direct form, a later element that is a raw header line
//!      (`name:` then a blank or the end, so `https://x/` is not one) is judged as a
//!      line by its name;
//!    - an object with a `name`, `key` or `header` member: its members other than
//!      the name members keep their value only when the name keeps its value, and
//!      are otherwise **all** replaced by `"<redacted>"` (a `values` list and any
//!      other member included);
//!    - a string `Name: value` (a raw header line): split at the first `:`, and when
//!      the name (blanks around it trimmed) is a header token, or any other non-empty
//!      name of at most 256 bytes with no line break (`X Debug`,
//!      `Xé`, `日本`: a name that is not a token is never benign), the value is kept
//!      for a name that keeps its value and otherwise reads `Name: [redacted]`, the
//!      text-mask literal a line already carries. Any other string is a block of header
//!      text, below.
//!
//!    **Header text with line breaks.** A string under a header-collection key, a
//!    header name, and any array element that is not a `Name: value` line is a block
//!    of header text. With line breaks in it, it is split at every `\r\n`, `\r` and
//!    `\n`, each line is judged by its name as above (any non-empty name, not only a
//!    token), a line folded onto a hidden header (it starts with a blank) goes with it,
//!    and the line breaks stay as written. A single line with no header-token name
//!    keeps the text pass alone, so a descriptive string stays readable. A **kept**
//!    header value (a benign name's value in a pair, a map, a header object or a raw
//!    line) that holds a line break is read the same way from its first break on: its
//!    first line is the value, every later line is judged by its name.
//!
//! Every string that is kept (a leaf, a kept header value) passes
//! `aitm_core::redact_strict::scrub_strict`, so a credential inside prose, a URL or
//! a free-text body is masked by content too. Every object key does as well (a secret
//! used as a key, `{"Bearer abc": 1}`, is masked in the key text; whether the value is
//! hidden is still decided on the original key). Numbers, booleans and nulls are
//! untouched.
//!
//! **The work is bounded** (Design 14.6 of `docs/superpowers/specs/2026-10-31-durable-audit-design.md`): a string leaf is examined
//! only up to its first 4096 bytes and the whole value only up to 64 KiB of string text,
//! in the order the walk visits it (the object's own iteration order, so the same
//! arguments always give the same entry). Text beyond the bound is dropped and shown as
//! the single character `…`; once the total is spent every later string leaf is `…`.
//! The text a leaf is shown as is cut at the same bound (a mask can lengthen text).
//! Numbers, booleans, nulls and values that are replaced by `"<redacted>"` cost
//! nothing. A name string inside a header collection (a pair name, a `name` member) is
//! a string leaf, cut at 256 bytes and charged to that budget; object keys are cut at
//! the same size and charged to pools of their own (64 KiB each, for the keys inside
//! header collections and for the others), so they cost the leaves nothing. Two names
//! that become the same text after the cut or the mask share one key in the output: the
//! later one overwrites the earlier (a collision can lose a name, never reveal a
//! value). A container nested deeper than 64 levels is replaced by `"<redacted>"`, so
//! hostile nesting cannot exhaust the stack.
//!
//! **The result is a fixed point.** The walk is run again over its own result until a
//! round leaves it alone (the first walk and at most three more, each with the budgets
//! of a fresh call), because text can be masked into a different shape: a colon that a
//! mask removes changes how a header array reads on the next walk. A value that does
//! not settle in those rounds is returned as the last round left it, as the strict text
//! pass itself does after its `MAX_ROUNDS` rounds; no input is known to reach that.
//!
//! The function is `pub`, and not private to the server, because the durable
//! writer reuses it: for an `args` text that parses as JSON it applies this same
//! function, so the file can never be less strict than the ring.
//!
//! Every pass runs on decoded string content, never on JSON text.

use aitm_core::redact_strict::{
    is_benign_header, is_secret_key_strict, scrub_strict, scrub_strict_bounded,
};
use serde_json::{Map, Value};

/// The literal that replaces a value this module hides, the one a secret-named
/// key has always produced.
const KEY_REDACTED: &str = "<redacted>";

/// The mask literal of the strict text pass: what a hidden value reads inside a raw
/// header line (`Cookie: [redacted]`), so a line looks the same whether the text
/// pass or rule D hid its value.
const TEXT_REDACTED: &str = "[redacted]";

/// Stands for text the bound dropped, and for every string leaf after the total
/// budget is spent.
const ELLIPSIS: char = '…';

/// The most bytes of any one string leaf that are examined, and that a leaf is shown
/// as (Design 14.6 of `docs/superpowers/specs/2026-10-31-durable-audit-design.md`).
const LEAF_EXAMINE_BYTES: usize = 4096;

/// The most bytes of string text that are examined in one walk (Design 14.6 of
/// `docs/superpowers/specs/2026-10-31-durable-audit-design.md`).
const TOTAL_EXAMINE_BYTES: usize = 64 * 1024;

/// The most bytes of one name that are examined, and that a name is shown as: an
/// object key, a pair name, a `name` member (cut on a char boundary, with `…`).
const NAME_EXAMINE_BYTES: usize = 256;

/// The deepest container nesting [`redact_value`] walks: the top value is level 1, and
/// a container at a deeper level is replaced by `"<redacted>"`.
const MAX_DEPTH: usize = 64;

/// The most bytes of an error reason that are scrubbed for the audit entry (the call
/// path must not pay for a megabyte echoed back): the bound the server gives
/// `scrub_strict_bounded`.
pub(crate) const REASON_EXAMINE_BYTES: usize = 8192;

/// The most further walks [`redact_value`] runs over its own result to reach a fixed
/// point, after the first.
const SETTLE_ROUNDS: usize = 3;

/// The most extra passes the text a leaf is shown as gets to settle within its bound.
const OUTPUT_ROUNDS: usize = 4;

/// Sibling keys that name a thing (a header, a form field, a selector): when the
/// name is a strict secret key, the sibling value keys hold its secret.
const SIBLING_NAME_KEYS: [&str; 6] = ["name", "key", "header", "field", "selector", "label"];

/// Sibling keys that hold the value of the thing a sibling name key names (a key
/// that ends in `value` or `values` does too: see [`is_value_key`]).
const SIBLING_VALUE_KEYS: [&str; 9] = [
    "value", "values", "val", "text", "data", "content", "input", "keys", "string",
];

/// The members of a header object that name the header.
const HEADER_NAME_KEYS: [&str; 3] = ["name", "key", "header"];

/// Redact a call's arguments for the audit entry (rules S and D, the secret-key
/// rule, the strict text pass over every kept string and every key, and the bounds on
/// the work; see the module doc).
///
/// Idempotent: `redact_value(&redact_value(v)) == redact_value(v)`, because the walk is
/// run again over its own result until a round leaves it alone (`settle`). The
/// one exception is a value that does not settle within the rounds, which is returned
/// as the last round left it; no input is known to do that.
pub fn redact_value(value: &Value) -> Value {
    settle(walk(value, &mut Budget::new()), |round| {
        walk(round, &mut Budget::new())
    })
}

/// Run `again` over `value` until a round leaves it unchanged, and return that value:
/// at most [`SETTLE_ROUNDS`] rounds, so a value that never settles is returned as the
/// last round left it, unconfirmed. A value that is already settled costs one round.
fn settle(first: Value, again: impl Fn(&Value) -> Value) -> Value {
    let mut current = first;
    for _ in 0..SETTLE_ROUNDS {
        let next = again(&current);
        if next == current {
            return current;
        }
        current = next;
    }
    current
}

// ---- budget and bounds ---------------------------------------------------------

/// How much text the traversal may still examine, and how deep it is. One per
/// [`redact_value`] call, spent in the order the walk visits the value.
struct Budget {
    /// Bytes of string leaves (and name strings) still to examine.
    left: usize,
    /// Bytes of object keys inside header collections still to examine.
    keys_left: usize,
    /// Bytes of the other object keys still to examine.
    plain_keys_left: usize,
    /// The container nesting level the walk is at.
    depth: usize,
}

/// What a pool of a [`Budget`] grants a string.
enum Granted<'a> {
    /// The pool is spent: the string is shown as `…` and nothing of it is examined.
    Nothing,
    /// The examined start of the string; `cut` says text beyond it was dropped.
    Head { head: &'a str, cut: bool },
}

impl Budget {
    fn new() -> Budget {
        Budget {
            left: TOTAL_EXAMINE_BYTES,
            keys_left: TOTAL_EXAMINE_BYTES,
            plain_keys_left: TOTAL_EXAMINE_BYTES,
            depth: 0,
        }
    }

    /// Grant a string leaf its examined start (see [`grant`]): at most
    /// [`LEAF_EXAMINE_BYTES`] and what is left of the leaf budget.
    fn take<'a>(&mut self, text: &'a str) -> Granted<'a> {
        grant(&mut self.left, LEAF_EXAMINE_BYTES, text)
    }

    /// Grant a name string (a pair name, a `name` member) its examined start: at most
    /// [`NAME_EXAMINE_BYTES`], charged to the leaf budget.
    fn take_name<'a>(&mut self, text: &'a str) -> Granted<'a> {
        grant(&mut self.left, NAME_EXAMINE_BYTES, text)
    }

    /// Grant an object key inside a header collection its examined start: at most
    /// [`NAME_EXAMINE_BYTES`], charged to the pool of those keys.
    fn take_key<'a>(&mut self, text: &'a str) -> Granted<'a> {
        grant(&mut self.keys_left, NAME_EXAMINE_BYTES, text)
    }

    /// Grant any other object key its examined start: at most [`NAME_EXAMINE_BYTES`],
    /// charged to the pool of those keys.
    fn take_plain_key<'a>(&mut self, text: &'a str) -> Granted<'a> {
        grant(&mut self.plain_keys_left, NAME_EXAMINE_BYTES, text)
    }
}

/// Grant `text` its examined start: at most `cap` bytes and at most what is `left` in
/// its pool, cut back to a char boundary, and charge that many bytes to the pool. A
/// spent pool grants nothing, even to an empty string.
fn grant<'a>(left: &mut usize, cap: usize, text: &'a str) -> Granted<'a> {
    if *left == 0 {
        return Granted::Nothing;
    }
    let allowed = cap.min(*left);
    if text.len() <= allowed {
        *left -= text.len();
        return Granted::Head {
            head: text,
            cut: false,
        };
    }
    let end = char_boundary_at_or_before(text, allowed);
    *left -= end;
    Granted::Head {
        head: &text[..end],
        cut: true,
    }
}

/// The largest index not above `index` (and not above the length) at which `text` may
/// be cut without splitting a character.
fn char_boundary_at_or_before(text: &str, index: usize) -> usize {
    let mut end = index.min(text.len());
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    end
}

impl Granted<'_> {
    /// The text a granted string is shown as: `…` when the pool was spent, otherwise
    /// `pass` over the examined start (with the `…` marker appended when text beyond it
    /// was dropped), kept within `limit` bytes ([`bounded_pass`]).
    fn render(self, limit: usize, pass: impl Fn(&str) -> String) -> String {
        match self {
            Granted::Nothing => ELLIPSIS.to_string(),
            Granted::Head { head, cut } => {
                let text = if cut {
                    with_marker(head)
                } else {
                    head.to_owned()
                };
                bounded_pass(&text, limit, pass)
            }
        }
    }
}

/// The examined start of a string that was cut, with the `…` marker appended. The
/// marker reaches the text pass, so a value the cut left unfinished (`password=abc` of
/// `password=abcdef`) is masked as an unquoted value that the marker ends.
fn with_marker(head: &str) -> String {
    let mut text = String::with_capacity(head.len() + ELLIPSIS.len_utf8());
    text.push_str(head);
    text.push(ELLIPSIS);
    text
}

/// `pass` over `text`, with the result kept within `limit` bytes as well: a mask can
/// lengthen text (`token=x ` becomes `token=[redacted] `), so a result that does not
/// fit is cut like an input and passed again, a few times at most, which makes a second
/// pass over the result leave it alone. If it still does not fit it is cut for good,
/// and a pass over that may read differently: a text that does not settle is returned
/// as the last round left it, as `scrub_strict` itself does after its `MAX_ROUNDS` rounds.
fn bounded_pass(text: &str, limit: usize, pass: impl Fn(&str) -> String) -> String {
    let mut text = pass(text);
    for _ in 0..OUTPUT_ROUNDS {
        if fits(&text, limit) {
            return text;
        }
        text = pass(&bound_text(&text, limit));
    }
    if fits(&text, limit) {
        text
    } else {
        bound_text(&text, limit)
    }
}

/// Whether `text` is within `limit` bytes, or is a cut one (`limit` bytes and the
/// marker): the form [`bound_text`] gives and a second pass leaves alone.
fn fits(text: &str, limit: usize) -> bool {
    text.len() <= limit || (text.len() <= limit + ELLIPSIS.len_utf8() && text.ends_with(ELLIPSIS))
}

/// `text` cut to at most `max_bytes` on a char boundary, with the `…` marker appended
/// only when something was cut.
fn bound_text(text: &str, max_bytes: usize) -> String {
    if text.len() <= max_bytes {
        return text.to_owned();
    }
    let end = char_boundary_at_or_before(text, max_bytes);
    with_marker(&text[..end])
}

/// Run `walk` one container level deeper, or replace the subtree when that passes
/// [`MAX_DEPTH`].
fn nested(budget: &mut Budget, walk: impl FnOnce(&mut Budget) -> Value) -> Value {
    if budget.depth >= MAX_DEPTH {
        return redacted();
    }
    budget.depth += 1;
    let out = walk(budget);
    budget.depth -= 1;
    out
}

// ---- the general walk ----------------------------------------------------------

/// Whether an argument key names a secret whose value must never be audited: the
/// strict vocabulary (so audit and findings redaction share one list, and the
/// audit adds its extra words), plus the reserved `_confirm` acknowledgment, which is
/// stripped before redaction already (belt and braces).
fn is_secret_key_audit(key: &str) -> bool {
    is_secret_key_strict(key) || key.to_ascii_lowercase().contains("_confirm")
}

/// The replacement for a hidden value.
fn redacted() -> Value {
    Value::from(KEY_REDACTED)
}

/// A string leaf: examined within the budget, then the strict text pass; `…` once
/// the budget is spent.
fn leaf(text: &str, budget: &mut Budget) -> Value {
    Value::String(budget.take(text).render(LEAF_EXAMINE_BYTES, scrub_strict))
}

/// The general walk: rule S and the secret-key rule over objects and arrays,
/// the strict text pass over strings, everything else cloned.
fn walk(value: &Value, budget: &mut Budget) -> Value {
    match value {
        Value::Object(map) => nested(budget, |b| Value::Object(walk_object(map, b))),
        Value::Array(items) => nested(budget, |b| Value::Array(walk_array(items, b))),
        Value::String(text) => leaf(text, budget),
        other => other.clone(),
    }
}

/// An object's members outside a header collection: the secret-key rule and rule S
/// decide which values are hidden, a member under a header-collection key opens one,
/// and the key text passes the strict text pass ([`plain_key_text`]).
fn walk_object(map: &Map<String, Value>, budget: &mut Budget) -> Map<String, Value> {
    let siblings = Siblings::of(map);
    map.iter()
        .map(|(key, val)| {
            // The key is charged before the value is walked, so a parent key is never
            // starved by the keys below it.
            let shown = plain_key_text(key, budget);
            let out = if siblings.hide(key) || is_secret_key_audit(key) {
                redacted()
            } else if is_header_collection_key(key) {
                walk_header_collection(val, budget)
            } else {
                walk(val, budget)
            };
            (shown, out)
        })
        .collect()
}

/// An array's elements. Rule S: exactly two strings whose first is a strict secret
/// key hide the second.
fn walk_array(items: &[Value], budget: &mut Budget) -> Vec<Value> {
    walk_array_with(items, budget, walk)
}

/// [`walk_array`] with `each` walking the elements (rule S is the same whichever
/// walk is used).
fn walk_array_with(
    items: &[Value],
    budget: &mut Budget,
    each: fn(&Value, &mut Budget) -> Value,
) -> Vec<Value> {
    if let [Value::String(name), Value::String(_)] = items {
        if is_secret_key_strict(name) {
            return vec![leaf(name, budget), redacted()];
        }
    }
    items.iter().map(|item| each(item, budget)).collect()
}

/// An object key outside a header collection as it is shown: its examined start
/// passes the strict text pass, so a credential used as a key is masked (`Bearer abc`,
/// `https://u:pw@host/`, a bare token); a key with no credential shape is unchanged.
/// Whether its value is hidden is decided on the original key.
fn plain_key_text(key: &str, budget: &mut Budget) -> String {
    budget
        .take_plain_key(key)
        .render(NAME_EXAMINE_BYTES, scrub_strict)
}

// ---- rule S --------------------------------------------------------------------

/// Whether `key` is one of `wanted`, ignoring ASCII case.
fn key_is(key: &str, wanted: &[&str]) -> bool {
    wanted.iter().any(|w| key.eq_ignore_ascii_case(w))
}

/// Whether `haystack` contains `needle` (non-empty, ASCII), ignoring ASCII case.
fn contains_ignore_ascii_case(haystack: &str, needle: &str) -> bool {
    haystack
        .as_bytes()
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle.as_bytes()))
}

/// Whether `text` ends with `suffix` (ASCII), ignoring ASCII case.
fn ends_with_ignore_ascii_case(text: &str, suffix: &str) -> bool {
    let bytes = text.as_bytes();
    bytes.len() >= suffix.len()
        && bytes[bytes.len() - suffix.len()..].eq_ignore_ascii_case(suffix.as_bytes())
}

/// Whether a sibling key holds the value of the thing a name sibling names: one of
/// [`SIBLING_VALUE_KEYS`], or any key that ends in `value` or `values`
/// (`cookie_value`, `header_values`).
fn is_value_key(key: &str) -> bool {
    key_is(key, &SIBLING_VALUE_KEYS)
        || ends_with_ignore_ascii_case(key, "value")
        || ends_with_ignore_ascii_case(key, "values")
}

/// Rule S's object form: which members of an object hold the secret that another
/// member names.
struct Siblings {
    /// A member among [`SIBLING_NAME_KEYS`] names a strict secret key: the value
    /// members hold its secret.
    secret_named: bool,
    /// A `header_name` member names a header that does not keep its value: the
    /// `header_value` member holds its value.
    header_named: bool,
}

impl Siblings {
    fn of(map: &Map<String, Value>) -> Siblings {
        Siblings {
            secret_named: map.iter().any(|(key, val)| {
                key_is(key, &SIBLING_NAME_KEYS) && val.as_str().is_some_and(is_secret_key_strict)
            }),
            header_named: map.iter().any(|(key, val)| {
                contains_ignore_ascii_case(key, "header_name")
                    && val.as_str().is_some_and(|name| !keeps_value_of(name))
            }),
        }
    }

    /// Whether the member `key` is one whose value is hidden.
    fn hide(&self, key: &str) -> bool {
        (self.secret_named && is_value_key(key))
            || (self.header_named && contains_ignore_ascii_case(key, "header_value"))
    }
}

// ---- rule D: header collections ------------------------------------------------

/// Where an array sits in a header collection.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ArrayValue {
    /// The array is the whole value of a header key (`"headers": [..]`).
    Whole,
    /// The array is one element of a collection array.
    Element,
}

/// Whether a key makes what is below it a header collection: its name contains
/// `header` or `hdr` (`headers`, `extra_headers`, `hdrs`, `req_hdrs`), or is
/// `trailer` or `trailers`, whatever the case.
fn is_header_collection_key(key: &str) -> bool {
    contains_ignore_ascii_case(key, "header")
        || contains_ignore_ascii_case(key, "hdr")
        || key.eq_ignore_ascii_case("trailer")
        || key.eq_ignore_ascii_case("trailers")
}

/// Whether a header name keeps its value under rule D: on the benign list and not
/// a strict secret key.
fn keeps_value_of(name: &str) -> bool {
    is_benign_header(name) && !is_secret_key_strict(name)
}

/// Whether every name member (`name`, `key`, `header`) of a header object is a
/// string that keeps its value. An object with a name member that is not a string
/// has no name to test, so its value is hidden.
fn header_name_is_benign(map: &Map<String, Value>) -> bool {
    map.iter()
        .filter(|(key, _)| key_is(key, &HEADER_NAME_KEYS))
        .all(|(_, val)| val.as_str().is_some_and(keeps_value_of))
}

/// Whether `map` is a header object: it has a name member (`name`, `key` or
/// `header`). Its other members, a `value` and a `values` list alike, belong to the
/// header that member names.
fn is_header_object(map: &Map<String, Value>) -> bool {
    map.keys().any(|key| key_is(key, &HEADER_NAME_KEYS))
}

/// Whether `byte` may appear in an HTTP header name (an RFC 9110 token character).
fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}

/// Whether `name` is a plausible header name: non-empty, token characters only (so
/// no blank and no `:`).
fn is_header_token(name: &str) -> bool {
    !name.is_empty() && name.bytes().all(is_token_byte)
}

/// A header collection (rule D): what sits under a header-collection key, and
/// everything below it (see [`is_header_collection_key`]).
///
/// An object is a header map ([`walk_header_map`]). An array holds header arrays
/// `[name, value, ..]`, header objects `{name, value, ..}`, plain maps, raw header
/// lines `"Name: value"` and further arrays ([`walk_header_array`]). A string is a
/// block of header text ([`header_block`]). A number, a boolean or a null stays.
fn walk_header_collection(value: &Value, budget: &mut Budget) -> Value {
    match value {
        Value::Object(map) => nested(budget, |b| Value::Object(walk_header_map(map, b))),
        Value::Array(items) => nested(budget, |b| walk_header_array(items, ArrayValue::Whole, b)),
        Value::String(text) => header_block(text, budget),
        other => other.clone(),
    }
}

/// One element of a header-collection array: an array ([`walk_header_array`]), an
/// object with a name member (a header object), any other object (a header map), a raw
/// header line ([`header_line`]); a number, a boolean or a null stays.
fn walk_header_entry(entry: &Value, budget: &mut Budget) -> Value {
    match entry {
        Value::Array(items) => nested(budget, |b| walk_header_array(items, ArrayValue::Element, b)),
        Value::Object(map) => nested(budget, |b| {
            Value::Object(if is_header_object(map) {
                walk_header_object(map, b)
            } else {
                walk_header_map(map, b)
            })
        }),
        Value::String(line) => header_line(line, budget),
        other => other.clone(),
    }
}

/// An array in a header collection. One that reads as a name and its values is a
/// header array: any array of two or more elements that is an element of a collection
/// array and starts with a string, and a whole-value array whose first element reads as
/// a name ([`reads_as_name_and_values`]). Any other is a list of entries, each read by
/// its shape.
fn walk_header_array(items: &[Value], array: ArrayValue, budget: &mut Budget) -> Value {
    match items {
        [Value::String(name), rest @ ..]
            if !rest.is_empty()
                && (array == ArrayValue::Element || reads_as_name_and_values(name)) =>
        {
            header_values(name, rest, array, budget)
        }
        _ => Value::Array(
            items
                .iter()
                .map(|item| walk_header_entry(item, budget))
                .collect(),
        ),
    }
}

/// Whether a whole-value header array, whose first element is the string `name`, is a
/// header name and its values, whatever its length: the first element holds no `:` once
/// the text pass has been over it (`["X-Debug", "v"]`, `["My Cookie", "a", "b"]`; a name
/// that is not a token is never benign, so every value is hidden). A first element with
/// a `:` is a line, and the array a list of lines.
///
/// The text pass decides, not the raw text: masking can remove the only colon (one
/// inside a quoted value or a private key block), and the array would read differently
/// the next time it is walked. Only the start of the name is examined, as it is shown.
fn reads_as_name_and_values(name: &str) -> bool {
    !scrub_strict_bounded(name, NAME_EXAMINE_BYTES).contains(':')
}

/// A map of headers: each member is a header, rule D by its key, and the key is a name
/// ([`key_text`]). A kept value is a scalar, a string or a list of them
/// ([`walk_kept`]); any other value is hidden.
fn walk_header_map(map: &Map<String, Value>, budget: &mut Budget) -> Map<String, Value> {
    map.iter()
        .map(|(name, val)| {
            let shown = key_text(name, budget);
            let out = if keeps_value_of(name) {
                walk_kept(val, budget)
            } else {
                redacted()
            };
            (shown, out)
        })
        .collect()
}

/// A header object, one with a name member: when no name member keeps its value, every
/// member other than the name members is hidden; otherwise they hold kept values. The
/// secret-key rule and rule S hide members as everywhere. The keys are names inside a
/// header collection ([`key_text`]).
fn walk_header_object(map: &Map<String, Value>, budget: &mut Budget) -> Map<String, Value> {
    let siblings = Siblings::of(map);
    let hide_members = !header_name_is_benign(map);
    map.iter()
        .map(|(key, val)| {
            let shown = key_text(key, budget);
            let is_name = key_is(key, &HEADER_NAME_KEYS);
            let out =
                if siblings.hide(key) || is_secret_key_audit(key) || (hide_members && !is_name) {
                    redacted()
                } else if is_name {
                    walk_name(val, budget)
                } else if is_header_collection_key(key) {
                    walk_header_collection(val, budget)
                } else {
                    walk_kept(val, budget)
                };
            (shown, out)
        })
        .collect()
}

/// The value of a header the name of which keeps its value: a string reads its later
/// lines as header lines ([`kept_value`]); a number, a boolean or a null stays; an
/// array is the multi-value form, each string element read the same way, rule S still
/// applying to a pair inside it, and a container inside it hidden; an object is hidden.
fn walk_kept(value: &Value, budget: &mut Budget) -> Value {
    match value {
        Value::String(text) => kept_value(text, budget),
        Value::Array(items) => Value::Array(walk_array_with(items, budget, walk_kept_scalar)),
        Value::Object(_) => redacted(),
        other => other.clone(),
    }
}

/// An element of a list of kept values: a string is read as a kept value, a number, a
/// boolean or a null stays, and an object or a list is hidden.
fn walk_kept_scalar(value: &Value, budget: &mut Budget) -> Value {
    match value {
        Value::String(text) => kept_value(text, budget),
        Value::Array(_) | Value::Object(_) => redacted(),
        other => other.clone(),
    }
}

/// A name member of a header object: a string is a name ([`name_string`]); anything
/// else keeps the header context ([`walk_header_collection`]).
fn walk_name(value: &Value, budget: &mut Budget) -> Value {
    match value {
        Value::String(text) => name_string(text, budget),
        other => walk_header_collection(other, budget),
    }
}

/// A header array `[name, value, ..]`: the name is a name ([`name_string`]), and rule D
/// decides **every** later element by it, whatever its type: kept (as a kept value)
/// for a name that keeps its value, replaced by `"<redacted>"` otherwise. In a
/// whole-value array a kept element that is a raw header line is judged as a line by
/// its name ([`is_header_line_text`]).
fn header_values(name: &str, rest: &[Value], array: ArrayValue, budget: &mut Budget) -> Value {
    let mut shown = vec![name_string(name, budget)];
    if keeps_value_of(name) {
        shown.extend(rest.iter().map(|value| match value {
            Value::String(text) if array == ArrayValue::Whole && is_header_line_text(text) => {
                header_line(text, budget)
            }
            other => walk_kept(other, budget),
        }));
    } else {
        shown.extend(rest.iter().map(|_| redacted()));
    }
    Value::Array(shown)
}

/// A name string inside a header collection (a pair name, a `name` member): cut at
/// [`NAME_EXAMINE_BYTES`] and charged to the leaf budget.
fn name_string(name: &str, budget: &mut Budget) -> Value {
    Value::String(name_text(budget.take_name(name)))
}

/// An object key inside a header collection: cut at [`NAME_EXAMINE_BYTES`] and charged
/// to the pool of its keys, which leaves the leaf budget alone.
fn key_text(key: &str, budget: &mut Budget) -> String {
    name_text(budget.take_key(key))
}

/// The text a name is shown as: its examined start with the header lines in it judged
/// by name and then the strict text pass, so a credential used as a name and a name
/// that carries a line break and a header line are masked. `…` once the pool is spent.
fn name_text(granted: Granted<'_>) -> String {
    granted.render(NAME_EXAMINE_BYTES, header_pass(FirstLine::Judged))
}

// ---- header text: raw lines, blocks, names -------------------------------------

/// How the first line of header text is read.
#[derive(Clone, Copy)]
enum FirstLine {
    /// Judged by its name like every other line: a block of header text.
    Judged,
    /// The value of a header the name of which keeps its value: left alone.
    Value,
}

/// How the name part of a `Name: value` line is read.
#[derive(Clone, Copy)]
enum NameShape {
    /// A header token only: a single descriptive line (`see the docs: https://x/`)
    /// stays prose.
    Token,
    /// Also any other non-empty name of at most [`NAME_EXAMINE_BYTES`] bytes with no
    /// line break (`X Debug`, `Xé`, `日本`). Such a name is never benign, so its value
    /// is hidden.
    Any,
}

/// The parts of a raw header line `Name: value`.
struct HeaderLine<'a> {
    /// Everything before the first `:`, as written (blanks included).
    name_part: &'a str,
    /// The name part with the blanks around it trimmed: what rule D looks up.
    name: &'a str,
    /// Everything after the first `:`.
    after_colon: &'a str,
    /// The line up to the start of the value (the colon and the blanks after it).
    prefix: &'a str,
    /// The rest of the line.
    value: &'a str,
}

impl HeaderLine<'_> {
    /// Whether the colon is followed by a blank or the end of the line: `X-Debug: v`
    /// and `X-Debug:` are, `https://x/` is not.
    fn blank_after_colon(&self) -> bool {
        self.after_colon.is_empty() || self.after_colon.starts_with([' ', '\t'])
    }
}

/// Split `line` at its first `:` when what comes before it is a name of the given
/// shape (blanks around it ignored): `None` for any other string. Under
/// [`NameShape::Any`] a header token of any length is a name too.
fn split_header_line(line: &str, shape: NameShape) -> Option<HeaderLine<'_>> {
    let colon = line.find(':')?;
    let name_part = &line[..colon];
    let name = name_part.trim_matches([' ', '\t']);
    let plausible = is_header_token(name)
        || (matches!(shape, NameShape::Any)
            && !name.is_empty()
            && name.len() <= NAME_EXAMINE_BYTES
            && !name.contains(['\r', '\n']));
    if !plausible {
        return None;
    }
    let after_colon = &line[colon + 1..];
    let value = after_colon.trim_start_matches([' ', '\t']);
    Some(HeaderLine {
        name_part,
        name,
        after_colon,
        prefix: &line[..line.len() - value.len()],
        value,
    })
}

/// A hidden header line: its name as written and the text-mask literal.
fn hidden_line(name_part: &str) -> String {
    format!("{name_part}: {TEXT_REDACTED}")
}

/// Whether `text` is a raw header line in a direct array: `name:` followed by a blank
/// or the end of the text, the name any non-empty one ([`NameShape::Any`]).
/// `https://x/` is not one (no blank after its colon); `X-Debug: v`, `X-Debug:` and
/// `X Debug: v` are.
fn is_header_line_text(text: &str) -> bool {
    split_header_line(text, NameShape::Any).is_some_and(|parts| parts.blank_after_colon())
}

/// A raw header line in a header collection: the line is examined within the
/// budget; when it is `Name: value` rule D decides the value by the name (kept, with
/// the lines after its first break judged by name and the text pass over it, or
/// `Name: [redacted]` for the whole line, the name passing the text pass too); any
/// other string is a block of header text.
fn header_line(line: &str, budget: &mut Budget) -> Value {
    let Granted::Head { head, cut } = budget.take(line) else {
        return Value::String(ELLIPSIS.to_string());
    };
    let Some(parts) = split_header_line(head, NameShape::Any) else {
        let block = Granted::Head { head, cut };
        return Value::String(block.render(LEAF_EXAMINE_BYTES, header_pass(FirstLine::Judged)));
    };
    Value::String(if keeps_value_of(parts.name) {
        // The line stays within the leaf bound as a whole: the prefix is part of it.
        let limit = LEAF_EXAMINE_BYTES.saturating_sub(parts.prefix.len());
        let value = Granted::Head {
            head: parts.value,
            cut,
        }
        .render(limit, header_pass(FirstLine::Value));
        format!("{}{value}", parts.prefix)
    } else {
        scrub_strict(&hidden_line(parts.name_part))
    })
}

/// The text pass over header text: the lines are judged by name first
/// ([`hide_header_lines`], with the first line read as `first` says), so a hidden line
/// takes the cut marker with its value and a kept line keeps it, and then the whole
/// text takes the strict text pass (so a private key block that has header lines inside
/// is still masked whole).
fn header_pass(first: FirstLine) -> impl Fn(&str) -> String {
    move |text| scrub_strict(&hide_header_lines(text, first))
}

/// Header text as a string leaf: examined within the budget, then [`header_pass`].
fn header_text(text: &str, first: FirstLine, budget: &mut Budget) -> Value {
    Value::String(
        budget
            .take(text)
            .render(LEAF_EXAMINE_BYTES, header_pass(first)),
    )
}

/// A block of header text: a string under a header-collection key, an element that is
/// not a `Name: value` line.
fn header_block(text: &str, budget: &mut Budget) -> Value {
    header_text(text, FirstLine::Judged, budget)
}

/// A KEPT header value: its first line is the value itself, the lines after its first
/// break are judged by name.
fn kept_value(text: &str, budget: &mut Budget) -> Value {
    header_text(text, FirstLine::Value, budget)
}

/// `text` split at every line break (`\r\n`, `\r` or `\n`): each line with the break
/// that ended it, and `""` for the last line, so joining every pair gives `text`.
fn split_lines(text: &str) -> Vec<(&str, &str)> {
    let bytes = text.as_bytes();
    let mut lines = Vec::new();
    let mut start = 0;
    let mut at = 0;
    while at < bytes.len() {
        if matches!(bytes[at], b'\r' | b'\n') {
            let end = if bytes[at] == b'\r' && bytes.get(at + 1) == Some(&b'\n') {
                at + 2
            } else {
                at + 1
            };
            lines.push((&text[start..at], &text[at..end]));
            start = end;
            at = end;
        } else {
            at += 1;
        }
    }
    lines.push((&text[start..], ""));
    lines
}

/// Rule D over the lines of `text`: a line `Name: value` whose name does not keep its
/// value becomes `Name: [redacted]`, and a line folded onto it (one that starts with a
/// blank) goes with it, break included; every other line stays, and so does every line
/// break. With line breaks in `text` any non-empty name makes a line
/// ([`NameShape::Any`]); a single line takes a header token only ([`NameShape::Token`]),
/// so a descriptive string stays prose. With [`FirstLine::Value`] the first line is
/// left alone (it is the value of a header the name of which keeps its value).
fn hide_header_lines(text: &str, first: FirstLine) -> String {
    let lines = split_lines(text);
    let shape = if lines.len() > 1 {
        NameShape::Any
    } else {
        NameShape::Token
    };
    let mut out = String::with_capacity(text.len());
    let mut after_hidden = false;
    for (index, (line, line_break)) in lines.into_iter().enumerate() {
        if index == 0 && matches!(first, FirstLine::Value) {
            out.push_str(line);
            out.push_str(line_break);
            continue;
        }
        if after_hidden && line.starts_with([' ', '\t']) {
            continue;
        }
        after_hidden = false;
        match split_header_line(line, shape) {
            Some(parts) if !keeps_value_of(parts.name) => {
                out.push_str(&hidden_line(parts.name_part));
                after_hidden = true;
            }
            _ => out.push_str(line),
        }
        out.push_str(line_break);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// A made-up secret: never a real credential.
    const CANARY: &str = "CNRYx5eed0000";

    /// Collect every row whose output differs from its expectation into one
    /// assertion message, so a single run names every wrong row.
    fn check(rows: Vec<(&str, Value, Value)>) {
        let failures: Vec<String> = rows
            .into_iter()
            .filter_map(|(label, input, expected)| {
                let got = redact_value(&input);
                (got != expected)
                    .then(|| format!("{label}: input {input}, expected {expected}, got {got}"))
            })
            .collect();
        assert!(
            failures.is_empty(),
            "{} row(s) wrong:\n{}",
            failures.len(),
            failures.join("\n")
        );
    }

    /// The reserved `_confirm` acknowledgment is hidden by key, in any case and
    /// wherever it sits in the key.
    #[test]
    fn confirm_keys_are_redacted_by_the_audit_vocabulary() {
        check(vec![
            (
                "_confirm",
                json!({"_confirm": CANARY, "note": "n"}),
                json!({"_confirm": "<redacted>", "note": "n"}),
            ),
            (
                "contains _confirm, any case",
                json!({"x_Confirm_token_id": CANARY}),
                json!({"x_Confirm_token_id": KEY_REDACTED}),
            ),
        ]);
    }

    /// The secret-key rule uses the strict vocabulary at any depth, whatever the
    /// type of the value it hides.
    #[test]
    fn secret_named_keys_hide_their_value_whatever_its_type() {
        check(vec![
            (
                "string",
                json!({"a": {"passphrase": CANARY}}),
                json!({"a": {"passphrase": KEY_REDACTED}}),
            ),
            (
                "object",
                json!({"token": {"inner": CANARY}}),
                json!({"token": KEY_REDACTED}),
            ),
            (
                "number",
                json!({"otp": 123456}),
                json!({"otp": KEY_REDACTED}),
            ),
            (
                "look-alike key stays",
                json!({"author": "bob", "bypass": 1}),
                json!({"author": "bob", "bypass": 1}),
            ),
        ]);
    }

    /// Rule D keeps a value only for a benign name that is not a strict secret key,
    /// whatever the value's type, and the name test is case-insensitive.
    #[test]
    fn rule_d_decides_by_the_name_and_keeps_names_visible() {
        check(vec![
            (
                "a benign name keeps a number",
                json!({"headers": {"Content-Length": 5}}),
                json!({"headers": {"Content-Length": 5}}),
            ),
            (
                "a non-benign name hides an object",
                json!({"headers": {"X-Obj": {"k": CANARY}}}),
                json!({"headers": {"X-Obj": KEY_REDACTED}}),
            ),
            (
                "a non-benign name hides a null",
                json!({"headers": {"X-Null": null}}),
                json!({"headers": {"X-Null": KEY_REDACTED}}),
            ),
            (
                "a benign prefix that is a strict secret key is hidden",
                json!({"headers": {"Sec-Ch-Pass": CANARY, "Sec-Ch-Ua": "ua"}}),
                json!({"headers": {"Sec-Ch-Pass": KEY_REDACTED, "Sec-Ch-Ua": "ua"}}),
            ),
            (
                "collection keys and names are case-insensitive",
                json!({"REQUEST_Headers": {"HOST": "h.test", "x-zed": CANARY}}),
                json!({"REQUEST_Headers": {"HOST": "h.test", "x-zed": KEY_REDACTED}}),
            ),
            (
                "every collection key",
                json!({
                    "header": {"X-A": "a"},
                    "request_headers": {"X-A": "a"},
                    "response_headers": {"X-A": "a"},
                    "req_headers": {"X-A": "a"},
                    "resp_headers": {"X-A": "a"},
                    "http_headers": {"X-A": "a"},
                }),
                json!({
                    "header": {"X-A": KEY_REDACTED},
                    "request_headers": {"X-A": KEY_REDACTED},
                    "response_headers": {"X-A": KEY_REDACTED},
                    "req_headers": {"X-A": KEY_REDACTED},
                    "resp_headers": {"X-A": KEY_REDACTED},
                    "http_headers": {"X-A": KEY_REDACTED},
                }),
            ),
            (
                "a header string of raw lines takes the text pass",
                json!({"headers": "Cookie: a=b; z=c\r\nHost: x"}),
                json!({"headers": "Cookie: [redacted]\r\nHost: x"}),
            ),
        ]);
    }

    /// A header collection array: pairs and header objects (name member `name`,
    /// `key` or `header`) get rule D, per element; any other element takes the
    /// general walk. An object whose name member is not a string has no name to
    /// test, so its value is hidden.
    #[test]
    fn rule_d_in_arrays_is_per_element() {
        check(vec![
            (
                "key and header name members",
                json!({"headers": [
                    {"key": "X-Zed", "value": "z"},
                    {"header": "Host", "value": "h.test"},
                    {"name": "Accept", "value": 7},
                ]}),
                json!({"headers": [
                    {"key": "X-Zed", "value": KEY_REDACTED},
                    {"header": "Host", "value": "h.test"},
                    {"name": "Accept", "value": 7},
                ]}),
            ),
            (
                "a name member that is not a string",
                json!({"headers": [{"name": 5, "value": "c"}]}),
                json!({"headers": [{"name": 5, "value": KEY_REDACTED}]}),
            ),
            (
                "two name members must both be benign",
                json!({"headers": [{"name": "Accept", "key": "X-Zed", "value": "c"}]}),
                json!({"headers": [{"name": "Accept", "key": "X-Zed", "value": KEY_REDACTED}]}),
            ),
            (
                "a kept value takes the text pass, other members the general walk",
                json!({"headers": [
                    {"name": "Referer", "value": "https://x.test/?token=c", "note": "a"},
                ]}),
                json!({"headers": [
                    {"name": "Referer", "value": "https://x.test/?token=[redacted]", "note": "a"},
                ]}),
            ),
            // An object element with no name member is a header map: rule D applies to
            // its members by key, so `{"anything": "else"}` is hidden.
            (
                "an object with no name member is a header map, the rest by shape",
                json!({"headers": [
                    ["X-Zed", "z"],
                    "Cookie: a=b",
                    ["Accept", "t", "extra"],
                    {"anything": "else"},
                ]}),
                json!({"headers": [
                    ["X-Zed", KEY_REDACTED],
                    "Cookie: [redacted]",
                    ["Accept", "t", "extra"],
                    {"anything": KEY_REDACTED},
                ]}),
            ),
        ]);
    }

    /// Rule S: a two-string array with a secret first element hides the second; a
    /// name/value object hides its value members, of any type; the sibling keys
    /// are matched ignoring case; names and other members stay.
    #[test]
    fn rule_s_hides_the_second_element_and_the_sibling_values() {
        check(vec![
            (
                "a pair outside any header key",
                json!({"jar": [["session", CANARY], ["theme", "dark"]]}),
                json!({"jar": [["session", KEY_REDACTED], ["theme", "dark"]]}),
            ),
            (
                "not exactly two strings is not a pair",
                json!({"x": [["Cookie", "a", "b"], ["Cookie", 5]]}),
                json!({"x": [["Cookie", "a", "b"], ["Cookie", 5]]}),
            ),
            (
                "every sibling value key, any type",
                json!({
                    "label": "api_token",
                    "value": {"deep": CANARY},
                    "val": 1,
                    "text": CANARY,
                    "data": [CANARY],
                    "content": true,
                    "input": null,
                    "keys": CANARY,
                    "string": CANARY,
                    "note": "kept",
                }),
                json!({
                    "label": "api_token",
                    "value": KEY_REDACTED,
                    "val": KEY_REDACTED,
                    "text": KEY_REDACTED,
                    "data": KEY_REDACTED,
                    "content": KEY_REDACTED,
                    "input": KEY_REDACTED,
                    "keys": KEY_REDACTED,
                    "string": KEY_REDACTED,
                    "note": "kept",
                }),
            ),
            (
                "field and key name members",
                json!([
                    {"field": "password", "value": CANARY},
                    {"key": "pw", "value": CANARY},
                ]),
                json!([
                    {"field": "password", "value": KEY_REDACTED},
                    {"key": "pw", "value": KEY_REDACTED},
                ]),
            ),
            (
                "sibling keys match ignoring case",
                json!({"Selector": "#password", "Text": CANARY}),
                json!({"Selector": "#password", "Text": KEY_REDACTED}),
            ),
            (
                "a non-secret name hides nothing",
                json!({"name": "color", "value": "blue", "text": "t"}),
                json!({"name": "color", "value": "blue", "text": "t"}),
            ),
        ]);
    }

    /// Assert `redact_value` is a fixed point on each input (a second pass over its
    /// own output changes nothing), collecting every failing row. Every row must
    /// also be one the redaction changes: an input it leaves alone is trivially a
    /// fixed point and would prove nothing (a deleted function body would pass).
    fn check_fixed_points(rows: Vec<(&str, Value)>) {
        let failures: Vec<String> = rows
            .into_iter()
            .filter_map(|(label, input)| {
                let once = redact_value(&input);
                if once == input {
                    return Some(format!("{label}: redaction changed nothing"));
                }
                let twice = redact_value(&once);
                (once != twice).then(|| format!("{label}: once {once}, twice {twice}"))
            })
            .collect();
        assert!(
            failures.is_empty(),
            "{} row(s) not idempotent:\n{}",
            failures.len(),
            failures.join("\n")
        );
    }

    // ---- the bounded traversal (Design 14.6 of the durable audit spec)

    /// The single character that stands for text the bound dropped.
    const CUT: &str = "…";

    /// A leaf longer than 4096 bytes is shown as its first 4096 bytes and `…`.
    #[test]
    fn a_leaf_beyond_4096_bytes_is_cut_with_an_ellipsis() {
        let got = redact_value(&json!({"a": "x".repeat(5000)}));
        assert_eq!(got, json!({"a": format!("{}{CUT}", "x".repeat(4096))}));
    }

    /// The leaf bound is exact (4096 whole, 4097 cut) and the cut moves back to a
    /// char boundary instead of splitting a character.
    #[test]
    fn the_leaf_bound_is_exact_and_lands_on_a_char_boundary() {
        check(vec![
            (
                "exactly 4096 bytes",
                json!("y".repeat(4096)),
                json!("y".repeat(4096)),
            ),
            (
                "4097 bytes",
                json!("y".repeat(4097)),
                json!(format!("{}{CUT}", "y".repeat(4096))),
            ),
            // `€` is three bytes and 4096 = 1365 * 3 + 1, so the cut moves back to 4095.
            (
                "a three-byte character straddles the bound",
                json!("€".repeat(2000)),
                json!(format!("{}{CUT}", "€".repeat(1365))),
            ),
        ]);
    }

    /// Once 64 KiB of text has been examined, every later string leaf is `…`.
    #[test]
    fn after_64_kib_every_later_leaf_is_an_ellipsis() {
        let full = "a".repeat(4096);
        let got = redact_value(&Value::Array(vec![Value::from(full.clone()); 20]));
        let mut expected = vec![Value::from(full); 16];
        expected.extend(vec![Value::from(CUT); 4]);
        assert_eq!(got, Value::Array(expected));
    }

    /// The total budget is shared: the leaf that crosses it is examined only up to
    /// what is left, and the leaf after that is `…`.
    #[test]
    fn the_total_budget_cuts_the_leaf_that_crosses_it() {
        // 15 whole leaves spend 61440 bytes and leave 4096.
        let mut input = vec![json!("a".repeat(4096)); 15];
        input.push(json!("b".repeat(3000))); // examined whole, 1096 left
        input.push(json!("c".repeat(3000))); // 1096 examined, then `…`
        input.push(json!("d")); // the budget is spent
        let mut expected = vec![json!("a".repeat(4096)); 15];
        expected.push(json!("b".repeat(3000)));
        expected.push(json!(format!("{}{CUT}", "c".repeat(1096))));
        expected.push(json!(CUT));
        assert_eq!(redact_value(&Value::Array(input)), Value::Array(expected));
    }

    /// Numbers, booleans, nulls, object keys (cut at 256 bytes, charged to pools of
    /// their own) and values this module hides cost the leaf budget nothing: 100 KiB
    /// of each ahead of them, and 16 whole 4096-byte leaves still fit exactly.
    /// (Hidden values are not examined; a value that cost anything would cut the
    /// sixteenth leaf.)
    #[test]
    fn numbers_names_and_hidden_values_cost_nothing() {
        let big = "z".repeat(100_000);
        let long_key = "k".repeat(70_000);
        let shown_key = format!("{}{CUT}", "k".repeat(256));
        let input = json!({
            "token": big,
            "headers": {"X-Zed": big, "X-Zip": big},
            "numbers": vec![7; 100_000],
            "flags": [true, false, null],
            long_key.clone(): 1,
            "leaves": vec!["a".repeat(4096); 16],
        });
        let expected = json!({
            "token": KEY_REDACTED,
            "headers": {"X-Zed": KEY_REDACTED, "X-Zip": KEY_REDACTED},
            "numbers": vec![7; 100_000],
            "flags": [true, false, null],
            shown_key: 1,
            "leaves": vec!["a".repeat(4096); 16],
        });
        assert_eq!(redact_value(&input), expected);
    }

    /// A value the bound cuts is masked as an unquoted value (the marker ends it),
    /// so a secret cut in half is hidden whole; one that starts past the bound is
    /// simply not there.
    #[test]
    fn a_value_cut_by_the_bound_is_masked_as_an_unquoted_value() {
        let lead = "a".repeat(3999);
        check(vec![
            (
                "the key starts at character 4000 and its value runs past the bound",
                json!({"a": format!("{lead} password={}", CANARY.repeat(20))}),
                json!({"a": format!("{lead} password=[redacted]")}),
            ),
            (
                "the secret starts at character 4100",
                json!({"a": format!("{} password={CANARY}", "a".repeat(4099))}),
                json!({"a": format!("{}{CUT}", "a".repeat(4096))}),
            ),
        ]);
    }

    /// Bounded outputs are fixed points too: the cut leaf, the ellipsis leaves, a
    /// masked cut secret and a multibyte cut survive a second pass unchanged.
    #[test]
    fn a_bounded_result_is_a_fixed_point() {
        let mut crossing = vec![json!("a".repeat(4096)); 15];
        crossing.push(json!("c".repeat(6000)));
        crossing.push(json!("d"));
        check_fixed_points(vec![
            ("one long leaf", json!({"a": "x".repeat(5000)})),
            (
                "a cut secret",
                json!({"a": format!("{} password={}", "a".repeat(3999), CANARY.repeat(20))}),
            ),
            (
                "twenty full leaves",
                Value::Array(vec![json!("a".repeat(4096)); 20]),
            ),
            ("a leaf cut by the budget", Value::Array(crossing)),
            ("a multibyte cut", json!("€".repeat(2000))),
        ]);
    }

    // ---- header shapes beyond rule D's two forms

    /// A two-element array whose first element is a string is a header pair under a
    /// header-collection key, whatever the type of its second element: rule D
    /// decides by the name. Outside a header key the shape is the general walk.
    #[test]
    fn a_header_pair_takes_rule_d_whatever_its_value_type() {
        check(vec![
            (
                "a number under a non-benign name",
                json!({"headers": [["X-N", 5]]}),
                json!({"headers": [["X-N", KEY_REDACTED]]}),
            ),
            (
                "null, bool, array and object under non-benign names",
                json!({"headers": [
                    ["X-Null", null],
                    ["X-Bool", true],
                    ["X-Arr", [CANARY]],
                    ["X-Obj", {"k": CANARY}],
                ]}),
                json!({"headers": [
                    ["X-Null", KEY_REDACTED],
                    ["X-Bool", KEY_REDACTED],
                    ["X-Arr", KEY_REDACTED],
                    ["X-Obj", KEY_REDACTED],
                ]}),
            ),
            (
                "a benign name keeps a non-string value",
                json!({"headers": [["Content-Length", 5], ["Accept", ["text/html"]]]}),
                json!({"headers": [["Content-Length", 5], ["Accept", ["text/html"]]]}),
            ),
            (
                "a kept string takes the text pass",
                json!({"headers": [["Referer", "https://x.test/?token=c"]]}),
                json!({"headers": [["Referer", "https://x.test/?token=[redacted]"]]}),
            ),
            (
                "a strict secret name hides any type, and so does a benign prefix that is one",
                json!({"headers": [["Authorization", 5], ["Sec-Ch-Pass", 6]]}),
                json!({"headers": [["Authorization", KEY_REDACTED], ["Sec-Ch-Pass", KEY_REDACTED]]}),
            ),
            (
                "a first element that is not a header token is still a name: its text is passed",
                json!({"headers": [["Cookie: a=b", 5]]}),
                json!({"headers": [["Cookie: [redacted]", KEY_REDACTED]]}),
            ),
            (
                "at any depth under the key",
                json!({"a": {"request_headers": [["X-Zed", 1]]}}),
                json!({"a": {"request_headers": [["X-Zed", KEY_REDACTED]]}}),
            ),
            (
                "the pair is the value of the key itself",
                json!({"headers": ["X-Debug", CANARY]}),
                json!({"headers": ["X-Debug", KEY_REDACTED]}),
            ),
            (
                "the pair is the value of the key itself, a number",
                json!({"headers": ["X-N", 5]}),
                json!({"headers": ["X-N", KEY_REDACTED]}),
            ),
            (
                "the pair is the value of the key itself, a benign name",
                json!({"headers": ["Accept", "text/html"]}),
                json!({"headers": ["Accept", "text/html"]}),
            ),
            (
                "outside a header key it is the general walk",
                json!({"x": [["X-N", 5], ["X-Zed", "plain"]]}),
                json!({"x": [["X-N", 5], ["X-Zed", "plain"]]}),
            ),
        ]);
    }

    /// An array of `Name: value` strings under a header-collection key is a header
    /// collection: each line takes rule D by its name (a hidden value reads
    /// `[redacted]`, the text-mask literal a line already carries); a string with no
    /// header name keeps the general text pass.
    #[test]
    fn raw_header_lines_in_a_collection_take_rule_d_by_name() {
        let c = CANARY;
        check(vec![
            (
                "benign lines survive, the rest are hidden",
                json!({"headers": [
                    "Host: example.com",
                    "Accept: text/html",
                    format!("X-Debug: {c}"),
                    format!("Cookie: a={c}; c=d"),
                    "Authorization: Basic Zm9v",
                ]}),
                json!({"headers": [
                    "Host: example.com",
                    "Accept: text/html",
                    "X-Debug: [redacted]",
                    "Cookie: [redacted]",
                    "Authorization: [redacted]",
                ]}),
            ),
            (
                "a kept value takes the text pass",
                json!({"headers": ["Referer: https://x.test/cb?token=c"]}),
                json!({"headers": ["Referer: https://x.test/cb?token=[redacted]"]}),
            ),
            (
                "no blank after the colon, any case",
                json!({"headers": ["HOST:h.test", "cookie:a=b"]}),
                json!({"headers": ["HOST:h.test", "cookie: [redacted]"]}),
            ),
            (
                "blanks around the name do not hide it",
                json!({"headers": ["X-Debug : c", " X-Zed: c"]}),
                json!({"headers": ["X-Debug : [redacted]", " X-Zed: [redacted]"]}),
            ),
            (
                "an empty value is hidden too",
                json!({"headers": ["X-Debug:"]}),
                json!({"headers": ["X-Debug: [redacted]"]}),
            ),
            (
                "a multi-line value is hidden whole",
                json!({"headers": [format!("X-Debug: a\r\nCookie: {c}")]}),
                json!({"headers": ["X-Debug: [redacted]"]}),
            ),
            (
                "a benign prefix that is a strict secret key is hidden",
                json!({"headers": ["Sec-Ch-Pass: c", "Sec-Ch-Ua: ua"]}),
                json!({"headers": ["Sec-Ch-Pass: [redacted]", "Sec-Ch-Ua: ua"]}),
            ),
            (
                "a string with no header name keeps the general text pass",
                json!({"headers": [
                    ": no name",
                    "just prose",
                    "",
                    format!("set the password={c} now"),
                ]}),
                json!({"headers": [
                    ": no name",
                    "just prose",
                    "",
                    "set the password=[redacted] now",
                ]}),
            ),
            (
                "a prose line whose first word is a valid header name is a header line",
                json!({"headers": ["note: Authorization: Bearer abc"]}),
                json!({"headers": ["note: [redacted]"]}),
            ),
            (
                "mixed elements each take their own shape",
                json!({"headers": [
                    "X-Debug: c",
                    ["X-Zed", "z"],
                    {"name": "X-A", "value": "v"},
                    5,
                ]}),
                json!({"headers": [
                    "X-Debug: [redacted]",
                    ["X-Zed", KEY_REDACTED],
                    {"name": "X-A", "value": KEY_REDACTED},
                    5,
                ]}),
            ),
            (
                "two lines are lines, not a header pair",
                json!({"headers": ["Cookie: a=b", "X-Debug: c"]}),
                json!({"headers": ["Cookie: [redacted]", "X-Debug: [redacted]"]}),
            ),
            (
                "outside a header key a string is prose",
                json!({"x": ["X-Debug: plain"]}),
                json!({"x": ["X-Debug: plain"]}),
            ),
        ]);
    }

    /// A header object whose name is not benign keeps its name members and nothing
    /// else: the `value`, a `values` list and any other member read `<redacted>`.
    /// A benign name keeps the object's members under the general walk.
    #[test]
    fn a_header_object_under_a_hidden_name_hides_every_member_but_its_names() {
        let c = CANARY;
        check(vec![
            (
                "a values list beside the value",
                json!({"headers": [{"name": "X-Debug", "value": c, "values": [c, "b"]}]}),
                json!({"headers": [{
                    "name": "X-Debug", "value": KEY_REDACTED, "values": KEY_REDACTED,
                }]}),
            ),
            (
                "a values list and no value",
                json!({"headers": [{"name": "Set-Cookie", "values": [c]}]}),
                json!({"headers": [{"name": "Set-Cookie", "values": KEY_REDACTED}]}),
            ),
            (
                "any other member, whatever its type",
                json!({"headers": [{
                    "name": "X-Zed", "value": "z", "comment": "n", "meta": {"k": "v"},
                }]}),
                json!({"headers": [{
                    "name": "X-Zed", "value": KEY_REDACTED,
                    "comment": KEY_REDACTED, "meta": KEY_REDACTED,
                }]}),
            ),
            (
                "a strict secret name",
                json!({"headers": [{"name": "Authorization", "value": c, "values": [c]}]}),
                json!({"headers": [{
                    "name": "Authorization", "value": KEY_REDACTED, "values": KEY_REDACTED,
                }]}),
            ),
            (
                "both name members stay, every other member is hidden",
                json!({"headers": [{"name": "Accept", "key": "X-Zed", "value": "c", "extra": "e"}]}),
                json!({"headers": [{
                    "name": "Accept", "key": "X-Zed", "value": KEY_REDACTED, "extra": KEY_REDACTED,
                }]}),
            ),
            (
                "a header member names the header",
                json!({"headers": [{"header": "X-Zed", "value": "z", "values": ["v"]}]}),
                json!({"headers": [{
                    "header": "X-Zed", "value": KEY_REDACTED, "values": KEY_REDACTED,
                }]}),
            ),
            (
                "a name that is not a string has no name to test",
                json!({"headers": [{"name": 5, "value": "c", "extra": "e"}]}),
                json!({"headers": [{"name": 5, "value": KEY_REDACTED, "extra": KEY_REDACTED}]}),
            ),
            (
                "a benign name keeps the value and walks the other members",
                json!({"headers": [{"name": "Host", "value": "h.test", "values": ["a=b"]}]}),
                json!({"headers": [{"name": "Host", "value": "h.test", "values": ["a=b"]}]}),
            ),
            (
                "outside a header key the object is a plain one",
                json!({"x": [{"name": "X-Zed", "value": "z", "values": ["v"]}]}),
                json!({"x": [{"name": "X-Zed", "value": "z", "values": ["v"]}]}),
            ),
        ]);
    }

    /// The new header shapes are fixed points: a hidden value reads the same when
    /// the output is redacted again.
    #[test]
    fn the_header_shapes_are_fixed_points() {
        check_fixed_points(vec![
            (
                "pairs",
                json!({"headers": [["X-N", 5], ["Accept", ["text/html"]], ["Cookie", "a=b"]]}),
            ),
            ("direct pair", json!({"headers": ["X-Debug", CANARY]})),
            (
                "lines",
                json!({"headers": [
                    "Host: example.com", "X-Debug : c", "X-Debug:", "Cookie:a=b",
                    "Referer: https://x.test/cb?token=c",
                ]}),
            ),
            (
                "objects",
                json!({"headers": [
                    {"name": "X-Debug", "value": "c", "values": ["a"]},
                    {"name": 5, "value": "c", "extra": "e"},
                ]}),
            ),
        ]);
    }

    // ---- header text with line breaks, multi-value arrays, kept values

    /// A string under a header-collection key is a block of header lines: each line
    /// is judged by its name (rule D) and the line breaks stay as they were. A string
    /// with no line break and no header-shaped name keeps the text pass.
    fn header_block_rows() -> Vec<(&'static str, Value, Value)> {
        let c = CANARY;
        let token = format!("ghp_{c}{}", "a".repeat(30));
        vec![
            (
                "CRLF lines: a hidden one and a benign one",
                json!({"headers": format!("X-Debug: {c}\r\nHost: x")}),
                json!({"headers": "X-Debug: [redacted]\r\nHost: x"}),
            ),
            (
                "bare LF",
                json!({"headers": format!("X-Debug: {c}\nHost: x\nAccept: a")}),
                json!({"headers": "X-Debug: [redacted]\nHost: x\nAccept: a"}),
            ),
            (
                "bare CR",
                json!({"headers": format!("X-Debug: {c}\rHost: x")}),
                json!({"headers": "X-Debug: [redacted]\rHost: x"}),
            ),
            (
                "every break stays as written, the trailing one too",
                json!({"headers": "A-B: c\r\nHost: x\nX-Zed: z\rAccept: a\r\n"}),
                json!({"headers": "A-B: [redacted]\r\nHost: x\nX-Zed: [redacted]\rAccept: a\r\n"}),
            ),
            (
                "a request line, headers and a body",
                json!({"headers": format!("GET / HTTP/1.1\r\nHost: x\r\nX-Debug: {c}\r\n\r\nbody=1")}),
                json!({"headers": "GET / HTTP/1.1\r\nHost: x\r\nX-Debug: [redacted]\r\n\r\nbody=1"}),
            ),
            (
                "a folded continuation goes with the hidden header it continues",
                json!({"headers": format!("X-Debug: a\r\n  {c}\r\n\tmore\r\nHost: x")}),
                json!({"headers": "X-Debug: [redacted]\r\nHost: x"}),
            ),
            (
                "a folded continuation of a benign header stays with it",
                json!({"headers": "Host: x\r\n  continued\r\nX-Debug: c"}),
                json!({"headers": "Host: x\r\n  continued\r\nX-Debug: [redacted]"}),
            ),
            (
                "a single hidden header line",
                json!({"headers": "X-Debug: c"}),
                json!({"headers": "X-Debug: [redacted]"}),
            ),
            (
                "a single benign header line stays",
                json!({"headers": "Host: x"}),
                json!({"headers": "Host: x"}),
            ),
            (
                "an element with a name that has blanks is a line, prose with no colon keeps the text pass",
                json!({"headers": ["see the docs: https://x.test/", format!("set the password={c} now")]}),
                json!({"headers": ["see the docs: [redacted]", "set the password=[redacted] now"]}),
            ),
            (
                "a string that is only prose keeps today's text pass",
                json!({"headers": format!("set the password={c} now")}),
                json!({"headers": "set the password=[redacted] now"}),
            ),
            (
                "a private key block with header lines inside is masked whole",
                json!({"headers": format!(
                    "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,{c}\n\nBODY{c}\n-----END RSA PRIVATE KEY-----"
                )}),
                json!({"headers": "[redacted]"}),
            ),
            (
                "text beyond the bound is dropped with the hidden line it was in",
                json!({"headers": format!("X-Debug: {}", "s".repeat(5000))}),
                json!({"headers": "X-Debug: [redacted]"}),
            ),
            (
                "a benign line cut by the bound keeps its start and the marker",
                json!({"headers": format!("Host: {}", "h".repeat(5000))}),
                json!({"headers": format!("Host: {}{CUT}", "h".repeat(4090))}),
            ),
            (
                "a block line whose name is itself a credential is masked",
                json!({"headers": format!("{token}: v\r\nHost: x")}),
                json!({"headers": "[redacted]: [redacted]\r\nHost: x"}),
            ),
            (
                "outside a header key a string is prose",
                json!({"x": "X-Debug: plain\r\nHost: x"}),
                json!({"x": "X-Debug: plain\r\nHost: x"}),
            ),
        ]
    }

    #[test]
    fn a_header_string_with_line_breaks_is_judged_line_by_line() {
        check(header_block_rows());
    }

    /// A header-array element of three or more items whose first element is a string
    /// takes rule D by that name over ALL the rest.
    fn multi_value_rows() -> Vec<(&'static str, Value, Value)> {
        let r = KEY_REDACTED;
        vec![
            (
                "a hidden name hides every later element",
                json!({"headers": [["X-Zed", "a", "b"]]}),
                json!({"headers": [["X-Zed", r, r]]}),
            ),
            (
                "a strict secret name, four items",
                json!({"headers": [["Authorization", "a", "b", "c"]]}),
                json!({"headers": [["Authorization", r, r, r]]}),
            ),
            (
                "a benign name keeps them (the pinned shape)",
                json!({"headers": [["Accept", "t", "extra"]]}),
                json!({"headers": [["Accept", "t", "extra"]]}),
            ),
            (
                "kept strings take the text pass and other types stay",
                json!({"headers": [["Referer", "https://x.test/?token=c", "b", 5, null]]}),
                json!({"headers": [["Referer", "https://x.test/?token=[redacted]", "b", 5, null]]}),
            ),
            (
                "a hidden name hides every type",
                json!({"headers": [["X-Zed", 5, null, true, ["a"], {"k": "v"}]]}),
                json!({"headers": [["X-Zed", r, r, r, r, r]]}),
            ),
            (
                "a benign prefix that is a strict secret key is hidden",
                json!({"headers": [["Sec-Ch-Pass", "a", "b"]]}),
                json!({"headers": [["Sec-Ch-Pass", r, r]]}),
            ),
            (
                "a first element that is not a string, or one item, is the general walk",
                json!({"headers": [[5, "a", "b"], ["X-Zed"], []]}),
                json!({"headers": [[5, "a", "b"], ["X-Zed"], []]}),
            ),
            (
                "the array is the value of the key itself",
                json!({"headers": ["X-Zed", "a", "b"]}),
                json!({"headers": ["X-Zed", r, r]}),
            ),
            (
                "the array is the value of the key itself, a benign name",
                json!({"headers": ["Accept", "a", "b"]}),
                json!({"headers": ["Accept", "a", "b"]}),
            ),
            // Accepted over-redaction, the strict direction: a bare list of two header
            // names is read as a name and its value, so the second name is hidden.
            (
                "a bare list of two names reads as a pair",
                json!({"headers": ["X-A", "X-B"]}),
                json!({"headers": ["X-A", r]}),
            ),
            (
                "outside a header key it is the general walk",
                json!({"x": [["X-Zed", "a", "b"]]}),
                json!({"x": [["X-Zed", "a", "b"]]}),
            ),
        ]
    }

    #[test]
    fn a_header_array_with_three_or_more_items_takes_rule_d_by_its_first_element() {
        check(multi_value_rows());
    }

    /// A KEPT header value with a line break in it: the part after the first break
    /// is a block of header lines judged by name.
    fn kept_value_rows() -> Vec<(&'static str, Value, Value)> {
        let c = CANARY;
        let r = KEY_REDACTED;
        vec![
            (
                "a pair",
                json!({"headers": [["Host", format!("x\r\nX-Debug: {c}")]]}),
                json!({"headers": [["Host", "x\r\nX-Debug: [redacted]"]]}),
            ),
            (
                "a map, benign lines after the break stay",
                json!({"headers": {"Host": format!("x\r\nAccept: a\r\nX-Debug: {c}")}}),
                json!({"headers": {"Host": "x\r\nAccept: a\r\nX-Debug: [redacted]"}}),
            ),
            (
                "a header object's value",
                json!({"headers": [{"name": "Host", "value": format!("x\nX-Debug: {c}")}]}),
                json!({"headers": [{"name": "Host", "value": "x\nX-Debug: [redacted]"}]}),
            ),
            (
                "a header object's other member",
                json!({"headers": [{
                    "name": "Host", "value": "h", "values": [format!("a\r\nX-Debug: {c}")],
                }]}),
                json!({"headers": [{
                    "name": "Host", "value": "h", "values": ["a\r\nX-Debug: [redacted]"],
                }]}),
            ),
            (
                "a raw header line",
                json!({"headers": [format!("Host: x\r\nX-Debug: {c}")]}),
                json!({"headers": ["Host: x\r\nX-Debug: [redacted]"]}),
            ),
            (
                "a list of values",
                json!({"headers": {"Accept": ["a", format!("b\r\nCookie: {c}")]}}),
                json!({"headers": {"Accept": ["a", "b\r\nCookie: [redacted]"]}}),
            ),
            (
                "a rule S pair inside a kept value is still hidden",
                json!({"headers": {"Accept": ["Cookie", "x"]}}),
                json!({"headers": {"Accept": ["Cookie", r]}}),
            ),
            (
                "a hidden header's value is hidden whole whatever is in it",
                json!({"headers": [["X-Zed", format!("a\r\nHost: {c}")]]}),
                json!({"headers": [["X-Zed", r]]}),
            ),
            // The first line of a kept value is the value itself, whatever it looks
            // like: only the lines after the first break are read as header lines.
            (
                "the first line is the value",
                json!({"headers": {"Host": "X-Debug: c"}}),
                json!({"headers": {"Host": "X-Debug: c"}}),
            ),
            (
                "the first line of a raw line's value is the value",
                json!({"headers": ["Host: X-Debug: c"]}),
                json!({"headers": ["Host: X-Debug: c"]}),
            ),
        ]
    }

    #[test]
    fn later_lines_of_a_kept_header_value_are_judged_by_name() {
        check(kept_value_rows());
    }

    /// A header name that carries a line break and a header line is judged like any
    /// block, and a raw line whose name is itself a credential is masked.
    fn header_name_rows() -> Vec<(&'static str, Value, Value)> {
        let c = CANARY;
        let r = KEY_REDACTED;
        let token = format!("ghp_{c}{}", "a".repeat(30));
        vec![
            (
                "a pair name",
                json!({"headers": [[format!("X-A\r\nX-Debug: {c}"), "v"]]}),
                json!({"headers": [["X-A\r\nX-Debug: [redacted]", r]]}),
            ),
            (
                "a header object name member",
                json!({"headers": [{"name": format!("X-A\r\nX-Debug: {c}"), "value": "v"}]}),
                json!({"headers": [{"name": "X-A\r\nX-Debug: [redacted]", "value": r}]}),
            ),
            (
                "a header object key member",
                json!({"headers": [{"key": format!("X-A\nX-Debug: {c}"), "value": "v"}]}),
                json!({"headers": [{"key": "X-A\nX-Debug: [redacted]", "value": r}]}),
            ),
            (
                "a raw line whose name is a credential",
                json!({"headers": [format!("{token}: v")]}),
                json!({"headers": ["[redacted]: [redacted]"]}),
            ),
        ]
    }

    #[test]
    fn a_line_break_in_a_header_name_does_not_hide_a_header_line() {
        check(header_name_rows());
    }

    /// Header text is charged to the budget like any string: spent, it is `…`; part
    /// of it left, only that part is examined.
    #[test]
    fn header_text_is_charged_to_the_budget() {
        let r = KEY_REDACTED;
        let spent = || json!(vec!["a".repeat(4096); 16]);
        let nearly = || {
            let mut leaves = vec![json!("a".repeat(4096)); 15];
            leaves.push(json!("b".repeat(4084)));
            Value::Array(leaves)
        };
        check(vec![
            (
                "a header string after the budget is spent",
                json!({"a": spent(), "headers": "X-Debug: c\r\nHost: x"}),
                json!({"a": spent(), "headers": CUT}),
            ),
            (
                "a pair name, a raw line and a hidden value after the budget",
                json!({"a": spent(), "headers": [["X-Zed", "z"], "X-Debug: c", "Host: x"]}),
                json!({"a": spent(), "headers": [[CUT, r], CUT, CUT]}),
            ),
            (
                "a kept value after the budget",
                json!({"a": spent(), "headers": {"Host": "x\r\nX-Debug: c"}}),
                json!({"a": spent(), "headers": {"Host": CUT}}),
            ),
            // `X-Debug: [redacted]\r\n…` is longer than the 12 bytes that are left, so the
            // walk that confirms the result cuts it again: the settled text is the hidden
            // line alone.
            (
                "a block cut by what is left of the budget",
                json!({"a": nearly(), "headers": "X-Debug: c\r\nHost: xyz"}),
                json!({"a": nearly(), "headers": "X-Debug: [redacted]"}),
            ),
        ]);
    }

    // ---- collection keys, plain maps, nesting, names

    /// A key is a header collection when it contains `header` or `hdr` (any case) or
    /// is `trailer` or `trailers`; scalars and plain strings under such a key without
    /// a header shape stay byte for byte.
    fn collection_key_rows() -> Vec<(&'static str, Value, Value)> {
        let c = CANARY;
        let r = KEY_REDACTED;
        vec![
            (
                "extra_headers, a map",
                json!({"extra_headers": {"X-Debug": c, "Host": "h"}}),
                json!({"extra_headers": {"X-Debug": r, "Host": "h"}}),
            ),
            (
                "custom_headers, pairs",
                json!({"custom_headers": [["X-Debug", c], ["Accept", "a"]]}),
                json!({"custom_headers": [["X-Debug", r], ["Accept", "a"]]}),
            ),
            (
                "hdrs",
                json!({"hdrs": {"X-Debug": c}}),
                json!({"hdrs": {"X-Debug": r}}),
            ),
            (
                "req_hdrs and two mixed-case keys",
                json!({
                    "req_hdrs": ["X-Debug: c"],
                    "RequestHeaders": {"X-Debug": c},
                    "x_HDR_list": [["X-Zed", "z"]],
                }),
                json!({
                    "req_hdrs": ["X-Debug: [redacted]"],
                    "RequestHeaders": {"X-Debug": r},
                    "x_HDR_list": [["X-Zed", r]],
                }),
            ),
            (
                "trailers, Trailer and TRAILERS in any case",
                json!({
                    "trailers": {"X-Checksum": c},
                    "Trailer": [["X-Sig", c]],
                    "TRAILERS": "X-Sig: c",
                }),
                json!({
                    "trailers": {"X-Checksum": r},
                    "Trailer": [["X-Sig", r]],
                    "TRAILERS": "X-Sig: [redacted]",
                }),
            ),
            (
                "a key that only starts like trailers, or like header, is not one",
                json!({"trailer_count": {"X-Debug": "plain"}, "heads": {"X-Debug": "plain"}}),
                json!({"trailer_count": {"X-Debug": "plain"}, "heads": {"X-Debug": "plain"}}),
            ),
            (
                "scalars and plain strings under such keys stay byte for byte",
                json!({
                    "include_headers": true,
                    "header_name": "X-Foo",
                    "headers_count": 5,
                    "hdr": null,
                    "trailer": false,
                    "trailers": 3,
                    "Max_Header_Size": 8192,
                    "header": "Content-Type",
                }),
                json!({
                    "include_headers": true,
                    "header_name": "X-Foo",
                    "headers_count": 5,
                    "hdr": null,
                    "trailer": false,
                    "trailers": 3,
                    "Max_Header_Size": 8192,
                    "header": "Content-Type",
                }),
            ),
        ]
    }

    #[test]
    fn keys_naming_headers_or_trailers_are_header_collections() {
        check(collection_key_rows());
    }

    /// An object element of an array under a header collection that is not a header
    /// object (no name member) is a header map: rule D by key.
    fn plain_map_rows() -> Vec<(&'static str, Value, Value)> {
        let c = CANARY;
        let r = KEY_REDACTED;
        vec![
            (
                "a plain map in an array",
                json!({"headers": [{"X-Debug": c, "Host": "h"}]}),
                json!({"headers": [{"X-Debug": r, "Host": "h"}]}),
            ),
            (
                "a plain map with no benign key",
                json!({"headers": [{"anything": "else"}]}),
                json!({"headers": [{"anything": r}]}),
            ),
            (
                "a plain map's scalars under benign keys stay",
                json!({"headers": [{"Content-Length": 5, "Host": null, "Expect": true}]}),
                json!({"headers": [{"Content-Length": 5, "Host": null, "Expect": true}]}),
            ),
            (
                "a map in an array in an array",
                json!({"headers": [[{"X-Debug": c}]]}),
                json!({"headers": [[{"X-Debug": r}]]}),
            ),
            (
                "a map under a hidden key of a plain map",
                json!({"headers": [{"a": {"X-Debug": c}}]}),
                json!({"headers": [{"a": r}]}),
            ),
            (
                "a map of maps",
                json!({"headers": {"X": {"Host": "h"}}}),
                json!({"headers": {"X": r}}),
            ),
        ]
    }

    #[test]
    fn a_plain_map_in_a_header_array_is_a_header_map() {
        check(plain_map_rows());
    }

    /// Everything below a header-collection key keeps the header context, and a value
    /// under a KEPT benign name is a string or a number, boolean or null; an object, or
    /// a container nested in a list, is hidden. A list of scalars and strings is the
    /// multi-value form of the header and stays (each string judged like a single one).
    fn nesting_rows() -> Vec<(&'static str, Value, Value)> {
        let c = CANARY;
        let r = KEY_REDACTED;
        vec![
            (
                "a pair three arrays deep",
                json!({"headers": [[["X-Zed", c]]]}),
                json!({"headers": [[["X-Zed", r]]]}),
            ),
            // An inner array whose first element is a string is a name and its values, so
            // the later element of `["X-Debug: c", "Host: h"]` is hidden (accepted
            // over-redaction); a one-element inner array is a line.
            (
                "an array of arrays: a name and its values, and a line",
                json!({"headers": [["X-Debug: c", "Host: h"], ["Accept: a"]]}),
                json!({"headers": [["X-Debug: [redacted]", r], ["Accept: a"]]}),
            ),
            (
                "a benign name with an object value",
                json!({"headers": {"Host": {"k": c}}}),
                json!({"headers": {"Host": r}}),
            ),
            (
                "a benign name with scalars",
                json!({"headers": {"Host": 5, "Expect": true, "Accept": null}}),
                json!({"headers": {"Host": 5, "Expect": true, "Accept": null}}),
            ),
            (
                "a benign name with a list of strings stays",
                json!({"headers": {"Accept": ["a", "b"]}}),
                json!({"headers": {"Accept": ["a", "b"]}}),
            ),
            (
                "an object or a nested list inside that list is hidden",
                json!({"headers": {"Accept": ["a", {"k": c}, ["b"]]}}),
                json!({"headers": {"Accept": ["a", r, r]}}),
            ),
            (
                "an extra element that is an object",
                json!({"headers": [["Host", "x", {"k": c}]]}),
                json!({"headers": [["Host", "x", r]]}),
            ),
            (
                "an extra element that is a list of strings stays, in a direct array",
                json!({"headers": ["Host", "x", ["a", "b"]]}),
                json!({"headers": ["Host", "x", ["a", "b"]]}),
            ),
            (
                "an extra element that is a list holding a list is hidden inside",
                json!({"headers": ["Host", "x", [[c], "b"]]}),
                json!({"headers": ["Host", "x", [r, "b"]]}),
            ),
            (
                "a pair whose value is an object",
                json!({"headers": [["Host", {"k": c}]]}),
                json!({"headers": [["Host", r]]}),
            ),
            (
                "a header object's value, and its other member, are objects",
                json!({"headers": [{"name": "Host", "value": {"k": c}, "note": {"k": c}}]}),
                json!({"headers": [{"name": "Host", "value": r, "note": r}]}),
            ),
            (
                "a name member that is a map keeps the header context",
                json!({"headers": [{"name": {"X-Debug": c}, "value": "v"}]}),
                json!({"headers": [{"name": {"X-Debug": r}, "value": r}]}),
            ),
            (
                "a header object nested in a list of a kept member",
                json!({"headers": [{"name": "Host", "value": "h", "values": [{"k": c}]}]}),
                json!({"headers": [{"name": "Host", "value": "h", "values": [r]}]}),
            ),
        ]
    }

    #[test]
    fn everything_below_a_header_key_keeps_the_header_context() {
        check(nesting_rows());
    }

    /// In a direct array (the whole value of a header key), an element after the first
    /// that is a raw header line (`token:` then a blank or the end) is judged by its
    /// name; `https://x/` has no blank after its colon, so it is a value.
    fn direct_line_rows() -> Vec<(&'static str, Value, Value)> {
        let c = CANARY;
        let r = KEY_REDACTED;
        vec![
            (
                "a header line after a benign first element",
                json!({"headers": ["Host", format!("X-Debug: {c}")]}),
                json!({"headers": ["Host", "X-Debug: [redacted]"]}),
            ),
            (
                "several lines, a benign one stays, an empty value is a line too",
                json!({"headers": ["Host", "Accept: a", "X-Zed:", format!("Cookie: a={c}")]}),
                json!({"headers": ["Host", "Accept: a", "X-Zed: [redacted]", "Cookie: [redacted]"]}),
            ),
            (
                "a URL after a benign first element is a value",
                json!({"headers": ["Referer", "https://x/"]}),
                json!({"headers": ["Referer", "https://x/"]}),
            ),
            (
                "a hidden first element hides every later element, lines included",
                json!({"headers": ["X-Zed", "Host: h", "https://x/"]}),
                json!({"headers": ["X-Zed", r, r]}),
            ),
            (
                "in a pair (not a direct array) the second element is a value",
                json!({"headers": [["Host", "X-Debug: plain"]]}),
                json!({"headers": [["Host", "X-Debug: plain"]]}),
            ),
        ]
    }

    #[test]
    fn a_header_line_after_a_benign_first_element_is_judged_by_name() {
        check(direct_line_rows());
    }

    /// Names inside header collections (map keys, pair names, name members, the keys of
    /// a header object) take the strict text pass, cut at 256 bytes on a char boundary
    /// with `…`; ordinary names are unchanged byte for byte.
    fn name_text_rows() -> Vec<(&'static str, Value, Value)> {
        let c = CANARY;
        let r = KEY_REDACTED;
        let token = format!("ghp_{c}{}", "a".repeat(30));
        let uuid = "550e8400-e29b-41d4-a716-446655440000";
        vec![
            (
                "ordinary map keys are unchanged",
                json!({"headers": {
                    "Content-Type": "application/json",
                    "X-Forwarded-For": "1.2.3.4",
                    "Sec-Fetch-Mode": "cors",
                    uuid: "v",
                }}),
                json!({"headers": {
                    "Content-Type": "application/json",
                    "X-Forwarded-For": "1.2.3.4",
                    "Sec-Fetch-Mode": "cors",
                    uuid: r,
                }}),
            ),
            (
                "ordinary pair names are unchanged",
                json!({"headers": [["Content-Type", "a"], ["X-Forwarded-For", "b"], [uuid, "v"]]}),
                json!({"headers": [["Content-Type", "a"], ["X-Forwarded-For", "b"], [uuid, r]]}),
            ),
            (
                "a credential used as a map key",
                json!({"headers": {token.clone(): "v"}}),
                json!({"headers": {"[redacted]": r}}),
            ),
            (
                "a map key with a break and a header line",
                json!({"headers": {format!("X-A\r\nX-Debug: {c}"): "v"}}),
                json!({"headers": {"X-A\r\nX-Debug: [redacted]": r}}),
            ),
            (
                "a key of a plain map",
                json!({"headers": [{token.clone(): "v"}]}),
                json!({"headers": [{"[redacted]": r}]}),
            ),
            (
                "a pair name that is a credential",
                json!({"headers": [[token.clone(), "v"]]}),
                json!({"headers": [["[redacted]", r]]}),
            ),
            (
                "a name member that is a credential",
                json!({"headers": [{"name": token.clone(), "value": "v"}]}),
                json!({"headers": [{"name": "[redacted]", "value": r}]}),
            ),
            (
                "the keys of a header object are names too",
                json!({"headers": [{"name": "X-Zed", "value": "v", token.clone(): 1}]}),
                json!({"headers": [{"name": "X-Zed", "value": r, "[redacted]": r}]}),
            ),
            (
                "a long map key is cut at 256 bytes",
                json!({"headers": {"k".repeat(300): "v"}}),
                json!({"headers": {format!("{}{CUT}", "k".repeat(256)): r}}),
            ),
            (
                "a long name is cut on a char boundary",
                json!({"headers": [["€".repeat(100), "v"]]}),
                json!({"headers": [[format!("{}{CUT}", "€".repeat(85)), r]]}),
            ),
            // Two names that are the same after the cut (or the mask) share one key in the
            // output, and the later one overwrites the earlier. Accepted: both values are
            // hidden here, and a collision can only lose a name, never reveal a value.
            (
                "two names that collide after the cut keep one key",
                json!({"headers": {"k".repeat(300): "a", format!("{}z", "k".repeat(300)): "b"}}),
                json!({"headers": {format!("{}{CUT}", "k".repeat(256)): r}}),
            ),
            (
                "outside a header key a credential key is masked too",
                json!({"x": {token.clone(): "v"}}),
                json!({"x": {"[redacted]": "v"}}),
            ),
        ]
    }

    #[test]
    fn names_inside_header_collections_take_the_text_pass_and_a_cap() {
        check(name_text_rows());
    }

    /// Object keys inside header collections are charged to their own 64 KiB pool, so
    /// they stay free for the leaf budget: 300 keys of 253 bytes use 259 whole names, a
    /// nine-byte rest and then `…`, and 16 whole 4096-byte leaves still fit after them.
    #[test]
    fn header_keys_are_charged_to_their_own_pool() {
        let mut keys = serde_json::Map::new();
        for i in 0..300 {
            keys.insert(format!("{}{i:03}", "n".repeat(250)), json!("v"));
        }
        let leaves = || json!(vec!["a".repeat(4096); 16]);
        let got = redact_value(&json!({"headers": Value::Object(keys), "leaves": leaves()}));
        let Some(headers) = got["headers"].as_object() else {
            panic!("headers stays a map: {}", got["headers"]);
        };
        assert_eq!(headers.len(), 259 + 1 + 1, "259 whole names, the rest, `…`");
        assert!(headers.contains_key(&format!("{}{CUT}", "n".repeat(9))));
        assert!(headers.contains_key(CUT));
        assert!(headers.values().all(|v| v == KEY_REDACTED));
        assert_eq!(got["leaves"], leaves(), "the leaf budget is untouched");
    }

    /// A name string (a pair name, a name member) is charged to the leaf budget and cut
    /// at 256 bytes: ahead of 16 leaves it takes 256 bytes from the sixteenth.
    #[test]
    fn a_name_string_is_charged_to_the_leaf_budget() {
        let r = KEY_REDACTED;
        let mut expected = vec![json!("a".repeat(4096)); 15];
        expected.push(json!(format!("{}{CUT}", "a".repeat(4096 - 256))));
        check(vec![(
            "a 300-byte pair name ahead of the leaves",
            json!({"aa_headers": [["n".repeat(300), "v"]], "leaves": vec!["a".repeat(4096); 16]}),
            json!({
                "aa_headers": [[format!("{}{CUT}", "n".repeat(256)), r]],
                "leaves": Value::Array(expected),
            }),
        )]);
    }

    /// Every row of the collection-key, plain-map, nesting, direct-line and name rows
    /// that redaction changes is a fixed point.
    #[test]
    fn the_collection_context_shapes_are_fixed_points() {
        let rows: Vec<(&str, Value)> = collection_key_rows()
            .into_iter()
            .chain(plain_map_rows())
            .chain(nesting_rows())
            .chain(direct_line_rows())
            .chain(name_text_rows())
            .filter(|(_, input, expected)| input != expected)
            .map(|(label, input, _)| (label, input))
            .collect();
        assert!(!rows.is_empty(), "no row of these tables changes");
        check_fixed_points(rows);
    }

    /// Every row of the line-break and multi-value shapes that redaction changes is
    /// a fixed point: redacted again, it reads the same.
    #[test]
    fn the_multi_line_and_multi_value_shapes_are_fixed_points() {
        let rows: Vec<(&str, Value)> = header_block_rows()
            .into_iter()
            .chain(multi_value_rows())
            .chain(kept_value_rows())
            .chain(header_name_rows())
            .filter(|(_, input, expected)| input != expected)
            .map(|(label, input, _)| (label, input))
            .collect();
        assert!(!rows.is_empty(), "no row of these tables changes");
        check_fixed_points(rows);
    }

    // ---- direct pairs, key text, sibling values, loose names, depth, reasons

    /// A direct header array of exactly two strings whose first holds no `:` is a name
    /// and its value even when the name is no header token (rule S's shape, decided by
    /// rule D, which hides the value of a name that is no token).
    fn direct_pair_rows() -> Vec<(&'static str, Value, Value)> {
        let c = CANARY;
        let r = KEY_REDACTED;
        vec![
            (
                "a name with a blank",
                json!({"headers": ["My Cookie", format!("foo={c}")]}),
                json!({"headers": ["My Cookie", r]}),
            ),
            (
                "another header key",
                json!({"request_headers": ["X-Api Key", c]}),
                json!({"request_headers": ["X-Api Key", r]}),
            ),
            (
                "any name that is no token",
                json!({"headers": ["see the docs", "x"]}),
                json!({"headers": ["see the docs", r]}),
            ),
            (
                "the same pair as an element",
                json!({"headers": [["My Cookie", c]]}),
                json!({"headers": [["My Cookie", r]]}),
            ),
            (
                "a second element that is no string is hidden too",
                json!({"headers": ["My Cookie", 5]}),
                json!({"headers": ["My Cookie", r]}),
            ),
            (
                "three elements: a name that is no token hides every later one",
                json!({"headers": ["X-Api Key", c, "CNRY2"]}),
                json!({"headers": ["X-Api Key", r, r]}),
            ),
            (
                "three elements, a cookie name with a blank",
                json!({"headers": ["Set Cookie", format!("a={c}"), "b=CNRY2"]}),
                json!({"headers": ["Set Cookie", r, r]}),
            ),
            (
                "a first element with a colon stays a list of lines, whatever its length",
                json!({"headers": ["Host: x", "just prose", "more"]}),
                json!({"headers": ["Host: x", "just prose", "more"]}),
            ),
        ]
    }

    #[test]
    fn a_direct_array_of_two_strings_with_a_name_that_is_no_token_is_a_pair() {
        check(direct_pair_rows());
    }

    /// An object key outside a header collection passes the strict text pass and is cut
    /// at 256 bytes; whether the value is hidden is still decided on the original key,
    /// and a key with no credential shape is unchanged.
    fn plain_key_rows() -> Vec<(&'static str, Value, Value)> {
        let c = CANARY;
        let r = KEY_REDACTED;
        let jwt = format!(
            "eyJ{}.eyJ{}.{}",
            "a".repeat(20),
            "b".repeat(20),
            "c".repeat(20)
        );
        let token = format!("ghp_{c}{}", "a".repeat(30));
        vec![
            (
                "a bearer credential used as a key (its value is hidden by the key)",
                json!({"vars": {format!("Bearer {c}"): "x"}}),
                json!({"vars": {"Bearer [redacted]": r}}),
            ),
            (
                "a URL with a password used as a key",
                json!({"urls": {format!("https://u:{c}@h/"): "x"}}),
                json!({"urls": {"https://u:[redacted]@h/": "x"}}),
            ),
            (
                "a JWT used as a key",
                json!({"m": {jwt.clone(): 1}}),
                json!({"m": {"[redacted]": 1}}),
            ),
            (
                "a bare token used as a key",
                json!({"m": {token: 2}}),
                json!({"m": {"[redacted]": 2}}),
            ),
            (
                "a credential used as a top-level key",
                json!({jwt: "x"}),
                json!({"[redacted]": "x"}),
            ),
            (
                "ordinary keys are byte for byte what they were",
                json!({"vars": {
                    "target": "http://t.test",
                    "user": "admin",
                    "x-y.z": 1,
                    "550e8400-e29b-41d4-a716-446655440000": 2,
                    "a b c": 3,
                    "日本": 4,
                }}),
                json!({"vars": {
                    "target": "http://t.test",
                    "user": "admin",
                    "x-y.z": 1,
                    "550e8400-e29b-41d4-a716-446655440000": 2,
                    "a b c": 3,
                    "日本": 4,
                }}),
            ),
            (
                "a long key is cut at 256 bytes",
                json!({"m": {"k".repeat(300): 1}}),
                json!({"m": {format!("{}{CUT}", "k".repeat(256)): 1}}),
            ),
            // Two keys that are the same text after the cut share one key in the output
            // and the later one overwrites the earlier: a collision can lose a name, never
            // reveal a value.
            (
                "two long keys collide after the cut",
                json!({"m": {"k".repeat(300): 1, format!("{}z", "k".repeat(300)): 2}}),
                json!({"m": {format!("{}{CUT}", "k".repeat(256)): 2}}),
            ),
        ]
    }

    #[test]
    fn object_keys_outside_header_collections_take_the_text_pass_and_a_cap() {
        check(plain_key_rows());
    }

    /// The keys outside header collections are charged to a pool of their own: 300 keys
    /// of 253 bytes use 259 whole names, a seven-byte rest and then `…`, and 16 whole
    /// 4096-byte leaves still fit beside them.
    #[test]
    fn plain_keys_are_charged_to_their_own_pool() {
        let mut keys = serde_json::Map::new();
        for i in 0..300 {
            keys.insert(format!("{}{i:03}", "n".repeat(250)), json!(1));
        }
        let leaves = || json!(vec!["a".repeat(4096); 16]);
        let got = redact_value(&json!({"a": leaves(), "m": Value::Object(keys)}));
        let Some(shown) = got["m"].as_object() else {
            panic!("m stays a map: {}", got["m"]);
        };
        // The two top-level keys `a` and `m` take two bytes of the pool.
        assert_eq!(shown.len(), 259 + 1 + 1, "259 whole names, the rest, `…`");
        assert!(shown.contains_key(&format!("{}{CUT}", "n".repeat(7))));
        assert!(shown.contains_key(CUT));
        assert_eq!(got["a"], leaves(), "the leaf budget is untouched");
    }

    /// A key is charged at most 256 bytes, however long it is: 300 distinct keys of 300
    /// bytes use 256 whole (cut) names and then `…`, in both pools of keys (the plain
    /// keys, and the keys inside a header collection).
    #[test]
    fn long_keys_are_charged_at_most_256_bytes_each() {
        let keys = || -> serde_json::Map<String, Value> {
            (0..300)
                .map(|i| (format!("{i:03}{}", "n".repeat(297)), json!(1)))
                .collect()
        };
        let plain = redact_value(&Value::Object(keys()));
        let header = redact_value(&json!({"headers": Value::Object(keys())}));
        for (label, shown) in [("plain keys", &plain), ("header keys", &header["headers"])] {
            let Some(map) = shown.as_object() else {
                panic!("{label}: not a map: {shown}");
            };
            assert_eq!(map.len(), 256 + 1, "{label}: 256 cut names, then `…`");
            assert!(map.contains_key(CUT), "{label}: the spent pool shows `…`");
            assert!(
                map.contains_key(&format!("000{}{CUT}", "n".repeat(253))),
                "{label}: a long name is cut at 256 bytes"
            );
        }
    }

    /// Rule S's value siblings: a `values` list, any key that ends in `value` or
    /// `values`, and a `header_value` beside a `header_name` that names a header that
    /// does not keep its value.
    fn sibling_value_rows() -> Vec<(&'static str, Value, Value)> {
        let c = CANARY;
        let r = KEY_REDACTED;
        vec![
            (
                "a values list beside a secret header name",
                json!({"name": "Set-Cookie", "values": [c]}),
                json!({"name": "Set-Cookie", "values": r}),
            ),
            (
                "keys that end in value or values",
                json!({"key": "password", "my_value": c, "x_values": [c], "note": "kept"}),
                json!({"key": "password", "my_value": r, "x_values": r, "note": "kept"}),
            ),
            (
                "a header_name that is a secret",
                json!({"header_name": "X-Api-Key", "header_value": c}),
                json!({"header_name": "X-Api-Key", "header_value": r}),
            ),
            (
                "a header_name that is only off the benign list",
                json!({"header_name": "X-Debug", "header_value": c, "note": "kept"}),
                json!({"header_name": "X-Debug", "header_value": r, "note": "kept"}),
            ),
            (
                "a benign header_name keeps its header_value",
                json!({"header_name": "Accept", "header_value": "text/html"}),
                json!({"header_name": "Accept", "header_value": "text/html"}),
            ),
            (
                "the keys are read in any case",
                json!({"Header_Name": "X-Debug", "HEADER_VALUE": c}),
                json!({"Header_Name": "X-Debug", "HEADER_VALUE": r}),
            ),
            (
                "a name that is no secret hides nothing",
                json!({"name": "color", "values": ["blue"], "my_value": "x"}),
                json!({"name": "color", "values": ["blue"], "my_value": "x"}),
            ),
        ]
    }

    #[test]
    fn rule_s_hides_every_value_sibling_of_a_secret_name() {
        check(sibling_value_rows());
    }

    /// A raw header line whose name is no header token is judged by its name in an
    /// array and in a block of lines, and its value is hidden (a name that is no token
    /// is never benign). A single line under a header key keeps the token-only reading,
    /// so a descriptive string stays.
    fn loose_name_rows() -> Vec<(&'static str, Value, Value)> {
        let c = CANARY;
        vec![
            (
                "a name with an accent",
                json!({"headers": [format!("Xé: {c}")]}),
                json!({"headers": ["Xé: [redacted]"]}),
            ),
            (
                "a name in kanji",
                json!({"headers": ["日本: X"]}),
                json!({"headers": ["日本: [redacted]"]}),
            ),
            (
                "a zero-width space in a name",
                json!({"headers": ["X-A\u{200b}: X"]}),
                json!({"headers": ["X-A\u{200b}: [redacted]"]}),
            ),
            (
                "a blank in a name",
                json!({"headers": [format!("X Debug: {c}")]}),
                json!({"headers": ["X Debug: [redacted]"]}),
            ),
            (
                "a long token name is still a line",
                json!({"headers": [format!("{}: {c}", "n".repeat(300))]}),
                json!({"headers": [format!("{}: [redacted]", "n".repeat(300))]}),
            ),
            (
                "a long token name in a block of lines is a line too",
                json!({"headers": format!("Host: x\r\n{}: {c}", "n".repeat(300))}),
                json!({"headers": format!("Host: x\r\n{}: [redacted]", "n".repeat(300))}),
            ),
            (
                "an element that holds lines is read line by line, not as one header",
                json!({"headers": [format!("a\r\nHost: x\r\nX-Debug: {c}")]}),
                json!({"headers": ["a\r\nHost: x\r\nX-Debug: [redacted]"]}),
            ),
            (
                "a name that is no token and longer than 256 bytes is not a line",
                json!({"headers": [format!("é{}: v", "n".repeat(300))]}),
                json!({"headers": [format!("é{}: v", "n".repeat(300))]}),
            ),
            (
                "an empty or blank name is not a line",
                json!({"headers": [": no name", "   : x"]}),
                json!({"headers": [": no name", "   : x"]}),
            ),
            (
                "a block of lines, benign ones stay",
                json!({"headers": format!("Host: x\r\nXé: {c}\nX Debug: s")}),
                json!({"headers": "Host: x\r\nXé: [redacted]\nX Debug: [redacted]"}),
            ),
            (
                "the later lines of a kept value",
                json!({"headers": {"Host": format!("x\r\nXé: {c}")}}),
                json!({"headers": {"Host": "x\r\nXé: [redacted]"}}),
            ),
            (
                "a line after the benign first element of a direct array",
                json!({"headers": ["Host", "X Debug: s"]}),
                json!({"headers": ["Host", "X Debug: [redacted]"]}),
            ),
            (
                "a single line under the key keeps the token-only reading",
                json!({"headers": "Xé: s", "extra_headers": "see the docs: https://x.test/"}),
                json!({"headers": "Xé: s", "extra_headers": "see the docs: https://x.test/"}),
            ),
        ]
    }

    #[test]
    fn header_lines_with_names_that_are_no_token_are_judged_by_name() {
        check(loose_name_rows());
    }

    /// `depth` levels of one container around a null, built in a loop (no recursion):
    /// `shape` is `'a'` for arrays, `'o'` for objects, `'m'` for the two alternating, and
    /// `'h'` for arrays under a `headers` key.
    fn nest(shape: char, depth: usize) -> Value {
        let mut value = Value::Null;
        for level in 0..depth {
            let array = shape == 'a' || shape == 'h' || (shape == 'm' && level % 2 == 0);
            value = if array {
                Value::Array(vec![value])
            } else {
                let mut map = serde_json::Map::new();
                map.insert("a".to_owned(), value);
                Value::Object(map)
            };
        }
        if shape == 'h' {
            let mut map = serde_json::Map::new();
            map.insert("headers".to_owned(), value);
            value = Value::Object(map);
        }
        value
    }

    /// Take a nest apart without recursion. serde_json drops a value with one nested
    /// call per level, and a test thread's stack does not hold 100000 of them, so the
    /// hostile nests are emptied one level at a time instead of being dropped whole.
    fn dismantle(mut value: Value) {
        loop {
            value = match value {
                Value::Array(mut items) => match items.pop() {
                    Some(inner) => inner,
                    None => return,
                },
                Value::Object(map) => match map.into_iter().next() {
                    Some((_, inner)) => inner,
                    None => return,
                },
                _ => return,
            };
        }
    }

    /// How many single-element arrays and single-member objects `value` nests, and
    /// what is at the bottom, found with a loop.
    fn depth_and_bottom(value: &Value) -> (usize, &Value) {
        let mut depth = 0;
        let mut at = value;
        loop {
            let inner = match at {
                Value::Array(items) if items.len() == 1 => &items[0],
                Value::Object(map) if map.len() == 1 => match map.values().next() {
                    Some(inner) => inner,
                    None => return (depth, at),
                },
                _ => return (depth, at),
            };
            depth += 1;
            at = inner;
        }
    }

    /// A container nested deeper than 64 levels is replaced by `"<redacted>"`, for every
    /// container shape, and a nest of 100000 levels is as harmless as one of 65.
    #[test]
    fn hostile_nesting_is_cut_at_the_depth_bound() {
        let mut failures = Vec::new();
        for shape in ['a', 'o', 'm', 'h'] {
            // The `headers` shape has an object around its arrays, which is one level.
            let fits = if shape == 'h' { 63 } else { 64 };
            for (depth, kept) in [
                (fits, true),
                (fits + 1, false),
                (128, false),
                (100_000, false),
            ] {
                let input = nest(shape, depth);
                let output = redact_value(&input);
                let (levels, bottom) = depth_and_bottom(&output);
                let expected_bottom = if kept {
                    Value::Null
                } else {
                    json!("<redacted>")
                };
                if (levels, bottom) != (64, &expected_bottom) {
                    failures.push(format!(
                        "shape {shape} depth {depth}: {levels} levels, bottom {bottom}, \
                         expected 64 levels and {expected_bottom}"
                    ));
                }
                dismantle(input);
            }
        }
        assert!(
            failures.is_empty(),
            "{} nest(s) wrong:\n{}",
            failures.len(),
            failures.join("\n")
        );
    }

    /// The depth is the nesting level, not the number of containers walked so far: a
    /// wide value of 100 siblings, in a general walk and in a header collection, is
    /// untouched.
    #[test]
    fn siblings_do_not_use_up_the_depth() {
        check(vec![
            (
                "an array of 100 arrays",
                json!(vec![[1]; 100]),
                json!(vec![[1]; 100]),
            ),
            (
                "an object of 100 objects",
                Value::Object(
                    (0..100)
                        .map(|i| (format!("k{i}"), json!({"a": 1})))
                        .collect(),
                ),
                Value::Object(
                    (0..100)
                        .map(|i| (format!("k{i}"), json!({"a": 1})))
                        .collect(),
                ),
            ),
            (
                "a header collection of 100 arrays",
                json!({"headers": vec![[1]; 100]}),
                json!({"headers": vec![[1]; 100]}),
            ),
        ]);
    }

    /// The text a leaf is shown as is cut at the bound too: a mask lengthens `token=x `
    /// to `token=[redacted] `, and a second pass over the 8 KB that gave must not read
    /// differently.
    #[test]
    fn the_text_a_leaf_is_shown_as_is_cut_at_the_bound_too() {
        let once = redact_value(&json!({"a": "token=x ".repeat(700)}));
        let expected = format!("{}token=[redacted]", "token=[redacted] ".repeat(240));
        assert_eq!(once, json!({"a": expected}));
        assert_eq!(redact_value(&once), once, "a second pass changes nothing");
    }

    #[test]
    fn bound_text_cuts_on_a_char_boundary_and_marks_only_a_cut() {
        for (label, text, max, expected) in [
            ("short text", "abc", 10, "abc"),
            ("exactly the bound", "abcdef", 6, "abcdef"),
            ("one byte over", "abcdefg", 6, "abcdef…"),
            ("empty text", "", 0, ""),
            (
                "a three-byte character straddles the bound",
                "€€€€",
                4,
                "€…",
            ),
            ("a bound of nothing", "ab", 0, "…"),
        ] {
            assert_eq!(bound_text(text, max), expected, "{label}");
        }
    }

    /// The text a leaf is shown as is cut for good when the pass never settles: a pass
    /// that doubles its input has no fixed point, and the result still fits the bound.
    #[test]
    fn a_pass_that_never_settles_is_cut_for_good() {
        assert_eq!(
            bounded_pass("abcdefgh", 8, |t| format!("{t}{t}")),
            "abcdefgh…"
        );
        assert_eq!(bounded_pass("abc", 8, str::to_uppercase), "ABC");
    }

    /// A direct header array changes shape when masking removes the only `:` of its
    /// first element: that colon is part of a masked quoted value, or of a private key
    /// block. The shape is decided on the text as it is shown, so the result is the one
    /// a second pass leaves alone and the second element is hidden in the first.
    fn settling_rows() -> Vec<(&'static str, Value, Value)> {
        let c = CANARY;
        vec![
            (
                "a colon inside a masked quoted value",
                json!({"headers": [format!("password=\"{c}: x"), "X-Zed"]}),
                json!({"headers": ["password=\"[redacted] x", KEY_REDACTED]}),
            ),
            (
                "a colon inside a private key block",
                json!({"extra_headers": ["-----BEGIN PRIVATE KEY-----\nabc: d", c]}),
                json!({"extra_headers": ["[redacted]", KEY_REDACTED]}),
            ),
        ]
    }

    #[test]
    fn a_direct_array_whose_colon_is_masked_reads_as_a_name_and_its_values() {
        check(settling_rows());
    }

    /// One walk is already the fixed point for those shapes: the loop that settles the
    /// result is a guarantee for what is not known, not what makes these rows pass.
    #[test]
    fn one_walk_settles_the_known_divergences() {
        let failures: Vec<String> = settling_rows()
            .into_iter()
            .filter_map(|(label, input, expected)| {
                let once = walk(&input, &mut Budget::new());
                (once != expected).then(|| format!("{label}: one walk gave {once}"))
            })
            .collect();
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }

    /// `settle` runs a further round until one leaves the value alone: a value that
    /// needs two changes is returned after the third round has confirmed it, and one
    /// that never settles is returned after the third round, as that round left it.
    #[test]
    fn settle_stops_at_a_fixed_point_or_after_three_rounds() {
        let rounds = std::cell::Cell::new(0);
        let grow_to_three = |value: &Value| {
            rounds.set(rounds.get() + 1);
            let text = value.as_str().unwrap_or_default();
            json!(if text.len() < 3 {
                format!("{text}x")
            } else {
                text.to_owned()
            })
        };
        assert_eq!(settle(json!("x"), grow_to_three), json!("xxx"));
        assert_eq!(
            rounds.get(),
            3,
            "two changes and the round that confirms them"
        );

        let rounds = std::cell::Cell::new(0);
        let never = |value: &Value| {
            rounds.set(rounds.get() + 1);
            json!(format!("{}x", value.as_str().unwrap_or_default()))
        };
        assert_eq!(settle(json!(""), never), json!("xxx"));
        assert_eq!(
            rounds.get(),
            3,
            "no fixed point: three rounds, then it gives up"
        );

        let rounds = std::cell::Cell::new(0);
        let already = |value: &Value| {
            rounds.set(rounds.get() + 1);
            value.clone()
        };
        assert_eq!(settle(json!("done"), already), json!("done"));
        assert_eq!(
            rounds.get(),
            1,
            "a settled value costs one confirming round"
        );
    }

    /// A spent pool grants nothing, even to an empty string: after 64 KiB of leaves the
    /// next leaf is `…` whatever it is.
    #[test]
    fn a_spent_pool_shows_an_ellipsis_even_for_an_empty_string() {
        let mut leaves = vec![json!("a".repeat(4096)); 16];
        let mut expected = leaves.clone();
        leaves.push(json!(""));
        expected.push(json!(CUT));
        assert_eq!(redact_value(&Value::Array(leaves)), Value::Array(expected));
    }

    /// The rows of the direct-pair, key, sibling and loose-name tables that redaction
    /// changes, and a leaf and a block of header lines whose masks lengthen them past
    /// the bound, are fixed points.
    #[test]
    fn the_hardening_shapes_are_fixed_points() {
        let mut rows: Vec<(&str, Value)> = direct_pair_rows()
            .into_iter()
            .chain(plain_key_rows())
            .chain(sibling_value_rows())
            .chain(loose_name_rows())
            .chain(settling_rows())
            .filter(|(_, input, expected)| input != expected)
            .map(|(label, input, _)| (label, input))
            .collect();
        rows.push((
            "a leaf whose masks pass the bound",
            json!({"a": "token=x ".repeat(700)}),
        ));
        rows.push((
            "a block of header lines whose masks pass the bound",
            json!({"headers": format!("Host: h\r\n{}", "X-A: s\r\n".repeat(900))}),
        ));
        assert!(!rows.is_empty(), "no row of these tables changes");
        check_fixed_points(rows);
    }
}
