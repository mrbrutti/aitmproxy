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
//!    has its members among `value`, `val`, `text`, `data`, `content`, `input`,
//!    `keys` and `string` replaced (`{"selector":"#password","text":"x"}`). Names
//!    and every other member stay.
//! 3. **Rule D** (default-deny, inside a header collection only). A header
//!    collection is an object or an array under a key named `headers`, `header`,
//!    `request_headers`, `response_headers`, `req_headers`, `resp_headers` or
//!    `http_headers` (case-insensitive), at any depth. Inside one, a header's value
//!    is kept only when its name is on the benign list and is not a strict secret
//!    key; every other value is replaced by `"<redacted>"` whatever its type. The
//!    names stay. The shapes a header takes in an array:
//!    - a two-element array whose first element is a string, **whatever the type
//!      of the second** (`["X-N", 5]`), which is also read when it is the whole
//!      value of the key (`"headers": ["X-Debug", "v"]`) and its first element is a
//!      header token (a line such as `["Cookie: a=b", "X-Debug: c"]` is two lines,
//!      below);
//!    - an object with a `name`, `key` or `header` member: its members other than
//!      the name members keep their value only when the name keeps its value, and
//!      are otherwise **all** replaced by `"<redacted>"` (a `values` list and any
//!      other member included);
//!    - a string `Name: value` (a raw header line): split at the first `:`, and when
//!      the name (blanks around it trimmed) is made of header token characters,
//!      the value is kept for a name that keeps its value and otherwise reads
//!      `Name: [redacted]`, the text-mask literal a line already carries. A string
//!      with no such name takes the general text pass.
//!
//! Every string that is kept (a leaf, a kept header value) passes
//! `aitm_core::redact_strict::scrub_strict`, so a credential inside prose, a URL or
//! a free-text body is masked by content too. Numbers, booleans, nulls and the
//! object keys themselves are untouched.
//!
//! **The work is bounded** (Design 14.6): a string leaf is examined only up to its
//! first [`LEAF_EXAMINE_BYTES`] bytes and the whole value only up to
//! [`TOTAL_EXAMINE_BYTES`] bytes of string text, in the order the walk visits it
//! (the object's own iteration order, so the same arguments always give the same
//! entry). Text beyond the bound is dropped and shown as the single character `…`;
//! once the total is spent every later string leaf is `…`. Numbers, booleans, nulls,
//! object keys and values that are replaced by `"<redacted>"` cost nothing.
//!
//! The function is `pub`, and not private to the server, because the durable
//! writer reuses it: for an `args` text that parses as JSON it applies this same
//! function, so the file can never be less strict than the ring.
//!
//! Every pass runs on decoded string content, never on JSON text.

use aitm_core::redact_strict::{is_benign_header, is_secret_key_strict, scrub_strict};
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

/// The most bytes of any one string leaf that are examined (Design 14.6).
const LEAF_EXAMINE_BYTES: usize = 4096;

/// The most bytes of string text that are examined in one [`redact_value`] call
/// (Design 14.6).
const TOTAL_EXAMINE_BYTES: usize = 64 * 1024;

/// Keys whose object or array value is a header collection (compared
/// ASCII-case-insensitively).
const HEADER_COLLECTION_KEYS: [&str; 7] = [
    "headers",
    "header",
    "request_headers",
    "response_headers",
    "req_headers",
    "resp_headers",
    "http_headers",
];

/// Sibling keys that name a thing (a header, a form field, a selector): when the
/// name is a strict secret key, the sibling value keys hold its secret.
const SIBLING_NAME_KEYS: [&str; 6] = ["name", "key", "header", "field", "selector", "label"];

/// Sibling keys that hold the value of the thing a sibling name key names.
const SIBLING_VALUE_KEYS: [&str; 8] = [
    "value", "val", "text", "data", "content", "input", "keys", "string",
];

/// The members of a header object that name the header.
const HEADER_NAME_KEYS: [&str; 3] = ["name", "key", "header"];

/// Redact a call's arguments for the audit entry (rules S and D, the secret-key
/// rule, the strict text pass over every kept string, and the bound on the work;
/// see the module doc).
///
/// Idempotent: `redact_value(&redact_value(v)) == redact_value(v)`, for any output
/// that fits the bound. (A value so large that the bound reached into it can read
/// differently on a second pass only when a mask lengthened the text it hid, such
/// as `token=x` becoming `token=[redacted]`: the second pass then spends its budget
/// sooner and shows a later leaf as `…`.)
pub fn redact_value(value: &Value) -> Value {
    walk(value, &mut Budget::new())
}

/// How much string text the traversal may still examine. One per
/// [`redact_value`] call, spent in the order the walk visits the value.
struct Budget {
    left: usize,
}

/// What [`Budget::take`] grants a string leaf.
enum Granted<'a> {
    /// The budget is spent: the leaf is shown as `…` and nothing of it is examined.
    Nothing,
    /// The examined start of the leaf; `cut` says text beyond it was dropped.
    Head { head: &'a str, cut: bool },
}

impl Budget {
    fn new() -> Budget {
        Budget {
            left: TOTAL_EXAMINE_BYTES,
        }
    }

    /// Grant `text` its examined start: at most [`LEAF_EXAMINE_BYTES`] and at most
    /// what is left of the total, cut back to a char boundary, and charge that
    /// many bytes. A spent budget grants nothing, even to an empty string.
    fn take<'a>(&mut self, text: &'a str) -> Granted<'a> {
        if self.left == 0 {
            return Granted::Nothing;
        }
        let allowed = LEAF_EXAMINE_BYTES.min(self.left);
        if text.len() <= allowed {
            self.left -= text.len();
            return Granted::Head {
                head: text,
                cut: false,
            };
        }
        let mut end = allowed;
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        self.left -= end;
        Granted::Head {
            head: &text[..end],
            cut: true,
        }
    }
}

/// Whether an argument key names a secret whose value must never be audited: the
/// strict vocabulary (so audit and findings redaction share one list, and the
/// audit adds its extra words), plus the reserved `_confirm` acknowledgment, an
/// MCP-local addition (it is already stripped before redaction, so this is belt
/// and braces).
fn is_secret_key_audit(key: &str) -> bool {
    is_secret_key_strict(key) || key.to_ascii_lowercase().contains("_confirm")
}

/// The replacement for a hidden value.
fn redacted() -> Value {
    Value::from(KEY_REDACTED)
}

/// Whether `key` is one of `wanted`, ignoring ASCII case.
fn key_is(key: &str, wanted: &[&str]) -> bool {
    wanted.iter().any(|w| key.eq_ignore_ascii_case(w))
}

/// The strict text pass over the examined start of a leaf. A cut start carries the
/// `…` marker into the pass, so a value the cut left unfinished (`password=abc` of
/// `password=abcdef`) is masked as an unquoted value that the marker ends, and a
/// second pass over the output has nothing left to change.
fn scrub_head(head: &str, cut: bool) -> String {
    if cut {
        let mut marked = String::with_capacity(head.len() + ELLIPSIS.len_utf8());
        marked.push_str(head);
        marked.push(ELLIPSIS);
        scrub_strict(&marked)
    } else {
        scrub_strict(head)
    }
}

/// A string leaf: examined within the budget, then the strict text pass; `…` once
/// the budget is spent.
fn leaf(text: &str, budget: &mut Budget) -> Value {
    Value::String(match budget.take(text) {
        Granted::Nothing => ELLIPSIS.to_string(),
        Granted::Head { head, cut } => scrub_head(head, cut),
    })
}

/// The general walk: rule S and the secret-key rule over objects and arrays,
/// the strict text pass over strings, everything else cloned.
fn walk(value: &Value, budget: &mut Budget) -> Value {
    match value {
        Value::Object(map) => Value::Object(walk_object(map, false, budget)),
        Value::Array(items) => Value::Array(walk_array(items, budget)),
        Value::String(text) => leaf(text, budget),
        other => other.clone(),
    }
}

/// An object's members. `header_entry` says the object is one element of a header
/// collection that has a name member, so rule D decides its members: when no name
/// member keeps its value, every member other than the name members is hidden.
fn walk_object(
    map: &Map<String, Value>,
    header_entry: bool,
    budget: &mut Budget,
) -> Map<String, Value> {
    let sibling_secret = names_a_secret(map);
    let hide_members = header_entry && !header_name_is_benign(map);
    map.iter()
        .map(|(key, val)| {
            let hidden = is_secret_key_audit(key)
                || (sibling_secret && key_is(key, &SIBLING_VALUE_KEYS))
                || (hide_members && !key_is(key, &HEADER_NAME_KEYS));
            let out = if hidden {
                redacted()
            } else if key_is(key, &HEADER_COLLECTION_KEYS) {
                walk_header_collection(val, budget)
            } else {
                walk(val, budget)
            };
            (key.clone(), out)
        })
        .collect()
}

/// An array's elements. Rule S: exactly two strings whose first is a strict secret
/// key hide the second.
fn walk_array(items: &[Value], budget: &mut Budget) -> Vec<Value> {
    if let [Value::String(name), Value::String(_)] = items {
        if is_secret_key_strict(name) {
            return vec![leaf(name, budget), redacted()];
        }
    }
    items.iter().map(|item| walk(item, budget)).collect()
}

/// Whether `map` has a string member among [`SIBLING_NAME_KEYS`] whose value is a
/// strict secret key (rule S, object form).
fn names_a_secret(map: &Map<String, Value>) -> bool {
    map.iter().any(|(key, val)| {
        key_is(key, &SIBLING_NAME_KEYS) && val.as_str().is_some_and(is_secret_key_strict)
    })
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

/// A header collection (rule D): the value of a header-collection key.
///
/// An object maps header names to values. An array holds header pairs
/// `[name, value]`, header objects `{name, value, ..}` and raw header lines
/// `"Name: value"` (see [`walk_header_entry`]); an element of none of these shapes
/// takes the general walk. An array that is itself a pair whose first element is a
/// header token (`"headers": ["X-Debug", "v"]`) is read as that pair. Anything else
/// (a string of raw header lines, a number) takes the general walk too.
fn walk_header_collection(value: &Value, budget: &mut Budget) -> Value {
    match value {
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(name, val)| {
                    let out = if keeps_value_of(name) {
                        walk(val, budget)
                    } else {
                        redacted()
                    };
                    (name.clone(), out)
                })
                .collect(),
        ),
        Value::Array(items) => match items.as_slice() {
            [Value::String(name), val] if is_header_token(name) => header_pair(name, val, budget),
            _ => Value::Array(
                items
                    .iter()
                    .map(|item| walk_header_entry(item, budget))
                    .collect(),
            ),
        },
        other => walk(other, budget),
    }
}

/// A header pair `[name, value]`: the name takes the text pass, and rule D decides
/// the value by the name whatever the value's type; a kept value takes the general
/// walk (so a kept string takes the text pass).
fn header_pair(name: &str, value: &Value, budget: &mut Budget) -> Value {
    let shown_name = leaf(name, budget);
    let shown_value = if keeps_value_of(name) {
        walk(value, budget)
    } else {
        redacted()
    };
    Value::Array(vec![shown_name, shown_value])
}

/// One element of a header-collection array: a two-element array whose first
/// element is a string (a pair), an object with a name member, or a raw header
/// line; anything else takes the general walk.
fn walk_header_entry(entry: &Value, budget: &mut Budget) -> Value {
    match entry {
        Value::Array(pair) => match pair.as_slice() {
            [Value::String(name), value] => header_pair(name, value, budget),
            _ => walk(entry, budget),
        },
        Value::Object(map) if is_header_object(map) => {
            Value::Object(walk_object(map, true, budget))
        }
        Value::String(line) => header_line(line, budget),
        other => walk(other, budget),
    }
}

/// The parts of a raw header line `Name: value`.
struct HeaderLine<'a> {
    /// Everything before the first `:`, as written (blanks included).
    name_part: &'a str,
    /// The name part with the blanks around it trimmed: what rule D looks up.
    name: &'a str,
    /// The line up to the start of the value (the colon and the blanks after it).
    prefix: &'a str,
    /// The rest of the line.
    value: &'a str,
}

/// Split `line` at its first `:` when what comes before it is a plausible header
/// name (token characters only, blanks around it ignored); `None` for any other
/// string.
fn split_header_line(line: &str) -> Option<HeaderLine<'_>> {
    let colon = line.find(':')?;
    let name_part = &line[..colon];
    let name = name_part.trim_matches([' ', '\t']);
    if !is_header_token(name) {
        return None;
    }
    let value = line[colon + 1..].trim_start_matches([' ', '\t']);
    Some(HeaderLine {
        name_part,
        name,
        prefix: &line[..line.len() - value.len()],
        value,
    })
}

/// A raw header line in a header collection: the line is examined within the
/// budget; when it is `Name: value` rule D decides the value by the name (kept, and
/// passed through the text pass, or `Name: [redacted]`); any other string takes the
/// text pass.
fn header_line(line: &str, budget: &mut Budget) -> Value {
    let (head, cut) = match budget.take(line) {
        Granted::Nothing => return Value::String(ELLIPSIS.to_string()),
        Granted::Head { head, cut } => (head, cut),
    };
    let Some(parts) = split_header_line(head) else {
        return Value::String(scrub_head(head, cut));
    };
    Value::String(if keeps_value_of(parts.name) {
        format!("{}{}", parts.prefix, scrub_head(parts.value, cut))
    } else {
        format!("{}: {TEXT_REDACTED}", parts.name_part)
    })
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

    /// The reserved `_confirm` acknowledgment is hidden by key, as the local
    /// `is_secret_key` of `server.rs` did before it moved here (plan ambiguity 18).
    #[test]
    fn confirm_keys_are_redacted_by_the_audit_vocabulary() {
        check(vec![
            (
                "_confirm",
                json!({"_confirm": CANARY, "note": "n"}),
                json!({"_confirm": KEY_REDACTED, "note": "n"}),
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
            (
                "an element of neither shape takes the general walk",
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
                    {"anything": "else"},
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

    // ------------------------------------------------ the bounded traversal (14.6)

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

    /// Numbers, booleans, nulls, object keys and values this module hides cost no
    /// budget: 100 KiB of each ahead of them, and 16 whole 4096-byte leaves still
    /// fit exactly. (Hidden values are not examined; a value that cost anything
    /// would cut the sixteenth leaf.)
    #[test]
    fn numbers_names_and_hidden_values_cost_nothing() {
        let big = "z".repeat(100_000);
        let long_key = "k".repeat(70_000);
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
            long_key: 1,
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

    // ------------------------------------- header shapes beyond rule D's two forms

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
                    "just prose",
                    "see the docs: https://x.test/",
                    ": no name",
                    "",
                    format!("set the password={c} now"),
                ]}),
                json!({"headers": [
                    "just prose",
                    "see the docs: https://x.test/",
                    ": no name",
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
}
