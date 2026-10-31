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
//!    names stay.
//!
//! Every string that is kept (a leaf, a kept header value) passes
//! `aitm_core::redact_strict::scrub_strict`, so a credential inside prose, a URL or
//! a free-text body is masked by content too. Numbers, booleans, nulls and the
//! object keys themselves are untouched.
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

/// The member of a header object (`{name, value}`) that holds the header's value.
const HEADER_VALUE_KEY: &str = "value";

/// The members of a header object that name the header.
const HEADER_NAME_KEYS: [&str; 3] = ["name", "key", "header"];

/// Redact a call's arguments for the audit entry (rules S and D, the secret-key
/// rule, and the strict text pass over every kept string; see the module doc).
///
/// Idempotent: `redact_value(&redact_value(v)) == redact_value(v)`.
pub fn redact_value(value: &Value) -> Value {
    walk(value)
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

/// A string leaf: the strict text pass.
fn leaf(text: &str) -> Value {
    Value::String(scrub_strict(text))
}

/// The general walk: rule S and the secret-key rule over objects and arrays,
/// the strict text pass over strings, everything else cloned.
fn walk(value: &Value) -> Value {
    match value {
        Value::Object(map) => Value::Object(walk_object(map, false)),
        Value::Array(items) => Value::Array(walk_array(items)),
        Value::String(text) => leaf(text),
        other => other.clone(),
    }
}

/// An object's members. `header_entry` says the object is one element of a header
/// collection that has a name member and a `value` member, so rule D decides its
/// `value`.
fn walk_object(map: &Map<String, Value>, header_entry: bool) -> Map<String, Value> {
    let sibling_secret = names_a_secret(map);
    let keep_header_value = !header_entry || header_name_is_benign(map);
    map.iter()
        .map(|(key, val)| {
            let hidden_by_sibling = sibling_secret && key_is(key, &SIBLING_VALUE_KEYS);
            let out = if hidden_by_sibling || is_secret_key_audit(key) {
                redacted()
            } else if header_entry && key.eq_ignore_ascii_case(HEADER_VALUE_KEY) {
                if keep_header_value {
                    walk(val)
                } else {
                    redacted()
                }
            } else if key_is(key, &HEADER_COLLECTION_KEYS) {
                walk_header_collection(val)
            } else {
                walk(val)
            };
            (key.clone(), out)
        })
        .collect()
}

/// An array's elements. Rule S: exactly two strings whose first is a strict secret
/// key hide the second.
fn walk_array(items: &[Value]) -> Vec<Value> {
    if let [Value::String(name), Value::String(_)] = items {
        if is_secret_key_strict(name) {
            return vec![leaf(name), redacted()];
        }
    }
    items.iter().map(walk).collect()
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

/// Whether `map` is a header object: a name member and a `value` member.
fn is_header_object(map: &Map<String, Value>) -> bool {
    map.keys().any(|key| key_is(key, &HEADER_NAME_KEYS))
        && map
            .keys()
            .any(|key| key.eq_ignore_ascii_case(HEADER_VALUE_KEY))
}

/// A header collection (rule D): the value of a header-collection key.
///
/// An object maps header names to values. An array holds two-string arrays
/// `[name, value]` or header objects `{name, value}`; an element of neither shape
/// takes the general walk. Anything else (a string of raw header lines, a number)
/// takes the general walk too.
fn walk_header_collection(value: &Value) -> Value {
    match value {
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(name, val)| {
                    let out = if keeps_value_of(name) {
                        walk(val)
                    } else {
                        redacted()
                    };
                    (name.clone(), out)
                })
                .collect(),
        ),
        Value::Array(items) => Value::Array(items.iter().map(walk_header_entry).collect()),
        other => walk(other),
    }
}

/// One element of a header-collection array.
fn walk_header_entry(entry: &Value) -> Value {
    match entry {
        Value::Array(pair) => match pair.as_slice() {
            [Value::String(name), Value::String(val)] => {
                let shown = if keeps_value_of(name) {
                    leaf(val)
                } else {
                    redacted()
                };
                Value::Array(vec![leaf(name), shown])
            }
            _ => walk(entry),
        },
        Value::Object(map) if is_header_object(map) => Value::Object(walk_object(map, true)),
        other => walk(other),
    }
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
}
