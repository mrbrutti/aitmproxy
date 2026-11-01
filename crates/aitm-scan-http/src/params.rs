//! Form, cookie and JSON walking, body format and path splitting (task 5).
//!
//! The pure parameter layer of the HTTP lane (spec **D8.1**, "Insertion points
//! v2"): it turns a captured request's query, form body, cookie header and JSON
//! body into named values with stable paths, and puts a mutated value back
//! **with its original JSON type** — research 20 §3.10 (4): v1's JSON mutation
//! always wrote a string, so a numeric field under test silently changed type
//! and the target rejected the probe before the check ever ran.
//!
//! Nothing here touches the network, logs, or carries a value into an error
//! message other than a JSON *path* (never a JSON value): redaction of examples
//! is `redact.rs`'s job, and `points.rs` is the only caller that builds an
//! `InsertionPoint` from these.

// Removed by the tasks that fill the modules consuming these helpers.
#![allow(dead_code)]

use aitm_core::{Body, HttpRequest};
use anyhow::{anyhow, bail};
use serde_json::Value;

use crate::limits::{MAX_JSON_DEPTH, MAX_PAIRS};

// --- form and cookie pairs ------------------------------------------------

/// Parse an `application/x-www-form-urlencoded` string (a query string or a
/// form body) the way a browser encodes one: `%xx` decoded, `+` a space.
/// Empty names are dropped; the count is capped at [`MAX_PAIRS`].
pub(crate) fn form_pairs(input: &str) -> Vec<(String, String)> {
    url::form_urlencoded::parse(input.as_bytes())
        .filter(|(name, _)| !name.is_empty())
        .take(MAX_PAIRS)
        .map(|(name, value)| (name.into_owned(), value.into_owned()))
        .collect()
}

/// Re-encode decoded pairs as `application/x-www-form-urlencoded`.
pub(crate) fn serialize_form(pairs: &[(String, String)]) -> String {
    let mut out = url::form_urlencoded::Serializer::new(String::new());
    for (name, value) in pairs {
        out.append_pair(name, value);
    }
    out.finish()
}

/// Split a `Cookie` header into its `name=value` pairs. Cookie values are not
/// form-encoded, so they are taken verbatim; the first `=` splits, surrounding
/// whitespace is trimmed, and entries without a `=` or with an empty name are
/// skipped. Capped at [`MAX_PAIRS`].
pub(crate) fn cookie_pairs(header: &str) -> Vec<(String, String)> {
    header
        .split(';')
        .filter_map(|pair| {
            let (name, value) = pair.trim().split_once('=')?;
            let name = name.trim();
            if name.is_empty() {
                return None;
            }
            Some((name.to_string(), value.trim().to_string()))
        })
        .take(MAX_PAIRS)
        .collect()
}

/// Re-encode cookie pairs as a `Cookie` header value (`"a=1; b=2"`).
pub(crate) fn serialize_cookies(pairs: &[(String, String)]) -> String {
    pairs
        .iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>()
        .join("; ")
}

// --- JSON leaves and paths ------------------------------------------------

/// A scalar found in a JSON document, with the path that addresses it.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct JsonLeaf {
    /// Dotted/indexed path, e.g. `profile.address.city` or `items[0].name`.
    pub path: String,
    /// The scalar itself, with its JSON type.
    pub value: Value,
}

/// Every scalar leaf (string, number, bool, null) of `root`, in document order.
///
/// Empty objects and empty arrays contribute nothing: they hold no value to
/// mutate. Descent stops at [`MAX_JSON_DEPTH`] and collection at [`MAX_PAIRS`].
/// A scalar document has no addressable leaf and yields an empty vector.
pub(crate) fn json_leaves(root: &Value) -> Vec<JsonLeaf> {
    let mut out = Vec::new();
    let mut path = String::new();
    walk_leaves(root, &mut path, 0, &mut out);
    out
}

fn walk_leaves(value: &Value, path: &mut String, depth: usize, out: &mut Vec<JsonLeaf>) {
    if out.len() >= MAX_PAIRS {
        return;
    }
    match value {
        Value::Object(map) => {
            if depth >= MAX_JSON_DEPTH {
                return;
            }
            for (key, child) in map {
                if out.len() >= MAX_PAIRS {
                    return;
                }
                let mark = path.len();
                push_key(path, key);
                walk_leaves(child, path, depth + 1, out);
                path.truncate(mark);
            }
        }
        Value::Array(items) => {
            if depth >= MAX_JSON_DEPTH {
                return;
            }
            for (index, child) in items.iter().enumerate() {
                if out.len() >= MAX_PAIRS {
                    return;
                }
                let mark = path.len();
                path.push_str(&format!("[{index}]"));
                walk_leaves(child, path, depth + 1, out);
                path.truncate(mark);
            }
        }
        _ => {
            if path.is_empty() {
                return;
            }
            out.push(JsonLeaf {
                path: path.clone(),
                value: value.clone(),
            });
        }
    }
}

/// Append an object key to a path, bracket-quoting it when a bare key would be
/// ambiguous (`a.b` → `["a.b"]`), so [`parse_json_path`] round-trips it.
fn push_key(path: &mut String, key: &str) {
    if key.is_empty() || key.contains(['.', '[', ']', '"']) {
        path.push_str("[\"");
        path.push_str(key);
        path.push_str("\"]");
    } else {
        if !path.is_empty() {
            path.push('.');
        }
        path.push_str(key);
    }
}

/// One step of a parsed JSON path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum JsonStep {
    /// An object key.
    Key(String),
    /// An array index.
    Index(usize),
}

/// Parse a path written by [`json_leaves`]: bare keys separated by `.`, array
/// indexes as `[0]`, and keys that need quoting as `["a.b"]`.
///
/// Returns `Err` naming the whole path, never a value.
pub(crate) fn parse_json_path(path: &str) -> anyhow::Result<Vec<JsonStep>> {
    if path.is_empty() {
        bail!("empty JSON path");
    }
    let mut steps = Vec::new();
    let mut rest = path;
    loop {
        if let Some(after) = rest.strip_prefix('[') {
            if let Some(quoted) = after.strip_prefix('"') {
                let end = quoted
                    .find("\"]")
                    .ok_or_else(|| anyhow!("unterminated quoted key in JSON path {path}"))?;
                steps.push(JsonStep::Key(quoted[..end].to_string()));
                rest = &quoted[end + 2..];
            } else {
                let end = after
                    .find(']')
                    .ok_or_else(|| anyhow!("unterminated index in JSON path {path}"))?;
                let index = after[..end]
                    .parse::<usize>()
                    .map_err(|_| anyhow!("bad array index in JSON path {path}"))?;
                steps.push(JsonStep::Index(index));
                rest = &after[end + 1..];
            }
        } else {
            let end = rest.find(['.', '[']).unwrap_or(rest.len());
            if end == 0 {
                bail!("empty key in JSON path {path}");
            }
            steps.push(JsonStep::Key(rest[..end].to_string()));
            rest = &rest[end..];
        }

        if rest.is_empty() {
            return Ok(steps);
        }
        if let Some(after_dot) = rest.strip_prefix('.') {
            if after_dot.is_empty() {
                bail!("trailing '.' in JSON path {path}");
            }
            rest = after_dot;
        } else if !rest.starts_with('[') {
            bail!("unexpected separator in JSON path {path}");
        }
    }
}

/// The value at `path`, or `None` when the path does not resolve (including a
/// malformed path).
pub(crate) fn json_get<'a>(root: &'a Value, path: &str) -> Option<&'a Value> {
    let steps = parse_json_path(path).ok()?;
    let mut current = root;
    for step in &steps {
        current = match (step, current) {
            (JsonStep::Key(key), Value::Object(map)) => map.get(key)?,
            (JsonStep::Index(index), Value::Array(items)) => items.get(*index)?,
            _ => return None,
        };
    }
    Some(current)
}

/// Replace the value at `path` with `new`.
///
/// Every parent step must already exist and be of the matching container type;
/// an array index must be in range. A missing **final** object key is inserted,
/// which is how `param_name_*` points add a sibling. `Err` names the path and
/// never a value.
pub(crate) fn json_set(root: &mut Value, path: &str, new: Value) -> anyhow::Result<()> {
    let steps = parse_json_path(path)?;
    let Some((last, parents)) = steps.split_last() else {
        bail!("empty JSON path {path}");
    };
    let mut current = root;
    for step in parents {
        current = match (step, current) {
            (JsonStep::Key(key), Value::Object(map)) => map
                .get_mut(key)
                .ok_or_else(|| anyhow!("no JSON value at path {path}"))?,
            (JsonStep::Index(index), Value::Array(items)) => items
                .get_mut(*index)
                .ok_or_else(|| anyhow!("no JSON value at path {path}"))?,
            _ => bail!("no JSON container at path {path}"),
        };
    }
    match (last, current) {
        (JsonStep::Key(key), Value::Object(map)) => {
            map.insert(key.clone(), new);
            Ok(())
        }
        (JsonStep::Index(index), Value::Array(items)) => {
            let slot = items
                .get_mut(*index)
                .ok_or_else(|| anyhow!("no JSON value at path {path}"))?;
            *slot = new;
            Ok(())
        }
        _ => bail!("no JSON container at path {path}"),
    }
}

/// Rename a top-level object key, keeping it in its original position so the
/// re-serialised body differs from the original in the key alone (the
/// `param_name_body` mutation). `Err` names the key, never a value.
pub(crate) fn json_rename_top(root: &mut Value, key: &str, new_key: &str) -> anyhow::Result<()> {
    let Value::Object(map) = root else {
        bail!("JSON root is not an object, cannot rename key {key}");
    };
    if !map.contains_key(key) {
        bail!("no top-level JSON key {key}");
    }
    if key == new_key {
        return Ok(());
    }
    let mut renamed = serde_json::Map::with_capacity(map.len());
    for (name, value) in std::mem::take(map) {
        if name == key {
            renamed.insert(new_key.to_string(), value);
        } else {
            renamed.insert(name, value);
        }
    }
    *map = renamed;
    Ok(())
}

/// The replacement for a JSON leaf, keeping the original's type where `text`
/// still fits it (research 20 §3.10 (4)): a number stays a number when `text`
/// parses as a finite number, a bool stays a bool for `true`/`false`, and
/// everything else — including every payload with a quote, a space or a tag —
/// becomes a string.
pub(crate) fn typed_replacement(original: &Value, text: &str) -> Value {
    match original {
        Value::Number(_) => number_value(text).unwrap_or_else(|| Value::String(text.to_string())),
        Value::Bool(_) => match text {
            "true" => Value::Bool(true),
            "false" => Value::Bool(false),
            _ => Value::String(text.to_string()),
        },
        _ => Value::String(text.to_string()),
    }
}

fn number_value(text: &str) -> Option<Value> {
    if let Ok(signed) = text.parse::<i64>() {
        return Some(Value::Number(signed.into()));
    }
    if let Ok(unsigned) = text.parse::<u64>() {
        return Some(Value::Number(unsigned.into()));
    }
    let float = text.parse::<f64>().ok()?;
    if !float.is_finite() {
        return None;
    }
    serde_json::Number::from_f64(float).map(Value::Number)
}

// --- request path and body ------------------------------------------------

/// A request target split into its path and its raw query string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SplitPath<'a> {
    /// The path, without the `?`.
    pub path: &'a str,
    /// The raw query string after the first `?`, if any.
    pub query: Option<&'a str>,
}

/// Split `path?query` (the `HttpRequest::path` shape) at the first `?`.
pub(crate) fn split_path(raw: &str) -> SplitPath<'_> {
    match raw.split_once('?') {
        Some((path, query)) => SplitPath {
            path,
            query: Some(query),
        },
        None => SplitPath {
            path: raw,
            query: None,
        },
    }
}

/// The bytes of a buffered body, or `None` while it is still streaming (the
/// lane never blocks a scan on a body it does not have).
pub(crate) fn body_bytes(body: &Body) -> Option<&[u8]> {
    match body {
        Body::Bytes(bytes) => Some(bytes.as_slice()),
        Body::Empty => Some(&[]),
        Body::Streamed(_) => None,
    }
}

/// How a request body should be walked for insertion points.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum BodyFormat {
    /// No body to walk.
    None,
    /// `application/x-www-form-urlencoded`.
    Form,
    /// `application/json` or a `+json` suffix type.
    Json,
    /// `application/xml`, `text/xml` or a `+xml` suffix type.
    Xml,
    /// `multipart/form-data` with its boundary.
    Multipart {
        /// The boundary, quotes stripped.
        boundary: String,
    },
    /// A body of some other type: one `entire_body` point.
    Other,
    /// Still streaming: no body points, no error.
    Unavailable,
}

/// Classify a request's body from its `Content-Type` and what is buffered.
pub(crate) fn body_format(req: &HttpRequest) -> BodyFormat {
    match &req.body {
        Body::Empty => return BodyFormat::None,
        Body::Streamed(_) => return BodyFormat::Unavailable,
        // An empty buffered body has nothing to walk whatever it claims to be.
        Body::Bytes(bytes) if bytes.is_empty() => return BodyFormat::None,
        Body::Bytes(_) => {}
    }
    let Some(content_type) = req.headers.get("content-type") else {
        return BodyFormat::Other;
    };
    let essence = content_type
        .split(';')
        .next()
        .unwrap_or(content_type)
        .trim()
        .to_ascii_lowercase();

    if essence == "application/x-www-form-urlencoded" {
        return BodyFormat::Form;
    }
    if essence == "application/json" || essence.ends_with("+json") {
        return BodyFormat::Json;
    }
    if essence == "application/xml" || essence == "text/xml" || essence.ends_with("+xml") {
        return BodyFormat::Xml;
    }
    if essence == "multipart/form-data" {
        if let Some(boundary) = boundary_param(content_type) {
            return BodyFormat::Multipart { boundary };
        }
    }
    BodyFormat::Other
}

/// The `boundary=` parameter of a `Content-Type`, quotes stripped.
fn boundary_param(content_type: &str) -> Option<String> {
    for param in content_type.split(';').skip(1) {
        let Some((name, value)) = param.split_once('=') else {
            continue;
        };
        if !name.trim().eq_ignore_ascii_case("boundary") {
            continue;
        }
        let value = value.trim();
        let value = value
            .strip_prefix('"')
            .and_then(|rest| rest.strip_suffix('"'))
            .unwrap_or(value);
        if !value.is_empty() {
            return Some(value.to_string());
        }
    }
    None
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use aitm_core::{Body, HeaderMap, HttpRequest, HttpVersion, StreamBody};
    use serde_json::json;
    use std::time::SystemTime;

    /// A request carrying `body`, with `content-type` set when given.
    fn req(content_type: Option<&str>, body: Body) -> HttpRequest {
        let mut headers = HeaderMap::new();
        if let Some(ct) = content_type {
            headers.set("content-type", ct);
        }
        HttpRequest {
            method: "POST".to_string(),
            scheme: "http".to_string(),
            authority: "t:8080".to_string(),
            path: "/a".to_string(),
            version: HttpVersion::Http11,
            headers,
            body,
            timestamp: SystemTime::now(),
        }
    }

    fn owned(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    #[test]
    fn json_leaves_pins() {
        let root = json!({
            "profile": {"address": {"city": "Lisbon"}},
            "items": [{"name": "a"}],
            "n": 3,
            "ok": true,
            "z": null,
            "e": {},
            "arr": []
        });
        let leaves = json_leaves(&root);

        // Wire order: the workspace's `serde_json` has `preserve_order` unified
        // through `aitm-poc`, so the first leaf is the first key of the document.
        assert_eq!(leaves[0].path, "profile.address.city");
        assert_eq!(leaves[0].value, json!("Lisbon"));

        let mut paths: Vec<&str> = leaves.iter().map(|leaf| leaf.path.as_str()).collect();
        paths.sort_unstable();
        assert_eq!(
            paths,
            ["items[0].name", "n", "ok", "profile.address.city", "z"]
        );
    }

    #[test]
    fn json_leaves_quote_odd_keys() {
        let root = json!({"a.b": 1, "x": {"c[0]": 2}});
        let leaves = json_leaves(&root);
        let paths: Vec<&str> = leaves.iter().map(|leaf| leaf.path.as_str()).collect();
        assert_eq!(paths, ["[\"a.b\"]", "x[\"c[0]\"]"]);
    }

    #[test]
    fn json_set_and_get() {
        let mut root =
            json!({"profile": {"address": {"city": "Lisbon"}}, "items": [{"name": "a"}]});

        json_set(&mut root, "profile.address.city", json!("X")).unwrap();
        assert_eq!(json_get(&root, "profile.address.city"), Some(&json!("X")));

        json_set(&mut root, "items[0].name", json!(7)).unwrap();
        assert_eq!(json_get(&root, "items[0].name"), Some(&json!(7)));

        let err = json_set(&mut root, "items[5].name", json!("y"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("items[5].name"), "error was {err:?}");

        let mut dotted = json!({"a.b": 1});
        json_set(&mut dotted, "[\"a.b\"]", json!(2)).unwrap();
        assert_eq!(json_get(&dotted, "[\"a.b\"]"), Some(&json!(2)));
        assert_eq!(dotted, json!({"a.b": 2}));
    }

    #[test]
    fn json_rename_top_keeps_order() {
        let mut root = json!({"a": 1, "b": 2, "c": 3});
        json_rename_top(&mut root, "b", "b'").unwrap();
        assert_eq!(
            serde_json::to_string(&root).unwrap(),
            r#"{"a":1,"b'":2,"c":3}"#
        );

        let err = json_rename_top(&mut root, "nope", "x")
            .unwrap_err()
            .to_string();
        assert!(err.contains("nope"), "error was {err:?}");

        let mut scalar = json!(3);
        assert!(json_rename_top(&mut scalar, "a", "b").is_err());
    }

    #[test]
    fn typed_replacement_pins() {
        assert_eq!(typed_replacement(&json!(3), "7"), json!(7));
        assert_eq!(typed_replacement(&json!(3), "7'"), json!("7'"));
        assert_eq!(typed_replacement(&json!(1.5), "2.5"), json!(2.5));
        assert_eq!(typed_replacement(&json!(true), "false"), json!(false));
        assert_eq!(typed_replacement(&json!("x"), "5"), json!("5"));
        assert_eq!(typed_replacement(&json!(null), "5"), json!("5"));
    }

    #[test]
    fn cookie_pairs_pins() {
        let pairs = cookie_pairs("a=1; b=2=3; ;c");
        assert_eq!(pairs, owned(&[("a", "1"), ("b", "2=3")]));
        assert_eq!(serialize_cookies(&pairs), "a=1; b=2=3");
    }

    #[test]
    fn form_round_trip() {
        assert_eq!(serialize_form(&form_pairs("a=1&b=x+y&=z")), "a=1&b=x+y");
    }

    #[test]
    fn body_format_pins() {
        assert_eq!(
            body_format(&req(
                Some("application/json; charset=utf-8"),
                Body::Bytes(b"{\"a\":1}".to_vec())
            )),
            BodyFormat::Json
        );
        assert_eq!(
            body_format(&req(
                Some("multipart/form-data; boundary=\"XyZ\""),
                Body::Bytes(b"--XyZ--\r\n".to_vec())
            )),
            BodyFormat::Multipart {
                boundary: "XyZ".to_string()
            }
        );
        assert_eq!(
            body_format(&req(Some("text/xml"), Body::Bytes(b"<a/>".to_vec()))),
            BodyFormat::Xml
        );
        assert_eq!(
            body_format(&req(
                Some("application/soap+xml"),
                Body::Bytes(b"<a/>".to_vec())
            )),
            BodyFormat::Xml
        );
        assert_eq!(
            body_format(&req(Some("application/json"), Body::Empty)),
            BodyFormat::None
        );
        assert_eq!(
            body_format(&req(Some("application/json"), Body::Streamed(StreamBody))),
            BodyFormat::Unavailable
        );
        assert_eq!(
            body_format(&req(Some("text/plain"), Body::Bytes(b"hello".to_vec()))),
            BodyFormat::Other
        );
        assert_eq!(
            body_format(&req(
                Some("application/x-www-form-urlencoded"),
                Body::Bytes(b"a=1".to_vec())
            )),
            BodyFormat::Form
        );
    }

    #[test]
    fn body_bytes_pins() {
        assert_eq!(body_bytes(&Body::Bytes(b"xy".to_vec())), Some(&b"xy"[..]));
        assert_eq!(body_bytes(&Body::Empty), Some(&b""[..]));
        assert_eq!(body_bytes(&Body::Streamed(StreamBody)), None);
    }

    #[test]
    fn split_path_pins() {
        let split = split_path("/a/b?x=1&y");
        assert_eq!(split.path, "/a/b");
        assert_eq!(split.query, Some("x=1&y"));

        let split = split_path("/a");
        assert_eq!(split.path, "/a");
        assert_eq!(split.query, None);
    }
}
