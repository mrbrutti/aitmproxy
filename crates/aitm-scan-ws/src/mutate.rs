//! Placing a [`Payload`] at a [`Locator`] — written by task 4 of the T4 plan.
//!
//! One pure function, [`place`], turns a captured client frame plus a payload
//! into the bytes a probe actually sends; [`canonical_len`] gives the length of
//! that same frame with an empty payload, which is the baseline the oversize
//! check pads from (T4 plan call 21). Nothing here does I/O or holds state, so
//! the whole module is exercised by bytes-in/bytes-out tests.
//!
//! JSON frames are **re-serialised** by `serde_json` rather than byte-spliced
//! (T4 plan call 15): the output is compact and its key order is `serde_json`'s,
//! not the capture's. Enabling `preserve_order` would change `serde_json::Value`
//! for the whole workspace through feature unification, so it is deliberately
//! not used. Form frames are re-encoded by `form_urlencoded::Serializer`, which
//! writes a space as `+` and percent-encodes every byte outside
//! `[A-Za-z0-9*\-._]`.
//!
//! Nothing here may panic on frame bytes: a frame came off the wire, so every
//! parse, lookup and index returns an error instead (plan "Crate rules"). Error
//! texts name the *path or parameter* that was missing, never a value from the
//! frame, so an error cannot carry a secret out into a `Verdict.detail`.

use aitm_scan_model::{Payload, PayloadMode};
use anyhow::{anyhow, bail, Context as _, Result};

use crate::types::Locator;

/// One step of a JSON path: an object key or an array index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Seg<'a> {
    /// Look this key up in an object.
    Key(&'a str),
    /// Index into an array.
    Index(usize),
}

/// Split a dotted/bracket path into its steps.
///
/// `user.id` is one key then another; `tags[0]` is a key then an index;
/// `items[1].id` is key, index, key. A leading `[0]` (a top-level array) is just
/// an index. An empty path, an unclosed `[`, or a non-numeric index is an error.
fn parse_segments(path: &str) -> Result<Vec<Seg<'_>>> {
    let mut out = Vec::new();
    for part in path.split('.') {
        // Everything before the first `[` is an object key; the rest is indices.
        let (name, mut rest) = match part.find('[') {
            Some(at) => (&part[..at], &part[at..]),
            None => (part, ""),
        };
        if !name.is_empty() {
            out.push(Seg::Key(name));
        }
        while !rest.is_empty() {
            let close = rest
                .find(']')
                .ok_or_else(|| anyhow!("json path has an unclosed `[`: {path}"))?;
            // `rest` starts at `[`, one byte, so `1..close` is in bounds and on
            // char boundaries.
            let index: usize = rest[1..close]
                .parse()
                .map_err(|_| anyhow!("json path has a non-numeric index: {path}"))?;
            out.push(Seg::Index(index));
            rest = &rest[close + 1..];
        }
    }
    if out.is_empty() {
        bail!("json path is empty");
    }
    Ok(out)
}

/// The leaf `path` addresses inside `root`, or `None` when it is not there.
///
/// The read-only half of the walker [`place`] uses, so a probe can read the
/// value it is about to mutate without re-implementing the path syntax. A path
/// that does not parse, names a key of a non-object, or indexes past the end of
/// an array is `None` rather than a panic.
#[must_use]
pub fn json_leaf<'a>(root: &'a serde_json::Value, path: &str) -> Option<&'a serde_json::Value> {
    let mut cur = root;
    for seg in parse_segments(path).ok()? {
        cur = match seg {
            Seg::Key(key) => cur.get(key)?,
            Seg::Index(index) => cur.get(index)?,
        };
    }
    Some(cur)
}

/// The same walk as [`json_leaf`], mutable, with a named error when it misses.
fn json_leaf_mut<'a>(
    root: &'a mut serde_json::Value,
    path: &str,
) -> Result<&'a mut serde_json::Value> {
    let mut cur = root;
    for seg in parse_segments(path)? {
        // Called as an associated fn so `cur` is *moved* into the call rather
        // than reborrowed; that is what carries `'a` through the loop.
        cur = match seg {
            Seg::Key(key) => serde_json::Value::get_mut(cur, key),
            Seg::Index(index) => serde_json::Value::get_mut(cur, index),
        }
        .ok_or_else(|| anyhow!("json path not found in frame: {path}"))?;
    }
    Ok(cur)
}

/// The text a leaf contributes to a `Prefix`/`Suffix` concatenation.
///
/// A string leaf contributes its text (not its quoted JSON form); every other
/// leaf contributes its compact JSON text, so `1` contributes `1` and `null`
/// contributes `null`.
fn leaf_text(leaf: &serde_json::Value) -> String {
    match leaf {
        serde_json::Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// `payload` combined with the value already there, per [`PayloadMode`].
fn combine(existing: &str, payload: &Payload) -> String {
    match payload.mode {
        PayloadMode::Replace => payload.value.clone(),
        PayloadMode::Prefix => format!("{}{existing}", payload.value),
        PayloadMode::Suffix => format!("{existing}{}", payload.value),
    }
}

/// The same combination over raw bytes, for binary frames.
fn combine_bytes(existing: &[u8], payload: &[u8], mode: PayloadMode) -> Vec<u8> {
    match mode {
        PayloadMode::Replace => payload.to_vec(),
        PayloadMode::Prefix => [payload, existing].concat(),
        PayloadMode::Suffix => [existing, payload].concat(),
    }
}

/// `frame` with `payload` placed at `locator`.
///
/// The lane's half of the spec's "the point is mutated with the payload by the
/// lane" (D8.3, "Probe semantics"): a check names a payload, the probe host
/// names the locator the point was discovered at, and this returns the bytes to
/// send.
///
/// - [`Locator::JsonPath`] parses the frame as JSON, walks the dotted/bracket
///   path and makes the leaf a **string** built by [`PayloadMode`] (plan call
///   15), then re-serialises the whole document compactly.
/// - [`Locator::FormParam`] replaces, prefixes or suffixes the value of the
///   **first** pair with that name and re-encodes every pair in its original
///   order.
/// - [`Locator::WholeText`] and [`Locator::Binary`] combine with the frame
///   itself; a binary payload prefers `payload.bytes` and falls back to the
///   UTF-8 of `payload.value`.
///
/// # Errors
///
/// When the frame is not JSON (or form-encoded) where the locator says it is,
/// when the path or parameter is absent, or when the locator is a
/// [`Locator::HandshakeHeader`] — those are applied to the handshake request by
/// the probe host, not to a frame. No error text carries a value from the frame.
pub fn place(frame: &[u8], locator: &Locator, payload: &Payload) -> Result<Vec<u8>> {
    match locator {
        Locator::JsonPath(path) => {
            let mut root: serde_json::Value =
                serde_json::from_slice(frame).context("frame at a json point is not valid json")?;
            let leaf = json_leaf_mut(&mut root, path)?;
            let combined = combine(&leaf_text(leaf), payload);
            *leaf = serde_json::Value::String(combined);
            serde_json::to_vec(&root).context("re-serialising the mutated json frame")
        }
        Locator::FormParam(name) => {
            let pairs: Vec<(String, String)> = form_urlencoded::parse(frame)
                .map(|(key, value)| (key.into_owned(), value.into_owned()))
                .collect();
            let mut placed = false;
            let mut out = form_urlencoded::Serializer::new(String::new());
            for (key, value) in &pairs {
                if !placed && key == name {
                    placed = true;
                    out.append_pair(key, &combine(value, payload));
                } else {
                    out.append_pair(key, value);
                }
            }
            if !placed {
                bail!("form parameter not found in frame: {name}");
            }
            Ok(out.finish().into_bytes())
        }
        Locator::WholeText => Ok(combine_bytes(frame, payload.value.as_bytes(), payload.mode)),
        Locator::Binary => {
            let bytes = payload
                .bytes
                .clone()
                .unwrap_or_else(|| payload.value.as_bytes().to_vec());
            Ok(combine_bytes(frame, &bytes, payload.mode))
        }
        Locator::HandshakeHeader(_) => {
            bail!("handshake headers are placed by the probe host, not in a frame")
        }
    }
}

/// The length of `frame` at `locator` with an **empty** payload placed.
///
/// Not `frame.len()`: a JSON frame is re-serialised compactly and its leaf is
/// stringified, so the bytes a probe sends for "no payload at all" can be
/// shorter (whitespace dropped) or longer (a number quoted) than the capture.
/// The oversize check pads to an exact byte count, so it needs the length of
/// the frame the probe host will actually build (plan call 21).
///
/// # Errors
///
/// The same conditions as [`place`].
pub fn canonical_len(frame: &[u8], locator: &Locator) -> Result<usize> {
    let empty = Payload {
        value: String::new(),
        mode: PayloadMode::Suffix,
        bytes: None,
    };
    Ok(place(frame, locator, &empty)?.len())
}

#[cfg(test)]
mod tests {
    use super::{canonical_len, json_leaf, place};
    use crate::types::Locator;
    use aitm_scan_model::{Payload, PayloadMode};

    /// A text payload in `mode`.
    fn p(value: &str, mode: PayloadMode) -> Payload {
        Payload {
            value: value.to_string(),
            mode,
            bytes: None,
        }
    }

    /// The placed frame, re-parsed as JSON.
    fn placed_json(frame: &[u8], path: &str, payload: &Payload) -> serde_json::Value {
        let out = place(frame, &Locator::JsonPath(path.to_string()), payload)
            .expect("placing at a present json path succeeds");
        serde_json::from_slice(&out).expect("the placed frame is still json")
    }

    #[test]
    fn json_leaf_replace_by_dotted_path() {
        let v = placed_json(
            br#"{"a":{"b":"x"},"c":1}"#,
            "a.b",
            &p("P", PayloadMode::Replace),
        );
        assert_eq!(json_leaf(&v, "a.b"), Some(&serde_json::json!("P")));
        assert_eq!(json_leaf(&v, "c"), Some(&serde_json::json!(1)));
    }

    #[test]
    fn json_bracket_path_replaces_array_element() {
        let v = placed_json(
            br#"{"items":[{"id":1},{"id":2}]}"#,
            "items[1].id",
            &p("P", PayloadMode::Replace),
        );
        assert_eq!(json_leaf(&v, "items[1].id"), Some(&serde_json::json!("P")));
        assert_eq!(json_leaf(&v, "items[0].id"), Some(&serde_json::json!(1)));
    }

    #[test]
    fn json_non_string_leaf_prefix_stringifies() {
        let pre = placed_json(br#"{"c":1}"#, "c", &p("P", PayloadMode::Prefix));
        assert_eq!(json_leaf(&pre, "c"), Some(&serde_json::json!("P1")));
        let suf = placed_json(br#"{"c":1}"#, "c", &p("P", PayloadMode::Suffix));
        assert_eq!(json_leaf(&suf, "c"), Some(&serde_json::json!("1P")));
    }

    #[test]
    fn json_missing_path_is_err() {
        let err = place(
            br#"{"a":1}"#,
            &Locator::JsonPath("b".to_string()),
            &p("P", PayloadMode::Replace),
        )
        .expect_err("a missing json path is an error")
        .to_string();
        assert!(err.contains('b'), "error names the path: {err}");
    }

    #[test]
    fn form_param_replaced_and_reencoded() {
        let locator = Locator::FormParam("b".to_string());
        let replaced = place(b"a=1&b=h%20i", &locator, &p("x y", PayloadMode::Replace))
            .expect("replacing a present form pair succeeds");
        assert_eq!(replaced, b"a=1&b=x+y".to_vec());
        let suffixed = place(b"a=1&b=h%20i", &locator, &p("!", PayloadMode::Suffix))
            .expect("suffixing a present form pair succeeds");
        // `!` is `%21` per `form_urlencoded`'s unreserved set.
        assert_eq!(suffixed, b"a=1&b=h+i%21".to_vec());
    }

    #[test]
    fn form_param_missing_is_err() {
        let err = place(
            b"a=1",
            &Locator::FormParam("b".to_string()),
            &p("P", PayloadMode::Replace),
        )
        .expect_err("a missing form pair is an error")
        .to_string();
        assert!(err.contains('b'), "error names the parameter: {err}");
    }

    #[test]
    fn whole_text_modes() {
        let l = Locator::WholeText;
        assert_eq!(
            place(b"hi", &l, &p("P", PayloadMode::Prefix)).expect("prefix"),
            b"Phi".to_vec()
        );
        assert_eq!(
            place(b"hi", &l, &p("P", PayloadMode::Suffix)).expect("suffix"),
            b"hiP".to_vec()
        );
        assert_eq!(
            place(b"hi", &l, &p("P", PayloadMode::Replace)).expect("replace"),
            b"P".to_vec()
        );
    }

    #[test]
    fn binary_uses_bytes_when_present() {
        let payload = Payload {
            value: "ignored".to_string(),
            mode: PayloadMode::Suffix,
            bytes: Some(vec![9, 9]),
        };
        assert_eq!(
            place(&[1, 2], &Locator::Binary, &payload).expect("binary suffix"),
            vec![1, 2, 9, 9]
        );
    }

    #[test]
    fn handshake_locator_is_err() {
        let err = place(
            b"anything",
            &Locator::HandshakeHeader("Origin".to_string()),
            &p("P", PayloadMode::Replace),
        )
        .expect_err("a handshake header is not placed here")
        .to_string();
        assert!(
            err.contains("handshake headers are placed by the probe host"),
            "{err}"
        );
    }

    #[test]
    fn canonical_len_of_compact_json() {
        let len = canonical_len(br#"{ "a" : "x" }"#, &Locator::JsonPath("a".to_string()))
            .expect("canonical length of a present path");
        assert_eq!(len, 9);
    }
}
