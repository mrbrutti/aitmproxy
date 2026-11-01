//! The single request mutation function `build_request` (task 11).
//!
//! Every probe the HTTP lane sends is the captured request with **one** value
//! changed, and this module is the only place that change is made (spec
//! **D8.1**: "`build_request(point, payload, mode)` is the single mutation
//! function"). Keeping it in one function is what makes `header`, `cookie` and
//! `path_segment` points mutable at all — research 20 §3.5 found v1 mutating
//! only query and body parameters because each check re-encoded the request
//! itself and none of them knew how to put a value back into a path or a
//! multipart part.
//!
//! What this module guarantees:
//!
//! - **One value moves, nothing else.** XML and multipart bodies are spliced by
//!   byte span (`xml.rs`, `multipart.rs`), so declaration, whitespace, boundary
//!   text and untouched file bytes survive the round trip; query, form and JSON
//!   bodies are re-serialised from the parse of the original.
//! - **The request stays coherent.** A `Body::Bytes` body gets a recomputed
//!   `Content-Length` and loses `Transfer-Encoding`, so a mutated body length
//!   can never desync the sender. `Host` is never touched: it names the target,
//!   not a value under test (a `host` point does not exist, call A8).
//! - **A stale point is an error, not a corrupt probe.** A point is enumerated
//!   from one capture and may be replayed against another request; when the
//!   parameter, format or slot it names is gone, the mutation fails with the
//!   point's kind token and id rather than silently probing the wrong place.
//! - **No value in an error.** Messages carry the kind token, the point id and a
//!   structural reason — never a payload, header value, cookie or body (crate
//!   redaction rule, D8.1). `HeaderError`'s own `Display` prints the rejected
//!   value, so it is deliberately not propagated.
//!
//! Nothing here logs, and nothing here reaches the network: the caller
//! (`host.rs`) owns both.

use aitm_core::{Body, HeaderMap, HttpRequest};
use aitm_scan_model::{InsertionKind, InsertionPoint, Payload, PayloadMode};
use anyhow::{anyhow, Result};
use serde_json::Value;

use crate::multipart;
use crate::params::{
    body_bytes, body_format, cookie_pairs, form_pairs, json_get, json_rename_top, json_set,
    serialize_cookies, serialize_form, split_path, typed_replacement, BodyFormat,
};
use crate::points::kind_token;
use crate::xml::{self, XmlSlotKind};

/// Combine a payload with the value already at an insertion point.
pub(crate) fn apply_mode(original: &str, payload: &Payload) -> String {
    match payload.mode {
        PayloadMode::Replace => payload.value.clone(),
        PayloadMode::Prefix => format!("{}{original}", payload.value),
        PayloadMode::Suffix => format!("{original}{}", payload.value),
    }
}

/// The captured request with `payload` placed at `point`, and nothing else
/// changed (spec D8.1).
///
/// The value already at the point is combined with the payload by
/// [`apply_mode`] first, so a `prefix`/`suffix` payload keeps the application's
/// own value — for `param_name_*` points the *key* is what the mode applies to,
/// and for `entire_body` the whole body text.
///
/// # Errors
///
/// Returns `Err` when the point no longer resolves against `original` — the
/// parameter, header, cookie, path segment, JSON path, XML slot or multipart
/// part is gone, the body is not (or no longer) the format the kind implies, or
/// the body is still streaming — and when the mutated value cannot go on the
/// wire (a header value with a control character). WebSocket and L4 kinds
/// belong to other lanes and are refused. Every message names the kind's wire
/// token and the point id, and never a value.
pub(crate) fn build_request(
    original: &HttpRequest,
    point: &InsertionPoint,
    payload: &Payload,
) -> Result<HttpRequest> {
    let mut req = original.clone();
    match point.kind {
        InsertionKind::Query => rewrite_query(&mut req, point, payload, Rewrite::Value)?,
        InsertionKind::ParamNameQuery => rewrite_query(&mut req, point, payload, Rewrite::Name)?,
        InsertionKind::BodyParam => rewrite_form_body(&mut req, point, payload, Rewrite::Value)?,
        InsertionKind::ParamNameBody => rewrite_param_name_body(&mut req, point, payload)?,
        InsertionKind::JsonValue => mutate_json_value(&mut req, point, payload)?,
        InsertionKind::XmlValue => mutate_xml(&mut req, point, payload, XmlSlotKind::Text)?,
        InsertionKind::XmlAttr => mutate_xml(&mut req, point, payload, XmlSlotKind::Attr)?,
        InsertionKind::MultipartValue => mutate_multipart_value(&mut req, point, payload)?,
        InsertionKind::MultipartFilename => mutate_multipart_filename(&mut req, point, payload)?,
        InsertionKind::Header => mutate_header(&mut req, point, payload)?,
        InsertionKind::Cookie => mutate_cookie(&mut req, point, payload)?,
        InsertionKind::PathSegment | InsertionKind::PathFilename => {
            mutate_path_segment(&mut req, point, payload)?;
        }
        InsertionKind::EntireBody => mutate_entire_body(&mut req, point, payload)?,
        InsertionKind::WsJsonValue
        | InsertionKind::WsText
        | InsertionKind::WsFormParam
        | InsertionKind::WsBinary
        | InsertionKind::WsHandshakeHeader
        | InsertionKind::L4Field => {
            return Err(anyhow!(
                "{} point {} belongs to another lane and cannot be placed in an HTTP request",
                kind_token(point.kind),
                point.id
            ));
        }
    }
    resync_body_headers(&mut req);
    Ok(req)
}

// --- query and form parameters --------------------------------------------

/// Whether a parameter rewrite moves the value or the key.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Rewrite {
    Value,
    Name,
}

/// Replace one query parameter's value (or rename its key) and re-serialise the
/// whole query, keeping parameter order.
fn rewrite_query(
    req: &mut HttpRequest,
    point: &InsertionPoint,
    payload: &Payload,
    what: Rewrite,
) -> Result<()> {
    let split = split_path(&req.path);
    let path = split.path.to_string();
    let mut pairs = form_pairs(split.query.unwrap_or_default());

    let Some(slot) = pairs.iter_mut().find(|(name, _)| *name == point.name) else {
        return Err(stale(
            point,
            "the request has no query parameter of that name",
        ));
    };
    match what {
        Rewrite::Value => slot.1 = apply_mode(&slot.1, payload),
        Rewrite::Name => slot.0 = apply_mode(&slot.0, payload),
    }

    let query = serialize_form(&pairs);
    req.path = format!("{path}?{query}");
    Ok(())
}

/// The same for an `application/x-www-form-urlencoded` body.
fn rewrite_form_body(
    req: &mut HttpRequest,
    point: &InsertionPoint,
    payload: &Payload,
    what: Rewrite,
) -> Result<()> {
    if body_format(req) != BodyFormat::Form {
        return Err(stale(point, "the request body is not form-encoded"));
    }
    let bytes =
        body_bytes(&req.body).ok_or_else(|| stale(point, "the request body is streaming"))?;
    let text = String::from_utf8_lossy(bytes).into_owned();
    let mut pairs = form_pairs(&text);

    let Some(slot) = pairs.iter_mut().find(|(name, _)| *name == point.name) else {
        return Err(stale(point, "the body has no parameter of that name"));
    };
    match what {
        Rewrite::Value => slot.1 = apply_mode(&slot.1, payload),
        Rewrite::Name => slot.0 = apply_mode(&slot.0, payload),
    }

    req.body = Body::Bytes(serialize_form(&pairs).into_bytes());
    Ok(())
}

/// A `param_name_body` point renames a form key or a top-level JSON key
/// (call A10: nested JSON keys are not renamed).
fn rewrite_param_name_body(
    req: &mut HttpRequest,
    point: &InsertionPoint,
    payload: &Payload,
) -> Result<()> {
    match body_format(req) {
        BodyFormat::Form => rewrite_form_body(req, point, payload, Rewrite::Name),
        BodyFormat::Json => {
            let mut root = parse_json_body(req, point)?;
            let renamed = apply_mode(&point.name, payload);
            json_rename_top(&mut root, &point.name, &renamed)
                .map_err(|_| stale(point, "the body has no top-level key of that name"))?;
            write_json_body(req, point, &root)
        }
        _ => Err(stale(
            point,
            "the request body is neither form-encoded nor JSON",
        )),
    }
}

// --- JSON ------------------------------------------------------------------

/// Replace one JSON leaf, keeping its type where the payload still fits it.
fn mutate_json_value(
    req: &mut HttpRequest,
    point: &InsertionPoint,
    payload: &Payload,
) -> Result<()> {
    let mut root = parse_json_body(req, point)?;
    let path = point
        .path
        .as_deref()
        .ok_or_else(|| stale(point, "the point carries no JSON path"))?;

    // `json_set` inserts a missing final key, so a path that no longer resolves
    // has to be refused here rather than quietly adding a field.
    let current = json_get(&root, path)
        .cloned()
        .ok_or_else(|| stale(point, "the body has no value at the point's path"))?;

    let original = match &current {
        Value::String(text) => text.clone(),
        other => other.to_string(),
    };
    let replacement = typed_replacement(&current, &apply_mode(&original, payload));
    json_set(&mut root, path, replacement)
        .map_err(|_| stale(point, "the point's JSON path no longer resolves"))?;

    write_json_body(req, point, &root)
}

fn parse_json_body(req: &HttpRequest, point: &InsertionPoint) -> Result<Value> {
    if body_format(req) != BodyFormat::Json {
        return Err(stale(point, "the request body is not JSON"));
    }
    let bytes =
        body_bytes(&req.body).ok_or_else(|| stale(point, "the request body is streaming"))?;
    serde_json::from_slice(bytes).map_err(|_| stale(point, "the request body is not valid JSON"))
}

fn write_json_body(req: &mut HttpRequest, point: &InsertionPoint, root: &Value) -> Result<()> {
    let encoded = serde_json::to_vec(root)
        .map_err(|_| stale(point, "the mutated body cannot be serialised as JSON"))?;
    req.body = Body::Bytes(encoded);
    Ok(())
}

// --- XML and multipart (byte-span splices) ---------------------------------

/// Splice one XML element text or attribute value, escaped unless the payload
/// carries raw bytes (a check that wants to break the markup sets `bytes`).
fn mutate_xml(
    req: &mut HttpRequest,
    point: &InsertionPoint,
    payload: &Payload,
    want: XmlSlotKind,
) -> Result<()> {
    if body_format(req) != BodyFormat::Xml {
        return Err(stale(point, "the request body is not XML"));
    }
    let bytes = body_bytes(&req.body)
        .ok_or_else(|| stale(point, "the request body is streaming"))?
        .to_vec();
    let path = point
        .path
        .as_deref()
        .ok_or_else(|| stale(point, "the point carries no XML path"))?;

    let slots = xml::scan(&bytes).map_err(|_| stale(point, "the request body is not valid XML"))?;
    let slot = slots
        .iter()
        .find(|slot| slot.kind == want && slot.path == path)
        .ok_or_else(|| stale(point, "the body has no XML slot at the point's path"))?;
    let span = checked_span(point, &slot.span, bytes.len())?;

    let replacement = match &payload.bytes {
        Some(raw) => raw.clone(),
        None => xml::escape(&apply_mode(&slot.value, payload)).into_bytes(),
    };
    req.body = Body::Bytes(xml::splice(&bytes, span, &replacement));
    Ok(())
}

/// Splice one multipart part's content, leaving every other part byte-identical
/// (file parts are never copied out of the body).
fn mutate_multipart_value(
    req: &mut HttpRequest,
    point: &InsertionPoint,
    payload: &Payload,
) -> Result<()> {
    let (bytes, parts) = parse_multipart_body(req, point)?;
    let part = parts
        .iter()
        .find(|part| part.name.as_deref() == Some(point.name.as_str()))
        .ok_or_else(|| stale(point, "the body has no part of that name"))?;
    let span = checked_span(point, &part.value_span, bytes.len())?;

    let replacement = match &payload.bytes {
        Some(raw) => raw.clone(),
        None => {
            let current = String::from_utf8_lossy(bytes.get(span.clone()).unwrap_or_default());
            apply_mode(&current, payload).into_bytes()
        }
    };
    req.body = Body::Bytes(multipart::splice(&bytes, span, &replacement));
    Ok(())
}

/// Splice one multipart part's declared filename, with only the characters that
/// would break the quoted `filename=` parameter escaped.
fn mutate_multipart_filename(
    req: &mut HttpRequest,
    point: &InsertionPoint,
    payload: &Payload,
) -> Result<()> {
    let (bytes, parts) = parse_multipart_body(req, point)?;
    let part = parts
        .iter()
        .find(|part| part.name.as_deref() == Some(point.name.as_str()))
        .ok_or_else(|| stale(point, "the body has no part of that name"))?;
    let filename_span = part
        .filename_span
        .as_ref()
        .ok_or_else(|| stale(point, "the part no longer declares a filename"))?;
    let span = checked_span(point, filename_span, bytes.len())?;

    let current = part.filename.clone().unwrap_or_default();
    let replacement = multipart::escape_filename(&apply_mode(&current, payload));
    req.body = Body::Bytes(multipart::splice(&bytes, span, replacement.as_bytes()));
    Ok(())
}

fn parse_multipart_body(
    req: &HttpRequest,
    point: &InsertionPoint,
) -> Result<(Vec<u8>, Vec<multipart::Part>)> {
    let BodyFormat::Multipart { boundary } = body_format(req) else {
        return Err(stale(point, "the request body is not multipart/form-data"));
    };
    let bytes = body_bytes(&req.body)
        .ok_or_else(|| stale(point, "the request body is streaming"))?
        .to_vec();
    let parts = multipart::parse(&bytes, &boundary)
        .map_err(|_| stale(point, "the request body is not a parseable multipart body"))?;
    Ok((bytes, parts))
}

/// A span is only spliced when it still fits the body it came from: both
/// splices clamp or no-op on a bad span, which would silently probe the wrong
/// bytes, so a stale span is an error here instead.
fn checked_span(
    point: &InsertionPoint,
    span: &std::ops::Range<usize>,
    len: usize,
) -> Result<std::ops::Range<usize>> {
    if span.start > span.end || span.end > len {
        return Err(stale(point, "the point's byte span is outside the body"));
    }
    Ok(span.clone())
}

// --- headers and cookies ---------------------------------------------------

/// Replace one header's value. `HeaderMap::set` appends, so the existing
/// entries are removed first and exactly one entry is written back.
fn mutate_header(req: &mut HttpRequest, point: &InsertionPoint, payload: &Payload) -> Result<()> {
    let current = req
        .headers
        .get(&point.name)
        .ok_or_else(|| stale(point, "the request has no header of that name"))?
        .to_string();
    let value = apply_mode(&current, payload);
    let name = written_name(&req.headers, &point.name).unwrap_or_else(|| point.name.clone());

    req.headers.remove(&point.name);
    req.headers.try_set(&name, &value).map_err(|_| {
        // `HeaderError` prints the rejected value; the message is rebuilt
        // without it (crate redaction rule).
        anyhow!(
            "{} point {} produced a value that cannot go on the wire",
            kind_token(point.kind),
            point.id
        )
    })
}

/// Replace one cookie's value and rebuild the whole `Cookie` header in the
/// original order. Only the three characters that would split the header or
/// start another cookie are encoded; everything else reaches the application
/// as written.
fn mutate_cookie(req: &mut HttpRequest, point: &InsertionPoint, payload: &Payload) -> Result<()> {
    let header = req
        .headers
        .get("cookie")
        .ok_or_else(|| stale(point, "the request has no Cookie header"))?
        .to_string();
    let mut pairs = cookie_pairs(&header);

    let Some(slot) = pairs.iter_mut().find(|(name, _)| *name == point.name) else {
        return Err(stale(point, "the Cookie header has no cookie of that name"));
    };
    slot.1 = encode_cookie_value(&apply_mode(&slot.1, payload));

    let value = serialize_cookies(&pairs);
    let name = written_name(&req.headers, "cookie").unwrap_or_else(|| "cookie".to_string());
    req.headers.remove("cookie");
    req.headers.try_set(&name, &value).map_err(|_| {
        anyhow!(
            "{} point {} produced a value that cannot go on the wire",
            kind_token(point.kind),
            point.id
        )
    })
}

/// `;`, CR and LF percent-encoded: the three characters that would end this
/// cookie, or the header, early.
fn encode_cookie_value(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            ';' => out.push_str("%3B"),
            '\r' => out.push_str("%0D"),
            '\n' => out.push_str("%0A"),
            other => out.push(other),
        }
    }
    out
}

/// A header's name as the capture spelled it, so a mutation does not re-case a
/// header the target may be sensitive to.
fn written_name(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .iter()
        .find(|(written, _)| written.eq_ignore_ascii_case(name))
        .map(|(written, _)| written.to_string())
}

// --- path ------------------------------------------------------------------

/// Replace the path segment the point's 1-based index names (call A9: the index,
/// not the text, is what addresses it, so two segments with the same text stay
/// distinguishable). The query is kept verbatim.
fn mutate_path_segment(
    req: &mut HttpRequest,
    point: &InsertionPoint,
    payload: &Payload,
) -> Result<()> {
    let split = split_path(&req.path);
    let query = split.query.map(str::to_string);
    let mut segments: Vec<String> = split.path.split('/').map(str::to_string).collect();

    let index: usize = point
        .path
        .as_deref()
        .and_then(|index| index.parse().ok())
        .ok_or_else(|| stale(point, "the point carries no path segment index"))?;
    let ordinal = index
        .checked_sub(1)
        .ok_or_else(|| stale(point, "the point's path segment index is not 1-based"))?;
    let position = segments
        .iter()
        .enumerate()
        .filter(|(_, segment)| !segment.is_empty())
        .map(|(position, _)| position)
        .nth(ordinal)
        .ok_or_else(|| stale(point, "the path has no segment at the point's index"))?;

    let Some(segment) = segments.get_mut(position) else {
        return Err(stale(point, "the path has no segment at the point's index"));
    };
    *segment = encode_path_segment(&apply_mode(segment, payload));

    let path = segments.join("/");
    req.path = match query {
        Some(query) => format!("{path}?{query}"),
        None => path,
    };
    Ok(())
}

/// Percent-encode everything outside the RFC 3986 path-segment set — unless the
/// payload already carries a `%`, in which case it is a traversal or
/// double-decoding probe and is passed through exactly as written.
fn encode_path_segment(text: &str) -> String {
    if text.contains('%') {
        return text.to_string();
    }
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        if is_pchar(byte) {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// RFC 3986 `pchar` minus `pct-encoded`: unreserved, sub-delims, `:` and `@`.
fn is_pchar(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'-' | b'.'
                | b'_'
                | b'~'
                | b'!'
                | b'$'
                | b'&'
                | b'\''
                | b'('
                | b')'
                | b'*'
                | b'+'
                | b','
                | b';'
                | b'='
                | b':'
                | b'@'
        )
}

// --- whole body ------------------------------------------------------------

/// Replace the whole body: raw `bytes` when the payload carries them, else the
/// body text combined with the payload by the mode.
fn mutate_entire_body(
    req: &mut HttpRequest,
    point: &InsertionPoint,
    payload: &Payload,
) -> Result<()> {
    let bytes = match &payload.bytes {
        Some(raw) => raw.clone(),
        None => {
            let current = body_bytes(&req.body)
                .ok_or_else(|| stale(point, "the request body is streaming"))?;
            apply_mode(&String::from_utf8_lossy(current), payload).into_bytes()
        }
    };
    req.body = Body::Bytes(bytes);
    Ok(())
}

// --- shared tail -----------------------------------------------------------

/// Keep the framing honest after a mutation: a buffered body's
/// `Content-Length` is recomputed and `Transfer-Encoding` dropped, so the
/// sender can never frame the mutated body by a stale length. `Host` and
/// `Content-Type` are left exactly as captured.
fn resync_body_headers(req: &mut HttpRequest) {
    let Body::Bytes(bytes) = &req.body else {
        return;
    };
    let length = bytes.len().to_string();
    let name = written_name(&req.headers, "content-length")
        .unwrap_or_else(|| "content-length".to_string());
    req.headers.remove("content-length");
    // A decimal length is a value this module produced, never user input.
    req.headers.set(&name, &length);
    req.headers.remove("transfer-encoding");
}

/// The error for a point that no longer resolves against the request.
///
/// Carries the kind's wire token and the point id so a probe failure names the
/// point, and a structural `reason` that never includes a value.
fn stale(point: &InsertionPoint, reason: &str) -> anyhow::Error {
    anyhow!(
        "{} point {} no longer resolves: {reason}",
        kind_token(point.kind),
        point.id
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use aitm_core::{Body, HttpRequest};
    use aitm_scan_model::{InsertionKind, InsertionPoint, LaneKind, Payload, PayloadMode};

    use super::{apply_mode, build_request};
    use crate::multipart;
    use crate::params::body_bytes;
    use crate::testutil::request;

    /// The multipart body pinned by task 7 (boundary `XyZ`), CRLF throughout.
    const MULTIPART: &[u8] = b"--XyZ\r\nContent-Disposition: form-data; name=\"title\"\r\n\r\nhello\r\n--XyZ\r\nContent-Disposition: form-data; name=\"doc\"; filename=\"a.txt\"\r\nContent-Type: text/plain\r\n\r\nfile-bytes\r\n--XyZ--\r\n";

    fn point(kind: InsertionKind, name: &str, path: Option<&str>) -> InsertionPoint {
        InsertionPoint {
            id: "flow-1:point:0".to_string(),
            lane: LaneKind::Http,
            kind,
            name: name.to_string(),
            path: path.map(str::to_string),
            example: None,
            flow: None,
            site_node: None,
            traits: Vec::new(),
            frequency: 1,
            method: None,
            url: None,
        }
    }

    fn text_payload(value: &str, mode: PayloadMode) -> Payload {
        Payload {
            value: value.to_string(),
            mode,
            bytes: None,
        }
    }

    fn replace(value: &str) -> Payload {
        text_payload(value, PayloadMode::Replace)
    }

    fn raw_payload(bytes: &[u8]) -> Payload {
        Payload {
            value: String::new(),
            mode: PayloadMode::Replace,
            bytes: Some(bytes.to_vec()),
        }
    }

    fn body_text(req: &HttpRequest) -> String {
        String::from_utf8(body_bytes(&req.body).unwrap().to_vec()).unwrap()
    }

    fn json_request(body: &str) -> HttpRequest {
        request(
            "POST",
            "http://t:8080/api",
            &[],
            Some(("application/json", body.as_bytes())),
        )
    }

    fn xml_request(body: &str) -> HttpRequest {
        request(
            "POST",
            "http://t:8080/api",
            &[],
            Some(("text/xml", body.as_bytes())),
        )
    }

    fn multipart_request() -> HttpRequest {
        request(
            "POST",
            "http://t:8080/upload",
            &[],
            Some(("multipart/form-data; boundary=XyZ", MULTIPART)),
        )
    }

    #[test]
    fn apply_mode_pins() {
        assert_eq!(apply_mode("hello", &replace("<s>")), "<s>");
        assert_eq!(
            apply_mode("hello", &text_payload("<s>", PayloadMode::Prefix)),
            "<s>hello"
        );
        assert_eq!(
            apply_mode("hello", &text_payload("<s>", PayloadMode::Suffix)),
            "hello<s>"
        );
    }

    #[test]
    fn query_pins() {
        let req = request("GET", "http://t:8080/search?q=hello&x=1", &[], None);
        let point = point(InsertionKind::Query, "q", None);

        let out = build_request(&req, &point, &replace("<s>")).unwrap();
        assert_eq!(out.path, "/search?q=%3Cs%3E&x=1");

        let out = build_request(&req, &point, &text_payload("<s>", PayloadMode::Suffix)).unwrap();
        assert_eq!(out.path, "/search?q=hello%3Cs%3E&x=1");

        let out = build_request(&req, &point, &text_payload("<s>", PayloadMode::Prefix)).unwrap();
        assert_eq!(out.path, "/search?q=%3Cs%3Ehello&x=1");
    }

    #[test]
    fn form_pins() {
        let req = request(
            "POST",
            "http://t:8080/login",
            &[],
            Some(("application/x-www-form-urlencoded", b"a=1&b=2")),
        );
        let out = build_request(
            &req,
            &point(InsertionKind::BodyParam, "b", None),
            &replace("x y"),
        )
        .unwrap();

        assert_eq!(body_bytes(&out.body), Some(&b"a=1&b=x+y"[..]));
        // The plan's Task 11 line says `"7"`, which is the *original* body's
        // length; the spec requires `Content-Length` to be recomputed, and the
        // mutated body it names in the same sentence is nine bytes long.
        assert_eq!(out.headers.get("content-length"), Some("9"));
    }

    #[test]
    fn json_typed() {
        let req = json_request(r#"{"n":3,"s":"a"}"#);
        let numeric = point(InsertionKind::JsonValue, "n", Some("n"));

        let out = build_request(&req, &numeric, &replace("7")).unwrap();
        assert_eq!(body_text(&out), r#"{"n":7,"s":"a"}"#);

        let out = build_request(&req, &numeric, &replace("7'")).unwrap();
        assert_eq!(body_text(&out), r#"{"n":"7'","s":"a"}"#);

        let nested = json_request(r#"{"profile":{"address":{"city":"Lisbon"}}}"#);
        let out = build_request(
            &nested,
            &point(
                InsertionKind::JsonValue,
                "city",
                Some("profile.address.city"),
            ),
            &replace("Porto"),
        )
        .unwrap();
        assert_eq!(
            body_text(&out),
            r#"{"profile":{"address":{"city":"Porto"}}}"#
        );

        let err = build_request(
            &req,
            &point(InsertionKind::JsonValue, "missing", Some("missing")),
            &replace("7"),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("json_value"), "{err}");
        assert!(err.contains("flow-1:point:0"), "{err}");
    }

    #[test]
    fn xml_pins() {
        let req = xml_request("<a><b>v</b></a>");
        let out = build_request(
            &req,
            &point(InsertionKind::XmlValue, "b", Some("a.b")),
            &replace("<x>&\""),
        )
        .unwrap();
        assert_eq!(body_text(&out), "<a><b>&lt;x&gt;&amp;&quot;</b></a>");

        let attr = xml_request("<a id=\"1\"/>");
        let out = build_request(
            &attr,
            &point(InsertionKind::XmlAttr, "id", Some("a@id")),
            &replace("\""),
        )
        .unwrap();
        assert_eq!(body_text(&out), "<a id=\"&quot;\"/>");

        let out = build_request(
            &req,
            &point(InsertionKind::XmlValue, "b", Some("a.b")),
            &raw_payload(b"<raw/>"),
        )
        .unwrap();
        assert_eq!(body_text(&out), "<a><b><raw/></b></a>");
    }

    #[test]
    fn multipart_pins() {
        let req = multipart_request();

        let out = build_request(
            &req,
            &point(InsertionKind::MultipartValue, "title", None),
            &replace("<x>"),
        )
        .unwrap();
        let bytes = body_bytes(&out.body).unwrap().to_vec();
        let parts = multipart::parse(&bytes, "XyZ").unwrap();
        assert_eq!(&bytes[parts[0].value_span.clone()], b"<x>");
        assert_eq!(
            out.headers.get("content-length"),
            Some(bytes.len().to_string().as_str())
        );

        let out = build_request(
            &req,
            &point(InsertionKind::MultipartFilename, "doc", None),
            &replace("../x\"y.txt"),
        )
        .unwrap();
        let bytes = body_bytes(&out.body).unwrap().to_vec();
        let parts = multipart::parse(&bytes, "XyZ").unwrap();
        assert_eq!(parts[1].filename.as_deref(), Some("../x%22y.txt"));
    }

    #[test]
    fn header_and_cookie_pins() {
        let req = request(
            "GET",
            "http://t:8080/",
            &[("X-Client", "abc"), ("Cookie", "sid=S3; theme=dark")],
            None,
        );

        let out = build_request(
            &req,
            &point(InsertionKind::Header, "X-Client", None),
            &replace("zz"),
        )
        .unwrap();
        let client: Vec<&str> = out
            .headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("x-client"))
            .map(|(_, value)| value)
            .collect();
        assert_eq!(client, vec!["zz"]);

        let err = build_request(
            &req,
            &point(InsertionKind::Header, "X-Client", None),
            &replace("a\r\nb"),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("header"), "{err}");
        assert!(!err.contains("a\r\nb"), "the error leaked the payload");

        let out = build_request(
            &req,
            &point(InsertionKind::Cookie, "theme", None),
            &replace("<p>"),
        )
        .unwrap();
        assert_eq!(out.headers.get("cookie"), Some("sid=S3; theme=<p>"));

        let out = build_request(
            &req,
            &point(InsertionKind::Cookie, "theme", None),
            &replace("a;b"),
        )
        .unwrap();
        assert_eq!(out.headers.get("cookie"), Some("sid=S3; theme=a%3Bb"));
    }

    #[test]
    fn path_pins() {
        let req = request(
            "GET",
            "http://t:8080/files/reports/summary.pdf?x=1",
            &[],
            None,
        );
        let segment = point(InsertionKind::PathSegment, "reports", Some("2"));

        let out = build_request(&req, &segment, &replace("..%2f")).unwrap();
        assert_eq!(out.path, "/files/..%2f/summary.pdf?x=1");

        let out = build_request(&req, &segment, &replace("a b")).unwrap();
        assert_eq!(out.path, "/files/a%20b/summary.pdf?x=1");

        let out = build_request(
            &req,
            &point(InsertionKind::PathFilename, "summary.pdf", Some("3")),
            &replace("x.txt"),
        )
        .unwrap();
        assert_eq!(out.path, "/files/reports/x.txt?x=1");
    }

    #[test]
    fn param_name_pins() {
        let req = request("GET", "http://t:8080/search?q=hello&x=1", &[], None);
        let out = build_request(
            &req,
            &point(InsertionKind::ParamNameQuery, "q", None),
            &replace("qq"),
        )
        .unwrap();
        assert_eq!(out.path, "/search?qq=hello&x=1");

        let form = request(
            "POST",
            "http://t:8080/login",
            &[],
            Some(("application/x-www-form-urlencoded", b"a=1&b=2")),
        );
        let out = build_request(
            &form,
            &point(InsertionKind::ParamNameBody, "b", None),
            &replace("bb"),
        )
        .unwrap();
        assert_eq!(body_text(&out), "a=1&bb=2");

        let json = json_request(r#"{"n":3}"#);
        let out = build_request(
            &json,
            &point(InsertionKind::ParamNameBody, "n", None),
            &replace("nn"),
        )
        .unwrap();
        assert_eq!(body_text(&out), r#"{"nn":3}"#);
    }

    #[test]
    fn entire_body_pins() {
        let req = request(
            "POST",
            "http://t:8080/raw",
            &[],
            Some(("application/octet-stream", b"hello")),
        );
        let body = point(InsertionKind::EntireBody, "body", None);

        let out = build_request(&req, &body, &replace("X")).unwrap();
        assert_eq!(body_bytes(&out.body), Some(&b"X"[..]));
        assert_eq!(
            out.headers.get("content-type"),
            Some("application/octet-stream")
        );
        assert_eq!(out.headers.get("content-length"), Some("1"));

        let out = build_request(&req, &body, &raw_payload(&[0, 1, 2])).unwrap();
        assert_eq!(body_bytes(&out.body), Some(&[0u8, 1, 2][..]));
        assert_eq!(out.headers.get("content-length"), Some("3"));
    }

    #[test]
    fn host_untouched_and_te_removed() {
        let req = request(
            "POST",
            "http://t:8080/login",
            &[("Transfer-Encoding", "chunked")],
            Some(("application/x-www-form-urlencoded", b"a=1&b=2")),
        );
        let out = build_request(
            &req,
            &point(InsertionKind::BodyParam, "b", None),
            &replace("x"),
        )
        .unwrap();
        assert_eq!(out.headers.get("host"), Some("t:8080"));
        assert_eq!(out.headers.get("transfer-encoding"), None);
        assert_eq!(out.authority, req.authority);

        let get = request(
            "GET",
            "http://t:8080/search?q=hello&x=1",
            &[("X-Client", "abc"), ("Cookie", "sid=S3; theme=dark")],
            None,
        );
        for point in [
            point(InsertionKind::Query, "q", None),
            point(InsertionKind::Header, "X-Client", None),
            point(InsertionKind::Cookie, "theme", None),
        ] {
            let out = build_request(&get, &point, &replace("z")).unwrap();
            assert_eq!(out.headers.get("host"), Some("t:8080"));
            assert!(matches!(out.body, Body::Empty));
        }
    }

    #[test]
    fn stale_point_errors() {
        let req = request("GET", "http://t:8080/search?q=hello&x=1", &[], None);
        let err = build_request(
            &req,
            &point(InsertionKind::Query, "missing", None),
            &replace("z"),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("query"), "{err}");
        assert!(err.contains("flow-1:point:0"), "{err}");

        let json = json_request(r#"{"n":3}"#);
        let err = build_request(
            &json,
            &point(InsertionKind::BodyParam, "n", None),
            &replace("z"),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("body_param"), "{err}");

        let xml = xml_request("<a><b>v</b></a>");
        let err = build_request(
            &xml,
            &point(InsertionKind::XmlValue, "gone", Some("a.gone")),
            &replace("z"),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("xml_value"), "{err}");

        let multipart = multipart_request();
        let err = build_request(
            &multipart,
            &point(InsertionKind::MultipartValue, "nope", None),
            &replace("z"),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("multipart_value"), "{err}");

        let err = build_request(
            &req,
            &point(InsertionKind::PathSegment, "reports", Some("9")),
            &replace("z"),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("path_segment"), "{err}");

        let err = build_request(
            &req,
            &point(InsertionKind::Header, "X-Absent", None),
            &replace("z"),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("header"), "{err}");
    }

    #[test]
    fn ws_and_l4_kinds_are_refused() {
        let req = request("GET", "http://t:8080/", &[], None);
        for kind in [
            InsertionKind::WsJsonValue,
            InsertionKind::WsText,
            InsertionKind::WsFormParam,
            InsertionKind::WsBinary,
            InsertionKind::WsHandshakeHeader,
            InsertionKind::L4Field,
        ] {
            let err = build_request(&req, &point(kind, "f", None), &replace("z"))
                .unwrap_err()
                .to_string();
            assert!(err.contains("flow-1:point:0"), "{err}");
        }
    }
}
