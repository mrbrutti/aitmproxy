//! mitmproxy `.flows` import (import only; no egress).
//!
//! A `.flows` file is a concatenation of tnetstring-encoded flow-state dicts, one
//! per flow, exactly as `mitmproxy.io.FlowWriter` emits them. We decode the
//! tnetstrings and map each HTTP flow's state into our `HttpFlow`. Non-HTTP flows
//! (raw TCP, DNS) are skipped rather than failing the whole import.
//!
//! tnetstring framing is `<ascii-length>:<payload><type-byte>`, with type bytes
//! `,` bytes, `;` utf-8 string, `#` int, `^` float, `!` bool, `~` null, `]` list,
//! `}` dict (key then value, repeated). This mirrors mitmproxy's own
//! `io/tnetstring.py`.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::UNIX_EPOCH;

use aitm_core::{
    Body, ConnInfo, Flow, FlowId, FlowMeta, HeaderMap, HttpFlow, HttpRequest, HttpResponse,
    HttpVersion, InterceptState,
};
use anyhow::{bail, ensure, Context};

/// A decoded tnetstring value. Dict keys are normalized to `String`. Floats and
/// bools are validated but their payloads discarded: nothing in a flow state that
/// we map is a float or a bool, but the decoder must still walk past them to reach
/// the fields it does read.
#[derive(Debug, Clone)]
enum Tns {
    Bytes(Vec<u8>),
    Str(String),
    Int(i64),
    Float,
    Bool,
    Null,
    List(Vec<Tns>),
    Dict(Vec<(String, Tns)>),
}

impl Tns {
    fn get(&self, key: &str) -> Option<&Tns> {
        match self {
            Tns::Dict(kvs) => kvs.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    /// A string view of a `;` string or a `,` bytes value (lossy for bytes).
    fn as_text(&self) -> Option<String> {
        match self {
            Tns::Str(s) => Some(s.clone()),
            Tns::Bytes(b) => Some(String::from_utf8_lossy(b).into_owned()),
            _ => None,
        }
    }

    fn as_bytes(&self) -> Option<Vec<u8>> {
        match self {
            Tns::Bytes(b) => Some(b.clone()),
            Tns::Str(s) => Some(s.clone().into_bytes()),
            _ => None,
        }
    }

    fn as_i64(&self) -> Option<i64> {
        match self {
            Tns::Int(i) => Some(*i),
            _ => None,
        }
    }

    fn as_list(&self) -> Option<&[Tns]> {
        match self {
            Tns::List(l) => Some(l),
            _ => None,
        }
    }
}

/// Maximum tnetstring nesting the parser will descend before refusing. A `.flows`
/// blob is attacker-supplied (`flow.import {format:"mitmproxy"}` is agent-reachable),
/// so a pathologically nested document must return `Err` rather than recurse until
/// the thread's stack overflows. 64 matches serde_json's default recursion posture;
/// a genuine mitmproxy flow nests only a handful of levels deep.
const MAX_DEPTH: usize = 64;

/// Import every HTTP flow from a mitmproxy `.flows` byte blob.
pub fn mitmproxy_to_flows(bytes: &[u8]) -> anyhow::Result<Vec<Flow>> {
    let mut out = Vec::new();
    let mut data = bytes;
    while !data.is_empty() {
        let (value, rest) = pop(data, 0).context("decoding mitmproxy .flows stream")?;
        data = rest;
        if let Some(flow) = flow_from_state(&value)? {
            out.push(flow);
        }
    }
    Ok(out)
}

/// Pop one tnetstring off the front, returning it and the remaining bytes. `depth`
/// is the current nesting level; a list/dict payload is parsed one level deeper.
fn pop(data: &[u8], depth: usize) -> anyhow::Result<(Tns, &[u8])> {
    // Refuse before descending past the cap so a deeply nested blob cannot drive
    // the recursion into a stack overflow.
    ensure!(depth <= MAX_DEPTH, "tnetstring: nesting exceeds depth cap");
    let colon = data
        .iter()
        .position(|&b| b == b':')
        .context("tnetstring: missing length prefix")?;
    let len: usize = std::str::from_utf8(&data[..colon])
        .ok()
        .and_then(|s| s.parse().ok())
        .context("tnetstring: invalid length prefix")?;
    let payload_start = colon + 1;
    // Checked: a length that overflows `usize` or runs to/past the end of the
    // buffer is rejected instead of slicing or indexing out of bounds.
    // `payload_end` must be strictly less than `data.len()` to leave room for the
    // trailing type byte at `data[payload_end]`.
    let payload_end = payload_start
        .checked_add(len)
        .filter(|&end| end < data.len())
        .context("tnetstring: length overruns input")?;
    let payload = &data[payload_start..payload_end];
    let type_byte = data[payload_end];
    let value = parse(type_byte, payload, depth)?;
    Ok((value, &data[payload_end + 1..]))
}

fn parse(type_byte: u8, payload: &[u8], depth: usize) -> anyhow::Result<Tns> {
    Ok(match type_byte {
        b',' => Tns::Bytes(payload.to_vec()),
        b';' => Tns::Str(String::from_utf8(payload.to_vec()).context("tnetstring: bad utf8")?),
        b'#' => Tns::Int(
            std::str::from_utf8(payload)
                .ok()
                .and_then(|s| s.parse().ok())
                .context("tnetstring: bad integer")?,
        ),
        b'^' => {
            let _: f64 = std::str::from_utf8(payload)
                .ok()
                .and_then(|s| s.parse().ok())
                .context("tnetstring: bad float")?;
            Tns::Float
        }
        b'!' => match payload {
            b"true" | b"false" => Tns::Bool,
            _ => bail!("tnetstring: bad boolean"),
        },
        b'~' => {
            ensure!(payload.is_empty(), "tnetstring: non-empty null");
            Tns::Null
        }
        b']' => {
            let mut items = Vec::new();
            let mut rest = payload;
            while !rest.is_empty() {
                let (item, next) = pop(rest, depth + 1)?;
                items.push(item);
                rest = next;
            }
            Tns::List(items)
        }
        b'}' => {
            let mut kvs = Vec::new();
            let mut rest = payload;
            while !rest.is_empty() {
                let (key, next) = pop(rest, depth + 1)?;
                let (val, next) = pop(next, depth + 1)?;
                kvs.push((key.as_text().unwrap_or_default(), val));
                rest = next;
            }
            Tns::Dict(kvs)
        }
        other => bail!("tnetstring: unknown type tag {other:#x}"),
    })
}

/// Map one mitmproxy flow-state dict into a `Flow`. Returns `None` for a
/// non-HTTP flow, which import skips.
fn flow_from_state(state: &Tns) -> anyhow::Result<Option<Flow>> {
    if state.get("type").and_then(Tns::as_text).as_deref() != Some("http") {
        return Ok(None);
    }
    let req_state = state
        .get("request")
        .context("mitmproxy flow missing request")?;
    let request = mitm_request(req_state)?;
    let response = match state.get("response") {
        Some(r) if !matches!(r, Tns::Null) => Some(mitm_response(r)?),
        _ => None,
    };
    let tls = request.scheme == "https";
    Ok(Some(Flow::Http(HttpFlow {
        id: FlowId::new(),
        request,
        response,
        client_conn: conn(tls),
        server_conn: Some(conn(tls)),
        metadata: FlowMeta::default(),
        intercept: InterceptState::Observed,
    })))
}

fn mitm_request(r: &Tns) -> anyhow::Result<HttpRequest> {
    let host = r.get("host").and_then(Tns::as_text).unwrap_or_default();
    let port = r.get("port").and_then(Tns::as_i64).unwrap_or(0);
    Ok(HttpRequest {
        method: r.get("method").and_then(Tns::as_text).unwrap_or_default(),
        scheme: r.get("scheme").and_then(Tns::as_text).unwrap_or_default(),
        authority: format!("{host}:{port}"),
        path: r.get("path").and_then(Tns::as_text).unwrap_or_default(),
        version: mitm_version(r),
        headers: mitm_headers(r),
        body: mitm_body(r),
        timestamp: UNIX_EPOCH,
    })
}

fn mitm_response(r: &Tns) -> anyhow::Result<HttpResponse> {
    let status = r
        .get("status_code")
        .and_then(Tns::as_i64)
        .context("mitmproxy response missing status_code")?;
    // An out-of-range status is a corrupt flow, not a 0-or-wrapped one: refuse the
    // import rather than silently truncating `status as u16`.
    let status = u16::try_from(status).map_err(|_| {
        anyhow::anyhow!("mitmproxy response status_code {status} out of range (0..=65535)")
    })?;
    Ok(HttpResponse {
        status,
        version: mitm_version(r),
        headers: mitm_headers(r),
        // The trailers mitmproxy records on a response are not imported.
        trailers: HeaderMap::new(),
        body: mitm_body(r),
        timestamp: UNIX_EPOCH,
        peer: None,
    })
}

fn mitm_version(msg: &Tns) -> HttpVersion {
    match msg.get("http_version").and_then(Tns::as_text).as_deref() {
        Some(v) if v.contains("/2") => HttpVersion::H2,
        _ => HttpVersion::Http11,
    }
}

fn mitm_headers(msg: &Tns) -> HeaderMap {
    let mut headers = HeaderMap::new();
    let Some(list) = msg.get("headers").and_then(Tns::as_list) else {
        return headers;
    };
    for pair in list {
        let Some(fields) = pair.as_list() else {
            continue;
        };
        let (Some(name), Some(value)) = (fields.first(), fields.get(1)) else {
            continue;
        };
        if let (Some(name), Some(value)) = (name.as_bytes(), value.as_bytes()) {
            // `set` drops a name/value that cannot go on the wire; an imported
            // header cannot smuggle a CRLF into the store.
            headers.set(
                &String::from_utf8_lossy(&name),
                &String::from_utf8_lossy(&value),
            );
        }
    }
    headers
}

fn mitm_body(msg: &Tns) -> Body {
    match msg.get("content").and_then(Tns::as_bytes) {
        Some(b) if !b.is_empty() => Body::Bytes(b),
        _ => Body::Empty,
    }
}

fn conn(tls: bool) -> ConnInfo {
    ConnInfo {
        peer: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
        sni: None,
        alpn: None,
        tls,
        established: UNIX_EPOCH,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A tnetstring whose length prefix overflows `usize` must be rejected, not
    /// used to index past the buffer. `18446744073709551615` is `u64::MAX`.
    #[test]
    fn oversized_length_prefix_is_rejected() {
        let err = mitmproxy_to_flows(b"18446744073709551615:x,").unwrap_err();
        assert!(
            err.to_string().contains("mitmproxy")
                || err.chain().any(|e| e.to_string().contains("overruns")),
            "an overflowing length prefix must error, got: {err:#}"
        );
    }

    /// A length one byte past the buffer (no room for the trailing type byte) is a
    /// truncated payload: it must error rather than slice out of bounds.
    #[test]
    fn length_one_past_buffer_is_rejected() {
        // `5:abcd,` claims a 5-byte payload but only `abcd` (4) precedes the type
        // byte, so the payload would run onto the `,` and the type byte off the end.
        assert!(pop(b"5:abcd,", 0).is_err());
        assert!(mitmproxy_to_flows(b"5:abcd,").is_err());
    }

    /// Build `levels` of nested empty lists as a single tnetstring blob.
    fn nested_lists(levels: usize) -> Vec<u8> {
        let mut s = String::from("0:]"); // one empty list
        for _ in 0..levels {
            s = format!("{}:{}]", s.len(), s);
        }
        s.into_bytes()
    }

    /// A shallow blob parses; one nested past the depth cap returns `Err` instead
    /// of recursing until the stack overflows.
    #[test]
    fn deeply_nested_input_is_rejected() {
        // A handful of levels is fine (and maps to no HTTP flow, so an empty Vec).
        assert!(mitmproxy_to_flows(&nested_lists(5)).is_ok());
        // Well past MAX_DEPTH: refused, no panic, no stack overflow.
        let err = mitmproxy_to_flows(&nested_lists(MAX_DEPTH + 8)).unwrap_err();
        assert!(
            err.chain().any(|e| e.to_string().contains("depth")),
            "a too-deeply-nested blob must error on the depth cap, got: {err:#}"
        );
    }

    /// An out-of-range response status is a corrupt flow: it must error rather than
    /// silently truncating via `as u16` (70000 would wrap to 4464).
    #[test]
    fn out_of_range_status_is_rejected() {
        let resp = Tns::Dict(vec![("status_code".to_string(), Tns::Int(70_000))]);
        assert!(mitm_response(&resp).is_err());

        let ok = Tns::Dict(vec![("status_code".to_string(), Tns::Int(200))]);
        assert_eq!(mitm_response(&ok).expect("200 parses").status, 200);
    }
}
