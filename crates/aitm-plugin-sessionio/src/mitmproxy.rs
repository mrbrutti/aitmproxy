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

/// Import every HTTP flow from a mitmproxy `.flows` byte blob.
pub fn mitmproxy_to_flows(bytes: &[u8]) -> anyhow::Result<Vec<Flow>> {
    let mut out = Vec::new();
    let mut data = bytes;
    while !data.is_empty() {
        let (value, rest) = pop(data).context("decoding mitmproxy .flows stream")?;
        data = rest;
        if let Some(flow) = flow_from_state(&value)? {
            out.push(flow);
        }
    }
    Ok(out)
}

/// Pop one tnetstring off the front, returning it and the remaining bytes.
fn pop(data: &[u8]) -> anyhow::Result<(Tns, &[u8])> {
    let colon = data
        .iter()
        .position(|&b| b == b':')
        .context("tnetstring: missing length prefix")?;
    let len: usize = std::str::from_utf8(&data[..colon])
        .ok()
        .and_then(|s| s.parse().ok())
        .context("tnetstring: invalid length prefix")?;
    let payload_start = colon + 1;
    let payload_end = payload_start + len;
    ensure!(data.len() > payload_end, "tnetstring: truncated payload");
    let payload = &data[payload_start..payload_end];
    let type_byte = data[payload_end];
    let value = parse(type_byte, payload)?;
    Ok((value, &data[payload_end + 1..]))
}

fn parse(type_byte: u8, payload: &[u8]) -> anyhow::Result<Tns> {
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
                let (item, next) = pop(rest)?;
                items.push(item);
                rest = next;
            }
            Tns::List(items)
        }
        b'}' => {
            let mut kvs = Vec::new();
            let mut rest = payload;
            while !rest.is_empty() {
                let (key, next) = pop(rest)?;
                let (val, next) = pop(next)?;
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
    Ok(HttpResponse {
        status: status as u16,
        version: mitm_version(r),
        headers: mitm_headers(r),
        body: mitm_body(r),
        timestamp: UNIX_EPOCH,
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
