//! `/ws` WebSocket seed (spec D4): RFC 6455 server codec and handshake
//! primitives (Task A4), the upgrade handler, frame loop and `/log/ws`
//! logging (Task A17).
//!
//! The codec is pure: bytes in, bytes or a verdict out. The server side of
//! RFC 6455 is deliberately strict: a client frame without a mask is a
//! protocol error (`Decoded::Unmasked`, close `1002`), a declared payload above
//! [`MAX_FRAME`] is refused before any payload byte is read
//! (`Decoded::Oversize`, close `1009`), and a reserved opcode or RSV bit is
//! `Decoded::Malformed`. No `unwrap`/`expect` touches wire bytes.
//!
//! The handshake is checked in the D4 order: key and version (400), HTTP/1.1
//! only (400 over h2), `Origin` (403 in P), the login cookie (401 in P), the
//! subprotocol echo (V only). Every outcome writes a `handshake` entry; the
//! accepted connection's frames are logged in both directions and the loop's
//! end writes a `close` entry and stamps the connection closed (the 101 marks
//! the connection upgraded, so the listener's own close after hyper hands
//! the socket off does not stamp it first).

use std::sync::Arc;

use base64::Engine as _;
use bytes::Bytes;
use http_body_util::Full;
use hyper::header::HeaderValue;
use hyper::{Response, StatusCode};
use hyper_util::rt::TokioIo;
use sha1::{Digest as _, Sha1};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};

use crate::app::{html, html_escape, AppState, RequestInfo, Resp};
use crate::log::{
    sha256_hex, ConnInfo, Dir, WsCloseEntry, WsFrameEntry, WsHandshakeEntry, WsLogEntry, WsOpcode,
};
use crate::seed::{SeedMode, SESSION_USER};

/// Largest payload (bytes) a single client frame may declare.
pub(crate) const MAX_FRAME: u64 = 1_048_576;

/// RFC 6455 section 1.3 handshake GUID.
const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// The `{"type":"error","error":"bad message"}` reply for anything that is
/// not an `echo`/`chat` message (spec D4, Echo row).
const BAD_MESSAGE: &str = r#"{"type":"error","error":"bad message"}"#;

/// RFC 6455 section 5.2 opcodes (the six defined ones; the rest are reserved).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Opcode {
    Continuation,
    Text,
    Binary,
    Close,
    Ping,
    Pong,
}

impl Opcode {
    pub(crate) fn from_u8(v: u8) -> Option<Opcode> {
        match v {
            0x0 => Some(Opcode::Continuation),
            0x1 => Some(Opcode::Text),
            0x2 => Some(Opcode::Binary),
            0x8 => Some(Opcode::Close),
            0x9 => Some(Opcode::Ping),
            0xA => Some(Opcode::Pong),
            _ => None,
        }
    }

    fn to_u8(self) -> u8 {
        match self {
            Opcode::Continuation => 0x0,
            Opcode::Text => 0x1,
            Opcode::Binary => 0x2,
            Opcode::Close => 0x8,
            Opcode::Ping => 0x9,
            Opcode::Pong => 0xA,
        }
    }

    /// Lower-case wire token (the `frame` log entry serialises
    /// [`WsOpcode`] instead; kept for callers that print opcodes).
    #[allow(dead_code)] // only the `opcode_table` unit test calls it
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            Opcode::Continuation => "continuation",
            Opcode::Text => "text",
            Opcode::Binary => "binary",
            Opcode::Close => "close",
            Opcode::Ping => "ping",
            Opcode::Pong => "pong",
        }
    }
}

/// One decoded (and unmasked) frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Frame {
    pub fin: bool,
    pub opcode: Opcode,
    pub payload: Vec<u8>,
}

/// Verdict of [`decode_frame`] on the front of a receive buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Decoded {
    /// A complete frame; `consumed` bytes may be drained from the buffer.
    Frame { frame: Frame, consumed: usize },
    /// Not enough bytes yet; read more.
    Incomplete,
    /// The header declares more than [`MAX_FRAME`] payload bytes (close 1009).
    Oversize { declared: u64 },
    /// A client frame arrived without the mask bit (close 1002).
    Unmasked,
    /// Reserved opcode, RSV bits set, or an invalid length encoding.
    Malformed,
}

/// Decode the frame at the front of `buf` as a server (client frames must be
/// masked). The length is validated against [`MAX_FRAME`] before any payload
/// byte is required, so an oversize declaration is refused on the header alone.
pub(crate) fn decode_frame(buf: &[u8]) -> Decoded {
    let (Some(&b0), Some(&b1)) = (buf.first(), buf.get(1)) else {
        return Decoded::Incomplete;
    };
    if b0 & 0x70 != 0 {
        return Decoded::Malformed;
    }
    let fin = b0 & 0x80 != 0;
    let Some(opcode) = Opcode::from_u8(b0 & 0x0f) else {
        return Decoded::Malformed;
    };
    let masked = b1 & 0x80 != 0;
    let len7 = b1 & 0x7f;
    let (declared, mut pos): (u64, usize) = match len7 {
        126 => {
            let Some(bytes) = buf.get(2..4) else {
                return Decoded::Incomplete;
            };
            let v = u16::from_be_bytes([bytes[0], bytes[1]]);
            (u64::from(v), 4)
        }
        127 => {
            let Some(bytes) = buf.get(2..10) else {
                return Decoded::Incomplete;
            };
            let mut raw = [0u8; 8];
            raw.copy_from_slice(bytes);
            let v = u64::from_be_bytes(raw);
            if v & (1 << 63) != 0 {
                // RFC 6455 section 5.2: the most significant bit must be 0.
                return Decoded::Malformed;
            }
            (v, 10)
        }
        n => (u64::from(n), 2),
    };
    if declared > MAX_FRAME {
        return Decoded::Oversize { declared };
    }
    if !masked {
        return Decoded::Unmasked;
    }
    let Some(key) = buf.get(pos..pos + 4) else {
        return Decoded::Incomplete;
    };
    let mask = [key[0], key[1], key[2], key[3]];
    pos += 4;
    // `declared <= MAX_FRAME` so this cannot truncate on any supported target.
    let len = declared as usize;
    let Some(masked_payload) = buf.get(pos..pos + len) else {
        return Decoded::Incomplete;
    };
    let payload: Vec<u8> = masked_payload
        .iter()
        .enumerate()
        .map(|(i, b)| b ^ mask[i % 4])
        .collect();
    Decoded::Frame {
        frame: Frame {
            fin,
            opcode,
            payload,
        },
        consumed: pos + len,
    }
}

/// Encode one unmasked, FIN server frame with a 7-, 16- or 64-bit length.
pub(crate) fn encode_frame(opcode: Opcode, payload: &[u8]) -> Vec<u8> {
    let len = payload.len();
    let mut out = Vec::with_capacity(10 + len);
    out.push(0x80 | opcode.to_u8());
    if len < 126 {
        // `len < 126` fits a byte.
        out.push(len as u8);
    } else if len <= usize::from(u16::MAX) {
        out.push(126);
        // Bounded by the branch condition.
        out.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        out.push(127);
        out.extend_from_slice(&(len as u64).to_be_bytes());
    }
    out.extend_from_slice(payload);
    out
}

/// A close frame carrying only the two-byte status code.
pub(crate) fn close_frame(code: u16) -> Vec<u8> {
    encode_frame(Opcode::Close, &code.to_be_bytes())
}

/// `Sec-WebSocket-Accept` for a `Sec-WebSocket-Key` (RFC 6455 section 4.2.2).
pub(crate) fn accept_key(key: &str) -> String {
    let mut hasher = Sha1::new();
    hasher.update(key.as_bytes());
    hasher.update(WS_GUID.as_bytes());
    base64::engine::general_purpose::STANDARD.encode(hasher.finalize())
}

/// D4 handshake rule: V accepts any `Origin`; P accepts an absent `Origin` or
/// one byte-equal to `<scheme>://<Host header>`.
pub(crate) fn origin_allowed(
    mode: SeedMode,
    origin: Option<&str>,
    scheme: &str,
    host: &str,
) -> bool {
    match (mode, origin) {
        (SeedMode::Vulnerable, _) | (SeedMode::Patched, None) => true,
        (SeedMode::Patched, Some(o)) => o == format!("{scheme}://{host}"),
    }
}

/// D4 echo rule. `{"type":T,"msg":M}` with `T` in `echo`/`chat` becomes
/// `{"type":T,"msg":M',"html":"<b>M'</b>"}`; `M'` is `M` raw in V and
/// HTML-escaped in P. Anything else is the `bad message` error JSON.
pub(crate) fn echo_reply(mode: SeedMode, text: &str) -> String {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(text) else {
        return BAD_MESSAGE.to_string();
    };
    let (Some(kind), Some(msg)) = (
        value.get("type").and_then(serde_json::Value::as_str),
        value.get("msg").and_then(serde_json::Value::as_str),
    ) else {
        return BAD_MESSAGE.to_string();
    };
    if kind != "echo" && kind != "chat" {
        return BAD_MESSAGE.to_string();
    }
    let shown = match mode {
        SeedMode::Vulnerable => msg.to_string(),
        SeedMode::Patched => html_escape(msg),
    };
    // Key order is the spec's `type, msg, html`; `serde_json::Value::String`'s
    // `Display` is the JSON string escaping and cannot fail.
    let quoted = |s: &str| serde_json::Value::String(s.to_string()).to_string();
    format!(
        r#"{{"type":{},"msg":{},"html":{}}}"#,
        quoted(kind),
        quoted(&shown),
        quoted(&format!("<b>{shown}</b>"))
    )
}

/// D4 subprotocol rule: V echoes the first comma-separated token (trimmed)
/// of `Sec-WebSocket-Protocol`; P never answers with the header.
pub(crate) fn subprotocol_reply(mode: SeedMode, requested: Option<&str>) -> Option<String> {
    match mode {
        SeedMode::Patched => None,
        SeedMode::Vulnerable => requested
            .and_then(|r| r.split(',').next())
            .map(str::trim)
            .filter(|t| !t.is_empty())
            .map(str::to_string),
    }
}

/// Initial receive buffer; it grows as a frame needs, up to [`MAX_BUFFER`].
const READ_CHUNK: usize = 64 * 1024;

/// Largest receive buffer: one [`MAX_FRAME`] payload plus the longest header
/// (2 bytes, 8-byte extended length, 4-byte mask).
const MAX_BUFFER: usize = MAX_FRAME as usize + 14;

/// Answer a `/ws` request: the handshake (D4), then the frame loop on the
/// upgraded connection, spawned on the runtime. The response carries the
/// handshake verdict; the loop logs the rest.
pub(crate) fn serve_upgrade(
    info: &RequestInfo,
    on_upgrade: hyper::upgrade::OnUpgrade,
    state: Arc<AppState>,
) -> Resp {
    let mode = state.mode;
    let key = info.header("sec-websocket-key").map(str::trim);
    let version = info.header("sec-websocket-version").map(str::trim);
    let origin = info.header("origin");
    let session_valid = info
        .cookie("session")
        .is_some_and(|s| state.sessions.is_valid(s));
    let cookie_names = crate::log::redact_headers(&info.headers).cookie_names;

    let verdict = handshake_verdict(
        mode,
        key,
        version,
        info.conn.alpn.as_deref(),
        origin,
        info.scheme,
        &info.host,
        session_valid,
        info.header("sec-websocket-protocol"),
    );

    let (status, accepted, subprotocol) = match &verdict {
        Ok(accept) => (
            StatusCode::SWITCHING_PROTOCOLS,
            true,
            accept.subprotocol.clone(),
        ),
        Err((status, _)) => (*status, false, None),
    };
    state.log.log_ws(WsLogEntry::Handshake(WsHandshakeEntry {
        seq: 0,
        ts_ms: 0,
        conn_id: info.conn.conn_id.clone(),
        listener: info.conn.listener,
        path: info.path.clone(),
        origin: origin.map(str::to_string),
        sec_websocket_key: key.unwrap_or_default().to_string(),
        cookie_names,
        session_valid,
        accepted,
        status: status.as_u16(),
        subprotocol: subprotocol.clone(),
    }));

    let accept = match verdict {
        Ok(accept) => accept,
        Err((status, body)) => return html(status, body.to_string()),
    };
    // From here the connection belongs to the frame loop: the listener's
    // close right after this 101 must not stamp it (see `finish`).
    info.conn.mark_upgraded();

    let mut resp = Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header("upgrade", "websocket")
        .header("connection", "Upgrade")
        .body(Full::new(Bytes::new()))
        .expect("valid response");
    // The accept key is base64 (always a valid header value); the subprotocol
    // token came off the client's header, so a value hyper refuses is dropped
    // rather than trusted.
    if let Ok(v) = HeaderValue::from_str(&accept.accept_key) {
        resp.headers_mut().insert("sec-websocket-accept", v);
    }
    if let Some(v) = subprotocol
        .as_deref()
        .and_then(|s| HeaderValue::from_str(s).ok())
    {
        resp.headers_mut().insert("sec-websocket-protocol", v);
    }

    let conn = info.conn.clone();
    tokio::spawn(async move {
        match on_upgrade.await {
            Ok(upgraded) => {
                run_frames(TokioIo::new(upgraded), state, conn, session_valid).await;
            }
            // The client went away between the 101 and the handoff: there is
            // no loop to run, but the connection is still over.
            Err(_) => finish(&state, &conn, None),
        }
    });
    resp
}

/// What an accepted handshake answers with.
struct Accepted {
    accept_key: String,
    subprotocol: Option<String>,
}

/// The D4 handshake decision, in order: key + version 13 (400), h1 only
/// (400 over h2), `Origin` (403), login (401 in P), then the subprotocol echo.
#[allow(clippy::too_many_arguments)]
fn handshake_verdict(
    mode: SeedMode,
    key: Option<&str>,
    version: Option<&str>,
    alpn: Option<&str>,
    origin: Option<&str>,
    scheme: &str,
    host: &str,
    session_valid: bool,
    requested_protocol: Option<&str>,
) -> Result<Accepted, (StatusCode, &'static str)> {
    let key = match (key, version) {
        (Some(k), Some("13")) if !k.is_empty() => k,
        _ => return Err((StatusCode::BAD_REQUEST, "bad websocket handshake")),
    };
    if alpn == Some("h2") {
        return Err((StatusCode::BAD_REQUEST, "websocket requires HTTP/1.1"));
    }
    if !origin_allowed(mode, origin, scheme, host) {
        return Err((StatusCode::FORBIDDEN, "<p>forbidden origin</p>"));
    }
    if mode == SeedMode::Patched && !session_valid {
        return Err((StatusCode::UNAUTHORIZED, "<p>login required</p>"));
    }
    Ok(Accepted {
        accept_key: accept_key(key),
        subprotocol: subprotocol_reply(mode, requested_protocol),
    })
}

/// Drive one upgraded connection: send the hello frame, then decode and
/// answer client frames until a close, a protocol error, EOF or an I/O error.
/// Every frame in both directions is logged; when the loop ends a `close`
/// entry is written and the connection is stamped closed. Returns the close
/// code sent or echoed (`None` when the socket simply ended).
pub(crate) async fn run_frames<IO>(
    mut io: IO,
    state: Arc<AppState>,
    conn: Arc<ConnInfo>,
    session_valid: bool,
) -> Option<u16>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let code = frame_loop(&mut io, &state, &conn, session_valid).await;
    finish(&state, &conn, code);
    code
}

/// Log the `close` entry and stamp the connection closed. This is the only
/// closer of an upgraded connection: the listener's `close_conn` right after
/// the 101 is a no-op once `serve_upgrade` marked the connection upgraded.
fn finish(state: &AppState, conn: &ConnInfo, code: Option<u16>) {
    state.log.log_ws(WsLogEntry::Close(WsCloseEntry {
        seq: 0,
        ts_ms: 0,
        conn_id: conn.conn_id.clone(),
        code,
    }));
    state.log.close_conn_upgraded(conn);
}

/// What the loop does after handling one decoded frame.
enum Next {
    Continue,
    End(Option<u16>),
}

async fn frame_loop<IO>(
    io: &mut IO,
    state: &AppState,
    conn: &ConnInfo,
    session_valid: bool,
) -> Option<u16>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let mode = state.mode;
    let user = if session_valid {
        SESSION_USER
    } else {
        "anonymous"
    };
    let hello = format!(r#"{{"type":"hello","user":"{user}"}}"#);
    if !send(io, state, conn, Opcode::Text, hello.as_bytes()).await {
        return None;
    }

    let mut buf: Vec<u8> = Vec::with_capacity(READ_CHUNK);
    let mut chunk = vec![0u8; READ_CHUNK];
    loop {
        // Handle every complete frame at the front of the buffer, then drain
        // them all at once (one memmove per read, not one per frame).
        let mut consumed_total = 0usize;
        loop {
            match decode_frame(buf.get(consumed_total..).unwrap_or(&[])) {
                Decoded::Incomplete => break,
                Decoded::Frame { frame, consumed } => {
                    consumed_total += consumed;
                    match handle_frame(io, state, conn, mode, frame).await {
                        Next::Continue => {}
                        Next::End(code) => return code,
                    }
                }
                Decoded::Oversize { .. } => return close_with(io, state, conn, 1009).await,
                Decoded::Unmasked | Decoded::Malformed => {
                    return close_with(io, state, conn, 1002).await;
                }
            }
        }
        buf.drain(..consumed_total.min(buf.len()));
        // A frame within MAX_FRAME always fits MAX_BUFFER, so a full buffer
        // that still decodes as Incomplete cannot be honoured.
        let room = MAX_BUFFER.saturating_sub(buf.len());
        if room == 0 {
            return close_with(io, state, conn, 1009).await;
        }
        let want = room.min(chunk.len());
        match io.read(&mut chunk[..want]).await {
            Ok(0) | Err(_) => return None,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }
}

/// Answer one decoded client frame (D4 Echo and Control rows).
async fn handle_frame<IO>(
    io: &mut IO,
    state: &AppState,
    conn: &ConnInfo,
    mode: SeedMode,
    frame: Frame,
) -> Next
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    log_frame(state, conn, Dir::In, frame.opcode, &frame.payload);
    match frame.opcode {
        // Fragmented messages are not supported: a continuation, or a data
        // frame that announces one, is refused with 1003.
        Opcode::Continuation => Next::End(close_with(io, state, conn, 1003).await),
        Opcode::Text | Opcode::Binary if !frame.fin => {
            Next::End(close_with(io, state, conn, 1003).await)
        }
        Opcode::Text => {
            let text = String::from_utf8_lossy(&frame.payload);
            let reply = echo_reply(mode, &text);
            continue_if(send(io, state, conn, Opcode::Text, reply.as_bytes()).await)
        }
        Opcode::Binary => continue_if(send(io, state, conn, Opcode::Binary, &frame.payload).await),
        Opcode::Ping => continue_if(send(io, state, conn, Opcode::Pong, &frame.payload).await),
        Opcode::Pong => Next::Continue,
        Opcode::Close => {
            let code = frame
                .payload
                .get(..2)
                .map(|c| u16::from_be_bytes([c[0], c[1]]));
            send(io, state, conn, Opcode::Close, &frame.payload).await;
            Next::End(code)
        }
    }
}

fn continue_if(sent: bool) -> Next {
    if sent {
        Next::Continue
    } else {
        Next::End(None)
    }
}

/// Send a close frame with `code` and report it as the loop's close code.
async fn close_with<IO>(io: &mut IO, state: &AppState, conn: &ConnInfo, code: u16) -> Option<u16>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    if write_wire(io, &close_frame(code)).await {
        log_frame(state, conn, Dir::Out, Opcode::Close, &code.to_be_bytes());
    }
    Some(code)
}

/// Write one server frame and log it; `false` when the socket refused it.
async fn send<IO>(
    io: &mut IO,
    state: &AppState,
    conn: &ConnInfo,
    opcode: Opcode,
    payload: &[u8],
) -> bool
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let ok = write_wire(io, &encode_frame(opcode, payload)).await;
    if ok {
        log_frame(state, conn, Dir::Out, opcode, payload);
    }
    ok
}

async fn write_wire<IO>(io: &mut IO, wire: &[u8]) -> bool
where
    IO: AsyncWrite + Unpin,
{
    io.write_all(wire).await.is_ok() && io.flush().await.is_ok()
}

fn log_frame(state: &AppState, conn: &ConnInfo, dir: Dir, opcode: Opcode, payload: &[u8]) {
    // `WsOpcode` has no continuation variant (D2 lists text|binary|ping|pong|
    // close); the refusing close frame that follows is logged instead.
    let opcode = match opcode {
        Opcode::Text => WsOpcode::Text,
        Opcode::Binary => WsOpcode::Binary,
        Opcode::Ping => WsOpcode::Ping,
        Opcode::Pong => WsOpcode::Pong,
        Opcode::Close => WsOpcode::Close,
        Opcode::Continuation => return,
    };
    state.log.log_ws(WsLogEntry::Frame(WsFrameEntry {
        seq: 0,
        ts_ms: 0,
        conn_id: conn.conn_id.clone(),
        dir,
        opcode,
        len: payload.len(),
        sha256: sha256_hex(payload),
    }));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seed::SeedMode::{Patched, Vulnerable};

    #[test]
    fn accept_key_rfc_vector() {
        assert_eq!(
            accept_key("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }

    #[test]
    fn decode_masked_text() {
        // RFC 6455 section 5.7: a single-frame masked text message "Hello".
        let wire = [
            0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58,
        ];
        match decode_frame(&wire) {
            Decoded::Frame { frame, consumed } => {
                assert!(frame.fin);
                assert_eq!(frame.opcode, Opcode::Text);
                assert_eq!(frame.payload, b"Hello");
                assert_eq!(consumed, 11);
            }
            other => panic!("expected Frame, got {other:?}"),
        }
        // A truncated copy is Incomplete, not an error.
        assert!(matches!(decode_frame(&wire[..7]), Decoded::Incomplete));
        assert!(matches!(decode_frame(&[]), Decoded::Incomplete));
    }

    #[test]
    fn unmasked_client_frame_is_refused() {
        let wire = [0x81, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f];
        assert!(matches!(decode_frame(&wire), Decoded::Unmasked));
    }

    #[test]
    fn oversize_declared_length() {
        // FIN|Binary, MASK|127, 64-bit length 1_048_577, mask key; no payload bytes.
        let declared: u64 = 1_048_577;
        let mut wire = vec![0x82, 0x80 | 127];
        wire.extend_from_slice(&declared.to_be_bytes());
        wire.extend_from_slice(&[1, 2, 3, 4]);
        match decode_frame(&wire) {
            Decoded::Oversize { declared: d } => assert_eq!(d, 1_048_577),
            other => panic!("expected Oversize, got {other:?}"),
        }
        // Exactly MAX_FRAME is not oversize; with no payload present it is Incomplete.
        let mut ok = vec![0x82, 0x80 | 127];
        ok.extend_from_slice(&MAX_FRAME.to_be_bytes());
        ok.extend_from_slice(&[1, 2, 3, 4]);
        assert!(matches!(decode_frame(&ok), Decoded::Incomplete));
    }

    #[test]
    fn encode_roundtrip_lengths() {
        let small = encode_frame(Opcode::Text, &[b'a'; 125]);
        assert_eq!(&small[..2], &[0x81, 125]);
        assert_eq!(small.len(), 2 + 125);

        let medium = encode_frame(Opcode::Text, &[b'a'; 126]);
        assert_eq!(&medium[..4], &[0x81, 126, 0x00, 0x7e]);
        assert_eq!(medium.len(), 4 + 126);

        let large = encode_frame(Opcode::Text, &[b'a'; 65_536]);
        assert_eq!(&large[..10], &[0x81, 127, 0, 0, 0, 0, 0, 1, 0, 0]);
        assert_eq!(large.len(), 10 + 65_536);

        // Server frames are unmasked, so the codec refuses its own output as a
        // client frame; the plain header + payload must still be what we encoded.
        assert_eq!(&small[2..], &[b'a'; 125]);
        assert!(matches!(decode_frame(&small), Decoded::Unmasked));

        let close = close_frame(1009);
        assert_eq!(close, vec![0x88, 0x02, 0x03, 0xf1]);
    }

    #[test]
    fn opcode_table() {
        assert_eq!(Opcode::from_u8(0x0), Some(Opcode::Continuation));
        assert_eq!(Opcode::from_u8(0x1), Some(Opcode::Text));
        assert_eq!(Opcode::from_u8(0x2), Some(Opcode::Binary));
        assert_eq!(Opcode::from_u8(0x8), Some(Opcode::Close));
        assert_eq!(Opcode::from_u8(0x9), Some(Opcode::Ping));
        assert_eq!(Opcode::from_u8(0xA), Some(Opcode::Pong));
        assert_eq!(Opcode::from_u8(0x3), None);
        assert_eq!(Opcode::from_u8(0xB), None);
        assert_eq!(Opcode::Text.as_str(), "text");
        assert_eq!(Opcode::Binary.as_str(), "binary");
        assert_eq!(Opcode::Close.as_str(), "close");
        assert_eq!(Opcode::Ping.as_str(), "ping");
        assert_eq!(Opcode::Pong.as_str(), "pong");
        assert_eq!(Opcode::Continuation.as_str(), "continuation");
        // A reserved opcode on the wire is Malformed, not a panic.
        let wire = [0x83, 0x80, 1, 2, 3, 4];
        assert!(matches!(decode_frame(&wire), Decoded::Malformed));
    }

    #[test]
    fn origin_rule() {
        assert!(!origin_allowed(
            Patched,
            Some("http://127.0.0.1:8/"),
            "http",
            "127.0.0.1:8"
        ));
        assert!(origin_allowed(
            Patched,
            Some("http://127.0.0.1:8"),
            "http",
            "127.0.0.1:8"
        ));
        assert!(origin_allowed(Patched, None, "http", "127.0.0.1:8"));
        assert!(!origin_allowed(
            Patched,
            Some("http://evil.example"),
            "http",
            "127.0.0.1:8"
        ));
        assert!(origin_allowed(
            Vulnerable,
            Some("http://evil.example"),
            "http",
            "127.0.0.1:8"
        ));
        assert!(origin_allowed(
            Patched,
            Some("https://127.0.0.1:8"),
            "https",
            "127.0.0.1:8"
        ));
    }

    #[test]
    fn echo_reply_modes() {
        assert_eq!(
            echo_reply(Vulnerable, r#"{"type":"echo","msg":"<i>"}"#),
            r#"{"type":"echo","msg":"<i>","html":"<b><i></b>"}"#
        );
        assert_eq!(
            echo_reply(Vulnerable, r#"{"type":"chat","msg":"<i>"}"#),
            r#"{"type":"chat","msg":"<i>","html":"<b><i></b>"}"#
        );
        assert_eq!(
            echo_reply(Patched, r#"{"type":"chat","msg":"<i>"}"#),
            r#"{"type":"chat","msg":"&lt;i&gt;","html":"<b>&lt;i&gt;</b>"}"#
        );
        assert_eq!(
            echo_reply(Patched, r#"{"type":"echo","msg":"<i>"}"#),
            r#"{"type":"echo","msg":"&lt;i&gt;","html":"<b>&lt;i&gt;</b>"}"#
        );
        // Every HTML metacharacter is escaped in P; serde_json escapes the quote
        // in V so the reply is still valid JSON.
        assert_eq!(
            echo_reply(Patched, r#"{"type":"echo","msg":"&<>\"'"}"#),
            r#"{"type":"echo","msg":"&amp;&lt;&gt;&quot;&#x27;","html":"<b>&amp;&lt;&gt;&quot;&#x27;</b>"}"#
        );
        assert_eq!(
            echo_reply(Vulnerable, r#"{"type":"echo","msg":"a\"b"}"#),
            r#"{"type":"echo","msg":"a\"b","html":"<b>a\"b</b>"}"#
        );
        let bad = r#"{"type":"error","error":"bad message"}"#;
        assert_eq!(echo_reply(Vulnerable, "nope"), bad);
        assert_eq!(echo_reply(Patched, "nope"), bad);
        // Other JSON: wrong type, missing msg, non-string msg, non-object.
        assert_eq!(echo_reply(Vulnerable, r#"{"type":"hello","msg":"x"}"#), bad);
        assert_eq!(echo_reply(Vulnerable, r#"{"type":"echo"}"#), bad);
        assert_eq!(echo_reply(Vulnerable, r#"{"type":"echo","msg":7}"#), bad);
        assert_eq!(echo_reply(Vulnerable, r#"["echo"]"#), bad);
    }

    #[test]
    fn subprotocol_rule() {
        assert_eq!(
            subprotocol_reply(Vulnerable, Some("chat, json")),
            Some("chat".to_string())
        );
        assert_eq!(
            subprotocol_reply(Vulnerable, Some("  soap ")),
            Some("soap".to_string())
        );
        assert_eq!(subprotocol_reply(Vulnerable, Some("")), None);
        assert_eq!(subprotocol_reply(Vulnerable, Some(" , chat")), None);
        assert_eq!(subprotocol_reply(Vulnerable, None), None);
        assert_eq!(subprotocol_reply(Patched, Some("chat")), None);
        assert_eq!(subprotocol_reply(Patched, None), None);
    }

    // --- A17: handshake and frame loop -------------------------------------

    use http_body_util::BodyExt as _;

    use crate::log::{ControlLog, Listener};

    const RFC_KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";
    const RFC_ACCEPT: &str = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";

    fn state(mode: SeedMode) -> Arc<AppState> {
        Arc::new(AppState::new(mode, ControlLog::new(mode)))
    }

    /// An `OnUpgrade` for a request that is never upgraded: its future errors
    /// at once, so the spawned loop ends without a socket.
    fn never_upgraded() -> hyper::upgrade::OnUpgrade {
        let mut req = hyper::Request::new(Full::new(Bytes::new()));
        hyper::upgrade::on(&mut req)
    }

    fn ws_request(extra: &[(&str, &str)]) -> RequestInfo {
        let mut headers = vec![
            ("host", "127.0.0.1:1"),
            ("upgrade", "websocket"),
            ("connection", "Upgrade"),
            ("sec-websocket-key", RFC_KEY),
            ("sec-websocket-version", "13"),
        ];
        headers.extend_from_slice(extra);
        RequestInfo::test_request("GET", "/ws", &headers, b"")
    }

    fn header<'a>(resp: &'a crate::app::Resp, name: &str) -> Option<&'a str> {
        resp.headers().get(name).and_then(|v| v.to_str().ok())
    }

    async fn body_text(resp: crate::app::Resp) -> String {
        let bytes = resp
            .into_body()
            .collect()
            .await
            .expect("Full body")
            .to_bytes();
        String::from_utf8(bytes.to_vec()).expect("utf-8 body")
    }

    #[tokio::test]
    async fn handshake_response_shape() {
        // V accepts any Origin.
        let v = state(Vulnerable);
        let resp = serve_upgrade(
            &ws_request(&[("origin", "http://evil.example")]),
            never_upgraded(),
            v.clone(),
        );
        assert_eq!(resp.status().as_u16(), 101);
        assert_eq!(header(&resp, "sec-websocket-accept"), Some(RFC_ACCEPT));
        assert_eq!(header(&resp, "upgrade"), Some("websocket"));
        assert_eq!(header(&resp, "connection"), Some("Upgrade"));
        assert_eq!(header(&resp, "sec-websocket-protocol"), None);

        // P refuses a foreign Origin.
        let p = state(Patched);
        let resp = serve_upgrade(
            &ws_request(&[("origin", "http://evil.example")]),
            never_upgraded(),
            p.clone(),
        );
        assert_eq!(resp.status().as_u16(), 403);
        assert_eq!(body_text(resp).await, "<p>forbidden origin</p>");

        // P with a same-origin Origin but no session cookie.
        let resp = serve_upgrade(
            &ws_request(&[("origin", "http://127.0.0.1:1")]),
            never_upgraded(),
            p.clone(),
        );
        assert_eq!(resp.status().as_u16(), 401);
        assert_eq!(body_text(resp).await, "<p>login required</p>");

        // P with an absent Origin and no session: the origin rule passes,
        // the login rule does not.
        let resp = serve_upgrade(&ws_request(&[]), never_upgraded(), p.clone());
        assert_eq!(resp.status().as_u16(), 401);

        // P with a same-origin Origin and a live session upgrades, and never
        // answers with a subprotocol.
        let session = p.sessions.create(1);
        let cookie = format!("session={session}");
        let resp = serve_upgrade(
            &ws_request(&[
                ("origin", "http://127.0.0.1:1"),
                ("cookie", cookie.as_str()),
                ("sec-websocket-protocol", "chat, json"),
            ]),
            never_upgraded(),
            p.clone(),
        );
        assert_eq!(resp.status().as_u16(), 101);
        assert_eq!(header(&resp, "sec-websocket-accept"), Some(RFC_ACCEPT));
        assert_eq!(header(&resp, "sec-websocket-protocol"), None);
        let ws = p.log.ws_json();
        let last = ws["entries"]
            .as_array()
            .and_then(|e| {
                e.iter()
                    .rev()
                    .find(|e| e["kind"] == serde_json::json!("handshake"))
            })
            .cloned()
            .expect("handshake entry");
        assert_eq!(last["session_valid"], serde_json::json!(true));
        assert_eq!(last["cookie_names"], serde_json::json!(["session"]));

        // V echoes the first requested subprotocol.
        let resp = serve_upgrade(
            &ws_request(&[("sec-websocket-protocol", "chat, json")]),
            never_upgraded(),
            v.clone(),
        );
        assert_eq!(resp.status().as_u16(), 101);
        assert_eq!(header(&resp, "sec-websocket-protocol"), Some("chat"));

        // Missing key / wrong version are 400 in both modes.
        let no_key = RequestInfo::test_request(
            "GET",
            "/ws",
            &[
                ("host", "127.0.0.1:1"),
                ("upgrade", "websocket"),
                ("connection", "Upgrade"),
                ("sec-websocket-version", "13"),
            ],
            b"",
        );
        let resp = serve_upgrade(&no_key, never_upgraded(), v.clone());
        assert_eq!(resp.status().as_u16(), 400);
        let bad_version = RequestInfo::test_request(
            "GET",
            "/ws",
            &[
                ("host", "127.0.0.1:1"),
                ("upgrade", "websocket"),
                ("connection", "Upgrade"),
                ("sec-websocket-key", RFC_KEY),
                ("sec-websocket-version", "8"),
            ],
            b"",
        );
        let resp = serve_upgrade(&bad_version, never_upgraded(), p.clone());
        assert_eq!(resp.status().as_u16(), 400);

        // Over an h2 connection the upgrade is refused (D1 TLS row).
        let mut h2 = ws_request(&[]);
        h2.conn = ControlLog::new(Vulnerable).open_conn(
            Listener::Tls,
            Some("h2"),
            "127.0.0.1:2".parse().expect("peer"),
        );
        h2.scheme = "https";
        let resp = serve_upgrade(&h2, never_upgraded(), v.clone());
        assert_eq!(resp.status().as_u16(), 400);
        assert_eq!(body_text(resp).await, "websocket requires HTTP/1.1");
    }

    #[tokio::test]
    async fn handshake_is_logged() {
        let v = state(Vulnerable);
        let info = ws_request(&[
            ("origin", "http://evil.example"),
            ("cookie", "theme=dark; session=nope"),
        ]);
        let resp = serve_upgrade(&info, never_upgraded(), v.clone());
        assert_eq!(resp.status().as_u16(), 101);

        let ws = v.log.ws_json();
        let handshakes: Vec<&serde_json::Value> = ws["entries"]
            .as_array()
            .expect("entries")
            .iter()
            .filter(|e| e["kind"] == serde_json::json!("handshake"))
            .collect();
        assert_eq!(handshakes.len(), 1);
        let h = handshakes[0];
        assert_eq!(h["accepted"], serde_json::json!(true));
        assert_eq!(h["status"], serde_json::json!(101));
        assert_eq!(h["session_valid"], serde_json::json!(false));
        assert_eq!(h["origin"], serde_json::json!("http://evil.example"));
        assert_eq!(h["sec_websocket_key"], serde_json::json!(RFC_KEY));
        assert_eq!(h["cookie_names"], serde_json::json!(["session", "theme"]));
        assert_eq!(h["subprotocol"], serde_json::Value::Null);
        assert_eq!(h["path"], serde_json::json!("/ws"));
        assert_eq!(h["listener"], serde_json::json!("plain"));
        assert_eq!(h["conn_id"], serde_json::json!(info.conn.conn_id.clone()));
        assert_eq!(h["seq"], serde_json::json!(1));

        // A refused handshake is logged too, with its status.
        let p = state(Patched);
        let resp = serve_upgrade(
            &ws_request(&[("origin", "http://evil.example")]),
            never_upgraded(),
            p.clone(),
        );
        assert_eq!(resp.status().as_u16(), 403);
        let ws = p.log.ws_json();
        let h = &ws["entries"][0];
        assert_eq!(h["kind"], serde_json::json!("handshake"));
        assert_eq!(h["accepted"], serde_json::json!(false));
        assert_eq!(h["status"], serde_json::json!(403));
    }

    /// A client-side (masked) frame, for driving the loop over a duplex pipe.
    fn masked(opcode: Opcode, payload: &[u8]) -> Vec<u8> {
        let mask = [0x37, 0xfa, 0x21, 0x3d];
        let mut out = encode_frame(opcode, payload);
        let header_len = out.len() - payload.len();
        out[1] |= 0x80;
        let mut tail = Vec::with_capacity(4 + payload.len());
        tail.extend_from_slice(&mask);
        tail.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
        out.truncate(header_len);
        out.extend_from_slice(&tail);
        out
    }

    /// Read one server frame off the pipe (unmasked, payload < 64 KiB).
    async fn read_frame(io: &mut tokio::io::DuplexStream) -> (Opcode, Vec<u8>) {
        let mut head = [0u8; 2];
        io.read_exact(&mut head).await.expect("frame header");
        let opcode = Opcode::from_u8(head[0] & 0x0f).expect("opcode");
        let len = match head[1] & 0x7f {
            126 => {
                let mut ext = [0u8; 2];
                io.read_exact(&mut ext).await.expect("len16");
                usize::from(u16::from_be_bytes(ext))
            }
            n => usize::from(n),
        };
        let mut payload = vec![0u8; len];
        io.read_exact(&mut payload).await.expect("payload");
        (opcode, payload)
    }

    #[tokio::test]
    async fn frame_loop_hello_echo_ping_close() {
        let v = state(Vulnerable);
        let conn = v
            .log
            .open_conn(Listener::Plain, None, "127.0.0.1:3".parse().expect("peer"));
        let (server, mut client) = tokio::io::duplex(1 << 20);
        let task = tokio::spawn(run_frames(server, v.clone(), conn.clone(), false));

        let (op, hello) = read_frame(&mut client).await;
        assert_eq!(op, Opcode::Text);
        assert_eq!(hello, br#"{"type":"hello","user":"anonymous"}"#);

        client
            .write_all(&masked(Opcode::Text, br#"{"type":"chat","msg":"<i>"}"#))
            .await
            .expect("write text");
        let (op, echo) = read_frame(&mut client).await;
        assert_eq!(op, Opcode::Text);
        assert_eq!(echo, br#"{"type":"chat","msg":"<i>","html":"<b><i></b>"}"#);

        client
            .write_all(&masked(Opcode::Binary, &[0, 1, 2, 255]))
            .await
            .expect("write binary");
        let (op, bin) = read_frame(&mut client).await;
        assert_eq!(op, Opcode::Binary);
        assert_eq!(bin, vec![0, 1, 2, 255]);

        client
            .write_all(&masked(Opcode::Ping, b"hb"))
            .await
            .expect("write ping");
        let (op, pong) = read_frame(&mut client).await;
        assert_eq!(op, Opcode::Pong);
        assert_eq!(pong, b"hb");

        client
            .write_all(&masked(Opcode::Close, &1000u16.to_be_bytes()))
            .await
            .expect("write close");
        let (op, close) = read_frame(&mut client).await;
        assert_eq!(op, Opcode::Close);
        assert_eq!(close, vec![0x03, 0xe8]);

        assert_eq!(task.await.expect("loop task"), Some(1000));
    }

    #[tokio::test]
    async fn frame_loop_answers_two_frames_from_one_read() {
        // Two complete frames in one write (and so, typically, one read) are
        // both decoded and answered in order; the receive buffer is drained
        // once per read, not per frame.
        let v = state(Vulnerable);
        let conn = v
            .log
            .open_conn(Listener::Plain, None, "127.0.0.1:10".parse().expect("peer"));
        let (server, mut client) = tokio::io::duplex(1 << 20);
        let task = tokio::spawn(run_frames(server, v.clone(), conn.clone(), false));
        let _hello = read_frame(&mut client).await;
        let mut wire = masked(Opcode::Ping, b"one");
        wire.extend_from_slice(&masked(Opcode::Text, br#"{"type":"echo","msg":"two"}"#));
        wire.extend_from_slice(&masked(Opcode::Close, &1000u16.to_be_bytes()));
        client.write_all(&wire).await.expect("write three frames");
        let (op, pong) = read_frame(&mut client).await;
        assert_eq!((op, pong.as_slice()), (Opcode::Pong, &b"one"[..]));
        let (op, echo) = read_frame(&mut client).await;
        assert_eq!(op, Opcode::Text);
        assert_eq!(echo, br#"{"type":"echo","msg":"two","html":"<b>two</b>"}"#);
        let (op, close) = read_frame(&mut client).await;
        assert_eq!((op, close), (Opcode::Close, vec![0x03, 0xe8]));
        assert_eq!(task.await.expect("loop task"), Some(1000));
    }

    #[tokio::test]
    async fn frame_loop_refuses_oversize_unmasked_and_continuation() {
        for (wire, code) in [
            // Declared 1_048_577 bytes, no payload: close 1009 before reading it.
            (
                {
                    let mut w = vec![0x82, 0x80 | 127];
                    w.extend_from_slice(&1_048_577u64.to_be_bytes());
                    w.extend_from_slice(&[1, 2, 3, 4]);
                    w
                },
                1009u16,
            ),
            // Unmasked client frame: close 1002.
            (encode_frame(Opcode::Text, b"hi"), 1002),
            // Continuation frame: close 1003.
            (masked(Opcode::Continuation, b"frag"), 1003),
        ] {
            let v = state(Vulnerable);
            let conn = v
                .log
                .open_conn(Listener::Plain, None, "127.0.0.1:4".parse().expect("peer"));
            let (server, mut client) = tokio::io::duplex(1 << 20);
            let task = tokio::spawn(run_frames(server, v.clone(), conn.clone(), true));
            let (_, hello) = read_frame(&mut client).await;
            assert_eq!(hello, br#"{"type":"hello","user":"alice"}"#);
            client.write_all(&wire).await.expect("write");
            let (op, payload) = read_frame(&mut client).await;
            assert_eq!(op, Opcode::Close);
            assert_eq!(payload, code.to_be_bytes().to_vec());
            assert_eq!(task.await.expect("loop task"), Some(code));
        }
    }

    #[tokio::test]
    async fn upgraded_conn_closes_only_when_the_loop_ends() {
        let v = state(Vulnerable);
        // The 101 marks the connection upgraded; a refused handshake does not.
        let info = ws_request(&[]);
        assert!(!info.conn.is_upgraded());
        let resp = serve_upgrade(&info, never_upgraded(), v.clone());
        assert_eq!(resp.status().as_u16(), 101);
        assert!(info.conn.is_upgraded());
        let refused = RequestInfo::test_request("GET", "/ws", &[("host", "127.0.0.1:1")], b"");
        let resp = serve_upgrade(&refused, never_upgraded(), v.clone());
        assert_eq!(resp.status().as_u16(), 400);
        assert!(!refused.conn.is_upgraded());

        // hyper resolves `serve_h1` as soon as the upgrade is handed off, so
        // the listener stamps a close right after the 101: on an upgraded
        // connection that stamp must be a no-op until the frame loop ends.
        let conn = v
            .log
            .open_conn(Listener::Plain, None, "127.0.0.1:9".parse().expect("peer"));
        conn.mark_upgraded();
        v.log.close_conn(&conn);
        assert_eq!(*conn.closed_ms.lock().expect("closed_ms"), None);
        let (server, mut client) = tokio::io::duplex(1 << 20);
        let task = tokio::spawn(run_frames(server, v.clone(), conn.clone(), false));
        let _hello = read_frame(&mut client).await;
        v.log.close_conn(&conn);
        assert_eq!(*conn.closed_ms.lock().expect("closed_ms"), None);
        // (`test_request` mints its connections on its own log; this is the
        // only row on `v.log`.)
        let row = v.log.conns_json()["entries"][0].clone();
        assert_eq!(row["conn_id"], serde_json::json!(conn.conn_id.clone()));
        assert_eq!(row["closed_ms"], serde_json::Value::Null);
        client
            .write_all(&masked(Opcode::Close, &1000u16.to_be_bytes()))
            .await
            .expect("write close");
        let _close = read_frame(&mut client).await;
        assert_eq!(task.await.expect("loop task"), Some(1000));
        let closed = *conn.closed_ms.lock().expect("closed_ms");
        assert!(closed.is_some_and(|c| c >= conn.opened_ms), "{closed:?}");
        assert_eq!(
            v.log.conns_json()["entries"][0]["closed_ms"],
            serde_json::json!(closed)
        );
    }

    #[tokio::test]
    async fn frame_loop_logs_frames_close_and_closed_ms() {
        let v = state(Vulnerable);
        let conn = v
            .log
            .open_conn(Listener::Plain, None, "127.0.0.1:5".parse().expect("peer"));
        // The listener closes the connection as soon as hyper hands off the
        // upgrade; on an upgraded connection only the loop's end counts.
        conn.mark_upgraded();
        v.log.close_conn(&conn);
        assert_eq!(*conn.closed_ms.lock().expect("closed_ms"), None);

        let (server, mut client) = tokio::io::duplex(1 << 20);
        let task = tokio::spawn(run_frames(server, v.clone(), conn.clone(), false));
        let _hello = read_frame(&mut client).await;
        client
            .write_all(&masked(Opcode::Text, b"nope"))
            .await
            .expect("write text");
        let (_, reply) = read_frame(&mut client).await;
        assert_eq!(reply, br#"{"type":"error","error":"bad message"}"#);
        client
            .write_all(&masked(Opcode::Close, &1000u16.to_be_bytes()))
            .await
            .expect("write close");
        let _close = read_frame(&mut client).await;
        task.await.expect("loop task");

        let ws = v.log.ws_json();
        let kinds: Vec<(String, String, String, usize)> = ws["entries"]
            .as_array()
            .expect("entries")
            .iter()
            .map(|e| {
                (
                    e["kind"].as_str().unwrap_or("").to_string(),
                    e["dir"].as_str().unwrap_or("").to_string(),
                    e["opcode"].as_str().unwrap_or("").to_string(),
                    e["len"].as_u64().unwrap_or(0) as usize,
                )
            })
            .collect();
        let s =
            |a: &str, b: &str, c: &str, n: usize| (a.to_string(), b.to_string(), c.to_string(), n);
        assert_eq!(
            kinds,
            vec![
                s("frame", "out", "text", 35),
                s("frame", "in", "text", 4),
                s("frame", "out", "text", 38),
                s("frame", "in", "close", 2),
                s("frame", "out", "close", 2),
                s("close", "", "", 0),
            ]
        );
        let entries = ws["entries"].as_array().expect("entries");
        assert_eq!(
            entries[1]["sha256"],
            serde_json::json!(crate::log::sha256_hex(b"nope"))
        );
        assert_eq!(entries[5]["code"], serde_json::json!(1000));
        assert_eq!(
            entries[5]["conn_id"],
            serde_json::json!(conn.conn_id.clone())
        );

        let closed = *conn.closed_ms.lock().expect("closed_ms");
        assert!(closed.is_some_and(|c| c >= conn.opened_ms), "{closed:?}");
    }

    // --- Tester additions (stage 5): close without code, pong, fragments, EOF ---

    #[tokio::test]
    async fn frame_loop_close_without_code_pong_bad_utf8_and_fragments() {
        // A close with no payload echoes an empty close and reports no code;
        // an unsolicited pong is ignored; invalid UTF-8 text is `bad message`.
        let v = state(Vulnerable);
        let conn = v
            .log
            .open_conn(Listener::Plain, None, "127.0.0.1:6".parse().expect("peer"));
        let (server, mut client) = tokio::io::duplex(1 << 20);
        let task = tokio::spawn(run_frames(server, v.clone(), conn.clone(), false));
        let _hello = read_frame(&mut client).await;
        client
            .write_all(&masked(Opcode::Pong, b"late"))
            .await
            .expect("write pong");
        client
            .write_all(&masked(Opcode::Text, &[0xff, 0xfe]))
            .await
            .expect("write bad utf-8");
        let (op, reply) = read_frame(&mut client).await;
        assert_eq!(op, Opcode::Text);
        assert_eq!(reply, br#"{"type":"error","error":"bad message"}"#);
        client
            .write_all(&masked(Opcode::Close, b""))
            .await
            .expect("write close");
        let (op, close) = read_frame(&mut client).await;
        assert_eq!(op, Opcode::Close);
        assert!(close.is_empty());
        assert_eq!(task.await.expect("loop task"), None);
        let ws = v.log.ws_json();
        let last = ws["entries"]
            .as_array()
            .expect("entries")
            .last()
            .cloned()
            .expect("close entry");
        assert_eq!(last["kind"], serde_json::json!("close"));
        assert_eq!(last["code"], serde_json::Value::Null);
        // The pong was logged as an `in` frame.
        assert!(ws["entries"]
            .as_array()
            .expect("entries")
            .iter()
            .any(|e| e["kind"] == "frame" && e["dir"] == "in" && e["opcode"] == "pong"));

        // A text frame announcing a continuation (FIN clear) is refused with 1003.
        let v = state(Vulnerable);
        let conn = v
            .log
            .open_conn(Listener::Plain, None, "127.0.0.1:7".parse().expect("peer"));
        let (server, mut client) = tokio::io::duplex(1 << 20);
        let task = tokio::spawn(run_frames(server, v.clone(), conn.clone(), false));
        let _hello = read_frame(&mut client).await;
        let mut first_fragment = masked(Opcode::Text, b"part");
        first_fragment[0] &= 0x7f;
        client
            .write_all(&first_fragment)
            .await
            .expect("write fragment");
        let (op, payload) = read_frame(&mut client).await;
        assert_eq!(op, Opcode::Close);
        assert_eq!(payload, 1003u16.to_be_bytes().to_vec());
        assert_eq!(task.await.expect("loop task"), Some(1003));

        // The client vanishing mid-frame ends the loop without a code and
        // still writes the close entry and stamps the connection.
        let v = state(Vulnerable);
        let conn = v
            .log
            .open_conn(Listener::Plain, None, "127.0.0.1:8".parse().expect("peer"));
        let (server, mut client) = tokio::io::duplex(1 << 20);
        let task = tokio::spawn(run_frames(server, v.clone(), conn.clone(), false));
        let _hello = read_frame(&mut client).await;
        client.write_all(&[0x81]).await.expect("write partial");
        drop(client);
        assert_eq!(task.await.expect("loop task"), None);
        let ws = v.log.ws_json();
        let last = ws["entries"]
            .as_array()
            .expect("entries")
            .last()
            .cloned()
            .expect("close entry");
        assert_eq!(last["kind"], serde_json::json!("close"));
        assert_eq!(last["code"], serde_json::Value::Null);
        assert!(conn.closed_ms.lock().expect("closed_ms").is_some());

        // A reserved opcode on the wire closes with 1002.
        let v = state(Vulnerable);
        let conn = v
            .log
            .open_conn(Listener::Plain, None, "127.0.0.1:9".parse().expect("peer"));
        let (server, mut client) = tokio::io::duplex(1 << 20);
        let task = tokio::spawn(run_frames(server, v.clone(), conn.clone(), false));
        let _hello = read_frame(&mut client).await;
        client
            .write_all(&[0x83, 0x80, 1, 2, 3, 4])
            .await
            .expect("write reserved opcode");
        let (op, payload) = read_frame(&mut client).await;
        assert_eq!(op, Opcode::Close);
        assert_eq!(payload, 1002u16.to_be_bytes().to_vec());
        assert_eq!(task.await.expect("loop task"), Some(1002));
    }
}
