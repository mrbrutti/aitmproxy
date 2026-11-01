//! `/ws` WebSocket seed: RFC 6455 server codec and handshake primitives
//! (Task A4). The upgrade handler, frame loop and logging arrive in A5/A17.
//!
//! Everything here is pure: bytes in, bytes or a verdict out. The server side
//! of RFC 6455 is deliberately strict: a client frame without a mask is a
//! protocol error (`Decoded::Unmasked`, close `1002`), a declared payload above
//! [`MAX_FRAME`] is refused before any payload byte is read
//! (`Decoded::Oversize`, close `1009`), and a reserved opcode or RSV bit is
//! `Decoded::Malformed`. No `unwrap`/`expect` touches wire bytes.

// A17 consumes this: until the upgrade handler lands, nothing outside the
// unit tests calls these items.
#![allow(dead_code)]

use base64::Engine as _;
use sha1::{Digest as _, Sha1};

use crate::seed::SeedMode;

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

    /// Lower-case token used by the `frame` log entry.
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

/// Private copy of `app.rs::html_escape` (A4 owns only this file): escapes
/// `& < > " '` as `&amp; &lt; &gt; &quot; &#x27;`.
fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            _ => out.push(c),
        }
    }
    out
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
}
