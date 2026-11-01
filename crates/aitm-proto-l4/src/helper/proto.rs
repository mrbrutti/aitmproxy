//! The helper wire protocol: framing, message types, encode and decode
//! (spec §5.2).
//!
//! Both ends of the privilege boundary link this module, so there is one
//! definition of the wire rather than two that can drift. It is pure: it takes
//! bytes from any [`std::io::Read`] and produces bytes into a `Vec<u8>`; it
//! opens nothing and knows nothing about sockets.
//!
//! # Framing
//!
//! Every message is
//!
//! ```text
//! +--------------+--------+-----------------+
//! | length (u32) | type   | payload         |
//! |  big-endian  | 1 byte | length - 1 bytes|
//! +--------------+--------+-----------------+
//! ```
//!
//! **The length counts the type byte and the payload, not itself**, so a
//! message occupies `4 + length` bytes on the wire and the smallest legal
//! length is 1 (a type byte with an empty payload). A length of 0, or above
//! [`MAX_FRAME`], is not a message.
//!
//! Control payloads are JSON. [`Msg::Frame`] and [`Msg::Inject`] carry a small
//! binary header followed by the raw packet bytes, because they are the hot
//! path and base64 in JSON would cost a third more bytes per packet:
//!
//! - `Frame`: `capture_id` (u64 big-endian), `ts_us` (u64 big-endian), then the
//!   raw bytes. The capture id names the capture, whose interface the peer
//!   already set in [`Msg::CaptureOpen`], so no interface is repeated per
//!   packet.
//! - `Inject`: `request_id` (u64 big-endian), the interface as a u16
//!   big-endian byte length followed by that many UTF-8 bytes, then the raw
//!   bytes.
//!
//! # Hostile input
//!
//! The reader treats everything after the length as attacker-controlled. It
//! refuses an over-long length by the number alone, before reading or
//! allocating a body of that size ([`ProtoError::TooLong`]); it never indexes
//! past the payload it holds ([`ProtoError::BadBinary`] on any truncation or a
//! non-UTF-8 interface name); it never panics, unwraps or expects. A clean EOF
//! **at a message boundary** is [`ProtoError::Eof`] — the peer closed — while an
//! EOF part way through a message is [`ProtoError::Io`], so a peer that died
//! mid-write is not mistaken for an orderly close. Every one of these ends the
//! session at the caller (spec §5.2).

use serde::{Deserialize, Serialize};

use crate::config::L4Config;
use crate::types::{L4Direction, L4ScopeEntry};

/// Protocol version carried by [`Msg::Hello`] / [`Msg::HelloAck`]. A mismatch
/// closes the session; the core reports `helper.status: "version_mismatch"`.
pub const PROTO: u32 = 1;

/// Largest `length` field accepted, in bytes (type byte plus payload). A
/// declared length above this is refused before anything is allocated.
pub const MAX_FRAME: usize = 256 * 1024;

const TYPE_HELLO: u8 = 0x01;
const TYPE_HELLO_ACK: u8 = 0x02;
const TYPE_SCOPE_SET: u8 = 0x03;
const TYPE_CAPTURE_OPEN: u8 = 0x04;
const TYPE_CAPTURE_CLOSE: u8 = 0x05;
const TYPE_FRAME: u8 = 0x06;
const TYPE_CAPTURE_CLOSED: u8 = 0x07;
const TYPE_INJECT: u8 = 0x08;
const TYPE_INJECT_RESULT: u8 = 0x09;

/// The guard state the core hands the helper: the scope entries, the three
/// limits and the core's own listening ports.
///
/// The helper enforces the guard itself over this set rather than trusting a
/// decision from the other side (spec §5.3). It is resent on every change.
///
/// An unknown top-level key is [`ProtoError::BadJson`]: this is a trust
/// boundary, and a peer that speaks a different shape is a different
/// protocol, which is what [`PROTO`] is for. The entries keep the core's
/// [`L4ScopeEntry`] rules unchanged.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeSet {
    /// Deny-by-default scope entries, verbatim from the core's guard.
    pub scope: Vec<L4ScopeEntry>,
    /// Tool-wide injection ceiling in packets/sec. `0` ⇒ refuse.
    pub global_inject_pps: u32,
    /// Hard cap on a single injected packet.
    pub max_packet_bytes: usize,
    /// Hard cap on packets emitted by one command invocation.
    pub max_packets_per_call: u32,
    /// The core's own listening ports, excluded from capture (parity §2.1).
    /// Not part of [`L4Config`]; the helper applies it separately.
    pub self_ports: Vec<u16>,
}

impl ScopeSet {
    /// The config to build the helper's own [`crate::guard::L4Guard`] from.
    ///
    /// `enabled` is true (the helper exists only because L4 is on), the scope
    /// and the three limits are copied, and every other field keeps
    /// [`L4Config::default`] — conservative, and in particular every
    /// `allow_agent_*` gate stays closed, since the helper never serves an
    /// agent directly. `self_ports` has no `L4Config` home and is applied by
    /// the caller.
    #[must_use]
    pub fn to_config(&self) -> L4Config {
        L4Config {
            enabled: true,
            scope: self.scope.clone(),
            global_inject_pps: self.global_inject_pps,
            max_packet_bytes: self.max_packet_bytes,
            max_packets_per_call: self.max_packets_per_call,
            ..L4Config::default()
        }
    }
}

/// One message on the helper socket. The type byte of each variant is fixed by
/// the spec's table (§5.2) and is part of the contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Msg {
    /// core → helper, `0x01`: open the session.
    Hello {
        /// Protocol version the core speaks, [`PROTO`].
        proto: u32,
        /// Version string of the core binary.
        core_version: String,
    },
    /// helper → core, `0x02`: accept the session.
    HelloAck {
        /// Protocol version the helper speaks, [`PROTO`].
        proto: u32,
        /// Version string of the helper binary.
        helper_version: String,
        /// Effective privileges the helper actually holds, e.g. `cap_net_raw`.
        caps: Vec<String>,
    },
    /// core → helper, `0x03`: the guard state, resent on every change.
    ScopeSet(ScopeSet),
    /// core → helper, `0x04`: start a capture. No filter string: the helper
    /// compiles its own from its [`ScopeSet`] (spec §5.3).
    CaptureOpen {
        /// Capture id, chosen by the core; names this capture in later messages.
        id: u64,
        /// Interface to capture on.
        interface: String,
        /// Direction the capture covers.
        direction: L4Direction,
        /// Read timeout handed to the capture backend, milliseconds.
        read_timeout_ms: u32,
    },
    /// core → helper, `0x05`: stop a capture.
    CaptureClose {
        /// Capture id from the matching [`Msg::CaptureOpen`].
        id: u64,
    },
    /// helper → core, `0x06`: one captured packet.
    Frame {
        /// Capture this packet came from.
        capture_id: u64,
        /// Capture timestamp, microseconds since the epoch.
        ts_us: u64,
        /// The raw link-layer bytes.
        bytes: Vec<u8>,
    },
    /// helper → core, `0x07`: a capture ended, with the reason to show.
    CaptureClosed {
        /// Capture that ended.
        capture_id: u64,
        /// Why it ended, for display.
        reason: String,
    },
    /// core → helper, `0x08`: send one frame. The helper parses and guards it
    /// itself; the core's intent is never trusted as authorization.
    Inject {
        /// Correlates with the [`Msg::InjectResult`].
        request_id: u64,
        /// Interface to send on.
        interface: String,
        /// The raw link-layer bytes to send.
        bytes: Vec<u8>,
    },
    /// helper → core, `0x09`: the outcome of one [`Msg::Inject`].
    InjectResult {
        /// The id from the matching [`Msg::Inject`].
        request_id: u64,
        /// `None` on success; otherwise the guard or wire error text.
        error: Option<String>,
    },
}

/// Why a message could not be read. Every variant closes the session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtoError {
    /// The declared length exceeds [`MAX_FRAME`]; carries the length found.
    /// Nothing of that size was read or allocated.
    TooLong(usize),
    /// The type byte is none of the nine defined ones; carries the byte.
    UnknownType(u8),
    /// A control payload is not the JSON its type requires; carries the
    /// parser's message.
    BadJson(String),
    /// A binary payload is truncated, overruns its own length field, or
    /// carries a non-UTF-8 interface name. Also a length of 0, which has no
    /// room for a type byte.
    BadBinary,
    /// The peer closed cleanly at a message boundary.
    Eof,
    /// The transport failed, or the stream ended part way through a message;
    /// carries the I/O error's message.
    Io(String),
}

impl std::fmt::Display for ProtoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProtoError::TooLong(len) => {
                write!(f, "frame length {len} exceeds the {MAX_FRAME}-byte maximum")
            }
            ProtoError::UnknownType(ty) => write!(f, "unknown message type {ty:#04x}"),
            ProtoError::BadJson(msg) => write!(f, "malformed message JSON: {msg}"),
            ProtoError::BadBinary => write!(f, "malformed binary message payload"),
            ProtoError::Eof => write!(f, "peer closed the session"),
            ProtoError::Io(msg) => write!(f, "helper socket I/O error: {msg}"),
        }
    }
}

impl std::error::Error for ProtoError {}

// The JSON bodies of the control messages. They are separate from `Msg` so the
// type byte is the only discriminant on the wire: a payload can never claim to
// be a different variant than its type byte says. Each denies unknown keys: at
// this trust boundary a key the type does not define is `BadJson`, and a peer
// that needs a new key needs a new `PROTO`.

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HelloJson {
    proto: u32,
    core_version: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HelloAckJson {
    proto: u32,
    helper_version: String,
    caps: Vec<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CaptureOpenJson {
    id: u64,
    interface: String,
    direction: L4Direction,
    read_timeout_ms: u32,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CaptureCloseJson {
    id: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CaptureClosedJson {
    capture_id: u64,
    reason: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InjectResultJson {
    request_id: u64,
    error: Option<String>,
}

/// Serialize a control body. These are scalars, strings and string vectors, so
/// serde cannot fail; if it ever did, the fallback is a body that no decoder
/// accepts, so the peer answers [`ProtoError::BadJson`] and closes rather than
/// acting on a half-written message.
fn to_json<T: Serialize>(value: &T) -> Vec<u8> {
    serde_json::to_vec(value).unwrap_or_else(|_| b"!".to_vec())
}

fn from_json<T: serde::de::DeserializeOwned>(payload: &[u8]) -> Result<T, ProtoError> {
    serde_json::from_slice(payload).map_err(|err| ProtoError::BadJson(err.to_string()))
}

/// Encode a message, header included.
///
/// This does **not** enforce [`MAX_FRAME`]: the caller owns the packet-size
/// limits (`max_packet_bytes`) and is expected to keep payloads inside them. An
/// over-long message is refused by the peer with [`ProtoError::TooLong`], which
/// closes the session — fail-closed either way. For the same reason two values
/// that do not fit their field are written as something the peer refuses
/// rather than as a truncation it would accept as something else:
///
/// - A length that would not fit a `u32` is written as `u32::MAX`, which the
///   peer refuses by the number alone ([`ProtoError::TooLong`]) before it reads
///   a byte of the body, whatever the body holds.
/// - An [`Msg::Inject`] interface name that would not fit a `u16` is written as
///   the `u16::MAX` length marker followed by **nothing**: the name and the
///   frame bytes are both dropped, so the claimed name is always longer than
///   the payload and the peer answers [`ProtoError::BadBinary`] whatever the
///   frame length. (Writing the frame bytes after the marker would let 65 535
///   or more of them satisfy the claimed name, and the peer would decode an
///   `Inject` for a different interface with a shorter frame.)
#[must_use]
pub fn encode(msg: &Msg) -> Vec<u8> {
    let (ty, payload) = match msg {
        Msg::Hello {
            proto,
            core_version,
        } => (
            TYPE_HELLO,
            to_json(&HelloJson {
                proto: *proto,
                core_version: core_version.clone(),
            }),
        ),
        Msg::HelloAck {
            proto,
            helper_version,
            caps,
        } => (
            TYPE_HELLO_ACK,
            to_json(&HelloAckJson {
                proto: *proto,
                helper_version: helper_version.clone(),
                caps: caps.clone(),
            }),
        ),
        Msg::ScopeSet(set) => (TYPE_SCOPE_SET, to_json(set)),
        Msg::CaptureOpen {
            id,
            interface,
            direction,
            read_timeout_ms,
        } => (
            TYPE_CAPTURE_OPEN,
            to_json(&CaptureOpenJson {
                id: *id,
                interface: interface.clone(),
                direction: *direction,
                read_timeout_ms: *read_timeout_ms,
            }),
        ),
        Msg::CaptureClose { id } => (TYPE_CAPTURE_CLOSE, to_json(&CaptureCloseJson { id: *id })),
        Msg::Frame {
            capture_id,
            ts_us,
            bytes,
        } => {
            let mut payload = Vec::with_capacity(16 + bytes.len());
            payload.extend_from_slice(&capture_id.to_be_bytes());
            payload.extend_from_slice(&ts_us.to_be_bytes());
            payload.extend_from_slice(bytes);
            (TYPE_FRAME, payload)
        }
        Msg::CaptureClosed { capture_id, reason } => (
            TYPE_CAPTURE_CLOSED,
            to_json(&CaptureClosedJson {
                capture_id: *capture_id,
                reason: reason.clone(),
            }),
        ),
        Msg::Inject {
            request_id,
            interface,
            bytes,
        } => {
            let name = interface.as_bytes();
            let mut payload = Vec::with_capacity(10 + name.len() + bytes.len());
            payload.extend_from_slice(&request_id.to_be_bytes());
            match u16::try_from(name.len()) {
                Ok(len) => {
                    payload.extend_from_slice(&len.to_be_bytes());
                    payload.extend_from_slice(name);
                    payload.extend_from_slice(bytes);
                }
                // No OS has an interface name this long (IFNAMSIZ is 16). Write
                // the u16::MAX length marker and nothing after it — not the
                // name, and not the frame bytes either — so the claimed name is
                // always longer than the payload and the peer answers BadBinary
                // and closes, whatever the frame length. Frame bytes after the
                // marker would satisfy the claimed name once there are 65 535
                // of them, and the peer would accept an Inject for a different
                // interface with a shorter frame.
                Err(_) => payload.extend_from_slice(&u16::MAX.to_be_bytes()),
            }
            (TYPE_INJECT, payload)
        }
        Msg::InjectResult { request_id, error } => (
            TYPE_INJECT_RESULT,
            to_json(&InjectResultJson {
                request_id: *request_id,
                error: error.clone(),
            }),
        ),
    };

    // The length counts the type byte. `saturating_add` and the `u32::MAX`
    // fallback only matter for a payload the caller should never have built.
    // Unlike the interface-name marker above, nothing has to be dropped here:
    // `read_msg` checks the length number alone, before reading a byte of the
    // body, and `u32::MAX` exceeds `MAX_FRAME`, so the peer answers TooLong
    // whatever follows the header and however long the body is.
    let len = u32::try_from(payload.len().saturating_add(1)).unwrap_or(u32::MAX);
    let mut out = Vec::with_capacity(5 + payload.len());
    out.extend_from_slice(&len.to_be_bytes());
    out.push(ty);
    out.extend_from_slice(&payload);
    out
}

/// Read one message.
///
/// Reads exactly the bytes of one message and no more, so the reader is left at
/// the next message boundary. See the module docs for the guarantees on hostile
/// input.
///
/// # Errors
///
/// [`ProtoError::Eof`] at a clean close, [`ProtoError::TooLong`],
/// [`ProtoError::UnknownType`], [`ProtoError::BadJson`],
/// [`ProtoError::BadBinary`] on a refused message, [`ProtoError::Io`] on a
/// transport failure or a message cut short.
pub fn read_msg(r: &mut impl std::io::Read) -> Result<Msg, ProtoError> {
    let Some(first) = read_one(r)? else {
        return Err(ProtoError::Eof);
    };
    let mut rest = [0u8; 3];
    read_exact(r, &mut rest)?;

    let len = u32::from_be_bytes([first, rest[0], rest[1], rest[2]]) as usize;
    // Checked before any allocation or read of that size (AC18).
    if len > MAX_FRAME {
        return Err(ProtoError::TooLong(len));
    }
    // A message is at least its type byte.
    if len == 0 {
        return Err(ProtoError::BadBinary);
    }

    let mut ty = [0u8; 1];
    read_exact(r, &mut ty)?;
    let mut payload = vec![0u8; len - 1];
    read_exact(r, &mut payload)?;

    decode(ty[0], &payload)
}

/// Read one byte, distinguishing a clean close (`Ok(None)`) from a failure.
fn read_one(r: &mut impl std::io::Read) -> Result<Option<u8>, ProtoError> {
    let mut byte = [0u8; 1];
    loop {
        match r.read(&mut byte) {
            Ok(0) => return Ok(None),
            Ok(_) => return Ok(Some(byte[0])),
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(ProtoError::Io(err.to_string())),
        }
    }
}

/// Fill `buf`. A stream that ends here ended inside a message, so it is an
/// `Io` error (`UnexpectedEof`), not [`ProtoError::Eof`].
fn read_exact(r: &mut impl std::io::Read, buf: &mut [u8]) -> Result<(), ProtoError> {
    r.read_exact(buf)
        .map_err(|err| ProtoError::Io(err.to_string()))
}

/// Turn one type byte and its payload into a message.
fn decode(ty: u8, payload: &[u8]) -> Result<Msg, ProtoError> {
    match ty {
        TYPE_HELLO => {
            let body: HelloJson = from_json(payload)?;
            Ok(Msg::Hello {
                proto: body.proto,
                core_version: body.core_version,
            })
        }
        TYPE_HELLO_ACK => {
            let body: HelloAckJson = from_json(payload)?;
            Ok(Msg::HelloAck {
                proto: body.proto,
                helper_version: body.helper_version,
                caps: body.caps,
            })
        }
        TYPE_SCOPE_SET => Ok(Msg::ScopeSet(from_json(payload)?)),
        TYPE_CAPTURE_OPEN => {
            let body: CaptureOpenJson = from_json(payload)?;
            Ok(Msg::CaptureOpen {
                id: body.id,
                interface: body.interface,
                direction: body.direction,
                read_timeout_ms: body.read_timeout_ms,
            })
        }
        TYPE_CAPTURE_CLOSE => {
            let body: CaptureCloseJson = from_json(payload)?;
            Ok(Msg::CaptureClose { id: body.id })
        }
        TYPE_FRAME => {
            let mut cur = Cursor::new(payload);
            let capture_id = cur.u64()?;
            let ts_us = cur.u64()?;
            Ok(Msg::Frame {
                capture_id,
                ts_us,
                bytes: cur.rest().to_vec(),
            })
        }
        TYPE_CAPTURE_CLOSED => {
            let body: CaptureClosedJson = from_json(payload)?;
            Ok(Msg::CaptureClosed {
                capture_id: body.capture_id,
                reason: body.reason,
            })
        }
        TYPE_INJECT => {
            let mut cur = Cursor::new(payload);
            let request_id = cur.u64()?;
            let interface = cur.string()?;
            Ok(Msg::Inject {
                request_id,
                interface,
                bytes: cur.rest().to_vec(),
            })
        }
        TYPE_INJECT_RESULT => {
            let body: InjectResultJson = from_json(payload)?;
            Ok(Msg::InjectResult {
                request_id: body.request_id,
                error: body.error,
            })
        }
        other => Err(ProtoError::UnknownType(other)),
    }
}

/// A bounds-checked walk over a binary payload. Every read is a `get`, so a
/// truncated or overrunning payload is [`ProtoError::BadBinary`] and never a
/// panic.
struct Cursor<'a> {
    buf: &'a [u8],
    at: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, at: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], ProtoError> {
        let end = self.at.checked_add(n).ok_or(ProtoError::BadBinary)?;
        let slice = self.buf.get(self.at..end).ok_or(ProtoError::BadBinary)?;
        self.at = end;
        Ok(slice)
    }

    fn u64(&mut self) -> Result<u64, ProtoError> {
        let bytes: [u8; 8] = self
            .take(8)?
            .try_into()
            .map_err(|_| ProtoError::BadBinary)?;
        Ok(u64::from_be_bytes(bytes))
    }

    fn u16(&mut self) -> Result<u16, ProtoError> {
        let bytes: [u8; 2] = self
            .take(2)?
            .try_into()
            .map_err(|_| ProtoError::BadBinary)?;
        Ok(u16::from_be_bytes(bytes))
    }

    /// A u16-length-prefixed UTF-8 string. Non-UTF-8 is `BadBinary`: an
    /// interface name is matched against scope, so it is never lossily
    /// reconstructed.
    fn string(&mut self) -> Result<String, ProtoError> {
        let len = self.u16()? as usize;
        let bytes = self.take(len)?;
        String::from_utf8(bytes.to_vec()).map_err(|_| ProtoError::BadBinary)
    }

    /// Everything not yet consumed.
    fn rest(&mut self) -> &'a [u8] {
        let slice = self.buf.get(self.at..).unwrap_or(&[]);
        self.at = self.buf.len();
        slice
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{
        IpCidr, L4Capability, L4Direction, L4ScopeEntry, L4ScopeId, L4ScopeSource, PortRange,
        RateCap,
    };
    use std::io::Cursor;
    use std::net::{IpAddr, Ipv4Addr};

    /// The scope set used by the round-trip and `to_config` tests: one
    /// capture entry on `lo0` for 127.0.0.1:9053.
    fn scope_set() -> ScopeSet {
        ScopeSet {
            scope: vec![L4ScopeEntry {
                id: L4ScopeId::new(),
                cidr: IpCidr {
                    addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                    prefix: 32,
                },
                ports: PortRange { lo: 9053, hi: 9053 },
                interface: "lo0".to_string(),
                direction: L4Direction::Outbound,
                capability: L4Capability::Capture,
                inject_rate: RateCap { pps: 10, burst: 5 },
                source: L4ScopeSource::Config,
            }],
            global_inject_pps: 7,
            max_packet_bytes: 1500,
            max_packets_per_call: 4,
            self_ports: vec![8080, 8081],
        }
    }

    /// All nine variants survive `encode` -> `read_msg` with their literal
    /// field values, and the frame header on the wire is the documented
    /// 4-byte big-endian length (type byte included) plus the type byte.
    #[test]
    fn every_variant_round_trips() {
        let msgs = vec![
            Msg::Hello {
                proto: PROTO,
                core_version: "0.5.9".to_string(),
            },
            Msg::HelloAck {
                proto: PROTO,
                helper_version: "0.5.9".to_string(),
                caps: vec!["cap_net_raw".to_string()],
            },
            Msg::ScopeSet(scope_set()),
            Msg::CaptureOpen {
                id: 11,
                interface: "lo0".to_string(),
                direction: L4Direction::Inbound,
                read_timeout_ms: 250,
            },
            Msg::CaptureClose { id: 11 },
            Msg::Frame {
                capture_id: 11,
                ts_us: 1_762_000_000_123_456,
                bytes: vec![0xde, 0xad, 0xbe, 0xef],
            },
            Msg::CaptureClosed {
                capture_id: 11,
                reason: "interface went down".to_string(),
            },
            Msg::Inject {
                request_id: 12,
                interface: "lo0".to_string(),
                bytes: vec![0x45, 0x00, 0x00, 0x1c],
            },
            Msg::InjectResult {
                request_id: 12,
                error: Some("out of scope".to_string()),
            },
            Msg::InjectResult {
                request_id: 13,
                error: None,
            },
        ];

        // Each one alone.
        for msg in &msgs {
            let bytes = encode(msg);
            let mut reader = Cursor::new(bytes);
            assert_eq!(read_msg(&mut reader), Ok(msg.clone()), "round trip {msg:?}");
        }

        // And all of them back to back on one stream, in order, then a clean
        // EOF at the final message boundary: that is what the socket sees.
        let mut stream = Vec::new();
        for msg in &msgs {
            stream.extend_from_slice(&encode(msg));
        }
        let mut reader = Cursor::new(stream);
        for msg in &msgs {
            assert_eq!(read_msg(&mut reader), Ok(msg.clone()));
        }
        assert_eq!(read_msg(&mut reader), Err(ProtoError::Eof));

        // The literal header of a Hello: length counts the type byte.
        let hello = encode(&Msg::Hello {
            proto: 1,
            core_version: "0.5.9".to_string(),
        });
        let payload = br#"{"proto":1,"core_version":"0.5.9"}"#;
        assert_eq!(
            &hello[..5],
            &[0, 0, 0, (payload.len() + 1) as u8, 0x01],
            "4-byte BE length (type included) then the type byte"
        );
        assert_eq!(&hello[5..], payload, "control payloads are JSON");

        // The literal header of a Frame: ids and timestamp big-endian, then the
        // raw bytes.
        let frame = encode(&Msg::Frame {
            capture_id: 11,
            ts_us: 1_762_000_000_123_456,
            bytes: vec![0xde, 0xad, 0xbe, 0xef],
        });
        assert_eq!(&frame[..5], &[0, 0, 0, 21, 0x06]);
        assert_eq!(&frame[5..13], &11u64.to_be_bytes());
        assert_eq!(&frame[13..21], &1_762_000_000_123_456u64.to_be_bytes());
        assert_eq!(&frame[21..], &[0xde, 0xad, 0xbe, 0xef]);

        // And of an Inject: id, u16 interface length, interface, raw bytes.
        let inject = encode(&Msg::Inject {
            request_id: 12,
            interface: "lo0".to_string(),
            bytes: vec![0x45],
        });
        assert_eq!(&inject[..5], &[0, 0, 0, 15, 0x08]);
        assert_eq!(&inject[5..13], &12u64.to_be_bytes());
        assert_eq!(&inject[13..15], &3u16.to_be_bytes());
        assert_eq!(&inject[15..18], b"lo0");
        assert_eq!(&inject[18..], &[0x45]);

        // The type bytes are the contract: one per variant, as the spec table.
        let types: Vec<u8> = msgs.iter().map(|m| encode(m)[4]).collect();
        assert_eq!(
            types,
            vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x09]
        );
    }

    /// `ScopeSet::to_config` enables L4, copies the scope and the three limits,
    /// and leaves every other field at its conservative default.
    #[test]
    fn scope_set_to_config_enables_and_copies_the_limits() {
        let set = scope_set();
        let config = set.to_config();

        assert!(config.enabled);
        assert_eq!(config.scope, set.scope);
        assert_eq!(config.global_inject_pps, 7);
        assert_eq!(config.max_packet_bytes, 1500);
        assert_eq!(config.max_packets_per_call, 4);

        let default = crate::config::L4Config::default();
        assert_eq!(config.capture_backend, default.capture_backend);
        assert_eq!(config.default_recv_timeout, default.default_recv_timeout);
        assert_eq!(config.intercept, default.intercept);
        assert!(!config.dangerous_dst_override);
        assert!(!config.allow_agent_widen);
        assert!(!config.allow_agent_inject);
        assert!(!config.allow_agent_capture);
        assert!(!config.allow_agent_intercept);
    }

    /// A declared length above `MAX_FRAME` is refused by the number alone,
    /// before anything of that size is read or allocated (spec §5.2, AC18).
    #[test]
    fn length_over_max_is_too_long() {
        assert_eq!(MAX_FRAME, 262_144);

        // Only the 5 header bytes exist: an implementation that tried to read
        // the body before checking the length would report an I/O error.
        let mut header = Vec::new();
        header.extend_from_slice(&262_145u32.to_be_bytes());
        header.push(0x01);
        let mut reader = Cursor::new(header);
        assert_eq!(read_msg(&mut reader), Err(ProtoError::TooLong(262_145)));

        // u32::MAX is refused the same way, not wrapped or truncated.
        let mut reader = Cursor::new(u32::MAX.to_be_bytes().to_vec());
        assert_eq!(
            read_msg(&mut reader),
            Err(ProtoError::TooLong(4_294_967_295))
        );

        // Exactly MAX_FRAME is still accepted (the boundary is inclusive).
        let body = vec![0u8; MAX_FRAME - 1 - 16];
        let max = encode(&Msg::Frame {
            capture_id: 1,
            ts_us: 2,
            bytes: body.clone(),
        });
        assert_eq!(max.len(), 4 + MAX_FRAME);
        let mut reader = Cursor::new(max);
        assert_eq!(
            read_msg(&mut reader),
            Ok(Msg::Frame {
                capture_id: 1,
                ts_us: 2,
                bytes: body
            })
        );
    }

    /// An unknown type byte closes the session rather than being guessed at.
    #[test]
    fn unknown_type_is_refused() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&1u32.to_be_bytes());
        bytes.push(0x7f);
        let mut reader = Cursor::new(bytes);
        assert_eq!(read_msg(&mut reader), Err(ProtoError::UnknownType(127)));

        // 0x00 and 0x0a sit either side of the nine defined types.
        for ty in [0x00u8, 0x0a] {
            let mut bytes = Vec::new();
            bytes.extend_from_slice(&3u32.to_be_bytes());
            bytes.push(ty);
            bytes.extend_from_slice(b"hi");
            let mut reader = Cursor::new(bytes);
            assert_eq!(read_msg(&mut reader), Err(ProtoError::UnknownType(ty)));
        }

        // A zero length has no type byte at all; it is not a message.
        let mut reader = Cursor::new(0u32.to_be_bytes().to_vec());
        assert_eq!(read_msg(&mut reader), Err(ProtoError::BadBinary));
    }

    /// A control payload that is not the JSON the variant expects is a
    /// `BadJson`, carrying the parser's message, never a panic.
    #[test]
    fn malformed_json_is_bad_json() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&2u32.to_be_bytes());
        bytes.push(0x01);
        bytes.push(b'{');
        let mut reader = Cursor::new(bytes);
        match read_msg(&mut reader) {
            Err(ProtoError::BadJson(msg)) => assert!(!msg.is_empty()),
            other => panic!("a truncated JSON Hello must be BadJson, got {other:?}"),
        }

        // Well-formed JSON of the wrong shape is refused too (a Hello without
        // `core_version`), and so is a non-UTF-8 payload.
        for payload in [&b"{\"proto\":1}"[..], &[0xff, 0xfe][..]] {
            let mut bytes = Vec::new();
            bytes.extend_from_slice(&((payload.len() + 1) as u32).to_be_bytes());
            bytes.push(0x01);
            bytes.extend_from_slice(payload);
            let mut reader = Cursor::new(bytes);
            assert!(
                matches!(read_msg(&mut reader), Err(ProtoError::BadJson(_))),
                "payload {payload:?} must be BadJson"
            );
        }
    }

    /// EOF at a message boundary is `Eof`; EOF part way through a message is
    /// an `Io` error, so a peer that died mid-write is not mistaken for a
    /// clean close.
    #[test]
    fn clean_eof_is_eof() {
        let mut reader = Cursor::new(Vec::new());
        assert_eq!(read_msg(&mut reader), Err(ProtoError::Eof));

        // A partial length header.
        let mut reader = Cursor::new(vec![0u8, 0, 0]);
        assert!(matches!(read_msg(&mut reader), Err(ProtoError::Io(_))));

        // A complete length but no type byte, and a short payload.
        let mut reader = Cursor::new(4u32.to_be_bytes().to_vec());
        assert!(matches!(read_msg(&mut reader), Err(ProtoError::Io(_))));
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&10u32.to_be_bytes());
        bytes.push(0x01);
        bytes.extend_from_slice(b"{}");
        let mut reader = Cursor::new(bytes);
        assert!(matches!(read_msg(&mut reader), Err(ProtoError::Io(_))));
    }

    /// A binary header the other side truncated is `BadBinary`: the decoder
    /// never indexes past the payload it was given.
    #[test]
    fn truncated_binary_header_is_bad_binary() {
        // A Frame carrying only its capture id (no timestamp).
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&9u32.to_be_bytes());
        bytes.push(0x06);
        bytes.extend_from_slice(&11u64.to_be_bytes());
        let mut reader = Cursor::new(bytes);
        assert_eq!(read_msg(&mut reader), Err(ProtoError::BadBinary));

        // An empty Frame payload, and every truncation of a valid Frame.
        let whole = encode(&Msg::Frame {
            capture_id: 11,
            ts_us: 22,
            bytes: vec![1, 2, 3],
        });
        for cut in 5..(5 + 16) {
            let body = &whole[5..cut];
            let mut bytes = Vec::new();
            bytes.extend_from_slice(&((body.len() + 1) as u32).to_be_bytes());
            bytes.push(0x06);
            bytes.extend_from_slice(body);
            let mut reader = Cursor::new(bytes);
            assert_eq!(
                read_msg(&mut reader),
                Err(ProtoError::BadBinary),
                "a Frame cut to {} payload bytes",
                body.len()
            );
        }

        // An Inject whose u16 interface length overruns the payload.
        let mut body = Vec::new();
        body.extend_from_slice(&12u64.to_be_bytes());
        body.extend_from_slice(&9u16.to_be_bytes());
        body.extend_from_slice(b"lo0");
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&((body.len() + 1) as u32).to_be_bytes());
        bytes.push(0x08);
        bytes.extend_from_slice(&body);
        let mut reader = Cursor::new(bytes);
        assert_eq!(read_msg(&mut reader), Err(ProtoError::BadBinary));

        // An Inject whose interface name is not UTF-8.
        let mut body = Vec::new();
        body.extend_from_slice(&12u64.to_be_bytes());
        body.extend_from_slice(&2u16.to_be_bytes());
        body.extend_from_slice(&[0xff, 0xfe]);
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&((body.len() + 1) as u32).to_be_bytes());
        bytes.push(0x08);
        bytes.extend_from_slice(&body);
        let mut reader = Cursor::new(bytes);
        assert_eq!(read_msg(&mut reader), Err(ProtoError::BadBinary));
    }

    // ---- Tester edge cases (stage 5, unit p1a) ----------------------------

    /// One message on the wire: 4-byte big-endian length (type byte
    /// included), the type byte, then `payload`.
    fn framed(ty: u8, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(5 + payload.len());
        out.extend_from_slice(&((payload.len() + 1) as u32).to_be_bytes());
        out.push(ty);
        out.extend_from_slice(payload);
        out
    }

    fn hello() -> Msg {
        Msg::Hello {
            proto: PROTO,
            core_version: "0.5.9".to_string(),
        }
    }

    /// A reader driven by a script of deliveries and failures, so a peer that
    /// dies mid-write, dribbles bytes, or is interrupted can be staged.
    enum Step {
        Data(Vec<u8>),
        Fail(std::io::ErrorKind, &'static str),
    }

    struct Scripted(std::collections::VecDeque<Step>);

    impl std::io::Read for Scripted {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            match self.0.pop_front() {
                None => Ok(0),
                Some(Step::Fail(kind, msg)) => Err(std::io::Error::new(kind, msg)),
                Some(Step::Data(mut data)) => {
                    let n = data.len().min(buf.len());
                    buf[..n].copy_from_slice(&data[..n]);
                    if n < data.len() {
                        let rest = data.split_off(n);
                        self.0.push_front(Step::Data(rest));
                    }
                    Ok(n)
                }
            }
        }
    }

    fn scripted(steps: Vec<Step>) -> Scripted {
        Scripted(steps.into_iter().collect())
    }

    #[test]
    fn tester_too_long_is_refused_with_the_body_unread() {
        // MAX_FRAME + 1 with the whole body present: refused on the number, and
        // the reader has consumed exactly the 4 length bytes, so nothing of
        // that size was read or allocated (AC18).
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&((MAX_FRAME + 1) as u32).to_be_bytes());
        bytes.push(TYPE_FRAME);
        bytes.extend(std::iter::repeat_n(0u8, MAX_FRAME));
        assert_eq!(bytes.len(), 4 + MAX_FRAME + 1);
        let mut reader = Cursor::new(bytes);
        assert_eq!(
            read_msg(&mut reader),
            Err(ProtoError::TooLong(MAX_FRAME + 1))
        );
        assert_eq!(reader.position(), 4, "only the length was consumed");

        // u32::MAX followed by a body: the same, without a 4 GiB allocation.
        let mut bytes = u32::MAX.to_be_bytes().to_vec();
        bytes.extend_from_slice(&[TYPE_HELLO, b'{', b'}']);
        let mut reader = Cursor::new(bytes);
        assert_eq!(
            read_msg(&mut reader),
            Err(ProtoError::TooLong(4_294_967_295))
        );
        assert_eq!(reader.position(), 4);
        assert_eq!(
            ProtoError::TooLong(4_294_967_295).to_string(),
            "frame length 4294967295 exceeds the 262144-byte maximum"
        );
    }

    #[test]
    fn tester_max_frame_boundary_on_an_inject() {
        // The largest Inject that fits: type + id + name length + "lo0" + body.
        let fill = MAX_FRAME - 1 - 8 - 2 - 3;
        let msg = Msg::Inject {
            request_id: 7,
            interface: "lo0".to_string(),
            bytes: vec![0xAB; fill],
        };
        let wire = encode(&msg);
        assert_eq!(wire.len(), 4 + MAX_FRAME);
        assert_eq!(&wire[..4], &(MAX_FRAME as u32).to_be_bytes());
        let mut reader = Cursor::new(wire);
        assert_eq!(read_msg(&mut reader), Ok(msg));
        assert_eq!(read_msg(&mut reader), Err(ProtoError::Eof));

        // One byte more: encode writes MAX_FRAME + 1 and the peer refuses it.
        let wire = encode(&Msg::Inject {
            request_id: 7,
            interface: "lo0".to_string(),
            bytes: vec![0xAB; fill + 1],
        });
        assert_eq!(&wire[..4], &((MAX_FRAME + 1) as u32).to_be_bytes());
        let mut reader = Cursor::new(wire);
        assert_eq!(
            read_msg(&mut reader),
            Err(ProtoError::TooLong(MAX_FRAME + 1))
        );
    }

    #[test]
    fn tester_inject_payload_shorter_than_its_header_is_bad_binary() {
        let whole = encode(&Msg::Inject {
            request_id: 12,
            interface: "lo0".to_string(),
            bytes: vec![1, 2, 3],
        });
        // The binary header is 8 + 2 + 3 = 13 payload bytes; every cut inside
        // it is BadBinary.
        for cut in 0..13 {
            let mut reader = Cursor::new(framed(TYPE_INJECT, &whole[5..5 + cut]));
            assert_eq!(
                read_msg(&mut reader),
                Err(ProtoError::BadBinary),
                "an Inject cut to {cut} payload bytes"
            );
        }
        // Exactly the header: an Inject carrying no frame bytes.
        let mut reader = Cursor::new(framed(TYPE_INJECT, &whole[5..18]));
        assert_eq!(
            read_msg(&mut reader),
            Ok(Msg::Inject {
                request_id: 12,
                interface: "lo0".to_string(),
                bytes: Vec::new(),
            })
        );
        // The minimum header: an id and a zero-length name.
        let mut body = 12u64.to_be_bytes().to_vec();
        body.extend_from_slice(&0u16.to_be_bytes());
        let mut reader = Cursor::new(framed(TYPE_INJECT, &body));
        assert_eq!(
            read_msg(&mut reader),
            Ok(Msg::Inject {
                request_id: 12,
                interface: String::new(),
                bytes: Vec::new(),
            })
        );
        // A Frame of exactly its 16-byte header carries no bytes.
        let mut body = 11u64.to_be_bytes().to_vec();
        body.extend_from_slice(&22u64.to_be_bytes());
        let mut reader = Cursor::new(framed(TYPE_FRAME, &body));
        assert_eq!(
            read_msg(&mut reader),
            Ok(Msg::Frame {
                capture_id: 11,
                ts_us: 22,
                bytes: Vec::new(),
            })
        );
        // A type byte alone (length 1): BadBinary for the binary types,
        // BadJson for every control type. Never a default message.
        for ty in [TYPE_FRAME, TYPE_INJECT] {
            let mut reader = Cursor::new(framed(ty, &[]));
            assert_eq!(
                read_msg(&mut reader),
                Err(ProtoError::BadBinary),
                "type {ty:#04x}"
            );
        }
        for ty in [
            TYPE_HELLO,
            TYPE_HELLO_ACK,
            TYPE_SCOPE_SET,
            TYPE_CAPTURE_OPEN,
            TYPE_CAPTURE_CLOSE,
            TYPE_CAPTURE_CLOSED,
            TYPE_INJECT_RESULT,
        ] {
            let mut reader = Cursor::new(framed(ty, &[]));
            assert!(
                matches!(read_msg(&mut reader), Err(ProtoError::BadJson(_))),
                "type {ty:#04x}"
            );
        }
    }

    #[test]
    fn tester_interface_name_at_the_u16_boundary() {
        // Exactly u16::MAX bytes round-trips with its literal length field.
        let name = "a".repeat(65_535);
        let msg = Msg::Inject {
            request_id: 1,
            interface: name,
            bytes: vec![0x45],
        };
        let wire = encode(&msg);
        assert_eq!(&wire[13..15], &[0xff, 0xff]);
        assert_eq!(wire.len(), 4 + 1 + 8 + 2 + 65_535 + 1);
        let mut reader = Cursor::new(wire);
        assert_eq!(read_msg(&mut reader), Ok(msg));

        // One byte over: the encoder writes a 0xFFFF length and nothing after
        // it, neither the name nor the frame bytes, so the peer answers
        // BadBinary (see `fix_f1_oversized_interface_name_is_always_bad_binary`).
        let wire = encode(&Msg::Inject {
            request_id: 1,
            interface: "a".repeat(65_536),
            bytes: vec![0x45, 0x00],
        });
        assert_eq!(
            wire.len(),
            4 + 1 + 8 + 2,
            "neither the name nor the frame bytes are written"
        );
        assert_eq!(&wire[13..15], &[0xff, 0xff]);
        let mut reader = Cursor::new(wire);
        assert_eq!(read_msg(&mut reader), Err(ProtoError::BadBinary));

        // The length is bytes, not chars: 21845 three-byte chars fill a u16.
        let euro = "\u{20ac}".repeat(21_845);
        assert_eq!(euro.len(), 65_535);
        let msg = Msg::Inject {
            request_id: 2,
            interface: euro,
            bytes: Vec::new(),
        };
        let mut reader = Cursor::new(encode(&msg));
        assert_eq!(read_msg(&mut reader), Ok(msg));
    }

    #[test]
    fn tester_scope_set_json_edge_cases() {
        let set = scope_set();
        let base: serde_json::Value =
            serde_json::from_slice(&to_json(&set)).expect("a ScopeSet serializes");
        let read = |v: &serde_json::Value| {
            let mut reader = Cursor::new(framed(TYPE_SCOPE_SET, v.to_string().as_bytes()));
            read_msg(&mut reader)
        };

        // An unknown field inside an entry is ignored (`L4ScopeEntry` is the
        // core's type) and the known fields decode to the literal set.
        let mut v = base.clone();
        v["scope"][0]["filter"] = serde_json::json!("not port 22");
        assert_eq!(read(&v), Ok(Msg::ScopeSet(set.clone())));
        // An unknown field at the top level is BadJson naming it. (A `filter`
        // key in particular: the helper takes no filter from the core.)
        for (key, value) in [
            ("unexpected", serde_json::json!({"deep": [1, 2]})),
            ("filter", serde_json::json!("not port 22")),
        ] {
            let mut v = base.clone();
            v[key] = value;
            match read(&v) {
                Err(ProtoError::BadJson(msg)) => assert!(
                    msg.starts_with(&format!("unknown field `{key}`")),
                    "{key}: {msg}"
                ),
                other => panic!("top-level {key} must be BadJson, got {other:?}"),
            }
        }

        // Every required top-level field missing is BadJson naming it.
        for field in [
            "scope",
            "global_inject_pps",
            "max_packet_bytes",
            "max_packets_per_call",
            "self_ports",
        ] {
            let mut v = base.clone();
            v.as_object_mut().expect("object").remove(field);
            match read(&v) {
                Err(ProtoError::BadJson(msg)) => assert!(
                    msg.starts_with(&format!("missing field `{field}`")),
                    "{field}: {msg}"
                ),
                other => panic!("missing {field} must be BadJson, got {other:?}"),
            }
        }

        // Wrong types and out-of-range numbers: BadJson, never a clamp.
        let bad: [(&str, serde_json::Value); 9] = [
            ("global_inject_pps", serde_json::json!(-1)),
            ("global_inject_pps", serde_json::json!(4_294_967_296u64)),
            ("max_packet_bytes", serde_json::json!(-1)),
            ("max_packet_bytes", serde_json::json!(1.5)),
            ("max_packets_per_call", serde_json::json!("8")),
            ("self_ports", serde_json::json!([70_000])),
            ("self_ports", serde_json::json!([-1])),
            ("self_ports", serde_json::json!(8080)),
            ("scope", serde_json::json!({})),
        ];
        for (field, value) in bad {
            let mut v = base.clone();
            v[field] = value.clone();
            assert!(
                matches!(read(&v), Err(ProtoError::BadJson(_))),
                "{field} = {value} must be BadJson"
            );
        }
        // Inside an entry: an unknown direction, capability, a prefix over
        // 255 and a port over 65535.
        let bad_entry: [(&str, serde_json::Value); 5] = [
            ("direction", serde_json::json!("sideways")),
            ("capability", serde_json::json!("root")),
            ("interface", serde_json::json!(0)),
            (
                "cidr",
                serde_json::json!({"addr": "127.0.0.1", "prefix": 300}),
            ),
            ("ports", serde_json::json!({"lo": 0, "hi": 65_536})),
        ];
        for (field, value) in bad_entry {
            let mut v = base.clone();
            v["scope"][0][field] = value.clone();
            assert!(
                matches!(read(&v), Err(ProtoError::BadJson(_))),
                "scope[0].{field} = {value} must be BadJson"
            );
        }
        // A non-object document.
        for doc in ["[]", "null", "1", "\"scope\""] {
            let mut reader = Cursor::new(framed(TYPE_SCOPE_SET, doc.as_bytes()));
            assert!(
                matches!(read_msg(&mut reader), Err(ProtoError::BadJson(_))),
                "{doc}"
            );
        }

        // An empty scope is a legal set (the helper then denies everything).
        let mut v = base.clone();
        v["scope"] = serde_json::json!([]);
        assert_eq!(
            read(&v),
            Ok(Msg::ScopeSet(ScopeSet {
                scope: Vec::new(),
                ..set.clone()
            }))
        );
    }

    #[test]
    fn tester_control_json_shape_edge_cases() {
        // Trailing bytes after a well-formed body.
        let mut reader = Cursor::new(framed(
            TYPE_HELLO,
            br#"{"proto":1,"core_version":"0.5.9"}garbage"#,
        ));
        match read_msg(&mut reader) {
            Err(ProtoError::BadJson(msg)) => {
                assert!(msg.starts_with("trailing characters"), "{msg}");
            }
            other => panic!("trailing bytes must be BadJson, got {other:?}"),
        }

        // The decoder passes any proto through: the mismatch is the session's
        // decision (spec §5.2), not the framing's. (A proto-2 body with a new
        // key is BadJson instead; see `fix_f2_...`.)
        let mut reader = Cursor::new(framed(TYPE_HELLO, br#"{"proto":2,"core_version":"9.9.9"}"#));
        assert_eq!(
            read_msg(&mut reader),
            Ok(Msg::Hello {
                proto: 2,
                core_version: "9.9.9".to_string(),
            })
        );
        // But not a proto that is not a u32.
        for body in [
            &br#"{"proto":-1,"core_version":"x"}"#[..],
            br#"{"proto":4294967296,"core_version":"x"}"#,
            br#"{"proto":"1","core_version":"x"}"#,
        ] {
            let mut reader = Cursor::new(framed(TYPE_HELLO, body));
            assert!(
                matches!(read_msg(&mut reader), Err(ProtoError::BadJson(_))),
                "{}",
                String::from_utf8_lossy(body)
            );
        }

        // The type byte is the only discriminant: a CaptureOpen body under
        // the Hello type is BadJson, not a CaptureOpen.
        let open = br#"{"id":11,"interface":"lo0","direction":"inbound","read_timeout_ms":250}"#;
        let mut reader = Cursor::new(framed(TYPE_HELLO, open));
        assert!(matches!(read_msg(&mut reader), Err(ProtoError::BadJson(_))));
        let mut reader = Cursor::new(framed(TYPE_CAPTURE_OPEN, open));
        assert_eq!(
            read_msg(&mut reader),
            Ok(Msg::CaptureOpen {
                id: 11,
                interface: "lo0".to_string(),
                direction: L4Direction::Inbound,
                read_timeout_ms: 250,
            })
        );

        // CaptureOpen: an unknown direction, a negative timeout, an id past u64.
        for body in [
            &br#"{"id":11,"interface":"lo0","direction":"sideways","read_timeout_ms":250}"#[..],
            br#"{"id":11,"interface":"lo0","direction":"inbound","read_timeout_ms":-1}"#,
            br#"{"id":18446744073709551616,"interface":"lo0","direction":"inbound","read_timeout_ms":1}"#,
            br#"{"id":11,"interface":null,"direction":"inbound","read_timeout_ms":1}"#,
        ] {
            let mut reader = Cursor::new(framed(TYPE_CAPTURE_OPEN, body));
            assert!(
                matches!(read_msg(&mut reader), Err(ProtoError::BadJson(_))),
                "{}",
                String::from_utf8_lossy(body)
            );
        }
        // CaptureClose with a string id.
        let mut reader = Cursor::new(framed(TYPE_CAPTURE_CLOSE, br#"{"id":"11"}"#));
        assert!(matches!(read_msg(&mut reader), Err(ProtoError::BadJson(_))));

        // InjectResult: a missing or null `error` is `None` (success); a
        // non-string error is refused.
        for body in [
            &br#"{"request_id":1}"#[..],
            br#"{"request_id":1,"error":null}"#,
        ] {
            let mut reader = Cursor::new(framed(TYPE_INJECT_RESULT, body));
            assert_eq!(
                read_msg(&mut reader),
                Ok(Msg::InjectResult {
                    request_id: 1,
                    error: None,
                }),
                "{}",
                String::from_utf8_lossy(body)
            );
        }
        let mut reader = Cursor::new(framed(TYPE_INJECT_RESULT, br#"{"request_id":1,"error":5}"#));
        assert!(matches!(read_msg(&mut reader), Err(ProtoError::BadJson(_))));

        // HelloAck: caps must be an array of strings; an empty one is legal.
        let mut reader = Cursor::new(framed(
            TYPE_HELLO_ACK,
            br#"{"proto":1,"helper_version":"0.5.9","caps":"cap_net_raw"}"#,
        ));
        assert!(matches!(read_msg(&mut reader), Err(ProtoError::BadJson(_))));
        let mut reader = Cursor::new(framed(
            TYPE_HELLO_ACK,
            br#"{"proto":1,"helper_version":"0.5.9","caps":[]}"#,
        ));
        assert_eq!(
            read_msg(&mut reader),
            Ok(Msg::HelloAck {
                proto: 1,
                helper_version: "0.5.9".to_string(),
                caps: Vec::new(),
            })
        );
    }

    #[test]
    fn tester_transport_failure_mid_message_is_io_never_eof() {
        let wire = encode(&hello());

        // The peer dies after the length and type: Io carrying the message.
        let mut r = scripted(vec![
            Step::Data(wire[..5].to_vec()),
            Step::Fail(std::io::ErrorKind::ConnectionReset, "peer vanished"),
        ]);
        assert_eq!(
            read_msg(&mut r),
            Err(ProtoError::Io("peer vanished".to_string()))
        );
        assert_eq!(
            ProtoError::Io("peer vanished".to_string()).to_string(),
            "helper socket I/O error: peer vanished"
        );

        // A failure on the very first byte is a failure, not a clean close.
        let mut r = scripted(vec![Step::Fail(std::io::ErrorKind::BrokenPipe, "pipe")]);
        assert_eq!(read_msg(&mut r), Err(ProtoError::Io("pipe".to_string())));

        // The stream ends inside the length word: Io, not Eof.
        let mut r = scripted(vec![Step::Data(wire[..2].to_vec())]);
        match read_msg(&mut r) {
            Err(ProtoError::Io(msg)) => {
                assert!(msg.contains("failed to fill whole buffer"), "{msg}");
            }
            other => panic!("a cut length word must be Io, got {other:?}"),
        }

        // EINTR before the first byte, and again inside the payload, is
        // retried: the message still decodes.
        let mut r = scripted(vec![
            Step::Fail(std::io::ErrorKind::Interrupted, "eintr"),
            Step::Data(wire[..1].to_vec()),
            Step::Fail(std::io::ErrorKind::Interrupted, "eintr"),
            Step::Data(wire[1..9].to_vec()),
            Step::Fail(std::io::ErrorKind::Interrupted, "eintr"),
            Step::Data(wire[9..].to_vec()),
        ]);
        assert_eq!(read_msg(&mut r), Ok(hello()));
        assert_eq!(read_msg(&mut r), Err(ProtoError::Eof));

        // One byte per read: the framing reassembles it.
        let mut r = scripted(wire.iter().map(|b| Step::Data(vec![*b])).collect());
        assert_eq!(read_msg(&mut r), Ok(hello()));
        assert_eq!(read_msg(&mut r), Err(ProtoError::Eof));
    }

    #[test]
    fn tester_read_msg_stops_at_the_boundary_after_a_refusal() {
        // A refused message consumes exactly its own bytes, so the next one on
        // the stream is still readable (the caller closes anyway; this pins
        // that the reader never over- or under-reads).
        let refusals: [(Vec<u8>, ProtoError); 3] = [
            (framed(0x7f, b"junk"), ProtoError::UnknownType(0x7f)),
            (
                framed(TYPE_FRAME, &11u64.to_be_bytes()),
                ProtoError::BadBinary,
            ),
            (
                framed(TYPE_HELLO, b"{"),
                ProtoError::BadJson("EOF while parsing an object at line 1 column 1".to_string()),
            ),
        ];
        for (bad, err) in refusals {
            let mut stream = bad.clone();
            stream.extend_from_slice(&encode(&hello()));
            let mut reader = Cursor::new(stream);
            assert_eq!(read_msg(&mut reader), Err(err));
            assert_eq!(reader.position() as usize, bad.len());
            assert_eq!(read_msg(&mut reader), Ok(hello()));
            assert_eq!(read_msg(&mut reader), Err(ProtoError::Eof));
        }
    }

    /// Tester F1. An interface name that does not fit a `u16` must be refused
    /// by the peer whatever the frame length. Before the fix the encoder wrote
    /// the `0xFFFF` marker and then the frame bytes, so 70 000 frame bytes
    /// satisfied the claimed 65 535-byte name and the peer decoded an `Inject`
    /// with a 65 535-byte name of `'A'`s and the last 4 465 bytes as the frame.
    #[test]
    fn fix_f1_oversized_interface_name_is_always_bad_binary() {
        let wire = encode(&Msg::Inject {
            request_id: 1,
            interface: "a".repeat(65_536),
            bytes: vec![0x41; 70_000],
        });
        let mut reader = Cursor::new(wire);
        match read_msg(&mut reader) {
            Err(ProtoError::BadBinary) => {}
            Ok(Msg::Inject {
                interface, bytes, ..
            }) => panic!(
                "decoded as an Inject with a {}-byte name and {} frame bytes",
                interface.len(),
                bytes.len()
            ),
            other => panic!("must be BadBinary, got {other:?}"),
        }

        // Whatever the frame length, the wire is the request id, the 0xFFFF
        // marker and nothing else: the frame bytes are dropped, so the claimed
        // name is always longer than the payload and the peer always refuses.
        for frame_len in [0usize, 1, 2, 65_534, 65_535, 65_536, 70_000, 200_000] {
            let wire = encode(&Msg::Inject {
                request_id: 1,
                interface: "a".repeat(65_536),
                bytes: vec![0x41; frame_len],
            });
            assert_eq!(
                wire.len(),
                4 + 1 + 8 + 2,
                "frame_len {frame_len}: the frame bytes must not be written"
            );
            assert_eq!(&wire[..4], &11u32.to_be_bytes());
            assert_eq!(wire[4], TYPE_INJECT);
            assert_eq!(&wire[5..13], &1u64.to_be_bytes());
            assert_eq!(&wire[13..15], &[0xff, 0xff]);
            let mut reader = Cursor::new(wire);
            assert_eq!(
                read_msg(&mut reader),
                Err(ProtoError::BadBinary),
                "frame_len {frame_len}"
            );
        }
    }

    /// Tester F2. An unknown key at the top level of any JSON control payload
    /// is `BadJson` at this trust boundary (version skew is [`PROTO`]'s job),
    /// while an unknown key inside a scope entry is still ignored:
    /// `L4ScopeEntry` is the core's type, not this module's to tighten.
    #[test]
    fn fix_f2_unknown_top_level_key_is_bad_json_entry_level_key_is_ignored() {
        let set = scope_set();
        let mut v: serde_json::Value =
            serde_json::from_slice(&to_json(&set)).expect("a ScopeSet serializes");
        v["scope"][0]["filter"] = serde_json::json!("not port 22");
        let mut reader = Cursor::new(framed(TYPE_SCOPE_SET, v.to_string().as_bytes()));
        assert_eq!(
            read_msg(&mut reader),
            Ok(Msg::ScopeSet(set.clone())),
            "an unknown key inside an entry is ignored"
        );

        v["filter"] = serde_json::json!("not port 22");
        let mut reader = Cursor::new(framed(TYPE_SCOPE_SET, v.to_string().as_bytes()));
        match read_msg(&mut reader) {
            Err(ProtoError::BadJson(msg)) => {
                assert!(msg.starts_with("unknown field `filter`"), "{msg}");
            }
            other => panic!("a top-level unknown key must be BadJson, got {other:?}"),
        }

        // Every JSON control type: the canonical body decodes, the same body
        // with one stray key is BadJson naming that key.
        let bodies: [(u8, &[u8], &[u8]); 6] = [
            (
                TYPE_HELLO,
                &br#"{"proto":1,"core_version":"0.5.9"}"#[..],
                &br#"{"proto":1,"core_version":"0.5.9","future":true}"#[..],
            ),
            (
                TYPE_HELLO_ACK,
                &br#"{"proto":1,"helper_version":"0.5.9","caps":[]}"#[..],
                &br#"{"proto":1,"helper_version":"0.5.9","caps":[],"future":true}"#[..],
            ),
            (
                TYPE_CAPTURE_OPEN,
                &br#"{"id":11,"interface":"lo0","direction":"inbound","read_timeout_ms":250}"#[..],
                &br#"{"id":11,"interface":"lo0","direction":"inbound","read_timeout_ms":250,"future":true}"#[..],
            ),
            (
                TYPE_CAPTURE_CLOSE,
                &br#"{"id":11}"#[..],
                &br#"{"id":11,"future":true}"#[..],
            ),
            (
                TYPE_CAPTURE_CLOSED,
                &br#"{"capture_id":11,"reason":"x"}"#[..],
                &br#"{"capture_id":11,"reason":"x","future":true}"#[..],
            ),
            (
                TYPE_INJECT_RESULT,
                &br#"{"request_id":1,"error":null}"#[..],
                &br#"{"request_id":1,"error":null,"future":true}"#[..],
            ),
        ];
        for (ty, ok_body, bad_body) in bodies {
            let mut reader = Cursor::new(framed(ty, ok_body));
            assert!(
                read_msg(&mut reader).is_ok(),
                "{ty:#04x}: {}",
                String::from_utf8_lossy(ok_body)
            );
            let mut reader = Cursor::new(framed(ty, bad_body));
            match read_msg(&mut reader) {
                Err(ProtoError::BadJson(msg)) => {
                    assert!(
                        msg.starts_with("unknown field `future`"),
                        "{ty:#04x}: {msg}"
                    );
                }
                other => panic!(
                    "{ty:#04x}: {} must be BadJson, got {other:?}",
                    String::from_utf8_lossy(bad_body)
                ),
            }
        }
    }

    /// Tester re-run on F1. The fix's sweep stops at 200 000 frame bytes and
    /// uses one over-long name. This one takes the frame length through
    /// `MAX_FRAME - 1`, `MAX_FRAME` and `MAX_FRAME + 1` (where the `u16::MAX`
    /// marker and the `u32` length path meet) and several over-long names,
    /// ASCII and multi-byte. For every pair the wire is exactly the 15-byte
    /// header (so it can never exceed `MAX_FRAME`), the request id is intact,
    /// the peer answers `BadBinary`, and the refusal consumes exactly one
    /// message: a second refused message is read from the boundary and the
    /// stream then ends in `Eof`.
    #[test]
    fn tester_rerun_f1_oversized_name_sweep_reaches_max_frame_and_keeps_the_boundary() {
        let euro = "\u{20ac}".repeat(21_846);
        assert_eq!(
            euro.len(),
            65_538,
            "three-byte chars, one past the u16 marker"
        );
        let names: [(&str, String); 4] = [
            ("65_536 ascii", "a".repeat(65_536)),
            ("65_537 ascii", "b".repeat(65_537)),
            ("65_538 bytes as 21_846 euro signs", euro),
            ("1_000_000 ascii", "c".repeat(1_000_000)),
        ];
        let frame_lens = [
            0usize,
            1,
            65_534,
            65_535,
            65_536,
            200_000,
            MAX_FRAME - 1,
            MAX_FRAME,
            MAX_FRAME + 1,
        ];
        let request_id: u64 = 0xDEAD_BEEF_CAFE_F00D;
        for (label, name) in &names {
            for &frame_len in &frame_lens {
                let wire = encode(&Msg::Inject {
                    request_id,
                    interface: name.clone(),
                    bytes: vec![0x45; frame_len],
                });
                assert_eq!(
                    wire.len(),
                    15,
                    "{label}, frame_len {frame_len}: wire length"
                );
                assert!(
                    wire.len() <= 4 + MAX_FRAME,
                    "{label}, frame_len {frame_len}: the wire must fit MAX_FRAME"
                );
                assert_eq!(
                    &wire[..4],
                    &11u32.to_be_bytes(),
                    "{label}, frame_len {frame_len}: length field"
                );
                assert_eq!(wire[4], TYPE_INJECT, "{label}, frame_len {frame_len}");
                assert_eq!(
                    &wire[5..13],
                    &request_id.to_be_bytes(),
                    "{label}, frame_len {frame_len}: request id"
                );
                assert_eq!(
                    &wire[13..15],
                    &[0xff, 0xff],
                    "{label}, frame_len {frame_len}: u16::MAX marker"
                );

                let mut two = wire.clone();
                two.extend_from_slice(&wire);
                let mut reader = Cursor::new(two);
                assert_eq!(
                    read_msg(&mut reader),
                    Err(ProtoError::BadBinary),
                    "{label}, frame_len {frame_len}: first message"
                );
                assert_eq!(
                    read_msg(&mut reader),
                    Err(ProtoError::BadBinary),
                    "{label}, frame_len {frame_len}: second message from the boundary"
                );
                assert_eq!(
                    read_msg(&mut reader),
                    Err(ProtoError::Eof),
                    "{label}, frame_len {frame_len}: clean end after both"
                );
            }
        }
    }

    /// Tester re-run on F2. The fix's bodies put the stray key last. serde
    /// must refuse an unknown key wherever it sits and whatever it holds:
    /// first or last, with a `null`, an empty name, or a case variant of a
    /// real key; and a duplicated known key is refused too. Checked for
    /// `ScopeSet` and all six control types, each against its canonical body,
    /// which still decodes. Inside a scope entry the same stray keys stay
    /// ignored (`L4ScopeEntry` is the core's type).
    #[test]
    fn tester_rerun_f2_unknown_key_is_bad_json_in_any_position_and_shape() {
        let set = scope_set();
        let set_json = String::from_utf8(to_json(&set)).expect("UTF-8");
        let set_inner = set_json
            .strip_prefix('{')
            .and_then(|s| s.strip_suffix('}'))
            .expect("a JSON object");
        // (type, the canonical body without its braces, the name of one real
        // key whose case variant must count as unknown).
        let bodies: [(u8, &str, &str); 7] = [
            (TYPE_HELLO, r#""proto":1,"core_version":"0.5.9""#, "proto"),
            (
                TYPE_HELLO_ACK,
                r#""proto":1,"helper_version":"0.5.9","caps":[]"#,
                "caps",
            ),
            (
                TYPE_CAPTURE_OPEN,
                r#""id":11,"interface":"lo0","direction":"inbound","read_timeout_ms":250"#,
                "interface",
            ),
            (TYPE_CAPTURE_CLOSE, r#""id":11"#, "id"),
            (
                TYPE_CAPTURE_CLOSED,
                r#""capture_id":11,"reason":"x""#,
                "reason",
            ),
            (
                TYPE_INJECT_RESULT,
                r#""request_id":1,"error":null"#,
                "error",
            ),
            (TYPE_SCOPE_SET, set_inner, "scope"),
        ];
        for (ty, body, real_key) in bodies {
            let canonical = format!("{{{body}}}");
            let mut reader = Cursor::new(framed(ty, canonical.as_bytes()));
            assert!(
                read_msg(&mut reader).is_ok(),
                "{ty:#04x}: canonical body must decode: {canonical}"
            );

            let upper = real_key.to_ascii_uppercase();
            let strays: [(&str, String); 4] = [
                ("stray", r#""stray":null"#.to_string()),
                ("stray", r#""stray":{"deep":[1,{"x":true}]}"#.to_string()),
                ("", r#""":0"#.to_string()),
                (upper.as_str(), format!(r#""{upper}":1"#)),
            ];
            for (key, stray) in &strays {
                for doc in [format!("{{{stray},{body}}}"), format!("{{{body},{stray}}}")] {
                    let mut reader = Cursor::new(framed(ty, doc.as_bytes()));
                    match read_msg(&mut reader) {
                        Err(ProtoError::BadJson(msg)) => assert!(
                            msg.starts_with(&format!("unknown field `{key}`")),
                            "{ty:#04x}: {doc}: {msg}"
                        ),
                        other => panic!("{ty:#04x}: {doc} must be BadJson, got {other:?}"),
                    }
                }
            }

            // A real key given twice is refused as well, not last-wins.
            let dup = format!("{{{body},{body}}}");
            let mut reader = Cursor::new(framed(ty, dup.as_bytes()));
            match read_msg(&mut reader) {
                Err(ProtoError::BadJson(msg)) => {
                    assert!(
                        msg.starts_with("duplicate field `"),
                        "{ty:#04x}: {dup}: {msg}"
                    );
                }
                other => panic!("{ty:#04x}: {dup} must be BadJson, got {other:?}"),
            }
        }

        // The same stray keys inside a scope entry are ignored and the set
        // decodes to the literal value.
        let mut v: serde_json::Value = serde_json::from_str(&set_json).expect("object");
        v["scope"][0]["stray"] = serde_json::json!({"deep": [1, {"x": true}]});
        v["scope"][0][""] = serde_json::json!(0);
        v["scope"][0]["INTERFACE"] = serde_json::json!(1);
        let mut reader = Cursor::new(framed(TYPE_SCOPE_SET, v.to_string().as_bytes()));
        assert_eq!(read_msg(&mut reader), Ok(Msg::ScopeSet(set)));
    }
}
