//! Hand-rolled HTTP/2 frames for the observe-only h2 checks.
//!
//! The `h2` and `http` crates refuse a malformed header field by construction:
//! `http::HeaderName`/`HeaderValue` reject a CRLF, and `h2` validates the
//! pseudo-header set before it writes a frame. The observe-only checks of spec
//! D8.2 need to put exactly such a field on the wire and watch what the server
//! does with it, so this module writes and reads the handful of frames those
//! checks need, by hand:
//!
//! * the connection preface, a frame header, and the HPACK literal encoder used
//!   to build a HEADERS block (RFC 9113 §4.1, RFC 7541 §5.1, §6.2.2);
//! * a frame splitter plus payload parsers for SETTINGS, RST_STREAM and GOAWAY.
//!
//! The codec half is pure and I/O-free. [`RawH2Client::probe`] is the driver
//! that speaks those bytes over one connection: preface, SETTINGS exchange, at
//! most [`MAX_RAW_STREAMS`] streams, read until every stream has an outcome or
//! the peer resets, goes away or falls silent, then close. It is deliberately
//! small and strictly bounded — one connection per call, no retry, a read
//! budget, a per-read timeout and a whole-probe timeout, none of them
//! overridable — because its only callers are observe-only conformance checks
//! that watch how a server reacts, never checks that try to make it fail.
//!
//! ## When the driver may accept any server certificate
//!
//! [`TlsVerify::AcceptAny`] is permitted **only** under all of the conditions of
//! the T3 plan's session call S6 (coordinator decision 4, 2026-10-31):
//!
//! * the check has already called `host.baseline()`, so the guarded job client
//!   passed the scope gate for this authority before any raw byte was written;
//! * the raw connection goes to **that same authority** and no other — and,
//!   when the check hands over [`RawH2Target::addr`], to exactly the address
//!   that baseline came from, with no second name lookup;
//! * the request carries **no** session material — no `cookie`,
//!   `authorization`, `proxy-authorization` or `set-cookie` field, which
//!   [`RawH2Client::probe`] refuses outright;
//! * the probe is observe-only: its result is an observation of the server's
//!   HTTP/2 behaviour, not a trust decision, and nothing it reads is replayed.
//!
//! Outside those conditions use [`TlsVerify::WebPki`], which verifies against
//! the webpki roots like every other outbound client in this crate.
//!
//! There is deliberately **no** general HPACK decoder. The observe checks'
//! oracle is reset-vs-answer, not the response body, so the driver records
//! "HEADERS received, N bytes" and reads a `:status` only when the server
//! encoded it as a static-table index (`parse_status_indexed`). Decoding a
//! literal response field would need the dynamic table this module does not
//! keep.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use rustls::pki_types::ServerName;
use rustls::ClientConfig;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::Instant;
use tokio_rustls::TlsConnector;

use crate::sender::{
    split_authority, Dialer, HostResolver, ProbeStream, SystemResolver, TcpDialer, ALPN_H2,
};

/// The client connection preface (RFC 9113 §3.4), sent before any frame.
pub(crate) const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// Length of a frame header in bytes (RFC 9113 §4.1). Internal: the public
/// surface of this module is the nine-byte array [`frame_header`] returns.
pub(crate) const FRAME_HEADER_LEN: usize = 9;

/// Largest frame payload this codec will accept from a peer.
///
/// Equal to the RFC 9113 §6.5.2 minimum `SETTINGS_MAX_FRAME_SIZE`, which is what
/// a raw probe advertises: a peer that declares more than this is not answering
/// the probe we sent, and [`parse_frame`] refuses it rather than sizing a buffer
/// from an attacker-chosen length.
pub(crate) const MAX_FRAME_BYTES: usize = 16 * 1024;

/// The frame types this codec writes or recognises (RFC 9113 §6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FrameType {
    /// `DATA` (0x0).
    Data = 0x0,
    /// `HEADERS` (0x1).
    Headers = 0x1,
    /// `RST_STREAM` (0x3).
    RstStream = 0x3,
    /// `SETTINGS` (0x4).
    Settings = 0x4,
    /// `PING` (0x6).
    Ping = 0x6,
    /// `GOAWAY` (0x7).
    GoAway = 0x7,
    /// `WINDOW_UPDATE` (0x8).
    WindowUpdate = 0x8,
}

impl FrameType {
    /// The frame type for a wire type byte, or `None` for one this codec does
    /// not recognise (`PRIORITY`, `PUSH_PROMISE`, `CONTINUATION`, extensions).
    #[must_use]
    pub fn from_u8(v: u8) -> Option<FrameType> {
        match v {
            0x0 => Some(FrameType::Data),
            0x1 => Some(FrameType::Headers),
            0x3 => Some(FrameType::RstStream),
            0x4 => Some(FrameType::Settings),
            0x6 => Some(FrameType::Ping),
            0x7 => Some(FrameType::GoAway),
            0x8 => Some(FrameType::WindowUpdate),
            _ => None,
        }
    }
}

/// The frame flag bits this codec uses (RFC 9113 §6).
///
/// `ACK` and `END_STREAM` share bit 0; which one a `0x1` means depends on the
/// frame type, so they are two names for one value on purpose.
pub(crate) mod flags {
    /// `END_STREAM` on DATA and HEADERS.
    pub const END_STREAM: u8 = 0x1;
    /// `END_HEADERS` on HEADERS.
    pub const END_HEADERS: u8 = 0x4;
    /// `ACK` on SETTINGS and PING.
    pub const ACK: u8 = 0x1;
}

/// Encode a frame header: 24-bit length, 8-bit type, 8-bit flags, 31-bit stream
/// id with the reserved bit cleared (RFC 9113 §4.1).
///
/// `len` is the payload length and is truncated to its low 24 bits, which is all
/// the field holds; every caller in this crate writes a payload well under
/// [`MAX_FRAME_BYTES`].
#[must_use]
pub(crate) fn frame_header(len: u32, kind: FrameType, flags: u8, stream: u32) -> [u8; 9] {
    let l = len.to_be_bytes();
    let s = (stream & 0x7fff_ffff).to_be_bytes();
    [l[1], l[2], l[3], kind as u8, flags, s[0], s[1], s[2], s[3]]
}

/// One frame read off the wire.
///
/// `kind` is the raw type byte, not a [`FrameType`], so a frame type this codec
/// does not model still round-trips through the driver's read loop and can be
/// skipped by length.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Frame {
    /// The wire type byte (see [`FrameType::from_u8`]).
    pub kind: u8,
    /// The flag bits (see [`flags`]).
    pub flags: u8,
    /// The stream id, reserved bit cleared.
    pub stream: u32,
    /// The frame payload, `len` bytes.
    pub payload: Vec<u8>,
}

/// Split one whole frame off the front of `buf`.
///
/// Returns `Ok(Some((frame, consumed)))` when `buf` holds a complete frame,
/// where `consumed` is `9 + payload_len`; `Ok(None)` when it holds less than one
/// whole frame and the caller should read more; and `Err` when the declared
/// payload length exceeds [`MAX_FRAME_BYTES`].
///
/// # Errors
///
/// Returns an error whose message contains `frame too large` when the peer
/// declares a payload longer than [`MAX_FRAME_BYTES`].
pub(crate) fn parse_frame(buf: &[u8]) -> anyhow::Result<Option<(Frame, usize)>> {
    let Some(header) = buf.get(..FRAME_HEADER_LEN) else {
        return Ok(None);
    };
    let [l0, l1, l2, kind, flags, s0, s1, s2, s3] = header else {
        return Ok(None);
    };

    let declared = u32::from_be_bytes([0, *l0, *l1, *l2]);
    if declared as u64 > MAX_FRAME_BYTES as u64 {
        anyhow::bail!("frame too large: {declared} bytes declared, limit {MAX_FRAME_BYTES}");
    }
    // The bound above keeps this cast exact on every supported target.
    let len = declared as usize;
    let total = FRAME_HEADER_LEN + len;
    let Some(payload) = buf.get(FRAME_HEADER_LEN..total) else {
        return Ok(None);
    };

    let frame = Frame {
        kind: *kind,
        flags: *flags,
        stream: u32::from_be_bytes([*s0, *s1, *s2, *s3]) & 0x7fff_ffff,
        payload: payload.to_vec(),
    };
    Ok(Some((frame, total)))
}

/// One header field, as raw bytes.
///
/// [`RawHeader::raw`] is how a check sends a name or value containing a CRLF or
/// any other byte `http::HeaderName`/`HeaderValue` refuse by construction. The
/// encoder validates nothing: that is the point of the observe-only probes.
#[derive(Clone, PartialEq, Eq)]
pub struct RawHeader {
    /// The field name bytes, exactly as they go on the wire.
    pub name: Vec<u8>,
    /// The field value bytes, exactly as they go on the wire.
    pub value: Vec<u8>,
}

/// Prints `name=<N bytes>`: the value is never rendered.
///
/// A probe's field value is the one part of a plan that can carry something
/// worth keeping out of a log or an error — and [`RawH2Plan`] is debug-printed
/// by its callers, so the derived `Debug` would have carried every value with
/// it (review finding SEC-6).
impl std::fmt::Debug for RawHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}=<{} bytes>",
            String::from_utf8_lossy(&self.name),
            self.value.len()
        )
    }
}

impl RawHeader {
    /// A field from two strings.
    #[must_use]
    pub fn new(name: &str, value: &str) -> Self {
        Self {
            name: name.as_bytes().to_vec(),
            value: value.as_bytes().to_vec(),
        }
    }

    /// A field from raw bytes, including bytes a well-formed field may not hold.
    #[must_use]
    pub fn raw(name: &[u8], value: &[u8]) -> Self {
        Self {
            name: name.to_vec(),
            value: value.to_vec(),
        }
    }
}

/// Encode an HPACK integer (RFC 7541 §5.1).
///
/// `prefix_bits` (clamped to `1..=8`) is the width of the prefix inside
/// `first_byte`, whose prefix bits are cleared before the value is written, so
/// the caller passes only the pattern bits (for example `0x20` for a
/// dynamic-table size update's 5-bit prefix).
#[must_use]
pub(crate) fn encode_integer(value: usize, prefix_bits: u8, first_byte: u8) -> Vec<u8> {
    let prefix_bits = prefix_bits.clamp(1, 8);
    let max_prefix = (1usize << prefix_bits) - 1;
    // `max_prefix` is at most 255, so both casts below are exact.
    let head = first_byte & !(max_prefix as u8);

    if value < max_prefix {
        return vec![head | value as u8];
    }

    let mut out = vec![head | max_prefix as u8];
    let mut rest = value - max_prefix;
    while rest >= 128 {
        out.push(((rest % 128) + 128) as u8);
        rest /= 128;
    }
    out.push(rest as u8);
    out
}

/// Encode a HEADERS block: every field as an HPACK **literal header field
/// without indexing, new name** (RFC 7541 §6.2.2).
///
/// Each field is a `0x00` pattern byte, then the name as a 7-bit-prefix length
/// and its bytes, then the value the same way. No Huffman coding, no
/// dynamic-table insert, and no validation of either the name or the value — a
/// probe's whole purpose can be the byte the `http` crate would reject.
#[must_use]
pub(crate) fn encode_block(headers: &[RawHeader]) -> Vec<u8> {
    let mut out = Vec::new();
    for header in headers {
        // 0x00: literal without indexing, name not in the table.
        out.push(0x00);
        // 0x00 first byte: 7-bit length prefix with the Huffman bit clear.
        out.extend_from_slice(&encode_integer(header.name.len(), 7, 0x00));
        out.extend_from_slice(&header.name);
        out.extend_from_slice(&encode_integer(header.value.len(), 7, 0x00));
        out.extend_from_slice(&header.value);
    }
    out
}

/// Read a SETTINGS payload into its `(identifier, value)` pairs (RFC 9113
/// §6.5.1). A trailing partial pair is ignored.
#[must_use]
pub(crate) fn parse_settings(payload: &[u8]) -> Vec<(u16, u32)> {
    payload
        .chunks_exact(6)
        .filter_map(|c| match c {
            [i0, i1, v0, v1, v2, v3] => Some((
                u16::from_be_bytes([*i0, *i1]),
                u32::from_be_bytes([*v0, *v1, *v2, *v3]),
            )),
            _ => None,
        })
        .collect()
}

/// Read an RST_STREAM payload's error code (RFC 9113 §6.4), or `None` when the
/// payload is not exactly four bytes.
#[must_use]
pub(crate) fn parse_rst_stream(payload: &[u8]) -> Option<u32> {
    match payload {
        [e0, e1, e2, e3] => Some(u32::from_be_bytes([*e0, *e1, *e2, *e3])),
        _ => None,
    }
}

/// Read a GOAWAY payload's `(last_stream_id, error_code)` (RFC 9113 §6.8), or
/// `None` when the payload is shorter than eight bytes. Any trailing opaque
/// debug data is ignored — it is peer-controlled and never surfaced as evidence.
#[must_use]
pub(crate) fn parse_goaway(payload: &[u8]) -> Option<(u32, u32)> {
    match payload {
        [l0, l1, l2, l3, e0, e1, e2, e3, ..] => Some((
            u32::from_be_bytes([*l0, *l1, *l2, *l3]) & 0x7fff_ffff,
            u32::from_be_bytes([*e0, *e1, *e2, *e3]),
        )),
        _ => None,
    }
}

/// `PADDED` on a HEADERS frame (RFC 9113 §6.2). Not in [`flags`]: this codec
/// never *writes* a padded frame, it only has to read one correctly.
const HEADERS_PADDED: u8 = 0x8;

/// `PRIORITY` on a HEADERS frame (RFC 9113 §6.2), likewise read-only.
const HEADERS_PRIORITY: u8 = 0x20;

/// The header block fragment inside a HEADERS payload (RFC 9113 §6.2): the
/// pad-length byte, the 5-byte stream-dependency/weight field and the trailing
/// padding are frame furniture, not block bytes.
///
/// `None` when the frame is malformed — a `PADDED` frame with no pad-length
/// byte, a padding run longer than the payload, or a `PRIORITY` field that does
/// not fit. A caller reads no status from such a frame rather than reading the
/// furniture as one (review finding SEC-4).
fn headers_block_fragment(frame_flags: u8, payload: &[u8]) -> Option<&[u8]> {
    let mut rest = payload;
    let mut pad = 0usize;
    if frame_flags & HEADERS_PADDED != 0 {
        let (len, tail) = rest.split_first()?;
        pad = *len as usize;
        rest = tail;
    }
    if frame_flags & HEADERS_PRIORITY != 0 {
        rest = rest.get(5..)?;
    }
    rest.get(..rest.len().checked_sub(pad)?)
}

/// Read a `:status` from a response HEADERS block, but only when the server
/// encoded it as the block's first field and as an HPACK **indexed** field from
/// the static table (RFC 7541 Appendix A, entries 8-14).
///
/// Returns `None` for every other encoding, including a literal `:status` or a
/// status not in the static table. That is enough for the observe-only checks,
/// whose oracle is reset-vs-answer; see the module docs.
#[must_use]
pub(crate) fn parse_status_indexed(block: &[u8]) -> Option<u16> {
    match block.first()? {
        0x88 => Some(200),
        0x89 => Some(204),
        0x8a => Some(206),
        0x8b => Some(304),
        0x8c => Some(400),
        0x8d => Some(404),
        0x8e => Some(500),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// The connection driver
// ---------------------------------------------------------------------------

/// The most streams a raw probe ever opens on its one connection (spec D8.2,
/// AC T3-3). Not overridable: a plan asking for more is refused before the
/// driver dials.
pub const MAX_RAW_STREAMS: u8 = 8;

/// The most bytes a probe reads from the peer across the whole conversation.
/// A peer that keeps talking past this has the connection hung up on it.
const RAW_READ_BUDGET: usize = 256 * 1024;

/// How long one read may wait before the driver treats the peer as silent.
const RAW_READ_TIMEOUT: Duration = Duration::from_secs(5);

/// How long the whole probe — dial, TLS, handshake, streams — may take.
const RAW_TOTAL_TIMEOUT: Duration = Duration::from_secs(15);

/// How long the default dialer waits for a TCP connection.
const RAW_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// How long the driver waits for the connection to shut down cleanly.
const RAW_CLOSE_TIMEOUT: Duration = Duration::from_secs(1);

/// How much the driver reads at a time.
const RAW_READ_CHUNK: usize = 8 * 1024;

/// `RST_STREAM` error code `CANCEL` (RFC 9113 §7), what a rapid-reset pair
/// sends.
const RST_CANCEL: u32 = 0x8;

/// `RST_STREAM` error code `REFUSED_STREAM` (RFC 9113 §7), the signal that the
/// peer is shedding load rather than failing a stream.
const RST_REFUSED_STREAM: u32 = 0x7;

/// Header names a raw probe never puts on the wire, whatever a caller asks
/// for: no probe of this kind needs session material, and an observation is
/// not worth leaking one (spec anti-goals, plan "Redaction").
const FORBIDDEN_HEADERS: [&str; 4] = [
    "cookie",
    "authorization",
    "proxy-authorization",
    "set-cookie",
];

/// Where a raw probe connects. `scheme` is `http` or `https`; `authority` is
/// `host[:port]` and is the authority the check already cleared with
/// `host.baseline()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawH2Target {
    /// `http` (prior-knowledge cleartext h2) or `https` (ALPN `h2`).
    pub scheme: String,
    /// `host[:port]`; the scheme's default port applies when none is given.
    pub authority: String,
    /// The address the caller already validated — for the observe checks, the
    /// peer the guarded baseline response actually came from
    /// (`ProbeHost::baseline_peer_addr`, plan amendment A5 / T3-7).
    ///
    /// `Some(addr)`: the driver does **not** consult the resolver at all and
    /// dials exactly `addr`, so a record that flipped between the baseline
    /// and the probe cannot move the connection (the DNS-rebinding window).
    /// The SSRF and live-scope gate still runs, on that one address, and its
    /// port must be the authority's port or the probe is refused before the
    /// dial.
    ///
    /// `None`: the name is resolved and every answer is gated, exactly as
    /// before.
    pub addr: Option<SocketAddr>,
}

/// What the probe does once the SETTINGS exchange is done.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RawH2Mode {
    /// One HEADERS frame on stream 1 carrying `RawH2Plan::headers`, then wait
    /// for its outcome.
    SingleRequest,
    /// One stream per block, opened in order on stream ids 1, 3, 5, ...; each
    /// stream is awaited to its [`StreamOutcome`] before the next opens, so a
    /// check that sends several malformed variants learns which one the peer
    /// tolerated. `RawH2Plan::headers` is ignored. Never more than
    /// [`MAX_RAW_STREAMS`] blocks, refused before the dial (plan amendment A3).
    Blocks(Vec<Vec<RawHeader>>),
    /// `pairs` HEADERS frames, each immediately cancelled with
    /// `RST_STREAM(CANCEL)`. Never more than [`MAX_RAW_STREAMS`] pairs, and
    /// never repeated: the check looks for a mitigation signal, not a flood.
    RapidReset {
        /// How many open/reset pairs to send.
        pairs: u8,
    },
    /// Open no stream at all: read the peer's SETTINGS and leave.
    SettingsOnly,
}

impl RawH2Mode {
    /// How many streams this mode opens.
    fn stream_count(&self) -> usize {
        match self {
            RawH2Mode::SettingsOnly => 0,
            RawH2Mode::SingleRequest => 1,
            RawH2Mode::RapidReset { pairs } => *pairs as usize,
            RawH2Mode::Blocks(blocks) => blocks.len(),
        }
    }

    /// The header blocks this mode writes, one per stream, in order.
    fn blocks<'a>(&'a self, headers: &'a [RawHeader]) -> Vec<&'a [RawHeader]> {
        match self {
            RawH2Mode::SettingsOnly => Vec::new(),
            RawH2Mode::SingleRequest => vec![headers],
            RawH2Mode::RapidReset { pairs } => vec![headers; *pairs as usize],
            RawH2Mode::Blocks(blocks) => blocks.iter().map(Vec::as_slice).collect(),
        }
    }
}

/// One probe: where to go, what header block to send, and how.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawH2Plan {
    /// The authority to probe.
    pub target: RawH2Target,
    /// The header fields, encoded verbatim — including the malformed field a
    /// check is testing. The driver adds nothing and validates nothing beyond
    /// the forbidden-name guard.
    pub headers: Vec<RawHeader>,
    /// What to do with the connection.
    pub mode: RawH2Mode,
    /// How many streams this plan declares it will open. Must be at most
    /// [`MAX_RAW_STREAMS`] and at least what `mode` opens; both are checked
    /// before the driver dials.
    pub streams: u8,
}

/// What became of one stream the probe opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamOutcome {
    /// The peer answered with HEADERS. `status` is filled only when the peer
    /// encoded `:status` as a static-table index (see `parse_status_indexed`).
    Headers {
        /// The response status, when it was readable without HPACK state.
        status: Option<u16>,
    },
    /// The peer reset the stream with this error code.
    Reset {
        /// The RFC 9113 §7 error code.
        error_code: u32,
    },
    /// The peer refused the stream (`REFUSED_STREAM`) — a load-shedding signal.
    Refused,
    /// Nothing came back before the driver stopped reading.
    Timeout,
}

/// What one probe observed. Carries no response body and no peer-supplied text:
/// the observe-only checks' oracle is reset-vs-answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawH2Observation {
    /// The `(identifier, value)` pairs from the peer's first SETTINGS frame.
    pub settings: Vec<(u16, u32)>,
    /// One entry per stream the plan opened, in stream-id order (1, 3, 5, ...).
    pub streams: Vec<StreamOutcome>,
    /// The peer's `GOAWAY(last_stream_id, error_code)`, if it sent one.
    pub goaway: Option<(u32, u32)>,
    /// True when the conversation ended with the connection torn down rather
    /// than finished: the peer sent EOF or `GOAWAY`, or the driver hung up
    /// because the read budget or the whole-probe timeout was spent. False
    /// when every stream reached an outcome on a healthy connection the
    /// driver then closed itself, and false when the peer merely went silent
    /// (`peer_silent`).
    pub connection_closed: bool,
    /// True when the probe ended because the peer sent nothing for
    /// `RAW_READ_TIMEOUT` while the connection stayed open: a silent peer,
    /// not a closed one. A server that discards cancelled streams without a
    /// word looks exactly like this, so the checks must not read it as a
    /// hang-up (live run against hyper, 2026-11-01). Never set together
    /// with `connection_closed`.
    pub peer_silent: bool,
    /// Wall-clock time from the dial to the close, in milliseconds.
    pub elapsed_ms: u32,
}

/// How the probe verifies the server certificate on an `https` target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsVerify {
    /// Verify against the webpki roots, like the rest of the crate.
    WebPki,
    /// Accept whatever the server presents. Allowed only under the conditions
    /// in this module's documentation.
    AcceptAny,
}

/// Opens one raw HTTP/2 connection per [`probe`](RawH2Client::probe) call.
///
/// The dialer and resolver are the same seams [`crate::sender::HttpSender`]
/// uses, so the whole driver runs over `tokio::io::duplex` in tests without
/// binding a port.
pub struct RawH2Client {
    tls: TlsVerify,
    dialer: Arc<dyn Dialer>,
    resolver: Arc<dyn HostResolver>,
    ssrf: Option<crate::sender::SsrfGate>,
    /// Set by the first `probe` that runs without an SSRF gate, so the
    /// warning about it is logged once per client, not once per probe.
    warned_no_gate: AtomicBool,
    /// The connect timeout the default dialer was built with, kept so a test
    /// can inspect what `new` handed it (review findings QM-7, T-D2).
    #[cfg(test)]
    connect_timeout: Duration,
}

impl RawH2Client {
    /// A client that dials real TCP and resolves through the system resolver.
    #[must_use]
    pub fn new(verify: TlsVerify) -> Self {
        // The sender's dialer, with the raw driver's own, shorter connect
        // timeout: one implementation, two postures (review finding Q4).
        let connect_timeout = RAW_CONNECT_TIMEOUT;
        Self {
            tls: verify,
            dialer: Arc::new(TcpDialer::new(connect_timeout)),
            resolver: Arc::new(SystemResolver),
            ssrf: None,
            warned_no_gate: AtomicBool::new(false),
            #[cfg(test)]
            connect_timeout,
        }
    }

    /// The connect timeout the default dialer was built with.
    #[cfg(test)]
    pub(crate) fn connect_timeout(&self) -> Duration {
        self.connect_timeout
    }

    /// Enforce the SSRF policy against `scope` on every probe: refuse a
    /// private, loopback or metadata address unless an in-scope IP literal
    /// lifts it, exactly as [`crate::sender::HttpSender::with_ssrf`] does for
    /// the reissue path. The check runs on every address the probe might go
    /// to — every address the target resolved to, or the single
    /// [`RawH2Target::addr`] the caller pre-validated — immediately before
    /// the dial, so neither a short-TTL record flipped after the check
    /// already passed `host.baseline()` nor an address a caller handed over
    /// can steer an accept-any probe at an internal address.
    ///
    /// Opt-in: a client built without this behaves exactly as before. Every
    /// live caller (the checks crate's raw h2 runner) is expected to configure
    /// it.
    #[must_use]
    pub fn with_ssrf(
        mut self,
        policy: aitm_core::SsrfPolicy,
        scope: Arc<dyn aitm_core::ScopeRateGuard>,
    ) -> Self {
        self.ssrf = Some(crate::sender::SsrfGate { policy, scope });
        self
    }

    /// Replace the dial seam (tests, or a caller with its own transport).
    #[must_use]
    pub fn with_dialer(mut self, dialer: Arc<dyn Dialer>) -> Self {
        self.dialer = dialer;
        self
    }

    /// Replace the name resolver.
    #[must_use]
    pub fn with_resolver(mut self, resolver: Arc<dyn HostResolver>) -> Self {
        self.resolver = resolver;
        self
    }

    /// Run one probe: exactly one connection, no retry, every cap enforced.
    ///
    /// # Errors
    ///
    /// Returns an error — before any byte is written — when the plan asks for
    /// more than [`MAX_RAW_STREAMS`] streams, when its mode opens more streams
    /// than it declares, when it carries a forbidden header, when the target
    /// is unusable (bad scheme, bad authority, no address), or when its
    /// pre-validated [`RawH2Target::addr`] is on a port other than the
    /// authority's. After that it errors only on a transport failure, or when
    /// `RAW_TOTAL_TIMEOUT` runs out before a connection exists (there is
    /// nothing to observe); a peer that resets, goes away or says nothing is
    /// an observation, not an error.
    pub async fn probe(&self, plan: &RawH2Plan) -> Result<RawH2Observation> {
        let encoded = validate_and_encode(plan)?;
        let streams = encoded.len();

        // A runner that forgot `with_ssrf` probes wherever the name points.
        // Say so once per client, loudly enough to be seen (review finding
        // SEC-13); the gate itself stays opt-in.
        if self.ssrf.is_none() && !self.warned_no_gate.swap(true, Ordering::Relaxed) {
            tracing::warn!("raw h2 probe running without an SSRF gate");
        }

        let scheme = plan.target.scheme.to_ascii_lowercase();
        let tls = match scheme.as_str() {
            "https" => true,
            "http" => false,
            other => anyhow::bail!("raw h2 probe cannot speak scheme {other:?}"),
        };
        let (host, port) = split_authority(&plan.target.authority, &scheme)?;
        let authority = aitm_core::Authority::new(&host, port).to_string();

        // A pre-validated address on another port is not the peer the
        // caller's baseline reported, whatever else it is: refused here,
        // before the gate and before the dial (plan amendment A5, T3-7).
        if let Some(addr) = plan.target.addr {
            if addr.port() != port {
                anyhow::bail!(
                    "raw h2 probe: the pre-validated address {addr} is not on the port of \
                     authority {authority}"
                );
            }
        }

        let mut obs = RawH2Observation {
            settings: Vec::new(),
            streams: vec![StreamOutcome::Timeout; streams],
            goaway: None,
            connection_closed: false,
            peer_silent: false,
            elapsed_ms: 0,
        };

        let started = Instant::now();
        // Set once the transport is established (after TLS and ALPN for an
        // `https` target). A cap that fires before then observed nothing.
        let mut connected = false;
        let outcome = tokio::time::timeout(RAW_TOTAL_TIMEOUT, async {
            // A caller that already validated an address (the observe
            // checks hand over the peer their guarded baseline answered
            // from) is dialled there and the name is never looked up: no
            // second resolve, so no window for a record to flip between the
            // baseline and the probe (plan amendment A5, T3-7).
            //
            // Otherwise the resolve runs, *inside* the cap: a name server
            // that never answers must not hold the probe open past the
            // whole-probe deadline.
            let ips = match plan.target.addr {
                Some(addr) => vec![addr.ip()],
                None => self.resolver.resolve(host.clone(), port).await?,
            };
            // Then the gate, on every address in hand — the one the caller
            // pre-validated, or every address this name answered —
            // immediately before the dial, so the address the driver
            // connects to is one the operator's policy and scope actually
            // allow. A pre-validated address is not exempt: it is checked
            // the same way (spec reviewer, PR 2a F9 range).
            // The live scope permit is held until the conversation ends, so
            // the connection is paced and counted as one active egress and a
            // scope change during the probe is seen on the next one.
            let _permit = match &self.ssrf {
                Some(gate) => Some(gate.check_live("raw h2 probe", &authority, &host, &ips)?),
                None => None,
            };
            let addr = match plan.target.addr {
                Some(addr) => addr,
                None => ips
                    .into_iter()
                    .next()
                    .map(|ip| SocketAddr::new(ip, port))
                    .ok_or_else(|| anyhow!("no address for {host}:{port}"))?,
            };
            let mut stream = self.connect(addr, &host, tls).await?;
            connected = true;
            let result = converse(&mut *stream, plan, &encoded, &mut obs).await;
            let _ = tokio::time::timeout(RAW_CLOSE_TIMEOUT, stream.shutdown()).await;
            result
        })
        .await;
        obs.elapsed_ms = u32::try_from(started.elapsed().as_millis()).unwrap_or(u32::MAX);

        match outcome {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Err(e),
            // The whole-probe cap ran out before the resolve, the dial or the
            // TLS handshake finished: no peer was ever talked to, so an
            // observation shaped like a server hang-up would be a lie
            // (review finding SEC-11).
            Err(_) if !connected => {
                anyhow::bail!("raw h2 probe to {host}: no connection within the cap")
            }
            // The whole-probe cap ran out mid-conversation: the connection is
            // dropped here, and whatever the peer had already said stands as
            // the observation.
            Err(_) => obs.connection_closed = true,
        }
        Ok(obs)
    }

    /// Dial once and wrap in TLS for an `https` target. No retry: a failure
    /// here is the probe's result.
    async fn connect(
        &self,
        addr: SocketAddr,
        host: &str,
        tls: bool,
    ) -> Result<Box<dyn ProbeStream>> {
        let dialed = self
            .dialer
            .dial(addr)
            .await
            .with_context(|| format!("raw h2 dial {addr}"))?;

        if !tls {
            return Ok(dialed);
        }
        let name = ServerName::try_from(host.to_string())
            .map_err(|e| anyhow!("invalid server name {host:?}: {e}"))?;
        let tls_stream = TlsConnector::from(self.client_config()?)
            .connect(name, dialed)
            .await
            .with_context(|| format!("raw h2 TLS to {host}"))?;
        if tls_stream.get_ref().1.alpn_protocol() != Some(ALPN_H2) {
            anyhow::bail!("raw h2 probe: {host} did not negotiate ALPN h2");
        }
        Ok(Box::new(tls_stream))
    }

    /// The TLS config: ALPN `h2` only, verified per [`TlsVerify`].
    fn client_config(&self) -> Result<Arc<ClientConfig>> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let builder = ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .context("raw h2 TLS versions")?;
        let mut cfg = match self.tls {
            TlsVerify::AcceptAny => builder
                .dangerous()
                .with_custom_certificate_verifier(crate::module::accept_any_verifier(provider))
                .with_no_client_auth(),
            TlsVerify::WebPki => {
                let mut roots = rustls::RootCertStore::empty();
                roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
                builder.with_root_certificates(roots).with_no_client_auth()
            }
        };
        cfg.alpn_protocols = vec![ALPN_H2.to_vec()];
        Ok(Arc::new(cfg))
    }
}

/// Check a plan against the caps and the forbidden-header list, encode its
/// header blocks and check their size, and return the encoded blocks — one per
/// stream, in the order they will be written.
///
/// Everything a plan can be refused for is decided here, before the dial, so a
/// refused plan costs the target not even a connection (review finding Q7).
fn validate_and_encode(plan: &RawH2Plan) -> Result<Vec<Vec<u8>>> {
    if plan.streams > MAX_RAW_STREAMS {
        anyhow::bail!(
            "a raw h2 probe opens at most {MAX_RAW_STREAMS} streams on its one connection; the \
             plan declares {}",
            plan.streams
        );
    }
    let wanted = plan.mode.stream_count();
    if wanted > MAX_RAW_STREAMS as usize {
        anyhow::bail!(
            "a raw h2 probe opens at most {MAX_RAW_STREAMS} streams on its one connection; this \
             mode opens {wanted}"
        );
    }
    if wanted > plan.streams as usize {
        anyhow::bail!(
            "the plan declares {} stream(s) but its mode opens {wanted}",
            plan.streams
        );
    }

    let blocks = plan.mode.blocks(&plan.headers);
    let mut checked = blocks.clone();
    // `plan.headers` is scanned even when the mode ignores it (`Blocks`,
    // `SettingsOnly`): a forbidden header anywhere in a plan is refused.
    checked.push(&plan.headers);
    for header in checked.into_iter().flatten() {
        let name = String::from_utf8_lossy(&header.name).to_ascii_lowercase();
        for forbidden in FORBIDDEN_HEADERS {
            if name == forbidden {
                // The name only: a value is exactly what must not be echoed.
                anyhow::bail!("a raw h2 probe never sends a `{forbidden}` header");
            }
        }
    }

    // The driver never writes a frame larger than the RFC 9113 §6.5.2 minimum
    // `SETTINGS_MAX_FRAME_SIZE` every peer must accept.
    let mut encoded = Vec::with_capacity(wanted);
    for block in blocks {
        let bytes = encode_block(block);
        if bytes.len() > MAX_FRAME_BYTES {
            anyhow::bail!(
                "raw h2 HEADERS block of {} bytes exceeds the {MAX_FRAME_BYTES}-byte frame cap",
                bytes.len()
            );
        }
        encoded.push(bytes);
    }
    debug_assert_eq!(encoded.len(), wanted);
    Ok(encoded)
}

/// What a read attempt produced.
enum Next {
    /// One whole frame.
    Frame(Frame),
    /// The peer closed the connection.
    Eof,
    /// Nothing arrived within [`RAW_READ_TIMEOUT`].
    Idle,
    /// [`RAW_READ_BUDGET`] is spent.
    Budget,
}

/// Reads whole frames off a stream, under the read budget and the per-read
/// timeout.
#[derive(Default)]
struct FrameReader {
    buf: Vec<u8>,
    read: usize,
}

impl FrameReader {
    /// The next whole frame, or why there is not one.
    async fn next(&mut self, stream: &mut dyn ProbeStream) -> Result<Next> {
        loop {
            if let Some((frame, used)) = parse_frame(&self.buf)? {
                self.buf.drain(..used);
                return Ok(Next::Frame(frame));
            }
            if self.read >= RAW_READ_BUDGET {
                return Ok(Next::Budget);
            }

            let start = self.buf.len();
            self.buf.resize(start + RAW_READ_CHUNK, 0);
            let read = tokio::time::timeout(RAW_READ_TIMEOUT, stream.read(&mut self.buf[start..]));
            let n = match read.await {
                Err(_) => {
                    self.buf.truncate(start);
                    return Ok(Next::Idle);
                }
                Ok(Err(e)) => {
                    self.buf.truncate(start);
                    return Err(anyhow::Error::new(e).context("raw h2 read"));
                }
                Ok(Ok(n)) => n,
            };
            self.buf.truncate(start + n);
            if n == 0 {
                return Ok(Next::Eof);
            }
            self.read += n;
        }
    }
}

/// Record `outcome` for the stream `id` carries, unless that stream already has
/// an outcome or the driver has not opened it.
///
/// `opened` is how many streams this probe has actually written HEADERS for. A
/// frame naming anything beyond that — a server id, an even id, a stream the
/// plan has not reached yet — is recorded for nobody: otherwise a peer could
/// fill a later slot and make the sequential `Blocks` mode open the next block
/// before the one in flight was answered (review finding SEC-5).
fn record(obs: &mut RawH2Observation, id: u32, outcome: StreamOutcome, opened: usize) {
    if id == 0 || id.is_multiple_of(2) {
        return;
    }
    let index = usize::try_from((id - 1) / 2).unwrap_or(usize::MAX);
    if index >= opened {
        return;
    }
    if let Some(slot) = obs.streams.get_mut(index) {
        if *slot == StreamOutcome::Timeout {
            *slot = outcome;
        }
    }
}

/// The conversation on an established connection: preface, SETTINGS exchange,
/// the plan's streams, then read until every stream has an outcome or the
/// connection ends.
async fn converse(
    stream: &mut dyn ProbeStream,
    plan: &RawH2Plan,
    encoded: &[Vec<u8>],
    obs: &mut RawH2Observation,
) -> Result<()> {
    let mut opening = PREFACE.to_vec();
    opening.extend_from_slice(&frame_header(0, FrameType::Settings, 0x00, 0));
    stream.write_all(&opening).await.context("raw h2 preface")?;
    stream.flush().await.context("raw h2 preface")?;

    let mut reader = FrameReader::default();

    // Read until the peer's own SETTINGS arrives, then acknowledge it once.
    loop {
        match reader.next(stream).await? {
            Next::Frame(frame) => {
                if frame.kind == FrameType::GoAway as u8 {
                    obs.goaway = parse_goaway(&frame.payload);
                    obs.connection_closed = true;
                    return Ok(());
                }
                if frame.kind == FrameType::Settings as u8 && frame.flags & flags::ACK == 0 {
                    obs.settings = parse_settings(&frame.payload);
                    stream
                        .write_all(&frame_header(0, FrameType::Settings, flags::ACK, 0))
                        .await
                        .context("raw h2 settings ack")?;
                    stream.flush().await.context("raw h2 settings ack")?;
                    break;
                }
            }
            Next::Idle => {
                obs.peer_silent = true;
                return Ok(());
            }
            Next::Eof | Next::Budget => {
                obs.connection_closed = true;
                return Ok(());
            }
        }
    }

    if encoded.is_empty() {
        return Ok(());
    }

    let rapid_reset = matches!(plan.mode, RawH2Mode::RapidReset { .. });

    if let RawH2Mode::Blocks(_) = plan.mode {
        // Sequential: one stream at a time, each awaited to its outcome before
        // the next opens. A silent or closed peer ends the probe; the blocks not
        // yet written stay `Timeout` and cost the target nothing.
        for (index, block) in encoded.iter().enumerate() {
            let id = u32::try_from(index * 2 + 1).unwrap_or(u32::MAX);
            write_headers(stream, id, block, false).await?;
            if !read_outcomes(stream, &mut reader, obs, index + 1).await? {
                return Ok(());
            }
        }
        return Ok(());
    }

    // Batch: every stream's HEADERS back to back, then read until each has an
    // outcome or the connection ends.
    for (index, block) in encoded.iter().enumerate() {
        let id = u32::try_from(index * 2 + 1).unwrap_or(u32::MAX);
        write_headers(stream, id, block, rapid_reset).await?;
    }
    read_outcomes(stream, &mut reader, obs, encoded.len()).await?;
    Ok(())
}

/// Write one HEADERS frame (END_HEADERS | END_STREAM) carrying `block` on
/// stream `id`, followed by `RST_STREAM(CANCEL)` when `reset` (a rapid-reset
/// pair), and flush.
async fn write_headers(
    stream: &mut dyn ProbeStream,
    id: u32,
    block: &[u8],
    reset: bool,
) -> Result<()> {
    let block_len = u32::try_from(block.len()).unwrap_or(u32::MAX);
    let mut out = frame_header(
        block_len,
        FrameType::Headers,
        flags::END_HEADERS | flags::END_STREAM,
        id,
    )
    .to_vec();
    out.extend_from_slice(block);
    if reset {
        out.extend_from_slice(&frame_header(4, FrameType::RstStream, 0x00, id));
        out.extend_from_slice(&RST_CANCEL.to_be_bytes());
    }
    stream.write_all(&out).await.context("raw h2 headers")?;
    stream.flush().await.context("raw h2 headers")?;
    Ok(())
}

/// Read frames until every one of the first `opened` streams has an outcome,
/// or the connection ends. Returns whether the connection is still usable.
///
/// The condition is per slot, not a count: in `Blocks` mode the slot that
/// matters is the one just opened, and a count could be satisfied by some
/// other slot (review finding SEC-5).
async fn read_outcomes(
    stream: &mut dyn ProbeStream,
    reader: &mut FrameReader,
    obs: &mut RawH2Observation,
    opened: usize,
) -> Result<bool> {
    while obs
        .streams
        .iter()
        .take(opened)
        .any(|o| *o == StreamOutcome::Timeout)
    {
        match reader.next(stream).await? {
            Next::Frame(frame) => match FrameType::from_u8(frame.kind) {
                Some(FrameType::GoAway) => {
                    obs.goaway = parse_goaway(&frame.payload);
                    obs.connection_closed = true;
                    return Ok(false);
                }
                Some(FrameType::Headers) => {
                    // The *block*, not the payload: a `PADDED` or `PRIORITY`
                    // frame carries bytes in front of it that are not HPACK.
                    let status = headers_block_fragment(frame.flags, &frame.payload)
                        .and_then(parse_status_indexed);
                    record(obs, frame.stream, StreamOutcome::Headers { status }, opened);
                }
                Some(FrameType::RstStream) => {
                    if let Some(code) = parse_rst_stream(&frame.payload) {
                        let outcome = if code == RST_REFUSED_STREAM {
                            StreamOutcome::Refused
                        } else {
                            StreamOutcome::Reset { error_code: code }
                        };
                        record(obs, frame.stream, outcome, opened);
                    }
                }
                // DATA, PING, WINDOW_UPDATE, SETTINGS beyond the first and any
                // frame type this codec does not model are read and dropped:
                // the oracle is reset-vs-answer.
                _ => {}
            },
            // A silent peer ends the probe too, but the connection is still
            // open: the observation says so, and says it apart from a close.
            Next::Idle => {
                obs.peer_silent = true;
                return Ok(false);
            }
            Next::Eof | Next::Budget => {
                obs.connection_closed = true;
                return Ok(false);
            }
        }
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The module's public surface is the driver and its types — what
    /// `crates/aitm-scan-checks-http` imports — and nothing else: the codec
    /// (preface, frame header, HPACK literal encoder, payload parsers) is
    /// `pub(crate)`, used by the driver and by `h2_sender`'s tests (final
    /// quality review FQ-3). Pinned on the source, the way the checks crate
    /// pins its one raw-client construction, because the compiler cannot say
    /// "nothing else is public".
    #[test]
    fn only_the_driver_and_its_types_are_public() {
        // The library half only: this test's own literals must not satisfy it.
        let src = include_str!("raw_h2.rs")
            .split("#[cfg(test)]\nmod tests {")
            .next()
            .expect("split yields at least one piece");
        for private in [
            "pub(crate) const PREFACE:",
            "pub(crate) const MAX_FRAME_BYTES:",
            "pub(crate) enum FrameType {",
            "pub(crate) mod flags {",
            "pub(crate) fn frame_header(",
            "pub(crate) struct Frame {",
            "pub(crate) fn parse_frame(",
            "pub(crate) fn encode_integer(",
            "pub(crate) fn encode_block(",
            "pub(crate) fn parse_settings(",
            "pub(crate) fn parse_rst_stream(",
            "pub(crate) fn parse_goaway(",
            "pub(crate) fn parse_status_indexed(",
        ] {
            assert!(src.contains(private), "{private} is not crate-private");
        }
        for public in [
            "pub const MAX_RAW_STREAMS:",
            "pub struct RawHeader {",
            "pub struct RawH2Target {",
            "pub enum RawH2Mode {",
            "pub struct RawH2Plan {",
            "pub enum StreamOutcome {",
            "pub struct RawH2Observation {",
            "pub enum TlsVerify {",
            "pub struct RawH2Client {",
            "pub fn new(verify: TlsVerify)",
            "pub fn with_ssrf(",
            "pub fn with_dialer(",
            "pub fn with_resolver(",
            "pub async fn probe(",
        ] {
            assert!(src.contains(public), "{public} is not public");
        }
    }

    /// Q4: the raw driver shares the sender's dialer, but not its 30 s connect
    /// timeout — a probe gives a target ten seconds to answer and no more, and
    /// that has to leave room inside the whole-probe cap for the handshake and
    /// the streams.
    ///
    /// QM-7 / T-D2: the client built by `RawH2Client::new` is what is
    /// inspected, not the constant against itself, so swapping the argument
    /// at the construction site is what this test catches.
    #[test]
    fn the_raw_driver_keeps_its_own_connect_timeout() {
        assert_eq!(RAW_CONNECT_TIMEOUT, Duration::from_secs(10));
        assert!(
            RAW_CONNECT_TIMEOUT < RAW_TOTAL_TIMEOUT,
            "a connect timeout of {RAW_CONNECT_TIMEOUT:?} outlives the whole-probe cap of \
             {RAW_TOTAL_TIMEOUT:?}, which would make it unreachable"
        );
        assert_eq!(
            RawH2Client::new(TlsVerify::WebPki).connect_timeout(),
            RAW_CONNECT_TIMEOUT,
            "a default client dials with the raw driver's own connect timeout"
        );
        assert_eq!(
            TcpDialer::new(RAW_CONNECT_TIMEOUT).connect_timeout(),
            RAW_CONNECT_TIMEOUT,
            "the shared dialer carries the timeout it was built with"
        );
    }

    #[test]
    fn the_preface_is_the_rfc_string() {
        assert_eq!(PREFACE, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
        assert_eq!(PREFACE.len(), 24);
    }

    #[test]
    fn frame_header_encodes_length_type_flags_and_stream() {
        assert_eq!(
            frame_header(
                1,
                FrameType::Headers,
                flags::END_HEADERS | flags::END_STREAM,
                1
            ),
            [0x00, 0x00, 0x01, 0x01, 0x05, 0x00, 0x00, 0x00, 0x01]
        );
    }

    #[test]
    fn a_literal_without_indexing_encodes_a_pseudo_header() {
        assert_eq!(
            encode_block(&[RawHeader::new(":path", "/x")]),
            vec![0x00, 0x05, b':', b'p', b'a', b't', b'h', 0x02, b'/', b'x']
        );
    }

    #[test]
    fn the_encoder_accepts_a_crlf_in_a_name_and_in_a_value() {
        let in_name = encode_block(&[RawHeader::raw(b"x-a\r\nx-b", b"1")]);
        assert_eq!(&in_name[..2], &[0x00, 0x08]);
        assert!(in_name.windows(2).any(|w| w == [0x0d, 0x0a]));
        assert_eq!(
            in_name,
            vec![0x00, 0x08, b'x', b'-', b'a', 0x0d, 0x0a, b'x', b'-', b'b', 0x01, b'1']
        );

        let in_value = encode_block(&[RawHeader::raw(b"x-a", b"1\r\nx-b: 2")]);
        assert!(in_value.windows(2).any(|w| w == [0x0d, 0x0a]));
        assert_eq!(
            in_value,
            vec![
                0x00, 0x03, b'x', b'-', b'a', 0x09, b'1', 0x0d, 0x0a, b'x', b'-', b'b', b':', b' ',
                b'2'
            ]
        );
    }

    /// SEC-6: a header's value is the one thing a probe may be carrying that
    /// must never be printed. `Debug` names the field and sizes the value.
    #[test]
    fn raw_header_debug_redacts_the_value() {
        let shown = format!("{:?}", RawHeader::new("x-token", "secret"));
        assert_eq!(shown, "x-token=<6 bytes>");
    }

    /// The redaction holds through every container that prints a header: a
    /// whole plan is debug-printed by callers and log lines.
    #[test]
    fn a_plan_debug_redacts_every_header_value() {
        let plan = RawH2Plan {
            target: RawH2Target {
                scheme: "https".into(),
                authority: "origin.test".into(),
                addr: None,
            },
            headers: vec![RawHeader::new("x-token", "secret")],
            mode: RawH2Mode::Blocks(vec![vec![RawHeader::raw(b"x-other", b"hush")]]),
            streams: 1,
        };
        let shown = format!("{plan:?}");
        assert!(shown.contains("x-token=<6 bytes>"), "{shown}");
        assert!(shown.contains("x-other=<4 bytes>"), "{shown}");
        assert!(!shown.contains("secret"), "{shown}");
        assert!(!shown.contains("hush"), "{shown}");
    }

    #[test]
    fn encode_integer_uses_the_continuation_form() {
        assert_eq!(encode_integer(1337, 5, 0x20), vec![0x3f, 0x9a, 0x0a]);
        // Below the prefix maximum the value rides in the first byte alone.
        assert_eq!(encode_integer(10, 5, 0x20), vec![0x2a]);
        assert_eq!(encode_integer(5, 7, 0x00), vec![0x05]);
    }

    #[test]
    fn parse_settings_reads_each_pair() {
        let payload = [
            0x00, 0x03, 0x00, 0x00, 0x00, 0x80, 0x00, 0x04, 0x00, 0x00, 0xff, 0xff,
        ];
        assert_eq!(
            parse_settings(&payload),
            vec![(3u16, 128u32), (4u16, 65535u32)]
        );
        assert_eq!(parse_settings(&[]), vec![]);
    }

    #[test]
    fn parse_frame_needs_a_whole_frame() -> anyhow::Result<()> {
        assert!(parse_frame(&[0x00, 0x00, 0x06, 0x04, 0x00])?.is_none());

        let mut buf = frame_header(6, FrameType::Settings, 0x00, 0).to_vec();
        buf.extend_from_slice(&[0x00, 0x03, 0x00, 0x00, 0x00, 0x80]);
        let (frame, used) = parse_frame(&buf)?.expect("a whole SETTINGS frame parses");
        assert_eq!(used, 9 + 6);
        assert_eq!(frame.kind, 0x04);
        assert_eq!(frame.flags, 0x00);
        assert_eq!(frame.stream, 0);
        assert_eq!(frame.payload, vec![0x00, 0x03, 0x00, 0x00, 0x00, 0x80]);
        assert_eq!(parse_settings(&frame.payload), vec![(3u16, 128u32)]);
        Ok(())
    }

    #[test]
    fn parse_frame_refuses_an_oversized_declared_length() {
        let oversized = u32::try_from(MAX_FRAME_BYTES + 1).expect("fits in 24 bits");
        let header = frame_header(oversized, FrameType::Data, 0x00, 1);
        let err = parse_frame(&header).expect_err("an oversized declared length is refused");
        assert!(
            err.to_string().contains("frame too large"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn parse_rst_stream_reads_the_error_code() {
        assert_eq!(parse_rst_stream(&[0x00, 0x00, 0x00, 0x01]), Some(1));
        assert_eq!(parse_rst_stream(&[0x00, 0x00, 0x00, 0x0b]), Some(11));
        assert_eq!(parse_rst_stream(&[0x00, 0x00, 0x01]), None);
    }

    #[test]
    fn parse_goaway_reads_the_last_stream_and_the_error_code() {
        assert_eq!(
            parse_goaway(&[0x80, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x01]),
            Some((3, 1))
        );
        // The trailing opaque debug data is ignored.
        assert_eq!(
            parse_goaway(&[0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, b'h', b'i']),
            Some((5, 0))
        );
        assert_eq!(parse_goaway(&[0x00, 0x00, 0x00, 0x05]), None);
    }

    #[test]
    fn parse_status_indexed_maps_the_static_table() {
        assert_eq!(parse_status_indexed(&[0x88]), Some(200));
        assert_eq!(parse_status_indexed(&[0x8c]), Some(400));
        assert_eq!(parse_status_indexed(&[0x8d]), Some(404));
        assert_eq!(parse_status_indexed(&[0x00]), None);
        assert_eq!(parse_status_indexed(&[]), None);
    }

    /// SEC-4: the block fragment of a HEADERS payload under every flag
    /// combination the codec can meet.
    #[test]
    fn the_headers_block_fragment_skips_padding_and_priority() {
        // No flags: the whole payload is the block.
        assert_eq!(headers_block_fragment(0x00, &[0x88]), Some(&[0x88][..]));
        // PADDED: one pad-length byte in front, that many bytes behind.
        assert_eq!(
            headers_block_fragment(HEADERS_PADDED, &[0x02, 0x8d, 0x00, 0x00]),
            Some(&[0x8d][..])
        );
        // PRIORITY: a 5-byte stream-dependency + weight field in front.
        assert_eq!(
            headers_block_fragment(HEADERS_PRIORITY, &[0, 0, 0, 1, 16, 0x8e]),
            Some(&[0x8e][..])
        );
        // Both, together.
        assert_eq!(
            headers_block_fragment(
                HEADERS_PADDED | HEADERS_PRIORITY,
                &[0x01, 0, 0, 0, 1, 16, 0x89, 0x00]
            ),
            Some(&[0x89][..])
        );
        // A pad length longer than what is left is malformed.
        assert_eq!(headers_block_fragment(HEADERS_PADDED, &[0x88, 0x88]), None);
        // So is a PRIORITY field that does not fit.
        assert_eq!(
            headers_block_fragment(HEADERS_PRIORITY, &[0, 0, 0, 1]),
            None
        );
        // And an empty PADDED payload has not even a pad-length byte.
        assert_eq!(headers_block_fragment(HEADERS_PADDED, &[]), None);
    }

    #[test]
    fn frame_type_round_trips_through_its_wire_byte() {
        assert_eq!(FrameType::from_u8(0x01), Some(FrameType::Headers));
        assert_eq!(FrameType::from_u8(0x07), Some(FrameType::GoAway));
        assert_eq!(FrameType::from_u8(0x09), None);
        assert_eq!(FrameType::Settings as u8, 0x04);
        assert_eq!(FrameType::RstStream as u8, 0x03);
    }
}

#[cfg(test)]
mod driver_tests {
    use super::*;

    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
    use std::sync::{Arc, Mutex};

    use anyhow::{anyhow, Result};
    use futures::future::BoxFuture;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

    use crate::sender::{Dialer, HostResolver, ProbeStream};

    /// How the scripted peer answers each HEADERS frame it reads.
    #[derive(Clone, Copy)]
    enum Answer {
        /// Say nothing — the stream stays open until the driver gives up.
        Nothing,
        /// `RST_STREAM` with this error code.
        Reset(u32),
        /// HEADERS whose block is one static-table indexed `:status` byte.
        Status(u8),
        /// A `PADDED` HEADERS frame: `pad_len` as the pad-length byte, then
        /// `indexed` as the block, then `padding` bytes of padding. The three
        /// are independent so a test can script a well-formed padded frame and
        /// a lying pad length alike.
        PaddedStatus {
            pad_len: u8,
            indexed: u8,
            padding: u8,
        },
        /// `GOAWAY(last_stream_id, error_code)`, once, after the first HEADERS.
        GoAway(u32, u32),
        /// `RST_STREAM(REFUSED_STREAM)` for a *different* stream id than the
        /// one the HEADERS arrived on, and nothing for that one.
        ResetOther(u32),
        /// Drop the connection on the first HEADERS: no reset, no GOAWAY,
        /// just a FIN — what a reset-rate mitigation in front of an origin
        /// does.
        HangUp,
    }

    /// What the scripted peer does, and what it saw while doing it.
    struct Script {
        /// The SETTINGS pairs it sends once the preface has arrived.
        settings: Vec<(u16, u32)>,
        answer: Answer,
        /// Write SETTINGS frames forever instead of reading (budget probe).
        flood: bool,
        /// Read the preface and then say nothing at all (timeout probe).
        silent: bool,
        /// Read the preface and hang up before sending any SETTINGS.
        hang_up_before_settings: bool,
    }

    impl Script {
        fn new(settings: Vec<(u16, u32)>, answer: Answer) -> Self {
            Self {
                settings,
                answer,
                flood: false,
                silent: false,
                hang_up_before_settings: false,
            }
        }
    }

    /// What the scripted peer observed on the wire.
    #[derive(Default)]
    struct ServerLog {
        preface: Vec<u8>,
        headers_streams: Vec<u32>,
        /// The HEADERS payload (the encoded block) per HEADERS frame, in order.
        headers_blocks: Vec<Vec<u8>>,
        rst_streams: Vec<u32>,
        settings_acks: usize,
        bytes_written: usize,
    }

    fn settings_payload(pairs: &[(u16, u32)]) -> Vec<u8> {
        let mut out = Vec::with_capacity(pairs.len() * 6);
        for (id, value) in pairs {
            out.extend_from_slice(&id.to_be_bytes());
            out.extend_from_slice(&value.to_be_bytes());
        }
        out
    }

    fn framed(kind: FrameType, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
        let len = u32::try_from(payload.len()).expect("a test frame fits in 24 bits");
        let mut out = frame_header(len, kind, flags, stream).to_vec();
        out.extend_from_slice(payload);
        out
    }

    /// Drive the far end of the duplex: read the preface, play the script,
    /// record every client frame.
    async fn run_script<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
        mut io: S,
        script: Script,
        log: Arc<Mutex<ServerLog>>,
    ) {
        let mut preface = vec![0u8; PREFACE.len()];
        if io.read_exact(&mut preface).await.is_err() {
            return;
        }
        log.lock().expect("server log").preface = preface;

        if script.silent {
            // Hold the connection open, saying nothing, past any client timeout.
            tokio::time::sleep(Duration::from_secs(3600)).await;
            return;
        }

        if script.hang_up_before_settings {
            // Dropping `io` here closes the duplex: the driver reads EOF
            // where it expected the peer's SETTINGS.
            return;
        }

        let settings = framed(
            FrameType::Settings,
            0x00,
            0,
            &settings_payload(&script.settings),
        );
        if io.write_all(&settings).await.is_err() {
            return;
        }

        if script.flood {
            loop {
                if io.write_all(&settings).await.is_err() {
                    return;
                }
                log.lock().expect("server log").bytes_written += settings.len();
            }
        }

        let mut buf: Vec<u8> = Vec::new();
        let mut chunk = vec![0u8; 4096];
        let mut sent_goaway = false;
        loop {
            let n = match io.read(&mut chunk).await {
                Ok(0) | Err(_) => return,
                Ok(n) => n,
            };
            buf.extend_from_slice(&chunk[..n]);
            while let Ok(Some((frame, used))) = parse_frame(&buf) {
                buf.drain(..used);
                let reply = match FrameType::from_u8(frame.kind) {
                    Some(FrameType::Settings) if frame.flags & flags::ACK != 0 => {
                        log.lock().expect("server log").settings_acks += 1;
                        None
                    }
                    Some(FrameType::RstStream) => {
                        log.lock()
                            .expect("server log")
                            .rst_streams
                            .push(frame.stream);
                        None
                    }
                    Some(FrameType::Headers) => {
                        {
                            let mut log = log.lock().expect("server log");
                            log.headers_streams.push(frame.stream);
                            log.headers_blocks.push(frame.payload.clone());
                        }
                        match script.answer {
                            Answer::Nothing => None,
                            Answer::Reset(code) => Some(framed(
                                FrameType::RstStream,
                                0x00,
                                frame.stream,
                                &code.to_be_bytes(),
                            )),
                            Answer::Status(indexed) => Some(framed(
                                FrameType::Headers,
                                flags::END_HEADERS | flags::END_STREAM,
                                frame.stream,
                                &[indexed],
                            )),
                            Answer::PaddedStatus {
                                pad_len,
                                indexed,
                                padding,
                            } => {
                                let mut payload = vec![pad_len, indexed];
                                payload.extend(std::iter::repeat_n(0u8, padding as usize));
                                Some(framed(
                                    FrameType::Headers,
                                    flags::END_HEADERS | flags::END_STREAM | HEADERS_PADDED,
                                    frame.stream,
                                    &payload,
                                ))
                            }
                            Answer::GoAway(last, code) if !sent_goaway => {
                                sent_goaway = true;
                                let mut payload = last.to_be_bytes().to_vec();
                                payload.extend_from_slice(&code.to_be_bytes());
                                Some(framed(FrameType::GoAway, 0x00, 0, &payload))
                            }
                            Answer::GoAway(..) => None,
                            Answer::ResetOther(other) => Some(framed(
                                FrameType::RstStream,
                                0x00,
                                other,
                                &7u32.to_be_bytes(),
                            )),
                            // Return, dropping `io`: the client sees a FIN
                            // with nothing said about the stream.
                            Answer::HangUp => return,
                        }
                    }
                    _ => None,
                };
                if let Some(bytes) = reply {
                    if io.write_all(&bytes).await.is_err() {
                        return;
                    }
                }
            }
        }
    }

    /// Hands out the one duplex client half and records every dial attempt
    /// with the address it was asked for.
    struct CountingDialer {
        stream: Mutex<Option<DuplexStream>>,
        calls: AtomicUsize,
        addrs: Mutex<Vec<SocketAddr>>,
    }

    impl CountingDialer {
        fn calls(&self) -> usize {
            self.calls.load(AtomicOrdering::SeqCst)
        }

        /// The addresses the driver asked for, in order.
        fn addrs(&self) -> Vec<SocketAddr> {
            self.addrs.lock().expect("dialer addresses").clone()
        }
    }

    impl Dialer for CountingDialer {
        fn dial(&self, addr: SocketAddr) -> BoxFuture<'static, Result<Box<dyn ProbeStream>>> {
            self.calls.fetch_add(1, AtomicOrdering::SeqCst);
            self.addrs.lock().expect("dialer addresses").push(addr);
            let next = self
                .stream
                .lock()
                .expect("dialer stream")
                .take()
                .map(|s| Box::new(s) as Box<dyn ProbeStream>);
            Box::pin(
                async move { next.ok_or_else(|| anyhow!("the dialer was asked to dial twice")) },
            )
        }
    }

    /// Every name answers loopback, so the dial seam decides what we talk to.
    struct LoopbackResolver;

    impl HostResolver for LoopbackResolver {
        fn resolve(&self, _host: String, _port: u16) -> BoxFuture<'static, Result<Vec<IpAddr>>> {
            Box::pin(async { Ok(vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]) })
        }
    }

    const DUPLEX_CAPACITY: usize = 64 * 1024;

    /// A client wired to a freshly spawned scripted peer.
    fn peer(script: Script) -> (RawH2Client, Arc<CountingDialer>, Arc<Mutex<ServerLog>>) {
        let (client_half, server_half) = tokio::io::duplex(DUPLEX_CAPACITY);
        let log = Arc::new(Mutex::new(ServerLog::default()));
        tokio::spawn(run_script(server_half, script, log.clone()));
        let dialer = Arc::new(CountingDialer {
            stream: Mutex::new(Some(client_half)),
            calls: AtomicUsize::new(0),
            addrs: Mutex::new(Vec::new()),
        });
        let client = RawH2Client::new(TlsVerify::AcceptAny)
            .with_dialer(dialer.clone())
            .with_resolver(Arc::new(LoopbackResolver));
        (client, dialer, log)
    }

    /// Yield until the scripted peer has finished reading what the driver
    /// wrote. The probe can return before the peer's task has drained the last
    /// frames out of the duplex, so peer-side assertions wait for them.
    async fn settled(log: &Arc<Mutex<ServerLog>>, done: impl Fn(&ServerLog) -> bool) {
        for _ in 0..10_000 {
            if done(&log.lock().expect("server log")) {
                return;
            }
            tokio::task::yield_now().await;
        }
        panic!("the scripted peer never read what the driver wrote");
    }

    fn plan(mode: RawH2Mode, streams: u8) -> RawH2Plan {
        RawH2Plan {
            target: RawH2Target {
                scheme: "http".to_string(),
                authority: "origin.test:80".to_string(),
                addr: None,
            },
            headers: vec![
                RawHeader::new(":method", "GET"),
                RawHeader::new(":scheme", "http"),
                RawHeader::new(":authority", "origin.test"),
                RawHeader::new(":path", "/"),
            ],
            mode,
            streams,
        }
    }

    #[tokio::test]
    async fn probe_reads_the_servers_settings_and_closes() {
        let (client, dialer, log) = peer(Script::new(vec![(3, 128), (4, 65535)], Answer::Nothing));

        let obs = client
            .probe(&plan(RawH2Mode::SettingsOnly, 0))
            .await
            .expect("the probe completes");

        assert_eq!(obs.settings, vec![(3u16, 128u32), (4u16, 65535u32)]);
        assert_eq!(obs.streams, vec![]);
        assert_eq!(obs.goaway, None);
        assert!(!obs.connection_closed);
        assert_eq!(dialer.calls(), 1);

        settled(&log, |l| l.settings_acks == 1).await;
        let log = log.lock().expect("server log");
        assert_eq!(log.preface, PREFACE.to_vec());
        assert_eq!(log.settings_acks, 1);
        assert_eq!(log.headers_streams, Vec::<u32>::new());
    }

    #[tokio::test]
    async fn a_reset_stream_is_recorded_with_its_error_code() {
        let (client, dialer, log) = peer(Script::new(vec![(3, 100)], Answer::Reset(1)));

        let obs = client
            .probe(&plan(RawH2Mode::SingleRequest, 1))
            .await
            .expect("the probe completes");

        assert_eq!(obs.streams, vec![StreamOutcome::Reset { error_code: 1 }]);
        assert_eq!(dialer.calls(), 1);
        assert_eq!(log.lock().expect("server log").headers_streams, vec![1u32]);
    }

    #[tokio::test]
    async fn a_refused_stream_is_recorded_as_refused() {
        // REFUSED_STREAM (0x7) is the mitigation signal the rapid-reset check
        // looks for, so it is its own outcome rather than a reset code.
        let (client, _dialer, _log) = peer(Script::new(vec![(3, 100)], Answer::Reset(0x7)));

        let obs = client
            .probe(&plan(RawH2Mode::SingleRequest, 1))
            .await
            .expect("the probe completes");

        assert_eq!(obs.streams, vec![StreamOutcome::Refused]);
    }

    #[tokio::test]
    async fn an_answered_stream_records_its_status() {
        let (client, _dialer, _log) = peer(Script::new(vec![(3, 100)], Answer::Status(0x88)));

        let obs = client
            .probe(&plan(RawH2Mode::SingleRequest, 1))
            .await
            .expect("the probe completes");

        assert_eq!(
            obs.streams,
            vec![StreamOutcome::Headers { status: Some(200) }]
        );
    }

    /// SEC-4: a `PADDED` HEADERS frame's first byte is the pad length, not the
    /// block. Read past it (and the trailing padding) before the status.
    #[tokio::test]
    async fn a_padded_headers_frame_is_read_past_its_pad_length() {
        let (client, dialer, _log) = peer(Script::new(
            vec![(3, 100)],
            Answer::PaddedStatus {
                pad_len: 1,
                indexed: 0x8d,
                padding: 1,
            },
        ));

        let obs = client
            .probe(&plan(RawH2Mode::SingleRequest, 1))
            .await
            .expect("the probe completes");

        assert_eq!(
            obs.streams,
            vec![StreamOutcome::Headers { status: Some(404) }],
            "the pad-length byte must not be mistaken for the block"
        );
        assert_eq!(dialer.calls(), 1);
    }

    /// SEC-4: a pad length of `0x88` with nothing behind it is a malformed
    /// frame, not "status 200" — the byte the naive reader would have taken.
    #[tokio::test]
    async fn a_lying_pad_length_is_not_read_as_a_status() {
        let (client, dialer, _log) = peer(Script::new(
            vec![(3, 100)],
            Answer::PaddedStatus {
                pad_len: 0x88,
                indexed: 0x88,
                padding: 0,
            },
        ));

        let obs = client
            .probe(&plan(RawH2Mode::SingleRequest, 1))
            .await
            .expect("the probe completes");

        assert_eq!(
            obs.streams,
            vec![StreamOutcome::Headers { status: None }],
            "a padded frame whose padding does not fit has no readable status"
        );
        assert_eq!(dialer.calls(), 1);
    }

    #[tokio::test]
    async fn the_plan_refuses_more_than_eight_streams() {
        let (client, dialer, _log) = peer(Script::new(vec![], Answer::Nothing));

        let err = client
            .probe(&plan(RawH2Mode::SingleRequest, 9))
            .await
            .expect_err("nine streams is refused");

        assert_eq!(
            err.to_string(),
            format!(
                "a raw h2 probe opens at most {MAX_RAW_STREAMS} streams on its one connection; \
                 the plan declares 9"
            )
        );
        assert_eq!(dialer.calls(), 0);
    }

    #[tokio::test]
    async fn the_mode_may_not_outrun_the_cap_either() {
        let (client, dialer, _log) = peer(Script::new(vec![], Answer::Nothing));

        let err = client
            .probe(&plan(RawH2Mode::RapidReset { pairs: 9 }, 8))
            .await
            .expect_err("nine reset pairs is refused");

        assert_eq!(
            err.to_string(),
            format!(
                "a raw h2 probe opens at most {MAX_RAW_STREAMS} streams on its one connection; \
                 this mode opens 9"
            )
        );
        assert_eq!(dialer.calls(), 0);
    }

    #[tokio::test]
    async fn rapid_reset_opens_exactly_the_requested_pairs() {
        let (client, dialer, log) = peer(Script::new(vec![(3, 100)], Answer::Reset(0x8)));

        let obs = client
            .probe(&plan(RawH2Mode::RapidReset { pairs: 8 }, 8))
            .await
            .expect("the probe completes");

        assert_eq!(obs.streams, vec![StreamOutcome::Reset { error_code: 8 }; 8]);
        assert_eq!(dialer.calls(), 1);

        settled(&log, |l| l.rst_streams.len() == 8).await;
        let log = log.lock().expect("server log");
        assert_eq!(log.headers_streams, vec![1, 3, 5, 7, 9, 11, 13, 15]);
        assert_eq!(log.rst_streams, vec![1, 3, 5, 7, 9, 11, 13, 15]);
    }

    #[tokio::test]
    async fn a_goaway_ends_the_probe() {
        // The peer answers the first HEADERS with `GOAWAY(1, ENHANCE_YOUR_CALM)`
        // and says nothing else.
        let (client, dialer, _log) = peer(Script::new(vec![(3, 100)], Answer::GoAway(1, 11)));

        let obs = client
            .probe(&plan(RawH2Mode::RapidReset { pairs: 8 }, 8))
            .await
            .expect("the probe completes");

        assert_eq!(
            obs.goaway,
            Some((1, 11)),
            "the last stream id and the error code are the observation"
        );
        assert_eq!(obs.streams.len(), 8, "one slot per stream the plan opened");
        assert_eq!(
            obs.streams,
            vec![StreamOutcome::Timeout; 8],
            "the probe stops at the GOAWAY: no stream ever got an outcome"
        );
        assert!(obs.connection_closed);
        assert_eq!(dialer.calls(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn a_silent_server_times_out_bounded() {
        let (client, dialer, _log) = peer(Script {
            silent: true,
            ..Script::new(vec![], Answer::Nothing)
        });

        let started = tokio::time::Instant::now();
        let obs = client
            .probe(&plan(RawH2Mode::SingleRequest, 1))
            .await
            .expect("the probe completes");
        let waited = started.elapsed();

        assert_eq!(obs.streams, vec![StreamOutcome::Timeout]);
        assert_eq!(obs.settings, vec![]);
        // Virtual time: a peer that never sends its SETTINGS costs exactly one
        // read timeout, not a byte of slack.
        assert_eq!(
            waited, RAW_READ_TIMEOUT,
            "the probe took {waited:?}; one silent read should cost exactly {RAW_READ_TIMEOUT:?}"
        );
        assert_eq!(dialer.calls(), 1);
    }

    /// A peer that drops the connection in the middle of the probe — no
    /// `GOAWAY`, no `RST_STREAM`, just a FIN — is an **observation**, not an
    /// error: the streams it never answered stay `Timeout` and
    /// `connection_closed` records the hang-up. `h2-rapid-reset-mitigation`
    /// reads exactly this shape as "the peer cut us off" and calls it clean,
    /// so EOF has to set the flag and not merely end the read loop (tester
    /// whole-branch pass: dropping `Next::Eof` from the mid-conversation arm
    /// left all 238 lib tests green).
    #[tokio::test(start_paused = true)]
    async fn a_peer_that_hangs_up_mid_probe_closes_the_connection_without_a_timeout() {
        let (client, dialer, _log) = peer(Script::new(vec![(3, 100)], Answer::HangUp));

        let started = tokio::time::Instant::now();
        let obs = client
            .probe(&plan(RawH2Mode::RapidReset { pairs: 8 }, 8))
            .await
            .expect("a hang-up is an observation, not an error");
        let waited = started.elapsed();

        assert!(obs.connection_closed, "the peer hung up on the probe");
        assert_eq!(obs.goaway, None, "a FIN is not a GOAWAY");
        assert_eq!(obs.streams, vec![StreamOutcome::Timeout; 8]);
        assert_eq!(
            obs.settings,
            vec![(3, 100)],
            "the peer's SETTINGS arrived before it hung up"
        );
        // Virtual time: EOF is noticed when it arrives, not after a read
        // timeout's worth of waiting.
        assert_eq!(
            waited,
            Duration::ZERO,
            "a hang-up cost {waited:?}; it should cost no wait at all"
        );
        assert_eq!(dialer.calls(), 1);
    }

    /// The same hang-up one step earlier, before the peer's SETTINGS ever
    /// arrive: nothing was observed, and the probe still returns an
    /// observation that says the connection closed rather than an error or a
    /// timeout (tester whole-branch pass: dropping `Next::Eof` from the
    /// SETTINGS arm left all 238 lib tests green).
    #[tokio::test(start_paused = true)]
    async fn a_peer_that_hangs_up_before_its_settings_closes_the_connection() {
        let (client, dialer, _log) = peer(Script {
            hang_up_before_settings: true,
            ..Script::new(vec![(3, 100)], Answer::Nothing)
        });

        let started = tokio::time::Instant::now();
        let obs = client
            .probe(&plan(RawH2Mode::SingleRequest, 1))
            .await
            .expect("a hang-up is an observation, not an error");
        let waited = started.elapsed();

        assert!(obs.connection_closed);
        assert_eq!(obs.settings, Vec::new(), "nothing was ever advertised");
        assert_eq!(obs.streams, vec![StreamOutcome::Timeout]);
        assert_eq!(obs.goaway, None);
        assert_eq!(
            waited,
            Duration::ZERO,
            "a hang-up cost {waited:?}; it should cost no wait at all"
        );
        assert_eq!(dialer.calls(), 1);
    }

    #[tokio::test]
    async fn the_driver_refuses_a_cookie_header() {
        let (client, dialer, _log) = peer(Script::new(vec![], Answer::Nothing));

        let mut p = plan(RawH2Mode::SingleRequest, 1);
        p.headers.push(RawHeader::new("cookie", "a=b"));
        let err = client.probe(&p).await.expect_err("a cookie is refused");

        assert!(
            err.to_string().contains("cookie"),
            "unexpected error: {err}"
        );
        assert!(
            !err.to_string().contains("a=b"),
            "the error must not echo the value: {err}"
        );
        assert_eq!(dialer.calls(), 0);
    }

    #[tokio::test]
    async fn the_driver_refuses_an_authorization_header() {
        let (client, dialer, _log) = peer(Script::new(vec![], Answer::Nothing));

        let mut p = plan(RawH2Mode::SingleRequest, 1);
        p.headers
            .push(RawHeader::new("Authorization", "Bearer s3cret"));
        let err = client
            .probe(&p)
            .await
            .expect_err("an auth header is refused");

        assert!(
            err.to_string().contains("authorization"),
            "unexpected error: {err}"
        );
        assert!(
            !err.to_string().contains("s3cret"),
            "the error must not echo the value: {err}"
        );
        assert_eq!(dialer.calls(), 0);
    }

    #[tokio::test]
    async fn an_oversized_header_block_is_refused() {
        // The driver never writes a frame larger than the RFC 9113 §6.5.2
        // minimum `SETTINGS_MAX_FRAME_SIZE` every peer is required to accept.
        let (client, dialer, _log) = peer(Script::new(vec![(3, 100)], Answer::Nothing));

        let mut p = plan(RawH2Mode::SingleRequest, 1);
        p.headers
            .push(RawHeader::raw(b"x-big", &vec![b'a'; MAX_FRAME_BYTES + 1]));
        let err = client
            .probe(&p)
            .await
            .expect_err("a header block over the frame cap is refused");

        assert!(
            err.to_string().contains("exceeds the 16384-byte frame cap"),
            "unexpected error: {err}"
        );
        // The guard is part of validation, so the probe costs the target
        // nothing at all: no dial, let alone a HEADERS frame.
        assert_eq!(dialer.calls(), 0);
    }

    #[tokio::test]
    async fn the_read_budget_is_enforced() {
        let (client, _dialer, log) = peer(Script {
            flood: true,
            ..Script::new(vec![(3, 100)], Answer::Nothing)
        });

        let obs = client
            .probe(&plan(RawH2Mode::SingleRequest, 1))
            .await
            .expect("the probe completes");

        assert!(obs.connection_closed);
        assert_eq!(obs.streams, vec![StreamOutcome::Timeout]);
        // The peer can only get as far ahead as the driver read plus one
        // in-flight chunk and whatever the duplex buffer still holds.
        let written = log.lock().expect("server log").bytes_written;
        assert!(
            written <= RAW_READ_BUDGET + DUPLEX_CAPACITY + RAW_READ_CHUNK,
            "the peer pushed {written} bytes past the {RAW_READ_BUDGET}-byte budget"
        );
    }

    /// A TLS server config for `origin.test` offering `alpn` in preference
    /// order (the pattern `module.rs` and `sender.rs` use in their tests).
    fn server_config(alpn: &[&[u8]]) -> Arc<rustls::ServerConfig> {
        let key = rcgen::KeyPair::generate().expect("key");
        let cert = rcgen::CertificateParams::new(vec!["origin.test".to_string()])
            .expect("params")
            .self_signed(&key)
            .expect("cert");
        let mut cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("versions")
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
                key.serialize_der(),
            )),
        )
        .expect("server config");
        cfg.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
        Arc::new(cfg)
    }

    /// The same scripted peer, behind a self-signed TLS listener.
    fn tls_peer(
        script: Script,
        verify: TlsVerify,
        alpn: &[&[u8]],
    ) -> (RawH2Client, Arc<CountingDialer>, Arc<Mutex<ServerLog>>) {
        let (client_half, server_half) = tokio::io::duplex(DUPLEX_CAPACITY);
        let log = Arc::new(Mutex::new(ServerLog::default()));
        let cfg = server_config(alpn);
        let peer_log = log.clone();
        tokio::spawn(async move {
            if let Ok(tls) = tokio_rustls::TlsAcceptor::from(cfg)
                .accept(server_half)
                .await
            {
                run_script(tls, script, peer_log).await;
            }
        });
        let dialer = Arc::new(CountingDialer {
            stream: Mutex::new(Some(client_half)),
            calls: AtomicUsize::new(0),
            addrs: Mutex::new(Vec::new()),
        });
        let client = RawH2Client::new(verify)
            .with_dialer(dialer.clone())
            .with_resolver(Arc::new(LoopbackResolver));
        (client, dialer, log)
    }

    fn https_plan(mode: RawH2Mode, streams: u8) -> RawH2Plan {
        let mut p = plan(mode, streams);
        p.target.scheme = "https".to_string();
        p.target.authority = "origin.test".to_string();
        p
    }

    #[tokio::test]
    async fn an_https_probe_negotiates_h2_and_accepts_a_self_signed_leaf() {
        let (client, dialer, log) = tls_peer(
            Script::new(vec![(3, 128)], Answer::Status(0x88)),
            TlsVerify::AcceptAny,
            &[b"h2"],
        );

        let obs = client
            .probe(&https_plan(RawH2Mode::SingleRequest, 1))
            .await
            .expect("the probe completes");

        assert_eq!(obs.settings, vec![(3u16, 128u32)]);
        assert_eq!(
            obs.streams,
            vec![StreamOutcome::Headers { status: Some(200) }]
        );
        assert_eq!(dialer.calls(), 1);
        settled(&log, |l| l.headers_streams == vec![1]).await;
        assert_eq!(log.lock().expect("server log").preface, PREFACE.to_vec());
    }

    #[tokio::test]
    async fn an_https_probe_is_refused_by_an_alpn_refusing_peer() {
        // The listener's ALPN list is `http/1.1` and the probe offers `h2`
        // alone, so the peer rejects the ClientHello outright: the failure is
        // in the handshake, and the driver never writes an h2 frame at an
        // HTTP/1.1 server.
        let (client, dialer, _log) = tls_peer(
            Script::new(vec![(3, 128)], Answer::Nothing),
            TlsVerify::AcceptAny,
            &[b"http/1.1"],
        );

        let err = client
            .probe(&https_plan(RawH2Mode::SingleRequest, 1))
            .await
            .expect_err("a peer that will not speak h2 is refused");

        assert!(
            err.to_string().contains("raw h2 TLS to origin.test"),
            "unexpected error: {err}"
        );
        assert_eq!(dialer.calls(), 1);
    }

    #[tokio::test]
    async fn an_https_probe_is_refused_when_the_handshake_selects_no_alpn() {
        // A listener with no ALPN list at all completes the handshake and
        // selects nothing — the other half of the guard, after the handshake.
        let (client, dialer, _log) = tls_peer(
            Script::new(vec![(3, 128)], Answer::Nothing),
            TlsVerify::AcceptAny,
            &[],
        );

        let err = client
            .probe(&https_plan(RawH2Mode::SingleRequest, 1))
            .await
            .expect_err("a peer that negotiated no protocol is refused");

        assert!(
            err.to_string()
                .contains("raw h2 probe: origin.test did not negotiate ALPN h2"),
            "unexpected error: {err}"
        );
        assert_eq!(dialer.calls(), 1);
    }

    #[tokio::test]
    async fn webpki_verification_rejects_the_self_signed_leaf() {
        // The accept-any posture is a deliberate choice, not the default: the
        // same probe against the same peer fails when it verifies properly.
        let (client, dialer, _log) = tls_peer(
            Script::new(vec![(3, 128)], Answer::Status(0x88)),
            TlsVerify::WebPki,
            &[b"h2"],
        );

        let err = client
            .probe(&https_plan(RawH2Mode::SingleRequest, 1))
            .await
            .expect_err("an untrusted leaf is refused under WebPki");

        assert!(
            err.to_string().contains("TLS to origin.test"),
            "unexpected error: {err}"
        );
        assert_eq!(dialer.calls(), 1);
    }

    /// Three `Blocks` variants told apart by their `:path`.
    fn three_variants() -> Vec<Vec<RawHeader>> {
        let base = |path: &str| {
            vec![
                RawHeader::new(":method", "GET"),
                RawHeader::new(":scheme", "http"),
                RawHeader::new(":authority", "origin.test"),
                RawHeader::new(":path", path),
            ]
        };
        vec![base("/a"), base("/b"), base("/c")]
    }

    /// Whether `haystack` holds `needle` anywhere.
    fn holds(haystack: &[u8], needle: &[u8]) -> bool {
        !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
    }

    /// Plan amendment A3: `Blocks` opens one stream per block, in order, each
    /// carrying its own encoded block, all on the one connection.
    #[tokio::test]
    async fn blocks_open_one_stream_per_block_in_order_on_one_connection() {
        let (client, dialer, log) = peer(Script::new(vec![(3, 100)], Answer::Status(0x88)));

        let obs = client
            .probe(&plan(RawH2Mode::Blocks(three_variants()), 3))
            .await
            .expect("the probe completes");

        assert_eq!(
            obs.streams,
            vec![StreamOutcome::Headers { status: Some(200) }; 3]
        );
        assert_eq!(dialer.calls(), 1);
        settled(&log, |l| l.headers_streams.len() == 3).await;
        let log = log.lock().expect("server log");
        assert_eq!(log.headers_streams, vec![1, 3, 5]);
        // Each stream carries *its own* variant, in the plan's order: the
        // paths are what tell the three apart on the wire.
        let blocks = &log.headers_blocks;
        assert_eq!(blocks.len(), 3);
        assert!(holds(&blocks[0], b"/a"), "stream 1 carried {:?}", blocks[0]);
        assert!(holds(&blocks[1], b"/b"), "stream 3 carried {:?}", blocks[1]);
        assert!(holds(&blocks[2], b"/c"), "stream 5 carried {:?}", blocks[2]);
        assert!(!holds(&blocks[0], b"/b") && !holds(&blocks[0], b"/c"));
        assert!(blocks[0] != blocks[1] && blocks[1] != blocks[2] && blocks[0] != blocks[2]);
        // And the whole field, name and value, really is on the wire.
        assert!(holds(&blocks[0], b":path"), "{:?}", blocks[0]);
        assert!(log.rst_streams.is_empty(), "no reset pairs in Blocks mode");
    }

    /// SEC-5: `Blocks` advances only when the stream it just opened has an
    /// outcome. A peer that resets a stream id the driver never opened fills
    /// no slot and does not let the next block out early.
    #[tokio::test(start_paused = true)]
    async fn a_reset_for_an_unopened_stream_neither_fills_a_slot_nor_opens_the_next_block() {
        // Stream 5 is the third slot: the driver has only opened stream 1.
        let (client, dialer, log) = peer(Script::new(vec![(3, 100)], Answer::ResetOther(5)));

        let obs = client
            .probe(&plan(RawH2Mode::Blocks(three_variants()), 3))
            .await
            .expect("the probe completes");

        assert_eq!(
            obs.streams,
            vec![StreamOutcome::Timeout; 3],
            "a reset for an unopened stream is not an outcome for any slot"
        );
        assert!(obs.peer_silent, "the first stream was never answered");
        assert!(!obs.connection_closed, "silence is not a close");
        assert_eq!(dialer.calls(), 1);
        settled(&log, |l| l.headers_streams.len() == 1).await;
        assert_eq!(
            log.lock().expect("server log").headers_streams,
            vec![1],
            "block 2 must not be written while block 1 is unanswered"
        );
    }

    #[tokio::test]
    async fn blocks_record_a_reset_per_variant() {
        let (client, dialer, _log) = peer(Script::new(vec![], Answer::Reset(0x1)));

        let obs = client
            .probe(&plan(RawH2Mode::Blocks(three_variants()), 3))
            .await
            .expect("the probe completes");

        assert_eq!(obs.streams, vec![StreamOutcome::Reset { error_code: 1 }; 3]);
        assert_eq!(dialer.calls(), 1);
    }

    #[tokio::test]
    async fn blocks_refuse_more_than_eight_before_the_dial() {
        let (client, dialer, _log) = peer(Script::new(vec![], Answer::Nothing));
        let nine: Vec<Vec<RawHeader>> = (0..9).map(|_| three_variants().remove(0)).collect();

        let err = client
            .probe(&plan(RawH2Mode::Blocks(nine), 8))
            .await
            .expect_err("nine blocks are refused");

        assert_eq!(
            err.to_string(),
            format!(
                "a raw h2 probe opens at most {MAX_RAW_STREAMS} streams on its one connection; \
                 this mode opens 9"
            )
        );
        assert_eq!(dialer.calls(), 0);
    }

    #[tokio::test]
    async fn blocks_refuse_a_cookie_header_in_any_block() {
        let (client, dialer, _log) = peer(Script::new(vec![], Answer::Nothing));
        let mut variants = three_variants();
        variants[1].push(RawHeader::new("Cookie", "sid=secret"));

        let err = client
            .probe(&plan(RawH2Mode::Blocks(variants), 3))
            .await
            .expect_err("a cookie in the second block is refused");

        assert!(
            err.to_string().contains("cookie"),
            "unexpected error: {err}"
        );
        assert!(
            !err.to_string().contains("secret"),
            "the error must not echo the value: {err}"
        );
        assert_eq!(dialer.calls(), 0);
    }

    /// A server that discards cancelled streams without a word — what a
    /// conforming server does, and what hyper did in the live run of
    /// 2026-11-01 — leaves every rapid-reset slot `Timeout` with the
    /// connection still open: `peer_silent`, not `connection_closed`, so the
    /// check can tell "no reaction" from "hung up".
    #[tokio::test(start_paused = true)]
    async fn a_silent_peer_on_a_rapid_reset_probe_is_recorded_as_silent_not_closed() {
        let (client, dialer, log) = peer(Script::new(vec![(3, 100)], Answer::Nothing));

        let obs = client
            .probe(&plan(RawH2Mode::RapidReset { pairs: 8 }, 8))
            .await
            .expect("the probe completes");

        assert_eq!(obs.streams, vec![StreamOutcome::Timeout; 8]);
        assert!(obs.peer_silent);
        assert!(!obs.connection_closed);
        assert_eq!(obs.goaway, None);
        assert_eq!(dialer.calls(), 1);
        settled(&log, |l| l.headers_streams.len() == 8).await;
        assert_eq!(
            log.lock().expect("server log").headers_streams,
            vec![1, 3, 5, 7, 9, 11, 13, 15],
            "all eight pairs were written before the peer's silence ended the probe"
        );
    }

    /// Each block is awaited before the next opens: a peer that never answers
    /// the first stream sees exactly one HEADERS frame, the remaining variants
    /// stay `Timeout`, and the probe ends within one read timeout of the cap.
    #[tokio::test(start_paused = true)]
    async fn blocks_stop_after_a_silent_stream_without_opening_the_rest() {
        let (client, dialer, log) = peer(Script::new(vec![(3, 100)], Answer::Nothing));

        let started = tokio::time::Instant::now();
        let obs = client
            .probe(&plan(RawH2Mode::Blocks(three_variants()), 3))
            .await
            .expect("the probe completes");
        let waited = started.elapsed();

        assert_eq!(obs.streams, vec![StreamOutcome::Timeout; 3]);
        assert!(
            obs.peer_silent,
            "the peer said nothing within the read timeout"
        );
        assert!(!obs.connection_closed, "silence is not a close");
        assert_eq!(
            waited, RAW_READ_TIMEOUT,
            "the probe took {waited:?}; one silent stream should cost exactly one read timeout"
        );
        assert_eq!(dialer.calls(), 1);
        settled(&log, |l| l.headers_streams.len() == 1).await;
        assert_eq!(log.lock().expect("server log").headers_streams, vec![1]);
    }

    #[tokio::test]
    async fn blocks_ignore_the_plan_headers_field() {
        let (client, _dialer, log) = peer(Script::new(vec![], Answer::Status(0x88)));
        let variants = vec![three_variants().remove(2)];
        let mut p = plan(RawH2Mode::Blocks(variants), 1);
        p.headers.push(RawHeader::new("x-ignored", "yes"));

        client.probe(&p).await.expect("the probe completes");

        settled(&log, |l| l.headers_streams.len() == 1).await;
        let log = log.lock().expect("server log");
        assert_eq!(log.headers_blocks.len(), 1);
        let block = &log.headers_blocks[0];
        assert!(holds(block, b"/c"), "the block is the variant: {block:?}");
        assert!(
            !holds(block, b"x-ignored"),
            "the plan's own headers field must not reach the wire: {block:?}"
        );
        assert!(!holds(block, b"yes"), "{block:?}");
    }

    /// Every name answers one fixed address, so a test can choose exactly what
    /// the SSRF gate sees.
    struct FixedResolver(IpAddr);

    impl HostResolver for FixedResolver {
        fn resolve(&self, _host: String, _port: u16) -> BoxFuture<'static, Result<Vec<IpAddr>>> {
            let ip = self.0;
            Box::pin(async move { Ok(vec![ip]) })
        }
    }

    /// A resolver that never answers.
    struct HangingResolver;

    impl HostResolver for HangingResolver {
        fn resolve(&self, _host: String, _port: u16) -> BoxFuture<'static, Result<Vec<IpAddr>>> {
            Box::pin(std::future::pending())
        }
    }

    const METADATA: IpAddr = IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254));
    const PRIVATE: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));

    /// SEC-1: a name that resolves to the cloud metadata address is refused
    /// before the driver dials, once the gate is configured.
    #[tokio::test]
    async fn the_ssrf_gate_refuses_a_metadata_address_before_the_dial() {
        use aitm_core::{SsrfPolicy, StdGuard};

        let (client, dialer, _log) = peer(Script::new(vec![], Answer::Nothing));
        let client = client
            .with_resolver(Arc::new(FixedResolver(METADATA)))
            .with_ssrf(SsrfPolicy::default(), Arc::new(StdGuard::default()));

        let err = client
            .probe(&plan(RawH2Mode::SingleRequest, 1))
            .await
            .expect_err("the metadata address is refused");

        assert!(err.to_string().contains("SSRF"), "unexpected error: {err}");
        assert!(
            !err.to_string().contains("169.254.169.254"),
            "the refusal must not name the resolved address: {err}"
        );
        assert_eq!(dialer.calls(), 0, "a refused probe never dials");
    }

    /// SEC-1: the same for an RFC 1918 address behind a public name.
    #[tokio::test]
    async fn the_ssrf_gate_refuses_a_private_address_before_the_dial() {
        use aitm_core::{SsrfPolicy, StdGuard};

        let (client, dialer, _log) = peer(Script::new(vec![], Answer::Nothing));
        let client = client
            .with_resolver(Arc::new(FixedResolver(PRIVATE)))
            .with_ssrf(SsrfPolicy::default(), Arc::new(StdGuard::default()));

        let err = client
            .probe(&plan(RawH2Mode::SingleRequest, 1))
            .await
            .expect_err("a private address is refused");

        assert!(err.to_string().contains("SSRF"), "unexpected error: {err}");
        assert_eq!(dialer.calls(), 0, "a refused probe never dials");
    }

    /// SEC-1: an operator who scoped the IP literal lifts the block, exactly as
    /// on the sender's reissue path — the probe then runs to completion.
    #[tokio::test]
    async fn an_in_scope_ip_literal_lifts_the_raw_probe_ssrf_block() {
        use aitm_core::{ScopeEntry, ScopeRateGuard, SsrfPolicy, StdGuard};

        let (client, dialer, log) = peer(Script::new(vec![(3, 128)], Answer::Status(0x88)));
        let guard = Arc::new(StdGuard::default());
        guard.add_scope(ScopeEntry {
            host: "127.0.0.1".into(),
        });
        // The live scope permit is taken for the name the probe dials.
        guard.add_scope(ScopeEntry {
            host: "origin.test".into(),
        });
        let client = client.with_ssrf(SsrfPolicy::default(), guard);

        let obs = client
            .probe(&plan(RawH2Mode::SingleRequest, 1))
            .await
            .expect("a scoped loopback literal passes the gate");

        assert_eq!(
            obs.streams,
            vec![StreamOutcome::Headers { status: Some(200) }]
        );
        assert_eq!(dialer.calls(), 1, "the gate let the dial through");
        settled(&log, |l| l.headers_streams == vec![1]).await;
    }

    /// The gate takes the scope guard's live permit for the name it dials
    /// (panel review of PR 2a): a scope that lifts the private-address block
    /// for the IP literal but does not hold the host itself refuses the probe
    /// before the dial, and says it was the scope, not SSRF.
    #[tokio::test]
    async fn the_gate_refuses_a_host_the_live_scope_does_not_hold() {
        use aitm_core::{ScopeEntry, ScopeRateGuard, SsrfPolicy, StdGuard};

        let (client, dialer, _log) = peer(Script::new(vec![(3, 128)], Answer::Status(0x88)));
        let guard = Arc::new(StdGuard::default());
        guard.add_scope(ScopeEntry {
            host: "127.0.0.1".into(),
        });
        let client = client.with_ssrf(SsrfPolicy::default(), guard);

        let err = client
            .probe(&plan(RawH2Mode::SingleRequest, 1))
            .await
            .expect_err("a host outside the live scope is refused");

        assert!(
            err.to_string()
                .starts_with("scope: refusing raw h2 probe to origin.test:80"),
            "{err}"
        );
        assert_eq!(dialer.calls(), 0, "a refused probe never dials");
    }

    // ---------------------------------------------------------------
    // T3-7 (plan amendment A5): the pre-validated address
    // ---------------------------------------------------------------

    /// Answers loopback like [`LoopbackResolver`] and counts how many times it
    /// was asked, so a test can say the name was *not* looked up.
    #[derive(Default)]
    struct CountingResolver {
        calls: AtomicUsize,
    }

    impl CountingResolver {
        fn calls(&self) -> usize {
            self.calls.load(AtomicOrdering::SeqCst)
        }
    }

    impl HostResolver for CountingResolver {
        fn resolve(&self, _host: String, _port: u16) -> BoxFuture<'static, Result<Vec<IpAddr>>> {
            self.calls.fetch_add(1, AtomicOrdering::SeqCst);
            Box::pin(async { Ok(vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]) })
        }
    }

    /// The same plan as [`plan`], carrying the address the caller's baseline
    /// already validated.
    fn plan_at(addr: SocketAddr, mode: RawH2Mode, streams: u8) -> RawH2Plan {
        let mut plan = plan(mode, streams);
        plan.target.addr = Some(addr);
        plan
    }

    /// The address a caller's baseline reported. Documentation space
    /// (RFC 5737), on the authority's own port.
    const BASELINE_PEER: &str = "203.0.113.7:80";

    /// T3-7: a plan that carries the address its baseline came from is dialled
    /// at exactly that address and the name is never looked up again, so a
    /// record that flipped between the baseline and the probe cannot move the
    /// connection (the DNS-rebinding window).
    #[tokio::test]
    async fn a_pre_validated_address_is_dialled_and_the_name_is_not_resolved() {
        let (client, dialer, log) = peer(Script::new(vec![(3, 128)], Answer::Status(0x88)));
        let resolver = Arc::new(CountingResolver::default());
        let client = client.with_resolver(resolver.clone());
        let addr: SocketAddr = BASELINE_PEER.parse().expect("a literal address");

        let obs = client
            .probe(&plan_at(addr, RawH2Mode::SingleRequest, 1))
            .await
            .expect("the probe completes");

        assert_eq!(
            obs.streams,
            vec![StreamOutcome::Headers { status: Some(200) }]
        );
        assert_eq!(dialer.addrs(), vec![addr]);
        assert_eq!(resolver.calls(), 0, "the resolver must not be consulted");
        settled(&log, |l| l.headers_streams == vec![1]).await;
    }

    /// T3-7: the address being pre-validated by the caller does not excuse it
    /// from the driver's own gate. The SSRF half refuses a private address the
    /// caller handed over, and the live-scope half refuses a host the scope
    /// does not hold — both before any dial, with the same two messages the
    /// resolve path produces.
    #[tokio::test]
    async fn the_gate_still_runs_on_a_pre_validated_address() {
        use aitm_core::{ScopeEntry, ScopeRateGuard, SsrfPolicy, StdGuard};

        // The scope holds the host, so only the address can refuse this one.
        let (client, dialer, _log) = peer(Script::new(vec![], Answer::Nothing));
        let guard = Arc::new(StdGuard::default());
        guard.add_scope(ScopeEntry {
            host: "origin.test".into(),
        });
        let client = client.with_ssrf(SsrfPolicy::default(), guard);
        let private = SocketAddr::new(PRIVATE, 80);

        let err = client
            .probe(&plan_at(private, RawH2Mode::SingleRequest, 1))
            .await
            .expect_err("a private address is refused however it arrived");

        assert!(err.to_string().contains("SSRF"), "unexpected error: {err}");
        assert_eq!(dialer.calls(), 0, "a refused probe never dials");

        // The other half: the operator scoped the address itself, which
        // lifts the policy block, but the live scope does not hold the host.
        let (client, dialer, _log) = peer(Script::new(vec![], Answer::Nothing));
        let addr: SocketAddr = BASELINE_PEER.parse().expect("a literal address");
        let guard = Arc::new(StdGuard::default());
        guard.add_scope(ScopeEntry {
            host: addr.ip().to_string(),
        });
        let client = client.with_ssrf(SsrfPolicy::default(), guard);

        let err = client
            .probe(&plan_at(addr, RawH2Mode::SingleRequest, 1))
            .await
            .expect_err("a host outside the live scope is refused");

        assert!(
            err.to_string()
                .starts_with("scope: refusing raw h2 probe to origin.test:80"),
            "{err}"
        );
        assert_eq!(dialer.calls(), 0, "a refused probe never dials");
    }

    /// T3-7: an address on a different port than the authority is not the
    /// baseline's peer, whatever it is, so the probe is refused and the error
    /// names both. Nothing is dialled and no gate is consulted.
    #[tokio::test]
    async fn a_pre_validated_address_on_another_port_is_refused_naming_both() {
        let (client, dialer, _log) = peer(Script::new(vec![], Answer::Nothing));
        let other_port: SocketAddr = "203.0.113.7:8443".parse().expect("a literal address");

        let err = client
            .probe(&plan_at(other_port, RawH2Mode::SingleRequest, 1))
            .await
            .expect_err("an address on another port is refused");

        assert_eq!(
            err.to_string(),
            "raw h2 probe: the pre-validated address 203.0.113.7:8443 is not on the port of \
             authority origin.test:80"
        );
        assert_eq!(dialer.calls(), 0, "a refused plan never dials");
    }

    /// T3-7: a plan without an address keeps the resolve path exactly as it
    /// was — one lookup, and the dial goes to what the name answered.
    #[tokio::test]
    async fn a_plan_without_an_address_still_resolves_the_name() {
        let (client, dialer, log) = peer(Script::new(vec![(3, 128)], Answer::Status(0x88)));
        let resolver = Arc::new(CountingResolver::default());
        let client = client.with_resolver(resolver.clone());

        let obs = client
            .probe(&plan(RawH2Mode::SingleRequest, 1))
            .await
            .expect("the probe completes");

        assert_eq!(
            obs.streams,
            vec![StreamOutcome::Headers { status: Some(200) }]
        );
        assert_eq!(resolver.calls(), 1, "the name is looked up exactly once");
        assert_eq!(
            dialer.addrs(),
            vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 80)]
        );
        settled(&log, |l| l.headers_streams == vec![1]).await;
    }

    /// SEC-1: without `with_ssrf` the driver behaves exactly as before — the
    /// gate is opt-in, and the live wiring is the checks crate's job.
    #[tokio::test]
    async fn without_the_gate_a_private_address_is_still_dialled() {
        let (client, dialer, log) = peer(Script::new(vec![(3, 128)], Answer::Status(0x88)));
        let client = client.with_resolver(Arc::new(FixedResolver(PRIVATE)));

        let obs = client
            .probe(&plan(RawH2Mode::SingleRequest, 1))
            .await
            .expect("the probe completes");

        assert_eq!(
            obs.streams,
            vec![StreamOutcome::Headers { status: Some(200) }]
        );
        assert_eq!(dialer.calls(), 1);
        settled(&log, |l| l.headers_streams == vec![1]).await;
    }

    /// SEC-1/SEC-9: the resolve is inside the whole-probe cap, so a resolver
    /// that never answers cannot hold the probe open past it. SEC-11: and a
    /// cap that fires before a connection exists is an *error*, not an
    /// observation shaped like a peer that hung up — nothing was observed.
    /// The outer guard (T-O3) makes a regression a red test, not a hung one.
    #[tokio::test(start_paused = true)]
    async fn a_resolver_that_never_answers_is_bounded_by_the_total_timeout() {
        let (client, dialer, _log) = peer(Script::new(vec![], Answer::Nothing));
        let client = client.with_resolver(Arc::new(HangingResolver));

        let started = tokio::time::Instant::now();
        let err = tokio::time::timeout(
            RAW_TOTAL_TIMEOUT * 4,
            client.probe(&plan(RawH2Mode::SingleRequest, 1)),
        )
        .await
        .expect("the probe must not outlive its own cap")
        .expect_err("a probe that never connected has nothing to observe");
        let waited = started.elapsed();

        assert_eq!(
            err.to_string(),
            "raw h2 probe to origin.test: no connection within the cap",
            "unexpected error: {err}"
        );
        assert_eq!(
            waited, RAW_TOTAL_TIMEOUT,
            "the probe took {waited:?}; the cap is exactly {RAW_TOTAL_TIMEOUT:?}"
        );
        assert_eq!(dialer.calls(), 0, "a probe that never resolved never dials");
    }

    /// Captures this crate's own tracing events on the current thread (a
    /// local copy of `h2_sender`'s; accepted duplicate, review finding QM-10).
    #[derive(Clone, Default)]
    struct LogCapture {
        events: Arc<Mutex<Vec<(tracing::Level, String)>>>,
    }

    struct Fields(String);

    impl tracing::field::Visit for Fields {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            self.0.push_str(&format!(" {}={value:?}", field.name()));
        }
        fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
            self.0.push_str(&format!(" {}={value}", field.name()));
        }
    }

    impl tracing::Subscriber for LogCapture {
        fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
        fn event(&self, event: &tracing::Event<'_>) {
            if !event.metadata().target().starts_with("aitm_proto_http") {
                return;
            }
            let mut fields = Fields(String::new());
            event.record(&mut fields);
            self.events
                .lock()
                .expect("events")
                .push((*event.metadata().level(), fields.0));
        }
        fn enter(&self, _: &tracing::span::Id) {}
        fn exit(&self, _: &tracing::span::Id) {}
    }

    const NO_GATE_WARNING: &str = "raw h2 probe running without an SSRF gate";

    fn gate_warnings(events: &Arc<Mutex<Vec<(tracing::Level, String)>>>) -> Vec<tracing::Level> {
        events
            .lock()
            .expect("events")
            .iter()
            .filter(|(_, fields)| fields.contains(NO_GATE_WARNING))
            .map(|(level, _)| *level)
            .collect()
    }

    /// Installs a `LogCapture` on this thread that the gate warning is
    /// proven to reach, and returns its guard and its (emptied) event log.
    ///
    /// `tracing` caches one `Interest` per callsite for the whole process,
    /// and every other driver test probes through an ungated client with no
    /// subscriber on its thread. If one of them first-registers the warning's
    /// callsite while a gate test is installing its capture, the callsite
    /// stays cached as "never" and the warning is dropped before any
    /// subscriber sees it (4 failures in 22 runs; the same race
    /// `h2_sender`'s GOAWAY log test hit). So, as there: rebuild the cache
    /// with this capture registered, then replay a fresh ungated probe —
    /// bounded — until its warning lands. Only then is the capture handed to
    /// the test, emptied, for the real assertion.
    async fn live_gate_capture() -> (
        tracing::subscriber::DefaultGuard,
        Arc<Mutex<Vec<(tracing::Level, String)>>>,
    ) {
        let capture = LogCapture::default();
        let events = capture.events.clone();
        let guard = tracing::subscriber::set_default(capture);

        let mut landed = false;
        for _ in 0..8 {
            tracing::callsite::rebuild_interest_cache();
            let (ungated, _dialer, _log) = peer(Script::new(vec![(3, 128)], Answer::Status(0x88)));
            ungated
                .probe(&plan(RawH2Mode::SingleRequest, 1))
                .await
                .expect("the warm-up probe completes");
            if !gate_warnings(&events).is_empty() {
                landed = true;
                break;
            }
        }
        assert!(
            landed,
            "the gate warning never reached the capture in eight replays"
        );
        events.lock().expect("events").clear();
        (guard, events)
    }

    /// SEC-13: a client probing without `with_ssrf` says so, once, at `warn`
    /// — so a mis-wired runner shows in the logs rather than silently probing
    /// unguarded — and a second probe on the same client does not repeat it.
    #[tokio::test]
    async fn probing_without_an_ssrf_gate_warns_exactly_once_per_client() {
        let (_guard, events) = live_gate_capture().await;

        let (client, _dialer, _log) = peer(Script::new(vec![(3, 128)], Answer::Status(0x88)));
        client
            .probe(&plan(RawH2Mode::SingleRequest, 1))
            .await
            .expect("the first probe completes");
        assert_eq!(
            gate_warnings(&events),
            vec![tracing::Level::WARN],
            "the first unguarded probe warns once: {:?}",
            events.lock().expect("events")
        );

        // The one connection is spent; a second probe fails to dial, which is
        // fine — the warning is about the gate, and it must not repeat.
        let _ = client.probe(&plan(RawH2Mode::SingleRequest, 1)).await;
        assert_eq!(
            gate_warnings(&events),
            vec![tracing::Level::WARN],
            "the second probe on the same client does not warn again"
        );
    }

    /// SEC-13: a client built with the gate never warns.
    #[tokio::test]
    async fn probing_with_an_ssrf_gate_does_not_warn() {
        use aitm_core::{ScopeEntry, ScopeRateGuard, SsrfPolicy, StdGuard};

        let (_guard, events) = live_gate_capture().await;

        let (client, _dialer, _log) = peer(Script::new(vec![(3, 128)], Answer::Status(0x88)));
        let scope = Arc::new(StdGuard::default());
        scope.add_scope(ScopeEntry {
            host: "127.0.0.1".into(),
        });
        scope.add_scope(ScopeEntry {
            host: "origin.test".into(),
        });
        let client = client.with_ssrf(SsrfPolicy::default(), scope);
        client
            .probe(&plan(RawH2Mode::SingleRequest, 1))
            .await
            .expect("the gated probe completes");

        assert!(
            gate_warnings(&events).is_empty(),
            "a gated client must not warn: {:?}",
            events.lock().expect("events")
        );

        // The positive control, without which this test would also pass if
        // nothing at all reached the capture: an ungated client on a fresh
        // peer must produce the warning the gated one did not (tester
        // whole-branch pass). `live_gate_capture` proved the callsite live
        // before the gated probe; this proves it stayed so through it.
        let (ungated, _dialer, _log) = peer(Script::new(vec![(3, 128)], Answer::Status(0x88)));
        ungated
            .probe(&plan(RawH2Mode::SingleRequest, 1))
            .await
            .expect("the ungated probe completes");
        assert_eq!(
            gate_warnings(&events),
            vec![tracing::Level::WARN],
            "the capture was live: an ungated client warns where the gated one did not"
        );
    }
}
