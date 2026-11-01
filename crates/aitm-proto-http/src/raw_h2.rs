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
//! * the raw connection goes to **that same authority** and no other;
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
//! encoded it as a static-table index ([`parse_status_indexed`]). Decoding a
//! literal response field would need the dynamic table this module does not
//! keep.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use futures::future::BoxFuture;
use rustls::pki_types::ServerName;
use rustls::ClientConfig;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::Instant;
use tokio_rustls::TlsConnector;

use crate::sender::{Dialer, HostResolver, ProbeStream};

/// The client connection preface (RFC 9113 §3.4), sent before any frame.
pub const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// Length of a frame header in bytes (RFC 9113 §4.1).
pub const FRAME_HEADER_LEN: usize = 9;

/// Largest frame payload this codec will accept from a peer.
///
/// Equal to the RFC 9113 §6.5.2 minimum `SETTINGS_MAX_FRAME_SIZE`, which is what
/// a raw probe advertises: a peer that declares more than this is not answering
/// the probe we sent, and [`parse_frame`] refuses it rather than sizing a buffer
/// from an attacker-chosen length.
pub const MAX_FRAME_BYTES: usize = 16 * 1024;

/// The frame types this codec writes or recognises (RFC 9113 §6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameType {
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
pub mod flags {
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
pub fn frame_header(len: u32, kind: FrameType, flags: u8, stream: u32) -> [u8; FRAME_HEADER_LEN] {
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
pub struct Frame {
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
pub fn parse_frame(buf: &[u8]) -> anyhow::Result<Option<(Frame, usize)>> {
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawHeader {
    /// The field name bytes, exactly as they go on the wire.
    pub name: Vec<u8>,
    /// The field value bytes, exactly as they go on the wire.
    pub value: Vec<u8>,
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
pub fn encode_integer(value: usize, prefix_bits: u8, first_byte: u8) -> Vec<u8> {
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
pub fn encode_block(headers: &[RawHeader]) -> Vec<u8> {
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
pub fn parse_settings(payload: &[u8]) -> Vec<(u16, u32)> {
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
pub fn parse_rst_stream(payload: &[u8]) -> Option<u32> {
    match payload {
        [e0, e1, e2, e3] => Some(u32::from_be_bytes([*e0, *e1, *e2, *e3])),
        _ => None,
    }
}

/// Read a GOAWAY payload's `(last_stream_id, error_code)` (RFC 9113 §6.8), or
/// `None` when the payload is shorter than eight bytes. Any trailing opaque
/// debug data is ignored — it is peer-controlled and never surfaced as evidence.
#[must_use]
pub fn parse_goaway(payload: &[u8]) -> Option<(u32, u32)> {
    match payload {
        [l0, l1, l2, l3, e0, e1, e2, e3, ..] => Some((
            u32::from_be_bytes([*l0, *l1, *l2, *l3]) & 0x7fff_ffff,
            u32::from_be_bytes([*e0, *e1, *e2, *e3]),
        )),
        _ => None,
    }
}

/// Read a `:status` from a response HEADERS block, but only when the server
/// encoded it as the block's first field and as an HPACK **indexed** field from
/// the static table (RFC 7541 Appendix A, entries 8-14).
///
/// Returns `None` for every other encoding, including a literal `:status` or a
/// status not in the static table. That is enough for the observe-only checks,
/// whose oracle is reset-vs-answer; see the module docs.
#[must_use]
pub fn parse_status_indexed(block: &[u8]) -> Option<u16> {
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

/// The only ALPN protocol a raw probe offers.
const ALPN_H2: &[u8] = b"h2";

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
}

/// What the probe does once the SETTINGS exchange is done.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RawH2Mode {
    /// One HEADERS frame on stream 1, then wait for its outcome.
    SingleRequest,
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
    fn stream_count(self) -> usize {
        match self {
            RawH2Mode::SettingsOnly => 0,
            RawH2Mode::SingleRequest => 1,
            RawH2Mode::RapidReset { pairs } => pairs as usize,
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
    /// encoded `:status` as a static-table index (see [`parse_status_indexed`]).
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
    /// because the read budget, the read timeout or the whole-probe timeout was
    /// spent. False when every stream reached an outcome on a healthy
    /// connection the driver then closed itself.
    pub connection_closed: bool,
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
}

impl RawH2Client {
    /// A client that dials real TCP and resolves through the system resolver.
    #[must_use]
    pub fn new(verify: TlsVerify) -> Self {
        Self {
            tls: verify,
            dialer: Arc::new(RawTcpDialer),
            resolver: Arc::new(RawSystemResolver),
        }
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
    /// than it declares, when it carries a forbidden header, or when the target
    /// is unusable (bad scheme, bad authority, no address). After that it
    /// errors only on a transport failure; a peer that resets, goes away or
    /// says nothing is an observation, not an error.
    pub async fn probe(&self, plan: &RawH2Plan) -> Result<RawH2Observation> {
        let streams = validate(plan)?;

        let scheme = plan.target.scheme.to_ascii_lowercase();
        let tls = match scheme.as_str() {
            "https" => true,
            "http" => false,
            other => anyhow::bail!("raw h2 probe cannot speak scheme {other:?}"),
        };
        let (host, port) = split_target(&plan.target.authority, tls)?;

        let addr = self
            .resolver
            .resolve(host.clone(), port)
            .await?
            .into_iter()
            .next()
            .map(|ip| SocketAddr::new(ip, port))
            .ok_or_else(|| anyhow!("no address for {host}:{port}"))?;

        let mut obs = RawH2Observation {
            settings: Vec::new(),
            streams: vec![StreamOutcome::Timeout; streams],
            goaway: None,
            connection_closed: false,
            elapsed_ms: 0,
        };

        let started = Instant::now();
        let outcome = tokio::time::timeout(
            RAW_TOTAL_TIMEOUT,
            self.connect_and_converse(plan, addr, &host, tls, streams, &mut obs),
        )
        .await;
        obs.elapsed_ms = u32::try_from(started.elapsed().as_millis()).unwrap_or(u32::MAX);

        match outcome {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Err(e),
            // The whole-probe cap ran out: the connection is dropped here, and
            // whatever the peer had already said stands as the observation.
            Err(_) => obs.connection_closed = true,
        }
        Ok(obs)
    }

    /// Dial once, wrap in TLS for an `https` target, run the conversation and
    /// close. No retry: a failure here is the probe's result.
    async fn connect_and_converse(
        &self,
        plan: &RawH2Plan,
        addr: SocketAddr,
        host: &str,
        tls: bool,
        streams: usize,
        obs: &mut RawH2Observation,
    ) -> Result<()> {
        let dialed = self
            .dialer
            .dial(addr)
            .await
            .with_context(|| format!("raw h2 dial {addr}"))?;

        let mut stream: Box<dyn ProbeStream> = if tls {
            let name = ServerName::try_from(host.to_string())
                .map_err(|e| anyhow!("invalid server name {host:?}: {e}"))?;
            let tls_stream = TlsConnector::from(self.client_config()?)
                .connect(name, dialed)
                .await
                .with_context(|| format!("raw h2 TLS to {host}"))?;
            if tls_stream.get_ref().1.alpn_protocol() != Some(ALPN_H2) {
                anyhow::bail!("raw h2 probe: {host} did not negotiate ALPN h2");
            }
            Box::new(tls_stream)
        } else {
            dialed
        };

        let result = converse(&mut *stream, plan, streams, obs).await;
        let _ = tokio::time::timeout(RAW_CLOSE_TIMEOUT, stream.shutdown()).await;
        result
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

/// Check a plan against the caps and the forbidden-header list, and return how
/// many streams it will open. Runs before the dial, so a refused plan costs the
/// target nothing.
fn validate(plan: &RawH2Plan) -> Result<usize> {
    if plan.streams > MAX_RAW_STREAMS {
        anyhow::bail!(
            "a raw h2 probe opens at most 8 streams on its one connection; the plan declares {}",
            plan.streams
        );
    }
    let wanted = plan.mode.stream_count();
    if wanted > MAX_RAW_STREAMS as usize {
        anyhow::bail!(
            "a raw h2 probe opens at most 8 streams on its one connection; this mode opens {wanted}"
        );
    }
    if wanted > plan.streams as usize {
        anyhow::bail!(
            "the plan declares {} stream(s) but its mode opens {wanted}",
            plan.streams
        );
    }

    for header in &plan.headers {
        let name = String::from_utf8_lossy(&header.name).to_ascii_lowercase();
        for forbidden in FORBIDDEN_HEADERS {
            if name == forbidden {
                // The name only: a value is exactly what must not be echoed.
                anyhow::bail!("a raw h2 probe never sends a `{forbidden}` header");
            }
        }
    }
    Ok(wanted)
}

/// Split `host[:port]`, defaulting the port from the scheme.
fn split_target(authority: &str, tls: bool) -> Result<(String, u16)> {
    let default = if tls { 443 } else { 80 };
    let parsed = aitm_core::Authority::parse_with_default(authority, default)
        .map_err(|e| anyhow!("bad authority {authority:?}: {e}"))?;
    let port = if parsed.port == 0 {
        default
    } else {
        parsed.port
    };
    Ok((parsed.host, port))
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
/// one. Returns whether it filled a slot that was still pending.
fn record(obs: &mut RawH2Observation, id: u32, outcome: StreamOutcome) -> bool {
    if id == 0 || id.is_multiple_of(2) {
        return false;
    }
    let index = usize::try_from((id - 1) / 2).unwrap_or(usize::MAX);
    match obs.streams.get_mut(index) {
        Some(slot) if *slot == StreamOutcome::Timeout => {
            *slot = outcome;
            true
        }
        _ => false,
    }
}

/// The conversation on an established connection: preface, SETTINGS exchange,
/// the plan's streams, then read until every stream has an outcome or the
/// connection ends.
async fn converse(
    stream: &mut dyn ProbeStream,
    plan: &RawH2Plan,
    streams: usize,
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
            Next::Eof | Next::Idle | Next::Budget => {
                obs.connection_closed = true;
                return Ok(());
            }
        }
    }

    if streams == 0 {
        return Ok(());
    }

    // One HEADERS block, reused on every stream this plan opens.
    let block = encode_block(&plan.headers);
    let block_len = u32::try_from(block.len()).unwrap_or(u32::MAX);
    if block.len() > MAX_FRAME_BYTES {
        anyhow::bail!(
            "raw h2 HEADERS block of {} bytes exceeds the {MAX_FRAME_BYTES}-byte frame cap",
            block.len()
        );
    }
    let rapid_reset = matches!(plan.mode, RawH2Mode::RapidReset { .. });

    let mut id: u32 = 1;
    for _ in 0..streams {
        let mut out = frame_header(
            block_len,
            FrameType::Headers,
            flags::END_HEADERS | flags::END_STREAM,
            id,
        )
        .to_vec();
        out.extend_from_slice(&block);
        if rapid_reset {
            out.extend_from_slice(&frame_header(4, FrameType::RstStream, 0x00, id));
            out.extend_from_slice(&RST_CANCEL.to_be_bytes());
        }
        stream.write_all(&out).await.context("raw h2 headers")?;
        id += 2;
    }
    stream.flush().await.context("raw h2 headers")?;

    // Read until every stream has an outcome, or the connection ends.
    let mut pending = streams;
    while pending > 0 {
        match reader.next(stream).await? {
            Next::Frame(frame) => match FrameType::from_u8(frame.kind) {
                Some(FrameType::GoAway) => {
                    obs.goaway = parse_goaway(&frame.payload);
                    obs.connection_closed = true;
                    return Ok(());
                }
                Some(FrameType::Headers) => {
                    let status = parse_status_indexed(&frame.payload);
                    if record(obs, frame.stream, StreamOutcome::Headers { status }) {
                        pending -= 1;
                    }
                }
                Some(FrameType::RstStream) => {
                    if let Some(code) = parse_rst_stream(&frame.payload) {
                        let outcome = if code == RST_REFUSED_STREAM {
                            StreamOutcome::Refused
                        } else {
                            StreamOutcome::Reset { error_code: code }
                        };
                        if record(obs, frame.stream, outcome) {
                            pending -= 1;
                        }
                    }
                }
                // DATA, PING, WINDOW_UPDATE, SETTINGS beyond the first and any
                // frame type this codec does not model are read and dropped:
                // the oracle is reset-vs-answer.
                _ => {}
            },
            Next::Eof | Next::Idle | Next::Budget => {
                obs.connection_closed = true;
                return Ok(());
            }
        }
    }
    Ok(())
}

/// A real TCP connection, bounded by [`RAW_CONNECT_TIMEOUT`]. (The sender's
/// equivalent is private to its module.)
struct RawTcpDialer;

impl Dialer for RawTcpDialer {
    fn dial(&self, addr: SocketAddr) -> BoxFuture<'static, Result<Box<dyn ProbeStream>>> {
        Box::pin(async move {
            let tcp = tokio::time::timeout(RAW_CONNECT_TIMEOUT, TcpStream::connect(addr))
                .await
                .map_err(|_| anyhow!("connect to {addr} timed out"))??;
            Ok(Box::new(tcp) as Box<dyn ProbeStream>)
        })
    }
}

/// The operating system's resolver. (The sender's equivalent is private to its
/// module.)
struct RawSystemResolver;

impl HostResolver for RawSystemResolver {
    fn resolve(&self, host: String, port: u16) -> BoxFuture<'static, Result<Vec<IpAddr>>> {
        Box::pin(async move {
            let addrs = tokio::net::lookup_host((host.as_str(), port))
                .await
                .with_context(|| format!("resolve {host}:{port}"))?;
            Ok(addrs.map(|a| a.ip()).collect())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        /// `GOAWAY(last_stream_id, error_code)`, once, after the first HEADERS.
        GoAway(u32, u32),
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
    }

    impl Script {
        fn new(settings: Vec<(u16, u32)>, answer: Answer) -> Self {
            Self {
                settings,
                answer,
                flood: false,
                silent: false,
            }
        }
    }

    /// What the scripted peer observed on the wire.
    #[derive(Default)]
    struct ServerLog {
        preface: Vec<u8>,
        headers_streams: Vec<u32>,
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
                        log.lock()
                            .expect("server log")
                            .headers_streams
                            .push(frame.stream);
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
                            Answer::GoAway(last, code) if !sent_goaway => {
                                sent_goaway = true;
                                let mut payload = last.to_be_bytes().to_vec();
                                payload.extend_from_slice(&code.to_be_bytes());
                                Some(framed(FrameType::GoAway, 0x00, 0, &payload))
                            }
                            Answer::GoAway(..) => None,
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

    /// Hands out the one duplex client half and counts dial attempts.
    struct CountingDialer {
        stream: Mutex<Option<DuplexStream>>,
        calls: AtomicUsize,
    }

    impl CountingDialer {
        fn calls(&self) -> usize {
            self.calls.load(AtomicOrdering::SeqCst)
        }
    }

    impl Dialer for CountingDialer {
        fn dial(&self, _addr: SocketAddr) -> BoxFuture<'static, Result<Box<dyn ProbeStream>>> {
            self.calls.fetch_add(1, AtomicOrdering::SeqCst);
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

    #[tokio::test]
    async fn the_plan_refuses_more_than_eight_streams() {
        let (client, dialer, _log) = peer(Script::new(vec![], Answer::Nothing));

        let err = client
            .probe(&plan(RawH2Mode::SingleRequest, 9))
            .await
            .expect_err("nine streams is refused");

        assert!(
            err.to_string().contains("at most 8 streams"),
            "unexpected error: {err}"
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

        assert!(
            err.to_string().contains("at most 8 streams"),
            "unexpected error: {err}"
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
        let (client, dialer, _log) = peer(Script::new(vec![(3, 100)], Answer::GoAway(1, 11)));

        let obs = client
            .probe(&plan(RawH2Mode::RapidReset { pairs: 8 }, 8))
            .await
            .expect("the probe completes");

        assert_eq!(obs.goaway, Some((1, 11)));
        assert!(obs.streams.len() <= 8, "streams: {:?}", obs.streams);
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
        assert!(
            waited <= RAW_TOTAL_TIMEOUT,
            "the probe took {waited:?}, cap is {RAW_TOTAL_TIMEOUT:?}"
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
        // The guard is inside the conversation, so the dial happened, but no
        // HEADERS frame did.
        assert_eq!(dialer.calls(), 1);
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
    async fn an_https_probe_offers_only_h2_so_an_http1_only_peer_is_refused() {
        // The listener speaks `http/1.1` only; the probe offers `h2` alone, so
        // the handshake fails rather than the driver writing h2 frames at an
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
            err.to_string().contains("TLS to origin.test")
                || err.to_string().contains("did not negotiate ALPN h2"),
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
}
