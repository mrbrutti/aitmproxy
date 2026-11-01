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
//! Everything here is pure and I/O-free; Task 6 adds the connection driver that
//! speaks these bytes over a socket.
//!
//! There is deliberately **no** general HPACK decoder. The observe checks'
//! oracle is reset-vs-answer, not the response body, so the driver records
//! "HEADERS received, N bytes" and reads a `:status` only when the server
//! encoded it as a static-table index ([`parse_status_indexed`]). Decoding a
//! literal response field would need the dynamic table this module does not
//! keep.

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
