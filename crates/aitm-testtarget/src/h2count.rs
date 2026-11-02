//! Read-side HTTP/2 stream observer for the `h2` connections of the TLS
//! listener (spec D2 `streams`, umbrella amendment 51, the T3-3 oracle).
//!
//! [`H2StreamCounter`] wraps the TLS stream `app::serve_h2` reads from. Every
//! byte goes to hyper unchanged and every write passes through untouched; on
//! the read side a tiny framing state machine ([`FrameState`]) walks the
//! inbound bytes: the 24-byte connection preface, then 9-byte frame headers
//! (24-bit length, 8-bit type, 8-bit flags, 31-bit stream id) with their
//! payload skipped by count. A HEADERS frame (type `0x1`) on an odd stream id
//! greater than the last one counted opens a client stream, and the
//! connection's [`ConnInfo::streams`] goes up by one, BEFORE hyper parses the
//! frame, so a stream hyper rejects (malformed header block) or the client
//! cancels (`RST_STREAM`) counts exactly like a served one.
//!
//! This is an observer, never a gate: a byte that does not match the preface
//! or a frame that cannot be walked stops the counting (the count is left as
//! is) and nothing else happens to the connection.

use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::log::ConnInfo;

/// The HTTP/2 connection preface every client sends first (RFC 9113 §3.4).
const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
/// Size of an HTTP/2 frame header (RFC 9113 §4.1).
const FRAME_HEADER_LEN: usize = 9;
/// HEADERS frame type (RFC 9113 §6.2): the only frame that opens a client stream.
const TYPE_HEADERS: u8 = 0x1;
/// The largest payload a 24-bit length can carry (2^24 - 1); anything the
/// decoder returns above it is impossible by construction, so a value there
/// means the walk lost sync and counting stops.
const MAX_FRAME_LEN: usize = 0x00FF_FFFF;

/// Where the observer is in the inbound byte stream. Carried across
/// `poll_read` calls so partial reads at any boundary are handled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum FrameState {
    /// Inside the 24-byte connection preface; `seen` bytes matched so far.
    Preface { seen: usize },
    /// Collecting a 9-byte frame header; `have` bytes of `buf` are filled.
    Header {
        buf: [u8; FRAME_HEADER_LEN],
        have: usize,
    },
    /// Skipping a frame payload; `remaining` bytes left before the next header.
    Payload { remaining: usize },
    /// The bytes stopped looking like HTTP/2 framing; count nothing further.
    Stopped,
}

/// Decode a complete 9-byte frame header into (payload length, type, stream id).
/// The length is 24-bit big-endian, the type is byte 3 and the stream id is
/// the low 31 bits of bytes 5..9 (the reserved top bit is dropped).
fn decode_header(h: &[u8; FRAME_HEADER_LEN]) -> (usize, u8, u32) {
    let len = u32::from_be_bytes([0, h[0], h[1], h[2]]) as usize;
    let kind = h[3];
    let id = u32::from_be_bytes([h[5], h[6], h[7], h[8]]) & 0x7FFF_FFFF;
    (len, kind, id)
}

impl FrameState {
    /// The start state: expecting the connection preface.
    pub(crate) fn new() -> Self {
        FrameState::Preface { seen: 0 }
    }

    /// Walk `bytes` (the next slice of the inbound stream) and return how many
    /// NEW client streams opened in it. `last_stream` is the highest odd id
    /// counted so far, kept by the caller so the pure walk stays testable.
    fn step(&mut self, bytes: &[u8], last_stream: &mut u32) -> u32 {
        let mut opened = 0;
        let mut rest = bytes;
        while !rest.is_empty() {
            match self {
                FrameState::Stopped => return opened,
                FrameState::Preface { seen } => {
                    let want = &PREFACE[*seen..];
                    let n = rest.len().min(want.len());
                    if rest[..n] != want[..n] {
                        *self = FrameState::Stopped;
                        return opened;
                    }
                    *seen += n;
                    rest = &rest[n..];
                    if *seen == PREFACE.len() {
                        *self = FrameState::Header {
                            buf: [0; FRAME_HEADER_LEN],
                            have: 0,
                        };
                    }
                }
                FrameState::Header { buf, have } => {
                    let n = rest.len().min(FRAME_HEADER_LEN - *have);
                    buf[*have..*have + n].copy_from_slice(&rest[..n]);
                    *have += n;
                    rest = &rest[n..];
                    if *have < FRAME_HEADER_LEN {
                        continue;
                    }
                    let (len, kind, id) = decode_header(buf);
                    if len > MAX_FRAME_LEN {
                        *self = FrameState::Stopped;
                        return opened;
                    }
                    if kind == TYPE_HEADERS && id % 2 == 1 && id > *last_stream {
                        *last_stream = id;
                        opened += 1;
                    }
                    *self = if len == 0 {
                        FrameState::Header {
                            buf: [0; FRAME_HEADER_LEN],
                            have: 0,
                        }
                    } else {
                        FrameState::Payload { remaining: len }
                    };
                }
                FrameState::Payload { remaining } => {
                    let n = rest.len().min(*remaining);
                    *remaining -= n;
                    rest = &rest[n..];
                    if *remaining == 0 {
                        *self = FrameState::Header {
                            buf: [0; FRAME_HEADER_LEN],
                            have: 0,
                        };
                    }
                }
            }
        }
        opened
    }
}

/// A [`FrameState`] plus the highest client stream id counted so far: the
/// whole observer, pure and socket-free.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Observer {
    state: FrameState,
    last_stream: u32,
}

impl Observer {
    pub(crate) fn new() -> Self {
        Observer {
            state: FrameState::new(),
            last_stream: 0,
        }
    }

    /// Feed the next inbound slice; returns the number of NEW client streams
    /// (HEADERS on an odd id above every id seen before) it opened.
    pub(crate) fn observe(&mut self, bytes: &[u8]) -> u32 {
        self.state.step(bytes, &mut self.last_stream)
    }

    /// The current framing position (asserted by the unit tests).
    #[cfg(test)]
    pub(crate) fn state(&self) -> &FrameState {
        &self.state
    }
}

/// An `AsyncRead + AsyncWrite` wrapper that counts the client streams opened
/// on an `h2` connection into `conn.streams` while handing every byte to the
/// reader unchanged. Writes are delegated as is.
pub(crate) struct H2StreamCounter<IO> {
    inner: IO,
    conn: Arc<ConnInfo>,
    observer: Observer,
}

impl<IO> H2StreamCounter<IO> {
    /// Wrap `inner`; stream openings are added to `conn.streams`.
    pub(crate) fn new(inner: IO, conn: Arc<ConnInfo>) -> Self {
        H2StreamCounter {
            inner,
            conn,
            observer: Observer::new(),
        }
    }
}

impl<IO: AsyncRead + Unpin> AsyncRead for H2StreamCounter<IO> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let poll = Pin::new(&mut this.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &poll {
            let fresh = &buf.filled()[before..];
            if !fresh.is_empty() {
                let opened = this.observer.observe(fresh);
                if opened > 0 {
                    this.conn.streams.fetch_add(opened, Ordering::SeqCst);
                }
            }
        }
        poll
    }
}

impl<IO: AsyncWrite + Unpin> AsyncWrite for H2StreamCounter<IO> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

    /// One h2 frame: 9-byte header followed by `payload`.
    fn frame(kind: u8, flags: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
        let len = payload.len() as u32;
        let mut f = Vec::with_capacity(9 + payload.len());
        f.extend_from_slice(&len.to_be_bytes()[1..]);
        f.push(kind);
        f.push(flags);
        f.extend_from_slice(&stream_id.to_be_bytes());
        f.extend_from_slice(payload);
        f
    }

    /// The plan's sequence: preface, SETTINGS(0 len, id 0), HEADERS(1, 5 B),
    /// HEADERS(3, 2 B), RST_STREAM(3, 4 B), HEADERS(5, 7 B garbage),
    /// DATA(1, 3 B). Exactly three client streams are opened on the wire.
    fn plan_sequence() -> Vec<u8> {
        let mut bytes = PREFACE.to_vec();
        bytes.extend(frame(0x4, 0x0, 0, &[]));
        bytes.extend(frame(0x1, 0x5, 1, &[0x82, 0x86, 0x84, 0x41, 0x0a]));
        bytes.extend(frame(0x1, 0x5, 3, &[0x82, 0x86]));
        bytes.extend(frame(0x3, 0x0, 3, &[0, 0, 0, 8]));
        bytes.extend(frame(0x1, 0x5, 5, &[0xff; 7]));
        bytes.extend(frame(0x0, 0x1, 1, b"abc"));
        bytes
    }

    /// Feed `bytes` to a fresh state machine in `chunk`-sized slices; return
    /// the sum of every slice's reported new streams and the final state.
    fn observe_in_chunks(bytes: &[u8], chunk: usize) -> (u32, Observer) {
        let mut state = Observer::new();
        let mut total = 0;
        for piece in bytes.chunks(chunk) {
            total += state.observe(piece);
        }
        (total, state)
    }

    #[test]
    fn plan_sequence_counts_three_streams_at_every_chunk_size() {
        let bytes = plan_sequence();
        for chunk in [1usize, 7, 9, 64, bytes.len()] {
            let (total, state) = observe_in_chunks(&bytes, chunk);
            assert_eq!(total, 3, "chunk size {chunk}");
            assert!(
                matches!(state.state(), FrameState::Header { have: 0, .. }),
                "chunk size {chunk}: ends on a frame boundary, got {state:?}"
            );
        }
    }

    #[test]
    fn per_chunk_sums_are_the_total_and_land_on_the_headers_frames() {
        // With 9-byte chunks the HEADERS headers land in distinct slices, so
        // the per-slice results are a sequence of zeros and ones summing to 3.
        let bytes = plan_sequence();
        let mut state = Observer::new();
        let per_chunk: Vec<u32> = bytes.chunks(9).map(|c| state.observe(c)).collect();
        assert_eq!(per_chunk.iter().sum::<u32>(), 3);
        assert!(per_chunk.iter().all(|&n| n <= 1), "{per_chunk:?}");
    }

    #[test]
    fn reused_even_and_continuation_ids_do_not_count() {
        let mut bytes = PREFACE.to_vec();
        bytes.extend(frame(0x1, 0x4, 1, &[0x82]));
        // A second HEADERS on stream 1 (trailers / re-use): not a new stream.
        bytes.extend(frame(0x1, 0x5, 1, &[0x82]));
        // An even id is server-initiated: never a client stream.
        bytes.extend(frame(0x1, 0x5, 4, &[0x82]));
        // CONTINUATION (0x9) never opens a stream, and does not move the
        // high-water mark either.
        bytes.extend(frame(0x9, 0x4, 7, &[0x82]));
        // A new odd id above every one seen (5 > 1) is a stream: 2 so far.
        bytes.extend(frame(0x1, 0x5, 5, &[0x82]));
        // Lower odd ids after a higher one are protocol errors, not streams.
        bytes.extend(frame(0x1, 0x5, 3, &[0x82]));
        bytes.extend(frame(0x1, 0x5, 1, &[0x82]));
        let (total, state) = observe_in_chunks(&bytes, bytes.len());
        assert_eq!(total, 2);
        assert!(
            matches!(state.state(), FrameState::Header { have: 0, .. }),
            "{state:?}"
        );
        // ...and then a genuinely new odd id still counts.
        let mut state = state;
        assert_eq!(state.observe(&frame(0x1, 0x5, 9, &[0x82])), 1);
    }

    #[test]
    fn h1_bytes_without_a_preface_never_count_and_stop() {
        let mut state = Observer::new();
        let n = state.observe(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
        assert_eq!(n, 0);
        assert!(matches!(state.state(), FrameState::Stopped), "{state:?}");
        // Once stopped, even a well-formed HEADERS frame is ignored.
        assert_eq!(state.observe(&frame(0x1, 0x5, 1, &[0x82])), 0);
        assert!(matches!(state.state(), FrameState::Stopped), "{state:?}");
    }

    #[test]
    fn a_wrong_preface_byte_at_position_ten_stops_with_zero() {
        let mut bytes = PREFACE.to_vec();
        bytes[10] ^= 0x20;
        bytes.extend(frame(0x1, 0x5, 1, &[0x82]));
        // Byte-at-a-time so the stop happens mid-preface, not at a boundary.
        let (total, state) = observe_in_chunks(&bytes, 1);
        assert_eq!(total, 0);
        assert!(matches!(state.state(), FrameState::Stopped), "{state:?}");
        // And an exact prefix of the real preface is still "in progress".
        let mut state = Observer::new();
        assert_eq!(state.observe(&PREFACE[..10]), 0);
        assert!(
            matches!(state.state(), FrameState::Preface { seen: 10 }),
            "{state:?}"
        );
    }

    #[test]
    fn zero_length_frames_go_straight_back_to_the_next_header() {
        // SETTINGS ack (0 len) immediately followed by HEADERS: the HEADERS
        // header must be read as a header, not as payload.
        let mut bytes = PREFACE.to_vec();
        bytes.extend(frame(0x4, 0x1, 0, &[]));
        bytes.extend(frame(0x4, 0x1, 0, &[]));
        bytes.extend(frame(0x1, 0x5, 1, &[]));
        bytes.extend(frame(0x1, 0x5, 3, &[]));
        for chunk in [1usize, 2, 9, bytes.len()] {
            let (total, _) = observe_in_chunks(&bytes, chunk);
            assert_eq!(total, 2, "chunk size {chunk}");
        }
    }

    #[test]
    fn frame_header_fields_decode_big_endian_with_the_reserved_bit_dropped() {
        // Length 0x01_02_03, type 0x1, flags 0x5, stream id with the reserved
        // top bit set (must be masked off): 0x8000_0005 -> 5.
        let header = [0x01, 0x02, 0x03, 0x01, 0x05, 0x80, 0x00, 0x00, 0x05];
        let (len, kind, id) = decode_header(&header);
        assert_eq!((len, kind, id), (0x01_02_03, 0x1, 5));
    }

    /// The wrapper over an in-memory IO: hyper-side bytes are unchanged, the
    /// counter on the `ConnInfo` moves, writes pass straight through.
    #[tokio::test]
    async fn wrapper_passes_bytes_through_and_counts_on_the_conn() {
        use crate::log::{ControlLog, Listener};
        use crate::SeedMode;
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let log = ControlLog::new(SeedMode::Vulnerable);
        let peer = "127.0.0.1:40000".parse().expect("peer");
        let conn = log.open_conn(Listener::Tls, Some("h2"), peer);
        let bytes = plan_sequence();

        let (mut client, server) = tokio::io::duplex(64);
        let mut counted = H2StreamCounter::new(server, conn.clone());
        let writer = tokio::spawn({
            let bytes = bytes.clone();
            async move {
                for piece in bytes.chunks(5) {
                    client.write_all(piece).await.expect("client write");
                }
                client.shutdown().await.expect("client shutdown");
                // Read whatever the server side wrote back.
                let mut back = Vec::new();
                client.read_to_end(&mut back).await.expect("client read");
                back
            }
        });

        let mut seen = Vec::new();
        counted.read_to_end(&mut seen).await.expect("server read");
        assert_eq!(seen, bytes, "hyper-side bytes are the wire bytes");
        assert_eq!(conn.streams.load(Ordering::SeqCst), 3);
        counted
            .write_all(b"server-bytes")
            .await
            .expect("server write");
        counted.shutdown().await.expect("server shutdown");
        let back = writer.await.expect("writer task");
        assert_eq!(back, b"server-bytes", "writes pass through untouched");
    }
}
