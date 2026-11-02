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

    // --- Tester additions (stage 5): max-length payload, header-boundary
    // splits, sticky stop, write-path delegation, read errors, the JSON row ---

    /// Spec D2: "skips ... payload by count" and "stops counting on a frame
    /// length past 16 MiB". The largest length a 24-bit field can carry is
    /// 16_777_215 (one byte short of 16 MiB), so the maximum frame is SKIPPED,
    /// never a stop: its payload, stuffed with bytes that spell HEADERS
    /// headers on huge odd ids, counts nothing in any chunking, the walk does
    /// not stall or lose sync, and the real HEADERS(1) right after it counts.
    #[test]
    fn a_maximum_length_payload_is_skipped_by_count_across_many_chunks() {
        // The decoder's ceiling is exactly MAX_FRAME_LEN, so the `>` stop is
        // unreachable from the wire; documented here on purpose.
        let max_header = [0xff, 0xff, 0xff, 0x0, 0x0, 0, 0, 0, 1];
        assert_eq!(decode_header(&max_header), (MAX_FRAME_LEN, 0x0, 1));
        assert_eq!(MAX_FRAME_LEN, 16 * 1024 * 1024 - 1);

        // Payload: HEADERS headers on id 0x7fff_fffd (odd, enormous) back to
        // back; if any of them were read as a frame the high-water mark
        // would jump and the trailing HEADERS(1) could never count.
        let mut payload = Vec::with_capacity(MAX_FRAME_LEN);
        while payload.len() < MAX_FRAME_LEN {
            payload.extend(frame(0x1, 0x5, 0x7fff_fffd, &[]));
        }
        payload.truncate(MAX_FRAME_LEN);
        let mut bytes = PREFACE.to_vec();
        bytes.extend_from_slice(&max_header);
        bytes.extend_from_slice(&payload);
        bytes.extend(frame(0x1, 0x5, 1, &[0x82]));
        bytes.extend(frame(0x1, 0x5, 3, &[0x82]));

        for chunk in [4093usize, 65_536, bytes.len()] {
            let (total, state) = observe_in_chunks(&bytes, chunk);
            assert_eq!(total, 2, "chunk size {chunk}");
            assert!(
                matches!(state.state(), FrameState::Header { have: 0, .. }),
                "chunk size {chunk}: {state:?}"
            );
        }

        // And the remaining-count is exact at the frame's edge: one byte
        // short of the payload is still Payload { 1 }, the next byte is the
        // header boundary.
        let mut state = Observer::new();
        let edge = PREFACE.len() + FRAME_HEADER_LEN + MAX_FRAME_LEN - 1;
        assert_eq!(state.observe(&bytes[..edge]), 0);
        assert_eq!(state.state(), &FrameState::Payload { remaining: 1 });
        assert_eq!(state.observe(&bytes[edge..edge + 1]), 0);
        assert!(
            matches!(state.state(), FrameState::Header { have: 0, .. }),
            "{state:?}"
        );
        assert_eq!(state.observe(&bytes[edge + 1..]), 2);
    }

    /// "Partial reads carried across polls": a HEADERS frame split exactly at
    /// the 9-byte header boundary counts in the slice that completes the
    /// header (the id is known there), and one split inside the stream-id
    /// bytes counts only once the id's last byte arrives; every single cut
    /// point of the sequence totals the same.
    #[test]
    fn a_headers_frame_split_at_the_header_boundary_and_inside_the_stream_id() {
        let mut bytes = PREFACE.to_vec();
        bytes.extend(frame(0x4, 0x0, 0, &[]));
        let hdr = bytes.len(); // the HEADERS(1) header starts here
        bytes.extend(frame(0x1, 0x5, 1, &[0x82, 0x86, 0x84]));
        bytes.extend(frame(0x1, 0x5, 3, &[0x82]));

        // Split exactly after the 9-byte header, before the payload.
        let mut state = Observer::new();
        assert_eq!(state.observe(&bytes[..hdr + FRAME_HEADER_LEN]), 1);
        assert_eq!(state.state(), &FrameState::Payload { remaining: 3 });
        assert_eq!(state.observe(&bytes[hdr + FRAME_HEADER_LEN..]), 1);
        assert!(
            matches!(state.state(), FrameState::Header { have: 0, .. }),
            "{state:?}"
        );

        // Split inside the stream-id bytes (7 of 9 header bytes seen: the id
        // is bytes 5..9, so two of its four bytes are still missing).
        let mut state = Observer::new();
        assert_eq!(state.observe(&bytes[..hdr + 7]), 0);
        match state.state() {
            FrameState::Header { buf, have } => {
                assert_eq!(*have, 7);
                assert_eq!(&buf[..7], &bytes[hdr..hdr + 7]);
            }
            other => panic!("expected a partial header, got {other:?}"),
        }
        // Only the last two id bytes: that is the moment the stream counts.
        assert_eq!(state.observe(&bytes[hdr + 7..hdr + 9]), 1);
        assert_eq!(state.state(), &FrameState::Payload { remaining: 3 });
        assert_eq!(state.observe(&bytes[hdr + 9..]), 1);

        // Every cut point (including 0 and len, i.e. an empty slice) totals 2.
        for cut in 0..=bytes.len() {
            let mut state = Observer::new();
            let total = state.observe(&bytes[..cut]) + state.observe(&bytes[cut..]);
            assert_eq!(total, 2, "cut at {cut}");
        }
    }

    /// "Stops counting (leaving the count as is)": `Stopped` is sticky. After
    /// a preface that goes wrong on its LAST byte, a complete valid preface
    /// plus SETTINGS and HEADERS on 1, 3, 5 (the plan sequence) fed in every
    /// chunk size opens nothing and never moves the state again.
    #[test]
    fn stopped_is_sticky_across_further_bytes_including_a_later_valid_headers() {
        let mut state = Observer::new();
        assert_eq!(state.observe(&PREFACE[..PREFACE.len() - 1]), 0);
        assert_eq!(
            state.state(),
            &FrameState::Preface {
                seen: PREFACE.len() - 1
            }
        );
        assert_eq!(state.observe(b"X"), 0);
        assert_eq!(state.state(), &FrameState::Stopped);

        let good = plan_sequence();
        for chunk in [1usize, 9, good.len()] {
            for piece in good.chunks(chunk) {
                assert_eq!(state.observe(piece), 0, "chunk size {chunk}");
            }
            assert_eq!(state.state(), &FrameState::Stopped, "chunk size {chunk}");
        }
        assert_eq!(state.observe(&frame(0x1, 0x5, 1, &[0x82])), 0);
        assert_eq!(state.observe(&[]), 0);
        assert_eq!(state.state(), &FrameState::Stopped);
        // The high-water mark never moved either.
        assert_eq!(state.last_stream, 0);
    }

    /// A scripted IO for the wrapper: `poll_read` serves `reads` in order
    /// (an `Err` is returned as is, exhaustion is EOF); every write call is
    /// recorded by SHAPE, `write` buffers and `write_vectored` slice lists
    /// separately, so delegation of each method is observable, not just the
    /// concatenated bytes. `max_write` caps a single write to prove the
    /// wrapper reports the inner count, not the caller's.
    #[derive(Default)]
    struct ScriptedIo {
        reads: std::collections::VecDeque<std::io::Result<Vec<u8>>>,
        writes: Vec<Vec<u8>>,
        vectored: Vec<Vec<Vec<u8>>>,
        flushes: usize,
        shutdowns: usize,
        vectored_ok: bool,
        max_write: Option<usize>,
    }

    impl AsyncRead for ScriptedIo {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            let this = self.get_mut();
            match this.reads.pop_front() {
                None => Poll::Ready(Ok(())),
                Some(Err(e)) => Poll::Ready(Err(e)),
                Some(Ok(bytes)) => {
                    let n = bytes.len().min(buf.remaining());
                    buf.put_slice(&bytes[..n]);
                    if n < bytes.len() {
                        this.reads.push_front(Ok(bytes[n..].to_vec()));
                    }
                    Poll::Ready(Ok(()))
                }
            }
        }
    }

    impl AsyncWrite for ScriptedIo {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            let this = self.get_mut();
            let n = this.max_write.map_or(buf.len(), |m| m.min(buf.len()));
            this.writes.push(buf[..n].to_vec());
            Poll::Ready(Ok(n))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            self.get_mut().flushes += 1;
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            self.get_mut().shutdowns += 1;
            Poll::Ready(Ok(()))
        }

        fn poll_write_vectored(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            bufs: &[std::io::IoSlice<'_>],
        ) -> Poll<std::io::Result<usize>> {
            let this = self.get_mut();
            let total = bufs.iter().map(|b| b.len()).sum();
            this.vectored
                .push(bufs.iter().map(|b| b.to_vec()).collect());
            Poll::Ready(Ok(total))
        }

        fn is_write_vectored(&self) -> bool {
            self.vectored_ok
        }
    }

    fn test_conn() -> Arc<ConnInfo> {
        use crate::log::{ControlLog, Listener};
        use crate::SeedMode;
        let log = ControlLog::new(SeedMode::Vulnerable);
        let peer = "127.0.0.1:40000".parse().expect("peer");
        log.open_conn(Listener::Tls, Some("h2"), peer)
    }

    /// "Writes pass through untouched": each of `poll_write`,
    /// `poll_write_vectored`, `poll_flush`, `poll_shutdown` and
    /// `is_write_vectored` reaches the inner IO as the same call with the
    /// same bytes, a short write is reported as the inner reported it, and
    /// none of it touches the stream count.
    #[tokio::test]
    async fn every_write_method_is_delegated_byte_identical() {
        use std::io::IoSlice;
        use tokio::io::AsyncWriteExt as _;

        let conn = test_conn();
        let io = ScriptedIo {
            vectored_ok: true,
            max_write: Some(4),
            ..ScriptedIo::default()
        };
        let mut counted = H2StreamCounter::new(io, conn.clone());
        assert!(counted.is_write_vectored(), "delegates is_write_vectored");

        // A capped write: the wrapper must report the inner's 4, not 6.
        let n = counted.write(b"abcdef").await.expect("write");
        assert_eq!(n, 4);
        // Vectored: the exact slice list reaches the inner.
        let bufs = [
            IoSlice::new(b"PRI"),
            IoSlice::new(b""),
            IoSlice::new(b" * "),
        ];
        let n = counted.write_vectored(&bufs).await.expect("write_vectored");
        assert_eq!(n, 6);
        counted.flush().await.expect("flush");
        counted.shutdown().await.expect("shutdown");

        let inner = &counted.inner;
        assert_eq!(inner.writes, vec![b"abcd".to_vec()]);
        assert_eq!(
            inner.vectored,
            vec![vec![b"PRI".to_vec(), Vec::new(), b" * ".to_vec()]]
        );
        assert_eq!(inner.flushes, 1);
        assert_eq!(inner.shutdowns, 1);
        assert_eq!(conn.streams.load(Ordering::SeqCst), 0, "writes never count");

        // And a non-vectored inner is reported as such.
        let plain = H2StreamCounter::new(ScriptedIo::default(), test_conn());
        assert!(!plain.is_write_vectored());
    }

    /// Connection drop mid-stream: a read error from the inner IO is handed
    /// back as is (same kind), the streams counted before it stay, nothing
    /// after it is counted, and a half-delivered frame header at the drop
    /// does not count. EOF (`Ok` with no bytes) is passed through too.
    #[tokio::test]
    async fn a_read_error_passes_through_and_leaves_the_count_as_is() {
        use std::io::{Error, ErrorKind};
        use tokio::io::AsyncReadExt as _;

        let mut first = PREFACE.to_vec();
        first.extend(frame(0x4, 0x0, 0, &[]));
        first.extend(frame(0x1, 0x5, 1, &[0x82]));
        // HEADERS(3) cut after 7 header bytes: the id is incomplete.
        first.extend_from_slice(&frame(0x1, 0x5, 3, &[0x82])[..7]);

        let conn = test_conn();
        let io = ScriptedIo {
            reads: [
                Ok(first.clone()),
                Err(Error::new(ErrorKind::ConnectionReset, "peer went away")),
                Ok(frame(0x1, 0x5, 5, &[0x82])),
            ]
            .into_iter()
            .collect(),
            ..ScriptedIo::default()
        };
        let mut counted = H2StreamCounter::new(io, conn.clone());

        let mut buf = vec![0u8; 4096];
        let n = counted.read(&mut buf).await.expect("first read");
        assert_eq!(&buf[..n], &first[..], "hyper-side bytes unchanged");
        assert_eq!(conn.streams.load(Ordering::SeqCst), 1);

        let err = counted.read(&mut buf).await.expect_err("the reset");
        assert_eq!(err.kind(), ErrorKind::ConnectionReset);
        assert_eq!(
            conn.streams.load(Ordering::SeqCst),
            1,
            "error counts nothing"
        );

        // The observer is mid-header (not Stopped), so if the transport did
        // deliver more the walk continues from where it was: the first two
        // bytes of HEADERS(5) complete HEADERS(3)'s header as id 0 (even:
        // not a stream) with length 1, the third byte is that payload, and
        // the other seven are a pending header. Count stays exactly 1 and the
        // bytes reach the reader untouched.
        assert!(
            matches!(counted.observer.state(), FrameState::Header { have: 7, .. }),
            "{:?}",
            counted.observer.state()
        );
        let n = counted.read(&mut buf).await.expect("third read");
        assert_eq!(n, 10);
        assert_eq!(&buf[..n], &frame(0x1, 0x5, 5, &[0x82])[..]);
        assert_eq!(conn.streams.load(Ordering::SeqCst), 1);
        assert!(
            matches!(counted.observer.state(), FrameState::Header { have: 7, .. }),
            "{:?}",
            counted.observer.state()
        );

        // EOF passes through as a zero-length read.
        let n = counted.read(&mut buf).await.expect("eof");
        assert_eq!(n, 0);
        assert_eq!(conn.streams.load(Ordering::SeqCst), 1);
    }

    /// One `poll_read` that delivers several HEADERS frames adds ALL of them
    /// (the per-slice `opened`, not a flag): the whole plan sequence in a
    /// single read is 3 on the conn at once.
    #[tokio::test]
    async fn one_read_carrying_several_headers_adds_them_all() {
        use tokio::io::AsyncReadExt as _;

        let conn = test_conn();
        let io = ScriptedIo {
            reads: [Ok(plan_sequence())].into_iter().collect(),
            ..ScriptedIo::default()
        };
        let mut counted = H2StreamCounter::new(io, conn.clone());
        let mut buf = vec![0u8; 4096];
        let n = counted.read(&mut buf).await.expect("one read");
        assert_eq!(n, plan_sequence().len(), "the whole sequence in one poll");
        assert_eq!(conn.streams.load(Ordering::SeqCst), 3);
    }

    /// (e) The wrapper counts on the very `Arc<ConnInfo>` the `/log/conns`
    /// row reads: `ControlLog::conns_json` shows the number, it follows
    /// further openings, and it survives `close_conn`.
    #[tokio::test]
    async fn the_log_conns_row_reports_what_the_wrapper_counted() {
        use crate::log::{ControlLog, Listener};
        use crate::SeedMode;
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let log = ControlLog::new(SeedMode::Vulnerable);
        let peer = "127.0.0.1:40000".parse().expect("peer");
        let conn = log.open_conn(Listener::Tls, Some("h2"), peer);
        let row = |log: &ControlLog| log.conns_json()["entries"][0].clone();
        assert_eq!(row(&log)["streams"], serde_json::json!(0));

        let (mut client, server) = tokio::io::duplex(16);
        let mut counted = H2StreamCounter::new(server, conn.clone());
        let bytes = plan_sequence();
        let writer = tokio::spawn(async move {
            for piece in bytes.chunks(3) {
                client.write_all(piece).await.expect("client write");
            }
            client
        });
        let mut seen = vec![0u8; 1024];
        let mut got = 0;
        while got < plan_sequence().len() {
            got += counted.read(&mut seen[got..]).await.expect("read");
        }
        assert_eq!(&seen[..got], &plan_sequence()[..]);
        assert_eq!(row(&log)["streams"], serde_json::json!(3), "{}", row(&log));
        assert_eq!(row(&log)["alpn"], serde_json::json!("h2"));

        // One more HEADERS on a new odd id: the row follows.
        let mut client = writer.await.expect("writer");
        client
            .write_all(&frame(0x1, 0x5, 7, &[0x82]))
            .await
            .expect("client write");
        let mut got = 0;
        while got < 10 {
            got += counted.read(&mut seen[got..]).await.expect("read");
        }
        assert_eq!(row(&log)["streams"], serde_json::json!(4), "{}", row(&log));

        // Closing the connection keeps the number on the row.
        log.close_conn(&conn);
        let closed = row(&log);
        assert_eq!(closed["streams"], serde_json::json!(4), "{closed}");
        assert_ne!(closed["closed_ms"], serde_json::Value::Null, "{closed}");
        assert_eq!(closed["requests"], serde_json::json!(0), "{closed}");
    }
}
