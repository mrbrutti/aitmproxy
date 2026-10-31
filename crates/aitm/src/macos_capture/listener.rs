//! Core-side listener for the macOS Network/System Extension capture handoff
//! (L4 Phase 2, Task 8).
//!
//! The extension's `NETransparentProxyProvider` hands each captured flow to the
//! core over **Unix domain sockets**: one **control channel** plus **one data
//! socket per flow** (research Candidate B1, hardened — spec §D3). This module is
//! the core (listener) half; the provider half is Band C (Swift). It is provable
//! in the sandbox against a loopback UDS client, needing no Mac.
//!
//! # Topology
//!
//! - A **socket directory** the core owns, locked to mode **0700** so no other
//!   uid can reach the sockets inside it (the first half of "a root sysex must not
//!   ship plaintext to a squatter"; peer **code-signature** validation is the
//!   provider's job — Task 11).
//! - A **control** UDS (`control.sock`) carrying metadata only: a capability
//!   [`Hello`], the active scope/intercept [`ScopeSpec`], and one [`FlowOpen`]
//!   per flow. **Never bulk flow bytes.**
//! - A **data** UDS (`data.sock`) the provider dials **once per flow**. Each flow
//!   therefore gets its own socket — its own kernel buffers and its own
//!   backpressure (a slow consumer of one flow stalls only that flow). The first
//!   frame on a data socket is a [`DataHandshake`] naming the `flow_id` it belongs
//!   to; after it, the socket carries raw bytes (TCP) or length-delimited
//!   datagrams (UDP, via [`write_datagram`] / [`DataConnection::recv_datagram`]).
//!
//! # Flow representation (pinned here, consumed by the adapter task)
//!
//! [`FlowOpen`] is the durable handoff representation the macOS capture-backend
//! adapter (plan Task 2) maps onto the ingress types in
//! [`crate::ingress`]: `remote` → `CapturedTcpFlow::dst` / the UDP target,
//! `remote_hostname` → `CapturedTcpFlow::sni`, `source_app` → `peer_identity`,
//! and the per-flow data socket → `CapturedTcpFlow::stream` /
//! `CapturedUdpFlow::datagrams`. This module does **not** dispatch and does
//! **not** redeclare those ingress types.

use std::fs;
use std::io;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{UnixListener, UnixStream};

use super::rendezvous;

/// Filenames of the two sockets inside the capture directory.
pub(crate) const CONTROL_SOCK: &str = "control.sock";
const DATA_SOCK: &str = "data.sock";

/// Upper bound on a control-frame body we will allocate for from a peer-declared
/// `u32` length prefix. Control frames are metadata (a [`Hello`], a [`ScopeSpec`],
/// a [`FlowOpen`]) — kilobytes, not megabytes; 1 MiB is ample headroom.
const MAX_FRAME_LEN: usize = 1 << 20;

/// How long [`CaptureListener::accept_data`] waits for a freshly accepted data
/// socket's [`DataHandshake`]. The handshake is read **before** the peer can be
/// verified (the verifier needs the finished connection), so without a bound one
/// silent same-uid peer would pin the accepting task forever. A real provider sends
/// the handshake immediately after connecting; seconds is generous.
const DATA_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// Upper bound on a length-delimited datagram body. A UDP datagram cannot exceed
/// 64 KiB, so any larger declared length is corrupt or hostile.
const MAX_DATAGRAM_LEN: usize = 64 * 1024;

/// Whether a captured flow is a TCP/stream flow or a UDP datagram flow. Maps to
/// the two ingress flow types (`CapturedTcpFlow` / `CapturedUdpFlow`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FlowKind {
    /// A TCP/stream flow: the data socket carries raw bytes.
    Tcp,
    /// A UDP flow: the data socket carries length-delimited datagrams.
    Udp,
}

/// The provider's opening capability announcement on the control channel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hello {
    /// Handoff protocol version, so a mismatched provider/core pair fails loudly
    /// rather than misreading each other's frames.
    pub protocol_version: u32,
}

/// The active scope/intercept spec the provider matches flows against before it
/// opens them. Carried on the control channel; the concrete encoding is refined
/// by the adapter task — this is a serialized placeholder, not bulk data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeSpec {
    /// The serialized scope/intercept spec.
    pub spec: String,
}

/// Per-flow open notification: the metadata the core needs to route one captured
/// flow, sent on the control channel before (or as) the provider dials the flow's
/// data socket. This is the pinned handoff flow representation (see the module
/// docs); the per-flow bulk bytes never appear here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowOpen {
    /// Correlates this metadata with the data socket whose [`DataHandshake`]
    /// carries the same id.
    pub flow_id: u64,
    /// TCP or UDP.
    pub kind: FlowKind,
    /// The authoritative original remote endpoint the client was reaching
    /// (→ `CapturedTcpFlow::dst` / the UDP target).
    pub remote: std::net::SocketAddr,
    /// The remote hostname / ClientHello SNI, when the provider observed one
    /// (→ `CapturedTcpFlow::sni`).
    pub remote_hostname: Option<String>,
    /// The source-app signing identity, when the provider resolved one from the
    /// flow's audit token (macOS `SourceAppId` → `peer_identity`).
    pub source_app: Option<String>,
    /// The flow's local endpoint; meaningful for UDP (where the core replies from
    /// it), `None` for TCP.
    pub local: Option<std::net::SocketAddr>,
}

/// One message on the control channel — metadata only, by construction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ControlMessage {
    /// Opening capability announcement.
    Hello(Hello),
    /// The active scope/intercept spec.
    Scope(ScopeSpec),
    /// A per-flow open notification.
    FlowOpen(FlowOpen),
}

/// The first frame on a per-flow data socket, correlating it to the [`FlowOpen`]
/// of the same `flow_id` on the control channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataHandshake {
    /// The flow this data socket carries.
    pub flow_id: u64,
}

/// Core-side listener for the capture handoff. Owns the 0700 socket directory and
/// the control + data listeners bound inside it.
pub struct CaptureListener {
    dir: PathBuf,
    control: UnixListener,
    data: UnixListener,
}

impl CaptureListener {
    /// Create (or reuse) `dir`, lock it to **0700**, and bind the control and data
    /// sockets inside it. Stale socket files from a previous run are removed first
    /// so the bind does not fail with `EADDRINUSE`.
    ///
    /// # Errors
    /// Fails if the directory cannot be created or locked, or either socket cannot
    /// be bound.
    pub fn bind(dir: impl AsRef<Path>) -> io::Result<Self> {
        let dir = dir.as_ref().to_path_buf();
        // Create the directory **atomically private** (mode 0700 at creation), so
        // there is no create→chmod window in which another uid could reach it.
        // `recursive(true)` makes an existing directory a no-op (it does not widen
        // it); the explicit `set_permissions` below then narrows an inherited dir —
        // and fails closed (EPERM) if that dir is owned by another uid.
        fs::DirBuilder::new()
            .mode(0o700)
            .recursive(true)
            .create(&dir)?;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;

        let control_path = dir.join(CONTROL_SOCK);
        let data_path = dir.join(DATA_SOCK);
        // A UDS bind fails if the path already exists; clear stale sockets.
        let _ = fs::remove_file(&control_path);
        let _ = fs::remove_file(&data_path);

        let control = UnixListener::bind(&control_path)?;
        let data = UnixListener::bind(&data_path)?;
        Ok(Self { dir, control, data })
    }

    /// The private socket directory.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Publish this listener's socket dir to the well-known rendezvous path so
    /// the Swift provider can discover it. Returns an RAII guard that removes the
    /// rendezvous file on drop. Call after [`bind`](Self::bind) has locked the
    /// dir to 0700.
    ///
    /// # Errors
    /// Fails if the socket dir cannot be canonicalized, its path is too long to
    /// fit a socket name within `sun_path`, or the rendezvous file cannot be
    /// created (see [`rendezvous::RendezvousFile::publish`]).
    pub fn publish_rendezvous(&self) -> io::Result<rendezvous::RendezvousFile> {
        rendezvous::RendezvousFile::publish(self.dir(), rendezvous::RENDEZVOUS_PATH)
    }

    /// Path of the control socket.
    #[must_use]
    pub fn control_path(&self) -> PathBuf {
        self.dir.join(CONTROL_SOCK)
    }

    /// Path of the data socket.
    #[must_use]
    pub fn data_path(&self) -> PathBuf {
        self.dir.join(DATA_SOCK)
    }

    /// Accept the provider's control connection.
    ///
    /// # Errors
    /// Fails if accepting the connection fails.
    pub async fn accept_control(&self) -> io::Result<ControlChannel> {
        let (stream, _addr) = self.control.accept().await?;
        Ok(ControlChannel::from_stream(stream))
    }

    /// Accept one per-flow data connection and read its [`DataHandshake`], returning
    /// the correlating `flow_id` alongside the raw data stream. Each call yields an
    /// independent socket — its own buffers and backpressure.
    ///
    /// # Errors
    /// Fails if accepting the connection fails, the peer closes before sending a
    /// handshake, or the handshake does not arrive within a few seconds
    /// ([`io::ErrorKind::TimedOut`]).
    pub async fn accept_data(&self) -> io::Result<DataConnection> {
        let (mut stream, _addr) = self.data.accept().await?;
        let handshake = read_handshake(&mut stream, DATA_HANDSHAKE_TIMEOUT).await?;
        Ok(DataConnection {
            flow_id: handshake.flow_id,
            stream,
        })
    }
}

impl Drop for CaptureListener {
    fn drop(&mut self) {
        // Best-effort: don't leave the bound socket files behind.
        let _ = fs::remove_file(self.dir.join(CONTROL_SOCK));
        let _ = fs::remove_file(self.dir.join(DATA_SOCK));
    }
}

/// The control channel: a framed [`ControlMessage`] codec over the control UDS.
/// Symmetric, so the core (receiver) and the provider/tests (sender) share one
/// codec. It counts the bytes it has read so a caller can prove no bulk data ever
/// crossed it.
pub struct ControlChannel {
    stream: UnixStream,
    bytes_read: u64,
}

impl ControlChannel {
    /// Wrap a connected control-socket stream.
    #[must_use]
    pub fn from_stream(stream: UnixStream) -> Self {
        Self {
            stream,
            bytes_read: 0,
        }
    }

    /// Send one control message.
    ///
    /// # Errors
    /// Fails on a serialization or write error.
    pub async fn send(&mut self, msg: &ControlMessage) -> io::Result<()> {
        write_frame(&mut self.stream, msg).await
    }

    /// Read the next control message, or `None` at a clean end of stream.
    ///
    /// Not cancel-safe: dropping this future mid-frame loses the bytes already
    /// read. A caller that must also write on a timer uses
    /// [`into_halves`](Self::into_halves) instead of racing this in a `select!`.
    ///
    /// # Errors
    /// Fails on a short read mid-frame or a malformed frame.
    pub async fn recv(&mut self) -> io::Result<Option<ControlMessage>> {
        recv_control(&mut self.stream, &mut self.bytes_read).await
    }

    /// Total bytes read off the control channel so far — used to prove the control
    /// channel never carried bulk flow data.
    #[must_use]
    pub fn bytes_read(&self) -> u64 {
        self.bytes_read
    }

    /// Split into an independent reader and writer over the one socket, so a
    /// caller can read frames in one future and write frames in another without
    /// either borrowing the other (and without ever cancelling a read mid-frame).
    /// The byte count read so far carries over to the reader. The peer-verification
    /// fd ([`AsRawFd`]) is only available before the split.
    #[must_use]
    pub fn into_halves(self) -> (ControlReader, ControlWriter) {
        let (read, write) = self.stream.into_split();
        (
            ControlReader {
                read,
                bytes_read: self.bytes_read,
            },
            ControlWriter { write },
        )
    }
}

/// The read half of a split [`ControlChannel`]: the same frame codec and byte
/// count, over the read side only.
pub struct ControlReader {
    read: OwnedReadHalf,
    bytes_read: u64,
}

impl ControlReader {
    /// Read the next control message, or `None` at a clean end of stream. Not
    /// cancel-safe (see [`ControlChannel::recv`]): run it in a loop that is only
    /// ever dropped as a whole.
    ///
    /// # Errors
    /// Fails on a short read mid-frame or a malformed frame.
    pub async fn recv(&mut self) -> io::Result<Option<ControlMessage>> {
        recv_control(&mut self.read, &mut self.bytes_read).await
    }

    /// Total bytes read off the control channel so far (including before the
    /// split).
    #[must_use]
    pub fn bytes_read(&self) -> u64 {
        self.bytes_read
    }
}

/// The write half of a split [`ControlChannel`].
pub struct ControlWriter {
    write: OwnedWriteHalf,
}

impl ControlWriter {
    /// Send one control message.
    ///
    /// # Errors
    /// Fails on a serialization or write error.
    pub async fn send(&mut self, msg: &ControlMessage) -> io::Result<()> {
        write_frame(&mut self.write, msg).await
    }
}

/// Read one control frame off `r`, adding its wire size to `bytes_read`. Shared by
/// [`ControlChannel::recv`] and [`ControlReader::recv`] so the two cannot drift.
async fn recv_control<R>(r: &mut R, bytes_read: &mut u64) -> io::Result<Option<ControlMessage>>
where
    R: AsyncRead + Unpin,
{
    let Some(buf) = read_capped(r, MAX_FRAME_LEN).await? else {
        return Ok(None);
    };
    *bytes_read += 4 + buf.len() as u64;
    let msg =
        serde_json::from_slice(&buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    Ok(Some(msg))
}

/// The control stream's file descriptor, so a [`PeerVerifier`] can read the peer's
/// audit token off the socket. The descriptor stays owned by the channel; callers
/// must not close it or use it past the channel's lifetime.
///
/// [`PeerVerifier`]: super::peer_auth::PeerVerifier
impl AsRawFd for ControlChannel {
    fn as_raw_fd(&self) -> RawFd {
        self.stream.as_raw_fd()
    }
}

/// One accepted per-flow data socket, after its handshake.
pub struct DataConnection {
    /// The flow this socket carries (from its [`DataHandshake`]).
    pub flow_id: u64,
    stream: UnixStream,
}

impl DataConnection {
    /// Take the raw data stream (TCP: the client byte stream).
    #[must_use]
    pub fn into_stream(self) -> UnixStream {
        self.stream
    }

    /// Borrow the raw data stream.
    pub fn stream_mut(&mut self) -> &mut UnixStream {
        &mut self.stream
    }

    /// The data stream's file descriptor, so a [`PeerVerifier`] can read the peer's
    /// audit token off the socket. The descriptor stays owned by this connection;
    /// callers must not close it or use it past the connection's lifetime.
    ///
    /// [`PeerVerifier`]: super::peer_auth::PeerVerifier
    #[must_use]
    pub fn peer_fd(&self) -> RawFd {
        self.stream.as_raw_fd()
    }

    /// Read the next length-delimited datagram (UDP), or `None` at end of stream.
    ///
    /// # Errors
    /// Fails on a short read mid-datagram.
    pub async fn recv_datagram(&mut self) -> io::Result<Option<Vec<u8>>> {
        read_datagram(&mut self.stream).await
    }
}

/// Write a [`DataHandshake`] as the first frame on a per-flow data socket (the
/// provider/test side of [`CaptureListener::accept_data`]).
///
/// # Errors
/// Fails on a serialization or write error.
pub async fn write_data_handshake<W>(w: &mut W, handshake: DataHandshake) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    write_frame(w, &handshake).await
}

/// Write one length-delimited datagram (`u32` big-endian length + bytes) — the UDP
/// data-socket framing.
///
/// # Errors
/// Fails if the datagram is larger than `u32::MAX` or on a write error.
pub async fn write_datagram<W>(w: &mut W, datagram: &[u8]) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    if datagram.len() > MAX_DATAGRAM_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "datagram exceeds maximum",
        ));
    }
    let len = u32::try_from(datagram.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "datagram too large"))?;
    w.write_all(&len.to_be_bytes()).await?;
    w.write_all(datagram).await?;
    w.flush().await?;
    Ok(())
}

/// Read one length-delimited datagram, or `None` at a clean end of stream.
///
/// # Errors
/// Fails on a short read mid-datagram.
pub async fn read_datagram<R>(r: &mut R) -> io::Result<Option<Vec<u8>>>
where
    R: AsyncRead + Unpin,
{
    read_capped(r, MAX_DATAGRAM_LEN).await
}

/// Write a `u32`-length-prefixed JSON frame.
async fn write_frame<T, W>(w: &mut W, msg: &T) -> io::Result<()>
where
    T: Serialize,
    W: AsyncWrite + Unpin,
{
    let bytes =
        serde_json::to_vec(msg).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    if bytes.len() > MAX_FRAME_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "control frame exceeds maximum",
        ));
    }
    let len = u32::try_from(bytes.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "control frame too large"))?;
    w.write_all(&len.to_be_bytes()).await?;
    w.write_all(&bytes).await?;
    w.flush().await?;
    Ok(())
}

/// Read a `u32`-length-prefixed JSON frame, or `None` at a clean end of stream.
async fn read_frame<T, R>(r: &mut R) -> io::Result<Option<T>>
where
    T: DeserializeOwned,
    R: AsyncRead + Unpin,
{
    let Some(buf) = read_capped(r, MAX_FRAME_LEN).await? else {
        return Ok(None);
    };
    let msg =
        serde_json::from_slice(&buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    Ok(Some(msg))
}

/// Read the [`DataHandshake`] off a just-accepted data socket within `within`.
/// A peer that stays silent or sends half a frame is cut off with
/// [`io::ErrorKind::TimedOut`]; one that closes first is
/// [`io::ErrorKind::UnexpectedEof`].
async fn read_handshake<R>(r: &mut R, within: Duration) -> io::Result<DataHandshake>
where
    R: AsyncRead + Unpin,
{
    match tokio::time::timeout(within, read_frame(r)).await {
        Ok(Ok(Some(handshake))) => Ok(handshake),
        Ok(Ok(None)) => Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "data socket closed before its handshake",
        )),
        Ok(Err(e)) => Err(e),
        Err(_elapsed) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "data socket sent no handshake in time",
        )),
    }
}

/// Read a `u32`-big-endian length prefix and that many bytes.
///
/// Rejects any declared length above `max` with `InvalidData` **before
/// allocating**, so a corrupt or hostile 4-byte prefix (e.g. `0xFFFFFFFF`) cannot
/// drive the core to allocate up to 4 GiB. Returns `Ok(None)` at a clean end of
/// stream (EOF before the length prefix). Shared by every length-prefixed reader.
async fn read_capped<R>(r: &mut R, max: usize) -> io::Result<Option<Vec<u8>>>
where
    R: AsyncRead + Unpin,
{
    let mut len_buf = [0u8; 4];
    match r.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > max {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame length exceeds maximum",
        ));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await?;
    Ok(Some(buf))
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::time::Duration;

    use tokio::io::AsyncWriteExt;

    use super::{
        read_handshake, write_data_handshake, AsRawFd, ControlChannel, ControlMessage,
        DataConnection, DataHandshake, Hello, ScopeSpec,
    };

    /// A data socket that connects and never sends its handshake is cut off at the
    /// deadline with `TimedOut`, not waited on forever: otherwise one silent
    /// same-uid peer (not yet verified — the handshake is read first) pins an
    /// accept slot indefinitely.
    #[tokio::test]
    async fn silent_data_peer_times_out_instead_of_hanging() {
        let (_silent_peer, mut core) = tokio::io::duplex(64);
        let err = read_handshake(&mut core, Duration::from_millis(50))
            .await
            .expect_err("a silent peer must time out");
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    }

    /// A peer that sends only part of the handshake frame (the length prefix, then
    /// nothing) is cut off the same way.
    #[tokio::test]
    async fn half_sent_handshake_times_out() {
        let (mut peer, mut core) = tokio::io::duplex(64);
        peer.write_all(&[0, 0, 0, 20]).await.unwrap();
        let err = read_handshake(&mut core, Duration::from_millis(50))
            .await
            .expect_err("a half-sent handshake must time out");
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    }

    /// A prompt handshake inside the deadline is read normally, and a peer that
    /// closes without sending one is `UnexpectedEof`, not a timeout.
    #[tokio::test]
    async fn prompt_handshake_is_read_and_early_close_is_eof() {
        let (mut peer, mut core) = tokio::io::duplex(64);
        write_data_handshake(&mut peer, DataHandshake { flow_id: 42 })
            .await
            .unwrap();
        assert_eq!(
            read_handshake(&mut core, Duration::from_secs(5))
                .await
                .unwrap(),
            DataHandshake { flow_id: 42 }
        );

        let (peer, mut core) = tokio::io::duplex(64);
        drop(peer);
        let err = read_handshake(&mut core, Duration::from_secs(5))
            .await
            .expect_err("closing before the handshake is an error");
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    /// After a split, the reader and the writer work independently over the one
    /// socket: the reader yields what the provider sent (and counts its bytes), the
    /// writer's frames reach the provider. This is what lets the feeder read
    /// `FlowOpen`s while a timer re-sends `Scope` on the same control channel.
    #[tokio::test]
    async fn into_halves_reads_and_writes_independently() {
        let (provider, core) = tokio::net::UnixStream::pair().unwrap();
        let mut provider = ControlChannel::from_stream(provider);
        let (mut reader, mut writer) = ControlChannel::from_stream(core).into_halves();

        provider
            .send(&ControlMessage::Hello(Hello {
                protocol_version: 1,
            }))
            .await
            .unwrap();
        writer
            .send(&ControlMessage::Scope(ScopeSpec {
                spec: "example.com".to_string(),
            }))
            .await
            .unwrap();

        assert_eq!(
            reader.recv().await.unwrap(),
            Some(ControlMessage::Hello(Hello {
                protocol_version: 1
            }))
        );
        // 4-byte length prefix + the 32-byte JSON body.
        assert_eq!(reader.bytes_read(), 36);
        assert_eq!(
            provider.recv().await.unwrap(),
            Some(ControlMessage::Scope(ScopeSpec {
                spec: "example.com".to_string()
            }))
        );
    }

    /// The bytes already read on the unsplit channel (the Hello the feeder gates on)
    /// carry over to the reader, so the control/data-separation count stays whole.
    #[tokio::test]
    async fn into_halves_keeps_the_bytes_read_so_far() {
        let (provider, core) = tokio::net::UnixStream::pair().unwrap();
        let mut provider = ControlChannel::from_stream(provider);
        let mut core = ControlChannel::from_stream(core);
        provider
            .send(&ControlMessage::Hello(Hello {
                protocol_version: 1,
            }))
            .await
            .unwrap();
        core.recv().await.unwrap();
        assert_eq!(core.bytes_read(), 36);

        let (reader, _writer) = core.into_halves();
        assert_eq!(reader.bytes_read(), 36);
    }

    /// Dropping both halves closes the socket: the provider sees a clean end of
    /// stream, not a hang.
    #[tokio::test]
    async fn dropping_both_halves_gives_the_provider_a_clean_eof() {
        let (provider, core) = tokio::net::UnixStream::pair().unwrap();
        let mut provider = ControlChannel::from_stream(provider);
        let (reader, writer) = ControlChannel::from_stream(core).into_halves();
        drop(writer);
        drop(reader);
        assert_eq!(provider.recv().await.unwrap(), None);
    }

    /// A `DataConnection` over a connected pair (no path bind) exposes the very
    /// descriptor of its stream, so a peer verifier reads the right socket.
    #[tokio::test]
    async fn data_connection_peer_fd_is_the_stream_fd() {
        let (a, _b) = tokio::net::UnixStream::pair().unwrap();
        let raw = a.as_raw_fd();
        let conn = DataConnection {
            flow_id: 7,
            stream: a,
        };
        assert!(conn.peer_fd() >= 0);
        assert_eq!(conn.peer_fd(), raw);
    }
}
