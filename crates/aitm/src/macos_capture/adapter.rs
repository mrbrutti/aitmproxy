//! The macOS capture-backend adapter (L4 Phase 2, plan Task 2 — NE-AC1/2/3).
//!
//! Task 8 pinned the handoff on the control/data sockets: a [`Hello`], then one
//! [`FlowOpen`] per flow on the control channel, each paired with a per-flow data
//! socket ([`DataConnection`]). This adapter is the **thin** glue that turns one
//! such handoff flow into the protocol-general ingress types in [`crate::ingress`]
//! and dispatches it — it does **not** re-implement dispatch, redeclare the flow
//! types, or add a guard. Deny-by-default lives **inside** the ingress
//! ([`CoreIngress::dispatch_tcp`] refuses an out-of-scope stream before any module
//! match; [`CoreIngress::dispatch_udp`] routes each datagram through the shared
//! `L4Guard`), so this path is guarded identically to the Linux/CLI `pcap` path.
//!
//! The one wrinkle over the explicit-proxy acceptor: tokio's [`UnixStream`] cannot
//! `peek`, so a TCP flow's leading bytes are **read** for protocol sniffing and
//! re-emitted ahead of the live stream by [`PrefixedStream`] — the module the
//! ingress picks still sees `first_bytes`, exactly as the peeking acceptor's does.
//!
//! [`UnixStream`]: tokio::net::UnixStream
//! [`CoreIngress::dispatch_tcp`]: crate::ingress::CoreIngress
//! [`CoreIngress::dispatch_udp`]: crate::ingress::CoreIngress::dispatch_udp

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use aitm_core::ByteStream;
use aitm_proto_l4::types::{L4Direction, L4Proto, L4Target};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};

use crate::ingress::{
    dispatch_captured_tcp, CapturedTcpFlow, CapturedUdpFlow, CoreIngress, IngressOutcome,
    StreamOutcome,
};
use crate::macos_capture::listener::{
    ControlChannel, ControlMessage, DataConnection, FlowKind, FlowOpen, Hello,
};

/// The handoff protocol version this core speaks. A provider announcing a
/// different version in its [`Hello`] is refused ([`check_hello`]) — a mismatched
/// provider/core pair must fail loudly, not misread each other's frames. The
/// version check the listener deferred to the adapter (see `listener::Hello`).
pub const HANDOFF_PROTOCOL_VERSION: u32 = 1;

/// The sentinel interface the macOS NE capture backend tags its L4 flows with. The
/// extension captures **system-wide** — there is no `pcap` interface — so operator
/// L4 scope for the NE path is authored against this interface name, which the
/// shared `L4Guard` matches by exact string. A constant, not a guess, so the
/// operator's scope and the adapter's target agree.
pub const CAPTURE_INTERFACE: &str = "macos-ne";

/// Leading bytes read off a TCP flow for protocol sniffing (a whole TLS
/// ClientHello for SNI, or an HTTP/CONNECT request line), matching the acceptor's
/// 2 KiB peek. The bytes are not lost — [`PrefixedStream`] re-emits them.
const SNIFF_LEN: usize = 2048;

/// What the ingress did with one adapted capture flow — the TCP (stream) outcome
/// or the UDP (L4) outcome, by kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureOutcome {
    /// A TCP/stream flow's [`StreamOutcome`].
    Tcp(StreamOutcome),
    /// A UDP flow's [`IngressOutcome`].
    Udp(IngressOutcome),
}

/// Validate the provider's opening [`Hello`]. A version mismatch is refused with
/// [`io::ErrorKind::InvalidData`] so a wrong-version provider fails loudly.
///
/// # Errors
/// Fails when `hello.protocol_version != HANDOFF_PROTOCOL_VERSION`.
pub fn check_hello(hello: &Hello) -> io::Result<()> {
    if hello.protocol_version != HANDOFF_PROTOCOL_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "handoff protocol version mismatch: provider announced {}, core speaks {HANDOFF_PROTOCOL_VERSION}",
                hello.protocol_version
            ),
        ));
    }
    Ok(())
}

/// Read and validate the provider's opening frame on the control channel: it must
/// be a [`Hello`], and its `protocol_version` must match ([`check_hello`]). This is
/// the adapter's control-channel entry point — the live feeder (plan Task 9) calls
/// it before reading any [`FlowOpen`], so the version gate runs for real on every
/// session, not just in isolation.
///
/// # Errors
/// Fails if the channel closes before a frame, the first frame is not a `Hello`, or
/// the announced version does not match [`HANDOFF_PROTOCOL_VERSION`].
pub async fn recv_hello(control: &mut ControlChannel) -> io::Result<Hello> {
    match control.recv().await? {
        Some(ControlMessage::Hello(hello)) => {
            check_hello(&hello)?;
            Ok(hello)
        }
        Some(other) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("expected Hello as the first control frame, got {other:?}"),
        )),
        None => Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "control channel closed before the Hello",
        )),
    }
}

/// Adapt one captured flow onto the ingress and dispatch it. `open` is its
/// control-channel metadata; `data` is its correlated per-flow data socket. The
/// kind in `open` selects the TCP (stream) or UDP (L4) path. The caller pairs the
/// [`FlowOpen`] with the right [`DataConnection`]; a `flow_id` mismatch is refused
/// here (fail-closed), never dispatched on a mis-paired socket.
///
/// # Errors
/// Fails on a `flow_id` mismatch, or on an I/O error reading the data socket.
pub async fn dispatch_captured_flow(
    ingress: &CoreIngress,
    open: &FlowOpen,
    data: DataConnection,
) -> io::Result<CaptureOutcome> {
    if open.flow_id != data.flow_id {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "flow id mismatch: control flow-open {} paired with data socket {}",
                open.flow_id, data.flow_id
            ),
        ));
    }
    match open.kind {
        FlowKind::Tcp => Ok(CaptureOutcome::Tcp(adapt_tcp(ingress, open, data).await?)),
        FlowKind::Udp => Ok(CaptureOutcome::Udp(adapt_udp(ingress, open, data).await?)),
    }
}

/// Adapt a captured **TCP** handoff flow onto [`CapturedTcpFlow`] and dispatch it
/// through the protocol-general ingress (which guards, matches, and either spawns
/// a module or passes the flow through).
async fn adapt_tcp(
    ingress: &CoreIngress,
    open: &FlowOpen,
    data: DataConnection,
) -> io::Result<StreamOutcome> {
    let (first_bytes, stream) = sniff_prefix(data.into_stream()).await?;
    let flow = tcp_flow(open, Box::pin(stream), first_bytes);
    Ok(dispatch_captured_tcp(ingress, flow).await)
}

/// Adapt a captured **UDP** handoff flow onto [`CapturedUdpFlow`] and dispatch it
/// over the existing deny-by-default L4 path (the shared `L4Guard`).
///
/// **Guard-before-work (mirroring the TCP path):** the scope guard is consulted
/// *first*, from the [`FlowOpen`] metadata alone, so an out-of-scope (or
/// no-backend) flow is refused before a single datagram payload is read — never
/// buffered. An admitted flow is then streamed and dispatched **one datagram at a
/// time**, so the adapter never accumulates an unbounded buffer: live memory is a
/// single datagram (the listener caps each at 64 KiB), whatever the flow's length.
async fn adapt_udp(
    ingress: &CoreIngress,
    open: &FlowOpen,
    mut data: DataConnection,
) -> io::Result<IngressOutcome> {
    let target = udp_target(open);
    // Refuse before buffering: an out-of-scope or no-backend flow is decided from
    // metadata alone, draining no payload.
    match ingress.udp_admits(&target) {
        IngressOutcome::Unhandled => return Ok(IngressOutcome::Unhandled),
        IngressOutcome::Refused => return Ok(IngressOutcome::Refused),
        IngressOutcome::Captured => {} // admitted — stream the datagrams, bounded.
    }

    // Admitted: dispatch each datagram as it arrives. Each `dispatch_udp` call
    // re-applies the same `L4Guard` check (the guard below the ingress stays
    // authoritative) and appends to the one shared capture flow.
    let mut outcome = IngressOutcome::Refused;
    while let Some(datagram) = data.recv_datagram().await? {
        if ingress.dispatch_udp(CapturedUdpFlow {
            target: target.clone(),
            datagrams: vec![datagram],
            peer_identity: open.source_app.clone(),
        }) == IngressOutcome::Captured
        {
            outcome = IngressOutcome::Captured;
        }
    }
    Ok(outcome)
}

/// Map a TCP [`FlowOpen`] and its sniffed stream onto the ingress's own
/// [`CapturedTcpFlow`]: `remote → dst`, `remote_hostname → sni`,
/// `source_app → peer_identity`. The destination is the **authoritative original**
/// endpoint the provider observed, not an accepted-socket peer.
fn tcp_flow(open: &FlowOpen, stream: ByteStream, first_bytes: Vec<u8>) -> CapturedTcpFlow {
    CapturedTcpFlow {
        stream,
        dst: open.remote,
        sni: open.remote_hostname.clone(),
        first_bytes,
        peer_identity: open.source_app.clone(),
    }
}

/// Build the L4 dispatch target the UDP guard authorizes against from a UDP
/// [`FlowOpen`]: the authoritative original remote endpoint, tagged with the NE
/// capture interface and the outbound direction. Matches the `(Capture, target)`
/// a `pcap`-fed UDP packet presents, so one `L4Guard` grant covers both paths.
fn udp_target(open: &FlowOpen) -> L4Target {
    L4Target {
        interface: CAPTURE_INTERFACE.to_string(),
        direction: L4Direction::Outbound,
        dst: Some(open.remote.ip()),
        dst_port: Some(open.remote.port()),
        proto: L4Proto::Udp,
    }
}

/// Read up to [`SNIFF_LEN`] leading bytes off `stream` for protocol sniffing, and
/// return them alongside a [`PrefixedStream`] that re-emits them ahead of the rest
/// — so the module the ingress picks still reads `first_bytes`. tokio's
/// `UnixStream` has no `peek`, so the bytes are read once and prepended, which is
/// equivalent for a stream that is only read forward.
async fn sniff_prefix<S>(mut stream: S) -> io::Result<(Vec<u8>, PrefixedStream<S>)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; SNIFF_LEN];
    let n = stream.read(&mut buf).await?;
    buf.truncate(n);
    Ok((buf.clone(), PrefixedStream::new(buf, stream)))
}

/// A duplex stream that yields a buffered `prefix` before delegating reads to its
/// `inner` stream; writes pass straight through. Lets the adapter sniff a flow's
/// leading bytes and still hand the ingress a stream that re-emits them.
struct PrefixedStream<S> {
    prefix: Vec<u8>,
    pos: usize,
    inner: S,
}

impl<S> PrefixedStream<S> {
    fn new(prefix: Vec<u8>, inner: S) -> Self {
        Self {
            prefix,
            pos: 0,
            inner,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixedStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.pos < this.prefix.len() {
            let remaining = &this.prefix[this.pos..];
            let n = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..n]);
            this.pos += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixedStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    fn tcp_open() -> FlowOpen {
        FlowOpen {
            flow_id: 7,
            kind: FlowKind::Tcp,
            remote: "93.184.216.34:443".parse().unwrap(),
            remote_hostname: Some("example.com".to_string()),
            source_app: Some("com.example.browser".to_string()),
            local: None,
        }
    }

    /// `check_hello` accepts the version the core speaks and refuses any other.
    #[test]
    fn hello_version_is_validated() {
        assert!(check_hello(&Hello {
            protocol_version: HANDOFF_PROTOCOL_VERSION,
        })
        .is_ok());
        let err = check_hello(&Hello {
            protocol_version: HANDOFF_PROTOCOL_VERSION + 1,
        })
        .expect_err("a mismatched handoff version must be refused");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    /// `recv_hello` runs the version gate on the live control channel: it accepts a
    /// matching `Hello`, refuses a mismatched version, and rejects a non-`Hello`
    /// first frame — so the gate runs for real, not just in isolation.
    #[tokio::test]
    async fn recv_hello_gates_the_control_channel() {
        use crate::macos_capture::listener::ScopeSpec;

        // Matching version → accepted.
        let (provider, core) = tokio::net::UnixStream::pair().unwrap();
        let mut provider = ControlChannel::from_stream(provider);
        let mut core = ControlChannel::from_stream(core);
        provider
            .send(&ControlMessage::Hello(Hello {
                protocol_version: HANDOFF_PROTOCOL_VERSION,
            }))
            .await
            .unwrap();
        assert_eq!(
            recv_hello(&mut core)
                .await
                .expect("hello accepted")
                .protocol_version,
            HANDOFF_PROTOCOL_VERSION
        );

        // Mismatched version → refused.
        let (provider, core) = tokio::net::UnixStream::pair().unwrap();
        let mut provider = ControlChannel::from_stream(provider);
        let mut core = ControlChannel::from_stream(core);
        provider
            .send(&ControlMessage::Hello(Hello {
                protocol_version: HANDOFF_PROTOCOL_VERSION + 1,
            }))
            .await
            .unwrap();
        assert_eq!(
            recv_hello(&mut core)
                .await
                .expect_err("mismatch refused")
                .kind(),
            io::ErrorKind::InvalidData
        );

        // A non-Hello first frame → refused.
        let (provider, core) = tokio::net::UnixStream::pair().unwrap();
        let mut provider = ControlChannel::from_stream(provider);
        let mut core = ControlChannel::from_stream(core);
        provider
            .send(&ControlMessage::Scope(ScopeSpec {
                spec: "scope".to_string(),
            }))
            .await
            .unwrap();
        assert_eq!(
            recv_hello(&mut core)
                .await
                .expect_err("non-hello refused")
                .kind(),
            io::ErrorKind::InvalidData
        );
    }

    /// The TCP mapping carries the authoritative remote, the SNI, the source-app
    /// identity (→ `peer_identity`), and the sniffed `first_bytes`.
    #[test]
    fn tcp_flow_maps_every_handoff_field() {
        let open = tcp_open();
        let first = vec![0x16, 0x03, 0x01];
        let flow = tcp_flow(&open, Box::pin(tokio::io::duplex(16).0), first.clone());
        assert_eq!(flow.dst, open.remote);
        assert_eq!(flow.sni.as_deref(), Some("example.com"));
        assert_eq!(
            flow.peer_identity.as_deref(),
            Some("com.example.browser"),
            "source_app maps onto peer_identity"
        );
        assert_eq!(flow.first_bytes, first);
    }

    /// The UDP mapping tags the flow with the NE capture interface and the
    /// authoritative remote endpoint, as a `Udp`/`Outbound` L4 target.
    #[test]
    fn udp_target_maps_remote_and_interface() {
        let open = FlowOpen {
            flow_id: 3,
            kind: FlowKind::Udp,
            remote: "198.51.100.7:53".parse().unwrap(),
            remote_hostname: None,
            source_app: None,
            local: Some("192.0.2.1:50000".parse().unwrap()),
        };
        let target = udp_target(&open);
        assert_eq!(target.interface, CAPTURE_INTERFACE);
        assert_eq!(target.direction, L4Direction::Outbound);
        assert_eq!(target.proto, L4Proto::Udp);
        assert_eq!(target.dst, Some("198.51.100.7".parse().unwrap()));
        assert_eq!(target.dst_port, Some(53));
    }

    /// The sniffed prefix is re-emitted ahead of the live stream: a reader of the
    /// returned stream sees the leading bytes followed by the rest, in order, and
    /// `first_bytes` holds exactly the sniffed prefix.
    #[tokio::test]
    async fn prefixed_stream_reemits_sniffed_bytes_then_the_rest() {
        let (mut peer, inner) = tokio::io::duplex(1024);
        let writer = tokio::spawn(async move {
            peer.write_all(b"GET / HTTP/1.1\r\nrest-of-stream")
                .await
                .unwrap();
            peer.shutdown().await.unwrap();
        });

        let (first_bytes, mut stream) = sniff_prefix(inner).await.expect("sniff");
        let mut all = Vec::new();
        stream.read_to_end(&mut all).await.expect("read all");
        writer.await.unwrap();

        assert!(
            !first_bytes.is_empty(),
            "the leading bytes were sniffed, not lost"
        );
        assert_eq!(
            all, b"GET / HTTP/1.1\r\nrest-of-stream",
            "the whole stream is readable: the sniffed prefix precedes the rest"
        );
        assert!(
            all.starts_with(&first_bytes),
            "the re-emitted stream begins with the sniffed first_bytes"
        );
    }

    /// Writes to a `PrefixedStream` reach the inner stream even while its read side
    /// still owes the buffered prefix — the prefix gates reads only, never writes.
    #[tokio::test]
    async fn prefixed_stream_writes_pass_through() {
        let (near, mut far) = tokio::io::duplex(1024);
        let mut stream = PrefixedStream::new(b"unread-prefix".to_vec(), near);
        stream.write_all(b"client-says-hi").await.expect("write");
        stream.shutdown().await.expect("shutdown");

        let mut got = Vec::new();
        far.read_to_end(&mut got).await.expect("read peer");
        assert_eq!(got, b"client-says-hi");
    }
}
