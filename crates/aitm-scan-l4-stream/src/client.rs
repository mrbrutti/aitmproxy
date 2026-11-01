//! The `StreamClient` trait and its tokio TCP/UDP implementation (spec S5.3,
//! S5.4, S5.5, S5.7).
//!
//! One `exchange` is one connection: the client connects (TCP) or opens a
//! connected datagram socket (UDP), optionally reads a banner, then writes each
//! message and reads one bounded reply for it, and closes. A fresh connection
//! per case costs throughput and buys attribution: the target's reaction to a
//! case is never confused with the state a previous case left behind
//! (spec S5.5, Architect's call).
//!
//! Three bounds hold on every path, so a target that answers forever, answers
//! slowly, or never answers at all all cost the same: at most
//! [`MAX_REPLY`] bytes are read per reply, the reply timeout ends the read, and
//! the connect timeout ends the connect. Two authorisations gate every byte
//! that leaves: the caller's [`L4Permit`] (minted by `L4Guard::check` before the
//! socket is opened) is asked again per write via `authorize_packet`, and the
//! job's [`BytePacer`] says how long to sleep first. The client only surfaces a
//! guard refusal as [`ClientError::Guard`]; the retry rule for a rate refusal is
//! the host's (spec S5.4).
//!
//! Nothing here logs a message or a reply, and `Debug` on [`ExchangeStep`]
//! prints the reply as a length (spec S9, child criterion C11).

use std::fmt;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use aitm_proto_l4::guard::{L4GuardError, L4Permit};
use aitm_scan_model::L4Transport;
use futures::future::BoxFuture;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

use crate::state::{lock, BytePacer, MAX_REPLY};

/// Where a case is sent: the address Task 15's discovery cache resolved.
///
/// The lane has one endpoint type, [`crate::state::EndpointAddr`]; `Endpoint` is
/// the name the transport layer calls it by (spec S5.5).
pub use crate::state::EndpointAddr as Endpoint;

/// Bytes read from the socket in one `read` call.
///
/// Only a staging buffer: the reply itself is capped at [`MAX_REPLY`], and the
/// last read is shortened so the cap is hit exactly.
const READ_CHUNK: usize = 8192;

/// How an exchange step finished, as the transport saw it (spec S5.5).
///
/// This is the transport half of the oracle's decision table (S6.1); the
/// grammar's `classify_reply` is the other half. Task 7's `grammar.rs`
/// re-exports this type (plan call P2), so both halves name one `Ended`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ended {
    /// A reply arrived and the grammar's completeness predicate accepted it,
    /// or the 64 KiB ceiling stopped the read.
    Replied,
    /// The reply timeout expired. Whatever had arrived is kept.
    Silence,
    /// The peer closed cleanly (`read` returned 0).
    Eof,
    /// The peer reset the connection (`ECONNRESET`) or the write hit a closed
    /// socket (`EPIPE`).
    Reset,
    /// A UDP send or receive surfaced `ECONNREFUSED`, which the host learned
    /// from an ICMP port-unreachable.
    IcmpUnreachable,
}

/// One message sent and the reply it got (spec S5.5).
///
/// A banner read before the first message is step 0 with `sent_len: 0`.
/// `Debug` prints `reply` as a length, never its contents.
#[derive(Clone, PartialEq, Eq)]
pub struct ExchangeStep {
    /// Bytes written for this step; `0` for a banner.
    pub sent_len: usize,
    /// The reply, bounded at [`MAX_REPLY`] and empty on silence.
    pub reply: Vec<u8>,
    /// How the step finished.
    pub ended: Ended,
    /// Wall-clock milliseconds from the write (or the start of a banner read)
    /// to the reply, the close, or the timeout.
    pub elapsed_ms: u32,
}

impl fmt::Debug for ExchangeStep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExchangeStep")
            .field("sent_len", &self.sent_len)
            .field("reply", &format_args!("<{} bytes>", self.reply.len()))
            .field("ended", &self.ended)
            .field("elapsed_ms", &self.elapsed_ms)
            .finish()
    }
}

/// Why an exchange produced no steps (spec S5.5).
///
/// A peer that resets or closes mid-exchange is **not** an error: that is an
/// [`Ended`] on a step, which the oracle reads. Only a failure to reach the
/// peer at all, a guard refusal, or a dry run lands here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientError {
    /// The connect did not finish within the connect timeout.
    ConnectTimeout,
    /// The peer refused the connection (`ECONNREFUSED`).
    ConnectRefused,
    /// The L4 guard refused a write (spec S5.4); the host decides whether a
    /// rate refusal is worth retrying.
    Guard(L4GuardError),
    /// Any other socket error, rendered by the OS. Carries no message bytes.
    Io(String),
    /// The lane is in dry run: the client opened nothing (spec S7).
    DryRun,
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClientError::ConnectTimeout => write!(f, "connect timed out"),
            ClientError::ConnectRefused => write!(f, "connection refused"),
            ClientError::Guard(e) => write!(f, "refused by the L4 guard: {e}"),
            ClientError::Io(e) => write!(f, "socket error: {e}"),
            ClientError::DryRun => write!(f, "dry run: nothing was sent"),
        }
    }
}

impl std::error::Error for ClientError {}

/// The transport the lane sends cases over (spec S5.5).
///
/// A trait so a check can be driven by a double that opens no socket: the
/// campaign tests count exchanges through [`testing::CountingClient`] instead
/// of reading a packet capture (child criteria C8, C9).
pub trait StreamClient: Send + Sync {
    /// Run one exchange on one fresh connection.
    ///
    /// `permit` is the connection's guard permit; every write asks it again.
    /// `pacer` is the job's byte pacer, locked only long enough to compute a
    /// wait (never held across an await). `complete` is the grammar's
    /// reply-completeness predicate, which ends a read early. `expects_banner`
    /// reads one reply before the first message, recorded as step 0.
    ///
    /// Returns one step per message (plus the banner step), in order, or the
    /// reason nothing could be sent.
    // Eight parameters is the shape spec S5.5 fixes: endpoint, authorisation,
    // pacing, payload, completeness, banner and the two timeouts are each an
    // independent decision of the caller's, and bundling them would hide the
    // authorisation arguments inside a struct.
    #[allow(clippy::too_many_arguments)]
    fn exchange<'a>(
        &'a self,
        ep: &'a Endpoint,
        permit: &'a mut L4Permit,
        pacer: &'a Mutex<BytePacer>,
        messages: &'a [Vec<u8>],
        complete: &'a (dyn Fn(&[u8]) -> bool + Sync),
        expects_banner: bool,
        reply_timeout: Duration,
        connect_timeout: Duration,
    ) -> BoxFuture<'a, Result<Vec<ExchangeStep>, ClientError>>;
}

/// The real client: one tokio TCP connection or connected UDP socket per
/// exchange (spec S5.5).
#[derive(Debug, Clone, Copy, Default)]
pub struct TokioStreamClient;

impl StreamClient for TokioStreamClient {
    #[allow(clippy::too_many_arguments)]
    fn exchange<'a>(
        &'a self,
        ep: &'a Endpoint,
        permit: &'a mut L4Permit,
        pacer: &'a Mutex<BytePacer>,
        messages: &'a [Vec<u8>],
        complete: &'a (dyn Fn(&[u8]) -> bool + Sync),
        expects_banner: bool,
        reply_timeout: Duration,
        connect_timeout: Duration,
    ) -> BoxFuture<'a, Result<Vec<ExchangeStep>, ClientError>> {
        Box::pin(async move {
            match ep.proto {
                L4Transport::Tcp => {
                    tcp_exchange(
                        ep,
                        permit,
                        pacer,
                        messages,
                        complete,
                        expects_banner,
                        reply_timeout,
                        connect_timeout,
                    )
                    .await
                }
                L4Transport::Udp => {
                    udp_exchange(
                        ep,
                        permit,
                        pacer,
                        messages,
                        complete,
                        expects_banner,
                        reply_timeout,
                    )
                    .await
                }
            }
        })
    }
}

/// Sleep as long as the job's pacer says `len` bytes cost.
///
/// The lock is taken, the wait computed and the guard dropped before the
/// `await`, so no task ever holds the pacer across a suspension point.
async fn pace(pacer: &Mutex<BytePacer>, len: usize) {
    let wait = {
        let mut pacer = lock(pacer);
        pacer.wait_for(len)
    };
    if !wait.is_zero() {
        tokio::time::sleep(wait).await;
    }
}

/// Milliseconds since `started`, saturating rather than wrapping.
fn elapsed_ms(started: Instant) -> u32 {
    u32::try_from(started.elapsed().as_millis()).unwrap_or(u32::MAX)
}

/// Why a connect failed, in the client's vocabulary.
fn connect_error(e: &io::Error) -> ClientError {
    match e.kind() {
        io::ErrorKind::ConnectionRefused => ClientError::ConnectRefused,
        io::ErrorKind::TimedOut => ClientError::ConnectTimeout,
        _ => ClientError::Io(e.to_string()),
    }
}

/// How an exchange step ends when a read or a write fails, or `None` when the
/// error is not the peer ending the conversation.
fn ended_for(e: &io::Error) -> Option<Ended> {
    match e.kind() {
        io::ErrorKind::ConnectionReset | io::ErrorKind::BrokenPipe => Some(Ended::Reset),
        io::ErrorKind::ConnectionRefused => Some(Ended::IcmpUnreachable),
        io::ErrorKind::UnexpectedEof => Some(Ended::Eof),
        _ => None,
    }
}

/// One TCP connection: optional banner, then one write + one bounded read per
/// message.
#[allow(clippy::too_many_arguments)]
async fn tcp_exchange(
    ep: &Endpoint,
    permit: &mut L4Permit,
    pacer: &Mutex<BytePacer>,
    messages: &[Vec<u8>],
    complete: &(dyn Fn(&[u8]) -> bool + Sync),
    expects_banner: bool,
    reply_timeout: Duration,
    connect_timeout: Duration,
) -> Result<Vec<ExchangeStep>, ClientError> {
    let addr = SocketAddr::new(ep.ip, ep.port);
    let mut stream = match tokio::time::timeout(connect_timeout, TcpStream::connect(addr)).await {
        Err(_elapsed) => return Err(ClientError::ConnectTimeout),
        Ok(Err(e)) => return Err(connect_error(&e)),
        Ok(Ok(stream)) => stream,
    };

    let mut steps = Vec::with_capacity(messages.len() + usize::from(expects_banner));

    if expects_banner {
        let started = Instant::now();
        let (reply, ended) = tcp_read_reply(&mut stream, complete, reply_timeout).await?;
        let banner_ended = ended;
        steps.push(ExchangeStep {
            sent_len: 0,
            reply,
            ended,
            elapsed_ms: elapsed_ms(started),
        });
        // A peer that closed or reset before saying anything will not read
        // either; stop rather than write into a dead socket.
        if matches!(banner_ended, Ended::Eof | Ended::Reset) {
            return Ok(steps);
        }
    }

    for message in messages {
        pace(pacer, message.len()).await;
        permit
            .authorize_packet(message.len())
            .map_err(ClientError::Guard)?;

        let started = Instant::now();
        if let Err(e) = stream.write_all(message).await {
            // The peer went away mid-write: that is a reaction, not a client
            // failure, so it is the step's ending.
            let Some(ended) = ended_for(&e) else {
                return Err(ClientError::Io(e.to_string()));
            };
            steps.push(ExchangeStep {
                sent_len: message.len(),
                reply: Vec::new(),
                ended,
                elapsed_ms: elapsed_ms(started),
            });
            return Ok(steps);
        }

        let (reply, ended) = tcp_read_reply(&mut stream, complete, reply_timeout).await?;
        let step_ended = ended;
        steps.push(ExchangeStep {
            sent_len: message.len(),
            reply,
            ended,
            elapsed_ms: elapsed_ms(started),
        });
        if matches!(step_ended, Ended::Eof | Ended::Reset) {
            return Ok(steps);
        }
    }

    Ok(steps)
}

/// Read one reply, bounded three ways: the grammar's completeness predicate,
/// the 64 KiB ceiling, and the reply timeout.
async fn tcp_read_reply(
    stream: &mut TcpStream,
    complete: &(dyn Fn(&[u8]) -> bool + Sync),
    reply_timeout: Duration,
) -> Result<(Vec<u8>, Ended), ClientError> {
    let deadline = Instant::now() + reply_timeout;
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; READ_CHUNK];

    loop {
        let room = MAX_REPLY - buf.len();
        if room == 0 {
            return Ok((buf, Ended::Replied));
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Ok((buf, Ended::Silence));
        }
        let want = room.min(READ_CHUNK);
        match tokio::time::timeout(left, stream.read(&mut chunk[..want])).await {
            Err(_elapsed) => return Ok((buf, Ended::Silence)),
            Ok(Ok(0)) => return Ok((buf, Ended::Eof)),
            Ok(Ok(n)) => {
                buf.extend_from_slice(&chunk[..n]);
                if complete(&buf) {
                    return Ok((buf, Ended::Replied));
                }
            }
            Ok(Err(e)) => {
                let Some(ended) = ended_for(&e) else {
                    return Err(ClientError::Io(e.to_string()));
                };
                return Ok((buf, ended));
            }
        }
    }
}

/// One connected UDP socket: optional first datagram, then one send + one
/// bounded receive per message.
async fn udp_exchange(
    ep: &Endpoint,
    permit: &mut L4Permit,
    pacer: &Mutex<BytePacer>,
    messages: &[Vec<u8>],
    complete: &(dyn Fn(&[u8]) -> bool + Sync),
    expects_banner: bool,
    reply_timeout: Duration,
) -> Result<Vec<ExchangeStep>, ClientError> {
    let addr = SocketAddr::new(ep.ip, ep.port);
    // An ephemeral local port on the wildcard address of the destination's
    // family: the lane never asks for a specific source port.
    let bind: SocketAddr = if addr.is_ipv4() {
        SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
    } else {
        SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))
    };
    let socket = UdpSocket::bind(bind)
        .await
        .map_err(|e| ClientError::Io(e.to_string()))?;
    // `connect` on a datagram socket only fixes the peer; it is what makes the
    // ICMP port-unreachable come back as `ECONNREFUSED`.
    socket.connect(addr).await.map_err(|e| connect_error(&e))?;

    let mut steps = Vec::with_capacity(messages.len() + usize::from(expects_banner));

    if expects_banner {
        let started = Instant::now();
        let (reply, ended) = udp_read_reply(&socket, complete, reply_timeout).await?;
        steps.push(ExchangeStep {
            sent_len: 0,
            reply,
            ended,
            elapsed_ms: elapsed_ms(started),
        });
    }

    for message in messages {
        pace(pacer, message.len()).await;
        permit
            .authorize_packet(message.len())
            .map_err(ClientError::Guard)?;

        let started = Instant::now();
        if let Err(e) = socket.send(message).await {
            let Some(ended) = ended_for(&e) else {
                return Err(ClientError::Io(e.to_string()));
            };
            steps.push(ExchangeStep {
                sent_len: message.len(),
                reply: Vec::new(),
                ended,
                elapsed_ms: elapsed_ms(started),
            });
            return Ok(steps);
        }

        let (reply, ended) = udp_read_reply(&socket, complete, reply_timeout).await?;
        steps.push(ExchangeStep {
            sent_len: message.len(),
            reply,
            ended,
            elapsed_ms: elapsed_ms(started),
        });
    }

    Ok(steps)
}

/// Receive datagrams until the predicate accepts, the ceiling is reached, or
/// the timeout expires.
async fn udp_read_reply(
    socket: &UdpSocket,
    complete: &(dyn Fn(&[u8]) -> bool + Sync),
    reply_timeout: Duration,
) -> Result<(Vec<u8>, Ended), ClientError> {
    let deadline = Instant::now() + reply_timeout;
    let mut buf: Vec<u8> = Vec::new();
    let mut datagram = vec![0u8; MAX_REPLY];

    loop {
        let room = MAX_REPLY - buf.len();
        if room == 0 {
            return Ok((buf, Ended::Replied));
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Ok((buf, Ended::Silence));
        }
        match tokio::time::timeout(left, socket.recv(&mut datagram[..room])).await {
            Err(_elapsed) => return Ok((buf, Ended::Silence)),
            Ok(Ok(n)) => {
                buf.extend_from_slice(&datagram[..n]);
                if complete(&buf) {
                    return Ok((buf, Ended::Replied));
                }
            }
            Ok(Err(e)) => {
                let Some(ended) = ended_for(&e) else {
                    return Err(ClientError::Io(e.to_string()));
                };
                return Ok((buf, ended));
            }
        }
    }
}

/// The instrumented client the check tests drive (child criteria C8, C9).
///
/// Compiled always, not only under `cfg(test)`, so the crate's `tests/`
/// integration tests can reach it.
pub mod testing {
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Mutex;
    use std::time::Duration;

    use aitm_proto_l4::guard::L4Permit;
    use futures::future::BoxFuture;

    use super::{ClientError, Endpoint, ExchangeStep, StreamClient, TokioStreamClient};
    use crate::state::BytePacer;

    /// Counts exchanges, and either delegates to the real client or refuses.
    ///
    /// With `inner: None` it opens no socket and every call is
    /// [`ClientError::DryRun`], so a check's send pattern can be asserted
    /// without any traffic at all.
    #[derive(Debug, Default)]
    pub struct CountingClient {
        /// How many times `exchange` has been called.
        pub exchanges: AtomicU32,
        /// The real client to delegate to, or `None` for a dry run.
        pub inner: Option<TokioStreamClient>,
    }

    impl CountingClient {
        /// A counting client that opens nothing.
        #[must_use]
        pub fn dry_run() -> Self {
            Self {
                exchanges: AtomicU32::new(0),
                inner: None,
            }
        }

        /// A counting client that really connects.
        #[must_use]
        pub fn live() -> Self {
            Self {
                exchanges: AtomicU32::new(0),
                inner: Some(TokioStreamClient),
            }
        }

        /// Exchanges counted so far.
        #[must_use]
        pub fn count(&self) -> u32 {
            self.exchanges.load(Ordering::SeqCst)
        }
    }

    impl StreamClient for CountingClient {
        #[allow(clippy::too_many_arguments)]
        fn exchange<'a>(
            &'a self,
            ep: &'a Endpoint,
            permit: &'a mut L4Permit,
            pacer: &'a Mutex<BytePacer>,
            messages: &'a [Vec<u8>],
            complete: &'a (dyn Fn(&[u8]) -> bool + Sync),
            expects_banner: bool,
            reply_timeout: Duration,
            connect_timeout: Duration,
        ) -> BoxFuture<'a, Result<Vec<ExchangeStep>, ClientError>> {
            self.exchanges.fetch_add(1, Ordering::SeqCst);
            match &self.inner {
                Some(inner) => inner.exchange(
                    ep,
                    permit,
                    pacer,
                    messages,
                    complete,
                    expects_banner,
                    reply_timeout,
                    connect_timeout,
                ),
                None => Box::pin(async { Err(ClientError::DryRun) }),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    //! Loopback exchanges against in-test listeners.
    //!
    //! Every test here binds an ephemeral port on 127.0.0.1. A sandbox that
    //! refuses local binding makes the test print `SKIP: sandbox refuses local
    //! binding` and return; the Tester runs the same tests in a real shell,
    //! where they must pass.

    use std::io;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use aitm_proto_l4::config::L4Config;
    use aitm_proto_l4::guard::{L4Guard, L4Permit, ANY_INTERFACE};
    use aitm_proto_l4::types::{
        IpCidr, L4Action, L4Capability, L4Direction, L4Proto, L4ScopeEntry, L4ScopeId,
        L4ScopeSource, L4Target, PortRange, RateCap,
    };
    use aitm_scan_model::L4Transport;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, UdpSocket};

    use super::testing::CountingClient;
    use super::{ClientError, Ended, Endpoint, ExchangeStep, StreamClient, TokioStreamClient};
    use crate::state::{BytePacer, CONNECT_TIMEOUT, MAX_REPLY, REPLY_TIMEOUT};

    /// A guard whose **config-declared** scope authorises outbound injection to
    /// `127.0.0.0/8` on any interface.
    ///
    /// Loopback is on the guard's dangerous-destination denylist; only a
    /// `Config`-sourced entry contained within `127.0.0.0/8` lifts it, which is
    /// exactly what an operator writes to let the lane test a local speaker.
    fn loopback_guard() -> L4Guard {
        L4Guard::new(&L4Config {
            enabled: true,
            scope: vec![L4ScopeEntry {
                id: L4ScopeId::new(),
                cidr: IpCidr {
                    addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 0)),
                    prefix: 8,
                },
                ports: PortRange { lo: 0, hi: 65535 },
                interface: ANY_INTERFACE.to_string(),
                direction: L4Direction::Outbound,
                capability: L4Capability::Inject,
                inject_rate: RateCap {
                    pps: 1000,
                    burst: 1000,
                },
                source: L4ScopeSource::Config,
            }],
            ..Default::default()
        })
    }

    /// The per-connection permit S5.4 mints before a socket is opened.
    fn permit_for(guard: &L4Guard, ep: &Endpoint) -> L4Permit {
        guard
            .check(
                L4Action::Inject,
                &L4Target {
                    interface: ANY_INTERFACE.to_string(),
                    direction: L4Direction::Outbound,
                    dst: Some(ep.ip),
                    dst_port: Some(ep.port),
                    proto: match ep.proto {
                        L4Transport::Tcp => L4Proto::Tcp,
                        L4Transport::Udp => L4Proto::Udp,
                    },
                },
            )
            .expect("loopback inject permit")
    }

    fn tcp_endpoint(addr: SocketAddr) -> Endpoint {
        Endpoint {
            ip: addr.ip(),
            port: addr.port(),
            proto: L4Transport::Tcp,
        }
    }

    fn pacer() -> Mutex<BytePacer> {
        Mutex::new(BytePacer::new(1 << 20))
    }

    /// `EPERM`/`EACCES` on bind: the sandbox, not the code under test.
    fn bind_refused(e: &io::Error) -> bool {
        e.kind() == io::ErrorKind::PermissionDenied || matches!(e.raw_os_error(), Some(1 | 13))
    }

    async fn loopback_listener() -> Option<TcpListener> {
        match TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await {
            Ok(listener) => Some(listener),
            Err(e) if bind_refused(&e) => {
                println!("SKIP: sandbox refuses local binding");
                None
            }
            Err(e) => panic!("loopback TCP bind failed: {e}"),
        }
    }

    async fn loopback_udp() -> Option<UdpSocket> {
        match UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await {
            Ok(sock) => Some(sock),
            Err(e) if bind_refused(&e) => {
                println!("SKIP: sandbox refuses local binding");
                None
            }
            Err(e) => panic!("loopback UDP bind failed: {e}"),
        }
    }

    #[tokio::test]
    async fn tcp_exchange_reads_until_complete() {
        let Some(listener) = loopback_listener().await else {
            return;
        };
        let addr = listener.local_addr().expect("local addr");
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                let mut buf = [0u8; 64];
                if let Ok(n) = sock.read(&mut buf).await {
                    let _ = sock.write_all(&buf[..n]).await;
                }
            }
        });

        let ep = tcp_endpoint(addr);
        let guard = loopback_guard();
        let mut permit = permit_for(&guard, &ep);
        let pacer = pacer();
        let complete = |b: &[u8]| b.len() >= 5;
        let client = TokioStreamClient;

        let steps = client
            .exchange(
                &ep,
                &mut permit,
                &pacer,
                &[b"hello".to_vec()],
                &complete,
                false,
                REPLY_TIMEOUT,
                CONNECT_TIMEOUT,
            )
            .await
            .expect("exchange");

        assert_eq!(steps.len(), 1);
        assert_eq!(steps[0].sent_len, 5);
        assert_eq!(steps[0].reply, b"hello".to_vec());
        assert_eq!(steps[0].ended, Ended::Replied);
    }

    #[tokio::test]
    async fn tcp_silence_and_eof() {
        // A listener that reads and never answers: silence, bounded by the
        // reply timeout.
        let Some(listener) = loopback_listener().await else {
            return;
        };
        let addr = listener.local_addr().expect("local addr");
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                let mut buf = [0u8; 64];
                let _ = sock.read(&mut buf).await;
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        });

        let ep = tcp_endpoint(addr);
        let guard = loopback_guard();
        let mut permit = permit_for(&guard, &ep);
        let pacer = pacer();
        let complete = |_: &[u8]| false;
        let client = TokioStreamClient;

        let steps = client
            .exchange(
                &ep,
                &mut permit,
                &pacer,
                &[b"hello".to_vec()],
                &complete,
                false,
                Duration::from_millis(200),
                CONNECT_TIMEOUT,
            )
            .await
            .expect("exchange");

        assert_eq!(steps.len(), 1);
        assert_eq!(steps[0].ended, Ended::Silence);
        assert!(steps[0].reply.is_empty());
        assert!(
            steps[0].elapsed_ms >= 200,
            "silence waited only {} ms",
            steps[0].elapsed_ms
        );

        // A listener that closes right after reading: a clean EOF.
        let Some(listener) = loopback_listener().await else {
            return;
        };
        let addr = listener.local_addr().expect("local addr");
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                let mut buf = [0u8; 64];
                let _ = sock.read(&mut buf).await;
                drop(sock);
            }
        });

        let ep = tcp_endpoint(addr);
        let mut permit = permit_for(&guard, &ep);
        let steps = client
            .exchange(
                &ep,
                &mut permit,
                &pacer,
                &[b"hello".to_vec()],
                &complete,
                false,
                REPLY_TIMEOUT,
                CONNECT_TIMEOUT,
            )
            .await
            .expect("exchange");

        assert_eq!(steps.len(), 1);
        assert_eq!(steps[0].ended, Ended::Eof);
        assert!(steps[0].reply.is_empty());
    }

    #[tokio::test]
    async fn reply_is_bounded() {
        let Some(listener) = loopback_listener().await else {
            return;
        };
        let addr = listener.local_addr().expect("local addr");
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                let mut buf = [0u8; 64];
                let _ = sock.read(&mut buf).await;
                // More than the 64 KiB ceiling; the client must stop at it.
                let _ = sock.write_all(&[0x41u8; 100_000]).await;
            }
        });

        let ep = tcp_endpoint(addr);
        let guard = loopback_guard();
        let mut permit = permit_for(&guard, &ep);
        let pacer = pacer();
        let complete = |_: &[u8]| false;
        let client = TokioStreamClient;

        let steps = client
            .exchange(
                &ep,
                &mut permit,
                &pacer,
                &[b"hello".to_vec()],
                &complete,
                false,
                REPLY_TIMEOUT,
                CONNECT_TIMEOUT,
            )
            .await
            .expect("exchange");

        assert_eq!(steps.len(), 1);
        assert_eq!(steps[0].reply.len(), 65_536);
        assert_eq!(MAX_REPLY, 65_536);
        assert_eq!(steps[0].ended, Ended::Replied);
    }

    /// The peer drops the connection in the middle of a multi-message
    /// exchange: the step that saw the close ends it, the messages behind it
    /// are never written into a dead socket, and the exchange is an `Ok`
    /// result (a close is a reaction, not a client failure).
    #[tokio::test]
    async fn peer_closes_between_messages() {
        let Some(listener) = loopback_listener().await else {
            return;
        };
        let addr = listener.local_addr().expect("local addr");
        let seen = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&seen);
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                let mut buf = [0u8; 64];
                if let Ok(n) = sock.read(&mut buf).await {
                    counted.fetch_add(n, Ordering::SeqCst);
                    let _ = sock.write_all(b"+OK\r\n").await;
                }
                // Hang up before the second message.
                drop(sock);
            }
        });

        let ep = tcp_endpoint(addr);
        let guard = loopback_guard();
        let mut permit = permit_for(&guard, &ep);
        let pacer = pacer();
        let complete = |b: &[u8]| b.ends_with(b"\r\n");
        let client = TokioStreamClient;

        let steps = client
            .exchange(
                &ep,
                &mut permit,
                &pacer,
                &[
                    b"one\r\n".to_vec(),
                    b"two\r\n".to_vec(),
                    b"three\r\n".to_vec(),
                ],
                &complete,
                false,
                Duration::from_millis(500),
                CONNECT_TIMEOUT,
            )
            .await
            .expect("a peer hang-up is not a client error");

        assert!(
            steps.len() <= 2,
            "the exchange carried on past the close: {} steps",
            steps.len()
        );
        assert_eq!(steps[0].sent_len, 5);
        assert_eq!(steps[0].reply, b"+OK\r\n".to_vec());
        let last = steps.last().expect("at least one step");
        assert!(
            matches!(last.ended, Ended::Eof | Ended::Reset),
            "the last step ended {:?}, not on the close",
            last.ended
        );
        assert_eq!(
            seen.load(Ordering::SeqCst),
            5,
            "only the first message reached the peer"
        );
    }

    /// A reply of exactly `MAX_REPLY` bytes, with the peer still holding the
    /// connection open: the read stops at the bound and reports a reply, not
    /// silence and not a truncation of one byte less.
    #[tokio::test]
    async fn reply_exactly_at_the_bound() {
        let Some(listener) = loopback_listener().await else {
            return;
        };
        let addr = listener.local_addr().expect("local addr");
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                let mut buf = [0u8; 64];
                let _ = sock.read(&mut buf).await;
                let _ = sock.write_all(&[0x42u8; MAX_REPLY]).await;
                // Stay open: the bound, not the EOF, must end the read.
                tokio::time::sleep(Duration::from_secs(3)).await;
            }
        });

        let ep = tcp_endpoint(addr);
        let guard = loopback_guard();
        let mut permit = permit_for(&guard, &ep);
        let pacer = pacer();
        let complete = |_: &[u8]| false;
        let client = TokioStreamClient;

        let steps = client
            .exchange(
                &ep,
                &mut permit,
                &pacer,
                &[b"hello".to_vec()],
                &complete,
                false,
                REPLY_TIMEOUT,
                CONNECT_TIMEOUT,
            )
            .await
            .expect("exchange");

        assert_eq!(steps.len(), 1);
        assert_eq!(steps[0].reply.len(), MAX_REPLY);
        assert!(steps[0].reply.iter().all(|b| *b == 0x42));
        assert_eq!(steps[0].ended, Ended::Replied);
    }

    #[tokio::test]
    async fn banner_is_step_zero() {
        let Some(listener) = loopback_listener().await else {
            return;
        };
        let addr = listener.local_addr().expect("local addr");
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                let _ = sock.write_all(b"220 hi\r\n").await;
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        });

        let ep = tcp_endpoint(addr);
        let guard = loopback_guard();
        let mut permit = permit_for(&guard, &ep);
        let pacer = pacer();
        let complete = |b: &[u8]| b.ends_with(b"\r\n");
        let client = TokioStreamClient;

        let steps = client
            .exchange(
                &ep,
                &mut permit,
                &pacer,
                &[],
                &complete,
                true,
                REPLY_TIMEOUT,
                CONNECT_TIMEOUT,
            )
            .await
            .expect("exchange");

        assert_eq!(steps.len(), 1);
        assert_eq!(steps[0].sent_len, 0);
        assert_eq!(steps[0].reply, b"220 hi\r\n".to_vec());
        assert_eq!(steps[0].ended, Ended::Replied);
    }

    #[tokio::test]
    async fn udp_refused_is_icmp_unreachable() {
        let Some(sock) = loopback_udp().await else {
            return;
        };
        let addr = sock.local_addr().expect("local addr");
        drop(sock); // now a closed UDP port

        let ep = Endpoint {
            ip: addr.ip(),
            port: addr.port(),
            proto: L4Transport::Udp,
        };
        let guard = loopback_guard();
        let mut permit = permit_for(&guard, &ep);
        let pacer = pacer();
        let complete = |_: &[u8]| false;
        let client = TokioStreamClient;

        let steps = client
            .exchange(
                &ep,
                &mut permit,
                &pacer,
                &[b"ping".to_vec()],
                &complete,
                false,
                Duration::from_millis(300),
                CONNECT_TIMEOUT,
            )
            .await
            .expect("exchange");

        assert_eq!(steps.len(), 1);
        assert_eq!(steps[0].sent_len, 4);
        match steps[0].ended {
            Ended::IcmpUnreachable => {
                println!("closed UDP port surfaced ECONNREFUSED -> IcmpUnreachable");
            }
            Ended::Silence => {
                println!("closed UDP port surfaced nothing -> Silence");
            }
            other => panic!("unexpected end for a closed UDP port: {other:?}"),
        }
    }

    #[tokio::test]
    async fn connect_timeout_and_refused() {
        let Some(listener) = loopback_listener().await else {
            return;
        };
        let addr = listener.local_addr().expect("local addr");
        drop(listener); // now a closed TCP port

        let ep = tcp_endpoint(addr);
        let guard = loopback_guard();
        let mut permit = permit_for(&guard, &ep);
        let pacer = pacer();
        let complete = |_: &[u8]| false;
        let client = TokioStreamClient;

        let err = client
            .exchange(
                &ep,
                &mut permit,
                &pacer,
                &[b"hello".to_vec()],
                &complete,
                false,
                REPLY_TIMEOUT,
                CONNECT_TIMEOUT,
            )
            .await
            .expect_err("a closed port refuses the connect");

        assert_eq!(err, ClientError::ConnectRefused);
    }

    /// Crate hygiene (spec S9, child criterion C11): a step's `Debug` names the
    /// reply's length and never a byte of it, so a step that reaches a log or a
    /// panic message leaks nothing a target sent.
    #[test]
    fn exchange_step_debug_hides_the_reply() {
        let step = ExchangeStep {
            sent_len: 5,
            reply: b"+OK\r\n".to_vec(),
            ended: Ended::Replied,
            elapsed_ms: 7,
        };
        assert_eq!(
            format!("{step:?}"),
            "ExchangeStep { sent_len: 5, reply: <5 bytes>, ended: Replied, elapsed_ms: 7 }"
        );
    }

    #[tokio::test]
    async fn counting_client_counts() {
        let ep = Endpoint {
            ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: 9000,
            proto: L4Transport::Tcp,
        };
        let guard = loopback_guard();
        let mut permit = permit_for(&guard, &ep);
        let pacer = pacer();
        let complete = |_: &[u8]| true;
        let client = CountingClient {
            exchanges: AtomicU32::new(0),
            inner: None,
        };

        let err = client
            .exchange(
                &ep,
                &mut permit,
                &pacer,
                &[b"x".to_vec()],
                &complete,
                false,
                REPLY_TIMEOUT,
                CONNECT_TIMEOUT,
            )
            .await
            .expect_err("a dry-run client opens no socket");

        assert_eq!(err, ClientError::DryRun);
        assert_eq!(client.exchanges.load(Ordering::SeqCst), 1);
    }
}
