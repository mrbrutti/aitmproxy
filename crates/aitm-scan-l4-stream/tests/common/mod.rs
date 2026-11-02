//! In-process speakers, a job double and a tracing capture for the lane's
//! inner-loop tests (plan Task 21; spec C7, C11).
//!
//! The speakers mimic the triggers of T10's seeded services (T10 spec D5) over
//! loopback inside the test process: a TLV frame whose declared length is over
//! 4096, or over what arrived after 200 ms of idle, and a RESP `$N` over 1 MiB.
//! They are the inner loop and never acceptance evidence: only Task 23's real
//! run against T10's own speakers satisfies T6-1..T6-5.
//!
//! Every constructor binds an ephemeral loopback port through [`bind_or_skip`],
//! which prints `SKIP: sandbox refuses local binding` and returns `None` when
//! the sandbox refuses to bind, so each test returns early instead of failing
//! for a reason that is not the lane's.
//!
//! Nothing here holds a credential or a secret: the `log` is the speaker's own
//! record of what the lane sent it, inside one test process.

#![allow(
    dead_code,
    reason = "shared across tests/campaign.rs and tests/gates.rs; each binary \
              uses a subset"
)]

use std::fmt::{self, Write as _};
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::{Duration, Instant};

use aitm_core::{
    BrowserDriver, FlowStore, HttpFlow, HttpRequest, MemFlowStore, ProxyClient, ScopeRateGuard,
    StdGuard,
};
use aitm_proto_l4::config::L4Config;
use aitm_proto_l4::guard::{L4Guard, ANY_INTERFACE};
use aitm_proto_l4::types::{
    IpCidr, L4Capability, L4Direction, L4ScopeEntry, L4ScopeId, L4ScopeSource, PortRange, RateCap,
};
use aitm_scan_model::{JobCtx, ScanProfile, SessionMaterial};
use futures::future::BoxFuture;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot};
use tracing::field::{Field, Visit};
use tracing::{span, Event, Metadata, Subscriber};

/// What a test prints when the sandbox refuses to bind a loopback port.
pub const SKIP_LINE: &str = "SKIP: sandbox refuses local binding";

/// Idle time after which a TLV speaker decides the declared length lies
/// (T10 spec D5: "or len > received after 200 ms idle").
pub const IDLE: Duration = Duration::from_millis(200);

/// How long an unframed speaker waits before it answers, and how long it keeps
/// draining one message.
///
/// Not decoration: `oracle::latency_outlier` compares a case against the median
/// of the lane's latency window, and a loopback service that answers in under a
/// millisecond gives a median of `0`, against which *any* 1 ms case is "more
/// than five times the median" and every speaker would look like a latency
/// finding. A floor of 10 ms puts the outlier threshold at roughly 100 ms,
/// which ordinary loopback jitter does not reach, and keeps
/// [`tlv_slow_case`]'s delay (1 s in the test, under the lane's 2 s reply
/// timeout) an unambiguous outlier.
pub const REPLY_FLOOR: Duration = Duration::from_millis(10);

/// What a *framed* TLV speaker waits before every answer.
///
/// The same rule as [`REPLY_FLOOR`], one step further: a framed speaker decides
/// some cases immediately (a declared length over 4096) and some only after
/// [`IDLE`], so without a floor its own replies would differ by two orders of
/// magnitude and the fast majority would make the slow minority an "outlier".
/// Sleeping [`IDLE`] before every answer puts every case within a factor of two
/// of every other, well inside the oracle's five-times rule, so a P-mode
/// speaker reads as clean (spec C7, A7).
pub const FRAMED_REPLY: Duration = IDLE;

/// A TLV declared length over this is a trigger on its own (T10 spec D5).
pub const TLV_MAX_DECLARED: usize = 4096;

/// A RESP bulk length over this is a trigger (T10 spec D5).
pub const RESP_MAX_BULK: u64 = 1 << 20;

/// The TLV P-mode reply: a three-byte `ERR` body behind its length.
pub const TLV_PROTOCOL_ERROR: &[u8] = &[0x00, 0x03, 0x45, 0x52, 0x52];

/// The RESP P-mode reply, as Redis words it.
pub const RESP_PROTOCOL_ERROR: &[u8] = b"-ERR Protocol error: invalid bulk length\r\n";

/// The RESP answer to anything the speaker accepts, and to `PING\r\n`, which is
/// the grammar's liveness probe (`Expect::Prefix("+PONG")`).
pub const RESP_PONG: &[u8] = b"+PONG\r\n";

// ---------------------------------------------------------------------------
// Binding
// ---------------------------------------------------------------------------

/// `EPERM`/`EACCES` on bind: the sandbox, not the code under test.
fn bind_refused(e: &io::Error) -> bool {
    e.kind() == io::ErrorKind::PermissionDenied || matches!(e.raw_os_error(), Some(1 | 13))
}

/// An ephemeral loopback listener, or `None` when the sandbox refuses to bind.
///
/// Prints [`SKIP_LINE`] on refusal; every test returns early on `None`.
///
/// # Panics
///
/// On any other bind error, which is a real failure and must not be silent.
pub async fn bind_or_skip() -> Option<TcpListener> {
    bind_on(0).await
}

/// [`bind_or_skip`] for one named port, which is how a crashed speaker comes
/// back on the port it went down on.
async fn bind_on(port: u16) -> Option<TcpListener> {
    match TcpListener::bind((Ipv4Addr::LOCALHOST, port)).await {
        Ok(listener) => Some(listener),
        Err(e) if bind_refused(&e) => {
            println!("{SKIP_LINE}");
            None
        }
        Err(e) => panic!("loopback TCP bind on port {port} failed: {e}"),
    }
}

/// Re-bind `port` after a crash window, retrying while the kernel still holds
/// it. `None` when it never comes back, which ends the speaker.
async fn rebind(port: u16) -> Option<TcpListener> {
    let started = Instant::now();
    loop {
        match TcpListener::bind((Ipv4Addr::LOCALHOST, port)).await {
            Ok(listener) => return Some(listener),
            Err(e) if bind_refused(&e) => {
                println!("{SKIP_LINE}");
                return None;
            }
            Err(_) if started.elapsed() < Duration::from_secs(10) => {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Err(_) => return None,
        }
    }
}

// ---------------------------------------------------------------------------
// The speakers
// ---------------------------------------------------------------------------

/// One in-process service the lane fuzzes.
///
/// The counters are what a test asserts on: how many connections were accepted,
/// the high-water mark of concurrent ones (the lane's four-connection ceiling),
/// and every message the speaker read.
pub struct Speaker {
    /// Where the lane reaches it.
    pub addr: SocketAddr,
    /// Connections accepted since it started.
    pub accepts: Arc<AtomicU32>,
    /// The most connections it ever held at once.
    pub max_concurrent: Arc<AtomicU32>,
    /// Every message it read, in arrival order.
    pub log: Arc<Mutex<Vec<Vec<u8>>>>,
    /// How often its trigger fired.
    triggers: Arc<AtomicU32>,
    /// The exact case [`tlv_slow_case`] holds back, settable after discovery.
    slow_trigger: Arc<Mutex<Vec<u8>>>,
}

impl fmt::Debug for Speaker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Speaker")
            .field("addr", &self.addr)
            .field("accepts", &self.accepts())
            .field("max_concurrent", &self.max_concurrent())
            .field("messages", &lock(&self.log).len())
            .field("triggers", &self.triggered_count())
            .finish()
    }
}

impl Speaker {
    /// Connections accepted so far.
    #[must_use]
    pub fn accepts(&self) -> u32 {
        self.accepts.load(Ordering::SeqCst)
    }

    /// The high-water mark of concurrent connections.
    #[must_use]
    pub fn max_concurrent(&self) -> u32 {
        self.max_concurrent.load(Ordering::SeqCst)
    }

    /// A copy of everything it read.
    #[must_use]
    pub fn messages(&self) -> Vec<Vec<u8>> {
        lock(&self.log).clone()
    }

    /// How often its trigger fired.
    #[must_use]
    pub fn triggered_count(&self) -> u32 {
        self.triggers.load(Ordering::SeqCst)
    }

    /// Whether its trigger ever fired, which is how a test proves the fault
    /// path was exercised at all.
    #[must_use]
    pub fn triggered(&self) -> bool {
        self.triggered_count() > 0
    }

    /// The exact case a [`tlv_slow_case`] speaker answers late.
    pub fn set_slow_case(&self, bytes: Vec<u8>) {
        *lock(&self.slow_trigger) = bytes;
    }

    fn with_slow_trigger(mut self, trigger: Arc<Mutex<Vec<u8>>>) -> Speaker {
        self.slow_trigger = trigger;
        self
    }
}

/// What a speaker does when its trigger fires.
///
/// Named for the behaviour, not the mode: T10 calls the two builds of each
/// seeded service V (vulnerable) and P (patched), and `TlvPMode` is this
/// harness mimicking the P build.
#[derive(Debug, Clone)]
enum Behaviour {
    /// Close the connection, drop the listener, come back on the same port
    /// after the window. Connects are refused meanwhile (T10's V mode).
    TlvCrash { window: Duration },
    /// Close the connection without replying and keep accepting.
    TlvCloseSilent,
    /// Answer [`TLV_PROTOCOL_ERROR`], close, stay up (T10's P mode).
    TlvPMode,
    /// Answer [`RESP_PROTOCOL_ERROR`] to a bulk length over 1 MiB, close,
    /// stay up (T10's P mode for RESP).
    RespPMode,
    /// Echo everything, delaying one exact case.
    TlvSlowCase {
        delay: Duration,
        trigger: Arc<Mutex<Vec<u8>>>,
    },
    /// Read and never answer.
    Silent,
    /// Close on the trigger and never come back.
    DeadAfterTrigger,
}

/// A TLV echo speaker that goes down for `window` on a bad length.
pub async fn tlv_crash(window: Duration) -> Option<Speaker> {
    spawn(Behaviour::TlvCrash { window }).await
}

/// A TLV echo speaker that closes on a bad length without replying and keeps
/// accepting.
pub async fn tlv_close_silent() -> Option<Speaker> {
    spawn(Behaviour::TlvCloseSilent).await
}

/// A TLV echo speaker in P mode: its own protocol error, then a close.
pub async fn tlv_p_mode() -> Option<Speaker> {
    spawn(Behaviour::TlvPMode).await
}

/// A RESP speaker in P mode: `-ERR Protocol error: invalid bulk length`, then a
/// close, on a `$N` over 1 MiB.
pub async fn resp_p_mode() -> Option<Speaker> {
    spawn(Behaviour::RespPMode).await
}

/// A TLV echo speaker that answers one exact case `delay` late.
///
/// The case's bytes come out of the deterministic schedule, which is keyed by
/// the point id and so by the speaker's own port: pass an empty `trigger` here
/// and set it with [`Speaker::set_slow_case`] once discovery has named the
/// case. Discovery opens no socket, so nothing is sent in between.
pub async fn tlv_slow_case(delay: Duration, trigger: Vec<u8>) -> Option<Speaker> {
    let trigger = Arc::new(Mutex::new(trigger));
    spawn(Behaviour::TlvSlowCase {
        delay,
        trigger: Arc::clone(&trigger),
    })
    .await
    .map(|speaker| speaker.with_slow_trigger(trigger))
}

/// A speaker that reads and never answers, leaving the connection open.
pub async fn silent() -> Option<Speaker> {
    spawn(Behaviour::Silent).await
}

/// A TLV speaker that closes on a bad length and never comes back.
pub async fn dead_after_trigger() -> Option<Speaker> {
    spawn(Behaviour::DeadAfterTrigger).await
}

/// The counters every connection task shares with its [`Speaker`].
#[derive(Clone)]
pub(crate) struct Counters {
    accepts: Arc<AtomicU32>,
    live: Arc<AtomicU32>,
    max_concurrent: Arc<AtomicU32>,
    log: Arc<Mutex<Vec<Vec<u8>>>>,
    triggers: Arc<AtomicU32>,
}

impl Counters {
    /// Fresh counters, which a harness self-test hands to a reader directly.
    #[must_use]
    pub(crate) fn new() -> Counters {
        Counters {
            accepts: Arc::new(AtomicU32::new(0)),
            live: Arc::new(AtomicU32::new(0)),
            max_concurrent: Arc::new(AtomicU32::new(0)),
            log: Arc::new(Mutex::new(Vec::new())),
            triggers: Arc::new(AtomicU32::new(0)),
        }
    }

    /// Count one accepted connection, and hold it counted until the guard
    /// drops.
    fn accepted(&self) -> Live {
        self.accepts.fetch_add(1, Ordering::SeqCst);
        let live = self.live.fetch_add(1, Ordering::SeqCst) + 1;
        self.max_concurrent.fetch_max(live, Ordering::SeqCst);
        Live {
            live: Arc::clone(&self.live),
        }
    }

    /// Every message the speaker read, in arrival order.
    #[must_use]
    pub(crate) fn messages(&self) -> Vec<Vec<u8>> {
        lock(&self.log).clone()
    }

    fn record(&self, message: &[u8]) {
        lock(&self.log).push(message.to_vec());
    }

    fn triggered(&self) {
        self.triggers.fetch_add(1, Ordering::SeqCst);
    }
}

/// Keeps one connection counted as live for as long as it is held.
struct Live {
    live: Arc<AtomicU32>,
}

impl Drop for Live {
    fn drop(&mut self) {
        self.live.fetch_sub(1, Ordering::SeqCst);
    }
}

/// What a connection task tells the accept loop.
enum Signal {
    /// The trigger fired: take the listener down, then acknowledge.
    ///
    /// The acknowledgement is what makes "the service went down" observable in
    /// the right order: the connection is closed only once the listener is
    /// gone, so the lane can never see the close, reconnect, and find the
    /// speaker still accepting.
    Down(oneshot::Sender<()>),
}

/// Bind, spawn the accept loop, and hand back the speaker.
async fn spawn(mode: Behaviour) -> Option<Speaker> {
    let listener = bind_or_skip().await?;
    let addr = match listener.local_addr() {
        Ok(addr) => addr,
        Err(e) => panic!("a bound loopback listener has a local address: {e}"),
    };
    let counters = Counters::new();
    let speaker = Speaker {
        addr,
        accepts: Arc::clone(&counters.accepts),
        max_concurrent: Arc::clone(&counters.max_concurrent),
        log: Arc::clone(&counters.log),
        triggers: Arc::clone(&counters.triggers),
        slow_trigger: Arc::new(Mutex::new(Vec::new())),
    };
    tokio::spawn(accept_loop(listener, mode, counters, addr.port()));
    Some(speaker)
}

/// Accept connections, and take the listener down when a connection signals
/// that the trigger fired.
async fn accept_loop(listener: TcpListener, mode: Behaviour, counters: Counters, port: u16) {
    let (tx, mut rx) = mpsc::channel::<Signal>(16);
    let mut listener = listener;
    loop {
        // Serve until a connection says the service went down, and hand back
        // the acknowledgement it is waiting for.
        let acknowledge = loop {
            tokio::select! {
                biased;
                signal = rx.recv() => match signal {
                    Some(Signal::Down(ack)) => break ack,
                    // Every sender is gone: nothing can take the speaker down.
                    None => return,
                },
                accepted = listener.accept() => {
                    let Ok((stream, _peer)) = accepted else { return };
                    let live = counters.accepted();
                    tokio::spawn(serve(stream, mode.clone(), counters.clone(), tx.clone(), live));
                }
            }
        };
        drop(listener);
        let _ = acknowledge.send(());
        match &mode {
            Behaviour::TlvCrash { window } => {
                tokio::time::sleep(*window).await;
                let Some(fresh) = rebind(port).await else {
                    return;
                };
                listener = fresh;
            }
            // Every other trigger either keeps the listener or ends the
            // speaker for good.
            _ => return,
        }
    }
}

/// One connection, start to close.
async fn serve(
    stream: TcpStream,
    mode: Behaviour,
    counters: Counters,
    tx: mpsc::Sender<Signal>,
    live: Live,
) {
    let mut stream = stream;
    match mode {
        Behaviour::TlvCrash { .. } | Behaviour::DeadAfterTrigger => {
            if let TlvRead::Trigger = tlv_loop(&mut stream, &counters).await {
                counters.triggered();
                // Take the listener down *first*, then close: the lane must
                // find the port refusing connections the moment it reacts.
                let (ack, done) = oneshot::channel();
                if tx.send(Signal::Down(ack)).await.is_ok() {
                    let _ = done.await;
                }
                drop(stream);
            }
        }
        Behaviour::TlvCloseSilent => {
            if let TlvRead::Trigger = tlv_loop(&mut stream, &counters).await {
                counters.triggered();
            }
        }
        Behaviour::TlvPMode => {
            if let TlvRead::Trigger = tlv_loop(&mut stream, &counters).await {
                counters.triggered();
                tokio::time::sleep(FRAMED_REPLY).await;
                let _ = stream.write_all(TLV_PROTOCOL_ERROR).await;
                let _ = stream.flush().await;
            }
        }
        Behaviour::TlvSlowCase { delay, trigger } => {
            slow_case(&mut stream, &counters, delay, &trigger).await;
        }
        Behaviour::RespPMode => resp_p(&mut stream, &counters).await,
        Behaviour::Silent => {
            let mut sink = [0u8; 4096];
            let mut seen = Vec::new();
            while let Ok(read) = stream.read(&mut sink).await {
                if read == 0 {
                    break;
                }
                seen.extend_from_slice(&sink[..read]);
            }
            if !seen.is_empty() {
                counters.record(&seen);
            }
        }
    }
    drop(live);
}

/// Echo whole TLV frames until the trigger fires or the peer goes away.
async fn tlv_loop<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    counters: &Counters,
) -> TlvRead {
    loop {
        match tlv_read(stream, counters).await {
            TlvRead::Frame(frame) => {
                tokio::time::sleep(FRAMED_REPLY).await;
                if stream.write_all(&frame).await.is_err() || stream.flush().await.is_err() {
                    return TlvRead::Gone;
                }
            }
            other => return other,
        }
    }
}

/// What one read off a TLV connection produced.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum TlvRead {
    /// A whole frame: its declared body arrived.
    Frame(Vec<u8>),
    /// The declared length is over 4096, or over what arrived in 200 ms.
    Trigger,
    /// The peer closed, or the socket failed.
    Gone,
}

/// Read one TLV frame: two big-endian length bytes, then that many bytes.
pub(crate) async fn tlv_read<S: AsyncRead + Unpin>(stream: &mut S, counters: &Counters) -> TlvRead {
    let mut buf: Vec<u8> = Vec::new();
    while buf.len() < 2 {
        match read_more(stream, &mut buf, None).await {
            ReadMore::Read => {}
            ReadMore::Idle | ReadMore::Gone => {
                if !buf.is_empty() {
                    counters.record(&buf);
                }
                return TlvRead::Gone;
            }
        }
    }
    let declared = usize::from(u16::from_be_bytes([buf[0], buf[1]]));
    loop {
        if declared > TLV_MAX_DECLARED {
            counters.record(&buf);
            return TlvRead::Trigger;
        }
        if buf.len() - 2 >= declared {
            let frame = buf[..2 + declared].to_vec();
            counters.record(&frame);
            return TlvRead::Frame(frame);
        }
        match read_more(stream, &mut buf, Some(IDLE)).await {
            ReadMore::Read => {}
            // The declared length is over what arrived: the T10 trigger.
            ReadMore::Idle => {
                counters.record(&buf);
                return TlvRead::Trigger;
            }
            ReadMore::Gone => {
                counters.record(&buf);
                return TlvRead::Gone;
            }
        }
    }
}

/// Echo whatever arrives, holding back one exact case.
async fn slow_case<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    counters: &Counters,
    delay: Duration,
    trigger: &Mutex<Vec<u8>>,
) {
    loop {
        let Some(message) = read_message(stream).await else {
            return;
        };
        counters.record(&message);
        let wanted = lock(trigger).clone();
        if !wanted.is_empty() && message == wanted {
            counters.triggered();
            tokio::time::sleep(delay).await;
        } else {
            tokio::time::sleep(REPLY_FLOOR).await;
        }
        if stream.write_all(&message).await.is_err() || stream.flush().await.is_err() {
            return;
        }
    }
}

/// Answer RESP requests, refusing a bulk length over 1 MiB the way Redis does.
async fn resp_p<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S, counters: &Counters) {
    loop {
        let Some(message) = read_message(stream).await else {
            return;
        };
        counters.record(&message);
        tokio::time::sleep(REPLY_FLOOR).await;
        if oversize_bulk(&message) {
            counters.triggered();
            let _ = stream.write_all(RESP_PROTOCOL_ERROR).await;
            let _ = stream.flush().await;
            return;
        }
        if stream.write_all(RESP_PONG).await.is_err() || stream.flush().await.is_err() {
            return;
        }
    }
}

/// Whether any `$N` in the message declares more than 1 MiB.
#[must_use]
pub(crate) fn oversize_bulk(message: &[u8]) -> bool {
    let mut rest = message;
    while let Some(at) = rest.iter().position(|byte| *byte == b'$') {
        rest = &rest[at + 1..];
        let digits: Vec<u8> = rest
            .iter()
            .copied()
            .take_while(u8::is_ascii_digit)
            .collect();
        if digits.is_empty() {
            continue;
        }
        let text = String::from_utf8_lossy(&digits);
        if text.parse::<u64>().is_ok_and(|n| n > RESP_MAX_BULK) {
            return true;
        }
    }
    false
}

/// One message: whatever arrives, plus whatever follows within [`REPLY_FLOOR`].
///
/// The lane opens a fresh connection per case and writes it in one go, so one
/// drained read is one case.
pub(crate) async fn read_message<S: AsyncRead + Unpin>(stream: &mut S) -> Option<Vec<u8>> {
    let mut buf: Vec<u8> = Vec::new();
    match read_more(stream, &mut buf, None).await {
        ReadMore::Read => {}
        ReadMore::Idle | ReadMore::Gone => return None,
    }
    loop {
        match read_more(stream, &mut buf, Some(REPLY_FLOOR)).await {
            ReadMore::Read => {}
            ReadMore::Idle | ReadMore::Gone => return Some(buf),
        }
    }
}

/// How one read ended.
enum ReadMore {
    /// Bytes were appended to the buffer.
    Read,
    /// Nothing arrived within the idle window.
    Idle,
    /// The peer closed, or the socket failed.
    Gone,
}

/// Append one chunk to `buf`, waiting at most `idle` when one is given.
async fn read_more<S: AsyncRead + Unpin>(
    stream: &mut S,
    buf: &mut Vec<u8>,
    idle: Option<Duration>,
) -> ReadMore {
    let mut chunk = [0u8; 8192];
    let read = match idle {
        Some(window) => match tokio::time::timeout(window, stream.read(&mut chunk)).await {
            Ok(read) => read,
            Err(_elapsed) => return ReadMore::Idle,
        },
        None => stream.read(&mut chunk).await,
    };
    match read {
        Ok(0) | Err(_) => ReadMore::Gone,
        Ok(n) => {
            buf.extend_from_slice(&chunk[..n]);
            ReadMore::Read
        }
    }
}

// ---------------------------------------------------------------------------
// The guard
// ---------------------------------------------------------------------------

/// A guard whose one config-declared entry authorises outbound injection to
/// `127.0.0.0/8` on any interface, over the range `ports` covers.
///
/// This is what an operator writes to let the lane reach a local speaker
/// (spec C10): the lane's target interface is `"*"`, which no literal interface
/// entry matches.
#[must_use]
pub fn wildcard_guard(ports: &[u16]) -> Arc<L4Guard> {
    let lo = ports.iter().copied().min().unwrap_or(0);
    let hi = ports.iter().copied().max().unwrap_or(u16::MAX);
    Arc::new(L4Guard::new(&L4Config {
        enabled: true,
        scope: vec![L4ScopeEntry {
            id: L4ScopeId::new(),
            cidr: IpCidr {
                addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 0)),
                prefix: 8,
            },
            ports: PortRange { lo, hi },
            interface: ANY_INTERFACE.to_string(),
            direction: L4Direction::Outbound,
            capability: L4Capability::Inject,
            inject_rate: RateCap {
                pps: 10_000,
                burst: 10_000,
            },
            source: L4ScopeSource::Config,
        }],
        ..Default::default()
    }))
}

// ---------------------------------------------------------------------------
// The job double
// ---------------------------------------------------------------------------

/// A `ProxyClient` that performs no I/O; a job context needs one to exist.
struct NullClient;

impl ProxyClient for NullClient {
    fn send(&self, _req: HttpRequest) -> BoxFuture<'_, anyhow::Result<HttpFlow>> {
        Box::pin(async { Err(anyhow::anyhow!("no HTTP client in the L4 test context")) })
    }
}

/// A `JobCtx` with a configurable profile, marker, budget, deadline and
/// cancellation flag, counting every charge the lane makes.
pub struct TestJob {
    profile: ScanProfile,
    job_id: String,
    marker: String,
    budget: u32,
    charges: AtomicU32,
    cancelled: AtomicBool,
    deadline: Instant,
    client: Arc<dyn ProxyClient>,
    store: Arc<dyn FlowStore>,
    guard: Arc<dyn ScopeRateGuard>,
}

impl fmt::Debug for TestJob {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TestJob")
            .field("job_id", &self.job_id)
            .field("marker", &self.marker)
            .field("budget", &self.budget)
            .field("charges", &self.charges())
            .field("cancelled", &self.cancelled.load(Ordering::SeqCst))
            .finish()
    }
}

impl TestJob {
    /// A job running `profile`, with ten minutes and a budget of 10 000
    /// stimuli: enough that no inner-loop test stops on either.
    #[must_use]
    pub fn new(profile: ScanProfile) -> TestJob {
        TestJob {
            profile,
            job_id: "scan-21".to_string(),
            marker: "aitm21".to_string(),
            budget: 10_000,
            charges: AtomicU32::new(0),
            cancelled: AtomicBool::new(false),
            deadline: Instant::now() + Duration::from_secs(600),
            client: Arc::new(NullClient),
            store: Arc::new(MemFlowStore::new()),
            guard: Arc::new(StdGuard::default()),
        }
    }

    #[must_use]
    pub fn with_job_id(mut self, job_id: &str) -> TestJob {
        self.job_id = job_id.to_string();
        self
    }

    #[must_use]
    pub fn with_marker(mut self, marker: &str) -> TestJob {
        self.marker = marker.to_string();
        self
    }

    #[must_use]
    pub fn with_budget(mut self, budget: u32) -> TestJob {
        self.budget = budget;
        self
    }

    #[must_use]
    pub fn with_deadline(mut self, deadline: Instant) -> TestJob {
        self.deadline = deadline;
        self
    }

    /// Cancel the job, as the engine does when the operator stops a scan.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }

    /// Budget units charged so far.
    #[must_use]
    pub fn charges(&self) -> u32 {
        self.charges.load(Ordering::SeqCst)
    }
}

impl JobCtx for TestJob {
    fn job_id(&self) -> &str {
        &self.job_id
    }

    fn profile(&self) -> &ScanProfile {
        &self.profile
    }

    fn client(&self) -> Arc<dyn ProxyClient> {
        Arc::clone(&self.client)
    }

    fn store(&self) -> Arc<dyn FlowStore> {
        Arc::clone(&self.store)
    }

    fn guard(&self) -> Arc<dyn ScopeRateGuard> {
        Arc::clone(&self.guard)
    }

    fn browser(&self) -> Option<Arc<dyn BrowserDriver>> {
        None
    }

    fn session(&self) -> Option<Arc<SessionMaterial>> {
        None
    }

    fn charge(&self, units: u32) -> bool {
        let spent = self.charges.load(Ordering::SeqCst);
        if spent.saturating_add(units) > self.budget {
            return false;
        }
        self.charges.fetch_add(units, Ordering::SeqCst);
        true
    }

    fn budget_left(&self) -> u32 {
        self.budget.saturating_sub(self.charges())
    }

    fn deadline(&self) -> Instant {
        self.deadline
    }

    fn cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }

    fn marker(&self) -> String {
        self.marker.clone()
    }
}

// ---------------------------------------------------------------------------
// The tracing capture (C11)
// ---------------------------------------------------------------------------

/// Keeps a tracing capture's lines readable for as long as it is held, and
/// clears them when it drops.
struct Guard {
    sink: Arc<Mutex<Vec<String>>>,
}

impl Drop for Guard {
    fn drop(&mut self) {
        lock(&self.sink).clear();
    }
}

/// A held tracing capture: the process-wide serial lock and the shared sink,
/// bundled so a test takes both in one `capture_tracing().await`.
///
/// The sink is one process-wide buffer cleared on every call, so two tests
/// reading it at once would wipe each other's lines. Holding this is holding
/// the serial lock that keeps them in turn; its [`lines`](Self::lines) stay
/// readable for as long as it lives and are cleared when it drops.
pub struct TracingCapture {
    // Field order is load-bearing: fields drop in declaration order, so the
    // sink-clearing guard must drop BEFORE the serial lock is released, or the
    // next test could acquire the lock and start recording into a sink this
    // one then wipes.
    _guard: Guard,
    _serial: tokio::sync::MutexGuard<'static, ()>,
    /// The shared sink of recorded lines.
    pub lines: Arc<Mutex<Vec<String>>>,
}

/// Record every `tracing` event of the process, with all its fields.
///
/// A hand-rolled [`Subscriber`]: there is no `tracing-subscriber` dependency in
/// this workspace and the plan forbids adding one. It is installed as the
/// *global* default, not the thread-local one, because a multi-thread runtime
/// moves the campaign between workers at every await, and a thread-local
/// subscriber would miss most of a run. A process can only install one, so the
/// sink is shared and cleared on each call; a test that records nothing at all
/// should say so rather than pass vacuously.
///
/// The returned [`TracingCapture`] holds the process-wide serial lock, so a
/// test awaits it and never races another on the shared sink.
#[must_use]
pub async fn capture_tracing() -> TracingCapture {
    /// Held for as long as a test reads the captured tracing lines, so two
    /// tests in one binary take the shared sink in turn.
    static TRACING: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    static SINK: OnceLock<Arc<Mutex<Vec<String>>>> = OnceLock::new();

    let serial = TRACING.lock().await;
    let sink = SINK.get_or_init(|| {
        let sink = Arc::new(Mutex::new(Vec::new()));
        let subscriber = Capture {
            sink: Arc::clone(&sink),
            next_span: AtomicU64::new(1),
        };
        if tracing::subscriber::set_global_default(subscriber).is_err() {
            println!("NOTE: a global tracing subscriber was already installed");
        }
        sink
    });
    lock(sink).clear();
    TracingCapture {
        _guard: Guard {
            sink: Arc::clone(sink),
        },
        _serial: serial,
        lines: Arc::clone(sink),
    }
}

/// The capturing subscriber: every event, rendered with its fields.
struct Capture {
    sink: Arc<Mutex<Vec<String>>>,
    next_span: AtomicU64,
}

impl Subscriber for Capture {
    fn enabled(&self, _metadata: &Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, _span: &span::Attributes<'_>) -> span::Id {
        // `Id::from_u64` rejects zero, so the counter starts at one.
        span::Id::from_u64(self.next_span.fetch_add(1, Ordering::SeqCst))
    }

    fn record(&self, _span: &span::Id, _values: &span::Record<'_>) {}

    fn record_follows_from(&self, _span: &span::Id, _follows: &span::Id) {}

    fn event(&self, event: &Event<'_>) {
        let metadata = event.metadata();
        let mut fields = Fields::default();
        event.record(&mut fields);
        lock(&self.sink).push(format!(
            "{level} {target} {name}{fields}",
            level = metadata.level(),
            target = metadata.target(),
            name = metadata.name(),
            fields = fields.text,
        ));
    }

    fn enter(&self, _span: &span::Id) {}

    fn exit(&self, _span: &span::Id) {}
}

/// Every field of one event, rendered.
#[derive(Default)]
struct Fields {
    text: String,
}

impl Visit for Fields {
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        let _ = write!(self.text, " {name}={value:?}", name = field.name());
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        let _ = write!(self.text, " {name}={value}", name = field.name());
    }
}

// ---------------------------------------------------------------------------
// Shared
// ---------------------------------------------------------------------------

/// Lock a mutex, ignoring poisoning: a panicking test has already failed, and a
/// second panic here would hide it.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}
