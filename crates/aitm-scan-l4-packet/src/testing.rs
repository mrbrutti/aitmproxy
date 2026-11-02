//! The inner-loop harness: mock backend, loopback guard, test job context and
//! profile helpers — owned by scanner v2 track T5, plan task 6.
//!
//! This module is `#[doc(hidden)] pub` and **always compiled** (not
//! `#[cfg(test)]`), so the crate's unit tests, `tests/live_loopback.rs` and the
//! later tracks' tests all drive one harness (plan call C19). Nothing here
//! opens a socket, a pcap handle or a file: [`MockBackend`] answers injected
//! stimuli from memory, so the whole lane is exercised in a sandbox with no
//! capture privilege.
//!
//! Per spec **Verification**, `cargo test` against this harness is the inner
//! loop and never the proof: the acceptance evidence for T5 is the real-bus
//! e2e cells and the live loopback test.

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime};

use aitm_core::{
    BrowserDriver, FlowStore, HttpFlow, HttpRequest, MemFlowStore, ProxyClient, ScopeRateGuard,
    StdGuard,
};
use aitm_proto_l4::backend::{CaptureInjectBackend, CaptureSource, L4Error};
use aitm_proto_l4::config::L4Config;
use aitm_proto_l4::craft::{IcmpSpec, Ipv4Spec, Ipv6Spec, Layer, PacketSpec, TcpSpec, UdpSpec};
use aitm_proto_l4::flow::L4Packet;
use aitm_proto_l4::guard::L4Guard;
use aitm_proto_l4::icmp::transport_payload;
use aitm_proto_l4::types::{
    IpCidr, L4Capability, L4Direction, L4Proto, L4ScopeEntry, L4ScopeId, L4ScopeSource, PortRange,
    RateCap,
};
use aitm_scan_model::{
    JobCtx, L4Options, L4Seed, L4TargetSpec, L4Transport, LaneKind, ProfileTarget, ScanProfile,
    SessionMaterial,
};
use futures::future::BoxFuture;

use crate::sync::lock;

/// What [`MockBackend`] answers an injected stimulus with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MockReply {
    /// The stimulus reflected back with the five-tuple reversed — the reply
    /// `send_recv` classifies as `Response` (an echo service).
    Echo,
    /// An ICMPv4 error from the target host: the closed-UDP-port
    /// `(3, 3)` the lane's oracle reads as `icmp(3,3)`.
    Icmp {
        /// ICMP type (`3` for destination unreachable).
        icmp_type: u8,
        /// ICMP code (`3` for port unreachable).
        code: u8,
    },
    /// A TCP reset from the target host — a closed TCP port.
    Rst,
    /// Nothing at all: every stimulus times out.
    Silence,
}

/// One queued reply frame and the instant it becomes readable, so
/// [`MockBackend::reply_delay`] is observed by the awaiting capture (where
/// `send_recv` measures latency) rather than by the inject.
struct Pending {
    ready_at: Instant,
    frame: Vec<u8>,
}

impl fmt::Debug for Pending {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Pending")
            .field("frame", &format_args!("<{} bytes>", self.frame.len()))
            .finish()
    }
}

/// The payload pattern that makes the mock "crash", mirroring T10's seeded
/// `l4-udp-payload-crash` service (plan call C28).
struct Pattern {
    prefix: Vec<u8>,
    min_len: usize,
    silent_frames: usize,
    repeat: bool,
}

impl fmt::Debug for Pattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Pattern")
            .field("prefix", &format_args!("<{} bytes>", self.prefix.len()))
            .field("min_len", &self.min_len)
            .field("silent_frames", &self.silent_frames)
            .field("repeat", &self.repeat)
            .finish()
    }
}

/// The mock's scripted misbehaviour, all of it interior-mutable so a test
/// configures an already-shared `Arc<MockBackend>`.
#[derive(Debug, Default)]
struct Script {
    /// Answer the first `n` injects, then go silent forever.
    dies_after: Option<usize>,
    /// The payload pattern that triggers a bounded silence.
    pattern: Option<Pattern>,
    /// How many further injects stay silent.
    silent_left: usize,
    /// Whether the pattern has fired once already.
    triggered: bool,
    /// How long a reply waits in the queue before a capture may read it.
    reply_delay: Duration,
    /// Whether every inject fails with [`L4Error::WireWrite`].
    wire_write_fails: bool,
    /// At most one ICMP reply per target per this window, as a kernel that
    /// rate-limits the ICMP errors it generates does.
    icmp_window: Option<Duration>,
    /// When each target last had an ICMP reply out of this mock.
    last_icmp: HashMap<IpAddr, Instant>,
}

/// An in-memory [`CaptureInjectBackend`]: it answers injected stimuli from a
/// per-backend reply queue the capture sources read, so the lane's whole
/// send-and-receive path runs with no pcap handle, no socket and no privilege.
///
/// `send_recv` opens the capture **before** it injects and then polls
/// `next_frame` until the timeout, so the reply is computed at inject time and
/// pushed onto the shared queue the already-open capture is draining. The BPF
/// filter `send_recv` passes (the guard's self-exclusion clause) is ignored:
/// the mock never synthesises the core's own traffic.
///
/// **The mock echoes the stimulus like a real loopback capture.** A capture
/// taps the interface, not one direction of it: on Linux `lo` libpcap delivers
/// the RX copy of the frame just injected, and macOS `lo0` BPF reports sent
/// frames too, so the first frame a real reply capture reads is the stimulus
/// itself (the T5 live proof found `send_recv` classifying that frame instead
/// of the reply). Every `inject` therefore queues the injected bytes **ahead
/// of** the scripted reply, by default; `send_recv` must ignore them, and a
/// lane test that goes red here would go red on the real loopback too.
/// [`MockBackend::without_self_echo`] models a capture that never sees its
/// own injects, for a test that needs exactly the reply queue.
///
/// Replies are built as L3 (IP-first) frames with the stimulus's five-tuple
/// reversed, which is what [`aitm_proto_l4::sendrecv::ReplyMatch::FiveTuple`]
/// correlation needs: an [`MockReply::Echo`] is a `Response`, an
/// [`MockReply::Icmp`] or [`MockReply::Rst`] from the target host is an
/// `Other`. A stimulus the packet views cannot decode gets no reply at all.
pub struct MockBackend {
    reply: MockReply,
    available: bool,
    self_echo: AtomicBool,
    queue: Arc<Mutex<VecDeque<Pending>>>,
    injected: Mutex<Vec<Vec<u8>>>,
    script: Mutex<Script>,
}

impl fmt::Debug for MockBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let injected = lock(&self.injected);
        f.debug_struct("MockBackend")
            .field("reply", &self.reply)
            .field("available", &self.available)
            .field("self_echo", &self.self_echo.load(Ordering::SeqCst))
            .field("queued", &lock(&self.queue).len())
            .field("injected", &format_args!("<{} frames>", injected.len()))
            .field("script", &*lock(&self.script))
            .finish()
    }
}

impl MockBackend {
    /// A backend that answers every injected stimulus with `reply`.
    #[must_use]
    pub fn new(reply: MockReply) -> Arc<Self> {
        Arc::new(Self {
            reply,
            available: true,
            self_echo: AtomicBool::new(true),
            queue: Arc::new(Mutex::new(VecDeque::new())),
            injected: Mutex::new(Vec::new()),
            script: Mutex::new(Script::default()),
        })
    }

    /// A backend with no capture/inject privilege: every `open_capture` and
    /// `inject` fails closed with [`L4Error::Unavailable`], and an attempted
    /// inject is not recorded (nothing reached a wire).
    #[must_use]
    pub fn unavailable() -> Arc<Self> {
        Arc::new(Self {
            reply: MockReply::Silence,
            available: false,
            self_echo: AtomicBool::new(true),
            queue: Arc::new(Mutex::new(VecDeque::new())),
            injected: Mutex::new(Vec::new()),
            script: Mutex::new(Script::default()),
        })
    }

    /// Answer the first `n` injects, then never answer again — the "the target
    /// died and stayed dead" shape the crash check's liveness probe must see.
    pub fn dies_after_injects(&self, n: usize) {
        lock(&self.script).dies_after = Some(n);
    }

    /// Go silent on a stimulus whose UDP/TCP payload starts with `prefix` and
    /// is at least `min_len` bytes, and on the next `silent_frames` injects
    /// whatever they carry, then answer again — T10's seeded crash service
    /// (plan call C28). With `repeat: false` only the first match triggers;
    /// with `true` every match re-triggers.
    pub fn dies_on_pattern(
        &self,
        prefix: Vec<u8>,
        min_len: usize,
        silent_frames: usize,
        repeat: bool,
    ) {
        let mut script = lock(&self.script);
        script.pattern = Some(Pattern {
            prefix,
            min_len,
            silent_frames,
            repeat,
        });
        script.silent_left = 0;
        script.triggered = false;
    }

    /// Fail every inject the way a raw socket whose write is refused does:
    /// [`L4Error::WireWrite`], with nothing on the wire and nothing recorded as
    /// injected. The capture still opens, so this is the "the send path broke
    /// under us" shape, not the "no privilege" one
    /// ([`MockBackend::unavailable`]).
    pub fn fail_injects_with_wire_write(&self) {
        lock(&self.script).wire_write_fails = true;
    }

    /// Hold every reply in the queue for `d` before a capture may read it, so
    /// a test can drive the oracle's latency window and timeouts.
    pub fn reply_delay(&self, d: Duration) {
        lock(&self.script).reply_delay = d;
    }

    /// Answer at most one [`MockReply::Icmp`] per `window` per target and stay
    /// silent in between, the way a remote target's kernel rate-limits the
    /// ICMP errors it generates (Linux: `net.ipv4.icmp_ratelimit = 1000` ms per
    /// destination, the remote-host behaviour spec amendment 46 paces for;
    /// loopback is exempt, write-up `2026-11-01-t5-live-proof.md` section iii).
    ///
    /// The self-echo is unaffected: the capture still reads the injected frame
    /// first, exactly as loopback delivers it, whether or not an ICMP error
    /// follows.
    pub fn icmp_ratelimit(&self, window: Duration) {
        let mut script = lock(&self.script);
        script.icmp_window = Some(window);
        script.last_icmp.clear();
    }

    /// A capture that never sees its own injects: only the scripted reply is
    /// queued. The default models the real loopback, which delivers the
    /// stimulus first (see the type doc); use this for a test that needs the
    /// reply queue and nothing else.
    #[must_use]
    pub fn without_self_echo(self: Arc<Self>) -> Arc<Self> {
        self.self_echo.store(false, Ordering::SeqCst);
        self
    }

    /// Every frame handed to [`CaptureInjectBackend::inject`], in order.
    #[must_use]
    pub fn injected(&self) -> Vec<Vec<u8>> {
        lock(&self.injected).clone()
    }

    /// How many frames were injected.
    #[must_use]
    pub fn inject_count(&self) -> usize {
        lock(&self.injected).len()
    }

    /// Whether this inject goes unanswered, advancing the scripted state.
    /// `count` is the 1-based index of the inject.
    fn is_silent(&self, count: usize, stimulus: &[u8]) -> bool {
        let mut script = lock(&self.script);
        if script.dies_after.is_some_and(|n| count > n) {
            return true;
        }
        if script.silent_left > 0 {
            script.silent_left -= 1;
            return true;
        }
        let Some(pattern) = script.pattern.as_ref() else {
            return false;
        };
        let (silent_frames, repeat) = (pattern.silent_frames, pattern.repeat);
        let matched = payload_of(stimulus)
            .is_some_and(|p| p.len() >= pattern.min_len && p.starts_with(&pattern.prefix));
        if matched && (repeat || !script.triggered) {
            script.triggered = true;
            script.silent_left = silent_frames;
            return true;
        }
        false
    }

    /// Whether this mock may answer `target` with an ICMP error now: always,
    /// unless [`MockBackend::icmp_ratelimit`] set a window and one went out
    /// inside it. Spending the token is part of the answer, so the caller
    /// cannot ask twice for one reply.
    fn icmp_allowed(&self, target: IpAddr) -> bool {
        let mut script = lock(&self.script);
        let Some(window) = script.icmp_window else {
            return true;
        };
        let now = Instant::now();
        if script
            .last_icmp
            .get(&target)
            .is_some_and(|last| now.duration_since(*last) < window)
        {
            return false;
        }
        script.last_icmp.insert(target, now);
        true
    }

    /// The reply frame for `stimulus`, or `None` when this mock answers
    /// nothing or the stimulus does not decode to a UDP/TCP packet.
    fn reply_frame(&self, stimulus: &[u8]) -> Option<Vec<u8>> {
        let packet = as_packet(stimulus);
        let ends = transport_payload(&packet)?;
        // The reply comes *from* the stimulus's destination: source address and
        // source port are what `FiveTuple` correlation matches on.
        let ip = ip_layer(ends.dst, ends.src)?;
        let layers = match self.reply {
            MockReply::Silence => return None,
            MockReply::Echo => {
                let transport = match ends.proto {
                    L4Proto::Udp => Layer::Udp(UdpSpec {
                        src_port: Some(ends.dst_port),
                        dst_port: Some(ends.src_port),
                        ..UdpSpec::default()
                    }),
                    L4Proto::Tcp => Layer::Tcp(TcpSpec {
                        src_port: Some(ends.dst_port),
                        dst_port: Some(ends.src_port),
                        // SYN|ACK: the answer a listening TCP port gives.
                        flags: Some(0x12),
                        ..TcpSpec::default()
                    }),
                    _ => return None,
                };
                vec![ip, transport, Layer::Raw(ends.payload.to_vec())]
            }
            MockReply::Icmp { icmp_type, code } => {
                if !self.icmp_allowed(ends.dst) {
                    return None;
                }
                vec![
                    ip,
                    Layer::Icmp(IcmpSpec {
                        icmp_type: Some(icmp_type),
                        code: Some(code),
                        rest_of_header: Some(0),
                        checksum: None,
                    }),
                    // An ICMP error quotes the head of the offending datagram.
                    Layer::Raw(quoted_datagram(stimulus)),
                ]
            }
            MockReply::Rst => vec![
                ip,
                Layer::Tcp(TcpSpec {
                    src_port: Some(ends.dst_port),
                    dst_port: Some(ends.src_port),
                    // RST|ACK: the answer a closed TCP port gives.
                    flags: Some(0x14),
                    ..TcpSpec::default()
                }),
            ],
        };
        PacketSpec { layers }.build().ok()
    }
}

impl CaptureInjectBackend for MockBackend {
    fn open_capture(
        &self,
        _iface: &str,
        _filter: Option<&str>,
        _read_timeout: Duration,
    ) -> Result<Box<dyn CaptureSource>, L4Error> {
        if !self.available {
            return Err(L4Error::Unavailable("no capture privilege (mock)".into()));
        }
        Ok(Box::new(MockCapture {
            queue: Arc::clone(&self.queue),
        }))
    }

    fn inject(&self, _iface: &str, bytes: &[u8]) -> Result<(), L4Error> {
        if !self.available {
            return Err(L4Error::Unavailable("no inject privilege (mock)".into()));
        }
        if lock(&self.script).wire_write_fails {
            return Err(L4Error::WireWrite("mock wire down".into()));
        }
        let count = {
            let mut injected = lock(&self.injected);
            injected.push(bytes.to_vec());
            injected.len()
        };
        // The loopback truth: the capture reads the injected frame itself
        // before anything answers it, whether or not anything does.
        if self.self_echo.load(Ordering::SeqCst) {
            lock(&self.queue).push_back(Pending {
                ready_at: Instant::now(),
                frame: bytes.to_vec(),
            });
        }
        if self.is_silent(count, bytes) {
            return Ok(());
        }
        if let Some(frame) = self.reply_frame(bytes) {
            let ready_at = Instant::now() + lock(&self.script).reply_delay;
            lock(&self.queue).push_back(Pending { ready_at, frame });
        }
        Ok(())
    }
}

/// A capture over the backend's shared reply queue: it pops the next frame
/// whose delay has elapsed, or idles 2 ms and reports an elapsed poll, exactly
/// as a pcap read timeout does.
struct MockCapture {
    queue: Arc<Mutex<VecDeque<Pending>>>,
}

impl fmt::Debug for MockCapture {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MockCapture")
            .field("queued", &lock(&self.queue).len())
            .finish()
    }
}

impl CaptureSource for MockCapture {
    fn next_frame(&mut self) -> Result<Option<Vec<u8>>, L4Error> {
        let ready = {
            let mut queue = lock(&self.queue);
            match queue.front() {
                Some(pending) if pending.ready_at <= Instant::now() => {
                    queue.pop_front().map(|pending| pending.frame)
                }
                _ => None,
            }
        };
        if let Some(frame) = ready {
            return Ok(Some(frame));
        }
        std::thread::sleep(Duration::from_millis(2));
        Ok(None)
    }
}

/// Wrap raw frame bytes as the injected packet the packet views read.
fn as_packet(bytes: &[u8]) -> L4Packet {
    L4Packet {
        dir: L4Direction::Outbound,
        timestamp: SystemTime::now(),
        decoded: PacketSpec::summarize(bytes),
        bytes: bytes.to_vec(),
        injected: true,
    }
}

/// The UDP/TCP payload of a frame, or `None` when it does not decode.
fn payload_of(bytes: &[u8]) -> Option<Vec<u8>> {
    let packet = as_packet(bytes);
    transport_payload(&packet).map(|t| t.payload.to_vec())
}

/// The IP layer of a reply from `src` to `dst`; `None` for a mixed-family
/// pair, which cannot be crafted.
fn ip_layer(src: IpAddr, dst: IpAddr) -> Option<Layer> {
    match (src, dst) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => Some(Layer::Ipv4(Ipv4Spec {
            src: Some(src),
            dst: Some(dst),
            ..Ipv4Spec::default()
        })),
        (IpAddr::V6(src), IpAddr::V6(dst)) => Some(Layer::Ipv6(Ipv6Spec {
            src: Some(src),
            dst: Some(dst),
            ..Ipv6Spec::default()
        })),
        _ => None,
    }
}

/// The first 28 bytes of the stimulus's IP packet — what an ICMP error quotes.
/// Wire-derived bytes: every read is bounds-checked and a frame whose link
/// layer is unrecognised is quoted from its start.
fn quoted_datagram(frame: &[u8]) -> Vec<u8> {
    let is_ip = |b: u8| matches!(b >> 4, 4 | 6);
    let offset = if frame.first().copied().is_some_and(is_ip) {
        0
    } else if matches!(
        frame.get(12..14),
        Some(&[0x08, 0x00]) | Some(&[0x86, 0xdd]) | Some(&[0x08, 0x06])
    ) {
        14
    } else if frame.get(4).copied().is_some_and(is_ip) {
        4
    } else {
        0
    };
    frame
        .get(offset..)
        .unwrap_or_default()
        .iter()
        .take(28)
        .copied()
        .collect()
}

/// A guard scoped exactly as the packet lane needs on loopback: `Inject`
/// outbound and `Capture` inbound over `127.0.0.0/8`, every port, on
/// `interface` (`"*"` matches whatever the platform calls loopback, so one
/// helper serves macOS `lo0` and Linux `lo`).
///
/// `pps` is the per-entry injection rate cap. The tool-wide cap stays at
/// [`L4Config`]'s default, so a `pps` above it is still metered tool-wide.
#[must_use]
pub fn loopback_guard(interface: &str, pps: u32) -> Arc<L4Guard> {
    let entry = |direction, capability| L4ScopeEntry {
        id: L4ScopeId::new(),
        cidr: IpCidr {
            addr: IpAddr::from([127, 0, 0, 0]),
            prefix: 8,
        },
        ports: PortRange {
            lo: 0,
            hi: u16::MAX,
        },
        interface: interface.to_string(),
        direction,
        capability,
        inject_rate: RateCap { pps, burst: pps },
        source: L4ScopeSource::Config,
    };
    Arc::new(L4Guard::new(&L4Config {
        enabled: true,
        scope: vec![
            entry(L4Direction::Outbound, L4Capability::Inject),
            entry(L4Direction::Inbound, L4Capability::Capture),
        ],
        ..L4Config::default()
    }))
}

/// A `ProxyClient` that performs no I/O; the job context needs one to exist.
/// The packet lane never sends HTTP, so a call here is a bug in the test.
struct NullClient;

impl ProxyClient for NullClient {
    fn send(&self, _req: HttpRequest) -> BoxFuture<'_, anyhow::Result<HttpFlow>> {
        Box::pin(async { Err(anyhow::anyhow!("no http client in the l4 test context")) })
    }
}

/// The default budget a [`TestJob`] starts with.
const DEFAULT_BUDGET: u32 = 10_000;

/// A [`JobCtx`] test double: the profile, an inert HTTP client, an in-memory
/// flow store and the standard guard, plus the budget, deadline, job id and
/// cancellation flag the lane reads in every loop.
///
/// Everything mutable is interior-mutable, so the builders work on the
/// `Arc<Self>` a lane is handed: `TestJob::new(profile).with_budget(2)`.
pub struct TestJob {
    profile: ScanProfile,
    client: Arc<dyn ProxyClient>,
    store: Arc<dyn FlowStore>,
    guard: Arc<dyn ScopeRateGuard>,
    job_id: OnceLock<String>,
    marker: OnceLock<String>,
    budget: AtomicU32,
    charged: AtomicU32,
    deadline: Mutex<Instant>,
    cancelled: AtomicBool,
}

impl fmt::Debug for TestJob {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TestJob")
            .field("job_id", &self.job_id())
            .field("budget_left", &self.budget_left())
            .field("charged", &self.charged())
            .field("cancelled", &self.cancelled())
            .finish()
    }
}

impl TestJob {
    /// A job running `profile` with a 10 000-stimulus budget, a deadline 60 s
    /// out, marker `aitm7f3a` and job id `scan-1a2b3c4d`.
    #[must_use]
    pub fn new(profile: ScanProfile) -> Arc<Self> {
        Arc::new(Self {
            profile,
            client: Arc::new(NullClient),
            store: Arc::new(MemFlowStore::new()),
            guard: Arc::new(StdGuard::default()),
            job_id: OnceLock::new(),
            marker: OnceLock::new(),
            budget: AtomicU32::new(DEFAULT_BUDGET),
            charged: AtomicU32::new(0),
            deadline: Mutex::new(Instant::now() + Duration::from_secs(60)),
            cancelled: AtomicBool::new(false),
        })
    }

    /// Set the job's remaining budget.
    #[must_use]
    pub fn with_budget(self: Arc<Self>, n: u32) -> Arc<Self> {
        self.budget.store(n, Ordering::SeqCst);
        self
    }

    /// Set the job's marker, for a test that runs more than one job through
    /// one lane and needs their runners kept apart.
    #[must_use]
    pub fn with_marker(self: Arc<Self>, marker: &str) -> Arc<Self> {
        let _ = self.marker.set(marker.to_string());
        self
    }

    /// Set the job's deadline.
    #[must_use]
    pub fn with_deadline(self: Arc<Self>, at: Instant) -> Arc<Self> {
        *lock(&self.deadline) = at;
        self
    }

    /// Set the job's id. Only the first call takes effect, so the id a lane
    /// already keyed its state by never changes under it.
    #[must_use]
    pub fn with_job_id(self: Arc<Self>, id: &str) -> Arc<Self> {
        let _ = self.job_id.set(id.to_string());
        self
    }

    /// How many budget units the lane has charged so far.
    #[must_use]
    pub fn charged(&self) -> u32 {
        self.charged.load(Ordering::SeqCst)
    }

    /// Cancel the job, as the engine does when the operator stops a scan.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }
}

impl JobCtx for TestJob {
    fn job_id(&self) -> &str {
        self.job_id.get().map_or("scan-1a2b3c4d", String::as_str)
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

    /// Charge `units`, or charge nothing and report `false` when the remaining
    /// budget is short — the contract the lane's stop ladder depends on.
    fn charge(&self, units: u32) -> bool {
        let mut left = self.budget.load(Ordering::SeqCst);
        loop {
            if left < units {
                return false;
            }
            match self.budget.compare_exchange(
                left,
                left - units,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => {
                    self.charged.fetch_add(units, Ordering::SeqCst);
                    return true;
                }
                Err(now) => left = now,
            }
        }
    }

    fn budget_left(&self) -> u32 {
        self.budget.load(Ordering::SeqCst)
    }

    fn deadline(&self) -> Instant {
        *lock(&self.deadline)
    }

    fn cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }

    fn marker(&self) -> String {
        self.marker
            .get()
            .cloned()
            .unwrap_or_else(|| "aitm7f3a".to_string())
    }
}

/// A UDP target on `127.0.0.1:port`, no grammar (the packet lane never reads
/// one).
#[must_use]
pub fn udp_target(port: u16) -> L4TargetSpec {
    L4TargetSpec {
        ip: "127.0.0.1".to_string(),
        port,
        proto: L4Transport::Udp,
        grammar: None,
    }
}

/// A TCP target on `127.0.0.1:port`, no grammar.
#[must_use]
pub fn tcp_target(port: u16) -> L4TargetSpec {
    L4TargetSpec {
        ip: "127.0.0.1".to_string(),
        port,
        proto: L4Transport::Tcp,
        grammar: None,
    }
}

/// A packet-lane profile over `targets` with a `cases` budget and the L4
/// defaults the spec names (reproduce 3, liveness every 25, give up after 20
/// consecutive timeouts, no dry run).
#[must_use]
pub fn l4_profile(targets: Vec<L4TargetSpec>, cases: u32) -> ScanProfile {
    ScanProfile {
        target: ProfileTarget {
            origins: Vec::new(),
            l4: targets,
        },
        lanes: vec![LaneKind::L4Packet],
        l4: L4Options {
            cases,
            reproduce_count: 3,
            liveness_every: 25,
            consecutive_timeouts: 20,
            dry_run: false,
            ..L4Options::default()
        },
        ..ScanProfile::default()
    }
}

/// Push a hex seed onto `profile`'s L4 seed list.
#[must_use]
pub fn with_hex_seed(mut profile: ScanProfile, hex: &str) -> ScanProfile {
    profile.l4.seeds.push(L4Seed::Hex {
        hex: hex.to_string(),
    });
    profile
}

/// The `requested` field list the lane's discovery takes, while
/// `plan::requested_fields` still returns an empty list (plan call C1).
#[must_use]
pub fn fields(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| (*s).to_string()).collect()
}

/// The shared unit-test fixtures the lane's own modules drive, so `host.rs`,
/// `checks.rs` and `lane.rs` build one lane context the one way (review finding
/// M3). Only compiled for tests, but `pub` so each module's `#[cfg(test)]`
/// block reaches it through `crate::testing::harness`.
#[cfg(test)]
pub mod harness {
    use std::str::FromStr;
    use std::sync::Arc;
    use std::time::Duration;

    use aitm_proto_l4::backend::CaptureInjectBackend;
    use aitm_proto_l4::flow::{InMemoryL4FlowStore, L4FlowStore};
    use aitm_scan_model::{Discovery, InsertionPoint, JobCtx, ScanProfile};

    use super::{loopback_guard, MockBackend, TestJob};
    use crate::discover::discover_all;
    use crate::fields::FieldPath;
    use crate::host::{PointRunner, Shared, Timing};
    use crate::plan::{point_id, TargetPlan};
    use crate::state::{JobKey, LaneState};

    /// Millisecond timings, so a hundred cases cost milliseconds while the
    /// recovery ladder keeps its ten polls (so inject counts stay exact).
    #[must_use]
    pub fn fast_timing() -> Timing {
        Timing {
            reply_window: Duration::from_millis(50),
            liveness_retry: Duration::from_millis(10),
            replay_spacing: Duration::from_millis(10),
            recovery_poll: Duration::from_millis(10),
            recovery_polls: 10,
            // Unpaced by default, so a test that does not care about amendment
            // 46 still costs milliseconds; a test that does sets its own pace.
            icmp_pace: Some(Duration::ZERO),
            ..Timing::default()
        }
    }

    /// The lane context every unit test drives: the loopback guard, the mock
    /// backend, a lane-private case store, a separate seed store and a
    /// `LaneState` with the job already begun, timed by [`fast_timing`].
    #[must_use]
    pub fn setup(
        mock: Arc<MockBackend>,
        profile: ScanProfile,
        requested: &[String],
        pps: u32,
    ) -> (Arc<Shared>, Arc<TestJob>, Vec<TargetPlan>, Discovery) {
        let guard = loopback_guard("*", pps);
        let seed_store: Arc<dyn L4FlowStore> = Arc::new(InMemoryL4FlowStore::default());
        let case_store: Arc<dyn L4FlowStore> = Arc::new(InMemoryL4FlowStore::with_limits(1024, 16));
        let backend: Arc<dyn CaptureInjectBackend> = mock;
        let job = TestJob::new(profile.clone());
        let (plans, discovery) = discover_all(
            guard.as_ref(),
            backend.as_ref(),
            Some(seed_store.as_ref()),
            &profile.target,
            &profile,
            requested,
            &job.marker(),
        )
        .expect("the loopback profile discovers");
        let state = Arc::new(LaneState::new());
        let _ = state.begin_job(
            JobKey::new(job.job_id(), &job.marker()),
            plans.clone(),
            discovery.points.iter().map(|p| p.id.clone()).collect(),
            profile.l4.cases,
            profile.l4.consecutive_timeouts,
            profile.l4.dry_run,
        );
        let shared = Arc::new(Shared {
            guard,
            backend,
            case_store,
            seed_store: Some(seed_store),
            timing: fast_timing(),
            state,
        });
        (shared, job, plans, discovery)
    }

    /// The runner for one field of the job's first target.
    #[must_use]
    pub fn runner_for(
        shared: &Arc<Shared>,
        job: &Arc<TestJob>,
        plans: &[TargetPlan],
        points: &[InsertionPoint],
        field: &str,
    ) -> Arc<PointRunner> {
        let path = FieldPath::from_str(field).expect("a known field path");
        let plan = plans.first().expect("one target plan").clone();
        let id = point_id(&plan.target, path);
        let point = points
            .iter()
            .find(|point| point.id == id)
            .expect("the field's point")
            .clone();
        Arc::new(
            PointRunner::new(
                Arc::clone(shared),
                Arc::clone(job) as Arc<dyn JobCtx>,
                point,
                plan,
                path,
            )
            .expect("the field's seed builds"),
        )
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;
    use std::time::{Duration, Instant, SystemTime};

    use aitm_proto_l4::backend::{CaptureInjectBackend, CaptureSource, L4Error};
    use aitm_proto_l4::craft::{Ipv4Spec, Layer, PacketSpec, TcpSpec, UdpSpec};
    use aitm_proto_l4::flow::{InMemoryL4FlowStore, L4FlowStore, L4Packet};
    use aitm_proto_l4::icmp::{icmp_error, tcp_rst, transport_payload};
    use aitm_proto_l4::sendrecv::{send_recv, ReplyMatch, SendRecvOutcome, SendRecvSpec};
    use aitm_proto_l4::types::{L4Action, L4Direction, L4Proto, L4Target};
    use aitm_scan_model::{JobCtx, L4Seed, L4Transport, LaneKind, ScanProfile};

    use super::{fields, l4_profile, loopback_guard, tcp_target, udp_target, with_hex_seed};
    use super::{MockBackend, MockReply, TestJob};

    /// The interface every mock test names; the mock ignores it, the guard
    /// matches it through the `"*"` scope entries [`loopback_guard`] seeds.
    const IFACE: &str = "lo0";

    /// Wrap a captured frame the way `send_recv` hands one to the lane.
    fn captured(bytes: Vec<u8>) -> L4Packet {
        L4Packet {
            dir: L4Direction::Inbound,
            timestamp: SystemTime::now(),
            decoded: PacketSpec::summarize(&bytes),
            bytes,
            injected: false,
        }
    }

    /// An L3 UDP stimulus `127.0.0.1:40000 -> 127.0.0.1:9`.
    fn udp_stimulus(payload: &[u8]) -> Vec<u8> {
        PacketSpec {
            layers: vec![
                Layer::Ipv4(Ipv4Spec {
                    src: Some(Ipv4Addr::LOCALHOST),
                    dst: Some(Ipv4Addr::LOCALHOST),
                    ..Ipv4Spec::default()
                }),
                Layer::Udp(UdpSpec {
                    src_port: Some(40000),
                    dst_port: Some(9),
                    ..UdpSpec::default()
                }),
                Layer::Raw(payload.to_vec()),
            ],
        }
        .build()
        .expect("the udp stimulus builds")
    }

    /// An L3 TCP SYN stimulus `127.0.0.1:40000 -> 127.0.0.1:80`.
    fn tcp_stimulus(payload: &[u8]) -> Vec<u8> {
        PacketSpec {
            layers: vec![
                Layer::Ipv4(Ipv4Spec {
                    src: Some(Ipv4Addr::LOCALHOST),
                    dst: Some(Ipv4Addr::LOCALHOST),
                    ..Ipv4Spec::default()
                }),
                Layer::Tcp(TcpSpec {
                    src_port: Some(40000),
                    dst_port: Some(80),
                    flags: Some(0x02),
                    ..TcpSpec::default()
                }),
                Layer::Raw(payload.to_vec()),
            ],
        }
        .build()
        .expect("the tcp stimulus builds")
    }

    /// Poll `source` until a frame arrives or `within` elapses.
    fn wait_frame(source: &mut dyn CaptureSource, within: Duration) -> Option<Vec<u8>> {
        let start = Instant::now();
        while start.elapsed() < within {
            match source.next_frame() {
                Ok(Some(frame)) => return Some(frame),
                Ok(None) => {}
                Err(_) => return None,
            }
        }
        None
    }

    /// Assert the source stays silent (`Ok(None)`) for `within`.
    fn expect_silence(source: &mut dyn CaptureSource, within: Duration) {
        let start = Instant::now();
        while start.elapsed() < within {
            match source.next_frame() {
                Ok(None) => {}
                Ok(Some(frame)) => panic!("expected silence, got {} bytes", frame.len()),
                Err(e) => panic!("expected silence, got an error: {e}"),
            }
        }
    }

    /// The first frame after an inject is the injected frame itself, as on a
    /// real loopback capture; consume it and prove it is byte-equal.
    fn expect_self_echo(source: &mut dyn CaptureSource, stimulus: &[u8]) {
        let frame = wait_frame(source, Duration::from_millis(500))
            .expect("the capture sees the injected frame first");
        assert_eq!(
            frame, stimulus,
            "the self-echo is the stimulus byte-for-byte"
        );
    }

    /// T5 live proof: by default every inject reaches the capture queue ahead
    /// of its reply — the stimulus first, then the scripted echo — and a
    /// silent inject still shows its own frame. `without_self_echo` queues the
    /// reply alone.
    #[test]
    fn mock_echoes_the_stimulus_before_the_reply_like_a_loopback_capture() {
        let stimulus = udp_stimulus(b"probe");

        let backend = MockBackend::new(MockReply::Echo);
        let mut source = backend
            .open_capture(IFACE, None, Duration::from_millis(5))
            .expect("the mock capture opens");
        backend
            .inject(IFACE, &stimulus)
            .expect("the mock accepts the inject");
        expect_self_echo(source.as_mut(), &stimulus);
        let reply = wait_frame(source.as_mut(), Duration::from_millis(500)).expect("the echo");
        assert_ne!(
            reply, stimulus,
            "the reply is the reversed tuple, not the echo"
        );
        assert_eq!(
            transport_payload(&captured(reply))
                .expect("a udp reply")
                .src_port,
            9
        );
        expect_silence(source.as_mut(), Duration::from_millis(20));

        // A silent target still lets the capture see what was sent.
        let silent = MockBackend::new(MockReply::Silence);
        let mut source = silent
            .open_capture(IFACE, None, Duration::from_millis(5))
            .expect("the mock capture opens");
        silent
            .inject(IFACE, &stimulus)
            .expect("the mock accepts the inject");
        expect_self_echo(source.as_mut(), &stimulus);
        expect_silence(source.as_mut(), Duration::from_millis(20));

        // Opted out: only the reply.
        let quiet = MockBackend::new(MockReply::Echo).without_self_echo();
        let mut source = quiet
            .open_capture(IFACE, None, Duration::from_millis(5))
            .expect("the mock capture opens");
        quiet
            .inject(IFACE, &stimulus)
            .expect("the mock accepts the inject");
        let only = wait_frame(source.as_mut(), Duration::from_millis(500)).expect("the echo");
        assert_ne!(
            only, stimulus,
            "without the self-echo the first frame is the reply"
        );
        expect_silence(source.as_mut(), Duration::from_millis(20));
        assert_eq!(quiet.inject_count(), 1);
    }

    #[test]
    fn echo_mock_reverses_the_tuple() {
        let backend = MockBackend::new(MockReply::Echo);
        let stimulus = udp_stimulus(b"probe");
        backend
            .inject(IFACE, &stimulus)
            .expect("the mock accepts the inject");
        let mut source = backend
            .open_capture(IFACE, None, Duration::from_millis(5))
            .expect("the mock capture opens");

        expect_self_echo(source.as_mut(), &stimulus);
        let frame = wait_frame(source.as_mut(), Duration::from_millis(500)).expect("an echo reply");
        let pkt = captured(frame);
        let reply = transport_payload(&pkt).expect("the reply is a udp packet");
        assert_eq!(reply.src, IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(reply.src_port, 9);
        assert_eq!(reply.dst_port, 40000);
        assert_eq!(reply.proto, L4Proto::Udp);
        assert_eq!(reply.payload, b"probe");
        assert_eq!(backend.inject_count(), 1);
        assert_eq!(backend.injected().len(), 1);
    }

    #[test]
    fn icmp_mock_is_3_3() {
        let backend = MockBackend::new(MockReply::Icmp {
            icmp_type: 3,
            code: 3,
        });
        let mut source = backend
            .open_capture(IFACE, None, Duration::from_millis(5))
            .expect("the mock capture opens");
        let stimulus = udp_stimulus(b"probe");
        backend
            .inject(IFACE, &stimulus)
            .expect("the mock accepts the inject");

        expect_self_echo(source.as_mut(), &stimulus);
        let frame = wait_frame(source.as_mut(), Duration::from_millis(500)).expect("an icmp reply");
        let pkt = captured(frame);
        assert_eq!(icmp_error(&pkt), Some((3, 3)));
        assert!(!tcp_rst(&pkt));
    }

    /// Tester (T5 stage 5): the rate-limiting mock the two amendment-46
    /// differentials rest on answers **at most one ICMP error per window per
    /// target** and is silent in between, and the self-echo is delivered
    /// either way — so a lane test cannot mistake a suppressed error for a
    /// dropped stimulus. Without this the "unpaced reads silence / paced reads
    /// icmp(3,3)" pair would prove nothing about the pace.
    #[test]
    fn icmp_ratelimit_answers_once_per_window() {
        let window = Duration::from_millis(500);
        let backend = MockBackend::new(MockReply::Icmp {
            icmp_type: 3,
            code: 3,
        });
        backend.icmp_ratelimit(window);
        let mut source = backend
            .open_capture(IFACE, None, Duration::from_millis(5))
            .expect("the mock capture opens");
        let stimulus = udp_stimulus(b"probe");

        // The first stimulus of the window draws the port-unreachable.
        backend
            .inject(IFACE, &stimulus)
            .expect("the mock accepts the inject");
        expect_self_echo(source.as_mut(), &stimulus);
        let frame = wait_frame(source.as_mut(), Duration::from_millis(500)).expect("an icmp reply");
        assert_eq!(icmp_error(&captured(frame)), Some((3, 3)));

        // Two more inside the same window: the echo, and nothing behind it.
        for _ in 0..2 {
            backend
                .inject(IFACE, &stimulus)
                .expect("the mock accepts the inject");
            expect_self_echo(source.as_mut(), &stimulus);
            expect_silence(source.as_mut(), Duration::from_millis(20));
        }

        // Past the window the kernel's token is back.
        std::thread::sleep(window);
        backend
            .inject(IFACE, &stimulus)
            .expect("the mock accepts the inject");
        expect_self_echo(source.as_mut(), &stimulus);
        let frame =
            wait_frame(source.as_mut(), Duration::from_millis(500)).expect("the window reopened");
        assert_eq!(icmp_error(&captured(frame)), Some((3, 3)));
        assert_eq!(backend.inject_count(), 4);

        // Unlimited by default: three in a row, three errors.
        let open = MockBackend::new(MockReply::Icmp {
            icmp_type: 3,
            code: 3,
        });
        let mut source = open
            .open_capture(IFACE, None, Duration::from_millis(5))
            .expect("the mock capture opens");
        for _ in 0..3 {
            open.inject(IFACE, &stimulus)
                .expect("the mock accepts the inject");
            expect_self_echo(source.as_mut(), &stimulus);
            let frame =
                wait_frame(source.as_mut(), Duration::from_millis(500)).expect("an icmp reply");
            assert_eq!(icmp_error(&captured(frame)), Some((3, 3)));
        }
    }

    #[test]
    fn rst_mock_resets() {
        let backend = MockBackend::new(MockReply::Rst);
        let mut source = backend
            .open_capture(IFACE, None, Duration::from_millis(5))
            .expect("the mock capture opens");
        let stimulus = tcp_stimulus(b"");
        backend
            .inject(IFACE, &stimulus)
            .expect("the mock accepts the inject");

        expect_self_echo(source.as_mut(), &stimulus);
        let frame = wait_frame(source.as_mut(), Duration::from_millis(500)).expect("a reset reply");
        let pkt = captured(frame);
        assert!(tcp_rst(&pkt));
        assert_eq!(icmp_error(&pkt), None);
        let reply = transport_payload(&pkt).expect("the reply is a tcp segment");
        assert_eq!(reply.src_port, 80);
        assert_eq!(reply.dst_port, 40000);
        assert_eq!(reply.proto, L4Proto::Tcp);
    }

    /// Inject `stimulus` and consume its self-echo, so what follows on the
    /// queue is the target's answer (or nothing).
    fn inject_past_echo(backend: &MockBackend, source: &mut dyn CaptureSource, stimulus: &[u8]) {
        backend
            .inject(IFACE, stimulus)
            .expect("the mock accepts the inject");
        expect_self_echo(source, stimulus);
    }

    #[test]
    fn dies_after_n_goes_silent() {
        let backend = MockBackend::new(MockReply::Echo);
        backend.dies_after_injects(2);
        let mut source = backend
            .open_capture(IFACE, None, Duration::from_millis(5))
            .expect("the mock capture opens");

        for _ in 0..2 {
            inject_past_echo(&backend, source.as_mut(), &udp_stimulus(b"probe"));
            assert!(wait_frame(source.as_mut(), Duration::from_millis(500)).is_some());
        }

        inject_past_echo(&backend, source.as_mut(), &udp_stimulus(b"probe"));
        expect_silence(source.as_mut(), Duration::from_millis(20));

        // It never recovers.
        inject_past_echo(&backend, source.as_mut(), &udp_stimulus(b"probe"));
        expect_silence(source.as_mut(), Duration::from_millis(20));
        assert_eq!(backend.inject_count(), 4);
    }

    #[test]
    fn dies_on_pattern_then_recovers() {
        let trigger = [0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0x00, 0x00];
        let short = [0xde, 0xad, 0xbe, 0xef, 0x00, 0x00];

        let backend = MockBackend::new(MockReply::Echo);
        backend.dies_on_pattern(vec![0xde, 0xad, 0xbe, 0xef], 8, 2, false);
        let mut source = backend
            .open_capture(IFACE, None, Duration::from_millis(5))
            .expect("the mock capture opens");

        // Too short for the trigger: echoed.
        inject_past_echo(&backend, source.as_mut(), &udp_stimulus(&short));
        assert!(wait_frame(source.as_mut(), Duration::from_millis(500)).is_some());

        // The trigger itself and the next two injects are silent.
        inject_past_echo(&backend, source.as_mut(), &udp_stimulus(&trigger));
        expect_silence(source.as_mut(), Duration::from_millis(20));
        for payload in [b"a".as_slice(), b"b".as_slice()] {
            inject_past_echo(&backend, source.as_mut(), &udp_stimulus(payload));
            expect_silence(source.as_mut(), Duration::from_millis(20));
        }

        // The fourth inject after the trigger is answered again.
        inject_past_echo(&backend, source.as_mut(), &udp_stimulus(b"c"));
        assert!(wait_frame(source.as_mut(), Duration::from_millis(500)).is_some());

        // `repeat: false`, so a second trigger is answered.
        inject_past_echo(&backend, source.as_mut(), &udp_stimulus(&trigger));
        assert!(wait_frame(source.as_mut(), Duration::from_millis(500)).is_some());

        // `repeat: true` re-triggers on every match.
        let repeating = MockBackend::new(MockReply::Echo);
        repeating.dies_on_pattern(vec![0xde, 0xad, 0xbe, 0xef], 8, 1, true);
        let mut source = repeating
            .open_capture(IFACE, None, Duration::from_millis(5))
            .expect("the mock capture opens");
        inject_past_echo(&repeating, source.as_mut(), &udp_stimulus(&trigger));
        expect_silence(source.as_mut(), Duration::from_millis(20));
        inject_past_echo(&repeating, source.as_mut(), &udp_stimulus(b"a"));
        expect_silence(source.as_mut(), Duration::from_millis(20));
        inject_past_echo(&repeating, source.as_mut(), &udp_stimulus(b"b"));
        assert!(wait_frame(source.as_mut(), Duration::from_millis(500)).is_some());
        inject_past_echo(&repeating, source.as_mut(), &udp_stimulus(&trigger));
        expect_silence(source.as_mut(), Duration::from_millis(20));
    }

    #[test]
    fn unavailable_mock_fails_closed() {
        let backend = MockBackend::unavailable();
        assert!(matches!(
            backend.open_capture(IFACE, None, Duration::from_millis(5)),
            Err(L4Error::Unavailable(_))
        ));
        assert!(matches!(
            backend.inject(IFACE, &udp_stimulus(b"probe")),
            Err(L4Error::Unavailable(_))
        ));
        assert_eq!(backend.inject_count(), 0);
        assert!(backend.injected().is_empty());
    }

    #[test]
    fn test_job_budget() {
        let job = TestJob::new(ScanProfile::default()).with_budget(2);
        assert!(job.charge(1));
        assert!(job.charge(1));
        assert!(!job.charge(1));
        assert_eq!(job.charged(), 2);
        assert_eq!(job.budget_left(), 0);
        assert_eq!(job.job_id(), "scan-1a2b3c4d");
        assert_eq!(job.marker(), "aitm7f3a");
        assert!(!job.cancelled());
        job.cancel();
        assert!(job.cancelled());

        let deadline = Instant::now() + Duration::from_millis(5);
        let other = TestJob::new(ScanProfile::default())
            .with_job_id("scan-deadbeef")
            .with_deadline(deadline);
        assert_eq!(other.job_id(), "scan-deadbeef");
        assert_eq!(other.deadline(), deadline);
        assert_eq!(other.budget_left(), 10_000);
        // A charge larger than the budget charges nothing.
        assert!(!other.clone().with_budget(3).charge(4));
    }

    #[test]
    fn loopback_guard_authorizes_inject_and_capture() {
        let guard = loopback_guard("*", 100);
        {
            let inject = guard
                .check(
                    L4Action::Inject,
                    &L4Target {
                        interface: IFACE.to_string(),
                        direction: L4Direction::Outbound,
                        dst: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                        dst_port: Some(9),
                        proto: L4Proto::Udp,
                    },
                )
                .expect("the loopback guard authorizes the inject");
            let capture = guard
                .check(
                    L4Action::Capture,
                    &L4Target {
                        interface: IFACE.to_string(),
                        direction: L4Direction::Inbound,
                        dst: None,
                        dst_port: None,
                        proto: L4Proto::Raw,
                    },
                )
                .expect("the loopback guard authorizes the capture");
            assert_eq!(guard.in_flight(), 2);
            drop(inject);
            drop(capture);
        }
        assert_eq!(guard.in_flight(), 0);
        assert_eq!(guard.list_scope().len(), 2);
    }

    /// The harness's reason to exist: a real `send_recv` — which opens the
    /// capture *before* it injects and correlates by the reversed five-tuple —
    /// reads the mock's replies as the lane expects.
    #[test]
    fn send_recv_through_the_mock_classifies_the_reply() {
        let guard = loopback_guard("*", 100);
        let store: Arc<dyn L4FlowStore> = Arc::new(InMemoryL4FlowStore::new());
        let spec = |timeout| SendRecvSpec {
            packet: PacketSpec {
                layers: vec![
                    Layer::Ipv4(Ipv4Spec {
                        src: Some(Ipv4Addr::LOCALHOST),
                        dst: Some(Ipv4Addr::LOCALHOST),
                        ..Ipv4Spec::default()
                    }),
                    Layer::Udp(UdpSpec {
                        src_port: Some(40000),
                        dst_port: Some(9),
                        ..UdpSpec::default()
                    }),
                    Layer::Raw(b"probe".to_vec()),
                ],
            },
            dst: IpAddr::V4(Ipv4Addr::LOCALHOST),
            dst_port: Some(9),
            interface: IFACE.to_string(),
            timeout,
            expect: ReplyMatch::FiveTuple,
        };

        let (_, outcome) = send_recv(
            &guard,
            MockBackend::new(MockReply::Echo),
            Arc::clone(&store),
            spec(Duration::from_millis(500)),
        )
        .expect("the echo send_recv succeeds");
        match outcome {
            SendRecvOutcome::Response(pkt) => {
                let reply = transport_payload(&pkt).expect("a udp reply");
                assert_eq!(reply.payload, b"probe");
                assert_eq!(reply.src_port, 9);
            }
            other => panic!("expected a correlated response, got {other:?}"),
        }

        let (_, outcome) = send_recv(
            &guard,
            MockBackend::new(MockReply::Icmp {
                icmp_type: 3,
                code: 3,
            }),
            Arc::clone(&store),
            spec(Duration::from_millis(500)),
        )
        .expect("the icmp send_recv succeeds");
        match outcome {
            SendRecvOutcome::Other(pkt) => assert_eq!(icmp_error(&pkt), Some((3, 3))),
            other => panic!("expected an icmp error reply, got {other:?}"),
        }

        let (_, outcome) = send_recv(
            &guard,
            MockBackend::new(MockReply::Silence),
            Arc::clone(&store),
            spec(Duration::from_millis(30)),
        )
        .expect("the silent send_recv succeeds");
        assert!(matches!(outcome, SendRecvOutcome::NoResponse { .. }));

        assert!(matches!(
            send_recv(
                &guard,
                MockBackend::unavailable(),
                store,
                spec(Duration::from_millis(30)),
            ),
            Err(L4Error::Unavailable(_))
        ));
        assert_eq!(guard.in_flight(), 0);
    }

    #[test]
    fn profile_helpers_shape() {
        let profile = l4_profile(vec![udp_target(9), tcp_target(80)], 100);
        assert_eq!(profile.lanes, vec![LaneKind::L4Packet]);
        assert_eq!(profile.target.l4.len(), 2);
        assert_eq!(profile.target.l4[0].ip, "127.0.0.1");
        assert_eq!(profile.target.l4[0].port, 9);
        assert_eq!(profile.target.l4[0].proto, L4Transport::Udp);
        assert_eq!(profile.target.l4[0].grammar, None);
        assert_eq!(profile.target.l4[1].port, 80);
        assert_eq!(profile.target.l4[1].proto, L4Transport::Tcp);
        assert_eq!(profile.l4.cases, 100);
        assert_eq!(profile.l4.reproduce_count, 3);
        assert_eq!(profile.l4.liveness_every, 25);
        assert_eq!(profile.l4.consecutive_timeouts, 20);
        assert!(!profile.l4.dry_run);
        assert!(profile.l4.seeds.is_empty());

        let seeded = with_hex_seed(profile, "deadbeef");
        assert_eq!(
            seeded.l4.seeds,
            vec![L4Seed::Hex {
                hex: "deadbeef".to_string()
            }]
        );
        assert_eq!(
            fields(&["ipv4.ttl", "raw"]),
            vec!["ipv4.ttl".to_string(), "raw".to_string()]
        );
    }
}
