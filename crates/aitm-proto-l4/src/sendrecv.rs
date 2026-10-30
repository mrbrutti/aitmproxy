//! Guarded send-and-receive — the L4 analog of replay / `request.send` (M5 Task 8).
//!
//! [`send_recv`] injects one crafted stimulus through the single guarded wire
//! choke point ([`crate::wire::send_on_wire`]) and **awaits the correlated reply
//! within a timeout**, returning a typed [`SendRecvOutcome`] (scapy `sr`/`sr1`).
//! It is the primitive the L4 fuzzing / memory-safety loop drives: mutate a
//! [`PacketSpec`], send it, read the outcome — a [`SendRecvOutcome::NoResponse`]
//! where the target was answering is the candidate crash the agent confirms.
//!
//! It is gated **twice**, like every wire-touching L4 action:
//!
//! 1. **`Inject`**, to send: [`L4Guard::check`](crate::guard::L4Guard::check)
//!    mints an injection [`L4Permit`] (scope + denylist + rate/size/count) — the
//!    only key `send_on_wire` accepts. Deny-by-default: an empty or non-matching
//!    scope refuses before anything reaches the wire (AC1/AC2).
//! 2. **`Capture`**, to receive: a second check authorizes observing the reply on
//!    the interface. Both permits are held for the operation's lifetime.
//!
//! **Fail-closed.** When libpcap / the capture privilege is absent the capture
//! open returns [`L4Error::Unavailable`] and `send_recv` surfaces it without
//! sending (AC17). The `!Send` libpcap source is opened, the stimulus injected,
//! and the reply awaited all on **one dedicated thread** (mirroring the capture
//! task), so the `!Send` handle never crosses a thread boundary and the caller
//! simply joins for the outcome.
//!
//! **Never hangs.** The await is bounded by `spec.timeout`; silence returns
//! [`SendRecvOutcome::NoResponse`] carrying how long it waited (AC11).

use std::net::IpAddr;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use etherparse::{NetSlice, TransportSlice};

use crate::backend::{CaptureInjectBackend, L4Error};
use crate::craft::PacketSpec;
use crate::flow::{L4Bind, L4Flow, L4FlowId, L4FlowKind, L4FlowStore, L4Meta, L4Packet};
use crate::guard::{L4Guard, L4GuardError};
use crate::types::{L4Action, L4Direction, L4Proto, L4Target};
use crate::wire::send_on_wire;

/// How long to block each `next_frame` poll while awaiting a reply — short enough
/// that the timeout deadline is honoured promptly, never longer than the whole
/// timeout itself (and at least 1ms so a zero timeout still polls once).
const REPLY_POLL: Duration = Duration::from_millis(50);

/// A send-and-receive request: a crafted stimulus, where to send it, how long to
/// wait, and how a reply is correlated back to it.
#[derive(Debug, Clone)]
pub struct SendRecvSpec {
    /// The stimulus to craft and inject.
    pub packet: PacketSpec,
    /// The destination host the stimulus targets — also the host a `FiveTuple`
    /// reply must come from.
    pub dst: IpAddr,
    /// The destination port (for Tcp/Udp), matched in `FiveTuple` correlation.
    pub dst_port: Option<u16>,
    /// The interface to inject on and capture the reply from.
    pub interface: String,
    /// How long to await the correlated reply before reporting silence.
    pub timeout: Duration,
    /// How a captured frame is correlated to this stimulus.
    pub expect: ReplyMatch,
}

/// How a captured frame is correlated to the stimulus.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ReplyMatch {
    /// The reply must come from the stimulus destination with the five-tuple
    /// reversed (source host == `dst`, and for Tcp/Udp source port == `dst_port`
    /// and the same protocol). The default.
    #[default]
    FiveTuple,
    /// The reply must come from a specific host, regardless of port/protocol.
    FromHost(IpAddr),
    /// Any decodable reply that is not the stimulus echoed back.
    Any,
}

/// The typed result of a send-and-receive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SendRecvOutcome {
    /// The correlated reply (scapy `sr1`: the first matching answer).
    Response(L4Packet),
    /// Several correlated replies (reserved for batch send-and-receive).
    Responses(Vec<L4Packet>),
    /// A reply from the target that does not match the stimulus — an error or
    /// reset reply (ICMP unreachable, a TCP RST, a wrong-port/protocol answer).
    Other(L4Packet),
    /// No correlated reply arrived within the timeout — silence, the candidate
    /// crash/hang signal. Carries how long the await actually lasted.
    NoResponse {
        /// How long the await lasted before giving up (>= the requested timeout).
        waited: Duration,
    },
}

/// Inject a crafted stimulus through the guarded choke point and await the
/// correlated reply, recording both in a [`L4FlowKind::SendRecv`] flow.
///
/// Returns the flow id (so the caller can fetch the recorded stimulus + reply via
/// `l4.flow.get`) and the typed [`SendRecvOutcome`].
///
/// Authorization precedes any I/O: an `Inject` permit (scope + denylist + rate)
/// and a `Capture` permit are minted up front, so an unauthorized call never
/// reaches the wire. The capture is opened **before** the stimulus is injected so
/// a fast reply is never missed.
///
/// # Errors
/// - [`L4Error::Guard`] if the scope does not grant `Inject` to `dst`
///   (`OutOfL4Scope` / `DangerousDestinationBlocked` / rate caps) or `Capture` on
///   the interface (deny-by-default, AC1/AC2);
/// - [`L4Error::Unavailable`] if libpcap/privilege is absent (fail-closed, AC17);
/// - [`L4Error::WireWrite`] if the stimulus cannot be crafted or the backend
///   fails to put it on the wire.
pub fn send_recv(
    guard: &L4Guard,
    backend: Arc<dyn CaptureInjectBackend>,
    store: Arc<dyn L4FlowStore>,
    spec: SendRecvSpec,
) -> Result<(L4FlowId, SendRecvOutcome), L4Error> {
    // (0) Craft the stimulus up front — a pure, privilege-free step. A spec that
    // cannot be encoded fails before any authorization or I/O.
    let bytes = spec
        .packet
        .build()
        .map_err(|e| L4Error::WireWrite(format!("stimulus craft failed: {e}")))?;

    // C3: the guard must gate the destination actually put on the wire, not the
    // `spec.dst` field. The crafted stimulus carries its own IP layer and the kernel
    // routes by the packet's headers, so resolve the real target from the built bytes
    // (as the intercept-forward path does via `ip_target`) and refuse a stimulus whose
    // destination (or port) contradicts `spec.dst`/`spec.dst_port`, or that carries no
    // decodable IP destination — the latter cannot be proven in scope (deny-by-default).
    let real_target = crate::capture::packet_target(&bytes, &spec.interface, L4Direction::Outbound)
        .ok_or_else(|| {
            L4Error::Guard(L4GuardError::OutOfL4Scope(
                "crafted stimulus has no decodable IP destination; cannot verify scope".into(),
            ))
        })?;
    if real_target.dst != Some(spec.dst) {
        return Err(L4Error::Guard(L4GuardError::OutOfL4Scope(
            real_target
                .dst
                .map_or_else(|| spec.dst.to_string(), |d| d.to_string()),
        )));
    }
    if let Some(p) = spec.dst_port {
        if real_target.dst_port != Some(p) {
            return Err(L4Error::Guard(L4GuardError::OutOfL4Scope(format!(
                "{} (stimulus port {:?} ≠ declared {p})",
                spec.dst, real_target.dst_port
            ))));
        }
    }

    // (1) Authorization precedes any I/O. `Inject` (scope + denylist + rate) to
    // send, checked against the packet's *real* target, then `Capture` on the
    // interface to receive — deny-by-default refuses here, before the capture opens or
    // a byte reaches the wire. Both permits are held for the operation's lifetime
    // (moved into the worker thread).
    let stimulus_proto = spec.packet.transport_proto();
    let inject_permit = guard.check(L4Action::Inject, &real_target)?;

    // A send-and-receive observes the reply arriving on the interface; the bind
    // carries no single destination (mirrors `start_capture`), so the `Capture`
    // entry is matched on interface + inbound direction.
    let capture_target = L4Target {
        interface: spec.interface.clone(),
        direction: L4Direction::Inbound,
        dst: None,
        dst_port: None,
        proto: L4Proto::Raw,
    };
    let capture_permit = guard.check(L4Action::Capture, &capture_target)?;

    let correlation = Correlation {
        dst: spec.dst,
        dst_port: spec.dst_port,
        proto: stimulus_proto,
        expect: spec.expect,
        stimulus: bytes.clone(),
    };
    let poll = spec.timeout.min(REPLY_POLL).max(Duration::from_millis(1));
    let iface = spec.interface;
    let timeout = spec.timeout;

    // The `!Send` libpcap source is opened, the stimulus injected, and the reply
    // awaited all on one dedicated thread: the handle never crosses a boundary and
    // the capture is open *before* the inject, so a fast reply is not missed. The
    // permits move in and are released when the thread (hence the operation) ends.
    // The correlated reply is returned (not recorded here): the capture-scope
    // re-check that gates recording needs the guard, which stays on this thread.
    let worker_iface = iface.clone();
    let worker_store = store.clone();
    let worker = thread::spawn(move || -> Result<(L4FlowId, SendRecvOutcome), L4Error> {
        let mut inject_permit = inject_permit;
        let _capture_permit = capture_permit;

        // Open the capture first (fail-closed on missing privilege/libpcap).
        let mut source = backend.open_capture(&worker_iface, None, poll)?;

        // Send the stimulus through the single guarded choke point.
        send_on_wire(&mut inject_permit, backend.as_ref(), &worker_iface, &bytes)?;

        // The stimulus is on the wire: record it in a fresh SendRecv flow (no stray
        // flow if the open or the inject failed above).
        let flow_id = worker_store.insert(L4Flow {
            id: L4FlowId::new(),
            kind: L4FlowKind::SendRecv,
            bind: L4Bind {
                interface: worker_iface.clone(),
                filter: None,
                queue: None,
            },
            packets: std::collections::VecDeque::new(),
            metadata: L4Meta::default(),
        });
        worker_store.append_packet(flow_id, make_packet(&bytes, L4Direction::Outbound, true));

        // Await the correlated reply, bounded by the timeout — never hangs.
        let outcome = await_reply(source.as_mut(), &correlation, timeout);
        Ok((flow_id, outcome))
    });

    let (flow_id, outcome) = worker
        .join()
        .unwrap_or_else(|_| Err(L4Error::Unavailable("send_recv worker panicked".into())))?;

    // Capture-scope the correlated reply before recording it, exactly as the
    // background capture re-checks every delivered frame (`capture::record_frame`):
    // the bind-time `Capture` permit was minted with `dst: None`, so a reply must
    // still resolve to a `Capture`-authorized target or it is dropped — never
    // recorded. An undecodable reply (no IP target) is likewise not recorded.
    if let SendRecvOutcome::Response(ref pkt) | SendRecvOutcome::Other(ref pkt) = outcome {
        let authorized = crate::capture::packet_target(&pkt.bytes, &iface, L4Direction::Inbound)
            .is_some_and(|t| guard.check(L4Action::Capture, &t).is_ok());
        if authorized {
            store.append_packet(flow_id, pkt.clone());
        }
    }
    Ok((flow_id, outcome))
}

/// Block for up to `timeout` for a frame the `correlation` accepts, polling the
/// source so the deadline is honoured promptly. Returns the matched reply as a
/// typed outcome, or [`SendRecvOutcome::NoResponse`] on silence — it always
/// returns within roughly `timeout`.
fn await_reply(
    source: &mut dyn crate::backend::CaptureSource,
    correlation: &Correlation,
    timeout: Duration,
) -> SendRecvOutcome {
    let start = Instant::now();
    loop {
        if start.elapsed() >= timeout {
            return SendRecvOutcome::NoResponse {
                waited: start.elapsed(),
            };
        }
        match source.next_frame() {
            Ok(Some(frame)) => match correlation.classify(&frame) {
                Classified::Response => {
                    return SendRecvOutcome::Response(make_packet(
                        &frame,
                        L4Direction::Inbound,
                        false,
                    ));
                }
                Classified::Other => {
                    return SendRecvOutcome::Other(make_packet(
                        &frame,
                        L4Direction::Inbound,
                        false,
                    ));
                }
                // Not our reply (our own stimulus echoed, or unrelated traffic) —
                // keep waiting within the deadline.
                Classified::Ignore => {}
            },
            // A poll elapsed with no frame: loop and re-check the deadline.
            Ok(None) => {}
            // A mid-await read error ends the wait fail-closed: report the silence
            // we have rather than hanging or surfacing a wire error after sending.
            Err(_) => {
                return SendRecvOutcome::NoResponse {
                    waited: start.elapsed(),
                };
            }
        }
    }
}

/// How a captured frame is correlated to the stimulus, carrying everything the
/// per-frame decision needs.
struct Correlation {
    dst: IpAddr,
    dst_port: Option<u16>,
    proto: L4Proto,
    expect: ReplyMatch,
    stimulus: Vec<u8>,
}

/// The verdict on one captured frame.
enum Classified {
    /// The correlated reply.
    Response,
    /// A reply from the target that does not correlate (error / reset / wrong
    /// tuple) — reported as [`SendRecvOutcome::Other`].
    Other,
    /// Not a reply to this stimulus — skip it and keep waiting.
    Ignore,
}

impl Correlation {
    fn classify(&self, frame: &[u8]) -> Classified {
        let Some(info) = decode_reply(frame) else {
            return Classified::Ignore;
        };
        match self.expect {
            // Any decodable frame that is not our own stimulus echoed back.
            ReplyMatch::Any => {
                if frame == self.stimulus.as_slice() {
                    Classified::Ignore
                } else {
                    Classified::Response
                }
            }
            // Correlate purely by source host.
            ReplyMatch::FromHost(host) => {
                if info.src == host {
                    Classified::Response
                } else {
                    Classified::Ignore
                }
            }
            // The reversed five-tuple: from the target host, matching port +
            // protocol, and not a reset. Anything else from the host is Other;
            // anything from another host is unrelated.
            ReplyMatch::FiveTuple => {
                if info.src != self.dst {
                    return Classified::Ignore;
                }
                if info.tcp_rst {
                    return Classified::Other;
                }
                let proto_match = info.proto == self.proto;
                let port_match = match self.dst_port {
                    Some(p) if matches!(self.proto, L4Proto::Tcp | L4Proto::Udp) => {
                        info.src_port == Some(p)
                    }
                    _ => true,
                };
                if proto_match && port_match {
                    Classified::Response
                } else {
                    Classified::Other
                }
            }
        }
    }
}

/// What a reply frame carries for correlation: its source address + port, its
/// transport protocol, and whether it is a TCP reset.
struct ReplyInfo {
    src: IpAddr,
    src_port: Option<u16>,
    proto: L4Proto,
    tcp_rst: bool,
}

/// Decode a captured frame to its correlation fields. `None` for a frame with no
/// IP layer (ARP / undecodable) — such a frame cannot correlate to an IP stimulus.
/// Mirrors the link-layer probing in the capture task (our crafted frames start at
/// L3; a NIC delivers L2 Ethernet; BSD loopback prepends a 4-byte AF word).
fn decode_reply(frame: &[u8]) -> Option<ReplyInfo> {
    let parsed = crate::craft::parse_frame(frame)?;
    let src = match parsed.net? {
        NetSlice::Ipv4(ip) => IpAddr::V4(ip.header().source_addr()),
        NetSlice::Ipv6(ip) => IpAddr::V6(ip.header().source_addr()),
        NetSlice::Arp(_) => return None,
    };
    let (src_port, proto, tcp_rst) = match parsed.transport {
        Some(TransportSlice::Tcp(t)) => (Some(t.source_port()), L4Proto::Tcp, t.rst()),
        Some(TransportSlice::Udp(u)) => (Some(u.source_port()), L4Proto::Udp, false),
        Some(TransportSlice::Icmpv4(_)) => (None, L4Proto::Icmp, false),
        Some(TransportSlice::Icmpv6(_)) => (None, L4Proto::IcmpV6, false),
        _ => (None, L4Proto::Raw, false),
    };
    Some(ReplyInfo {
        src,
        src_port,
        proto,
        tcp_rst,
    })
}

/// Build the flow record for a frame: its direction, a structural decode, and
/// whether aitmproxy authored it.
fn make_packet(bytes: &[u8], dir: L4Direction, injected: bool) -> L4Packet {
    L4Packet {
        dir,
        timestamp: SystemTime::now(),
        decoded: PacketSpec::summarize(bytes),
        bytes: bytes.to_vec(),
        injected,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::backend::CaptureSource;
    use crate::config::L4Config;
    use crate::craft::{Ipv4Spec, Layer, UdpSpec};
    use crate::flow::InMemoryL4FlowStore;
    use crate::guard::L4GuardError;
    use crate::types::{IpCidr, L4Capability, L4ScopeEntry, L4ScopeId, PortRange, RateCap};
    use std::collections::VecDeque;
    use std::net::Ipv4Addr;
    use std::sync::Mutex;

    const IFACE: &str = "mock0";

    fn cfg() -> L4Config {
        L4Config::default()
    }

    fn entry(dir: L4Direction, cap: L4Capability) -> L4ScopeEntry {
        L4ScopeEntry {
            id: L4ScopeId::new(),
            cidr: IpCidr {
                addr: "127.0.0.1".parse().unwrap(),
                prefix: 32,
            },
            ports: PortRange {
                lo: 0,
                hi: u16::MAX,
            },
            interface: IFACE.to_string(),
            direction: dir,
            capability: cap,
            inject_rate: RateCap {
                pps: 100,
                burst: 100,
            },
            source: crate::types::L4ScopeSource::Config,
        }
    }

    /// A guard scoped so send_recv can both inject (outbound) and capture the
    /// reply (inbound) on the loopback host.
    fn send_recv_guard() -> L4Guard {
        let g = L4Guard::new(&cfg());
        g.add_scope(entry(L4Direction::Outbound, L4Capability::Inject))
            .unwrap();
        g.add_scope(entry(L4Direction::Inbound, L4Capability::Capture))
            .unwrap();
        g
    }

    fn udp_packet(dst: &str, dst_port: u16, payload: &[u8]) -> PacketSpec {
        PacketSpec {
            layers: vec![
                Layer::Ipv4(Ipv4Spec {
                    dst: Some(dst.parse::<Ipv4Addr>().unwrap()),
                    ..Ipv4Spec::default()
                }),
                Layer::Udp(UdpSpec {
                    dst_port: Some(dst_port),
                    ..UdpSpec::default()
                }),
                Layer::Raw(payload.to_vec()),
            ],
        }
    }

    /// A UDP reply frame: source == `src:src_port`, so it correlates by the
    /// reversed five-tuple of a stimulus sent to `src:src_port`.
    fn udp_reply(src: &str, src_port: u16, payload: &[u8]) -> Vec<u8> {
        PacketSpec {
            layers: vec![
                Layer::Ipv4(Ipv4Spec {
                    src: Some(src.parse::<Ipv4Addr>().unwrap()),
                    dst: Some("127.0.0.1".parse::<Ipv4Addr>().unwrap()),
                    ..Ipv4Spec::default()
                }),
                Layer::Udp(UdpSpec {
                    src_port: Some(src_port),
                    dst_port: Some(40000),
                    ..UdpSpec::default()
                }),
                Layer::Raw(payload.to_vec()),
            ],
        }
        .build()
        .expect("reply builds")
    }

    fn spec(expect: ReplyMatch, timeout: Duration) -> SendRecvSpec {
        SendRecvSpec {
            packet: udp_packet("127.0.0.1", 9, b"probe"),
            dst: "127.0.0.1".parse().unwrap(),
            dst_port: Some(9),
            interface: IFACE.to_string(),
            timeout,
            expect,
        }
    }

    /// A backend that records injected frames and replays a scripted set of reply
    /// frames into the awaiting capture, then idles like a real read timeout.
    /// `available == false` simulates missing privilege/libpcap (fail-closed).
    struct MockBackend {
        available: bool,
        replies: Mutex<Option<Vec<Vec<u8>>>>,
        injected: Mutex<Vec<Vec<u8>>>,
    }

    impl MockBackend {
        fn with_replies(replies: Vec<Vec<u8>>) -> Arc<Self> {
            Arc::new(Self {
                available: true,
                replies: Mutex::new(Some(replies)),
                injected: Mutex::new(Vec::new()),
            })
        }

        fn unavailable() -> Arc<Self> {
            Arc::new(Self {
                available: false,
                replies: Mutex::new(Some(Vec::new())),
                injected: Mutex::new(Vec::new()),
            })
        }

        fn injected(&self) -> Vec<Vec<u8>> {
            self.injected.lock().unwrap().clone()
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
                return Err(L4Error::Unavailable("no privilege (mock)".into()));
            }
            let replies = self.replies.lock().unwrap().take().unwrap_or_default();
            Ok(Box::new(ReplySource {
                frames: replies.into_iter().collect(),
            }))
        }

        fn inject(&self, _iface: &str, bytes: &[u8]) -> Result<(), L4Error> {
            if !self.available {
                return Err(L4Error::Unavailable("no privilege (mock)".into()));
            }
            self.injected.lock().unwrap().push(bytes.to_vec());
            Ok(())
        }
    }

    struct ReplySource {
        frames: VecDeque<Vec<u8>>,
    }

    impl CaptureSource for ReplySource {
        fn next_frame(&mut self) -> Result<Option<Vec<u8>>, L4Error> {
            match self.frames.pop_front() {
                Some(frame) => Ok(Some(frame)),
                None => {
                    thread::sleep(Duration::from_millis(2));
                    Ok(None)
                }
            }
        }
    }

    /// AC10 (hermetic): a correlated UDP reply yields `Response` carrying the
    /// echoed payload, and the flow records stimulus (injected) + reply.
    #[test]
    fn send_recv_response_matches_five_tuple() {
        let g = send_recv_guard();
        let backend = MockBackend::with_replies(vec![udp_reply("127.0.0.1", 9, b"echo")]);
        let store: Arc<dyn L4FlowStore> = Arc::new(InMemoryL4FlowStore::new());

        let (flow_id, outcome) = send_recv(
            &g,
            backend.clone(),
            store.clone(),
            spec(ReplyMatch::FiveTuple, Duration::from_secs(1)),
        )
        .expect("authorized send_recv runs");

        let reply = match outcome {
            SendRecvOutcome::Response(p) => p,
            other => panic!("expected Response, got {other:?}"),
        };
        assert_eq!(reply.decoded.layers, vec!["IPv4", "UDP"]);
        assert!(!reply.injected, "a reply is observed, not injected");

        // The stimulus actually reached the wire once.
        assert_eq!(backend.injected().len(), 1);

        // The flow links the injected stimulus and the observed reply.
        let flow = store.get(flow_id).expect("send_recv flow present");
        assert_eq!(flow.kind, L4FlowKind::SendRecv);
        assert_eq!(flow.packets.len(), 2);
        assert!(flow.packets[0].injected, "stimulus is injected");
        assert_eq!(flow.packets[0].dir, L4Direction::Outbound);
        assert!(!flow.packets[1].injected, "reply is observed");
        assert_eq!(flow.packets[1].dir, L4Direction::Inbound);

        // Both permits released after the operation.
        assert_eq!(g.in_flight(), 0);
    }

    /// AC11 (hermetic): no reply ⇒ `NoResponse { waited >= timeout }`, and the
    /// call returns rather than hanging. The stimulus was still sent + recorded.
    #[test]
    fn send_recv_no_reply_reports_silence() {
        let g = send_recv_guard();
        let backend = MockBackend::with_replies(vec![]);
        let store: Arc<dyn L4FlowStore> = Arc::new(InMemoryL4FlowStore::new());

        let timeout = Duration::from_millis(80);
        let (flow_id, outcome) = send_recv(
            &g,
            backend.clone(),
            store.clone(),
            spec(ReplyMatch::FiveTuple, timeout),
        )
        .expect("authorized send_recv runs");

        match outcome {
            SendRecvOutcome::NoResponse { waited } => {
                assert!(waited >= timeout, "waited {waited:?} < timeout {timeout:?}");
            }
            other => panic!("expected NoResponse, got {other:?}"),
        }
        assert_eq!(
            backend.injected().len(),
            1,
            "silence still sent the stimulus"
        );
        let flow = store.get(flow_id).expect("flow present");
        assert_eq!(flow.packets.len(), 1, "only the stimulus is recorded");
        assert!(flow.packets[0].injected);
        assert_eq!(g.in_flight(), 0);
    }

    /// A reply from the target host but with the wrong port (not the reversed
    /// five-tuple) is `Other`, not `Response`.
    #[test]
    fn send_recv_non_matching_reply_is_other() {
        let g = send_recv_guard();
        let backend = MockBackend::with_replies(vec![udp_reply("127.0.0.1", 99, b"nope")]);
        let store: Arc<dyn L4FlowStore> = Arc::new(InMemoryL4FlowStore::new());

        let (_flow_id, outcome) = send_recv(
            &g,
            backend,
            store,
            spec(ReplyMatch::FiveTuple, Duration::from_secs(1)),
        )
        .expect("runs");

        assert!(
            matches!(outcome, SendRecvOutcome::Other(_)),
            "wrong-port reply from the host is Other, got {outcome:?}"
        );
    }

    /// Panel finding (Minor): a correlated reply is capture-scope re-checked before
    /// it is recorded, exactly as the background capture re-checks each delivered
    /// frame. With `expect = Any` a decodable reply whose target is outside the
    /// `Capture` scope is dropped — the flow records only the stimulus.
    #[test]
    fn send_recv_out_of_scope_reply_not_recorded() {
        // Capture scope is 127.0.0.1/32 (inbound); this reply is addressed to an
        // out-of-scope destination, so the per-reply Capture check must drop it.
        let out_of_scope = PacketSpec {
            layers: vec![
                Layer::Ipv4(Ipv4Spec {
                    src: Some("127.0.0.1".parse().unwrap()),
                    dst: Some("10.9.9.9".parse().unwrap()),
                    ..Ipv4Spec::default()
                }),
                Layer::Udp(UdpSpec {
                    src_port: Some(9),
                    dst_port: Some(40000),
                    ..UdpSpec::default()
                }),
                Layer::Raw(b"nope".to_vec()),
            ],
        }
        .build()
        .expect("reply builds");

        let g = send_recv_guard();
        let backend = MockBackend::with_replies(vec![out_of_scope]);
        let store: Arc<dyn L4FlowStore> = Arc::new(InMemoryL4FlowStore::new());

        let (flow_id, _outcome) = send_recv(
            &g,
            backend,
            store.clone(),
            spec(ReplyMatch::Any, Duration::from_secs(1)),
        )
        .expect("authorized send_recv runs");

        let flow = store.get(flow_id).expect("send_recv flow present");
        assert_eq!(
            flow.packets.len(),
            1,
            "an out-of-scope reply is dropped; only the stimulus is recorded"
        );
        assert!(
            flow.packets[0].injected,
            "the one recorded packet is the injected stimulus"
        );
        assert_eq!(g.in_flight(), 0, "both permits released");
    }

    /// C3 (security): a stimulus whose crafted IP destination is a denylisted host,
    /// sent with an in-scope `spec.dst`, is refused — the guard gates the packet's real
    /// destination, not the `dst` field. Nothing reaches the wire.
    #[test]
    fn send_recv_spec_dst_overrides_param_is_refused() {
        let g = send_recv_guard(); // Inject+Capture scoped to 127.0.0.1/32.
        let backend = MockBackend::with_replies(vec![]);
        let store: Arc<dyn L4FlowStore> = Arc::new(InMemoryL4FlowStore::new());

        // The stimulus crafts a packet to the cloud-metadata denylist address while
        // declaring the in-scope `dst = 127.0.0.1` to satisfy the destination param.
        let spec = SendRecvSpec {
            packet: udp_packet("169.254.169.254", 9, b"probe"),
            dst: "127.0.0.1".parse().unwrap(),
            dst_port: Some(9),
            interface: IFACE.to_string(),
            timeout: Duration::from_secs(1),
            expect: ReplyMatch::FiveTuple,
        };

        let err = send_recv(&g, backend.clone(), store, spec).unwrap_err();
        assert!(
            matches!(err, L4Error::Guard(L4GuardError::OutOfL4Scope(_))),
            "a stimulus dst that contradicts the param must be refused, got {err:?}"
        );
        assert!(backend.injected().is_empty(), "nothing reached the wire");
        assert_eq!(g.in_flight(), 0, "no permit leaks on a refused send_recv");
    }

    /// AC1 deny-by-default: an empty scope refuses send_recv with `OutOfL4Scope`
    /// before any packet is sent.
    #[test]
    fn send_recv_empty_scope_refused() {
        let g = L4Guard::new(&cfg());
        let backend = MockBackend::with_replies(vec![]);
        let store: Arc<dyn L4FlowStore> = Arc::new(InMemoryL4FlowStore::new());

        let err = send_recv(
            &g,
            backend.clone(),
            store,
            spec(ReplyMatch::FiveTuple, Duration::from_secs(1)),
        )
        .unwrap_err();
        assert!(
            matches!(err, L4Error::Guard(L4GuardError::OutOfL4Scope(_))),
            "empty scope must refuse, got {err:?}"
        );
        assert!(backend.injected().is_empty(), "nothing reached the wire");
        assert_eq!(g.in_flight(), 0);
    }

    /// Both `Inject` and `Capture` are required: an inject-only scope (no capture
    /// authorization on the interface) is refused, and nothing is sent.
    #[test]
    fn send_recv_requires_capture_scope() {
        let g = L4Guard::new(&cfg());
        g.add_scope(entry(L4Direction::Outbound, L4Capability::Inject))
            .unwrap();
        let backend = MockBackend::with_replies(vec![]);
        let store: Arc<dyn L4FlowStore> = Arc::new(InMemoryL4FlowStore::new());

        let err = send_recv(
            &g,
            backend.clone(),
            store,
            spec(ReplyMatch::FiveTuple, Duration::from_secs(1)),
        )
        .unwrap_err();
        assert!(
            matches!(err, L4Error::Guard(_)),
            "missing capture scope must refuse, got {err:?}"
        );
        assert!(backend.injected().is_empty(), "nothing reached the wire");
        assert_eq!(g.in_flight(), 0);
    }

    /// AC17 fail-closed: an authorized send_recv whose backend has no privilege/
    /// libpcap surfaces `L4Unavailable` without sending, and releases its permits.
    #[test]
    fn send_recv_fail_closed_without_privilege() {
        let g = send_recv_guard();
        let backend = MockBackend::unavailable();
        let store: Arc<dyn L4FlowStore> = Arc::new(InMemoryL4FlowStore::new());

        let err = send_recv(
            &g,
            backend,
            store,
            spec(ReplyMatch::FiveTuple, Duration::from_secs(1)),
        )
        .unwrap_err();
        assert!(matches!(err, L4Error::Unavailable(_)), "got {err:?}");
        assert_eq!(g.in_flight(), 0, "a failed send_recv releases its permits");
    }

    /// A guard scoped to the whole loopback /8 so a real loopback send_recv can
    /// inject (outbound) and capture the reply (inbound) on `iface`.
    fn loopback_guard(iface: &str) -> L4Guard {
        let g = L4Guard::new(&cfg());
        for (dir, cap) in [
            (L4Direction::Outbound, L4Capability::Inject),
            (L4Direction::Inbound, L4Capability::Capture),
        ] {
            g.add_scope(L4ScopeEntry {
                id: L4ScopeId::new(),
                cidr: IpCidr {
                    addr: "127.0.0.0".parse().unwrap(),
                    prefix: 8,
                },
                ports: PortRange {
                    lo: 0,
                    hi: u16::MAX,
                },
                interface: iface.to_string(),
                direction: dir,
                capability: cap,
                inject_rate: RateCap {
                    pps: 100,
                    burst: 100,
                },
                source: crate::types::L4ScopeSource::Config,
            })
            .unwrap();
        }
        g
    }

    /// Pinned (plan Task 8 / AC10): a scoped loopback UDP echo yields `Response`
    /// with the echoed payload. Privilege-gated — `#[ignore]`d and run only with
    /// `AITM_L4_TESTS=1`; without raw privilege it skips on `L4Unavailable`.
    ///
    /// Linux-only: injection is L2 and the craft layer emits an Ethernet frame,
    /// which matches Linux loopback (`DLT_EN10MB`) but not macOS `lo0` (`DLT_NULL`,
    /// a 4-byte AF header the craft layer does not emit), so macOS is skipped.
    #[test]
    #[ignore = "requires raw-inject/capture privilege; run with AITM_L4_TESTS=1 and -- --ignored"]
    fn send_recv_response() {
        if std::env::var("AITM_L4_TESTS").ok().as_deref() != Some("1") || cfg!(target_os = "macos")
        {
            return;
        }
        use crate::backend::pcap::PcapBackend;
        use crate::craft::EtherSpec;
        use std::net::UdpSocket;

        // A loopback UDP echo responder: it replies from its own port back to the
        // datagram's source — the reversed five-tuple the stimulus expects.
        let echo = UdpSocket::bind("127.0.0.1:0").expect("bind echo");
        let echo_port = echo.local_addr().unwrap().port();
        let responder = thread::spawn(move || {
            let mut buf = [0u8; 2048];
            if let Ok((n, from)) = echo.recv_from(&mut buf) {
                let _ = echo.send_to(&buf[..n], from);
            }
        });

        // Craft an Ethernet/IPv4/UDP stimulus from 127.0.0.1:40000 to the echo port.
        let stimulus = PacketSpec {
            layers: vec![
                Layer::Ether(EtherSpec::default()),
                Layer::Ipv4(Ipv4Spec {
                    src: Some("127.0.0.1".parse().unwrap()),
                    dst: Some("127.0.0.1".parse().unwrap()),
                    ..Ipv4Spec::default()
                }),
                Layer::Udp(UdpSpec {
                    src_port: Some(40000),
                    dst_port: Some(echo_port),
                    ..UdpSpec::default()
                }),
                Layer::Raw(b"probe".to_vec()),
            ],
        };

        let g = loopback_guard("lo");
        let backend: Arc<dyn CaptureInjectBackend> = Arc::new(PcapBackend::new());
        let store: Arc<dyn L4FlowStore> = Arc::new(InMemoryL4FlowStore::new());
        let outcome = match send_recv(
            &g,
            backend,
            store,
            SendRecvSpec {
                packet: stimulus,
                dst: "127.0.0.1".parse().unwrap(),
                dst_port: Some(echo_port),
                interface: "lo".to_string(),
                timeout: Duration::from_secs(2),
                expect: ReplyMatch::FiveTuple,
            },
        ) {
            Ok((_, outcome)) => outcome,
            // No inject/capture privilege here: fail-closed contract, skip cleanly.
            Err(L4Error::Unavailable(_)) => return,
            Err(e) => panic!("unexpected send_recv error: {e:?}"),
        };
        let _ = responder.join();

        match outcome {
            SendRecvOutcome::Response(pkt) => {
                assert!(
                    pkt.bytes.windows(5).any(|w| w == b"probe"),
                    "the echoed payload is carried in the reply"
                );
            }
            other => panic!("expected Response from the echo responder, got {other:?}"),
        }
    }

    /// Pinned (plan Task 8 / AC11): a scoped loopback send_recv with no correlated
    /// responder returns `NoResponse { waited }` after the timeout and never hangs.
    /// Privilege-gated. Correlates on a host (TEST-NET-1) that never appears on
    /// loopback, so no frame ever matches regardless of injection delivery.
    #[test]
    #[ignore = "requires raw-inject/capture privilege; run with AITM_L4_TESTS=1 and -- --ignored"]
    fn send_recv_no_response() {
        if std::env::var("AITM_L4_TESTS").ok().as_deref() != Some("1") {
            return;
        }
        use crate::backend::pcap::PcapBackend;

        let iface = if cfg!(target_os = "macos") {
            "lo0"
        } else {
            "lo"
        };
        let g = loopback_guard(iface);
        let backend: Arc<dyn CaptureInjectBackend> = Arc::new(PcapBackend::new());
        let store: Arc<dyn L4FlowStore> = Arc::new(InMemoryL4FlowStore::new());

        let timeout = Duration::from_millis(300);
        let outcome = match send_recv(
            &g,
            backend,
            store,
            SendRecvSpec {
                packet: udp_packet("127.0.0.1", 9, b"probe"),
                dst: "127.0.0.1".parse().unwrap(),
                dst_port: Some(9),
                interface: iface.to_string(),
                timeout,
                // A host that never sources loopback traffic: nothing can correlate.
                expect: ReplyMatch::FromHost("192.0.2.1".parse().unwrap()),
            },
        ) {
            Ok((_, outcome)) => outcome,
            Err(L4Error::Unavailable(_)) => return,
            Err(e) => panic!("unexpected send_recv error: {e:?}"),
        };

        match outcome {
            SendRecvOutcome::NoResponse { waited } => {
                assert!(waited >= timeout, "waited {waited:?} < timeout {timeout:?}");
            }
            other => panic!("expected NoResponse, got {other:?}"),
        }
    }
}
