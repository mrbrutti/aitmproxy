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
//!
//! **The capture sees the stimulus itself.** A packet capture taps the
//! interface, not one direction of it: on Linux `lo` libpcap delivers the RX
//! copy of the frame we just injected, and macOS `lo0` BPF reports sent frames
//! too, so on a loopback target the first frame the reply capture reads is our
//! own stimulus. Under `FiveTuple` that frame comes "from" the target host with
//! the wrong source port, which once classified it `Other` and ended the await
//! before the real reply arrived (the scanner v2 T5 live proof on Linux saw
//! every case as `protocol_error` and never an echo, an ICMP error or a RST).
//! The correlator therefore ignores, in every match mode, a frame that travels
//! in the stimulus's own direction — same source address and port, same
//! destination address and port, same protocol, whatever link framing the
//! capture delivers it under — and keeps waiting for the reply behind it.

use std::net::IpAddr;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use etherparse::{NetSlice, TransportSlice};

use crate::backend::{CaptureInjectBackend, L4Error};
use crate::craft::{PacketEndpoints, PacketSpec};
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

    // The reply is correlated by the transport *decoded from the built frame*
    // (the same decode the C3 check used), not by the spec's layer list: a stimulus
    // handed over as one pre-built `Raw` frame has no transport layer in its spec
    // yet is an IPv4/UDP (or TCP) packet on the wire, and its reversed five-tuple
    // must still classify `Response` (scanner v2 T5 review, finding T2).
    let correlation = Correlation::new(
        spec.dst,
        spec.dst_port,
        real_target.proto,
        spec.expect,
        bytes.clone(),
    );
    let poll = spec.timeout.min(REPLY_POLL).max(Duration::from_millis(1));
    let iface = spec.interface;
    let timeout = spec.timeout;

    // The reply listener is a recorder, so on a loopback interface it is opened
    // with the kernel-side self-exclusion clause (`not port <bus> …`), exactly as
    // `capture::scope_filter` does for a background capture (L4PAR-AC34, spec
    // §2.1): the core's own frames — the bus's plaintext token line among them —
    // are not even delivered. `L4Guard::admit_frame` in `await_reply` is the
    // authoritative second boundary. `self_exclusion_bpf` is `None` on a
    // non-loopback interface, which is left unfiltered on purpose.
    let reply_filter = guard.self_exclusion_bpf(&iface);

    // The `!Send` libpcap source is opened, the stimulus injected, and the reply
    // awaited all on one dedicated thread: the handle never crosses a boundary and
    // the capture is open *before* the inject, so a fast reply is not missed. The
    // permits move in and are released when the thread (hence the operation) ends.
    // The thread is scoped so it borrows the guard (the self-exclusion choke point
    // every reply frame is asked of), the interface name and the store rather
    // than copies of them. The correlated reply is returned (not recorded here):
    // the capture-scope re-check that gates recording stays with the caller.
    let (flow_id, outcome) = thread::scope(|s| {
        let iface: &str = &iface;
        let store: &dyn L4FlowStore = store.as_ref();
        let worker = s.spawn(move || -> Result<(L4FlowId, SendRecvOutcome), L4Error> {
            let mut inject_permit = inject_permit;
            let _capture_permit = capture_permit;

            // Open the capture first (fail-closed on missing privilege/libpcap).
            let mut source = backend.open_capture(iface, reply_filter.as_deref(), poll)?;

            // Send the stimulus through the single guarded choke point.
            send_on_wire(&mut inject_permit, backend.as_ref(), iface, &bytes)?;

            // The stimulus is on the wire: record it in a fresh SendRecv flow (no
            // stray flow if the open or the inject failed above).
            let flow_id = store.insert(L4Flow {
                id: L4FlowId::new(),
                kind: L4FlowKind::SendRecv,
                bind: L4Bind {
                    interface: iface.to_string(),
                    filter: None,
                    queue: None,
                },
                packets: std::collections::VecDeque::new(),
                metadata: L4Meta::default(),
            });
            store.append_packet(flow_id, make_packet(&bytes, L4Direction::Outbound, true));

            // Await the correlated reply, bounded by the timeout — never hangs.
            let outcome = await_reply(source.as_mut(), guard, iface, &correlation, timeout);
            Ok((flow_id, outcome))
        });
        worker
            .join()
            .unwrap_or_else(|_| Err(L4Error::Unavailable("send_recv worker panicked".into())))
    })?;

    // Capture-scope the correlated reply before recording it, exactly as the
    // background capture re-checks every delivered frame (`capture::record_frame`):
    // the bind-time `Capture` permit was minted with `dst: None`, so a reply must
    // still resolve to a `Capture`-authorized target or it is dropped — never
    // recorded. An undecodable reply (no IP target) is likewise not recorded, and
    // the self-exclusion choke point is asked once more here, so nothing of the
    // core's own reaches the flow whatever the classification above did.
    if let SendRecvOutcome::Response(ref pkt) | SendRecvOutcome::Other(ref pkt) = outcome {
        let authorized = guard.admit_frame(&iface, &pkt.bytes)
            && crate::capture::packet_target(&pkt.bytes, &iface, L4Direction::Inbound)
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
///
/// Every frame is first asked of the self-exclusion choke point
/// ([`L4Guard::admit_frame`]): one the core itself sent or received on
/// `interface` — a loopback frame to or from one of its own listener ports — is
/// ignored before correlation, so it is never a `Response` or `Other`, under any
/// [`ReplyMatch`] (L4PAR-AC34, spec §2.1).
fn await_reply(
    source: &mut dyn crate::backend::CaptureSource,
    guard: &L4Guard,
    interface: &str,
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
            // The core's own traffic is not a reply to anything: skip it before
            // correlation, whatever the match mode, and keep waiting.
            Ok(Some(frame)) if !guard.admit_frame(interface, &frame) => {}
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
    /// The stimulus's own decoded tuple (`src:src_port -> dst:dst_port`,
    /// protocol), decoded once at construction so recognising our looped-back
    /// frame costs no per-frame re-parse of the stimulus.
    stimulus_ends: PacketEndpoints,
    /// The stimulus's transport bytes — everything after its IP header — copied
    /// once at construction. A kernel that puts our frame on the wire for us
    /// (Linux loopback, a header-included raw socket) may rewrite IP header
    /// fields (identification, checksum, a zero source address) but never the
    /// transport, so this is the part of our own frame that comes back verbatim.
    stimulus_transport: Vec<u8>,
    /// Whether the one same-host, portless self-echo has been consumed. The
    /// kernel delivers our injected frame to the capture exactly once per
    /// `send_recv`, so [`Correlation::is_own_stimulus`] claims at most one
    /// transport-equal same-host frame as ours and any further one is a reply.
    /// A `Cell`: `classify` takes `&self` and the correlation is owned by the
    /// one worker thread that awaits the reply (it moves into the thread, so it
    /// needs `Send`, never `Sync`).
    portless_echo_seen: std::cell::Cell<bool>,
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
    fn new(
        dst: IpAddr,
        dst_port: Option<u16>,
        proto: L4Proto,
        expect: ReplyMatch,
        stimulus: Vec<u8>,
    ) -> Self {
        // One decode of the stimulus, over the same parser every captured frame
        // goes through, so the two sides of every comparison are delimited alike.
        let (stimulus_ends, stimulus_transport) = decode_reply(&stimulus)
            .map(|info| (info.ends, info.transport.to_vec()))
            .unwrap_or_default();
        Self {
            dst,
            dst_port,
            proto,
            expect,
            stimulus,
            stimulus_ends,
            stimulus_transport,
            portless_echo_seen: std::cell::Cell::new(false),
        }
    }

    /// Whether the stimulus is portless (ICMP, an unknown protocol) between the
    /// same two addresses — the one shape whose self-echo cannot be told from a
    /// verbatim reply by direction, so it is counted instead.
    fn is_portless_same_host(&self) -> bool {
        let ends = &self.stimulus_ends;
        matches!((ends.src, ends.dst), (Some(src), Some(dst)) if src == dst)
            && !matches!((ends.src_port, ends.dst_port), (Some(_), Some(_)))
    }

    fn classify(&self, frame: &[u8]) -> Classified {
        // Our own stimulus, looped back to the capture that is awaiting its
        // reply (see the module doc), is not a reply under any match mode. The
        // byte-equal check is the cheap first cut; the direction check below is
        // the rule, since the capture may re-frame the copy.
        if frame == self.stimulus.as_slice() {
            // A verbatim copy (macOS BPF) is the one self-echo a same-host
            // portless stimulus gets: mark it consumed, so a verbatim reply
            // behind it is not taken for a second copy of our frame.
            if self.is_portless_same_host() {
                self.portless_echo_seen.set(true);
            }
            return Classified::Ignore;
        }
        let Some(info) = decode_reply(frame) else {
            return Classified::Ignore;
        };
        if self.is_own_stimulus(&info) {
            return Classified::Ignore;
        }
        let ends = &info.ends;
        match self.expect {
            // Any decodable frame that is not our own stimulus echoed back.
            ReplyMatch::Any => Classified::Response,
            // Correlate purely by source host.
            ReplyMatch::FromHost(host) => {
                if ends.src == Some(host) {
                    Classified::Response
                } else {
                    Classified::Ignore
                }
            }
            // The reversed five-tuple: from the target host, matching port +
            // protocol, and not a reset. Anything else from the host is Other;
            // anything from another host is unrelated.
            ReplyMatch::FiveTuple => {
                if ends.src != Some(self.dst) {
                    return Classified::Ignore;
                }
                if info.tcp_rst {
                    return Classified::Other;
                }
                // `self.proto` is the stimulus's `packet_target` protocol, where a
                // frame with no (or an unknown) transport is `Raw`; name the
                // reply's the same way so a raw-protocol stimulus matches its reply.
                let proto_match = ends.proto.unwrap_or(L4Proto::Raw) == self.proto;
                let port_match = match self.dst_port {
                    Some(p) if matches!(self.proto, L4Proto::Tcp | L4Proto::Udp) => {
                        ends.src_port == Some(p)
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

    /// Whether a decoded frame travels in the stimulus's **own direction** —
    /// the same source address and port, the same destination address and
    /// port, the same protocol — and is therefore our injected frame coming
    /// back through the capture, whatever link framing it came back under.
    ///
    /// A TCP/UDP stimulus states its direction with its ports, so this holds on
    /// loopback too (the lane never claims the target's own port as its
    /// source). A portless stimulus (ICMP, an unknown protocol) has only its
    /// addresses: off loopback they differ and still state a direction; on
    /// loopback both ends are the same host and the direction is symmetric, so
    /// the frame is ours when its **transport bytes** are the stimulus's. The
    /// IP header is not compared there: a kernel that sends our frame through a
    /// header-included raw socket (Linux `lo`) fills a zero identification and
    /// recomputes the header checksum, so the looped-back copy is not byte-equal
    /// (the fast path in [`Correlation::classify`] misses it) while its
    /// transport is untouched. A loopback ICMP echo reply differs in its
    /// transport (type 0, another checksum) and still correlates. A frame too
    /// short to carry a transport slice never compares equal.
    ///
    /// The transport comparison is consumed **at most once** per correlation
    /// (`portless_echo_seen`, also set by the byte-equal fast path in
    /// [`Correlation::classify`]): the kernel delivers our injected frame to the
    /// capture exactly once per `send_recv`, so the first transport-equal
    /// same-host frame is the self-echo and any further one is a reply. That
    /// removes the residual the security delta named — a same-host raw service
    /// for a protocol with no type field (IPPROTO 253, say) that echoes the
    /// stimulus verbatim used to be indistinguishable from the self-echo and
    /// was `Ignore`d in every mode. What remains: a reply that reached the
    /// capture **before** our own echo is read from it would be taken for the
    /// echo and the echo for the reply. On loopback that order cannot occur (the
    /// echo is delivered synchronously with the send, ahead of anything the
    /// target answers), which is why the rule is "at most one" and not "the
    /// first one is the echo". The accepted shape on the other side: two
    /// self-echo-shaped frames with no real reply behind them report the second
    /// as the `Response` (pinned by a test).
    fn is_own_stimulus(&self, info: &ReplyInfo<'_>) -> bool {
        let ends = &self.stimulus_ends;
        let (Some(src), Some(dst)) = (ends.src, ends.dst) else {
            return false;
        };
        if info.ends.src != Some(src) || info.ends.dst != Some(dst) || info.ends.proto != ends.proto
        {
            return false;
        }
        match (ends.src_port, ends.dst_port) {
            (Some(src_port), Some(dst_port)) => {
                info.ends.src_port == Some(src_port) && info.ends.dst_port == Some(dst_port)
            }
            _ => {
                if src != dst {
                    return true;
                }
                if info.transport == self.stimulus_transport.as_slice()
                    && !self.portless_echo_seen.get()
                {
                    self.portless_echo_seen.set(true);
                    return true;
                }
                false
            }
        }
    }
}

/// What a reply frame carries for correlation: its endpoints (addresses, ports,
/// transport protocol — the crate's one decode, [`crate::craft::endpoints_of`]),
/// whether it is a TCP reset, and its transport bytes (everything after the IP
/// header, as the parser delimits them).
struct ReplyInfo<'a> {
    ends: PacketEndpoints,
    tcp_rst: bool,
    transport: &'a [u8],
}

/// Decode a captured frame to its correlation fields. `None` for a frame with no
/// IP layer (ARP / undecodable) — such a frame cannot correlate to an IP stimulus.
/// Mirrors the link-layer probing in the capture task (our crafted frames start at
/// L3; a NIC delivers L2 Ethernet; BSD loopback prepends a 4-byte AF word).
fn decode_reply(frame: &[u8]) -> Option<ReplyInfo<'_>> {
    let parsed = crate::craft::parse_frame(frame)?;
    let transport = match parsed.net.as_ref()? {
        NetSlice::Ipv4(ip) => ip.payload().payload,
        NetSlice::Ipv6(ip) => ip.payload().payload,
        NetSlice::Arp(_) => return None,
    };
    let ends = crate::craft::endpoints_of(&parsed);
    if ends.src.is_none() || ends.dst.is_none() {
        return None;
    }
    let tcp_rst = matches!(&parsed.transport, Some(TransportSlice::Tcp(t)) if t.rst());
    Some(ReplyInfo {
        ends,
        tcp_rst,
        transport,
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
    use crate::craft::{Ipv4Spec, Layer, TcpSpec, UdpSpec};
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
        entry_on(IFACE, dir, cap)
    }

    /// A 127.0.0.1/32, all-ports scope entry on `iface`.
    fn entry_on(iface: &str, dir: L4Direction, cap: L4Capability) -> L4ScopeEntry {
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
            interface: iface.to_string(),
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
        send_recv_guard_on(IFACE)
    }

    /// [`send_recv_guard`] on an arbitrary interface name.
    fn send_recv_guard_on(iface: &str) -> L4Guard {
        let g = L4Guard::new(&cfg());
        g.add_scope(entry_on(iface, L4Direction::Outbound, L4Capability::Inject))
            .unwrap();
        g.add_scope(entry_on(iface, L4Direction::Inbound, L4Capability::Capture))
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
        spec_on(IFACE, expect, timeout)
    }

    /// [`spec`] on an arbitrary interface name.
    fn spec_on(iface: &str, expect: ReplyMatch, timeout: Duration) -> SendRecvSpec {
        SendRecvSpec {
            packet: udp_packet("127.0.0.1", 9, b"probe"),
            dst: "127.0.0.1".parse().unwrap(),
            dst_port: Some(9),
            interface: iface.to_string(),
            timeout,
            expect,
        }
    }

    /// A backend that records injected frames and replays a scripted set of reply
    /// frames into the awaiting capture, then idles like a real read timeout.
    /// `available == false` simulates missing privilege/libpcap (fail-closed).
    /// Every `open_capture` records the BPF filter it was handed.
    struct MockBackend {
        available: bool,
        replies: Mutex<Option<Vec<Vec<u8>>>>,
        injected: Mutex<Vec<Vec<u8>>>,
        filters: Mutex<Vec<Option<String>>>,
    }

    impl MockBackend {
        fn with_replies(replies: Vec<Vec<u8>>) -> Arc<Self> {
            Arc::new(Self {
                available: true,
                replies: Mutex::new(Some(replies)),
                injected: Mutex::new(Vec::new()),
                filters: Mutex::new(Vec::new()),
            })
        }

        fn unavailable() -> Arc<Self> {
            Arc::new(Self {
                available: false,
                replies: Mutex::new(Some(Vec::new())),
                injected: Mutex::new(Vec::new()),
                filters: Mutex::new(Vec::new()),
            })
        }

        fn injected(&self) -> Vec<Vec<u8>> {
            self.injected.lock().unwrap().clone()
        }

        /// The BPF filter of each `open_capture`, in call order.
        fn filters(&self) -> Vec<Option<String>> {
            self.filters.lock().unwrap().clone()
        }
    }

    impl CaptureInjectBackend for MockBackend {
        fn open_capture(
            &self,
            _iface: &str,
            filter: Option<&str>,
            _read_timeout: Duration,
        ) -> Result<Box<dyn CaptureSource>, L4Error> {
            self.filters
                .lock()
                .unwrap()
                .push(filter.map(str::to_string));
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

    /// A TCP RST reply frame from `src:src_port` to the stimulus source port, the
    /// kernel's answer for a closed TCP port.
    fn tcp_rst_reply(src: &str, src_port: u16) -> Vec<u8> {
        PacketSpec {
            layers: vec![
                Layer::Ipv4(Ipv4Spec {
                    src: Some(src.parse::<Ipv4Addr>().unwrap()),
                    dst: Some("127.0.0.1".parse::<Ipv4Addr>().unwrap()),
                    ..Ipv4Spec::default()
                }),
                Layer::Tcp(TcpSpec {
                    src_port: Some(src_port),
                    dst_port: Some(40000),
                    // RST (0x04) | ACK (0x10).
                    flags: Some(0x14),
                    ..TcpSpec::default()
                }),
            ],
        }
        .build()
        .expect("rst reply builds")
    }

    /// Scanner v2 T5 review, finding T2 (Minor): a stimulus handed over as one
    /// pre-built frame (`layers: [Raw(bytes)]`, the lane's liveness `probe` replay
    /// and any `l4.send_recv` caller with a ready frame) correlates by the protocol
    /// *decoded from those bytes*, not by the spec's layer list (which says `Raw`).
    /// The reversed five-tuple UDP echo is therefore `Response`, and a TCP RST
    /// from the target to the same stimulus is still `Other`.
    #[test]
    fn raw_wrapped_frame_correlates_by_its_decoded_protocol() {
        // The frame the lane would replay: IPv4/UDP 127.0.0.1:40000 -> 127.0.0.1:9.
        let frame = PacketSpec {
            layers: vec![
                Layer::Ipv4(Ipv4Spec {
                    src: Some("127.0.0.1".parse::<Ipv4Addr>().unwrap()),
                    dst: Some("127.0.0.1".parse::<Ipv4Addr>().unwrap()),
                    ..Ipv4Spec::default()
                }),
                Layer::Udp(UdpSpec {
                    src_port: Some(40000),
                    dst_port: Some(9),
                    ..UdpSpec::default()
                }),
                Layer::Raw(b"probe".to_vec()),
            ],
        }
        .build()
        .expect("stimulus builds");
        assert_eq!(
            PacketSpec::summarize(&frame).layers,
            vec!["IPv4", "UDP"],
            "the pre-built frame is IPv4/UDP on the wire"
        );
        let raw_wrapped = || PacketSpec {
            layers: vec![Layer::Raw(frame.clone())],
        };
        assert_eq!(
            raw_wrapped().transport_proto(),
            L4Proto::Raw,
            "the spec's own layer list cannot name the transport"
        );
        let raw_spec = |expect| SendRecvSpec {
            packet: raw_wrapped(),
            dst: "127.0.0.1".parse().unwrap(),
            dst_port: Some(9),
            interface: IFACE.to_string(),
            // The mock answers instantly, so this bound is only the hermetic
            // ceiling a stalled run would hit: ten seconds, wide enough that a
            // loaded CI box cannot turn a correlation into a Timeout, and the
            // wall time of a passing run is unchanged (security panel 3).
            timeout: Duration::from_secs(10),
            expect,
        };

        // The reversed five-tuple echo (UDP 127.0.0.1:9 -> :40000) is the Response.
        let g = send_recv_guard();
        let backend = MockBackend::with_replies(vec![udp_reply("127.0.0.1", 9, b"echo")]);
        let store: Arc<dyn L4FlowStore> = Arc::new(InMemoryL4FlowStore::new());
        let (flow_id, outcome) = send_recv(
            &g,
            backend.clone(),
            store.clone(),
            raw_spec(ReplyMatch::FiveTuple),
        )
        .expect("authorized send_recv runs");
        let reply = match outcome {
            SendRecvOutcome::Response(p) => p,
            other => panic!("expected the UDP echo as Response, got {other:?}"),
        };
        assert_eq!(reply.decoded.layers, vec!["IPv4", "UDP"]);
        assert!(reply.bytes.windows(4).any(|w| w == b"echo"));
        assert_eq!(
            backend.injected(),
            vec![frame.clone()],
            "the pre-built frame went to the wire byte-for-byte"
        );
        let flow = store.get(flow_id).expect("send_recv flow present");
        assert_eq!(
            flow.packets.len(),
            2,
            "stimulus + correlated reply recorded"
        );
        assert_eq!(g.in_flight(), 0);

        // A TCP RST from the target to the same stimulus is a reaction, not the reply.
        let g = send_recv_guard();
        let backend = MockBackend::with_replies(vec![tcp_rst_reply("127.0.0.1", 9)]);
        let store: Arc<dyn L4FlowStore> = Arc::new(InMemoryL4FlowStore::new());
        let (_flow_id, outcome) = send_recv(&g, backend, store, raw_spec(ReplyMatch::FiveTuple))
            .expect("authorized send_recv runs");
        match outcome {
            SendRecvOutcome::Other(p) => {
                assert_eq!(p.decoded.layers, vec!["IPv4", "TCP"]);
            }
            other => panic!("expected the TCP RST as Other, got {other:?}"),
        }
        assert_eq!(g.in_flight(), 0);
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

    /// The bus port the tests below register as one of the core's own listeners.
    const BUS_PORT: u16 = 27431;

    /// A loopback frame from the bus port to an operator client's ephemeral port —
    /// what the reply capture sees when a client connects while a send_recv waits.
    /// Carries the plaintext token line the bus's first frame carries.
    fn bus_frame() -> Vec<u8> {
        udp_reply("127.0.0.1", BUS_PORT, br#"{"token":"operator-secret"}"#)
    }

    /// L4PAR-AC34 / spec §2.1 (security Critical, second half): the send_recv reply
    /// capture is a recorder, so it asks the one self-exclusion choke point before
    /// it classifies anything. A frame to or from one of the core's own listener
    /// ports on a loopback interface is `Ignore`d — never a `Response`, never
    /// appended to the SendRecv flow — even under `ReplyMatch::Any`, which would
    /// otherwise take the first decodable non-stimulus frame. The genuine reply
    /// behind it is still correlated. The reply listener is also opened with the
    /// kernel-side `not port <bus>` clause.
    #[test]
    fn send_recv_reply_capture_ignores_self_traffic() {
        let g = send_recv_guard_on("lo0");
        g.set_self_ports([BUS_PORT]);
        let backend =
            MockBackend::with_replies(vec![bus_frame(), udp_reply("127.0.0.1", 9, b"echo")]);
        let store: Arc<dyn L4FlowStore> = Arc::new(InMemoryL4FlowStore::new());

        let (flow_id, outcome) = send_recv(
            &g,
            backend.clone(),
            store.clone(),
            spec_on("lo0", ReplyMatch::Any, Duration::from_secs(1)),
        )
        .expect("authorized send_recv runs");

        let reply = match outcome {
            SendRecvOutcome::Response(p) => p,
            other => panic!("expected the genuine reply as Response, got {other:?}"),
        };
        assert!(
            reply.bytes.windows(4).any(|w| w == b"echo"),
            "the Response is the genuine reply, not the bus frame"
        );
        assert!(
            !reply.bytes.windows(5).any(|w| w == b"token"),
            "the bus's token line is never returned as a reply"
        );

        let flow = store.get(flow_id).expect("send_recv flow present");
        assert_eq!(
            flow.packets.len(),
            2,
            "the flow holds the stimulus and the genuine reply only"
        );
        for p in &flow.packets {
            assert!(
                !p.bytes.windows(5).any(|w| w == b"token"),
                "no recorded packet carries the bus's token line: {:?}",
                String::from_utf8_lossy(&p.bytes)
            );
        }

        assert_eq!(
            backend.filters(),
            vec![Some(format!("not port {BUS_PORT}"))],
            "the reply listener is opened with the self-exclusion BPF clause"
        );
        assert_eq!(g.in_flight(), 0);
    }

    /// L4PAR-AC34: with only the core's own frame in the reply window, a
    /// `FiveTuple` send_recv reports silence — the bus frame is not `Other`
    /// (today's classification for a wrong-port frame from the host) and the flow
    /// holds only the stimulus.
    #[test]
    fn send_recv_self_traffic_alone_is_silence() {
        let g = send_recv_guard_on("lo0");
        g.set_self_ports([BUS_PORT]);
        let backend = MockBackend::with_replies(vec![bus_frame()]);
        let store: Arc<dyn L4FlowStore> = Arc::new(InMemoryL4FlowStore::new());

        let timeout = Duration::from_millis(80);
        let (flow_id, outcome) = send_recv(
            &g,
            backend,
            store.clone(),
            spec_on("lo0", ReplyMatch::FiveTuple, timeout),
        )
        .expect("authorized send_recv runs");

        assert!(
            matches!(outcome, SendRecvOutcome::NoResponse { .. }),
            "the core's own frame is never a reply, got {outcome:?}"
        );
        let flow = store.get(flow_id).expect("send_recv flow present");
        assert_eq!(flow.packets.len(), 1, "only the stimulus is recorded");
        assert!(flow.packets[0].injected);
        assert_eq!(g.in_flight(), 0);
    }

    /// An L3 UDP frame from `src:src_port` to `dst:dst_port` — both ends
    /// explicit, so a test can state a direction.
    fn udp_from_to(src: &str, src_port: u16, dst: &str, dst_port: u16, payload: &[u8]) -> Vec<u8> {
        PacketSpec {
            layers: vec![
                Layer::Ipv4(Ipv4Spec {
                    src: Some(src.parse::<Ipv4Addr>().unwrap()),
                    dst: Some(dst.parse::<Ipv4Addr>().unwrap()),
                    ..Ipv4Spec::default()
                }),
                Layer::Udp(UdpSpec {
                    src_port: Some(src_port),
                    dst_port: Some(dst_port),
                    ..UdpSpec::default()
                }),
                Layer::Raw(payload.to_vec()),
            ],
        }
        .build()
        .expect("udp frame builds")
    }

    /// A TCP SYN from 127.0.0.1:40000 to 127.0.0.1:`dst_port`.
    fn tcp_syn_to(dst_port: u16) -> Vec<u8> {
        PacketSpec {
            layers: vec![
                Layer::Ipv4(Ipv4Spec {
                    src: Some("127.0.0.1".parse::<Ipv4Addr>().unwrap()),
                    dst: Some("127.0.0.1".parse::<Ipv4Addr>().unwrap()),
                    ..Ipv4Spec::default()
                }),
                Layer::Tcp(TcpSpec {
                    src_port: Some(40000),
                    dst_port: Some(dst_port),
                    flags: Some(0x02),
                    ..TcpSpec::default()
                }),
            ],
        }
        .build()
        .expect("syn builds")
    }

    /// An ICMPv4 `icmp_type`/`code` from `src` to 127.0.0.1, quoting the head
    /// of `quoted` as a real ICMP error does.
    fn icmp_from(src: &str, icmp_type: u8, code: u8, quoted: &[u8]) -> Vec<u8> {
        use crate::craft::IcmpSpec;
        PacketSpec {
            layers: vec![
                Layer::Ipv4(Ipv4Spec {
                    src: Some(src.parse::<Ipv4Addr>().unwrap()),
                    dst: Some("127.0.0.1".parse::<Ipv4Addr>().unwrap()),
                    ..Ipv4Spec::default()
                }),
                Layer::Icmp(IcmpSpec {
                    icmp_type: Some(icmp_type),
                    code: Some(code),
                    rest_of_header: Some(0),
                    checksum: None,
                }),
                Layer::Raw(quoted.iter().take(28).copied().collect()),
            ],
        }
        .build()
        .expect("icmp builds")
    }

    /// `frame` as the one `Raw` layer of a spec, so exactly those bytes ship —
    /// how the lane hands `send_recv` a mutated case.
    fn raw_spec(
        frame: &[u8],
        dst_port: u16,
        expect: ReplyMatch,
        timeout: Duration,
    ) -> SendRecvSpec {
        SendRecvSpec {
            packet: PacketSpec {
                layers: vec![Layer::Raw(frame.to_vec())],
            },
            dst: "127.0.0.1".parse().unwrap(),
            dst_port: Some(dst_port),
            interface: IFACE.to_string(),
            timeout,
            expect,
        }
    }

    /// T5 live proof (Critical): on a loopback interface the reply capture
    /// inside `send_recv` is handed the **injected stimulus itself** before any
    /// reply (Linux `lo` delivers the RX copy of our own frame; macOS `lo0` BPF
    /// sees sent frames too). Under `FiveTuple` that frame has `src == dst` and
    /// the wrong source port, which classified it `Other` and ended the await
    /// before the real reply arrived. The stimulus must be `Ignore`d in every
    /// mode and the frame behind it correlated: (a) a UDP echo carrying the very
    /// same payload bytes with the ports reversed is the `Response`; (b) an
    /// ICMP 3/3 from the target host is `Other`; (c) a TCP RST is `Other`;
    /// (d) the self-echo alone is silence — the await keeps waiting past it.
    #[test]
    fn loopback_self_echo_is_ignored_and_the_real_reply_correlates() {
        let stimulus = udp_from_to("127.0.0.1", 40000, "127.0.0.1", 9, b"probe");

        // (a) self-echo, then the echo service's reply: identical payload,
        // ports reversed. The Response is the reply, never the echo.
        let echo = udp_reply("127.0.0.1", 9, b"probe");
        assert_ne!(
            echo, stimulus,
            "the echo differs from the stimulus only by direction"
        );
        let g = send_recv_guard();
        let backend = MockBackend::with_replies(vec![stimulus.clone(), echo.clone()]);
        let store: Arc<dyn L4FlowStore> = Arc::new(InMemoryL4FlowStore::new());
        let (flow_id, outcome) = send_recv(
            &g,
            backend.clone(),
            store.clone(),
            raw_spec(&stimulus, 9, ReplyMatch::FiveTuple, Duration::from_secs(10)),
        )
        .expect("authorized send_recv runs");
        match outcome {
            SendRecvOutcome::Response(p) => {
                assert_eq!(p.bytes, echo, "the reply, not the echo");
            }
            other => panic!("(a) expected the UDP echo as Response, got {other:?}"),
        }
        let flow = store.get(flow_id).expect("flow present");
        assert_eq!(
            flow.packets.len(),
            2,
            "stimulus + reply; the self-echo is never recorded"
        );
        assert_eq!(flow.packets[1].bytes, echo);
        assert_eq!(backend.injected(), vec![stimulus.clone()]);
        assert_eq!(g.in_flight(), 0);

        // (b) self-echo, then the kernel's port-unreachable.
        let unreachable = icmp_from("127.0.0.1", 3, 3, &stimulus);
        let g = send_recv_guard();
        let backend = MockBackend::with_replies(vec![stimulus.clone(), unreachable.clone()]);
        let store: Arc<dyn L4FlowStore> = Arc::new(InMemoryL4FlowStore::new());
        let (_, outcome) = send_recv(
            &g,
            backend,
            store,
            raw_spec(&stimulus, 9, ReplyMatch::FiveTuple, Duration::from_secs(10)),
        )
        .expect("authorized send_recv runs");
        match outcome {
            SendRecvOutcome::Other(p) => {
                assert_eq!(p.bytes, unreachable, "the icmp, not the echo");
            }
            other => panic!("(b) expected the ICMP 3/3 as Other, got {other:?}"),
        }

        // (c) a TCP SYN's self-echo, then the closed port's RST.
        let syn = tcp_syn_to(80);
        let rst = tcp_rst_reply("127.0.0.1", 80);
        let g = send_recv_guard();
        let backend = MockBackend::with_replies(vec![syn.clone(), rst.clone()]);
        let store: Arc<dyn L4FlowStore> = Arc::new(InMemoryL4FlowStore::new());
        let (_, outcome) = send_recv(
            &g,
            backend,
            store,
            raw_spec(&syn, 80, ReplyMatch::FiveTuple, Duration::from_secs(10)),
        )
        .expect("authorized send_recv runs");
        match outcome {
            SendRecvOutcome::Other(p) => assert_eq!(p.bytes, rst, "the rst, not the echo"),
            other => panic!("(c) expected the TCP RST as Other, got {other:?}"),
        }

        // (d) only the self-echo: the await lasts the whole window and reports
        // silence, and the flow holds the stimulus alone.
        let g = send_recv_guard();
        let backend = MockBackend::with_replies(vec![stimulus.clone()]);
        let store: Arc<dyn L4FlowStore> = Arc::new(InMemoryL4FlowStore::new());
        let timeout = Duration::from_millis(80);
        let (flow_id, outcome) = send_recv(
            &g,
            backend,
            store.clone(),
            raw_spec(&stimulus, 9, ReplyMatch::FiveTuple, timeout),
        )
        .expect("authorized send_recv runs");
        match outcome {
            SendRecvOutcome::NoResponse { waited } => {
                assert!(waited >= timeout, "waited {waited:?} < timeout {timeout:?}");
            }
            other => panic!("(d) expected NoResponse past the self-echo, got {other:?}"),
        }
        let flow = store.get(flow_id).expect("flow present");
        assert_eq!(flow.packets.len(), 1, "only the stimulus is recorded");
        assert_eq!(g.in_flight(), 0);
    }

    /// The self-echo is recognised by **direction**, not by byte equality: the
    /// capture may deliver our frame under another link framing (here with an
    /// Ethernet header the L3 stimulus did not carry), and it is still our own
    /// `src:src_port -> dst:dst_port`. Under `FromHost(127.0.0.1)`, which
    /// matches on the source host alone, the re-framed echo would otherwise be
    /// the "reply"; the genuine echo behind it must be the `Response` in every
    /// match mode.
    #[test]
    fn self_echo_is_recognised_by_direction_under_every_match_mode() {
        use crate::craft::EtherSpec;
        let stimulus = udp_from_to("127.0.0.1", 40000, "127.0.0.1", 9, b"probe");
        let reframed = PacketSpec {
            layers: vec![
                Layer::Ether(EtherSpec {
                    ethertype: Some(0x0800),
                    ..EtherSpec::default()
                }),
                Layer::Raw(stimulus.clone()),
            ],
        }
        .build()
        .expect("ethernet-framed copy builds");
        assert_ne!(reframed, stimulus);
        assert_eq!(
            PacketSpec::summarize(&reframed).layers,
            vec!["Ethernet", "IPv4", "UDP"],
            "the re-framed copy still decodes to our tuple"
        );
        let echo = udp_reply("127.0.0.1", 9, b"probe");

        for expect in [
            ReplyMatch::FiveTuple,
            ReplyMatch::FromHost("127.0.0.1".parse().unwrap()),
            ReplyMatch::Any,
        ] {
            let g = send_recv_guard();
            let backend = MockBackend::with_replies(vec![reframed.clone(), echo.clone()]);
            let store: Arc<dyn L4FlowStore> = Arc::new(InMemoryL4FlowStore::new());
            let (flow_id, outcome) = send_recv(
                &g,
                backend,
                store.clone(),
                raw_spec(&stimulus, 9, expect, Duration::from_secs(10)),
            )
            .expect("authorized send_recv runs");
            match outcome {
                SendRecvOutcome::Response(p) => {
                    assert_eq!(
                        p.bytes, echo,
                        "{expect:?}: the reply, not the re-framed echo"
                    );
                }
                other => panic!("{expect:?}: expected the echo as Response, got {other:?}"),
            }
            let flow = store.get(flow_id).expect("flow present");
            assert_eq!(flow.packets.len(), 2, "{expect:?}: stimulus + reply only");
            assert_eq!(g.in_flight(), 0);
        }
    }

    /// A portless stimulus (ICMP) has only addresses and protocol to state a
    /// direction. Off loopback that is enough: our `10.0.0.1 -> 10.0.0.2` echo
    /// request is ignored even re-framed, and the `10.0.0.2 -> 10.0.0.1` echo
    /// reply is the `Response`. On loopback both ends are `127.0.0.1`, so the
    /// direction is symmetric and only a byte-equal frame is the self-echo: the
    /// kernel's echo reply (type 0, a different frame) must still correlate.
    #[test]
    fn portless_self_echo_uses_addresses_and_never_swallows_a_loopback_echo_reply() {
        use crate::craft::{EtherSpec, IcmpSpec};
        let icmp = |src: &str, dst: &str, icmp_type: u8| {
            PacketSpec {
                layers: vec![
                    Layer::Ipv4(Ipv4Spec {
                        src: Some(src.parse::<Ipv4Addr>().unwrap()),
                        dst: Some(dst.parse::<Ipv4Addr>().unwrap()),
                        ..Ipv4Spec::default()
                    }),
                    Layer::Icmp(IcmpSpec {
                        icmp_type: Some(icmp_type),
                        code: Some(0),
                        rest_of_header: Some(0x1234_0001),
                        checksum: None,
                    }),
                    Layer::Raw(b"ping".to_vec()),
                ],
            }
            .build()
            .expect("icmp builds")
        };
        let reframe = |frame: &[u8]| {
            PacketSpec {
                layers: vec![
                    Layer::Ether(EtherSpec {
                        ethertype: Some(0x0800),
                        ..EtherSpec::default()
                    }),
                    Layer::Raw(frame.to_vec()),
                ],
            }
            .build()
            .expect("ethernet-framed copy builds")
        };

        // Off loopback.
        let request = icmp("10.0.0.1", "10.0.0.2", 8);
        let reply = icmp("10.0.0.2", "10.0.0.1", 0);
        let c = Correlation::new(
            "10.0.0.2".parse().unwrap(),
            None,
            L4Proto::Icmp,
            ReplyMatch::FiveTuple,
            request.clone(),
        );
        assert!(
            matches!(c.classify(&request), Classified::Ignore),
            "byte-equal echo"
        );
        assert!(
            matches!(c.classify(&reframe(&request)), Classified::Ignore),
            "re-framed echo, same direction"
        );
        assert!(
            matches!(c.classify(&reply), Classified::Response),
            "the echo reply"
        );

        // On loopback.
        let request = icmp("127.0.0.1", "127.0.0.1", 8);
        let reply = icmp("127.0.0.1", "127.0.0.1", 0);
        let c = Correlation::new(
            "127.0.0.1".parse().unwrap(),
            None,
            L4Proto::Icmp,
            ReplyMatch::FiveTuple,
            request.clone(),
        );
        assert!(
            matches!(c.classify(&request), Classified::Ignore),
            "byte-equal echo"
        );
        assert!(
            matches!(c.classify(&reply), Classified::Response),
            "a loopback echo reply differs from the stimulus and is the Response"
        );
    }

    /// An ICMPv4 echo frame of `icmp_type` (8 request / 0 reply), code 0,
    /// id `0x1234` seq 1, payload `ping`, from `src` to `dst`. Like every
    /// crafted frame it ships with IPv4 identification 0.
    fn icmp_echo(src: &str, dst: &str, icmp_type: u8) -> Vec<u8> {
        use crate::craft::IcmpSpec;
        PacketSpec {
            layers: vec![
                Layer::Ipv4(Ipv4Spec {
                    src: Some(src.parse::<Ipv4Addr>().unwrap()),
                    dst: Some(dst.parse::<Ipv4Addr>().unwrap()),
                    ..Ipv4Spec::default()
                }),
                Layer::Icmp(IcmpSpec {
                    icmp_type: Some(icmp_type),
                    code: Some(0),
                    rest_of_header: Some(0x1234_0001),
                    checksum: None,
                }),
                Layer::Raw(b"ping".to_vec()),
            ],
        }
        .build()
        .expect("icmp builds")
    }

    /// `frame` as a Linux header-included raw socket puts it on `lo`: the kernel
    /// fills a zero IPv4 identification (bytes 4..6) and recomputes the header
    /// checksum (bytes 10..12). Nothing after the IP header changes.
    fn kernel_shaped(frame: &[u8]) -> Vec<u8> {
        let mut f = frame.to_vec();
        assert_eq!(&f[4..6], &[0, 0], "crafted frames ship with id 0");
        f[4..6].copy_from_slice(&0xBEEF_u16.to_be_bytes());
        f[10..12].copy_from_slice(&[0, 0]);
        let ihl = usize::from(f[0] & 0x0F) * 4;
        let mut sum: u32 = f[..ihl]
            .chunks(2)
            .map(|w| u32::from(u16::from_be_bytes([w[0], w[1]])))
            .sum();
        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        let check = !u16::try_from(sum).expect("folded to 16 bits");
        f[10..12].copy_from_slice(&check.to_be_bytes());
        assert_ne!(f, frame, "the kernel copy is not byte-equal");
        assert_eq!(f[ihl..], frame[ihl..], "the transport bytes are untouched");
        f
    }

    /// A pre-built portless (ICMP) stimulus to 127.0.0.1 handed over as one
    /// `Raw` layer and declaring no port — how the lane sends a ping.
    fn raw_portless_spec(frame: &[u8], expect: ReplyMatch, timeout: Duration) -> SendRecvSpec {
        SendRecvSpec {
            packet: PacketSpec {
                layers: vec![Layer::Raw(frame.to_vec())],
            },
            dst: "127.0.0.1".parse().unwrap(),
            dst_port: None,
            interface: IFACE.to_string(),
            timeout,
            expect,
        }
    }

    /// The three match modes a loopback stimulus can run under.
    fn loopback_modes() -> [ReplyMatch; 3] {
        [
            ReplyMatch::FiveTuple,
            ReplyMatch::FromHost("127.0.0.1".parse().unwrap()),
            ReplyMatch::Any,
        ]
    }

    /// Security panel M2 (T5 live proof): on Linux `lo` the injected stimulus goes
    /// through a header-included raw socket, and the kernel fills the zero IPv4
    /// identification and recomputes the header checksum before the RX copy
    /// reaches the capture. A portless stimulus (ICMP) to a loopback address is
    /// then neither byte-equal nor directional (`src == dst`), and under
    /// `FiveTuple` our own ping was the "reply". The kernel-shaped copy must be
    /// ignored in every mode and the echo reply (type 0) behind it must still be
    /// the `Response`.
    #[test]
    fn linux_shaped_portless_self_echo_is_ignored() {
        let stimulus = icmp_echo("127.0.0.1", "127.0.0.1", 8);
        let self_echo = kernel_shaped(&stimulus);
        let reply = icmp_echo("127.0.0.1", "127.0.0.1", 0);
        assert_ne!(
            reply[20..],
            stimulus[20..],
            "the echo reply differs from the request past the IP header"
        );

        for expect in loopback_modes() {
            let c = Correlation::new(
                "127.0.0.1".parse().unwrap(),
                None,
                L4Proto::Icmp,
                expect,
                stimulus.clone(),
            );
            assert!(
                matches!(c.classify(&self_echo), Classified::Ignore),
                "{expect:?}: the kernel-shaped self-echo is our own stimulus"
            );
            assert!(
                matches!(c.classify(&reply), Classified::Response),
                "{expect:?}: the echo reply still correlates"
            );

            let g = send_recv_guard();
            let backend = MockBackend::with_replies(vec![self_echo.clone(), reply.clone()]);
            let store: Arc<dyn L4FlowStore> = Arc::new(InMemoryL4FlowStore::new());
            let (flow_id, outcome) = send_recv(
                &g,
                backend.clone(),
                store.clone(),
                raw_portless_spec(&stimulus, expect, Duration::from_secs(5)),
            )
            .expect("authorized send_recv runs");
            match outcome {
                SendRecvOutcome::Response(p) => {
                    assert_eq!(p.bytes, reply, "{expect:?}: the reply, not our own ping");
                    assert!(!p.injected, "{expect:?}: observed, not injected");
                }
                other => panic!("{expect:?}: expected the echo reply as Response, got {other:?}"),
            }
            let flow = store.get(flow_id).expect("flow present");
            assert_eq!(
                flow.packets.len(),
                2,
                "{expect:?}: the stimulus and the reply; the self-echo is not recorded"
            );
            assert_eq!(flow.packets[0].bytes, stimulus);
            assert!(flow.packets[0].injected);
            assert_eq!(flow.packets[1].bytes, reply);
            assert_eq!(backend.injected(), vec![stimulus.clone()]);
            assert_eq!(g.in_flight(), 0);
        }
    }

    /// Security panel M2: the kernel-shaped self-echo with nothing behind it is
    /// silence in every mode — the await runs the whole window and the flow holds
    /// only the injected stimulus.
    #[test]
    fn linux_shaped_portless_self_echo_alone_is_silence() {
        let stimulus = icmp_echo("127.0.0.1", "127.0.0.1", 8);
        let self_echo = kernel_shaped(&stimulus);
        let timeout = Duration::from_millis(80);

        for expect in loopback_modes() {
            let g = send_recv_guard();
            let backend = MockBackend::with_replies(vec![self_echo.clone()]);
            let store: Arc<dyn L4FlowStore> = Arc::new(InMemoryL4FlowStore::new());
            let (flow_id, outcome) = send_recv(
                &g,
                backend.clone(),
                store.clone(),
                raw_portless_spec(&stimulus, expect, timeout),
            )
            .expect("authorized send_recv runs");
            match outcome {
                SendRecvOutcome::NoResponse { waited } => assert!(
                    waited >= timeout,
                    "{expect:?}: waited {waited:?} < timeout {timeout:?}"
                ),
                other => panic!("{expect:?}: expected silence past the self-echo, got {other:?}"),
            }
            let flow = store.get(flow_id).expect("flow present");
            assert_eq!(flow.packets.len(), 1, "{expect:?}: the stimulus alone");
            assert!(flow.packets[0].injected, "{expect:?}: and it is ours");
            assert_eq!(flow.packets[0].bytes, stimulus);
            assert_eq!(backend.injected(), vec![stimulus.clone()]);
            assert_eq!(g.in_flight(), 0);
        }
    }

    /// An IPv4 frame of protocol 253 (an experimental protocol with no type
    /// field: nothing in its transport distinguishes a request from a reply) from
    /// `src` to `dst`, carrying `payload` verbatim, with the IPv4 identification
    /// and TTL the caller names (`None` ⇒ the crafted defaults, id 0 / TTL 64).
    fn raw_proto_frame(
        src: &str,
        dst: &str,
        identification: Option<u16>,
        ttl: Option<u8>,
        payload: &[u8],
    ) -> Vec<u8> {
        PacketSpec {
            layers: vec![
                Layer::Ipv4(Ipv4Spec {
                    src: Some(src.parse::<Ipv4Addr>().unwrap()),
                    dst: Some(dst.parse::<Ipv4Addr>().unwrap()),
                    protocol: Some(253),
                    identification,
                    ttl,
                    ..Ipv4Spec::default()
                }),
                Layer::Raw(payload.to_vec()),
            ],
        }
        .build()
        .expect("raw protocol frame builds")
    }

    /// Run a portless `send_recv` over `frames` under `expect` and assert its
    /// outcome is `Response` whose bytes are `want`, recorded behind the stimulus
    /// as the flow's only other packet.
    fn assert_portless_response(
        stimulus: &[u8],
        frames: Vec<Vec<u8>>,
        want: &[u8],
        expect: ReplyMatch,
    ) {
        let g = send_recv_guard();
        let backend = MockBackend::with_replies(frames);
        let store: Arc<dyn L4FlowStore> = Arc::new(InMemoryL4FlowStore::new());
        let (flow_id, outcome) = send_recv(
            &g,
            backend.clone(),
            store.clone(),
            raw_portless_spec(stimulus, expect, Duration::from_secs(5)),
        )
        .expect("authorized send_recv runs");
        match outcome {
            SendRecvOutcome::Response(p) => {
                assert_eq!(p.bytes, want, "{expect:?}: the reply, not our own frame");
                assert!(!p.injected, "{expect:?}: observed, not injected");
            }
            other => panic!("{expect:?}: expected the reply as Response, got {other:?}"),
        }
        let flow = store.get(flow_id).expect("flow present");
        assert_eq!(
            flow.packets.len(),
            2,
            "{expect:?}: the stimulus and the reply"
        );
        assert_eq!(flow.packets[0].bytes, stimulus);
        assert!(flow.packets[0].injected);
        assert_eq!(flow.packets[1].bytes, want);
        assert_eq!(backend.injected(), vec![stimulus.to_vec()]);
        assert_eq!(g.in_flight(), 0);
    }

    /// Security delta (Minor): a same-host, portless reply whose transport bytes
    /// echo the stimulus verbatim (protocol 253 to a loopback raw echo service:
    /// no type field to flip) was indistinguishable from the self-echo and was
    /// `Ignore`d in every mode. The self-echo arrives exactly once per
    /// `send_recv`, so at most one transport-equal same-host frame is consumed as
    /// ours: the kernel-shaped self-echo (new id, new checksum) is ignored, and
    /// the verbatim reply behind it (its own id and TTL, the same bytes past the
    /// IP header) is the `Response` in all three modes.
    #[test]
    fn verbatim_portless_echo_reply_after_the_self_echo_is_a_response() {
        let stimulus = raw_proto_frame("127.0.0.1", "127.0.0.1", None, None, b"raw-echo");
        let self_echo = kernel_shaped(&stimulus);
        let reply = raw_proto_frame(
            "127.0.0.1",
            "127.0.0.1",
            Some(0x1234),
            Some(63),
            b"raw-echo",
        );
        assert_eq!(
            reply[20..],
            stimulus[20..],
            "the reply's transport is verbatim"
        );
        assert_ne!(reply, self_echo, "but its IP header is the service's own");
        assert_ne!(reply, stimulus);

        for expect in loopback_modes() {
            let c = Correlation::new(
                "127.0.0.1".parse().unwrap(),
                None,
                L4Proto::Raw,
                expect,
                stimulus.clone(),
            );
            assert!(
                matches!(c.classify(&self_echo), Classified::Ignore),
                "{expect:?}: the kernel-shaped self-echo is our own stimulus"
            );
            assert!(
                matches!(c.classify(&reply), Classified::Response),
                "{expect:?}: the verbatim echo reply behind it is the reply"
            );
            assert_portless_response(
                &stimulus,
                vec![self_echo.clone(), reply.clone()],
                &reply,
                expect,
            );
        }
    }

    /// The macOS shape of the same case: BPF returns our frame byte-identical, so
    /// the whole-frame fast path in `classify` consumes the self-echo. That fast
    /// path must also mark the one self-echo as seen, so the verbatim reply behind
    /// it is the `Response` and not taken for a second copy of our frame.
    #[test]
    fn verbatim_portless_echo_reply_after_a_byte_identical_self_echo_is_a_response() {
        let stimulus = raw_proto_frame("127.0.0.1", "127.0.0.1", None, None, b"raw-echo");
        let reply = raw_proto_frame(
            "127.0.0.1",
            "127.0.0.1",
            Some(0x1234),
            Some(63),
            b"raw-echo",
        );
        assert_eq!(
            reply[20..],
            stimulus[20..],
            "the reply's transport is verbatim"
        );
        assert_ne!(reply, stimulus, "but its IP header is the service's own");

        for expect in loopback_modes() {
            let c = Correlation::new(
                "127.0.0.1".parse().unwrap(),
                None,
                L4Proto::Raw,
                expect,
                stimulus.clone(),
            );
            assert!(
                matches!(c.classify(&stimulus), Classified::Ignore),
                "{expect:?}: the byte-identical self-echo is our own stimulus"
            );
            assert!(
                matches!(c.classify(&reply), Classified::Response),
                "{expect:?}: the verbatim echo reply behind it is the reply"
            );
            assert_portless_response(
                &stimulus,
                vec![stimulus.clone(), reply.clone()],
                &reply,
                expect,
            );
        }
    }

    /// The accepted shape of the "at most one" rule: the correlator cannot tell a
    /// second self-echo-shaped frame from a verbatim reply, so when two
    /// kernel-shaped copies of our frame arrive with no real reply behind them,
    /// the second is reported as the `Response`. On a real interface the kernel
    /// delivers our frame to the capture exactly once per inject, so this shape
    /// needs a second party that echoes verbatim — which is a reply.
    #[test]
    fn a_second_self_echo_shaped_frame_is_reported_as_the_response() {
        let stimulus = raw_proto_frame("127.0.0.1", "127.0.0.1", None, None, b"raw-echo");
        let self_echo = kernel_shaped(&stimulus);

        for expect in loopback_modes() {
            let c = Correlation::new(
                "127.0.0.1".parse().unwrap(),
                None,
                L4Proto::Raw,
                expect,
                stimulus.clone(),
            );
            assert!(
                matches!(c.classify(&self_echo), Classified::Ignore),
                "{expect:?}: the first self-echo-shaped frame is consumed as ours"
            );
            assert!(
                matches!(c.classify(&self_echo), Classified::Response),
                "{expect:?}: the second is a reply — the accepted shape of the rule"
            );
            assert_portless_response(
                &stimulus,
                vec![self_echo.clone(), self_echo.clone()],
                &self_echo,
                expect,
            );
        }
    }

    /// Security panel M2, the length guard: a captured frame whose IPv4 header
    /// claims IHL 5 (20 bytes) but carries only 18 has no transport slice to
    /// compare. It is ignored without a panic in every mode, and the reply behind
    /// it still correlates.
    #[test]
    fn truncated_portless_frame_is_ignored_without_panic() {
        let stimulus = icmp_echo("127.0.0.1", "127.0.0.1", 8);
        let truncated = kernel_shaped(&stimulus)[..18].to_vec();
        assert_eq!(truncated[0], 0x45, "IHL 5 claimed, 18 bytes present");
        let reply = icmp_echo("127.0.0.1", "127.0.0.1", 0);

        for expect in loopback_modes() {
            let c = Correlation::new(
                "127.0.0.1".parse().unwrap(),
                None,
                L4Proto::Icmp,
                expect,
                stimulus.clone(),
            );
            assert!(
                matches!(c.classify(&truncated), Classified::Ignore),
                "{expect:?}: a truncated header is not a reply"
            );

            let g = send_recv_guard();
            let backend = MockBackend::with_replies(vec![truncated.clone(), reply.clone()]);
            let store: Arc<dyn L4FlowStore> = Arc::new(InMemoryL4FlowStore::new());
            let (flow_id, outcome) = send_recv(
                &g,
                backend,
                store.clone(),
                raw_portless_spec(&stimulus, expect, Duration::from_secs(5)),
            )
            .expect("authorized send_recv runs");
            match outcome {
                SendRecvOutcome::Response(p) => {
                    assert_eq!(
                        p.bytes, reply,
                        "{expect:?}: the reply behind the truncated frame"
                    );
                }
                other => panic!("{expect:?}: expected the echo reply as Response, got {other:?}"),
            }
            let flow = store.get(flow_id).expect("flow present");
            assert_eq!(
                flow.packets.len(),
                2,
                "{expect:?}: the truncated frame is not recorded"
            );
            assert_eq!(g.in_flight(), 0);
        }
    }

    /// Tester (T5 stage 5, plan Task 1 `send_recv_echoed_stimulus_alone_is_silence`):
    /// a capture that delivers the self-echo and nothing else is **silence in
    /// every match mode** — the await runs the whole window, reports how long it
    /// waited, and the flow holds exactly one packet, the injected stimulus.
    /// `Any` is the mode that would otherwise answer `Response` to any decodable
    /// frame, which on loopback is always our own.
    #[test]
    fn send_recv_echoed_stimulus_alone_is_silence() {
        let stimulus = udp_from_to("127.0.0.1", 40000, "127.0.0.1", 9, b"probe");
        let timeout = Duration::from_millis(80);

        for expect in [
            ReplyMatch::FiveTuple,
            ReplyMatch::FromHost("127.0.0.1".parse().unwrap()),
            ReplyMatch::Any,
        ] {
            let g = send_recv_guard();
            let backend = MockBackend::with_replies(vec![stimulus.clone()]);
            let store: Arc<dyn L4FlowStore> = Arc::new(InMemoryL4FlowStore::new());

            let (flow_id, outcome) = send_recv(
                &g,
                backend.clone(),
                store.clone(),
                raw_spec(&stimulus, 9, expect, timeout),
            )
            .expect("authorized send_recv runs");

            match outcome {
                SendRecvOutcome::NoResponse { waited } => assert!(
                    waited >= timeout,
                    "{expect:?}: waited {waited:?} < timeout {timeout:?}"
                ),
                other => panic!("{expect:?}: expected silence past the self-echo, got {other:?}"),
            }
            let flow = store.get(flow_id).expect("flow present");
            assert_eq!(flow.packets.len(), 1, "{expect:?}: the stimulus alone");
            assert!(flow.packets[0].injected, "{expect:?}: and it is ours");
            assert_eq!(flow.packets[0].bytes, stimulus);
            assert_eq!(backend.injected(), vec![stimulus.clone()]);
            assert_eq!(g.in_flight(), 0);
        }
    }

    /// Tester (plan Task 1 `send_recv_same_direction_frame_is_ignored`): the rule
    /// is the **direction**, not byte equality. A frame that is not our stimulus
    /// byte for byte — a different payload, a different IP id — but still runs
    /// `our src:src_port -> dst:dst_port` over our protocol is a copy of ours
    /// (a re-framed, re-checksummed or retransmitted one) and is ignored in every
    /// mode; the genuine reply behind it is still the `Response`.
    #[test]
    fn send_recv_same_direction_frame_is_ignored() {
        let stimulus = udp_from_to("127.0.0.1", 40000, "127.0.0.1", 9, b"probe");
        // Same tuple, different payload: byte equality cannot catch this one.
        let same_direction = udp_from_to("127.0.0.1", 40000, "127.0.0.1", 9, b"probe-rewritten");
        assert_ne!(same_direction, stimulus);
        let echo = udp_reply("127.0.0.1", 9, b"probe");

        for expect in [
            ReplyMatch::FiveTuple,
            ReplyMatch::FromHost("127.0.0.1".parse().unwrap()),
            ReplyMatch::Any,
        ] {
            // Alone it is silence.
            let g = send_recv_guard();
            let backend = MockBackend::with_replies(vec![same_direction.clone()]);
            let store: Arc<dyn L4FlowStore> = Arc::new(InMemoryL4FlowStore::new());
            let timeout = Duration::from_millis(80);
            let (flow_id, outcome) = send_recv(
                &g,
                backend,
                store.clone(),
                raw_spec(&stimulus, 9, expect, timeout),
            )
            .expect("authorized send_recv runs");
            match outcome {
                SendRecvOutcome::NoResponse { waited } => {
                    assert!(waited >= timeout, "{expect:?}: waited {waited:?}");
                }
                other => panic!("{expect:?}: a same-direction frame is no reply, got {other:?}"),
            }
            assert_eq!(
                store.get(flow_id).expect("flow present").packets.len(),
                1,
                "{expect:?}: nothing of ours is recorded as a reply"
            );

            // Ahead of the real reply it does not end the await either.
            let g = send_recv_guard();
            let backend = MockBackend::with_replies(vec![same_direction.clone(), echo.clone()]);
            let store: Arc<dyn L4FlowStore> = Arc::new(InMemoryL4FlowStore::new());
            let (flow_id, outcome) = send_recv(
                &g,
                backend,
                store.clone(),
                raw_spec(&stimulus, 9, expect, Duration::from_secs(10)),
            )
            .expect("authorized send_recv runs");
            match outcome {
                SendRecvOutcome::Response(p) => {
                    assert_eq!(p.bytes, echo, "{expect:?}: the reply, not our own copy");
                }
                other => panic!("{expect:?}: expected the echo as Response, got {other:?}"),
            }
            let flow = store.get(flow_id).expect("flow present");
            assert_eq!(flow.packets.len(), 2, "{expect:?}: stimulus + reply");
            assert_eq!(flow.packets[1].bytes, echo);
            assert_eq!(g.in_flight(), 0);
        }
    }

    /// Tester (the echo case the self-echo rule must not eat): a legitimate reply
    /// whose source port **is** our destination port and whose destination port
    /// is our source port is the reversed tuple — the only shape a reply can
    /// have — and must correlate even when it carries byte-identical payload.
    /// The documented limit is pinned beside it: a stimulus whose source port
    /// equals the target's port makes its own echo indistinguishable from
    /// itself, so that one reads as silence (the lane's liveness probe uses the
    /// unmutated seed, and `choose_src_port` never picks the target's port, so
    /// no crash follows).
    #[test]
    fn send_recv_reply_on_the_reversed_tuple_is_never_taken_for_the_stimulus() {
        let stimulus = udp_from_to("127.0.0.1", 40000, "127.0.0.1", 9, b"probe");
        // Identical payload, reversed ports: an echo service's answer.
        let echo = udp_from_to("127.0.0.1", 9, "127.0.0.1", 40000, b"probe");

        for expect in [
            ReplyMatch::FiveTuple,
            ReplyMatch::FromHost("127.0.0.1".parse().unwrap()),
            ReplyMatch::Any,
        ] {
            let g = send_recv_guard();
            let backend = MockBackend::with_replies(vec![stimulus.clone(), echo.clone()]);
            let store: Arc<dyn L4FlowStore> = Arc::new(InMemoryL4FlowStore::new());
            let (_, outcome) = send_recv(
                &g,
                backend,
                store,
                raw_spec(&stimulus, 9, expect, Duration::from_secs(10)),
            )
            .expect("authorized send_recv runs");
            match outcome {
                SendRecvOutcome::Response(p) => assert_eq!(
                    p.bytes, echo,
                    "{expect:?}: a reply to our source port is a reply"
                ),
                other => panic!("{expect:?}: expected the echo as Response, got {other:?}"),
            }
        }

        // The documented limit: source port == the target's port.
        let symmetric = udp_from_to("127.0.0.1", 9, "127.0.0.1", 9, b"probe");
        let symmetric_echo = udp_from_to("127.0.0.1", 9, "127.0.0.1", 9, b"probe-back");
        let c = Correlation::new(
            "127.0.0.1".parse().unwrap(),
            Some(9),
            L4Proto::Udp,
            ReplyMatch::FiveTuple,
            symmetric.clone(),
        );
        assert!(
            matches!(c.classify(&symmetric_echo), Classified::Ignore),
            "known limit: a symmetric tuple cannot tell the echo from the stimulus"
        );
    }

    /// Tester (edge cases a capture must survive): the frames a real interface
    /// hands the correlator include empty reads, truncated headers, non-IP link
    /// traffic and an oversized buffer. None of them may panic, none may be
    /// taken for the reply, and the real reply behind them must still correlate
    /// inside the window.
    #[test]
    fn malformed_empty_and_oversized_frames_never_correlate() {
        let stimulus = udp_from_to("127.0.0.1", 40000, "127.0.0.1", 9, b"probe");
        let echo = udp_reply("127.0.0.1", 9, b"probe");
        let junk: Vec<Vec<u8>> = vec![
            Vec::new(),                               // an empty read
            vec![0xFF],                               // one byte
            vec![0x45, 0x00, 0x00],                   // an IPv4 version nibble, nothing else
            vec![0x45; 19],                           // one byte short of an IPv4 header
            vec![0x60; 39],                           // one byte short of an IPv6 header
            vec![0xAA; 1500],                         // a full-MTU frame of noise
            vec![0x00; 65_535],                       // the largest buffer a capture can hand us
            b"\x08\x06arp-ish not a packet".to_vec(), // non-IP link traffic
        ];

        let mut frames = junk.clone();
        frames.push(echo.clone());
        let g = send_recv_guard();
        let backend = MockBackend::with_replies(frames);
        let store: Arc<dyn L4FlowStore> = Arc::new(InMemoryL4FlowStore::new());
        let (flow_id, outcome) = send_recv(
            &g,
            backend,
            store.clone(),
            raw_spec(&stimulus, 9, ReplyMatch::FiveTuple, Duration::from_secs(10)),
        )
        .expect("authorized send_recv runs");
        match outcome {
            SendRecvOutcome::Response(p) => assert_eq!(p.bytes, echo, "the reply, not the noise"),
            other => panic!("expected the echo as Response behind the noise, got {other:?}"),
        }
        let flow = store.get(flow_id).expect("flow present");
        assert_eq!(flow.packets.len(), 2, "no malformed frame is recorded");
        assert_eq!(g.in_flight(), 0);

        // The same noise with nothing behind it is silence, not a reply and not
        // a panic — in every match mode, `Any` included.
        for expect in [
            ReplyMatch::FiveTuple,
            ReplyMatch::FromHost("127.0.0.1".parse().unwrap()),
            ReplyMatch::Any,
        ] {
            let g = send_recv_guard();
            let backend = MockBackend::with_replies(junk.clone());
            let store: Arc<dyn L4FlowStore> = Arc::new(InMemoryL4FlowStore::new());
            let timeout = Duration::from_millis(80);
            let (flow_id, outcome) = send_recv(
                &g,
                backend,
                store.clone(),
                raw_spec(&stimulus, 9, expect, timeout),
            )
            .expect("authorized send_recv runs");
            match outcome {
                SendRecvOutcome::NoResponse { waited } => {
                    assert!(waited >= timeout, "{expect:?}: waited {waited:?}");
                }
                other => panic!("{expect:?}: undecodable noise is not a reply, got {other:?}"),
            }
            assert_eq!(store.get(flow_id).expect("flow present").packets.len(), 1);
            assert_eq!(g.in_flight(), 0);
        }
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
