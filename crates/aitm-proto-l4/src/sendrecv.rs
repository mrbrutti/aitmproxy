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
//!
//! **Correlation is strict: "the same host" is never enough.** A capture is a
//! tap on an interface, so inside its scope filter it carries everyone's
//! traffic, and on loopback every frame's source address is 127.0.0.1 — the
//! core's own bus, the test target's control channel, another job's datagrams.
//! Under [`ReplyMatch::FiveTuple`] a frame is the [`SendRecvOutcome::Response`]
//! only on the **reversed tuple** (from the address and port we probed, back to
//! the address and port we sent from, over the stimulus's protocol), and
//! [`SendRecvOutcome::Other`] only in two shapes — an ICMP error whose *quoted*
//! datagram is our stimulus, or a TCP reset between the same two ports.
//! Everything else is ignored and the await keeps waiting, so real silence
//! stays observable on a busy loopback. Reading "from the target host" as a
//! reaction is what made the packet lane's crash oracle blind: its V-crash job
//! scored 65 `clean` / 35 `protocol_error` and never once `silence`, against a
//! target tcpdump showed answering only 73 of 105 datagrams (task 4b, run 9).

use std::net::IpAddr;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use etherparse::{NetSlice, TransportSlice};

use crate::backend::{CaptureInjectBackend, L4Error};
use crate::craft::{PacketEndpoints, PacketSpec};
use crate::flow::{L4Bind, L4Flow, L4FlowId, L4FlowKind, L4FlowStore, L4Meta, L4Packet};
use crate::guard::{L4Guard, L4GuardError};
use crate::icmp::{icmp_key, icmp_quote, IcmpKey};
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
    /// reversed (source host == `dst`, and for Tcp/Udp source port ==
    /// `dst_port`, destination port == the port we sent from, and the same
    /// protocol). Any other frame is ignored, however near it looks: sharing
    /// the source host proves nothing on a loopback or any shared segment. The
    /// default, and the only mode a crash oracle should use.
    #[default]
    FiveTuple,
    /// The reply must come from a specific host and be addressed back to the
    /// port we sent from, but may be sourced from **any** port — the mode for a
    /// target that answers off another socket than the one probed. Still not
    /// "any frame from that host": an unrelated conversation between two other
    /// ports of the same host is ignored.
    FromHost(IpAddr),
    /// Any decodable reply that is not the stimulus echoed back — the
    /// operator's explicit "show me whatever answers" choice, with no
    /// correlation at all. On a loopback or any shared segment that means the
    /// first unrelated frame inside the capture's filter wins, so this mode
    /// cannot tell a reply from noise and must not drive a crash oracle.
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
    /// For an ICMP / ICMPv6 stimulus that is an informational **request** the
    /// protocol pairs with a reply (echo 8 → 0, timestamp 13 → 14; ICMPv6 echo
    /// 128 → 129), the key the reply must carry: the paired type with the
    /// request's identifier and sequence. `None` for every other stimulus —
    /// and then no frame is the reply of an ICMP stimulus, only an error
    /// quoting it can be its reaction.
    stimulus_icmp_reply: Option<IcmpKey>,
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
        let (stimulus_ends, stimulus_transport, stimulus_icmp_reply) = decode_reply(&stimulus)
            .map(|info| {
                (
                    info.ends,
                    info.transport.to_vec(),
                    info.icmp_key.and_then(IcmpKey::reply_key),
                )
            })
            .unwrap_or_default();
        Self {
            dst,
            dst_port,
            proto,
            expect,
            stimulus,
            stimulus_ends,
            stimulus_transport,
            stimulus_icmp_reply,
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
        // The one variable between the two correlating modes: the host the
        // reply must come from and — under `FiveTuple` — the port too.
        // `FromHost` frees the target's port (a service that answers off an
        // ephemeral socket); everything else is the same rule.
        let (host, port) = match self.expect {
            // Any decodable frame that is not our own stimulus echoed back. The
            // operator's explicit "show me whatever answers" choice.
            ReplyMatch::Any => return Classified::Response,
            ReplyMatch::FiveTuple => (self.dst, self.dst_port),
            ReplyMatch::FromHost(host) => (host, None),
        };
        // The reaction shapes are tested first: a reset carries the reversed
        // tuple too, and an ICMP error quoting our ICMP stimulus carries our
        // protocol — both are reactions, never the reply.
        if self.is_reaction(&info, host, port) {
            Classified::Other
        } else if self.is_reply(&info, host, port) {
            Classified::Response
        } else {
            Classified::Ignore
        }
    }

    /// The stimulus's own source address, when it states one. A crafted frame
    /// may leave the source unspecified (`0.0.0.0` / `::`) for the kernel to
    /// fill, and then it cannot say what address a reply will be addressed to.
    fn our_addr(&self) -> Option<IpAddr> {
        self.stimulus_ends.src.filter(|a| !a.is_unspecified())
    }

    /// The stimulus's own source port, when it has one (TCP / UDP). Port 0 is
    /// a real port here, not "unset": the raw path puts the frame on the wire
    /// verbatim (a header-included socket rewrites no transport field), so a
    /// stimulus sent from port 0 is answered **to port 0** and a reply to any
    /// other local port is someone else's. Only an unspecified *address*
    /// (`0.0.0.0` / `::`, which the kernel does fill) relaxes a pin, in
    /// [`Correlation::our_addr`].
    fn our_port(&self) -> Option<u16> {
        self.stimulus_ends.src_port
    }

    /// Whether the frame comes **from** `host` and, when `port` is given and
    /// the stimulus has ports, from that port: the target half of the reversed
    /// tuple. `FiveTuple` passes the port we probed; `FromHost` passes `None`
    /// and frees it.
    fn is_from(&self, info: &ReplyInfo<'_>, host: IpAddr, port: Option<u16>) -> bool {
        if info.ends.src != Some(host) {
            return false;
        }
        match port {
            Some(p) if matches!(self.proto, L4Proto::Tcp | L4Proto::Udp) => {
                info.ends.src_port == Some(p)
            }
            _ => true,
        }
    }

    /// Whether the frame is addressed **back to us**: to the stimulus's own
    /// source address and port, as far as the stimulus states them.
    fn is_addressed_to_us(&self, info: &ReplyInfo<'_>) -> bool {
        if let Some(our_addr) = self.our_addr() {
            if info.ends.dst != Some(our_addr) {
                return false;
            }
        }
        if let Some(our_port) = self.our_port() {
            if info.ends.dst_port != Some(our_port) {
                return false;
            }
        }
        true
    }

    /// Whether the frame carries the stimulus's protocol. `self.proto` is the
    /// stimulus's `packet_target` protocol, where a frame with no (or an
    /// unknown) transport is `Raw`; the frame's is named the same way so a
    /// raw-protocol stimulus matches its raw-protocol reply.
    fn is_our_proto(&self, info: &ReplyInfo<'_>) -> bool {
        info.ends.proto.unwrap_or(L4Proto::Raw) == self.proto
    }

    /// Whether the frame has the **shape of a reply** over the stimulus's
    /// protocol. For TCP, UDP and a raw protocol that is
    /// [`Correlation::is_our_proto`] alone (the ports and addresses are pinned
    /// by the caller). For an ICMP / ICMPv6 stimulus the protocol is not
    /// enough: ICMP has no ports, so on loopback every ICMP frame between the
    /// two addresses would pass, including an ICMP error about someone else's
    /// datagram (the kernel's port-unreachable for any UDP traffic on `lo`).
    /// The reply to an ICMP message is its **informational twin** — the paired
    /// type carrying the request's identifier and sequence (RFC 792 defines the
    /// two fields for exactly this matching) — and an ICMP *error* is never a
    /// reply: it is a reaction through the quote test or nothing. An ICMP
    /// stimulus with no paired reply type (a crafted error, a type etherparse
    /// does not name) has no reply shape at all, so only silence or a quoting
    /// error can be observed for it.
    fn is_our_protos_reply(&self, info: &ReplyInfo<'_>) -> bool {
        if !self.is_our_proto(info) {
            return false;
        }
        match self.proto {
            L4Proto::Icmp | L4Proto::IcmpV6 => {
                matches!((self.stimulus_icmp_reply, info.icmp_key), (Some(want), Some(got)) if want == got)
            }
            _ => true,
        }
    }

    /// The **only** shape a reply to our stimulus can have: from `host` (and
    /// under `FiveTuple` from the port we probed), back to the address and
    /// port we sent from, over the stimulus's protocol — for ICMP, its
    /// informational twin ([`Correlation::is_our_protos_reply`]). For a
    /// portless stimulus (ICMP, an unknown IP protocol) the port pins are
    /// moot and addresses and protocol carry the rule.
    ///
    /// "Same host" is deliberately not enough, in either mode. On loopback
    /// every frame's source address is 127.0.0.1, so accepting a frame on its
    /// source address alone reads the core's own bus traffic, another cell's
    /// datagrams and the test target's HTTP control channel as the target's
    /// answer — which is how the packet lane scored every case
    /// `clean`/`protocol_error` and never once observed the silence a crash
    /// shows up as (task 4b, rig run 9). `FromHost` frees the target's source
    /// port only; the frame must still be addressed back to the port we sent
    /// from.
    fn is_reply(&self, info: &ReplyInfo<'_>, host: IpAddr, port: Option<u16>) -> bool {
        self.is_from(info, host, port)
            && self.is_addressed_to_us(info)
            && self.is_our_protos_reply(info)
    }

    /// The two frames that are a reaction to our stimulus without being a reply
    /// to it ([`SendRecvOutcome::Other`]), and nothing else:
    ///
    /// (a) an ICMP error whose **quoted** datagram is our stimulus
    /// ([`Correlation::quote_is_our_stimulus`]). The quote is what makes the
    /// test sound, and the concrete reason it exists is the loopback hazard
    /// that produced the wrong reading: our stimulus carries a crafted source
    /// port no socket is bound to, so every time the target answers it the
    /// **kernel** sends an ICMP port-unreachable *to the target*, and the
    /// capture sees that error on the same loopback. Its quoted packet is the
    /// target's datagram — our tuple reversed — so without reading the quote
    /// the error would be taken for the target reacting to us, and a healthy
    /// echo service would score a protocol_error on every case. The error's
    /// own source address is not checked: a TTL-exceeded legitimately comes
    /// from a router that is not the target.
    ///
    /// (b) a TCP reset from `host` (and under `FiveTuple` from the port we
    /// probed) back to the port we sent from — a closed TCP port's answer **to
    /// a TCP stimulus**. Sequence and ack numbers are not checked (a kernel
    /// RST to a crafted SYN need not be in any window we track), but the
    /// endpoints and the stimulus's protocol are: a reset belonging to another
    /// loopback conversation is not ours, and a UDP probe cannot be reset, so
    /// a RST on a UDP stimulus's ports is another conversation's whatever its
    /// ports say.
    fn is_reaction(&self, info: &ReplyInfo<'_>, host: IpAddr, port: Option<u16>) -> bool {
        if let Some(quote) = info.icmp_quote {
            if self.quote_is_our_stimulus(&quote) {
                return true;
            }
        }
        self.proto == L4Proto::Tcp
            && info.tcp_rst
            && self.is_from(info, host, port)
            && self.is_addressed_to_us(info)
    }

    /// Whether an ICMP error's quoted inner packet is the stimulus we sent:
    /// same source, same destination, same protocol, and — when we sent ports —
    /// a quote that carries our ports. The pins are the stimulus's own
    /// (`self.dst:self.dst_port` is where we sent it) in **both** modes:
    /// `FromHost` frees the port the target answers *from*, never the port we
    /// sent *to*, so a quote of a datagram from our port to another port of
    /// the host is about another probe, not ours. A real kernel always quotes
    /// 8 transport bytes (RFC 792), a whole UDP header and enough of a TCP one
    /// to carry both ports; but the frame is wire-controlled, so anything on
    /// the segment can emit a bare-header quote with no ports, and on loopback
    /// both addresses are 127.0.0.1 and tell nothing. So a quote that does not
    /// carry our ports is **not** our stimulus — not "not disqualifying" —
    /// which is what separates our error from the kernel's port-unreachable
    /// for the target's reply (same addresses, only the ports differ) and what
    /// stops a hostile bare-header quote from turning the crash oracle's
    /// silence into a reaction. A portless stimulus (ICMP, an unknown
    /// protocol) has no ports to match, so the address-and-protocol rule
    /// stands on its own there.
    fn quote_is_our_stimulus(&self, quote: &PacketEndpoints) -> bool {
        if quote.dst != Some(self.dst) || quote.proto.unwrap_or(L4Proto::Raw) != self.proto {
            return false;
        }
        if let Some(our_addr) = self.our_addr() {
            if quote.src != Some(our_addr) {
                return false;
            }
        }
        if let Some(p) = self.dst_port {
            if quote.dst_port != Some(p) {
                return false;
            }
        }
        if let Some(our_port) = self.our_port() {
            if quote.src_port != Some(our_port) {
                return false;
            }
        }
        true
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
/// whether it is a TCP reset, its transport bytes (everything after the IP
/// header, as the parser delimits them) and, for an ICMP error, the endpoints
/// of the datagram it quotes.
struct ReplyInfo<'a> {
    ends: PacketEndpoints,
    tcp_rst: bool,
    transport: &'a [u8],
    /// The endpoints of the packet an ICMP error quotes — the offending
    /// datagram the error is *about*. `None` for every non-error ICMP type and
    /// for a quote too short or too malformed to read. The correlator accepts
    /// an ICMP error as a reaction to our stimulus only when this is our
    /// stimulus, which is what keeps the kernel's port-unreachable for the
    /// *target's* reply (same addresses, reversed ports) out of the result.
    icmp_quote: Option<PacketEndpoints>,
    /// The key of an ICMP **informational** message — its type with the
    /// identifier and sequence the protocol defines for pairing a request with
    /// its reply. `None` for an ICMP error, a type etherparse does not name
    /// and every non-ICMP transport. An ICMP stimulus's reply must carry the
    /// key [`IcmpKey::reply_key`] derives from the stimulus's own.
    icmp_key: Option<IcmpKey>,
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
        icmp_quote: icmp_quote(&parsed.transport),
        icmp_key: icmp_key(&parsed.transport),
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

    /// The hermetic UDP stimulus: from port 40000 (the port [`udp_reply`]
    /// answers to — a stimulus that stated no source port would go on the
    /// wire from port 0 and be answered there) to `dst:dst_port`.
    fn udp_packet(dst: &str, dst_port: u16, payload: &[u8]) -> PacketSpec {
        PacketSpec {
            layers: vec![
                Layer::Ipv4(Ipv4Spec {
                    dst: Some(dst.parse::<Ipv4Addr>().unwrap()),
                    ..Ipv4Spec::default()
                }),
                Layer::Udp(UdpSpec {
                    src_port: Some(40000),
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

    /// Task 4b (was `send_recv_non_matching_reply_is_other`): a frame from the
    /// target **host** whose source port is not the port we probed is not the
    /// reversed five-tuple, is neither of the two reaction shapes, and is
    /// therefore `Ignore`d — the await keeps waiting and reports silence. Under
    /// the old rule it was `Other`, which on a busy loopback made every
    /// unrelated frame a "protocol error" from the target.
    #[test]
    fn send_recv_non_matching_reply_is_ignored() {
        let g = send_recv_guard();
        let backend = MockBackend::with_replies(vec![udp_reply("127.0.0.1", 99, b"nope")]);
        let store: Arc<dyn L4FlowStore> = Arc::new(InMemoryL4FlowStore::new());

        let timeout = Duration::from_millis(80);
        let (flow_id, outcome) = send_recv(
            &g,
            backend,
            store.clone(),
            spec(ReplyMatch::FiveTuple, timeout),
        )
        .expect("runs");

        match outcome {
            SendRecvOutcome::NoResponse { waited } => {
                assert!(waited >= timeout, "waited {waited:?} < timeout {timeout:?}");
            }
            other => panic!("a wrong-port frame from the host is not a reply, got {other:?}"),
        }
        assert_eq!(
            store.get(flow_id).expect("flow present").packets.len(),
            1,
            "only the stimulus is recorded"
        );
        assert_eq!(g.in_flight(), 0);
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
    /// from the target to a raw-wrapped TCP SYN is still `Other` (a RST answers
    /// a TCP stimulus only — for the UDP frame it is `Ignore`, pinned by
    /// `a_reset_is_a_reaction_only_to_a_tcp_stimulus`).
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

        // A TCP RST from the target to a raw-wrapped TCP SYN (127.0.0.1:40000 ->
        // :9, decoded as TCP from the bytes) is a reaction, not the reply.
        let syn = tcp_syn_to(9);
        let raw_syn_spec = SendRecvSpec {
            packet: PacketSpec {
                layers: vec![Layer::Raw(syn.clone())],
            },
            dst: "127.0.0.1".parse().unwrap(),
            dst_port: Some(9),
            interface: IFACE.to_string(),
            timeout: Duration::from_secs(10),
            expect: ReplyMatch::FiveTuple,
        };
        let g = send_recv_guard();
        let backend = MockBackend::with_replies(vec![tcp_rst_reply("127.0.0.1", 9)]);
        let store: Arc<dyn L4FlowStore> = Arc::new(InMemoryL4FlowStore::new());
        let (_flow_id, outcome) =
            send_recv(&g, backend, store, raw_syn_spec).expect("authorized send_recv runs");
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

    /// An L3 TCP frame from `src:src_port` to `dst:dst_port` with `flags` —
    /// both ends explicit, so a test can state an unrelated conversation.
    fn tcp_from_to(src: &str, src_port: u16, dst: &str, dst_port: u16, flags: u8) -> Vec<u8> {
        PacketSpec {
            layers: vec![
                Layer::Ipv4(Ipv4Spec {
                    src: Some(src.parse::<Ipv4Addr>().unwrap()),
                    dst: Some(dst.parse::<Ipv4Addr>().unwrap()),
                    ..Ipv4Spec::default()
                }),
                Layer::Tcp(TcpSpec {
                    src_port: Some(src_port),
                    dst_port: Some(dst_port),
                    flags: Some(flags),
                    ..TcpSpec::default()
                }),
            ],
        }
        .build()
        .expect("tcp frame builds")
    }

    /// The lane's UDP stimulus on loopback: 127.0.0.1:40000 -> 127.0.0.1:9.
    fn lane_stimulus() -> Vec<u8> {
        udp_from_to("127.0.0.1", 40000, "127.0.0.1", 9, b"probe")
    }

    /// A correlation for [`lane_stimulus`], as `send_recv` builds it.
    fn lane_correlation(expect: ReplyMatch) -> Correlation {
        Correlation::new(
            "127.0.0.1".parse().unwrap(),
            Some(9),
            L4Proto::Udp,
            expect,
            lane_stimulus(),
        )
    }

    /// Run `frames` through a `FiveTuple` `send_recv` for [`lane_stimulus`] and
    /// return the outcome together with the recorded flow's packet count.
    fn lane_run(frames: Vec<Vec<u8>>, timeout: Duration) -> (SendRecvOutcome, usize) {
        lane_run_as(frames, ReplyMatch::FiveTuple, timeout)
    }

    /// [`lane_run`] under an arbitrary match mode.
    fn lane_run_as(
        frames: Vec<Vec<u8>>,
        expect: ReplyMatch,
        timeout: Duration,
    ) -> (SendRecvOutcome, usize) {
        let stimulus = lane_stimulus();
        let g = send_recv_guard();
        let backend = MockBackend::with_replies(frames);
        let store: Arc<dyn L4FlowStore> = Arc::new(InMemoryL4FlowStore::new());
        let (flow_id, outcome) = send_recv(
            &g,
            backend,
            store.clone(),
            raw_spec(&stimulus, 9, expect, timeout),
        )
        .expect("authorized send_recv runs");
        let packets = store.get(flow_id).expect("flow present").packets.len();
        assert_eq!(g.in_flight(), 0);
        (outcome, packets)
    }

    /// Task 4b (Critical, rig run 9): on a busy loopback every frame's source
    /// address is 127.0.0.1, so "the frame came from the target host" is no
    /// evidence at all. A bus-like TCP segment between two ports that are
    /// neither end of our stimulus must be `Ignore`d — under the old rule it was
    /// `Other`, which the lane's oracle read as `protocol_error` and which made
    /// real silence unobservable (the V-crash job scored 65 clean / 35
    /// protocol_error and never one `silence`).
    #[test]
    fn an_unrelated_tcp_frame_on_loopback_is_ignored_under_five_tuple() {
        // A client connecting to the core's bus: SYN/ACK 127.0.0.1:8080 -> :51000.
        let bus = tcp_from_to("127.0.0.1", 8080, "127.0.0.1", 51000, 0x12);
        assert!(
            matches!(
                lane_correlation(ReplyMatch::FiveTuple).classify(&bus),
                Classified::Ignore
            ),
            "an unrelated loopback TCP segment is not our target's reaction"
        );

        let timeout = Duration::from_millis(80);
        let (outcome, packets) = lane_run(vec![bus], timeout);
        match outcome {
            SendRecvOutcome::NoResponse { waited } => {
                assert!(waited >= timeout, "waited {waited:?} < timeout {timeout:?}");
            }
            other => panic!("expected silence past the unrelated frame, got {other:?}"),
        }
        assert_eq!(packets, 1, "the flow holds the stimulus alone");
    }

    /// The same for UDP: another cell's datagram between 127.0.0.1:53 and
    /// 127.0.0.1:34567 shares only the host with our stimulus and is ignored.
    #[test]
    fn an_unrelated_udp_frame_from_another_port_is_ignored() {
        let other_cell = udp_from_to("127.0.0.1", 53, "127.0.0.1", 34567, b"not-ours");
        assert!(
            matches!(
                lane_correlation(ReplyMatch::FiveTuple).classify(&other_cell),
                Classified::Ignore
            ),
            "a datagram between two foreign ports is not our reply"
        );

        let timeout = Duration::from_millis(80);
        let (outcome, packets) = lane_run(vec![other_cell], timeout);
        assert!(
            matches!(outcome, SendRecvOutcome::NoResponse { .. }),
            "expected silence, got {outcome:?}"
        );
        assert_eq!(packets, 1);
    }

    /// The loopback hazard the quoted-packet test closes: our stimulus carries a
    /// crafted source port no socket is bound to, so when the target answers it
    /// the kernel replies to **the target** with an ICMP port-unreachable. That
    /// error quotes the target's datagram (127.0.0.1:9 -> 127.0.0.1:40000, the
    /// reverse of ours), so it is the kernel reacting to the target, never the
    /// target reacting to us, and must be ignored — otherwise a perfectly
    /// healthy echo service scores a protocol_error on every case.
    #[test]
    fn the_kernels_port_unreachable_for_the_targets_echo_reply_is_not_our_reaction() {
        let targets_reply = udp_from_to("127.0.0.1", 9, "127.0.0.1", 40000, b"probe");
        let kernel_unreachable = icmp_from("127.0.0.1", 3, 3, &targets_reply);
        assert!(
            matches!(
                lane_correlation(ReplyMatch::FiveTuple).classify(&kernel_unreachable),
                Classified::Ignore
            ),
            "an ICMP error quoting the reversed packet is not our stimulus's error"
        );

        let timeout = Duration::from_millis(80);
        let (outcome, packets) = lane_run(vec![kernel_unreachable], timeout);
        assert!(
            matches!(outcome, SendRecvOutcome::NoResponse { .. }),
            "expected silence, got {outcome:?}"
        );
        assert_eq!(packets, 1);
    }

    /// The shape that **is** ours: an ICMP 3/3 whose quoted datagram is our own
    /// stimulus (127.0.0.1:40000 -> 127.0.0.1:9 udp). It is `Other`, and the
    /// lane's oracle reads `icmp(3,3)` off the recorded packet.
    #[test]
    fn an_icmp_error_quoting_our_stimulus_is_the_reaction() {
        let unreachable = icmp_from("127.0.0.1", 3, 3, &lane_stimulus());
        assert!(
            matches!(
                lane_correlation(ReplyMatch::FiveTuple).classify(&unreachable),
                Classified::Other
            ),
            "an ICMP error quoting our stimulus is the target's reaction"
        );

        let (outcome, packets) = lane_run(vec![unreachable.clone()], Duration::from_secs(10));
        match outcome {
            SendRecvOutcome::Other(p) => {
                assert_eq!(p.bytes, unreachable);
                assert_eq!(
                    crate::icmp::icmp_error(&p),
                    Some((3, 3)),
                    "the oracle reads the port-unreachable pair"
                );
            }
            other => panic!("expected the ICMP 3/3 as Other, got {other:?}"),
        }
        assert_eq!(packets, 2, "stimulus + the reaction");
    }

    /// A closed TCP port's reset is `Other` only when it comes **from the port
    /// we probed back to the port we sent from**; a reset belonging to another
    /// loopback conversation is ignored.
    #[test]
    fn a_reset_from_the_target_port_is_the_reaction() {
        let syn = tcp_syn_to(9);
        let c = Correlation::new(
            "127.0.0.1".parse().unwrap(),
            Some(9),
            L4Proto::Tcp,
            ReplyMatch::FiveTuple,
            syn.clone(),
        );
        let ours = tcp_from_to("127.0.0.1", 9, "127.0.0.1", 40000, 0x14);
        assert!(
            matches!(c.classify(&ours), Classified::Other),
            "the probed port's RST is the reaction"
        );
        let foreign = tcp_from_to("127.0.0.1", 1234, "127.0.0.1", 51000, 0x14);
        assert!(
            matches!(c.classify(&foreign), Classified::Ignore),
            "another conversation's RST is not our reaction"
        );

        let g = send_recv_guard();
        let backend = MockBackend::with_replies(vec![foreign.clone(), ours.clone()]);
        let store: Arc<dyn L4FlowStore> = Arc::new(InMemoryL4FlowStore::new());
        let (_, outcome) = send_recv(
            &g,
            backend,
            store,
            raw_spec(&syn, 9, ReplyMatch::FiveTuple, Duration::from_secs(10)),
        )
        .expect("authorized send_recv runs");
        match outcome {
            SendRecvOutcome::Other(p) => assert_eq!(p.bytes, ours, "our RST, not the foreign one"),
            other => panic!("expected the RST as Other, got {other:?}"),
        }
        assert_eq!(g.in_flight(), 0);
    }

    /// The positive the strict rule must not lose: with unrelated loopback
    /// traffic ahead of it, the target's echo reply is still the `Response` and
    /// the flow holds the stimulus and that reply only.
    #[test]
    fn a_real_echo_reply_still_correlates_on_a_busy_loopback() {
        let bus = tcp_from_to("127.0.0.1", 8080, "127.0.0.1", 51000, 0x12);
        let other_cell = udp_from_to("127.0.0.1", 53, "127.0.0.1", 34567, b"not-ours");
        let echo = udp_from_to("127.0.0.1", 9, "127.0.0.1", 40000, b"probe");

        let (outcome, packets) =
            lane_run(vec![bus, other_cell, echo.clone()], Duration::from_secs(10));
        match outcome {
            SendRecvOutcome::Response(p) => assert_eq!(p.bytes, echo, "the echo, not the noise"),
            other => panic!("expected the echo as Response, got {other:?}"),
        }
        assert_eq!(packets, 2, "stimulus + reply");
    }

    /// Amendment 66, positive (UDP): the reversed five-tuple echo from the port
    /// we probed is the `Response` — the strict rule drops no real reply.
    #[test]
    fn a_udp_echo_reply_from_the_target_port_is_the_response() {
        let echo = udp_from_to("127.0.0.1", 9, "127.0.0.1", 40000, b"probe");
        assert!(
            matches!(
                lane_correlation(ReplyMatch::FiveTuple).classify(&echo),
                Classified::Response
            ),
            "the reversed five-tuple is the reply"
        );
        let (outcome, packets) = lane_run(vec![echo.clone()], Duration::from_secs(10));
        match outcome {
            SendRecvOutcome::Response(p) => assert_eq!(p.bytes, echo),
            other => panic!("expected the UDP echo as Response, got {other:?}"),
        }
        assert_eq!(packets, 2);
    }

    /// Amendment 66, positive (TCP): a listening port's SYN-ACK from the port we
    /// probed back to the port we sent from is the `Response` — not `Other`
    /// (which would read as a protocol_error) and not `Ignore`.
    #[test]
    fn a_tcp_syn_ack_from_the_target_port_is_the_response() {
        let syn = tcp_syn_to(9);
        let c = Correlation::new(
            "127.0.0.1".parse().unwrap(),
            Some(9),
            L4Proto::Tcp,
            ReplyMatch::FiveTuple,
            syn.clone(),
        );
        let syn_ack = tcp_from_to("127.0.0.1", 9, "127.0.0.1", 40000, 0x12);
        assert!(
            matches!(c.classify(&syn_ack), Classified::Response),
            "a listening port's SYN-ACK is the reply"
        );

        let g = send_recv_guard();
        let backend = MockBackend::with_replies(vec![syn_ack.clone()]);
        let store: Arc<dyn L4FlowStore> = Arc::new(InMemoryL4FlowStore::new());
        let (flow_id, outcome) = send_recv(
            &g,
            backend,
            store.clone(),
            raw_spec(&syn, 9, ReplyMatch::FiveTuple, Duration::from_secs(10)),
        )
        .expect("authorized send_recv runs");
        match outcome {
            SendRecvOutcome::Response(p) => assert_eq!(p.bytes, syn_ack),
            other => panic!("expected the SYN-ACK as Response, got {other:?}"),
        }
        assert_eq!(store.get(flow_id).expect("flow present").packets.len(), 2);
        assert_eq!(g.in_flight(), 0);
    }

    /// `FromHost` is the mode for a target that answers from **another port**:
    /// the frame must come from the host and be addressed back to the port we
    /// sent from, but its source port is free. `FiveTuple` ignores the same
    /// frame, and a frame addressed to a foreign port is ignored in both.
    #[test]
    fn from_host_accepts_a_reply_from_another_port_that_five_tuple_ignores() {
        let from_another_port = udp_from_to("127.0.0.1", 1234, "127.0.0.1", 40000, b"probe");
        let host = ReplyMatch::FromHost("127.0.0.1".parse().unwrap());
        assert!(
            matches!(
                lane_correlation(host).classify(&from_another_port),
                Classified::Response
            ),
            "FromHost correlates a reply sourced from another port"
        );
        assert!(
            matches!(
                lane_correlation(ReplyMatch::FiveTuple).classify(&from_another_port),
                Classified::Ignore
            ),
            "FiveTuple requires the reversed tuple"
        );

        let to_a_foreign_port = udp_from_to("127.0.0.1", 53, "127.0.0.1", 34567, b"not-ours");
        assert!(
            matches!(
                lane_correlation(host).classify(&to_a_foreign_port),
                Classified::Ignore
            ),
            "FromHost still requires the frame to be addressed back to us"
        );

        let (outcome, packets) = lane_run_as(
            vec![to_a_foreign_port, from_another_port.clone()],
            host,
            Duration::from_secs(10),
        );
        match outcome {
            SendRecvOutcome::Response(p) => assert_eq!(p.bytes, from_another_port),
            other => panic!("expected the other-port reply as Response, got {other:?}"),
        }
        assert_eq!(packets, 2);
    }

    /// Quality panel (Important): `FromHost` relaxes the port the target
    /// *answers from*, not the port we *sent to*. An ICMP error's quote is our
    /// stimulus — sent from our address and port to `host:dst_port` — so the
    /// quoted destination port is pinned in both modes. A quote of a datagram
    /// from our port to **another** port of the host (another cell's probe, or
    /// the same socket probing port 7) is not about our stimulus and is
    /// `Ignore`d under `FromHost` exactly as under `FiveTuple`.
    ///
    /// Mutation: drop the `dst_port` pin from the one quote predicate (or
    /// resurrect a `FromHost` copy without it) and the `FromHost` half reads
    /// `Other`.
    #[test]
    fn from_host_quote_check_pins_the_destination_port_too() {
        let to_another_port = udp_from_to("127.0.0.1", 40000, "127.0.0.1", 7, b"probe");
        let unreachable = icmp_from("127.0.0.1", 3, 3, &to_another_port);
        let host = ReplyMatch::FromHost("127.0.0.1".parse().unwrap());
        assert!(
            matches!(
                lane_correlation(host).classify(&unreachable),
                Classified::Ignore
            ),
            "FromHost: a quote of our port to another port of the host is not our stimulus"
        );
        assert!(
            matches!(
                lane_correlation(ReplyMatch::FiveTuple).classify(&unreachable),
                Classified::Ignore
            ),
            "FiveTuple: the same"
        );
        let ours = icmp_from("127.0.0.1", 3, 3, &lane_stimulus());
        assert!(
            matches!(lane_correlation(host).classify(&ours), Classified::Other),
            "FromHost: the quote of our stimulus to host:9 is the reaction"
        );
    }

    // --- Tester (stage 5), amendment 66: the edges of the strict rule -------
    //
    // The lane's crash oracle reads silence, so every frame the correlator
    // accepts that is not really a reaction to our stimulus destroys a
    // reading. The tests below walk the shapes a busy loopback (and a hostile
    // target) can put in front of the capture.

    /// An ICMPv4 `ty`/`code` from `src` to `dst` quoting `quoted` **verbatim**,
    /// so a test can state a quote of any length (including one cut shorter
    /// than the 8 transport bytes a real error carries). [`icmp_from`] always
    /// quotes 28 bytes to 127.0.0.1; this one states both ends and the length.
    fn icmp_quoting(src: &str, dst: &str, ty: u8, code: u8, quoted: &[u8]) -> Vec<u8> {
        use crate::craft::IcmpSpec;
        PacketSpec {
            layers: vec![
                Layer::Ipv4(Ipv4Spec {
                    src: Some(src.parse::<Ipv4Addr>().unwrap()),
                    dst: Some(dst.parse::<Ipv4Addr>().unwrap()),
                    ..Ipv4Spec::default()
                }),
                Layer::Icmp(IcmpSpec {
                    icmp_type: Some(ty),
                    code: Some(code),
                    rest_of_header: Some(0),
                    checksum: None,
                }),
                Layer::Raw(quoted.to_vec()),
            ],
        }
        .build()
        .expect("icmp builds")
    }

    /// Amendment 66, the `Other` shape whose source is deliberately **not**
    /// checked: an ICMP error quoting our stimulus is the reaction to it
    /// wherever it comes from. A router's TTL-exceeded (type 11) is sourced
    /// from the router, not from the target we probed, and a port-unreachable
    /// may be relayed the same way; dropping it would lose the one reading
    /// that explains why the target never answered.
    ///
    /// Mutation: add `info.ends.src == Some(self.dst)` to
    /// `is_reaction_to_our_stimulus`'s quote branch and both halves fail.
    #[test]
    fn an_icmp_error_from_a_third_host_quoting_our_stimulus_is_the_reaction() {
        let c = lane_correlation(ReplyMatch::FiveTuple);
        let ttl_exceeded = icmp_quoting("10.0.0.1", "127.0.0.1", 11, 0, &lane_stimulus());
        assert!(
            matches!(c.classify(&ttl_exceeded), Classified::Other),
            "a router's TTL-exceeded quoting our stimulus is a reaction to it"
        );
        let relayed_unreachable = icmp_quoting("10.0.0.1", "127.0.0.1", 3, 1, &lane_stimulus());
        assert!(
            matches!(c.classify(&relayed_unreachable), Classified::Other),
            "a host-unreachable from a gateway quoting our stimulus is a reaction too"
        );
    }

    /// The other side of the quote test: an ICMP error that quotes *some*
    /// datagram of ours-looking shape but not our stimulus is `Ignore`, so the
    /// await keeps waiting and silence survives. Three ways to differ, each on
    /// its own: the quoted destination port (another port of the same target),
    /// the quoted source port (another local socket's datagram) and the quoted
    /// protocol (a TCP segment where we sent UDP).
    ///
    /// Mutation: drop the `dst_port` comparison in `quote_is_our_stimulus` and
    /// the first case reads `Other`; drop the `src_port` one and the second
    /// does; drop the `proto` one and the third does.
    #[test]
    fn an_icmp_error_quoting_another_datagram_is_ignored() {
        let c = lane_correlation(ReplyMatch::FiveTuple);

        let another_port = udp_from_to("127.0.0.1", 40000, "127.0.0.1", 7, b"probe");
        assert!(
            matches!(
                c.classify(&icmp_quoting("127.0.0.1", "127.0.0.1", 3, 3, &another_port)),
                Classified::Ignore
            ),
            "an error about port 7 is not an error about the port 9 we probed"
        );

        let another_socket = udp_from_to("127.0.0.1", 40001, "127.0.0.1", 9, b"probe");
        assert!(
            matches!(
                c.classify(&icmp_quoting(
                    "127.0.0.1",
                    "127.0.0.1",
                    3,
                    3,
                    &another_socket
                )),
                Classified::Ignore
            ),
            "an error about another local port's datagram is not ours"
        );

        let another_proto = tcp_from_to("127.0.0.1", 40000, "127.0.0.1", 9, 0x02);
        assert!(
            matches!(
                c.classify(&icmp_quoting(
                    "127.0.0.1",
                    "127.0.0.1",
                    3,
                    3,
                    &another_proto
                )),
                Classified::Ignore
            ),
            "an error about a TCP segment is not an error about our UDP stimulus"
        );
    }

    /// A quote is wire-derived and hostile: a truncated or garbage one must
    /// never panic, and `send_recv` must still finish. `quoted_endpoints`
    /// bounds-checks every read, so a quote with no IP header at all, with a
    /// header cut mid-way, or with fewer than the four bytes that carry the
    /// port pair all decode to "no correlation" rather than crashing.
    ///
    /// What each length does:
    /// * 0, 1, 19 bytes — no readable IP header, so no quote: `Ignore`.
    /// * garbage bytes — the same.
    /// * 24 bytes (header + the 4 bytes carrying both ports) — the ports are
    ///   read and compared, so our stimulus's head is `Other` and another
    ///   datagram's head is `Ignore`.
    /// * 20..=23 bytes (header, fewer than 4 transport bytes) — the quote
    ///   carries no ports. **Tester finding F1, now fixed:** our stimulus has
    ///   ports, so a quote that does not carry ours is not our stimulus and is
    ///   `Ignore`d. A real kernel always quotes 8 transport bytes (RFC 792);
    ///   the frame is wire-controlled, so anything on the segment could emit a
    ///   bare-header quote, and on loopback the addresses alone tell nothing —
    ///   accepting it would turn the crash oracle's silence into a reaction.
    ///
    /// Mutation: make any read in `quoted_endpoints` unchecked (`quote[..4]`,
    /// `&quote[v4.slice().len()..]`) and the short cases panic instead.
    #[test]
    fn a_truncated_or_garbage_icmp_quote_never_panics() {
        let c = lane_correlation(ReplyMatch::FiveTuple);
        let stimulus = lane_stimulus();
        let reversed = udp_from_to("127.0.0.1", 9, "127.0.0.1", 40000, b"probe");

        for len in [0_usize, 1, 8, 19] {
            let cut: Vec<u8> = stimulus.iter().take(len).copied().collect();
            assert!(
                matches!(
                    c.classify(&icmp_quoting("127.0.0.1", "127.0.0.1", 3, 3, &cut)),
                    Classified::Ignore
                ),
                "a {len}-byte quote carries no readable packet and correlates to nothing"
            );
        }
        assert!(
            matches!(
                c.classify(&icmp_quoting("127.0.0.1", "127.0.0.1", 3, 3, &[0xFF; 12])),
                Classified::Ignore
            ),
            "a garbage quote correlates to nothing"
        );

        // 24 bytes: the IP header plus exactly the port pair — the shortest
        // quote the port test can read, and it does read it.
        let ours_24: Vec<u8> = stimulus.iter().take(24).copied().collect();
        assert!(
            matches!(
                c.classify(&icmp_quoting("127.0.0.1", "127.0.0.1", 3, 3, &ours_24)),
                Classified::Other
            ),
            "a 24-byte quote of our stimulus still names both ports"
        );
        let theirs_24: Vec<u8> = reversed.iter().take(24).copied().collect();
        assert!(
            matches!(
                c.classify(&icmp_quoting("127.0.0.1", "127.0.0.1", 3, 3, &theirs_24)),
                Classified::Ignore
            ),
            "a 24-byte quote of the target's reply is still not ours"
        );

        // 20..=23 bytes: no port pair. Tester finding F1, now fixed — a quote
        // the ports cannot be read from is not our stimulus, because our
        // stimulus carries ports and this quote does not. On loopback the
        // addresses tell nothing, so a wire-controlled bare-header quote of the
        // reversed packet no longer reads as ours: `Ignore`, silence survives.
        for len in 20..=23_usize {
            let theirs: Vec<u8> = reversed.iter().take(len).copied().collect();
            assert!(
                matches!(
                    c.classify(&icmp_quoting("127.0.0.1", "127.0.0.1", 3, 3, &theirs)),
                    Classified::Ignore
                ),
                "finding F1: a {len}-byte port-less quote is not our ported stimulus"
            );
        }

        // Whatever a quote says, the await ends: no panic, no hang.
        let timeout = Duration::from_millis(80);
        let (outcome, packets) = lane_run(
            vec![icmp_quoting("127.0.0.1", "127.0.0.1", 3, 3, &[])],
            timeout,
        );
        assert!(
            matches!(outcome, SendRecvOutcome::NoResponse { .. }),
            "expected silence past an empty quote, got {outcome:?}"
        );
        assert_eq!(packets, 1, "the flow holds the stimulus alone");
    }

    /// Tester finding F1 (amendment 66): our stimulus carries ports, so an ICMP
    /// error whose quote the ports cannot be read from is **not** our reaction.
    /// A real kernel quotes 8 transport bytes (RFC 792), but the frame is
    /// wire-controlled — anything on the segment can emit a bare-header quote,
    /// and on loopback both addresses are 127.0.0.1 so the quote's addresses
    /// prove nothing. Accepting it would turn the crash oracle's silence into a
    /// `protocol_error`. The quote must therefore carry our ports; one that does
    /// not is `Ignore`d under both match modes, and the await keeps waiting.
    ///
    /// The positive twin — the same error with a full 8-byte transport quote —
    /// names both ports and is the reaction it always was: `Other`.
    #[test]
    fn a_port_less_quote_of_a_ported_stimulus_is_not_our_reaction() {
        let stimulus = lane_stimulus();
        // The 20-byte inner IP header alone: proto UDP, both addresses
        // 127.0.0.1, no transport bytes, so no ports.
        let bare_header: Vec<u8> = stimulus.iter().take(20).copied().collect();
        let bare_quote = icmp_quoting("127.0.0.1", "127.0.0.1", 3, 3, &bare_header);

        let five_tuple = lane_correlation(ReplyMatch::FiveTuple);
        assert!(
            matches!(five_tuple.classify(&bare_quote), Classified::Ignore),
            "FiveTuple: a bare-header quote carries no ports and is not our ported stimulus"
        );
        let from_host = lane_correlation(ReplyMatch::FromHost("127.0.0.1".parse().unwrap()));
        assert!(
            matches!(from_host.classify(&bare_quote), Classified::Ignore),
            "FromHost: the quote must still carry the port we sent from"
        );

        // End to end: the bare-header quote ends nothing, so silence survives.
        let timeout = Duration::from_millis(80);
        let (outcome, packets) = lane_run(vec![bare_quote], timeout);
        assert!(
            matches!(outcome, SendRecvOutcome::NoResponse { .. }),
            "expected silence past a port-less quote, got {outcome:?}"
        );
        assert_eq!(packets, 1, "the flow holds the stimulus alone");

        // The positive twin: header + the full 8-byte UDP transport, so both
        // ports are read and the error is our reaction.
        let with_ports: Vec<u8> = stimulus.iter().take(28).copied().collect();
        let ported_quote = icmp_quoting("127.0.0.1", "127.0.0.1", 3, 3, &with_ports);
        assert!(
            matches!(five_tuple.classify(&ported_quote), Classified::Other),
            "FiveTuple: an 8-byte transport quote names our ports and is our reaction"
        );
        assert!(
            matches!(from_host.classify(&ported_quote), Classified::Other),
            "FromHost: the same quote, carrying the port we sent from, is our reaction"
        );
    }

    /// A reset that carries exactly our two ports but comes from **another
    /// host** is not ours: on a shared segment (and in a spoofed frame) the
    /// ports prove nothing without the address. `FiveTuple` ignores it because
    /// the source address is not the target; `FromHost` ignores it because the
    /// source address is not the host it was given.
    ///
    /// Mutation: drop `self.is_from_the_target(info)` from the RST branch of
    /// `is_reaction_to_our_stimulus` (or `info.ends.src == Some(host)` from
    /// `is_reaction_from_host`) and the matching half reads `Other`.
    #[test]
    fn a_reset_with_our_ports_from_another_host_is_ignored() {
        let syn = tcp_syn_to(9);
        let five_tuple = Correlation::new(
            "127.0.0.1".parse().unwrap(),
            Some(9),
            L4Proto::Tcp,
            ReplyMatch::FiveTuple,
            syn.clone(),
        );
        let from_host = Correlation::new(
            "127.0.0.1".parse().unwrap(),
            Some(9),
            L4Proto::Tcp,
            ReplyMatch::FromHost("127.0.0.1".parse().unwrap()),
            syn,
        );
        let impostor = tcp_from_to("10.0.0.9", 9, "127.0.0.1", 40000, 0x14);
        assert!(
            matches!(five_tuple.classify(&impostor), Classified::Ignore),
            "FiveTuple: a RST from another host is not the probed port's reset"
        );
        assert!(
            matches!(from_host.classify(&impostor), Classified::Ignore),
            "FromHost: the host is part of the rule, not just the ports"
        );
    }

    /// The same for a well-formed reply: the reversed port pair from the wrong
    /// source address is `Ignore` in both correlating modes. This is the shape
    /// an off-path spoofer would use to end the await early and hide a crash.
    ///
    /// Mutation: drop `info.ends.src != Some(self.dst)` from
    /// `is_from_the_target` (or `info.ends.src == Some(host)` from
    /// `is_reply_from_host`) and the matching half reads `Response`.
    #[test]
    fn a_reply_with_our_ports_from_another_address_is_ignored() {
        let impostor = udp_from_to("10.1.2.3", 9, "127.0.0.1", 40000, b"probe");
        assert!(
            matches!(
                lane_correlation(ReplyMatch::FiveTuple).classify(&impostor),
                Classified::Ignore
            ),
            "FiveTuple: the reply must come from the address we probed"
        );
        let host = ReplyMatch::FromHost("127.0.0.1".parse().unwrap());
        assert!(
            matches!(
                lane_correlation(host).classify(&impostor),
                Classified::Ignore
            ),
            "FromHost: a free source port is not a free source address"
        );

        // End to end: the impostor does not end the await, and the target's
        // own reply behind it is still the Response.
        let echo = udp_from_to("127.0.0.1", 9, "127.0.0.1", 40000, b"probe");
        let (outcome, packets) = lane_run(vec![impostor, echo.clone()], Duration::from_secs(10));
        match outcome {
            SendRecvOutcome::Response(p) => assert_eq!(p.bytes, echo, "the target's reply"),
            other => panic!("expected the echo as Response, got {other:?}"),
        }
        assert_eq!(
            packets, 2,
            "stimulus + the real reply; the impostor is not recorded"
        );
    }

    /// An IPv6/UDP frame from `src`:`sp` to `dst`:`dp`.
    fn udp6_from_to(src: &str, sp: u16, dst: &str, dp: u16, payload: &[u8]) -> Vec<u8> {
        use crate::craft::Ipv6Spec;
        use std::net::Ipv6Addr;
        PacketSpec {
            layers: vec![
                Layer::Ipv6(Ipv6Spec {
                    src: Some(src.parse::<Ipv6Addr>().unwrap()),
                    dst: Some(dst.parse::<Ipv6Addr>().unwrap()),
                    ..Ipv6Spec::default()
                }),
                Layer::Udp(UdpSpec {
                    src_port: Some(sp),
                    dst_port: Some(dp),
                    ..UdpSpec::default()
                }),
                Layer::Raw(payload.to_vec()),
            ],
        }
        .build()
        .expect("v6 udp builds")
    }

    /// An ICMPv6 message by hand (the craft layer has no ICMPv6 spec): an IPv6
    /// header with next-header 58 over `type, code, checksum, rest-of-header`
    /// and `body` — the quoted packet for an error, the echo data for a ping.
    fn icmp6_from_to(src: &str, dst: &str, ty: u8, code: u8, body: &[u8]) -> Vec<u8> {
        icmp6_with_rest(src, dst, ty, code, [0, 0, 0, 0], body)
    }

    /// [`icmp6_from_to`] with an explicit rest-of-header word — for an echo,
    /// the identifier and sequence (`[id_hi, id_lo, seq_hi, seq_lo]`).
    fn icmp6_with_rest(
        src: &str,
        dst: &str,
        ty: u8,
        code: u8,
        rest: [u8; 4],
        body: &[u8],
    ) -> Vec<u8> {
        use crate::craft::Ipv6Spec;
        use std::net::Ipv6Addr;
        let mut icmp = vec![ty, code, 0, 0];
        icmp.extend_from_slice(&rest);
        icmp.extend_from_slice(body);
        PacketSpec {
            layers: vec![
                Layer::Ipv6(Ipv6Spec {
                    src: Some(src.parse::<Ipv6Addr>().unwrap()),
                    dst: Some(dst.parse::<Ipv6Addr>().unwrap()),
                    next_header: Some(58),
                    ..Ipv6Spec::default()
                }),
                Layer::Raw(icmp),
            ],
        }
        .build()
        .expect("v6 icmp builds")
    }

    /// Amendment 66 over IPv6, which the lane reaches through a `[::1]` target:
    /// the reversed tuple is the `Response`, another address is `Ignore`, an
    /// ICMPv6 destination-unreachable (type 1) quoting our stimulus is `Other`,
    /// the same error quoting the target's reply is `Ignore`, and an *echo
    /// reply* (type 129) is not an error at all — its payload is not a quote,
    /// so carrying a copy of our stimulus in it correlates to nothing.
    ///
    /// Mutation: widen `icmp_quote`'s ICMPv6 arm from `1..=4` to any type and
    /// the type-129 case reads `Other`; drop the quote test and the
    /// reversed-quote case does.
    #[test]
    fn ipv6_replies_and_icmpv6_errors_follow_the_same_strict_rule() {
        let stimulus = udp6_from_to("::1", 40000, "::1", 9, b"probe");
        let c = Correlation::new(
            "::1".parse().unwrap(),
            Some(9),
            L4Proto::Udp,
            ReplyMatch::FiveTuple,
            stimulus.clone(),
        );

        let echo = udp6_from_to("::1", 9, "::1", 40000, b"probe");
        assert!(
            matches!(c.classify(&echo), Classified::Response),
            "the reversed v6 tuple is the reply"
        );
        let foreign = udp6_from_to("fe80::2", 9, "::1", 40000, b"probe");
        assert!(
            matches!(c.classify(&foreign), Classified::Ignore),
            "a v6 frame from another address is not our reply"
        );

        let ours = icmp6_from_to("::1", "::1", 1, 4, &stimulus);
        assert!(
            matches!(c.classify(&ours), Classified::Other),
            "an ICMPv6 unreachable quoting our v6 stimulus is the reaction"
        );
        let theirs = icmp6_from_to("::1", "::1", 1, 4, &echo);
        assert!(
            matches!(c.classify(&theirs), Classified::Ignore),
            "the kernel's unreachable for the target's v6 reply is not ours"
        );
        let informational = icmp6_from_to("::1", "::1", 129, 0, &stimulus);
        assert!(
            matches!(c.classify(&informational), Classified::Ignore),
            "an echo reply's payload is not a quote, whatever it carries"
        );
    }

    /// The portless IPv6 case the lane uses for a v6 ping: our own echo
    /// request on `::1` is the self-echo and is ignored, the echo reply
    /// (type 129) on the same two addresses is the `Response` because its
    /// transport bytes differ, and an ICMPv6 error quoting the ping is `Other`.
    ///
    /// Mutation: make `is_own_stimulus` compare addresses only (drop the
    /// transport comparison) and the echo reply is swallowed as our own frame.
    #[test]
    fn an_ipv6_ping_correlates_its_echo_reply_and_ignores_its_own_echo() {
        let ping = icmp6_from_to("::1", "::1", 128, 0, b"ping");
        let c = Correlation::new(
            "::1".parse().unwrap(),
            None,
            L4Proto::IcmpV6,
            ReplyMatch::FiveTuple,
            ping.clone(),
        );
        assert!(
            matches!(c.classify(&ping), Classified::Ignore),
            "our own v6 ping, looped back, is not a reply"
        );
        let reply = icmp6_from_to("::1", "::1", 129, 0, b"ping");
        assert!(
            matches!(c.classify(&reply), Classified::Response),
            "the v6 echo reply is the response"
        );
        let unreachable = icmp6_from_to("::1", "::1", 1, 4, &ping);
        assert!(
            matches!(c.classify(&unreachable), Classified::Other),
            "an ICMPv6 unreachable quoting our ping is the reaction"
        );
    }

    /// [`icmp_echo`] with an explicit identifier/sequence word, so a reply can
    /// carry another identifier or sequence than the request.
    fn icmp_echo_with(src: &str, dst: &str, icmp_type: u8, rest_of_header: u32) -> Vec<u8> {
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
                    rest_of_header: Some(rest_of_header),
                    checksum: None,
                }),
                Layer::Raw(b"ping".to_vec()),
            ],
        }
        .build()
        .expect("icmp builds")
    }

    /// The lane's loopback ping as `send_recv` correlates it: the
    /// [`icmp_echo`] request 127.0.0.1 -> 127.0.0.1 (id `0x1234`, seq 1),
    /// portless, protocol ICMP.
    fn ping_correlation(expect: ReplyMatch) -> Correlation {
        Correlation::new(
            "127.0.0.1".parse().unwrap(),
            None,
            L4Proto::Icmp,
            expect,
            icmp_echo("127.0.0.1", "127.0.0.1", 8),
        )
    }

    /// The two modes a ping correlates under; `Any` takes whatever answers by
    /// the operator's explicit choice and is not under test here.
    fn strict_loopback_modes() -> [ReplyMatch; 2] {
        [
            ReplyMatch::FiveTuple,
            ReplyMatch::FromHost("127.0.0.1".parse().unwrap()),
        ]
    }

    /// Security panel minor 2 (amendment 66), the portless edge the packet
    /// lane never reaches but `l4.send` with an ICMP stimulus does: for a ping
    /// the reversed "tuple" used to be addresses and protocol alone, so **any**
    /// ICMP frame from the target to us that was not our own echo was the
    /// `Response` — including an ICMP error quoting someone else's datagram,
    /// which fails the quote test and then passes the address test. On
    /// loopback that is every kernel port-unreachable for anyone's UDP
    /// traffic. An ICMP *error* type is never a reply to a ping: it is `Other`
    /// through the quote test or nothing.
    ///
    /// Mutation: drop the twin-type test from the ICMP reply rule and the
    /// error reads `Response` in both modes.
    #[test]
    fn an_icmp_error_from_the_target_is_not_the_reply_to_our_ping() {
        let stimulus = icmp_echo("127.0.0.1", "127.0.0.1", 8);
        let someone_elses = udp_from_to("127.0.0.1", 53, "127.0.0.1", 34567, b"not-ours");
        let unreachable = icmp_from("127.0.0.1", 3, 3, &someone_elses);
        for expect in strict_loopback_modes() {
            let c = ping_correlation(expect);
            assert!(
                matches!(c.classify(&unreachable), Classified::Ignore),
                "{expect:?}: an ICMP error quoting another datagram is not the echo reply"
            );
        }

        let g = send_recv_guard();
        let backend = MockBackend::with_replies(vec![stimulus.clone(), unreachable]);
        let store: Arc<dyn L4FlowStore> = Arc::new(InMemoryL4FlowStore::new());
        let (flow_id, outcome) = send_recv(
            &g,
            backend,
            store.clone(),
            raw_portless_spec(&stimulus, ReplyMatch::FiveTuple, Duration::from_millis(80)),
        )
        .expect("authorized send_recv runs");
        assert!(
            matches!(outcome, SendRecvOutcome::NoResponse { .. }),
            "expected silence, got {outcome:?}"
        );
        assert_eq!(
            store.get(flow_id).expect("flow present").packets.len(),
            1,
            "the stimulus alone; neither the self-echo nor the foreign error is recorded"
        );
        assert_eq!(g.in_flight(), 0);
    }

    /// The reply to an echo request is the echo reply **with the same
    /// identifier and sequence** (RFC 792: the two fields exist to match the
    /// pair). A reply carrying another identifier or another sequence belongs
    /// to someone else's ping and is `Ignore`d; so is another echo *request*
    /// addressed to us, which is a peer pinging us, not an answer.
    ///
    /// Mutation: compare the type alone and the first two cases read
    /// `Response`.
    #[test]
    fn an_echo_reply_with_another_identifier_is_ignored() {
        let other_id = icmp_echo_with("127.0.0.1", "127.0.0.1", 0, 0x1235_0001);
        let other_seq = icmp_echo_with("127.0.0.1", "127.0.0.1", 0, 0x1234_0002);
        for expect in strict_loopback_modes() {
            let c = ping_correlation(expect);
            assert!(
                matches!(c.classify(&other_id), Classified::Ignore),
                "{expect:?}: an echo reply with another identifier is another ping's"
            );
            assert!(
                matches!(c.classify(&other_seq), Classified::Ignore),
                "{expect:?}: an echo reply with another sequence is another ping's"
            );
        }

        // Off loopback the direction tells our echo from a peer's request, so a
        // type-8 frame from the target with our very id/seq is not consumed as
        // our self-echo — and it is still not the reply.
        let request = icmp_echo("10.0.0.1", "10.0.0.2", 8);
        let c = Correlation::new(
            "10.0.0.2".parse().unwrap(),
            None,
            L4Proto::Icmp,
            ReplyMatch::FiveTuple,
            request,
        );
        let peer_request = icmp_echo("10.0.0.2", "10.0.0.1", 8);
        assert!(
            matches!(c.classify(&peer_request), Classified::Ignore),
            "the target pinging us back is not its echo reply"
        );
    }

    /// The positive the twin rule must keep: the echo reply (type 0) with our
    /// identifier and sequence is the `Response` in both strict modes, and
    /// end to end behind the loopback self-echo.
    #[test]
    fn the_echo_reply_with_our_identifier_and_sequence_is_the_response() {
        let stimulus = icmp_echo("127.0.0.1", "127.0.0.1", 8);
        let reply = icmp_echo("127.0.0.1", "127.0.0.1", 0);
        for expect in strict_loopback_modes() {
            let c = ping_correlation(expect);
            assert!(
                matches!(c.classify(&reply), Classified::Response),
                "{expect:?}: the echo reply with our id/seq is the response"
            );
            assert_portless_response(
                &stimulus,
                vec![stimulus.clone(), reply.clone()],
                &reply,
                expect,
            );
        }
    }

    /// The ICMPv6 twin of the rule: a ping on `::1` (type 128) is answered by
    /// a type-129 echo reply with its identifier and sequence; an ICMPv6
    /// error from the target quoting someone else's datagram is `Ignore`, and
    /// so is a type-129 reply carrying another identifier.
    #[test]
    fn an_icmpv6_error_is_not_the_reply_to_our_ping() {
        let ping = icmp6_with_rest("::1", "::1", 128, 0, [0x12, 0x34, 0, 1], b"ping");
        let someone_elses = udp6_from_to("::1", 53, "::1", 34567, b"not-ours");
        let unreachable = icmp6_from_to("::1", "::1", 1, 4, &someone_elses);
        let other_id = icmp6_with_rest("::1", "::1", 129, 0, [0x12, 0x35, 0, 1], b"ping");
        let reply = icmp6_with_rest("::1", "::1", 129, 0, [0x12, 0x34, 0, 1], b"ping");
        for expect in [
            ReplyMatch::FiveTuple,
            ReplyMatch::FromHost("::1".parse().unwrap()),
        ] {
            let c = Correlation::new(
                "::1".parse().unwrap(),
                None,
                L4Proto::IcmpV6,
                expect,
                ping.clone(),
            );
            assert!(
                matches!(c.classify(&unreachable), Classified::Ignore),
                "{expect:?}: an ICMPv6 error quoting another datagram is not our echo reply"
            );
            assert!(
                matches!(c.classify(&other_id), Classified::Ignore),
                "{expect:?}: a v6 echo reply with another identifier is another ping's"
            );
            assert!(
                matches!(c.classify(&reply), Classified::Response),
                "{expect:?}: the v6 echo reply with our id/seq is the response"
            );
        }
    }

    /// Security panel minor 2 (amendment 66), the second edge: a UDP stimulus
    /// crafted with source port 0 is legal on the wire and the raw path sends
    /// it verbatim (no kernel rewrite under `IP_HDRINCL`), so a reply comes
    /// back **to port 0** and nowhere else. Port 0 used to read as "unset",
    /// which dropped the destination-port test and accepted a reply to any
    /// local port. Port 0 is a real port: the reply to port 40000 is `Ignore`,
    /// the reply to port 0 from the target port is the `Response`, and an
    /// ICMP error is ours only when its quote carries source port 0.
    ///
    /// Mutation: restore `.filter(|p| *p != 0)` in `our_port` and the two
    /// negative cases read `Response` / `Other`.
    #[test]
    fn a_stimulus_with_source_port_zero_still_pins_the_reply_port() {
        let stimulus = udp_from_to("127.0.0.1", 0, "127.0.0.1", 9, b"probe");
        let to_another_port = udp_from_to("127.0.0.1", 9, "127.0.0.1", 40000, b"probe");
        let to_port_zero = udp_from_to("127.0.0.1", 9, "127.0.0.1", 0, b"probe");
        let quoting_another_port = icmp_from(
            "127.0.0.1",
            3,
            3,
            &udp_from_to("127.0.0.1", 40000, "127.0.0.1", 9, b"probe"),
        );
        let quoting_ours = icmp_from("127.0.0.1", 3, 3, &stimulus);
        for expect in strict_loopback_modes() {
            let c = Correlation::new(
                "127.0.0.1".parse().unwrap(),
                Some(9),
                L4Proto::Udp,
                expect,
                stimulus.clone(),
            );
            assert!(
                matches!(c.classify(&stimulus), Classified::Ignore),
                "{expect:?}: the self-echo of a port-0 stimulus is still ours"
            );
            assert!(
                matches!(c.classify(&to_another_port), Classified::Ignore),
                "{expect:?}: a reply to port 40000 is not addressed to our port 0"
            );
            assert!(
                matches!(c.classify(&to_port_zero), Classified::Response),
                "{expect:?}: the reply to port 0 from the target port is the response"
            );
            assert!(
                matches!(c.classify(&quoting_another_port), Classified::Ignore),
                "{expect:?}: an error quoting source port 40000 is not about our port-0 datagram"
            );
            assert!(
                matches!(c.classify(&quoting_ours), Classified::Other),
                "{expect:?}: an error quoting our port-0 datagram is the reaction"
            );
        }
    }

    /// Security panel minor 2 (amendment 66), the third edge: a TCP reset is
    /// a closed **TCP** port's answer. For a UDP stimulus 40000 -> 9 a RST
    /// 9 -> 40000 used to be `Other` (the RST arm never asked the stimulus's
    /// protocol); it is `Ignore` — a UDP probe cannot be reset — and the
    /// await keeps waiting. The same RST for a TCP SYN to port 9 stays the
    /// reaction.
    ///
    /// Mutation: drop the `L4Proto::Tcp` test from the RST arm and the UDP
    /// cases read `Other`.
    #[test]
    fn a_reset_is_a_reaction_only_to_a_tcp_stimulus() {
        let rst = tcp_from_to("127.0.0.1", 9, "127.0.0.1", 40000, 0x14);
        for expect in strict_loopback_modes() {
            assert!(
                matches!(lane_correlation(expect).classify(&rst), Classified::Ignore),
                "{expect:?}: a RST is not a reaction to a UDP stimulus"
            );
        }
        let tcp = Correlation::new(
            "127.0.0.1".parse().unwrap(),
            Some(9),
            L4Proto::Tcp,
            ReplyMatch::FiveTuple,
            tcp_syn_to(9),
        );
        assert!(
            matches!(tcp.classify(&rst), Classified::Other),
            "the same RST answers a TCP SYN"
        );

        let (outcome, packets) = lane_run(vec![rst], Duration::from_millis(80));
        assert!(
            matches!(outcome, SendRecvOutcome::NoResponse { .. }),
            "expected silence, got {outcome:?}"
        );
        assert_eq!(packets, 1, "the stimulus alone");
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
