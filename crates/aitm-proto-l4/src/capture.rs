//! Scoped background packet capture (M5 Task 7).
//!
//! A capture is the passive half of L4: it sniffs a NIC and records the traffic
//! an operator is authorized to observe. It is **deliberately stronger than L7
//! passive capture** — a raw sniff is promiscuous and privileged, so a capture is
//! gated twice:
//!
//! 1. **At start, by the guard.** [`start_capture`] mints a `Capture`-capability
//!    [`L4Permit`] from [`L4Guard::check`](crate::guard::L4Guard::check) *before*
//!    any libpcap handle is opened. An empty scope, or a scope that grants only
//!    `Inject`/`Intercept` on the interface, is refused — no permit, no capture
//!    (deny-by-default, AC8). The permit is held for the capture's lifetime.
//! 2. **At the first boundary, by a scope-derived BPF filter.** [`scope_filter`]
//!    compiles the interface's `Capture` scope entries into a libpcap filter so the
//!    kernel never even delivers out-of-scope traffic.
//! 3. **Per packet, by the same guard.** Every delivered frame is decoded and
//!    re-checked with [`L4Guard::check`]; only an in-scope, capture-authorized
//!    packet is appended to the flow. The BPF filter is best-effort; the guard is
//!    authoritative, so an out-of-scope packet is never recorded even if the
//!    filter is broad.
//!
//! **Fail-closed.** When libpcap or the capture privilege is absent, the backend
//! returns [`L4Error::Unavailable`] and `start_capture` surfaces it without
//! spawning a live capture (AC17). The `pcap` capture source is `!Send`, so the
//! capture loop opens its handle on its **own dedicated thread** (mirroring the
//! NFQUEUE pattern) and reports the open result back through a channel, keeping the
//! synchronous fail-closed contract while never moving a `!Send` handle.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex, PoisonError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime};

use etherparse::{NetSlice, TransportSlice};

use crate::backend::{CaptureInjectBackend, L4Error};
use crate::craft::PacketSpec;
use crate::flow::{L4Bind, L4Flow, L4FlowId, L4FlowKind, L4FlowStore, L4Meta, L4Packet};
use crate::guard::{L4Guard, L4Permit};
use crate::types::{
    IpCidr, L4Action, L4Capability, L4Direction, L4Proto, L4ScopeEntry, L4Target, PortRange,
};

/// Default per-poll read timeout for a capture. Short enough that a stop signal is
/// honoured promptly (the loop re-checks it on every elapsed poll), long enough to
/// avoid a busy spin.
pub const DEFAULT_READ_TIMEOUT: Duration = Duration::from_millis(250);

/// Where and how to bind a scoped capture. The interface + direction name the bind
/// the guard authorizes; `read_timeout` bounds each `next_frame` poll.
#[derive(Debug, Clone)]
pub struct CaptureParams {
    /// The interface to sniff (e.g. `lo0`, `eth0`).
    pub interface: String,
    /// The direction the scope entries authorizing this capture declare.
    pub direction: L4Direction,
    /// Per-poll read timeout handed to the backend.
    pub read_timeout: Duration,
}

impl CaptureParams {
    /// Parameters for `interface` + `direction` with the default read timeout.
    #[must_use]
    pub fn new(interface: impl Into<String>, direction: L4Direction) -> Self {
        Self {
            interface: interface.into(),
            direction,
            read_timeout: DEFAULT_READ_TIMEOUT,
        }
    }
}

/// A live capture: the flow it records into, the stop flag its thread polls, and
/// the `Capture` permit held for the capture's lifetime (its RAII in-flight slot
/// is released only when the capture ends).
#[derive(Debug)]
pub struct CaptureHandle {
    flow_id: L4FlowId,
    stop: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
    /// Held, not used: proves the capture was authorized and keeps the guard's
    /// in-flight gauge accurate until the capture stops.
    _permit: L4Permit,
}

impl CaptureHandle {
    /// The id of the `Capture` flow this capture appends packets to.
    #[must_use]
    pub fn flow_id(&self) -> L4FlowId {
        self.flow_id
    }

    /// Signal the capture thread to stop and wait for it to drain and exit.
    pub fn stop(mut self) {
        self.shutdown();
    }

    fn shutdown(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

impl Drop for CaptureHandle {
    /// A dropped handle never leaks its thread: dropping signals stop and joins.
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// A registry of live captures, keyed by their flow id — the handle Task 10's
/// `l4.capture.*` commands use to list and stop running captures. Dropping the
/// registry stops every capture it owns (each [`CaptureHandle`]'s `Drop`).
#[derive(Debug, Default)]
pub struct CaptureRegistry {
    inner: Mutex<HashMap<L4FlowId, CaptureHandle>>,
}

impl CaptureRegistry {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Track a live capture; returns its flow id (the key it is stored under).
    pub fn register(&self, handle: CaptureHandle) -> L4FlowId {
        let id = handle.flow_id();
        self.inner
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(id, handle);
        id
    }

    /// Stop and remove the capture with `id`; returns whether one was tracked.
    pub fn stop(&self, id: L4FlowId) -> bool {
        let handle = self
            .inner
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&id);
        match handle {
            Some(handle) => {
                handle.stop();
                true
            }
            None => false,
        }
    }

    /// The flow ids of the currently-tracked captures.
    #[must_use]
    pub fn list(&self) -> Vec<L4FlowId> {
        self.inner
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .keys()
            .copied()
            .collect()
    }

    /// Whether no capture is currently tracked.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_empty()
    }

    /// The number of currently-tracked captures.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }
}

/// Start a scoped background capture on `params.interface`.
///
/// Authorization precedes any I/O: a `Capture` [`L4Permit`] is minted first (so an
/// unauthorized capture never opens a handle), then a scope-derived BPF filter is
/// compiled, then the capture loop opens its `!Send` libpcap handle on a dedicated
/// thread and reports the open result back. Each delivered frame is decoded and
/// re-checked by the **same** guard; only in-scope packets are appended.
///
/// # Errors
/// - [`L4Error::Guard`] if the scope does not grant `Capture` on the interface
///   (deny-by-default: `OutOfL4Scope` / `CapabilityNotGranted`);
/// - [`L4Error::Unavailable`] if libpcap/privilege is absent (fail-closed), or the
///   capture thread dies before opening.
pub fn start_capture(
    guard: Arc<L4Guard>,
    backend: Arc<dyn CaptureInjectBackend>,
    store: Arc<dyn L4FlowStore>,
    params: CaptureParams,
) -> Result<CaptureHandle, L4Error> {
    // (1) Authorization precedes any I/O. A capture bind has no single destination,
    // so the target carries `dst: None`: the guard then requires a `Capture` entry
    // on this interface + direction (deny-by-default) without a CIDR constraint at
    // bind time. The minted permit is held for the capture's lifetime.
    let bind_target = L4Target {
        interface: params.interface.clone(),
        direction: params.direction,
        dst: None,
        dst_port: None,
        proto: L4Proto::Raw,
    };
    let permit = guard.check(L4Action::Capture, &bind_target)?;

    // (2) Scope-derived BPF filter: the first boundary (the per-packet guard is the
    // second, authoritative one).
    let filter = scope_filter(&guard, &params.interface);
    let bind = L4Bind {
        interface: params.interface.clone(),
        filter: filter.clone(),
        queue: None,
    };

    let stop = Arc::new(AtomicBool::new(false));
    let (tx, rx) = mpsc::channel::<Result<L4FlowId, L4Error>>();

    let thread_stop = stop.clone();
    let thread_guard = guard.clone();
    let iface = params.interface.clone();
    let direction = params.direction;
    let read_timeout = params.read_timeout;

    let join = thread::spawn(move || {
        // Open on this dedicated thread: the libpcap source is `!Send`, so the
        // handle is created here and never crosses a thread boundary. The open
        // result (fail-closed on missing privilege/libpcap) goes back over `tx`.
        let mut source = match backend.open_capture(&iface, filter.as_deref(), read_timeout) {
            Ok(source) => source,
            Err(e) => {
                let _ = tx.send(Err(e));
                return;
            }
        };
        // The capture is live: create its flow only now (no stray flow on a failed
        // open) and report the id the caller addresses it by.
        let flow_id = store.insert(L4Flow {
            id: L4FlowId::new(),
            kind: L4FlowKind::Capture,
            bind,
            packets: std::collections::VecDeque::new(),
            metadata: L4Meta::default(),
        });
        if tx.send(Ok(flow_id)).is_err() {
            return; // the caller gave up before we opened; nothing to record into.
        }

        while !thread_stop.load(Ordering::Acquire) {
            match source.next_frame() {
                Ok(Some(frame)) => record_frame(
                    &frame,
                    &iface,
                    direction,
                    &thread_guard,
                    store.as_ref(),
                    flow_id,
                ),
                // A timed-out poll means "no frame yet" — loop and re-check `stop`.
                Ok(None) => {}
                // A read error is fail-closed: end the capture rather than spin.
                Err(_) => break,
            }
        }
    });

    match rx.recv() {
        Ok(Ok(flow_id)) => Ok(CaptureHandle {
            flow_id,
            stop,
            join: Some(join),
            _permit: permit,
        }),
        Ok(Err(e)) => {
            let _ = join.join();
            Err(e)
        }
        Err(_) => {
            let _ = join.join();
            Err(L4Error::Unavailable(
                "capture thread terminated before opening".into(),
            ))
        }
    }
}

/// Compile the `Capture` scope entries for `interface` into a libpcap BPF filter —
/// the first boundary that keeps out-of-scope traffic from ever being delivered.
///
/// The scope part is `None` when the capture should not be narrowed at the BPF
/// level: no `Capture` entry carries an address/port constraint, or at least one
/// authorizes unconstrained traffic (narrowing then would wrongly drop packets
/// that entry permits). The per-packet guard check remains authoritative in every
/// case.
///
/// On a loopback interface (`lo`, `lo0`, …) the core's own listener ports
/// ([`L4Guard::self_ports`]) are ANDed out — `(<scope>) and not port 27431`, or
/// `not (port 27431 or port 28182)` for several — whatever the scope says, so the
/// kernel never delivers the bus's own frames (L4PAR-AC34, spec §2.1). The
/// per-packet [`L4Guard::is_self_traffic`] drop in the capture loop is the
/// authoritative second boundary.
#[must_use]
pub fn scope_filter(guard: &L4Guard, interface: &str) -> Option<String> {
    let scope = scope_clause(guard, interface);
    if !is_loopback_interface(interface) {
        return scope;
    }
    let self_ports = guard.self_ports();
    let exclusion = match self_ports.as_slice() {
        [] => return scope,
        [port] => format!("not port {port}"),
        ports => format!(
            "not ({})",
            ports
                .iter()
                .map(|p| format!("port {p}"))
                .collect::<Vec<_>>()
                .join(" or ")
        ),
    };
    Some(match scope {
        Some(clause) => format!("({clause}) and {exclusion}"),
        None => exclusion,
    })
}

/// The scope half of [`scope_filter`]: the `Capture` entries for `interface`
/// compiled to a BPF clause, or `None` when the capture should not be narrowed.
fn scope_clause(guard: &L4Guard, interface: &str) -> Option<String> {
    let entries: Vec<L4ScopeEntry> = guard
        .list_scope()
        .into_iter()
        .filter(|e| e.capability == L4Capability::Capture && e.interface == interface)
        .collect();
    if entries.is_empty() {
        return None;
    }
    let mut clauses = Vec::with_capacity(entries.len());
    for entry in &entries {
        // An unconstrained entry (`?` yields `None`) authorizes everything on the
        // interface: narrowing the BPF filter would wrongly drop packets it
        // permits, so decline to narrow and let the per-packet guard decide.
        clauses.push(entry_bpf_clause(entry)?);
    }
    match clauses.len() {
        0 => None,
        1 => clauses.pop(),
        _ => Some(
            clauses
                .into_iter()
                .map(|c| format!("({c})"))
                .collect::<Vec<_>>()
                .join(" or "),
        ),
    }
}

/// Whether `interface` is a loopback interface: `lo` (Linux) or `lo<digits>`
/// (`lo0` on macOS and the BSDs).
fn is_loopback_interface(interface: &str) -> bool {
    interface
        .strip_prefix("lo")
        .is_some_and(|rest| rest.chars().all(|c| c.is_ascii_digit()))
}

/// Decode one delivered frame and, if the **same** guard authorizes it for
/// `Capture`, append it to the flow. Out-of-scope, undecodable, or non-IP frames
/// are silently dropped — never recorded.
fn record_frame(
    frame: &[u8],
    interface: &str,
    direction: L4Direction,
    guard: &L4Guard,
    store: &dyn L4FlowStore,
    flow_id: L4FlowId,
) {
    // The core's own traffic (a loopback frame to or from one of its listener
    // ports — the bus's plaintext token line among it) is dropped before the
    // scope check and before anything is recorded, whatever the scope says
    // (L4PAR-AC34, spec §2.1).
    if guard.is_self_traffic(&PacketSpec::endpoints(frame)) {
        return;
    }
    // A frame that carries no IP target cannot be in a CIDR-scoped capture.
    let Some(target) = packet_target(frame, interface, direction) else {
        return;
    };
    // The same guard that authorized the bind decides every packet: an out-of-scope
    // or non-`Capture` frame is dropped, never recorded. A `Capture` check consumes
    // no injection budget; the minted permit is released immediately.
    if guard.check(L4Action::Capture, &target).is_err() {
        return;
    }
    store.append_packet(
        flow_id,
        L4Packet {
            dir: direction,
            timestamp: SystemTime::now(),
            decoded: PacketSpec::summarize(frame),
            bytes: frame.to_vec(),
            injected: false,
        },
    );
}

/// Resolve a captured frame to the `L4Target` the guard checks: destination
/// address, destination port (for TCP/UDP), and protocol. `None` for a frame that
/// carries no IP layer (ARP, or an undecodable buffer) — such a frame is out of a
/// CIDR-scoped capture by definition.
///
/// `pub(crate)` so `send_recv` re-checks a correlated reply with the *same* target
/// resolution the background capture uses before recording it ([`record_frame`]).
pub(crate) fn packet_target(
    frame: &[u8],
    interface: &str,
    direction: L4Direction,
) -> Option<L4Target> {
    let parsed = crate::craft::parse_frame(frame)?;
    let dst = match parsed.net? {
        NetSlice::Ipv4(ip) => IpAddr::V4(ip.header().destination_addr()),
        NetSlice::Ipv6(ip) => IpAddr::V6(ip.header().destination_addr()),
        NetSlice::Arp(_) => return None,
    };
    let (dst_port, proto) = match parsed.transport {
        Some(TransportSlice::Tcp(t)) => (Some(t.destination_port()), L4Proto::Tcp),
        Some(TransportSlice::Udp(u)) => (Some(u.destination_port()), L4Proto::Udp),
        Some(TransportSlice::Icmpv4(_)) => (None, L4Proto::Icmp),
        Some(TransportSlice::Icmpv6(_)) => (None, L4Proto::IcmpV6),
        _ => (None, L4Proto::Raw),
    };
    Some(L4Target {
        interface: interface.to_string(),
        direction,
        dst: Some(dst),
        dst_port,
        proto,
    })
}

/// The BPF clause for one scope entry: its address predicate AND its port
/// predicate. `None` when the entry constrains neither (any address, any port).
fn entry_bpf_clause(entry: &L4ScopeEntry) -> Option<String> {
    let mut parts = Vec::new();
    if let Some(addr) = cidr_bpf(&entry.cidr) {
        parts.push(addr);
    }
    if let Some(port) = ports_bpf(&entry.ports) {
        parts.push(port);
    }
    match parts.len() {
        0 => None,
        1 => parts.pop(),
        _ => Some(parts.join(" and ")),
    }
}

/// The BPF address predicate for a CIDR, or `None` for a `/0` (matches everything).
fn cidr_bpf(cidr: &IpCidr) -> Option<String> {
    let full = match cidr.addr {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    if cidr.prefix == 0 {
        None
    } else if cidr.prefix >= full {
        Some(format!("host {}", cidr.addr))
    } else {
        Some(format!("net {}/{}", cidr.addr, cidr.prefix))
    }
}

/// The BPF port predicate for a port range, or `None` for the full range.
fn ports_bpf(ports: &PortRange) -> Option<String> {
    if ports.lo == 0 && ports.hi == u16::MAX {
        None
    } else if ports.lo == ports.hi {
        Some(format!("port {}", ports.lo))
    } else {
        Some(format!("portrange {}-{}", ports.lo, ports.hi))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::backend::{CaptureSource, L4Error};
    use crate::config::L4Config;
    use crate::craft::{Ipv4Spec, Layer, PacketSpec, UdpSpec};
    use crate::flow::InMemoryL4FlowStore;
    use crate::types::{L4ScopeId, RateCap};
    use std::collections::VecDeque;
    use std::net::Ipv4Addr;

    const MOCK_IFACE: &str = "mock0";

    fn cfg() -> L4Config {
        L4Config::default()
    }

    fn entry(cidr: (&str, u8), ports: (u16, u16), cap: L4Capability) -> L4ScopeEntry {
        L4ScopeEntry {
            id: L4ScopeId::new(),
            cidr: IpCidr {
                addr: cidr.0.parse().unwrap(),
                prefix: cidr.1,
            },
            ports: PortRange {
                lo: ports.0,
                hi: ports.1,
            },
            interface: MOCK_IFACE.to_string(),
            direction: L4Direction::Outbound,
            capability: cap,
            inject_rate: RateCap { pps: 10, burst: 10 },
            source: crate::types::L4ScopeSource::Config,
        }
    }

    /// A crafted IPv4/UDP frame (starting at L3) to `dst:9` — a packet our capture
    /// loop decodes exactly as `packet_target` does.
    fn udp_frame(dst: &str) -> Vec<u8> {
        PacketSpec {
            layers: vec![
                Layer::Ipv4(Ipv4Spec {
                    dst: Some(dst.parse::<Ipv4Addr>().unwrap()),
                    ..Ipv4Spec::default()
                }),
                Layer::Udp(UdpSpec {
                    dst_port: Some(9),
                    ..UdpSpec::default()
                }),
                Layer::Raw(b"probe".to_vec()),
            ],
        }
        .build()
        .expect("craft builds")
    }

    /// A backend that replays a fixed script of frames into one capture, then goes
    /// quiet — flipping `delivered` once every scripted frame has been handed out,
    /// so a test can wait deterministically for the loop to drain. `available`
    /// false simulates missing privilege/libpcap (fail-closed).
    struct ScriptBackend {
        available: bool,
        frames: Mutex<Option<Vec<Vec<u8>>>>,
        delivered: Arc<AtomicBool>,
    }

    impl ScriptBackend {
        fn with_frames(frames: Vec<Vec<u8>>) -> Arc<Self> {
            Arc::new(Self {
                available: true,
                frames: Mutex::new(Some(frames)),
                delivered: Arc::new(AtomicBool::new(false)),
            })
        }

        fn unavailable() -> Arc<Self> {
            Arc::new(Self {
                available: false,
                frames: Mutex::new(Some(Vec::new())),
                delivered: Arc::new(AtomicBool::new(false)),
            })
        }
    }

    impl CaptureInjectBackend for ScriptBackend {
        fn open_capture(
            &self,
            _iface: &str,
            _filter: Option<&str>,
            _read_timeout: Duration,
        ) -> Result<Box<dyn CaptureSource>, L4Error> {
            if !self.available {
                return Err(L4Error::Unavailable("no privilege (mock)".into()));
            }
            let frames = self.frames.lock().unwrap().take().unwrap_or_default();
            Ok(Box::new(ScriptSource {
                frames: frames.into_iter().collect(),
                delivered: self.delivered.clone(),
            }))
        }

        fn inject(&self, _iface: &str, _bytes: &[u8]) -> Result<(), L4Error> {
            Ok(())
        }
    }

    struct ScriptSource {
        frames: VecDeque<Vec<u8>>,
        delivered: Arc<AtomicBool>,
    }

    impl CaptureSource for ScriptSource {
        fn next_frame(&mut self) -> Result<Option<Vec<u8>>, L4Error> {
            match self.frames.pop_front() {
                Some(frame) => Ok(Some(frame)),
                None => {
                    // Drained: signal the test and idle like a real read timeout.
                    self.delivered.store(true, Ordering::Release);
                    thread::sleep(Duration::from_millis(5));
                    Ok(None)
                }
            }
        }
    }

    fn guard_with(entries: Vec<L4ScopeEntry>) -> Arc<L4Guard> {
        let g = L4Guard::new(&cfg());
        for e in entries {
            g.add_scope(e).unwrap();
        }
        Arc::new(g)
    }

    fn wait_for(flag: &AtomicBool) {
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while !flag.load(Ordering::Acquire) {
            assert!(
                std::time::Instant::now() < deadline,
                "capture did not drain"
            );
            thread::sleep(Duration::from_millis(5));
        }
    }

    /// A single host entry compiles to a `host` BPF clause; a non-`Capture` entry
    /// on the same interface does not contribute.
    #[test]
    fn scope_filter_host_clause() {
        let g = guard_with(vec![
            entry(("127.0.0.1", 32), (0, u16::MAX), L4Capability::Capture),
            entry(("127.0.0.1", 32), (0, u16::MAX), L4Capability::Inject),
        ]);
        assert_eq!(
            scope_filter(&g, MOCK_IFACE),
            Some("host 127.0.0.1".to_string())
        );
    }

    /// A CIDR + a specific port compile to `net .../prefix and port N`.
    #[test]
    fn scope_filter_net_and_port() {
        let g = guard_with(vec![entry(
            ("127.0.0.0", 24),
            (9, 9),
            L4Capability::Capture,
        )]);
        assert_eq!(
            scope_filter(&g, MOCK_IFACE),
            Some("net 127.0.0.0/24 and port 9".to_string())
        );
    }

    /// An unconstrained `Capture` entry (`/0`, any port) means "do not narrow at
    /// the BPF level" — the per-packet guard stays authoritative.
    #[test]
    fn scope_filter_unconstrained_is_none() {
        let g = guard_with(vec![entry(
            ("0.0.0.0", 0),
            (0, u16::MAX),
            L4Capability::Capture,
        )]);
        assert_eq!(scope_filter(&g, MOCK_IFACE), None);
    }

    /// Several constrained entries OR together.
    #[test]
    fn scope_filter_multiple_entries_or() {
        let g = guard_with(vec![
            entry(("127.0.0.1", 32), (0, u16::MAX), L4Capability::Capture),
            entry(("127.0.0.2", 32), (0, u16::MAX), L4Capability::Capture),
        ]);
        assert_eq!(
            scope_filter(&g, MOCK_IFACE),
            Some("(host 127.0.0.1) or (host 127.0.0.2)".to_string())
        );
    }

    /// A `Capture` entry on `lo0`, the macOS loopback (the plan's A10 tests speak
    /// of the rig's interface).
    fn lo0_entry(ports: (u16, u16)) -> L4ScopeEntry {
        let mut e = entry(("127.0.0.1", 32), ports, L4Capability::Capture);
        e.interface = "lo0".to_string();
        e
    }

    /// A crafted IPv4/TCP frame 127.0.0.1:`src_port` → 127.0.0.1:`dst_port`
    /// carrying a bus-shaped first line — the frame an agent would read the
    /// operator token out of.
    fn lo_tcp_frame(src_port: u16, dst_port: u16) -> Vec<u8> {
        use crate::craft::TcpSpec;
        PacketSpec {
            layers: vec![
                Layer::Ipv4(Ipv4Spec {
                    src: Some(Ipv4Addr::LOCALHOST),
                    dst: Some(Ipv4Addr::LOCALHOST),
                    ..Ipv4Spec::default()
                }),
                Layer::Tcp(TcpSpec {
                    src_port: Some(src_port),
                    dst_port: Some(dst_port),
                    ..TcpSpec::default()
                }),
                Layer::Raw(b"{\"token\": \"not-for-agents\"}\n".to_vec()),
            ],
        }
        .build()
        .expect("craft builds")
    }

    /// An empty `Capture` flow on `lo0` for `record_frame` to append into.
    fn lo0_capture_flow(store: &dyn L4FlowStore) -> L4FlowId {
        store.insert(L4Flow {
            id: L4FlowId::new(),
            kind: L4FlowKind::Capture,
            bind: L4Bind {
                interface: "lo0".to_string(),
                filter: None,
                queue: None,
            },
            packets: VecDeque::new(),
            metadata: L4Meta::default(),
        })
    }

    /// L4PAR-AC34 (plan A10): with self ports `{27431}` (the bus), a loopback
    /// frame to the bus and its reply from the bus are never recorded — even
    /// under a capture scope covering `127.0.0.1/32` on every port — while a
    /// frame to an in-scope, non-self port is.
    #[test]
    fn self_traffic_is_never_recorded() {
        let g = guard_with(vec![lo0_entry((0, u16::MAX))]);
        g.set_self_ports([27431]);
        let store = InMemoryL4FlowStore::new();
        let flow_id = lo0_capture_flow(&store);

        record_frame(
            &lo_tcp_frame(51000, 27431),
            "lo0",
            L4Direction::Outbound,
            &g,
            &store,
            flow_id,
        );
        record_frame(
            &lo_tcp_frame(27431, 51000),
            "lo0",
            L4Direction::Outbound,
            &g,
            &store,
            flow_id,
        );
        assert_eq!(
            store.get(flow_id).expect("flow").packets.len(),
            0,
            "a frame to or from the bus port is never recorded"
        );

        record_frame(
            &lo_tcp_frame(51000, 9099),
            "lo0",
            L4Direction::Outbound,
            &g,
            &store,
            flow_id,
        );
        let flow = store.get(flow_id).expect("flow");
        assert_eq!(flow.packets.len(), 1, "an in-scope non-self frame is kept");
        assert_eq!(
            PacketSpec::endpoints(&flow.packets[0].bytes).dst_port,
            Some(9099)
        );
    }

    /// L4PAR-AC34 (plan A10): on a loopback interface the scope-derived BPF
    /// filter ANDs `not port …` for every self port (ascending); on any other
    /// interface it is unchanged.
    #[test]
    fn scope_filter_excludes_self_ports() {
        let g = guard_with(vec![lo0_entry((0, u16::MAX))]);
        g.set_self_ports([27431]);
        assert_eq!(
            scope_filter(&g, "lo0"),
            Some("(host 127.0.0.1) and not port 27431".to_string())
        );

        let g = guard_with(vec![lo0_entry((9000, 9999))]);
        g.set_self_ports([28182, 27431]);
        assert_eq!(
            scope_filter(&g, "lo0"),
            Some(
                "(host 127.0.0.1 and portrange 9000-9999) and not (port 27431 or port 28182)"
                    .to_string()
            )
        );

        // An unconstrained loopback scope still excludes the core's own ports.
        let mut any = lo0_entry((0, u16::MAX));
        any.cidr = IpCidr {
            addr: "0.0.0.0".parse().unwrap(),
            prefix: 0,
        };
        let g = guard_with(vec![any]);
        g.set_self_ports([27431]);
        assert_eq!(scope_filter(&g, "lo0"), Some("not port 27431".to_string()));

        // Linux `lo` is a loopback interface too.
        let mut lo = lo0_entry((0, u16::MAX));
        lo.interface = "lo".to_string();
        let g = guard_with(vec![lo]);
        g.set_self_ports([27431]);
        assert_eq!(
            scope_filter(&g, "lo"),
            Some("(host 127.0.0.1) and not port 27431".to_string())
        );

        // A non-loopback interface: the filter is exactly what it was.
        let g = guard_with(vec![entry(
            ("127.0.0.1", 32),
            (0, u16::MAX),
            L4Capability::Capture,
        )]);
        g.set_self_ports([27431]);
        assert_eq!(
            scope_filter(&g, MOCK_IFACE),
            Some("host 127.0.0.1".to_string())
        );

        // No self ports: a loopback filter is unchanged too.
        let g = guard_with(vec![lo0_entry((0, u16::MAX))]);
        assert_eq!(scope_filter(&g, "lo0"), Some("host 127.0.0.1".to_string()));
    }

    /// AC8 / deny-by-default: an empty scope refuses to start a capture — no permit,
    /// no handle.
    #[test]
    fn start_capture_empty_scope_refused() {
        let g = Arc::new(L4Guard::new(&cfg()));
        let backend = ScriptBackend::with_frames(vec![]);
        let store: Arc<dyn L4FlowStore> = Arc::new(InMemoryL4FlowStore::new());
        let err = start_capture(
            g,
            backend,
            store,
            CaptureParams::new(MOCK_IFACE, L4Direction::Outbound),
        )
        .unwrap_err();
        assert!(
            matches!(
                err,
                L4Error::Guard(crate::guard::L4GuardError::OutOfL4Scope(_))
            ),
            "empty scope must refuse capture, got {err:?}"
        );
    }

    /// AC3/AC8: a scope that grants only `Inject` on the interface refuses capture
    /// with `CapabilityNotGranted(Capture)`.
    #[test]
    fn start_capture_requires_capture_capability() {
        let g = guard_with(vec![entry(
            ("127.0.0.1", 32),
            (0, u16::MAX),
            L4Capability::Inject,
        )]);
        let backend = ScriptBackend::with_frames(vec![]);
        let store: Arc<dyn L4FlowStore> = Arc::new(InMemoryL4FlowStore::new());
        let err = start_capture(
            g,
            backend,
            store,
            CaptureParams::new(MOCK_IFACE, L4Direction::Outbound),
        )
        .unwrap_err();
        assert_eq!(
            err,
            L4Error::Guard(crate::guard::L4GuardError::CapabilityNotGranted(
                L4Capability::Capture
            ))
        );
    }

    /// AC17 fail-closed: an authorized capture whose backend has no privilege/
    /// libpcap surfaces `L4Unavailable` and spawns no live capture — and the
    /// momentary permit is released (the guard's in-flight gauge returns to zero).
    #[test]
    fn start_capture_fail_closed_without_privilege() {
        let g = guard_with(vec![entry(
            ("127.0.0.1", 32),
            (0, u16::MAX),
            L4Capability::Capture,
        )]);
        let backend = ScriptBackend::unavailable();
        let store: Arc<dyn L4FlowStore> = Arc::new(InMemoryL4FlowStore::new());
        let err = start_capture(
            g.clone(),
            backend,
            store,
            CaptureParams::new(MOCK_IFACE, L4Direction::Outbound),
        )
        .unwrap_err();
        assert!(matches!(err, L4Error::Unavailable(_)), "got {err:?}");
        assert_eq!(g.in_flight(), 0, "a failed capture releases its permit");
    }

    /// AC8 (hermetic): a capture scoped to CIDR *A* records the in-scope packet and
    /// drops the out-of-scope one delivered on the same interface. Proves the
    /// per-packet guard filter end-to-end, no privilege needed.
    #[test]
    fn capture_records_only_in_scope() {
        let g = guard_with(vec![entry(
            ("127.0.0.1", 32),
            (0, u16::MAX),
            L4Capability::Capture,
        )]);
        let backend = ScriptBackend::with_frames(vec![
            udp_frame("127.0.0.1"), // in scope
            udp_frame("127.0.0.2"), // out of scope, same interface
        ]);
        let delivered = backend.delivered.clone();
        let store: Arc<dyn L4FlowStore> = Arc::new(InMemoryL4FlowStore::new());

        let handle = start_capture(
            g.clone(),
            backend,
            store.clone(),
            CaptureParams::new(MOCK_IFACE, L4Direction::Outbound),
        )
        .expect("authorized capture starts");
        let flow_id = handle.flow_id();

        wait_for(&delivered);
        handle.stop();

        let flow = store.get(flow_id).expect("capture flow present");
        assert_eq!(flow.kind, L4FlowKind::Capture);
        assert_eq!(
            flow.packets.len(),
            1,
            "only the in-scope packet is recorded"
        );
        let pkt = &flow.packets[0];
        assert!(!pkt.injected, "captured traffic is not injected");
        assert_eq!(
            pkt.decoded.layers,
            vec!["IPv4".to_string(), "UDP".to_string()]
        );
        // The captured packet is the one destined for the in-scope address.
        let t = packet_target(&pkt.bytes, MOCK_IFACE, L4Direction::Outbound).unwrap();
        assert_eq!(t.dst, Some("127.0.0.1".parse().unwrap()));
        assert_eq!(g.in_flight(), 0, "stopping the capture releases its permit");
    }

    /// MINOR (link-layer autodetect): a real Ethernet frame whose destination MAC
    /// starts with an IP-looking nibble (here `0x45`, which a first-byte check misreads
    /// as an IPv4 header) is parsed as Ethernet, so `packet_target` resolves the true
    /// IPv4 destination rather than a byte-offset artifact.
    #[test]
    fn packet_target_ethernet_with_ip_like_dst_mac() {
        use crate::craft::EtherSpec;
        let frame = PacketSpec {
            layers: vec![
                Layer::Ether(EtherSpec {
                    dst: Some([0x45, 0x00, 0x00, 0x00, 0x00, 0x01]),
                    src: Some([0x00, 0x00, 0x00, 0x00, 0x00, 0x02]),
                    ..EtherSpec::default()
                }),
                Layer::Ipv4(Ipv4Spec {
                    dst: Some("10.1.2.3".parse::<Ipv4Addr>().unwrap()),
                    ..Ipv4Spec::default()
                }),
                Layer::Udp(UdpSpec {
                    dst_port: Some(9),
                    ..UdpSpec::default()
                }),
                Layer::Raw(b"probe".to_vec()),
            ],
        }
        .build()
        .expect("craft builds");

        let target = packet_target(&frame, MOCK_IFACE, L4Direction::Outbound)
            .expect("an Ethernet frame resolves to its IPv4 target");
        assert_eq!(target.dst, Some("10.1.2.3".parse().unwrap()));
        assert_eq!(target.dst_port, Some(9));
    }

    /// The registry tracks a live capture, lists it, and stops it on request.
    #[test]
    fn registry_register_list_stop() {
        let g = guard_with(vec![entry(
            ("127.0.0.1", 32),
            (0, u16::MAX),
            L4Capability::Capture,
        )]);
        let backend = ScriptBackend::with_frames(vec![udp_frame("127.0.0.1")]);
        let store: Arc<dyn L4FlowStore> = Arc::new(InMemoryL4FlowStore::new());
        let registry = CaptureRegistry::new();

        let handle = start_capture(
            g,
            backend,
            store,
            CaptureParams::new(MOCK_IFACE, L4Direction::Outbound),
        )
        .expect("capture starts");
        let id = registry.register(handle);

        assert_eq!(registry.list(), vec![id]);
        assert_eq!(registry.len(), 1);
        assert!(registry.stop(id), "a tracked capture stops");
        assert!(registry.is_empty());
        assert!(!registry.stop(id), "stopping an unknown capture is false");
    }

    /// Pinned (plan Task 7): a scoped loopback capture records the in-scope packet
    /// and excludes the out-of-scope one. Privilege-gated — `#[ignore]`d and run
    /// only with `AITM_L4_TESTS=1`; without capture privilege it asserts
    /// `L4Unavailable` and skips cleanly rather than failing.
    #[test]
    #[ignore = "requires raw-capture privilege; run with AITM_L4_TESTS=1 and -- --ignored"]
    fn capture_excludes_out_of_scope() {
        if std::env::var("AITM_L4_TESTS").ok().as_deref() != Some("1") {
            return;
        }
        use crate::backend::pcap::PcapBackend;

        let iface = if cfg!(target_os = "macos") {
            "lo0"
        } else {
            "lo"
        };
        let g = Arc::new(L4Guard::new(&cfg()));
        g.add_scope(L4ScopeEntry {
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
            direction: L4Direction::Outbound,
            capability: L4Capability::Capture,
            inject_rate: RateCap { pps: 10, burst: 10 },
            source: crate::types::L4ScopeSource::Config,
        })
        .unwrap();

        let backend: Arc<dyn CaptureInjectBackend> = Arc::new(PcapBackend::new());
        let store: Arc<dyn L4FlowStore> = Arc::new(InMemoryL4FlowStore::new());

        let handle = match start_capture(
            g,
            backend,
            store.clone(),
            CaptureParams::new(iface, L4Direction::Outbound),
        ) {
            Ok(handle) => handle,
            // No capture privilege here: fail-closed contract, skip cleanly.
            Err(L4Error::Unavailable(_)) => return,
            Err(e) => panic!("unexpected capture start error: {e:?}"),
        };
        let flow_id = handle.flow_id();

        // Generate real loopback traffic without raw privilege: ordinary UDP sends.
        let sock = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind loopback udp");
        let _ = sock.send_to(b"in-scope", "127.0.0.1:9");
        let _ = sock.send_to(b"out-of-scope", "127.0.0.2:9");
        thread::sleep(Duration::from_millis(400));
        handle.stop();

        let flow = store.get(flow_id).expect("capture flow present");
        assert!(
            !flow.packets.is_empty(),
            "the in-scope loopback packet is captured"
        );
        for pkt in &flow.packets {
            let t = packet_target(&pkt.bytes, iface, L4Direction::Outbound)
                .expect("captured packet decodes");
            assert_eq!(
                t.dst,
                Some("127.0.0.1".parse().unwrap()),
                "no out-of-scope packet surfaces"
            );
        }
    }
}
