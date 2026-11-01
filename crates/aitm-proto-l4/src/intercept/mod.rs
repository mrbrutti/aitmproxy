//! In-path packet interception — the L4 analog of `flow.intercept` / `flow.mutate`
//! (M5 Task 11).
//!
//! On Linux, a scoped `nft ... queue num N` rule hands matching packets to
//! userspace; aitmproxy binds queue `N` and, for each packet, **parks** it (holds
//! the kernel's verdict), lets a command or agent mutate it, then **forwards**
//! (possibly mangled) or **drops** it. macOS has no equivalent, so the backend
//! there returns [`L4Error::Unavailable`].
//!
//! The NFQUEUE API is blocking and its `recv`/`verdict` share one owner, so the
//! queue lives on a **dedicated owning thread** (mirroring the capture task's
//! `!Send` pcap handle). That thread is the single reader: it decodes each packet,
//! asks the **same** [`L4Guard`] whether it is in scope, and parks only in-scope
//! packets; out-of-scope packets are **auto-forwarded untouched, never parked**
//! (AC14) — the `nft` rule is the first scope boundary, the guard is the second.
//!
//! **aitmproxy owns the lifecycle the kernel does not provide.** Every parked
//! packet has a verdict **deadline** (`verdict_timeout`); on expiry `on_timeout`
//! applies — default [`Verdict::Forward`], so a packet nobody judged in time is
//! **not** black-holed (AC15). A **parked-queue cap** (`max_parked`) bounds held
//! packets; on overflow `on_overflow` (default Forward) applies. Both defaults
//! fail **open**: in-path interception must never stall the target's unrelated
//! traffic.
//!
//! **One choke point.** The reader decodes and scopes every packet, but the module
//! is seam-tested through [`InterceptBackend`] / [`InterceptQueue`] so the
//! park / forward / timeout / overflow state machine is provable without NFQUEUE
//! or privilege; the production backend is Linux `nfq`, a mock stands in for tests.

#[cfg(target_os = "linux")]
mod nfqueue_linux;
#[cfg(not(target_os = "linux"))]
mod unsupported;

/// The production in-path backend: Linux NFQUEUE (`nfq`) where supported, a
/// fail-closed `L4Unavailable` stub on every other OS.
#[cfg(target_os = "linux")]
pub use nfqueue_linux::NfqueueBackend;
#[cfg(not(target_os = "linux"))]
pub use unsupported::NfqueueBackend;

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex, PoisonError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime};

use etherparse::{NetSlice, SlicedPacket, TransportSlice};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::backend::L4Error;
use crate::config::{InterceptConfig, Verdict};
use crate::craft::PacketSpec;
use crate::flow::{L4Bind, L4Flow, L4FlowId, L4FlowKind, L4FlowStore, L4Meta, L4Packet};
use crate::guard::{L4Guard, L4Permit};
use crate::types::{L4Action, L4Direction, L4Proto, L4Target};

/// Default per-poll read timeout for the reader thread — short enough that the
/// stop flag and verdict deadlines are honoured promptly, long enough to avoid a
/// busy spin. Mirrors the capture task's default.
pub const DEFAULT_READ_TIMEOUT: Duration = Duration::from_millis(100);

/// Stable identifier for a parked packet (uuid-backed), like `L4FlowId`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ParkedId(Uuid);

impl ParkedId {
    /// Mint a fresh parked-packet id.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for ParkedId {
    fn default() -> Self {
        Self::new()
    }
}

/// A live, in-flight packet held awaiting a verdict — the `flow.intercept` analog
/// at the packet level. Carries a decoded copy of the packet (the kernel still
/// holds the original), the interception state, and the aitm-enforced deadline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParkedPacket {
    /// Stable identity for addressing this parked packet in `l4.intercept.*`.
    pub id: ParkedId,
    /// The interception flow this packet belongs to.
    pub flow: L4FlowId,
    /// The parked packet, decoded.
    pub packet: L4Packet,
    /// Its interception state (Parked / Mutated / Forwarded / Dropped).
    pub state: L4InterceptState,
    /// When `on_timeout` applies if no verdict arrives first.
    pub deadline: SystemTime,
    /// Arrival sequence within its session: assigned from a monotonic per-session
    /// counter when the packet is parked, so `l4.intercept.list` can order parked
    /// packets oldest first (the id is a random uuid and carries no order).
    pub parked_seq: u64,
    /// When the packet was parked (`l4.intercept.list` reports it as epoch ms).
    pub parked_at: SystemTime,
}

/// The platform `InterceptState` model, at the packet level. A `backup` of the
/// original packet is kept so a mutation can be reverted (`l4.intercept.revert`,
/// M5 Task 12).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum L4InterceptState {
    /// Held, unmodified, awaiting a verdict.
    Parked {
        /// The original packet, for revert.
        backup: Box<L4Packet>,
    },
    /// Edited; the mutation can still be reverted to `backup`.
    Mutated {
        /// The original packet, for revert.
        backup: Box<L4Packet>,
    },
    /// Forwarded (possibly mangled) — a terminal state.
    Forwarded,
    /// Dropped — a terminal state.
    Dropped,
}

impl L4InterceptState {
    /// Whether this packet is still held (awaiting a verdict), as opposed to a
    /// terminal Forwarded/Dropped. A deadline only applies while it is live.
    #[must_use]
    pub fn is_live(&self) -> bool {
        matches!(self, Self::Parked { .. } | Self::Mutated { .. })
    }
}

/// A raw packet pulled off the in-path queue, awaiting a verdict. `handle` is the
/// backend's opaque key for issuing that verdict later (the NFQUEUE packet id).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueuedPacket {
    /// The backend's key for verdicting this packet.
    pub handle: u32,
    /// The packet's on-wire bytes (NFQUEUE delivers the IP packet, no L2 header).
    pub bytes: Vec<u8>,
}

/// The verdict handed back to the queue for one packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireVerdict {
    /// Accept the packet: `Some(bytes)` reinjects a mangled payload, `None`
    /// forwards the kernel's original packet untouched.
    Forward(Option<Vec<u8>>),
    /// Drop the packet.
    Drop,
}

/// A bound in-path queue: the (not necessarily `Send`) half owned by the dedicated
/// reader thread. `next_packet` blocks up to `read_timeout` so the owning loop
/// stays responsive to the stop flag and verdict deadlines; `verdict` releases a
/// packet the queue still holds. Mirrors [`CaptureSource`](crate::backend::CaptureSource),
/// with a verdict path.
pub trait InterceptQueue {
    /// Block up to `read_timeout` for the next queued packet. `Ok(None)` means the
    /// poll elapsed with no packet (loop and re-check deadlines); `Err` is
    /// fail-closed and ends the reader.
    fn next_packet(&mut self, read_timeout: Duration) -> Result<Option<QueuedPacket>, L4Error>;

    /// Issue the verdict for a packet the queue still holds, by its `handle`. An
    /// unknown/already-verdicted handle is a no-op (idempotent).
    fn verdict(&mut self, handle: u32, verdict: WireVerdict) -> Result<(), L4Error>;
}

/// Opens a bound in-path queue. The `Send + Sync` half the module holds; `open`
/// runs on the dedicated reader thread (the NFQUEUE handle is best created and
/// owned there, like the pcap capture source). Fail-closed: [`L4Error::Unavailable`]
/// on macOS/unsupported or without `CAP_NET_ADMIN`.
pub trait InterceptBackend: Send + Sync {
    /// Bind the queue and return its reader. Fail-closed on missing privilege or an
    /// unsupported OS.
    fn open(&self) -> Result<Box<dyn InterceptQueue>, L4Error>;
}

/// Where and how to bind an in-path interception. The interface + direction name
/// the bind the guard authorizes and the scope the per-packet check uses; `config`
/// carries the queue number and the fail-open lifecycle knobs.
#[derive(Debug, Clone)]
pub struct InterceptParams {
    /// The interface the `nft` rule steers into the queue (e.g. `eth0`).
    pub interface: String,
    /// The direction the authorizing scope entries declare.
    pub direction: L4Direction,
    /// Queue number + fail-open lifecycle (`verdict_timeout`, `max_parked`,
    /// `on_timeout`, `on_overflow`).
    pub config: InterceptConfig,
    /// Per-poll read timeout handed to the queue.
    pub read_timeout: Duration,
}

impl InterceptParams {
    /// Parameters for `interface` + `direction` + `config` with the default read
    /// timeout.
    #[must_use]
    pub fn new(
        interface: impl Into<String>,
        direction: L4Direction,
        config: InterceptConfig,
    ) -> Self {
        Self {
            interface: interface.into(),
            direction,
            config,
            read_timeout: DEFAULT_READ_TIMEOUT,
        }
    }
}

/// One parked packet plus the backend handle needed to verdict it. The handle
/// never leaves the reader thread; commands address the packet by its [`ParkedId`]
/// and the thread maps that to the handle.
#[derive(Debug)]
struct ParkedEntry {
    handle: u32,
    parked: ParkedPacket,
}

/// The parked-packet table shared between the reader thread and the handle: the
/// thread inserts/expires, commands read ([`InterceptHandle::parked`]) and submit
/// verdicts. It also owns the session's **arrival sequence**: [`ParkedTable::park`]
/// takes the next number under the same lock as the insert, so `parked_seq` order
/// is exactly insertion order (spec §4 / AC37).
#[derive(Debug, Default)]
struct ParkedTable {
    entries: HashMap<ParkedId, ParkedEntry>,
    /// The next arrival sequence number for this session (monotonic, from 0).
    next_seq: u64,
}

impl ParkedTable {
    /// Park `packet` as `id` behind the backend `handle`, stamping its arrival
    /// sequence and `parked_at`. The only way a packet enters the table.
    fn park(
        &mut self,
        handle: u32,
        id: ParkedId,
        flow: L4FlowId,
        packet: L4Packet,
        parked_at: SystemTime,
        deadline: SystemTime,
    ) {
        let parked_seq = self.next_seq;
        self.next_seq += 1;
        let parked = ParkedPacket {
            id,
            flow,
            packet: packet.clone(),
            state: L4InterceptState::Parked {
                backup: Box::new(packet),
            },
            deadline,
            parked_seq,
            parked_at,
        };
        self.entries.insert(id, ParkedEntry { handle, parked });
    }
}

/// A verdict a command submits for a parked packet (M5 Task 12 routes through
/// here). Applied on the reader thread so the backend stays single-owner.
#[derive(Debug)]
struct VerdictRequest {
    id: ParkedId,
    verdict: Verdict,
    /// Mangled payload for a `Forward` (`None` forwards untouched).
    mutated: Option<Vec<u8>>,
}

/// A live interception session: the flow it records into, the parked-packet table,
/// the channel that submits verdicts to the reader thread, the stop flag, and the
/// `Intercept` permit held for the session's lifetime.
#[derive(Debug)]
pub struct InterceptHandle {
    flow_id: L4FlowId,
    parked: Arc<Mutex<ParkedTable>>,
    verdict_tx: mpsc::Sender<VerdictRequest>,
    stop: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
    /// Held, not used: proves the session was authorized and keeps the guard's
    /// in-flight gauge accurate until the session ends.
    _permit: L4Permit,
}

impl InterceptHandle {
    /// The id of the `Intercept` flow this session records packets into.
    #[must_use]
    pub fn flow_id(&self) -> L4FlowId {
        self.flow_id
    }

    /// A snapshot of the currently-parked packets (clones), for `l4.intercept.list`.
    #[must_use]
    pub fn parked(&self) -> Vec<ParkedPacket> {
        self.parked
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entries
            .values()
            .map(|e| e.parked.clone())
            .collect()
    }

    /// Submit a verdict for the parked packet `id` (M5 Task 12's `forward`/`drop`).
    /// The reader thread applies it against the backend on its next poll. Returns
    /// `false` if the channel is closed (the session has ended).
    pub fn submit_verdict(&self, id: ParkedId, verdict: Verdict, mutated: Option<Vec<u8>>) -> bool {
        self.verdict_tx
            .send(VerdictRequest {
                id,
                verdict,
                mutated,
            })
            .is_ok()
    }

    /// Signal the reader thread to stop and wait for it to drain and exit. On exit
    /// the thread fail-open forwards anything still parked (never black-holed).
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

impl Drop for InterceptHandle {
    /// A dropped handle never leaks its thread: dropping signals stop and joins.
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Start a scoped in-path interception on `params.interface`.
///
/// Authorization precedes any I/O: an `Intercept` [`L4Permit`] is minted first (so
/// an unauthorized session never binds a queue), then the queue is opened on a
/// dedicated thread (fail-closed on missing privilege / unsupported OS). The reader
/// parks only in-scope packets, auto-forwards out-of-scope ones untouched, and
/// enforces the fail-open lifecycle.
///
/// # Errors
/// - [`L4Error::Guard`] if the scope does not grant `Intercept` on the interface
///   (deny-by-default: `OutOfL4Scope` / `CapabilityNotGranted`);
/// - [`L4Error::Unavailable`] if NFQUEUE/privilege is absent or the OS is
///   unsupported (fail-closed), or the reader thread dies before binding.
pub fn start_intercept(
    guard: Arc<L4Guard>,
    store: Arc<dyn L4FlowStore>,
    backend: Arc<dyn InterceptBackend>,
    params: InterceptParams,
) -> Result<InterceptHandle, L4Error> {
    // (1) Authorization precedes any I/O. An interception bind has no single
    // destination, so the target carries `dst: None`: the guard then requires an
    // `Intercept` entry on this interface + direction (deny-by-default). The minted
    // permit is held for the session's lifetime.
    let bind_target = L4Target {
        interface: params.interface.clone(),
        direction: params.direction,
        dst: None,
        dst_port: None,
        proto: L4Proto::Raw,
    };
    let permit = guard.check(L4Action::Intercept, &bind_target)?;

    let parked: Arc<Mutex<ParkedTable>> = Arc::new(Mutex::new(ParkedTable::default()));
    let stop = Arc::new(AtomicBool::new(false));
    let (verdict_tx, verdict_rx) = mpsc::channel::<VerdictRequest>();
    let (open_tx, open_rx) = mpsc::channel::<Result<L4FlowId, L4Error>>();

    let bind = L4Bind {
        interface: params.interface.clone(),
        filter: None,
        queue: Some(params.config.queue_num),
    };

    let thread_guard = guard.clone();
    let thread_store = store.clone();
    let thread_parked = parked.clone();
    let thread_stop = stop.clone();
    let thread_params = params.clone();

    let join = thread::spawn(move || {
        // Open on this dedicated thread: the NFQUEUE handle is best owned here (its
        // recv/verdict share one owner, and the stable API is blocking), mirroring
        // the pcap capture source. The fail-closed open result goes back over
        // `open_tx`.
        let queue = match backend.open() {
            Ok(queue) => queue,
            Err(e) => {
                let _ = open_tx.send(Err(e));
                return;
            }
        };
        // The session is live: create its flow only now (no stray flow on a failed
        // bind) and report the id the caller addresses it by.
        let flow_id = thread_store.insert(L4Flow {
            id: L4FlowId::new(),
            kind: L4FlowKind::Intercept,
            bind,
            packets: std::collections::VecDeque::new(),
            metadata: L4Meta::default(),
        });
        if open_tx.send(Ok(flow_id)).is_err() {
            return; // the caller gave up before we bound; nothing to record into.
        }

        run_loop(
            queue,
            &thread_guard,
            thread_store.as_ref(),
            &thread_parked,
            &verdict_rx,
            &thread_stop,
            flow_id,
            &thread_params,
        );
    });

    match open_rx.recv() {
        Ok(Ok(flow_id)) => Ok(InterceptHandle {
            flow_id,
            parked,
            verdict_tx,
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
                "intercept thread terminated before binding".into(),
            ))
        }
    }
}

/// The reader loop, owned by the dedicated thread. Each iteration: apply any
/// submitted verdicts, expire any parked packet past its deadline (fail-open
/// `on_timeout`), then poll for the next packet and park-or-forward it. On stop it
/// fail-open forwards everything still parked.
#[allow(clippy::too_many_arguments)]
fn run_loop(
    mut queue: Box<dyn InterceptQueue>,
    guard: &L4Guard,
    store: &dyn L4FlowStore,
    parked: &Mutex<ParkedTable>,
    verdict_rx: &mpsc::Receiver<VerdictRequest>,
    stop: &AtomicBool,
    flow_id: L4FlowId,
    params: &InterceptParams,
) {
    while !stop.load(Ordering::Acquire) {
        // (1) Apply any command-submitted verdicts (forward/drop) first.
        while let Ok(req) = verdict_rx.try_recv() {
            apply_submitted(queue.as_mut(), parked, req);
        }
        // (2) Expire any parked packet past its deadline — fail open (default
        // Forward) so a packet nobody judged in time is never black-holed.
        expire_due(queue.as_mut(), parked, params.config.on_timeout);
        // (3) Poll for the next packet and park-or-forward it.
        match queue.next_packet(params.read_timeout) {
            Ok(Some(qp)) => {
                process_packet(qp, guard, store, parked, queue.as_mut(), params, flow_id);
            }
            // Timed-out poll: no packet yet — loop and re-check verdicts/deadlines.
            Ok(None) => {}
            // A read error is fail-closed: end the reader rather than spin.
            Err(_) => break,
        }
    }
    // On shutdown, fail-open forward anything still parked — never black-hole a
    // held packet when the session ends.
    drain_forward(queue.as_mut(), parked);
}

/// Apply a command-submitted verdict to a parked packet, if it is still parked.
fn apply_submitted(
    queue: &mut dyn InterceptQueue,
    parked: &Mutex<ParkedTable>,
    req: VerdictRequest,
) {
    let entry = parked
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .entries
        .remove(&req.id);
    if let Some(entry) = entry {
        let _ = queue.verdict(entry.handle, wire_of(req.verdict, req.mutated));
    }
}

/// Forward or drop every parked packet whose deadline has passed, per `on_timeout`
/// (default Forward — fail open). Removes them from the table.
fn expire_due(queue: &mut dyn InterceptQueue, parked: &Mutex<ParkedTable>, on_timeout: Verdict) {
    let now = SystemTime::now();
    let due: Vec<ParkedId> = {
        let table = parked.lock().unwrap_or_else(PoisonError::into_inner);
        table
            .entries
            .iter()
            .filter(|(_, e)| e.parked.state.is_live() && e.parked.deadline <= now)
            .map(|(id, _)| *id)
            .collect()
    };
    for id in due {
        let entry = parked
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entries
            .remove(&id);
        if let Some(entry) = entry {
            let _ = queue.verdict(entry.handle, wire_of(on_timeout, None));
        }
    }
}

/// Fail-open forward every packet still parked (used on session shutdown so a
/// held packet is never black-holed).
fn drain_forward(queue: &mut dyn InterceptQueue, parked: &Mutex<ParkedTable>) {
    let ids: Vec<ParkedId> = parked
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .entries
        .keys()
        .copied()
        .collect();
    for id in ids {
        let entry = parked
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entries
            .remove(&id);
        if let Some(entry) = entry {
            let _ = queue.verdict(entry.handle, WireVerdict::Forward(None));
        }
    }
}

/// Decode a queued packet and, if the **same** guard authorizes it for `Intercept`,
/// park it; otherwise auto-forward it untouched (AC14). Overflow past `max_parked`
/// fails open per `on_overflow`.
#[allow(clippy::too_many_arguments)]
fn process_packet(
    qp: QueuedPacket,
    guard: &L4Guard,
    store: &dyn L4FlowStore,
    parked: &Mutex<ParkedTable>,
    queue: &mut dyn InterceptQueue,
    params: &InterceptParams,
    flow_id: L4FlowId,
) {
    // A packet that carries no IP target cannot be in a CIDR-scoped interception —
    // forward it untouched rather than park it.
    let Some(target) = ip_target(&qp.bytes, &params.interface, params.direction) else {
        let _ = queue.verdict(qp.handle, WireVerdict::Forward(None));
        return;
    };
    // The second scope boundary (the `nft` rule is the first): only in-scope packets
    // park. An out-of-scope packet is auto-forwarded untouched, never parked (AC14).
    // A dropped momentary `Intercept` permit keeps the guard's in-flight gauge even.
    if guard.check(L4Action::Intercept, &target).is_err() {
        let _ = queue.verdict(qp.handle, WireVerdict::Forward(None));
        return;
    }
    // Overflow: fail open (default Forward) rather than black-hole the packet.
    {
        let table = parked.lock().unwrap_or_else(PoisonError::into_inner);
        if table.entries.len() as u32 >= params.config.max_parked {
            drop(table);
            let _ = queue.verdict(qp.handle, wire_of(params.config.on_overflow, None));
            return;
        }
    }
    let now = SystemTime::now();
    let packet = L4Packet {
        dir: params.direction,
        timestamp: now,
        decoded: PacketSpec::summarize(&qp.bytes),
        bytes: qp.bytes.clone(),
        injected: false,
    };
    // Park under the table's lock, which stamps the arrival sequence (AC37).
    parked.lock().unwrap_or_else(PoisonError::into_inner).park(
        qp.handle,
        ParkedId::new(),
        flow_id,
        packet.clone(),
        now,
        now + params.config.verdict_timeout,
    );
    // Record the parked packet in the interception flow (observed, not injected).
    store.append_packet(flow_id, packet);
}

/// A config [`Verdict`] plus optional mangled payload as a wire verdict.
fn wire_of(verdict: Verdict, mutated: Option<Vec<u8>>) -> WireVerdict {
    match verdict {
        Verdict::Forward => WireVerdict::Forward(mutated),
        Verdict::Drop => WireVerdict::Drop,
    }
}

/// Resolve an NFQUEUE payload (an IP packet — no L2 header) to the `L4Target` the
/// guard checks: destination address, destination port (TCP/UDP), and protocol.
/// `None` for a buffer that carries no IP layer (such a packet is out of a
/// CIDR-scoped interception by definition).
///
/// `pub(crate)` so the command layer can re-resolve a *mutated* packet's target and
/// re-check it against the guard before reinjecting it (M5 Task 12 forward path).
pub(crate) fn ip_target(
    payload: &[u8],
    interface: &str,
    direction: L4Direction,
) -> Option<L4Target> {
    let parsed = SlicedPacket::from_ip(payload).ok()?;
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

// Test-only seams. They sit after every production item on purpose: the AC21
// tripwire in `tests/hard_gates.rs` audits the text before the first test-only
// `cfg` attribute as the production code.
#[cfg(test)]
impl ParkedId {
    /// A deterministic id for tests that need to control uuid string order.
    #[must_use]
    pub fn from_u128(v: u128) -> Self {
        Self(Uuid::from_u128(v))
    }
}

#[cfg(test)]
impl InterceptHandle {
    /// Park `packet` under a caller-chosen `id` with no backend packet behind it
    /// (the kernel handle is a sentinel), through the same [`ParkedTable::park`]
    /// path the reader uses, so the command layer can prove arrival ordering with
    /// deterministic ids. A verdict on it is a no-op at the mock queue.
    pub(crate) fn park_for_test(&self, id: ParkedId, packet: L4Packet, deadline: SystemTime) {
        self.parked
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .park(
                u32::MAX,
                id,
                self.flow_id,
                packet,
                SystemTime::now(),
                deadline,
            );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::config::L4Config;
    use crate::craft::{Ipv4Spec, Layer, PacketSpec, UdpSpec};
    use crate::flow::InMemoryL4FlowStore;
    use crate::types::{IpCidr, L4Capability, L4ScopeEntry, L4ScopeId, PortRange, RateCap};
    use std::net::Ipv4Addr;
    use std::sync::atomic::AtomicU32;

    const IFACE: &str = "eth0";

    fn cfg() -> L4Config {
        L4Config::default()
    }

    /// An `Intercept` scope entry on [`IFACE`] covering `cidr`.
    fn intercept_entry(cidr: (&str, u8)) -> L4ScopeEntry {
        L4ScopeEntry {
            id: L4ScopeId::new(),
            cidr: IpCidr {
                addr: cidr.0.parse().unwrap(),
                prefix: cidr.1,
            },
            ports: PortRange {
                lo: 0,
                hi: u16::MAX,
            },
            interface: IFACE.to_string(),
            direction: L4Direction::Outbound,
            capability: L4Capability::Intercept,
            inject_rate: RateCap { pps: 10, burst: 10 },
            source: crate::types::L4ScopeSource::Config,
        }
    }

    fn guard_with(entries: Vec<L4ScopeEntry>) -> Arc<L4Guard> {
        let g = L4Guard::new(&cfg());
        for e in entries {
            g.add_scope(e).unwrap();
        }
        Arc::new(g)
    }

    /// A crafted IPv4/UDP packet (starting at L3, exactly as NFQUEUE delivers) to
    /// `dst:9`.
    fn ip_udp(dst: &str) -> Vec<u8> {
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

    /// A recorded verdict: the packet handle and what was decided.
    #[derive(Debug, Clone, PartialEq, Eq)]
    enum VKind {
        Forward,
        ForwardMangled(Vec<u8>),
        Drop,
    }

    /// The shared log of `(handle, verdict)` the mock queue records.
    type VerdictLog = Arc<Mutex<Vec<(u32, VKind)>>>;

    /// A mock [`InterceptBackend`] + [`InterceptQueue`]: it replays a fixed script
    /// of packets into one session, records every verdict, and flips `drained`
    /// once the script is exhausted so a test can wait deterministically. No
    /// NFQUEUE, no privilege. `available` false simulates a fail-closed bind.
    struct MockBackend {
        available: bool,
        script: Mutex<Option<Vec<Vec<u8>>>>,
        verdicts: VerdictLog,
        drained: Arc<AtomicBool>,
    }

    impl MockBackend {
        fn with(frames: Vec<Vec<u8>>) -> (Arc<Self>, VerdictLog, Arc<AtomicBool>) {
            let verdicts = Arc::new(Mutex::new(Vec::new()));
            let drained = Arc::new(AtomicBool::new(false));
            let backend = Arc::new(Self {
                available: true,
                script: Mutex::new(Some(frames)),
                verdicts: verdicts.clone(),
                drained: drained.clone(),
            });
            (backend, verdicts, drained)
        }

        fn unavailable() -> Arc<Self> {
            Arc::new(Self {
                available: false,
                script: Mutex::new(Some(Vec::new())),
                verdicts: Arc::new(Mutex::new(Vec::new())),
                drained: Arc::new(AtomicBool::new(false)),
            })
        }
    }

    impl InterceptBackend for MockBackend {
        fn open(&self) -> Result<Box<dyn InterceptQueue>, L4Error> {
            if !self.available {
                return Err(L4Error::Unavailable("no privilege (mock)".into()));
            }
            let frames = self.script.lock().unwrap().take().unwrap_or_default();
            Ok(Box::new(MockQueue {
                frames: frames.into_iter().collect(),
                next_handle: AtomicU32::new(0),
                verdicts: self.verdicts.clone(),
                drained: self.drained.clone(),
            }))
        }
    }

    struct MockQueue {
        frames: std::collections::VecDeque<Vec<u8>>,
        next_handle: AtomicU32,
        verdicts: VerdictLog,
        drained: Arc<AtomicBool>,
    }

    impl InterceptQueue for MockQueue {
        fn next_packet(
            &mut self,
            _read_timeout: Duration,
        ) -> Result<Option<QueuedPacket>, L4Error> {
            match self.frames.pop_front() {
                Some(bytes) => {
                    let handle = self.next_handle.fetch_add(1, Ordering::SeqCst);
                    Ok(Some(QueuedPacket { handle, bytes }))
                }
                None => {
                    // Drained: signal the test and idle like a real read timeout.
                    self.drained.store(true, Ordering::Release);
                    thread::sleep(Duration::from_millis(5));
                    Ok(None)
                }
            }
        }

        fn verdict(&mut self, handle: u32, verdict: WireVerdict) -> Result<(), L4Error> {
            let kind = match verdict {
                WireVerdict::Forward(None) => VKind::Forward,
                WireVerdict::Forward(Some(bytes)) => VKind::ForwardMangled(bytes),
                WireVerdict::Drop => VKind::Drop,
            };
            self.verdicts.lock().unwrap().push((handle, kind));
            Ok(())
        }
    }

    fn params(config: InterceptConfig) -> InterceptParams {
        let mut p = InterceptParams::new(IFACE, L4Direction::Outbound, config);
        // Fast poll so deadlines/stop are honoured promptly in tests.
        p.read_timeout = Duration::from_millis(5);
        p
    }

    fn wait_for(flag: &AtomicBool) {
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while !flag.load(Ordering::Acquire) {
            assert!(std::time::Instant::now() < deadline, "reader did not drain");
            thread::sleep(Duration::from_millis(2));
        }
    }

    fn wait_until(mut cond: impl FnMut() -> bool, what: &str) {
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while !cond() {
            assert!(
                std::time::Instant::now() < deadline,
                "timed out waiting for {what}"
            );
            thread::sleep(Duration::from_millis(2));
        }
    }

    fn intercept_config(verdict_timeout: Duration, on_timeout: Verdict) -> InterceptConfig {
        InterceptConfig {
            queue_num: 0,
            verdict_timeout,
            on_timeout,
            max_parked: 16,
            on_overflow: Verdict::Forward,
        }
    }

    /// Pinned (plan Task 11, AC14): an out-of-scope queued packet is forwarded
    /// untouched and never parked. Empty scope ⇒ every packet is out of scope.
    /// Hermetic — the mock backend proves the state machine with no NFQUEUE.
    #[test]
    fn out_of_scope_auto_forward() {
        // The session is authorized for a narrow in-scope CIDR (the bind passes the
        // guard), but the queued packet is destined elsewhere — out of scope.
        let guard = guard_with(vec![intercept_entry(("10.0.0.5", 32))]);
        let store: Arc<dyn L4FlowStore> = Arc::new(InMemoryL4FlowStore::new());
        let (backend, verdicts, drained) = MockBackend::with(vec![ip_udp("8.8.8.8")]);

        let handle = start_intercept(
            guard,
            store,
            backend,
            params(intercept_config(Duration::from_secs(5), Verdict::Forward)),
        )
        .expect("authorized bind starts");

        wait_for(&drained);
        // The out-of-scope packet was forwarded untouched, and nothing parked.
        wait_until(
            || !verdicts.lock().unwrap().is_empty(),
            "the forward verdict",
        );
        assert_eq!(verdicts.lock().unwrap().as_slice(), &[(0, VKind::Forward)]);
        assert!(
            handle.parked().is_empty(),
            "an out-of-scope packet is never parked"
        );

        handle.stop();
    }

    /// Pinned (plan Task 11, AC15): a parked packet past its deadline gets
    /// `on_timeout` (Forward) and the reader does not hang. Hermetic.
    #[test]
    fn verdict_timeout_forwards() {
        let guard = guard_with(vec![intercept_entry(("10.0.0.5", 32))]);
        let store: Arc<dyn L4FlowStore> = Arc::new(InMemoryL4FlowStore::new());
        let (backend, verdicts, _drained) = MockBackend::with(vec![ip_udp("10.0.0.5")]);

        let handle = start_intercept(
            guard,
            store,
            backend,
            // Short deadline so the timeout fires quickly; on_timeout = Forward.
            params(intercept_config(
                Duration::from_millis(40),
                Verdict::Forward,
            )),
        )
        .expect("authorized bind starts");

        // The in-scope packet parks first ...
        wait_until(|| !handle.parked().is_empty(), "the packet to park");
        // ... then, past its deadline, on_timeout forwards it and clears the park.
        wait_until(
            || !verdicts.lock().unwrap().is_empty(),
            "the timeout verdict",
        );
        assert_eq!(verdicts.lock().unwrap().as_slice(), &[(0, VKind::Forward)]);
        wait_until(
            || handle.parked().is_empty(),
            "the park to clear on timeout",
        );

        // The reader did not hang: stop() joins promptly.
        handle.stop();
    }

    /// A command-submitted Forward verdict reaches the backend and clears the park
    /// (the seam M5 Task 12's `l4.intercept.forward` rides). Hermetic.
    #[test]
    fn submitted_forward_verdict_delivered() {
        let guard = guard_with(vec![intercept_entry(("10.0.0.5", 32))]);
        let store: Arc<dyn L4FlowStore> = Arc::new(InMemoryL4FlowStore::new());
        let (backend, verdicts, _drained) = MockBackend::with(vec![ip_udp("10.0.0.5")]);

        let handle = start_intercept(
            guard,
            store,
            backend,
            // Long deadline so the packet stays parked until we verdict it.
            params(intercept_config(Duration::from_secs(10), Verdict::Forward)),
        )
        .expect("authorized bind starts");

        wait_until(|| !handle.parked().is_empty(), "the packet to park");
        let id = handle.parked()[0].id;
        assert!(handle.submit_verdict(id, Verdict::Forward, None));

        wait_until(
            || !verdicts.lock().unwrap().is_empty(),
            "the submitted verdict",
        );
        assert_eq!(verdicts.lock().unwrap().as_slice(), &[(0, VKind::Forward)]);
        wait_until(|| handle.parked().is_empty(), "the park to clear");

        handle.stop();
    }

    /// Deny-by-default: an empty scope refuses to bind an interception — no permit,
    /// no queue.
    #[test]
    fn empty_scope_refused() {
        let guard = guard_with(vec![]);
        let store: Arc<dyn L4FlowStore> = Arc::new(InMemoryL4FlowStore::new());
        let (backend, _v, _d) = MockBackend::with(vec![]);
        let err = start_intercept(
            guard,
            store,
            backend,
            params(intercept_config(Duration::from_secs(5), Verdict::Forward)),
        )
        .unwrap_err();
        assert!(
            matches!(
                err,
                L4Error::Guard(crate::guard::L4GuardError::OutOfL4Scope(_))
            ),
            "empty scope must refuse the bind, got {err:?}"
        );
    }

    /// Fail-closed: an authorized bind whose backend cannot open surfaces
    /// `L4Unavailable` and spawns no live session; the momentary permit is released.
    #[test]
    fn bind_fail_closed_without_privilege() {
        let guard = guard_with(vec![intercept_entry(("10.0.0.5", 32))]);
        let store: Arc<dyn L4FlowStore> = Arc::new(InMemoryL4FlowStore::new());
        let backend = MockBackend::unavailable();
        let err = start_intercept(
            guard.clone(),
            store,
            backend,
            params(intercept_config(Duration::from_secs(5), Verdict::Forward)),
        )
        .unwrap_err();
        assert!(matches!(err, L4Error::Unavailable(_)), "got {err:?}");
        assert_eq!(guard.in_flight(), 0, "a failed bind releases its permit");
    }

    /// Pinned (plan Task 11, AC16): on a non-Linux OS (or Linux without
    /// `CAP_NET_ADMIN`) starting a real NFQUEUE interception returns `L4Unavailable`
    /// and never panics. The bind scope grants `Intercept` so the failure is the
    /// backend's, not the guard's.
    #[test]
    fn unsupported_or_no_cap() {
        let guard = guard_with(vec![intercept_entry(("0.0.0.0", 0))]);
        let store: Arc<dyn L4FlowStore> = Arc::new(InMemoryL4FlowStore::new());
        let backend: Arc<dyn InterceptBackend> = Arc::new(NfqueueBackend::new(0));
        let res = start_intercept(
            guard,
            store,
            backend,
            params(intercept_config(Duration::from_secs(5), Verdict::Forward)),
        );

        #[cfg(not(target_os = "linux"))]
        assert!(
            matches!(res, Err(L4Error::Unavailable(_))),
            "in-path interception is Linux-only; every other OS must be L4Unavailable, got {res:?}"
        );

        #[cfg(target_os = "linux")]
        match res {
            // With CAP_NET_ADMIN and a free queue it may bind; without, it is
            // L4Unavailable. Either is fine — the point is no panic.
            Ok(handle) => handle.stop(),
            Err(L4Error::Unavailable(_)) => {}
            Err(e) => panic!("unexpected non-unavailable error: {e:?}"),
        }
    }
}
