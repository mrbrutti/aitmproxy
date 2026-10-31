//! The live capture feeder for the macOS Network/System Extension: the core-side
//! runtime that binds the [`CaptureListener`], publishes the rendezvous file,
//! authenticates the provider, pushes scope, and pumps every captured flow into
//! [`CoreIngress`] through [`dispatch_captured_flow`].
//!
//! It adds **no** dispatch, guard, or wire-write path of its own: scope and
//! deny-by-default live below it in the ingress, exactly as for the Linux `pcap`
//! path. It is **fail-open at every step** — a bind, accept, auth, scope, or pump
//! failure is logged and ends only the thing that failed; nothing here panics or
//! aborts the core, and a feeder that never starts or stops leaves the provider
//! with no attached core, which by the provider's contract sends every flow direct.
//!
//! # Shape
//!
//! [`CaptureSession::run`] owns the listener and the rendezvous guard for the whole
//! session and serves one attached provider at a time. Serving an attachment runs
//! two concerns concurrently, sharing one per-attachment `FlowPairing`:
//!
//! - **control** (`serve_control`): verify the peer's code
//!   signature, gate on the `Hello`, push the scope (and re-push it when it
//!   changes), then read `FlowOpen`s;
//! - **data**: accept per-flow data sockets, verify each peer, and pair each with
//!   its `FlowOpen` by `flow_id`. A paired flow gets its own pump task.
//!
//! The control channel is split ([`ControlChannel::into_halves`]) after the peer
//! and `Hello` checks so the read loop and the scope timer never cancel each
//! other mid-frame.

use std::collections::VecDeque;
use std::future::Future;
use std::io;
use std::os::fd::{AsRawFd, RawFd};
use std::panic::AssertUnwindSafe;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use aitm_core::ScopeRateGuard;
use aitm_proto_l4::guard::L4Guard;
use futures::stream::{FuturesUnordered, StreamExt};
use futures::FutureExt;
use tokio::sync::{watch, OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinHandle;
use tracing::{debug, error, info, warn};

use super::adapter::{dispatch_captured_flow, recv_hello, CaptureOutcome};
use super::listener::{
    CaptureListener, ControlChannel, ControlMessage, DataConnection, FlowOpen, ScopeSpec,
};
use super::peer_auth::PeerVerifier;
use super::scope_spec::provider_scope_spec;
use crate::ingress::CoreIngress;

/// The production socket directory: short enough for the `sun_path` budget, created
/// and locked to 0700 by [`CaptureListener::bind`].
pub const DEFAULT_SOCKET_DIR: &str = "/private/tmp/aitmproxy-capture.d";

/// How often an attached provider's scope is recomputed. The provider is a coarse
/// pre-filter under the authoritative core guard, so a scope at most this stale is
/// safe: too narrow sends a flow direct, too wide is refused by the core guard.
pub(crate) const DEFAULT_SCOPE_POLL: Duration = Duration::from_secs(1);

/// Cap on each of the two pending-pairing maps (unpaired opens, unpaired data
/// sockets); the oldest is evicted past it.
pub(crate) const DEFAULT_PENDING_CAP: usize = 1024;

/// Cap on concurrently pumped flows; a pair arriving at the cap is shed.
pub(crate) const DEFAULT_MAX_CONCURRENT_FLOWS: usize = 4096;

/// How long an unpaired half may wait for its other half before it is dropped.
pub(crate) const DEFAULT_PENDING_TTL: Duration = Duration::from_secs(30);

/// Concurrent data-accept pipelines (accept, handshake, verify, pair). One silent
/// or slow peer holds one slot, never the whole data path.
const DATA_ACCEPTORS: usize = 16;

/// Pause after an accept error before retrying, so a persistent failure (fd
/// exhaustion) cannot spin the loop.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(500);

/// How long a just-accepted control connection has to be verified and send its
/// `Hello`. The feeder serves one attachment at a time, so a connected peer that
/// never says anything (one silent same-uid squatter, or a wedged provider) would
/// otherwise hold the single attachment slot, and every later provider, forever. A
/// real provider sends its `Hello` immediately after connecting and verification is
/// a local Security.framework call; seconds is generous. Mirrors the data socket's
/// `DATA_HANDSHAKE_TIMEOUT`.
const HELLO_TIMEOUT: Duration = Duration::from_secs(5);

/// Lock `m`, recovering from a poisoned lock: the maps hold plain data and no
/// critical section here can leave them inconsistent.
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// One side's pending halves, oldest first, bounded.
struct Pending<T> {
    cap: usize,
    items: VecDeque<(u64, Instant, T)>,
    evicted: u64,
}

impl<T> Pending<T> {
    fn new(cap: usize) -> Self {
        Self {
            cap,
            items: VecDeque::new(),
            evicted: 0,
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.items.len()
    }

    /// Remove and return the half waiting for `flow_id`. The wait is short and the
    /// queue is capped, so a scan from the oldest end is cheap.
    fn take(&mut self, flow_id: u64) -> Option<T> {
        let idx = self.items.iter().position(|(id, _, _)| *id == flow_id)?;
        self.items.remove(idx).map(|(_, _, item)| item)
    }

    /// Hold `item`, replacing any older half for the same `flow_id` and evicting
    /// the oldest halves while over the cap.
    fn insert(&mut self, flow_id: u64, now: Instant, item: T) {
        if self.take(flow_id).is_some() {
            self.evicted += 1;
        }
        self.items.push_back((flow_id, now, item));
        while self.items.len() > self.cap {
            self.items.pop_front();
            self.evicted += 1;
        }
    }

    /// Drop halves that have waited longer than `ttl` (the queue is in arrival
    /// order, so the stale ones are at the front).
    fn sweep(&mut self, now: Instant, ttl: Duration) {
        while let Some((_, since, _)) = self.items.front() {
            if now.saturating_duration_since(*since) <= ttl {
                break;
            }
            self.items.pop_front();
            self.evicted += 1;
        }
    }
}

/// Pairs each `FlowOpen` (control channel) with its data socket by `flow_id`. The
/// two arrive on different sockets in either order, so each side waits, bounded,
/// for the other. Generic over the data half so the logic is testable without a
/// bound listener (a real [`DataConnection`] needs one).
pub(crate) struct FlowPairing<D = DataConnection> {
    ttl: Duration,
    opens: Pending<FlowOpen>,
    data: Pending<D>,
}

impl<D> FlowPairing<D> {
    /// An empty pairing map holding at most `cap` unpaired opens and `cap` unpaired
    /// data halves, each dropped after `ttl` unpaired.
    #[must_use]
    pub(crate) fn new(cap: usize, ttl: Duration) -> Self {
        Self {
            ttl,
            opens: Pending::new(cap),
            data: Pending::new(cap),
        }
    }

    /// Offer a `FlowOpen`. Returns the ready pair if its data half is already here,
    /// else holds it (evicting the oldest open past the cap).
    pub(crate) fn offer_open(&mut self, open: FlowOpen, now: Instant) -> Option<(FlowOpen, D)> {
        if let Some(data) = self.data.take(open.flow_id) {
            return Some((open, data));
        }
        self.opens.insert(open.flow_id, now, open);
        None
    }

    /// Offer the data half of `flow_id`. Returns the ready pair if its `FlowOpen` is
    /// already here, else holds it (evicting the oldest data half past the cap).
    pub(crate) fn offer_data(
        &mut self,
        flow_id: u64,
        data: D,
        now: Instant,
    ) -> Option<(FlowOpen, D)> {
        if let Some(open) = self.opens.take(flow_id) {
            return Some((open, data));
        }
        self.data.insert(flow_id, now, data);
        None
    }

    /// Drop every half that has waited longer than the ttl.
    pub(crate) fn sweep(&mut self, now: Instant) {
        self.opens.sweep(now, self.ttl);
        self.data.sweep(now, self.ttl);
    }

    /// Unpaired opens currently held.
    #[cfg(test)]
    #[must_use]
    fn pending_opens_len(&self) -> usize {
        self.opens.len()
    }

    /// Unpaired data halves currently held.
    #[cfg(test)]
    #[must_use]
    fn pending_data_len(&self) -> usize {
        self.data.len()
    }

    /// Halves dropped (cap eviction, replacement, or timeout) since the last call;
    /// resets to 0.
    pub(crate) fn take_evicted(&mut self) -> u64 {
        std::mem::take(&mut self.opens.evicted) + std::mem::take(&mut self.data.evicted)
    }
}

/// The capture session: everything [`run`](Self::run) needs to bind, authenticate,
/// serve, and feed `CoreIngress`.
pub struct CaptureSession {
    ingress: Arc<CoreIngress>,
    l7_guard: Arc<dyn ScopeRateGuard>,
    l4_guard: Option<Arc<L4Guard>>,
    verifier: Arc<dyn PeerVerifier>,
    socket_dir: PathBuf,
    scope_poll: Duration,
    pending_cap: usize,
    pending_ttl: Duration,
    hello_timeout: Duration,
    pump_slots: Arc<Semaphore>,
    stop: watch::Sender<bool>,
}

impl CaptureSession {
    /// A session over the given ingress, guards, verifier, and socket directory,
    /// with the default tuning (`DEFAULT_SCOPE_POLL`, `DEFAULT_PENDING_CAP`,
    /// `DEFAULT_PENDING_TTL`, `DEFAULT_MAX_CONCURRENT_FLOWS`). `l4_guard` is `None`
    /// when L4 is not enabled.
    #[must_use]
    pub fn new(
        ingress: Arc<CoreIngress>,
        l7_guard: Arc<dyn ScopeRateGuard>,
        l4_guard: Option<Arc<L4Guard>>,
        verifier: Arc<dyn PeerVerifier>,
        socket_dir: PathBuf,
    ) -> Self {
        Self {
            ingress,
            l7_guard,
            l4_guard,
            verifier,
            socket_dir,
            scope_poll: DEFAULT_SCOPE_POLL,
            pending_cap: DEFAULT_PENDING_CAP,
            pending_ttl: DEFAULT_PENDING_TTL,
            hello_timeout: HELLO_TIMEOUT,
            pump_slots: Arc::new(Semaphore::new(DEFAULT_MAX_CONCURRENT_FLOWS)),
            stop: watch::channel(false).0,
        }
    }

    /// Recompute the scope this often (at least 1 ms).
    #[cfg(test)]
    #[must_use]
    fn with_scope_poll_interval(mut self, interval: Duration) -> Self {
        self.scope_poll = interval.max(Duration::from_millis(1));
        self
    }

    /// Cap each pending-pairing map at `cap`.
    #[cfg(test)]
    #[must_use]
    fn with_pending_cap(mut self, cap: usize) -> Self {
        self.pending_cap = cap;
        self
    }

    /// Drop an unpaired half after `ttl`.
    #[cfg(test)]
    #[must_use]
    fn with_pending_ttl(mut self, ttl: Duration) -> Self {
        self.pending_ttl = ttl;
        self
    }

    /// Allow at most `max` concurrently pumped flows; more are shed.
    #[cfg(test)]
    #[must_use]
    fn with_max_concurrent_flows(mut self, max: usize) -> Self {
        self.pump_slots = Arc::new(Semaphore::new(max));
        self
    }

    /// Give a new control connection `timeout` (not `HELLO_TIMEOUT`) to be verified
    /// and send its `Hello`.
    #[cfg(test)]
    #[must_use]
    fn with_hello_timeout(mut self, timeout: Duration) -> Self {
        self.hello_timeout = timeout;
        self
    }

    /// Run the session until `shutdown` resolves. Fail-open throughout: any
    /// failure is logged and ends only that step; the call never panics out, so a
    /// feeder bug cannot take the proxy's accept loops down with it.
    pub async fn run(self, shutdown: impl Future<Output = ()> + Send) {
        if AssertUnwindSafe(self.run_session(shutdown))
            .catch_unwind()
            .await
            .is_err()
        {
            error!("macOS capture feeder panicked and stopped; the proxy keeps serving");
        }
    }

    /// The lifecycle: bind, publish the rendezvous (holding its guard), then accept
    /// and serve providers one at a time until `shutdown`.
    async fn run_session(self, shutdown: impl Future<Output = ()> + Send) {
        tokio::pin!(shutdown);

        let listener = match CaptureListener::bind(&self.socket_dir) {
            Ok(listener) => listener,
            Err(e) => {
                warn!(dir = %self.socket_dir.display(), error = %e,
                    "macOS capture feeder cannot bind its sockets; capture is off");
                return;
            }
        };
        // Held for the whole session; removes the file on drop. Declared after the
        // listener so it is removed first: the provider stops discovering the dir
        // before the sockets in it go away.
        let _rendezvous = match listener.publish_rendezvous() {
            Ok(guard) => guard,
            Err(e) => {
                warn!(error = %e, "macOS capture feeder cannot publish its rendezvous file; capture is off");
                return;
            }
        };
        info!(dir = %listener.dir().display(), "macOS capture feeder listening");

        loop {
            let control = tokio::select! {
                () = &mut shutdown => break,
                accepted = listener.accept_control() => match accepted {
                    Ok(control) => control,
                    Err(e) => {
                        warn!(error = %e, "capture control accept failed; retrying");
                        tokio::select! {
                            () = &mut shutdown => break,
                            () = tokio::time::sleep(ACCEPT_BACKOFF) => {}
                        }
                        continue;
                    }
                },
            };
            tokio::select! {
                () = &mut shutdown => break,
                () = self.serve_attachment(&listener, control) => {}
            }
        }

        // Abort every running pump; the rendezvous guard and the listener then drop.
        self.stop.send_replace(true);
        info!("macOS capture feeder stopped");
    }

    /// Serve one attached provider: its control channel and the data sockets that
    /// pair with its `FlowOpen`s, over a pairing map that lives only as long as the
    /// attachment (a reconnecting provider's flow ids cannot collide with stale
    /// entries). Returns when the control channel ends.
    async fn serve_attachment(&self, listener: &CaptureListener, control: ControlChannel) {
        let pairing = Mutex::new(FlowPairing::new(self.pending_cap, self.pending_ttl));
        tokio::select! {
            () = self.serve_control(control, &pairing) => {}
            () = self.serve_data(listener, &pairing) => {}
        }
    }

    /// The scope to push to the provider right now: the emitter's rendering of the
    /// live L7 scope and (when L4 is enabled) the live L4 scope.
    fn current_scope_spec(&self) -> ScopeSpec {
        let l4_scope = self
            .l4_guard
            .as_ref()
            .map(|guard| guard.list_scope())
            .unwrap_or_default();
        provider_scope_spec(&self.l7_guard.list_scope(), &l4_scope)
    }

    /// Ask the verifier about the peer behind `fd`, off the async workers (the real
    /// check calls Security.framework). Fail-closed: a verifier that panics is a
    /// rejection.
    ///
    /// The caller keeps the owner of `fd` alive across this await. If the caller is
    /// cancelled first the check may finish against a closed descriptor, which can
    /// only fail, and its answer is discarded.
    async fn verify_peer(&self, fd: RawFd) -> bool {
        let verifier = Arc::clone(&self.verifier);
        match tokio::task::spawn_blocking(move || verifier.verify(fd)).await {
            Ok(verified) => verified,
            Err(e) => {
                error!(error = %e, "capture peer verifier failed; treating the peer as unverified");
                false
            }
        }
    }

    /// The control channel's admission prelude: verify the peer, then read and gate
    /// on its `Hello`. `true` only if both pass; every refusal is logged here.
    async fn admit_control(&self, control: &mut ControlChannel) -> bool {
        // The peer is verified, and its Hello read, on the whole channel: nothing is
        // read from a peer that has not been verified first.
        if !self.verify_peer(control.as_raw_fd()).await {
            warn!("capture control peer failed code-signature verification; refusing it");
            return false;
        }
        if let Err(e) = recv_hello(control).await {
            warn!(error = %e, "capture control Hello refused; closing the channel");
            return false;
        }
        true
    }

    /// Serve one attached provider's control channel: verify the peer, gate on the
    /// `Hello` (both within `hello_timeout`), push the scope and re-push it when it
    /// changes, and register each `FlowOpen` with `pairing` (starting a pump when its
    /// data half is already there). Returns when the provider detaches or any step
    /// fails.
    async fn serve_control(&self, mut control: ControlChannel, pairing: &Mutex<FlowPairing>) {
        // Bounded: the feeder serves one attachment at a time, so a peer that
        // connects and goes quiet must not hold the slot. On elapse the half-admitted
        // channel is dropped here and the accept loop takes the next connection.
        match tokio::time::timeout(self.hello_timeout, self.admit_control(&mut control)).await {
            Ok(true) => {}
            Ok(false) => return,
            Err(_elapsed) => {
                info!(
                    timeout = ?self.hello_timeout,
                    "capture control peer was not verified and did not send its Hello in time; dropping it"
                );
                return;
            }
        }
        let (mut reader, mut writer) = control.into_halves();

        let mut last_sent = self.current_scope_spec();
        if let Err(e) = writer.send(&ControlMessage::Scope(last_sent.clone())).await {
            warn!(error = %e, "could not send the initial scope; closing the channel");
            return;
        }
        info!("capture provider attached");
        debug!(scope = %last_sent.spec, "initial capture scope sent");

        // The two loops run concurrently inside the select below and are only ever
        // dropped as a whole, so the reader is never cancelled mid-frame.
        let read_loop = async {
            loop {
                match reader.recv().await {
                    Ok(Some(ControlMessage::FlowOpen(open))) => self.offer_open(pairing, open),
                    Ok(Some(other)) => {
                        debug!(message = ?other, "ignoring a non-FlowOpen control message");
                    }
                    Ok(None) => return,
                    Err(e) => {
                        warn!(error = %e, "capture control read failed; detaching the provider");
                        return;
                    }
                }
            }
        };
        let scope_loop = async {
            let mut tick = tokio::time::interval_at(
                tokio::time::Instant::now() + self.scope_poll,
                self.scope_poll,
            );
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tick.tick().await;
                self.sweep_pairing(pairing);
                let spec = self.current_scope_spec();
                if spec != last_sent {
                    if let Err(e) = writer.send(&ControlMessage::Scope(spec.clone())).await {
                        warn!(error = %e, "could not push the updated scope; detaching the provider");
                        return;
                    }
                    debug!(scope = %spec.spec, "capture scope updated");
                    last_sent = spec;
                }
            }
        };
        tokio::select! {
            () = read_loop => {}
            () = scope_loop => {}
        }
        info!("capture provider detached");
    }

    /// Accept per-flow data sockets for the life of an attachment. Each socket runs
    /// its own accept, handshake, verify, and pair pipeline, with several in flight
    /// at once, so a silent or slow peer holds one slot and never stalls the rest.
    async fn serve_data(&self, listener: &CaptureListener, pairing: &Mutex<FlowPairing>) {
        let mut pipelines = FuturesUnordered::new();
        for _ in 0..DATA_ACCEPTORS {
            pipelines.push(self.accept_one_data(listener, pairing));
        }
        while pipelines.next().await.is_some() {
            pipelines.push(self.accept_one_data(listener, pairing));
        }
    }

    /// One data socket, end to end: accept it, read its handshake (time-bounded),
    /// verify its peer, and pair it with its `FlowOpen`. Any failure drops just this
    /// socket.
    async fn accept_one_data(&self, listener: &CaptureListener, pairing: &Mutex<FlowPairing>) {
        let data = match listener.accept_data().await {
            Ok(data) => data,
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::UnexpectedEof
                        | io::ErrorKind::InvalidData
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::ConnectionReset
                ) =>
            {
                debug!(error = %e, "capture data socket dropped before pairing");
                return;
            }
            Err(e) => {
                warn!(error = %e, "capture data accept failed");
                tokio::time::sleep(ACCEPT_BACKOFF).await;
                return;
            }
        };
        let flow_id = data.flow_id;
        if !self.verify_peer(data.peer_fd()).await {
            warn!(
                flow_id,
                "capture data peer failed code-signature verification; dropping it"
            );
            return;
        }
        let ready = lock(pairing).offer_data(flow_id, data, Instant::now());
        if let Some((open, data)) = ready {
            self.start_pump(open, data);
        }
    }

    /// Register a `FlowOpen`, starting its pump if the data socket is already here.
    fn offer_open(&self, pairing: &Mutex<FlowPairing>, open: FlowOpen) {
        let ready = lock(pairing).offer_open(open, Instant::now());
        if let Some((open, data)) = ready {
            self.start_pump(open, data);
        }
    }

    /// Drop stale unpaired halves, and say so once per sweep if any were dropped
    /// (by timeout or by the cap) since the last one.
    fn sweep_pairing(&self, pairing: &Mutex<FlowPairing>) {
        let dropped = {
            let mut pairing = lock(pairing);
            pairing.sweep(Instant::now());
            pairing.take_evicted()
        };
        if dropped > 0 {
            warn!(
                dropped,
                "dropped unpaired capture flow halves (pairing cap or timeout)"
            );
        }
    }

    /// Start the pump for a paired flow, or shed it (dropping both sockets) when the
    /// concurrency cap is reached.
    fn start_pump(&self, open: FlowOpen, data: DataConnection) {
        let Some(permit) = self.claim_slot() else {
            warn!(
                flow_id = open.flow_id,
                "capture concurrency cap reached; shedding the flow"
            );
            return;
        };
        spawn_pump(
            Arc::clone(&self.ingress),
            open,
            data,
            permit,
            self.stop.subscribe(),
        );
    }

    /// Reserve a pump slot, or `None` at the concurrency cap (never queues: a queued
    /// flow would hold its sockets open and defeat the descriptor bound).
    fn claim_slot(&self) -> Option<OwnedSemaphorePermit> {
        Arc::clone(&self.pump_slots).try_acquire_owned().ok()
    }
}

/// Run `work` as one flow's pump, isolated: an `Err` or a panic is logged and ends
/// only this flow; the `permit` is released however it ends; `stop` aborts it at
/// shutdown (the sender being dropped counts as a stop).
fn spawn_guarded<F>(
    flow_id: u64,
    work: F,
    permit: OwnedSemaphorePermit,
    mut stop: watch::Receiver<bool>,
) -> JoinHandle<()>
where
    F: Future<Output = io::Result<CaptureOutcome>> + Send + 'static,
{
    tokio::spawn(async move {
        let _permit = permit;
        tokio::select! {
            result = AssertUnwindSafe(work).catch_unwind() => match result {
                Ok(Ok(outcome)) => debug!(flow_id, ?outcome, "captured flow finished"),
                Ok(Err(e)) => warn!(flow_id, error = %e, "captured flow ended with an error"),
                Err(_panic) => error!(flow_id, "captured flow pump panicked; only this flow is affected"),
            },
            // Resolves on `true` and on the sender going away; either is a stop.
            _ = stop.wait_for(|stopped| *stopped) => debug!(flow_id, "captured flow aborted at shutdown"),
        }
    })
}

/// Pump one paired flow into the ingress via [`dispatch_captured_flow`].
fn spawn_pump(
    ingress: Arc<CoreIngress>,
    open: FlowOpen,
    data: DataConnection,
    permit: OwnedSemaphorePermit,
    stop: watch::Receiver<bool>,
) -> JoinHandle<()> {
    let flow_id = open.flow_id;
    spawn_guarded(
        flow_id,
        async move { dispatch_captured_flow(&ingress, &open, data).await },
        permit,
        stop,
    )
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::sync::atomic::{AtomicU64, Ordering};

    use aitm_core::{ActionPermit, GuardError, ScopeEntry};
    use aitm_proto_l4::config::L4Config;
    use aitm_proto_l4::types::{
        IpCidr, L4Capability, L4Direction, L4ScopeEntry, L4ScopeId, L4ScopeSource, PortRange,
        RateCap,
    };
    use tokio::time::timeout;

    use super::*;
    use crate::macos_capture::adapter::{CAPTURE_INTERFACE, HANDOFF_PROTOCOL_VERSION};
    use crate::macos_capture::listener::{FlowKind, Hello};

    /// How long a test waits for something that should happen promptly.
    const PROMPT: Duration = Duration::from_secs(5);
    /// The scope poll the session tests run at.
    const POLL: Duration = Duration::from_millis(25);

    /// A verifier that records the fds it was asked about and answers a fixed way.
    struct StubVerifier {
        accept: bool,
        seen: Mutex<Vec<RawFd>>,
    }

    impl StubVerifier {
        fn new(accept: bool) -> Arc<Self> {
            Arc::new(Self {
                accept,
                seen: Mutex::new(Vec::new()),
            })
        }
    }

    impl PeerVerifier for StubVerifier {
        fn verify(&self, fd: RawFd) -> bool {
            lock(&self.seen).push(fd);
            self.accept
        }
    }

    /// A verifier with a bug.
    struct PanickingVerifier;

    impl PeerVerifier for PanickingVerifier {
        fn verify(&self, _fd: RawFd) -> bool {
            panic!("verifier bug")
        }
    }

    /// An L7 guard whose scope list tests mutate; only the scope methods are used.
    struct TestGuard {
        scope: Mutex<Vec<ScopeEntry>>,
    }

    impl TestGuard {
        fn with_hosts(hosts: &[&str]) -> Arc<Self> {
            Arc::new(Self {
                scope: Mutex::new(
                    hosts
                        .iter()
                        .map(|h| ScopeEntry {
                            host: (*h).to_string(),
                        })
                        .collect(),
                ),
            })
        }
    }

    impl ScopeRateGuard for TestGuard {
        fn check_active(&self, _host: &str) -> Result<ActionPermit, GuardError> {
            unreachable!("the feeder only lists scope")
        }
        fn add_scope(&self, entry: ScopeEntry) {
            lock(&self.scope).push(entry);
        }
        fn remove_scope(&self, _entry: &str) -> bool {
            false
        }
        fn list_scope(&self) -> Vec<ScopeEntry> {
            lock(&self.scope).clone()
        }
    }

    fn session_with(
        verifier: Arc<dyn PeerVerifier>,
        guard: Arc<TestGuard>,
        l4: Option<Arc<L4Guard>>,
    ) -> CaptureSession {
        CaptureSession::new(
            Arc::new(CoreIngress::empty()),
            guard,
            l4,
            verifier,
            PathBuf::from("/nonexistent-feeder-test-dir"),
        )
        .with_scope_poll_interval(POLL)
    }

    fn session(verifier: Arc<dyn PeerVerifier>, guard: Arc<TestGuard>) -> Arc<CaptureSession> {
        Arc::new(session_with(verifier, guard, None))
    }

    fn open(flow_id: u64) -> FlowOpen {
        FlowOpen {
            flow_id,
            kind: FlowKind::Tcp,
            remote: "93.184.216.34:443".parse().unwrap(),
            remote_hostname: Some("example.com".to_string()),
            source_app: None,
            local: None,
        }
    }

    fn hello(version: u32) -> ControlMessage {
        ControlMessage::Hello(Hello {
            protocol_version: version,
        })
    }

    fn scope(spec: &str) -> ControlMessage {
        ControlMessage::Scope(ScopeSpec {
            spec: spec.to_string(),
        })
    }

    /// A connected provider/core control pair.
    fn control_pair() -> (ControlChannel, ControlChannel) {
        let (provider, core) = tokio::net::UnixStream::pair().unwrap();
        (
            ControlChannel::from_stream(provider),
            ControlChannel::from_stream(core),
        )
    }

    fn new_pairing(session: &CaptureSession) -> Arc<Mutex<FlowPairing>> {
        Arc::new(Mutex::new(FlowPairing::new(
            session.pending_cap,
            session.pending_ttl,
        )))
    }

    /// Run `serve_control` for `core` on its own task.
    fn attach(
        session: &Arc<CaptureSession>,
        pairing: &Arc<Mutex<FlowPairing>>,
        core: ControlChannel,
    ) -> JoinHandle<()> {
        let (session, pairing) = (Arc::clone(session), Arc::clone(pairing));
        tokio::spawn(async move { session.serve_control(core, &pairing).await })
    }

    /// The provider's next frame, within `PROMPT`.
    async fn next_frame(provider: &mut ControlChannel) -> Option<ControlMessage> {
        timeout(PROMPT, provider.recv())
            .await
            .expect("a frame or EOF arrives promptly")
            .expect("a well-formed frame or clean EOF")
    }

    /// LF-AC3: a peer the verifier rejects gets nothing — no `Scope`, and the core
    /// never reads its bytes either. Its next read is a clean EOF.
    #[tokio::test]
    async fn rejected_control_peer_gets_no_scope() {
        let verifier = StubVerifier::new(false);
        let session = session(verifier.clone(), TestGuard::with_hosts(&["example.com"]));
        let pairing = new_pairing(&session);
        let (mut provider, core) = control_pair();
        provider
            .send(&hello(HANDOFF_PROTOCOL_VERSION))
            .await
            .unwrap();

        timeout(PROMPT, session.serve_control(core, &pairing))
            .await
            .expect("a rejected peer is dropped promptly");

        assert_eq!(lock(&verifier.seen).len(), 1, "the peer was asked about");
        match timeout(PROMPT, provider.recv()).await.unwrap() {
            Ok(None) => {}
            // macOS gives a clean EOF. The core deliberately never reads from an
            // unverified peer, so the provider's Hello stays unread at close, which
            // Linux reports as a reset; either way no ControlMessage was received.
            Err(e) if e.kind() == io::ErrorKind::ConnectionReset => {}
            other => panic!("a rejected peer must receive no ControlMessage, got {other:?}"),
        }
        assert_eq!(pairing_len(&pairing), 0);
    }

    fn pairing_len(pairing: &Mutex<FlowPairing>) -> usize {
        lock(pairing).pending_opens_len()
    }

    /// LF-AC3 + LF-AC5: an accepted peer's first frame is the emitter's rendering of
    /// the live scope, and the verifier was asked about that very control fd.
    #[tokio::test]
    async fn verified_peer_gets_scope_matching_emitter() {
        let verifier = StubVerifier::new(true);
        let session = session(verifier.clone(), TestGuard::with_hosts(&["example.com"]));
        let pairing = new_pairing(&session);
        let (mut provider, core) = control_pair();
        let core_fd = core.as_raw_fd();
        provider
            .send(&hello(HANDOFF_PROTOCOL_VERSION))
            .await
            .unwrap();

        let task = attach(&session, &pairing, core);

        assert_eq!(next_frame(&mut provider).await, Some(scope("example.com")));
        assert_eq!(*lock(&verifier.seen), vec![core_fd]);

        drop(provider);
        timeout(PROMPT, task)
            .await
            .expect("serve_control ends when the provider detaches")
            .unwrap();
    }

    /// LF-AC5: a scope change is pushed as a second `Scope`; an unchanged scope is
    /// not re-sent.
    #[tokio::test]
    async fn scope_change_triggers_resend() {
        let guard = TestGuard::with_hosts(&["example.com"]);
        let session = session(StubVerifier::new(true), guard.clone());
        let pairing = new_pairing(&session);
        let (mut provider, core) = control_pair();
        provider
            .send(&hello(HANDOFF_PROTOCOL_VERSION))
            .await
            .unwrap();
        let task = attach(&session, &pairing, core);

        assert_eq!(next_frame(&mut provider).await, Some(scope("example.com")));

        // Unchanged: nothing arrives across two poll intervals (and then some).
        assert!(
            timeout(POLL * 4, provider.recv()).await.is_err(),
            "an unchanged scope must not be re-sent"
        );

        guard.add_scope(ScopeEntry {
            host: "api.test".to_string(),
        });
        assert_eq!(
            next_frame(&mut provider).await,
            Some(scope("example.com api.test"))
        );

        // And again quiet.
        assert!(timeout(POLL * 4, provider.recv()).await.is_err());

        drop(provider);
        timeout(PROMPT, task).await.unwrap().unwrap();
    }

    /// LF-AC4: a `Hello` with the wrong version tears the channel down with no
    /// `Scope` sent.
    #[tokio::test]
    async fn hello_mismatch_tears_down() {
        let session = session(
            StubVerifier::new(true),
            TestGuard::with_hosts(&["example.com"]),
        );
        let pairing = new_pairing(&session);
        let (mut provider, core) = control_pair();
        provider.send(&hello(2)).await.unwrap();

        timeout(PROMPT, session.serve_control(core, &pairing))
            .await
            .expect("a bad Hello ends the attachment promptly");

        assert_eq!(next_frame(&mut provider).await, None, "clean EOF, no Scope");
    }

    /// LF-AC4: a first frame that is not a `Hello` is refused the same way.
    #[tokio::test]
    async fn non_hello_first_frame_tears_down() {
        let session = session(
            StubVerifier::new(true),
            TestGuard::with_hosts(&["example.com"]),
        );
        let pairing = new_pairing(&session);
        let (mut provider, core) = control_pair();
        provider.send(&scope("anything")).await.unwrap();

        timeout(PROMPT, session.serve_control(core, &pairing))
            .await
            .expect("a non-Hello first frame ends the attachment promptly");

        assert_eq!(next_frame(&mut provider).await, None);
    }

    /// A peer the verifier accepts that then never sends its `Hello` is cut off at
    /// the Hello deadline instead of holding the single attachment slot forever:
    /// `serve_control` returns (so `serve_attachment`'s select completes and the
    /// accept loop takes the next connection), it never reaches the scope push, and
    /// the channel is dropped, which the provider sees as a clean EOF.
    #[tokio::test]
    async fn verified_peer_that_never_sends_hello_is_cut_off() {
        let verifier = StubVerifier::new(true);
        let session = Arc::new(
            session_with(
                verifier.clone(),
                TestGuard::with_hosts(&["example.com"]),
                None,
            )
            .with_hello_timeout(Duration::from_millis(50)),
        );
        let pairing = new_pairing(&session);
        // The provider connects and stays connected, but says nothing.
        let (mut provider, core) = control_pair();

        timeout(PROMPT, session.serve_control(core, &pairing))
            .await
            .expect("a silent peer is cut off at the Hello deadline, not waited on forever");

        assert_eq!(
            lock(&verifier.seen).len(),
            1,
            "the peer was verified before the Hello was awaited"
        );
        assert_eq!(
            next_frame(&mut provider).await,
            None,
            "the channel was dropped with no Scope sent"
        );
        assert_eq!(pairing_len(&pairing), 0);
    }

    /// The deadline is a fixed production constant (the tests above shorten it per
    /// session): a session built with `new` waits exactly `HELLO_TIMEOUT`, five
    /// seconds, for a peer's `Hello`.
    #[test]
    fn hello_timeout_default_is_five_seconds() {
        assert_eq!(HELLO_TIMEOUT, Duration::from_secs(5));
        let session = session_with(StubVerifier::new(true), TestGuard::with_hosts(&[]), None);
        assert_eq!(session.hello_timeout, HELLO_TIMEOUT);
    }

    /// A peer that sends its `Hello` inside the deadline is unaffected by it.
    #[tokio::test]
    async fn prompt_hello_inside_the_deadline_still_attaches() {
        let session = Arc::new(
            session_with(
                StubVerifier::new(true),
                TestGuard::with_hosts(&["example.com"]),
                None,
            )
            .with_hello_timeout(Duration::from_secs(30)),
        );
        let pairing = new_pairing(&session);
        let (mut provider, core) = control_pair();
        provider
            .send(&hello(HANDOFF_PROTOCOL_VERSION))
            .await
            .unwrap();
        let task = attach(&session, &pairing, core);

        assert_eq!(next_frame(&mut provider).await, Some(scope("example.com")));

        drop(provider);
        timeout(PROMPT, task).await.unwrap().unwrap();
    }

    /// Fail-closed: a verifier that panics is a rejection, not a crash.
    #[tokio::test]
    async fn panicking_verifier_is_a_rejection() {
        let session = session(
            Arc::new(PanickingVerifier),
            TestGuard::with_hosts(&["example.com"]),
        );
        let pairing = new_pairing(&session);
        let (mut provider, core) = control_pair();
        provider
            .send(&hello(HANDOFF_PROTOCOL_VERSION))
            .await
            .unwrap();

        timeout(PROMPT, session.serve_control(core, &pairing))
            .await
            .expect("a panicking verifier does not hang or panic the caller");

        assert!(
            !matches!(timeout(PROMPT, provider.recv()).await.unwrap(), Ok(Some(_))),
            "no ControlMessage reaches a peer the verifier panicked on"
        );
    }

    /// The control loop acts only on `FlowOpen`: other frames (a stray `Scope`, a
    /// repeated `Hello`) are ignored without ending the attachment, and a `FlowOpen`
    /// is registered for pairing.
    #[tokio::test]
    async fn control_loop_acts_only_on_flow_open() {
        let session = session(
            StubVerifier::new(true),
            TestGuard::with_hosts(&["example.com"]),
        );
        let pairing = new_pairing(&session);
        let (mut provider, core) = control_pair();
        provider
            .send(&hello(HANDOFF_PROTOCOL_VERSION))
            .await
            .unwrap();
        let task = attach(&session, &pairing, core);
        assert_eq!(next_frame(&mut provider).await, Some(scope("example.com")));

        provider.send(&scope("ignored")).await.unwrap();
        provider
            .send(&hello(HANDOFF_PROTOCOL_VERSION))
            .await
            .unwrap();
        provider
            .send(&ControlMessage::FlowOpen(open(7)))
            .await
            .unwrap();

        timeout(PROMPT, async {
            while pairing_len(&pairing) != 1 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("the FlowOpen is registered for pairing");
        assert_eq!(pairing_len(&pairing), 1, "only the FlowOpen was acted on");
        assert!(
            !task.is_finished(),
            "ignored frames do not end the attachment"
        );

        drop(provider);
        timeout(PROMPT, task).await.unwrap().unwrap();
    }

    /// The scope tick also sweeps stale pairing halves, so an open whose data socket
    /// never arrives does not sit forever.
    #[tokio::test]
    async fn scope_tick_sweeps_stale_opens() {
        let session = Arc::new(
            session_with(StubVerifier::new(true), TestGuard::with_hosts(&[]), None)
                .with_pending_ttl(Duration::from_millis(30)),
        );
        let pairing = new_pairing(&session);
        let (mut provider, core) = control_pair();
        provider
            .send(&hello(HANDOFF_PROTOCOL_VERSION))
            .await
            .unwrap();
        let task = attach(&session, &pairing, core);
        assert_eq!(next_frame(&mut provider).await, Some(scope("")));

        provider
            .send(&ControlMessage::FlowOpen(open(1)))
            .await
            .unwrap();
        timeout(PROMPT, async {
            while pairing_len(&pairing) != 1 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        timeout(PROMPT, async {
            while pairing_len(&pairing) != 0 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("the unpaired open is swept after its ttl");

        drop(provider);
        timeout(PROMPT, task).await.unwrap().unwrap();
    }

    /// The session's pending cap bounds the pairing map an attachment fills from its
    /// control channel: with a cap of 2, a third unpaired `FlowOpen` evicts the
    /// oldest instead of growing the map.
    #[tokio::test]
    async fn pending_cap_bounds_the_unpaired_opens_of_an_attachment() {
        // A long scope poll keeps the sweep from consuming the eviction count.
        let session = Arc::new(
            session_with(StubVerifier::new(true), TestGuard::with_hosts(&[]), None)
                .with_scope_poll_interval(Duration::from_secs(3600))
                .with_pending_cap(2),
        );
        let pairing = new_pairing(&session);
        let (mut provider, core) = control_pair();
        provider
            .send(&hello(HANDOFF_PROTOCOL_VERSION))
            .await
            .unwrap();
        let task = attach(&session, &pairing, core);
        assert_eq!(next_frame(&mut provider).await, Some(scope("")));

        for flow_id in 1..=3 {
            provider
                .send(&ControlMessage::FlowOpen(open(flow_id)))
                .await
                .unwrap();
        }
        timeout(PROMPT, async {
            while lock(&pairing).take_evicted() == 0 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("the third open evicts the oldest");
        assert_eq!(pairing_len(&pairing), 2, "the map stays at the cap");

        drop(provider);
        timeout(PROMPT, task).await.unwrap().unwrap();
    }

    fn capture_l4_entry(addr: &str) -> L4ScopeEntry {
        L4ScopeEntry {
            id: L4ScopeId::new(),
            cidr: IpCidr {
                addr: addr.parse().unwrap(),
                prefix: 32,
            },
            ports: PortRange { lo: 0, hi: 65535 },
            interface: CAPTURE_INTERFACE.to_string(),
            direction: L4Direction::Outbound,
            capability: L4Capability::Capture,
            inject_rate: RateCap { pps: 0, burst: 0 },
            source: L4ScopeSource::Config,
        }
    }

    /// The pushed scope merges the L7 scope with the L4 guard's scope (the emitter
    /// renders L7 first, then L4), and is L7-only when L4 is not enabled.
    #[test]
    fn current_scope_spec_merges_l7_and_l4() {
        let l4 = Arc::new(L4Guard::new(&L4Config {
            scope: vec![capture_l4_entry("198.51.100.7")],
            ..L4Config::default()
        }));
        let with_l4 = session_with(
            StubVerifier::new(true),
            TestGuard::with_hosts(&["example.com"]),
            Some(l4),
        );
        assert_eq!(
            with_l4.current_scope_spec().spec,
            "example.com 198.51.100.7"
        );

        let without_l4 = session_with(
            StubVerifier::new(true),
            TestGuard::with_hosts(&["example.com"]),
            None,
        );
        assert_eq!(without_l4.current_scope_spec().spec, "example.com");
    }

    // ---- FlowPairing ----

    fn pairing_of<D>(cap: usize) -> FlowPairing<D> {
        FlowPairing::new(cap, Duration::from_secs(30))
    }

    /// LF-AC11: past the cap, the oldest unpaired open is evicted and the map stays
    /// at the cap.
    #[test]
    fn pairing_map_is_bounded() {
        let cap = 4;
        let mut pairing = pairing_of::<&'static str>(cap);
        let now = Instant::now();
        for id in 0..=(cap as u64) {
            assert!(pairing.offer_open(open(id), now).is_none());
        }
        assert_eq!(pairing.pending_opens_len(), cap);
        assert_eq!(pairing.take_evicted(), 1);
        assert_eq!(pairing.take_evicted(), 0, "the count resets once taken");

        // The oldest (flow 0) was the one evicted: its data finds no open, while
        // the newest (flow 4) still pairs.
        assert!(pairing.offer_data(0, "d0", now).is_none());
        assert_eq!(pairing.offer_data(4, "d4", now), Some((open(4), "d4")));
    }

    /// LF-AC11: the data side is bounded the same way.
    #[test]
    fn pairing_data_side_is_bounded() {
        let cap = 3;
        let mut pairing = pairing_of::<u8>(cap);
        let now = Instant::now();
        for id in 0..=(cap as u64) {
            assert!(pairing.offer_data(id, 0, now).is_none());
        }
        assert_eq!(pairing.pending_data_len(), cap);
        assert_eq!(pairing.take_evicted(), 1);
        assert!(
            pairing.offer_open(open(0), now).is_none(),
            "flow 0 was evicted"
        );
        assert_eq!(pairing.offer_open(open(3), now), Some((open(3), 0)));
    }

    /// Either half may arrive first; the pair comes out exactly once and leaves
    /// nothing pending.
    #[test]
    fn pairing_completes_in_either_order() {
        let mut pairing = pairing_of::<&'static str>(8);
        let now = Instant::now();

        assert!(pairing.offer_open(open(7), now).is_none());
        assert_eq!(pairing.offer_data(7, "d7", now), Some((open(7), "d7")));

        assert!(pairing.offer_data(8, "d8", now).is_none());
        assert_eq!(pairing.offer_open(open(8), now), Some((open(8), "d8")));

        assert_eq!(pairing.pending_opens_len(), 0);
        assert_eq!(pairing.pending_data_len(), 0);
        // Already consumed: a second offer starts fresh, it does not re-pair.
        assert!(pairing.offer_data(7, "again", now).is_none());
    }

    /// A repeated `flow_id` replaces the older half instead of piling up.
    #[test]
    fn duplicate_flow_id_replaces_the_older_half() {
        let mut pairing = pairing_of::<&'static str>(8);
        let now = Instant::now();
        assert!(pairing.offer_data(1, "first", now).is_none());
        assert!(pairing.offer_data(1, "second", now).is_none());
        assert_eq!(pairing.pending_data_len(), 1);
        assert_eq!(pairing.offer_open(open(1), now), Some((open(1), "second")));
    }

    /// Halves that wait past the ttl are dropped by a sweep; fresh ones stay.
    #[test]
    fn stale_halves_are_swept() {
        let ttl = Duration::from_secs(10);
        let mut pairing = FlowPairing::<u8>::new(8, ttl);
        let t0 = Instant::now();
        assert!(pairing.offer_open(open(1), t0).is_none());
        assert!(pairing.offer_data(2, 0, t0).is_none());
        assert!(pairing
            .offer_open(open(3), t0 + Duration::from_secs(8))
            .is_none());

        pairing.sweep(t0 + Duration::from_secs(11));

        assert_eq!(pairing.pending_opens_len(), 1, "only the fresh open stays");
        assert_eq!(pairing.pending_data_len(), 0);
        assert_eq!(pairing.take_evicted(), 2);
    }

    // ---- concurrency cap and pumps ----

    /// The concurrency cap sheds, it does not queue: past the cap `claim_slot` is
    /// `None` at once, and a finished flow frees its slot.
    #[test]
    fn concurrency_cap_sheds_instead_of_queueing() {
        let session = session_with(StubVerifier::new(true), TestGuard::with_hosts(&[]), None)
            .with_max_concurrent_flows(2);
        let first = session.claim_slot().expect("slot 1");
        let _second = session.claim_slot().expect("slot 2");
        assert!(session.claim_slot().is_none(), "the third is shed");
        drop(first);
        assert!(session.claim_slot().is_some(), "a freed slot is reusable");
    }

    fn one_slot() -> (Arc<Semaphore>, OwnedSemaphorePermit) {
        let slots = Arc::new(Semaphore::new(1));
        let permit = Arc::clone(&slots).try_acquire_owned().unwrap();
        (slots, permit)
    }

    async fn exploding_pump() -> io::Result<CaptureOutcome> {
        panic!("pump bug")
    }

    /// A pump that returns `Err` ends only itself: the task completes normally and
    /// its slot comes back.
    #[tokio::test]
    async fn pump_error_is_isolated_and_frees_its_slot() {
        let (slots, permit) = one_slot();
        let (_stop_tx, stop_rx) = watch::channel(false);
        let handle = spawn_guarded(1, async { Err(io::Error::other("boom")) }, permit, stop_rx);
        timeout(PROMPT, handle)
            .await
            .unwrap()
            .expect("the task did not panic");
        assert_eq!(slots.available_permits(), 1);
    }

    /// A pump that panics is caught: the task completes normally (no `JoinError`)
    /// and its slot comes back.
    #[tokio::test]
    async fn pump_panic_is_isolated_and_frees_its_slot() {
        let (slots, permit) = one_slot();
        let (_stop_tx, stop_rx) = watch::channel(false);
        let handle = spawn_guarded(2, exploding_pump(), permit, stop_rx);
        timeout(PROMPT, handle)
            .await
            .unwrap()
            .expect("a pump panic is caught, not propagated");
        assert_eq!(slots.available_permits(), 1);
    }

    /// LF-AC10: the stop signal aborts a pump that would otherwise run forever, and
    /// frees its slot.
    #[tokio::test]
    async fn stop_signal_aborts_a_running_pump() {
        let (slots, permit) = one_slot();
        let (stop_tx, stop_rx) = watch::channel(false);
        let handle = spawn_guarded(
            3,
            std::future::pending::<io::Result<CaptureOutcome>>(),
            permit,
            stop_rx,
        );
        assert_eq!(slots.available_permits(), 0, "the pump holds its slot");
        stop_tx.send(true).unwrap();
        timeout(PROMPT, handle).await.unwrap().unwrap();
        assert_eq!(slots.available_permits(), 1);
    }

    /// The sender going away (the session dropped) also stops its pumps.
    #[tokio::test]
    async fn dropping_the_session_stop_aborts_pumps() {
        let (slots, permit) = one_slot();
        let (stop_tx, stop_rx) = watch::channel(false);
        let handle = spawn_guarded(
            4,
            std::future::pending::<io::Result<CaptureOutcome>>(),
            permit,
            stop_rx,
        );
        drop(stop_tx);
        timeout(PROMPT, handle).await.unwrap().unwrap();
        assert_eq!(slots.available_permits(), 1);
    }

    /// A pump that finishes normally frees its slot too.
    #[tokio::test]
    async fn finished_pump_frees_its_slot() {
        let (slots, permit) = one_slot();
        let (_stop_tx, stop_rx) = watch::channel(false);
        let handle = spawn_guarded(
            5,
            async { Ok(CaptureOutcome::Tcp(crate::ingress::StreamOutcome::Refused)) },
            permit,
            stop_rx,
        );
        timeout(PROMPT, handle).await.unwrap().unwrap();
        assert_eq!(slots.available_permits(), 1);
    }

    // ---- run ----

    struct TempPath(PathBuf);

    impl TempPath {
        fn new() -> Self {
            static SEQ: AtomicU64 = AtomicU64::new(0);
            Self(std::env::temp_dir().join(format!(
                "aml-feeder-{}-{}",
                std::process::id(),
                SEQ.fetch_add(1, Ordering::Relaxed)
            )))
        }
        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempPath {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    /// LF-AC9: a socket directory that cannot be created (here, a path beneath a
    /// regular file) makes `run` log and return at once, without panicking and
    /// without binding or publishing anything.
    #[tokio::test]
    async fn run_returns_when_the_socket_dir_is_unusable() {
        let blocker = TempPath::new();
        std::fs::write(blocker.path(), b"not a directory").unwrap();
        let session = CaptureSession::new(
            Arc::new(CoreIngress::empty()),
            TestGuard::with_hosts(&[]),
            None,
            StubVerifier::new(true),
            blocker.path().join("sub"),
        );
        timeout(PROMPT, session.run(std::future::pending::<()>()))
            .await
            .expect("run returns instead of waiting on a session that never started");
    }

    /// `run` can be spawned as its own task (what the runtime wiring does): its
    /// future is `Send`.
    #[test]
    fn run_future_is_send() {
        fn assert_send<T: Send>(_: &T) {}
        let session = session_with(StubVerifier::new(true), TestGuard::with_hosts(&[]), None);
        let fut = session.run(std::future::pending::<()>());
        assert_send(&fut);
    }
}
