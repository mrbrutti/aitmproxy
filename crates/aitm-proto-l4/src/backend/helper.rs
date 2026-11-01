//! `HelperBackend`: the capture/inject backend over a privileged helper
//! session (spec §5.2 "`HelperBackend` implements the existing
//! `CaptureInjectBackend` trait", §5.3; privilege plan P1b.13).
//!
//! On Linux a core without `CAP_NET_RAW` reaches the wire only through the
//! helper process it spawned ([`HelperSession`], P1b.12). This backend speaks
//! the helper protocol so the commands, the capture task and the scripting
//! engine do not change: [`RoutedBackend`](super::routed::RoutedBackend) hands
//! them this backend whenever the privilege report says
//! `Available { via: Helper }`.
//!
//! # Scope travels before use
//!
//! The helper enforces the guard itself over the [`ScopeSet`] it holds (spec
//! §5.3). This backend sends the set once when it is built and again, before
//! the next `CaptureOpen` or `Inject`, whenever
//! [`L4Guard::scope_generation`] moved since the last send. **(Architect's
//! call:** resend-before-use, so every frame the helper acts on was checked
//! against the current scope; the core's own `admit_frame` still filters
//! every received frame.) The check-and-resend holds one lock so a concurrent
//! inject can never reach the wire ahead of the `ScopeSet` it depends on.
//!
//! # No filter string crosses
//!
//! `open_capture`'s `filter` argument is **not** sent: the helper compiles its
//! own BPF filter from its `ScopeSet` and accepts none from the core.
//!
//! # Fail-closed
//!
//! A closed session, a write failure or an unanswered inject is
//! [`L4Error::Unavailable`]; the helper's own guard or wire refusal text is
//! [`L4Error::WireWrite`] verbatim, so a scope refusal reads exactly as the
//! core's would.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use super::{CaptureInjectBackend, CaptureSource, L4Error};
use crate::guard::L4Guard;
use crate::helper::client::{CaptureEvent, HelperSession, SessionError};
use crate::helper::proto::Msg;
use crate::privilege::PrivilegeState;
use crate::types::L4Direction;

/// How long one `Inject` may wait for its `InjectResult` (plan P1b.13).
pub const INJECT_TIMEOUT: Duration = Duration::from_secs(2);

/// The direction every `CaptureOpen` carries.
///
/// The [`CaptureInjectBackend::open_capture`] seam has no direction
/// parameter: `capture::start_capture` checks the permit for
/// `params.direction` and then opens by interface, filter and read timeout
/// only, so the direction is not recoverable here. The helper's own
/// `CaptureOpen` check (`HelperGuard::capture_filter`) is by interface, not
/// direction, so this value is informational on the wire today. Flagged in
/// the P1b.13 report for the Architect: carrying the direction through the
/// trait is a later task.
pub const CAPTURE_OPEN_DIRECTION: L4Direction = L4Direction::Inbound;

/// Prefix of the `Unavailable` text once the helper ended a capture.
pub const CAPTURE_ENDED: &str = "helper capture ended: ";

/// `sent_gen` before the first `ScopeSet` went out.
const NEVER_SENT: u64 = u64::MAX;

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The capture/inject backend over one helper session.
pub struct HelperBackend {
    session: Arc<HelperSession>,
    guard: Arc<L4Guard>,
    /// The guard generation the last `ScopeSet` on the wire carried;
    /// [`NEVER_SENT`] until the first one.
    sent_gen: AtomicU64,
    /// Held across the generation check and the resend, so two callers cannot
    /// interleave a use ahead of the `ScopeSet` it needs.
    scope_send: Mutex<()>,
    /// Capture ids and inject request ids, one counter, starting at 1.
    next_id: AtomicU64,
}

impl std::fmt::Debug for HelperBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HelperBackend")
            .field("live", &self.is_live())
            .field("sent_gen", &self.sent_gen.load(Ordering::SeqCst))
            .finish_non_exhaustive()
    }
}

impl HelperBackend {
    /// Build the backend over a session past its handshake with its reader
    /// running, and send the guard's current `ScopeSet` once (session start).
    ///
    /// # Errors
    /// [`L4Error::Unavailable`] when that first send fails: the session is
    /// closed or the socket refused the write.
    pub fn new(session: Arc<HelperSession>, guard: Arc<L4Guard>) -> Result<Self, L4Error> {
        let backend = Self {
            session,
            guard,
            sent_gen: AtomicU64::new(NEVER_SENT),
            scope_send: Mutex::new(()),
            next_id: AtomicU64::new(1),
        };
        backend.sync_scope()?;
        Ok(backend)
    }

    /// Send the guard's `ScopeSet` if its generation moved since the last send
    /// (or nothing was sent yet). Holds `scope_send` across the check and the
    /// write, so the caller's following message lands after the set it needs.
    fn sync_scope(&self) -> Result<(), L4Error> {
        let _serial = lock(&self.scope_send);
        // Read the generation before the snapshot: a mutation between the two
        // leaves `sent_gen` behind the state we sent, so the next use resends.
        let generation = self.guard.scope_generation();
        if self.sent_gen.load(Ordering::SeqCst) == generation {
            return Ok(());
        }
        let set = self.guard.scope_set();
        self.session.send_scope(&set).map_err(unavailable)?;
        self.sent_gen.store(generation, Ordering::SeqCst);
        Ok(())
    }

    fn next_id(&self) -> u64 {
        self.next_id.fetch_add(1, Ordering::SeqCst)
    }

    /// True while the helper session is open. This is what the privilege
    /// prober's `session_connected` input should read (P1b.14).
    #[must_use]
    pub fn is_live(&self) -> bool {
        !self.session.is_closed()
    }

    /// Set this backend as the state's helper backend, so the routed backend
    /// takes it for `Available { via: Helper }` from the next call on.
    pub fn attach(self: &Arc<Self>, state: &PrivilegeState) {
        let backend: Arc<dyn CaptureInjectBackend> = Arc::<Self>::clone(self);
        state.set_helper_backend(Some(backend));
    }

    /// Clear the state's helper backend (the session ended).
    pub fn detach(state: &PrivilegeState) {
        state.set_helper_backend(None);
    }
}

/// A session failure is the fail-closed `Unavailable`, with the session's own
/// text (it names no command).
fn unavailable(err: SessionError) -> L4Error {
    L4Error::Unavailable(err.to_string())
}

impl CaptureInjectBackend for HelperBackend {
    fn open_capture(
        &self,
        iface: &str,
        _filter: Option<&str>,
        read_timeout: Duration,
    ) -> Result<Box<dyn CaptureSource>, L4Error> {
        self.sync_scope()?;
        let id = self.next_id();
        // Subscribe before the open, or the first frames have nowhere to go.
        let rx = self.session.subscribe_capture(id);
        let read_timeout_ms = u32::try_from(read_timeout.as_millis()).unwrap_or(u32::MAX);
        if let Err(err) = self.session.send(&Msg::CaptureOpen {
            id,
            interface: iface.to_string(),
            direction: CAPTURE_OPEN_DIRECTION,
            read_timeout_ms,
        }) {
            self.session.unsubscribe_capture(id);
            return Err(unavailable(err));
        }
        Ok(Box::new(HelperCapture {
            session: Arc::clone(&self.session),
            id,
            rx,
            read_timeout,
            ended: None,
        }))
    }

    fn inject(&self, iface: &str, bytes: &[u8]) -> Result<(), L4Error> {
        self.sync_scope()?;
        let request_id = self.next_id();
        match self
            .session
            .inject(request_id, iface, bytes, INJECT_TIMEOUT)
        {
            Ok(None) => Ok(()),
            Ok(Some(text)) => Err(L4Error::WireWrite(text)),
            Err(err) => Err(unavailable(err)),
        }
    }
}

/// A live helper capture: the receiver of one capture id's events.
struct HelperCapture {
    session: Arc<HelperSession>,
    id: u64,
    rx: Receiver<CaptureEvent>,
    read_timeout: Duration,
    /// Set once the capture ended; every later `next_frame` repeats it.
    ended: Option<String>,
}

impl CaptureSource for HelperCapture {
    fn next_frame(&mut self) -> Result<Option<Vec<u8>>, L4Error> {
        if let Some(reason) = &self.ended {
            return Err(L4Error::Unavailable(reason.clone()));
        }
        let reason = match self.rx.recv_timeout(self.read_timeout) {
            Ok(CaptureEvent::Frame { bytes, .. }) => return Ok(Some(bytes)),
            Err(RecvTimeoutError::Timeout) => return Ok(None),
            Ok(CaptureEvent::Closed { reason }) => format!("{CAPTURE_ENDED}{reason}"),
            // The session dropped our sender without a `Closed`: it is gone.
            Err(RecvTimeoutError::Disconnected) => {
                format!("{CAPTURE_ENDED}{}", SessionError::Closed)
            }
        };
        self.ended = Some(reason.clone());
        Err(L4Error::Unavailable(reason))
    }
}

impl Drop for HelperCapture {
    fn drop(&mut self) {
        self.session.unsubscribe_capture(self.id);
        // A capture the helper already ended needs no close; on a closed
        // session the send fails and there is nothing left to tell.
        if self.ended.is_none() {
            let _ = self.session.send(&Msg::CaptureClose { id: self.id });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{L4Config, L4PrivilegeConfig};
    use crate::helper::proto::{encode, read_msg, PROTO};
    use crate::privilege::derive::{LinuxInputs, ProbeInputs};
    use crate::privilege::report::{Platform, RequestProgress};
    use crate::privilege::state::{PrivilegeConfig, Prober, ProcessLifetime};
    use crate::types::{
        IpCidr, L4Capability, L4ScopeEntry, L4ScopeId, L4ScopeSource, PortRange, RateCap,
    };
    use std::io::Write;
    use std::os::unix::net::UnixStream;
    use std::time::Instant;

    /// Generous: the machine running these may be under heavy load.
    const PEER_READ: Duration = Duration::from_secs(20);

    /// A session past its handshake with the reader running, and the helper's
    /// raw end with a bounded read timeout so no test can hang.
    fn open_session() -> (Arc<HelperSession>, UnixStream) {
        let (core, mut peer) = UnixStream::pair().expect("socketpair");
        peer.set_read_timeout(Some(PEER_READ))
            .expect("peer timeout");
        let mut session = HelperSession::from_stream(core).expect("session");
        let t = std::thread::spawn(move || {
            let hello = read_msg(&mut peer).expect("hello");
            assert!(matches!(hello, Msg::Hello { proto: PROTO, .. }));
            peer.write_all(&encode(&Msg::HelloAck {
                proto: PROTO,
                helper_version: "0.9.9-helper".to_string(),
                caps: vec!["cap_net_raw".to_string()],
            }))
            .expect("ack");
            peer
        });
        session
            .handshake("0.9.9-test", Duration::from_secs(10))
            .expect("handshake");
        session.start_reader().expect("reader");
        (Arc::new(session), t.join().expect("peer thread"))
    }

    fn guard() -> Arc<L4Guard> {
        let cfg = L4Config {
            allow_agent_widen: true,
            global_inject_pps: 7,
            max_packet_bytes: 1400,
            max_packets_per_call: 3,
            ..L4Config::default()
        };
        let g = L4Guard::new(&cfg);
        g.set_self_ports([28182]);
        Arc::new(g)
    }

    fn entry() -> L4ScopeEntry {
        L4ScopeEntry {
            id: L4ScopeId::new(),
            cidr: IpCidr {
                addr: "127.0.0.1".parse().unwrap(),
                prefix: 32,
            },
            ports: PortRange { lo: 9000, hi: 9999 },
            interface: "lo".to_string(),
            direction: L4Direction::Inbound,
            capability: L4Capability::Inject,
            inject_rate: RateCap { pps: 10, burst: 10 },
            source: L4ScopeSource::Config,
        }
    }

    /// The backend over a fresh session; the initial `ScopeSet` is read off
    /// the peer and checked against the guard.
    fn backend_over(
        session: Arc<HelperSession>,
        guard: Arc<L4Guard>,
        peer: &mut UnixStream,
    ) -> Arc<HelperBackend> {
        let backend = HelperBackend::new(Arc::clone(&session), Arc::clone(&guard)).expect("new");
        let expected = guard.scope_set();
        assert_eq!(
            read_msg(peer).expect("initial scope set"),
            Msg::ScopeSet(expected.clone()),
            "construction sends the guard's scope once"
        );
        assert_eq!(expected.self_ports, vec![28182]);
        assert_eq!(expected.global_inject_pps, 7);
        Arc::new(backend)
    }

    fn unavailable_text(err: &L4Error) -> &str {
        match err {
            L4Error::Unavailable(text) => text,
            other => panic!("want L4Error::Unavailable, got {other:?}"),
        }
    }

    fn wait_closed(session: &HelperSession) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !session.is_closed() {
            assert!(Instant::now() < deadline, "session never closed");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// Plan P1b.13 `scope_resent_after_change`: construction sends the scope
    /// once; after `add_runtime_scope` an inject puts `ScopeSet` then `Inject`
    /// on the wire, in that order; a second inject without a change sends no
    /// `ScopeSet`.
    #[test]
    fn scope_resent_after_change() {
        let (session, mut peer) = open_session();
        let guard = guard();
        let backend = backend_over(Arc::clone(&session), Arc::clone(&guard), &mut peer);
        assert!(backend.is_live());

        let added = entry();
        let id = guard.add_runtime_scope(added.clone()).expect("widen on");
        let after_change = guard.scope_set();

        let t = std::thread::spawn(move || {
            let mut seen = Vec::new();
            for _ in 0..3 {
                let msg = read_msg(&mut peer).expect("message");
                match &msg {
                    Msg::Inject { request_id, .. } => {
                        peer.write_all(&encode(&Msg::InjectResult {
                            request_id: *request_id,
                            error: None,
                        }))
                        .expect("result");
                    }
                    Msg::ScopeSet(_) => {}
                    other => panic!("unexpected {other:?}"),
                }
                seen.push(msg);
            }
            (seen, peer)
        });

        backend.inject("lo", &[1, 2, 3]).expect("first inject ok");
        backend.inject("lo", &[4]).expect("second inject ok");
        let (seen, _peer) = t.join().expect("peer thread");

        assert_eq!(seen.len(), 3);
        assert_eq!(seen[0], Msg::ScopeSet(after_change.clone()));
        let Msg::ScopeSet(set) = &seen[0] else {
            panic!("want ScopeSet first, got {:?}", seen[0]);
        };
        assert_eq!(set.scope.len(), 1);
        assert_eq!(set.scope[0].id, id);
        assert_eq!(
            set.scope[0].source,
            L4ScopeSource::Runtime,
            "the guard forces Runtime provenance and the helper sees exactly that"
        );
        assert_eq!(set.scope[0].interface, "lo");
        assert_eq!(
            seen[1],
            Msg::Inject {
                request_id: 1,
                interface: "lo".to_string(),
                bytes: vec![1, 2, 3],
            }
        );
        assert_eq!(
            seen[2],
            Msg::Inject {
                request_id: 2,
                interface: "lo".to_string(),
                bytes: vec![4],
            },
            "no ScopeSet between two injects without a scope change"
        );
    }

    /// Plan P1b.13 `inject_error_text_is_returned`: the helper's refusal text
    /// comes back verbatim as `L4Error::WireWrite`.
    #[test]
    fn inject_error_text_is_returned() {
        let (session, mut peer) = open_session();
        let backend = backend_over(Arc::clone(&session), guard(), &mut peer);
        let t = std::thread::spawn(move || {
            let msg = read_msg(&mut peer).expect("inject");
            assert_eq!(
                msg,
                Msg::Inject {
                    request_id: 1,
                    interface: "lo".to_string(),
                    bytes: vec![0xAA, 0xBB],
                }
            );
            peer.write_all(&encode(&Msg::InjectResult {
                request_id: 1,
                error: Some("target 127.0.0.1:8999 is out of L4 scope".to_string()),
            }))
            .expect("result");
            peer
        });
        let err = backend.inject("lo", &[0xAA, 0xBB]).expect_err("refused");
        assert_eq!(
            err,
            L4Error::WireWrite("target 127.0.0.1:8999 is out of L4 scope".to_string())
        );
        assert!(err.to_string().contains("scope"), "{err}");
        assert!(
            backend.is_live(),
            "a guard refusal does not end the session"
        );
        drop(t.join().expect("peer"));
    }

    /// A session that ended (the helper went away) makes every inject
    /// `Unavailable` and `is_live` false: the fail-closed contract, and what
    /// P1b.14 reads for `session_connected`.
    #[test]
    fn closed_session_is_unavailable_and_not_live() {
        let (session, mut peer) = open_session();
        let backend = backend_over(Arc::clone(&session), guard(), &mut peer);
        assert!(backend.is_live());
        drop(peer);
        wait_closed(&session);
        assert!(!backend.is_live());
        let err = backend.inject("lo", &[1]).expect_err("closed");
        assert_eq!(
            unavailable_text(&err),
            "the helper session is closed",
            "SessionError::Closed's text, verbatim"
        );
        let err = backend
            .open_capture("lo", None, Duration::from_millis(10))
            .err()
            .expect("closed");
        assert_eq!(unavailable_text(&err), "the helper session is closed");
    }

    /// Plan P1b.13 `capture_frames_arrive_in_order`: `open_capture` sends a
    /// `CaptureOpen` without the filter; three `Frame`s come back in order
    /// through `next_frame`; a `CaptureClosed` makes `next_frame` return
    /// `Err(Unavailable(..))` carrying the helper's reason, and keeps doing so.
    /// A capture the helper already closed sends no `CaptureClose` on drop.
    #[test]
    fn capture_frames_arrive_in_order() {
        let (session, mut peer) = open_session();
        let backend = backend_over(Arc::clone(&session), guard(), &mut peer);

        let mut source = backend
            .open_capture("lo", Some("udp and port 9053"), Duration::from_millis(500))
            .expect("open");
        assert_eq!(
            read_msg(&mut peer).expect("capture open"),
            Msg::CaptureOpen {
                id: 1,
                interface: "lo".to_string(),
                direction: CAPTURE_OPEN_DIRECTION,
                read_timeout_ms: 500,
            },
            "no filter string crosses the boundary"
        );

        for (ts, bytes) in [(10u64, vec![1u8, 2, 3]), (11, vec![4]), (12, vec![5, 6])] {
            peer.write_all(&encode(&Msg::Frame {
                capture_id: 1,
                ts_us: ts,
                bytes,
            }))
            .expect("frame");
        }
        peer.write_all(&encode(&Msg::CaptureClosed {
            capture_id: 1,
            reason: "interface went away".to_string(),
        }))
        .expect("closed");

        assert_eq!(source.next_frame().expect("f1"), Some(vec![1, 2, 3]));
        assert_eq!(source.next_frame().expect("f2"), Some(vec![4]));
        assert_eq!(source.next_frame().expect("f3"), Some(vec![5, 6]));
        let err = source.next_frame().expect_err("ended");
        assert_eq!(
            unavailable_text(&err),
            "helper capture ended: interface went away"
        );
        let again = source.next_frame().expect_err("still ended");
        assert_eq!(again, err, "the end is sticky");

        // The helper already ended it: dropping the source sends nothing, and
        // the session itself is still live.
        drop(source);
        assert!(backend.is_live());
        session.send(&Msg::CaptureClose { id: 99 }).expect("marker");
        assert_eq!(
            read_msg(&mut peer).expect("marker"),
            Msg::CaptureClose { id: 99 },
            "nothing was sent for capture 1 between the open and the marker"
        );
    }

    /// `next_frame` honours the read timeout with `Ok(None)` (the capture task
    /// uses that to re-check its stop flag), and dropping a live source sends
    /// `CaptureClose` for its id.
    #[test]
    fn next_frame_times_out_and_drop_closes_the_capture() {
        let (session, mut peer) = open_session();
        let backend = backend_over(Arc::clone(&session), guard(), &mut peer);

        let mut source = backend
            .open_capture("lo", None, Duration::from_millis(50))
            .expect("open");
        assert!(matches!(
            read_msg(&mut peer).expect("open"),
            Msg::CaptureOpen {
                id: 1,
                read_timeout_ms: 50,
                ..
            }
        ));
        let started = Instant::now();
        assert_eq!(source.next_frame().expect("poll"), None);
        assert!(
            started.elapsed() >= Duration::from_millis(50),
            "{:?}",
            started.elapsed()
        );

        drop(source);
        assert_eq!(
            read_msg(&mut peer).expect("close"),
            Msg::CaptureClose { id: 1 }
        );

        // A second capture gets the next id.
        let _second = backend
            .open_capture("lo", None, Duration::from_millis(50))
            .expect("open 2");
        assert!(matches!(
            read_msg(&mut peer).expect("open 2"),
            Msg::CaptureOpen { id: 2, .. }
        ));
    }

    /// A prober that always answers the same inputs.
    struct Fixed(ProbeInputs);

    impl Prober for Fixed {
        fn gather(&self, request: Option<&RequestProgress>) -> ProbeInputs {
            let mut inputs = self.0.clone();
            inputs.request = request.cloned();
            inputs
        }
    }

    /// Linux with a connected helper session and no process capability: the
    /// `Available { via: Helper }` row.
    fn helper_state() -> Arc<PrivilegeState> {
        let inputs = ProbeInputs {
            enabled: true,
            platform: Platform::Linux,
            mac: None,
            linux: Some(LinuxInputs {
                cap_net_raw: false,
                cap_net_admin: false,
                session_connected: true,
                helper: None,
                policy_file_present: false,
                pkexec_present: false,
                prompt_possible: false,
            }),
            request: None,
            now_ms: 0,
        };
        let cfg = PrivilegeConfig {
            enabled: true,
            l4: L4PrivilegeConfig::default(),
            lifetime: ProcessLifetime::Serving,
        };
        Arc::new(PrivilegeState::with_prober(
            &cfg,
            Box::new(Fixed(inputs)),
            Arc::new(|| 0),
        ))
    }

    /// `attach` fills the state's helper slot so `state.backend()` routes an
    /// inject to this session; `detach` empties it again.
    #[test]
    fn attach_and_detach_set_the_state_slot() {
        let (session, mut peer) = open_session();
        let backend = backend_over(Arc::clone(&session), guard(), &mut peer);
        let state = helper_state();
        assert!(state.helper_backend().is_none());

        backend.attach(&state);
        assert!(state.helper_backend().is_some());

        let t = std::thread::spawn(move || {
            let msg = read_msg(&mut peer).expect("inject");
            assert!(matches!(msg, Msg::Inject { request_id: 1, .. }));
            peer.write_all(&encode(&Msg::InjectResult {
                request_id: 1,
                error: None,
            }))
            .expect("result");
            peer
        });
        state
            .backend()
            .inject("lo", &[7])
            .expect("routed to the helper session");
        drop(t.join().expect("peer"));

        HelperBackend::detach(&state);
        assert!(state.helper_backend().is_none());
        let err = state.backend().inject("lo", &[7]).expect_err("unwired");
        assert_eq!(
            unavailable_text(&err),
            super::super::routed::HELPER_NOT_WIRED
        );
    }
    // ---- tester (privilege unit p1b): the helper goes away or misbehaves ------

    /// Tester: the helper dies mid-capture (connection drop). The frame that
    /// arrived before the drop is still delivered; then `next_frame` ends with
    /// the session's close reason, the end is sticky, the backend is no longer
    /// live, every inject is `Unavailable`, and dropping the ended source sends
    /// nothing on the closed session. The guard's scope is empty here: an
    /// empty `ScopeSet` is what construction puts on the wire.
    #[test]
    fn session_drop_mid_capture_ends_the_source_and_the_backend() {
        let (session, mut peer) = open_session();
        let guard = guard();
        assert!(
            guard.scope_set().scope.is_empty(),
            "the default guard has an empty scope: construction sends an empty set"
        );
        let backend = backend_over(Arc::clone(&session), guard, &mut peer);
        let mut source = backend
            .open_capture("lo", None, Duration::from_secs(5))
            .expect("open");
        assert!(matches!(
            read_msg(&mut peer).expect("open"),
            Msg::CaptureOpen { id: 1, .. }
        ));
        peer.write_all(&encode(&Msg::Frame {
            capture_id: 1,
            ts_us: 1,
            bytes: vec![9, 9],
        }))
        .expect("frame");
        drop(peer);

        assert_eq!(
            source.next_frame().expect("the frame before the drop"),
            Some(vec![9, 9])
        );
        let err = source.next_frame().expect_err("ended");
        assert_eq!(
            unavailable_text(&err),
            "helper capture ended: helper session closed: peer closed the session"
        );
        assert_eq!(source.next_frame().expect_err("sticky"), err);
        wait_closed(&session);
        assert!(!backend.is_live());
        let err = backend.inject("lo", &[1]).expect_err("closed");
        assert_eq!(unavailable_text(&err), "the helper session is closed");
        drop(source);
    }

    /// Tester: an oversized frame from the helper (a length above `MAX_FRAME`)
    /// closes the session before a byte of it is read; the open capture ends
    /// with that reason, the backend is no longer live, and the core has shut
    /// its end of the socket.
    #[test]
    fn oversized_helper_frame_ends_capture_and_session() {
        use crate::helper::proto::{ProtoError, MAX_FRAME};

        let (session, mut peer) = open_session();
        let backend = backend_over(Arc::clone(&session), guard(), &mut peer);
        let mut source = backend
            .open_capture("lo", None, Duration::from_secs(5))
            .expect("open");
        let _ = read_msg(&mut peer).expect("open");
        let len = u32::try_from(MAX_FRAME + 1).expect("fits");
        peer.write_all(&len.to_be_bytes()).expect("header");

        let err = source.next_frame().expect_err("ended");
        let text = unavailable_text(&err);
        assert!(
            text.starts_with(
                "helper capture ended: helper session closed: frame length 262145 exceeds"
            ),
            "{text}"
        );
        wait_closed(&session);
        assert!(!backend.is_live());
        assert_eq!(
            read_msg(&mut peer),
            Err(ProtoError::Eof),
            "the core shut its end"
        );
    }

    /// Tester: a helper that never answers an `Inject` costs exactly
    /// [`INJECT_TIMEOUT`] and is `Unavailable` with the timeout text; the
    /// session stays live (a slow helper is not a dead one) and the next
    /// inject is answered normally.
    #[test]
    fn inject_timeout_is_unavailable_and_keeps_the_session_live() {
        let (session, mut peer) = open_session();
        let backend = backend_over(Arc::clone(&session), guard(), &mut peer);
        let t = std::thread::spawn(move || {
            let first = read_msg(&mut peer).expect("inject 1");
            assert!(matches!(first, Msg::Inject { request_id: 1, .. }));
            // Never answer request 1; answer whatever comes next.
            let second = read_msg(&mut peer).expect("inject 2");
            let Msg::Inject { request_id, .. } = second else {
                panic!("want an Inject, got {second:?}");
            };
            peer.write_all(&encode(&Msg::InjectResult {
                request_id,
                error: None,
            }))
            .expect("result");
            peer
        });
        let started = Instant::now();
        let err = backend.inject("lo", &[1]).expect_err("no answer");
        assert_eq!(unavailable_text(&err), "the helper did not answer in time");
        assert!(
            started.elapsed() >= INJECT_TIMEOUT,
            "{:?}",
            started.elapsed()
        );
        assert!(backend.is_live(), "a timeout does not end the session");
        backend
            .inject("lo", &[2])
            .expect("the next inject is answered");
        drop(t.join().expect("peer"));
    }
}
