//! Core end of the privileged helper session (spec §5.1 step 5, §5.2;
//! plan P1b.12).
//!
//! The core owns a Unix socket under a directory only it can enter, spawns the
//! helper with that socket's absolute path, accepts exactly the connection
//! that comes from the process it spawned, runs the `Hello`/`HelloAck`
//! handshake, and then demultiplexes the helper's messages onto per-capture
//! channels and per-request inject waiters. Nothing here spawns a process or
//! touches system state beyond the socket directory it was asked to create.
//!
//! # Both ends check the peer
//!
//! The core checks the accepted socket's `SO_PEERCRED`: the uid must equal
//! the core's own uid and the pid must equal `expected_pid`, the pid the core
//! spawned. pkexec execs the helper in place (spike S7), so that is the
//! helper's pid, not a parent's. The helper does the mirror check on its side:
//! the peer uid equals the invoking user and the peer pid equals its
//! `getppid()`. Either side failing its check closes the connection.
//!
//! # The socket path is public
//!
//! The path goes on the helper's argv, which pkexec writes to the journal
//! (`[COMMAND=… --connect <path>]`), readable by every journal reader. It is
//! therefore `l4-helper-<core pid>.sock` and never carries a token, a random
//! nonce or anything else that must stay private. The directory's 0700 mode
//! and the peer-credential check are the access control, not the name.
//!
//! # Nothing blocks forever
//!
//! Every read on the socket is a bounded poll: the stream carries a short
//! read timeout and the reader loops on it checking a stop flag (and, during
//! the handshake, a deadline), so `read_msg`'s own lack of a timeout cannot
//! wedge a thread. Writes carry a timeout too; a write that fails closes the
//! session.
//!
//! # Platform
//!
//! The session and the demultiplexer are plain Unix-socket code and build on
//! every Unix, which is how their tests run on macOS over a
//! `UnixStream::pair()`. Only [`HelperListener`] needs `SO_PEERCRED` and is
//! Linux-only; elsewhere it exists with the same signatures and every call
//! fails with "helper sessions are Linux only".

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use super::proto::{encode, read_msg, Msg, ProtoError, ScopeSet, PROTO};

/// How often a blocked read wakes to check the stop flag or the deadline.
const POLL: Duration = Duration::from_millis(250);
/// How long one write may block before the session is considered dead.
const WRITE_TIMEOUT: Duration = Duration::from_secs(5);
/// Text for every I/O call of the non-Linux listener stub.
#[cfg(not(target_os = "linux"))]
const LINUX_ONLY: &str = "helper sessions are Linux only";

// ---------------------------------------------------------------------------
// Socket directory
// ---------------------------------------------------------------------------

/// The directory the helper socket lives in: `$XDG_RUNTIME_DIR/aitm` when the
/// runtime dir is known, else `/tmp/aitm-<uid>`.
///
/// Pure: nothing is created or checked. See [`ensure_socket_dir`].
#[must_use]
pub fn socket_dir(xdg_runtime: Option<&Path>, uid: u32) -> PathBuf {
    match xdg_runtime {
        Some(runtime) => runtime.join("aitm"),
        None => PathBuf::from(format!("/tmp/aitm-{uid}")),
    }
}

/// The socket path inside `dir` for a core with pid `core_pid`:
/// `l4-helper-<core pid>.sock`. Public by design (module docs).
#[must_use]
pub fn socket_path(dir: &Path, core_pid: u32) -> PathBuf {
    dir.join(format!("l4-helper-{core_pid}.sock"))
}

/// What [`socket_dir_ok`] judges: the directory's owner, its mode bits and
/// whether the path itself is a symlink (`lstat`, not `stat`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirMeta {
    /// Owner uid.
    pub uid: u32,
    /// `st_mode`; only the low permission bits (`0o777`) are judged.
    pub mode: u32,
    /// The path is a symbolic link (whatever it points at).
    pub is_symlink: bool,
}

/// The pure check behind [`ensure_socket_dir`]: the directory is not a
/// symlink, is owned by `uid` and has mode exactly `0700`. The error text
/// names the mismatch and no command.
pub fn socket_dir_ok(meta: &DirMeta, uid: u32) -> Result<(), String> {
    if meta.is_symlink {
        return Err("the packet-capture socket directory is a symbolic link".to_string());
    }
    if meta.uid != uid {
        return Err(format!(
            "the packet-capture socket directory is owned by uid {}, not uid {uid}",
            meta.uid
        ));
    }
    let bits = meta.mode & 0o777;
    if bits != 0o700 {
        return Err(format!(
            "the packet-capture socket directory has mode {bits:04o}, expected 0700"
        ));
    }
    Ok(())
}

/// Create `dir` with mode 0700 if it does not exist, then verify it is a
/// directory owned by `uid` with mode 0700 and not a symlink
/// ([`socket_dir_ok`]). An existing directory that fails the check is never
/// repaired, only refused (`PermissionDenied`): a directory someone else
/// prepared is not one to hand a socket to.
pub fn ensure_socket_dir(dir: &Path, uid: u32) -> io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};

    match std::fs::DirBuilder::new().mode(0o700).create(dir) {
        Ok(()) => {}
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {}
        Err(err) => return Err(err),
    }
    let meta = std::fs::symlink_metadata(dir)?;
    let dir_meta = DirMeta {
        uid: meta.uid(),
        mode: meta.mode(),
        is_symlink: meta.file_type().is_symlink(),
    };
    socket_dir_ok(&dir_meta, uid)
        .map_err(|msg| io::Error::new(io::ErrorKind::PermissionDenied, msg))?;
    if !meta.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "the packet-capture socket path is not a directory",
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Errors and events
// ---------------------------------------------------------------------------

/// Why a session step failed. Every variant except [`SessionError::Timeout`]
/// on an inject leaves the session closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionError {
    /// The connecting process runs as another uid; carries that uid.
    PeerUid(u32),
    /// The connecting process is not the one the core spawned; carries the
    /// pid that connected.
    PeerPid(u32),
    /// No connection, no `HelloAck` or no `InjectResult` within the allowed
    /// time.
    Timeout,
    /// The helper speaks another protocol version; carries its version.
    VersionMismatch(u32),
    /// A well-formed message of a type the core never receives: one of the
    /// core→helper types, or a second `HelloAck`. Carries the message name.
    UnexpectedMessage(&'static str),
    /// The wire was malformed or ended; see [`ProtoError`].
    Proto(ProtoError),
    /// The session is closed (by the peer, by a protocol error or by
    /// [`HelperSession::close`]).
    Closed,
    /// Socket or thread failure; carries the OS error text.
    Io(String),
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SessionError::PeerUid(uid) => {
                write!(f, "helper connection came from uid {uid}, not this user")
            }
            SessionError::PeerPid(pid) => write!(
                f,
                "helper connection came from pid {pid}, not the process that was started"
            ),
            SessionError::Timeout => write!(f, "the helper did not answer in time"),
            SessionError::VersionMismatch(proto) => {
                write!(
                    f,
                    "helper speaks protocol {proto}, this core speaks {PROTO}"
                )
            }
            SessionError::UnexpectedMessage(name) => {
                write!(
                    f,
                    "helper sent a {name} message, which the core never accepts"
                )
            }
            SessionError::Proto(err) => write!(f, "{err}"),
            SessionError::Closed => write!(f, "the helper session is closed"),
            SessionError::Io(msg) => write!(f, "helper socket error: {msg}"),
        }
    }
}

impl std::error::Error for SessionError {}

impl From<ProtoError> for SessionError {
    fn from(err: ProtoError) -> Self {
        SessionError::Proto(err)
    }
}

/// The helper's `HelloAck`, returned by [`HelperSession::handshake`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelloAck {
    /// Protocol version the helper speaks; always [`PROTO`] on `Ok`.
    pub proto: u32,
    /// Version string of the helper binary.
    pub helper_version: String,
    /// Effective privileges the helper actually holds, e.g. `cap_net_raw`.
    pub caps: Vec<String>,
}

/// What a capture subscriber receives (see
/// [`HelperSession::subscribe_capture`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaptureEvent {
    /// One captured packet.
    Frame {
        /// Capture timestamp, microseconds since the epoch.
        ts_us: u64,
        /// The raw link-layer bytes.
        bytes: Vec<u8>,
    },
    /// The capture ended: the helper said so (`CaptureClosed`), or the whole
    /// session closed. Nothing follows this on the channel.
    Closed {
        /// The helper's reason, or `helper session closed: <reason>`.
        reason: String,
    },
}

/// The name of a message type, for [`SessionError::UnexpectedMessage`].
fn msg_name(msg: &Msg) -> &'static str {
    match msg {
        Msg::Hello { .. } => "Hello",
        Msg::HelloAck { .. } => "HelloAck",
        Msg::ScopeSet(_) => "ScopeSet",
        Msg::CaptureOpen { .. } => "CaptureOpen",
        Msg::CaptureClose { .. } => "CaptureClose",
        Msg::Frame { .. } => "Frame",
        Msg::CaptureClosed { .. } => "CaptureClosed",
        Msg::Inject { .. } => "Inject",
        Msg::InjectResult { .. } => "InjectResult",
    }
}

/// Lock a mutex, taking the data even if a panicking thread poisoned it: the
/// maps inside are plain bookkeeping whose every update is a single insert or
/// remove, so there is no half-written state to protect.
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

// ---------------------------------------------------------------------------
// Bounded reads
// ---------------------------------------------------------------------------

/// Why a [`PollRead`] gave up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReadStop {
    /// The deadline passed while no byte was available.
    Deadline,
    /// The stop flag was raised while no byte was available.
    Stopped,
}

/// A `Read` over the socket whose timeouts never reach `read_msg`: on each
/// read timeout it checks the stop flag and the deadline and otherwise waits
/// again, so a message split across a timeout boundary is never lost. The
/// stream must carry a read timeout of about [`POLL`].
struct PollRead<'a> {
    stream: &'a UnixStream,
    deadline: Option<Instant>,
    stop: Option<&'a AtomicBool>,
    stopped: Option<ReadStop>,
}

impl Read for PollRead<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut stream = self.stream;
        loop {
            match stream.read(buf) {
                Err(err)
                    if matches!(
                        err.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    if self.stop.is_some_and(|flag| flag.load(Ordering::Acquire)) {
                        self.stopped = Some(ReadStop::Stopped);
                        // Not `Interrupted`: `read_msg` retries that one.
                        return Err(io::Error::other("session stopped"));
                    }
                    if self.deadline.is_some_and(|d| Instant::now() >= d) {
                        self.stopped = Some(ReadStop::Deadline);
                        return Err(io::Error::new(io::ErrorKind::TimedOut, "deadline passed"));
                    }
                }
                Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
                other => return other,
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

/// Outcome channel of one `Inject`: the helper's `error` field, or why no
/// answer will come.
type InjectReply = Result<Option<String>, SessionError>;

/// State shared between the session handle and its reader thread.
struct Shared {
    /// Raised by [`HelperSession::close`]; the reader exits at its next poll.
    stop: AtomicBool,
    /// Set once, by whichever side closes first.
    closed: AtomicBool,
    /// Why the session closed; `None` while open.
    reason: Mutex<Option<SessionError>>,
    /// Capture id → its subscriber.
    captures: Mutex<HashMap<u64, Sender<CaptureEvent>>>,
    /// Inject request id → its waiter.
    pending: Mutex<HashMap<u64, Sender<InjectReply>>>,
}

impl Shared {
    fn new() -> Self {
        Shared {
            stop: AtomicBool::new(false),
            closed: AtomicBool::new(false),
            reason: Mutex::new(None),
            captures: Mutex::new(HashMap::new()),
            pending: Mutex::new(HashMap::new()),
        }
    }

    /// Route one helper→core message. A type the core never receives is a
    /// protocol violation and closes the session.
    fn dispatch(&self, msg: Msg) -> Result<(), SessionError> {
        match msg {
            Msg::Frame {
                capture_id,
                ts_us,
                bytes,
            } => {
                let mut captures = lock(&self.captures);
                if let Some(tx) = captures.get(&capture_id) {
                    // A dropped receiver means the backend lost interest; drop
                    // the subscription with it.
                    if tx.send(CaptureEvent::Frame { ts_us, bytes }).is_err() {
                        captures.remove(&capture_id);
                    }
                }
                Ok(())
            }
            Msg::CaptureClosed { capture_id, reason } => {
                if let Some(tx) = lock(&self.captures).remove(&capture_id) {
                    let _ = tx.send(CaptureEvent::Closed { reason });
                }
                Ok(())
            }
            Msg::InjectResult { request_id, error } => {
                if let Some(tx) = lock(&self.pending).remove(&request_id) {
                    let _ = tx.send(Ok(error));
                }
                Ok(())
            }
            other => Err(SessionError::UnexpectedMessage(msg_name(&other))),
        }
    }

    /// Mark the session closed with `reason` (first close wins), fail every
    /// inject waiter with [`SessionError::Closed`] and end every capture
    /// subscription with a `Closed` event.
    fn close(&self, reason: SessionError) {
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        let text = format!("helper session closed: {reason}");
        *lock(&self.reason) = Some(reason);
        for (_, tx) in lock(&self.pending).drain() {
            let _ = tx.send(Err(SessionError::Closed));
        }
        for (_, tx) in lock(&self.captures).drain() {
            let _ = tx.send(CaptureEvent::Closed {
                reason: text.clone(),
            });
        }
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }
}

/// A connected, checked helper session: the core's end of spec §5.2.
///
/// Order of use: [`HelperSession::handshake`], then
/// [`HelperSession::start_reader`], then any mix of
/// [`HelperSession::send_scope`], [`HelperSession::subscribe_capture`],
/// [`HelperSession::send`] and [`HelperSession::inject`] from any thread.
/// Dropping the session closes it and shuts the socket, which is the EOF the
/// helper exits on (spec §5.1).
pub struct HelperSession {
    stream: UnixStream,
    /// Serialises writers so two messages never interleave on the wire.
    write_lock: Mutex<()>,
    shared: Arc<Shared>,
    reader: Mutex<Option<JoinHandle<()>>>,
}

impl std::fmt::Debug for HelperSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HelperSession")
            .field("closed", &self.is_closed())
            .finish_non_exhaustive()
    }
}

impl HelperSession {
    /// Wrap an already connected and peer-checked stream. The caller has done
    /// the `SO_PEERCRED` check ([`HelperListener::accept_checked`] does), or
    /// owns both ends (tests).
    pub fn from_stream(stream: UnixStream) -> Result<Self, SessionError> {
        let io = |err: io::Error| SessionError::Io(err.to_string());
        stream.set_nonblocking(false).map_err(io)?;
        stream.set_read_timeout(Some(POLL)).map_err(io)?;
        stream.set_write_timeout(Some(WRITE_TIMEOUT)).map_err(io)?;
        Ok(HelperSession {
            stream,
            write_lock: Mutex::new(()),
            shared: Arc::new(Shared::new()),
            reader: Mutex::new(None),
        })
    }

    /// Send `Hello` and wait up to `timeout` for the `HelloAck`.
    ///
    /// Runs before [`HelperSession::start_reader`]. The reply's `proto` is
    /// judged first: anything but [`PROTO`] is
    /// [`SessionError::VersionMismatch`] whatever else the message holds. A
    /// reply that is not a `HelloAck` is [`SessionError::UnexpectedMessage`];
    /// a malformed or absent one is [`SessionError::Proto`] or
    /// [`SessionError::Timeout`]. Every error closes the session.
    pub fn handshake(
        &mut self,
        core_version: &str,
        timeout: Duration,
    ) -> Result<HelloAck, SessionError> {
        if lock(&self.reader).is_some() {
            return Err(SessionError::Io(
                "handshake must run before the reader starts".to_string(),
            ));
        }
        let result = self.handshake_inner(core_version, timeout);
        if let Err(err) = &result {
            self.shared.close(err.clone());
            let _ = self.stream.shutdown(Shutdown::Both);
        }
        result
    }

    fn handshake_inner(
        &mut self,
        core_version: &str,
        timeout: Duration,
    ) -> Result<HelloAck, SessionError> {
        self.send(&Msg::Hello {
            proto: PROTO,
            core_version: core_version.to_string(),
        })?;
        let mut rd = PollRead {
            stream: &self.stream,
            deadline: Some(Instant::now() + timeout),
            stop: None,
            stopped: None,
        };
        let msg = match read_msg(&mut rd) {
            Ok(msg) => msg,
            Err(ProtoError::Io(_)) if rd.stopped == Some(ReadStop::Deadline) => {
                return Err(SessionError::Timeout);
            }
            Err(err) => return Err(SessionError::Proto(err)),
        };
        match msg {
            Msg::HelloAck {
                proto,
                helper_version,
                caps,
            } => {
                if proto != PROTO {
                    return Err(SessionError::VersionMismatch(proto));
                }
                Ok(HelloAck {
                    proto,
                    helper_version,
                    caps,
                })
            }
            other => Err(SessionError::UnexpectedMessage(msg_name(&other))),
        }
    }

    /// Start the reader thread that demultiplexes `Frame`, `CaptureClosed`
    /// and `InjectResult`. Idempotent. A protocol error, an oversized length,
    /// EOF or a core-bound message type closes the session; then
    /// [`HelperSession::is_closed`] is true, [`HelperSession::close_reason`]
    /// says why, every waiter gets [`SessionError::Closed`] and every capture
    /// channel ends with a `Closed` event.
    pub fn start_reader(&self) -> Result<(), SessionError> {
        let mut slot = lock(&self.reader);
        if slot.is_some() {
            return Ok(());
        }
        if self.is_closed() {
            return Err(SessionError::Closed);
        }
        let io = |err: io::Error| SessionError::Io(err.to_string());
        let stream = self.stream.try_clone().map_err(io)?;
        let shared = Arc::clone(&self.shared);
        let handle = std::thread::Builder::new()
            .name("l4-helper-reader".to_string())
            .spawn(move || reader_loop(&stream, &shared))
            .map_err(io)?;
        *slot = Some(handle);
        Ok(())
    }

    /// Write one message. Fails with [`SessionError::Closed`] on a closed
    /// session; a write error closes the session and is returned as
    /// [`SessionError::Io`].
    pub fn send(&self, msg: &Msg) -> Result<(), SessionError> {
        if self.is_closed() {
            return Err(SessionError::Closed);
        }
        let bytes = encode(msg);
        let _guard = lock(&self.write_lock);
        let mut stream = &self.stream;
        match stream.write_all(&bytes).and_then(|()| stream.flush()) {
            Ok(()) => Ok(()),
            Err(err) => {
                let err = SessionError::Io(err.to_string());
                self.shared.close(err.clone());
                let _ = self.stream.shutdown(Shutdown::Both);
                Err(err)
            }
        }
    }

    /// Send the guard state (`ScopeSet`), spec §5.2.
    pub fn send_scope(&self, set: &ScopeSet) -> Result<(), SessionError> {
        self.send(&Msg::ScopeSet(set.clone()))
    }

    /// Receive the `Frame`s and the `CaptureClosed` of capture `id`. Subscribe
    /// before sending the `CaptureOpen`, or the first frames have nowhere to
    /// go and are dropped. A later subscription for the same id replaces the
    /// earlier one.
    pub fn subscribe_capture(&self, id: u64) -> Receiver<CaptureEvent> {
        let (tx, rx) = mpsc::channel();
        lock(&self.shared.captures).insert(id, tx);
        rx
    }

    /// Forget capture `id`; frames for it are dropped from now on.
    pub fn unsubscribe_capture(&self, id: u64) {
        lock(&self.shared.captures).remove(&id);
    }

    /// Send one `Inject` and wait up to `timeout` for its `InjectResult`.
    /// `Ok(None)` is success; `Ok(Some(text))` is the helper's guard or wire
    /// error text. [`SessionError::Timeout`] leaves the session open; a late
    /// result for a forgotten request is dropped.
    pub fn inject(
        &self,
        request_id: u64,
        interface: &str,
        bytes: &[u8],
        timeout: Duration,
    ) -> Result<Option<String>, SessionError> {
        if self.is_closed() {
            return Err(SessionError::Closed);
        }
        let (tx, rx) = mpsc::channel();
        lock(&self.shared.pending).insert(request_id, tx);
        // `close` drains the map after raising the flag; a waiter registered
        // after that drain would otherwise sit until its timeout.
        if self.is_closed() {
            lock(&self.shared.pending).remove(&request_id);
            return Err(SessionError::Closed);
        }
        if let Err(err) = self.send(&Msg::Inject {
            request_id,
            interface: interface.to_string(),
            bytes: bytes.to_vec(),
        }) {
            lock(&self.shared.pending).remove(&request_id);
            return Err(err);
        }
        match rx.recv_timeout(timeout) {
            Ok(reply) => reply,
            Err(RecvTimeoutError::Timeout) => {
                lock(&self.shared.pending).remove(&request_id);
                Err(SessionError::Timeout)
            }
            Err(RecvTimeoutError::Disconnected) => Err(SessionError::Closed),
        }
    }

    /// True once the session closed for any reason.
    pub fn is_closed(&self) -> bool {
        self.shared.is_closed()
    }

    /// Why the session closed; `None` while it is open. A session the core
    /// closed itself reports [`SessionError::Closed`].
    pub fn close_reason(&self) -> Option<SessionError> {
        lock(&self.shared.reason).clone()
    }

    /// Close the session: fail the waiters, end the capture channels, shut the
    /// socket (the helper exits on that EOF) and join the reader thread.
    pub fn close(&self) {
        self.shared.stop.store(true, Ordering::Release);
        self.shared.close(SessionError::Closed);
        let _ = self.stream.shutdown(Shutdown::Both);
        let handle = lock(&self.reader).take();
        if let Some(handle) = handle {
            if std::thread::current().id() != handle.thread().id() {
                let _ = handle.join();
            }
        }
    }
}

impl Drop for HelperSession {
    fn drop(&mut self) {
        self.close();
    }
}

/// The reader thread body.
fn reader_loop(stream: &UnixStream, shared: &Shared) {
    let mut rd = PollRead {
        stream,
        deadline: None,
        stop: Some(&shared.stop),
        stopped: None,
    };
    let reason = loop {
        match read_msg(&mut rd) {
            Ok(msg) => {
                if let Err(err) = shared.dispatch(msg) {
                    break err;
                }
            }
            Err(ProtoError::Io(_)) if rd.stopped == Some(ReadStop::Stopped) => {
                break SessionError::Closed;
            }
            Err(err) => break SessionError::Proto(err),
        }
    };
    shared.close(reason);
    let _ = stream.shutdown(Shutdown::Both);
}

// ---------------------------------------------------------------------------
// Listener (Linux)
// ---------------------------------------------------------------------------

/// The core's listening socket, `l4-helper-<core pid>.sock` in the directory
/// from [`ensure_socket_dir`]. Removes its socket file on drop.
#[cfg(target_os = "linux")]
#[derive(Debug)]
pub struct HelperListener {
    listener: std::os::unix::net::UnixListener,
    path: PathBuf,
}

#[cfg(target_os = "linux")]
impl HelperListener {
    /// Bind `l4-helper-<core pid>.sock` in `dir`, removing a stale file of
    /// that name first (a previous core with this pid is gone, or we would
    /// not have its pid). `dir` has been checked by [`ensure_socket_dir`].
    pub fn bind(dir: &Path) -> io::Result<Self> {
        let path = socket_path(dir, std::process::id());
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => return Err(err),
        }
        let listener = std::os::unix::net::UnixListener::bind(&path)?;
        listener.set_nonblocking(true)?;
        Ok(HelperListener { listener, path })
    }

    /// The absolute socket path to put on the helper's argv.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Accept one connection within `timeout` and check its `SO_PEERCRED`:
    /// uid equal to this process's real uid, pid equal to `expected_pid` (the
    /// pid the core spawned; pkexec execs the helper in place). A failed check
    /// drops the connection and returns [`SessionError::PeerUid`] /
    /// [`SessionError::PeerPid`]; nothing within `timeout` is
    /// [`SessionError::Timeout`].
    pub fn accept_checked(
        &self,
        expected_pid: u32,
        timeout: Duration,
    ) -> Result<HelperSession, SessionError> {
        use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};

        let io = |err: io::Error| SessionError::Io(err.to_string());
        let deadline = Instant::now() + timeout;
        loop {
            match self.listener.accept() {
                Ok((stream, _addr)) => {
                    let creds = getsockopt(&stream, PeerCredentials)
                        .map_err(|err| SessionError::Io(err.to_string()))?;
                    let my_uid = nix::unistd::getuid().as_raw();
                    if creds.uid() != my_uid {
                        return Err(SessionError::PeerUid(creds.uid()));
                    }
                    let pid = u32::try_from(creds.pid()).unwrap_or(0);
                    if pid != expected_pid {
                        return Err(SessionError::PeerPid(pid));
                    }
                    return HelperSession::from_stream(stream);
                }
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                    let now = Instant::now();
                    if now >= deadline {
                        return Err(SessionError::Timeout);
                    }
                    std::thread::sleep((deadline - now).min(Duration::from_millis(20)));
                }
                Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
                Err(err) => return Err(io(err)),
            }
        }
    }
}

#[cfg(target_os = "linux")]
impl Drop for HelperListener {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// The listener on a platform without `SO_PEERCRED`: same signatures, every
/// call fails with "helper sessions are Linux only".
#[cfg(not(target_os = "linux"))]
#[derive(Debug)]
pub struct HelperListener {
    path: PathBuf,
}

#[cfg(not(target_os = "linux"))]
impl HelperListener {
    /// Always `Err(Unsupported)` off Linux.
    pub fn bind(_dir: &Path) -> io::Result<Self> {
        Err(io::Error::new(io::ErrorKind::Unsupported, LINUX_ONLY))
    }

    /// Unreachable in practice: [`HelperListener::bind`] never succeeds here.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Always `Err(Io("helper sessions are Linux only"))` off Linux.
    pub fn accept_checked(
        &self,
        _expected_pid: u32,
        _timeout: Duration,
    ) -> Result<HelperSession, SessionError> {
        Err(SessionError::Io(LINUX_ONLY.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::helper::proto::{encode, read_msg, Msg, ScopeSet, MAX_FRAME, PROTO};
    use crate::types::{
        IpCidr, L4Capability, L4Direction, L4ScopeEntry, L4ScopeId, L4ScopeSource, PortRange,
        RateCap,
    };
    use std::io::Write;
    use std::net::{IpAddr, Ipv4Addr};
    use std::os::unix::net::UnixStream;
    use std::path::Path;
    use std::time::{Duration, Instant};

    fn scope_set() -> ScopeSet {
        ScopeSet {
            scope: vec![L4ScopeEntry {
                id: L4ScopeId::new(),
                cidr: IpCidr {
                    addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                    prefix: 32,
                },
                ports: PortRange { lo: 9053, hi: 9053 },
                interface: "lo".to_string(),
                direction: L4Direction::Outbound,
                capability: L4Capability::Capture,
                inject_rate: RateCap { pps: 10, burst: 5 },
                source: L4ScopeSource::Config,
            }],
            global_inject_pps: 7,
            max_packet_bytes: 1500,
            max_packets_per_call: 4,
            self_ports: vec![28180],
        }
    }

    /// A connected pair: the core's end as a session, the helper's end raw.
    fn pair() -> (HelperSession, UnixStream) {
        let (core, helper) = UnixStream::pair().expect("socketpair");
        let session = HelperSession::from_stream(core).expect("session");
        (session, helper)
    }

    /// Play the helper's half of a good handshake on `peer`.
    fn ack_hello(peer: &mut UnixStream) {
        let hello = read_msg(peer).expect("hello");
        assert_eq!(
            hello,
            Msg::Hello {
                proto: PROTO,
                core_version: "0.9.9-test".to_string(),
            }
        );
        peer.write_all(&encode(&Msg::HelloAck {
            proto: PROTO,
            helper_version: "0.9.9-helper".to_string(),
            caps: vec!["cap_net_raw".to_string()],
        }))
        .expect("ack");
    }

    /// A session past its handshake with the reader running.
    fn open_session() -> (HelperSession, UnixStream) {
        let (mut session, mut peer) = pair();
        let t = std::thread::spawn(move || {
            ack_hello(&mut peer);
            peer
        });
        let ack = session
            .handshake("0.9.9-test", Duration::from_secs(5))
            .expect("handshake");
        assert_eq!(ack.proto, PROTO);
        assert_eq!(ack.helper_version, "0.9.9-helper");
        assert_eq!(ack.caps, vec!["cap_net_raw".to_string()]);
        session.start_reader().expect("reader");
        (session, t.join().expect("peer thread"))
    }

    fn wait_closed(session: &HelperSession) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !session.is_closed() {
            assert!(Instant::now() < deadline, "session never closed");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn socket_dir_refuses_foreign_owner() {
        let ok = DirMeta {
            uid: 1000,
            mode: 0o700,
            is_symlink: false,
        };
        assert_eq!(socket_dir_ok(&ok, 1000), Ok(()));
        let foreign = DirMeta { uid: 0, ..ok };
        assert!(socket_dir_ok(&foreign, 1000).is_err());
        let loose = DirMeta { mode: 0o750, ..ok };
        assert!(socket_dir_ok(&loose, 1000).is_err());
        let link = DirMeta {
            is_symlink: true,
            ..ok
        };
        assert!(socket_dir_ok(&link, 1000).is_err());
        // Extra bits above the permission triplet do not matter.
        let sticky = DirMeta {
            mode: 0o40700,
            ..ok
        };
        assert_eq!(socket_dir_ok(&sticky, 1000), Ok(()));
    }

    #[test]
    fn socket_dir_prefers_xdg_runtime_then_tmp() {
        assert_eq!(
            socket_dir(Some(Path::new("/run/user/1000")), 1000),
            Path::new("/run/user/1000/aitm")
        );
        assert_eq!(socket_dir(None, 1000), Path::new("/tmp/aitm-1000"));
        assert_eq!(
            socket_path(Path::new("/run/user/1000/aitm"), 4242),
            Path::new("/run/user/1000/aitm/l4-helper-4242.sock")
        );
    }

    #[test]
    fn ensure_socket_dir_creates_0700_and_checks_mode() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let base = std::env::temp_dir().join(format!("aitm-client-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let dir = base.join("aitm");
        let uid = std::fs::metadata(std::env::temp_dir())
            .map(|m| m.uid())
            .expect("tmp uid");
        std::fs::create_dir_all(&base).expect("base");
        let my_uid = std::fs::metadata(&base).expect("base meta").uid();
        assert_eq!(uid, my_uid, "test assumes $TMPDIR belongs to this user");

        ensure_socket_dir(&dir, my_uid).expect("create");
        let mode = std::fs::metadata(&dir).expect("meta").mode() & 0o777;
        assert_eq!(mode, 0o700);
        // Idempotent.
        ensure_socket_dir(&dir, my_uid).expect("again");

        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o750)).expect("chmod");
        let err = ensure_socket_dir(&dir, my_uid).expect_err("loose mode refused");
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);

        // Someone else's uid is refused even with the right mode.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        let err = ensure_socket_dir(&dir, my_uid.wrapping_add(1)).expect_err("foreign owner");
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn version_mismatch_is_reported() {
        let (mut session, mut peer) = pair();
        let t = std::thread::spawn(move || {
            let _hello = read_msg(&mut peer).expect("hello");
            peer.write_all(&encode(&Msg::HelloAck {
                proto: 2,
                helper_version: "9.9.9".to_string(),
                caps: vec![],
            }))
            .expect("ack");
            peer
        });
        let err = session
            .handshake("0.9.9-test", Duration::from_secs(5))
            .expect_err("mismatch");
        assert_eq!(err, SessionError::VersionMismatch(2));
        assert!(session.is_closed());
        drop(t.join().expect("peer"));
    }

    #[test]
    fn handshake_times_out() {
        let (mut session, peer) = pair();
        let started = Instant::now();
        let err = session
            .handshake("0.9.9-test", Duration::from_millis(300))
            .expect_err("timeout");
        assert_eq!(err, SessionError::Timeout);
        let elapsed = started.elapsed();
        assert!(elapsed >= Duration::from_millis(300), "{elapsed:?}");
        assert!(elapsed < Duration::from_secs(3), "{elapsed:?}");
        assert!(session.is_closed());
        drop(peer);
    }

    #[test]
    fn handshake_refuses_a_non_ack_reply() {
        let (mut session, mut peer) = pair();
        let t = std::thread::spawn(move || {
            let _hello = read_msg(&mut peer).expect("hello");
            peer.write_all(&encode(&Msg::Frame {
                capture_id: 1,
                ts_us: 2,
                bytes: vec![3],
            }))
            .expect("frame");
            peer
        });
        let err = session
            .handshake("0.9.9-test", Duration::from_secs(5))
            .expect_err("not an ack");
        assert_eq!(err, SessionError::UnexpectedMessage("Frame"));
        drop(t.join().expect("peer"));
    }

    #[test]
    fn oversized_frame_closes_session() {
        let (session, mut peer) = open_session();
        let len = u32::try_from(MAX_FRAME + 1).expect("fits");
        peer.write_all(&len.to_be_bytes()).expect("header");
        peer.write_all(&[0x06]).expect("type");
        wait_closed(&session);
        assert_eq!(
            session.close_reason(),
            Some(SessionError::Proto(ProtoError::TooLong(MAX_FRAME + 1)))
        );
        let err = session
            .inject(1, "lo", &[0u8; 4], Duration::from_secs(1))
            .expect_err("closed");
        assert_eq!(err, SessionError::Closed);
        // The core shut the socket, so the helper end sees EOF.
        assert_eq!(read_msg(&mut peer), Err(ProtoError::Eof));
    }

    #[test]
    fn core_bound_type_closes_session() {
        let (session, mut peer) = open_session();
        peer.write_all(&encode(&Msg::CaptureOpen {
            id: 1,
            interface: "lo".to_string(),
            direction: L4Direction::Inbound,
            read_timeout_ms: 100,
        }))
        .expect("write");
        wait_closed(&session);
        assert_eq!(
            session.close_reason(),
            Some(SessionError::UnexpectedMessage("CaptureOpen"))
        );
        assert_eq!(read_msg(&mut peer), Err(ProtoError::Eof));
    }

    #[test]
    fn eof_closes_session_and_fails_waiters() {
        let (session, peer) = open_session();
        let rx = session.subscribe_capture(3);
        drop(peer);
        wait_closed(&session);
        assert_eq!(
            session.close_reason(),
            Some(SessionError::Proto(ProtoError::Eof))
        );
        let event = rx
            .recv_timeout(Duration::from_secs(1))
            .expect("closed event");
        assert_eq!(
            event,
            CaptureEvent::Closed {
                reason: "helper session closed: peer closed the session".to_string(),
            }
        );
    }

    #[test]
    fn frames_demux_to_their_capture() {
        let (session, mut peer) = open_session();
        let rx7 = session.subscribe_capture(7);
        let rx8 = session.subscribe_capture(8);
        for msg in [
            Msg::Frame {
                capture_id: 7,
                ts_us: 10,
                bytes: vec![1, 2, 3],
            },
            Msg::Frame {
                capture_id: 8,
                ts_us: 11,
                bytes: vec![9],
            },
            Msg::Frame {
                capture_id: 7,
                ts_us: 12,
                bytes: vec![4],
            },
            Msg::CaptureClosed {
                capture_id: 7,
                reason: "interface went away".to_string(),
            },
        ] {
            peer.write_all(&encode(&msg)).expect("write");
        }
        let t = Duration::from_secs(2);
        assert_eq!(
            rx7.recv_timeout(t).expect("f1"),
            CaptureEvent::Frame {
                ts_us: 10,
                bytes: vec![1, 2, 3]
            }
        );
        assert_eq!(
            rx7.recv_timeout(t).expect("f2"),
            CaptureEvent::Frame {
                ts_us: 12,
                bytes: vec![4]
            }
        );
        assert_eq!(
            rx7.recv_timeout(t).expect("closed"),
            CaptureEvent::Closed {
                reason: "interface went away".to_string()
            }
        );
        assert_eq!(
            rx8.recv_timeout(t).expect("f8"),
            CaptureEvent::Frame {
                ts_us: 11,
                bytes: vec![9]
            }
        );
        assert!(!session.is_closed());
    }

    #[test]
    fn inject_round_trips_the_helper_error_text() {
        let (session, mut peer) = open_session();
        let t = std::thread::spawn(move || {
            let msg = read_msg(&mut peer).expect("inject");
            assert_eq!(
                msg,
                Msg::Inject {
                    request_id: 41,
                    interface: "lo".to_string(),
                    bytes: vec![0xAA, 0xBB],
                }
            );
            peer.write_all(&encode(&Msg::InjectResult {
                request_id: 41,
                error: Some("target 127.0.0.1:8999 is out of L4 scope".to_string()),
            }))
            .expect("result");
            // A second one succeeds.
            let _ = read_msg(&mut peer).expect("inject 2");
            peer.write_all(&encode(&Msg::InjectResult {
                request_id: 42,
                error: None,
            }))
            .expect("result 2");
            peer
        });
        let out = session
            .inject(41, "lo", &[0xAA, 0xBB], Duration::from_secs(2))
            .expect("answered");
        assert_eq!(
            out,
            Some("target 127.0.0.1:8999 is out of L4 scope".to_string())
        );
        let out = session
            .inject(42, "lo", &[0xCC], Duration::from_secs(2))
            .expect("answered");
        assert_eq!(out, None);
        drop(t.join().expect("peer"));
    }

    #[test]
    fn inject_times_out_without_a_result() {
        let (session, mut peer) = open_session();
        // The peer reads the Inject and never answers.
        let t = std::thread::spawn(move || {
            let msg = read_msg(&mut peer).expect("inject");
            assert!(matches!(msg, Msg::Inject { request_id: 5, .. }));
            peer
        });
        let err = session
            .inject(5, "lo", &[1], Duration::from_millis(200))
            .expect_err("no answer");
        assert_eq!(err, SessionError::Timeout);
        assert!(!session.is_closed());
        drop(t.join().expect("peer"));
    }

    #[test]
    fn send_scope_puts_scope_set_on_the_wire() {
        let (session, mut peer) = open_session();
        let set = scope_set();
        session.send_scope(&set).expect("send");
        assert_eq!(read_msg(&mut peer).expect("scope"), Msg::ScopeSet(set));
        session.send(&Msg::CaptureClose { id: 9 }).expect("send");
        assert_eq!(
            read_msg(&mut peer).expect("close"),
            Msg::CaptureClose { id: 9 }
        );
    }

    #[test]
    fn close_shuts_the_peer_and_refuses_sends() {
        let (session, mut peer) = open_session();
        session.close();
        assert!(session.is_closed());
        assert_eq!(read_msg(&mut peer), Err(ProtoError::Eof));
        assert_eq!(
            session.send(&Msg::CaptureClose { id: 1 }),
            Err(SessionError::Closed)
        );
    }

    #[test]
    fn session_error_display_names_no_command() {
        for err in [
            SessionError::PeerUid(7),
            SessionError::PeerPid(8),
            SessionError::Timeout,
            SessionError::VersionMismatch(2),
            SessionError::UnexpectedMessage("Hello"),
            SessionError::Proto(ProtoError::BadBinary),
            SessionError::Closed,
            SessionError::Io("x".to_string()),
        ] {
            let text = err.to_string();
            assert!(!text.is_empty());
            for word in ["sudo", "pkexec", "chmod", "setcap", "chown"] {
                assert!(!text.contains(word), "{text}");
            }
        }
        assert_eq!(
            SessionError::VersionMismatch(2).to_string(),
            "helper speaks protocol 2, this core speaks 1"
        );
        assert_eq!(
            SessionError::PeerPid(8).to_string(),
            "helper connection came from pid 8, not the process that was started"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn wrong_pid_is_refused() {
        let base = std::env::temp_dir().join(format!("aitm-client-pid-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).expect("base");
        let listener = HelperListener::bind(&base).expect("bind");
        let path = listener.path().to_path_buf();
        assert_eq!(
            path.file_name().and_then(|n| n.to_str()),
            Some(format!("l4-helper-{}.sock", std::process::id()).as_str())
        );
        let t = std::thread::spawn(move || UnixStream::connect(&path).expect("connect"));
        let err = listener
            .accept_checked(std::process::id() + 1, Duration::from_secs(5))
            .expect_err("wrong pid");
        assert_eq!(err, SessionError::PeerPid(std::process::id()));
        drop(t.join().expect("connector"));
        drop(listener);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn own_pid_is_accepted_and_times_out_otherwise() {
        let base = std::env::temp_dir().join(format!("aitm-client-ok-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).expect("base");
        let listener = HelperListener::bind(&base).expect("bind");
        let err = listener
            .accept_checked(std::process::id(), Duration::from_millis(200))
            .expect_err("nobody connected");
        assert_eq!(err, SessionError::Timeout);
        let path = listener.path().to_path_buf();
        let t = std::thread::spawn(move || UnixStream::connect(&path).expect("connect"));
        let session = listener
            .accept_checked(std::process::id(), Duration::from_secs(5))
            .expect("own pid");
        assert!(!session.is_closed());
        drop(t.join().expect("connector"));
        let sock = listener.path().to_path_buf();
        drop(listener);
        assert!(!sock.exists(), "socket file removed on drop");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn listener_is_linux_only_elsewhere() {
        let err = HelperListener::bind(Path::new("/nonexistent")).expect_err("stub");
        assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
    }
}
