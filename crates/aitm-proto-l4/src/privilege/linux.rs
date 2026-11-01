//! Linux gatherer: the inputs of the spec §2.2 Linux table and the §5.5
//! "a prompt is possible" test.
//!
//! The decisions live in pure functions ([`parse_cap_eff`], [`candidates`],
//! [`root_owned_chain`], [`prompt_possible`]) that compile and are tested on
//! every OS. The I/O ([`gather_linux`]) only reads: `/proc/self/status`, file
//! metadata along the helper's path, the policy file, `pkexec`'s presence, the
//! environment, and `/dev/tty`. The one thing it runs is the helper's own
//! `probe`, as this user, with a bounded wait. Discovery finds a helper to
//! probe; only the policy's exec path is ever run through polkit, by
//! [`request_linux`] below (plan P1b.14), whose argv is [`pkexec_argv`].

use std::any::Any;
use std::collections::{HashMap, VecDeque};
use std::ffi::OsString;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::time::{Duration, SystemTime};

use crate::privilege::contract::LINUX_HELPER_PATH;
use crate::privilege::derive::{text, LinuxInputs};
use crate::privilege::report::RequestState;
use crate::privilege::state::{Outcome, PrivilegeConfig, ProcessLifetime};

/// File name of the helper binary wherever it is installed.
pub const HELPER_FILE_NAME: &str = "aitm-l4-helper";

/// NixOS's `security.wrappers` output directory.
pub const NIX_WRAPPERS_HELPER_PATH: &str = "/run/wrappers/bin/aitm-l4-helper";

/// The polkit policy the Linux packages install (spec §5.4).
pub const POLKIT_POLICY_PATH: &str =
    "/usr/share/polkit-1/actions/com.mrbrutti.aitmproxy.l4-helper.policy";

/// Where the polkit launcher lives on every distribution the packages target.
pub const PKEXEC_PATH: &str = "/usr/bin/pkexec";

/// Capability bit numbers from `linux/capability.h`.
pub const CAP_NET_ADMIN: u32 = 12;
/// See [`CAP_NET_ADMIN`].
pub const CAP_NET_RAW: u32 = 13;

/// The `CapEff` mask from a `/proc/<pid>/status` document, when it has one.
#[must_use]
pub fn parse_cap_eff(status: &str) -> Option<u64> {
    status
        .lines()
        .find_map(|line| line.strip_prefix("CapEff:"))
        .and_then(|hex| u64::from_str_radix(hex.trim(), 16).ok())
}

/// Whether capability bit `cap` is set in an effective-capabilities mask.
#[must_use]
pub fn has_cap(cap_eff: u64, cap: u32) -> bool {
    cap < 64 && cap_eff & (1u64 << cap) != 0
}

/// Helper discovery order (spec §2.2): the configured `l4.privilege.helper_path`,
/// `<exe dir>/aitm-l4-helper`, the package path, then NixOS's wrappers directory.
/// A place named twice is listed once, so it is probed once.
#[must_use]
pub fn candidates(helper_path: Option<&Path>, exe_dir: &Path) -> Vec<PathBuf> {
    let mut order: Vec<PathBuf> = Vec::with_capacity(4);
    let mut push = |path: PathBuf| {
        if !order.contains(&path) {
            order.push(path);
        }
    };
    if let Some(configured) = helper_path {
        push(configured.to_path_buf());
    }
    push(exe_dir.join(HELPER_FILE_NAME));
    push(PathBuf::from(LINUX_HELPER_PATH));
    push(PathBuf::from(NIX_WRAPPERS_HELPER_PATH));
    order
}

/// What matters about one path component for [`root_owned_chain`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathMeta {
    /// Owner uid.
    pub uid: u32,
    /// Permission bits (`st_mode & 0o7777`).
    pub mode: u32,
    /// The component itself is a symlink (not followed).
    pub is_symlink: bool,
}

/// Group- or other-write bits: anyone but the owner could replace the file.
const GROUP_OR_OTHER_WRITE: u32 = 0o022;

/// A helper path only root could have placed: every component from the root
/// directory to the binary is root-owned, neither group- nor world-writable,
/// and not a symlink. An empty chain was never inspected and is `false`.
#[must_use]
pub fn root_owned_chain(chain: &[PathMeta]) -> bool {
    !chain.is_empty()
        && chain
            .iter()
            .all(|meta| meta.uid == 0 && meta.mode & GROUP_OR_OTHER_WRITE == 0 && !meta.is_symlink)
}

/// Spec §5.5 as corrected by spike S7: a polkit prompt can reach the operator
/// when `DISPLAY` or `WAYLAND_DISPLAY` is set (a graphical agent is likely), or
/// when the process has a controlling terminal (`open("/dev/tty")` succeeds;
/// pkexec's textual agent uses that, not stdin). An empty `DISPLAY` or
/// `WAYLAND_DISPLAY` counts as unset.
#[must_use]
pub fn prompt_possible(display: Option<&str>, wayland: Option<&str>, tty_opens: bool) -> bool {
    let set = |var: Option<&str>| var.is_some_and(|value| !value.is_empty());
    set(display) || set(wayland) || tty_opens
}

/// Everything `derive` needs from this Linux host (spec §2.2 Linux table).
/// `helper_path` is the configured `l4.privilege.helper_path`;
/// `session_connected` is what the helper-session owner knows (P1b.13).
///
/// `pub(crate)`: P1b.6's `PrivilegeState` wires it behind the `Prober` seam.
#[cfg(target_os = "linux")]
pub(crate) fn gather_linux(helper_path: Option<&Path>, session_connected: bool) -> LinuxInputs {
    use crate::privilege::derive::HelperCandidate;

    let cap_eff = std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| parse_cap_eff(&status))
        .unwrap_or(0);

    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(Path::to_path_buf))
        .unwrap_or_else(|| PathBuf::from("/nonexistent"));
    let helper = candidates(helper_path, &exe_dir)
        .into_iter()
        .find(|path| path.is_file())
        .map(|path| {
            let root_owned = path_chain(&path).is_some_and(|chain| root_owned_chain(&chain));
            // The probe runs only a helper root alone could have placed (it
            // executes the file), and once per `(path, mtime)`.
            let file_caps_net_raw = root_owned && probe_file_caps_cached(&path);
            HelperCandidate {
                at_policy_path: path == Path::new(LINUX_HELPER_PATH),
                root_owned_chain: root_owned,
                file_caps_net_raw,
                path,
            }
        });

    LinuxInputs {
        cap_net_raw: has_cap(cap_eff, CAP_NET_RAW),
        cap_net_admin: has_cap(cap_eff, CAP_NET_ADMIN),
        session_connected,
        helper,
        policy_file_present: Path::new(POLKIT_POLICY_PATH).is_file(),
        pkexec_present: Path::new(PKEXEC_PATH).is_file(),
        prompt_possible: prompt_possible(
            std::env::var("DISPLAY").ok().as_deref(),
            std::env::var("WAYLAND_DISPLAY").ok().as_deref(),
            std::fs::File::open("/dev/tty").is_ok(),
        ),
        // The session owner (`PrivilegeState`) knows the last handshake.
        last_session_error: None,
    }
}

/// Portable stand-in: nothing here is a Linux host, so no capability, helper,
/// policy, launcher or prompt is claimed.
#[cfg(not(target_os = "linux"))]
pub(crate) fn gather_linux(_helper_path: Option<&Path>, session_connected: bool) -> LinuxInputs {
    LinuxInputs {
        cap_net_raw: false,
        cap_net_admin: false,
        session_connected,
        helper: None,
        policy_file_present: false,
        pkexec_present: false,
        prompt_possible: false,
        last_session_error: None,
    }
}

/// Metadata of every component from `/` down to `path`, symlinks not followed.
/// `None` when any component cannot be read: an unreadable chain is not a
/// root-owned one.
#[cfg(target_os = "linux")]
fn path_chain(path: &Path) -> Option<Vec<PathMeta>> {
    use std::os::unix::fs::MetadataExt;

    if !path.is_absolute() {
        return None;
    }
    let mut chain = Vec::new();
    let mut cursor = PathBuf::new();
    for component in path.components() {
        cursor.push(component);
        let meta = std::fs::symlink_metadata(&cursor).ok()?;
        chain.push(PathMeta {
            uid: meta.uid(),
            mode: meta.mode() & 0o7777,
            is_symlink: meta.file_type().is_symlink(),
        });
    }
    Some(chain)
}

/// Answers of the helper's `probe`, one per `(path, mtime)`: the probe is a
/// subprocess and must not run on every re-probe of the report (1 s TTL).
/// A file that changed (new mtime) is probed again.
#[derive(Debug, Default)]
pub struct ProbeCache {
    seen: HashMap<PathBuf, (SystemTime, bool)>,
}

impl ProbeCache {
    /// The cached answer for `path` at `mtime`, else `probe()`'s, remembered.
    pub fn file_caps(
        &mut self,
        path: &Path,
        mtime: SystemTime,
        probe: impl FnOnce() -> bool,
    ) -> bool {
        if let Some((seen, answer)) = self.seen.get(path) {
            if *seen == mtime {
                return *answer;
            }
        }
        let answer = probe();
        self.seen.insert(path.to_path_buf(), (mtime, answer));
        answer
    }
}

/// [`probe_reports_net_raw`] through the process-wide [`ProbeCache`]. A
/// helper whose metadata cannot be read is not probed.
#[cfg(target_os = "linux")]
fn probe_file_caps_cached(helper: &Path) -> bool {
    use std::sync::OnceLock;

    static CACHE: OnceLock<Mutex<ProbeCache>> = OnceLock::new();

    let Ok(mtime) = std::fs::metadata(helper).and_then(|meta| meta.modified()) else {
        return false;
    };
    CACHE
        .get_or_init(|| Mutex::new(ProbeCache::default()))
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .file_caps(helper, mtime, || probe_reports_net_raw(helper))
}

/// Run `<helper> probe` as this user with a bounded wait and read the
/// `cap_net_raw` field of its one JSON line (plan P2.5). Anything short of
/// `true` is `false`: a helper that cannot run or answer has no file caps we
/// can rely on.
#[cfg(target_os = "linux")]
fn probe_reports_net_raw(helper: &Path) -> bool {
    use std::time::Instant;

    const PROBE_WAIT: Duration = Duration::from_secs(2);

    let Ok(mut child) = Command::new(helper)
        .arg("probe")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .env_clear()
        .spawn()
    else {
        return false;
    };
    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if started.elapsed() < PROBE_WAIT => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return false;
            }
            Err(_) => return false,
        }
    };
    if !status.success() {
        return false;
    }
    let mut stdout = Vec::new();
    if let Some(mut pipe) = child.stdout.take() {
        let _ = pipe.take(4096).read_to_end(&mut stdout);
    }
    serde_json::from_slice::<serde_json::Value>(&stdout)
        .ok()
        .and_then(|value| {
            value
                .get("cap_net_raw")
                .and_then(serde_json::Value::as_bool)
        })
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// The request (plan P1b.14): spawning the launcher, reading the child's end
// ---------------------------------------------------------------------------
//
// Everything that decides is pure and tested on every OS: the argv builders,
// the pre-spawn refusals in [`request_linux`], the §5.5 exit table in
// [`classify_exit`] and the watcher's step in [`watch_step`]. The one piece of
// I/O is [`StdSpawner`], which runs the argv it is given (never a shell) with
// stderr on a pipe drained into a bounded [`StderrTail`].

/// How a spawned child ended: an exit code, or death by a signal. The watcher
/// must tell `exit 127` from `killed by SIGINT` (spike S7), so the two are
/// distinct here; the real spawner reads `ExitStatus::code()` and
/// `ExitStatusExt::signal()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChildExit {
    /// `exit(n)`.
    Exited(i32),
    /// Killed by signal `n`.
    Signaled(i32),
}

/// `SIGINT`'s number on every Unix; Ctrl-C at the prompt (spec §5.5).
pub const SIGINT: i32 = 2;

/// One spawned process, as the watcher sees it. Nothing here blocks on the
/// child: `try_wait` polls, `kill` is best effort (a launcher running as
/// another user may refuse it), `stderr_tail` is a snapshot.
pub trait Child: Send {
    /// The pid the core spawned. pkexec execs the helper in place, so it is
    /// also the pid the socket's `SO_PEERCRED` must carry.
    fn id(&self) -> u32;
    /// `Some` once the child ended; `None` while it lives.
    fn try_wait(&mut self) -> io::Result<Option<ChildExit>>;
    /// Ask the child to die. Best effort, never waits.
    fn kill(&mut self);
    /// The last [`STDERR_TAIL_BYTES`] of the child's stderr so far.
    fn stderr_tail(&mut self) -> String;
}

/// Runs an argv. `argv[0]` is the program, absolute; no shell is involved.
pub trait Spawner: Send + Sync {
    /// Spawn `argv` and hand back the child.
    ///
    /// # Errors
    /// Whatever the OS says about the spawn.
    fn spawn(&self, argv: &[OsString]) -> io::Result<Box<dyn Child>>;
}

/// The SIGINT seam of spec §5.5 (S7, corrected in the p1b review log): while
/// a launcher child is alive, Ctrl-C must cancel the prompt without ending
/// the core, and `SIG_IGN` is never installed (it would be inherited across
/// `execve` and make the prompt un-cancellable).
///
/// The `aitm` binary already owns SIGINT through tokio's `ctrl_c`
/// (`shutdown_signal` in `crates/aitm/src/lib.rs`), so the signal never kills
/// the process by itself: what ends the run is the shutdown future. The hold
/// is therefore a count, [`HoldCount`], that the request raises for the
/// child's lifetime and the shutdown future consults: a Ctrl-C while held is
/// logged and the core keeps serving; the child, with the default disposition
/// restored across exec, dies of it and the watcher records `dismissed`. No
/// `unsafe`, no `sigaction`, no new crate (plan Rule 8 holds).
///
/// The trait has one operation, `hold`; nothing can install an ignore through
/// it. Tests count holds through the same type.
pub trait SignalGuard: Send + Sync {
    /// Take a hold for one child's lifetime; dropping the token releases it.
    fn hold(&self) -> Box<dyn Any + Send>;
}

/// The production [`SignalGuard`]: a shared count of live holds. Clones share
/// the counter, so the binary's shutdown future can hold one clone while the
/// privilege state holds another.
#[derive(Debug, Default, Clone)]
pub struct HoldCount(Arc<AtomicUsize>);

/// One hold on a [`HoldCount`]; dropping it releases the hold.
struct HoldToken(Arc<AtomicUsize>);

impl Drop for HoldToken {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

impl HoldCount {
    /// At least one hold is out: a prompt is up, Ctrl-C must not end the core.
    #[must_use]
    pub fn is_held(&self) -> bool {
        self.count() > 0
    }

    /// How many holds are out right now.
    #[must_use]
    pub fn count(&self) -> usize {
        self.0.load(Ordering::SeqCst)
    }
}

impl SignalGuard for HoldCount {
    fn hold(&self) -> Box<dyn Any + Send> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Box::new(HoldToken(Arc::clone(&self.0)))
    }
}

/// How much of the child's stderr is kept: the last 4 KiB (**Architect's
/// call**). The launcher's whole failure text fits many times over.
pub const STDERR_TAIL_BYTES: usize = 4096;

/// A bounded tail of bytes: `push` keeps the last [`STDERR_TAIL_BYTES`].
#[derive(Debug, Default, Clone)]
pub struct StderrTail {
    bytes: VecDeque<u8>,
}

impl StderrTail {
    /// An empty tail.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Append `chunk`, dropping the oldest bytes past the bound.
    pub fn push(&mut self, chunk: &[u8]) {
        let keep = chunk.len().min(STDERR_TAIL_BYTES);
        let tail = &chunk[chunk.len() - keep..];
        if keep == STDERR_TAIL_BYTES {
            self.bytes.clear();
        } else {
            let overflow = (self.bytes.len() + keep).saturating_sub(STDERR_TAIL_BYTES);
            self.bytes.drain(..overflow);
        }
        self.bytes.extend(tail);
    }

    /// Bytes held, at most [`STDERR_TAIL_BYTES`].
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Nothing held yet.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// The held bytes, oldest first.
    #[must_use]
    pub fn bytes(&self) -> Vec<u8> {
        self.bytes.iter().copied().collect()
    }

    /// The held bytes as text (lossy).
    #[must_use]
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.bytes()).into_owned()
    }
}

/// Copy `pipe` into `tail` until EOF or a read error. Runs on the drain
/// thread for as long as anything holds the pipe's write end: the helper
/// inherits the launcher's stderr and must never block on a full pipe.
pub fn drain_into(mut pipe: impl Read, tail: &Mutex<StderrTail>) {
    let mut buf = [0u8; 1024];
    loop {
        match pipe.read(&mut buf) {
            Ok(0) => return,
            Ok(n) => tail
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(&buf[..n]),
            Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return,
        }
    }
}

/// The only environment the child gets. pkexec itself needs nothing from the
/// core's environment: it talks to polkitd over the system bus and finds the
/// session's agent through logind, and the textual agent opens `/dev/tty`.
/// `DISPLAY`, `WAYLAND_DISPLAY` and `XAUTHORITY` are passed so a graphical
/// agent lookup sees the same session the core runs in. Deliberately absent:
/// `SHELL` (pkexec refuses a value not in `/etc/shells`), `LANG`/`LC_*` (the
/// C locale keeps the stderr texts [`classify_exit`] matches as spike S7
/// measured them), `PATH` (the program is absolute), and everything else.
pub const PASSED_ENV: [&str; 3] = ["DISPLAY", "WAYLAND_DISPLAY", "XAUTHORITY"];

/// The real spawner: `std::process::Command` over `argv[0]`, environment
/// cleared down to [`PASSED_ENV`], stdin and stdout inherited (the textual
/// agent prompts on the controlling terminal, not on stdio), stderr on a pipe
/// a drain thread copies into a bounded [`StderrTail`].
#[derive(Debug, Default, Clone, Copy)]
pub struct StdSpawner;

impl Spawner for StdSpawner {
    fn spawn(&self, argv: &[OsString]) -> io::Result<Box<dyn Child>> {
        let (program, args) = argv.split_first().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "an empty argv cannot be spawned",
            )
        })?;
        let mut command = Command::new(program);
        command
            .args(args)
            .env_clear()
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::piped());
        for key in PASSED_ENV {
            if let Some(value) = std::env::var_os(key) {
                command.env(key, value);
            }
        }
        let mut child = command.spawn()?;
        let tail = Arc::new(Mutex::new(StderrTail::new()));
        let done = Arc::new(DrainDone::default());
        if let Some(pipe) = child.stderr.take() {
            let tail = Arc::clone(&tail);
            let done = Arc::clone(&done);
            std::thread::Builder::new()
                .name("l4-helper-stderr".to_string())
                .spawn(move || {
                    drain_into(pipe, &tail);
                    done.finish();
                })?;
        } else {
            done.finish();
        }
        Ok(Box::new(StdChild {
            child,
            tail,
            done,
            exited: false,
        }))
    }
}

/// "The drain thread reached EOF": lets `stderr_tail` wait, bounded, for the
/// last bytes once the child has exited.
#[derive(Default)]
struct DrainDone {
    done: Mutex<bool>,
    changed: Condvar,
}

impl DrainDone {
    fn finish(&self) {
        *self.done.lock().unwrap_or_else(PoisonError::into_inner) = true;
        self.changed.notify_all();
    }

    fn wait(&self, timeout: Duration) {
        let guard = self.done.lock().unwrap_or_else(PoisonError::into_inner);
        let _ = self
            .changed
            .wait_timeout_while(guard, timeout, |done| !*done)
            .unwrap_or_else(PoisonError::into_inner);
    }
}

/// How long `stderr_tail` waits for the drain to reach EOF after the exit.
const DRAIN_SETTLE: Duration = Duration::from_millis(500);

struct StdChild {
    child: std::process::Child,
    tail: Arc<Mutex<StderrTail>>,
    done: Arc<DrainDone>,
    exited: bool,
}

impl Child for StdChild {
    fn id(&self) -> u32 {
        self.child.id()
    }

    fn try_wait(&mut self) -> io::Result<Option<ChildExit>> {
        let Some(status) = self.child.try_wait()? else {
            return Ok(None);
        };
        self.exited = true;
        Ok(Some(exit_of(status)))
    }

    fn kill(&mut self) {
        // A launcher running as another user refuses the signal (EPERM);
        // the watcher has already recorded the outcome, so nothing to report.
        let _ = self.child.kill();
    }

    fn stderr_tail(&mut self) -> String {
        if self.exited {
            self.done.wait(DRAIN_SETTLE);
        }
        self.tail
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .text()
    }
}

/// An `ExitStatus` as a [`ChildExit`]: the code when there is one, else the
/// signal (Unix).
fn exit_of(status: std::process::ExitStatus) -> ChildExit {
    if let Some(code) = status.code() {
        return ChildExit::Exited(code);
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(signal) = status.signal() {
            return ChildExit::Signaled(signal);
        }
    }
    ChildExit::Exited(-1)
}

/// The launcher's argv: `/usr/bin/pkexec <policy exec path> serve --connect
/// <socket>`. The program is the launcher's absolute path (no `PATH` lookup,
/// and [`PASSED_ENV`] carries none), and the helper path is the policy's
/// [`LINUX_HELPER_PATH`] literal: pkexec is never given a configured or
/// discovered path (AC17).
#[must_use]
pub fn pkexec_argv(socket: &Path) -> Vec<OsString> {
    vec![
        OsString::from(PKEXEC_PATH),
        OsString::from(LINUX_HELPER_PATH),
        OsString::from("serve"),
        OsString::from("--connect"),
        socket.as_os_str().to_os_string(),
    ]
}

/// The direct argv for a helper with file capabilities (the headless
/// fallback, spec §5.6): `<helper> serve --connect <socket>`, no launcher.
#[must_use]
pub fn direct_helper_argv(helper: &Path, socket: &Path) -> Vec<OsString> {
    vec![
        helper.as_os_str().to_os_string(),
        OsString::from("serve"),
        OsString::from("--connect"),
        socket.as_os_str().to_os_string(),
    ]
}

/// Progress and reply texts of the Linux request (spec §2.3, §2.4, §5.5).
pub mod msg {
    /// `cannot_prompt` from a one-shot process (spec §2.4).
    pub const ONE_SHOT: &str = "a one-shot command exits before the helper could serve it; set \
                                l4.privilege.request: at_start or use Allow in the TUI or web UI";
    /// `pending` with a display set.
    pub const PENDING_DIALOG: &str = "Waiting for administrator approval in the polkit dialog";
    /// `pending` without a display: the textual agent on the controlling tty.
    pub const PENDING_TERMINAL: &str =
        "Enter an administrator password in the terminal running aitm";
    /// `approved`: the helper connected and passed its checks.
    pub const APPROVED: &str = "Packet capture is available through the helper";
    /// `dismissed`: Cancel, Ctrl-D or Ctrl-C at the prompt.
    pub const CANCELLED: &str = "Approval was cancelled";
    /// `failed`: wrong password, or the caller is not an administrator.
    pub const AUTH_FAILED: &str =
        "Administrator authentication failed (wrong password or not authorized)";
    /// `failed`: the launcher found no agent after the predicate said it would.
    pub const NO_PROMPT_SHOWN: &str =
        "No password prompt could be shown here (no desktop session or terminal)";
    /// `failed`: nothing happened within [`super::APPROVAL_TIMEOUT_MS`].
    pub const TIMED_OUT: &str = "No approval within 5 minutes";
    /// `failed`: the helper connected but the state has no guard to build the
    /// backend over (the wiring seam; see `PrivilegeState::set_guard`).
    pub const NO_GUARD: &str = "no L4 guard attached to the privilege state";
    /// `cannot_prompt`: the spawn itself failed; the OS text follows.
    pub const SPAWN_FAILED: &str = "The packet-capture helper could not be started";
    /// `failed`: the listener kept failing `accept`; the socket error follows.
    pub const SOCKET_FAILED: &str = "The packet-capture helper socket failed";
}

/// Launcher stderr texts the §5.5 table keys on (spike S7, verbatim).
pub mod stderr_text {
    /// Exit 127: no controlling terminal for the textual agent.
    pub const NO_AGENT: &str = "Error creating textual authentication agent";
    /// Exit 127: Ctrl-D at the textual prompt.
    pub const EOF: &str = "Got unexpected EOF while reading from controlling terminal";
    /// Exit 127: wrong password, or not an administrator.
    pub const NOT_AUTHORIZED: &str = "Not authorized";
}

/// How long the watcher waits for approval before killing the child.
pub const APPROVAL_TIMEOUT_MS: u64 = 300_000;

/// A child the request spawned, with the SIGINT hold taken for its lifetime.
pub struct Spawned {
    /// The launcher (or the direct helper).
    pub child: Box<dyn Child>,
    /// Released when the child ends or connects.
    pub hold: Box<dyn Any + Send>,
}

impl std::fmt::Debug for Spawned {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Spawned")
            .field("pid", &self.child.id())
            .finish_non_exhaustive()
    }
}

/// What [`request_linux`] decided: the wire outcome and message, and the
/// child when one was spawned (`Pending` only).
#[derive(Debug)]
pub struct LinuxRequest {
    /// The wire `outcome`.
    pub outcome: Outcome,
    /// The operator's message; also the progress message for `Pending`.
    pub message: String,
    /// `Some` exactly when `outcome` is `Pending`.
    pub spawned: Option<Spawned>,
}

impl LinuxRequest {
    fn refuse(message: &str) -> Self {
        LinuxRequest {
            outcome: Outcome::CannotPrompt,
            message: message.to_string(),
            spawned: None,
        }
    }
}

/// The Linux half of `l4.privilege.request` (spec §2.3), up to the spawn.
/// In order: a one-shot process refuses (spec §2.4) and spawns nothing; no
/// prompt possible is `cannot_prompt` with the no-prompt text; a helper that
/// is not the root-owned policy exec path, a missing policy file or launcher
/// is `cannot_prompt` with the package label; otherwise a SIGINT hold is
/// taken and exactly [`pkexec_argv`]`(socket)` is spawned, answering
/// `Pending` with the dialog text when `display_set` (`DISPLAY` or
/// `WAYLAND_DISPLAY` non-empty) else the terminal text. `socket` is the
/// listener's absolute path, bound by the caller before this spawns.
pub fn request_linux(
    cfg: &PrivilegeConfig,
    inputs: &LinuxInputs,
    spawner: &dyn Spawner,
    signal: &dyn SignalGuard,
    socket: &Path,
    display_set: bool,
) -> LinuxRequest {
    if cfg.lifetime == ProcessLifetime::OneShot {
        return LinuxRequest::refuse(msg::ONE_SHOT);
    }
    let packaged = inputs
        .helper
        .as_ref()
        .is_some_and(|helper| helper.at_policy_path && helper.root_owned_chain)
        && inputs.policy_file_present
        && inputs.pkexec_present;
    if !packaged {
        return LinuxRequest::refuse(text::LINUX_INSTALL_LABEL);
    }
    if !inputs.prompt_possible {
        return LinuxRequest::refuse(text::LINUX_NO_PROMPT);
    }

    let hold = signal.hold();
    match spawner.spawn(&pkexec_argv(socket)) {
        Ok(child) => LinuxRequest {
            outcome: Outcome::Pending,
            message: if display_set {
                msg::PENDING_DIALOG.to_string()
            } else {
                msg::PENDING_TERMINAL.to_string()
            },
            spawned: Some(Spawned { child, hold }),
        },
        Err(err) => {
            drop(hold);
            LinuxRequest::refuse(&format!("{} ({err})", msg::SPAWN_FAILED))
        }
    }
}

/// Which §5.5 row ended the watch; what the watcher branches on (never the
/// message text).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitClass {
    /// Cancel, Ctrl-D or Ctrl-C at the prompt.
    Dismissed,
    /// Wrong password, or the caller is not an administrator.
    AuthFailed,
    /// The launcher found no authentication agent (the predicate and the
    /// launcher disagreed): the watcher also logs one `warn`.
    NoAgent,
    /// Nothing within [`APPROVAL_TIMEOUT_MS`]; the child was killed and must
    /// be reaped.
    TimedOut,
    /// Any other exit, signal, or a broken `try_wait`.
    Other,
}

/// The §5.5 exit table (S7), pure: how the launcher ended and its stderr
/// tail, to the row's class, the request's progress and the message. Exit
/// 126 is a graphical agent's Cancel; the textual agent never exits 126 and
/// tells its three endings apart only by text, checked in the order no-agent,
/// EOF, not authorized (the EOF text is followed by the same "Not authorized"
/// line).
#[must_use]
pub fn classify_exit_full(exit: ChildExit, stderr_tail: &str) -> (ExitClass, RequestState, String) {
    match exit {
        ChildExit::Exited(126) => (
            ExitClass::Dismissed,
            RequestState::Dismissed,
            msg::CANCELLED.to_string(),
        ),
        ChildExit::Exited(127) if stderr_tail.contains(stderr_text::NO_AGENT) => (
            ExitClass::NoAgent,
            RequestState::Failed,
            msg::NO_PROMPT_SHOWN.to_string(),
        ),
        ChildExit::Exited(127) if stderr_tail.contains(stderr_text::EOF) => (
            ExitClass::Dismissed,
            RequestState::Dismissed,
            msg::CANCELLED.to_string(),
        ),
        ChildExit::Exited(127) if stderr_tail.contains(stderr_text::NOT_AUTHORIZED) => (
            ExitClass::AuthFailed,
            RequestState::Failed,
            msg::AUTH_FAILED.to_string(),
        ),
        ChildExit::Signaled(SIGINT) => (
            ExitClass::Dismissed,
            RequestState::Dismissed,
            msg::CANCELLED.to_string(),
        ),
        ChildExit::Exited(code) => (
            ExitClass::Other,
            RequestState::Failed,
            format!("The packet-capture helper did not start (pkexec exit {code})"),
        ),
        ChildExit::Signaled(signal) => (
            ExitClass::Other,
            RequestState::Failed,
            format!("The packet-capture helper did not start (killed by signal {signal})"),
        ),
    }
}

/// [`classify_exit_full`] without the class: the progress and the message.
#[must_use]
pub fn classify_exit(exit: ChildExit, stderr_tail: &str) -> (RequestState, String) {
    let (_, state, message) = classify_exit_full(exit, stderr_tail);
    (state, message)
}

/// What one watcher step decided. A connected session is not a step outcome:
/// the watcher learns of it from its own `accept`, not from the child.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WatchOutcome {
    /// Nothing yet; step again.
    Waiting,
    /// The child ended (or was killed at the deadline); record this progress.
    Ended {
        /// Which row ended it; the watcher branches on this.
        reason: ExitClass,
        /// `Dismissed` or `Failed`.
        state: RequestState,
        /// The operator's message.
        message: String,
    },
}

/// One step of the watcher, pure over its inputs: a child that ended is
/// [`classify_exit_full`]ed over its stderr tail; else [`APPROVAL_TIMEOUT_MS`]
/// after `started_ms` on the injected clock the child is killed and the
/// request `failed` with the timeout text; else wait.
pub fn watch_step(child: &mut dyn Child, started_ms: u64, now_ms: u64) -> WatchOutcome {
    match child.try_wait() {
        Ok(Some(exit)) => {
            let tail = child.stderr_tail();
            let (reason, state, message) = classify_exit_full(exit, &tail);
            WatchOutcome::Ended {
                reason,
                state,
                message,
            }
        }
        Err(err) => WatchOutcome::Ended {
            reason: ExitClass::Other,
            state: RequestState::Failed,
            message: format!("The packet-capture helper did not start ({err})"),
        },
        Ok(None) if now_ms.saturating_sub(started_ms) >= APPROVAL_TIMEOUT_MS => {
            child.kill();
            WatchOutcome::Ended {
                reason: ExitClass::TimedOut,
                state: RequestState::Failed,
                message: msg::TIMED_OUT.to_string(),
            }
        }
        Ok(None) => WatchOutcome::Waiting,
    }
}

/// Scripted stand-ins for the request's seams, shared with `state`'s tests.
#[cfg(test)]
pub(crate) mod fakes {
    use std::ffi::OsString;
    use std::io;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use super::{Child, ChildExit, HoldCount, Spawner};

    /// A child that answers `try_wait` with `None` `ticks` times, then `exit`.
    pub(crate) struct FakeChild {
        pub(crate) pid: u32,
        pub(crate) ticks_left: u32,
        pub(crate) exit: Option<ChildExit>,
        pub(crate) stderr: String,
        pub(crate) killed: Arc<AtomicUsize>,
    }

    impl FakeChild {
        pub(crate) fn alive(pid: u32) -> Self {
            FakeChild {
                pid,
                ticks_left: 0,
                exit: None,
                stderr: String::new(),
                killed: Arc::new(AtomicUsize::new(0)),
            }
        }
    }

    impl Child for FakeChild {
        fn id(&self) -> u32 {
            self.pid
        }
        fn try_wait(&mut self) -> io::Result<Option<ChildExit>> {
            if self.ticks_left > 0 {
                self.ticks_left -= 1;
                return Ok(None);
            }
            Ok(self.exit)
        }
        fn kill(&mut self) {
            self.killed.fetch_add(1, Ordering::SeqCst);
        }
        fn stderr_tail(&mut self) -> String {
            self.stderr.clone()
        }
    }

    /// Records every argv it spawns and how many SIGINT holds were out at
    /// that moment (read off the production [`HoldCount`]).
    pub(crate) struct FakeSpawner {
        pub(crate) argvs: Mutex<Vec<Vec<OsString>>>,
        pub(crate) holds: HoldCount,
        pub(crate) holds_at_spawn: Mutex<Vec<usize>>,
    }

    impl FakeSpawner {
        pub(crate) fn new(holds: &HoldCount) -> Self {
            FakeSpawner {
                argvs: Mutex::new(Vec::new()),
                holds: holds.clone(),
                holds_at_spawn: Mutex::new(Vec::new()),
            }
        }
        pub(crate) fn argvs(&self) -> Vec<Vec<OsString>> {
            self.argvs.lock().unwrap().clone()
        }
    }

    impl Spawner for FakeSpawner {
        fn spawn(&self, argv: &[OsString]) -> io::Result<Box<dyn Child>> {
            self.argvs.lock().unwrap().push(argv.to_vec());
            self.holds_at_spawn.lock().unwrap().push(self.holds.count());
            Ok(Box::new(FakeChild::alive(4242)))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::*;

    #[test]
    fn parse_cap_eff_reads_the_hex_line() {
        assert_eq!(parse_cap_eff("CapEff:\t0000000000002000\n"), Some(0x2000));
        let status = "Name:\taitm\nCapInh:\t0000000000000000\nCapPrm:\t0000000000003000\nCapEff:\t0000000000003000\nCapBnd:\t000001ffffffffff\n";
        assert_eq!(parse_cap_eff(status), Some(0x3000));
        assert_eq!(parse_cap_eff("Name:\taitm\n"), None);
        assert_eq!(parse_cap_eff("CapEff:\tzz\n"), None);

        // The two bits derive cares about (P2.5 reads the same ones).
        assert!(has_cap(0x2000, CAP_NET_RAW));
        assert!(!has_cap(0x2000, CAP_NET_ADMIN));
        assert!(has_cap(0x1000, CAP_NET_ADMIN));
        assert!(!has_cap(0x1000, CAP_NET_RAW));
    }

    #[test]
    fn candidate_order_is_configured_exe_package_wrappers() {
        let order = candidates(Some(Path::new("/opt/x")), Path::new("/home/u/bin"));
        assert_eq!(
            order,
            vec![
                PathBuf::from("/opt/x"),
                PathBuf::from("/home/u/bin/aitm-l4-helper"),
                PathBuf::from("/usr/lib/aitmproxy/aitm-l4-helper"),
                PathBuf::from("/run/wrappers/bin/aitm-l4-helper"),
            ]
        );
        // Without a configured path the list is the three fixed places.
        let order = candidates(None, Path::new("/usr/bin"));
        assert_eq!(
            order,
            vec![
                PathBuf::from("/usr/bin/aitm-l4-helper"),
                PathBuf::from("/usr/lib/aitmproxy/aitm-l4-helper"),
                PathBuf::from("/run/wrappers/bin/aitm-l4-helper"),
            ]
        );
        // A configured path equal to a fixed place is probed once.
        let order = candidates(
            Some(Path::new("/usr/lib/aitmproxy/aitm-l4-helper")),
            Path::new("/usr/lib/aitmproxy"),
        );
        assert_eq!(
            order,
            vec![
                PathBuf::from("/usr/lib/aitmproxy/aitm-l4-helper"),
                PathBuf::from("/run/wrappers/bin/aitm-l4-helper"),
            ]
        );
    }

    fn root(mode: u32) -> PathMeta {
        PathMeta {
            uid: 0,
            mode,
            is_symlink: false,
        }
    }

    #[test]
    fn root_owned_chain_rejects_user_dirs_writable_bits_and_symlinks() {
        // The packaged path: / , /usr, /usr/lib, /usr/lib/aitmproxy, the helper.
        let packaged = [
            root(0o755),
            root(0o755),
            root(0o755),
            root(0o755),
            root(0o755),
        ];
        assert!(root_owned_chain(&packaged));
        // A 0750 root-owned helper (the headless layout) is still root-owned.
        assert!(root_owned_chain(&[root(0o755), root(0o755), root(0o750)]));

        // /home/u (uid 1000) in the chain.
        let home = [
            root(0o755),
            root(0o755),
            PathMeta {
                uid: 1000,
                mode: 0o755,
                is_symlink: false,
            },
            PathMeta {
                uid: 1000,
                mode: 0o755,
                is_symlink: false,
            },
        ];
        assert!(!root_owned_chain(&home));

        // Group-writable anywhere.
        assert!(!root_owned_chain(&[root(0o755), root(0o775), root(0o755)]));
        // World-writable anywhere (even sticky /tmp).
        assert!(!root_owned_chain(&[root(0o755), root(0o1777), root(0o755)]));
        // A symlink anywhere.
        assert!(!root_owned_chain(&[
            root(0o755),
            PathMeta {
                uid: 0,
                mode: 0o777,
                is_symlink: true,
            },
            root(0o755),
        ]));
        // Nothing inspected is not a root-owned chain.
        assert!(!root_owned_chain(&[]));
    }

    #[test]
    fn prompt_possible_three_rows() {
        assert!(!prompt_possible(None, None, false));
        assert!(prompt_possible(Some(":0"), None, false));
        assert!(prompt_possible(None, None, true));
        // Wayland alone is enough; an empty DISPLAY is unset.
        assert!(prompt_possible(None, Some("wayland-0"), false));
        assert!(!prompt_possible(Some(""), Some(""), false));
    }

    // ---- Task P1b.14: the request, pkexec's end, the watcher step ----

    use std::ffi::OsString;
    use std::io::Write;
    use std::os::unix::net::UnixStream;
    use std::sync::atomic::Ordering;
    use std::sync::{Arc, Mutex};

    use super::fakes::{FakeChild, FakeSpawner};
    use crate::config::L4PrivilegeConfig;
    use crate::privilege::derive::{HelperCandidate, LinuxInputs};
    use crate::privilege::report::RequestState;
    use crate::privilege::state::{Outcome, PrivilegeConfig, ProcessLifetime};

    const SOCKET: &str = "/run/user/1000/aitm/l4-helper-777.sock";

    /// The packaged install, complete, with a prompt possible (the pkexec row).
    fn packaged() -> LinuxInputs {
        LinuxInputs {
            cap_net_raw: false,
            cap_net_admin: false,
            session_connected: false,
            helper: Some(HelperCandidate {
                path: PathBuf::from(LINUX_HELPER_PATH),
                at_policy_path: true,
                root_owned_chain: true,
                file_caps_net_raw: false,
            }),
            policy_file_present: true,
            pkexec_present: true,
            prompt_possible: true,
            last_session_error: None,
        }
    }

    fn cfg(lifetime: ProcessLifetime, helper_path: Option<&str>) -> PrivilegeConfig {
        PrivilegeConfig {
            enabled: true,
            l4: L4PrivilegeConfig {
                helper_path: helper_path.map(PathBuf::from),
                ..L4PrivilegeConfig::default()
            },
            lifetime,
        }
    }

    fn os(parts: &[&str]) -> Vec<OsString> {
        parts.iter().map(OsString::from).collect()
    }

    #[test]
    fn one_shot_refuses_and_spawns_nothing() {
        let holds = HoldCount::default();
        let spawner = FakeSpawner::new(&holds);
        let req = request_linux(
            &cfg(ProcessLifetime::OneShot, None),
            &packaged(),
            &spawner,
            &holds,
            Path::new(SOCKET),
            true,
        );
        assert_eq!(req.outcome, Outcome::CannotPrompt);
        assert_eq!(
            req.message,
            "a one-shot command exits before the helper could serve it; set \
             l4.privilege.request: at_start or use Allow in the TUI or web UI"
        );
        assert!(req.spawned.is_none());
        assert!(spawner.argvs().is_empty(), "nothing is spawned");
        assert_eq!(holds.count(), 0, "no SIGINT hold without a child");
    }

    #[test]
    fn no_prompt_is_cannot_prompt_and_spawns_nothing() {
        let holds = HoldCount::default();
        let spawner = FakeSpawner::new(&holds);
        let guard = holds.clone();
        let serving = cfg(ProcessLifetime::Serving, None);

        let no_prompt = LinuxInputs {
            prompt_possible: false,
            ..packaged()
        };
        let req = request_linux(
            &serving,
            &no_prompt,
            &spawner,
            &guard,
            Path::new(SOCKET),
            false,
        );
        assert_eq!(req.outcome, Outcome::CannotPrompt);
        assert_eq!(
            req.message,
            "No password prompt can be shown here (no desktop session or terminal)"
        );
        assert!(req.spawned.is_none());

        // The package row: a helper found, but not root-owned (under $HOME).
        let home = LinuxInputs {
            helper: Some(HelperCandidate {
                path: PathBuf::from("/home/u/aitm-l4-helper"),
                at_policy_path: false,
                root_owned_chain: false,
                file_caps_net_raw: false,
            }),
            ..packaged()
        };
        let req = request_linux(&serving, &home, &spawner, &guard, Path::new(SOCKET), true);
        assert_eq!(req.outcome, Outcome::CannotPrompt);
        assert_eq!(
            req.message,
            "Install the aitm .deb or .rpm to get the packet-capture helper"
        );
        assert!(req.spawned.is_none());

        // No launcher, or no policy file: the same package row.
        let no_pkexec = LinuxInputs {
            pkexec_present: false,
            ..packaged()
        };
        let req = request_linux(
            &serving,
            &no_pkexec,
            &spawner,
            &guard,
            Path::new(SOCKET),
            true,
        );
        assert_eq!(req.outcome, Outcome::CannotPrompt);
        assert_eq!(
            req.message,
            "Install the aitm .deb or .rpm to get the packet-capture helper"
        );

        assert!(
            spawner.argvs().is_empty(),
            "nothing is spawned on any refusal"
        );
        assert_eq!(holds.count(), 0);
    }

    #[test]
    fn pkexec_argv_is_policy_path_only() {
        let holds = HoldCount::default();
        let spawner = FakeSpawner::new(&holds);
        let guard = holds.clone();
        // `l4.privilege.helper_path` points under $HOME; the request still runs
        // only the policy's exec path.
        let configured = cfg(ProcessLifetime::Serving, Some("/home/u/aitm-l4-helper"));

        let req = request_linux(
            &configured,
            &packaged(),
            &spawner,
            &guard,
            Path::new(SOCKET),
            true,
        );
        assert_eq!(req.outcome, Outcome::Pending);
        assert_eq!(
            req.message,
            "Waiting for administrator approval in the polkit dialog"
        );
        let spawned = req.spawned.expect("a child was spawned");
        assert_eq!(spawned.child.id(), 4242);

        let argvs = spawner.argvs();
        assert_eq!(
            argvs,
            vec![os(&[
                "/usr/bin/pkexec",
                "/usr/lib/aitmproxy/aitm-l4-helper",
                "serve",
                "--connect",
                SOCKET,
            ])]
        );
        for arg in argvs.iter().flatten() {
            assert!(
                !arg.to_string_lossy().contains("/home/u"),
                "the configured path never reaches pkexec: {arg:?}"
            );
        }
        assert_eq!(pkexec_argv(Path::new(SOCKET)), argvs[0]);

        // Without a display the message points at the terminal.
        let req = request_linux(
            &configured,
            &packaged(),
            &spawner,
            &guard,
            Path::new(SOCKET),
            false,
        );
        assert_eq!(req.outcome, Outcome::Pending);
        assert_eq!(
            req.message,
            "Enter an administrator password in the terminal running aitm"
        );
    }

    #[test]
    fn exit_126_is_dismissed() {
        assert_eq!(
            classify_exit(
                ChildExit::Exited(126),
                "Error executing command as another user: Request dismissed\n"
            ),
            (
                RequestState::Dismissed,
                "Approval was cancelled".to_string()
            )
        );
    }

    #[test]
    fn exit_127_not_authorized_is_failed() {
        let stderr = "polkit-agent-helper-1: pam_authenticate failed: Authentication failure\n\
                      ==== AUTHENTICATION FAILED ====\n\
                      Error executing command as another user: Not authorized\n";
        let (state, message) = classify_exit(ChildExit::Exited(127), stderr);
        assert_eq!(state, RequestState::Failed);
        assert_eq!(
            message,
            "Administrator authentication failed (wrong password or not authorized)"
        );
        assert!(message.contains("wrong password"));
    }

    #[test]
    fn exit_127_eof_is_dismissed() {
        let stderr = "==== AUTHENTICATING FOR com.mrbrutti.aitmproxy.l4-helper.run ====\n\
                      Authenticating as: root\n\
                      Password: \n\
                      polkit-agent-helper-1: Got unexpected EOF while reading from controlling terminal\n\
                      ==== AUTHENTICATION FAILED ====\n\
                      Error executing command as another user: Not authorized\n";
        assert_eq!(
            classify_exit(ChildExit::Exited(127), stderr),
            (
                RequestState::Dismissed,
                "Approval was cancelled".to_string()
            )
        );
    }

    #[test]
    fn no_agent_text_is_failed() {
        let stderr = "Error creating textual authentication agent: Error opening current \
                      controlling terminal for the process (`/dev/tty'): No such device or address\n";
        let (state, message) = classify_exit(ChildExit::Exited(127), stderr);
        assert_eq!(state, RequestState::Failed);
        assert_eq!(
            message,
            "No password prompt could be shown here (no desktop session or terminal)"
        );
        assert!(message.contains("No password prompt"));
    }

    #[test]
    fn sigint_is_dismissed() {
        assert_eq!(
            classify_exit(ChildExit::Signaled(SIGINT), ""),
            (
                RequestState::Dismissed,
                "Approval was cancelled".to_string()
            )
        );
        assert_eq!(SIGINT, 2);
    }

    #[test]
    fn other_exit_is_failed() {
        assert_eq!(
            classify_exit(ChildExit::Exited(2), "pkexec --version\n"),
            (
                RequestState::Failed,
                "The packet-capture helper did not start (pkexec exit 2)".to_string()
            )
        );
        // 127 with none of the known texts is the generic row too.
        assert_eq!(
            classify_exit(ChildExit::Exited(127), "something else entirely"),
            (
                RequestState::Failed,
                "The packet-capture helper did not start (pkexec exit 127)".to_string()
            )
        );
        assert_eq!(
            classify_exit(ChildExit::Signaled(9), ""),
            (
                RequestState::Failed,
                "The packet-capture helper did not start (killed by signal 9)".to_string()
            )
        );
    }

    #[test]
    fn timeout_is_failed_after_300s() {
        let mut child = FakeChild::alive(77);
        let killed = Arc::clone(&child.killed);
        let started = 10_000;

        // Still waiting one tick short of the deadline, nothing killed.
        assert_eq!(
            watch_step(&mut child, started, started + 299_999),
            WatchOutcome::Waiting
        );
        assert_eq!(killed.load(Ordering::SeqCst), 0);

        // At 300 s on the injected clock: kill and `failed`.
        assert_eq!(
            watch_step(&mut child, started, started + 300_000),
            WatchOutcome::Ended {
                reason: ExitClass::TimedOut,
                state: RequestState::Failed,
                message: "No approval within 5 minutes".to_string(),
            }
        );
        assert_eq!(killed.load(Ordering::SeqCst), 1);
        assert_eq!(APPROVAL_TIMEOUT_MS, 300_000);

        // A child that ended is classified, whatever the clock says.
        let mut child = FakeChild {
            exit: Some(ChildExit::Exited(126)),
            stderr: "Request dismissed".to_string(),
            ..FakeChild::alive(79)
        };
        assert_eq!(
            watch_step(&mut child, started, started + 1),
            WatchOutcome::Ended {
                reason: ExitClass::Dismissed,
                state: RequestState::Dismissed,
                message: "Approval was cancelled".to_string(),
            }
        );
    }

    #[test]
    fn file_caps_helper_spawns_directly() {
        let argv = direct_helper_argv(Path::new("/opt/aitm/aitm-l4-helper"), Path::new(SOCKET));
        assert_eq!(
            argv,
            os(&["/opt/aitm/aitm-l4-helper", "serve", "--connect", SOCKET])
        );
        assert_ne!(argv[0], OsString::from(PKEXEC_PATH));
        assert!(!argv
            .iter()
            .any(|arg| arg.to_string_lossy().contains("pkexec")));
    }

    /// Spec §5.5 as corrected (p1b review log, P1b.14 SIGINT): the guard is
    /// the production [`HoldCount`], not a fake. Its only operation is `hold`
    /// (nothing can install `SIG_IGN` through it); the spawn happens under
    /// exactly one hold, the token releases it, and the binary's shutdown
    /// future reads the same count through a clone.
    #[test]
    fn sigint_handler_installed_not_ignored() {
        let holds = HoldCount::default();
        let spawner = FakeSpawner::new(&holds);
        // What the binary's shutdown future would hold.
        let guard = holds.clone();
        assert!(!guard.is_held());

        let req = request_linux(
            &cfg(ProcessLifetime::Serving, None),
            &packaged(),
            &spawner,
            &guard,
            Path::new(SOCKET),
            true,
        );
        let spawned = req.spawned.expect("spawned");
        assert_eq!(holds.count(), 1, "one hold while the child lives");
        assert_eq!(
            *spawner.holds_at_spawn.lock().unwrap(),
            vec![1],
            "nothing is spawned without a hold"
        );

        assert!(guard.is_held(), "the shutdown future sees the hold");

        // The watcher drops the token when the child ends or connects; the
        // previous disposition is back.
        drop(spawned.hold);
        assert_eq!(holds.count(), 0);
        assert!(!guard.is_held());

        // The state's production guard is this type, by construction.
        let state =
            crate::privilege::state::PrivilegeState::new(&cfg(ProcessLifetime::Serving, None));
        let production: HoldCount = state.sigint_hold();
        assert!(!production.is_held());
    }

    #[test]
    fn stderr_pipe_is_drained_after_approval() {
        // The bounded buffer keeps exactly the last 4 KiB.
        let mut tail = StderrTail::new();
        tail.push(&[b'a'; 3000]);
        tail.push(&[b'b'; 3000]);
        assert_eq!(tail.len(), 4096);
        let text = tail.text();
        assert_eq!(text.len(), 4096);
        assert!(text.starts_with("aaaa"));
        assert!(text.ends_with("bbbb"));
        assert_eq!(text.matches('b').count(), 3000);
        assert_eq!(STDERR_TAIL_BYTES, 4096);

        // A child that keeps writing after approval: 64 KiB into the pipe never
        // blocks the writer, and the tail stays at 4 KiB.
        let (reader, mut writer) = UnixStream::pair().expect("pair");
        let shared = Arc::new(Mutex::new(StderrTail::new()));
        let drain = {
            let shared = Arc::clone(&shared);
            std::thread::spawn(move || drain_into(reader, &shared))
        };
        let mut expected_last = Vec::new();
        for round in 0..64u8 {
            let chunk = vec![round; 1024];
            writer.write_all(&chunk).expect("write");
            expected_last.extend_from_slice(&chunk);
        }
        drop(writer);
        drain.join().expect("drain thread");
        let tail = shared.lock().unwrap();
        assert_eq!(tail.len(), 4096);
        let last = &expected_last[expected_last.len() - 4096..];
        assert_eq!(tail.bytes(), last);
    }

    /// The real spawner on a real child: stderr lands in the tail, the exit
    /// code and the signal come back distinct (S7 needs both).
    #[test]
    fn std_spawner_reads_exit_code_signal_and_stderr() {
        let spawner = StdSpawner;
        let mut child = spawner
            .spawn(&os(&["/bin/sh", "-c", "echo not-a-prompt >&2; exit 126"]))
            .expect("spawn sh");
        assert!(child.id() > 0);
        let exit = wait_fake_free(child.as_mut());
        assert_eq!(exit, ChildExit::Exited(126));
        assert_eq!(child.stderr_tail(), "not-a-prompt\n");

        let mut child = spawner
            .spawn(&os(&["/bin/sh", "-c", "kill -INT $$"]))
            .expect("spawn sh");
        assert_eq!(wait_fake_free(child.as_mut()), ChildExit::Signaled(SIGINT));

        // The environment is cleared down to the display variables: SHELL and
        // PATH never reach the child.
        let mut child = spawner
            .spawn(&os(&[
                "/bin/sh",
                "-c",
                "env | grep -c '^SHELL=\\|^PATH=\\|^HOME=' >&2; exit 0",
            ]))
            .expect("spawn sh");
        assert_eq!(wait_fake_free(child.as_mut()), ChildExit::Exited(0));
        assert_eq!(child.stderr_tail().trim(), "0");
    }

    /// Plan P1b.14 `pkexec_env_is_cleared_but_for_display` (panel, 2026-11-01;
    /// spec §5.5 "How the launcher is spawned"): the child's environment is
    /// exactly the subset of [`PASSED_ENV`] set in the core; `SHELL`, `LANG`
    /// and `LC_ALL` never reach it. Through the real spawner on a real child:
    /// `/bin/sh` exists on macOS and Linux. The shell adds a few variables of
    /// its own under an empty environment (`PWD`, `SHLVL`, `_`, by shell), so
    /// the baseline is measured the same way under `env -i`, and what the
    /// spawner's child has beyond that baseline must be within `PASSED_ENV`.
    #[test]
    fn pkexec_env_is_cleared_but_for_display() {
        std::env::set_var("SHELL", "/bin/zsh");
        std::env::set_var("LANG", "en_US.UTF-8");
        std::env::set_var("LC_ALL", "C");
        std::env::set_var("DISPLAY", ":9");
        assert_eq!(
            std::env::var("LC_ALL").as_deref(),
            Ok("C"),
            "set in the core"
        );

        let keys_of = |env: &str| -> Vec<String> {
            env.lines()
                .filter(|line| !line.is_empty())
                .map(|line| line.split('=').next().unwrap_or(line).to_string())
                .collect()
        };
        let run = |argv: &[&str]| -> String {
            let mut child = StdSpawner.spawn(&os(argv)).expect("spawn");
            assert_eq!(wait_fake_free(child.as_mut()), ChildExit::Exited(0));
            child.stderr_tail()
        };

        // What the shell itself adds under an empty environment.
        let baseline = run(&["/usr/bin/env", "-i", "/bin/sh", "-c", "env >&2"]);
        let shell_own = keys_of(&baseline);
        assert!(
            !shell_own.iter().any(|k| k == "DISPLAY" || k == "SHELL"),
            "the baseline carries no display and no SHELL: {baseline:?}"
        );

        // The spawner's child, as pkexec would see it.
        let env = run(&["/bin/sh", "-c", "env >&2"]);
        let inherited: Vec<String> = keys_of(&env)
            .into_iter()
            .filter(|k| !shell_own.contains(k))
            .collect();
        // Keys only in the messages: a leaking spawner must not have this
        // test print the core's environment (proxy credentials live there).
        assert!(
            !inherited.is_empty() && inherited.iter().all(|k| PASSED_ENV.contains(&k.as_str())),
            "only DISPLAY, WAYLAND_DISPLAY and XAUTHORITY may be inherited; got {inherited:?}"
        );
        assert!(
            env.lines().any(|line| line == "DISPLAY=:9"),
            "DISPLAY is passed through verbatim; keys: {inherited:?}"
        );
        for absent in ["SHELL=", "LANG=", "LC_ALL=", "PATH=", "HOME="] {
            assert!(
                !env.lines().any(|line| line.starts_with(absent)),
                "{absent} reached the child"
            );
        }
    }

    fn wait_fake_free(child: &mut dyn Child) -> ChildExit {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
        loop {
            if let Some(exit) = child.try_wait().expect("try_wait") {
                // `stderr_tail` after an exit waits (bounded) for the drain
                // thread to land the last bytes; no sleep here.
                return exit;
            }
            assert!(std::time::Instant::now() < deadline, "child never ended");
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }
    // ---- tester (privilege unit p1b): oversized, hostile and failing inputs ---

    /// Tester: one chunk bigger than the bound keeps only its last 4 KiB; a
    /// later small chunk evicts the oldest bytes; bytes that are not UTF-8 (a
    /// launcher in another locale, or a binary-spewing helper) render lossily
    /// and never panic.
    #[test]
    fn stderr_tail_oversized_chunk_and_non_utf8() {
        let mut tail = StderrTail::new();
        assert!(tail.is_empty());
        assert_eq!(tail.text(), "");

        tail.push(&[b'a'; 10_000]);
        assert_eq!(tail.len(), STDERR_TAIL_BYTES);
        assert!(tail.bytes().iter().all(|b| *b == b'a'));

        tail.push(&[b'b'; 10]);
        assert_eq!(tail.len(), STDERR_TAIL_BYTES);
        let bytes = tail.bytes();
        assert!(bytes[..STDERR_TAIL_BYTES - 10].iter().all(|b| *b == b'a'));
        assert!(bytes[STDERR_TAIL_BYTES - 10..].iter().all(|b| *b == b'b'));

        tail.push(&[0xff, 0xfe, b'!']);
        let text = tail.text();
        assert!(text.ends_with("\u{FFFD}\u{FFFD}!"), "{text:?}");
        assert_eq!(text.chars().count(), STDERR_TAIL_BYTES);

        // Exactly the bound in one push replaces everything.
        tail.push(&[b'c'; STDERR_TAIL_BYTES]);
        assert_eq!(tail.len(), STDERR_TAIL_BYTES);
        assert!(tail.bytes().iter().all(|b| *b == b'c'));
    }

    /// Tester: the §5.5 table's precedence. Exit 126 is a Cancel whatever the
    /// text says; among the exit-127 texts the no-agent row wins, then EOF,
    /// then "Not authorized"; exit 0 before the helper connected is still a
    /// failure, not an approval; the key text is found inside 4 KiB of noise.
    #[test]
    fn classify_exit_precedence_and_exit_zero() {
        assert_eq!(
            classify_exit(ChildExit::Exited(126), "Not authorized").0,
            RequestState::Dismissed
        );
        let all_three = format!(
            "{}\n{}\n{}\n",
            stderr_text::NO_AGENT,
            stderr_text::EOF,
            stderr_text::NOT_AUTHORIZED
        );
        assert_eq!(
            classify_exit(ChildExit::Exited(127), &all_three),
            (RequestState::Failed, msg::NO_PROMPT_SHOWN.to_string())
        );
        let eof_and_auth = format!("{}\n{}\n", stderr_text::EOF, stderr_text::NOT_AUTHORIZED);
        assert_eq!(
            classify_exit(ChildExit::Exited(127), &eof_and_auth),
            (RequestState::Dismissed, msg::CANCELLED.to_string())
        );
        assert_eq!(
            classify_exit(ChildExit::Exited(127), "").0,
            RequestState::Failed
        );
        assert_eq!(
            classify_exit(ChildExit::Exited(0), ""),
            (
                RequestState::Failed,
                "The packet-capture helper did not start (pkexec exit 0)".to_string()
            )
        );
        let noisy = format!(
            "{}{}{}",
            "x".repeat(2000),
            stderr_text::NOT_AUTHORIZED,
            "y".repeat(2000)
        );
        assert_eq!(
            classify_exit(ChildExit::Exited(127), &noisy).1,
            msg::AUTH_FAILED
        );
    }

    /// Tester: when the launcher itself cannot be started (no `pkexec` binary,
    /// EPERM, ENOMEM), the request is `cannot_prompt` naming the OS error, the
    /// SIGINT hold taken for the spawn is released, and nothing is left running.
    #[test]
    fn spawn_failure_is_cannot_prompt_and_releases_the_hold() {
        struct Failing {
            holds: HoldCount,
            holds_at_spawn: Mutex<Vec<usize>>,
        }
        impl Spawner for Failing {
            fn spawn(&self, _argv: &[OsString]) -> std::io::Result<Box<dyn Child>> {
                self.holds_at_spawn.lock().unwrap().push(self.holds.count());
                Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "no pkexec here",
                ))
            }
        }

        let holds = HoldCount::default();
        let spawner = Failing {
            holds: holds.clone(),
            holds_at_spawn: Mutex::new(Vec::new()),
        };
        let req = request_linux(
            &cfg(ProcessLifetime::Serving, None),
            &packaged(),
            &spawner,
            &holds,
            Path::new(SOCKET),
            true,
        );
        assert_eq!(req.outcome, Outcome::CannotPrompt);
        assert_eq!(
            req.message,
            "The packet-capture helper could not be started (no pkexec here)"
        );
        assert!(req.spawned.is_none());
        assert_eq!(
            *spawner.holds_at_spawn.lock().unwrap(),
            vec![1],
            "the hold was taken for the spawn"
        );
        assert_eq!(holds.count(), 0, "and released when the spawn failed");
    }

    /// Tester: a `try_wait` error (the launcher was reaped by someone else, or
    /// `waitpid` failed) is a `failed` end naming the error, never a hang.
    #[test]
    fn watch_step_reports_a_try_wait_error_as_failed() {
        struct Broken;
        impl Child for Broken {
            fn id(&self) -> u32 {
                1
            }
            fn try_wait(&mut self) -> std::io::Result<Option<ChildExit>> {
                Err(std::io::Error::other("waitpid: ECHILD"))
            }
            fn kill(&mut self) {}
            fn stderr_tail(&mut self) -> String {
                String::new()
            }
        }
        let mut child = Broken;
        assert_eq!(
            watch_step(&mut child, 0, 1),
            WatchOutcome::Ended {
                reason: ExitClass::Other,
                state: RequestState::Failed,
                message: "The packet-capture helper did not start (waitpid: ECHILD)".to_string(),
            }
        );
    }

    /// Tester: a `/proc/self/status` the kernel did not write. An oversized,
    /// signed, empty or mis-labelled `CapEff` line yields no mask (and so no
    /// capability); whitespace around a good mask is tolerated; a capability
    /// number past the mask's width is never set.
    #[test]
    fn parse_cap_eff_rejects_oversized_signed_and_mislabelled_lines() {
        assert_eq!(parse_cap_eff("CapEff:\tffffffffffffffffff\n"), None);
        assert_eq!(parse_cap_eff("CapEff:\t-1\n"), None);
        assert_eq!(parse_cap_eff(""), None);
        assert_eq!(parse_cap_eff("XCapEff:\t0000000000002000\n"), None);
        assert_eq!(parse_cap_eff("CapEff:\t\n"), None);
        assert_eq!(
            parse_cap_eff("CapEff: 0000000000002000 \n"),
            Some(0x2000),
            "whitespace around the mask is tolerated"
        );
        assert_eq!(parse_cap_eff("CapEff:\tffffffffffffffff\n"), Some(u64::MAX));
        assert!(!has_cap(u64::MAX, 64));
        assert!(has_cap(u64::MAX, 63));
    }

    /// Tester: the real spawner refuses an empty argv before touching the OS,
    /// and reports a missing program as the OS does; neither leaves a child.
    #[test]
    fn std_spawner_refuses_empty_argv_and_missing_program() {
        let err = StdSpawner.spawn(&[]).err().expect("empty argv");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        let err = StdSpawner
            .spawn(&os(&["/nonexistent/aitm-tester-no-such-launcher", "serve"]))
            .err()
            .expect("missing program");
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
    }

    // ---- fix task 2026-11-01: I2 (the production SIGINT hold) ----

    /// The production `SignalGuard` is a hold count the binary's shutdown
    /// future consults: `hold` increments, the token's drop decrements, a
    /// clone shares the counter, `is_held` is "any token out".
    #[test]
    fn hold_count_tokens_increment_and_decrement_on_drop() {
        let hold = HoldCount::default();
        assert!(!hold.is_held());
        assert_eq!(hold.count(), 0);

        let a = hold.hold();
        assert!(hold.is_held());
        assert_eq!(hold.count(), 1);
        let b = hold.hold();
        assert_eq!(hold.count(), 2);

        let shared = hold.clone();
        assert!(shared.is_held());
        drop(a);
        assert_eq!(shared.count(), 1);
        assert!(hold.is_held());
        drop(b);
        assert_eq!(hold.count(), 0);
        assert!(!hold.is_held());
        assert!(!shared.is_held());
    }

    // ---- fix task 2026-11-01: S2 (the file-caps probe is cached per path+mtime) ----

    /// The helper's `probe` is a subprocess; it runs once per `(path, mtime)`
    /// and again only when the file changed, not on every 1 s re-probe.
    #[test]
    fn file_caps_probe_runs_once_per_path_and_mtime() {
        use std::time::{Duration, UNIX_EPOCH};

        let mut cache = ProbeCache::default();
        let runs = std::cell::Cell::new(0);
        let runs = &runs;
        let probe = |answer: bool| {
            move || {
                runs.set(runs.get() + 1);
                answer
            }
        };
        let helper = Path::new("/usr/lib/aitmproxy/aitm-l4-helper");
        let t1 = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let t2 = t1 + Duration::from_secs(60);

        assert!(cache.file_caps(helper, t1, probe(true)));
        assert!(
            cache.file_caps(helper, t1, probe(false)),
            "cached: the probe did not run"
        );
        assert_eq!(runs.get(), 1);

        // The file changed: probed again, and the new answer is kept.
        assert!(!cache.file_caps(helper, t2, probe(false)));
        assert_eq!(runs.get(), 2);
        assert!(!cache.file_caps(helper, t2, probe(true)));
        assert_eq!(runs.get(), 2);

        // Another path is its own entry.
        assert!(cache.file_caps(
            Path::new("/run/wrappers/bin/aitm-l4-helper"),
            t1,
            probe(true)
        ));
        assert_eq!(runs.get(), 3);
    }

    // ---- fix task 2026-11-01: Q2 (the exit class is an enum, not a text) ----

    /// The watcher decides on `ExitClass`, never by comparing message text.
    /// Every §5.5 row maps to one class; the timeout and a broken `try_wait`
    /// have theirs.
    #[test]
    fn exit_class_is_pinned_for_every_row() {
        let class = |exit, tail: &str| classify_exit_full(exit, tail).0;
        assert_eq!(class(ChildExit::Exited(126), ""), ExitClass::Dismissed);
        assert_eq!(
            class(ChildExit::Exited(127), stderr_text::NO_AGENT),
            ExitClass::NoAgent
        );
        assert_eq!(
            class(ChildExit::Exited(127), stderr_text::EOF),
            ExitClass::Dismissed
        );
        assert_eq!(
            class(ChildExit::Exited(127), stderr_text::NOT_AUTHORIZED),
            ExitClass::AuthFailed
        );
        assert_eq!(class(ChildExit::Signaled(SIGINT), ""), ExitClass::Dismissed);
        assert_eq!(class(ChildExit::Exited(1), ""), ExitClass::Other);
        assert_eq!(class(ChildExit::Exited(127), ""), ExitClass::Other);
        assert_eq!(class(ChildExit::Signaled(9), ""), ExitClass::Other);

        // The full form agrees with the pair form on state and message.
        let (reason, state, message) =
            classify_exit_full(ChildExit::Exited(127), stderr_text::NO_AGENT);
        assert_eq!(reason, ExitClass::NoAgent);
        assert_eq!(
            (state, message),
            classify_exit(ChildExit::Exited(127), stderr_text::NO_AGENT)
        );

        // Timed out and a broken child carry their classes through watch_step.
        let mut child = FakeChild::alive(77);
        assert_eq!(
            watch_step(&mut child, 0, APPROVAL_TIMEOUT_MS),
            WatchOutcome::Ended {
                reason: ExitClass::TimedOut,
                state: RequestState::Failed,
                message: "No approval within 5 minutes".to_string(),
            }
        );
        struct Broken;
        impl Child for Broken {
            fn id(&self) -> u32 {
                1
            }
            fn try_wait(&mut self) -> std::io::Result<Option<ChildExit>> {
                Err(std::io::Error::other("waitpid: ECHILD"))
            }
            fn kill(&mut self) {}
            fn stderr_tail(&mut self) -> String {
                String::new()
            }
        }
        match watch_step(&mut Broken, 0, 1) {
            WatchOutcome::Ended { reason, state, .. } => {
                assert_eq!(reason, ExitClass::Other);
                assert_eq!(state, RequestState::Failed);
            }
            other => panic!("expected Ended, got {other:?}"),
        }
    }
}
