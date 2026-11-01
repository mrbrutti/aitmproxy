//! The out-of-process watchdog that restores the system proxy when the core
//! dies without an orderly exit (spec §D9 (b)).
//!
//! The core spawns its own executable as `aitm sysproxy-watchdog --pid <core
//! pid> --state <state file>` with stdin piped from the core, which keeps
//! the write end open and never writes: the kernel closes that pipe on any
//! death of the core, so [`run`] wakes on stdin EOF with no polling and no
//! FFI. `--no-pipe` (tests) polls the pid once a second instead.
//! On wake it re-reads the state file and applies the §D6 unset rule:
//! restore the services that still equal `wrote`, leave the rest, remove
//! the file. The decision is [`decide`], a pure function; the restore goes
//! through the mechanism's [`PlatformOps`] with a fresh `RealExecutor`.
//!
//! One line per decision is appended to `system-proxy-watchdog.log` beside
//! the state file, truncated when the watchdog starts (plan C8):
//! `<rfc3339> <decision> services=<n> ms=<n>`.

use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use aitm_ca::exec::{CmdLine, Executor, RealExecutor};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::platform::{ops_for, PlatformOps};
use crate::state::StateFile;
use crate::{service_equals_wrote, Mechanism, ServiceRow, WATCHDOG_LOG_NAME};

/// The restore could not be completed; the state file is left for the
/// next-start recovery (§D9 (c)).
pub const EXIT_RESTORE_FAILED: i32 = 3;
/// Bad arguments (returned by the binary's parser, Task 10).
pub const EXIT_BAD_ARGS: i32 = 2;

/// How often `--no-pipe` asks whether the core is still alive.
const POLL_INTERVAL: Duration = Duration::from_secs(1);
/// The watchdog's executor timeouts: reads 10 s, the restore 30 s.
const QUERY_TIMEOUT: Duration = Duration::from_secs(10);
const MUTATE_TIMEOUT: Duration = Duration::from_secs(30);

/// What the watchdog does once it has woken (SP-AC13).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// No state file: an orderly unset beat us.
    Exit0,
    /// Restore `only` (the services still equal to `wrote`), leave
    /// `left_alone` (taken over by another tool since), remove the file.
    Restore {
        only: Vec<String>,
        left_alone: Vec<String>,
    },
}

/// The pure §D6 unset rule over the state file and a live read: each of the
/// file's `service_names()` is restored when its live row still equals
/// `wrote` (C3, `service_equals_wrote`); a name absent from `live` counts
/// as not equal. This is the rule the woken watchdog runs
/// ([`run_after_wake`]); `Exit0` is reached only through `decide(None, ..)`,
/// which is [`wake`]'s "no file: an orderly unset beat us" arm.
pub fn decide(file: Option<&StateFile>, live: &[ServiceRow]) -> Decision {
    let Some(file) = file else {
        return Decision::Exit0;
    };
    let (only, left_alone) = partition(file, live);
    Decision::Restore { only, left_alone }
}

/// [`decide`] for a file that is present: the services to restore and the
/// ones to leave alone. The engine's `unset`, `recover_at_startup` and
/// `managed_by_us` use this directly.
pub(crate) fn partition(file: &StateFile, live: &[ServiceRow]) -> (Vec<String>, Vec<String>) {
    file.service_names().into_iter().partition(|name| {
        live.iter()
            .any(|row| &row.service == name && service_equals_wrote(row, &file.wrote))
    })
}

/// The parsed `aitm sysproxy-watchdog` arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatchdogArgs {
    /// The core's pid (polled only with `no_pipe`).
    pub pid: u32,
    /// The state file; the log is written beside it.
    pub state: PathBuf,
    /// Poll the pid instead of waiting for stdin EOF.
    pub no_pipe: bool,
}

/// The core's side of a spawned watchdog. Holding `stdin` open is what
/// keeps the watchdog asleep; dropping the handle closes the pipe, and the
/// watchdog then sees the file (gone or present) and acts, while the child
/// is reaped off the core's thread ([`reap`]). Both fields are `Some` until
/// the drop takes them.
#[derive(Debug)]
pub struct WatchdogHandle {
    child: Option<Child>,
    stdin: Option<ChildStdin>,
}

impl WatchdogHandle {
    /// The watchdog's pid, for `Status::watchdog_pid`.
    pub fn pid(&self) -> u32 {
        self.child.as_ref().map_or(0, Child::id)
    }

    /// Still running (not exited, not yet reaped).
    pub fn is_alive(&mut self) -> bool {
        self.child
            .as_mut()
            .is_some_and(|child| matches!(child.try_wait(), Ok(None)))
    }
}

impl Drop for WatchdogHandle {
    fn drop(&mut self) {
        // Close our end of the pipe first: that is what wakes the watchdog,
        // and a reaper waiting on a watchdog that is still asleep would
        // never return.
        drop(self.stdin.take());
        if let Some(child) = self.child.take() {
            match reap(child) {
                Reaped::Now(status) => {
                    tracing::debug!(target: "aitm_sysproxy", %status, "watchdog had exited; reaped");
                }
                // Detach: the thread finishes when the watchdog does.
                Reaped::Deferred(thread) => drop(thread),
                Reaped::Dropped(e) => {
                    tracing::debug!(target: "aitm_sysproxy", error = %e, "watchdog child left for the OS to collect");
                }
            }
        }
    }
}

/// How [`reap`] disposed of a child.
#[derive(Debug)]
pub(crate) enum Reaped {
    /// Already exited: reaped on the spot.
    Now(ExitStatus),
    /// Still running: a detached thread owns the child and `wait`s on it.
    /// Dropping the handle detaches the thread.
    Deferred(thread::JoinHandle<io::Result<ExitStatus>>),
    /// No thread could be started; the child is dropped unreaped and the
    /// OS collects it when this process exits.
    Dropped(io::Error),
}

/// Reap `child` without blocking the caller: `try_wait` first, else `wait`
/// on a detached thread that owns the child. The core never waits for the
/// watchdog's restore, and no watchdog is left a zombie until the core
/// exits.
pub(crate) fn reap(mut child: Child) -> Reaped {
    if let Ok(Some(status)) = child.try_wait() {
        return Reaped::Now(status);
    }
    match thread::Builder::new()
        .name("sysproxy-watchdog-reaper".to_string())
        .spawn(move || child.wait())
    {
        Ok(handle) => Reaped::Deferred(handle),
        Err(e) => Reaped::Dropped(e),
    }
}

/// Spawn `exe sysproxy-watchdog --pid <core_pid> --state <state>` in its own
/// process group, stdout and stderr to null, stdin piped and never written.
pub fn spawn(exe: &Path, core_pid: u32, state: &Path) -> io::Result<WatchdogHandle> {
    let mut command = Command::new(exe);
    command
        .arg("sysproxy-watchdog")
        .arg("--pid")
        .arg(core_pid.to_string())
        .arg("--state")
        .arg(state)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(unix)]
    {
        // A terminal's SIGINT goes to the core's process group; the watchdog
        // must outlive that to restore.
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    let mut child = command.spawn()?;
    let stdin = child
        .stdin
        .take()
        .ok_or_else(|| io::Error::other("watchdog stdin was not piped"))?;
    Ok(WatchdogHandle {
        child: Some(child),
        stdin: Some(stdin),
    })
}

/// The watchdog process body: wait for the core to die, then decide and
/// restore. Returns the exit code: `0` (file gone, or restored), `3` (the
/// restore failed; the file is kept). Never prints.
pub fn run(args: &WatchdogArgs) -> i32 {
    let mut log = open_log(&args.state);
    let exec = RealExecutor::with_timeouts(QUERY_TIMEOUT, MUTATE_TIMEOUT);
    wait_for_death(args, &exec);
    wake(&args.state, &exec, &ops_for, &mut log)
}

/// The wake: load the file once, pick the ops its `mechanism` names, and
/// run the restore rule. No file (or a quarantined one) is `file-gone`,
/// exit 0; a corrupt file that could not be moved aside has nothing to
/// restore from and nothing a later start can do either, so it is
/// `restore-failed`, exit 3. Separated from [`run`] so the path is
/// unit-tested with scripted ops.
pub(crate) fn wake(
    state: &Path,
    exec: &dyn Executor,
    ops_for: &dyn Fn(Mechanism) -> Box<dyn PlatformOps>,
    log: &mut Option<File>,
) -> i32 {
    let started = Instant::now();
    match StateFile::load(state) {
        Ok(Some(file)) => {
            let ops = ops_for(file.mechanism);
            run_after_wake(state, &file, exec, ops.as_ref(), log)
        }
        Ok(None) => {
            log_line(log, "file-gone", 0, started);
            0
        }
        Err(_) => {
            log_line(log, "restore-failed", 0, started);
            EXIT_RESTORE_FAILED
        }
    }
}

/// Block until the core is gone: stdin EOF, or (with `no_pipe`) the pid no
/// longer answers the liveness probe.
fn wait_for_death(args: &WatchdogArgs, exec: &dyn Executor) {
    if args.no_pipe {
        while is_alive(args.pid, exec) {
            thread::sleep(POLL_INTERVAL);
        }
        return;
    }
    let mut stdin = io::stdin().lock();
    let mut buf = [0u8; 64];
    loop {
        match stdin.read(&mut buf) {
            Ok(0) => return,
            Ok(_) => continue,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            // A closed or unreadable stdin is as good as EOF.
            Err(_) => return,
        }
    }
}

/// The restore rule over a loaded `file`: read the live services through
/// `ops`, [`decide`], restore, remove the file, log. One C8 line per
/// decision: `restored` for the services put back, `left-alone` for the
/// rest, and `left-alone services=0` when there was nothing to put back
/// at all (a file naming no service), so every wake leaves a line.
pub(crate) fn run_after_wake(
    state: &Path,
    file: &StateFile,
    exec: &dyn Executor,
    ops: &dyn PlatformOps,
    log: &mut Option<File>,
) -> i32 {
    let started = Instant::now();
    let live = match ops.read_services(exec) {
        Ok(live) => live,
        Err(_) => {
            // Nothing can be judged against `wrote`; leave the file for (c).
            log_line(log, "restore-failed", file.service_names().len(), started);
            return EXIT_RESTORE_FAILED;
        }
    };
    // A present file always decides `Restore`; `Exit0` is `decide(None, ..)`
    // alone (see [`decide`]), and it would mean nothing to restore and
    // nothing to remove, which is exit 0 here too.
    let Decision::Restore { only, left_alone } = decide(Some(file), &live) else {
        return 0;
    };
    if !only.is_empty() {
        if ops.restore(exec, &file.previous, &only).is_err() {
            log_line(log, "restore-failed", only.len(), started);
            return EXIT_RESTORE_FAILED;
        }
        log_line(log, "restored", only.len(), started);
    }
    if only.is_empty() || !left_alone.is_empty() {
        log_line(log, "left-alone", left_alone.len(), started);
    }
    if StateFile::remove(state).is_err() {
        // Restored, but the file stays: the next start will find the live
        // rows no longer equal `wrote` and forget it (§D9 (c), last row).
        return EXIT_RESTORE_FAILED;
    }
    0
}

/// Is the core still running? macOS asks `/bin/ps -p <pid> -o pid=` (a
/// non-empty answer means yes, anything else, a `ps` that could not run
/// included, means no); Linux checks `/proc/<pid>`; any other OS answers
/// `false`. Only the test-only `--no-pipe` path asks; production liveness
/// is the stdin pipe.
pub fn is_alive(pid: u32, exec: &dyn Executor) -> bool {
    is_alive_on(std::env::consts::OS, pid, exec)
}

/// [`is_alive`] for a named OS word (`std::env::consts::OS` spelling).
pub(crate) fn is_alive_on(os: &str, pid: u32, exec: &dyn Executor) -> bool {
    match os {
        "macos" => {
            let cmd = CmdLine {
                program: "/bin/ps".to_string(),
                args: vec!["-p".into(), pid.to_string(), "-o".into(), "pid=".into()],
                stdin: None,
                mutating: false,
            };
            exec.run(&cmd)
                .map(|out| !out.stdout.trim().is_empty())
                .unwrap_or(false)
        }
        "linux" => exec.dir_exists(Path::new(&format!("/proc/{pid}"))),
        _ => false,
    }
}

/// Create the log fresh beside the state file. "Truncate" is remove, then
/// `create_new` (`O_EXCL`, which never follows a symlink), so a link
/// planted at the log name never gets another file truncated through it.
/// `None` when it cannot be opened: the watchdog still restores, it just
/// cannot say so.
pub(crate) fn open_log(state: &Path) -> Option<File> {
    let path = state.with_file_name(WATCHDOG_LOG_NAME);
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        let _ = fs::create_dir_all(parent);
    }
    match fs::remove_file(&path) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(_) => return None,
    }
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .ok()
}

/// Append one C8 line: `<rfc3339> <decision> services=<n> ms=<n>`.
fn log_line(log: &mut Option<File>, decision: &str, services: usize, started: Instant) {
    let Some(file) = log.as_mut() else {
        return;
    };
    let ms = started.elapsed().as_millis();
    let _ = writeln!(
        file,
        "{} {decision} services={services} ms={ms}",
        now_rfc3339()
    );
    let _ = file.flush();
}

/// Now, UTC, RFC 3339 at whole seconds (the state file's `saved_at` form).
fn now_rfc3339() -> String {
    let now = OffsetDateTime::now_utc();
    now.replace_nanosecond(0)
        .unwrap_or(now)
        .format(&Rfc3339)
        .unwrap_or_else(|_| now.unix_timestamp().to_string())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;
    use std::time::{SystemTime, UNIX_EPOCH};

    use std::io::Read;
    use std::process::{Command, Stdio};
    use std::thread;
    use std::time::{Duration, Instant};

    use aitm_ca::exec::{Executor, RealExecutor};
    use aitm_ca::testing::ScriptedExecutor;
    use time::format_description::well_known::Rfc3339;
    use time::OffsetDateTime;

    use super::*;
    use crate::platform::{PlatformOps, Snapshot};
    use crate::state::{Previous, StateFile};
    use crate::{
        Effective, Endpoint, Mechanism, ProtocolProxy, ReadError, ServiceRow, WriteError, Wrote,
        STATE_FILE_NAME, WATCHDOG_LOG_NAME,
    };

    fn temp_dir(tag: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after 1970")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("aitm-sysproxy-watchdog-{tag}-{nanos}"));
        fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    fn proxy(host: &str, port: u16) -> ProtocolProxy {
        ProtocolProxy {
            enabled: port != 0,
            host: host.to_string(),
            port,
        }
    }

    fn row(service: &str, host: &str, port: u16) -> ServiceRow {
        ServiceRow {
            service: service.to_string(),
            http: proxy(host, port),
            https: proxy(host, port),
            bypass: vec!["*.local".into(), "169.254/16".into()],
        }
    }

    fn wrote() -> Wrote {
        Wrote {
            host: "127.0.0.1".into(),
            port: 8080,
            bypass: vec!["*.local".into(), "169.254/16".into(), "localhost".into()],
        }
    }

    /// The §D7 document's shape: two macOS services, `Display Ethernet` first.
    fn two_service_file() -> StateFile {
        StateFile::new(
            Mechanism::Networksetup,
            48213,
            wrote(),
            Previous::Networksetup {
                services: vec![
                    row("Display Ethernet", "127.0.0.1", 9090),
                    row("Wi-Fi", "", 0),
                ],
            },
        )
    }

    fn live_equal() -> Vec<ServiceRow> {
        vec![
            row("Display Ethernet", "127.0.0.1", 8080),
            row("Wi-Fi", "127.0.0.1", 8080),
        ]
    }

    fn log_lines(state: &Path) -> Vec<String> {
        let log = state.with_file_name(WATCHDOG_LOG_NAME);
        fs::read_to_string(&log)
            .unwrap_or_else(|e| panic!("read {}: {e}", log.display()))
            .lines()
            .map(str::to_string)
            .collect()
    }

    /// C8: `<rfc3339> <decision> services=<n> ms=<n>`.
    fn assert_c8_line(line: &str, decision: &str, services: usize) {
        let words: Vec<&str> = line.split(' ').collect();
        assert_eq!(words.len(), 4, "four space-separated words: {line:?}");
        OffsetDateTime::parse(words[0], &Rfc3339)
            .unwrap_or_else(|e| panic!("{:?} is RFC 3339 ({e}) in {line:?}", words[0]));
        assert_eq!(words[1], decision, "decision word in {line:?}");
        assert_eq!(words[2], format!("services={services}"), "in {line:?}");
        let ms = words[3]
            .strip_prefix("ms=")
            .unwrap_or_else(|| panic!("`ms=` word in {line:?}"));
        ms.parse::<u64>()
            .unwrap_or_else(|e| panic!("ms is an integer ({e}) in {line:?}"));
    }

    /// SP-AC13: the pure decision table.
    #[test]
    fn decide_table() {
        assert_eq!(decide(None, &[]), Decision::Exit0);
        assert_eq!(decide(None, &live_equal()), Decision::Exit0);

        let file = two_service_file();
        assert_eq!(
            decide(Some(&file), &live_equal()),
            Decision::Restore {
                only: vec!["Display Ethernet".to_string(), "Wi-Fi".to_string()],
                left_alone: vec![],
            }
        );

        let one_taken = vec![
            row("Display Ethernet", "10.0.0.5", 3128),
            row("Wi-Fi", "127.0.0.1", 8080),
        ];
        assert_eq!(
            decide(Some(&file), &one_taken),
            Decision::Restore {
                only: vec!["Wi-Fi".to_string()],
                left_alone: vec!["Display Ethernet".to_string()],
            }
        );

        // A service the live read no longer lists counts as not equal.
        let wifi_only = vec![row("Wi-Fi", "127.0.0.1", 8080)];
        assert_eq!(
            decide(Some(&file), &wifi_only),
            Decision::Restore {
                only: vec!["Wi-Fi".to_string()],
                left_alone: vec!["Display Ethernet".to_string()],
            }
        );

        // C3: the bypass list is not compared.
        let mut bypass_changed = live_equal();
        bypass_changed[0].bypass = vec!["corp.test".into()];
        assert_eq!(
            decide(Some(&file), &bypass_changed),
            Decision::Restore {
                only: vec!["Display Ethernet".to_string(), "Wi-Fi".to_string()],
                left_alone: vec![],
            }
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn is_alive_uses_ps_on_macos() {
        let alive = ScriptedExecutor::new().respond("/bin/ps -p 4242 -o pid=", 0, "4242\n", "");
        assert!(is_alive(4242, &alive));
        assert_eq!(alive.runs(), vec!["/bin/ps -p 4242 -o pid=".to_string()]);

        let dead = ScriptedExecutor::new().respond("/bin/ps -p 4242 -o pid=", 1, "", "");
        assert!(!is_alive(4242, &dead));
        assert_eq!(dead.runs(), vec!["/bin/ps -p 4242 -o pid=".to_string()]);
    }

    /// The per-OS table behind `is_alive`, runnable on any host.
    #[test]
    fn is_alive_on_each_os() {
        let ps_alive = ScriptedExecutor::new().respond("/bin/ps -p 4242 -o pid=", 0, "4242\n", "");
        assert!(is_alive_on("macos", 4242, &ps_alive));
        let ps_dead = ScriptedExecutor::new().respond("/bin/ps -p 4242 -o pid=", 1, "", "");
        assert!(!is_alive_on("macos", 4242, &ps_dead));
        // Whitespace-only stdout is "no such process".
        let ps_blank = ScriptedExecutor::new().respond("/bin/ps -p 4242 -o pid=", 0, "\n", "");
        assert!(!is_alive_on("macos", 4242, &ps_blank));
        // A `ps` that cannot be started (the Bash sandbox refuses it) is not
        // "alive" either: the poll must end.
        assert!(!is_alive_on("macos", 4242, &FailingExec));

        let proc_alive = ScriptedExecutor::new().dir("/proc/4242");
        assert!(is_alive_on("linux", 4242, &proc_alive));
        assert!(proc_alive.runs().is_empty(), "Linux runs no command");
        let proc_dead = ScriptedExecutor::new();
        assert!(!is_alive_on("linux", 4242, &proc_dead));

        let other = ScriptedExecutor::new().dir("/proc/4242");
        assert!(!is_alive_on("windows", 4242, &other));
        assert!(other.runs().is_empty());
    }

    /// `--no-pipe` polls the pid; a dead pid and no file → `file-gone`, exit 0.
    #[test]
    fn no_pipe_run_restores_when_the_pid_is_dead_and_the_file_is_gone_exit_0() {
        let mut child = std::process::Command::new("/usr/bin/true")
            .spawn()
            .expect("spawn /usr/bin/true");
        let pid = child.id();
        assert!(child.wait().expect("wait").success());

        let dir = temp_dir("no-pipe");
        let state = dir.join(STATE_FILE_NAME);
        let args = WatchdogArgs {
            pid,
            state: state.clone(),
            no_pipe: true,
        };
        assert_eq!(run(&args), 0);
        let lines = log_lines(&state);
        assert_eq!(lines.len(), 1, "one decision line: {lines:?}");
        assert_c8_line(&lines[0], "file-gone", 0);
        assert!(!state.exists());
        fs::remove_dir_all(&dir).expect("remove temp dir");
    }

    #[test]
    fn spawn_builds_the_hidden_argv() {
        let mut handle = spawn(Path::new("/usr/bin/true"), 1, Path::new("/x")).expect("spawn");
        assert!(handle.pid() > 0);
        let status = handle
            .child
            .as_mut()
            .expect("child held until drop")
            .wait()
            .expect("wait");
        assert!(status.success(), "status = {status:?}");
        assert!(!handle.is_alive(), "waited child is not alive");
    }

    /// F1.2: `reap` never blocks its caller and really waits. An exited
    /// child yields its status (now, or on the thread when it had not quite
    /// exited yet); a child blocked on its stdin is handed to a detached
    /// thread whose `wait` yields the status once the pipe closes.
    #[test]
    fn reap_collects_now_or_on_a_detached_thread() {
        let done = Command::new("/usr/bin/true").spawn().expect("spawn true");
        let status = match reap(done) {
            Reaped::Now(status) => status,
            Reaped::Deferred(thread) => thread
                .join()
                .expect("reaper thread did not panic")
                .expect("wait succeeded"),
            Reaped::Dropped(e) => panic!("reaper thread could not start: {e}"),
        };
        assert!(status.success(), "true exits 0, got {status:?}");

        // `cat` blocks until its stdin closes, so it is certainly alive.
        let mut blocked = Command::new("/bin/cat")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .spawn()
            .expect("spawn cat");
        let stdin = blocked.stdin.take().expect("piped stdin");
        let started = Instant::now();
        let reaped = reap(blocked);
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "reap returned without waiting ({:?})",
            started.elapsed()
        );
        let Reaped::Deferred(thread) = reaped else {
            panic!("a running child is reaped on a thread");
        };
        assert!(!thread.is_finished(), "the thread waits while cat lives");
        drop(stdin);
        let status = thread
            .join()
            .expect("reaper thread did not panic")
            .expect("wait succeeded");
        assert!(status.success(), "cat exits 0 on EOF, got {status:?}");
    }

    /// F1.2: dropping the handle closes the pipe (the watchdog wakes) and
    /// returns at once; the child is reaped in the background, not left a
    /// zombie until the core exits.
    #[test]
    fn dropping_the_handle_closes_the_pipe_and_reaps_without_blocking() {
        // `cat`'s stdout reaches EOF only when cat has exited, which it does
        // on stdin EOF: that is how the pipe closure is observed.
        let mut cat = Command::new("/bin/cat")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("spawn cat");
        let stdin = cat.stdin.take().expect("piped stdin");
        let mut stdout = cat.stdout.take().expect("piped stdout");
        let pid = cat.id();
        let handle = WatchdogHandle {
            child: Some(cat),
            stdin: Some(stdin),
        };
        drop(handle);
        let mut out = Vec::new();
        stdout
            .read_to_end(&mut out)
            .expect("read cat stdout to EOF");
        assert!(out.is_empty(), "nothing was ever written to cat");

        // The OS liveness probe cannot run inside the Bash sandbox (`ps` is
        // refused); where it can, the pid is gone, not a `Z` zombie. Our own
        // pid is the control: alive if the probe works at all.
        let exec = RealExecutor::new();
        let os = std::env::consts::OS;
        if is_alive_on(os, std::process::id(), &exec) {
            let deadline = Instant::now() + Duration::from_secs(5);
            while is_alive_on(os, pid, &exec) && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(20));
            }
            assert!(
                !is_alive_on(os, pid, &exec),
                "watchdog child {pid} reaped after the handle was dropped"
            );
        } else {
            eprintln!(
                "NOTE: liveness probe unavailable here; the reap itself is proven by reap_collects_now_or_on_a_detached_thread"
            );
        }

        // A child that ignores the pipe must not make the drop wait for it.
        let mut sleeper = Command::new("/bin/sleep")
            .arg("2")
            .stdin(Stdio::piped())
            .spawn()
            .expect("spawn sleep");
        let stdin = sleeper.stdin.take().expect("piped stdin");
        let handle = WatchdogHandle {
            child: Some(sleeper),
            stdin: Some(stdin),
        };
        let started = Instant::now();
        drop(handle);
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "drop returned before the child exited ({:?})",
            started.elapsed()
        );
    }

    /// A `PlatformOps` whose reads and restores are scripted; the only ops
    /// `run_after_wake` needs.
    struct FakeOps {
        live: Result<Vec<ServiceRow>, ReadError>,
        restore_result: Result<(), WriteError>,
        restored: Mutex<Vec<Vec<String>>>,
    }

    impl FakeOps {
        fn new(live: Vec<ServiceRow>) -> FakeOps {
            FakeOps {
                live: Ok(live),
                restore_result: Ok(()),
                restored: Mutex::new(Vec::new()),
            }
        }

        fn restore_calls(&self) -> Vec<Vec<String>> {
            self.restored
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .clone()
        }
    }

    impl PlatformOps for FakeOps {
        fn mechanism(&self) -> Mechanism {
            Mechanism::Networksetup
        }
        fn read_effective(&self, _exec: &dyn Executor) -> Result<Effective, ReadError> {
            Err(ReadError::Unavailable("not used".into()))
        }
        fn read_services(&self, _exec: &dyn Executor) -> Result<Vec<ServiceRow>, ReadError> {
            self.live.clone()
        }
        fn snapshot(&self, _exec: &dyn Executor) -> Result<Snapshot, ReadError> {
            panic!("the watchdog never snapshots")
        }
        fn write(
            &self,
            _exec: &dyn Executor,
            _previous: &Previous,
            _ours: &Endpoint,
            _bypass_extra: &[String],
        ) -> Result<Vec<String>, WriteError> {
            panic!("the watchdog never writes")
        }
        fn restore(
            &self,
            _exec: &dyn Executor,
            _previous: &Previous,
            only: &[String],
        ) -> Result<Vec<String>, WriteError> {
            self.restored
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .push(only.to_vec());
            self.restore_result
                .clone()
                .map(|()| only.iter().map(|s| format!("restore {s}")).collect())
        }
    }

    /// An executor whose every `run` fails to start the program.
    struct FailingExec;

    impl Executor for FailingExec {
        fn run(&self, cmd: &aitm_ca::exec::CmdLine) -> anyhow::Result<aitm_ca::exec::CmdOutput> {
            anyhow::bail!("{}: operation not permitted", cmd.render())
        }
        fn read_file(&self, _path: &Path) -> anyhow::Result<Option<Vec<u8>>> {
            Ok(None)
        }
        fn dir_exists(&self, _path: &Path) -> bool {
            false
        }
        fn home_dir(&self) -> Option<PathBuf> {
            None
        }
        fn is_root(&self) -> bool {
            false
        }
    }

    fn saved(tag: &str) -> (PathBuf, PathBuf) {
        let dir = temp_dir(tag);
        let state = dir.join(STATE_FILE_NAME);
        two_service_file().save_atomic(&state).expect("save");
        (dir, state)
    }

    /// `run_after_wake` over the file saved at `state`, as `wake` loads it.
    fn after_wake(
        state: &Path,
        exec: &dyn Executor,
        ops: &dyn PlatformOps,
        log: &mut Option<File>,
    ) -> i32 {
        let file = StateFile::load(state).expect("load").expect("a saved file");
        run_after_wake(state, &file, exec, ops, log)
    }

    /// §D9 (b) + C8: live equal → every service restored, file removed, one line.
    #[test]
    fn after_wake_restores_all_and_logs_restored() {
        let (dir, state) = saved("restore-all");
        let exec = ScriptedExecutor::new();
        let ops = FakeOps::new(live_equal());
        let mut log = open_log(&state);
        assert_eq!(after_wake(&state, &exec, &ops, &mut log), 0);
        assert_eq!(
            ops.restore_calls(),
            vec![vec!["Display Ethernet".to_string(), "Wi-Fi".to_string()]]
        );
        assert!(!state.exists(), "state file removed after a restore");
        let lines = log_lines(&state);
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert_c8_line(&lines[0], "restored", 2);
        fs::remove_dir_all(&dir).expect("remove temp dir");
    }

    /// One service taken over → restore the other, say so, file removed.
    #[test]
    fn after_wake_leaves_a_taken_service_alone() {
        let (dir, state) = saved("partial");
        let exec = ScriptedExecutor::new();
        let ops = FakeOps::new(vec![
            row("Display Ethernet", "10.0.0.5", 3128),
            row("Wi-Fi", "127.0.0.1", 8080),
        ]);
        let mut log = open_log(&state);
        assert_eq!(after_wake(&state, &exec, &ops, &mut log), 0);
        assert_eq!(ops.restore_calls(), vec![vec!["Wi-Fi".to_string()]]);
        assert!(!state.exists());
        let lines = log_lines(&state);
        assert_eq!(lines.len(), 2, "{lines:?}");
        assert_c8_line(&lines[0], "restored", 1);
        assert_c8_line(&lines[1], "left-alone", 1);
        fs::remove_dir_all(&dir).expect("remove temp dir");
    }

    /// Every service taken over → nothing to restore, file removed, exit 0.
    #[test]
    fn after_wake_with_nothing_ours_removes_the_file_without_restoring() {
        let (dir, state) = saved("none-ours");
        let exec = ScriptedExecutor::new();
        let ops = FakeOps::new(vec![
            row("Display Ethernet", "10.0.0.5", 3128),
            row("Wi-Fi", "10.0.0.5", 3128),
        ]);
        let mut log = open_log(&state);
        assert_eq!(after_wake(&state, &exec, &ops, &mut log), 0);
        assert!(ops.restore_calls().is_empty(), "no restore call");
        assert!(!state.exists());
        let lines = log_lines(&state);
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert_c8_line(&lines[0], "left-alone", 2);
        fs::remove_dir_all(&dir).expect("remove temp dir");
    }

    /// Restore failed → the file stays for §D9 (c), exit 3.
    #[test]
    fn after_wake_restore_failure_keeps_the_file_and_exits_3() {
        let (dir, state) = saved("restore-failed");
        let exec = ScriptedExecutor::new();
        let mut ops = FakeOps::new(live_equal());
        ops.restore_result = Err(WriteError::Failed("networksetup exit 1".into()));
        let mut log = open_log(&state);
        assert_eq!(
            after_wake(&state, &exec, &ops, &mut log),
            EXIT_RESTORE_FAILED
        );
        assert_eq!(EXIT_RESTORE_FAILED, 3);
        assert_eq!(EXIT_BAD_ARGS, 2);
        assert!(state.exists(), "state file kept for next-start recovery");
        let lines = log_lines(&state);
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert_c8_line(&lines[0], "restore-failed", 2);
        fs::remove_dir_all(&dir).expect("remove temp dir");
    }

    /// The live read failed → nothing can be judged; file kept, exit 3.
    #[test]
    fn after_wake_read_failure_keeps_the_file_and_exits_3() {
        let (dir, state) = saved("read-failed");
        let exec = ScriptedExecutor::new();
        let mut ops = FakeOps::new(vec![]);
        ops.live = Err(ReadError::Unavailable("networksetup missing".into()));
        let mut log = open_log(&state);
        assert_eq!(after_wake(&state, &exec, &ops, &mut log), 3);
        assert!(ops.restore_calls().is_empty());
        assert!(state.exists());
        let lines = log_lines(&state);
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert_c8_line(&lines[0], "restore-failed", 2);
        fs::remove_dir_all(&dir).expect("remove temp dir");
    }

    /// `file-gone` through the wake path (the file is loaded exactly once,
    /// there), no ops are built for it, and the log is truncated on open.
    #[test]
    fn wake_without_a_file_is_exit_0_and_log_is_truncated_on_open() {
        let dir = temp_dir("file-gone");
        let state = dir.join(STATE_FILE_NAME);
        fs::write(state.with_file_name(WATCHDOG_LOG_NAME), "stale line\n").expect("seed log");
        let exec = ScriptedExecutor::new();
        let ops_for = |_: Mechanism| -> Box<dyn PlatformOps> { panic!("no file, no ops") };
        let mut log = open_log(&state);
        assert_eq!(wake(&state, &exec, &ops_for, &mut log), 0);
        assert!(exec.runs().is_empty(), "nothing read: {:?}", exec.runs());
        let lines = log_lines(&state);
        assert_eq!(lines.len(), 1, "stale line gone: {lines:?}");
        assert_c8_line(&lines[0], "file-gone", 0);
        fs::remove_dir_all(&dir).expect("remove temp dir");
    }

    /// S1: the log is truncated at start by removing and re-creating it, so
    /// a symlink planted at the log name is never followed: the file it
    /// points at keeps its bytes and the log is a regular file.
    #[cfg(unix)]
    #[test]
    fn open_log_does_not_follow_a_symlink_at_the_log_path() {
        let dir = temp_dir("log-symlink");
        let state = dir.join(STATE_FILE_NAME);
        let log_path = state.with_file_name(WATCHDOG_LOG_NAME);
        let victim = dir.join("victim");
        fs::write(&victim, b"victim\n").expect("write victim");
        std::os::unix::fs::symlink(&victim, &log_path).expect("plant the link");

        let mut log = open_log(&state);
        assert!(log.is_some(), "the log opens");
        log_line(&mut log, "file-gone", 0, Instant::now());

        assert_eq!(fs::read(&victim).expect("victim"), b"victim\n");
        let meta = fs::symlink_metadata(&log_path).expect("log meta");
        assert!(meta.is_file(), "a regular file, not a link");
        let lines = log_lines(&state);
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert_c8_line(&lines[0], "file-gone", 0);
        fs::remove_dir_all(&dir).expect("remove temp dir");
    }

    /// The Linux synthetic row is judged by name like any macOS service.
    #[test]
    fn decide_handles_the_linux_synthetic_row() {
        let file = StateFile::new(
            Mechanism::Gsettings,
            1,
            wrote(),
            Previous::Gsettings {
                keys: BTreeMap::new(),
            },
        );
        assert_eq!(
            decide(Some(&file), &[row("gsettings", "127.0.0.1", 8080)]),
            Decision::Restore {
                only: vec!["gsettings".to_string()],
                left_alone: vec![],
            }
        );
        assert_eq!(
            decide(Some(&file), &[row("gsettings", "", 0)]),
            Decision::Restore {
                only: vec![],
                left_alone: vec!["gsettings".to_string()],
            }
        );
    }
}

/// Tester (stage 5) additions: the wake path over a corrupt file and over
/// a file that names no service, through the real macOS ops with scripted
/// output.
#[cfg(test)]
mod tester_tests {
    use std::fs;
    use std::path::{Path, PathBuf};

    use aitm_ca::testing::ScriptedExecutor;

    use super::*;
    use crate::platform::macos::MacosOps;
    use crate::platform::PlatformOps;
    use crate::state::{Previous, StateFile};
    use crate::{Mechanism, Wrote, STATE_FILE_NAME, WATCHDOG_LOG_NAME};

    const LIST: &str = "/usr/sbin/networksetup -listallnetworkservices";

    fn temp_dir(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock after 1970")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("aitm-sysproxy-wd-tester-{tag}-{nanos}"));
        fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    fn log_lines(state: &Path) -> Vec<String> {
        fs::read_to_string(state.with_file_name(WATCHDOG_LOG_NAME))
            .expect("read log")
            .lines()
            .map(str::to_string)
            .collect()
    }

    /// One enabled service whose three `-get*` reads answer nothing useful.
    fn one_service_exec() -> ScriptedExecutor {
        ScriptedExecutor::new().respond(
            LIST,
            0,
            "An asterisk (*) denotes that a network service is disabled.\nWi-Fi\n",
            "",
        )
    }

    /// A corrupt state file at the wake is quarantined (not read as "ours"),
    /// the live state is never read, no restore runs, and the wake is
    /// `file-gone` with exit 0.
    #[test]
    fn corrupt_file_at_the_wake_is_quarantined_and_file_gone_exit_0() {
        let dir = temp_dir("corrupt");
        let state = dir.join(STATE_FILE_NAME);
        fs::write(&state, "not json").expect("seed a corrupt file");
        let exec = one_service_exec();
        let mut log = open_log(&state);
        let macos = |_: Mechanism| -> Box<dyn PlatformOps> { Box::new(MacosOps) };
        assert_eq!(wake(&state, &exec, &macos, &mut log), 0);
        assert!(
            exec.runs().is_empty(),
            "nothing read for an unjudgeable file: {:?}",
            exec.runs()
        );
        assert!(!state.exists());
        let quarantined = fs::read_dir(&dir)
            .expect("read dir")
            .filter(|e| {
                e.as_ref()
                    .expect("entry")
                    .file_name()
                    .to_string_lossy()
                    .starts_with(&format!("{STATE_FILE_NAME}.corrupt-"))
            })
            .count();
        assert_eq!(quarantined, 1);
        let lines = log_lines(&state);
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(
            lines[0].contains(" file-gone services=0 ms="),
            "{}",
            lines[0]
        );
        fs::remove_dir_all(&dir).expect("remove temp dir");
    }

    /// A file that names no service (every service was authenticated and
    /// skipped at set time) is removed without a restore and without a
    /// `-set*` line; the live state is read once to judge it.
    #[test]
    fn a_file_naming_no_service_is_removed_without_a_restore() {
        let dir = temp_dir("no-services");
        let state = dir.join(STATE_FILE_NAME);
        StateFile::new(
            Mechanism::Networksetup,
            1,
            Wrote {
                host: "127.0.0.1".into(),
                port: 8080,
                bypass: vec![],
            },
            Previous::Networksetup { services: vec![] },
        )
        .save_atomic(&state)
        .expect("save");
        let exec = one_service_exec();
        let mut log = open_log(&state);
        let file = StateFile::load(&state).expect("load").expect("saved");
        assert_eq!(
            decide(Some(&file), &[]),
            Decision::Restore {
                only: vec![],
                left_alone: vec![],
            }
        );
        assert_eq!(run_after_wake(&state, &file, &exec, &MacosOps, &mut log), 0);
        assert_eq!(exec.runs().len(), 4, "list + three gets: {:?}", exec.runs());
        assert!(!exec.runs().iter().any(|l| l.contains(" -set")));
        assert!(!state.exists(), "the empty file is forgotten");
        // Nothing to restore: the wake still leaves one C8 line behind, the
        // `left-alone` decision over zero services (Q5).
        let lines = log_lines(&state);
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(
            lines[0].contains(" left-alone services=0 ms="),
            "{}",
            lines[0]
        );
        fs::remove_dir_all(&dir).expect("remove temp dir");
    }
}
