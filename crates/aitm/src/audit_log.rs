//! The durable audit writer: the JSONL files the `aitm` binary appends every
//! audited command invocation to (spec `docs/superpowers/specs/2026-10-31-durable-audit-design.md`).
//!
//! The log is **best-effort and not tamper-evident**: it exists so that an
//! operator can reconstruct what ran after the in-memory ring has rolled over,
//! not so that a reader can prove nothing was removed.
//!
//! Entries go to one of **three streams**, each its own file with its own queue
//! and size budget, so that a flood of one kind of entry cannot push another
//! kind off the disk: `control` (evidence from the trusted operator and the
//! CLI), `agent` (evidence from every other origin) and `reads` (successful
//! `Read` calls, any origin).
//!
//! This part of the module is the stream vocabulary: [`StreamKind`] and its
//! limits, [`stream_path`] (which file a stream is written to) and
//! [`stream_for`] (which stream an entry belongs to); and the hardened file
//! layer: `preflight` opens a stream's file for append only when the path is
//! safe to write (an absolute path, a parent no other user can replace the file
//! in, a regular file with a single name, mode `0600`) and starts it with a
//! `start` marker.

use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use aitm_core::{AuditLane, Frontend};

/// One of the three audit streams.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamKind {
    /// Evidence-lane entries whose origin is trusted control (operator, CLI).
    Control,
    /// Evidence-lane entries of every other origin.
    Agent,
    /// Routine-lane entries: successful `Read` calls, any origin.
    Reads,
}

impl StreamKind {
    /// Every stream, in [`StreamKind::index`] order.
    pub const ALL: [StreamKind; 3] = [StreamKind::Control, StreamKind::Agent, StreamKind::Reads];

    /// Position in [`StreamKind::ALL`].
    pub const fn index(self) -> usize {
        match self {
            StreamKind::Control => 0,
            StreamKind::Agent => 1,
            StreamKind::Reads => 2,
        }
    }

    /// The short name used in thread names and log lines.
    pub const fn label(self) -> &'static str {
        match self {
            StreamKind::Control => "control",
            StreamKind::Agent => "agent",
            StreamKind::Reads => "reads",
        }
    }

    /// Entries the stream's queue holds before it drops the newest. The agent
    /// stream's queue is the deepest because the agent is the origin that can
    /// produce entries fastest; a full queue sheds load rather than blocking
    /// the call path.
    pub const fn queue_capacity(self) -> usize {
        match self {
            StreamKind::Control => 1024,
            StreamKind::Agent => 4096,
            StreamKind::Reads => 2048,
        }
    }

    /// Size at which the active file rotates.
    pub const fn max_bytes(self) -> u64 {
        match self {
            StreamKind::Control => 4 * MIB,
            StreamKind::Agent | StreamKind::Reads => 8 * MIB,
        }
    }

    /// Rotated files kept beside the active one. With [`StreamKind::max_bytes`]
    /// this bounds the stream at `max_bytes * (1 + keep_rotated)` on disk:
    /// 20 MiB, 48 MiB and 24 MiB, at most 92 MiB in all.
    pub const fn keep_rotated(self) -> usize {
        match self {
            StreamKind::Control => 4,
            StreamKind::Agent => 5,
            StreamKind::Reads => 2,
        }
    }
}

/// One mebibyte.
const MIB: u64 = 1024 * 1024;

/// The file `kind` is written to, given the configured base path.
///
/// The control stream is the base itself. The agent and reads streams put
/// `.agent` / `.reads` before the final extension, or append it when there is
/// none: `audit.jsonl` gives `audit.agent.jsonl`, `audit` gives `audit.agent`,
/// `audit.v2.jsonl` gives `audit.v2.agent.jsonl`. The name is assembled from
/// `OsStr`s, so a file name that is not UTF-8 works, and this never panics: a
/// base with no file name at all (`/`) borrows the stem `audit`, so the three
/// paths stay distinct and the later boot checks, not this function, reject it.
pub fn stream_path(base: &Path, kind: StreamKind) -> PathBuf {
    let infix = match kind {
        StreamKind::Control => return base.to_path_buf(),
        StreamKind::Agent => "agent",
        StreamKind::Reads => "reads",
    };
    let mut name = base
        .file_stem()
        .unwrap_or_else(|| "audit".as_ref())
        .to_os_string();
    name.push(".");
    name.push(infix);
    if let Some(extension) = base.extension() {
        name.push(".");
        name.push(extension);
    }
    base.with_file_name(name)
}

/// The stream an entry of `lane` and `origin` belongs to.
///
/// A successful read is `Reads` whoever made it. Evidence goes to `Control`
/// exactly when the origin is trusted control (the operator and the CLI), and
/// to `Agent` otherwise, so an origin this code has never heard of lands in
/// the untrusted stream. Nothing here compares against the agent role.
pub fn stream_for(lane: AuditLane, origin: Frontend) -> StreamKind {
    match lane {
        AuditLane::Routine => StreamKind::Reads,
        AuditLane::Evidence if origin.is_trusted_control() => StreamKind::Control,
        AuditLane::Evidence => StreamKind::Agent,
    }
}

/// Schema version carried by every `start` marker (and, from a later task, every
/// `gap` marker). A reader that sees a higher number than it knows should stop.
pub const MARKER_SCHEMA: u32 = 1;

/// Mode a log file is created with, and tightened to when it is found with any
/// group or other bit set.
#[cfg(unix)]
const PRIVATE_FILE_MODE: u32 = 0o600;

/// Mode a missing parent directory is created with.
#[cfg(unix)]
const PRIVATE_DIR_MODE: u32 = 0o700;

/// Device and inode of an open file: what makes two names "the same file".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileId {
    dev: u64,
    ino: u64,
}

/// One open, append-only log file as the writer thread sees it. The real one is
/// [`FsFile`]; later tasks' tests substitute a fake that records lines or blocks.
#[allow(dead_code)] // used from Task W5
trait LogFile: Send {
    /// Appends `line` and one `\n` with a single `write_all`, never buffered, so
    /// a reader sees the line at once and a crash tears at most the last line.
    fn append_line(&mut self, line: &str) -> io::Result<()>;
    /// The file's length in bytes, as this handle has grown it.
    fn size(&self) -> u64;
    /// Flushes the file's data to the device.
    fn sync(&mut self) -> io::Result<()>;
    /// The file's device and inode, `None` where the platform has none (and for
    /// a fake), which skips the path re-check.
    fn id(&self) -> Option<FileId>;
}

/// The real [`LogFile`]: a file opened for append by [`preflight`], tracking its
/// own length and identity.
struct FsFile {
    file: File,
    size: u64,
    id: Option<FileId>,
}

impl FsFile {
    /// Appends `bytes` with one `write_all` and grows the tracked size by what
    /// was written. A failed write leaves the size alone: a reopen (which runs
    /// [`preflight`] again) measures the file and closes a torn tail.
    fn append_bytes(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.file.write_all(bytes)?;
        self.size += bytes.len() as u64;
        Ok(())
    }

    /// Whether the file is empty or ends in a newline. The handle is open for
    /// reading as well as appending for exactly this; appends go to the end
    /// wherever the read left the cursor.
    fn ends_cleanly(&mut self) -> io::Result<bool> {
        if self.size == 0 {
            return Ok(true);
        }
        let mut last = [0_u8; 1];
        self.file.seek(SeekFrom::End(-1))?;
        self.file.read_exact(&mut last)?;
        Ok(last[0] == b'\n')
    }

    /// Writes the `start` marker, preceded by a newline when the file ends in a
    /// torn line, in one write.
    fn write_start(&mut self, stream: StreamKind) -> io::Result<()> {
        let marker = start_marker_line(stream, unix_ms(SystemTime::now()), std::process::id());
        let mut bytes = Vec::with_capacity(marker.len() + 2);
        if !self.ends_cleanly()? {
            bytes.push(b'\n');
        }
        bytes.extend_from_slice(marker.as_bytes());
        bytes.push(b'\n');
        self.append_bytes(&bytes)
    }
}

impl LogFile for FsFile {
    fn append_line(&mut self, line: &str) -> io::Result<()> {
        let mut bytes = Vec::with_capacity(line.len() + 1);
        bytes.extend_from_slice(line.as_bytes());
        bytes.push(b'\n');
        self.append_bytes(&bytes)
    }

    fn size(&self) -> u64 {
        self.size
    }

    fn sync(&mut self) -> io::Result<()> {
        self.file.sync_data()
    }

    fn id(&self) -> Option<FileId> {
        self.id
    }
}

/// `at` as milliseconds since the Unix epoch; a clock before the epoch reads 0
/// and one beyond `i64` saturates, so this never panics.
fn unix_ms(at: SystemTime) -> i64 {
    at.duration_since(UNIX_EPOCH)
        .map(|elapsed| i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

/// The `start` marker line (no newline): the first line of every file the writer
/// creates and one more at every boot that appends to an existing file. One JSON
/// object whose keys are written in alphabetical order, so the line is the same
/// whatever `serde_json`'s map ordering.
fn start_marker_line(stream: StreamKind, at_ms: i64, pid: u32) -> String {
    serde_json::json!({
        "at": at_ms,
        "marker": "start",
        "pid": pid,
        "schema": MARKER_SCHEMA,
        "stream": stream.label(),
        "version": env!("CARGO_PKG_VERSION"),
    })
    .to_string()
}

/// An error that refuses to use `path`, with the reason in the message.
fn refused(path: &Path, reason: impl std::fmt::Display) -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!("audit log {}: {reason}", path.display()),
    )
}

/// `source` with the path and what was being attempted put in front of it.
fn failed(path: &Path, what: impl std::fmt::Display, source: io::Error) -> io::Error {
    io::Error::new(
        source.kind(),
        format!("audit log {}: {what}: {source}", path.display()),
    )
}

/// The file's device and inode where the platform has them.
#[cfg(unix)]
fn file_id(meta: &Metadata) -> Option<FileId> {
    use std::os::unix::fs::MetadataExt;
    Some(FileId {
        dev: meta.dev(),
        ino: meta.ino(),
    })
}

#[cfg(not(unix))]
fn file_id(_meta: &Metadata) -> Option<FileId> {
    None
}

/// How many names the file has; 1 where the platform does not say.
#[cfg(unix)]
fn hard_links(meta: &Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt;
    meta.nlink()
}

#[cfg(not(unix))]
fn hard_links(_meta: &Metadata) -> u64 {
    1
}

/// Refuses anything that is not a regular file with exactly one name: a
/// symbolic link, a directory, a FIFO, a socket, a device, or a regular file with
/// a second hard link. Applied to the path's own metadata before opening and to
/// the opened handle's afterwards, so a swap in between is caught too.
fn refuse_hostile_file(path: &Path, meta: &Metadata) -> io::Result<()> {
    let kind = meta.file_type();
    if kind.is_symlink() {
        return Err(refused(
            path,
            "the path is a symbolic link; the writer never writes through one",
        ));
    }
    if !kind.is_file() {
        return Err(refused(
            path,
            "the path is not a regular file (a directory, FIFO, socket or device); it is not opened",
        ));
    }
    let links = hard_links(meta);
    if links > 1 {
        return Err(refused(
            path,
            format_args!(
                "the file has {links} hard links; the writer refuses a file another path can also write"
            ),
        ));
    }
    Ok(())
}

/// Step 1 of [`preflight`]: creates the missing parent directories (mode `0700`)
/// and refuses an existing parent that is world-writable and not sticky, where
/// any user could rename the file away and plant their own. A group-writable or
/// group- or other-readable parent is accepted: the file itself is `0600`, and
/// per-user groups make a group-writable `~/.config` the default on some
/// systems. Only the immediate parent is checked.
fn prepare_parent(path: &Path) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| refused(path, "the path has no parent directory"))?;
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(PRIVATE_DIR_MODE);
    }
    builder.create(parent).map_err(|source| {
        failed(
            path,
            format_args!("cannot create the parent directory {}", parent.display()),
            source,
        )
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let meta = fs::metadata(parent).map_err(|source| {
            failed(
                path,
                format_args!("cannot inspect the parent directory {}", parent.display()),
                source,
            )
        })?;
        let mode = meta.mode();
        if mode & 0o002 != 0 && mode & 0o1000 == 0 {
            return Err(refused(
                path,
                format_args!(
                    "the parent directory {} is world-writable and not sticky; another user could replace the log",
                    parent.display()
                ),
            ));
        }
    }
    Ok(())
}

/// Step 3 of [`preflight`]: opens `path` for append (and read, to inspect the
/// last byte), mode `0600`. A missing file is created with `create_new`, which
/// refuses an existing name, a symbolic link (even a dangling one) included; an
/// existing file is opened with no `create`.
fn open_private(path: &Path, create: bool) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).append(true);
    if create {
        options.create_new(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(PRIVATE_FILE_MODE);
    }
    options.open(path).map_err(|source| {
        let what = if create {
            "cannot create the file"
        } else {
            "cannot open the file for append"
        };
        failed(path, what, source)
    })
}

/// Step 3's re-check: the file at `path` now is the file that was opened
/// (`opened` is the handle's own metadata). A path swapped for another file or a
/// symbolic link since the first look is refused. Where the platform has no
/// identity both sides read `None` and the check passes.
fn confirm_same_file(path: &Path, opened: &Metadata) -> io::Result<()> {
    let now = fs::symlink_metadata(path)
        .map_err(|source| failed(path, "cannot re-inspect the path after opening it", source))?;
    if file_id(&now) != file_id(opened) {
        return Err(refused(
            path,
            "the path changed while it was being opened; refusing to use it",
        ));
    }
    Ok(())
}

/// Step 4 of [`preflight`]: an existing file with any group or other mode bit is
/// set to `0600` through the handle. When that fails (not the owner) the path is
/// refused.
#[cfg(unix)]
fn restrict_to_owner(path: &Path, file: &File, meta: &Metadata) -> io::Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    if meta.mode() & 0o077 == 0 {
        return Ok(());
    }
    file.set_permissions(fs::Permissions::from_mode(PRIVATE_FILE_MODE))
        .map_err(|source| {
            failed(
                path,
                "cannot restrict the file to its owner (mode 0600)",
                source,
            )
        })
}

#[cfg(not(unix))]
fn restrict_to_owner(_path: &Path, _file: &File, _meta: &Metadata) -> io::Result<()> {
    Ok(())
}

/// Opens the log file for `stream` at `path` for the writer, creating and
/// hardening it, or says exactly why it will not (spec Design 4). In order:
///
/// 0. a relative path is refused;
/// 1. missing parent directories are created `0700`; an existing parent that is
///    world-writable and not sticky is refused;
/// 2. the path is inspected without following a link: a symbolic link, a
///    directory, a FIFO, a socket or a device is refused **without opening it**
///    (so a FIFO cannot block the boot), as is a regular file with a second hard
///    link; a missing file is the fresh case;
/// 3. the file is opened for append, mode `0600` (`create_new` when it was
///    missing, which closes the window in which a link is planted after step 2);
///    the opened handle is checked as step 2 checked the path, and the path must
///    still name the very file that was opened (same device and inode);
/// 4. an existing file with any group or other bit is set to `0600`;
/// 5. a newline is appended first when the file does not end in one (a torn tail
///    from a crash or a full disk), then the `start` marker.
///
/// Nothing is ever truncated. Every error is an [`io::Error`] whose message names
/// the path and the reason. Mode, link-count and identity checks are Unix-only;
/// elsewhere the file is created with default permissions and has no identity.
#[allow(dead_code)] // used from Task W5
fn preflight(path: &Path, stream: StreamKind) -> io::Result<FsFile> {
    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "audit log {}: the path is not absolute; a relative audit path would follow the working directory",
                path.display()
            ),
        ));
    }
    prepare_parent(path)?;
    let create = match fs::symlink_metadata(path) {
        Ok(meta) => {
            refuse_hostile_file(path, &meta)?;
            false
        }
        Err(source) if source.kind() == io::ErrorKind::NotFound => true,
        Err(source) => return Err(failed(path, "cannot inspect the path", source)),
    };
    let file = open_private(path, create)?;
    let meta = file
        .metadata()
        .map_err(|source| failed(path, "cannot inspect the opened file", source))?;
    refuse_hostile_file(path, &meta)?;
    confirm_same_file(path, &meta)?;
    restrict_to_owner(path, &file, &meta)?;
    let mut out = FsFile {
        file,
        size: meta.len(),
        id: file_id(&meta),
    };
    out.write_start(stream)
        .map_err(|source| failed(path, "cannot write the start marker", source))?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs::{self, OpenOptions};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    use aitm_core::{AuditEntry, AuditResult};
    use serde_json::Value;

    /// A unique scratch directory that removes itself on drop, including a
    /// directory a test made unreadable (the tests below chmod freely).
    struct Scratch(PathBuf);

    impl Scratch {
        fn join(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            make_removable(&self.0);
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// Resets every real directory under `dir` to `0700` so `remove_dir_all`
    /// can run. Never follows a symbolic link.
    #[cfg(unix)]
    fn make_removable(dir: &Path) {
        use std::os::unix::fs::PermissionsExt;

        let is_dir = fs::symlink_metadata(dir)
            .map(|meta| meta.file_type().is_dir())
            .unwrap_or(false);
        if !is_dir {
            return;
        }
        let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
        if let Ok(children) = fs::read_dir(dir) {
            for child in children.flatten() {
                make_removable(&child.path());
            }
        }
    }

    #[cfg(not(unix))]
    fn make_removable(_dir: &Path) {}

    /// A fresh scratch directory (mode `0700`), unique per process, clock tick
    /// and call.
    fn scratch(tag: &str) -> Scratch {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "aitm-audit-log-{tag}-{}-{nanos}-{n}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).expect("create the scratch directory");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))
                .expect("restrict the scratch directory");
        }
        Scratch(dir)
    }

    /// An entry with an explicit `at` of `at_ms` milliseconds after the epoch,
    /// so a marker's `from` / `to` can be asserted exactly.
    #[allow(dead_code)] // used from Task W5
    fn entry(command: &str, origin: Frontend, at_ms: u64) -> AuditEntry {
        AuditEntry {
            at: UNIX_EPOCH + Duration::from_millis(at_ms),
            origin,
            client_label: None,
            connection_id: None,
            command: command.to_string(),
            args_summary: "{}".to_string(),
            result: AuditResult::Ok,
        }
    }

    /// Every line of `path` parsed as JSON; panics on a line that is not.
    fn read_lines(path: &Path) -> Vec<Value> {
        let text =
            fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        text.lines()
            .map(|line| {
                serde_json::from_str(line).unwrap_or_else(|e| {
                    panic!(
                        "{} holds a line that is not JSON ({e}): {line:?}",
                        path.display()
                    )
                })
            })
            .collect()
    }

    /// The `command` of every line that has one (markers have none).
    #[allow(dead_code)] // used from Task W5
    fn entry_commands(path: &Path) -> Vec<String> {
        read_lines(path)
            .iter()
            .filter_map(|line| line.get("command").and_then(Value::as_str))
            .map(str::to_string)
            .collect()
    }

    /// Polls `cond` every 5 ms until it holds or `timeout` passes. Never a fixed
    /// sleep: a fast machine finishes at once.
    #[allow(dead_code)] // used from Task W5
    fn wait_until(timeout: Duration, mut cond: impl FnMut() -> bool) -> bool {
        let deadline = Instant::now() + timeout;
        loop {
            if cond() {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// Runs `f` on its own thread and gives it `timeout`. A call that does not
    /// return (a `preflight` blocked on a FIFO, say) becomes an `Err` the test
    /// can report instead of a hung test run; the stuck thread is detached and
    /// dies with the process.
    fn try_within<T: Send + 'static>(
        timeout: Duration,
        what: &str,
        f: impl FnOnce() -> T + Send + 'static,
    ) -> Result<T, String> {
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(f());
        });
        match rx.recv_timeout(timeout) {
            Ok(value) => Ok(value),
            Err(mpsc::RecvTimeoutError::Timeout) => Err(format!(
                "{what} blocked for more than {} s",
                timeout.as_secs_f64()
            )),
            Err(mpsc::RecvTimeoutError::Disconnected) => Err(format!("{what} panicked")),
        }
    }

    /// [`try_within`] that fails the test when `f` is not done in time.
    fn within<T: Send + 'static>(
        timeout: Duration,
        what: &str,
        f: impl FnOnce() -> T + Send + 'static,
    ) -> T {
        try_within(timeout, what, f).unwrap_or_else(|message| panic!("{message}"))
    }

    /// Says on stderr that a test, or one row of it, did not run and why. A
    /// print macro would be swallowed by libtest when the test passes, and a
    /// skip nobody can see is worth nothing; stderr is not captured.
    fn skipped(why: &str) {
        let _ = writeln!(io::stderr(), "SKIPPED {why}");
    }

    /// How long a `preflight` may take. It does a handful of syscalls; this is
    /// generous on purpose.
    const PREFLIGHT_BUDGET: Duration = Duration::from_secs(2);

    /// `preflight` under the budget; a hang fails the calling test.
    fn preflight_within(path: &Path, stream: StreamKind) -> io::Result<FsFile> {
        let path = path.to_path_buf();
        within(PREFLIGHT_BUDGET, "preflight", move || {
            preflight(&path, stream)
        })
    }

    /// `None` when `preflight(path)` returns an error containing `needle`
    /// within the budget; otherwise the reason this row failed.
    fn refusal_failure(label: &str, path: &Path, needle: &str) -> Option<String> {
        let owned = path.to_path_buf();
        match try_within(PREFLIGHT_BUDGET, "preflight", move || {
            preflight(&owned, StreamKind::Control)
        }) {
            Err(hang) => Some(format!("{label}: {hang}")),
            Ok(Ok(_)) => Some(format!(
                "{label}: expected an error for a {label}, preflight returned Ok"
            )),
            Ok(Err(e)) if e.to_string().contains(needle) => None,
            Ok(Err(e)) => Some(format!(
                "{label}: the error {:?} does not contain {needle:?}",
                e.to_string()
            )),
        }
    }

    /// `None` when `preflight(path)` succeeds within the budget; otherwise why not.
    fn acceptance_failure(label: &str, path: &Path) -> Option<String> {
        let owned = path.to_path_buf();
        match try_within(PREFLIGHT_BUDGET, "preflight", move || {
            preflight(&owned, StreamKind::Control)
        }) {
            Err(hang) => Some(format!("{label}: {hang}")),
            Ok(Ok(_)) => None,
            Ok(Err(e)) => Some(format!("{label}: expected Ok, got {e}")),
        }
    }

    /// Routine entries are reads, whoever made them; evidence goes to `control`
    /// exactly when the origin is trusted control, and to `agent` otherwise.
    #[test]
    fn stream_for_routes_by_lane_and_trust() {
        let rows = [
            (AuditLane::Routine, Frontend::Cli, StreamKind::Reads),
            (AuditLane::Routine, Frontend::Mcp, StreamKind::Reads),
            (AuditLane::Routine, Frontend::Operator, StreamKind::Reads),
            (AuditLane::Evidence, Frontend::Operator, StreamKind::Control),
            (AuditLane::Evidence, Frontend::Cli, StreamKind::Control),
            (AuditLane::Evidence, Frontend::Mcp, StreamKind::Agent),
        ];
        let mut failures: Vec<String> = Vec::new();
        for (lane, origin, want) in rows {
            let got = stream_for(lane, origin);
            if got != want {
                failures.push(format!(
                    "({lane:?}, {origin:?}): left: {got:?}, right: {want:?}"
                ));
            }
        }
        assert!(
            failures.is_empty(),
            "{} row(s) failed:\n{}",
            failures.len(),
            failures.join("\n")
        );
    }

    /// The spec's budget: 20 + 48 + 24 MiB on disk at most, queues 1024 / 4096 / 2048.
    #[test]
    fn stream_limits_total_92_mib() {
        let mib = 1024 * 1024;
        let total: u64 = StreamKind::ALL
            .iter()
            .map(|kind| kind.max_bytes() * (1 + kind.keep_rotated() as u64))
            .sum();
        assert_eq!(total, 96_468_992);
        assert_eq!(
            StreamKind::ALL.map(StreamKind::max_bytes),
            [4 * mib, 8 * mib, 8 * mib]
        );
        assert_eq!(StreamKind::ALL.map(StreamKind::keep_rotated), [4, 5, 2]);
        assert_eq!(
            StreamKind::ALL.map(StreamKind::queue_capacity),
            [1024, 4096, 2048]
        );
    }

    /// `index` is the position in `ALL` (later tasks index arrays with it) and
    /// `label` names the stream in thread names and log lines.
    #[test]
    fn stream_index_and_label_name_each_stream() {
        assert_eq!(
            StreamKind::ALL.map(|kind| (kind.index(), kind.label())),
            [(0, "control"), (1, "agent"), (2, "reads")]
        );
    }

    /// A base with no extension, a dotfile and a base with no file name at all
    /// each give three distinct paths (a derived path equal to the control path
    /// would make two streams write one file).
    #[test]
    fn stream_path_edge_names_stay_distinct() {
        let rows = [
            // (base, agent, reads)
            ("audit.jsonl", "audit.agent.jsonl", "audit.reads.jsonl"),
            ("/a/.audit", "/a/.audit.agent", "/a/.audit.reads"),
            ("/a/audit.", "/a/audit.agent.", "/a/audit.reads."),
            ("/", "/audit.agent", "/audit.reads"),
        ];
        let mut failures: Vec<String> = Vec::new();
        for (base, agent, reads) in rows {
            let base = Path::new(base);
            for (kind, want) in [
                (StreamKind::Control, base),
                (StreamKind::Agent, Path::new(agent)),
                (StreamKind::Reads, Path::new(reads)),
            ] {
                let got = stream_path(base, kind);
                if got != want {
                    failures.push(format!("{base:?} {kind:?}: left: {got:?}, right: {want:?}"));
                }
            }
        }
        assert!(
            failures.is_empty(),
            "{} row(s) failed:\n{}",
            failures.len(),
            failures.join("\n")
        );
    }

    /// A file name that is not UTF-8 survives: the derived name is built from
    /// `OsStr`s, never through `str`.
    #[cfg(unix)]
    #[test]
    fn stream_path_keeps_a_non_utf8_name() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;

        let dir = Path::new("/a");
        let named = |bytes: &[u8]| dir.join(OsStr::from_bytes(bytes));
        let base = named(b"au\xffdit.jsonl");
        assert_eq!(
            stream_path(&base, StreamKind::Agent),
            named(b"au\xffdit.agent.jsonl")
        );
        assert_eq!(
            stream_path(&base, StreamKind::Reads),
            named(b"au\xffdit.reads.jsonl")
        );
        assert_eq!(stream_path(&base, StreamKind::Control), base);
    }

    /// AC7: every hostile thing that can sit at, or above, the log path is
    /// refused within the budget with a message that says why, and nothing is
    /// written through it. The FIFO row is the reason the budget exists: opening
    /// a FIFO for writing blocks until a reader appears.
    #[cfg(unix)]
    #[test]
    fn hostile_paths_are_refused_without_hanging() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        use std::process::Command;

        let dir = scratch("hostile");
        let mut failures: Vec<String> = Vec::new();
        let mode_of = |path: &Path| fs::metadata(path).map(|m| m.permissions().mode() & 0o7777);

        // A symbolic link to a regular file: refused, and the target is untouched.
        let target = dir.join("target.txt");
        fs::write(&target, "keep\n").expect("write the link target");
        let link = dir.join("link");
        symlink(&target, &link).expect("make the symlink");
        failures.extend(refusal_failure("symbolic link", &link, "symbolic link"));
        if fs::read_to_string(&target).ok().as_deref() != Some("keep\n") {
            failures.push("symbolic link: the target was written through the link".into());
        }

        // A dangling symbolic link: refused, and the target is not created.
        let dangling = dir.join("dangling");
        symlink("missing-target", &dangling).expect("make the dangling symlink");
        failures.extend(refusal_failure(
            "dangling symbolic link",
            &dangling,
            "symbolic link",
        ));
        if fs::symlink_metadata(dir.join("missing-target")).is_ok() {
            failures.push("dangling symbolic link: the target was created through the link".into());
        }

        // A directory at the path.
        let directory = dir.join("a-directory");
        fs::create_dir(&directory).expect("make the directory");
        failures.extend(refusal_failure("directory", &directory, "regular file"));

        // A FIFO at the path.
        let fifo = dir.join("a-fifo");
        match Command::new("mkfifo").arg(&fifo).status() {
            Err(e) => skipped(&format!("the FIFO row: mkfifo cannot be spawned ({e})")),
            Ok(status) if !status.success() => {
                failures.push(format!("FIFO: mkfifo failed with {status}"));
            }
            Ok(_) => failures.extend(refusal_failure("FIFO", &fifo, "regular file")),
        }

        // A regular file with a second hard link: refused, and left untouched.
        let first = dir.join("hard-a");
        fs::write(&first, "x\n").expect("write the hard link source");
        fs::hard_link(&first, dir.join("hard-b")).expect("make the hard link");
        failures.extend(refusal_failure("hard link", &first, "hard link"));
        if fs::read_to_string(&first).ok().as_deref() != Some("x\n") {
            failures.push("hard link: the file was written".into());
        }

        // A world-writable parent without the sticky bit: refused, nothing created.
        let open_dir = dir.join("open-dir");
        fs::create_dir(&open_dir).expect("make the world-writable parent");
        fs::set_permissions(&open_dir, fs::Permissions::from_mode(0o777)).expect("chmod 0777");
        failures.extend(refusal_failure(
            "world-writable parent",
            &open_dir.join("audit.jsonl"),
            "world-writable",
        ));
        if fs::symlink_metadata(open_dir.join("audit.jsonl")).is_ok() {
            failures.push("world-writable parent: a file was created in it".into());
        }

        // The same directory with the sticky bit (like /tmp) is accepted.
        let sticky_dir = dir.join("sticky-dir");
        fs::create_dir(&sticky_dir).expect("make the sticky parent");
        fs::set_permissions(&sticky_dir, fs::Permissions::from_mode(0o1777)).expect("chmod 1777");
        failures.extend(acceptance_failure(
            "sticky world-writable parent",
            &sticky_dir.join("audit.jsonl"),
        ));

        // A group-writable, other-readable parent (0775) is accepted.
        let group_dir = dir.join("group-dir");
        fs::create_dir(&group_dir).expect("make the group-writable parent");
        fs::set_permissions(&group_dir, fs::Permissions::from_mode(0o775)).expect("chmod 0775");
        failures.extend(acceptance_failure(
            "0775 parent",
            &group_dir.join("audit.jsonl"),
        ));

        // A pre-existing 0644 file starts, keeps its content and becomes 0600.
        let loose = dir.join("loose.jsonl");
        fs::write(&loose, "{\"old\":1}\n").expect("write the loose file");
        fs::set_permissions(&loose, fs::Permissions::from_mode(0o644)).expect("chmod 0644");
        failures.extend(acceptance_failure("0644 file", &loose));
        match mode_of(&loose) {
            Ok(0o600) => {}
            Ok(mode) => failures.push(format!(
                "0644 file: mode afterwards is {mode:04o}, not 0600"
            )),
            Err(e) => failures.push(format!("0644 file: cannot stat it afterwards: {e}")),
        }
        if !fs::read_to_string(&loose)
            .map(|text| text.starts_with("{\"old\":1}\n"))
            .unwrap_or(false)
        {
            failures.push("0644 file: its existing content was not preserved".into());
        }

        assert!(
            failures.is_empty(),
            "{} row(s) failed:\n{}",
            failures.len(),
            failures.join("\n")
        );
    }

    /// AC8: a parent the process cannot write into is an error that names the
    /// path, and nothing is created.
    #[cfg(unix)]
    #[test]
    fn an_unwritable_parent_is_an_error() {
        use std::os::unix::fs::PermissionsExt;

        let dir = scratch("unwritable");
        let locked = dir.join("locked");
        fs::create_dir(&locked).expect("make the locked directory");
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o500)).expect("chmod 0500");

        // Root writes into a 0500 directory anyway, so there is nothing to refuse.
        let probe = locked.join("probe");
        if fs::File::create(&probe).is_ok() {
            let _ = fs::remove_file(&probe);
            skipped("(running as root)");
            return;
        }

        let path = locked.join("audit.jsonl");
        let err = match preflight_within(&path, StreamKind::Control) {
            Ok(_) => panic!("preflight accepted a path in an unwritable directory"),
            Err(e) => e,
        };
        let message = err.to_string();
        assert!(
            message.contains(&path.display().to_string()),
            "the error does not name {}: {message}",
            path.display()
        );
        assert!(
            fs::symlink_metadata(&path).is_err(),
            "a file was created anyway"
        );
    }

    /// Mechanism for AC5: a missing nested parent is created `0700`, the file is
    /// created `0600`, and it holds exactly the `start` marker, with the keys,
    /// values and size the spec fixes.
    #[cfg(unix)]
    #[test]
    fn preflight_creates_private_dirs_and_files_with_a_start_marker() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let dir = scratch("fresh");
        let path = dir.join("a/b/audit.jsonl");
        let before = unix_ms(SystemTime::now());
        let file = preflight_within(&path, StreamKind::Control)
            .unwrap_or_else(|e| panic!("preflight of a fresh path failed: {e}"));
        let after = unix_ms(SystemTime::now());

        let mode = |p: &Path| fs::metadata(p).expect("stat").permissions().mode() & 0o777;
        assert_eq!(mode(&dir.join("a")), 0o700, "mode of a");
        assert_eq!(mode(&dir.join("a/b")), 0o700, "mode of a/b");
        assert_eq!(mode(&path), 0o600, "mode of the file");

        let lines = read_lines(&path);
        assert_eq!(lines.len(), 1, "exactly one line: {lines:?}");
        let marker = &lines[0];
        let mut keys: Vec<&str> = marker
            .as_object()
            .expect("the marker is an object")
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(keys, ["at", "marker", "pid", "schema", "stream", "version"]);
        assert_eq!(marker["marker"], "start");
        assert_eq!(marker["schema"], 1);
        assert_eq!(marker["stream"], "control");
        assert_eq!(marker["pid"], std::process::id());
        assert_eq!(marker["version"], env!("CARGO_PKG_VERSION"));
        let at = marker["at"].as_i64().expect("`at` is an integer");
        assert!(
            before <= at && at <= after,
            "`at` {at} is not within [{before}, {after}]"
        );

        let meta = fs::metadata(&path).expect("stat the file");
        assert_eq!(file.size(), meta.len(), "FsFile::size");
        assert_eq!(
            file.id(),
            Some(FileId {
                dev: meta.dev(),
                ino: meta.ino()
            }),
            "FsFile::id"
        );
    }

    /// The marker is one JSON object with its keys in alphabetical order and no
    /// newline, for every stream.
    #[test]
    fn start_marker_line_is_one_sorted_json_object() {
        let version = env!("CARGO_PKG_VERSION");
        let mut failures: Vec<String> = Vec::new();
        for (stream, label) in [
            (StreamKind::Control, "control"),
            (StreamKind::Agent, "agent"),
            (StreamKind::Reads, "reads"),
        ] {
            let want = format!(
                "{{\"at\":1700000000000,\"marker\":\"start\",\"pid\":4242,\"schema\":1,\"stream\":\"{label}\",\"version\":\"{version}\"}}"
            );
            let got = start_marker_line(stream, 1_700_000_000_000, 4242);
            if got != want {
                failures.push(format!("{label}: left: {got}, right: {want}"));
            }
        }
        assert!(
            failures.is_empty(),
            "{} row(s) failed:\n{}",
            failures.len(),
            failures.join("\n")
        );
    }

    /// Mechanism for AC6: an existing file is appended to, never truncated; a
    /// torn tail (no final newline) is closed with a newline before the marker,
    /// and a complete tail gets no blank line.
    #[test]
    fn preflight_appends_a_start_marker_and_repairs_a_torn_tail() {
        let dir = scratch("torn");

        let torn = dir.join("torn.jsonl");
        fs::write(&torn, "{\"a\":1}\n{\"b\"").expect("write the torn file");
        let file = preflight_within(&torn, StreamKind::Agent)
            .unwrap_or_else(|e| panic!("preflight of a torn file failed: {e}"));
        let text = fs::read_to_string(&torn).expect("read the torn file");
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 3, "three lines: {text:?}");
        assert_eq!(lines[0], "{\"a\":1}");
        assert_eq!(lines[1], "{\"b\"");
        let marker: Value = serde_json::from_str(lines[2]).expect("the marker is JSON");
        assert_eq!(marker["marker"], "start");
        assert_eq!(marker["stream"], "agent");
        assert!(text.ends_with('\n'), "the file ends in a newline: {text:?}");
        assert_eq!(
            file.size(),
            text.len() as u64,
            "FsFile::size of the torn file"
        );

        let tidy = dir.join("tidy.jsonl");
        fs::write(&tidy, "{\"a\":1}\n").expect("write the tidy file");
        let file = preflight_within(&tidy, StreamKind::Reads)
            .unwrap_or_else(|e| panic!("preflight of a tidy file failed: {e}"));
        let text = fs::read_to_string(&tidy).expect("read the tidy file");
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2, "two lines and no blank one: {text:?}");
        assert_eq!(lines[0], "{\"a\":1}");
        assert!(!text.contains("\n\n"), "a blank line: {text:?}");
        assert_eq!(
            file.size(),
            text.len() as u64,
            "FsFile::size of the tidy file"
        );

        // A second start on the same file appends another marker.
        preflight_within(&tidy, StreamKind::Reads).expect("a second preflight");
        let text = fs::read_to_string(&tidy).expect("read the tidy file again");
        assert_eq!(
            text.lines().count(),
            3,
            "three lines after a restart: {text:?}"
        );
    }

    /// A relative path is refused with a message that says why, before anything
    /// is created (a CWD-relative audit file is an anti-goal).
    #[test]
    fn preflight_refuses_a_relative_path() {
        let relative_dir = format!("aitm-audit-relative-{}", std::process::id());
        let relative = Path::new(&relative_dir).join("audit.jsonl");
        let err = match preflight_within(&relative, StreamKind::Control) {
            Ok(_) => panic!("preflight accepted a relative path"),
            Err(e) => e,
        };
        assert!(
            err.to_string().contains("absolute"),
            "the error does not say `absolute`: {err}"
        );
        assert!(
            fs::symlink_metadata(&relative_dir).is_err(),
            "{relative_dir} was created"
        );
    }

    /// `FsFile` writes a line and its newline in one call, a reader sees it at
    /// once (nothing is buffered), and the tracked size follows the file.
    #[test]
    fn fs_file_appends_one_line_per_call_and_tracks_its_size() {
        let dir = scratch("append");
        let path = dir.join("audit.jsonl");
        let mut file = preflight_within(&path, StreamKind::Control).expect("preflight");
        let start_len = file.size();

        file.append_line("{\"x\":1}").expect("first line");
        let text = fs::read_to_string(&path).expect("read after the first line");
        assert!(text.ends_with("{\"x\":1}\n"), "{text:?}");
        assert_eq!(file.size(), start_len + 8, "size after one line");

        file.append_line("{\"y\":2}").expect("second line");
        let text = fs::read_to_string(&path).expect("read after the second line");
        assert!(text.ends_with("{\"x\":1}\n{\"y\":2}\n"), "{text:?}");
        assert_eq!(file.size(), text.len() as u64, "size after two lines");
        file.sync().expect("sync");
    }

    /// The re-check after `open`: a path whose file is replaced (by another
    /// regular file or by a symbolic link) between the first inspection and the
    /// open is refused, and the same file passes. The replacement is put in place
    /// with `rename`, so the opened inode is still alive and cannot be reused.
    #[cfg(unix)]
    #[test]
    fn a_path_replaced_after_opening_is_refused() {
        use std::os::unix::fs::symlink;

        let dir = scratch("swap");
        let path = dir.join("audit.jsonl");
        fs::write(&path, "").expect("write the log file");
        let handle = OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("open the log file");
        let opened = handle.metadata().expect("stat the handle");

        confirm_same_file(&path, &opened).expect("the same file passes");

        let other = dir.join("other.jsonl");
        fs::write(&other, "").expect("write the replacement");
        fs::rename(&other, &path).expect("replace the log file");
        let err = confirm_same_file(&path, &opened).expect_err("a replaced file must be refused");
        assert!(
            err.to_string().contains("changed"),
            "the error does not say `changed`: {err}"
        );

        let elsewhere = dir.join("elsewhere.jsonl");
        fs::write(&elsewhere, "").expect("write the link target");
        let decoy = dir.join("decoy");
        symlink(&elsewhere, &decoy).expect("make the decoy link");
        fs::rename(&decoy, &path).expect("replace the log file with a link");
        let err = confirm_same_file(&path, &opened)
            .expect_err("a link in place of the file must be refused");
        assert!(
            err.to_string().contains("changed"),
            "the error does not say `changed`: {err}"
        );
    }
}
