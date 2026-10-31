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

use std::fmt;
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use aitm_core::{AuditEntry, AuditLane, DurableAudit, DurableAuditStatus, Frontend};

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
trait LogFile: Send {
    /// Appends `line` and one `\n` with a single `write_all`, never buffered, so
    /// a reader sees the line at once and a crash tears at most the last line.
    fn append_line(&mut self, line: &str) -> io::Result<()>;
    /// The file's length in bytes, as this handle has grown it.
    #[allow(dead_code)] // used from Task W8
    fn size(&self) -> u64;
    /// Flushes the file's data to the device.
    fn sync(&mut self) -> io::Result<()>;
    /// The file's device and inode, `None` where the platform has none (and for
    /// a fake), which skips the path re-check.
    #[allow(dead_code)] // used from Task W9
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

/// How long `main.rs` gives the writer to flush at exit (spec Design 7). A
/// writer that has not finished by then is left behind and the process exits
/// regardless: a shutdown never hangs.
pub const SHUTDOWN_BUDGET: Duration = Duration::from_secs(2);

/// The pause between two tries of a loop that must not block (a full queue
/// that has to take its `Close`, a thread that has not finished yet).
const POLL: Duration = Duration::from_millis(1);

/// What a re-check of a stream's path found. Only the common answer exists
/// until the re-check itself (Task W9) adds the others.
#[derive(Debug, PartialEq, Eq)]
enum Recheck {
    /// The path still names the open file.
    Same,
}

/// How a stream's thread reaches its file: open it, rotate it, and check that
/// its path still names it. The real one is [`FsBackend`]; tests substitute a
/// fake that records lines, blocks or fails. It is `Send` because the thread
/// that uses it owns it.
trait Backend: Send {
    /// Opens `path` for append, ready to write (a `start` marker already in it).
    /// The real one is [`preflight`].
    #[allow(dead_code)] // used from Task W7
    fn open(&mut self, path: &Path, stream: StreamKind) -> io::Result<Box<dyn LogFile>>;

    /// Moves the full active file aside, keeps `keep` rotated files and opens a
    /// fresh one. Unsupported until Task W8.
    #[allow(dead_code)] // used from Task W8
    fn rotate(
        &mut self,
        path: &Path,
        stream: StreamKind,
        keep: usize,
    ) -> io::Result<Box<dyn LogFile>> {
        let _ = (path, stream, keep);
        Err(io::ErrorKind::Unsupported.into())
    }

    /// Whether `path` still names `file`. Always the same until Task W9.
    #[allow(dead_code)] // used from Task W9
    fn recheck(&mut self, path: &Path, file: &dyn LogFile) -> Recheck {
        let _ = (path, file);
        Recheck::Same
    }
}

/// The real [`Backend`]: files on disk, opened and hardened by [`preflight`].
#[allow(dead_code)] // used from Task W11
struct FsBackend;

impl Backend for FsBackend {
    fn open(&mut self, path: &Path, stream: StreamKind) -> io::Result<Box<dyn LogFile>> {
        let file: Box<dyn LogFile> = Box::new(preflight(path, stream)?);
        Ok(file)
    }
}

/// Everything one stream's thread owns: where its file is, how to reach it, and
/// the file itself. `file` is `None` when the stream could not be opened at boot
/// and is to be retried; such a stream starts degraded.
struct StreamSpec {
    #[allow(dead_code)] // used from Task W7
    path: PathBuf,
    #[allow(dead_code)] // used from Task W7
    backend: Box<dyn Backend>,
    file: Option<Box<dyn LogFile>>,
}

/// The writer's numbers and intervals, per stream where they differ. Production
/// uses [`Tuning::production`]; tests shorten an interval or a cap instead of
/// sleeping for it.
#[derive(Debug, Clone)]
struct Tuning {
    /// Entries each stream's queue holds, indexed by [`StreamKind::index`].
    queue: [usize; 3],
    /// Size at which each stream's file rotates.
    #[allow(dead_code)] // used from Task W8
    cap_bytes: [u64; 3],
    /// Rotated files each stream keeps.
    #[allow(dead_code)] // used from Task W8
    keep: [usize; 3],
    /// How often a stream checks that its path still names its file.
    #[allow(dead_code)] // used from Task W9
    recheck: Duration,
    /// How soon a failed stream tries to reopen its file.
    #[allow(dead_code)] // used from Task W7
    reopen: Duration,
    /// How soon a stream retries a rotation that failed.
    #[allow(dead_code)] // used from Task W8
    rotate_retry: Duration,
    /// How often a repeated failure is logged again.
    #[allow(dead_code)] // used from Task W7
    warn_every: Duration,
}

impl Tuning {
    /// The spec's constants: the per-stream limits of [`StreamKind`], a re-check
    /// every 5 s, a reopen after 1 s, a rotation retry after 60 s and one log
    /// line per failure kind per 60 s.
    #[allow(dead_code)] // used from Task W11
    fn production() -> Tuning {
        Tuning {
            queue: StreamKind::ALL.map(StreamKind::queue_capacity),
            cap_bytes: StreamKind::ALL.map(StreamKind::max_bytes),
            keep: StreamKind::ALL.map(StreamKind::keep_rotated),
            recheck: Duration::from_secs(5),
            reopen: Duration::from_secs(1),
            rotate_retry: Duration::from_secs(60),
            warn_every: Duration::from_secs(60),
        }
    }
}

/// What a shutdown found when its budget ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShutdownReport {
    /// Every stream's thread had finished: everything accepted is on disk.
    pub complete: bool,
    /// When not `complete`, roughly how many accepted entries had not been
    /// written (queued, or in the write that is stuck). Always 0 when `complete`.
    pub estimated_left: usize,
}

/// A message to a stream's thread.
enum Msg {
    /// One entry to write.
    Entry(AuditEntry),
    /// Everything queued before this has been written: sync the file and exit.
    Close,
}

/// One stream's counters and flags, shared between the producers and the
/// stream's thread. Atomics only: nothing here is a lock, so a producer never
/// waits on a thread that is blocked in file I/O.
#[derive(Default)]
struct StreamShared {
    /// Entries refused: the queue was full, or the thread is gone.
    dropped: AtomicU64,
    /// Entries the thread could not write.
    write_failures: AtomicU64,
    /// The most recent write failed (or there is no file); the next success clears it.
    degraded: AtomicBool,
    /// The thread ended through a `Close`.
    closed: AtomicBool,
    /// The thread ended any other way: it panicked, or every sender is gone.
    dead: AtomicBool,
    /// Entries accepted by `record` and not yet written.
    queued: AtomicUsize,
}

/// Sets `dead` when a stream's thread ends without a `Close`.
struct DeadGuard<'a>(&'a StreamShared);

impl Drop for DeadGuard<'_> {
    fn drop(&mut self) {
        if !self.0.closed.load(Ordering::Acquire) {
            self.0.dead.store(true, Ordering::Release);
        }
    }
}

/// The producer's end of one stream.
struct StreamEnds {
    tx: SyncSender<Msg>,
    shared: Arc<StreamShared>,
}

/// The body of a stream's thread: writes what it is sent, in order, until a
/// `Close` (sync, mark closed, exit) or until every sender is gone.
fn run_stream(rx: Receiver<Msg>, mut spec: StreamSpec, shared: &StreamShared) {
    while let Ok(message) = rx.recv() {
        match message {
            Msg::Entry(entry) => {
                write_entry(&mut spec, &entry, shared);
                shared.queued.fetch_sub(1, Ordering::Relaxed);
            }
            Msg::Close => {
                if let Some(file) = spec.file.as_mut() {
                    // A failed sync leaves nothing further to try at exit.
                    let _ = file.sync();
                }
                shared.closed.store(true, Ordering::Release);
                return;
            }
        }
    }
}

/// Writes one entry as its JSONL line. A failure (or a stream with no file) is
/// counted, marks the stream degraded and loses this entry; the next write that
/// succeeds clears `degraded`.
fn write_entry(spec: &mut StreamSpec, entry: &AuditEntry, shared: &StreamShared) {
    let line = aitm_ca::audit::entry_to_jsonl(entry);
    let written = match spec.file.as_mut() {
        Some(file) => file.append_line(&line),
        None => Err(io::Error::new(
            io::ErrorKind::NotFound,
            "the stream has no open file",
        )),
    };
    match written {
        Ok(()) => shared.degraded.store(false, Ordering::Release),
        Err(_) => {
            shared.degraded.store(true, Ordering::Release);
            shared.write_failures.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Starts one stream's thread, named `aitm-audit-<label>`, with a queue of
/// `capacity` entries.
fn spawn_stream(
    kind: StreamKind,
    spec: StreamSpec,
    capacity: usize,
) -> io::Result<(StreamEnds, JoinHandle<()>)> {
    let (tx, rx) = sync_channel(capacity);
    let shared = Arc::new(StreamShared::default());
    shared
        .degraded
        .store(spec.file.is_none(), Ordering::Relaxed);
    let thread_shared = Arc::clone(&shared);
    let handle = thread::Builder::new()
        .name(format!("aitm-audit-{}", kind.label()))
        .spawn(move || {
            // Declared first, so it drops last: when this stream reads as dead
            // its receiver is already gone, and the next record counts as dropped.
            let _guard = DeadGuard(&thread_shared);
            run_stream(rx, spec, &thread_shared);
        })
        .map_err(|source| {
            io::Error::new(
                source.kind(),
                format!(
                    "cannot start the audit writer thread for the {} stream: {source}",
                    kind.label()
                ),
            )
        })?;
    Ok((StreamEnds { tx, shared }, handle))
}

/// A point in time a loop gives up at, or never when the budget is so large
/// that the sum overflows (`Instant + Duration` would panic).
struct Deadline(Option<Instant>);

impl Deadline {
    fn after(budget: Duration) -> Deadline {
        Deadline(Instant::now().checked_add(budget))
    }

    fn passed(&self) -> bool {
        self.0.is_some_and(|at| Instant::now() >= at)
    }
}

/// The durable audit writer: a [`DurableAudit`] that hands each entry to the
/// stream it belongs to ([`stream_for`]). Each stream has a bounded queue and
/// one thread that owns its file, so a stream that stalls or floods cannot slow
/// the call path or another stream: [`record`](DurableAudit::record) is a
/// `try_send` and nothing else.
pub struct AuditLogWriter {
    streams: [StreamEnds; 3],
    /// The streams' threads until a shutdown takes them, so `shutdown` works
    /// through `&self`.
    threads: Mutex<Vec<JoinHandle<()>>>,
}

impl AuditLogWriter {
    /// Starts the three stream threads over `specs` (in [`StreamKind::ALL`]
    /// order). Fails only when a thread cannot be spawned; the threads started
    /// before it end by themselves.
    #[allow(dead_code)] // used from Task W11
    fn from_specs(specs: [StreamSpec; 3], tuning: Tuning) -> io::Result<AuditLogWriter> {
        let [control, agent, reads] = specs;
        let capacity = |kind: StreamKind| tuning.queue[kind.index()];
        let (control, control_thread) =
            spawn_stream(StreamKind::Control, control, capacity(StreamKind::Control))?;
        let (agent, agent_thread) =
            spawn_stream(StreamKind::Agent, agent, capacity(StreamKind::Agent))?;
        let (reads, reads_thread) =
            spawn_stream(StreamKind::Reads, reads, capacity(StreamKind::Reads))?;
        Ok(AuditLogWriter {
            streams: [control, agent, reads],
            threads: Mutex::new(vec![control_thread, agent_thread, reads_thread]),
        })
    }

    /// Flushes and stops the writer within `budget`: sends each stream a `Close`
    /// (retrying while its queue is full), then waits for the threads. Each
    /// thread writes everything queued before its `Close`, syncs its file and
    /// exits. A thread still running when the budget ends (a write that is
    /// stuck) is left behind and the report says so; the caller exits
    /// regardless. A second call finds nothing to wait for and reports complete.
    pub fn shutdown(&self, budget: Duration) -> ShutdownReport {
        let handles = std::mem::take(&mut *self.lock_threads());
        if handles.is_empty() {
            return ShutdownReport {
                complete: true,
                estimated_left: 0,
            };
        }
        let deadline = Deadline::after(budget);
        for stream in &self.streams {
            // Never a blocking `send`: a full queue behind a stuck write must not
            // hold the caller past the budget. A gone receiver means the thread
            // already ended, and there is nothing to close.
            while let Err(TrySendError::Full(_)) = stream.tx.try_send(Msg::Close) {
                if deadline.passed() {
                    break;
                }
                thread::sleep(POLL);
            }
        }
        while !handles.iter().all(JoinHandle::is_finished) && !deadline.passed() {
            thread::sleep(POLL);
        }
        let mut complete = true;
        for handle in handles {
            if handle.is_finished() {
                // A thread that panicked has nothing more to say here; its
                // stream already reads as dead.
                let _ = handle.join();
            } else {
                // Dropping the handle detaches the thread.
                complete = false;
            }
        }
        let estimated_left = if complete {
            0
        } else {
            self.streams
                .iter()
                .map(|stream| stream.shared.queued.load(Ordering::Relaxed))
                .sum()
        };
        ShutdownReport {
            complete,
            estimated_left,
        }
    }

    fn lock_threads(&self) -> MutexGuard<'_, Vec<JoinHandle<()>>> {
        self.threads.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl fmt::Debug for AuditLogWriter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuditLogWriter")
            .field("status", &self.status())
            .finish_non_exhaustive()
    }
}

impl DurableAudit for AuditLogWriter {
    /// Hands `entry` to its stream's queue. Never blocks, never panics and
    /// does no file I/O: a full queue, or a stream whose thread has ended, counts
    /// the entry as dropped instead.
    fn record(&self, lane: AuditLane, entry: AuditEntry) {
        let stream = &self.streams[stream_for(lane, entry.origin).index()];
        stream.shared.queued.fetch_add(1, Ordering::Relaxed);
        if stream.tx.try_send(Msg::Entry(entry)).is_err() {
            stream.shared.queued.fetch_sub(1, Ordering::Relaxed);
            stream.shared.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// The counters summed over the streams. `degraded` is true when any stream
    /// is dead or its latest write failed; a stream that ended through a `Close`
    /// is closed, not degraded.
    fn status(&self) -> DurableAuditStatus {
        let mut status = DurableAuditStatus::default();
        for stream in &self.streams {
            let shared = &stream.shared;
            status.dropped = status
                .dropped
                .saturating_add(shared.dropped.load(Ordering::Relaxed));
            status.write_failures = status
                .write_failures
                .saturating_add(shared.write_failures.load(Ordering::Relaxed));
            status.degraded |=
                shared.degraded.load(Ordering::Acquire) || shared.dead.load(Ordering::Acquire);
        }
        status
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs::{self, OpenOptions};
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
    use std::sync::{mpsc, Arc, Condvar, Mutex, MutexGuard, PoisonError};
    use std::time::{Duration, Instant};

    use aitm_core::{AuditEntry, AuditResult, AuditRing, AuditSink};
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
    fn entry_commands(path: &Path) -> Vec<String> {
        read_lines(path)
            .iter()
            .filter_map(|line| line.get("command").and_then(Value::as_str))
            .map(str::to_string)
            .collect()
    }

    /// Polls `cond` every 5 ms until it holds or `timeout` passes. Never a fixed
    /// sleep: a fast machine finishes at once.
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

    // ---- the writer core (Task W5) -------------------------------------

    /// How long a test gives a shutdown that has real work to do.
    const FLUSH_BUDGET: Duration = Duration::from_secs(5);

    /// Locks `m` whether or not a thread panicked holding it: a fake that is told
    /// to panic must not take the test's own assertions down with it.
    fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
        m.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// A real writer over three real files in `dir`: each stream's path comes
    /// from `stream_path`, is opened with `preflight`, and gets the real backend.
    /// The writer is attached to a fresh ring, so a test appends through the ring
    /// the way every audited call does.
    fn fs_writer(
        dir: &Scratch,
        tuning: Tuning,
    ) -> (Arc<AuditRing>, Arc<AuditLogWriter>, [PathBuf; 3]) {
        let base = dir.join("audit.jsonl");
        let paths = StreamKind::ALL.map(|kind| stream_path(&base, kind));
        let specs = StreamKind::ALL.map(|kind| {
            let path = stream_path(&base, kind);
            let file = preflight(&path, kind)
                .unwrap_or_else(|e| panic!("preflight of the {} stream failed: {e}", kind.label()));
            StreamSpec {
                path,
                backend: Box::new(FsBackend),
                file: Some(Box::new(file)),
            }
        });
        let writer = Arc::new(
            AuditLogWriter::from_specs(specs, tuning).unwrap_or_else(|e| panic!("start: {e}")),
        );
        let ring = Arc::new(AuditRing::new(8192));
        assert!(
            ring.attach_durable(writer.clone()),
            "a fresh ring takes its first sink"
        );
        (ring, writer, paths)
    }

    /// Where the first write of a gated [`FakeState`] waits, and how a test
    /// lets it go.
    #[derive(Default)]
    struct Gate {
        state: Mutex<GateState>,
        changed: Condvar,
    }

    #[derive(Default)]
    struct GateState {
        /// The first write has reached the gate.
        reached: bool,
        /// The test has let it go.
        released: bool,
    }

    impl Gate {
        /// The longest a write waits when a failing test never releases it: the
        /// stuck thread is detached, so this only keeps it from living forever.
        const LIMIT: Duration = Duration::from_secs(30);

        /// Blocks the first caller until [`Gate::release`]; every later call
        /// passes at once.
        fn pass(&self) {
            let mut state = lock(&self.state);
            if state.reached {
                return;
            }
            state.reached = true;
            let _ = self
                .changed
                .wait_timeout_while(state, Self::LIMIT, |s| !s.released)
                .unwrap_or_else(PoisonError::into_inner);
        }
    }

    /// What a fake log file remembers and how it misbehaves, shared with the
    /// test through an `Arc`. Used from here on by the tasks that script a
    /// failing or a stalled disk.
    #[derive(Default)]
    struct FakeState {
        /// Every line written, without its newline.
        lines: Mutex<Vec<String>>,
        /// The name of the thread each write ran on.
        writer_threads: Mutex<Vec<String>>,
        /// How many times the file was synced.
        syncs: AtomicUsize,
        /// The next this-many writes fail with `StorageFull`.
        fail_next: AtomicUsize,
        /// A write panics.
        panic_on_write: AtomicBool,
        /// The first write blocks here when set.
        gate: Option<Gate>,
    }

    impl FakeState {
        fn plain() -> Arc<FakeState> {
            Arc::new(FakeState::default())
        }

        /// A state whose first write blocks until [`FakeState::release`].
        fn gated() -> Arc<FakeState> {
            Arc::new(FakeState {
                gate: Some(Gate::default()),
                ..FakeState::default()
            })
        }

        /// Three plain states, one per stream.
        fn three() -> [Arc<FakeState>; 3] {
            std::array::from_fn(|_| FakeState::plain())
        }

        fn lines(&self) -> Vec<String> {
            lock(&self.lines).clone()
        }

        fn writer_threads(&self) -> Vec<String> {
            lock(&self.writer_threads).clone()
        }

        /// Whether the first write is blocked at the gate.
        fn inside(&self) -> bool {
            self.gate
                .as_ref()
                .is_some_and(|gate| lock(&gate.state).reached)
        }

        /// Lets the blocked first write go.
        fn release(&self) {
            if let Some(gate) = &self.gate {
                lock(&gate.state).released = true;
                gate.changed.notify_all();
            }
        }
    }

    struct FakeFile(Arc<FakeState>);

    impl LogFile for FakeFile {
        fn append_line(&mut self, line: &str) -> io::Result<()> {
            let state = &self.0;
            let thread = std::thread::current();
            lock(&state.writer_threads).push(thread.name().unwrap_or("").to_string());
            if state.panic_on_write.load(Ordering::SeqCst) {
                panic!("the fake file was told to panic on a write");
            }
            let order = Ordering::SeqCst;
            let failing = state
                .fail_next
                .fetch_update(order, order, |left| left.checked_sub(1));
            if failing.is_ok() {
                return Err(io::Error::new(
                    io::ErrorKind::StorageFull,
                    "the fake disk is full",
                ));
            }
            if let Some(gate) = &state.gate {
                gate.pass();
            }
            lock(&state.lines).push(line.to_string());
            Ok(())
        }

        fn size(&self) -> u64 {
            lock(&self.0.lines)
                .iter()
                .map(|line| line.len() as u64 + 1)
                .sum()
        }

        fn sync(&mut self) -> io::Result<()> {
            self.0.syncs.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        fn id(&self) -> Option<FileId> {
            None
        }
    }

    struct FakeBackend(Arc<FakeState>);

    impl Backend for FakeBackend {
        fn open(&mut self, _path: &Path, _stream: StreamKind) -> io::Result<Box<dyn LogFile>> {
            Ok(Box::new(FakeFile(self.0.clone())))
        }
    }

    /// A writer over three fake files, one per state, nothing on disk.
    fn fake_writer(states: &[Arc<FakeState>; 3], tuning: Tuning) -> Arc<AuditLogWriter> {
        let mut specs = Vec::new();
        for (kind, state) in StreamKind::ALL.into_iter().zip(states) {
            specs.push(StreamSpec {
                path: PathBuf::from(format!("/fake/{}.jsonl", kind.label())),
                backend: Box::new(FakeBackend(state.clone())),
                file: Some(Box::new(FakeFile(state.clone()))),
            });
        }
        let specs: [StreamSpec; 3] = match specs.try_into() {
            Ok(specs) => specs,
            Err(_) => panic!("three streams make three specs"),
        };
        Arc::new(AuditLogWriter::from_specs(specs, tuning).unwrap_or_else(|e| panic!("start: {e}")))
    }

    /// AC11: the lane and the trust of the origin pick the stream, and the
    /// operator's entry is on disk although an agent could not read it.
    #[test]
    fn entries_are_routed_by_lane_and_trust() {
        let dir = scratch("routing");
        let (ring, writer, paths) = fs_writer(&dir, Tuning::production());

        let op_e = entry("op_e", Frontend::Operator, 1);
        let ag_e = entry("ag_e", Frontend::Mcp, 2);
        let ag_r = entry("ag_r", Frontend::Mcp, 3);
        let op_r = entry("op_r", Frontend::Operator, 4);
        let cli_e = entry("cli_e", Frontend::Cli, 5);
        assert!(
            !op_e.visible_to(Frontend::Mcp),
            "the operator's entry is hidden from an agent"
        );
        ring.append_in(AuditLane::Evidence, op_e);
        ring.append_in(AuditLane::Evidence, ag_e);
        ring.append_in(AuditLane::Routine, ag_r);
        ring.append_in(AuditLane::Routine, op_r);
        ring.append(cli_e);
        let report = writer.shutdown(FLUSH_BUDGET);
        assert!(report.complete, "the flush did not finish: {report:?}");

        assert_eq!(entry_commands(&paths[0]), ["op_e", "cli_e"], "control file");
        assert_eq!(entry_commands(&paths[1]), ["ag_e"], "agent file");
        assert_eq!(entry_commands(&paths[2]), ["ag_r", "op_r"], "reads file");
    }

    /// AC12: an entry line has the seven keys the ring entry has, and it is the
    /// line `entry_to_jsonl` renders; an error result is `{"error": reason}`.
    #[test]
    fn an_entry_line_has_exactly_the_seven_keys() {
        let dir = scratch("seven-keys");
        let (ring, writer, paths) = fs_writer(&dir, Tuning::production());

        let honest = AuditEntry {
            client_label: Some("probe-a".to_string()),
            connection_id: Some("conn-7".to_string()),
            args_summary: "{\"flow\":\"f1\"}".to_string(),
            ..entry("flow.get", Frontend::Mcp, 1_700_000_000_123)
        };
        let refused = AuditEntry {
            result: AuditResult::Error("not permitted for this origin".to_string()),
            ..entry("agent.set", Frontend::Mcp, 1_700_000_000_456)
        };
        ring.append_in(AuditLane::Evidence, honest.clone());
        ring.append_in(AuditLane::Evidence, refused.clone());
        let report = writer.shutdown(FLUSH_BUDGET);
        assert!(report.complete, "the flush did not finish: {report:?}");

        let raw = fs::read_to_string(&paths[1]).expect("read the agent file");
        let entry_lines: Vec<(&str, Value)> = raw
            .lines()
            .filter_map(|line| {
                let parsed: Value = serde_json::from_str(line).expect("every line is JSON");
                parsed.get("command").is_some().then_some((line, parsed))
            })
            .collect();
        assert_eq!(entry_lines.len(), 2, "two entry lines in: {raw:?}");

        let mut failures: Vec<String> = Vec::new();
        for ((line, parsed), source) in entry_lines.iter().zip([&honest, &refused]) {
            let mut keys: Vec<&str> = parsed
                .as_object()
                .expect("an entry line is an object")
                .keys()
                .map(String::as_str)
                .collect();
            keys.sort_unstable();
            let want_keys = [
                "args",
                "at",
                "client_label",
                "command",
                "connection_id",
                "origin",
                "result",
            ];
            if keys != want_keys {
                failures.push(format!("{}: keys {keys:?}", source.command));
            }
            let want_line = aitm_ca::audit::entry_to_jsonl(source);
            if *line != want_line {
                failures.push(format!(
                    "{}: left: {line}, right: {want_line}",
                    source.command
                ));
            }
        }
        assert!(
            failures.is_empty(),
            "{} row(s) failed:\n{}",
            failures.len(),
            failures.join("\n")
        );
        assert_eq!(entry_lines[0].1["result"], "ok");
        assert_eq!(
            entry_lines[1].1["result"],
            serde_json::json!({"error": "not permitted for this origin"})
        );
    }

    /// AC21: after a complete shutdown a record is counted as dropped, returns
    /// at once and never panics.
    #[test]
    fn recording_after_shutdown_is_counted_never_blocking() {
        let dir = scratch("after-shutdown");
        let (ring, writer, _paths) = fs_writer(&dir, Tuning::production());
        let report = writer.shutdown(FLUSH_BUDGET);
        assert!(
            report.complete,
            "the idle shutdown did not finish: {report:?}"
        );
        assert_eq!(writer.status().dropped, 0, "nothing was dropped yet");

        let rows = [
            (AuditLane::Evidence, Frontend::Operator),
            (AuditLane::Evidence, Frontend::Mcp),
            (AuditLane::Routine, Frontend::Mcp),
        ];
        let appender = ring.clone();
        within(
            Duration::from_secs(1),
            "ten appends after shutdown",
            move || {
                for (i, (lane, origin)) in rows.into_iter().cycle().take(10).enumerate() {
                    appender.append_in(lane, entry(&format!("late{i}"), origin, i as u64));
                }
            },
        );
        assert_eq!(writer.status().dropped, 10);
        assert_eq!(writer.status().write_failures, 0);
    }

    /// AC29: everything queued before a shutdown is on disk after it, in order,
    /// behind the file's `start` marker.
    #[test]
    fn shutdown_flushes_every_queued_entry() {
        let dir = scratch("flush");
        let (ring, writer, paths) = fs_writer(&dir, Tuning::production());
        for i in 0..2000_u64 {
            ring.append_in(
                AuditLane::Evidence,
                entry(&format!("e{i}"), Frontend::Mcp, i),
            );
        }
        let report = writer.shutdown(FLUSH_BUDGET);
        assert!(report.complete, "the flush did not finish: {report:?}");
        assert_eq!(report.estimated_left, 0);

        let want: Vec<String> = (0..2000).map(|i| format!("e{i}")).collect();
        let got = entry_commands(&paths[1]);
        assert_eq!(got.len(), want.len(), "entry lines in the agent file");
        let first_difference = got.iter().zip(&want).position(|(g, w)| g != w);
        assert_eq!(first_difference, None, "first entry out of order");
        let lines = read_lines(&paths[1]);
        assert_eq!(lines[0]["marker"], "start", "the first line is the marker");
    }

    /// AC30: a writer stuck inside a write cannot hold a shutdown past its
    /// budget, and the report says entries are left.
    #[test]
    fn shutdown_of_a_blocked_writer_returns_within_its_budget() {
        let states = [FakeState::plain(), FakeState::gated(), FakeState::plain()];
        let writer = fake_writer(&states, Tuning::production());
        writer.record(AuditLane::Evidence, entry("blocked", Frontend::Mcp, 1));
        assert!(
            wait_until(Duration::from_secs(2), || states[1].inside()),
            "the agent writer never reached its write"
        );

        let started = Instant::now();
        let report = writer.shutdown(Duration::from_millis(300));
        let took = started.elapsed();
        // Let the stuck thread go before any assertion can fail, so it can exit.
        states[1].release();

        assert!(took < Duration::from_millis(1500), "shutdown took {took:?}");
        assert!(!report.complete);
        assert!(
            report.estimated_left >= 1,
            "estimated_left is {}",
            report.estimated_left
        );
        assert!(
            wait_until(Duration::from_secs(2), || {
                states[1].syncs.load(Ordering::SeqCst) == 1
            }),
            "after the release the writer did not process its Close"
        );
    }

    /// The estimate of entries left is exactly what was accepted and is not yet
    /// written: an entry whose write has finished, failed or not, no longer counts.
    #[test]
    fn the_estimate_of_entries_left_counts_only_what_is_not_yet_written() {
        let states = [FakeState::plain(), FakeState::gated(), FakeState::plain()];
        // The first two writes fail before they reach the gate.
        states[1].fail_next.store(2, Ordering::SeqCst);
        let writer = fake_writer(&states, Tuning::production());
        writer.record(AuditLane::Evidence, entry("failed1", Frontend::Mcp, 1));
        writer.record(AuditLane::Evidence, entry("failed2", Frontend::Mcp, 2));
        assert!(
            wait_until(Duration::from_secs(2), || {
                writer.status().write_failures == 2
            }),
            "the two failing writes were not processed: {:?}",
            writer.status()
        );

        // One entry now blocks inside its write and one waits behind it.
        writer.record(AuditLane::Evidence, entry("stuck", Frontend::Mcp, 3));
        writer.record(AuditLane::Evidence, entry("waiting", Frontend::Mcp, 4));
        assert!(
            wait_until(Duration::from_secs(2), || states[1].inside()),
            "the agent writer never reached its write"
        );
        let report = writer.shutdown(Duration::from_millis(200));
        states[1].release();

        assert!(!report.complete);
        assert_eq!(report.estimated_left, 2);
    }

    /// The spec's constants, in one place.
    #[test]
    fn production_tuning_is_the_specs_numbers() {
        let tuning = Tuning::production();
        assert_eq!(tuning.queue, [1024, 4096, 2048]);
        assert_eq!(
            tuning.cap_bytes,
            [4 * 1024 * 1024, 8 * 1024 * 1024, 8 * 1024 * 1024]
        );
        assert_eq!(tuning.keep, [4, 5, 2]);
        assert_eq!(tuning.recheck, Duration::from_secs(5));
        assert_eq!(tuning.reopen, Duration::from_secs(1));
        assert_eq!(tuning.rotate_retry, Duration::from_secs(60));
        assert_eq!(tuning.warn_every, Duration::from_secs(60));
        assert_eq!(SHUTDOWN_BUDGET, Duration::from_secs(2));
    }

    /// Each stream writes on a thread named for it, and only its own entries.
    #[test]
    fn each_stream_writes_on_its_own_named_thread() {
        let states = FakeState::three();
        let writer = fake_writer(&states, Tuning::production());
        writer.record(AuditLane::Evidence, entry("c", Frontend::Operator, 1));
        writer.record(AuditLane::Evidence, entry("a", Frontend::Mcp, 2));
        writer.record(AuditLane::Routine, entry("r", Frontend::Mcp, 3));
        let report = writer.shutdown(FLUSH_BUDGET);
        assert!(report.complete, "the flush did not finish: {report:?}");

        let mut failures: Vec<String> = Vec::new();
        for (kind, state) in StreamKind::ALL.into_iter().zip(&states) {
            let want = vec![format!("aitm-audit-{}", kind.label())];
            if state.writer_threads() != want {
                failures.push(format!(
                    "{}: left: {:?}, right: {want:?}",
                    kind.label(),
                    state.writer_threads()
                ));
            }
            if state.lines().len() != 1 {
                failures.push(format!(
                    "{}: {} lines written, not 1",
                    kind.label(),
                    state.lines().len()
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

    /// A `Close` syncs the stream's file once and ends its thread; a second
    /// shutdown finds nothing left to wait for.
    #[test]
    fn shutdown_syncs_every_stream_and_is_idempotent() {
        let states = FakeState::three();
        let writer = fake_writer(&states, Tuning::production());
        writer.record(AuditLane::Evidence, entry("c", Frontend::Operator, 1));

        let first = writer.shutdown(FLUSH_BUDGET);
        assert_eq!(
            first,
            ShutdownReport {
                complete: true,
                estimated_left: 0
            }
        );
        let syncs: Vec<usize> = states
            .iter()
            .map(|state| state.syncs.load(Ordering::SeqCst))
            .collect();
        assert_eq!(syncs, [1, 1, 1], "syncs per stream after a shutdown");

        let second = writer.shutdown(FLUSH_BUDGET);
        assert_eq!(
            second,
            ShutdownReport {
                complete: true,
                estimated_left: 0
            }
        );
        let syncs: Vec<usize> = states
            .iter()
            .map(|state| state.syncs.load(Ordering::SeqCst))
            .collect();
        assert_eq!(syncs, [1, 1, 1], "a second shutdown syncs nothing more");
    }

    /// A budget so large that `Instant::now() + budget` would overflow is not a
    /// panic: the deadline simply never comes, and the flush still finishes.
    #[test]
    fn an_enormous_budget_is_not_a_panic() {
        let states = FakeState::three();
        let writer = fake_writer(&states, Tuning::production());
        let report = within(
            Duration::from_secs(5),
            "shutdown with an enormous budget",
            move || writer.shutdown(Duration::MAX),
        );
        assert_eq!(
            report,
            ShutdownReport {
                complete: true,
                estimated_left: 0
            }
        );
    }

    /// A failed write is counted, marks the writer degraded and drops that entry;
    /// the next write that succeeds clears `degraded` and keeps the counter.
    #[test]
    fn a_failed_write_is_counted_and_the_next_success_clears_degraded() {
        let states = FakeState::three();
        states[1].fail_next.store(2, Ordering::SeqCst);
        let writer = fake_writer(&states, Tuning::production());
        assert!(!writer.status().degraded, "healthy at the start");

        writer.record(AuditLane::Evidence, entry("lost1", Frontend::Mcp, 1));
        writer.record(AuditLane::Evidence, entry("lost2", Frontend::Mcp, 2));
        assert!(
            wait_until(Duration::from_secs(2), || {
                let status = writer.status();
                status.write_failures == 2 && status.degraded
            }),
            "two failures and degraded were not reported: {:?}",
            writer.status()
        );

        writer.record(AuditLane::Evidence, entry("kept", Frontend::Mcp, 3));
        assert!(
            wait_until(Duration::from_secs(2), || {
                !writer.status().degraded && states[1].lines().len() == 1
            }),
            "a successful write did not clear degraded: {:?}",
            writer.status()
        );
        let status = writer.status();
        assert_eq!(status.write_failures, 2, "the counter is never reset");
        assert_eq!(status.dropped, 0, "a failed write is not a dropped entry");
        let kept = aitm_ca::audit::entry_to_jsonl(&entry("kept", Frontend::Mcp, 3));
        assert_eq!(states[1].lines(), [kept]);
        assert!(writer.shutdown(FLUSH_BUDGET).complete);
    }

    /// A stream with no open file starts degraded; a stream that ended through
    /// a normal `Close` is closed, not degraded.
    #[test]
    fn degraded_is_a_missing_file_never_a_normal_close() {
        let states = FakeState::three();
        let healthy = fake_writer(&states, Tuning::production());
        assert!(!healthy.status().degraded, "healthy before the close");
        assert!(healthy.shutdown(FLUSH_BUDGET).complete);
        assert_eq!(
            healthy.status(),
            DurableAuditStatus {
                degraded: false,
                dropped: 0,
                write_failures: 0
            },
            "a closed writer"
        );

        let states = FakeState::three();
        let mut specs = Vec::new();
        for (kind, state) in StreamKind::ALL.into_iter().zip(&states) {
            let file: Option<Box<dyn LogFile>> = match kind {
                StreamKind::Agent => None,
                _ => Some(Box::new(FakeFile(state.clone()))),
            };
            specs.push(StreamSpec {
                path: PathBuf::from(format!("/fake/{}.jsonl", kind.label())),
                backend: Box::new(FakeBackend(state.clone())),
                file,
            });
        }
        let specs: [StreamSpec; 3] = match specs.try_into() {
            Ok(specs) => specs,
            Err(_) => panic!("three streams make three specs"),
        };
        let writer = AuditLogWriter::from_specs(specs, Tuning::production()).expect("start");
        assert!(
            writer.status().degraded,
            "a stream with no file starts degraded"
        );
        assert!(
            format!("{writer:?}").contains("AuditLogWriter"),
            "the Debug form names the type"
        );
        assert!(writer.shutdown(FLUSH_BUDGET).complete);
    }

    /// A writer thread that dies marks its stream dead (the writer is degraded),
    /// and every later record is counted as dropped, never blocking or panicking.
    #[test]
    fn a_panicking_writer_marks_its_stream_dead_and_later_records_are_dropped() {
        let states = FakeState::three();
        states[1].panic_on_write.store(true, Ordering::SeqCst);
        let writer = fake_writer(&states, Tuning::production());

        writer.record(AuditLane::Evidence, entry("boom", Frontend::Mcp, 1));
        assert!(
            wait_until(Duration::from_secs(2), || writer.status().degraded),
            "a dead writer thread did not degrade the writer"
        );
        assert_eq!(writer.status().dropped, 0, "nothing dropped yet");

        writer.record(AuditLane::Evidence, entry("after", Frontend::Mcp, 2));
        assert_eq!(writer.status().dropped, 1, "a record after the death");
        assert!(
            writer.status().degraded,
            "the writer stays degraded once a thread died"
        );
        // The other streams still work.
        writer.record(AuditLane::Evidence, entry("fine", Frontend::Operator, 3));
        let report = writer.shutdown(FLUSH_BUDGET);
        assert!(report.complete, "a dead thread is finished: {report:?}");
        assert_eq!(states[0].lines().len(), 1, "the control stream still wrote");
    }
}
