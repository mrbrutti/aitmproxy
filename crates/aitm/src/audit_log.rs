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
//!
//! [`start`] is the boot. It resolves the `mcp.audit_log` setting (`Off` starts
//! nothing and creates nothing), refuses a configuration in which a stream file
//! would be the CA audit log, opens each stream under the boot policy (a path the
//! operator named that cannot be used fails the boot; the default path starts
//! degraded and says so once per stream), registers every secret the process
//! holds with the writer's [`SecretRegistry`], attaches the writer to the shared
//! ring and says one line. The [`AuditLogHandle`] it returns reaches the running
//! writer: its registry, its health and its shutdown.
//!
//! The writer does not trust an entry. Each stream's thread puts every entry
//! through the field pipeline of the `pipeline` module just before it renders the
//! line: each text field is bounded, scrubbed, masked with the registry (as it
//! stands when the line is written, so a secret registered while the entry
//! waited is masked in it), stripped of control characters and cut to its cap. An
//! entry the call path produced passes through unchanged.

use std::fmt;
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use aitm_core::{
    AuditEntry, AuditLane, AuditLogSetting, AuditRing, Config, DurableAudit, DurableAuditStatus,
    Frontend, McpTransport,
};
use tracing::{info, warn};

mod jsonscan;
mod pipeline;
mod registry;

pub use registry::{Registration, SecretRegistry};

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
fn stream_for(lane: AuditLane, origin: Frontend) -> StreamKind {
    match lane {
        AuditLane::Routine => StreamKind::Reads,
        AuditLane::Evidence if origin.is_trusted_control() => StreamKind::Control,
        AuditLane::Evidence => StreamKind::Agent,
    }
}

/// Schema version carried by every `start` marker (a `gap` marker has no
/// `schema` key: it always follows a `start` marker in its file). A reader that
/// sees a higher number than it knows should stop.
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
/// [`FsFile`]; the writer's tests substitute a fake that records lines or blocks.
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
fn io_refusal(path: &Path, reason: impl fmt::Display) -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!("audit log {}: {reason}", path.display()),
    )
}

/// `source` with the path and what was being attempted put in front of it.
fn io_context(path: &Path, what: impl fmt::Display, source: io::Error) -> io::Error {
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
        return Err(io_refusal(
            path,
            "the path is a symbolic link; the writer never writes through one",
        ));
    }
    if !kind.is_file() {
        return Err(io_refusal(
            path,
            "the path is not a regular file (a directory, FIFO, socket or device); it is not opened",
        ));
    }
    let links = hard_links(meta);
    if links > 1 {
        return Err(io_refusal(
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
        .ok_or_else(|| io_refusal(path, "the path has no parent directory"))?;
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(PRIVATE_DIR_MODE);
    }
    builder.create(parent).map_err(|source| {
        io_context(
            path,
            format_args!("cannot create the parent directory {}", parent.display()),
            source,
        )
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let meta = fs::metadata(parent).map_err(|source| {
            io_context(
                path,
                format_args!("cannot inspect the parent directory {}", parent.display()),
                source,
            )
        })?;
        let mode = meta.mode();
        if mode & 0o002 != 0 && mode & 0o1000 == 0 {
            return Err(io_refusal(
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
        io_context(path, what, source)
    })
}

/// Step 3's re-check: the file at `path` now is the file that was opened
/// (`opened` is the handle's own metadata). A path swapped for another file or a
/// symbolic link since the first look is refused. Where the platform has no
/// identity both sides read `None` and the check passes.
fn confirm_same_file(path: &Path, opened: &Metadata) -> io::Result<()> {
    let now = fs::symlink_metadata(path).map_err(|source| {
        io_context(path, "cannot re-inspect the path after opening it", source)
    })?;
    if file_id(&now) != file_id(opened) {
        return Err(io_refusal(
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
            io_context(
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
        Err(source) => return Err(io_context(path, "cannot inspect the path", source)),
    };
    let file = open_private(path, create)?;
    let meta = file
        .metadata()
        .map_err(|source| io_context(path, "cannot inspect the opened file", source))?;
    refuse_hostile_file(path, &meta)?;
    confirm_same_file(path, &meta)?;
    restrict_to_owner(path, &file, &meta)?;
    let mut out = FsFile {
        file,
        size: meta.len(),
        id: file_id(&meta),
    };
    out.write_start(stream)
        .map_err(|source| io_context(path, "cannot write the start marker", source))?;
    Ok(out)
}

/// How long `main.rs` gives the writer to flush at exit (spec Design 7). A
/// writer that has not finished by then is left behind and the process exits
/// regardless: a shutdown never hangs.
pub const SHUTDOWN_BUDGET: Duration = Duration::from_secs(2);

/// The pause between two tries of a loop that must not block (a full queue
/// that has to take its `Close`, a thread that has not finished yet).
const POLL: Duration = Duration::from_millis(1);

/// What a re-check of a stream's path found when it compared the path with the
/// file the stream holds open (spec Design 8). Without it the writer would keep
/// appending to an unlinked inode and the lines would vanish silently.
#[derive(Debug, PartialEq, Eq)]
enum Recheck {
    /// The path still names the open file.
    Same,
    /// Nothing is at the path, or its directory is gone: the operator removed
    /// the file. The writer reopens at once.
    Gone,
    /// A different regular file is at the path (an external `logrotate` renamed
    /// the open one). The writer reopens at once.
    Replaced,
    /// A symbolic link or a file that is not a regular file is at the path, or the
    /// path cannot be inspected. The writer drops its handle and writes nothing;
    /// the failed entries report this reason (the path is put in front of it).
    Refused(String),
}

/// How a stream's thread reaches its file: open it, rotate it, and check that
/// its path still names it. The real one is [`FsBackend`]; tests substitute a
/// fake that records lines, blocks or fails. It is `Send` because the thread
/// that uses it owns it.
trait Backend: Send {
    /// Opens `path` for append, ready to write (a `start` marker already in it).
    /// The real one is [`preflight`].
    fn open(&mut self, path: &Path, stream: StreamKind) -> io::Result<Box<dyn LogFile>>;

    /// Moves the full active file aside, keeps `keep` rotated files and opens a
    /// fresh one (a `start` marker already in it). The caller has synced the
    /// old file. A backend that never rotates (a test double) keeps this
    /// default, which refuses.
    fn rotate(
        &mut self,
        path: &Path,
        stream: StreamKind,
        keep: usize,
    ) -> io::Result<Box<dyn LogFile>> {
        let _ = (path, stream, keep);
        Err(io::ErrorKind::Unsupported.into())
    }

    /// Whether `path` still names `file`. A backend with no path to compare (a
    /// test double) keeps this default, which says it does.
    fn recheck(&mut self, path: &Path, file: &dyn LogFile) -> Recheck {
        let _ = (path, file);
        Recheck::Same
    }
}

/// The name of the `n`th rotated file of the stream file `path`: its whole file
/// name with `.n` appended (`audit.agent.jsonl` gives `audit.agent.jsonl.1`).
fn rotated_path(path: &Path, n: usize) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(format!(".{n}"));
    PathBuf::from(name)
}

/// Renames `from` to `to`. A `from` that is not there is skipped: a rotation
/// that stopped half way (or a file an operator removed) leaves gaps in the
/// numbering, and the files after the gap still move.
fn move_aside(from: &Path, to: &Path) -> io::Result<()> {
    match fs::rename(from, to) {
        Err(source) if source.kind() != io::ErrorKind::NotFound => Err(io_context(
            from,
            format_args!("cannot rename it to {}", to.display()),
            source,
        )),
        _ => Ok(()),
    }
}

/// The names half of a rotation (spec Design 8): frees the slot `F.keep` and
/// shifts every rotated file up by one, then moves the active file `F` to `F.1`.
/// Only `F.keep`, the oldest rotated file, is ever deleted, and only when it is
/// a regular file: anything else there (a symbolic link, a directory, a FIFO)
/// stops the rotation before it has changed a name, so nothing is deleted or
/// renamed. Every other step is a rename into a slot the step before it just
/// emptied, so no file is overwritten. Nothing of another stream is touched.
fn shift_rotated_files(path: &Path, keep: usize) -> io::Result<()> {
    // The active file is never the file that is deleted: keep at least one.
    let keep = keep.max(1);
    let oldest = rotated_path(path, keep);
    match fs::symlink_metadata(&oldest) {
        Ok(meta) if meta.file_type().is_file() => fs::remove_file(&oldest).map_err(|source| {
            io_context(&oldest, "cannot delete the oldest rotated file", source)
        })?,
        Ok(_) => {
            return Err(io_refusal(
                &oldest,
                "the oldest rotated slot is not a regular file; rotation never deletes one",
            ))
        }
        Err(source) if source.kind() == io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(io_context(
                &oldest,
                "cannot inspect the oldest rotated slot",
                source,
            ))
        }
    }
    for n in (1..keep).rev() {
        move_aside(&rotated_path(path, n), &rotated_path(path, n + 1))?;
    }
    move_aside(path, &rotated_path(path, 1))
}

/// The real [`Backend`]: files on disk, opened and hardened by [`preflight`].
struct FsBackend;

impl Backend for FsBackend {
    fn open(&mut self, path: &Path, stream: StreamKind) -> io::Result<Box<dyn LogFile>> {
        let file: Box<dyn LogFile> = Box::new(preflight(path, stream)?);
        Ok(file)
    }

    /// Shifts the names ([`shift_rotated_files`]), then creates the new active
    /// file exactly as the first boot does: [`preflight`] makes it with
    /// `create_new` (mode `0600`, refusing a name someone planted in the
    /// meantime) and writes its `start` marker.
    fn rotate(
        &mut self,
        path: &Path,
        stream: StreamKind,
        keep: usize,
    ) -> io::Result<Box<dyn LogFile>> {
        shift_rotated_files(path, keep)?;
        let file: Box<dyn LogFile> = Box::new(preflight(path, stream)?);
        Ok(file)
    }

    /// Compares what is at `path` now, without following a link, with the open
    /// `file` (spec Design 8). Nothing there, or no directory to hold it, is
    /// [`Recheck::Gone`]; a symbolic link, a directory, a FIFO, a socket or a
    /// device is refused, as is a path that cannot be inspected; a regular file
    /// is the same file when its device and inode are the open file's and
    /// [`Recheck::Replaced`] when they are not. A file with no identity (a test
    /// double, or a platform without one) is taken to be the same. Nothing is
    /// opened: a FIFO at the path cannot block the check.
    fn recheck(&mut self, path: &Path, file: &dyn LogFile) -> Recheck {
        let meta = match fs::symlink_metadata(path) {
            Ok(meta) => meta,
            Err(source) if source.kind() == io::ErrorKind::NotFound => return Recheck::Gone,
            Err(source) => {
                return Recheck::Refused(format!("cannot inspect the path: {source}"));
            }
        };
        let kind = meta.file_type();
        if kind.is_symlink() {
            return Recheck::Refused(
                "the path is now a symbolic link; the writer never writes through one".to_string(),
            );
        }
        if !kind.is_file() {
            return Recheck::Refused(
                "the path is now not a regular file (a directory, FIFO, socket or device); it is not opened"
                    .to_string(),
            );
        }
        match (file.id(), file_id(&meta)) {
            (Some(open), Some(named)) if open != named => Recheck::Replaced,
            _ => Recheck::Same,
        }
    }
}

/// Everything one stream's thread owns: where its file is, how to reach it, and
/// the file itself. `file` is `None` when the stream could not be opened at boot
/// and is to be retried; such a stream starts degraded.
struct StreamSpec {
    path: PathBuf,
    backend: Box<dyn Backend>,
    file: Option<Box<dyn LogFile>>,
}

/// The writer's numbers and intervals, per stream where they differ. Production
/// uses [`Tuning::production`]; tests shorten an interval or a cap instead of
/// sleeping for it.
#[derive(Debug, Clone)]
#[doc(hidden)]
pub struct Tuning {
    /// Entries each stream's queue holds, indexed by [`StreamKind::index`].
    pub(crate) queue: [usize; 3],
    /// Size at which each stream's file rotates.
    pub(crate) cap_bytes: [u64; 3],
    /// Rotated files each stream keeps.
    pub(crate) keep: [usize; 3],
    /// How often a stream checks that its path still names its file.
    pub(crate) recheck: Duration,
    /// How soon a failed stream tries to reopen its file.
    pub(crate) reopen: Duration,
    /// How soon a stream retries a rotation that failed.
    pub(crate) rotate_retry: Duration,
    /// How often a repeated failure is logged again.
    pub(crate) warn_every: Duration,
}

impl Tuning {
    /// The spec's constants: the per-stream limits of [`StreamKind`], a re-check
    /// every 5 s, a reopen after 1 s, a rotation retry after 60 s and one log
    /// line per failure kind per 60 s.
    pub fn production() -> Tuning {
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

    /// These numbers with every stream's size cap set to `bytes`: a test that
    /// wants a file to rotate after a few lines asks for a small one. Nothing
    /// else changes.
    #[doc(hidden)]
    pub fn with_cap_bytes(self, bytes: u64) -> Tuning {
        Tuning {
            cap_bytes: [bytes; 3],
            ..self
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

/// What a stream's file does not hold yet: the entries the queue refused and the
/// entries a failed write lost, with the span of their `at`. The producers add
/// to it and the stream's thread takes it, so it sits behind a lock that only
/// ever guards a few integer operations.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct GapState {
    /// Entries refused by a full queue (or by a stream that is closing or gone).
    dropped: u64,
    /// Entries lost to a write error.
    failed: u64,
    /// The `at` (epoch milliseconds) of the earliest lost entry.
    from: Option<i64>,
    /// The `at` (epoch milliseconds) of the latest lost entry.
    to: Option<i64>,
}

impl GapState {
    /// Stretches the span to cover `at_ms`, whichever side it falls on.
    fn widen(&mut self, at_ms: i64) {
        self.from = Some(self.from.map_or(at_ms, |from| from.min(at_ms)));
        self.to = Some(self.to.map_or(at_ms, |to| to.max(at_ms)));
    }

    /// An entry refused, whose `at` was `at_ms`.
    fn note_drop(&mut self, at_ms: i64) {
        self.dropped = self.dropped.saturating_add(1);
        self.widen(at_ms);
    }

    /// An entry lost to a write error, whose `at` was `at_ms`.
    fn note_fail(&mut self, at_ms: i64) {
        self.failed = self.failed.saturating_add(1);
        self.widen(at_ms);
    }

    /// Adds `other`, a gap that was taken and could not be written, back in.
    fn merge(&mut self, other: GapState) {
        self.dropped = self.dropped.saturating_add(other.dropped);
        self.failed = self.failed.saturating_add(other.failed);
        if let Some(from) = other.from {
            self.widen(from);
        }
        if let Some(to) = other.to {
            self.widen(to);
        }
    }

    /// The pending gap, leaving none behind; `None` when nothing is pending.
    fn take(&mut self) -> Option<GapState> {
        if self.dropped == 0 && self.failed == 0 {
            return None;
        }
        Some(std::mem::take(self))
    }
}

/// The `gap` marker line (no newline), written before the next entry that gets
/// written after a hole: `from` and `to` are the `at` of the first and last lost
/// entry, `at` is when the marker was written. The keys are in alphabetical
/// order, as in [`start_marker_line`].
fn gap_marker_line(now_ms: i64, from: i64, to: i64, dropped: u64, failed: u64) -> String {
    serde_json::json!({
        "at": now_ms,
        "dropped": dropped,
        "failed": failed,
        "from": from,
        "marker": "gap",
        "to": to,
    })
    .to_string()
}

/// Lets a repeated warning through once per interval, so that a disk that fails
/// every entry costs one log line a minute and not one per entry. Each stream
/// has its own, owned by its thread.
struct WarnThrottle {
    every: Duration,
    /// When a line was last let through; `None` before the first.
    last: Option<Instant>,
    /// Lines held back since then.
    suppressed: u64,
}

impl WarnThrottle {
    fn new(every: Duration) -> WarnThrottle {
        WarnThrottle {
            every,
            last: None,
            suppressed: 0,
        }
    }

    /// `Some(n)` when a line may be logged at `now`, `n` being how many were held
    /// back since the previous one; `None` when this one is held back. The first
    /// call always passes. `now` is a parameter so that a test needs no clock.
    fn admit(&mut self, now: Instant) -> Option<u64> {
        let due = self
            .last
            .is_none_or(|last| now.saturating_duration_since(last) >= self.every);
        if due {
            self.last = Some(now);
            Some(std::mem::take(&mut self.suppressed))
        } else {
            self.suppressed = self.suppressed.saturating_add(1);
            None
        }
    }
}

/// A message to a stream's thread.
enum Msg {
    /// One entry to write.
    Entry(AuditEntry),
    /// Everything queued before this has been written: sync the file and exit.
    Close,
}

/// One stream's counters and flags, shared between the producers and the
/// stream's thread, and the registry the thread masks with. Atomics, and the one
/// lock of `gap`, which guards a few integer operations and is never held across
/// I/O: a producer never waits on a thread that is blocked in file I/O.
#[derive(Default)]
struct StreamShared {
    /// The writer's registry, also held by the writer and its handle. The thread
    /// masks every field with it when it writes the line, not when the entry was
    /// queued, so a secret registered while the entry waited is masked in it. A
    /// default is an empty registry, which masks nothing.
    registry: Arc<SecretRegistry>,
    /// Entries refused: the queue was full, the stream is closing, or the thread
    /// is gone.
    dropped: AtomicU64,
    /// Entries the thread could not write.
    write_failures: AtomicU64,
    /// The most recent write failed (or there is no file); the next success clears it.
    degraded: AtomicBool,
    /// The thread ended through a `Close`.
    closed: AtomicBool,
    /// The thread ended any other way: it panicked, or every sender is gone.
    dead: AtomicBool,
    /// A rotation failed and none has succeeded since: the file grows past its
    /// cap, and past twice its cap lines are refused (spec Design 8). A flag of
    /// its own, not `degraded`, because a line that is still written clears
    /// `degraded` and the wedge outlives that line.
    rotation_wedged: AtomicBool,
    /// Entries accepted by `record` and not yet written.
    queued: AtomicUsize,
    /// A shutdown has begun: `record` refuses every entry from now on, so none
    /// can be queued behind the `Close` (which would never be written). Set
    /// before the `Close` is sent and never cleared.
    closing: AtomicBool,
    /// `record` calls between announcing themselves and the end of their
    /// `try_send`. A shutdown that has set `closing` waits for this to reach
    /// zero before it sends the `Close`: a call that read `closing` as false has
    /// announced itself first, so the shutdown sees it and its entry is queued
    /// ahead of the `Close`. Every operation on this and on `closing` that takes
    /// part in that hand-shake is `SeqCst`.
    in_flight: AtomicUsize,
    /// The hole in this stream's file that is not yet written as a `gap` line.
    gap: Mutex<GapState>,
}

impl StreamShared {
    /// The pending gap. A lock that a panicking thread poisoned still holds
    /// plain integers, so it is used as it is.
    fn lock_gap(&self) -> MutexGuard<'_, GapState> {
        self.gap.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Takes back an entry `record` counted as queued but the queue refused:
    /// it is dropped, and its `at` goes into the pending gap.
    fn refuse(&self, at_ms: i64) {
        self.queued.fetch_sub(1, Ordering::Relaxed);
        self.dropped.fetch_add(1, Ordering::Relaxed);
        self.lock_gap().note_drop(at_ms);
    }
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

impl StreamEnds {
    /// Queues `entry` unless the stream is closing, its queue is full or its
    /// thread is gone, and says whether it did. Never blocks and does no I/O.
    ///
    /// The cheap check comes first so that a flood arriving after a shutdown
    /// began does not keep `in_flight` from reaching zero. The second check,
    /// after announcing the call, is the one that matters: see
    /// [`StreamShared::in_flight`].
    fn offer(&self, entry: AuditEntry) -> bool {
        self.offer_after_check(entry, || {})
    }

    /// [`offer`](Self::offer) that runs `between` once the entry has passed
    /// every check and before it is sent: the one point at which a shutdown can
    /// begin without the entry knowing. The test
    /// `a_record_caught_by_a_shutdown_mid_call_is_written_not_stranded` holds a call
    /// there; `offer` passes nothing.
    fn offer_after_check(&self, entry: AuditEntry, between: impl FnOnce()) -> bool {
        let shared = &self.shared;
        if shared.closing.load(Ordering::SeqCst) {
            return false;
        }
        shared.in_flight.fetch_add(1, Ordering::SeqCst);
        let accepted = if shared.closing.load(Ordering::SeqCst) {
            false
        } else {
            between();
            self.tx.try_send(Msg::Entry(entry)).is_ok()
        };
        shared.in_flight.fetch_sub(1, Ordering::SeqCst);
        accepted
    }
}

/// The body of a stream's thread: writes what it is sent, in order, until a
/// `Close` (mark any hole, sync, mark closed, exit) or until every sender is
/// gone.
fn run_stream(
    rx: Receiver<Msg>,
    spec: StreamSpec,
    shared: &StreamShared,
    kind: StreamKind,
    tuning: &Tuning,
) {
    let mut writer = StreamWriter::new(kind, spec, shared, tuning);
    while let Ok(message) = rx.recv() {
        match message {
            Msg::Entry(entry) => {
                writer.write_entry(&entry);
                shared.queued.fetch_sub(1, Ordering::Relaxed);
            }
            Msg::Close => {
                writer.finish();
                shared.closed.store(true, Ordering::Release);
                return;
            }
        }
    }
}

/// The `gap` marker line that reports `gap`, stamped now. A hole with no span
/// recorded (nothing sets one without the other) reads as now.
fn marker_for(gap: &GapState) -> String {
    let now_ms = unix_ms(SystemTime::now());
    gap_marker_line(
        now_ms,
        gap.from.unwrap_or(now_ms),
        gap.to.unwrap_or(now_ms),
        gap.dropped,
        gap.failed,
    )
}

/// An error with the kind and the text of `error`, for the one that has to be
/// kept as well as returned (an `io::Error` is not `Clone`).
fn copy_error(error: &io::Error) -> io::Error {
    io::Error::new(error.kind(), error.to_string())
}

/// What `write_through` did with the line it was given.
#[derive(Debug, PartialEq, Eq)]
enum Placed {
    /// The line, and the pending `gap` marker before it if there was one, are in
    /// the file.
    Written,
    /// Nothing was written: a rotation is wedged and the file is at its ceiling.
    HeldBack,
}

/// What one stream's thread owns while it runs: its file and the policy for
/// when the file goes wrong (spec Design 9) and when it is full (spec Design 8).
/// Best effort and one attempt per entry: a failed write loses that entry, closes
/// the file and marks the hole; the next entry reopens it if the reopen interval
/// has passed and fails fast otherwise, so a broken disk costs one `open` an
/// interval, not one per entry. A file at its cap is rotated before the line that
/// would overflow it is written, and a rotation that fails costs no line until the
/// file is at twice its cap: from there lines are refused, and counted, for as long
/// as the rotation stays wedged.
struct StreamWriter<'a> {
    kind: StreamKind,
    spec: StreamSpec,
    shared: &'a StreamShared,
    /// How long after the last try at opening the file the next may begin.
    reopen: Duration,
    /// When the file was last closed by an error, or an open of it last failed.
    /// A stream that arrived without a file counts boot as its last attempt.
    last_open_attempt: Instant,
    /// How long after the path was last compared with the open file it is
    /// compared again.
    recheck: Duration,
    /// When the path was last compared with the open file, by the interval or by
    /// a rotation about to begin. Starts when the thread does, so the first
    /// check by the interval comes one interval after boot (the preflight has
    /// just looked at the path).
    last_recheck: Instant,
    /// Size past which the file is rotated.
    cap_bytes: u64,
    /// Rotated files kept.
    keep: usize,
    /// How long after a rotation failed the next try may begin.
    rotate_retry: Duration,
    /// When a rotation last failed; `None` after a success and at boot.
    last_rotation_failure: Option<Instant>,
    /// Lets one failure in an interval reach the log, a failed rotation included.
    throttle: WarnThrottle,
    /// Entries lost since the last time the stream recovered.
    failures: u64,
    /// The latest real error of a write or an open, which an entry that fails
    /// fast reports: it made no attempt of its own, so the reason the stream is
    /// down is the one the last attempt found.
    last_error: io::Error,
}

impl<'a> StreamWriter<'a> {
    fn new(
        kind: StreamKind,
        spec: StreamSpec,
        shared: &'a StreamShared,
        tuning: &Tuning,
    ) -> StreamWriter<'a> {
        StreamWriter {
            kind,
            spec,
            shared,
            reopen: tuning.reopen,
            last_open_attempt: Instant::now(),
            recheck: tuning.recheck,
            last_recheck: Instant::now(),
            cap_bytes: tuning.cap_bytes[kind.index()],
            keep: tuning.keep[kind.index()],
            rotate_retry: tuning.rotate_retry,
            last_rotation_failure: None,
            throttle: WarnThrottle::new(tuning.warn_every),
            failures: 0,
            last_error: io::Error::new(io::ErrorKind::NotConnected, "the stream has no open file"),
        }
    }

    /// Writes one entry as its JSONL line (the entry after the field pipeline of
    /// `pipeline`, so no secret and no control character reaches the file),
    /// behind the pending `gap` marker if there is one. A failure is counted,
    /// marks the stream degraded and loses this entry; the next write that
    /// succeeds clears `degraded`.
    fn write_entry(&mut self, entry: &AuditEntry) {
        let line = pipeline::render_line(entry, &self.shared.registry);
        match self.try_write(&line) {
            Ok(Placed::Written) => self.succeeded(),
            Ok(Placed::HeldBack) => self.held_back(entry.at_millis()),
            Err(error) => self.failed(entry.at_millis(), &error),
        }
    }

    /// Reopens the file when there is none and it is time; with a file, checks
    /// that the path still names it when the re-check interval has passed. Then
    /// writes. A write that fails closes the file and starts the reopen interval.
    fn try_write(&mut self, line: &str) -> io::Result<Placed> {
        if self.spec.file.is_none() {
            self.reopen_file()?;
        } else if self.last_recheck.elapsed() >= self.recheck {
            self.recheck_path();
            if self.spec.file.is_none() {
                return Err(copy_error(&self.last_error));
            }
        }
        let written = self.write_through(Some(line));
        if let Err(error) = &written {
            self.spec.file = None;
            self.last_open_attempt = Instant::now();
            self.last_error = copy_error(error);
        }
        written
    }

    /// Opens the file if the reopen interval has passed since the last attempt;
    /// inside it, fails without calling the backend. A failed open starts the
    /// interval again.
    fn reopen_file(&mut self) -> io::Result<()> {
        if self.last_open_attempt.elapsed() < self.reopen {
            return Err(copy_error(&self.last_error));
        }
        self.open_file()
    }

    /// Opens the file now, whatever the reopen interval says. A failure starts
    /// the interval again and is what an entry that fails fast reports. A file
    /// opened afresh ends a wedge: it is not the one a rotation could not move
    /// (a rotation that stopped half way is repaired by this, and the next one to
    /// fail wedges the stream again).
    fn open_file(&mut self) -> io::Result<()> {
        match self.spec.backend.open(&self.spec.path, self.kind) {
            Ok(file) => {
                self.spec.file = Some(file);
                self.last_rotation_failure = None;
                self.shared.rotation_wedged.store(false, Ordering::Release);
                Ok(())
            }
            Err(error) => {
                self.last_open_attempt = Instant::now();
                self.last_error = copy_error(&error);
                Err(error)
            }
        }
    }

    /// Compares the path with the open file and acts on the answer (spec
    /// Design 8), and says whether the file is still the one the path names.
    ///
    /// - `Same`: nothing changes.
    /// - `Gone` or `Replaced`: the handle names an inode the path no longer does,
    ///   so it is dropped and the path is opened afresh at once, through the
    ///   backend's `open` (the preflight: it recreates the directory `0700` and
    ///   writes a `start` marker). A reopen that fails leaves no file and starts
    ///   the reopen interval, like any failed open.
    /// - `Refused`: the handle is dropped and nothing is opened. The reopen
    ///   interval starts, so the entries that follow fail fast with the reason.
    ///
    /// Whatever is found, the check has been made: the interval starts again.
    /// `false` also when the stream has no file to compare.
    fn recheck_path(&mut self) -> bool {
        let Some(file) = self.spec.file.as_deref() else {
            return false;
        };
        let answer = self.spec.backend.recheck(&self.spec.path, file);
        self.last_recheck = Instant::now();
        match answer {
            Recheck::Same => true,
            Recheck::Gone | Recheck::Replaced => {
                self.spec.file = None;
                // A failed open is already recorded by `open_file` (the reason,
                // the interval); the caller sees a stream with no file.
                let _ = self.open_file();
                false
            }
            Recheck::Refused(reason) => {
                self.spec.file = None;
                self.last_open_attempt = Instant::now();
                self.last_error = io_refusal(&self.spec.path, reason);
                false
            }
        }
    }

    /// Writes the pending `gap` marker, if any, and then `line`, to the open
    /// file, which is rotated first when they would not fit under the cap. With
    /// a marker and no line, writes the marker alone; with neither, does nothing
    /// and leaves the file untouched.
    ///
    /// A marker whose own write fails goes back into the pending gap, so the
    /// hole is still reported by the next write that succeeds, and the error is
    /// returned for the entry to be counted as failed.
    ///
    /// While a rotation is wedged nothing is written that would take the file past
    /// twice its cap ([`Placed::HeldBack`]); the pending marker stays pending.
    fn write_through(&mut self, line: Option<&str>) -> io::Result<Placed> {
        let shared = self.shared;
        // The guard lives for this statement only: the lock is never held across I/O.
        let pending = shared.lock_gap().take();
        let marker = pending.as_ref().map(marker_for);
        let incoming = marker.as_ref().map_or(0, |marker| marker.len() + 1)
            + line.map_or(0, |line| line.len() + 1);
        if incoming == 0 {
            return Ok(Placed::Written);
        }
        self.rotate_if_due(incoming as u64);
        let Some(file) = self.spec.file.as_ref() else {
            if let Some(gap) = pending {
                shared.lock_gap().merge(gap);
            }
            return Err(copy_error(&self.last_error));
        };
        if self.past_ceiling(file.size(), incoming as u64) {
            if let Some(gap) = pending {
                shared.lock_gap().merge(gap);
            }
            return Ok(Placed::HeldBack);
        }
        let Some(file) = self.spec.file.as_mut() else {
            return Err(copy_error(&self.last_error));
        };
        if let Some(marker) = marker {
            if let Err(error) = file.append_line(&marker) {
                if let Some(gap) = pending {
                    shared.lock_gap().merge(gap);
                }
                return Err(error);
            }
        }
        match line {
            Some(line) => file.append_line(line).map(|()| Placed::Written),
            None => Ok(Placed::Written),
        }
    }

    /// Whether `incoming` more bytes would take a file of `size` bytes past the
    /// ceiling: twice its cap, enforced only while a rotation is wedged (a file
    /// that rotates is bounded by its cap and its rotated files, and a rotation
    /// that has not failed has no reason to be doubted). An empty file takes
    /// whatever comes, as `rotate_if_due` does: a line bigger than the ceiling is
    /// the only thing it would hold.
    fn past_ceiling(&self, size: u64, incoming: u64) -> bool {
        self.last_rotation_failure.is_some()
            && size > 0
            && size.saturating_add(incoming) > self.cap_bytes.saturating_mul(2)
    }

    /// Rotates the file when it holds something and `incoming` more bytes would
    /// take it past the cap (so an oversized file at boot rotates on its first
    /// write, and a line larger than the cap lands in a fresh file), unless a
    /// rotation failed less than `rotate_retry` ago. At most once per call.
    ///
    /// A success replaces the file: the line is then written to the new one. A
    /// failure keeps the old file, which the line is written to all the same (the
    /// cap is soft while rotation fails, up to the ceiling of twice the cap that
    /// `write_through` holds), starts the retry interval, marks the stream wedged
    /// and logs through the stream's throttle. It is not a write failure.
    ///
    /// The path is checked before every rotation (spec Design 8): renaming
    /// whatever is at the path, when it is not the file the stream has been
    /// writing, would move somebody else's file aside and call it ours. When the
    /// check finds the file changed, the stream reopens (or fails the entry, or
    /// has no file) instead of rotating: a file just opened is not the full one.
    fn rotate_if_due(&mut self, incoming: u64) {
        let Some(file) = self.spec.file.as_ref() else {
            return;
        };
        let size = file.size();
        if size == 0 || size.saturating_add(incoming) <= self.cap_bytes {
            return;
        }
        let now = Instant::now();
        let waiting = self
            .last_rotation_failure
            .is_some_and(|failed_at| now.saturating_duration_since(failed_at) < self.rotate_retry);
        if waiting {
            return;
        }
        if !self.recheck_path() {
            return;
        }
        let Some(file) = self.spec.file.as_mut() else {
            return;
        };
        // What was written is on the device before the file is renamed. Best
        // effort, as at close: a failed sync leaves nothing else to try.
        let _ = file.sync();
        match self
            .spec
            .backend
            .rotate(&self.spec.path, self.kind, self.keep)
        {
            Ok(fresh) => {
                self.spec.file = Some(fresh);
                self.last_rotation_failure = None;
                self.shared.rotation_wedged.store(false, Ordering::Release);
            }
            Err(error) => {
                self.last_rotation_failure = Some(now);
                self.shared.rotation_wedged.store(true, Ordering::Release);
                if let Some(suppressed) = self.throttle.admit(now) {
                    // The path and the error, never a field of the entry.
                    warn!(
                        target: "aitm::audit",
                        stream = self.kind.label(),
                        path = %self.spec.path.display(),
                        error_kind = ?error.kind(),
                        error = %error,
                        suppressed,
                        "an audit log rotation failed; lines go to the current file, over its size cap and up to twice it (then they are refused), and the rotation is retried later"
                    );
                }
            }
        }
    }

    /// Ends the stream at a `Close`, once everything queued before it has been
    /// written: marks a hole that nothing was written after (a line refused or
    /// lost late, with no entry behind it to carry the marker), then syncs.
    /// The marker is best effort and is not an entry: when it cannot be written
    /// (or the stream has no file) the hole is left to the live counters and
    /// nothing is counted again.
    fn finish(&mut self) {
        if self.spec.file.is_some() {
            // A marker held back by the ceiling stays with the counters.
            let _ = self.write_through(None);
        }
        if let Some(file) = self.spec.file.as_mut() {
            // A failed sync leaves nothing further to try at exit.
            let _ = file.sync();
        }
    }

    /// The entry written at `at_ms` was lost to `error`.
    fn failed(&mut self, at_ms: i64, error: &io::Error) {
        let shared = self.shared;
        shared.degraded.store(true, Ordering::Release);
        shared.write_failures.fetch_add(1, Ordering::Relaxed);
        shared.lock_gap().note_fail(at_ms);
        self.failures = self.failures.saturating_add(1);
        if let Some(suppressed) = self.throttle.admit(Instant::now()) {
            // The path and the error (our own refusals name the path and the
            // reason; the system's name the cause), never a field of the entry.
            warn!(
                target: "aitm::audit",
                stream = self.kind.label(),
                path = %self.spec.path.display(),
                error_kind = ?error.kind(),
                error = %error,
                suppressed,
                "an audit log entry was lost to a write error; the stream retries"
            );
        }
    }

    /// The entry written at `at_ms` was refused: the rotation is wedged and the
    /// file is at its ceiling. It counts as dropped and goes into the pending
    /// `gap`, so the marker says so when a rotation succeeds; it is never written.
    fn held_back(&mut self, at_ms: i64) {
        self.shared.dropped.fetch_add(1, Ordering::Relaxed);
        self.shared.lock_gap().note_drop(at_ms);
    }

    /// An entry was written: the first one after a failure ends the degraded
    /// state and says so once.
    fn succeeded(&mut self) {
        if self.shared.degraded.swap(false, Ordering::AcqRel) {
            info!(
                target: "aitm::audit",
                stream = self.kind.label(),
                path = %self.spec.path.display(),
                failures = self.failures,
                "audit log writes recovered"
            );
            self.failures = 0;
        }
    }
}

/// Starts one stream's thread, named `aitm-audit-<label>`, with a queue of
/// `capacity` entries, masking with `registry`.
fn spawn_stream(
    kind: StreamKind,
    spec: StreamSpec,
    tuning: &Tuning,
    registry: &Arc<SecretRegistry>,
) -> io::Result<(StreamEnds, JoinHandle<()>)> {
    let (tx, rx) = sync_channel(tuning.queue[kind.index()]);
    let shared = Arc::new(StreamShared {
        registry: Arc::clone(registry),
        ..StreamShared::default()
    });
    shared
        .degraded
        .store(spec.file.is_none(), Ordering::Relaxed);
    let thread_shared = Arc::clone(&shared);
    let tuning = tuning.clone();
    let handle = thread::Builder::new()
        .name(format!("aitm-audit-{}", kind.label()))
        .spawn(move || {
            // Declared first, so it drops last: when this stream reads as dead
            // its receiver is already gone, and the next record counts as dropped.
            let _guard = DeadGuard(&thread_shared);
            run_stream(rx, spec, &thread_shared, kind, &tuning);
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
struct AuditLogWriter {
    streams: [StreamEnds; 3],
    /// The streams' threads until a shutdown takes them, so `shutdown` works
    /// through `&self`.
    threads: Mutex<Vec<JoinHandle<()>>>,
    /// The secrets the writer masks by value (spec Design 14.4). Empty until
    /// `start` registers the configured ones. Every stream thread holds a clone
    /// and masks each field with it as it writes the line (the field pipeline of
    /// `pipeline`), so a registration made while the writer runs is seen by the
    /// next entry any thread writes, one already queued included.
    registry: Arc<SecretRegistry>,
}

impl AuditLogWriter {
    /// Starts the three stream threads over `specs` (in [`StreamKind::ALL`]
    /// order). Fails only when a thread cannot be spawned; the threads started
    /// before it end by themselves.
    fn from_specs(specs: [StreamSpec; 3], tuning: Tuning) -> io::Result<AuditLogWriter> {
        let [control, agent, reads] = specs;
        let registry = Arc::new(SecretRegistry::new());
        let (control, control_thread) =
            spawn_stream(StreamKind::Control, control, &tuning, &registry)?;
        let (agent, agent_thread) = spawn_stream(StreamKind::Agent, agent, &tuning, &registry)?;
        let (reads, reads_thread) = spawn_stream(StreamKind::Reads, reads, &tuning, &registry)?;
        Ok(AuditLogWriter {
            streams: [control, agent, reads],
            threads: Mutex::new(vec![control_thread, agent_thread, reads_thread]),
            registry,
        })
    }

    /// The registry the stream threads mask with, empty at first. A secret
    /// registered through it is masked in every line written from then on.
    fn registry(&self) -> &Arc<SecretRegistry> {
        &self.registry
    }

    /// Flushes and stops the writer within `budget`: stops `record` taking
    /// entries, sends each stream a `Close` (retrying while its queue is full),
    /// then waits for the threads. Each thread writes everything queued before
    /// its `Close`, syncs its file and exits. A thread still running when the
    /// budget ends (a write that is stuck) is left running and the report says
    /// so; the caller exits regardless. A later call waits for the threads
    /// still left and reports on them; once none is left it reports complete.
    fn shutdown(&self, budget: Duration) -> ShutdownReport {
        let handles = std::mem::take(&mut *self.lock_threads());
        if handles.is_empty() {
            return ShutdownReport {
                complete: true,
                estimated_left: 0,
            };
        }
        let deadline = Deadline::after(budget);
        // From here `record` refuses every entry, so none is queued behind the
        // `Close` below, where no thread would ever write it.
        for stream in &self.streams {
            stream.shared.closing.store(true, Ordering::SeqCst);
        }
        // A `record` that read `closing` as false is mid-call. It never blocks,
        // so this wait is over in moments (the budget bounds it regardless);
        // its entry is then queued ahead of the `Close` and gets written.
        while self
            .streams
            .iter()
            .any(|stream| stream.shared.in_flight.load(Ordering::SeqCst) != 0)
            && !deadline.passed()
        {
            thread::sleep(POLL);
        }
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
        let mut unfinished = Vec::new();
        for handle in handles {
            if handle.is_finished() {
                // A thread that panicked has nothing more to say here; its
                // stream already reads as dead.
                let _ = handle.join();
            } else {
                unfinished.push(handle);
            }
        }
        let complete = unfinished.is_empty();
        if !complete {
            // Kept, so that a later shutdown still finds the thread that is
            // stuck instead of reporting it away.
            self.lock_threads().extend(unfinished);
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
    /// does no file I/O: a full queue (the newest entry, this one, is the one
    /// refused), a shutdown that has begun, or a stream whose thread has ended
    /// counts the entry as dropped instead, and notes its `at` in the stream's
    /// pending gap.
    fn record(&self, lane: AuditLane, entry: AuditEntry) {
        let stream = &self.streams[stream_for(lane, entry.origin).index()];
        let at_ms = entry.at_millis();
        // Counted before it is sent: the thread may write the entry and take it
        // off again before this call gets any further.
        stream.shared.queued.fetch_add(1, Ordering::Relaxed);
        if !stream.offer(entry) {
            stream.shared.refuse(at_ms);
        }
    }

    /// The counters summed over the streams. `degraded` is true when any stream
    /// is dead, its latest write failed or its rotation is wedged; a stream that
    /// ended through a `Close` is closed, not degraded.
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
            status.degraded |= shared.degraded.load(Ordering::Acquire)
                || shared.dead.load(Ordering::Acquire)
                || shared.rotation_wedged.load(Ordering::Acquire);
        }
        status
    }
}

/// Where a secret came from, for the registry's warning about a short one: the
/// label for the operator bridge token this process mints itself.
const BRIDGE_TOKEN_SOURCE: &str = "web.operator_bridge_token";

/// A variable of the process environment is taken for a secret when its name
/// contains one of these (ASCII case-insensitively). `SSH_AUTH_SOCK` and `HOME`
/// match none of them, deliberately: only names that say "secret" are masked by
/// value, so the masking cannot rewrite ordinary text.
const SECRET_ENV_FRAGMENTS: [&str; 10] = [
    "token",
    "secret",
    "password",
    "passwd",
    "credential",
    "api_key",
    "apikey",
    "private_key",
    "passphrase",
    "access_key",
];

/// Whether the environment variable `name` looks like it holds a secret.
fn is_secret_env_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    SECRET_ENV_FRAGMENTS
        .iter()
        .any(|fragment| lower.contains(fragment))
}

/// The values of a variable whose name says "secret" that are a switch, not a
/// secret: `TOKENIZERS_PARALLELISM=false`, `X_TOKEN=true`. The name rule cannot
/// tell them apart, and masking `false` as a whole token would turn every
/// `{"x":false}` the log carries into `{"x":[redacted]}`, which is not JSON.
const BENIGN_ENV_LITERALS: [&str; 12] = [
    "true", "false", "null", "none", "yes", "no", "on", "off", "default", "enabled", "disabled",
    "auto",
];

/// A run of digits this short is a port, a count or a level, not a secret.
const ENV_DIGITS_MIN_BYTES: usize = 8;

/// Whether the value of an environment variable that the name rule took for a
/// secret is empty, one of [`BENIGN_ENV_LITERALS`] (ASCII case-insensitively,
/// the whole value), or only ASCII digits and shorter than
/// [`ENV_DIGITS_MIN_BYTES`] bytes. Such a value is never given to the registry
/// (it is `Registration::Ignored` without being asked), so it is not masked and
/// is not warned about. Only environment values are asked: a token the operator
/// configured is masked whatever it looks like.
fn is_benign_env_value(value: &str) -> bool {
    value.is_empty()
        || BENIGN_ENV_LITERALS
            .iter()
            .any(|literal| value.eq_ignore_ascii_case(literal))
        || (value.len() < ENV_DIGITS_MIN_BYTES && value.bytes().all(|b| b.is_ascii_digit()))
}

/// What `start` returns when the audit log is on: the way to reach the running
/// writer. Clones share the writer and its registry. `Debug` prints the number
/// of registered secrets and nothing else, and there is no `Display`.
#[derive(Clone)]
pub struct AuditLogHandle {
    writer: Arc<AuditLogWriter>,
}

impl fmt::Debug for AuditLogHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuditLogHandle")
            .field("secrets", &self.writer.registry().len())
            .finish()
    }
}

impl AuditLogHandle {
    /// The registry the writer masks with.
    pub fn registry(&self) -> &Arc<SecretRegistry> {
        self.writer.registry()
    }

    /// Registers `secret` (from the place `source` names) with the writer, which
    /// masks it in every field it writes from now on.
    pub fn register_secret(&self, source: &str, secret: &str) -> Registration {
        self.writer.registry().register(source, secret)
    }

    /// Mints the per-run operator bridge token (`web::generate_token`) and
    /// registers it **before it returns**, so the token is never usable before it
    /// is masked. The `aitm web` block of `main.rs` calls this (through
    /// [`bridge_token`]) in place of `web::generate_token`.
    pub fn generate_bridge_token(&self) -> String {
        let token = crate::web::generate_token();
        self.writer.registry().register(BRIDGE_TOKEN_SOURCE, &token);
        token
    }

    /// Flushes and stops the writer within `budget`: stops it taking entries,
    /// writes what is queued and syncs each file, and says what was left if the
    /// budget ran out first.
    pub fn shutdown(&self, budget: Duration) -> ShutdownReport {
        self.writer.shutdown(budget)
    }

    /// The writer's health, as the ring's sink reports it.
    pub fn status(&self) -> DurableAuditStatus {
        self.writer.status()
    }
}

/// The operator bridge token: minted through the handle (so it is registered
/// before the caller sees it) when the audit log is on, and by
/// `web::generate_token` alone, registering nothing, when it is off. The one
/// expression `main.rs` calls.
pub fn bridge_token(handle: Option<&AuditLogHandle>) -> String {
    match handle {
        Some(handle) => handle.generate_bridge_token(),
        None => crate::web::generate_token(),
    }
}

/// Starts the durable audit log the configuration asks for, or says it is off.
///
/// `cfg.mcp.audit_log` decides: `Off` returns `Ok(None)` and touches nothing;
/// anything else resolves a base path and starts the writer there, with the
/// boot policy of [`start_at`] (a path set with `Path` is *explicit*). Every
/// secret the process holds (the transport, operator and agent tokens, the web
/// agent bridge token `web_token`, and each variable of `env` whose name looks
/// like a secret) is registered with the writer before the sink is attached, so
/// no entry can reach a file ahead of its registration. `env` is the process
/// environment, injected so that a test supplies its own.
pub fn start(
    cfg: &Config,
    ring: &Arc<AuditRing>,
    web_token: Option<&str>,
    env: &[(String, String)],
) -> anyhow::Result<Option<AuditLogHandle>> {
    start_tuned(cfg, ring, web_token, env, Tuning::production())
}

/// Starts the writer on `base` (the control stream's file; the other two sit
/// beside it) and attaches it to `ring`, registering no secret.
///
/// The boot policy (spec Design 4): with `explicit` set (the operator named the
/// path) a stream that cannot be used fails the boot with an error naming the
/// path and the reason, before any thread is started; without it the stream
/// starts degraded, one warning names the path and the reason, and the writer
/// retries opening it. A relative `base` is unusable either way. A stream path
/// equal to `ca_log` is an error in both modes, and nothing is created.
///
/// A ring takes one sink: a second writer for the same ring is an error.
///
/// Used by tests, which name the base path directly.
#[doc(hidden)]
pub fn start_at(
    ring: &Arc<AuditRing>,
    base: &Path,
    ca_log: &Path,
    explicit: bool,
) -> anyhow::Result<Option<AuditLogHandle>> {
    start_core(
        ring,
        base,
        ca_log,
        explicit,
        Tuning::production(),
        Vec::new(),
    )
}

/// [`start`] with the writer's numbers and intervals given: the seam a test uses
/// to make a stream rotate after a few lines.
#[doc(hidden)]
pub fn start_tuned(
    cfg: &Config,
    ring: &Arc<AuditRing>,
    web_token: Option<&str>,
    env: &[(String, String)],
    tuning: Tuning,
) -> anyhow::Result<Option<AuditLogHandle>> {
    let Some((base, explicit)) = boot_target(&cfg.mcp.audit_log) else {
        return Ok(None);
    };
    let secrets = configured_secrets(cfg, web_token, env);
    start_core(ring, &base, &cfg.ca.audit_log, explicit, tuning, secrets)
}

/// Where the writer starts for `setting` and whether the path is *explicit*
/// (the operator named it, so an unusable one fails the boot); `None` when the
/// log is off. Resolves a path and touches nothing.
fn boot_target(setting: &AuditLogSetting) -> Option<(PathBuf, bool)> {
    let base = setting.resolved_path()?;
    Some((base, matches!(setting, AuditLogSetting::Path(_))))
}

/// Every secret the writer must mask from the first line: `(source label,
/// value)`, an empty value skipped. A label names a place and never carries a
/// value; an environment variable's is `env:<NAME>`. An environment value that
/// is not a secret (see [`is_benign_env_value`]) is skipped too.
fn configured_secrets(
    cfg: &Config,
    web_token: Option<&str>,
    env: &[(String, String)],
) -> Vec<(String, String)> {
    let mut secrets: Vec<(String, String)> = Vec::new();
    let mut add = |label: &str, value: &str| {
        if !value.is_empty() {
            secrets.push((label.to_string(), value.to_string()));
        }
    };
    match &cfg.mcp.transport {
        McpTransport::LoopbackTcp { token, .. } | McpTransport::StreamableHttp { token, .. } => {
            add("mcp.transport.token", token);
        }
        McpTransport::Stdio => {}
    }
    if let Some(token) = &cfg.mcp.operator_token {
        add("mcp.operator_token", token);
    }
    if let Some(token) = &cfg.mcp.agent_token {
        add("mcp.agent_token", token);
    }
    if let Some(token) = web_token {
        add("web.agent_bridge_token", token);
    }
    for (name, value) in env {
        if is_secret_env_name(name) && !is_benign_env_value(value) {
            add(&format!("env:{name}"), value);
        }
    }
    secrets
}

/// One stream's file, opened and hardened by [`preflight`]. A path that cannot
/// be used is an error when `explicit`; otherwise one warning names the path
/// and the reason and the stream is returned without a file, to be retried.
fn open_stream(kind: StreamKind, base: &Path, explicit: bool) -> anyhow::Result<StreamSpec> {
    let path = stream_path(base, kind);
    // A relative base gives a relative path, which `preflight` refuses before it
    // touches anything.
    let file: Option<Box<dyn LogFile>> = match preflight(&path, kind) {
        Ok(file) => Some(Box::new(file)),
        Err(error) if explicit => {
            anyhow::bail!("{error}; fix mcp.audit_log (or AITM_AUDIT_LOG) or set it to off")
        }
        Err(error) => {
            warn!(
                target: "aitm::audit",
                stream = kind.label(),
                path = %path.display(),
                error = %error,
                "the audit log cannot be used; the writer starts degraded and retries opening it"
            );
            None
        }
    };
    Ok(StreamSpec {
        path,
        backend: Box::new(FsBackend),
        file,
    })
}

/// The first file a stream writes (its active file, or a rotated file it keeps:
/// `F.1` to `F.keep`) that is the CA audit log, as the stream, the path it writes
/// and whether it is a rotated one. The comparison is of the files: see
/// [`resolved`].
fn ca_log_collision(
    base: &Path,
    ca_log: &Path,
    tuning: &Tuning,
) -> Option<(StreamKind, PathBuf, bool)> {
    let ca_log = resolved(ca_log);
    StreamKind::ALL.into_iter().find_map(|kind| {
        let active = stream_path(base, kind);
        if resolved(&active) == ca_log {
            return Some((kind, active, false));
        }
        (1..=tuning.keep[kind.index()]).find_map(|n| {
            let rotated = rotated_path(&active, n);
            (resolved(&rotated) == ca_log).then_some((kind, rotated, true))
        })
    })
}

/// `path` made absolute and with every link and `..` in it resolved as far as
/// the file system can say: the longest ancestor that exists is canonicalised and
/// the rest, which does not exist and so is no link, is appended with its `.` and
/// `..` removed. Two spellings of one file give one path (`<d>/sub/../a`,
/// `<d>/link-to-d/a`, `<d>/a`), whether or not the file or the directories in
/// front of it are there yet.
fn resolved(path: &Path) -> PathBuf {
    let absolute = if path.is_relative() {
        match std::env::current_dir() {
            Ok(here) => here.join(path),
            Err(_) => return path.to_path_buf(),
        }
    } else {
        path.to_path_buf()
    };
    let mut head = absolute.clone();
    // The components cut off the end, last first.
    let mut rest: Vec<std::ffi::OsString> = Vec::new();
    loop {
        if let Ok(real) = fs::canonicalize(&head) {
            let mut out = real;
            for part in rest.iter().rev() {
                if part == ".." {
                    out.pop();
                } else if part != "." {
                    out.push(part);
                }
            }
            return out;
        }
        match head.components().next_back() {
            Some(std::path::Component::Normal(name)) => rest.push(name.to_os_string()),
            Some(std::path::Component::ParentDir) => rest.push("..".into()),
            Some(std::path::Component::CurDir) => rest.push(".".into()),
            _ => return absolute,
        }
        if !head.pop() {
            return absolute;
        }
    }
}

/// The boot, in order: refuse a stream path that is the CA audit log; open each
/// stream (control, agent, reads) under the boot policy; start the writer;
/// register every secret; attach the sink; say one line when every stream is open.
fn start_core(
    ring: &Arc<AuditRing>,
    base: &Path,
    ca_log: &Path,
    explicit: bool,
    tuning: Tuning,
    secrets: Vec<(String, String)>,
) -> anyhow::Result<Option<AuditLogHandle>> {
    if let Some((kind, path, rotated)) = ca_log_collision(base, ca_log, &tuning) {
        let what = if rotated {
            "would rotate its file to"
        } else {
            "would be"
        };
        anyhow::bail!(
            "the {} stream of the audit log {what} {}, which is ca.audit_log ({}): the CA audit log and the general audit log are different logs and must not share a file; move mcp.audit_log or ca.audit_log",
            kind.label(),
            path.display(),
            ca_log.display()
        );
    }
    let control = open_stream(StreamKind::Control, base, explicit)?;
    let agent = open_stream(StreamKind::Agent, base, explicit)?;
    let reads = open_stream(StreamKind::Reads, base, explicit)?;
    let healthy = [&control, &agent, &reads]
        .iter()
        .all(|stream| stream.file.is_some());
    let writer = match AuditLogWriter::from_specs([control, agent, reads], tuning) {
        Ok(writer) => Arc::new(writer),
        Err(error) if explicit => anyhow::bail!("{error}"),
        Err(error) => {
            warn!(
                target: "aitm::audit",
                error = %error,
                "the audit writer could not be started; nothing is written to the audit log this run"
            );
            return Ok(None);
        }
    };
    // Before the sink is attached: no entry can reach a file ahead of these.
    for (source, secret) in &secrets {
        writer.registry().register(source, secret);
    }
    if !ring.attach_durable(writer.clone()) {
        // The writer started above is not the ring's sink: stop it.
        let _ = writer.shutdown(SHUTDOWN_BUDGET);
        anyhow::bail!(
            "a durable audit sink is already attached to this audit ring; a ring takes one"
        );
    }
    // One line, and only for a healthy start: a stream that could not be opened
    // has already said so (a warning naming its file), and "on" beside that
    // would be false comfort.
    if healthy {
        info!(
            target: "aitm::audit",
            path = %stream_path(base, StreamKind::Control).display(),
            "durable audit log on"
        );
    }
    Ok(Some(AuditLogHandle { writer }))
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs::{self, OpenOptions};
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
    use std::sync::{mpsc, Arc, Condvar, Mutex, MutexGuard, PoisonError};
    use std::time::{Duration, Instant};

    use aitm_core::{
        AuditEntry, AuditLogSetting, AuditResult, AuditRing, AuditSink, Config, McpTransport,
    };
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

    /// How long a test waits for something another thread does. Far above what it
    /// takes: a wait that ends early costs nothing, and one that is too short fails
    /// on a loaded machine.
    const WAIT: Duration = Duration::from_secs(10);

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

    /// `index` is the position in `ALL` (the per-stream arrays are indexed with it) and
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

    /// A file `open_private` creates is `0600` from the moment it exists, not
    /// only after `restrict_to_owner` has run: a local process that opens it in
    /// between would keep a read descriptor that survives the later `chmod`.
    #[cfg(unix)]
    #[test]
    fn open_private_creates_the_file_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let dir = scratch("create-mode");
        let path = dir.join("audit.jsonl");
        let _file = open_private(&path, true)
            .unwrap_or_else(|e| panic!("creating a private file failed: {e}"));
        let mode = fs::metadata(&path).expect("stat").permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "mode of a file straight out of open_private");
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

    // ---- the writer core ------------------------------------------------

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
    /// test through an `Arc`. The tests that script a failing or a stalled disk
    /// use it.
    #[derive(Default)]
    struct FakeState {
        /// Every line written, without its newline.
        lines: Mutex<Vec<String>>,
        /// The name of the thread each write ran on.
        writer_threads: Mutex<Vec<String>>,
        /// How many times the file was synced.
        syncs: AtomicUsize,
        /// How many lines the file held at each sync, in order: what a sync
        /// had been asked to make durable.
        sync_marks: Mutex<Vec<usize>>,
        /// The next this-many writes fail with `StorageFull`.
        fail_next: AtomicUsize,
        /// A write panics.
        panic_on_write: AtomicBool,
        /// The first write blocks here when set.
        gate: Option<Gate>,
        /// How many times the backend was asked to open the file.
        open_calls: AtomicUsize,
        /// An open fails with `PermissionDenied` while this is set.
        fail_open: AtomicBool,
        /// What the next re-checks answer, in order; `Same` once it is empty.
        recheck_answers: Mutex<Vec<Recheck>>,
        /// How many times the backend was asked whether the path still names the file.
        recheck_calls: AtomicUsize,
    }

    impl FakeState {
        fn plain() -> Arc<FakeState> {
            Arc::new(FakeState::default())
        }

        /// Makes the next re-checks answer `answers`, one each, in order.
        fn script_rechecks(&self, answers: Vec<Recheck>) {
            *lock(&self.recheck_answers) = answers;
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

        fn sync_marks(&self) -> Vec<usize> {
            lock(&self.sync_marks).clone()
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
            let held = lock(&self.0.lines).len();
            lock(&self.0.sync_marks).push(held);
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
            self.0.open_calls.fetch_add(1, Ordering::SeqCst);
            if self.0.fail_open.load(Ordering::SeqCst) {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "the fake disk refuses to open",
                ));
            }
            Ok(Box::new(FakeFile(self.0.clone())))
        }

        fn recheck(&mut self, _path: &Path, _file: &dyn LogFile) -> Recheck {
            self.0.recheck_calls.fetch_add(1, Ordering::SeqCst);
            let mut answers = lock(&self.0.recheck_answers);
            if answers.is_empty() {
                Recheck::Same
            } else {
                answers.remove(0)
            }
        }
    }

    /// A writer over three fake files, one per state, nothing on disk.
    fn fake_writer(states: &[Arc<FakeState>; 3], tuning: Tuning) -> Arc<AuditLogWriter> {
        fake_writer_with_files(states, tuning, [true; 3])
    }

    /// [`fake_writer`] where a stream whose `has_file` is false arrives without
    /// an open file, as one whose boot open failed does.
    fn fake_writer_with_files(
        states: &[Arc<FakeState>; 3],
        tuning: Tuning,
        has_file: [bool; 3],
    ) -> Arc<AuditLogWriter> {
        let mut specs = Vec::new();
        for (kind, state) in StreamKind::ALL.into_iter().zip(states) {
            let file: Option<Box<dyn LogFile>> = if has_file[kind.index()] {
                Some(Box::new(FakeFile(state.clone())))
            } else {
                None
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
        Arc::new(AuditLogWriter::from_specs(specs, tuning).unwrap_or_else(|e| panic!("start: {e}")))
    }

    /// `production()` with no wait between a failed write and the next try at
    /// reopening the file: for the tests that are about what happens to the
    /// entries, not about timing.
    fn eager_reopen() -> Tuning {
        Tuning {
            reopen: Duration::ZERO,
            ..Tuning::production()
        }
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
    /// budget: the call returns while the write is still stuck, and the report says
    /// entries are left. (That it returned with the thread unfinished is the
    /// property; no clock is read, so a loaded machine cannot fail it.)
    #[test]
    fn shutdown_of_a_blocked_writer_returns_within_its_budget() {
        let states = [FakeState::plain(), FakeState::gated(), FakeState::plain()];
        let writer = fake_writer(&states, Tuning::production());
        writer.record(AuditLane::Evidence, entry("blocked", Frontend::Mcp, 1));
        assert!(
            wait_until(WAIT, || states[1].inside()),
            "the agent writer never reached its write"
        );

        let report = writer.shutdown(Duration::from_millis(300));
        // Let the stuck thread go before any assertion can fail, so it can exit.
        states[1].release();

        assert!(!report.complete, "the stuck write was waited for");
        assert!(
            report.estimated_left >= 1,
            "estimated_left is {}",
            report.estimated_left
        );
        assert!(
            wait_until(WAIT, || { states[1].syncs.load(Ordering::SeqCst) == 1 }),
            "after the release the writer did not process its Close"
        );
    }

    /// The estimate of entries left is exactly what was accepted and is not yet
    /// written: an entry whose write has finished, failed or not, no longer counts.
    #[test]
    fn the_estimate_of_entries_left_counts_only_what_is_not_yet_written() {
        let states = [FakeState::plain(), FakeState::gated(), FakeState::plain()];
        // The first two writes fail before they reach the gate: the entry
        // `failed1`, and the gap marker for it that `failed2` tries to write
        // first. With no wait to reopen, `stuck` then reopens the stream and
        // blocks in the write of that marker.
        states[1].fail_next.store(2, Ordering::SeqCst);
        let writer = fake_writer(&states, eager_reopen());
        writer.record(AuditLane::Evidence, entry("failed1", Frontend::Mcp, 1));
        writer.record(AuditLane::Evidence, entry("failed2", Frontend::Mcp, 2));
        assert!(
            wait_until(WAIT, || { writer.status().write_failures == 2 }),
            "the two failing writes were not processed: {:?}",
            writer.status()
        );

        // One entry now blocks inside its write and one waits behind it.
        writer.record(AuditLane::Evidence, entry("stuck", Frontend::Mcp, 3));
        writer.record(AuditLane::Evidence, entry("waiting", Frontend::Mcp, 4));
        assert!(
            wait_until(WAIT, || states[1].inside()),
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
    /// the next write that succeeds clears `degraded`, keeps the counter and is
    /// preceded by the gap marker for what was lost.
    #[test]
    fn a_failed_write_is_counted_and_the_next_success_clears_degraded() {
        let states = FakeState::three();
        states[1].fail_next.store(2, Ordering::SeqCst);
        let writer = fake_writer(&states, eager_reopen());
        assert!(!writer.status().degraded, "healthy at the start");

        writer.record(AuditLane::Evidence, entry("lost1", Frontend::Mcp, 1));
        writer.record(AuditLane::Evidence, entry("lost2", Frontend::Mcp, 2));
        assert!(
            wait_until(WAIT, || {
                let status = writer.status();
                status.write_failures == 2 && status.degraded
            }),
            "two failures and degraded were not reported: {:?}",
            writer.status()
        );

        writer.record(AuditLane::Evidence, entry("kept", Frontend::Mcp, 3));
        assert!(
            wait_until(WAIT, || {
                !writer.status().degraded && states[1].lines().len() == 2
            }),
            "a successful write did not clear degraded: {:?}",
            writer.status()
        );
        let status = writer.status();
        assert_eq!(status.write_failures, 2, "the counter is never reset");
        assert_eq!(status.dropped, 0, "a failed write is not a dropped entry");
        assert_eq!(fake_shape(&states[1]), ["gap", "kept"]);
        let gap = &fake_gaps(&states[1])[0];
        assert_eq!(gap["failed"], 2, "both lost entries are in the marker");
        assert_eq!(gap["dropped"], 0);
        assert_eq!(gap["from"], 1);
        assert_eq!(gap["to"], 2);
        let kept = aitm_ca::audit::entry_to_jsonl(&entry("kept", Frontend::Mcp, 3));
        assert_eq!(states[1].lines()[1], kept);
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
            wait_until(WAIT, || writer.status().degraded),
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

    // ---- drop-newest and gap markers ------------------------------------

    /// The clock the gap tests build their entries' `at` from, so a marker's
    /// `from` and `to` can be asserted exactly.
    const BASE_MS: u64 = 1_700_000_000_000;

    /// Lets a gated fake's blocked write go when dropped, so a test that fails an
    /// assertion does not leave its stream thread stuck behind the gate.
    struct ReleaseOnDrop(Arc<FakeState>);

    impl Drop for ReleaseOnDrop {
        fn drop(&mut self) {
            self.0.release();
        }
    }

    /// The agent-origin entry `a<i>`, whose `at` is `BASE_MS + i`.
    fn agent_entry(i: u64) -> AuditEntry {
        entry(&format!("a{i}"), Frontend::Mcp, BASE_MS + i)
    }

    /// `tuning` with the agent stream's queue holding `queue` entries.
    fn agent_queue(queue: usize) -> Tuning {
        Tuning {
            queue: [4, queue, 4],
            ..Tuning::production()
        }
    }

    /// A fake writer whose agent stream blocks inside its first write, with `a0`
    /// already in that write: the queue is empty and the stream is stuck until
    /// the returned guard (or the test) lets it go.
    fn stuck_agent_writer(
        tuning: Tuning,
    ) -> ([Arc<FakeState>; 3], Arc<AuditLogWriter>, ReleaseOnDrop) {
        let states = [FakeState::plain(), FakeState::gated(), FakeState::plain()];
        let release = ReleaseOnDrop(states[1].clone());
        let writer = fake_writer(&states, tuning);
        writer.record(AuditLane::Evidence, agent_entry(0));
        assert!(
            wait_until(WAIT, || states[1].inside()),
            "the agent writer never reached its write"
        );
        (states, writer, release)
    }

    /// Every line a fake file holds, parsed; panics on a line that is not JSON.
    fn fake_json(state: &FakeState) -> Vec<Value> {
        state
            .lines()
            .iter()
            .map(|line| {
                serde_json::from_str(line)
                    .unwrap_or_else(|e| panic!("a fake line is not JSON ({e}): {line:?}"))
            })
            .collect()
    }

    /// A fake file's lines, one word each: the entry's command, or `gap` for a
    /// gap marker (`start` and any other marker read as its own name).
    fn fake_shape(state: &FakeState) -> Vec<String> {
        fake_json(state)
            .iter()
            .map(|line| {
                let command = line.get("command").and_then(Value::as_str);
                let marker = line.get("marker").and_then(Value::as_str);
                command.or(marker).unwrap_or("?").to_string()
            })
            .collect()
    }

    /// The gap markers a fake file holds.
    fn fake_gaps(state: &FakeState) -> Vec<Value> {
        fake_json(state)
            .into_iter()
            .filter(|line| line["marker"] == "gap")
            .collect()
    }

    /// How many entries (not markers) a fake file holds.
    fn fake_entry_count(state: &FakeState) -> usize {
        fake_shape(state)
            .iter()
            .filter(|word| *word != "gap" && *word != "start")
            .count()
    }

    /// `prefix0` to `prefix{n - 1}`.
    fn names(prefix: &str, n: usize) -> Vec<String> {
        (0..n).map(|i| format!("{prefix}{i}")).collect()
    }

    /// AC18: a stalled disk never blocks the call path. The agent stream's first
    /// write does not return; its queue fills, every later entry is refused at
    /// once and counted, and when the disk answers the file holds the accepted
    /// prefix and one gap marker that says what is missing.
    #[test]
    fn a_stalled_disk_never_blocks_the_call_path() {
        let (states, writer, _release) = stuck_agent_writer(agent_queue(4096));
        let ring = Arc::new(AuditRing::new(8192));
        assert!(
            ring.attach_durable(writer.clone()),
            "a fresh ring takes its first sink"
        );

        let flood = ring.clone();
        within(
            Duration::from_secs(2),
            "5095 appends behind a stalled disk",
            move || {
                for i in 1..=5095 {
                    flood.append_in(AuditLane::Evidence, agent_entry(i));
                }
            },
        );
        let status = ring.durable_status().expect("a sink is attached");
        assert_eq!(status.dropped, 999, "queue of 4096 behind one stuck write");

        states[1].release();
        let report = writer.shutdown(FLUSH_BUDGET);
        assert!(report.complete, "the flush did not finish: {report:?}");

        let shape = fake_shape(&states[1]);
        let entries: Vec<&String> = shape.iter().filter(|word| *word != "gap").collect();
        let want = names("a", 4097);
        assert_eq!(entries.len(), want.len(), "entry lines in the agent file");
        let first_difference = entries
            .iter()
            .zip(&want)
            .position(|(got, want)| *got != want);
        assert_eq!(first_difference, None, "first entry out of order");

        let gaps = fake_gaps(&states[1]);
        assert_eq!(
            gaps.len(),
            1,
            "expected exactly one gap line, found {}",
            gaps.len()
        );
        let gap = &gaps[0];
        assert_eq!(gap["dropped"], 999);
        assert_eq!(gap["failed"], 0);
        assert_eq!(gap["from"], BASE_MS + 4097);
        assert_eq!(gap["to"], BASE_MS + 5095);
        assert!(gap["at"].is_i64(), "the marker carries its own time: {gap}");
    }

    /// AC19: one stream flooded and stuck does not stop another. The agent
    /// stream is stuck with its queue full while the control and reads streams,
    /// real files, take everything they are given.
    #[test]
    fn a_flooded_stream_cannot_starve_another() {
        let dir = scratch("starve");
        let base = dir.join("audit.jsonl");
        let paths = StreamKind::ALL.map(|kind| stream_path(&base, kind));
        let agent_state = FakeState::gated();
        let _release = ReleaseOnDrop(agent_state.clone());
        let specs = StreamKind::ALL.map(|kind| {
            let path = stream_path(&base, kind);
            match kind {
                StreamKind::Agent => StreamSpec {
                    path,
                    backend: Box::new(FakeBackend(agent_state.clone())),
                    file: Some(Box::new(FakeFile(agent_state.clone()))),
                },
                StreamKind::Control | StreamKind::Reads => {
                    let file = preflight(&path, kind).unwrap_or_else(|e| {
                        panic!("preflight of the {} stream failed: {e}", kind.label())
                    });
                    StreamSpec {
                        path,
                        backend: Box::new(FsBackend),
                        file: Some(Box::new(file)),
                    }
                }
            }
        });
        let writer = Arc::new(
            AuditLogWriter::from_specs(specs, Tuning::production())
                .unwrap_or_else(|e| panic!("start: {e}")),
        );
        let ring = Arc::new(AuditRing::new(8192));
        assert!(ring.attach_durable(writer.clone()));

        ring.append_in(AuditLane::Evidence, agent_entry(0));
        assert!(
            wait_until(WAIT, || agent_state.inside()),
            "the agent writer never reached its write"
        );
        let flood = ring.clone();
        within(
            Duration::from_secs(2),
            "5095 appends behind a stalled disk",
            move || {
                for i in 1..=5095 {
                    flood.append_in(AuditLane::Evidence, agent_entry(i));
                }
            },
        );
        for i in 0..10 {
            ring.append_in(
                AuditLane::Evidence,
                entry(&format!("c{i}"), Frontend::Operator, BASE_MS + i),
            );
            ring.append_in(
                AuditLane::Routine,
                entry(&format!("r{i}"), Frontend::Mcp, BASE_MS + i),
            );
        }

        // Counted without parsing, so a read that races a write cannot panic.
        let entries_in = |path: &Path| {
            fs::read_to_string(path)
                .map(|text| text.lines().filter(|l| l.contains("\"command\"")).count())
                .unwrap_or(0)
        };
        assert!(
            wait_until(WAIT, || {
                entries_in(&paths[0]) == 10 && entries_in(&paths[2]) == 10
            }),
            "control holds {} entries and reads {}, expected 10 each",
            entries_in(&paths[0]),
            entries_in(&paths[2])
        );
        assert!(
            agent_state.lines().is_empty(),
            "the agent stream was meant to still be stuck"
        );
        let status = ring.durable_status().expect("a sink is attached");
        assert_eq!(status.dropped, 999, "only the flooded stream dropped");

        agent_state.release();
        let report = writer.shutdown(FLUSH_BUDGET);
        assert!(report.complete, "the flush did not finish: {report:?}");
        assert_eq!(entry_commands(&paths[0]), names("c", 10), "control file");
        assert_eq!(entry_commands(&paths[2]), names("r", 10), "reads file");
    }

    /// The marker is one JSON object with exactly these keys, in alphabetical
    /// order, and no newline.
    #[test]
    fn gap_marker_line_has_exactly_the_documented_keys() {
        let line = gap_marker_line(
            1_700_000_000_999,
            1_700_000_000_100,
            1_700_000_000_200,
            3,
            2,
        );
        let parsed: Value = serde_json::from_str(&line).expect("a gap line is JSON");
        let mut keys: Vec<&str> = parsed
            .as_object()
            .expect("a gap line is an object")
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(keys, ["at", "dropped", "failed", "from", "marker", "to"]);
        assert_eq!(parsed["marker"], "gap");
        assert_eq!(
            line,
            "{\"at\":1700000000999,\"dropped\":3,\"failed\":2,\"from\":1700000000100,\"marker\":\"gap\",\"to\":1700000000200}"
        );
        assert!(!line.contains('\n'), "a marker is one line");
    }

    /// Notes widen `from` and `to` whatever order they arrive in; `take` hands
    /// back what is pending and leaves nothing behind.
    #[test]
    fn gap_state_merges_and_resets() {
        let mut gap = GapState::default();
        assert_eq!(gap.take(), None, "nothing is pending yet");

        gap.note_drop(10);
        gap.note_drop(30);
        gap.note_fail(20);
        assert_eq!(
            gap.take(),
            Some(GapState {
                dropped: 2,
                failed: 1,
                from: Some(10),
                to: Some(30)
            })
        );
        assert_eq!(gap.take(), None, "a second take finds nothing");

        // Out of order: the span still runs from the earliest to the latest.
        gap.note_drop(30);
        gap.note_fail(10);
        gap.note_drop(20);
        assert_eq!(
            gap.take(),
            Some(GapState {
                dropped: 2,
                failed: 1,
                from: Some(10),
                to: Some(30)
            })
        );
    }

    /// Putting a gap back adds its counts and widens the span, whatever was
    /// noted meanwhile; putting back nothing changes nothing.
    #[test]
    fn gap_state_merge_adds_counts_and_widens() {
        let mut gap = GapState::default();
        gap.note_drop(20);
        gap.note_drop(30);
        let earlier = GapState {
            dropped: 0,
            failed: 2,
            from: Some(10),
            to: Some(25),
        };
        gap.merge(earlier);
        let want = GapState {
            dropped: 2,
            failed: 2,
            from: Some(10),
            to: Some(30),
        };
        assert_eq!(gap, want);

        gap.merge(GapState::default());
        assert_eq!(gap, want, "merging nothing changes nothing");

        let mut empty = GapState::default();
        empty.merge(want.clone());
        assert_eq!(empty, want, "merging into nothing gives the other");
    }

    /// A full queue refuses the newest entry: what was accepted stays, in order,
    /// and the gap marker names the refused ones. (Where the marker sits is
    /// pinned by the idle-hole test above: here the hole is noted while a write
    /// is in progress, which reads the same either way.)
    #[test]
    fn a_full_queue_refuses_the_newest_entry_and_keeps_the_accepted_prefix() {
        let (states, writer, _release) = stuck_agent_writer(agent_queue(3));
        for i in 1..=5 {
            writer.record(AuditLane::Evidence, agent_entry(i));
        }
        // a1 to a3 fill the queue; a4 and a5 are the newest, and are refused.
        assert_eq!(writer.status().dropped, 2);

        states[1].release();
        let report = writer.shutdown(FLUSH_BUDGET);
        assert!(report.complete, "the flush did not finish: {report:?}");

        assert_eq!(fake_shape(&states[1]), ["a0", "gap", "a1", "a2", "a3"]);
        let gaps = fake_gaps(&states[1]);
        assert_eq!(gaps[0]["dropped"], 2);
        assert_eq!(gaps[0]["failed"], 0);
        assert_eq!(gaps[0]["from"], BASE_MS + 4, "the first refused entry");
        assert_eq!(gaps[0]["to"], BASE_MS + 5, "the last refused entry");
    }

    /// A hole noted while the stream is idle is written before the next entry
    /// that gets written, not after it (spec Design 6: "before the next
    /// successful entry"). A full queue means a busy thread, so the hole is
    /// noted by hand: the producers' own path into the pending gap.
    #[test]
    fn a_hole_noted_while_the_stream_is_idle_is_written_before_the_next_entry() {
        let states = FakeState::three();
        let writer = fake_writer(&states, Tuning::production());
        let agent = &writer.streams[StreamKind::Agent.index()];
        agent.shared.lock_gap().note_drop((BASE_MS + 7) as i64);
        agent.shared.lock_gap().note_drop((BASE_MS + 9) as i64);

        writer.record(AuditLane::Evidence, agent_entry(10));
        let report = writer.shutdown(FLUSH_BUDGET);
        assert!(report.complete, "the flush did not finish: {report:?}");

        assert_eq!(fake_shape(&states[1]), ["gap", "a10"]);
        let gap = &fake_gaps(&states[1])[0];
        assert_eq!(gap["dropped"], 2);
        assert_eq!(gap["from"], BASE_MS + 7);
        assert_eq!(gap["to"], BASE_MS + 9);
    }

    /// `record` returns at once on a full queue, however many entries it is
    /// given: it never waits for room.
    #[test]
    fn record_returns_at_once_on_a_full_queue() {
        let (_states, writer, _release) = stuck_agent_writer(agent_queue(1));
        writer.record(AuditLane::Evidence, agent_entry(1));

        let flood = writer.clone();
        within(
            Duration::from_secs(1),
            "fifty records into a full queue",
            move || {
                for i in 2..52 {
                    flood.record(AuditLane::Evidence, agent_entry(i));
                }
            },
        );
        assert_eq!(writer.status().dropped, 50);
    }

    /// An entry refused for a full queue leaves the estimate of entries left:
    /// only what was accepted and is not yet written counts.
    #[test]
    fn a_refused_entry_is_not_left_in_the_estimate() {
        let (_states, writer, _release) = stuck_agent_writer(agent_queue(3));
        for i in 1..=5 {
            writer.record(AuditLane::Evidence, agent_entry(i));
        }
        let report = writer.shutdown(Duration::from_millis(100));
        // The stuck a0 and the three queued entries, not the two refused ones.
        assert_eq!(
            report,
            ShutdownReport {
                complete: false,
                estimated_left: 4
            }
        );
    }

    /// `Tuning.queue` sizes each stream's queue: with every stream stuck, each
    /// takes its own number of entries and refuses the rest.
    #[test]
    fn tuning_queue_sizes_each_streams_queue() {
        let states = [FakeState::gated(), FakeState::gated(), FakeState::gated()];
        let _releases: Vec<ReleaseOnDrop> = states
            .iter()
            .map(|state| ReleaseOnDrop(state.clone()))
            .collect();
        let tuning = Tuning {
            queue: [2, 3, 4],
            ..Tuning::production()
        };
        let writer = fake_writer(&states, tuning);
        let rows = [
            (AuditLane::Evidence, Frontend::Operator, "c"),
            (AuditLane::Evidence, Frontend::Mcp, "a"),
            (AuditLane::Routine, Frontend::Mcp, "r"),
        ];
        for (lane, origin, name) in rows {
            writer.record(lane, entry(&format!("{name}0"), origin, BASE_MS));
        }
        assert!(
            wait_until(WAIT, || states.iter().all(|state| state.inside())),
            "a writer never reached its write"
        );
        for (lane, origin, name) in rows {
            for i in 1..=10 {
                writer.record(lane, entry(&format!("{name}{i}"), origin, BASE_MS + i));
            }
        }
        assert_eq!(writer.status().dropped, (10 - 2) + (10 - 3) + (10 - 4));

        for state in &states {
            state.release();
        }
        let report = writer.shutdown(FLUSH_BUDGET);
        assert!(report.complete, "the flush did not finish: {report:?}");
        let written: Vec<usize> = states.iter().map(|state| fake_entry_count(state)).collect();
        // The entry in the stuck write plus a full queue, per stream.
        assert_eq!(written, [1 + 2, 1 + 3, 1 + 4]);
    }

    /// The marker for a hole is not lost when its own write fails: it stays
    /// pending, and the next entry that is written is preceded by it. The entry
    /// whose turn the failed write was is a failed write, not a dropped one.
    #[test]
    fn a_gap_line_that_fails_to_write_is_kept_for_the_next_entry() {
        // No wait between a failed write and the next attempt: this test is
        // about what happens to the marker, not about timing.
        let tuning = Tuning {
            reopen: Duration::ZERO,
            ..agent_queue(1)
        };
        let (states, writer, _release) = stuck_agent_writer(tuning);
        writer.record(AuditLane::Evidence, agent_entry(1));
        writer.record(AuditLane::Evidence, agent_entry(2));
        // a1 is queued and a2 refused: a gap is pending.
        assert_eq!(writer.status().dropped, 1);

        // a0 is already past the failure check, so this fails the next write,
        // which is the gap line in front of a1.
        states[1].fail_next.store(1, Ordering::SeqCst);
        states[1].release();
        assert!(
            wait_until(WAIT, || { writer.status().write_failures == 1 }),
            "the failed gap write was not counted: {:?}",
            writer.status()
        );

        writer.record(AuditLane::Evidence, agent_entry(3));
        let report = writer.shutdown(FLUSH_BUDGET);
        assert!(report.complete, "the flush did not finish: {report:?}");
        assert_eq!(fake_shape(&states[1]), ["a0", "gap", "a3"]);
        assert_eq!(fake_gaps(&states[1])[0]["dropped"], 1);
        let status = writer.status();
        assert_eq!(status.dropped, 1);
        assert_eq!(status.write_failures, 1);
    }

    /// Spec Design 7: a record after shutdown began is counted as dropped. The
    /// writer here is stuck in a write, so after the first shutdown gives up its
    /// `Close` is still queued and the thread still alive: an entry accepted now
    /// would sit behind the `Close` and never be written, nor counted.
    #[test]
    fn a_record_after_shutdown_began_is_dropped_not_stranded_behind_close() {
        let (states, writer, _release) = stuck_agent_writer(agent_queue(8));
        let first = writer.shutdown(Duration::from_millis(100));
        assert!(!first.complete, "the stuck writer cannot have finished");

        writer.record(AuditLane::Evidence, agent_entry(1));
        assert_eq!(
            writer.status().dropped,
            1,
            "an entry sent after shutdown began is counted as dropped"
        );

        states[1].release();
        let report = writer.shutdown(FLUSH_BUDGET);
        assert_eq!(
            report,
            ShutdownReport {
                complete: true,
                estimated_left: 0
            }
        );
        // The refused entry is not on disk, but the hole it left is: nothing was
        // written after it, so the shutdown itself writes the marker.
        assert_eq!(
            fake_shape(&states[1]),
            ["a0", "gap"],
            "the refused entry is not on disk; its hole is marked"
        );
        let gap = &fake_gaps(&states[1])[0];
        assert_eq!(gap["dropped"], 1);
        assert_eq!(gap["failed"], 0);
        assert_eq!(gap["from"], BASE_MS + 1);
        assert_eq!(gap["to"], BASE_MS + 1);
        assert_eq!(writer.status().dropped, 1);
    }

    /// A `record` that has passed its checks when a shutdown begins is still on
    /// its way to `try_send`; its entry must land ahead of the `Close`, where it
    /// is written, not behind it, where it never is. The test holds a real call
    /// at exactly that point until the shutdown has started. The writer is stuck
    /// in a write, so a `Close` queued first would sit in front of the entry for
    /// good.
    #[test]
    fn a_record_caught_by_a_shutdown_mid_call_is_written_not_stranded() {
        let (states, writer, _release) = stuck_agent_writer(agent_queue(8));
        let agent = &writer.streams[StreamKind::Agent.index()];

        let mut closer = None;
        agent.shared.queued.fetch_add(1, Ordering::Relaxed);
        let accepted = agent.offer_after_check(agent_entry(1), || {
            let writer = writer.clone();
            closer = Some(std::thread::spawn(move || writer.shutdown(FLUSH_BUDGET)));
            assert!(
                wait_until(WAIT, || { agent.shared.closing.load(Ordering::SeqCst) }),
                "the shutdown never began"
            );
        });
        assert!(accepted, "the record was refused after passing its checks");

        states[1].release();
        let report = closer
            .expect("the shutdown was started")
            .join()
            .expect("the shutdown thread panicked");
        assert_eq!(
            report,
            ShutdownReport {
                complete: true,
                estimated_left: 0
            }
        );
        assert_eq!(
            fake_shape(&states[1]),
            ["a0", "a1"],
            "the entry the shutdown caught mid-call is written"
        );
    }

    /// Four threads record without pause while a shutdown runs: every record is
    /// either on disk or counted as dropped, exactly. Nothing is accepted into
    /// a queue that will not be read, and a flood does not keep the `Close` out.
    #[test]
    fn every_record_around_a_shutdown_is_written_or_counted() {
        let states = FakeState::three();
        let writer = fake_writer(&states, agent_queue(64));
        let stop = Arc::new(AtomicBool::new(false));
        let producers: Vec<JoinHandle<u64>> = (0..4)
            .map(|_| {
                let writer = writer.clone();
                let stop = stop.clone();
                std::thread::spawn(move || {
                    let mut issued = 0_u64;
                    while !stop.load(Ordering::Relaxed) {
                        writer.record(AuditLane::Evidence, agent_entry(issued));
                        issued += 1;
                    }
                    issued
                })
            })
            .collect();
        let started = wait_until(WAIT, || fake_entry_count(&states[1]) >= 200);

        let report = writer.shutdown(FLUSH_BUDGET);
        stop.store(true, Ordering::Relaxed);
        let issued: u64 = producers
            .into_iter()
            .map(|producer| producer.join().expect("a producer panicked"))
            .sum();
        assert!(started, "the producers never got going");
        assert!(report.complete, "the flush did not finish: {report:?}");

        let written = fake_entry_count(&states[1]) as u64;
        assert_eq!(
            written + writer.status().dropped,
            issued,
            "records neither written nor counted"
        );
    }

    /// A second shutdown of a writer that is still stuck is as incomplete as
    /// the first; once the writer is let go a later one completes.
    #[test]
    fn a_second_shutdown_of_a_stuck_writer_is_still_incomplete() {
        let (states, writer, _release) = stuck_agent_writer(agent_queue(8));
        let first = writer.shutdown(Duration::from_millis(100));
        assert_eq!(
            first,
            ShutdownReport {
                complete: false,
                estimated_left: 1
            }
        );

        let second = writer.shutdown(Duration::from_millis(100));
        assert_eq!(
            second,
            ShutdownReport {
                complete: false,
                estimated_left: 1
            },
            "the stuck thread is still there"
        );

        states[1].release();
        let third = writer.shutdown(FLUSH_BUDGET);
        assert_eq!(
            third,
            ShutdownReport {
                complete: true,
                estimated_left: 0
            }
        );
        assert_eq!(fake_shape(&states[1]), ["a0"]);
    }

    // ---- the runtime error policy ---------------------------------------

    /// AC20: a write error loses that entry, closes the file and marks the hole;
    /// the next entry reopens the stream, and its line is preceded by one `gap`
    /// marker that counts the five lost entries and spans their `at`.
    #[test]
    fn a_write_error_loses_the_entry_and_marks_the_gap() {
        let states = FakeState::three();
        states[0].fail_next.store(5, Ordering::SeqCst);
        let writer = fake_writer(&states, eager_reopen());
        let at = |i: u64| BASE_MS + i;
        let control_entry = |i: u64| entry(&format!("c{i}"), Frontend::Operator, at(i));

        for i in 1..=5 {
            writer.record(AuditLane::Evidence, control_entry(i));
        }
        assert!(
            wait_until(WAIT, || { writer.status().write_failures == 5 }),
            "five failures were not reported: {:?}",
            writer.status()
        );
        assert!(
            writer.status().degraded,
            "a stream whose writes fail is degraded"
        );

        writer.record(AuditLane::Evidence, control_entry(6));
        let report = writer.shutdown(FLUSH_BUDGET);
        assert!(report.complete, "the flush did not finish: {report:?}");
        assert!(
            !writer.status().degraded,
            "the sixth entry's write succeeded, which clears degraded"
        );

        let gaps = fake_gaps(&states[0]);
        assert_eq!(
            gaps.len(),
            1,
            "expected exactly one gap marker with failed == 5, found {}",
            gaps.len()
        );
        assert_eq!(gaps[0]["failed"], 5);
        assert_eq!(gaps[0]["dropped"], 0);
        assert_eq!(gaps[0]["from"], at(1));
        assert_eq!(gaps[0]["to"], at(5));
        assert_eq!(
            fake_shape(&states[0]),
            ["gap", "c6"],
            "the marker sits right before the first entry written after the hole"
        );
        assert_eq!(
            states[0].open_calls.load(Ordering::SeqCst),
            5,
            "each failure closed the file; c2 to c6 each reopened it"
        );
        assert_eq!(
            writer.status(),
            DurableAuditStatus {
                degraded: false,
                dropped: 0,
                write_failures: 5
            }
        );
    }

    /// A stream that arrived without a file (its boot open failed) counts boot
    /// as its last attempt: with a long reopen interval every entry is a failure
    /// that costs no `open`, and once the interval is zero each entry tries one.
    #[test]
    fn a_stream_that_never_opened_counts_every_entry_as_a_failure() {
        let run = |reopen: Duration| {
            let states = FakeState::three();
            states[1].fail_open.store(true, Ordering::SeqCst);
            let tuning = Tuning {
                reopen,
                ..Tuning::production()
            };
            let writer = fake_writer_with_files(&states, tuning, [true, false, true]);
            for i in 1..=3 {
                writer.record(AuditLane::Evidence, agent_entry(i));
            }
            let counted = wait_until(WAIT, || writer.status().write_failures == 3);
            let status = writer.status();
            let opens = states[1].open_calls.load(Ordering::SeqCst);
            let report = writer.shutdown(FLUSH_BUDGET);
            assert!(report.complete, "the flush did not finish: {report:?}");
            assert!(
                states[1].lines().is_empty(),
                "nothing can be written to a stream with no file"
            );
            (counted, status.write_failures, status.degraded, opens)
        };

        assert_eq!(
            run(Duration::from_secs(3600)),
            (true, 3, true, 0),
            "an hour between opens: three failures and no open"
        );
        assert_eq!(
            run(Duration::ZERO),
            (true, 3, true, 3),
            "no wait between opens: three failures and three opens"
        );
    }

    /// The throttle admits the first failure, then one line per interval, and
    /// says how many it swallowed in between: the count starts again after each
    /// line (the last call, at 121 s, swallowed only the one at 61 s).
    #[test]
    fn warn_throttle_logs_first_then_once_per_interval() {
        let mut throttle = WarnThrottle::new(Duration::from_secs(60));
        let t0 = Instant::now();
        let at = |seconds: u64| t0 + Duration::from_secs(seconds);
        let got = [0, 1, 2, 60, 61, 121].map(|seconds| throttle.admit(at(seconds)));
        assert_eq!(got, [Some(0), None, None, Some(2), None, Some(1)]);
    }

    /// A writer thread that panics in a write reads as degraded at once, every
    /// later `record` is counted as dropped, and nothing reaches the caller.
    #[test]
    fn a_dead_writer_thread_reports_degraded() {
        let states = FakeState::three();
        states[1].panic_on_write.store(true, Ordering::SeqCst);
        let writer = fake_writer(&states, Tuning::production());
        writer.record(AuditLane::Evidence, agent_entry(1));
        assert!(
            wait_until(WAIT, || writer.status().degraded),
            "a dead writer thread did not degrade the writer"
        );

        let caller = writer.clone();
        within(
            Duration::from_secs(1),
            "five records after the writer thread died",
            move || {
                for i in 2..=6 {
                    caller.record(AuditLane::Evidence, agent_entry(i));
                }
            },
        );
        assert_eq!(writer.status().dropped, 5);
        assert!(writer.status().degraded, "a dead thread stays degraded");
    }

    /// A moment far enough back that a reopen interval of a few seconds has
    /// passed since it, for the tests that drive a [`StreamWriter`] by hand.
    fn long_ago() -> Instant {
        let now = Instant::now();
        // A machine that started less than ten seconds ago has no such moment; the
        // tests then get no head start and fail on their own assertions.
        now.checked_sub(Duration::from_secs(10)).unwrap_or(now)
    }

    /// A [`StreamWriter`] over `state`, with its file open or not, whose reopen
    /// interval is five seconds and whose last attempt at opening is [`long_ago`]:
    /// the next entry may reopen, and an entry that follows an attempt of its own
    /// must not.
    fn hand_driven<'a>(
        state: &Arc<FakeState>,
        has_file: bool,
        shared: &'a StreamShared,
    ) -> StreamWriter<'a> {
        let file: Option<Box<dyn LogFile>> = if has_file {
            Some(Box::new(FakeFile(state.clone())))
        } else {
            None
        };
        let spec = StreamSpec {
            path: PathBuf::from("/fake/hand-driven.jsonl"),
            backend: Box::new(FakeBackend(state.clone())),
            file,
        };
        let tuning = Tuning {
            reopen: Duration::from_secs(5),
            ..Tuning::production()
        };
        let mut writer = StreamWriter::new(StreamKind::Agent, spec, shared, &tuning);
        writer.last_open_attempt = long_ago();
        writer
    }

    /// A write error closes the file and starts the reopen interval: the next
    /// entry fails fast without an `open`, even though the stream has been up
    /// longer than the interval; once the interval has passed again the next
    /// entry reopens and its line is preceded by the gap marker.
    #[test]
    fn a_write_error_closes_the_file_and_starts_the_reopen_interval() {
        let state = FakeState::plain();
        state.fail_next.store(1, Ordering::SeqCst);
        let shared = StreamShared::default();
        let mut writer = hand_driven(&state, true, &shared);

        let before = Instant::now();
        writer.write_entry(&agent_entry(1));
        assert!(
            writer.spec.file.is_none(),
            "the failed write closed the file"
        );
        assert!(
            writer.last_open_attempt >= before,
            "the failure started the reopen interval"
        );

        writer.write_entry(&agent_entry(2));
        assert_eq!(
            state.open_calls.load(Ordering::SeqCst),
            0,
            "inside the interval an entry fails fast"
        );
        assert_eq!(shared.write_failures.load(Ordering::Relaxed), 2);
        assert!(shared.degraded.load(Ordering::Relaxed));
        assert!(state.lines().is_empty(), "nothing was written yet");

        writer.last_open_attempt = long_ago();
        writer.write_entry(&agent_entry(3));
        assert_eq!(state.open_calls.load(Ordering::SeqCst), 1, "one reopen");
        assert_eq!(fake_shape(&state), ["gap", "a3"]);
        let gap = &fake_gaps(&state)[0];
        assert_eq!(gap["failed"], 2);
        assert_eq!(gap["from"], BASE_MS + 1);
        assert_eq!(gap["to"], BASE_MS + 2);
        assert_eq!(shared.write_failures.load(Ordering::Relaxed), 2);
        assert!(!shared.degraded.load(Ordering::Relaxed), "recovered");
    }

    /// A failed open starts the reopen interval again: the entry after it fails
    /// fast without another `open`.
    #[test]
    fn a_failed_open_starts_the_reopen_interval_again() {
        let state = FakeState::plain();
        state.fail_open.store(true, Ordering::SeqCst);
        let shared = StreamShared::default();
        let mut writer = hand_driven(&state, false, &shared);

        writer.write_entry(&agent_entry(1));
        assert_eq!(
            state.open_calls.load(Ordering::SeqCst),
            1,
            "one try to open"
        );
        writer.write_entry(&agent_entry(2));
        assert_eq!(
            state.open_calls.load(Ordering::SeqCst),
            1,
            "the failed open started the interval: no second open"
        );
        assert_eq!(shared.write_failures.load(Ordering::Relaxed), 2);

        state.fail_open.store(false, Ordering::SeqCst);
        writer.last_open_attempt = long_ago();
        writer.write_entry(&agent_entry(3));
        assert_eq!(state.open_calls.load(Ordering::SeqCst), 2);
        assert_eq!(fake_shape(&state), ["gap", "a3"]);
        assert_eq!(fake_gaps(&state)[0]["failed"], 2);
        assert!(!shared.degraded.load(Ordering::Relaxed), "recovered");
    }

    /// What a test subscriber wrote, shared with the test.
    #[derive(Clone, Default)]
    struct LogCapture(Arc<Mutex<Vec<u8>>>);

    impl LogCapture {
        fn text(&self) -> String {
            String::from_utf8_lossy(&lock(&self.0)).into_owned()
        }
    }

    impl io::Write for LogCapture {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            lock(&self.0).extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// Made up, like every canary in these tests; it stands for any entry field.
    const LOG_CANARY: &str = "CNRY0x00c0ffee00";

    /// Runs one stream's thread body over four entries, the first three of
    /// which are lost to write errors (the entry `e1`, then the gap marker that
    /// `e2` and `e3` try to write first), on **this** thread, under a subscriber
    /// scoped to it. Returns what was logged, the stream's counters and the file.
    fn run_a_failing_stream_logging() -> (String, StreamShared, Arc<FakeState>) {
        let state = FakeState::plain();
        state.fail_next.store(3, Ordering::SeqCst);
        let spec = StreamSpec {
            path: PathBuf::from("/fake/log-test/the-file.jsonl"),
            backend: Box::new(FakeBackend(state.clone())),
            file: Some(Box::new(FakeFile(state.clone()))),
        };
        let tuning = Tuning {
            reopen: Duration::ZERO,
            warn_every: Duration::from_secs(3600),
            ..Tuning::production()
        };
        let shared = StreamShared::default();
        let (tx, rx) = sync_channel(8);
        for i in 1..=4 {
            let queued = AuditEntry {
                args_summary: format!("{{\"token\":\"{LOG_CANARY}\"}}"),
                ..entry(&format!("{LOG_CANARY}-{i}"), Frontend::Mcp, BASE_MS + i)
            };
            shared.queued.fetch_add(1, Ordering::Relaxed);
            tx.send(Msg::Entry(queued)).expect("queue an entry");
        }
        tx.send(Msg::Close).expect("queue the close");

        let capture = LogCapture::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer({
                let capture = capture.clone();
                move || capture.clone()
            })
            .with_ansi(false)
            .without_time()
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            run_stream(rx, spec, &shared, StreamKind::Agent, &tuning);
        });
        (capture.text(), shared, state)
    }

    /// Failures are logged at `warn!` once (the throttle swallows the rest of
    /// the interval), the first success after them is one `info!` that names the
    /// stream and how many failed, and no line carries anything of an entry. The
    /// stream's thread body runs on the test's own thread here, so that a
    /// subscriber scoped to this thread sees its events.
    #[test]
    fn failures_are_logged_once_and_the_recovery_names_the_stream() {
        // `tracing` caches per callsite whether any subscriber wants it. Another
        // test's stream thread that reaches one of these callsites for the first
        // time in the process just as this thread installs its subscriber can
        // leave that cache saying "no one": `tracing-core` computes the interest
        // against a snapshot of the subscribers, then stores it, and the store
        // can land after the rebuild this subscriber's installation triggered.
        // A callsite registers once per process, and installing a subscriber
        // rebuilds the cache, so one more attempt sees the events. An attempt
        // whose log lacks a whole level is that race; anything else is judged.
        let mut attempt = run_a_failing_stream_logging();
        for _ in 0..4 {
            if attempt.0.contains("WARN") && attempt.0.contains("INFO") {
                break;
            }
            attempt = run_a_failing_stream_logging();
        }
        let (log, shared, state) = attempt;

        let lines_at = |level: &str| -> Vec<&str> {
            log.lines().filter(|line| line.contains(level)).collect()
        };
        let warns = lines_at("WARN");
        let infos = lines_at("INFO");
        assert_eq!(warns.len(), 1, "one warn for three failures: {log}");
        for needle in [
            "aitm::audit",
            "/fake/log-test/the-file.jsonl",
            "StorageFull",
            // The error's own text, not only its kind.
            "the fake disk is full",
            "suppressed=0",
        ] {
            assert!(warns[0].contains(needle), "the warn lacks {needle}: {log}");
        }
        assert_eq!(infos.len(), 1, "one info for the recovery: {log}");
        for needle in ["aitm::audit", "agent", "failures=3"] {
            assert!(infos[0].contains(needle), "the info lacks {needle}: {log}");
        }
        assert_eq!(
            log.lines().count(),
            2,
            "nothing else is logged on this path: {log}"
        );
        assert!(
            !log.contains(LOG_CANARY),
            "an entry field reached the log: {log}"
        );
        assert_eq!(shared.write_failures.load(Ordering::Relaxed), 3);
        assert!(!shared.degraded.load(Ordering::Relaxed), "recovered");
        assert_eq!(
            fake_shape(&state),
            ["gap".to_string(), format!("{LOG_CANARY}-4")]
        );
    }

    // ---- rotation and retention -----------------------------------------

    /// Real files, a cap of 2048 bytes and `keep` rotated files per stream.
    fn rotating(keep: usize) -> Tuning {
        Tuning {
            cap_bytes: [2048; 3],
            keep: [keep; 3],
            ..Tuning::production()
        }
    }

    /// The agent-origin entry `c<i>` whose line is about 250 bytes.
    fn fat_entry(i: u64) -> AuditEntry {
        AuditEntry {
            args_summary: "x".repeat(150),
            ..entry(&format!("c{i}"), Frontend::Mcp, BASE_MS + i)
        }
    }

    /// `path` with `.n` appended to its whole file name: how a rotated file is
    /// named.
    fn numbered(path: &Path, n: usize) -> PathBuf {
        PathBuf::from(format!("{}.{n}", path.display()))
    }

    /// One stream's files, oldest first: `F.n` ... `F.1`, `F`, only the ones
    /// that exist.
    fn stream_files(path: &Path) -> Vec<PathBuf> {
        let mut files = Vec::new();
        let mut n = 1;
        while numbered(path, n).exists() {
            files.push(numbered(path, n));
            n += 1;
        }
        files.reverse();
        files.push(path.to_path_buf());
        files
    }

    /// Records `c0` to `c{n - 1}` through the ring, as every audited call does.
    fn record_fat(ring: &AuditRing, n: u64) {
        for i in 0..n {
            ring.append_in(AuditLane::Evidence, fat_entry(i));
        }
    }

    /// The file names in `dir`, sorted.
    fn dir_listing(dir: &Path) -> Vec<String> {
        let mut found: Vec<String> = fs::read_dir(dir)
            .unwrap_or_else(|e| panic!("list {}: {e}", dir.display()))
            .flatten()
            .map(|child| child.file_name().to_string_lossy().into_owned())
            .collect();
        found.sort();
        found
    }

    /// Makes `dir` refuse new names (`chmod 0500`) while the files already open
    /// in it stay writable. `false` when it still takes a new file (the process
    /// is root): the caller reports the skip.
    #[cfg(unix)]
    fn lock_directory(dir: &Path) -> bool {
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(dir, fs::Permissions::from_mode(0o500)).expect("chmod 0500");
        let probe = dir.join("probe");
        let writable = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&probe)
            .is_ok();
        if writable {
            let _ = fs::remove_file(&probe);
            unlock_directory(dir);
        }
        !writable
    }

    #[cfg(unix)]
    fn unlock_directory(dir: &Path) {
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).expect("chmod 0700");
    }

    /// The real backend that counts the rotations it is asked for.
    struct CountingBackend {
        rotates: Arc<AtomicUsize>,
    }

    impl Backend for CountingBackend {
        fn open(&mut self, path: &Path, stream: StreamKind) -> io::Result<Box<dyn LogFile>> {
            FsBackend.open(path, stream)
        }

        fn rotate(
            &mut self,
            path: &Path,
            stream: StreamKind,
            keep: usize,
        ) -> io::Result<Box<dyn LogFile>> {
            self.rotates.fetch_add(1, Ordering::SeqCst);
            FsBackend.rotate(path, stream, keep)
        }
    }

    /// [`fs_writer`] whose backends count their rotations (one counter, shared).
    fn counting_fs_writer(
        dir: &Scratch,
        tuning: Tuning,
    ) -> (
        Arc<AuditRing>,
        Arc<AuditLogWriter>,
        [PathBuf; 3],
        Arc<AtomicUsize>,
    ) {
        let rotates = Arc::new(AtomicUsize::new(0));
        let base = dir.join("audit.jsonl");
        let paths = StreamKind::ALL.map(|kind| stream_path(&base, kind));
        let specs = StreamKind::ALL.map(|kind| {
            let path = stream_path(&base, kind);
            let file = preflight(&path, kind)
                .unwrap_or_else(|e| panic!("preflight of the {} stream failed: {e}", kind.label()));
            StreamSpec {
                path,
                backend: Box::new(CountingBackend {
                    rotates: rotates.clone(),
                }),
                file: Some(Box::new(file)),
            }
        });
        let writer = Arc::new(
            AuditLogWriter::from_specs(specs, tuning).unwrap_or_else(|e| panic!("start: {e}")),
        );
        let ring = Arc::new(AuditRing::new(8192));
        assert!(ring.attach_durable(writer.clone()));
        (ring, writer, paths, rotates)
    }

    /// The command of every entry line in `path` that is a number after `c`.
    fn c_numbers(path: &Path) -> Vec<u64> {
        entry_commands(path)
            .iter()
            .map(|command| {
                command[1..]
                    .parse()
                    .unwrap_or_else(|_| panic!("{command:?} is not c<number>"))
            })
            .collect()
    }

    /// AC23: with room for every rotated file, rotation loses no line and keeps
    /// them in order; no file is over the cap and each begins with a `start`
    /// marker. The line that triggers a rotation is written to the new file.
    #[test]
    fn rotation_loses_no_line() {
        let dir = scratch("rotate-all");
        let (ring, writer, paths) = fs_writer(&dir, rotating(100));
        record_fat(&ring, 100);
        let report = writer.shutdown(FLUSH_BUDGET);
        assert!(report.complete, "the flush did not finish: {report:?}");

        let files = stream_files(&paths[1]);
        let commands: Vec<String> = files.iter().flat_map(|file| entry_commands(file)).collect();
        let mut problems: Vec<String> = Vec::new();
        if files.len() < 3 {
            problems.push(format!(
                "only {} file(s) for the stream: the file never rotated",
                files.len()
            ));
        }
        for file in &files {
            let len = fs::metadata(file).map(|meta| meta.len()).unwrap_or(0);
            if len > 2048 {
                problems.push(format!(
                    "{} holds {len} bytes, over the 2048 cap",
                    file.display()
                ));
            }
            if !read_lines(file)
                .first()
                .is_some_and(|line| line["marker"] == "start")
            {
                problems.push(format!(
                    "{} does not begin with a start marker",
                    file.display()
                ));
            }
        }
        assert!(problems.is_empty(), "{}", problems.join("\n"));
        assert_eq!(commands, names("c", 100), "every line once, in order");
        assert_eq!(
            writer.status(),
            DurableAuditStatus {
                degraded: false,
                dropped: 0,
                write_failures: 0
            }
        );
    }

    /// AC24: with two rotated files kept, the oldest lines are the ones that go,
    /// and nothing but the three streams' files and the agent's two rotated
    /// ones is left in the directory.
    #[test]
    fn retention_deletes_only_the_oldest_rotated_file() {
        let dir = scratch("rotate-keep");
        let (ring, writer, paths) = fs_writer(&dir, rotating(2));
        record_fat(&ring, 100);
        let report = writer.shutdown(FLUSH_BUDGET);
        assert!(report.complete, "the flush did not finish: {report:?}");

        assert_eq!(
            dir_listing(&dir.0),
            [
                "audit.agent.jsonl",
                "audit.agent.jsonl.1",
                "audit.agent.jsonl.2",
                "audit.jsonl",
                "audit.reads.jsonl"
            ],
            "the agent stream keeps its file and two rotated ones, no F.3"
        );
        let agent = &paths[1];
        let oldest_first = [numbered(agent, 2), numbered(agent, 1), agent.clone()];
        let kept: Vec<u64> = oldest_first
            .iter()
            .flat_map(|file| c_numbers(file))
            .collect();
        assert!(
            kept.windows(2).all(|pair| pair[1] == pair[0] + 1),
            "the kept lines are not one contiguous run: {kept:?}"
        );
        assert_eq!(kept.last(), Some(&99), "the run ends at the newest line");
        assert!(
            kept.first().is_some_and(|first| *first > 0),
            "c0 is the oldest line and must be gone: {kept:?}"
        );
        assert!(
            c_numbers(agent).contains(&99) || c_numbers(&numbered(agent, 1)).contains(&99),
            "c99 is in F or F.1"
        );
        for other in [&paths[0], &paths[2]] {
            let lines = read_lines(other);
            assert_eq!(lines.len(), 1, "{} was written to", other.display());
            assert_eq!(lines[0]["marker"], "start");
        }
    }

    /// AC25: a rotation that cannot rename or create never costs a line: every
    /// line goes to the file that is still open, which grows past the cap (12
    /// lines of 250 bytes against a cap of 2048: past the cap, under the ceiling
    /// of twice the cap that `a_wedged_rotation_holds_the_file_to_twice_its_cap`
    /// covers), and a failed rotation is not a write failure; it does leave the
    /// writer `degraded` while it lasts.
    #[cfg(unix)]
    #[test]
    fn a_failed_rotation_never_drops_the_line() {
        let dir = scratch("rotate-fail");
        let (ring, writer, paths) = fs_writer(&dir, rotating(100));
        if !lock_directory(&dir.0) {
            skipped("a_failed_rotation_never_drops_the_line (running as root)");
            writer.shutdown(FLUSH_BUDGET);
            return;
        }
        record_fat(&ring, 12);
        let report = writer.shutdown(FLUSH_BUDGET);
        unlock_directory(&dir.0);
        assert!(report.complete, "the flush did not finish: {report:?}");

        let agent = &paths[1];
        assert_eq!(
            entry_commands(agent),
            names("c", 12),
            "all 12 lines are in the active file"
        );
        let len = fs::metadata(agent).expect("the active file").len();
        assert!(
            len > 2048,
            "the cap is soft while rotation fails: {len} bytes"
        );
        assert!(!numbered(agent, 1).exists(), "nothing rotated");
        assert_eq!(
            writer.status(),
            DurableAuditStatus {
                degraded: true,
                dropped: 0,
                write_failures: 0
            },
            "a failed rotation is not a write failure, and costs no line under the ceiling"
        );
    }

    /// AC26: a file that is already over the cap at boot (a restart after a long
    /// run) is rotated by its first write: the old content, then the boot
    /// `start` marker, are in `F.1`, and `F` is a fresh file.
    #[test]
    fn an_oversized_file_rotates_on_its_first_write() {
        let dir = scratch("rotate-oversized");
        let base = dir.join("audit.jsonl");
        let agent = stream_path(&base, StreamKind::Agent);
        // 50 whole lines of exactly 100 bytes each.
        let old: String = (0..50)
            .map(|i| format!("{{\"old\":{i:03},\"pad\":\"{}\"}}\n", "p".repeat(79)))
            .collect();
        assert_eq!(old.len(), 5000);
        fs::write(&agent, &old).expect("pre-fill the agent file");

        let (ring, writer, _paths) = fs_writer(&dir, rotating(3));
        ring.append_in(AuditLane::Evidence, fat_entry(0));
        let report = writer.shutdown(FLUSH_BUDGET);
        assert!(report.complete, "the flush did not finish: {report:?}");

        let rotated = fs::read_to_string(numbered(&agent, 1)).expect("F.1 exists");
        assert!(
            rotated.starts_with(&old),
            "F.1 does not begin with the old content"
        );
        let boot_marker: Vec<&str> = rotated[old.len()..].lines().collect();
        assert_eq!(boot_marker.len(), 1, "F.1 ends with the boot start marker");
        let boot_marker: Value = serde_json::from_str(boot_marker[0]).expect("a JSON marker");
        assert_eq!(boot_marker["marker"], "start");

        let fresh = read_lines(&agent);
        assert_eq!(fresh.len(), 2, "F is a start marker and the entry");
        assert_eq!(fresh[0]["marker"], "start");
        assert_eq!(fresh[1]["command"], "c0");
        assert!(!numbered(&agent, 2).exists(), "one rotation, no F.2");
    }

    /// The oldest slot holding something that is not a regular file makes the
    /// rotation fail without deleting or renaming anything; the writer keeps
    /// writing to the file it has.
    #[cfg(unix)]
    #[test]
    fn rotation_never_deletes_a_non_regular_oldest_slot() {
        let dir = scratch("rotate-slot");
        let base = dir.join("audit.jsonl");
        let agent = stream_path(&base, StreamKind::Agent);
        fs::write(numbered(&agent, 1), "older\n").expect("make F.1");
        let slot = numbered(&agent, 2);
        fs::create_dir(&slot).expect("make a directory at F.2");
        fs::write(slot.join("keep-me"), "precious").expect("fill the directory");

        let (ring, writer, _paths) = fs_writer(&dir, rotating(2));
        record_fat(&ring, 12);
        let report = writer.shutdown(FLUSH_BUDGET);
        assert!(report.complete, "the flush did not finish: {report:?}");

        let slot_kind = fs::symlink_metadata(&slot).map(|meta| meta.file_type().is_dir());
        assert!(slot_kind.unwrap_or(false), "the directory at F.2 is gone");
        assert_eq!(
            fs::read_to_string(slot.join("keep-me")).ok().as_deref(),
            Some("precious"),
            "the directory's content was touched"
        );
        assert_eq!(
            fs::read_to_string(numbered(&agent, 1)).ok().as_deref(),
            Some("older\n"),
            "F.1 was renamed or rewritten although the rotation could not finish"
        );
        assert_eq!(
            entry_commands(&agent),
            names("c", 12),
            "no line was lost to the failed rotation"
        );
        assert_eq!(writer.status().write_failures, 0);
    }

    /// A rotation that failed is retried at most once per `rotate_retry`, and
    /// retried again when the interval has passed: an hour allows one try over a
    /// hundred lines, no wait allows one per line. The lines are written either way.
    #[cfg(unix)]
    #[test]
    fn a_failed_rotation_is_retried_once_per_interval() {
        let run = |retry: Duration| -> Option<(usize, usize)> {
            let dir = scratch("rotate-retry");
            let tuning = Tuning {
                rotate_retry: retry,
                ..rotating(100)
            };
            let (ring, writer, paths, rotates) = counting_fs_writer(&dir, tuning);
            if !lock_directory(&dir.0) {
                writer.shutdown(FLUSH_BUDGET);
                return None;
            }
            record_fat(&ring, 100);
            let report = writer.shutdown(FLUSH_BUDGET);
            unlock_directory(&dir.0);
            assert!(report.complete, "the flush did not finish: {report:?}");
            Some((
                rotates.load(Ordering::SeqCst),
                entry_commands(&paths[1]).len(),
            ))
        };

        let Some((once, kept)) = run(Duration::from_secs(3600)) else {
            skipped("a_failed_rotation_is_retried_once_per_interval (running as root)");
            return;
        };
        // What fits under the ceiling of twice the cap (4096 bytes) is written, the
        // rest refused: the same either way, so the retry interval is all that
        // differs between the two runs.
        assert_eq!(once, 1, "an hour between tries: one try");
        assert!(
            (9..100).contains(&kept),
            "past the cap, under the ceiling: {kept} lines"
        );
        let (every_line, kept_again) = run(Duration::ZERO).expect("the first run was not skipped");
        assert_eq!(
            kept_again, kept,
            "the interval does not change what is written"
        );
        assert!(
            every_line > 10,
            "no wait between tries: expected a try per line past the cap, got {every_line}"
        );
    }

    /// A rotation that fails and then succeeds loses nothing across the change:
    /// the file that outgrew the cap while the directory was locked is kept whole
    /// as a rotated file, and the lines written after are in a fresh one.
    #[cfg(unix)]
    #[test]
    fn a_failed_rotation_succeeds_once_the_directory_allows_it() {
        let dir = scratch("rotate-recover");
        let tuning = Tuning {
            rotate_retry: Duration::ZERO,
            ..rotating(100)
        };
        let (ring, writer, paths) = fs_writer(&dir, tuning);
        if !lock_directory(&dir.0) {
            skipped("a_failed_rotation_succeeds_once_the_directory_allows_it (running as root)");
            writer.shutdown(FLUSH_BUDGET);
            return;
        }
        // Twelve lines: past the cap of 2048, under the ceiling of twice it.
        for i in 0..12 {
            ring.append_in(AuditLane::Evidence, fat_entry(i));
        }
        let agent = paths[1].clone();
        let written = wait_until(WAIT, || {
            fs::read_to_string(&agent)
                .map(|text| text.lines().filter(|l| l.contains("\"command\"")).count() == 12)
                .unwrap_or(false)
        });
        let degraded_while_locked = writer.status().degraded;
        unlock_directory(&dir.0);
        assert!(written, "the first twelve lines were not written");
        assert!(degraded_while_locked, "a rotation that fails is degraded");
        for i in 12..24 {
            ring.append_in(AuditLane::Evidence, fat_entry(i));
        }
        let report = writer.shutdown(FLUSH_BUDGET);
        assert!(report.complete, "the flush did not finish: {report:?}");
        assert!(!writer.status().degraded, "a rotation that succeeds is not");

        let files = stream_files(&agent);
        let commands: Vec<String> = files.iter().flat_map(|file| entry_commands(file)).collect();
        assert_eq!(commands, names("c", 24), "every line once, in order");
        assert!(
            files.len() >= 2,
            "the file rotated once the directory allowed it"
        );
        let first = fs::metadata(&files[0]).expect("the oldest file").len();
        assert!(
            first > 2048,
            "the file kept through the failures: {first} bytes"
        );
        assert_eq!(writer.status().write_failures, 0);
    }

    /// Plants a symbolic link at `path`, where a rotation looks for the oldest
    /// rotated file: a rotation stops there before it renames anything, on every
    /// try, and so is wedged for as long as the link is.
    #[cfg(unix)]
    fn plant_wedge(path: &Path, dir: &Scratch) {
        std::os::unix::fs::symlink(dir.join("elsewhere"), path).expect("plant the link");
    }

    /// Spec Design 8 and 9: while a rotation keeps failing the file is held to
    /// twice its cap, not left to grow without bound. A symbolic link at the
    /// oldest slot makes every rotation fail; 600 lines of 250 bytes against a
    /// cap of 2048 leave the file at no more than 4096 bytes, the lines that
    /// would take it past that are refused (counted as `dropped`, never written),
    /// what is in the file is the first lines in order, and the status says
    /// `degraded` although no write failed. The link is not touched.
    #[cfg(unix)]
    #[test]
    fn a_wedged_rotation_holds_the_file_to_twice_its_cap() {
        let dir = scratch("rotate-wedged");
        let agent = stream_path(&dir.join("audit.jsonl"), StreamKind::Agent);
        let slot = numbered(&agent, 2);
        plant_wedge(&slot, &dir);
        let tuning = Tuning {
            rotate_retry: Duration::ZERO,
            ..rotating(2)
        };
        let (ring, writer, paths) = fs_writer(&dir, tuning);
        record_fat(&ring, 600);
        let report = writer.shutdown(FLUSH_BUDGET);
        assert!(report.complete, "the flush did not finish: {report:?}");

        let len = fs::metadata(&paths[1]).expect("the active file").len();
        assert!(
            len > 2048 && len <= 2 * 2048,
            "over the cap, held to twice it: {len} bytes"
        );
        let written = entry_commands(&paths[1]);
        assert!(
            written.len() > 8 && written.len() < 600,
            "{} lines written",
            written.len()
        );
        assert_eq!(
            written,
            names("c", written.len()),
            "the first lines, in order, none after a hole"
        );
        assert_eq!(
            writer.status(),
            DurableAuditStatus {
                degraded: true,
                dropped: 600 - written.len() as u64,
                write_failures: 0
            },
            "refused lines are dropped; the wedge is degraded; nothing failed to write"
        );
        assert!(
            fs::symlink_metadata(&slot).is_ok_and(|meta| meta.file_type().is_symlink()),
            "the link at the oldest slot was touched"
        );
        assert!(!numbered(&agent, 1).exists(), "nothing was renamed");
    }

    /// The ceiling ends with the wedge: once the slot is free the next write
    /// rotates (the file that was held at its ceiling is kept whole as `F.1`),
    /// `degraded` clears, and the fresh file opens with a `start` marker and then
    /// one `gap` marker that holds every refused line (counted once). Driven by
    /// hand over real files so that the counts are exact.
    #[cfg(unix)]
    #[test]
    fn a_wedged_rotation_recovers_when_the_slot_is_free() {
        let dir = scratch("rotate-unwedge");
        let path = dir.join("audit.agent.jsonl");
        let slot = numbered(&path, 2);
        plant_wedge(&slot, &dir);
        let file = preflight(&path, StreamKind::Agent).expect("preflight");
        let spec = StreamSpec {
            path: path.clone(),
            backend: Box::new(FsBackend),
            file: Some(Box::new(file)),
        };
        let tuning = Tuning {
            rotate_retry: Duration::ZERO,
            ..rotating(2)
        };
        let shared = StreamShared::default();
        let mut writer = StreamWriter::new(StreamKind::Agent, spec, &shared, &tuning);
        for i in 0..30 {
            writer.write_entry(&fat_entry(i));
        }
        let refused = shared.dropped.load(Ordering::Relaxed);
        let written = entry_commands(&path).len();
        assert!(refused > 0, "the ceiling refused lines");
        assert_eq!(written as u64 + refused, 30, "every line is accounted for");
        assert!(shared.rotation_wedged.load(Ordering::Relaxed), "wedged");
        assert!(
            fs::metadata(&path).expect("the active file").len() <= 2 * 2048,
            "held to twice the cap"
        );

        fs::remove_file(&slot).expect("free the slot");
        writer.write_entry(&fat_entry(30));
        assert!(
            !shared.rotation_wedged.load(Ordering::Relaxed),
            "a rotation that succeeds ends the wedge"
        );
        assert_eq!(
            shared.dropped.load(Ordering::Relaxed),
            refused,
            "the refused lines are not counted again"
        );
        assert_eq!(
            entry_commands(&numbered(&path, 1)),
            names("c", written),
            "the file held at its ceiling is kept whole"
        );
        assert_eq!(line_shape(&path), ["start", "gap", "c30"]);
        let gap = &read_lines(&path)[1];
        assert_eq!(gap["dropped"], refused, "{gap}");
        assert_eq!(gap["failed"], 0, "{gap}");
        assert_eq!(gap["from"], BASE_MS + written as u64, "{gap}");
        assert_eq!(gap["to"], BASE_MS + 29, "{gap}");
    }

    /// The fake backend refuses to rotate (the trait default), so a stream over
    /// a small cap fails to rotate on every entry past it. One warn reaches the
    /// log for those failures (the throttle holds the rest back), it names the
    /// path and the error, never an entry field, and no line is lost to the
    /// failures while the file is under its ceiling: with a cap of two lines, the
    /// fifth of five (the third to fail) would take the file past twice the cap,
    /// and is refused instead.
    #[test]
    fn a_failed_rotation_is_logged_once_through_the_throttle() {
        let queued = |i: u64| AuditEntry {
            args_summary: format!("{{\"token\":\"{LOG_CANARY}\"}}"),
            ..entry(&format!("{LOG_CANARY}-{i}"), Frontend::Mcp, BASE_MS + i)
        };
        let line = aitm_ca::audit::entry_to_jsonl(&queued(1)).len() as u64 + 1;
        let run = || {
            let state = FakeState::plain();
            let spec = StreamSpec {
                path: PathBuf::from("/fake/rotation-log/the-file.jsonl"),
                backend: Box::new(FakeBackend(state.clone())),
                file: Some(Box::new(FakeFile(state.clone()))),
            };
            let tuning = Tuning {
                cap_bytes: [2 * line; 3],
                rotate_retry: Duration::ZERO,
                warn_every: Duration::from_secs(3600),
                ..Tuning::production()
            };
            let shared = StreamShared::default();
            let (tx, rx) = sync_channel(8);
            for i in 1..=5 {
                shared.queued.fetch_add(1, Ordering::Relaxed);
                tx.send(Msg::Entry(queued(i))).expect("queue an entry");
            }
            tx.send(Msg::Close).expect("queue the close");
            run_stream(rx, spec, &shared, StreamKind::Agent, &tuning);
            (shared, state)
        };
        let (log, (shared, state)) = logged_until("WARN", run);

        let warns: Vec<&str> = log.lines().filter(|line| line.contains("WARN")).collect();
        assert_eq!(warns.len(), 1, "one warn for three failed rotations: {log}");
        for needle in [
            "aitm::audit",
            "/fake/rotation-log/the-file.jsonl",
            "Unsupported",
            "rotation",
            "suppressed=0",
        ] {
            assert!(warns[0].contains(needle), "the warn lacks {needle}: {log}");
        }
        assert_eq!(log.lines().count(), 1, "nothing else is logged: {log}");
        assert!(
            !log.contains(LOG_CANARY),
            "an entry field reached the log: {log}"
        );
        assert_eq!(
            fake_entry_count(&state),
            4,
            "a failed rotation costs no line under the ceiling; the fifth is past it"
        );
        assert_eq!(shared.dropped.load(Ordering::Relaxed), 1);
        assert_eq!(shared.write_failures.load(Ordering::Relaxed), 0);
        assert!(!shared.degraded.load(Ordering::Relaxed));
        assert!(shared.rotation_wedged.load(Ordering::Relaxed));
        assert_eq!(
            state.syncs.load(Ordering::SeqCst),
            3 + 1 + 1,
            "the file is synced before each try at moving it (three lines, and the \
             marker at close that reports the refused one) and once at close"
        );
    }

    /// Spec Design 8: rotate when `size + line.len() > M`: a line that exactly
    /// fills the cap stays, one byte more rotates, and the `gap` marker that is
    /// pending is part of what has to fit. Driven by hand over a real file whose
    /// sizes are measured, so the cap can be set to the byte.
    #[test]
    fn the_cap_is_exact_and_counts_the_pending_gap_marker() {
        let rotated_with = |hole: bool, spare: i64| -> bool {
            let dir = scratch("rotate-exact");
            let path = dir.join("audit.agent.jsonl");
            let file = preflight(&path, StreamKind::Agent).expect("preflight");
            let boot = LogFile::size(&file) as i64;
            let queued = fat_entry(0);
            let line = aitm_ca::audit::entry_to_jsonl(&queued).len() as i64 + 1;
            let mut gap = GapState::default();
            gap.note_drop((BASE_MS + 5) as i64);
            let marker = if hole {
                marker_for(&gap).len() as i64 + 1
            } else {
                0
            };
            let cap = (boot + line + marker + spare) as u64;

            let spec = StreamSpec {
                path: path.clone(),
                backend: Box::new(FsBackend),
                file: Some(Box::new(file)),
            };
            let tuning = Tuning {
                cap_bytes: [cap; 3],
                keep: [3; 3],
                ..Tuning::production()
            };
            let shared = StreamShared::default();
            if hole {
                shared.lock_gap().note_drop((BASE_MS + 5) as i64);
            }
            let mut writer = StreamWriter::new(StreamKind::Agent, spec, &shared, &tuning);
            writer.write_entry(&queued);
            drop(writer);

            // Rotated or not, the active file reads: start, the gap if there was
            // one, then the entry. Rotated, the old file is only the boot marker.
            let want: &[&str] = if hole {
                &["start", "gap", "c0"]
            } else {
                &["start", "c0"]
            };
            let lines = read_lines(&path);
            let shape: Vec<&str> = lines
                .iter()
                .map(|line| {
                    line["command"]
                        .as_str()
                        .or(line["marker"].as_str())
                        .unwrap_or("?")
                })
                .collect();
            assert_eq!(shape, want, "hole {hole}, spare {spare}");
            let rotated = numbered(&path, 1).exists();
            if rotated {
                assert_eq!(
                    read_lines(&numbered(&path, 1)).len(),
                    1,
                    "the rotated file is only the boot marker"
                );
            }
            rotated
        };

        assert!(!rotated_with(false, 0), "a line that exactly fills the cap");
        assert!(rotated_with(false, -1), "a line one byte over the cap");
        assert!(
            !rotated_with(true, 0),
            "marker and line that exactly fill the cap"
        );
        assert!(
            rotated_with(true, -1),
            "the pending marker counts: marker and line one byte over the cap"
        );
    }

    /// Each stream rotates by its own cap and keeps its own number of rotated
    /// files, not another stream's: three different caps and keeps, the same
    /// hundred lines through each.
    #[test]
    fn each_stream_rotates_by_its_own_cap_and_keep() {
        let dir = scratch("rotate-own");
        let tuning = Tuning {
            cap_bytes: [1024, 2048, 4096],
            keep: [1, 2, 3],
            ..Tuning::production()
        };
        let (ring, writer, _paths) = fs_writer(&dir, tuning);
        for i in 0..100 {
            let fat = fat_entry(i);
            let operator = AuditEntry {
                origin: Frontend::Operator,
                ..fat.clone()
            };
            ring.append_in(AuditLane::Evidence, operator);
            ring.append_in(AuditLane::Evidence, fat.clone());
            ring.append_in(AuditLane::Routine, fat);
        }
        let report = writer.shutdown(FLUSH_BUDGET);
        assert!(report.complete, "the flush did not finish: {report:?}");

        assert_eq!(
            dir_listing(&dir.0),
            [
                "audit.agent.jsonl",
                "audit.agent.jsonl.1",
                "audit.agent.jsonl.2",
                "audit.jsonl",
                "audit.jsonl.1",
                "audit.reads.jsonl",
                "audit.reads.jsonl.1",
                "audit.reads.jsonl.2",
                "audit.reads.jsonl.3",
            ],
            "control keeps 1 rotated file, agent 2, reads 3"
        );
        let limits = [
            (&dir.join("audit.jsonl"), 1024),
            (&dir.join("audit.agent.jsonl"), 2048),
            (&dir.join("audit.reads.jsonl"), 4096),
        ];
        // A rotated file is full: the line that did not fit (under 300 bytes
        // here) would have taken it past its stream's cap. So a file is neither
        // over its own cap nor rotated early by a smaller stream's.
        let mut off: Vec<String> = Vec::new();
        for (active, cap) in limits {
            for file in stream_files(active) {
                let len = fs::metadata(&file).map(|meta| meta.len()).unwrap_or(0);
                if len > cap {
                    off.push(format!(
                        "{} holds {len} bytes, over its {cap} cap",
                        file.display()
                    ));
                }
                if file != *active && len + 300 <= cap {
                    off.push(format!(
                        "{} holds {len} bytes: rotated well before its {cap} cap",
                        file.display()
                    ));
                }
            }
        }
        assert!(off.is_empty(), "{}", off.join("\n"));
    }

    // ---- the reason in the log, and the gap at shutdown ------------------

    /// Runs `run` under a subscriber scoped to this thread and returns what it
    /// logged beside what it returned.
    fn logged<T>(run: impl FnOnce() -> T) -> (String, T) {
        let capture = LogCapture::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer({
                let capture = capture.clone();
                move || capture.clone()
            })
            .with_ansi(false)
            .without_time()
            .finish();
        let out = tracing::subscriber::with_default(subscriber, run);
        (capture.text(), out)
    }

    /// [`logged`] again while the log has no `level` line: `tracing` can cache
    /// "nobody listens" for a callsite another thread reached first (see
    /// `failures_are_logged_once_and_the_recovery_names_the_stream`), and one
    /// more attempt sees the event.
    fn logged_until<T>(level: &str, mut run: impl FnMut() -> T) -> (String, T) {
        let mut attempt = logged(&mut run);
        for _ in 0..4 {
            if attempt.0.contains(level) {
                break;
            }
            attempt = logged(&mut run);
        }
        attempt
    }

    /// The log of one stream over `path` with the real backend and no open file,
    /// which is asked to write one entry that carries [`LOG_CANARY`].
    #[cfg(unix)]
    fn log_of_a_refused_stream(path: &Path) -> String {
        let (log, ()) = logged_until("WARN", || {
            let spec = StreamSpec {
                path: path.to_path_buf(),
                backend: Box::new(FsBackend),
                file: None,
            };
            let tuning = Tuning {
                reopen: Duration::ZERO,
                ..Tuning::production()
            };
            let shared = StreamShared::default();
            let (tx, rx) = sync_channel(4);
            let queued = AuditEntry {
                args_summary: format!("{{\"token\":\"{LOG_CANARY}\"}}"),
                ..entry(&format!("{LOG_CANARY}-1"), Frontend::Mcp, BASE_MS)
            };
            shared.queued.fetch_add(1, Ordering::Relaxed);
            tx.send(Msg::Entry(queued)).expect("queue an entry");
            tx.send(Msg::Close).expect("queue the close");
            run_stream(rx, spec, &shared, StreamKind::Agent, &tuning);
        });
        log
    }

    /// A refusal by the preflight reaches the log with its reason (a symbolic
    /// link, a second hard link, a world-writable parent, a directory), not only
    /// the `io::ErrorKind` every one of them shares; and no entry field does.
    #[cfg(unix)]
    #[test]
    fn a_preflight_refusal_is_logged_with_its_reason_and_no_entry_field() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let dir = scratch("refusal-log");
        let mut rows: Vec<(&str, PathBuf, &str)> = Vec::new();

        let target = dir.join("target.txt");
        fs::write(&target, "keep\n").expect("write the link target");
        let link = dir.join("link.jsonl");
        symlink(&target, &link).expect("make the symlink");
        rows.push(("symbolic link", link, "symbolic link"));

        let first = dir.join("hard-a.jsonl");
        fs::write(&first, "x\n").expect("write the hard link source");
        fs::hard_link(&first, dir.join("hard-b.jsonl")).expect("make the hard link");
        rows.push(("hard link", first, "hard links"));

        let open_dir = dir.join("open-dir");
        fs::create_dir(&open_dir).expect("make the world-writable parent");
        fs::set_permissions(&open_dir, fs::Permissions::from_mode(0o777)).expect("chmod 0777");
        rows.push((
            "world-writable parent",
            open_dir.join("audit.agent.jsonl"),
            "world-writable",
        ));

        let directory = dir.join("a-directory.jsonl");
        fs::create_dir(&directory).expect("make the directory");
        rows.push(("directory", directory, "not a regular file"));

        let mut failures: Vec<String> = Vec::new();
        for (label, path, reason) in rows {
            let log = log_of_a_refused_stream(&path);
            if !log.contains(reason) {
                failures.push(format!("{label}: the log lacks {reason:?}: {log}"));
            }
            if !log.contains(&path.display().to_string()) {
                failures.push(format!("{label}: the log lacks the path: {log}"));
            }
            if log.contains(LOG_CANARY) {
                failures.push(format!("{label}: an entry field reached the log: {log}"));
            }
        }
        assert!(
            failures.is_empty(),
            "{} row(s) failed:\n{}",
            failures.len(),
            failures.join("\n")
        );
    }

    /// An entry that fails fast, inside the reopen interval, reports the error
    /// that closed the stream, not a message of its own: the one warn an hour
    /// later is as informative as the first.
    #[test]
    fn an_entry_that_fails_fast_reports_the_reason_of_the_last_real_error() {
        let state = FakeState::plain();
        state.fail_open.store(true, Ordering::SeqCst);
        let shared = StreamShared::default();
        let mut writer = hand_driven(&state, false, &shared);

        let first = writer.try_write("a").expect_err("the open fails");
        let second = writer
            .try_write("b")
            .expect_err("the interval has not passed");
        assert_eq!(state.open_calls.load(Ordering::SeqCst), 1, "no second open");
        assert_eq!(first.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(second.kind(), first.kind());
        assert!(
            second.to_string().contains("the fake disk refuses to open"),
            "the fast failure lost the reason: {second}"
        );
    }

    /// A hole noted after the last entry was written is marked in the file by
    /// the shutdown itself, before the final sync, so that a reader sees it. A
    /// stream with nothing pending is not touched.
    #[test]
    fn a_hole_with_no_later_entry_is_marked_at_shutdown_before_the_sync() {
        let states = FakeState::three();
        let writer = fake_writer(&states, Tuning::production());
        let agent = &writer.streams[StreamKind::Agent.index()];
        agent.shared.lock_gap().note_drop((BASE_MS + 7) as i64);
        agent.shared.lock_gap().note_drop((BASE_MS + 9) as i64);

        let report = writer.shutdown(FLUSH_BUDGET);
        assert!(report.complete, "the flush did not finish: {report:?}");

        assert_eq!(fake_shape(&states[1]), ["gap"]);
        let gap = &fake_gaps(&states[1])[0];
        assert_eq!(gap["dropped"], 2);
        assert_eq!(gap["failed"], 0);
        assert_eq!(gap["from"], BASE_MS + 7);
        assert_eq!(gap["to"], BASE_MS + 9);
        assert_eq!(
            states[1].sync_marks(),
            [1],
            "the one sync came after the marker was written"
        );
        for untouched in [&states[0], &states[2]] {
            assert!(
                untouched.lines().is_empty(),
                "a stream with no hole must not be written at shutdown"
            );
        }
    }

    /// The marker at shutdown is best effort: when its write fails the shutdown
    /// still completes, and the counters say what they said (the live counters
    /// are what is left to report the hole).
    #[test]
    fn a_gap_marker_that_fails_at_shutdown_changes_no_counter() {
        let (states, writer, _release) = stuck_agent_writer(agent_queue(8));
        let first = writer.shutdown(Duration::from_millis(100));
        assert!(!first.complete, "the stuck writer cannot have finished");
        writer.record(AuditLane::Evidence, agent_entry(1));
        assert_eq!(writer.status().dropped, 1, "refused: a hole is pending");

        // a0 is past the failure check, so the marker's write is the next to fail.
        states[1].fail_next.store(1, Ordering::SeqCst);
        states[1].release();
        let report = writer.shutdown(FLUSH_BUDGET);
        assert!(report.complete, "the flush did not finish: {report:?}");

        assert_eq!(
            fake_shape(&states[1]),
            ["a0"],
            "the marker could not be written"
        );
        assert_eq!(
            writer.status(),
            DurableAuditStatus {
                degraded: false,
                dropped: 1,
                write_failures: 0
            }
        );
    }

    // ---- the path re-check -----------------------------------------------

    /// A re-check before every entry: for the tests whose subject is what the
    /// writer does about the answer, not when it asks.
    fn rechecking() -> Tuning {
        Tuning {
            recheck: Duration::ZERO,
            ..Tuning::production()
        }
    }

    /// A re-check that never falls due on its own (an hour), and a cap of 2048
    /// bytes: only a rotation asks.
    fn rechecking_only_at_rotation() -> Tuning {
        Tuning {
            recheck: Duration::from_secs(3600),
            cap_bytes: [2048; 3],
            ..Tuning::production()
        }
    }

    /// The operator-origin evidence entry `o<i>` (the control stream), whose `at`
    /// is `BASE_MS + i`.
    fn operator_entry(i: u64) -> AuditEntry {
        entry(&format!("o{i}"), Frontend::Operator, BASE_MS + i)
    }

    /// One word per line of `path`: the entry's command, or the marker's name.
    fn shape_of(path: &Path) -> Vec<String> {
        read_lines(path)
            .iter()
            .map(|line| {
                let command = line.get("command").and_then(Value::as_str);
                let marker = line.get("marker").and_then(Value::as_str);
                command.or(marker).unwrap_or("?").to_string()
            })
            .collect()
    }

    /// The status of a writer that wrote everything and never failed.
    const CLEAN: DurableAuditStatus = DurableAuditStatus {
        degraded: false,
        dropped: 0,
        write_failures: 0,
    };

    /// Makes a FIFO at `path`. `false`, and a `SKIPPED` line, when `mkfifo`
    /// cannot be spawned: the caller skips that row only.
    #[cfg(unix)]
    fn make_fifo(path: &Path, what: &str) -> bool {
        match std::process::Command::new("mkfifo").arg(path).status() {
            Ok(status) if status.success() => true,
            Ok(status) => panic!("mkfifo failed with {status}"),
            Err(e) => {
                skipped(&format!("{what}: mkfifo cannot be spawned ({e})"));
                false
            }
        }
    }

    /// [`fs_writer`] with a backend of the caller's choosing per stream.
    fn fs_writer_with(
        dir: &Scratch,
        tuning: Tuning,
        backend: impl Fn(StreamKind) -> Box<dyn Backend>,
    ) -> (Arc<AuditRing>, Arc<AuditLogWriter>, [PathBuf; 3]) {
        let base = dir.join("audit.jsonl");
        let paths = StreamKind::ALL.map(|kind| stream_path(&base, kind));
        let specs = StreamKind::ALL.map(|kind| {
            let path = stream_path(&base, kind);
            let file = preflight(&path, kind)
                .unwrap_or_else(|e| panic!("preflight of the {} stream failed: {e}", kind.label()));
            StreamSpec {
                path,
                backend: backend(kind),
                file: Some(Box::new(file)),
            }
        });
        let writer = Arc::new(
            AuditLogWriter::from_specs(specs, tuning).unwrap_or_else(|e| panic!("start: {e}")),
        );
        let ring = Arc::new(AuditRing::new(8192));
        assert!(ring.attach_durable(writer.clone()));
        (ring, writer, paths)
    }

    /// The real backend that notes, in order, each call it is asked for, as
    /// `<stream>:open`, `<stream>:rotate` and `<stream>:recheck:<answer>`. With
    /// `half_rotation` a rotation moves the names and then fails to create the
    /// new file: the rotation that gets as far as the rename and no further.
    struct TracingBackend {
        stream: StreamKind,
        events: Events,
        half_rotation: bool,
    }

    /// The calls a [`TracingBackend`] was asked for, in order, shared with the test.
    type Events = Arc<Mutex<Vec<String>>>;

    impl TracingBackend {
        fn note(&self, what: &str) {
            lock(&self.events).push(format!("{}:{what}", self.stream.label()));
        }
    }

    impl Backend for TracingBackend {
        fn open(&mut self, path: &Path, stream: StreamKind) -> io::Result<Box<dyn LogFile>> {
            self.note("open");
            FsBackend.open(path, stream)
        }

        fn rotate(
            &mut self,
            path: &Path,
            stream: StreamKind,
            keep: usize,
        ) -> io::Result<Box<dyn LogFile>> {
            self.note("rotate");
            if self.half_rotation {
                shift_rotated_files(path, keep)?;
                return Err(io::Error::new(
                    io::ErrorKind::StorageFull,
                    "the new file cannot be created",
                ));
            }
            FsBackend.rotate(path, stream, keep)
        }

        fn recheck(&mut self, path: &Path, file: &dyn LogFile) -> Recheck {
            let answer = FsBackend.recheck(path, file);
            self.note(match &answer {
                Recheck::Same => "recheck:same",
                Recheck::Gone => "recheck:gone",
                Recheck::Replaced => "recheck:replaced",
                Recheck::Refused(_) => "recheck:refused",
            });
            answer
        }
    }

    /// [`fs_writer`] over [`TracingBackend`]s sharing one event log.
    fn traced_writer(
        dir: &Scratch,
        tuning: Tuning,
        half_rotation: bool,
    ) -> (Arc<AuditRing>, Arc<AuditLogWriter>, [PathBuf; 3], Events) {
        let events = Events::default();
        let (ring, writer, paths) = fs_writer_with(dir, tuning, |stream| {
            Box::new(TracingBackend {
                stream,
                events: events.clone(),
                half_rotation,
            })
        });
        (ring, writer, paths, events)
    }

    fn events_of(events: &Events) -> Vec<String> {
        lock(events).clone()
    }

    /// 50 whole lines of exactly 100 bytes each (5000 bytes), written to `path`
    /// before a writer starts on it: a file already past a 2048-byte cap.
    fn prefill_past_the_cap(path: &Path) -> String {
        let old: String = (0..50)
            .map(|i| format!("{{\"old\":{i:03},\"pad\":\"{}\"}}\n", "p".repeat(79)))
            .collect();
        assert_eq!(old.len(), 5000);
        fs::write(path, &old).expect("pre-fill the file");
        old
    }

    /// One run of AC22: after start the control file is deleted, `replace` puts
    /// something that is not a regular file at its path (and says whether it
    /// could), and 100 operator entries go through a ring with the writer
    /// attached. What went wrong, if anything.
    fn path_replaced_run(label: &str, replace: impl FnOnce(&Path) -> bool) -> Vec<String> {
        let dir = scratch("recheck-replaced");
        let (ring, writer, paths) = fs_writer(&dir, rechecking());
        fs::remove_file(&paths[0]).expect("delete the control file");
        if !replace(&paths[0]) {
            writer.shutdown(FLUSH_BUDGET);
            return Vec::new();
        }
        let calls = ring.clone();
        within(Duration::from_secs(2), "the 100 record calls", move || {
            for i in 0..100 {
                calls.append_in(AuditLane::Evidence, operator_entry(i));
            }
        });
        let flusher = writer.clone();
        let report = within(Duration::from_secs(5), "shutdown", move || {
            flusher.shutdown(Duration::from_secs(2))
        });

        let mut problems = Vec::new();
        if !report.complete {
            problems.push(format!("{label}: shutdown(2 s) did not finish: {report:?}"));
        }
        let want = DurableAuditStatus {
            degraded: true,
            dropped: 0,
            write_failures: 100,
        };
        if writer.status() != want {
            problems.push(format!(
                "{label}: status is {:?}, expected {want:?}",
                writer.status()
            ));
        }
        if ring.len() != 100 {
            problems.push(format!(
                "{label}: the ring holds {} entries, expected 100",
                ring.len()
            ));
        }
        problems
    }

    /// AC22: a path that becomes a directory (or a FIFO) costs the caller
    /// nothing: every call returns, every entry is a counted write failure, the
    /// ring has them all, and the writer never opens the thing at the path (a
    /// FIFO would block it for ever), so the shutdown does not hang either.
    #[test]
    fn a_path_that_becomes_a_directory_costs_the_caller_nothing() {
        let mut problems = path_replaced_run("directory", |path| {
            fs::create_dir(path).expect("make a directory at the path");
            true
        });
        #[cfg(unix)]
        problems.extend(path_replaced_run("FIFO", |path| {
            make_fifo(path, "the FIFO row")
        }));
        assert!(problems.is_empty(), "{}", problems.join("\n"));
    }

    /// One run of AC27: after start `remove` takes the control file (or its whole
    /// directory) away, and one entry is recorded. What went wrong, if anything.
    fn recreated_after(label: &str, remove: impl FnOnce(&Scratch, &Path)) -> Vec<String> {
        let dir = scratch("recheck-removed");
        let (ring, writer, paths) = fs_writer(&dir, rechecking());
        remove(&dir, &paths[0]);
        ring.append_in(AuditLane::Evidence, operator_entry(1));
        let report = writer.shutdown(FLUSH_BUDGET);

        let mut problems = Vec::new();
        if !report.complete {
            problems.push(format!("{label}: the flush did not finish: {report:?}"));
        }
        if !paths[0].exists() {
            problems.push(format!("{label}: no file at the path after the entry"));
            return problems;
        }
        let shape = shape_of(&paths[0]);
        if shape != ["start", "o1"] {
            problems.push(format!(
                "{label}: the file holds {shape:?}, expected a start marker then the entry"
            ));
        }
        if writer.status() != CLEAN {
            problems.push(format!(
                "{label}: a recreated file is not a failure, but the status is {:?}",
                writer.status()
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let mode = |path: &Path| fs::metadata(path).map(|m| m.permissions().mode() & 0o777);
            let parent = paths[0].parent().expect("the file has a parent");
            if mode(parent).ok() != Some(0o700) {
                problems.push(format!(
                    "{label}: the directory has mode {:?}, expected 0700",
                    mode(parent)
                ));
            }
            if mode(&paths[0]).ok() != Some(0o600) {
                problems.push(format!(
                    "{label}: the file has mode {:?}, expected 0600",
                    mode(&paths[0])
                ));
            }
        }
        problems
    }

    /// AC27: an operator who removes the file, or its whole directory, gets a new
    /// file with a `start` marker at the next entry instead of lines written to an
    /// unlinked inode.
    #[test]
    fn a_removed_file_or_directory_is_recreated_with_a_start_marker() {
        let mut problems = recreated_after("file", |_dir, file| {
            fs::remove_file(file).expect("delete the control file");
        });
        problems.extend(recreated_after("directory", |dir, _file| {
            fs::remove_dir_all(&dir.0).expect("remove the stream directory");
        }));
        assert!(problems.is_empty(), "{}", problems.join("\n"));
    }

    /// AC28: a symbolic link planted where the file was is not written through:
    /// its target keeps its bytes, the entry is a counted failure, and the link is
    /// left where it is.
    #[cfg(unix)]
    #[test]
    fn a_file_swapped_for_a_symlink_is_not_written_through() {
        use std::os::unix::fs::symlink;

        let dir = scratch("recheck-symlink");
        let (ring, writer, paths) = fs_writer(&dir, rechecking());
        let victim = dir.join("victim.txt");
        fs::write(&victim, "known bytes\n").expect("write the victim");
        fs::remove_file(&paths[0]).expect("delete the control file");
        symlink(&victim, &paths[0]).expect("plant the symlink");

        ring.append_in(AuditLane::Evidence, operator_entry(1));
        let report = writer.shutdown(FLUSH_BUDGET);
        assert!(report.complete, "the flush did not finish: {report:?}");

        assert_eq!(
            fs::read(&victim).expect("read the victim"),
            b"known bytes\n",
            "the entry was written through the link"
        );
        assert_eq!(
            writer.status(),
            DurableAuditStatus {
                degraded: true,
                dropped: 0,
                write_failures: 1
            }
        );
        let kind = fs::symlink_metadata(&paths[0]).expect("the link is still there");
        assert!(kind.file_type().is_symlink(), "the link was replaced");
    }

    /// The path's rotation check comes before the rotation. A file left past the
    /// cap and then deleted: the check finds it gone and the writer reopens at
    /// once, so there is no rotation at all (a rotation would create the file
    /// too, with the same lines, which only the order of the calls tells apart)
    /// and no `F.1` is made from a file that is not there.
    #[test]
    fn rotation_rechecks_the_path_first() {
        let dir = scratch("recheck-rotation-gone");
        prefill_past_the_cap(&dir.join("audit.jsonl"));
        let (ring, writer, paths, events) =
            traced_writer(&dir, rechecking_only_at_rotation(), false);
        fs::remove_file(&paths[0]).expect("delete the control file");

        ring.append_in(AuditLane::Evidence, operator_entry(0));
        let report = writer.shutdown(FLUSH_BUDGET);
        assert!(report.complete, "the flush did not finish: {report:?}");

        assert_eq!(
            events_of(&events),
            ["control:recheck:gone", "control:open"],
            "the check came first, found nothing, and the writer reopened without rotating"
        );
        assert_eq!(shape_of(&paths[0]), ["start", "o0"]);
        assert!(
            !numbered(&paths[0], 1).exists(),
            "an F.1 was made from a file that was deleted"
        );
        assert_eq!(writer.status(), CLEAN);
    }

    /// The same check, finding the file where it was: the rotation goes ahead,
    /// after it. `F.1` holds the old content and the boot marker, `F` a start
    /// marker and the entry.
    #[test]
    fn a_rotation_of_an_unchanged_path_checks_it_then_rotates() {
        let dir = scratch("recheck-rotation-same");
        let old = prefill_past_the_cap(&dir.join("audit.jsonl"));
        let (ring, writer, paths, events) =
            traced_writer(&dir, rechecking_only_at_rotation(), false);

        ring.append_in(AuditLane::Evidence, operator_entry(0));
        let report = writer.shutdown(FLUSH_BUDGET);
        assert!(report.complete, "the flush did not finish: {report:?}");

        assert_eq!(
            events_of(&events),
            ["control:recheck:same", "control:rotate"],
            "the check came before the rotation"
        );
        let rotated = fs::read_to_string(numbered(&paths[0], 1)).expect("F.1 exists");
        assert!(rotated.starts_with(&old), "F.1 lost the old content");
        assert_eq!(shape_of(&paths[0]), ["start", "o0"]);
        assert_eq!(writer.status(), CLEAN);
    }

    /// A symbolic link planted at the path of a file that is due for rotation is
    /// refused by the check that precedes the rotation: nothing is rotated or
    /// renamed (the link is not moved aside), the link's target is untouched, and
    /// the entry is a counted failure.
    #[cfg(unix)]
    #[test]
    fn no_rotation_is_attempted_over_a_refused_path() {
        use std::os::unix::fs::symlink;

        let dir = scratch("recheck-rotation-refused");
        prefill_past_the_cap(&dir.join("audit.jsonl"));
        let (ring, writer, paths, events) =
            traced_writer(&dir, rechecking_only_at_rotation(), false);
        let victim = dir.join("victim.txt");
        fs::write(&victim, "known bytes\n").expect("write the victim");
        fs::remove_file(&paths[0]).expect("delete the control file");
        symlink(&victim, &paths[0]).expect("plant the symlink");

        ring.append_in(AuditLane::Evidence, operator_entry(0));
        let report = writer.shutdown(FLUSH_BUDGET);
        assert!(report.complete, "the flush did not finish: {report:?}");

        assert_eq!(events_of(&events), ["control:recheck:refused"]);
        assert_eq!(fs::read(&victim).expect("read"), b"known bytes\n");
        let link = fs::symlink_metadata(&paths[0]).expect("the link is still there");
        assert!(
            link.file_type().is_symlink(),
            "the link was moved or replaced"
        );
        assert!(!numbered(&paths[0], 1).exists(), "the link was rotated");
        assert_eq!(
            writer.status(),
            DurableAuditStatus {
                degraded: true,
                dropped: 0,
                write_failures: 1
            }
        );
    }

    /// What [`FsBackend::recheck`] says about the path of an open file, row by
    /// row, as the path changes under it: unchanged, replaced by another file
    /// (the old one kept, so the new file cannot reuse its inode), deleted, its
    /// directory deleted, and replaced by a symbolic link, a directory and a FIFO.
    /// A file with no identity (a fake) is `Same` wherever the path is a regular file.
    #[test]
    fn fs_backend_recheck_classifies_the_path() {
        let dir = scratch("recheck-classify");
        let mut problems: Vec<String> = Vec::new();
        let mut row = |label: &str, answer: Recheck, want: &str| {
            let (name, reason) = match &answer {
                Recheck::Same => ("same", ""),
                Recheck::Gone => ("gone", ""),
                Recheck::Replaced => ("replaced", ""),
                Recheck::Refused(reason) => ("refused", reason.as_str()),
            };
            let expected = want.split_once(':').unwrap_or((want, ""));
            if name != expected.0 || !reason.contains(expected.1) {
                problems.push(format!(
                    "{label}: answered {answer:?}, expected {want:?} (kind, then a word in the reason)"
                ));
            }
        };

        let path = dir.join("a.jsonl");
        let file = preflight(&path, StreamKind::Control).expect("preflight");
        row("unchanged", FsBackend.recheck(&path, &file), "same");

        // Another file under the name; the first kept, so the inode is not reused.
        let moved = dir.join("a.moved");
        fs::rename(&path, &moved).expect("move the file aside");
        fs::write(&path, "x\n").expect("a new file at the path");
        row("replaced", FsBackend.recheck(&path, &file), "replaced");

        let fake = FakeFile(FakeState::plain());
        row("no identity", FsBackend.recheck(&path, &fake), "same");

        fs::remove_file(&path).expect("delete the file");
        row("deleted", FsBackend.recheck(&path, &file), "gone");

        let nested = dir.join("sub").join("b.jsonl");
        let inner = preflight(&nested, StreamKind::Control).expect("preflight of the nested path");
        fs::remove_dir_all(dir.join("sub")).expect("delete the directory");
        row(
            "directory deleted",
            FsBackend.recheck(&nested, &inner),
            "gone",
        );

        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&moved, &path).expect("plant a symlink");
            row(
                "symlink",
                FsBackend.recheck(&path, &file),
                "refused:symbolic link",
            );
            fs::remove_file(&path).expect("remove the symlink");

            fs::create_dir(&path).expect("make a directory");
            row(
                "directory",
                FsBackend.recheck(&path, &file),
                "refused:regular file",
            );
            fs::remove_dir(&path).expect("remove the directory");

            if make_fifo(&path, "the FIFO row") {
                row(
                    "FIFO",
                    FsBackend.recheck(&path, &file),
                    "refused:regular file",
                );
            }
        }
        assert!(problems.is_empty(), "{}", problems.join("\n"));
    }

    /// Spec Design 8: a file an external `logrotate` renamed, with a new file
    /// under the old name, is not written to: the writer reopens through the
    /// preflight, which keeps the new file's lines, tightens its mode and appends
    /// a `start` marker; the renamed file gets nothing more.
    #[test]
    fn an_externally_rotated_file_is_reopened_not_written_through() {
        let dir = scratch("recheck-logrotate");
        let (ring, writer, paths) = fs_writer(&dir, rechecking());
        let aside = dir.join("audit.jsonl.logrotated");
        fs::rename(&paths[0], &aside).expect("rename the file as logrotate does");
        fs::write(&paths[0], "{\"external\":1}\n").expect("a new file under the old name");

        ring.append_in(AuditLane::Evidence, operator_entry(1));
        let report = writer.shutdown(FLUSH_BUDGET);
        assert!(report.complete, "the flush did not finish: {report:?}");

        assert_eq!(
            shape_of(&aside),
            ["start"],
            "the renamed file was written to"
        );
        let lines = read_lines(&paths[0]);
        assert_eq!(lines.len(), 3, "the new file's line, a marker, the entry");
        assert_eq!(lines[0]["external"], 1, "the new file's own line is kept");
        assert_eq!(lines[1]["marker"], "start");
        assert_eq!(lines[2]["command"], "o1");
        assert_eq!(writer.status(), CLEAN);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let mode = fs::metadata(&paths[0])
                .expect("metadata")
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "the reopen went through the preflight");
        }
    }

    /// A rotation that renamed `F` to `F.1` and then could not create the new `F`
    /// leaves the writer appending to the inode now named `F.1`, with no file at
    /// the path. The next check, from the interval or from the rotation that is
    /// due again, finds the path gone and reopens through the preflight: a fresh
    /// `F` with a `start` marker. No line is lost, and neither the failed rotation
    /// nor the repair is a write failure.
    #[test]
    fn a_half_finished_rotation_is_repaired_by_the_next_recheck() {
        let by_interval = Tuning {
            recheck: Duration::ZERO,
            rotate_retry: Duration::from_secs(3600),
            ..rechecking_only_at_rotation()
        };
        let by_rotation = Tuning {
            recheck: Duration::from_secs(3600),
            rotate_retry: Duration::ZERO,
            ..rechecking_only_at_rotation()
        };
        let mut problems: Vec<String> = Vec::new();
        for (label, tuning) in [
            ("the interval check", by_interval),
            ("the check before the next rotation", by_rotation),
        ] {
            let dir = scratch("recheck-half-rotation");
            let (ring, writer, paths, events) = traced_writer(&dir, tuning, true);
            record_fat(&ring, 12);
            let report = writer.shutdown(FLUSH_BUDGET);
            if !report.complete {
                problems.push(format!("{label}: the flush did not finish: {report:?}"));
            }

            let agent = &paths[1];
            let events: Vec<String> = events_of(&events)
                .into_iter()
                .filter(|event| event.starts_with("agent:"))
                .collect();
            let rotation = events.iter().position(|event| event == "agent:rotate");
            let after: Vec<&str> = rotation
                .map(|at| events[at..].iter().take(3).map(String::as_str).collect())
                .unwrap_or_default();
            if after != ["agent:rotate", "agent:recheck:gone", "agent:open"] {
                problems.push(format!(
                    "{label}: the calls from the rotation on are {after:?}; all: {events:?}"
                ));
            }
            if events.iter().filter(|e| *e == "agent:rotate").count() != 1 {
                problems.push(format!(
                    "{label}: expected exactly one rotation: {events:?}"
                ));
            }

            let rotated = numbered(agent, 1);
            let files: Vec<PathBuf> = vec![rotated.clone(), agent.clone()];
            if !rotated.exists() || !agent.exists() {
                problems.push(format!("{label}: F.1 and F must both exist"));
                continue;
            }
            let commands: Vec<String> =
                files.iter().flat_map(|file| entry_commands(file)).collect();
            if commands != names("c", 12) {
                problems.push(format!("{label}: lines lost or reordered: {commands:?}"));
            }
            if shape_of(agent).first().map(String::as_str) != Some("start") {
                problems.push(format!(
                    "{label}: the fresh F does not begin with a start marker"
                ));
            }
            if writer.status() != CLEAN {
                problems.push(format!(
                    "{label}: neither the failed rotation nor the repair is a failure, status {:?}",
                    writer.status()
                ));
            }
        }
        assert!(problems.is_empty(), "{}", problems.join("\n"));
    }

    /// The interval check waits one interval after the thread starts, runs at
    /// most once per interval, and runs again when an interval has passed.
    #[test]
    fn the_interval_check_first_runs_one_interval_after_boot_and_then_once_per_interval() {
        let state = FakeState::plain();
        let shared = StreamShared::default();
        let before = Instant::now();
        let mut writer = hand_driven(&state, true, &shared);
        let calls = || state.recheck_calls.load(Ordering::SeqCst);
        assert!(
            writer.last_recheck >= before,
            "the interval starts when the writer does"
        );

        for i in 1..=3 {
            writer.write_entry(&agent_entry(i));
        }
        assert_eq!(calls(), 0, "no check before the first interval has passed");

        writer.last_recheck = long_ago();
        writer.write_entry(&agent_entry(4));
        assert_eq!(calls(), 1, "one check once an interval has passed");
        writer.write_entry(&agent_entry(5));
        writer.write_entry(&agent_entry(6));
        assert_eq!(calls(), 1, "at most one check per interval");

        writer.last_recheck = long_ago();
        writer.write_entry(&agent_entry(7));
        assert_eq!(calls(), 2, "and again one interval later");
        assert_eq!(fake_shape(&state), names("a", 8)[1..]);
        assert_eq!(shared.write_failures.load(Ordering::Relaxed), 0);
    }

    /// `Gone` and `Replaced` reopen at once: a reopen interval that is still
    /// running does not hold the reopen back, and the entry is written to the
    /// reopened file, not lost.
    #[test]
    fn a_gone_or_replaced_path_reopens_at_once_and_the_entry_is_written() {
        let state = FakeState::plain();
        state.script_rechecks(vec![Recheck::Gone, Recheck::Replaced]);
        let shared = StreamShared::default();
        let mut writer = hand_driven(&state, true, &shared);
        writer.last_open_attempt = Instant::now();

        for i in 1..=2 {
            writer.last_recheck = long_ago();
            writer.write_entry(&agent_entry(i));
        }

        assert_eq!(state.recheck_calls.load(Ordering::SeqCst), 2);
        assert_eq!(
            state.open_calls.load(Ordering::SeqCst),
            2,
            "one reopen for each answer, interval or not"
        );
        assert_eq!(fake_shape(&state), ["a1", "a2"]);
        assert_eq!(shared.write_failures.load(Ordering::Relaxed), 0);
        assert!(!shared.degraded.load(Ordering::Relaxed));
    }

    /// A `Gone` path whose reopen fails counts the entry as a failure, closes the
    /// handle and starts the reopen interval: the next entry fails fast with no
    /// `open`; once the interval has passed the next reopens, and the gap marker
    /// reports both entries.
    #[test]
    fn a_failed_reopen_after_a_gone_path_fails_the_entry_and_starts_the_interval() {
        let state = FakeState::plain();
        state.script_rechecks(vec![Recheck::Gone]);
        state.fail_open.store(true, Ordering::SeqCst);
        let shared = StreamShared::default();
        let mut writer = hand_driven(&state, true, &shared);

        writer.last_recheck = long_ago();
        let before = Instant::now();
        writer.write_entry(&agent_entry(1));
        assert_eq!(state.open_calls.load(Ordering::SeqCst), 1, "one try");
        assert!(writer.spec.file.is_none(), "the handle is closed");
        assert!(
            writer.last_open_attempt >= before,
            "the failed reopen started the interval"
        );
        assert_eq!(shared.write_failures.load(Ordering::Relaxed), 1);
        assert!(shared.degraded.load(Ordering::Relaxed));

        writer.write_entry(&agent_entry(2));
        assert_eq!(
            state.open_calls.load(Ordering::SeqCst),
            1,
            "inside the interval an entry fails fast"
        );
        assert_eq!(shared.write_failures.load(Ordering::Relaxed), 2);
        assert!(state.lines().is_empty(), "nothing was written");

        state.fail_open.store(false, Ordering::SeqCst);
        writer.last_open_attempt = long_ago();
        writer.write_entry(&agent_entry(3));
        assert_eq!(state.open_calls.load(Ordering::SeqCst), 2);
        assert_eq!(fake_shape(&state), ["gap", "a3"]);
        assert_eq!(fake_gaps(&state)[0]["failed"], 2);
        assert!(!shared.degraded.load(Ordering::Relaxed), "recovered");
    }

    /// A `Refused` path counts the entry as a failure, marks the stream degraded,
    /// drops the handle and writes nothing; it does not open anything (a refused
    /// path is not retried before the interval), and the reason it was refused is
    /// the reason the next entries report.
    #[test]
    fn a_refused_path_fails_the_entry_and_writes_nothing() {
        let state = FakeState::plain();
        state.script_rechecks(vec![Recheck::Refused(
            "the path is now a symbolic link".to_string(),
        )]);
        let shared = StreamShared::default();
        let mut writer = hand_driven(&state, true, &shared);

        writer.last_recheck = long_ago();
        writer.write_entry(&agent_entry(1));
        assert_eq!(shared.write_failures.load(Ordering::Relaxed), 1);
        assert!(shared.degraded.load(Ordering::Relaxed));
        assert!(writer.spec.file.is_none(), "the handle is dropped");
        assert!(state.lines().is_empty(), "nothing was written");
        assert_eq!(state.open_calls.load(Ordering::SeqCst), 0, "nothing opened");
        let reason = writer.last_error.to_string();
        assert!(
            reason.contains("/fake/hand-driven.jsonl")
                && reason.contains("the path is now a symbolic link"),
            "the failure names the path and the reason: {reason}"
        );

        writer.write_entry(&agent_entry(2));
        assert_eq!(shared.write_failures.load(Ordering::Relaxed), 2);
        assert_eq!(state.open_calls.load(Ordering::SeqCst), 0, "fails fast");

        writer.last_open_attempt = long_ago();
        writer.write_entry(&agent_entry(3));
        assert_eq!(state.open_calls.load(Ordering::SeqCst), 1);
        assert_eq!(fake_shape(&state), ["gap", "a3"]);
        assert_eq!(fake_gaps(&state)[0]["failed"], 2);
        assert!(!shared.degraded.load(Ordering::Relaxed), "recovered");
    }

    /// The check before a rotation runs after the pending `gap` marker has been
    /// taken for the write. When it refuses the path the marker goes back: the
    /// next write that succeeds reports the hole that was already there and the
    /// entry the refusal cost.
    #[test]
    fn a_refusal_before_a_rotation_keeps_the_pending_gap() {
        let state = FakeState::plain();
        state.script_rechecks(vec![Recheck::Refused(
            "the path is now a symbolic link".to_string(),
        )]);
        let shared = StreamShared::default();
        let spec = StreamSpec {
            path: PathBuf::from("/fake/hand-driven.jsonl"),
            backend: Box::new(FakeBackend(state.clone())),
            file: Some(Box::new(FakeFile(state.clone()))),
        };
        // A line is about 120 bytes: the second entry, with the marker, is past a
        // cap of 200 (so the check that refuses the path is asked), and the third
        // is past it too but under the ceiling of twice the cap, so it is written.
        let tuning = Tuning {
            cap_bytes: [200; 3],
            recheck: Duration::from_secs(3600),
            reopen: Duration::from_secs(5),
            ..Tuning::production()
        };
        let mut writer = StreamWriter::new(StreamKind::Agent, spec, &shared, &tuning);
        writer.last_open_attempt = long_ago();

        writer.write_entry(&agent_entry(1));
        assert_eq!(fake_shape(&state), ["a1"], "an empty file is not rotated");
        // A hole the queue left earlier, still to be written.
        shared.lock_gap().note_drop((BASE_MS + 50) as i64);
        writer.write_entry(&agent_entry(2));
        assert_eq!(
            state.recheck_calls.load(Ordering::SeqCst),
            1,
            "the rotation that was due asked first"
        );
        assert_eq!(
            fake_shape(&state),
            ["a1"],
            "the refused entry is not written"
        );
        assert_eq!(shared.write_failures.load(Ordering::Relaxed), 1);
        assert!(writer.spec.file.is_none(), "the handle is dropped");

        writer.last_open_attempt = long_ago();
        writer.write_entry(&agent_entry(3));
        assert_eq!(fake_shape(&state), ["a1", "gap", "a3"]);
        let gap = &fake_gaps(&state)[0];
        assert_eq!(gap["dropped"], 1, "the earlier hole was kept");
        assert_eq!(gap["failed"], 1, "and the entry the refusal cost added");
        assert_eq!(gap["from"], BASE_MS + 2);
        assert_eq!(gap["to"], BASE_MS + 50);
        assert!(!shared.degraded.load(Ordering::Relaxed), "recovered");
    }

    // ---- start, the handle and the boot policy ---------------------------
    //
    // No test here resolves `AuditLogSetting::Default`: that would write to the
    // operator's real config directory. Every start names a path under a
    // scratch directory, and every config puts `ca.audit_log` there too.

    /// A config whose audit log is `setting` and whose CA audit log is inside
    /// `dir`, so nothing a test starts touches a directory of the operator's.
    fn config_for(dir: &Scratch, setting: AuditLogSetting) -> Config {
        let mut cfg = Config::default();
        cfg.mcp.audit_log = setting;
        cfg.ca.audit_log = dir.join("ca-audit.jsonl");
        cfg
    }

    fn fresh_ring() -> Arc<AuditRing> {
        Arc::new(AuditRing::new(8192))
    }

    /// Shuts `handle` down and fails the test when the flush did not finish.
    fn flush(handle: &AuditLogHandle) {
        let report = handle.shutdown(FLUSH_BUDGET);
        assert!(report.complete, "the flush did not finish: {report:?}");
    }

    /// The names of everything directly inside `dir`, sorted.
    fn names_in(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(dir)
            .unwrap_or_else(|e| panic!("read {}: {e}", dir.display()))
            .map(|entry| entry.expect("a directory entry").file_name())
            .map(|name| name.to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    /// What each line of `path` is: its `command` for an entry, its `marker`
    /// for a marker.
    fn line_shape(path: &Path) -> Vec<String> {
        read_lines(path)
            .iter()
            .map(|line| {
                line.get("command")
                    .or_else(|| line.get("marker"))
                    .and_then(Value::as_str)
                    .unwrap_or("?")
                    .to_string()
            })
            .collect()
    }

    /// 64 hexadecimal digits, as `web::generate_token` makes them.
    fn is_bridge_token_shaped(token: &str) -> bool {
        token.len() == 64 && token.chars().all(|c| c.is_ascii_hexdigit())
    }

    /// AC5: a fresh start creates the missing directories `0700` and all three
    /// files `0600`, and each file holds exactly one line: its `start` marker.
    #[cfg(unix)]
    #[test]
    fn a_fresh_start_creates_private_files() {
        use std::os::unix::fs::PermissionsExt;

        let dir = scratch("fresh-start");
        let base = dir.join("a").join("b").join("audit.jsonl");
        let cfg = config_for(&dir, AuditLogSetting::Path(base.clone()));
        let ring = fresh_ring();
        let handle = start(&cfg, &ring, None, &[])
            .expect("a usable explicit path starts")
            .expect("an audit log is on");
        flush(&handle);

        let mode = |path: &Path| {
            fs::metadata(path)
                .map(|meta| meta.permissions().mode() & 0o777)
                .unwrap_or(0)
        };
        let mut failures: Vec<String> = Vec::new();
        for parent in [dir.join("a"), dir.join("a").join("b")] {
            let got = mode(&parent);
            if got != 0o700 {
                failures.push(format!("{}: left: {got:o}, right: 700", parent.display()));
            }
        }
        for kind in StreamKind::ALL {
            let path = stream_path(&base, kind);
            let got = mode(&path);
            if got != 0o600 {
                failures.push(format!("{}: left: {got:o}, right: 600", path.display()));
            }
            let text = fs::read_to_string(&path).unwrap_or_default();
            let lines: Vec<&str> = text.lines().collect();
            if lines.len() != 1 {
                failures.push(format!(
                    "{}: left: {} lines, right: 1: {text:?}",
                    path.display(),
                    lines.len()
                ));
                continue;
            }
            let Ok(marker) = serde_json::from_str::<Value>(lines[0]) else {
                failures.push(format!(
                    "{}: the line is not JSON: {text:?}",
                    path.display()
                ));
                continue;
            };
            let mut keys: Vec<&str> = marker
                .as_object()
                .map(|object| object.keys().map(String::as_str).collect())
                .unwrap_or_default();
            keys.sort_unstable();
            if keys != ["at", "marker", "pid", "schema", "stream", "version"] {
                failures.push(format!("{}: keys {keys:?}", path.display()));
            }
            if marker["marker"] != "start" || marker["schema"] != 1 {
                failures.push(format!(
                    "{}: not a schema 1 start: {marker}",
                    path.display()
                ));
            }
            if marker["stream"] != kind.label() {
                failures.push(format!(
                    "{}: left: {}, right: {:?}",
                    path.display(),
                    marker["stream"],
                    kind.label()
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

    /// AC6: a second start on the same path appends: the control file reads
    /// `start, c1, c2, c3, start, c4, c5`, and nothing of the first run is lost.
    #[test]
    fn restart_appends_never_truncates() {
        let dir = scratch("restart");
        let base = dir.join("audit.jsonl");
        let ca_log = dir.join("ca-audit.jsonl");

        let ring = fresh_ring();
        let first = start_at(&ring, &base, &ca_log, true)
            .expect("the first start")
            .expect("an audit log is on");
        for (i, command) in ["c1", "c2", "c3"].into_iter().enumerate() {
            ring.append_in(
                AuditLane::Evidence,
                entry(command, Frontend::Operator, 1 + i as u64),
            );
        }
        flush(&first);

        // A restart is a new process: a fresh ring takes its own sink.
        let ring = fresh_ring();
        let second = start_at(&ring, &base, &ca_log, true)
            .expect("the second start")
            .expect("an audit log is on");
        for (i, command) in ["c4", "c5"].into_iter().enumerate() {
            ring.append_in(
                AuditLane::Evidence,
                entry(command, Frontend::Operator, 10 + i as u64),
            );
        }
        flush(&second);

        assert_eq!(
            line_shape(&base),
            ["start", "c1", "c2", "c3", "start", "c4", "c5"]
        );
    }

    /// AC9: an explicit path that cannot be used fails the boot and creates
    /// nothing; the same path as a default starts degraded and counts every
    /// entry as a write failure; a relative path is unusable either way.
    #[test]
    fn explicit_fails_the_boot_default_degrades() {
        let dir = scratch("boot-policy");
        let blocker = dir.join("F");
        fs::write(&blocker, b"a regular file where a directory is needed")
            .expect("write the blocking file");
        let base = blocker.join("audit.jsonl");
        let ca_log = dir.join("ca-audit.jsonl");

        // Explicit: an error, nothing created, no sink.
        let ring = fresh_ring();
        let refused = start_at(&ring, &base, &ca_log, true);
        assert!(
            refused.is_err(),
            "expected Err for an explicit unusable path, got {refused:?}"
        );
        assert_eq!(names_in(&dir.0), ["F"], "nothing was created");
        assert!(ring.durable_status().is_none(), "no sink was attached");

        // Default: it boots, degraded at once, and an entry counts as a failure.
        let ring = fresh_ring();
        let handle = match start_at(&ring, &base, &ca_log, false) {
            Ok(Some(handle)) => handle,
            other => panic!("expected Some for a default unusable path, got {other:?}"),
        };
        let status = ring
            .durable_status()
            .expect("a sink is attached although the path is unusable");
        assert!(status.degraded, "degraded at once: {status:?}");
        ring.append_in(AuditLane::Evidence, entry("lost", Frontend::Operator, 1));
        assert!(
            wait_until(WAIT, || {
                ring.durable_status()
                    .is_some_and(|status| status.write_failures == 1)
            }),
            "the entry was not counted as a write failure: {:?}",
            ring.durable_status()
        );
        let status = ring.durable_status().expect("the sink stays attached");
        assert_eq!(status.write_failures, 1);
        assert!(status.degraded, "still degraded: {status:?}");
        flush(&handle);
        assert_eq!(names_in(&dir.0), ["F"], "still nothing created");

        // A relative path is unusable in both modes, and nothing is created
        // relative to the working directory.
        let relative_dir = format!("aitm-audit-relative-{}", std::process::id());
        let relative = Path::new(&relative_dir).join("audit.jsonl");
        let ring = fresh_ring();
        let explicit = start_at(&ring, &relative, &ca_log, true);
        let ring_default = fresh_ring();
        let default = start_at(&ring_default, &relative, &ca_log, false);
        let created = Path::new(&relative_dir).exists();
        let _ = fs::remove_dir_all(&relative_dir);
        assert!(
            explicit.is_err(),
            "expected Err for an explicit relative path, got {explicit:?}"
        );
        let Ok(Some(degraded)) = default else {
            panic!("expected Some for a default relative path, got {default:?}");
        };
        assert!(
            ring_default
                .durable_status()
                .is_some_and(|status| status.degraded),
            "a relative default path starts degraded"
        );
        flush(&degraded);
        assert!(!created, "{relative_dir}/ was created");
    }

    /// AC10: with the log off nothing is created and no sink is attached.
    /// (Written before `start` existed, it passes against a stub that returns
    /// `Ok(None)`; the other tests are what make `start` do anything.)
    #[test]
    fn off_creates_nothing() {
        let dir = scratch("off");
        let cfg = config_for(&dir, AuditLogSetting::Off);
        let ring = fresh_ring();
        let env = [("SERVICE_TOKEN".to_string(), "CNRYSRCx0ff0ff01".to_string())];
        let started = start(&cfg, &ring, Some("CNRYSRCx0ff0ff02"), &env)
            .expect("an audit log that is off is not an error");
        assert!(started.is_none(), "expected no handle, got {started:?}");
        assert_eq!(
            names_in(&dir.0),
            Vec::<String>::new(),
            "the directory stays empty"
        );
        assert!(ring.durable_status().is_none(), "no sink is attached");
    }

    /// AC53: the operator bridge token is registered when it is minted, before
    /// the caller sees it; with the audit off the fallback registers nothing.
    #[test]
    fn the_operator_bridge_token_is_registered_when_minted() {
        let dir = scratch("bridge-token");
        let ring = fresh_ring();
        let handle = start_at(&ring, &dir.join("audit.jsonl"), &dir.join("ca.jsonl"), true)
            .expect("start")
            .expect("an audit log is on");
        assert_eq!(handle.registry().len(), 0, "start registers nothing itself");

        let mut failures: Vec<String> = Vec::new();
        let first = handle.generate_bridge_token();
        let second = handle.generate_bridge_token();
        let through_fallback = bridge_token(Some(&handle));
        for (row, token) in [
            ("first", &first),
            ("second", &second),
            ("bridge_token(Some)", &through_fallback),
        ] {
            if !is_bridge_token_shaped(token) {
                failures.push(format!("{row}: not 64 hex digits: {} bytes", token.len()));
            }
            let masked = handle.registry().mask(&format!("a {token} b"));
            if masked != "a [redacted] b" {
                failures.push(format!(
                    "{row}: left: {masked:?}, right: \"a [redacted] b\""
                ));
            }
        }
        if first == second || first == through_fallback || second == through_fallback {
            failures.push("two tokens were equal".to_string());
        }
        if handle.registry().len() != 3 {
            failures.push(format!(
                "left: {} secrets registered, right: 3",
                handle.registry().len()
            ));
        }

        // With the audit off (no handle) the same expression mints a token and
        // registers nothing anywhere.
        let before = handle.registry().len();
        let plain = bridge_token(None);
        if !is_bridge_token_shaped(&plain) {
            failures.push(format!("bridge_token(None): {} bytes", plain.len()));
        }
        if handle.registry().len() != before {
            failures.push("bridge_token(None) registered a token".to_string());
        }
        if handle.registry().mask(&plain) != plain {
            failures.push("bridge_token(None) is masked by a handle it never met".to_string());
        }
        flush(&handle);
        assert!(
            failures.is_empty(),
            "{} row(s) failed:\n{}",
            failures.len(),
            failures.join("\n")
        );
    }

    /// Five made-up secrets, one of them shorter than 8 bytes so that the
    /// registry's short-secret warning fires. None is a prefix of another.
    const SECRETS_51: [&str; 5] = [
        "CNRY51x0badf001",
        "CNRY51x0badf002",
        "CNRY51x0badf003",
        "CNRY51x0badf004",
        "Q51x5",
    ];

    /// The log of one entry carrying every secret in every text field, written
    /// to a file that fails: the stream's thread body runs on this thread so a
    /// subscriber scoped to it sees the warning.
    fn log_of_a_failing_write_carrying(secrets: &[&str]) -> String {
        let (log, ()) = logged_until("WARN", || {
            let state = FakeState::plain();
            state.fail_next.store(1, Ordering::SeqCst);
            let spec = StreamSpec {
                path: PathBuf::from("/fake/secrets-log/the-file.jsonl"),
                backend: Box::new(FakeBackend(state.clone())),
                file: Some(Box::new(FakeFile(state.clone()))),
            };
            let tuning = Tuning {
                reopen: Duration::ZERO,
                ..Tuning::production()
            };
            let shared = StreamShared::default();
            let (tx, rx) = sync_channel(4);
            let all = secrets.join(" ");
            let carrying = AuditEntry {
                client_label: Some(all.clone()),
                connection_id: Some(all.clone()),
                args_summary: format!("{{\"k\":\"{all}\"}}"),
                result: AuditResult::Error(all.clone()),
                ..entry(&all, Frontend::Mcp, BASE_MS)
            };
            shared.queued.fetch_add(1, Ordering::Relaxed);
            tx.send(Msg::Entry(carrying)).expect("queue the entry");
            tx.send(Msg::Close).expect("queue the close");
            run_stream(rx, spec, &shared, StreamKind::Agent, &tuning);
        });
        log
    }

    /// AC51: no registered secret reaches a `Debug` text or a log line. The
    /// registry's `Debug` is its count; the handle's and the writer's carry no
    /// value; `start` and a failing write log no secret, a short one included.
    /// (That nothing here has a `Display` is a grep: see the task's gate.)
    #[test]
    fn a_secret_never_appears_in_debug_display_or_logs() {
        let dir = scratch("secret-hygiene");
        let base = dir.join("audit.jsonl");
        let (log, handle) = logged_until("WARN", || {
            let mut cfg = config_for(&dir, AuditLogSetting::Path(base.clone()));
            cfg.mcp.transport = McpTransport::LoopbackTcp {
                port: 0,
                token: SECRETS_51[0].to_string(),
                endpoint_file: None,
            };
            cfg.mcp.operator_token = Some(SECRETS_51[1].to_string());
            // The short one: the registry warns that this source is only
            // partly covered, naming the source and never the value.
            cfg.mcp.agent_token = Some(SECRETS_51[4].to_string());
            let env = [("SERVICE_TOKEN".to_string(), SECRETS_51[3].to_string())];
            let handle = start_tuned(
                &cfg,
                &fresh_ring(),
                Some(SECRETS_51[2]),
                &env,
                Tuning::production(),
            )
            .expect("start")
            .expect("an audit log is on");
            flush(&handle);
            handle
        });
        assert_eq!(handle.registry().len(), 5, "all five were registered");

        let mut failures: Vec<String> = Vec::new();
        let mut texts: Vec<(&str, String)> = vec![
            ("the log of start", log.clone()),
            ("registry", format!("{:?}", handle.registry())),
            ("registry by value", format!("{:?}", **handle.registry())),
            ("handle", format!("{handle:?}")),
            ("writer", format!("{:?}", handle.writer)),
            ("status", format!("{:?}", handle.status())),
            (
                "the log of a failing write",
                log_of_a_failing_write_carrying(&SECRETS_51),
            ),
        ];
        for secret in SECRETS_51 {
            texts.push((
                "a registration",
                format!("{:?}", handle.register_secret("source", secret)),
            ));
        }
        for (what, text) in &texts {
            for secret in SECRETS_51 {
                if text.contains(secret) {
                    failures.push(format!("{what} contains a registered secret: {text}"));
                }
            }
        }
        // The shapes: the counts, and the warning about the short one.
        let registry_debug = format!("{:?}", handle.registry());
        if registry_debug != "SecretRegistry { secrets: 5 }" {
            failures.push(format!("registry Debug: {registry_debug}"));
        }
        let handle_debug = format!("{handle:?}");
        if handle_debug != "AuditLogHandle { secrets: 5 }" {
            failures.push(format!("handle Debug: {handle_debug}"));
        }
        if !log.contains("WARN")
            || !log.contains("mcp.agent_token")
            || !log.contains("shorter than 8")
        {
            failures.push(format!("the short-secret warning is missing: {log}"));
        }
        let failing = log_of_a_failing_write_carrying(&SECRETS_51);
        if !failing.contains("WARN") || !failing.contains("/fake/secrets-log/the-file.jsonl") {
            failures.push(format!("the failing write logged no warning: {failing}"));
        }
        assert!(
            failures.is_empty(),
            "{} row(s) failed:\n{}",
            failures.len(),
            failures.join("\n")
        );
    }

    /// Made up, like every canary in these tests; 8 bytes or more so that each
    /// is masked as a substring.
    const SRC_TRANSPORT: &str = "CNRYSRCx1a2b3c01";
    const SRC_OPERATOR: &str = "CNRYSRCx1a2b3c02";
    const SRC_AGENT: &str = "CNRYSRCx1a2b3c03";
    const SRC_WEB: &str = "CNRYSRCx1a2b3c04";
    const SRC_ENV: &str = "CNRYSRCx1a2b3c05";
    /// Values of variables whose names do not look like secrets.
    const SRC_SOCK: &str = "/tmp/sock11xxxxxxxx";
    const SRC_HOME: &str = "/home/u11xxxxxx";

    /// The sources `start_tuned` registers, and the ones it leaves alone: the
    /// transport token (either transport), `operator_token`, `agent_token`, the
    /// web token argument and the secret-named variables of the injected
    /// environment; not `SSH_AUTH_SOCK`, not `HOME`, and no empty value.
    #[test]
    fn start_registers_the_configured_sources() {
        let dir = scratch("sources");
        let transports = [
            (
                "loopback",
                McpTransport::LoopbackTcp {
                    port: 0,
                    token: SRC_TRANSPORT.to_string(),
                    endpoint_file: None,
                },
            ),
            (
                "streamable http",
                McpTransport::streamable_http_default(SRC_TRANSPORT.to_string()),
            ),
        ];
        let env: Vec<(String, String)> = [
            ("GITHUB_TOKEN", SRC_ENV),
            ("SSH_AUTH_SOCK", SRC_SOCK),
            ("HOME", SRC_HOME),
        ]
        .map(|(name, value)| (name.to_string(), value.to_string()))
        .to_vec();

        let mut failures: Vec<String> = Vec::new();
        for (row, transport) in transports {
            let base = dir.join(&row.replace(' ', "-")).join("audit.jsonl");
            let mut cfg = config_for(&dir, AuditLogSetting::Path(base));
            cfg.mcp.transport = transport;
            cfg.mcp.operator_token = Some(SRC_OPERATOR.to_string());
            cfg.mcp.agent_token = Some(SRC_AGENT.to_string());
            let handle = start_tuned(
                &cfg,
                &fresh_ring(),
                Some(SRC_WEB),
                &env,
                Tuning::production(),
            )
            .expect("start")
            .expect("an audit log is on");
            if handle.registry().len() != 5 {
                failures.push(format!(
                    "{row}: left: {} secrets, right: 5",
                    handle.registry().len()
                ));
            }
            for (name, secret) in [
                ("transport token", SRC_TRANSPORT),
                ("operator_token", SRC_OPERATOR),
                ("agent_token", SRC_AGENT),
                ("web token", SRC_WEB),
                ("GITHUB_TOKEN", SRC_ENV),
            ] {
                let masked = handle.registry().mask(&format!("x {secret} y"));
                if masked != "x [redacted] y" {
                    failures.push(format!("{row}: {name}: left: {masked:?}, right: masked"));
                }
            }
            for (name, value) in [("SSH_AUTH_SOCK", SRC_SOCK), ("HOME", SRC_HOME)] {
                let text = format!("x {value} y");
                let masked = handle.registry().mask(&text);
                if masked != text {
                    failures.push(format!("{row}: {name}: left: {masked:?}, right: {text:?}"));
                }
            }
            flush(&handle);
        }

        // Nothing configured, or only empty values: nothing is registered.
        let mut cfg = config_for(
            &dir,
            AuditLogSetting::Path(dir.join("empty").join("audit.jsonl")),
        );
        cfg.mcp.operator_token = Some(String::new());
        cfg.mcp.agent_token = Some(String::new());
        let env = [("EMPTY_TOKEN".to_string(), String::new())];
        let handle = start_tuned(&cfg, &fresh_ring(), Some(""), &env, Tuning::production())
            .expect("start")
            .expect("an audit log is on");
        if !handle.registry().is_empty() {
            failures.push(format!(
                "empty values: left: {} secrets, right: 0",
                handle.registry().len()
            ));
        }
        flush(&handle);

        assert!(
            failures.is_empty(),
            "{} row(s) failed:\n{}",
            failures.len(),
            failures.join("\n")
        );
    }

    /// Which environment variable names are secret-looking: each of the ten
    /// fragments, in any case; and the names that must stay out.
    #[test]
    fn secret_env_names_match_the_documented_fragments() {
        let secret = [
            "TOKEN",
            "GITHUB_TOKEN",
            "github_token",
            "Service_Token_2",
            "AWS_SECRET_ACCESS_KEY",
            "CLIENT_SECRET",
            "DB_PASSWORD",
            "DB_PASSWD",
            "SERVICE_CREDENTIALS",
            "ANTHROPIC_API_KEY",
            "VENDOR_APIKEY",
            "SIGNING_PRIVATE_KEY",
            "GPG_PASSPHRASE",
            "AWS_ACCESS_KEY_ID",
        ];
        let plain = [
            "SSH_AUTH_SOCK",
            "HOME",
            "PATH",
            "EDITOR",
            "RUST_LOG",
            "AITM_AUDIT_LOG",
            "KEYBOARD_LAYOUT",
            "TERM",
            "",
        ];
        let mut failures: Vec<String> = Vec::new();
        for name in secret {
            if !is_secret_env_name(name) {
                failures.push(format!("{name:?}: left: false, right: true"));
            }
        }
        for name in plain {
            if is_secret_env_name(name) {
                failures.push(format!("{name:?}: left: true, right: false"));
            }
        }
        assert!(
            failures.is_empty(),
            "{} row(s) failed:\n{}",
            failures.len(),
            failures.join("\n")
        );
    }

    /// A healthy start says exactly one line: at `info`, on the audit target,
    /// naming the control file; no token, label, count or other path.
    #[test]
    fn a_healthy_start_says_one_line_naming_the_control_file() {
        let dir = scratch("one-line");
        let base = dir.join("audit.jsonl");
        let (log, ()) = logged_until("INFO", || {
            let cfg = config_for(&dir, AuditLogSetting::Path(base.clone()));
            let env = [("SERVICE_TOKEN".to_string(), SRC_TRANSPORT.to_string())];
            let handle = start_tuned(
                &cfg,
                &fresh_ring(),
                Some(SRC_OPERATOR),
                &env,
                Tuning::production(),
            )
            .expect("start")
            .expect("an audit log is on");
            flush(&handle);
        });
        let shown = base.display().to_string();
        assert_eq!(log.lines().count(), 1, "exactly one line: {log}");
        assert!(log.contains("INFO"), "at info: {log}");
        assert!(log.contains("aitm::audit"), "on the audit target: {log}");
        assert!(log.contains(&shown), "naming the control file: {log}");
        for other in [
            "audit.agent.jsonl",
            "audit.reads.jsonl",
            SRC_TRANSPORT,
            SRC_OPERATOR,
            "SERVICE_TOKEN",
        ] {
            assert!(!log.contains(other), "the line also carries {other}: {log}");
        }
    }

    /// A default path that cannot be used does not stop the boot, and says
    /// why: one warning per stream that could not be opened, on the audit
    /// target, naming that stream's file and the reason, and no secret.
    #[test]
    fn a_default_path_that_cannot_be_used_warns_with_the_path_and_the_reason() {
        let dir = scratch("degraded-warning");
        let blocker = dir.join("F");
        fs::write(&blocker, b"a regular file where a directory is needed")
            .expect("write the blocking file");
        let base = blocker.join("audit.jsonl");
        let (log, handle) = logged_until("WARN", || {
            let cfg = config_for(&dir, AuditLogSetting::Path(base.clone()));
            // `start_at` with `explicit: false` is the default-path policy.
            let ring = fresh_ring();
            let handle = start_at(&ring, &base, &cfg.ca.audit_log, false)
                .expect("a default path never fails the boot")
                .expect("a writer is started degraded");
            flush(&handle);
            handle
        });
        let warns: Vec<&str> = log.lines().filter(|line| line.contains("WARN")).collect();
        assert_eq!(warns.len(), 3, "one warning per failed stream: {log}");
        assert_eq!(
            log.lines().count(),
            3,
            "nothing but the warnings, in particular no \"audit log on\" line: {log}"
        );
        for kind in StreamKind::ALL {
            let shown = stream_path(&base, kind).display().to_string();
            let naming: Vec<&&str> = warns.iter().filter(|line| line.contains(&shown)).collect();
            assert_eq!(naming.len(), 1, "one warning names {shown}: {log}");
            assert!(
                naming[0].contains("aitm::audit"),
                "on the audit target: {log}"
            );
        }
        // The reason is the operating system's, through the preflight's own text.
        assert!(
            warns.iter().all(|line| line.contains("audit log ")),
            "each warning carries the preflight's reason: {log}"
        );
        assert!(handle.status().degraded, "the writer reports degraded");
    }

    /// One stream that cannot be used degrades alone: the other two are open
    /// and written, one warning names the stream that is not, and the boot says
    /// no "log on" line (it is not a healthy start).
    #[test]
    fn one_unusable_stream_degrades_alone() {
        let dir = scratch("one-bad-stream");
        let base = dir.join("audit.jsonl");
        // A directory where the agent stream's file should be: refused.
        fs::create_dir(dir.join("audit.agent.jsonl")).expect("make the blocking directory");
        let ca_log = dir.join("ca-audit.jsonl");
        let ring = fresh_ring();
        let (log, handle) = logged_until("WARN", || {
            // A fresh ring each attempt: a ring takes one sink.
            let handle = start_at(&fresh_ring(), &base, &ca_log, false)
                .expect("a default path never fails the boot")
                .expect("a writer is started");
            handle.shutdown(FLUSH_BUDGET);
            handle
        });
        drop(handle);

        let agent = dir.join("audit.agent.jsonl").display().to_string();
        let warns: Vec<&str> = log.lines().filter(|line| line.contains("WARN")).collect();
        assert_eq!(
            warns.len(),
            1,
            "one warning, for the stream that failed: {log}"
        );
        assert!(warns[0].contains(&agent), "it names the agent file: {log}");
        assert_eq!(log.lines().count(), 1, "and nothing else is said: {log}");

        // The other streams work: an operator entry reaches the control file, and
        // the writer as a whole reports degraded.
        let handle = start_at(&ring, &base, &ca_log, false)
            .expect("a default path never fails the boot")
            .expect("a writer is started");
        assert!(handle.status().degraded, "one stream is down: degraded");
        ring.append_in(AuditLane::Evidence, entry("kept", Frontend::Operator, 1));
        flush(&handle);
        assert_eq!(entry_commands(&base), ["kept"], "the control stream wrote");
    }

    /// The sink is set once: a second writer for a ring that has one is an
    /// error (the new writer is shut down), and the first goes on recording.
    #[test]
    fn a_ring_that_already_has_a_sink_refuses_a_second_writer() {
        let dir = scratch("second-sink");
        let ca_log = dir.join("ca-audit.jsonl");
        let ring = fresh_ring();
        let first = start_at(&ring, &dir.join("one.jsonl"), &ca_log, true)
            .expect("the first writer")
            .expect("an audit log is on");

        let second = start_at(&ring, &dir.join("two.jsonl"), &ca_log, true);
        let message = match &second {
            Err(error) => format!("{error:#}"),
            Ok(other) => panic!("expected an error for a second sink, got {other:?}"),
        };
        assert!(message.contains("already"), "the reason is said: {message}");

        ring.append_in(AuditLane::Evidence, entry("kept", Frontend::Operator, 1));
        flush(&first);
        assert_eq!(entry_commands(&dir.join("one.jsonl")), ["kept"]);
        assert_eq!(
            entry_commands(&dir.join("two.jsonl")),
            Vec::<String>::new(),
            "the refused writer wrote no entry"
        );
    }

    /// The setting decides where the writer starts and which boot policy
    /// applies: `Off` starts nothing, a path the operator named is explicit, and
    /// the default path is not. (The `Default` row resolves a path and creates
    /// nothing: only `start` would.) Through `start`, an explicit path that
    /// cannot be used fails the boot.
    #[test]
    fn the_setting_decides_the_boot_policy() {
        let dir = scratch("setting-policy");
        let named = dir.join("named.jsonl");
        assert_eq!(boot_target(&AuditLogSetting::Off), None);
        assert_eq!(
            boot_target(&AuditLogSetting::Path(named.clone())),
            Some((named, true))
        );
        let (default_path, explicit) =
            boot_target(&AuditLogSetting::Default).expect("the default setting has a path");
        assert!(!explicit, "the default path is not explicit");
        assert_eq!(
            default_path.file_name(),
            Some("audit.jsonl".as_ref()),
            "{default_path:?}"
        );

        let blocker = dir.join("F");
        fs::write(&blocker, b"a regular file where a directory is needed")
            .expect("write the blocking file");
        let cfg = config_for(&dir, AuditLogSetting::Path(blocker.join("audit.jsonl")));
        let started = start(&cfg, &fresh_ring(), None, &[]);
        assert!(
            started.is_err(),
            "expected Err for a configured path that cannot be used, got {started:?}"
        );
        assert_eq!(names_in(&dir.0), ["F"], "nothing was created");
    }

    /// `with_cap_bytes` sets the three caps and nothing else.
    #[test]
    fn with_cap_bytes_sets_the_three_caps_and_nothing_else() {
        let production = Tuning::production();
        let tuned = Tuning::production().with_cap_bytes(4096);
        assert_eq!(tuned.cap_bytes, [4096; 3]);
        assert_eq!(tuned.queue, production.queue);
        assert_eq!(tuned.keep, production.keep);
        assert_eq!(tuned.recheck, production.recheck);
        assert_eq!(tuned.reopen, production.reopen);
        assert_eq!(tuned.rotate_retry, production.rotate_retry);
        assert_eq!(tuned.warn_every, production.warn_every);
    }

    /// The tuning `start_tuned` is given reaches the streams: with a 512-byte
    /// cap the agent file rotates, with the production cap it does not.
    #[test]
    fn a_tuned_start_rotates_at_the_tuned_cap() {
        let dir = scratch("tuned-start");
        let mut failures: Vec<String> = Vec::new();
        for (row, tuning, rotates) in [
            (
                "a 512-byte cap",
                Tuning::production().with_cap_bytes(512),
                true,
            ),
            ("the production cap", Tuning::production(), false),
        ] {
            let base = dir.join(&row.replace(' ', "-")).join("audit.jsonl");
            let cfg = config_for(&dir, AuditLogSetting::Path(base.clone()));
            let ring = fresh_ring();
            let handle = start_tuned(&cfg, &ring, None, &[], tuning)
                .expect("start")
                .expect("an audit log is on");
            for i in 0..20_u64 {
                ring.append_in(
                    AuditLane::Evidence,
                    entry(&format!("agent-call-{i}"), Frontend::Mcp, i),
                );
            }
            flush(&handle);
            let agent = stream_path(&base, StreamKind::Agent);
            let first_rotated = rotated_path(&agent, 1);
            if first_rotated.exists() != rotates {
                failures.push(format!(
                    "{row}: left: {} exists, right: {rotates}",
                    first_rotated.display()
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

    // ---- the field pipeline on the stream's thread ------------------------

    /// AC50: a secret registered while the writer runs is masked in the line of
    /// an entry that was already queued and in one recorded afterwards. The
    /// control stream's file blocks inside its first write, so `e1` waits in the
    /// queue while the registration is made: masking happens when the line is
    /// written, not when the entry is recorded.
    #[test]
    fn a_late_registration_reaches_a_running_writer() {
        const LATE: &str = "LATE50TOKENVALUE";
        let states = [FakeState::gated(), FakeState::plain(), FakeState::plain()];
        let _release = ReleaseOnDrop(states[0].clone());
        let writer = fake_writer(&states, Tuning::production());
        let carrying = |command: &str, at_ms: u64| AuditEntry {
            args_summary: format!("note {LATE} end"),
            ..entry(command, Frontend::Operator, at_ms)
        };

        writer.record(
            AuditLane::Evidence,
            entry("e0", Frontend::Operator, BASE_MS),
        );
        assert!(
            wait_until(WAIT, || states[0].inside()),
            "the control stream never reached its first write"
        );
        writer.record(AuditLane::Evidence, carrying("e1", BASE_MS + 1));
        assert_eq!(
            writer.registry().register("test.late", LATE),
            Registration::Substring
        );
        states[0].release();
        writer.record(AuditLane::Evidence, carrying("e2", BASE_MS + 2));
        let report = writer.shutdown(FLUSH_BUDGET);
        assert!(report.complete, "the flush did not finish: {report:?}");

        assert_eq!(fake_shape(&states[0]), ["e0", "e1", "e2"]);
        for line in states[0].lines() {
            assert!(!line.contains(LATE), "the secret reached a line: {line}");
        }
        let args: Vec<String> = fake_json(&states[0])
            .iter()
            .map(|line| line["args"].as_str().unwrap_or("?").to_string())
            .collect();
        assert_eq!(args, ["{}", "note [redacted] end", "note [redacted] end"]);
    }

    /// AC16, the text fields (`args` is the whole-entry test below): a hand-built hostile
    /// entry reaches a real file with no secret in it, registered or shaped, no
    /// control byte other than the two line ends (the `start` marker's and the
    /// entry's), no DEL and no C1 character, and every field within its cap.
    #[test]
    fn a_hostile_text_entry_is_sanitised_before_it_is_written() {
        const REG: &str = "REGSECRET16XYZ";
        let dir = scratch("hostile-text");
        let (ring, writer, paths) = fs_writer(&dir, Tuning::production());
        writer.registry().register("test.registered", REG);
        let shaped = format!("ghp_{}", "Cx".repeat(18));
        let hostile = AuditEntry {
            client_label: Some("web-bridge\u{202E}\n token=LABELSECRET9".to_string()),
            connection_id: Some("c".repeat(10 * 1024)),
            command: format!("a\nb {shaped} {}", "z".repeat(200)),
            args_summary: format!(
                "{{\"k\":\"{REG}\"}} \u{9b}\u{7f}{}",
                "x".repeat(1024 * 1024)
            ),
            result: AuditResult::Error(format!(
                "Bearer REASONSECRET9 \u{1b}[31m \u{9b}2J\u{7f}\nnext {REG}"
            )),
            ..entry("unused", Frontend::Mcp, BASE_MS)
        };
        ring.append_in(AuditLane::Evidence, hostile);
        let report = writer.shutdown(FLUSH_BUDGET);
        assert!(report.complete, "the flush did not finish: {report:?}");

        let raw = fs::read(&paths[1]).expect("read the agent file");
        let mut failures: Vec<String> = Vec::new();
        let ends = raw.iter().filter(|byte| **byte == b'\n').count();
        if ends != 2 {
            failures.push(format!("left: {ends} line ends, right: 2"));
        }
        if let Some(byte) = raw.iter().find(|b| **b < 0x20 && **b != b'\n') {
            failures.push(format!("the file holds the control byte {byte:#04x}"));
        }
        if raw.contains(&0x7f) {
            failures.push("the file holds DEL".to_string());
        }
        if raw.windows(2).any(|pair| pair == [0xC2, 0x9B]) {
            failures.push("the file holds U+009B".to_string());
        }
        let text = String::from_utf8_lossy(&raw);
        for secret in ["LABELSECRET9", "REASONSECRET9", REG, shaped.as_str()] {
            if text.contains(secret) {
                failures.push(format!("{secret} is in the file"));
            }
        }
        let lines = read_lines(&paths[1]);
        match lines.last() {
            Some(line) if line.get("command").is_some() => {
                let chars = |path: &[&str]| {
                    let mut here = line;
                    for key in path {
                        here = &here[*key];
                    }
                    let text = here.as_str().unwrap_or("");
                    (text.chars().count(), text.len())
                };
                for (field, path, max_chars, max_bytes) in [
                    ("client_label", &["client_label"][..], 64, usize::MAX),
                    ("args", &["args"][..], usize::MAX, 515),
                    ("result.error", &["result", "error"][..], usize::MAX, 1027),
                    ("connection_id", &["connection_id"][..], usize::MAX, 64),
                    ("command", &["command"][..], 128, usize::MAX),
                ] {
                    let (got_chars, got_bytes) = chars(path);
                    if got_chars > max_chars || got_bytes > max_bytes {
                        failures.push(format!(
                            "{field}: {got_chars} chars, {got_bytes} bytes; at most {max_chars} chars, {max_bytes} bytes"
                        ));
                    }
                }
            }
            other => failures.push(format!("the last line is not the entry: {other:?}")),
        }
        assert!(
            failures.is_empty(),
            "{} row(s) failed:\n{}",
            failures.len(),
            failures.join("\n")
        );
    }

    // ---- the args pipeline: parse first, then the tolerant scan ----

    /// `text` with the content of every string literal deleted (the quotes
    /// stay): what two texts must agree on when only literal contents may differ.
    fn without_literal_contents(text: &str) -> String {
        let mut out = String::new();
        let (mut inside, mut escaped) = (false, false);
        for c in text.chars() {
            if !inside {
                out.push(c);
                inside = c == '"';
            } else if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                out.push(c);
                inside = false;
            }
        }
        out
    }

    /// AC16, the whole entry of the spec: a hand-built hostile entry (origin
    /// `Mcp`, so the agent file) reaches a real file with no secret in it, the two
    /// line ends of the file and no other control byte, no DEL and no C1 character,
    /// and every field within its cap. Its `args` is not JSON (a password and a
    /// megabyte of `x`), so Design 14.5 treats it as plain text and the key is
    /// masked in it.
    #[test]
    fn a_hostile_entry_is_sanitised_before_it_is_written() {
        let dir = scratch("hostile-entry");
        let (ring, writer, paths) = fs_writer(&dir, Tuning::production());
        let hostile = AuditEntry {
            client_label: Some("web-bridge\u{202E}\n token=LABELSECRET9".to_string()),
            connection_id: Some("c".repeat(10 * 1024)),
            command: format!("a\nb{}", "z".repeat(200)),
            args_summary: format!(" password=ARGSECRET9 {}", "x".repeat(1024 * 1024)),
            result: AuditResult::Error(
                "Bearer REASONSECRET9 \u{1b}[31m \u{9b}2J\u{7f}\nnext".to_string(),
            ),
            ..entry("unused", Frontend::Mcp, BASE_MS)
        };
        ring.append(hostile);
        let report = writer.shutdown(FLUSH_BUDGET);
        assert!(report.complete, "the flush did not finish: {report:?}");

        let raw = fs::read(&paths[1]).expect("read the agent file");
        let mut failures: Vec<String> = Vec::new();
        let ends = raw.iter().filter(|byte| **byte == b'\n').count();
        if ends != 2 {
            failures.push(format!("left: {ends} line ends, right: 2"));
        }
        if let Some(byte) = raw.iter().find(|b| **b < 0x20 && **b != b'\n') {
            failures.push(format!("the file holds the control byte {byte:#04x}"));
        }
        if raw.contains(&0x7f) {
            failures.push("the file holds DEL".to_string());
        }
        if raw.windows(2).any(|pair| pair == [0xC2, 0x9B]) {
            failures.push("the file holds U+009B".to_string());
        }
        let text = String::from_utf8_lossy(&raw);
        for secret in ["LABELSECRET9", "ARGSECRET9", "REASONSECRET9"] {
            if text.contains(secret) {
                failures.push(format!("{secret} is in the file"));
            }
        }
        let lines = read_lines(&paths[1]);
        match lines.last() {
            Some(line) if line.get("command").is_some() => {
                let field = |path: &[&str]| {
                    let mut here = line;
                    for key in path {
                        here = &here[*key];
                    }
                    here.as_str().unwrap_or("").to_string()
                };
                for (name, path, max_chars, max_bytes) in [
                    ("client_label", &["client_label"][..], 64, usize::MAX),
                    ("args", &["args"][..], usize::MAX, 515),
                    ("result.error", &["result", "error"][..], usize::MAX, 1027),
                    ("connection_id", &["connection_id"][..], usize::MAX, 64),
                    ("command", &["command"][..], 128, usize::MAX),
                ] {
                    let value = field(path);
                    let (chars, bytes) = (value.chars().count(), value.len());
                    if chars > max_chars || bytes > max_bytes {
                        failures.push(format!(
                            "{name}: {chars} chars, {bytes} bytes; at most {max_chars} chars, {max_bytes} bytes"
                        ));
                    }
                }
                // The password is masked in the plain text, and what the cap kept
                // of the megabyte after it is the 491 bytes that fit.
                let want_args = format!(" password=[redacted] {}…", "x".repeat(491));
                let got_args = field(&["args"]);
                if got_args != want_args {
                    failures.push(format!("args: left: {got_args:?}, right: {want_args:?}"));
                }
            }
            other => failures.push(format!("the last line is not the entry: {other:?}")),
        }
        assert!(
            failures.is_empty(),
            "{} row(s) failed:\n{}",
            failures.len(),
            failures.join("\n")
        );
    }

    /// AC54: a secret cut by a cap, and the tolerant scan of text that does not
    /// parse, through the real writer and a real file. (a) The source's cap cut a
    /// registered secret 10 bytes in and put its `…` after the cut (plan
    /// Ambiguities 14 and 15): the written `args` has the fragment masked and the
    /// marker back. (b) A cut text with a cookie in a header map and a cookie
    /// line in a literal: no secret, the structure outside the literals is the
    /// input's, and what rule D hides is not touched (it is a rule of the source).
    /// (c) Text that is not JSON is plain text. (d) Text that parses goes through
    /// the source's function.
    #[test]
    fn cut_secrets_and_the_tolerant_scan() {
        const CUT: &str = "CUT54SECRETVALUE0123456789";
        let dir = scratch("cut-secrets");
        let (ring, writer, paths) = fs_writer(&dir, Tuning::production());
        assert_eq!(
            writer.registry().register("test.cut54", CUT),
            Registration::Substring
        );

        // (a) `{"note":"` is 9 bytes: 493 `x` and the first 10 bytes of the secret
        // are the 512 bytes before the cut.
        let whole = format!("{{\"note\":\"{}{CUT}\"}}", "x".repeat(493));
        let cut = format!("{}…", whole.get(..512).expect("a char boundary"));
        assert!(cut.ends_with("CUT54SECRE…"), "the cut is mid-token: {cut}");
        assert_eq!(cut.len(), 515);
        let cut_a = format!("{{\"note\":\"{}[redacted]…", "x".repeat(493));

        let cookie_cut = r#"{"headers":{"Cookie":"a=b; s=SECRET54","X":"v"},"note":"GET /\r\nCookie: a=b; z=SECRET54b\r\nHo"#;
        let rows: [(&str, &str, String); 5] = [
            ("a: the cap cut the registered secret", &cut, cut_a),
            (
                "b: a cookie map and a cookie line in a cut text",
                cookie_cut,
                r#"{"headers":{"Cookie":"<redacted>","X":"v"},"note":"GET /\r\nCookie: [redacted]\r\nHo"#
                    .to_string(),
            ),
            (
                "b: a secret key's value in a cut text",
                r#"{"password":"SECRET54c","n":1"#,
                r#"{"password":"<redacted>","n":1"#.to_string(),
            ),
            (
                "c: not JSON",
                " password=SECRET54d x",
                " password=[redacted] x".to_string(),
            ),
            (
                "d: complete text goes through the source function",
                r#"{"headers":{"X-Custom":"SECRET54e"}}"#,
                r#"{"headers":{"X-Custom":"<redacted>"}}"#.to_string(),
            ),
        ];
        for (at, (_, args, _)) in rows.iter().enumerate() {
            ring.append(AuditEntry {
                args_summary: args.to_string(),
                ..entry(&format!("row{at}"), Frontend::Mcp, BASE_MS + at as u64)
            });
        }
        let report = writer.shutdown(FLUSH_BUDGET);
        assert!(report.complete, "the flush did not finish: {report:?}");

        let written: Vec<String> = read_lines(&paths[1])
            .iter()
            .filter(|line| line.get("command").is_some())
            .map(|line| line["args"].as_str().unwrap_or("?").to_string())
            .collect();
        let mut failures: Vec<String> = Vec::new();
        if written.len() != rows.len() {
            failures.push(format!(
                "{} entry lines, expected {}",
                written.len(),
                rows.len()
            ));
        }
        for ((row, args, want), got) in rows.iter().zip(&written) {
            if got != want {
                failures.push(format!("{row}: left: {got:?}, right: {want:?}"));
            }
            if got.contains("CUT54S") || got.contains("SECRET54") {
                failures.push(format!("{row}: a secret is in {got:?}"));
            }
            if !row.starts_with("a:")
                && !row.starts_with("d:")
                && !row.starts_with("c:")
                && without_literal_contents(got) != without_literal_contents(args)
            {
                failures.push(format!(
                    "{row}: the structure changed: {got:?} from {args:?}"
                ));
            }
        }
        if written
            .get(1)
            .is_some_and(|got| !got.contains(r#""X":"v""#))
        {
            failures.push("b: the header X was not left alone".to_string());
        }
        assert!(
            failures.is_empty(),
            "{} row(s) failed:\n{}",
            failures.len(),
            failures.join("\n")
        );
    }

    /// The environment values the rule skips: literals that say "on" or "off"
    /// rather than hold a secret, and digit runs too short to be one.
    const BENIGN_ENV_VALUES: [&str; 31] = [
        "true", "false", "null", "none", "yes", "no", "on", "off", "default", "enabled",
        "disabled", "auto", "TRUE", "False", "NULL", "None", "Yes", "nO", "ON", "oFF", "Default",
        "ENABLED", "Disabled", "AUTO", "0", "1", "42", "12345", "1234567", "007", "9999999",
    ];

    /// The shapes of a real secret a variable named `..._TOKEN` holds.
    fn env_secret_values() -> [String; 4] {
        [
            format!("ghp_{}", "Cq".repeat(18)),
            "9f86d081884c7d659a2feaa0c55ad015".to_string(),
            "12345678".to_string(),
            "1234567a".to_string(),
        ]
    }

    /// A value is skipped from the environment rule only when it is one of the
    /// literals whole (ASCII case-insensitively) or digits only and shorter than
    /// 8 bytes; a longer digit run, a literal with anything beside it and every
    /// secret-looking value are registered. The label names the variable, never
    /// the value. Configured tokens are not subject to the rule at all.
    #[test]
    fn the_environment_rule_skips_values_that_are_not_secrets() {
        let kept_beside: Vec<String> = [
            "truest",
            "nothing",
            " true",
            "true ",
            "falsey",
            "automatic",
            "yes!",
            "0x12345",
            "12345 67",
        ]
        .iter()
        .map(|value| value.to_string())
        .collect();
        let mut env: Vec<(String, String)> = Vec::new();
        for (i, value) in BENIGN_ENV_VALUES.iter().enumerate() {
            env.push((format!("SKIP{i}_TOKEN"), value.to_string()));
        }
        env.push(("EMPTY_TOKEN".to_string(), String::new()));
        let mut want: Vec<(String, String)> = Vec::new();
        for (i, value) in env_secret_values()
            .into_iter()
            .chain(kept_beside)
            .enumerate()
        {
            let pair = (format!("KEEP{i}_SECRET"), value);
            env.push(pair.clone());
            want.push((format!("env:{}", pair.0), pair.1));
        }

        let cfg = Config::default();
        let got: Vec<(String, String)> = configured_secrets(&cfg, None, &env)
            .into_iter()
            .filter(|(label, _)| label.starts_with("env:"))
            .collect();
        assert_eq!(got, want);

        // A configured token keeps full masking whatever it looks like.
        let mut cfg = Config::default();
        cfg.mcp.transport = McpTransport::LoopbackTcp {
            port: 0,
            token: "on".to_string(),
            endpoint_file: None,
        };
        cfg.mcp.operator_token = Some("false".to_string());
        cfg.mcp.agent_token = Some("0".to_string());
        let configured = configured_secrets(&cfg, Some("true"), &env);
        let first_four: Vec<(&str, &str)> = configured
            .iter()
            .take(4)
            .map(|(label, value)| (label.as_str(), value.as_str()))
            .collect();
        assert_eq!(
            first_four,
            [
                ("mcp.transport.token", "on"),
                ("mcp.operator_token", "false"),
                ("mcp.agent_token", "0"),
                ("web.agent_bridge_token", "true"),
            ]
        );
    }

    /// A variable such as `TOKENIZERS_PARALLELISM=false` must not make `false`
    /// a secret: with it present, ordinary JSON survives byte for byte, the
    /// boot logs no warning about it, and a real secret-looking value of
    /// another variable is registered and masked.
    #[test]
    fn a_flag_like_environment_value_never_masks_ordinary_text() {
        let dir = scratch("env-flags");
        let base = dir.join("audit.jsonl");
        let secrets = env_secret_values();
        let env: Vec<(String, String)> = [
            ("X_TOKEN", "true"),
            ("TOKENIZERS_PARALLELISM", "false"),
            ("NULLISH_SECRET", "null"),
            ("PROMPT_PASSWORD", "none"),
            ("CLEAR_CREDENTIAL", "default"),
            ("BARE_TOKEN", "enabled"),
            ("PORT_TOKEN", "1234567"),
            ("GITHUB_TOKEN", secrets[0].as_str()),
            ("BUILD_SECRET", secrets[1].as_str()),
        ]
        .map(|(name, value)| (name.to_string(), value.to_string()))
        .to_vec();

        let (log, ()) = logged_until("INFO", || {
            let cfg = config_for(
                &dir,
                AuditLogSetting::Path(dir.join("probe").join("a.jsonl")),
            );
            let handle = start_tuned(&cfg, &fresh_ring(), None, &env, Tuning::production())
                .expect("start")
                .expect("an audit log is on");
            flush(&handle);
        });
        assert!(!log.contains("WARN"), "no warning about a flag: {log}");
        assert_eq!(log.lines().count(), 1, "only the start line: {log}");
        assert!(!log.contains("PARALLELISM"), "{log}");

        let cfg = config_for(&dir, AuditLogSetting::Path(base.clone()));
        let ring = fresh_ring();
        let handle = start_tuned(&cfg, &ring, None, &env, Tuning::production())
            .expect("start")
            .expect("an audit log is on");
        assert_eq!(handle.registry().len(), 2, "only the two real secrets");
        let flags =
            r#"{"a":false,"b":true,"c":null,"d":"none","e":"default","f":"enabled","g":1234567}"#;
        let benign = AuditEntry {
            args_summary: flags.to_string(),
            ..entry("flag.use", Frontend::Mcp, BASE_MS)
        };
        let leaking = AuditEntry {
            args_summary: format!(
                "{{\"u\":\"x?next={}\",\"h\":\"{}\"}}",
                secrets[0], secrets[1]
            ),
            ..entry("secret.use", Frontend::Mcp, BASE_MS + 1)
        };
        ring.append_in(AuditLane::Evidence, benign.clone());
        ring.append_in(AuditLane::Evidence, leaking);
        flush(&handle);

        let agent = stream_path(&base, StreamKind::Agent);
        let written: Vec<String> = fs::read_to_string(&agent)
            .expect("read the agent file")
            .lines()
            .filter(|line| line.contains("\"command\""))
            .map(str::to_string)
            .collect();
        assert_eq!(written.len(), 2, "{written:?}");
        assert_eq!(written[0], aitm_ca::audit::entry_to_jsonl(&benign));
        let leaked = read_lines(&agent);
        assert_eq!(
            leaked[2]["args"],
            r#"{"u":"x?next=[redacted]","h":"[redacted]"}"#
        );
    }

    /// A configured token is masked whatever it looks like: the environment
    /// rule that skips `true` and `false` does not apply to the five sources
    /// the operator configured.
    #[test]
    fn a_configured_token_keeps_full_masking_whatever_its_value() {
        let dir = scratch("configured-literals");
        let mut cfg = config_for(&dir, AuditLogSetting::Path(dir.join("audit.jsonl")));
        cfg.mcp.operator_token = Some("false".to_string());
        cfg.mcp.agent_token = Some("12345".to_string());
        let handle = start_tuned(
            &cfg,
            &fresh_ring(),
            Some("true"),
            &[("X_TOKEN".to_string(), "null".to_string())],
            Tuning::production(),
        )
        .expect("start")
        .expect("an audit log is on");
        flush(&handle);
        assert_eq!(
            handle.registry().len(),
            3,
            "the environment's `null` is not one"
        );
        assert_eq!(handle.registry().mask("a false b"), "a [redacted] b");
        assert_eq!(handle.registry().mask("a 12345 b"), "a [redacted] b");
        assert_eq!(handle.registry().mask("a true b"), "a [redacted] b");
        assert_eq!(handle.registry().mask("a null b"), "a null b");
    }
}
