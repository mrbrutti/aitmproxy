//! The core pointer file (spec D4; plan Task 1).
//!
//! A serving core writes `<run dir>/<pid>.json`: one compact JSON line that
//! tells a one-shot `aitm` verb where the core's operator bus listens and
//! which config file holds the operator token. The pointer **never carries a
//! token**. The run dir is `<aitm dir>/run/cores` ([`default_run_dir`], the
//! `run` sibling of the CA audit log, exactly as W1 derives its `logs` dir),
//! overridable with `AITM_RUN_DIR` ([`run_dir`]).
//!
//! Liveness is the advisory lock, not the pid: the writer holds
//! `File::try_lock` on the inode from before the rename until the listener
//! ends, and a reader probes with `File::try_lock_shared` ([`liveness`]). A
//! lock the kernel released means the writer is gone, SIGKILL included.
//!
//! The process context ([`publish`], [`context`]) is a write-once `OnceLock`
//! set by `main.rs` for the serving modes only; an in-process `McpServer`
//! built by a test has no context and publishes nothing (AC-R14-12).

use std::fs::{self, DirBuilder, File, Metadata, OpenOptions, TryLockError};
use std::io::{self, Write as _};
use std::net::SocketAddr;
use std::os::unix::fs::{
    DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _,
};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Map, Value as JsonValue};

/// The pointer schema version this writer emits and this reader accepts.
pub const POINTER_VERSION: u64 = 1;

/// Environment variable that overrides the run dir for writer and reader.
pub const RUN_DIR_ENV: &str = "AITM_RUN_DIR";

/// What a serving process publishes once so the transport can write a pointer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PointerContext {
    /// Absolute path of the config file the core read.
    pub config: PathBuf,
    /// The directory pointers are written to.
    pub run_dir: PathBuf,
}

static CONTEXT: OnceLock<PointerContext> = OnceLock::new();

/// Publish the process context. Write-once: `false` when already set.
pub fn publish(ctx: PointerContext) -> bool {
    CONTEXT.set(ctx).is_ok()
}

/// The published process context, if any.
pub fn context() -> Option<&'static PointerContext> {
    CONTEXT.get()
}

/// `<aitm dir>/run/cores`, the `run` sibling of the CA audit log.
pub fn default_run_dir() -> PathBuf {
    aitm_core::CaConfig::default()
        .audit_log
        .with_file_name("run")
        .join("cores")
}

/// The run dir: a non-empty [`RUN_DIR_ENV`] wins, else [`default_run_dir`].
pub fn run_dir(env: &dyn Fn(&str) -> Option<String>) -> PathBuf {
    match env(RUN_DIR_ENV) {
        Some(dir) if !dir.is_empty() => PathBuf::from(dir),
        _ => default_run_dir(),
    }
}

/// The pointer file's content (spec D4 table).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorePointer {
    /// Schema version, [`POINTER_VERSION`].
    pub v: u64,
    /// The core's pid.
    pub pid: u32,
    /// The operator bus address; always loopback.
    pub bus: SocketAddr,
    /// Whether the bus accepts an operator token.
    pub operator: bool,
    /// Absolute path of the config file the core read.
    pub config: PathBuf,
    /// Epoch seconds when the bus bound.
    pub started_unix: u64,
    /// `CARGO_PKG_VERSION` of the writer.
    pub version: String,
}

impl CorePointer {
    /// One compact JSON line, keys in the order
    /// `v,pid,bus,operator,config,started_unix,version`, trailing newline.
    ///
    /// Built by hand: `aitm-mcp` has no `serde` derive (zero new edges, spec
    /// §Constraints) and the key order is part of the D4 contract.
    pub fn to_json_line(&self) -> String {
        format!(
            "{{\"v\":{},\"pid\":{},\"bus\":{},\"operator\":{},\"config\":{},\"started_unix\":{},\"version\":{}}}\n",
            self.v,
            self.pid,
            json_string(&self.bus.to_string()),
            self.operator,
            json_string(&self.config.to_string_lossy()),
            self.started_unix,
            json_string(&self.version),
        )
    }

    /// Parse one pointer line; unknown keys are ignored.
    pub fn parse(text: &str) -> Result<Self, PointerProblem> {
        let value: JsonValue =
            serde_json::from_str(text).map_err(|err| PointerProblem::NotJson(err.to_string()))?;
        let obj = value
            .as_object()
            .ok_or_else(|| PointerProblem::NotJson("not a JSON object".to_string()))?;
        let v = u64_field(obj, "v")?;
        if v != POINTER_VERSION {
            return Err(PointerProblem::UnknownVersion(v));
        }
        let pid = u32::try_from(u64_field(obj, "pid")?)
            .map_err(|_| PointerProblem::MissingField("pid"))?;
        let bus: SocketAddr = str_field(obj, "bus")?
            .parse()
            .map_err(|_| PointerProblem::MissingField("bus"))?;
        if !bus.ip().is_loopback() {
            return Err(PointerProblem::NonLoopback(bus));
        }
        let operator = obj
            .get("operator")
            .and_then(JsonValue::as_bool)
            .ok_or(PointerProblem::MissingField("operator"))?;
        let config = PathBuf::from(str_field(obj, "config")?);
        let started_unix = u64_field(obj, "started_unix")?;
        let version = str_field(obj, "version")?.to_string();
        Ok(Self {
            v,
            pid,
            bus,
            operator,
            config,
            started_unix,
            version,
        })
    }
}

/// `s` as a JSON string literal with `serde_json`'s escaping.
fn json_string(s: &str) -> String {
    JsonValue::String(s.to_string()).to_string()
}

fn u64_field(obj: &Map<String, JsonValue>, key: &'static str) -> Result<u64, PointerProblem> {
    obj.get(key)
        .and_then(JsonValue::as_u64)
        .ok_or(PointerProblem::MissingField(key))
}

fn str_field<'a>(
    obj: &'a Map<String, JsonValue>,
    key: &'static str,
) -> Result<&'a str, PointerProblem> {
    obj.get(key)
        .and_then(JsonValue::as_str)
        .ok_or(PointerProblem::MissingField(key))
}

/// Why a reader ignores a pointer (spec D4 trust rules).
#[derive(Debug, PartialEq, Eq)]
pub enum PointerProblem {
    /// Not a JSON object.
    NotJson(String),
    /// A schema version this reader does not know.
    UnknownVersion(u64),
    /// A required field is missing or has the wrong type.
    MissingField(&'static str),
    /// The bus address is not loopback.
    NonLoopback(SocketAddr),
    /// Not a regular file.
    NotRegular,
    /// Not owned by the current uid.
    Foreign,
    /// Wider than `0600`; carries `mode & 0o777`.
    Wide(u32),
}

/// The trust rules on a pointer's metadata: a regular file, owned by
/// `owner_uid`, no group or other bits.
pub fn trust(meta: &Metadata, owner_uid: u32) -> Result<(), PointerProblem> {
    if !meta.is_file() {
        return Err(PointerProblem::NotRegular);
    }
    if meta.uid() != owner_uid {
        return Err(PointerProblem::Foreign);
    }
    let mode = meta.mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(PointerProblem::Wide(mode));
    }
    Ok(())
}

/// Whether the pointer's writer still holds its lock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Liveness {
    /// The writer holds the exclusive lock.
    Alive,
    /// The lock is free: the writer is gone.
    Dead,
    /// The probe failed; treated as alive.
    Unknown,
}

/// Probe a pointer's lock with `try_lock_shared`: `WouldBlock` means the
/// writer holds it; success means the writer is gone (the shared lock is
/// released again); any other error is `Unknown`.
pub fn liveness(path: &Path) -> Liveness {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(err) => {
            tracing::debug!(path = %path.display(), %err, "could not open the core pointer to probe its lock");
            return Liveness::Unknown;
        }
    };
    match file.try_lock_shared() {
        Err(TryLockError::WouldBlock) => Liveness::Alive,
        Ok(()) => {
            if let Err(err) = file.unlock() {
                tracing::debug!(path = %path.display(), %err, "could not release the probe lock on the core pointer");
            }
            Liveness::Dead
        }
        Err(TryLockError::Error(err)) => {
            tracing::debug!(path = %path.display(), %err, "could not probe the core pointer's lock");
            Liveness::Unknown
        }
    }
}

/// A pointer this process wrote; dropping it removes the file.
pub struct Published {
    /// The pointer file's path.
    pub path: PathBuf,
    /// The exclusively locked handle, held for the pointer's lifetime so the
    /// kernel releases the lock only when this value drops or the process
    /// ends. Never read; it exists to be held.
    _lock: File,
}

impl Drop for Published {
    fn drop(&mut self) {
        // The file is removed while still locked, so no reader ever sees an
        // unlocked file at this path; the handle closes right after.
        remove(&self.path);
    }
}

/// Write `ptr` atomically as `<dir>/<pid>.json`, mode `0600`, locked before
/// it becomes visible. A `dir` this call creates is `0700` whatever the
/// umask; one that already exists is the operator's (an `AITM_RUN_DIR` they
/// chose, or a data dir they set up) and is left exactly as they have it,
/// with one `debug!` when it is wider than `0700` (security S3).
pub fn write(dir: &Path, ptr: &CorePointer) -> io::Result<Published> {
    // One stat decides (quality Q16): a dir that exists (a link to one
    // included) is the operator's and keeps its mode; a missing one is made.
    let owner_uid = match fs::metadata(dir) {
        Ok(meta) => {
            let mode = meta.mode() & 0o777;
            if mode & 0o077 != 0 {
                tracing::debug!(path = %dir.display(), mode = %format_args!("{mode:o}"), "the core pointer run dir already exists wider than 0700; leaving it as the operator has it");
            }
            meta.uid()
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            let mut builder = DirBuilder::new();
            builder.recursive(true).mode(0o700);
            builder.create(dir)?;
            fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
            fs::metadata(dir)?.uid()
        }
        Err(err) => return Err(err),
    };

    let path = dir.join(format!("{}.json", ptr.pid));
    let tmp = dir.join(format!("{}.json.tmp", ptr.pid));
    remove_stale_tmp(&tmp, owner_uid);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)?;
    match fill_lock_rename(&mut file, ptr, &tmp, &path) {
        Ok(()) => Ok(Published { path, _lock: file }),
        Err(err) => {
            remove(&tmp);
            Err(err)
        }
    }
}

/// A `<pid>.json.tmp` left by a writer that died between `create_new` and
/// its rename, met again once the pid is reused: removed, so the core still
/// publishes, when it is a regular file owned by `owner_uid` (the run dir's
/// owner). `symlink_metadata` never follows a link; a link, a non-regular or
/// a foreign file is left alone and `create_new` then reports it.
fn remove_stale_tmp(tmp: &Path, owner_uid: u32) {
    let meta = match fs::symlink_metadata(tmp) {
        Ok(meta) => meta,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return,
        Err(err) => {
            tracing::debug!(path = %tmp.display(), %err, "could not read a leftover core pointer temp file");
            return;
        }
    };
    if !meta.is_file() || meta.uid() != owner_uid {
        tracing::debug!(path = %tmp.display(), "leaving a leftover core pointer temp file alone: not this user's regular file");
        return;
    }
    tracing::debug!(path = %tmp.display(), "removing a leftover core pointer temp file from an earlier writer");
    remove(tmp);
}

/// Write the line, take the exclusive lock, then rename over the final name,
/// so the inode is locked from the first instant it is visible.
fn fill_lock_rename(file: &mut File, ptr: &CorePointer, tmp: &Path, path: &Path) -> io::Result<()> {
    file.write_all(ptr.to_json_line().as_bytes())?;
    file.try_lock().map_err(|err| match err {
        TryLockError::WouldBlock => io::Error::new(
            io::ErrorKind::WouldBlock,
            "the new pointer file is already locked",
        ),
        TryLockError::Error(err) => err,
    })?;
    fs::rename(tmp, path)
}

/// Remove a pointer file; a missing one is fine (idempotent).
pub fn remove(path: &Path) {
    match fs::remove_file(path) {
        Ok(()) => {}
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => {
            tracing::debug!(path = %path.display(), %err, "could not remove the core pointer file");
        }
    }
}

/// A pointer that passed the trust rules and parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Found {
    /// The pointer file's path.
    pub path: PathBuf,
    /// Its content.
    pub pointer: CorePointer,
}

/// Every `*.json` in `dir`, sorted by name, each trusted ([`trust`] on its
/// own metadata, symlinks not followed) and parsed, or reported with its
/// problem. A missing dir is empty; an entry that vanishes mid-scan is skipped.
pub fn scan(dir: &Path, owner_uid: u32) -> Vec<Result<Found, (PathBuf, PointerProblem)>> {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(err) => {
            if err.kind() != io::ErrorKind::NotFound {
                tracing::debug!(path = %dir.display(), %err, "could not read the core pointer dir");
            }
            return Vec::new();
        }
    };
    let mut paths: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .collect();
    paths.sort();
    paths
        .into_iter()
        .filter_map(|path| {
            let meta = match fs::symlink_metadata(&path) {
                Ok(meta) => meta,
                Err(err) => {
                    tracing::debug!(path = %path.display(), %err, "core pointer vanished mid-scan");
                    return None;
                }
            };
            if let Err(problem) = trust(&meta, owner_uid) {
                return Some(Err((path, problem)));
            }
            let text = match fs::read_to_string(&path) {
                Ok(text) => text,
                Err(err) => {
                    tracing::debug!(path = %path.display(), %err, "could not read a core pointer");
                    return None;
                }
            };
            Some(match CorePointer::parse(&text) {
                Ok(pointer) => Ok(Found { path, pointer }),
                Err(problem) => Err((path, problem)),
            })
        })
        .collect()
}

/// The transport's one call: write this process's pointer under the
/// published context, or nothing when no context was published. A write
/// failure is one `warn!` and `None`; it never ends a boot.
pub fn publish_pointer(bus: SocketAddr, operator: bool) -> Option<Published> {
    let ctx = context()?;
    let started_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs());
    let ptr = CorePointer {
        v: POINTER_VERSION,
        pid: std::process::id(),
        bus,
        operator,
        config: ctx.config.clone(),
        started_unix,
        version: env!("CARGO_PKG_VERSION").to_string(),
    };
    match write(&ctx.run_dir, &ptr) {
        Ok(published) => Some(published),
        Err(err) => {
            tracing::warn!(path = %ctx.run_dir.display(), %err, "could not publish the core pointer");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::atomic::{AtomicU64, Ordering};

    /// A unique empty temp directory for one test, removed by the test.
    fn temp_root(tag: &str) -> PathBuf {
        static N: AtomicU64 = AtomicU64::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("aitm-mcp-pointer-{}-{n}-{tag}", std::process::id()));
        fs::create_dir_all(&dir).expect("create temp root");
        dir
    }

    fn sample() -> CorePointer {
        CorePointer {
            v: 1,
            pid: 4821,
            bus: "127.0.0.1:50512".parse().expect("addr"),
            operator: true,
            config: PathBuf::from("/Users/matt/Library/Application Support/aitmproxy/config.yaml"),
            started_unix: 1761998645,
            version: "0.5.11".to_string(),
        }
    }

    const LINE: &str = "{\"v\":1,\"pid\":4821,\"bus\":\"127.0.0.1:50512\",\"operator\":true,\"config\":\"/Users/matt/Library/Application Support/aitmproxy/config.yaml\",\"started_unix\":1761998645,\"version\":\"0.5.11\"}\n";

    /// AC-R14-10: the spec's example line byte for byte, and it round-trips.
    #[test]
    fn to_json_line_has_the_contract_shape() {
        assert_eq!(sample().to_json_line(), LINE);
        assert_eq!(CorePointer::parse(LINE), Ok(sample()));
    }

    /// D4 trust: unknown `v`, a missing field, a non-loopback bus and non-JSON
    /// are each refused by name; an unknown extra key is ignored.
    #[test]
    fn parse_rejects_bad_pointers() {
        let v2 = LINE.replacen("\"v\":1", "\"v\":2", 1);
        assert_eq!(
            CorePointer::parse(&v2),
            Err(PointerProblem::UnknownVersion(2))
        );
        assert_eq!(
            CorePointer::parse("{\"v\":1,\"pid\":1}"),
            Err(PointerProblem::MissingField("bus"))
        );
        let off_box = LINE.replace("127.0.0.1:50512", "10.0.0.5:1");
        assert_eq!(
            CorePointer::parse(&off_box),
            Err(PointerProblem::NonLoopback(
                "10.0.0.5:1".parse().expect("addr")
            ))
        );
        match CorePointer::parse("not json") {
            Err(PointerProblem::NotJson(msg)) => assert!(!msg.is_empty()),
            other => panic!("expected NotJson, got {other:?}"),
        }
        let extra = LINE.replacen('{', "{\"extra\":\"ignored\",", 1);
        assert_eq!(CorePointer::parse(&extra), Ok(sample()));
    }

    /// AC-R14-10: `0600` file in `0700` `run` and `cores`, no `.tmp` left, the
    /// exact line, locked while published, removed on drop, and an unlocked
    /// file at the same path reads `Dead`.
    #[test]
    fn write_is_atomic_0600_locked_in_a_0700_dir() {
        let root = temp_root("write");
        let cores = root.join("run").join("cores");
        let ptr = sample();

        let published = write(&cores, &ptr).expect("write pointer");
        assert_eq!(published.path, cores.join("4821.json"));
        let mode = |p: &Path| fs::metadata(p).expect("metadata").permissions().mode() & 0o777;
        assert_eq!(mode(&published.path), 0o600);
        assert_eq!(mode(&cores), 0o700);
        assert_eq!(mode(&root.join("run")), 0o700);
        let names: Vec<String> = fs::read_dir(&cores)
            .expect("read cores")
            .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec!["4821.json".to_string()]);
        assert_eq!(
            fs::read_to_string(&published.path).expect("read pointer"),
            ptr.to_json_line()
        );
        assert_eq!(liveness(&published.path), Liveness::Alive);

        let path = published.path.clone();
        drop(published);
        assert!(!path.exists(), "drop removes the pointer");

        File::create(&path).expect("an unlocked file");
        assert_eq!(liveness(&path), Liveness::Dead);

        fs::remove_dir_all(&root).expect("cleanup");
    }

    /// S3 (security pass 1): a run dir that already exists is the operator's
    /// (an `AITM_RUN_DIR` they chose, or a data dir they set up); its mode is
    /// left exactly as it was, `0750` here, while the pointer inside is still
    /// `0600`. A dir this call creates is `0700`.
    #[test]
    fn write_leaves_a_pre_existing_run_dir_mode_alone() {
        let root = temp_root("preexisting");
        let mode = |p: &Path| fs::metadata(p).expect("metadata").permissions().mode() & 0o777;

        let theirs = root.join("theirs");
        fs::create_dir(&theirs).expect("the operator's run dir");
        fs::set_permissions(&theirs, fs::Permissions::from_mode(0o750)).expect("chmod 750");
        let published = write(&theirs, &sample()).expect("write into the existing dir");
        assert_eq!(
            mode(&theirs),
            0o750,
            "a pre-existing run dir keeps its mode"
        );
        assert_eq!(mode(&published.path), 0o600);
        assert_eq!(liveness(&published.path), Liveness::Alive);
        drop(published);

        let ours = root.join("made").join("cores");
        let published = write(&ours, &sample()).expect("write into a new dir");
        assert_eq!(mode(&ours), 0o700, "a dir this call created is 0700");
        assert_eq!(mode(&published.path), 0o600);
        drop(published);

        fs::remove_dir_all(&root).expect("cleanup");
    }

    /// Tester edge (2026-11-01): a `<pid>.json.tmp` left by a crash before
    /// its rename, met again after pid reuse. Our own stale temp file is
    /// removed before `create_new`, so the core still publishes: the final
    /// pointer is `0600`, locked, the exact line, and no `.tmp` remains.
    #[test]
    fn write_removes_our_own_stale_tmp_first() {
        let root = temp_root("stale-tmp");
        let cores = root.join("run").join("cores");
        fs::create_dir_all(&cores).expect("cores dir");
        let ptr = sample();
        let stale = cores.join("4821.json.tmp");
        fs::write(&stale, "half a line from a crashed writer").expect("plant stale tmp");

        let published = write(&cores, &ptr).expect("write over a stale tmp");
        assert_eq!(published.path, cores.join("4821.json"));
        let mode = fs::metadata(&published.path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
        assert_eq!(liveness(&published.path), Liveness::Alive);
        assert_eq!(
            fs::read_to_string(&published.path).expect("read pointer"),
            ptr.to_json_line()
        );
        let names: Vec<String> = fs::read_dir(&cores)
            .expect("read cores")
            .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec!["4821.json".to_string()]);
        assert!(!stale.exists(), "the stale tmp is gone");

        drop(published);
        fs::remove_dir_all(&root).expect("cleanup");
    }

    /// A symlink at `<pid>.json.tmp` is never followed or removed: `write`
    /// fails with `AlreadyExists`, the link survives, and its target is
    /// untouched.
    #[test]
    fn write_leaves_a_symlinked_tmp_alone() {
        let root = temp_root("symlink-tmp");
        let cores = root.join("run").join("cores");
        fs::create_dir_all(&cores).expect("cores dir");
        let target = root.join("victim");
        fs::write(&target, "untouched").expect("target");
        let link = cores.join("4821.json.tmp");
        std::os::unix::fs::symlink(&target, &link).expect("symlink");

        let kind = match write(&cores, &sample()) {
            Ok(_) => panic!("a symlinked tmp must refuse"),
            Err(err) => err.kind(),
        };
        assert_eq!(kind, io::ErrorKind::AlreadyExists);
        assert!(fs::symlink_metadata(&link)
            .expect("link stays")
            .file_type()
            .is_symlink());
        assert_eq!(fs::read_to_string(&target).expect("target"), "untouched");
        assert!(!cores.join("4821.json").exists());

        fs::remove_dir_all(&root).expect("cleanup");
    }

    /// AC-R14-32 (pure half): a `0644` pointer, a directory named `x.json` and
    /// a valid one are reported by file, in name order; a `.tmp` sibling is
    /// not a pointer; a foreign uid is `Foreign`; a missing dir is empty.
    #[test]
    fn scan_reports_trust_problems_by_file() {
        let root = temp_root("scan");
        let cores = root.join("cores");
        fs::create_dir_all(&cores).expect("cores");
        let owner_uid = fs::metadata(&cores).expect("cores metadata").uid();

        let wide = cores.join("1.json");
        fs::write(&wide, sample().to_json_line()).expect("wide pointer");
        fs::set_permissions(&wide, fs::Permissions::from_mode(0o644)).expect("chmod 644");
        let dir = cores.join("2.json");
        fs::create_dir(&dir).expect("dir named x.json");
        let good = cores.join("3.json");
        fs::write(&good, sample().to_json_line()).expect("good pointer");
        fs::set_permissions(&good, fs::Permissions::from_mode(0o600)).expect("chmod 600");
        fs::write(cores.join("4.json.tmp"), "half").expect("tmp sibling");

        assert_eq!(
            scan(&cores, owner_uid),
            vec![
                Err((wide.clone(), PointerProblem::Wide(0o644))),
                Err((dir.clone(), PointerProblem::NotRegular)),
                Ok(Found {
                    path: good.clone(),
                    pointer: sample()
                }),
            ]
        );
        assert_eq!(
            scan(&cores, owner_uid.wrapping_add(1)),
            vec![
                Err((wide, PointerProblem::Foreign)),
                Err((dir, PointerProblem::NotRegular)),
                Err((good, PointerProblem::Foreign)),
            ]
        );
        assert!(scan(&root.join("missing"), owner_uid).is_empty());

        fs::remove_dir_all(&root).expect("cleanup");
    }

    /// AC-R14-11: a non-empty `AITM_RUN_DIR` wins; empty or unset falls back
    /// to the default, which is the `run/cores` sibling of the CA audit log.
    #[test]
    fn run_dir_prefers_the_env_override() {
        let set = |k: &str| (k == "AITM_RUN_DIR").then(|| "/tmp/claude/r".to_string());
        assert_eq!(run_dir(&set), PathBuf::from("/tmp/claude/r"));
        let empty = |k: &str| (k == "AITM_RUN_DIR").then(String::new);
        assert_eq!(run_dir(&empty), default_run_dir());
        let unset = |_: &str| -> Option<String> { None };
        assert_eq!(run_dir(&unset), default_run_dir());
        assert!(
            default_run_dir().ends_with("aitmproxy/run/cores"),
            "{}",
            default_run_dir().display()
        );
        assert_eq!(
            default_run_dir(),
            aitm_core::CaConfig::default()
                .audit_log
                .with_file_name("run")
                .join("cores")
        );
    }

    /// AC-R14-12: the unit-test binary never publishes a context, so the
    /// transport's call writes nothing, anywhere.
    #[test]
    fn publish_pointer_without_context_writes_nothing() {
        assert!(context().is_none(), "the unit-test binary never publishes");
        let bus: SocketAddr = "127.0.0.1:50512".parse().expect("addr");
        assert!(publish_pointer(bus, true).is_none());
        let own = default_run_dir().join(format!("{}.json", std::process::id()));
        assert!(!own.exists(), "{} must not exist", own.display());
    }

    // ---- tester additions (stage 5, R14 pass 1) ----

    /// Tester — D4 trust: the mask is `0o077`, so a group-only (`0640`) and
    /// an other-only (`0604`) bit are each `Wide` on their own; `0600`,
    /// `0400` and `0700` pass. Kills a widened mask (`0o007`, `0o070`).
    #[test]
    fn tester_scan_rejects_group_and_other_bits_separately() {
        let root = temp_root("tester-bits");
        let cores = root.join("cores");
        fs::create_dir_all(&cores).expect("cores");
        let owner_uid = fs::metadata(&cores).expect("cores metadata").uid();
        let line = sample().to_json_line();
        let mk = |name: &str, mode: u32| {
            let p = cores.join(name);
            fs::write(&p, &line).expect("write pointer");
            fs::set_permissions(&p, fs::Permissions::from_mode(mode)).expect("chmod");
            p
        };
        let group = mk("1.json", 0o640);
        let other = mk("2.json", 0o604);
        let tight = mk("3.json", 0o600);
        let read_only = mk("4.json", 0o400);
        let owner_exec = mk("5.json", 0o700);
        assert_eq!(
            scan(&cores, owner_uid),
            vec![
                Err((group, PointerProblem::Wide(0o640))),
                Err((other, PointerProblem::Wide(0o604))),
                Ok(Found {
                    path: tight,
                    pointer: sample()
                }),
                Ok(Found {
                    path: read_only,
                    pointer: sample()
                }),
                Ok(Found {
                    path: owner_exec,
                    pointer: sample()
                }),
            ]
        );
        fs::remove_dir_all(&root).expect("cleanup");
    }

    /// Tester — D4 trust: `scan` reads each entry's own metadata (symlinks
    /// are not followed), so a symlink named `<pid>.json` is `NotRegular`
    /// even when its target is a perfect `0600` pointer, and the target is
    /// left untouched. A planted link can never redirect a reader.
    #[test]
    fn tester_scan_never_follows_a_symlinked_pointer() {
        let root = temp_root("tester-symlink");
        let cores = root.join("cores");
        fs::create_dir_all(&cores).expect("cores");
        let owner_uid = fs::metadata(&cores).expect("cores metadata").uid();
        let elsewhere = root.join("elsewhere.json");
        fs::write(&elsewhere, sample().to_json_line()).expect("target");
        fs::set_permissions(&elsewhere, fs::Permissions::from_mode(0o600)).expect("chmod");
        let link = cores.join("9.json");
        std::os::unix::fs::symlink(&elsewhere, &link).expect("symlink");

        assert_eq!(
            scan(&cores, owner_uid),
            vec![Err((link.clone(), PointerProblem::NotRegular))]
        );
        assert!(
            fs::symlink_metadata(&link)
                .expect("link metadata")
                .file_type()
                .is_symlink(),
            "the link is kept"
        );
        assert_eq!(
            fs::read_to_string(&elsewhere).expect("target kept"),
            sample().to_json_line()
        );
        fs::remove_dir_all(&root).expect("cleanup");
    }

    /// Tester — `scan` keys on the `.json` extension alone: a non-numeric
    /// name is still a pointer (the content, not the name, carries the pid),
    /// a `.json.tmp` leftover is not, an empty file is `NotJson`, and an
    /// unreadable (`0000`) file is skipped without a report.
    #[test]
    fn tester_scan_takes_any_json_name_skips_tmp_and_unreadable_reports_empty() {
        let root = temp_root("tester-names");
        let cores = root.join("cores");
        fs::create_dir_all(&cores).expect("cores");
        let owner_uid = fs::metadata(&cores).expect("cores metadata").uid();
        let named = cores.join("not-a-pid.json");
        fs::write(&named, sample().to_json_line()).expect("named pointer");
        fs::set_permissions(&named, fs::Permissions::from_mode(0o600)).expect("chmod");
        fs::write(cores.join("12.json.tmp"), sample().to_json_line()).expect("tmp leftover");
        let empty = cores.join("13.json");
        fs::write(&empty, "").expect("empty pointer");
        fs::set_permissions(&empty, fs::Permissions::from_mode(0o600)).expect("chmod");
        let unreadable = cores.join("14.json");
        fs::write(&unreadable, sample().to_json_line()).expect("unreadable pointer");
        fs::set_permissions(&unreadable, fs::Permissions::from_mode(0o000)).expect("chmod");
        if fs::read(&unreadable).is_ok() {
            eprintln!("skipping: this user can read a 0000 file (root)");
            fs::remove_dir_all(&root).expect("cleanup");
            return;
        }

        let got = scan(&cores, owner_uid);
        assert_eq!(got.len(), 2, "{got:?}");
        match &got[0] {
            Err((path, PointerProblem::NotJson(_))) => assert_eq!(path, &empty),
            other => panic!("expected NotJson for the empty file, got {other:?}"),
        }
        assert_eq!(
            got[1],
            Ok(Found {
                path: named.clone(),
                pointer: sample()
            })
        );

        fs::set_permissions(&unreadable, fs::Permissions::from_mode(0o600)).expect("restore");
        fs::remove_dir_all(&root).expect("cleanup");
    }

    /// Tester — C3: a probe that cannot open the file is `Unknown` (the
    /// reader treats it as alive and never deletes it): a `0000` file, and a
    /// path that vanished between the scan and the probe. Once readable
    /// again the same unlocked file reads `Dead`.
    #[test]
    fn tester_liveness_is_unknown_when_the_file_cannot_be_opened() {
        let root = temp_root("tester-liveness");
        let p = root.join("1.json");
        fs::write(&p, sample().to_json_line()).expect("write");
        fs::set_permissions(&p, fs::Permissions::from_mode(0o000)).expect("chmod");
        if fs::read(&p).is_ok() {
            eprintln!("skipping: this user can read a 0000 file (root)");
            fs::remove_dir_all(&root).expect("cleanup");
            return;
        }
        assert_eq!(liveness(&p), Liveness::Unknown);
        fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).expect("restore");
        assert_eq!(liveness(&p), Liveness::Dead);
        assert_eq!(liveness(&root.join("gone.json")), Liveness::Unknown);
        fs::remove_dir_all(&root).expect("cleanup");
    }

    /// Tester — the writer given a run dir that is a symlink: the link counts
    /// as an existing dir, the `0600` pointer lands in the link's target,
    /// `liveness` reads `Alive` through either path, and the drop removes the
    /// file from the target. Pinned as observed: spec D4 does not rule on a
    /// symlinked run dir (it sits inside the user's own `0700` data dir, or
    /// wherever `AITM_RUN_DIR` points by the operator's choice). Since S3 the
    /// pre-existing target keeps its `0755`: it is the operator's.
    #[test]
    fn tester_write_through_a_symlinked_run_dir_lands_in_the_target() {
        let root = temp_root("tester-linkdir");
        let real = root.join("real-cores");
        fs::create_dir_all(&real).expect("real dir");
        fs::set_permissions(&real, fs::Permissions::from_mode(0o755)).expect("chmod");
        let link = root.join("cores");
        std::os::unix::fs::symlink(&real, &link).expect("symlink the run dir");

        let published = write(&link, &sample()).expect("write through the link");
        assert_eq!(published.path, link.join("4821.json"));
        let mode = |p: &Path| fs::metadata(p).expect("metadata").permissions().mode() & 0o777;
        assert_eq!(mode(&real.join("4821.json")), 0o600);
        assert_eq!(
            mode(&real),
            0o755,
            "a pre-existing target is left as the operator has it (S3)"
        );
        assert!(
            fs::symlink_metadata(&link)
                .expect("link metadata")
                .file_type()
                .is_symlink(),
            "the link is not replaced"
        );
        assert_eq!(liveness(&published.path), Liveness::Alive);
        assert_eq!(liveness(&real.join("4821.json")), Liveness::Alive);
        drop(published);
        assert!(
            !real.join("4821.json").exists(),
            "drop removes the target's file"
        );
        fs::remove_dir_all(&root).expect("cleanup");
    }

    /// Tester — the pointer line is built from the struct alone: a config
    /// path is the only free text in it, and it is JSON-escaped (a quote or a
    /// newline in the path cannot break the one-line contract).
    #[test]
    fn tester_json_line_escapes_the_config_path_and_stays_one_line() {
        let odd = CorePointer {
            config: PathBuf::from("/tmp/we\"ird\npath/config.yaml"),
            ..sample()
        };
        let line = odd.to_json_line();
        assert_eq!(line.matches('\n').count(), 1, "{line:?}");
        assert!(line.ends_with('\n'));
        assert!(line.contains("\\\"ird\\npath"), "{line:?}");
        assert_eq!(CorePointer::parse(&line), Ok(odd));
    }

    /// Tester — D4 trust (AC-R14-31's sibling for pointers): a FIFO named
    /// `<pid>.json` is `NotRegular` from its own metadata and is never
    /// opened — `scan` returns at once even though nobody writes the pipe
    /// (opening it would block forever). Run on a helper thread with a
    /// deadline so a regression hangs the probe, not the suite.
    #[test]
    fn tester_scan_never_opens_a_fifo_pointer() {
        let root = temp_root("tester-fifo");
        let cores = root.join("cores");
        fs::create_dir_all(&cores).expect("cores");
        let owner_uid = fs::metadata(&cores).expect("cores metadata").uid();
        let fifo = cores.join("7.json");
        let made = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .expect("run mkfifo");
        assert!(made.success(), "mkfifo {}", fifo.display());

        let (tx, rx) = std::sync::mpsc::channel();
        let probe_dir = cores.clone();
        std::thread::spawn(move || {
            let _ = tx.send(scan(&probe_dir, owner_uid));
        });
        let got = rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("scan must not block on a FIFO pointer");
        assert_eq!(got, vec![Err((fifo.clone(), PointerProblem::NotRegular))]);
        fs::remove_dir_all(&root).expect("cleanup");
    }
}
