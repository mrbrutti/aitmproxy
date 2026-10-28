//! Test support shared by this crate's integration tests and by `aitm`'s:
//! the fingerprints of the checked-in fixture CA (`tests/fixtures/ca.crt`),
//! and the `Executor` / `AuditLog` doubles.
//!
//! The fixture is a self-signed P-256 certificate whose key was discarded at
//! generation; only the certificate is in the tree.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::bail;

use crate::audit::{AuditLog, AuditRecord};
use crate::exec::{lock, CmdLine, CmdOutput, Executor};

/// SHA-256 fingerprint of `tests/fixtures/ca.crt`, colon form, exactly as
/// `openssl x509 -noout -fingerprint -sha256` prints it.
pub const FIXTURE_FP256: &str =
    "41:88:D2:5C:9E:BD:56:21:31:81:52:AD:D8:CE:78:C4:9C:40:77:C4:07:D1:7F:0D:4B:58:6E:22:E4:4A:CA:43";

/// SHA-1 fingerprint of `tests/fixtures/ca.crt`, colon form, exactly as
/// `openssl x509 -noout -fingerprint -sha1` prints it.
pub const FIXTURE_FP1: &str = "B1:30:2C:92:2B:7C:A0:78:5D:76:E0:A0:00:43:01:51:1C:05:92:90";

/// A host made of canned answers. `run` never reaches the OS: responses are
/// keyed by rendered command line, with a default for anything unlisted.
/// Files, directories, home and root status are fixed by the builder
/// methods; every `run` (line plus stdin) and every `read_file` path is
/// recorded in order, so tests assert exact command sequences and prove no
/// path ever names `ca.key`.
#[derive(Debug)]
pub struct ScriptedExecutor {
    /// Several `respond` calls for one line are played in order; the last
    /// one repeats. Behind a mutex because `run` takes `&self`.
    responses: Mutex<BTreeMap<String, VecDeque<CmdOutput>>>,
    default_response: CmdOutput,
    files: BTreeMap<PathBuf, Vec<u8>>,
    dirs: BTreeSet<PathBuf>,
    home: Option<PathBuf>,
    is_root: bool,
    real_fs: bool,
    runs: Mutex<Vec<(String, Option<Vec<u8>>)>>,
    reads: Mutex<Vec<PathBuf>>,
}

impl Default for ScriptedExecutor {
    fn default() -> Self {
        Self::new()
    }
}

impl ScriptedExecutor {
    /// Home `/Users/t`, not root, every command exits 0 with empty output.
    pub fn new() -> Self {
        Self {
            responses: Mutex::new(BTreeMap::new()),
            default_response: CmdOutput {
                code: Some(0),
                ..CmdOutput::default()
            },
            files: BTreeMap::new(),
            dirs: BTreeSet::new(),
            home: Some(PathBuf::from("/Users/t")),
            is_root: false,
            real_fs: false,
            runs: Mutex::new(Vec::new()),
            reads: Mutex::new(Vec::new()),
        }
    }

    /// Answer `rendered` (a `CmdLine::render()` string) with this output.
    /// Called again for the same line, the responses play in order and the
    /// last one repeats.
    pub fn respond(self, rendered: &str, code: i32, stdout: &str, stderr: &str) -> Self {
        lock(&self.responses)
            .entry(rendered.to_string())
            .or_default()
            .push_back(CmdOutput {
                code: Some(code),
                stdout: stdout.to_string(),
                stderr: stderr.to_string(),
            });
        self
    }

    pub fn file(mut self, path: &str, bytes: &[u8]) -> Self {
        self.files.insert(PathBuf::from(path), bytes.to_vec());
        self
    }

    pub fn dir(mut self, path: &str) -> Self {
        self.dirs.insert(PathBuf::from(path));
        self
    }

    pub fn root(mut self, is_root: bool) -> Self {
        self.is_root = is_root;
        self
    }

    /// `read_file` and `dir_exists` use the real filesystem; `run` stays
    /// scripted. For tests that need a real directory.
    pub fn with_real_fs(mut self) -> Self {
        self.real_fs = true;
        self
    }

    /// Rendered lines of every `run`, in order.
    pub fn runs(&self) -> Vec<String> {
        lock(&self.runs)
            .iter()
            .map(|(line, _)| line.clone())
            .collect()
    }

    /// The stdin of every `run`, in the same order as [`Self::runs`].
    pub fn stdins(&self) -> Vec<Option<Vec<u8>>> {
        lock(&self.runs)
            .iter()
            .map(|(_, stdin)| stdin.clone())
            .collect()
    }

    /// Every path `read_file` was asked for, in order.
    pub fn reads(&self) -> Vec<PathBuf> {
        lock(&self.reads).clone()
    }
}

impl Executor for ScriptedExecutor {
    fn run(&self, cmd: &CmdLine) -> anyhow::Result<CmdOutput> {
        let rendered = cmd.render();
        lock(&self.runs).push((rendered.clone(), cmd.stdin.clone()));
        let mut responses = lock(&self.responses);
        let out = match responses.get_mut(&rendered) {
            // Queued responses play in order; the last one repeats.
            Some(queue) if queue.len() > 1 => queue.pop_front().unwrap_or_default(),
            Some(queue) => queue.front().cloned().unwrap_or_default(),
            None => self.default_response.clone(),
        };
        Ok(out)
    }

    fn read_file(&self, path: &Path) -> anyhow::Result<Option<Vec<u8>>> {
        lock(&self.reads).push(path.to_path_buf());
        if self.real_fs {
            return match std::fs::read(path) {
                Ok(bytes) => Ok(Some(bytes)),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
                Err(e) => Err(e.into()),
            };
        }
        Ok(self.files.get(path).cloned())
    }

    fn dir_exists(&self, path: &Path) -> bool {
        if self.real_fs {
            return path.is_dir();
        }
        self.dirs.contains(path)
    }

    fn home_dir(&self) -> Option<PathBuf> {
        self.home.clone()
    }

    fn is_root(&self) -> bool {
        self.is_root
    }
}

/// Records in memory; `failing()` refuses `open()`, the way an unwritable
/// log file would.
#[derive(Debug, Default)]
pub struct MemoryAuditLog {
    records: Mutex<Vec<AuditRecord>>,
    fail_open: bool,
}

impl MemoryAuditLog {
    pub fn new() -> Self {
        Self::default()
    }

    /// `open()` returns `Err`, so a command using this log must refuse.
    pub fn failing() -> Self {
        Self {
            records: Mutex::new(Vec::new()),
            fail_open: true,
        }
    }

    pub fn records(&self) -> Vec<AuditRecord> {
        lock(&self.records).clone()
    }
}

impl AuditLog for MemoryAuditLog {
    fn open(&self) -> anyhow::Result<()> {
        if self.fail_open {
            bail!("audit log is not writable (scripted failure)");
        }
        Ok(())
    }

    fn record(&self, rec: &AuditRecord) -> anyhow::Result<()> {
        lock(&self.records).push(rec.clone());
        Ok(())
    }
}
