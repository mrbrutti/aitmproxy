//! Task 10 — `CaCert`: parse `<dir>/ca.crt`, digest it, and never touch
//! anything else in the directory.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use aitm_ca::cert::CaCert;
use aitm_ca::exec::{CmdLine, CmdOutput, Executor};
use aitm_ca::testing::{FIXTURE_FP1, FIXTURE_FP256};

/// The checked-in fixture CA, exactly as `ca.crt` on disk.
const FIXTURE: &[u8] = include_bytes!("fixtures/ca.crt");

/// A minimal `Executor` whose only job is to answer `read_file` from an
/// in-memory map and record every path it was asked for. (Task 11's
/// `ScriptedExecutor` subsumes this; Task 10 keeps its own so it commits
/// before Task 11.)
struct StubExec {
    files: BTreeMap<PathBuf, Vec<u8>>,
    reads: Mutex<Vec<PathBuf>>,
}

impl StubExec {
    fn new() -> Self {
        Self {
            files: BTreeMap::new(),
            reads: Mutex::new(Vec::new()),
        }
    }

    fn file(mut self, path: &str, bytes: &[u8]) -> Self {
        self.files.insert(PathBuf::from(path), bytes.to_vec());
        self
    }

    fn reads(&self) -> Vec<PathBuf> {
        self.reads.lock().unwrap().clone()
    }
}

impl Executor for StubExec {
    fn run(&self, _cmd: &CmdLine) -> anyhow::Result<CmdOutput> {
        Ok(CmdOutput::default())
    }

    fn read_file(&self, path: &Path) -> anyhow::Result<Option<Vec<u8>>> {
        self.reads.lock().unwrap().push(path.to_path_buf());
        Ok(self.files.get(path).cloned())
    }

    fn dir_exists(&self, _path: &Path) -> bool {
        false
    }

    fn home_dir(&self) -> Option<PathBuf> {
        Some(PathBuf::from("/Users/t"))
    }

    fn is_root(&self) -> bool {
        false
    }
}

#[test]
fn fixture_fingerprints() {
    let exec = StubExec::new().file("/ca/ca.crt", FIXTURE);
    let cert = CaCert::load(Path::new("/ca"), &exec)
        .unwrap()
        .expect("fixture is present");

    assert_eq!(cert.fingerprint_sha256(), FIXTURE_FP256);
    assert_eq!(cert.fingerprint_sha1(), FIXTURE_FP1);
    assert_eq!(cert.sha256_hex(), FIXTURE_FP256.replace(':', ""));
    assert_eq!(
        cert.sha1_hex_lower(),
        FIXTURE_FP1.replace(':', "").to_lowercase()
    );
    // DER of an X.509 certificate is a SEQUENCE in long form (0x30 0x82 ...).
    assert_eq!(&cert.der[0..2], &[0x30, 0x82]);
}

#[test]
fn missing_is_none() {
    let exec = StubExec::new();
    let got = CaCert::load(Path::new("/ca"), &exec).unwrap();
    assert!(got.is_none());
    assert_eq!(exec.reads(), vec![PathBuf::from("/ca/ca.crt")]);
}

#[test]
fn two_blocks_is_an_error() {
    let mut doubled = FIXTURE.to_vec();
    doubled.push(b'\n');
    doubled.extend_from_slice(FIXTURE);
    let exec = StubExec::new().file("/ca/ca.crt", &doubled);

    let err = CaCert::load(Path::new("/ca"), &exec).unwrap_err();
    assert!(err.to_string().contains("exactly one"), "got: {err}");
}

/// A combined key+certificate PEM renamed to `ca.crt` must never be loaded:
/// `export` ships the file text and `install` tees it into a world-readable
/// anchor, so any block that is not a `CERTIFICATE` is an error that names
/// the block's label without echoing its contents.
#[test]
fn foreign_block_is_an_error() {
    let key: &[u8] = b"-----BEGIN EC PRIVATE KEY-----\nAAAA\n-----END EC PRIVATE KEY-----\n";
    for (tag, bytes) in [
        ("cert then key", [FIXTURE, key].concat()),
        ("key then cert", [key, FIXTURE].concat()),
    ] {
        let exec = StubExec::new().file("/ca/ca.crt", &bytes);
        let err = CaCert::load(Path::new("/ca"), &exec).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("EC PRIVATE KEY"), "{tag}: got: {msg}");
        assert!(msg.contains("/ca/ca.crt"), "{tag}: got: {msg}");
        assert!(!msg.contains("AAAA"), "{tag}: echoes block contents: {msg}");
    }
}

#[test]
fn key_is_never_read() {
    let exec = StubExec::new()
        .file("/ca/ca.crt", FIXTURE)
        .file("/ca/ca.key", b"not a real key");

    let _ = CaCert::load(Path::new("/ca"), &exec)
        .unwrap()
        .expect("fixture is present");

    // load opens exactly one file: ca.crt. ca.key is never read.
    assert_eq!(exec.reads(), vec![PathBuf::from("/ca/ca.crt")]);
}
