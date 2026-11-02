//! macOS gatherer: the inputs of the spec §2.2 macOS table and the §2.3 handoff
//! validation.
//!
//! The decisions live in pure functions ([`bundle_of_exe`], [`handoff_target`],
//! [`validate_handoff_app`]) that compile and are tested on every OS. The I/O
//! ([`app_facts`], [`gather_mac`]) only reads: it opens `/dev/bpf*`, reads the
//! receipt, and asks `plutil` and `codesign` about a bundle. It never changes
//! system state and never runs a shell.

use std::path::{Path, PathBuf};
use std::time::SystemTime;

use crate::privilege::contract::APP_BUNDLE_ID;
#[cfg(target_os = "macos")]
use crate::privilege::contract::TEAM_ID;
use crate::privilege::contract::{Receipt, HELPER_PLIST_REL, RECEIPT_PATH};
use crate::privilege::derive::MacInputs;

/// The tail an executable has when it is the core inside the macOS app bundle.
const BUNDLED_CORE_TAIL: [&str; 4] = ["Contents", "Resources", "core", "aitm"];

/// Where a handoff app is never accepted from (spec §2.3): per-user and shared
/// temporary trees, where any process could drop a look-alike bundle. `/var` is
/// a symlink to `/private/var` on macOS, so both spellings of the folders tree
/// are listed.
const TEMP_PREFIXES: [&str; 4] = [
    "/tmp",
    "/private/tmp",
    "/var/folders",
    "/private/var/folders",
];

/// The `<X>.app` a core runs from, when its executable is
/// `<X>.app/Contents/Resources/core/aitm`; `None` for any other layout.
#[must_use]
pub fn bundle_of_exe(exe: &Path) -> Option<PathBuf> {
    let mut cursor = exe;
    for expected in BUNDLED_CORE_TAIL.iter().rev() {
        if cursor.file_name()?.to_str()? != *expected {
            return None;
        }
        cursor = cursor.parent()?;
    }
    is_app_bundle_path(cursor).then(|| cursor.to_path_buf())
}

/// The app `l4.privilege.request` hands off to (spec §2.3): the running core's
/// own bundle when it runs from one, else the configured `macos_app_path`.
#[must_use]
pub fn handoff_target(exe: Option<&Path>, macos_app_path: &Path) -> PathBuf {
    exe.and_then(bundle_of_exe)
        .unwrap_or_else(|| macos_app_path.to_path_buf())
}

/// What the gatherer learned about a candidate handoff app.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppFacts {
    /// The path exists and is a directory.
    pub is_dir: bool,
    /// `CFBundleIdentifier` from its `Info.plist`, when readable.
    pub bundle_id: Option<String>,
    /// Its code signature verifies strictly and its team is the project's.
    pub team_ok: bool,
}

/// Why a handoff app is refused (spec §2.3). Each variant is a fact for a log
/// line; a frontend only ever sees the `package` label built by `derive`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandoffRefusal {
    /// The path does not exist or is not a directory.
    Missing,
    /// The path does not end in `.app`.
    NotAnApp,
    /// The path is under a temporary tree.
    TempPath,
    /// The bundle id is not [`APP_BUNDLE_ID`]; carries the id found (empty when
    /// none was readable).
    WrongBundleId(String),
    /// The signature does not verify, or its team is not the project's.
    BadSignature,
}

/// The handoff app's canonical path (symlinks and `/var` → `/private/var`
/// resolved), so the checks below see the real location; a path that cannot
/// be canonicalized does not exist for us: `Missing`.
pub(crate) fn canonicalize_or_missing(path: &Path) -> Result<PathBuf, HandoffRefusal> {
    std::fs::canonicalize(path).map_err(|_| HandoffRefusal::Missing)
}

/// Canonicalize, refuse by the canonical path's shape (temporary tree, `.app`
/// suffix) **before** any fact is gathered about it, then validate the facts
/// gathered for the canonical path. Each check runs once. `Ok` carries the
/// canonical path to use from here on.
pub(crate) fn validated_handoff(
    path: &Path,
    facts: impl FnOnce(&Path) -> AppFacts,
) -> Result<PathBuf, HandoffRefusal> {
    let canonical = canonicalize_or_missing(path)?;
    refuse_by_path(&canonical)?;
    validate_facts(&facts(&canonical))?;
    Ok(canonical)
}

/// The path-shape half of [`validate_handoff_app`]: a temporary tree, then
/// the `.app` suffix.
fn refuse_by_path(path: &Path) -> Result<(), HandoffRefusal> {
    if TEMP_PREFIXES.iter().any(|prefix| path.starts_with(prefix)) {
        return Err(HandoffRefusal::TempPath);
    }
    if !is_app_bundle_path(path) {
        return Err(HandoffRefusal::NotAnApp);
    }
    Ok(())
}

/// The facts half of [`validate_handoff_app`]: exists, bundle id, signature,
/// in that order.
fn validate_facts(facts: &AppFacts) -> Result<(), HandoffRefusal> {
    if !facts.is_dir {
        return Err(HandoffRefusal::Missing);
    }
    match facts.bundle_id.as_deref() {
        Some(APP_BUNDLE_ID) => {}
        Some(other) => return Err(HandoffRefusal::WrongBundleId(other.to_string())),
        None => return Err(HandoffRefusal::WrongBundleId(String::new())),
    }
    if !facts.team_ok {
        return Err(HandoffRefusal::BadSignature);
    }
    Ok(())
}

/// Validate a handoff app against the facts gathered about it. Pure: the path
/// shape is checked first ([`refuse_by_path`]: temporary tree, `.app`
/// suffix), then the facts ([`validate_facts`]: exists, bundle id,
/// signature), so a path we would never use is refused before anything about
/// it is trusted. Callers give it the **canonical** path.
pub fn validate_handoff_app(path: &Path, facts: &AppFacts) -> Result<(), HandoffRefusal> {
    refuse_by_path(path)?;
    validate_facts(facts)
}

fn is_app_bundle_path(path: &Path) -> bool {
    path.extension().and_then(|ext| ext.to_str()) == Some("app")
        && path.file_name().is_some_and(|name| name != ".app")
}

/// Everything `derive` needs from this Mac (spec §2.2 macOS table), gathered
/// read-only: a `/dev/bpf*` read+write open, the helper's receipt, and whether
/// the handoff app embeds the helper plist. `macos_app_path` is the configured
/// fallback; a core running inside a bundle uses its own.
///
/// `pub(crate)`: P1b.6's `PrivilegeState` wires it behind the `Prober` seam.
pub(crate) fn gather_mac(macos_app_path: &Path) -> MacInputs {
    let exe = std::env::current_exe().ok();
    let app = handoff_target(exe.as_deref(), macos_app_path);
    // Canonical path first: the temporary-tree refusal applies to where the
    // bundle really is, and the facts are gathered for that path.
    let handoff_app_embeds_helper = validated_handoff(&app, app_facts)
        .is_ok_and(|canonical| canonical.join(HELPER_PLIST_REL).is_file());
    MacInputs {
        bpf_rw_opens: bpf_rw_opens(),
        receipt: read_receipt(),
        handoff_app_embeds_helper,
    }
}

/// The first `/dev/bpf<n>` that opens read+write proves capture and inject, the
/// same walk `module.rs`'s start-up probe does. The handle drops at once.
fn bpf_rw_opens() -> bool {
    use std::io::ErrorKind;
    for n in 0..256u32 {
        let path = format!("/dev/bpf{n}");
        match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
        {
            Ok(_handle) => return true,
            // Past the last device node.
            Err(err) if err.kind() == ErrorKind::NotFound => return false,
            // Denied or busy: try the next node.
            Err(_) => continue,
        }
    }
    false
}

/// The helper's receipt, when one is present and this build can read it.
fn read_receipt() -> Option<Receipt> {
    let bytes = std::fs::read(RECEIPT_PATH).ok()?;
    Receipt::parse(&bytes).ok()
}

/// The app bundle's main executable, relative to the bundle: the
/// `CFBundleExecutable` of `apps/mac/Info.plist.in`. Read as a fixed path
/// rather than from the plist, which would cost a `plutil` run per probe.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) const APP_EXECUTABLE_REL: &str = "Contents/MacOS/Aitmproxy";

/// The code signature's resource list: the fallback stamp when the main
/// executable is not where [`APP_EXECUTABLE_REL`] says (it is rewritten by
/// every re-sign).
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) const CODE_RESOURCES_REL: &str = "Contents/_CodeSignature/CodeResources";

/// One file's mtime and size, as a bundle part is stamped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) struct FileStamp {
    /// Last modification.
    pub mtime: SystemTime,
    /// `st_size`.
    pub size: u64,
}

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
impl FileStamp {
    /// The stamp of a file as its metadata describes it (`None` when the
    /// filesystem reports no mtime).
    #[must_use]
    pub fn of(meta: &std::fs::Metadata) -> Option<Self> {
        Some(FileStamp {
            mtime: meta.modified().ok()?,
            size: meta.len(),
        })
    }
}

/// [`FileStamp`] of the file at `path`, `None` when it cannot be read.
#[must_use]
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) fn file_stamp(path: &Path) -> Option<FileStamp> {
    std::fs::metadata(path)
        .ok()
        .and_then(|meta| FileStamp::of(&meta))
}

/// The executable part of a [`BundleStamp`]: the main executable's stamp
/// when it exists, else the code signature's resource list, else nothing.
#[must_use]
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) fn executable_stamp(
    main_executable: Option<FileStamp>,
    code_resources: Option<FileStamp>,
) -> Option<FileStamp> {
    main_executable.or(code_resources)
}

/// What the facts cache is keyed on (spec §2.3, panel 2): the bundle
/// directory's identity and the parts a replaced or re-signed bundle changes.
/// The directory's own mtime is not among them: swapping the executable or
/// `Info.plist` in place leaves it alone, and a fresh copy with the same
/// mtime is a different inode. `Info.plist` and the main executable are
/// each stamped by mtime **and** size (panel 3, D9), so an in-place
/// overwrite of either is a new key.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) struct BundleStamp {
    /// `st_dev` of the bundle directory.
    dev: u64,
    /// `st_ino` of the bundle directory.
    ino: u64,
    /// [`FileStamp`] of `Contents/Info.plist`, when it exists.
    info_plist: Option<FileStamp>,
    /// [`executable_stamp`]: the main executable, else `CodeResources`.
    executable: Option<FileStamp>,
}

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
impl BundleStamp {
    /// The key for a bundle directory with identity `(dev, ino)`, its
    /// `Info.plist` stamp and its executable stamp (see [`executable_stamp`]).
    #[must_use]
    pub fn new(
        dev: u64,
        ino: u64,
        info_plist: Option<FileStamp>,
        executable: Option<FileStamp>,
    ) -> Self {
        BundleStamp {
            dev,
            ino,
            info_plist,
            executable,
        }
    }
}

/// Ask macOS about a bundle: its `CFBundleIdentifier` via `plutil`, and whether
/// `codesign --verify --strict` accepts it under a requirement pinning the
/// project's team. Both are absolute program paths with a bounded wait and no
/// shell. Results are cached by path under a [`BundleStamp`] so the signature
/// check does not run on every re-probe **(Architect's call)**.
#[cfg(target_os = "macos")]
fn app_facts(path: &Path) -> AppFacts {
    use std::collections::HashMap;
    use std::os::unix::fs::MetadataExt;
    use std::sync::{Mutex, OnceLock};

    static CACHE: OnceLock<Mutex<HashMap<PathBuf, (BundleStamp, AppFacts)>>> = OnceLock::new();

    let Ok(meta) = std::fs::metadata(path) else {
        return AppFacts {
            is_dir: false,
            bundle_id: None,
            team_ok: false,
        };
    };
    if !meta.is_dir() {
        return AppFacts {
            is_dir: false,
            bundle_id: None,
            team_ok: false,
        };
    }
    let stamp = BundleStamp::new(
        meta.dev(),
        meta.ino(),
        file_stamp(&path.join("Contents/Info.plist")),
        executable_stamp(
            file_stamp(&path.join(APP_EXECUTABLE_REL)),
            file_stamp(&path.join(CODE_RESOURCES_REL)),
        ),
    );

    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Ok(map) = cache.lock() {
        if let Some((seen, facts)) = map.get(path) {
            if *seen == stamp {
                return facts.clone();
            }
        }
    }

    let facts = AppFacts {
        is_dir: true,
        bundle_id: read_bundle_id(path),
        team_ok: team_signature_ok(path),
    };
    // A poisoned lock only means another probe panicked mid-insert; the cache
    // is an optimisation, so take the inner map and carry on.
    let mut map = cache
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    map.insert(path.to_path_buf(), (stamp, facts.clone()));
    facts
}

/// Portable stand-in: without `plutil` and `codesign` nothing about a bundle
/// can be asserted, so a non-macOS build never validates a handoff app.
#[cfg(not(target_os = "macos"))]
fn app_facts(path: &Path) -> AppFacts {
    AppFacts {
        is_dir: path.is_dir(),
        bundle_id: None,
        team_ok: false,
    }
}

/// How long `plutil` or `codesign` may take before the probe gives up on them.
#[cfg(target_os = "macos")]
const TOOL_WAIT: std::time::Duration = std::time::Duration::from_secs(5);

#[cfg(target_os = "macos")]
fn read_bundle_id(app: &Path) -> Option<String> {
    let plist = app.join("Contents/Info.plist");
    let (status, stdout) = run_bounded(
        "/usr/bin/plutil",
        &[
            "-extract".as_ref(),
            "CFBundleIdentifier".as_ref(),
            "raw".as_ref(),
            "-o".as_ref(),
            "-".as_ref(),
            plist.as_os_str(),
        ],
        TOOL_WAIT,
    )?;
    if !status.success() {
        return None;
    }
    let id = String::from_utf8(stdout).ok()?;
    let id = id.trim();
    (!id.is_empty()).then(|| id.to_string())
}

#[cfg(target_os = "macos")]
fn team_signature_ok(app: &Path) -> bool {
    let requirement =
        format!("-R=anchor apple generic and certificate leaf[subject.OU] = \"{TEAM_ID}\"");
    run_bounded(
        "/usr/bin/codesign",
        &[
            "--verify".as_ref(),
            "--strict".as_ref(),
            requirement.as_ref(),
            app.as_os_str(),
        ],
        TOOL_WAIT,
    )
    .is_some_and(|(status, _)| status.success())
}

/// Run an absolute program with no shell, stdin closed, and a bounded wait.
/// `None` when it could not be started or did not finish in time (it is killed).
#[cfg(target_os = "macos")]
fn run_bounded(
    program: &str,
    args: &[&std::ffi::OsStr],
    wait: std::time::Duration,
) -> Option<(std::process::ExitStatus, Vec<u8>)> {
    use std::io::Read;
    use std::process::{Command, Stdio};
    use std::time::Instant;

    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if started.elapsed() < wait => {
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
            Err(_) => return None,
        }
    };
    let mut stdout = Vec::new();
    if let Some(mut pipe) = child.stdout.take() {
        let _ = pipe.read_to_end(&mut stdout);
    }
    Some((status, stdout))
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::*;
    use crate::privilege::contract::APP_BUNDLE_ID;

    fn facts(bundle_id: Option<&str>, team_ok: bool) -> AppFacts {
        AppFacts {
            is_dir: true,
            bundle_id: bundle_id.map(str::to_string),
            team_ok,
        }
    }

    fn good() -> AppFacts {
        facts(Some(APP_BUNDLE_ID), true)
    }

    #[test]
    fn bundle_of_exe_both_cases() {
        assert_eq!(
            bundle_of_exe(Path::new(
                "/Applications/Aitmproxy.app/Contents/Resources/core/aitm"
            )),
            Some(PathBuf::from("/Applications/Aitmproxy.app"))
        );
        assert_eq!(bundle_of_exe(Path::new("/opt/homebrew/bin/aitm")), None);
        // The right tail under something that is not a bundle is not a bundle.
        assert_eq!(
            bundle_of_exe(Path::new("/opt/Aitmproxy/Contents/Resources/core/aitm")),
            None
        );
    }

    #[test]
    fn temp_paths_are_refused_before_anything_else() {
        for path in [
            "/tmp/Aitmproxy-dev.app",
            "/private/tmp/Aitmproxy-dev.app",
            "/var/folders/xy/abc123/T/A.app",
            "/private/var/folders/xy/abc123/T/A.app",
        ] {
            assert_eq!(
                validate_handoff_app(Path::new(path), &good()),
                Err(HandoffRefusal::TempPath),
                "{path}"
            );
        }
        // Only the directory prefix counts, not a string prefix.
        assert_eq!(
            validate_handoff_app(Path::new("/tmpfs/Aitmproxy.app"), &good()),
            Ok(())
        );
    }

    #[test]
    fn non_app_and_missing_are_refused() {
        assert_eq!(
            validate_handoff_app(Path::new("/Applications/Aitmproxy"), &good()),
            Err(HandoffRefusal::NotAnApp)
        );
        assert_eq!(
            validate_handoff_app(
                Path::new("/Applications/Aitmproxy.app"),
                &AppFacts {
                    is_dir: false,
                    ..good()
                }
            ),
            Err(HandoffRefusal::Missing)
        );
    }

    #[test]
    fn wrong_bundle_id_is_named() {
        assert_eq!(
            validate_handoff_app(
                Path::new("/Applications/Aitmproxy.app"),
                &facts(Some("com.example"), true)
            ),
            Err(HandoffRefusal::WrongBundleId("com.example".to_string()))
        );
        // No readable bundle id at all is reported as an empty wrong id.
        assert_eq!(
            validate_handoff_app(Path::new("/Applications/Aitmproxy.app"), &facts(None, true)),
            Err(HandoffRefusal::WrongBundleId(String::new()))
        );
    }

    #[test]
    fn bad_team_is_bad_signature() {
        assert_eq!(
            validate_handoff_app(
                Path::new("/Applications/Aitmproxy.app"),
                &facts(Some(APP_BUNDLE_ID), false)
            ),
            Err(HandoffRefusal::BadSignature)
        );
    }

    #[test]
    fn installed_app_is_ok() {
        assert_eq!(
            validate_handoff_app(Path::new("/Applications/Aitmproxy.app"), &good()),
            Ok(())
        );
    }

    #[test]
    fn handoff_target_prefers_the_running_bundle() {
        let configured = Path::new("/Applications/Aitmproxy.app");
        assert_eq!(
            handoff_target(
                Some(Path::new("/Users/u/Dev.app/Contents/Resources/core/aitm")),
                configured
            ),
            PathBuf::from("/Users/u/Dev.app")
        );
        assert_eq!(
            handoff_target(Some(Path::new("/opt/homebrew/bin/aitm")), configured),
            PathBuf::from("/Applications/Aitmproxy.app")
        );
        assert_eq!(
            handoff_target(None, configured),
            PathBuf::from("/Applications/Aitmproxy.app")
        );
    }

    // ---- fix task 2026-11-01: S3 (facts cache key), S4 (canonical path first) ----

    /// S3, as amended by panel 2 (C7): the facts cache is keyed on the
    /// bundle's identity and contents, not the directory's own mtime:
    /// `(dev, ino)` of the bundle, the mtime **and size** of
    /// `Contents/Info.plist` (panel 3, D9) and of the main executable
    /// (`Contents/MacOS/Aitmproxy`), falling back to
    /// `Contents/_CodeSignature/CodeResources` when there is none. Any change
    /// of any part is a new key; a part overwritten in place (same directory,
    /// same inode) is seen through its own stamp.
    #[test]
    fn bundle_stamp_keys_on_identity_plist_and_executable() {
        use std::time::{Duration, UNIX_EPOCH};
        let t = |s: u64| UNIX_EPOCH + Duration::from_secs(s);
        let stamp = |s: u64, size: u64| Some(FileStamp { mtime: t(s), size });

        let base = BundleStamp::new(5, 100, stamp(10, 1_234), stamp(20, 4_096));
        assert_eq!(
            base,
            BundleStamp::new(5, 100, stamp(10, 1_234), stamp(20, 4_096))
        );
        assert_ne!(
            base,
            BundleStamp::new(6, 100, stamp(10, 1_234), stamp(20, 4_096)),
            "device"
        );
        assert_ne!(
            base,
            BundleStamp::new(5, 101, stamp(10, 1_234), stamp(20, 4_096)),
            "inode"
        );
        assert_ne!(
            base,
            BundleStamp::new(5, 100, stamp(11, 1_234), stamp(20, 4_096)),
            "Info.plist mtime"
        );
        assert_ne!(
            base,
            BundleStamp::new(5, 100, stamp(10, 1_235), stamp(20, 4_096)),
            "Info.plist size"
        );
        assert_ne!(
            base,
            BundleStamp::new(5, 100, stamp(10, 1_234), stamp(21, 4_096)),
            "executable mtime"
        );
        assert_ne!(
            base,
            BundleStamp::new(5, 100, stamp(10, 1_234), stamp(20, 4_097)),
            "executable size"
        );
        assert_ne!(
            base,
            BundleStamp::new(5, 100, None, stamp(20, 4_096)),
            "no plist at all is a different key from any plist"
        );
        assert_ne!(
            base,
            BundleStamp::new(5, 100, stamp(10, 1_234), None),
            "no executable at all is a different key from any executable"
        );

        // The executable stamp: the main executable when it exists, else the
        // code signature's resource list, else nothing.
        assert_eq!(
            executable_stamp(stamp(20, 4_096), stamp(30, 512)),
            stamp(20, 4_096)
        );
        assert_eq!(executable_stamp(None, stamp(30, 512)), stamp(30, 512));
        assert_eq!(executable_stamp(None, None), None);
        assert_eq!(APP_EXECUTABLE_REL, "Contents/MacOS/Aitmproxy");
        assert_eq!(CODE_RESOURCES_REL, "Contents/_CodeSignature/CodeResources");
    }

    /// `FileStamp::of` reads mtime and size off real metadata, and
    /// `file_stamp` is `None` for a missing path.
    #[test]
    fn file_stamp_reads_mtime_and_size() {
        let dir = std::env::temp_dir().join(format!("aitm-file-stamp-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let exe = dir.join("Aitmproxy");
        std::fs::write(&exe, b"#!/bin/sh\n").expect("write");
        let stamp = file_stamp(&exe).expect("a stamp for an existing file");
        assert_eq!(stamp.size, 10);
        assert_eq!(
            stamp.mtime,
            std::fs::metadata(&exe)
                .and_then(|m| m.modified())
                .expect("mtime")
        );
        assert_eq!(file_stamp(&dir.join("missing")), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// S4: the handoff app's path is canonicalized before anything is
    /// checked; a path that cannot be canonicalized is `Missing`, and the
    /// temporary-tree refusal applies to the canonical path (so a symlink or
    /// `/var` spelling into a temp tree is still refused) before any facts
    /// are gathered about it. The bundle is built under a member of
    /// `TEMP_PREFIXES` (the process's temp dir, which canonicalizes into
    /// `/private/var/folders` or `/private/tmp` on macOS and `/tmp` on
    /// Linux), so the outcome here is `TempPath` only; the outside-a-temp-tree
    /// case is the pure literal call below.
    #[test]
    fn handoff_path_is_canonicalized_before_the_checks() {
        assert_eq!(
            canonicalize_or_missing(Path::new("/nonexistent/Aitmproxy.app")),
            Err(HandoffRefusal::Missing)
        );

        let dir = std::env::temp_dir().join(format!("aitm-s4-{}", std::process::id()));
        let app = dir.join("Aitmproxy.app");
        std::fs::create_dir_all(&app).expect("temp app dir");
        let canonical = canonicalize_or_missing(&app).expect("canonical");
        assert!(canonical.is_absolute());
        assert!(
            TEMP_PREFIXES
                .iter()
                .any(|prefix| canonical.starts_with(prefix)),
            "this test builds its bundle inside a TEMP_PREFIXES member; the temp dir \
             canonicalizes to {canonical:?}"
        );
        let facts_asked = std::cell::Cell::new(false);
        let result = validated_handoff(&app, |_| {
            facts_asked.set(true);
            good()
        });
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(result, Err(HandoffRefusal::TempPath), "{canonical:?}");
        assert!(!facts_asked.get(), "refused before any facts were gathered");

        // Outside every temporary tree (pure, literal): good facts pass.
        assert_eq!(
            validate_handoff_app(Path::new("/Applications/Aitmproxy.app"), &good()),
            Ok(())
        );

        // The pure check on a canonical spelling into a temp tree.
        assert_eq!(
            validate_handoff_app(Path::new("/private/tmp/Aitmproxy.app"), &good()),
            Err(HandoffRefusal::TempPath)
        );
        assert_eq!(
            validated_handoff(Path::new("/nonexistent/Aitmproxy.app"), |_| good()),
            Err(HandoffRefusal::Missing)
        );
    }
}
