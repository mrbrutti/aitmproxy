//! macOS gatherer: the inputs of the spec §2.2 macOS table and the §2.3 handoff
//! validation.
//!
//! The decisions live in pure functions ([`bundle_of_exe`], [`handoff_target`],
//! [`validate_handoff_app`]) that compile and are tested on every OS. The I/O
//! ([`app_facts`], [`gather_mac`]) only reads: it opens `/dev/bpf*`, reads the
//! receipt, and asks `plutil` and `codesign` about a bundle. It never changes
//! system state and never runs a shell.

use std::path::{Path, PathBuf};

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

/// Validate a handoff app against the facts gathered about it. Pure: the path
/// shape is checked first (temporary tree, `.app` suffix), then the facts
/// (exists, bundle id, signature), so a path we would never use is refused
/// before anything about it is trusted.
pub fn validate_handoff_app(path: &Path, facts: &AppFacts) -> Result<(), HandoffRefusal> {
    if TEMP_PREFIXES.iter().any(|prefix| path.starts_with(prefix)) {
        return Err(HandoffRefusal::TempPath);
    }
    if !is_app_bundle_path(path) {
        return Err(HandoffRefusal::NotAnApp);
    }
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
    let handoff_app_embeds_helper = validate_handoff_app(&app, &app_facts(&app)).is_ok()
        && app.join(HELPER_PLIST_REL).is_file();
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

/// Ask macOS about a bundle: its `CFBundleIdentifier` via `plutil`, and whether
/// `codesign --verify --strict` accepts it under a requirement pinning the
/// project's team. Both are absolute program paths with a bounded wait and no
/// shell. Results are cached by `(path, mtime)` so the signature check does not
/// run on every re-probe **(Architect's call)**.
#[cfg(target_os = "macos")]
fn app_facts(path: &Path) -> AppFacts {
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};
    use std::time::SystemTime;

    static CACHE: OnceLock<Mutex<HashMap<PathBuf, (SystemTime, AppFacts)>>> = OnceLock::new();

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
    let mtime = meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);

    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Ok(map) = cache.lock() {
        if let Some((seen, facts)) = map.get(path) {
            if *seen == mtime {
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
    map.insert(path.to_path_buf(), (mtime, facts.clone()));
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
}
