//! The detection catalogue aitmproxy ships with (`scripts/bundled/`).
//!
//! These are first-party Rhai scripts — passive OWASP/vulnerability detectors
//! for HTTP, HTTPS and WebSocket plus operator-invoked active and L4 checks —
//! installed beside the binary and loaded by default, so a fresh install flags
//! common findings on in-scope traffic with no setup.
//!
//! **Posture.** The passive detectors are observe-only: they read a flow, mark
//! it and record findings; they send no traffic and mutate nothing, so loading
//! them by default does not change deny-by-default. The active/L4 scripts only
//! register operator commands (`check.*`, `l4.*`) that must be invoked and are
//! scope- and rate-gated like any other host call; loading them arms no
//! automatic behaviour. `AITM_NO_BUNDLED_SCRIPTS` turns the whole catalogue off.
//!
//! Discovery mirrors the obscura engine's: an explicit `AITM_BUNDLED_SCRIPTS`
//! override, then a `share/aitm/scripts` directory beside the executable (and
//! one level up, for a `bin/` + `share/` install layout), then a dev checkout
//! fallback. The directory is walked recursively; declared `scripts:` entries
//! win over a bundled file of the same canonical path, so an operator can
//! re-declare one with custom options or disable it.

use std::path::{Path, PathBuf};

use aitm_plugin_rhai::{RhaiConfig, ScriptEntry};

/// Point discovery at a specific catalogue directory (wins over the probed
/// candidates). Set it empty or to a missing path to effectively ship none.
pub const BUNDLED_DIR: &str = "AITM_BUNDLED_SCRIPTS";

/// Truthy (`1`/`true`/`yes`) ⇒ load no bundled scripts at all.
pub const NO_BUNDLED: &str = "AITM_NO_BUNDLED_SCRIPTS";

fn is_truthy(raw: &str) -> bool {
    matches!(
        raw.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes"
    )
}

/// The catalogue directory to load from, or `None` when disabled or not found.
/// `exe` is the current executable (canonicalized by the caller where possible);
/// `lookup` reads the environment (injected so tests never touch the process).
pub fn discover_dir(
    exe: Option<&Path>,
    lookup: impl Fn(&str) -> Option<String>,
) -> Option<PathBuf> {
    if lookup(NO_BUNDLED).as_deref().is_some_and(is_truthy) {
        return None;
    }
    if let Some(raw) = lookup(BUNDLED_DIR) {
        let p = PathBuf::from(raw);
        return p.is_dir().then_some(p);
    }
    let exe_dir = exe.and_then(Path::parent);
    candidates(exe_dir).into_iter().find(|c| c.is_dir())
}

/// Where a `share/aitm/scripts` catalogue sits relative to the executable, plus
/// a dev-checkout fallback (`<target>/<profile>/aitm` → `scripts/bundled`).
fn candidates(exe_dir: Option<&Path>) -> Vec<PathBuf> {
    let Some(dir) = exe_dir else {
        return Vec::new();
    };
    vec![
        // Beside the binary (macOS tarball layout, and the Linux lib dir).
        dir.join("share").join("aitm").join("scripts"),
        // `bin/` + `share/` sibling layout (one level up).
        dir.join("..").join("share").join("aitm").join("scripts"),
        // `/usr/lib/aitmproxy/aitm` -> `/usr/share/aitm/scripts` (two up).
        dir.join("..")
            .join("..")
            .join("share")
            .join("aitm")
            .join("scripts"),
        // Dev checkout: `target/<profile>/aitm` -> repo `scripts/bundled`.
        dir.join("..").join("..").join("scripts").join("bundled"),
    ]
}

/// Append every `*.rhai` under `dir` (recursively, name-sorted) to `cfg.scripts`
/// as an enabled entry, skipping any a declared entry already names (compared
/// canonicalized, so the operator's entry and its options win). A missing or
/// unreadable directory appends nothing.
pub fn append(cfg: &mut RhaiConfig, dir: &Path) {
    let mut found = Vec::new();
    collect_rhai(dir, &mut found);
    found.sort();
    append_undeclared(cfg, found);
}

/// Append each path in `found` (already name-sorted) to `cfg.scripts` as an
/// enabled entry, skipping any a declared entry already names. Paths are
/// compared canonicalized, so `./a.rhai` and an absolute spelling are one
/// script and the declared entry's options/`enabled` win. Shared by the
/// bundled catalogue here and `config_file`'s `scripts_dir` scan, so the
/// dedup rule has one implementation.
pub fn append_undeclared(cfg: &mut RhaiConfig, found: Vec<PathBuf>) {
    let canon = |p: &Path| p.canonicalize().unwrap_or_else(|_| p.to_path_buf());
    let mut declared: Vec<PathBuf> = cfg.scripts.iter().map(|e| canon(&e.path)).collect();
    for path in found {
        let resolved = canon(&path);
        if declared.contains(&resolved) {
            continue;
        }
        declared.push(resolved);
        cfg.scripts.push(ScriptEntry::new(path));
    }
}

fn collect_rhai(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(read) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in read.flatten() {
        let Ok(ty) = entry.file_type() else { continue };
        let path = entry.path();
        if ty.is_dir() {
            collect_rhai(&path, out);
        } else if ty.is_file() && path.extension().and_then(|e| e.to_str()) == Some("rhai") {
            out.push(path);
        }
    }
}

/// Discover and append the bundled catalogue onto `cfg`, honouring the env
/// opt-out/override. Called at startup after the config file and `AITM_SCRIPTS`.
pub fn apply(cfg: &mut RhaiConfig, lookup: impl Fn(&str) -> Option<String>) {
    let exe = std::env::current_exe()
        .ok()
        .map(|e| std::fs::canonicalize(&e).unwrap_or(e));
    if let Some(dir) = discover_dir(exe.as_deref(), &lookup) {
        append(cfg, &dir);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A unique scratch directory under the system temp dir, removed on drop.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(tag: &str) -> Self {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let dir = std::env::temp_dir().join(format!("aitm-bundled-{tag}-{nanos}"));
            std::fs::create_dir_all(&dir).unwrap();
            Scratch(dir)
        }
        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn write(dir: &Path, rel: &str, body: &str) {
        let path = dir.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, body).unwrap();
    }

    #[test]
    fn discover_honours_override_and_opt_out() {
        let tmp = Scratch::new("discover");
        let dir = tmp.path();
        write(dir, "http/a.rhai", "// a");

        let dir_s = dir.to_str().unwrap().to_string();
        let override_only = {
            let dir_s = dir_s.clone();
            move |k: &str| (k == BUNDLED_DIR).then(|| dir_s.clone())
        };
        let found = discover_dir(None, override_only);
        assert_eq!(found.as_deref(), Some(dir));

        // Opt-out wins even with an override set.
        let both = move |k: &str| match k {
            NO_BUNDLED => Some("1".to_string()),
            BUNDLED_DIR => Some(dir_s.clone()),
            _ => None,
        };
        assert_eq!(discover_dir(None, both), None);
    }

    #[test]
    fn append_walks_recursively_and_dedups_declared() {
        let tmp = Scratch::new("append");
        let dir = tmp.path();
        write(dir, "http/a.rhai", "// a");
        write(dir, "http/b.rhai", "// b");
        write(dir, "ws/c.rhai", "// c");
        write(dir, "notes.txt", "ignored");

        let mut cfg = RhaiConfig::default();
        cfg.scripts.push(ScriptEntry::new(dir.join("http/a.rhai")));
        append(&mut cfg, dir);

        let paths: Vec<String> = cfg
            .scripts
            .iter()
            .map(|e| e.path.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(paths.iter().filter(|p| p.as_str() == "a.rhai").count(), 1);
        assert!(paths.contains(&"b.rhai".to_string()));
        assert!(paths.contains(&"c.rhai".to_string()));
        assert!(!paths.contains(&"notes.txt".to_string()));
    }
}
