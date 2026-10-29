//! M3 Task 15: the `scripts:` and `rhai:` config sections (spec OQ8).
//!
//! The M2 config file owns `aitm_core::Config`; the scripting tier's settings
//! are a second, additive product of the same file, so one parse yields both
//! and a misspelled scripting knob is an error exactly like a misspelled
//! browser one. Declaration order in `scripts:` is chain order (spec §8), so
//! these tests pin the order the list is read in, not just its contents.

use std::path::PathBuf;
use std::time::Duration;

use aitm::config_file::{parse_settings, Settings};
use aitm_core::Value;

fn settings(yaml: &str) -> Settings {
    parse_settings(yaml).expect("the config parses")
}

/// The whole scripting section, read off the file the operator writes.
#[test]
fn scripts_and_rhai_sections_parse() {
    let s = settings(
        r#"
listen: "127.0.0.1:8080"
scripts:
  - path: addons/tagger.rhai
    options:
      tag: seen-by-aitm
      retries: 3
  - path: addons/guard-admin-writes.rhai
  - path: addons/parked.rhai
    enabled: false
rhai:
  strict: true
  allow_scope_add: true
  hook_timeout: 5
  max_operations: 500000
  max_string_size: 4096
"#,
    );

    let paths: Vec<&PathBuf> = s.rhai.scripts.iter().map(|e| &e.path).collect();
    assert_eq!(
        paths,
        [
            &PathBuf::from("addons/tagger.rhai"),
            &PathBuf::from("addons/guard-admin-writes.rhai"),
            &PathBuf::from("addons/parked.rhai"),
        ],
        "declaration order is preserved — it is the chain order",
    );

    let tagger = &s.rhai.scripts[0];
    assert_eq!(
        tagger.options.get("tag"),
        Some(&Value::Str("seen-by-aitm".into())),
    );
    assert_eq!(tagger.options.get("retries"), Some(&Value::Int(3)));
    assert!(
        tagger.enabled,
        "an entry is enabled unless it says otherwise"
    );
    assert!(s.rhai.scripts[1].options.is_empty());
    assert!(!s.rhai.scripts[2].enabled, "enabled: false is honoured");

    assert!(s.rhai.strict);
    assert!(
        s.rhai.allow_scope_add,
        "the operator opted plugin scripts into scope.add"
    );
    assert_eq!(s.rhai.hook_timeout, Duration::from_secs(5));
    assert_eq!(s.rhai.limits.max_operations, 500_000);
    assert_eq!(s.rhai.limits.max_string_size, 4096);
    assert_eq!(
        s.rhai.limits.max_array_size,
        aitm_plugin_rhai::RhaiLimits::default().max_array_size,
        "a limit the file does not set keeps its default",
    );

    // The M2 config is unaffected by the new sections.
    assert_eq!(s.core.listen.to_string(), "127.0.0.1:8080");
}

/// A file with no scripting sections is the M1/M2 file, unchanged: no scripts
/// and the shipped defaults.
#[test]
fn absent_sections_keep_defaults() {
    let s = settings("listen: \"127.0.0.1:9000\"\n");
    assert!(s.rhai.scripts.is_empty());
    assert!(!s.rhai.strict);
    assert!(
        !s.rhai.allow_scope_add,
        "scripts may not widen the scope unless the operator says so"
    );
    assert_eq!(s.rhai.hook_timeout, Duration::from_secs(2));
    assert_eq!(
        s.rhai.limits,
        aitm_plugin_rhai::RhaiLimits::default(),
        "untouched limits are the crate's defaults",
    );
}

/// `deny_unknown_fields` reaches the new sections too: a typo is refused, not
/// silently ignored (the M2 config's rule).
#[test]
fn a_misspelled_scripting_knob_is_refused() {
    let err = parse_settings("rhai:\n  max_oprations: 10\n").expect_err("a typo must be refused");
    assert!(
        err.to_string().contains("max_oprations")
            || err.chain().any(|c| c.to_string().contains("max_oprations")),
        "the error should name the bad key, got: {err:#}",
    );

    let err = parse_settings("scripts:\n  - path: a.rhai\n    optoins: {}\n")
        .expect_err("a typo refused");
    assert!(
        err.to_string().contains("optoins")
            || err.chain().any(|c| c.to_string().contains("optoins")),
        "the error should name the bad key, got: {err:#}",
    );
}

/// The env bridge: `AITM_SCRIPTS` appends declarations after the file's (so a
/// one-off script joins the end of the chain) and `AITM_SCRIPTS_STRICT` flips
/// the compile-error policy for CI.
#[test]
fn env_appends_scripts_and_sets_strict() {
    let mut s = settings("scripts:\n  - path: from-file.rhai\n");
    aitm::env::apply_rhai(&mut s.rhai, |k| match k {
        "AITM_SCRIPTS" => Some("one.rhai:two.rhai".to_string()),
        "AITM_SCRIPTS_STRICT" => Some("1".to_string()),
        _ => None,
    });

    let paths: Vec<&PathBuf> = s.rhai.scripts.iter().map(|e| &e.path).collect();
    assert_eq!(
        paths,
        [
            &PathBuf::from("from-file.rhai"),
            &PathBuf::from("one.rhai"),
            &PathBuf::from("two.rhai"),
        ],
        "env entries follow the file's, in the order written",
    );
    assert!(s.rhai.strict);
}

/// An unset environment leaves the file's answer alone.
#[test]
fn env_absent_changes_nothing() {
    let mut s = settings("rhai:\n  strict: true\n");
    aitm::env::apply_rhai(&mut s.rhai, |_| None);
    assert!(s.rhai.strict);
    assert!(s.rhai.scripts.is_empty());
}

/// A scratch directory removed on drop.
struct ScratchDir(PathBuf);

impl ScratchDir {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "aitm-config-rhai-{tag}-{}-{}",
            std::process::id(),
            aitm_core::FlowId::new()
        ));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        Self(dir)
    }

    fn touch(&self, file: &str) -> PathBuf {
        let path = self.0.join(file);
        std::fs::write(&path, "fn on_request(flow) { }\n").expect("write");
        path
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// F8b: `rhai.scripts_dir` is read off the file; absent, it stays unset.
#[test]
fn scripts_dir_is_read_from_the_rhai_section() {
    let s = settings("rhai:\n  scripts_dir: /var/aitm/scripts\n");
    assert_eq!(
        s.rhai.scripts_dir,
        Some(PathBuf::from("/var/aitm/scripts")),
        "a `rhai.scripts_dir` key reaches RhaiConfig"
    );
    assert_eq!(settings("rhai:\n  strict: true\n").rhai.scripts_dir, None);
    assert_eq!(
        settings("listen: \"127.0.0.1:8080\"\n").rhai.scripts_dir,
        None
    );
}

/// F8b persistence seam: every `*.rhai` in `scripts_dir` becomes an enabled
/// entry after the declared ones, so a script `script.save` wrote loads on the
/// next start. Other files are ignored.
#[test]
fn scripts_dir_files_are_appended_as_enabled_entries() {
    let dir = ScratchDir::new("scan");
    let a = dir.touch("alpha.rhai");
    let b = dir.touch("beta.rhai");
    dir.touch("notes.txt");
    dir.touch(".hidden.tmp");
    std::fs::create_dir(dir.0.join("sub.rhai")).expect("a directory named like a script");

    let s = settings(&format!(
        "scripts:\n  - path: declared.rhai\nrhai:\n  scripts_dir: {}\n",
        dir.0.display()
    ));

    let paths: Vec<PathBuf> = s.rhai.scripts.iter().map(|e| e.path.clone()).collect();
    assert_eq!(
        paths,
        [PathBuf::from("declared.rhai"), a, b],
        "declared entries first, then the directory's scripts in name order"
    );
    assert!(s.rhai.scripts.iter().all(|e| e.enabled));
    assert!(s.rhai.scripts[1].options.is_empty());
}

/// A script already declared in `scripts:` — even by a different spelling of
/// the same file — is not loaded twice, and keeps its declared options and
/// enabled flag (a declared `enabled: false` stays off).
#[test]
fn scripts_dir_scan_does_not_duplicate_a_declared_script() {
    let dir = ScratchDir::new("dedupe");
    let declared = dir.touch("declared.rhai");
    let parked = dir.touch("parked.rhai");
    let extra = dir.touch("extra.rhai");
    // The same file as `declared`, spelled through a `..` detour.
    let detour = dir
        .0
        .join("..")
        .join(dir.0.file_name().expect("name"))
        .join("declared.rhai");

    let s = settings(&format!(
        "scripts:\n  - path: {}\n    options:\n      tag: x\n  - path: {}\n    enabled: false\nrhai:\n  scripts_dir: {}\n",
        detour.display(),
        parked.display(),
        dir.0.display()
    ));

    assert_eq!(s.rhai.scripts.len(), 3, "{:?}", s.rhai.scripts);
    assert_eq!(s.rhai.scripts[0].path, detour);
    assert_eq!(
        s.rhai.scripts[0].options.get("tag"),
        Some(&Value::Str("x".into())),
        "the declared entry keeps its options"
    );
    assert!(
        !s.rhai.scripts[1].enabled,
        "a declared enabled: false stays off"
    );
    assert_eq!(s.rhai.scripts[2].path, extra);
    assert!(!s.rhai.scripts.iter().any(|e| e.path == declared));
}

/// A missing or unreadable `scripts_dir` loads nothing extra and is not fatal.
#[test]
fn a_missing_scripts_dir_adds_no_entries_and_is_not_fatal() {
    let s = settings("rhai:\n  scripts_dir: /nonexistent/aitm/scripts-dir\n");
    assert!(s.rhai.scripts.is_empty());
    assert_eq!(
        s.rhai.scripts_dir,
        Some(PathBuf::from("/nonexistent/aitm/scripts-dir")),
        "the dir stays configured so script.save can create it"
    );
}
