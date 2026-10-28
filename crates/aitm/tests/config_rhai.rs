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
