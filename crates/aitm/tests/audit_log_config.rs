//! The durable audit log's configuration (AC1, AC2): the `mcp.audit_log` config
//! key and the `AITM_AUDIT_LOG` environment override.
//!
//! The key accepts `true`, `false`, `off` (any case) and an absolute path; every
//! other value is a config error naming `mcp.audit_log` and "absolute". The
//! environment wins over the file, but an unparseable `AITM_AUDIT_LOG` leaves the
//! file's setting exactly as it was (and says so with one warning): for an audit
//! control the fail-safe direction is "stay on", so a typo must not disable the
//! trail. Paths are Unix literals; the repo's CI is Unix.
//!
//! `stream_paths_follow_the_rule` (AC3): the three stream files are derived from
//! the one configured base path.
//!
//! `a_stream_path_equal_to_the_ca_log_is_refused` (AC4) and
//! `a_ca_log_that_is_a_stream_file_in_another_spelling_is_refused`: `start`
//! refuses a configuration in which a stream file, or a file a stream rotates to,
//! would be the CA audit log, however its path is spelled.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use aitm::audit_log::{self, stream_path, StreamKind};
use aitm::config_file::parse;
use aitm::env;
use aitm_core::{AuditLogSetting, AuditRing, CaConfig, Config};
use tracing_subscriber::fmt::MakeWriter;

/// The `mcp.audit_log` the file parser produced, or the whole error chain.
fn parsed(yaml: &str) -> Result<AuditLogSetting, String> {
    parse(yaml)
        .map(|cfg| cfg.mcp.audit_log)
        .map_err(|err| format!("{err:#}"))
}

/// AC1: every documented spelling of the key, and every refusal.
#[test]
fn audit_log_key_parses_every_spelling() {
    let abs = "/var/log/aitm/audit.jsonl";
    let accepted: Vec<(String, AuditLogSetting)> = vec![
        // The key is absent: from a file with no `mcp` section and from one with.
        ("listen: 127.0.0.1:8080\n".into(), AuditLogSetting::Default),
        (
            "mcp:\n  stdio_role: agent\n".into(),
            AuditLogSetting::Default,
        ),
        // `true` is the default; `false`, `off` and `OFF` turn the file off.
        ("mcp:\n  audit_log: true\n".into(), AuditLogSetting::Default),
        ("mcp:\n  audit_log: false\n".into(), AuditLogSetting::Off),
        ("mcp:\n  audit_log: off\n".into(), AuditLogSetting::Off),
        ("mcp:\n  audit_log: OFF\n".into(), AuditLogSetting::Off),
        ("mcp:\n  audit_log: \"Off\"\n".into(), AuditLogSetting::Off),
        // An absolute path names the control stream file.
        (
            format!("mcp:\n  audit_log: {abs}\n"),
            AuditLogSetting::Path(PathBuf::from(abs)),
        ),
    ];
    let refused = [
        "mcp:\n  audit_log: audit.jsonl\n",
        "mcp:\n  audit_log: ~/audit.jsonl\n",
        "mcp:\n  audit_log: \"\"\n",
        "mcp:\n  audit_log: 5\n",
        "mcp:\n  audit_log: [a, b]\n",
    ];

    let mut failures: Vec<String> = Vec::new();
    for (yaml, want) in &accepted {
        match parsed(yaml) {
            Ok(got) if got == *want => {}
            other => failures.push(format!("{yaml:?}: left: {other:?}, right: Ok({want:?})")),
        }
    }
    for yaml in refused {
        match parsed(yaml) {
            Err(text) if text.contains("mcp.audit_log") && text.contains("absolute") => {}
            other => failures.push(format!(
                "{yaml:?}: left: {other:?}, right: an error naming `mcp.audit_log` and `absolute`"
            )),
        }
    }
    // A misspelled sibling is still an unknown field, not a silently kept default.
    match parsed("mcp:\n  audit_logg: off\n") {
        Err(text) if text.contains("unknown field") && text.contains("audit_logg") => {}
        other => failures.push(format!(
            "`mcp.audit_logg`: left: {other:?}, right: an unknown-field error"
        )),
    }

    assert!(
        failures.is_empty(),
        "{} row(s) failed:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// An in-memory `tracing` sink, so a test can read what `env::apply` logged.
#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Capture {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().expect("capture lock")).into_owned()
    }
}

impl io::Write for Capture {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().expect("capture lock").extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for Capture {
    type Writer = Capture;

    fn make_writer(&'a self) -> Capture {
        self.clone()
    }
}

/// Apply `AITM_AUDIT_LOG=<value>` (or nothing, for `None`) over a config whose
/// file value is `file`; return the setting that results and everything the
/// call logged.
fn with_env(file: &AuditLogSetting, value: Option<&str>) -> (AuditLogSetting, String) {
    let mut cfg = Config::default();
    cfg.mcp.audit_log = file.clone();
    let capture = Capture::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(capture.clone())
        .with_ansi(false)
        .without_time()
        .finish();
    tracing::subscriber::with_default(subscriber, || {
        env::apply(&mut cfg, |key| {
            if key == "AITM_AUDIT_LOG" {
                value.map(str::to_string)
            } else {
                None
            }
        });
    });
    (cfg.mcp.audit_log, capture.text())
}

/// AC2: the environment wins; a value that means nothing leaves the file's
/// setting exactly as it was and says so once.
#[test]
fn audit_log_env_wins_and_never_silently_disables() {
    let starts = [
        AuditLogSetting::Default,
        AuditLogSetting::Off,
        AuditLogSetting::Path(PathBuf::from("/a/audit.jsonl")),
    ];
    let mut failures: Vec<String> = Vec::new();
    // `reason` is what the warning must say is wrong with the value, when it warns.
    let mut check = |start: &AuditLogSetting,
                     value: Option<&str>,
                     want: &AuditLogSetting,
                     reason: Option<&str>| {
        let (got, log) = with_env(start, value);
        let row = format!("file {start:?}, env {value:?}");
        if got != *want {
            failures.push(format!("{row}: left: {got:?}, right: {want:?}"));
        }
        let lines = log.lines().count();
        if let Some(reason) = reason {
            // One line, on the audit target, naming the variable and the reason
            // and never the value (so a newline in it cannot forge a line and a
            // secret pasted into it is not logged).
            for needle in ["AITM_AUDIT_LOG", reason, "aitm::audit", "WARN", "unchanged"] {
                if !log.contains(needle) {
                    failures.push(format!("{row}: the warning lacks {needle:?}: {log:?}"));
                }
            }
            if lines != 1 {
                failures.push(format!("{row}: {lines} log lines, want exactly 1: {log:?}"));
            }
        } else if !log.is_empty() {
            failures.push(format!("{row}: logged when it should not: {log:?}"));
        }
    };

    for start in &starts {
        // Off spellings, ASCII case-insensitive.
        for value in ["off", "false", "0", "no", "OFF"] {
            check(start, Some(value), &AuditLogSetting::Off, None);
        }
        // On spellings, ASCII case-insensitive.
        for value in ["on", "true", "1", "yes", "default", "True"] {
            check(start, Some(value), &AuditLogSetting::Default, None);
        }
        // An absolute path selects `Path`.
        check(
            start,
            Some("/tmp/x/a.jsonl"),
            &AuditLogSetting::Path(PathBuf::from("/tmp/x/a.jsonl")),
            None,
        );
        // Unset: the file's value survives.
        check(start, None, start, None);
        // Anything else leaves the file's setting exactly as it was: a typo, a
        // relative path, an empty string, a value that only looks like "off"
        // (the parse is not trimmed), a value with a newline in it. The warning
        // says which kind of wrong it is.
        let other = "not one of off/on/default or an absolute path";
        for (value, reason) in [
            ("ofd", other),
            ("relative.jsonl", other),
            ("~/audit.jsonl", "a relative path"),
            ("logs/audit.jsonl", "a relative path"),
            ("", "empty"),
            (" off", other),
            ("off ", other),
            ("a\nb", other),
        ] {
            check(start, Some(value), start, Some(reason));
        }
    }

    assert!(
        failures.is_empty(),
        "{} row(s) failed:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// AC3: the control stream is the configured base; the agent and reads streams
/// put `.agent` / `.reads` before the final extension (or append it when there
/// is none). The default path sits beside the CA audit log; `Off` has no path.
#[test]
fn stream_paths_follow_the_rule() {
    let rows = [
        (
            "/a/audit.jsonl",
            [
                "/a/audit.jsonl",
                "/a/audit.agent.jsonl",
                "/a/audit.reads.jsonl",
            ],
        ),
        ("/a/audit", ["/a/audit", "/a/audit.agent", "/a/audit.reads"]),
        // Extra row: only the final extension is split off.
        (
            "/a/audit.v2.jsonl",
            [
                "/a/audit.v2.jsonl",
                "/a/audit.v2.agent.jsonl",
                "/a/audit.v2.reads.jsonl",
            ],
        ),
    ];
    let mut failures: Vec<String> = Vec::new();
    for (base, want) in rows {
        let base = PathBuf::from(base);
        let got: Vec<PathBuf> = [StreamKind::Control, StreamKind::Agent, StreamKind::Reads]
            .into_iter()
            .map(|kind| stream_path(&base, kind))
            .collect();
        let want: Vec<PathBuf> = want.into_iter().map(PathBuf::from).collect();
        if got != want {
            failures.push(format!("{base:?}: left: {got:?}, right: {want:?}"));
        }
    }

    // `Default` is `audit.jsonl` in the directory the CA audit log lives in.
    match AuditLogSetting::Default.resolved_path() {
        Some(path) => {
            if path.file_name() != Some("audit.jsonl".as_ref()) {
                failures.push(format!("Default: {path:?} does not end in audit.jsonl"));
            }
            let ca_log = CaConfig::default().audit_log;
            if path.parent() != ca_log.parent() {
                failures.push(format!(
                    "Default: parent of {path:?} is not the parent of {ca_log:?}"
                ));
            }
        }
        None => failures.push("Default: resolved_path() is None".to_string()),
    }
    if let Some(path) = AuditLogSetting::Off.resolved_path() {
        failures.push(format!("Off: left: Some({path:?}), right: None"));
    }

    assert!(
        failures.is_empty(),
        "{} row(s) failed:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// A unique scratch directory under the system temp directory that removes
/// itself on drop (the crate has no `tempfile`). Unique per process, clock tick
/// and call.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Scratch {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "aitm-audit-config-{tag}-{}-{nanos}-{n}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("create the scratch directory");
        Scratch(dir)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    /// The names of everything directly inside the directory, sorted.
    fn names(&self) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(&self.0)
            .expect("read the scratch directory")
            .map(|entry| entry.expect("a directory entry").file_name())
            .map(|name| name.to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// AC4: the general audit and the CA audit are different logs with different
/// shapes and must never share a file. `start` refuses a configuration in which
/// any of the three stream files is `ca.audit_log`, says so by name, and creates
/// nothing; a different CA log is not a collision.
#[test]
fn a_stream_path_equal_to_the_ca_log_is_refused() {
    let dir = Scratch::new("ca-collision");
    let base = dir.path().join("audit.jsonl");
    let rows = [
        // The control stream is the base itself.
        ("the control stream", dir.path().join("audit.jsonl")),
        // A derived stream path collides the same way.
        ("the reads stream", dir.path().join("audit.reads.jsonl")),
        ("the agent stream", dir.path().join("audit.agent.jsonl")),
    ];

    let mut failures: Vec<String> = Vec::new();
    for (row, ca_log) in rows {
        let mut cfg = Config::default();
        cfg.mcp.audit_log = AuditLogSetting::Path(base.clone());
        cfg.ca.audit_log = ca_log.clone();
        let ring = Arc::new(AuditRing::new(16));
        match audit_log::start(&cfg, &ring, None, &[]) {
            Err(err) => {
                let text = format!("{err:#}");
                if !text.contains("ca.audit_log") {
                    failures.push(format!(
                        "{row}: the error does not name ca.audit_log: {text}"
                    ));
                }
                let shown = ca_log.display().to_string();
                if !text.contains(&shown) {
                    failures.push(format!("{row}: the error does not name {shown}: {text}"));
                }
            }
            Ok(other) => failures.push(format!(
                "{row}: left: Ok({other:?}), right: an error naming ca.audit_log"
            )),
        }
        let left = dir.names();
        if !left.is_empty() {
            failures.push(format!("{row}: left: {left:?}, right: no file created"));
        }
        if ring.durable_status().is_some() {
            failures.push(format!("{row}: a sink was attached to the ring"));
        }
    }

    // The other side of the check: a CA log that is none of the three paths
    // starts normally (so an `start` that always refused would not pass).
    let mut cfg = Config::default();
    cfg.mcp.audit_log = AuditLogSetting::Path(base.clone());
    cfg.ca.audit_log = dir.path().join("ca-audit.jsonl");
    let ring = Arc::new(AuditRing::new(16));
    match audit_log::start(&cfg, &ring, None, &[]) {
        Ok(Some(handle)) => {
            let report = handle.shutdown(std::time::Duration::from_secs(5));
            if !report.complete {
                failures.push(format!(
                    "a distinct CA log: the flush did not finish: {report:?}"
                ));
            }
            if !base.is_file() {
                failures.push("a distinct CA log: the control file was not created".to_string());
            }
        }
        other => failures.push(format!(
            "a distinct CA log: left: {other:?}, right: Ok(Some(handle))"
        )),
    }

    assert!(
        failures.is_empty(),
        "{} row(s) failed:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// `start` against `ca_log` with the stream base `<dir>/audit.jsonl`: the error
/// text when it refuses, or why the answer is not a refusal.
fn start_against(dir: &Scratch, ca_log: PathBuf) -> Result<String, String> {
    let mut cfg = Config::default();
    cfg.mcp.audit_log = AuditLogSetting::Path(dir.path().join("audit.jsonl"));
    cfg.ca.audit_log = ca_log;
    let ring = Arc::new(AuditRing::new(16));
    match audit_log::start(&cfg, &ring, None, &[]) {
        Err(err) => Ok(format!("{err:#}")),
        Ok(Some(handle)) => {
            let _ = handle.shutdown(std::time::Duration::from_secs(5));
            Err("started".to_string())
        }
        Ok(None) => Err("returned no handle".to_string()),
    }
}

/// The CA audit log is the same file as a stream file however its path is
/// spelled: through `..` (the directory it goes through present or not), through
/// a symbolic link to the directory, or as the file a stream rotates its own to
/// (`audit.jsonl.4`, `audit.agent.jsonl.5`, `audit.reads.jsonl.2`: the rotated
/// files each stream keeps, 4, 5 and 2). Each is refused by name, nothing is
/// created, and the names just past what a stream keeps are not a collision.
#[test]
fn a_ca_log_that_is_a_stream_file_in_another_spelling_is_refused() {
    let mut failures: Vec<String> = Vec::new();
    let mut refused = |row: &str, setup: &dyn Fn(&Scratch) -> PathBuf, want_left: &[&str]| {
        let dir = Scratch::new("ca-spelling");
        let ca_log = setup(&dir);
        match start_against(&dir, ca_log.clone()) {
            Ok(text) => {
                if !text.contains("ca.audit_log") {
                    failures.push(format!(
                        "{row}: the error does not name ca.audit_log: {text}"
                    ));
                }
                let shown = ca_log.display().to_string();
                if !text.contains(&shown) {
                    failures.push(format!("{row}: the error does not name {shown}: {text}"));
                }
            }
            Err(why) => failures.push(format!(
                "{row}: left: {why}, right: an error naming ca.audit_log"
            )),
        }
        if dir.names() != want_left {
            failures.push(format!(
                "{row}: left: {:?}, right: {want_left:?}",
                dir.names()
            ));
        }
    };

    refused(
        "through a directory that is there",
        &|dir| {
            std::fs::create_dir(dir.path().join("sub")).expect("make sub");
            dir.path().join("sub").join("..").join("audit.jsonl")
        },
        &["sub"],
    );
    refused(
        "through a directory that is not there",
        &|dir| dir.path().join("nosuch").join("..").join("audit.jsonl"),
        &[],
    );
    refused(
        "through a link to the directory",
        &|dir| {
            std::os::unix::fs::symlink(dir.path(), dir.path().join("link")).expect("make link");
            dir.path().join("link").join("audit.jsonl")
        },
        &["link"],
    );
    for (row, name) in [
        ("the control stream's newest rotated file", "audit.jsonl.1"),
        ("the control stream's oldest rotated file", "audit.jsonl.4"),
        (
            "the agent stream's oldest rotated file",
            "audit.agent.jsonl.5",
        ),
        (
            "the reads stream's oldest rotated file",
            "audit.reads.jsonl.2",
        ),
    ] {
        refused(row, &|dir| dir.path().join(name), &[]);
    }

    // Just past what a stream keeps is not a name it ever writes.
    for name in [
        "audit.jsonl.5",
        "audit.agent.jsonl.6",
        "audit.reads.jsonl.3",
    ] {
        let dir = Scratch::new("ca-past-keep");
        match start_against(&dir, dir.path().join(name)) {
            Err(started) if started == "started" => {}
            other => failures.push(format!("{name}: left: {other:?}, right: a normal start")),
        }
    }

    assert!(
        failures.is_empty(),
        "{} row(s) failed:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// A value that is not a setting is never printed: not in the warning the
/// environment variable gives, whatever it holds (a token pasted into the wrong
/// variable is the case), and not in the error the config file gives, whatever
/// YAML shape it has (a mapping with a key of its own, a list, a number, a
/// string). The errors say what kind of value it was.
#[test]
fn a_value_that_is_not_a_setting_is_never_echoed() {
    const CANARY: &str = "CNRY04xdeadbeefcafe";
    let mut failures: Vec<String> = Vec::new();

    for value in [
        CANARY.to_string(),
        format!("{CANARY}/audit.jsonl"),
        format!("operator_token={CANARY}"),
    ] {
        let (setting, log) = with_env(&AuditLogSetting::Default, Some(&value));
        if setting != AuditLogSetting::Default {
            failures.push(format!("env {value:?} changed the setting: {setting:?}"));
        }
        if log.contains(CANARY) {
            failures.push(format!(
                "env {value:?}: the warning carries the value: {log}"
            ));
        }
        if !log.contains("WARN") {
            failures.push(format!("env {value:?}: no warning: {log:?}"));
        }
    }

    for (row, yaml, kind) in [
        (
            "a mapping",
            format!("mcp:\n  audit_log:\n    operator_token: {CANARY}\n"),
            "a mapping",
        ),
        (
            "a list",
            format!("mcp:\n  audit_log: [{CANARY}, b]\n"),
            "a list",
        ),
        ("a number", "mcp:\n  audit_log: 5\n".to_string(), "a number"),
        (
            "a relative path",
            format!("mcp:\n  audit_log: {CANARY}/audit.jsonl\n"),
            "a string",
        ),
        (
            "a bare word",
            format!("mcp:\n  audit_log: {CANARY}\n"),
            "a string",
        ),
    ] {
        match parsed(&yaml) {
            Err(text) => {
                if text.contains(CANARY) {
                    failures.push(format!("{row}: the error carries the value: {text}"));
                }
                for needle in ["mcp.audit_log", "absolute", kind] {
                    if !text.contains(needle) {
                        failures.push(format!("{row}: the error lacks {needle:?}: {text}"));
                    }
                }
            }
            Ok(setting) => failures.push(format!("{row}: left: Ok({setting:?}), right: an error")),
        }
    }

    assert!(
        failures.is_empty(),
        "{} row(s) failed:\n{}",
        failures.len(),
        failures.join("\n")
    );
}
