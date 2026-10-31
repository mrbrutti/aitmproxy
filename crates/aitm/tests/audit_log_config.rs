//! Durable audit, task W2 (AC1, AC2): the `mcp.audit_log` config key and the
//! `AITM_AUDIT_LOG` environment override.
//!
//! The key accepts `true`, `false`, `off` (any case) and an absolute path; every
//! other value is a config error naming `mcp.audit_log` and "absolute". The
//! environment wins over the file, but an unparseable `AITM_AUDIT_LOG` leaves the
//! file's setting exactly as it was (and says so with one warning): for an audit
//! control the fail-safe direction is "stay on", so a typo must not disable the
//! trail. Paths are Unix literals; the repo's CI is Unix.
//!
//! Task W3 adds AC3 (`stream_paths_follow_the_rule`): the three stream files are
//! derived from the one configured base path.

use std::io;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use aitm::audit_log::{stream_path, StreamKind};
use aitm::config_file::parse;
use aitm::env;
use aitm_core::{AuditLogSetting, CaConfig, Config};
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
    let mut check = |start: &AuditLogSetting,
                     value: Option<&str>,
                     want: &AuditLogSetting,
                     want_warning: bool| {
        let (got, log) = with_env(start, value);
        let row = format!("file {start:?}, env {value:?}");
        if got != *want {
            failures.push(format!("{row}: left: {got:?}, right: {want:?}"));
        }
        let lines = log.lines().count();
        if want_warning {
            // One line, on the audit target, naming the variable and the
            // Debug-escaped value (a newline in the value cannot forge a line).
            let escaped = format!("AITM_AUDIT_LOG={:?}", value.unwrap_or_default());
            for needle in [escaped.as_str(), "aitm::audit", "WARN", "unchanged"] {
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
            check(start, Some(value), &AuditLogSetting::Off, false);
        }
        // On spellings, ASCII case-insensitive.
        for value in ["on", "true", "1", "yes", "default", "True"] {
            check(start, Some(value), &AuditLogSetting::Default, false);
        }
        // An absolute path selects `Path`.
        check(
            start,
            Some("/tmp/x/a.jsonl"),
            &AuditLogSetting::Path(PathBuf::from("/tmp/x/a.jsonl")),
            false,
        );
        // Unset: the file's value survives.
        check(start, None, start, false);
        // Anything else leaves the file's setting exactly as it was: a typo, a
        // relative path, an empty string, a value that only looks like "off"
        // (the parse is not trimmed), a value with a newline in it.
        for value in [
            "ofd",
            "relative.jsonl",
            "~/audit.jsonl",
            "",
            " off",
            "off ",
            "a\nb",
        ] {
            check(start, Some(value), start, true);
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
    // (These two rows are green on arrival: Task W1 built `resolved_path`.)
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
