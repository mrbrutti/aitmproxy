//! Tester (stage 5, wave-2 pass 2), plan 2026-11-01-cli-terminal-reporting-wave2
//! Task 15: `main` answers every help form as `Mode::Help` before the runtime
//! (plan C32/C33), the mode usage errors take the M-W2-5 shape (C34/C36), and
//! an implicit bare token that names no group falls through to `Mode::Cli`.
//! The unit tests pin the parsers and the page builders; this runs the REAL
//! binary to pin the wiring they cannot reach — what `main()` writes to which
//! stream, the exit status, and that the help path leaves a fresh `HOME`
//! untouched (no CA, no log file). No port is bound anywhere here (help is
//! pre-boot; the one-shot fall-through returns before any bind), so this runs
//! in the sandbox.
//!
//! Spec: docs/superpowers/specs/2026-11-01-cli-terminal-reporting-design.md
//! (AC-W2-1 … AC-W2-5, AC-W2-7)
//! Plan: docs/superpowers/plans/2026-11-01-cli-terminal-reporting-wave2-plan.md
//! (Task 15; mock-ups M-W2-1 … M-W2-5, M-W2-7)

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// The shipped catalogue, named explicitly so the count does not depend on
/// where the test binary's `aitm` sits relative to `scripts/bundled`.
const BUNDLED: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../scripts/bundled");

/// The version the top page's title carries: the crate's, by construction.
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The environment every run inherits beyond the scrubbed process env: a
/// UTF-8 locale and a real terminal type so the piped output is the UTF-8
/// plain form (`—`, `·`; no escape byte because the streams are pipes).
const BASE_ENV: &[(&str, &str)] = &[("LANG", "en_US.UTF-8"), ("TERM", "xterm-256color")];

/// What the test scrubs from the inherited environment so the operator's
/// shell cannot steer the run (the `help.sh` scrub list plus the locale and
/// terminal keys `BASE_ENV` sets).
const SCRUBBED: &[&str] = &[
    "AITM_CONFIG",
    "RUST_LOG",
    "NO_COLOR",
    "CLICOLOR_FORCE",
    "AITM_TERM",
    "CI",
    "AITM_LOG_FILE",
    "XDG_CONFIG_HOME",
    "AITM_NO_BUNDLED_SCRIPTS",
    "AITM_BUNDLED_SCRIPTS",
    "AITM_SCRIPTS",
    "LC_ALL",
    "LC_CTYPE",
];

fn temp_dir(tag: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let dir = std::env::temp_dir().join(format!("aitm-help-dispatch-{tag}-{nanos}"));
    fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn pump(mut reader: impl Read + Send + 'static) -> JoinHandle<String> {
    thread::spawn(move || {
        let mut out = String::new();
        let _ = reader.read_to_string(&mut out);
        out
    })
}

/// Wait at most `timeout` for the child; a child still running then is
/// killed (a server that started serving would never exit on its own).
fn wait_bounded(child: &mut Child, timeout: Duration) -> Option<ExitStatus> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait().expect("try_wait") {
            return Some(status);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return None;
        }
        thread::sleep(Duration::from_millis(25));
    }
}

/// One run of the real binary.
struct Run {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

impl Run {
    fn ok(&self) -> bool {
        self.code == Some(0)
    }
}

/// Run `aitm <args>` with `home` as both `HOME` and `XDG_CONFIG_HOME` (so the
/// CA, config and log paths of both platforms land under it), a closed stdin,
/// both output streams piped, the scrubbed environment plus `BASE_ENV` and
/// `env`. Panics if the process does not exit within 60 s.
fn aitm(home: &Path, env: &[(&str, &str)], args: &[&str]) -> Run {
    let mut command = Command::new(env!("CARGO_BIN_EXE_aitm"));
    command
        .args(args)
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for key in SCRUBBED {
        command.env_remove(key);
    }
    for (key, value) in BASE_ENV.iter().chain(env) {
        command.env(key, value);
    }
    let mut child = command.spawn().expect("spawn aitm");
    let stdout = pump(child.stdout.take().expect("piped stdout"));
    let stderr = pump(child.stderr.take().expect("piped stderr"));
    let status = wait_bounded(&mut child, Duration::from_secs(60));
    let out = stdout.join().expect("stdout pump");
    let err = stderr.join().expect("stderr pump");
    let status = status
        .unwrap_or_else(|| panic!("aitm {args:?} did not exit; stdout={out:?} stderr={err:?}"));
    Run {
        code: status.code(),
        stdout: out,
        stderr: err,
    }
}

/// Every path under `home`, relative, sorted: what a run created.
fn created_under(home: &Path) -> Vec<String> {
    fn walk(dir: &Path, root: &Path, out: &mut Vec<String>) {
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            out.push(
                path.strip_prefix(root)
                    .unwrap_or(&path)
                    .display()
                    .to_string(),
            );
            if path.is_dir() {
                walk(&path, root, out);
            }
        }
    }
    let mut out = Vec::new();
    walk(home, home, &mut out);
    out.sort();
    out
}

/// The lines between the `Groups:` heading and the next blank line.
fn group_rows(page: &str) -> Vec<&str> {
    page.lines()
        .skip_while(|line| *line != "Groups:")
        .skip(1)
        .take_while(|line| !line.is_empty())
        .collect()
}

/// `[a-z_]+\.[a-z_]+`: a dotted command name in prose (AC-W2-4).
fn has_dotted_token(text: &str) -> bool {
    let is_name = |c: char| c.is_ascii_lowercase() || c == '_';
    let chars: Vec<char> = text.chars().collect();
    chars
        .windows(3)
        .any(|w| w[1] == '.' && is_name(w[0]) && is_name(w[2]))
}

/// The stderr of a post-boot error without its `log:` footer line, which
/// names a path (`aitmproxy/logs/aitm.log`) and is not prose.
fn without_log_line(stderr: &str) -> String {
    stderr
        .lines()
        .filter(|line| !line.trim_start().starts_with("log: "))
        .map(|line| format!("{line}\n"))
        .collect()
}

/// AC-W2-1, AC-W2-7, AC-W2-10's observable half: `aitm --help`, `aitm -h`
/// and `aitm help` are byte-identical, exit 0, print nothing to stderr, open
/// with the versioned title, list 19 groups with the catalogue and 18
/// without, carry no escape byte even with colour forced onto the pipe, and
/// leave a fresh `HOME` with no file at all (no CA, no config, no log).
#[test]
fn top_page_forms_are_identical_pre_boot_and_create_nothing() {
    let home = temp_dir("top");
    let catalogue = [("AITM_BUNDLED_SCRIPTS", BUNDLED)];

    let by_flag = aitm(&home, &catalogue, &["--help"]);
    let by_short = aitm(&home, &catalogue, &["-h"]);
    let by_word = aitm(&home, &catalogue, &["help"]);
    for (form, run) in [("--help", &by_flag), ("-h", &by_short), ("help", &by_word)] {
        assert!(
            run.ok(),
            "{form}: exit {:?}, stderr={:?}",
            run.code,
            run.stderr
        );
        assert_eq!(run.stderr, "", "{form}: nothing on stderr");
    }
    assert_eq!(
        by_flag.stdout, by_short.stdout,
        "`aitm -h` is `aitm --help`"
    );
    assert_eq!(
        by_flag.stdout, by_word.stdout,
        "`aitm help` is `aitm --help`"
    );

    let page = &by_flag.stdout;
    assert_eq!(
        page.lines().next(),
        Some(
            format!("aitm {VERSION} — intercepting proxy for authorized security testing").as_str()
        )
    );
    for heading in ["Usage:", "Groups:", "Options:", "Examples:", "Learn more:"] {
        assert!(
            page.lines().any(|line| line == heading),
            "{heading} missing from\n{page}"
        );
    }
    let rows = group_rows(page);
    assert_eq!(rows.len(), 19, "{rows:#?}");
    assert!(
        rows.iter()
            .any(|row| row.starts_with("  scope ") && row.ends_with("which hosts are decrypted")),
        "{rows:#?}"
    );
    assert!(rows.iter().any(|row| row.starts_with("  l4 ")), "{rows:#?}");
    assert!(
        rows.iter().any(|row| row.starts_with("  check ")),
        "{rows:#?}"
    );
    assert!(page.contains("aitm scope add --host <host>"), "{page}");
    assert!(page.ends_with("Trust the CA:  aitm ca install\n"), "{page}");
    assert!(
        !page.as_bytes().contains(&0x1b),
        "an escape byte in a pipe: {page:?}"
    );

    // Without the catalogue the `l4` row goes and 18 built-in groups stay.
    let bare = aitm(&home, &[("AITM_NO_BUNDLED_SCRIPTS", "1")], &["--help"]);
    assert!(bare.ok(), "{:?} {:?}", bare.code, bare.stderr);
    let bare_rows = group_rows(&bare.stdout);
    assert_eq!(bare_rows.len(), 18, "{bare_rows:#?}");
    assert!(
        !bare_rows.iter().any(|row| row.starts_with("  l4 ")),
        "{bare_rows:#?}"
    );
    assert!(
        bare_rows.iter().any(|row| row.starts_with("  check ")),
        "{bare_rows:#?}"
    );

    // Colour forced onto a pipe is inert (spec D2 rule 7, plan C6).
    let forced = aitm(&home, &catalogue, &["--color=always", "--help"]);
    assert!(forced.ok(), "{:?} {:?}", forced.code, forced.stderr);
    assert_eq!(
        forced.stdout, by_flag.stdout,
        "`--color=always` changes no byte on a pipe"
    );
    assert!(!forced.stdout.as_bytes().contains(&0x1b));
    let quiet = aitm(&home, &catalogue, &["-q", "--help"]);
    assert_eq!(
        quiet.stdout, by_flag.stdout,
        "`-q` changes no byte of the page"
    );

    assert_eq!(
        created_under(&home),
        Vec::<String>::new(),
        "help created something under HOME (plan rule 12)"
    );
    fs::remove_dir_all(&home).expect("remove temp dir");
}

/// AC-W2-2, AC-W2-3 (the group case), AC-W2-7: `aitm scope`, `aitm help
/// scope` and `aitm scope --help` are one page; `aitm scope add --help` and
/// `aitm help scope add` are one page with the flag type, the required mark
/// and an example; `aitm scan` is a group page; `aitm flow detail --help`
/// carries the core's default words; the three mode pages print with their
/// one `Usage:` line and the Homebrew phrase; nothing is booted — no log
/// record, no file under `HOME` — across all of it.
#[test]
fn group_verb_and_mode_pages_are_identical_across_forms_and_boot_nothing() {
    let home = temp_dir("pages");
    let catalogue = [("AITM_BUNDLED_SCRIPTS", BUNDLED)];
    let page = |args: &[&str]| {
        let run = aitm(&home, &catalogue, args);
        assert!(
            run.ok(),
            "{args:?}: exit {:?}, stderr={:?}",
            run.code,
            run.stderr
        );
        assert_eq!(run.stderr, "", "{args:?}: nothing on stderr");
        assert!(
            !run.stdout.as_bytes().contains(&0x1b),
            "{args:?}: {:?}",
            run.stdout
        );
        run.stdout
    };

    let scope = page(&["scope"]);
    assert_eq!(
        scope,
        page(&["help", "scope"]),
        "`aitm help scope` equals `aitm scope`"
    );
    assert_eq!(
        scope,
        page(&["scope", "--help"]),
        "`aitm scope --help` equals `aitm scope`"
    );
    assert!(scope.starts_with("aitm scope — which hosts are decrypted\n\nUsage:\n  aitm scope <verb> [--flag <value>]...\n\nVerbs:\n"), "{scope}");
    assert!(
        scope.contains(
            "\n  add --host <host>         Add a host, host:port, or *.wildcard to Scope.\n"
        ),
        "{scope}"
    );
    assert!(
        scope.ends_with("\nNothing is decrypted until a host is in Scope.\n"),
        "{scope}"
    );

    let scope_add = page(&["scope", "add", "--help"]);
    assert_eq!(
        scope_add,
        page(&["help", "scope", "add"]),
        "`aitm help scope add` equals `aitm scope add --help`"
    );
    assert!(
        scope_add.starts_with(
            "Add a host, host:port, or *.wildcard to Scope. New connections to it are\n"
        ),
        "{scope_add}"
    );
    assert!(
        scope_add.contains("\nUsage:\n  aitm scope add --host <host>\n"),
        "{scope_add}"
    );
    assert!(
        scope_add
            .contains("\nFlags:\n  --host <string>           The scope entry to add. [required]\n"),
        "{scope_add}"
    );
    assert!(
        scope_add.contains("\nExamples:\n  $ aitm scope add --host app.example.test\n"),
        "{scope_add}"
    );

    let scan = page(&["scan"]);
    assert!(scan.starts_with("aitm scan — "), "{scan}");
    assert!(scan.contains("\nVerbs:\n"), "{scan}");

    let flow_detail = page(&["flow", "detail", "--help"]);
    assert!(flow_detail.contains("(default inline)"), "{flow_detail}");
    assert!(
        flow_detail.contains("\n  --id <flow-id>            The flow to inspect. [required]\n"),
        "{flow_detail}"
    );

    // The mode pages (plan C48; AC-W2-5's `web operator UI` pin).
    let web = page(&["web", "--help"]);
    assert!(web.contains("web operator UI"), "{web}");
    assert!(web.contains("\nUsage:\n  aitm [--config <path>] web [--listen <addr>] [--token <token>] [--no-open]\n"), "{web}");
    assert_eq!(web, page(&["help", "web"]));
    // `--help` wins over the web options before them: the web parser never
    // runs, so a valueless `--listen` is not an error here.
    assert_eq!(web, page(&["web", "--listen", "--help"]));
    let tui = page(&["tui", "--help"]);
    assert!(
        tui.contains("\nUsage:\n  aitm [--config <path>] tui\n"),
        "{tui}"
    );
    let token = page(&["operator-token", "--help"]);
    assert!(
        token.contains("\nUsage:\n  aitm [--config <path>] operator-token generate [--force]\n"),
        "{token}"
    );
    assert!(!token.contains("token:"), "never a token value: {token}");

    assert_eq!(
        created_under(&home),
        Vec::<String>::new(),
        "a help page booted something: a file appeared under HOME"
    );
    fs::remove_dir_all(&home).expect("remove temp dir");
}

/// Plan C33's exception and M-W2-4's pre-boot panel: an explicit help request
/// that names nothing (`aitm help scpe`, `aitm scope ad --help`) is a usage
/// error before boot — exit 2, the did-you-mean, the right pointer, no `log:`
/// footer, nothing created, nothing on stdout.
#[test]
fn explicit_unknown_topics_are_pre_boot_usage_errors() {
    let home = temp_dir("explicit");
    let bare = [("AITM_NO_BUNDLED_SCRIPTS", "1")];

    let scpe = aitm(&home, &bare, &["help", "scpe"]);
    assert_eq!(scpe.code, Some(2), "{scpe:?}", scpe = scpe.stderr);
    assert_eq!(scpe.stdout, "");
    assert_eq!(
        scpe.stderr,
        "error: unknown command `scpe`\n  did you mean: scope\n  fix: aitm --help\n"
    );

    let verb = aitm(&home, &bare, &["scope", "ad", "--help"]);
    assert_eq!(verb.code, Some(2), "{}", verb.stderr);
    assert_eq!(verb.stdout, "");
    assert_eq!(
        verb.stderr,
        "error: unknown command `scope ad`\n  did you mean: scope add\n  fix: aitm scope\n"
    );
    assert_eq!(
        aitm(&home, &bare, &["help", "scope", "ad"]).stderr,
        verb.stderr
    );

    // `-q` holds on the pre-boot usage path (spec D9): the panel still prints
    // (errors are never quiet) and the exit code is the same.
    let quiet = aitm(&home, &bare, &["-q", "help", "scpe"]);
    assert_eq!(quiet.code, Some(2));
    assert_eq!(quiet.stderr, scpe.stderr);

    for text in [&scpe.stderr, &verb.stderr] {
        assert!(!has_dotted_token(text), "dotted name in {text:?}");
    }
    assert_eq!(
        created_under(&home),
        Vec::<String>::new(),
        "a pre-boot usage error created something under HOME"
    );
    fs::remove_dir_all(&home).expect("remove temp dir");
}

/// AC-W2-5, mock-up M-W2-5: `aitm tui --bad`, `aitm operator-token` (and an
/// unknown operator-token verb), `aitm web --bad` and a valueless web flag
/// print the headline, the one `Usage:` line and the pointer, exit 2, with
/// nothing on stdout and nothing created (they are answered before boot).
/// Security S6 (panel pass 5): a token carrying a newline cannot split the
/// headline from its `Usage:` line and demote the panel to a failure — the
/// renderer folds it to a space and the exit code stays 2.
#[test]
fn mode_usage_errors_take_the_usage_form_shape() {
    let home = temp_dir("modes");
    let cases: [(&[&str], &str); 7] = [
        (
            &["tui", "--bad"],
            "error: tui takes no further arguments, got `--bad`\n  Usage: aitm [--config <path>] tui\n  fix: aitm --help\n",
        ),
        (
            &["operator-token"],
            "error: operator-token needs a verb\n  Usage: aitm [--config <path>] operator-token generate [--force]\n  fix: aitm --help\n",
        ),
        (
            &["operator-token", "rotate"],
            "error: unknown verb `rotate` for operator-token\n  Usage: aitm [--config <path>] operator-token generate [--force]\n  fix: aitm --help\n",
        ),
        (
            &["web", "--bad"],
            "error: unknown argument to `aitm web`: --bad\n  Usage: aitm [--config <path>] web [--listen <addr>] [--token <token>] [--no-open]\n  fix: aitm web --help\n",
        ),
        (
            &["web", "--listen"],
            "error: --listen requires a value\n  Usage: aitm [--config <path>] web [--listen <addr>] [--token <token>] [--no-open]\n  fix: aitm web --help\n",
        ),
        (
            &["tui", "x\ny"],
            "error: tui takes no further arguments, got `x y`\n  Usage: aitm [--config <path>] tui\n  fix: aitm --help\n",
        ),
        (
            &["operator-token", "x\ny"],
            "error: unknown verb `x y` for operator-token\n  Usage: aitm [--config <path>] operator-token generate [--force]\n  fix: aitm --help\n",
        ),
    ];
    for (args, expected) in cases {
        let run = aitm(&home, &[], args);
        assert_eq!(run.code, Some(2), "{args:?}: {}", run.stderr);
        assert_eq!(run.stdout, "", "{args:?}");
        assert_eq!(run.stderr, expected, "{args:?}");
        assert!(!has_dotted_token(&run.stderr), "{args:?}: {}", run.stderr);
    }
    assert_eq!(
        created_under(&home),
        Vec::<String>::new(),
        "a mode usage error created something under HOME"
    );
    fs::remove_dir_all(&home).expect("remove temp dir");
}

/// Plan C33 through `main()`: an implicit single token that names no group
/// (`aitm scpe`) is `Answer::NotHelp`, the invocation is rewritten to
/// `Mode::Cli` and the dispatcher answers after boot — the same did-you-mean
/// panel as the pre-boot one plus the `log:` footer, and the log file now
/// exists. `aitm scpe add --host x` (AC-W2-3's literal) and `aitm --bad`
/// (M-W2-5's post-boot panel) take the same path; no panel carries a dotted
/// command name (AC-W2-4).
#[test]
fn implicit_unknown_token_falls_through_to_the_cli_after_boot() {
    let home = temp_dir("fallthrough");
    let bare = [("AITM_NO_BUNDLED_SCRIPTS", "1")];
    let log_line = |stderr: &str| -> Option<String> {
        stderr
            .lines()
            .find_map(|line| line.strip_prefix("  log: ").map(str::to_string))
    };

    let implicit = aitm(&home, &bare, &["scpe"]);
    assert_eq!(implicit.code, Some(2), "{}", implicit.stderr);
    assert_eq!(implicit.stdout, "");
    assert_eq!(
        without_log_line(&implicit.stderr),
        "error: unknown command `scpe`\n  did you mean: scope\n  fix: aitm --help\n"
    );
    let log = log_line(&implicit.stderr)
        .unwrap_or_else(|| panic!("a post-boot panel names its log: {:?}", implicit.stderr));
    assert!(
        Path::new(&log).starts_with(&home),
        "the log footer names a path under the test HOME: {log}"
    );
    assert!(log.ends_with("aitmproxy/logs/aitm.log"), "{log}");
    assert!(
        Path::new(&log).is_file(),
        "the fall-through booted, so the log file exists: {log}"
    );

    let literal = aitm(&home, &bare, &["scpe", "add", "--host", "x"]);
    assert_eq!(literal.code, Some(2), "{}", literal.stderr);
    assert_eq!(
        without_log_line(&literal.stderr),
        "error: unknown command `scpe`\n  did you mean: scope\n  fix: aitm --help\n"
    );
    assert_eq!(log_line(&literal.stderr).as_deref(), Some(log.as_str()));

    let flag_first = aitm(&home, &bare, &["--bad"]);
    assert_eq!(flag_first.code, Some(2), "{}", flag_first.stderr);
    assert_eq!(
        without_log_line(&flag_first.stderr),
        "error: expected a command before flags, got `--bad`\n  Usage: aitm <group> <verb> [--flag <value>]...\n  fix: aitm --help\n"
    );
    assert!(
        log_line(&flag_first.stderr).is_some(),
        "{}",
        flag_first.stderr
    );

    let bogus = aitm(&home, &bare, &["flow", "list", "--bogus", "1"]);
    assert_eq!(bogus.code, Some(2), "{}", bogus.stderr);
    assert_eq!(
        without_log_line(&bogus.stderr),
        "error: unknown flag --bogus for `flow list`\n  Usage: aitm flow list\n  fix: aitm flow list --help\n"
    );

    for run in [&implicit, &literal, &flag_first, &bogus] {
        assert!(
            !has_dotted_token(&without_log_line(&run.stderr)),
            "dotted name in {:?}",
            run.stderr
        );
    }
    fs::remove_dir_all(&home).expect("remove temp dir");
}

/// Plan C31 and item 9b through the binary: a config that cannot be read
/// never fails help — the page prints, exit 0 — and exactly one `warning:
/// config not read` line names the path and the error's first line with any
/// scalar serde quoted redacted: a token mis-indented under a numeric key, a
/// token on an enum field (serde quotes that value raw, even across lines
/// when it is a block scalar) and a missing file. `AITM_CONFIG` is honoured
/// like `--config`. Nothing is created.
#[test]
fn config_not_read_warns_once_and_echoes_no_value() {
    let home = temp_dir("config");
    let files = temp_dir("config-files");
    let bare = [("AITM_NO_BUNDLED_SCRIPTS", "1")];
    let scalar = files.join("scalar.yaml");
    fs::write(&scalar, "limits:\n  max_body_bytes: optoken-test-abc\n").expect("write");
    let variant = files.join("variant.yaml");
    fs::write(
        &variant,
        "mcp:\n  stdio_role: |\n    optoken-1\n    optoken-2\n",
    )
    .expect("write");
    let missing = files.join("nope").join("config.yaml");

    let warning = |run: &Run, path: &Path| -> String {
        assert!(run.ok(), "exit {:?}: {}", run.code, run.stderr);
        assert!(
            run.stdout
                .starts_with("aitm scope — which hosts are decrypted\n"),
            "{}",
            run.stdout
        );
        assert_eq!(
            run.stderr.lines().count(),
            1,
            "one warning line: {:?}",
            run.stderr
        );
        let prefix = format!("warning: config not read · {}: ", path.display());
        let reason = run
            .stderr
            .strip_prefix(&prefix)
            .and_then(|s| s.strip_suffix(" · help lists the default command set\n"))
            .unwrap_or_else(|| panic!("the C31 shape around {prefix:?}: {:?}", run.stderr));
        reason.to_string()
    };

    let scalar_run = aitm(
        &home,
        &bare,
        &["--config", scalar.to_str().unwrap(), "scope"],
    );
    let reason = warning(&scalar_run, &scalar);
    assert!(
        !reason.contains("optoken"),
        "the scalar is echoed: {reason}"
    );
    assert!(
        reason.starts_with("limits.max_body_bytes: invalid type: string \"…\", expected "),
        "{reason}"
    );

    let variant_run = aitm(
        &home,
        &bare,
        &["--config", variant.to_str().unwrap(), "scope"],
    );
    let reason = warning(&variant_run, &variant);
    assert!(
        !reason.contains("optoken"),
        "the variant value is echoed: {reason}"
    );
    assert!(
        reason.starts_with("mcp.stdio_role: unknown variant `…`, expected `agent` or `operator`"),
        "{reason}"
    );

    let missing_run = aitm(
        &home,
        &bare,
        &["--config", missing.to_str().unwrap(), "scope"],
    );
    let reason = warning(&missing_run, &missing);
    assert!(!reason.is_empty());

    let via_env = aitm(
        &home,
        &[
            ("AITM_NO_BUNDLED_SCRIPTS", "1"),
            ("AITM_CONFIG", scalar.to_str().unwrap()),
        ],
        &["scope"],
    );
    assert_eq!(
        via_env.stderr, scalar_run.stderr,
        "AITM_CONFIG is read like --config"
    );

    assert_eq!(
        fs::read_to_string(&scalar).unwrap(),
        "limits:\n  max_body_bytes: optoken-test-abc\n",
        "the config is never written"
    );
    assert_eq!(created_under(&home), Vec::<String>::new());
    assert!(
        !missing.parent().unwrap().exists(),
        "the missing config's directory was created"
    );
    fs::remove_dir_all(&home).expect("remove temp dir");
    fs::remove_dir_all(&files).expect("remove temp dir");
}
