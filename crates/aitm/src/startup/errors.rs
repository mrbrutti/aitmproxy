//! Typed startup errors and their panels (spec D6, M2; plan Task 8, call
//! C15): [`StartupError`], [`report_for`], [`exit_with`], [`USAGE_PREFIXES`].
//!
//! `run()` fails with an `anyhow::Error`. The startup failures the operator
//! meets most are typed here so [`report_for`] can turn each into the exact
//! what/why/fix/command panel of mock-up M2, while the `Display` of every
//! variant stays what 0.5.10 printed (the `main.rs` pin and
//! `cli-startup.sh` read it through `anyhow`). A dispatcher, mode-parser or
//! valued-global-flag usage error becomes a [`ErrorKind::Usage`] panel (exit
//! 2) pointing at `aitm --help`; anything else is the `anyhow` chain, one cause per line
//! (exit 1). Addressed by path (`startup::errors::…`), never re-exported from
//! `mod.rs`.
//!
//! [`ErrorKind::Usage`]: aitm_term::error::ErrorKind::Usage

use std::error::Error as StdError;
use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use aitm_term::caps::{Caps, ColorChoice, Verbosity};
use aitm_term::error::ErrorReport;
use aitm_term::reporter::Reporter;

/// How an `aitm_cli` dispatch error begins when the command line could not be
/// understood (spec D6 rule 4). A top message starting with one of these is a
/// usage error: exit 2, `aitm --help` as the fix command.
pub const USAGE_PREFIXES: &[&str] = &[
    "unknown command",
    "expected a command",
    "unknown flag",
    "missing required flag",
    "flag --",
    "unexpected argument",
];

/// How every mode usage line and the dispatcher's own begins.
const USAGE_LINE: &str = "usage:";
/// The word a valued global flag's one-line error carries when its value is
/// missing (`--config requires a path`, `--script requires a path`,
/// `--bus-endpoint-file requires a path`; tester F2). With a headline that
/// starts with `--`, it is a usage error.
const REQUIRES: &str = " requires ";
/// The first line of the dispatcher's full command list, which the panel
/// drops in favour of the `aitm --help` pointer (plan C15).
const REGISTRY_DUMP_HEADER: &str = "usage: aitm <command> [--flag value]...";
/// The cause sentence of a port conflict, verbatim from 0.5.10 (M2).
const HELD_BY: &str = "It is most likely held by another running `aitm`, the aitmproxy macOS app's embedded core, or another program.";
/// The remedy when the config file named by `--config` does not exist.
const CONFIG_MISSING_FIX: &str = "Create it, or run without --config to use the defaults.";
/// The remedy for any other config-file failure.
const CONFIG_BAD_FIX: &str = "Fix the file, or pass --config <path> to use another.";
/// The remedy for a strict-mode script failure.
const STRICT_SCRIPTS_FIX: &str = "Fix the scripts above, or unset rhai.strict.";

/// The startup failures `run()` types so their panels can be exact (spec D6).
///
/// Holds `anyhow::Error` and `io::Error`, so it derives `Debug` only (plan
/// C27, "where the fields allow").
#[derive(Debug)]
pub enum StartupError {
    /// A service port is held by another process. `role` names the service
    /// (`the proxy`, `the embedded browser's proxy`, …) and `remedy` is the
    /// sentence naming the config key to change.
    PortInUse {
        role: String,
        addr: SocketAddr,
        remedy: String,
    },
    /// The config file could not be read or parsed; `source` is
    /// `config_file::load_settings`'s chain.
    ConfigFile {
        path: PathBuf,
        source: anyhow::Error,
    },
    /// `failed` scripts did not load while `rhai.strict` is set.
    StrictScripts { failed: usize },
    /// The log file could not be opened. Never fatal: startup continues
    /// without it and `startup::log::open_sink` prints this variant's
    /// `Display` as the warning (AC-W1-17), so the wording lives here once.
    LogFile { path: PathBuf, source: io::Error },
}

/// The one copy-safe command that names a port's holder (M2).
fn lsof_command(port: u16) -> String {
    format!("lsof -nP -iTCP:{port} -sTCP:LISTEN")
}

impl StartupError {
    /// The panel for the variants spec D6 maps (rules 1–3); `None` for
    /// [`StartupError::LogFile`], which is built for its `Display` by
    /// `startup::log::open_sink`, never returned as an error, and so falls
    /// through to the generic rule should it ever reach `report_for`.
    fn report(&self) -> Option<ErrorReport> {
        match self {
            StartupError::PortInUse { role, addr, remedy } => Some(
                ErrorReport::failure(format!(
                    "cannot start: {role} port {addr} is already in use"
                ))
                .with_why(vec![HELD_BY.to_string()])
                .with_fix(remedy.clone())
                .with_command(lsof_command(addr.port())),
            ),
            StartupError::ConfigFile { source, .. } => {
                let what = self.to_string();
                let why = source
                    .chain()
                    .map(ToString::to_string)
                    .filter(|cause| *cause != what)
                    .collect();
                let missing = source.chain().any(|cause| {
                    cause
                        .downcast_ref::<io::Error>()
                        .is_some_and(|e| e.kind() == io::ErrorKind::NotFound)
                });
                let fix = if missing {
                    CONFIG_MISSING_FIX
                } else {
                    CONFIG_BAD_FIX
                };
                Some(ErrorReport::failure(what).with_why(why).with_fix(fix))
            }
            StartupError::StrictScripts { .. } => {
                Some(ErrorReport::failure(self.to_string()).with_fix(STRICT_SCRIPTS_FIX))
            }
            StartupError::LogFile { .. } => None,
        }
    }
}

impl fmt::Display for StartupError {
    /// `PortInUse` is 0.5.10's four lines byte for byte (spec D6).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StartupError::PortInUse { role, addr, remedy } => write!(
                f,
                "cannot start: {role} port {addr} is already in use.\n\
                 {HELD_BY}\n\
                 {remedy}\n\
                 Find the holder with:  {}",
                lsof_command(addr.port())
            ),
            StartupError::ConfigFile { path, .. } => {
                write!(f, "in config file {}", path.display())
            }
            StartupError::StrictScripts { failed } => {
                write!(
                    f,
                    "{failed} script(s) failed to load and `rhai.strict` is set"
                )
            }
            StartupError::LogFile { path, source } => {
                write!(f, "log file unavailable: {} ({source})", path.display())
            }
        }
    }
}

impl StdError for StartupError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            StartupError::ConfigFile { source, .. } => Some(&**source),
            StartupError::LogFile { source, .. } => Some(source),
            StartupError::PortInUse { .. } | StartupError::StrictScripts { .. } => None,
        }
    }
}

/// The panel for `err` (spec D6, first match wins over `err.chain()`):
///
/// 1. a [`StartupError::PortInUse`] anywhere in the chain → the M2 fields;
/// 2. a [`StartupError::ConfigFile`] → `in config file <path>`, its source
///    chain as the causes (minus any equal to the headline), the
///    create-or-drop-`--config` remedy when the chain holds a `NotFound`
///    `io::Error`, else the fix-the-file remedy;
/// 3. a [`StartupError::StrictScripts`] → today's message plus its remedy;
/// 4. a usage error (the top message starts with one of [`USAGE_PREFIXES`]
///    or with `usage:`, or is a `--<flag> requires <value>` line, or its
///    headline is followed by the mode parser's own `usage:` line) →
///    [`ErrorReport::usage`]: the first line as the
///    headline, the following lines as causes up to, not including, the
///    dispatcher's command list, which the `aitm --help` pointer replaces
///    (plan C15);
/// 5. anything else → the top message and every `source()` in order.
///
/// `log` becomes the footer whenever it is given.
pub fn report_for(err: &anyhow::Error, log: Option<&Path>) -> ErrorReport {
    let report = err
        .chain()
        .find_map(|cause| {
            cause
                .downcast_ref::<StartupError>()
                .and_then(StartupError::report)
        })
        .or_else(|| usage_report(&err.to_string()))
        .unwrap_or_else(|| generic_report(err));
    report.with_log(log.map(Path::to_path_buf))
}

/// Rule 4 of [`report_for`], or `None` when `message` is not a usage error.
fn usage_report(message: &str) -> Option<ErrorReport> {
    let mut lines = message.lines();
    let what = lines.next().unwrap_or("");
    let mut rest = lines.peekable();
    let is_usage = USAGE_PREFIXES.iter().any(|p| what.starts_with(p))
        || what.starts_with(USAGE_LINE)
        || flag_requires_a_value(what)
        || rest.peek().is_some_and(|line| line.starts_with(USAGE_LINE));
    if !is_usage {
        return None;
    }
    let why = if what.starts_with(REGISTRY_DUMP_HEADER) {
        Vec::new()
    } else {
        rest.take_while(|line| !line.starts_with(REGISTRY_DUMP_HEADER))
            .filter(|line| !line.trim().is_empty())
            .map(str::to_string)
            .collect()
    };
    Some(ErrorReport::usage(what).with_why(why))
}

/// Part of rule 4: a valued flag given without its value (`--config requires
/// a path`), raised by `main.rs` as a bare one-line error (tester F2).
fn flag_requires_a_value(what: &str) -> bool {
    what.starts_with("--") && what.contains(REQUIRES)
}

/// Rule 5 of [`report_for`]: the top message, then each cause.
fn generic_report(err: &anyhow::Error) -> ErrorReport {
    ErrorReport::failure(err.to_string())
        .with_why(err.chain().skip(1).map(ToString::to_string).collect())
}

/// Render `report` and exit the process with its status; never returns.
///
/// Through `reporter` when `run()` has one: [`Reporter::error`] ends the live
/// region itself (the running phases are marked failed and the panel is
/// printed below them, rich or plain per the caps), and [`Reporter::finish`]
/// then joins the render thread. The order matters: `finish()` also switches
/// the renderer to plain lines, so calling it first would turn M2's TTY panel
/// into the piped form. Without a reporter (the argument-parsing failures,
/// before `TermOpts` exist) a fresh one on stderr with auto-detected caps is
/// used. No unit test can call this; the callers are exercised by the live
/// proof (AC-W1-3, AC-W1-13, AC-W1-14).
pub fn exit_with(report: &ErrorReport, reporter: Option<&Reporter>) -> ! {
    let fresh;
    let reporter = match reporter {
        Some(reporter) => reporter,
        None => {
            fresh = Reporter::stderr(Caps::detect_stderr(ColorChoice::Auto), Verbosity::Normal);
            &fresh
        }
    };
    reporter.error(report);
    reporter.finish();
    std::process::exit(report.exit_code())
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::net::SocketAddr;
    use std::path::{Path, PathBuf};

    use aitm_term::error::{ErrorKind, ErrorReport, FixCommand};

    use super::{report_for, StartupError, USAGE_PREFIXES};

    const CONFIG: &str = "/Users/matt/Library/Application Support/aitmproxy/config.yaml";
    const LOG: &str = "/Users/matt/Library/Application Support/aitmproxy/logs/aitm.log";
    const HELD_BY: &str = "It is most likely held by another running `aitm`, the aitmproxy macOS app's embedded core, or another program.";

    fn proxy_addr() -> SocketAddr {
        "127.0.0.1:8080".parse().expect("literal socket address")
    }

    fn remedy() -> String {
        format!("Free it, or set `listen:` to another address in {CONFIG}.")
    }

    fn port_in_use() -> StartupError {
        StartupError::PortInUse {
            role: "the proxy".to_string(),
            addr: proxy_addr(),
            remedy: remedy(),
        }
    }

    /// The M2 fields for the proxy-port conflict with the log footer.
    fn m2_report() -> ErrorReport {
        ErrorReport {
            kind: ErrorKind::Failure,
            what: "cannot start: the proxy port 127.0.0.1:8080 is already in use".to_string(),
            why: vec![HELD_BY.to_string()],
            fix: Some(remedy()),
            command: Some(FixCommand("lsof -nP -iTCP:8080 -sTCP:LISTEN".to_string())),
            log: Some(PathBuf::from(LOG)),
        }
    }

    #[test]
    fn port_in_use_display_is_byte_identical_to_0_5_10() {
        let expected = "cannot start: the proxy port 127.0.0.1:8080 is already in use.\nIt is most likely held by another running `aitm`, the aitmproxy macOS app's embedded core, or another program.\nFree it, or set `listen:` to another address in /Users/matt/Library/Application Support/aitmproxy/config.yaml.\nFind the holder with:  lsof -nP -iTCP:8080 -sTCP:LISTEN";
        assert_eq!(port_in_use().to_string(), expected);
        // The `main.rs` pin (spec D6) reads the same text through `anyhow`.
        let err = anyhow::Error::new(port_in_use());
        assert!(err
            .to_string()
            .starts_with("cannot start: the proxy port 127.0.0.1:8080 is already in use."));
        assert!(err.downcast_ref::<StartupError>().is_some());
    }

    #[test]
    fn report_for_port_in_use_has_the_m2_fields() {
        let log = Path::new(LOG);
        let err = anyhow::Error::new(port_in_use());
        assert_eq!(report_for(&err, Some(log)), m2_report());

        // An outer context (the bind helper's) changes nothing: the typed
        // error wins over the chain (D6, "first match wins").
        let wrapped = anyhow::Error::new(port_in_use()).context("binding ports");
        assert_eq!(report_for(&wrapped, Some(log)), m2_report());

        // No log opened yet: no footer.
        assert_eq!(report_for(&err, None), m2_report().with_log(None));
    }

    #[test]
    fn report_for_config_file_missing_and_parse_errors() {
        let missing = anyhow::Error::new(StartupError::ConfigFile {
            path: PathBuf::from("/x/cfg.yaml"),
            source: anyhow::anyhow!(io::Error::from(io::ErrorKind::NotFound))
                .context("reading config file /x/cfg.yaml"),
        });
        let report = report_for(&missing, None);
        assert_eq!(report.kind, ErrorKind::Failure);
        assert_eq!(report.exit_code(), 1);
        assert_eq!(report.what, "in config file /x/cfg.yaml");
        assert_eq!(
            report.why,
            vec![
                "reading config file /x/cfg.yaml".to_string(),
                "entity not found".to_string()
            ]
        );
        assert_eq!(
            report.fix.as_deref(),
            Some("Create it, or run without --config to use the defaults.")
        );
        assert_eq!(report.command, None);
        assert_eq!(report.log, None);

        let parse = anyhow::Error::new(StartupError::ConfigFile {
            path: PathBuf::from("/x/cfg.yaml"),
            source: anyhow::anyhow!("listen: invalid socket address syntax at line 1 column 9")
                .context("parsing config YAML")
                .context("in config file /x/cfg.yaml"),
        });
        let report = report_for(&parse, Some(Path::new(LOG)));
        assert_eq!(report.kind, ErrorKind::Failure);
        assert_eq!(report.exit_code(), 1);
        assert_eq!(report.what, "in config file /x/cfg.yaml");
        assert_eq!(
            report.why,
            vec![
                "parsing config YAML".to_string(),
                "listen: invalid socket address syntax at line 1 column 9".to_string()
            ]
        );
        assert_eq!(
            report.fix.as_deref(),
            Some("Fix the file, or pass --config <path> to use another.")
        );
        assert_eq!(report.command, None);
        assert_eq!(report.log, Some(PathBuf::from(LOG)));
    }

    #[test]
    fn report_for_strict_scripts() {
        let err = anyhow::Error::new(StartupError::StrictScripts { failed: 2 });
        let report = report_for(&err, None);
        assert_eq!(report.kind, ErrorKind::Failure);
        assert_eq!(report.exit_code(), 1);
        assert_eq!(
            report.what,
            "2 script(s) failed to load and `rhai.strict` is set"
        );
        assert_eq!(report.why, Vec::<String>::new());
        assert_eq!(
            report.fix.as_deref(),
            Some("Fix the scripts above, or unset rhai.strict.")
        );
        assert_eq!(report.command, None);
    }

    #[test]
    fn report_for_usage_prefixes_exit_2_with_the_help_pointer() {
        assert_eq!(
            USAGE_PREFIXES,
            &[
                "unknown command",
                "expected a command",
                "unknown flag",
                "missing required flag",
                "flag --",
                "unexpected argument",
            ]
        );
        let usage_messages = [
            "unknown command `foo`; run with no arguments to list commands",
            "expected a command before flags, got `--x`",
            "unknown flag --bogus for `flow.list`; accepted: id",
            "missing required flag --id for `findings.get`",
            "flag --id needs a value",
            "unexpected argument `x` for `scope.add`; flags are `--name value`",
            "usage: aitm sysproxy-watchdog --pid <pid> --state <file> [--no-pipe]",
        ];
        for message in usage_messages {
            let report = report_for(&anyhow::anyhow!("{message}"), None);
            assert_eq!(report.kind, ErrorKind::Usage, "{message:?}");
            assert_eq!(report.exit_code(), 2, "{message:?}");
            assert_eq!(
                report.command,
                Some(FixCommand("aitm --help".to_string())),
                "{message:?}"
            );
            assert_eq!(report.what, message, "{message:?}");
            assert_eq!(report.why, Vec::<String>::new(), "{message:?}");
            assert_eq!(report.fix, None, "{message:?}");
        }

        // A command that was understood and failed stays a failure (exit 1).
        let failure = report_for(
            &anyhow::anyhow!("findings get: no such finding `nope`"),
            None,
        );
        assert_eq!(failure.kind, ErrorKind::Failure);
        assert_eq!(failure.exit_code(), 1);
        assert_eq!(failure.what, "findings get: no such finding `nope`");
        assert_eq!(failure.command, None);
    }

    /// Tester F2 (spec D6 rule 4, AC-W1-13): a valued global flag given
    /// without its value (`aitm --config`, `--script`, `--bus-endpoint-file`)
    /// is a usage error — exit 2 with the `aitm --help` pointer — even though
    /// `main.rs` raises it as a bare one-line `anyhow!` with no `usage:`
    /// line. The rule is "starts with `--` and contains ` requires `", so a
    /// failure that merely mentions a flag, or an unrelated `requires`, stays
    /// exit 1.
    #[test]
    fn report_for_a_flag_that_requires_a_value_is_a_usage_error() {
        for message in [
            "--config requires a path",
            "--script requires a path",
            "--bus-endpoint-file requires a path",
        ] {
            let report = report_for(&anyhow::anyhow!("{message}"), None);
            assert_eq!(report.kind, ErrorKind::Usage, "{message:?}");
            assert_eq!(report.exit_code(), 2, "{message:?}");
            assert_eq!(report.what, message, "{message:?}");
            assert_eq!(report.why, Vec::<String>::new(), "{message:?}");
            assert_eq!(report.fix, None, "{message:?}");
            assert_eq!(
                report.command,
                Some(FixCommand("aitm --help".to_string())),
                "{message:?}"
            );
        }
        // The watchdog's two-line form is unchanged by the new rule.
        let watchdog = report_for(
            &anyhow::anyhow!(
                "--state requires a path\nusage: aitm sysproxy-watchdog --pid <pid> --state <file> [--no-pipe]"
            ),
            None,
        );
        assert_eq!(watchdog.kind, ErrorKind::Usage);
        assert_eq!(watchdog.what, "--state requires a path");

        for not_usage in [
            "reading config file --config requires a path",
            "the proxy requires a path",
            "--config: No such file or directory",
            "--configrequires a path",
        ] {
            let report = report_for(&anyhow::anyhow!("{not_usage}"), None);
            assert_eq!(report.kind, ErrorKind::Failure, "{not_usage:?}");
            assert_eq!(report.exit_code(), 1, "{not_usage:?}");
            assert_eq!(report.command, None, "{not_usage:?}");
        }
    }

    #[test]
    fn report_for_usage_drops_the_registry_dump() {
        // The dispatcher appends its whole command list; the panel keeps only
        // the headline and points at `aitm --help` instead (plan C15).
        let dumped = "expected a command before flags, got `--x`\nusage: aitm <command> [--flag value]...\n(a value that itself starts with `--` must be given as --flag=value;\n--yes answers a command's confirmation prompt without asking)\n\ncommands:\n  flow list\n";
        let report = report_for(&anyhow::anyhow!("{dumped}"), None);
        assert_eq!(report.kind, ErrorKind::Usage);
        assert_eq!(report.exit_code(), 2);
        assert_eq!(report.what, "expected a command before flags, got `--x`");
        assert_eq!(report.why, Vec::<String>::new());
        assert_eq!(report.command, Some(FixCommand("aitm --help".to_string())));

        // A mode parser's two-line error keeps its own usage line verbatim as
        // the cause (spec AC-W1-14, D13: mode usage errors print their line,
        // exit 2).
        let two_line =
            "unknown argument `x`\nusage: aitm [--config <path>] operator-token generate [--force]";
        let report = report_for(&anyhow::anyhow!("{two_line}"), None);
        assert_eq!(report.what, "unknown argument `x`");
        assert_eq!(
            report.why,
            vec!["usage: aitm [--config <path>] operator-token generate [--force]".to_string()]
        );
        assert_eq!(report.kind, ErrorKind::Usage);
        assert_eq!(report.exit_code(), 2);

        // The watchdog pin's inputs (`sysproxy_watchdog_dispatch.rs`).
        let watchdog = "--state requires a path\nusage: aitm sysproxy-watchdog --pid <pid> --state <file> [--no-pipe]";
        let report = report_for(&anyhow::anyhow!("{watchdog}"), None);
        assert_eq!(report.what, "--state requires a path");
        assert_eq!(
            report.why,
            vec![
                "usage: aitm sysproxy-watchdog --pid <pid> --state <file> [--no-pipe]".to_string()
            ]
        );
        assert_eq!(report.exit_code(), 2);
    }

    #[test]
    fn report_for_generic_error_chains_every_source() {
        let err = anyhow::anyhow!("inner").context("middle").context("top");
        let report = report_for(&err, None);
        assert_eq!(report.kind, ErrorKind::Failure);
        assert_eq!(report.exit_code(), 1);
        assert_eq!(report.what, "top");
        assert_eq!(report.why, vec!["middle".to_string(), "inner".to_string()]);
        assert_eq!(report.fix, None);
        assert_eq!(report.command, None);
        assert_eq!(report.log, None);
        assert_eq!(
            report_for(&err, Some(Path::new(LOG))).log,
            Some(PathBuf::from(LOG))
        );
    }

    #[test]
    fn display_and_source_of_the_other_variants() {
        let config = StartupError::ConfigFile {
            path: PathBuf::from("/x/cfg.yaml"),
            source: anyhow::anyhow!("parsing config YAML"),
        };
        assert_eq!(config.to_string(), "in config file /x/cfg.yaml");
        assert_eq!(
            std::error::Error::source(&config).map(ToString::to_string),
            Some("parsing config YAML".to_string())
        );

        let strict = StartupError::StrictScripts { failed: 1 };
        assert_eq!(
            strict.to_string(),
            "1 script(s) failed to load and `rhai.strict` is set"
        );
        assert!(std::error::Error::source(&strict).is_none());

        let log = StartupError::LogFile {
            path: PathBuf::from("/x/logs/aitm.log"),
            source: io::Error::from(io::ErrorKind::PermissionDenied),
        };
        assert_eq!(
            log.to_string(),
            "log file unavailable: /x/logs/aitm.log (permission denied)"
        );
        assert_eq!(
            std::error::Error::source(&log).map(ToString::to_string),
            Some("permission denied".to_string())
        );
    }

    // ---- tester, whole-branch pass (spec D6 rules 1–5, plan C15) ----

    fn addr6() -> SocketAddr {
        "[::1]:8080".parse().expect("literal socket address")
    }

    /// Degenerate shapes stay deterministic and never panic: an empty
    /// message is an empty-headlined failure; a bare `usage:` is a usage
    /// headline; an empty first line followed by a usage line makes that line
    /// the cause; the registry dump header as the first line keeps only the
    /// header; blank lines before the dump are dropped and indented detail
    /// lines are kept verbatim; the prefix match is on the first line only
    /// and is case-sensitive.
    #[test]
    fn report_for_degenerate_usage_shapes() {
        let empty = report_for(&anyhow::anyhow!(""), None);
        assert_eq!(
            empty,
            ErrorReport {
                kind: ErrorKind::Failure,
                what: String::new(),
                why: Vec::new(),
                fix: None,
                command: None,
                log: None,
            }
        );
        assert_eq!(empty.exit_code(), 1);

        let bare = report_for(&anyhow::anyhow!("usage:"), None);
        assert_eq!(bare.kind, ErrorKind::Usage);
        assert_eq!(bare.exit_code(), 2);
        assert_eq!(bare.what, "usage:");
        assert_eq!(bare.why, Vec::<String>::new());
        assert_eq!(bare.command, Some(FixCommand("aitm --help".to_string())));

        let led = report_for(&anyhow::anyhow!("\nusage: aitm x"), None);
        assert_eq!(led.kind, ErrorKind::Usage);
        assert_eq!(led.what, "");
        assert_eq!(led.why, vec!["usage: aitm x".to_string()]);

        let dump = "usage: aitm <command> [--flag value]...\n(a value that itself starts with `--` must be given as --flag=value)\n\ncommands:\n  flow list\n";
        let report = report_for(&anyhow::anyhow!("{dump}"), None);
        assert_eq!(report.kind, ErrorKind::Usage);
        assert_eq!(report.what, "usage: aitm <command> [--flag value]...");
        assert_eq!(report.why, Vec::<String>::new());
        assert_eq!(report.command, Some(FixCommand("aitm --help".to_string())));

        let spaced = "unknown flag --x for `a.b`\n\n  accepted: y, z\n   \nusage: aitm <command> [--flag value]...\ncommands:\n  a b\n";
        let report = report_for(&anyhow::anyhow!("{spaced}"), None);
        assert_eq!(report.kind, ErrorKind::Usage);
        assert_eq!(report.what, "unknown flag --x for `a.b`");
        assert_eq!(report.why, vec!["  accepted: y, z".to_string()]);

        // A later line that looks like a usage prefix does not make a failure
        // a usage error; the whole message stays the headline (rule 5).
        let later = report_for(&anyhow::anyhow!("boom\nunknown command `x`"), None);
        assert_eq!(later.kind, ErrorKind::Failure);
        assert_eq!(later.exit_code(), 1);
        assert_eq!(later.what, "boom\nunknown command `x`");
        assert_eq!(later.why, Vec::<String>::new());
        assert_eq!(later.command, None);

        let cased = report_for(&anyhow::anyhow!("Unknown command `x`"), None);
        assert_eq!(cased.kind, ErrorKind::Failure, "the prefixes are lowercase");
        let cased = report_for(&anyhow::anyhow!("Usage: aitm x"), None);
        assert_eq!(cased.kind, ErrorKind::Failure, "`usage:` is lowercase");
    }

    /// Rule order: a typed error anywhere in the chain beats a usage-looking
    /// top message, however deep the contexts are.
    #[test]
    fn report_for_prefers_the_typed_error_over_a_usage_looking_context() {
        let err = anyhow::Error::new(port_in_use()).context("unknown command `x`");
        assert_eq!(report_for(&err, None), m2_report().with_log(None));

        let deep = anyhow::Error::new(port_in_use())
            .context("binding ports")
            .context("starting")
            .context("expected a command before flags, got `--x`");
        assert_eq!(
            report_for(&deep, Some(Path::new(LOG))),
            m2_report(),
            "three contexts deep, the M2 fields still win"
        );

        let strict = anyhow::Error::new(StartupError::StrictScripts { failed: 3 })
            .context("loading detections");
        let report = report_for(&strict, None);
        assert_eq!(
            report.what,
            "3 script(s) failed to load and `rhai.strict` is set"
        );
        assert_eq!(report.why, Vec::<String>::new());
        assert_eq!(
            report.fix.as_deref(),
            Some("Fix the scripts above, or unset rhai.strict.")
        );
        assert_eq!(report.kind, ErrorKind::Failure);

        let config = anyhow::Error::new(StartupError::ConfigFile {
            path: PathBuf::from("/x/cfg.yaml"),
            source: anyhow::anyhow!("bad yaml").context("parsing config YAML"),
        })
        .context("reading config");
        let report = report_for(&config, None);
        assert_eq!(report.what, "in config file /x/cfg.yaml");
        assert_eq!(
            report.why,
            vec!["parsing config YAML".to_string(), "bad yaml".to_string()],
            "the outer context is not a cause: the typed source chain is"
        );
    }

    /// `LogFile` is never fatal and has no panel of its own; should it ever
    /// be returned it falls through to rule 5 with its source as the cause.
    #[test]
    fn report_for_log_file_variant_falls_through_to_the_generic_chain() {
        let err = anyhow::Error::new(StartupError::LogFile {
            path: PathBuf::from("/x/logs/aitm.log"),
            source: io::Error::from(io::ErrorKind::PermissionDenied),
        });
        assert_eq!(
            report_for(&err, None),
            ErrorReport {
                kind: ErrorKind::Failure,
                what: "log file unavailable: /x/logs/aitm.log (permission denied)".to_string(),
                why: vec!["permission denied".to_string()],
                fix: None,
                command: None,
                log: None,
            }
        );
    }

    /// Rule 2's corners: a source equal to the headline is filtered out of
    /// the causes; a `NotFound` three levels deep still picks the create
    /// remedy; any other `io::Error` kind picks the fix-the-file remedy.
    #[test]
    fn report_for_config_file_source_corners() {
        let same = anyhow::Error::new(StartupError::ConfigFile {
            path: PathBuf::from("/x/cfg.yaml"),
            source: anyhow::anyhow!("in config file /x/cfg.yaml"),
        });
        let report = report_for(&same, None);
        assert_eq!(report.what, "in config file /x/cfg.yaml");
        assert_eq!(report.why, Vec::<String>::new());
        assert_eq!(
            report.fix.as_deref(),
            Some("Fix the file, or pass --config <path> to use another.")
        );

        let deep = anyhow::Error::new(StartupError::ConfigFile {
            path: PathBuf::from("/x/cfg.yaml"),
            source: anyhow::anyhow!(io::Error::new(io::ErrorKind::NotFound, "nope"))
                .context("a")
                .context("b"),
        });
        let report = report_for(&deep, None);
        assert_eq!(
            report.why,
            vec!["b".to_string(), "a".to_string(), "nope".to_string()]
        );
        assert_eq!(
            report.fix.as_deref(),
            Some("Create it, or run without --config to use the defaults.")
        );

        let denied = anyhow::Error::new(StartupError::ConfigFile {
            path: PathBuf::from("/x/cfg.yaml"),
            source: anyhow::anyhow!(io::Error::from(io::ErrorKind::PermissionDenied))
                .context("reading config file /x/cfg.yaml"),
        });
        let report = report_for(&denied, None);
        assert_eq!(
            report.why,
            vec![
                "reading config file /x/cfg.yaml".to_string(),
                "permission denied".to_string()
            ]
        );
        assert_eq!(
            report.fix.as_deref(),
            Some("Fix the file, or pass --config <path> to use another."),
            "only NotFound earns the create remedy"
        );
        assert_eq!(report.exit_code(), 1);
    }

    /// Rule 1 for the other two roles `main` binds, and for an IPv6 address:
    /// the headline carries the role and the full address, the command only
    /// the port.
    #[test]
    fn port_in_use_fields_for_the_other_roles_and_ipv6() {
        let browser = StartupError::PortInUse {
            role: "the embedded browser's proxy".to_string(),
            addr: "127.0.0.1:8081".parse().unwrap(),
            remedy: "Free it, or set `browser.proxy_addr:` to another address in /x.yaml."
                .to_string(),
        };
        let report = report_for(&anyhow::Error::new(browser), None);
        assert_eq!(
            report.what,
            "cannot start: the embedded browser's proxy port 127.0.0.1:8081 is already in use"
        );
        assert_eq!(
            report.fix.as_deref(),
            Some("Free it, or set `browser.proxy_addr:` to another address in /x.yaml.")
        );
        assert_eq!(
            report.command,
            Some(FixCommand("lsof -nP -iTCP:8081 -sTCP:LISTEN".to_string()))
        );
        assert_eq!(report.why, vec![HELD_BY.to_string()]);

        let web = StartupError::PortInUse {
            role: "the web UI".to_string(),
            addr: "127.0.0.1:8082".parse().unwrap(),
            remedy: "Free it, or pass `--listen 127.0.0.1:<port>` (env AITM_WEB_LISTEN)."
                .to_string(),
        };
        let report = report_for(&anyhow::Error::new(web), None);
        assert_eq!(
            report.what,
            "cannot start: the web UI port 127.0.0.1:8082 is already in use"
        );
        assert_eq!(
            report.command,
            Some(FixCommand("lsof -nP -iTCP:8082 -sTCP:LISTEN".to_string()))
        );

        let v6 = StartupError::PortInUse {
            role: "the proxy".to_string(),
            addr: addr6(),
            remedy: remedy(),
        };
        assert_eq!(
            v6.to_string(),
            format!(
                "cannot start: the proxy port [::1]:8080 is already in use.\n{HELD_BY}\n{}\nFind the holder with:  lsof -nP -iTCP:8080 -sTCP:LISTEN",
                remedy()
            )
        );
        let report = report_for(&anyhow::Error::new(v6), None);
        assert_eq!(
            report.what,
            "cannot start: the proxy port [::1]:8080 is already in use"
        );
        assert_eq!(
            report.command,
            Some(FixCommand("lsof -nP -iTCP:8080 -sTCP:LISTEN".to_string()))
        );
    }

    /// AC-W1-3's literal strings, end to end through the plain panel (M2
    /// piped): the headline, the held-by sentence, the remedy, the trimmed
    /// `fix: lsof …` line and the `log:` footer, in that order, with no
    /// `os error` text and no escape byte.
    #[test]
    fn port_in_use_plain_panel_is_m2_piped_verbatim() {
        let report = report_for(&anyhow::Error::new(port_in_use()), Some(Path::new(LOG)));
        let plain = report.render_plain(&aitm_term::glyphs::ASCII);
        assert_eq!(
            plain,
            format!(
                "error: cannot start: the proxy port 127.0.0.1:8080 is already in use\n\
                 \x20 {HELD_BY}\n\
                 \x20 {}\n\
                 \x20 fix: lsof -nP -iTCP:8080 -sTCP:LISTEN\n\
                 \x20 log: {LOG}\n",
                remedy()
            )
        );
        assert!(!plain.contains("os error"));
        assert!(!plain.as_bytes().contains(&0x1b));
        assert_eq!(
            plain
                .lines()
                .filter(|l| l.trim() == "fix: lsof -nP -iTCP:8080 -sTCP:LISTEN")
                .count(),
            1
        );
    }
}
