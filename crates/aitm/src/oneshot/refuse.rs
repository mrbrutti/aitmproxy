//! The refusal panels of spec D9: what a one-shot says when it cannot run a
//! live verb on a core.
//!
//! Every panel is a W1 [`ErrorReport`] of kind `Failure` (exit 1, stdout
//! empty): the headline names what was tried, the `why` ends on the outcome
//! (`Nothing was changed.`, or `Whether anything changed is unknown.` when
//! the call may have reached the core), the `fix` is prose and the command is
//! true for the operator's situation. Every sentence is a literal here; the
//! caller adds the `Log` footer (`with_log`) and the renderer wraps, shortens
//! and sanitizes. Paths are printed in full (T6); a verb is its space form
//! (`scope add`); a token never appears in any text.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use aitm_term::error::ErrorReport;

/// The closing sentence of every `why` whose outcome is known.
pub(crate) const NOTHING_CHANGED: &str = "Nothing was changed.";
/// The closing sentence when the call may have reached the core.
pub(crate) const OUTCOME_UNKNOWN: &str = "Whether anything changed is unknown.";
/// The substring every `Frontend::Cli`-only gate sentence carries (research
/// F14): `tls passthrough add|remove`, `map add|remove`, `session save|load`
/// and `flow export|import` with a path, `script validate --path`.
pub(crate) const GATE_MARK: &str = "from an agent frontend";

const START_OR_SCOPE_PAGE: &str = "Start aitm, or use the app's Scope page.";
const CHECK_LOG_THEN_RETRY: &str = "Check the core's log, then retry.";
const START_COMMAND: &str = "aitm";

/// A running core as a panel names it: from a pointer, every field is known;
/// a configured port knows only the address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoreRef {
    pub addr: SocketAddr,
    pub pid: Option<u32>,
    pub started_unix: Option<u64>,
    pub config: Option<PathBuf>,
}

/// Where the operator token a core refused came from. Carries the locator,
/// never the token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenSource {
    /// `mcp.operator_token` of this config file.
    Config(PathBuf),
    /// `--token-file <path>`.
    TokenFile(PathBuf),
    /// `AITM_BUS_TOKEN`.
    Env,
}

/// **R1** — nothing found to dial: no explicit address, no configured
/// loopback transport, no live pointer.
pub fn nothing_found(
    verb: &str,
    config: &Path,
    run_dir: &Path,
    explicit_config: bool,
) -> ErrorReport {
    ErrorReport::failure("no running core found")
        .with_why(vec![format!(
            "Looked for a core started from {} and for any core published under {}; none is \
             running, so {} has nothing to change. {NOTHING_CHANGED}",
            config.display(),
            run_dir.display(),
            verb_words(verb)
        )])
        .with_fix(START_OR_SCOPE_PAGE)
        .with_command(start_command(config, explicit_config))
}

/// **R2** — the config's `mcp.transport.loopback_tcp.port` refuses the
/// connection. `others` are the live pointers found meanwhile, one sentence
/// each, so the operator can `--bus` one of them.
pub fn not_listening_config_port(
    verb: &str,
    addr: SocketAddr,
    config: &Path,
    explicit_config: bool,
    others: &[CoreRef],
    now: u64,
) -> ErrorReport {
    let mut why = vec![format!(
        "{} sets mcp.transport.loopback_tcp.port {}, but nothing is listening there, so {} has \
         nothing to change. {NOTHING_CHANGED}",
        config.display(),
        addr.port(),
        verb_words(verb)
    )];
    for other in others {
        let mut details = Vec::new();
        if let Some(pid) = other.pid {
            details.push(format!("pid {pid}"));
        }
        if let Some(started) = other.started_unix {
            details.push(format!("started {}", age_words(started, now)));
        }
        if let Some(path) = &other.config {
            details.push(format!("config {}", path.display()));
        }
        let details = if details.is_empty() {
            String::new()
        } else {
            format!(" ({})", details.join(", "))
        };
        why.push(format!(
            "A different core is running at {addr}{details}; pass --bus {addr} to use it.",
            addr = other.addr
        ));
    }
    ErrorReport::failure(format!("no running core at {addr}"))
        .with_why(why)
        .with_fix("Start aitm with that config, or use the app's Scope page.")
        .with_command(start_command(config, explicit_config))
}

/// **R2'** — the address `--bus` (or, `from_env`, `AITM_BUS`) named refuses
/// the connection.
pub fn not_listening_explicit(verb: &str, addr: SocketAddr, from_env: bool) -> ErrorReport {
    let named = if from_env { "AITM_BUS" } else { "--bus" };
    ErrorReport::failure(format!("no running core at {addr}"))
        .with_why(vec![format!(
            "Nothing is listening at the address {named} named, so {} has nothing to change. \
             {NOTHING_CHANGED}",
            verb_words(verb)
        )])
        .with_fix("Start aitm, or drop --bus to let aitm find the core.")
        .with_command(START_COMMAND)
}

/// **R3** — the config's `endpoint_file` names an address that refuses the
/// connection: the core that wrote it has exited.
pub fn stale_endpoint_file(
    addr: SocketAddr,
    endpoint_file: &Path,
    config: &Path,
    explicit_config: bool,
) -> ErrorReport {
    ErrorReport::failure(format!("no running core at {addr}"))
        .with_why(vec![format!(
            "The endpoint file {} names an address nothing is listening on; the core that wrote \
             it has exited. {NOTHING_CHANGED}",
            endpoint_file.display()
        )])
        .with_fix(START_OR_SCOPE_PAGE)
        .with_command(start_command(config, explicit_config))
}

/// **R4** — a pointer whose writer still holds the lock names an address that
/// refuses the connection. The pointer is kept; the panel says when to
/// delete it.
pub fn pointer_not_listening(
    verb: &str,
    addr: SocketAddr,
    pointer_path: &Path,
    pid: u32,
) -> ErrorReport {
    ErrorReport::failure(format!("no running core at {addr}"))
        .with_why(vec![format!(
            "The core pointer {} names process {pid}, which is running but not listening there, \
             so {} has nothing to change. If that core has exited, delete the file. \
             {NOTHING_CHANGED}",
            pointer_path.display(),
            verb_words(verb)
        )])
        .with_fix(START_OR_SCOPE_PAGE)
        .with_command(START_COMMAND)
}

/// **R5** — nothing found, and the loaded config has
/// `mcp.operator_bus.enabled: false` with a stdio or HTTP transport
/// (`transport_word` is `stdio` or `HTTP`). No command: there is no true one.
pub fn no_operator_bus_configured(config: &Path, transport_word: &str) -> ErrorReport {
    ErrorReport::failure(format!(
        "this config serves MCP over {transport_word} and no operator bus, which a second client \
         cannot reach"
    ))
    .with_why(vec![format!(
        "{} sets mcp.operator_bus.enabled: false, so a core started from it has no address a \
         one-shot can dial. {NOTHING_CHANGED}",
        config.display()
    )])
    .with_fix(format!(
        "Remove mcp.operator_bus.enabled: false from {} (or set mcp.transport.loopback_tcp and \
         mcp.operator_token) and restart aitm, or use the app's Scope page.",
        config.display()
    ))
}

/// **R6** — the resolved core has no operator token: the config's
/// `operator_token` is empty, or the pointer says `operator: false`. The
/// generate command is offered only when `config` exists.
pub fn no_operator_token(addr: SocketAddr, config: &Path, config_exists: bool) -> ErrorReport {
    let mut fix = String::from("Generate one and restart the core.");
    if !config_exists {
        fix.push_str(&format!(" Create {} first.", config.display()));
    }
    let report = ErrorReport::failure(format!("the core at {addr} has no operator token"))
        .with_why(vec![format!(
            "{} sets no mcp.operator_token, so a one-shot could only connect as an agent, and an \
             agent may not change Scope. {NOTHING_CHANGED}",
            config.display()
        )])
        .with_fix(fix);
    if config_exists {
        report.with_command("aitm operator-token generate")
    } else {
        report
    }
}

/// **R7** — the core answered `-32001`: it refused the token `source` named.
pub fn token_refused(addr: SocketAddr, source: &TokenSource) -> ErrorReport {
    let (why, fix) = match source {
        TokenSource::Config(_) => (
            format!(
                "The config changed after that core started; a rotated token only takes effect \
                 on restart. {NOTHING_CHANGED}"
            ),
            "Restart the core, or pass --config for the config it was started with.",
        ),
        TokenSource::TokenFile(_) | TokenSource::Env => (
            format!(
                "It matched neither the agent nor the operator token of that core. \
                 {NOTHING_CHANGED}"
            ),
            "Check the token, or drop --bus to let aitm find the core.",
        ),
    };
    ErrorReport::failure(format!(
        "the core at {addr} refused the operator token in {}",
        locator(source)
    ))
    .with_why(vec![why])
    .with_fix(fix)
}

/// Where a token came from, as a panel names it: the file's path, or the
/// variable's name. Never the token.
fn locator(source: &TokenSource) -> String {
    match source {
        TokenSource::Config(path) | TokenSource::TokenFile(path) => path.display().to_string(),
        TokenSource::Env => "AITM_BUS_TOKEN".to_string(),
    }
}

/// **R8** — `initialize` answered a role other than `operator`: the token
/// `source` named is that core's agent token. From a config, the fix and its
/// command rotate that config's token. From `--token-file` or
/// `AITM_BUS_TOKEN` (an explicit `--bus`/`AITM_BUS` core) the one-shot never
/// read that core's config, so no command it could offer is known to be true
/// (spec D9, 2026-11-01): the fix is prose and there is no command.
pub fn connected_as_agent(addr: SocketAddr, source: &TokenSource) -> ErrorReport {
    let report = ErrorReport::failure(format!("the core at {addr} would treat this as an agent"))
        .with_why(vec![format!(
            "The token in {} is that core's agent token, not its operator token, and an agent \
             may not change Scope. {NOTHING_CHANGED}",
            locator(source)
        )]);
    match source {
        TokenSource::Config(_) => report
            .with_fix("Set mcp.operator_token to a different value and restart the core.")
            .with_command("aitm operator-token generate --force"),
        TokenSource::TokenFile(_) | TokenSource::Env => report
            .with_fix("Pass that core's operator token, or drop --bus to let aitm find the core."),
    }
}

/// **R9** — the core's `isError` text is a `Frontend::Cli`-only gate
/// sentence ([`is_cli_only_gate`]). The headline is the core's sentence
/// verbatim (T6); every operator surface is refused by the same gate, so the
/// only true fix is the config key the sentence names, in `config` when the
/// one-shot resolved the core from a config (a configured transport or a
/// pointer), or in "the config that core was started with" when the core
/// was named by `--bus`/`AITM_BUS` and no file was read (spec D9,
/// 2026-11-01).
pub fn cli_only_gate(sentence: &str, addr: SocketAddr, config: Option<&Path>) -> ErrorReport {
    let fix = match config {
        Some(path) => format!(
            "Set the config key the sentence names in {} and restart the core.",
            path.display()
        ),
        None => "Set the config key the sentence names in the config that core was started \
                 with, and restart it."
            .to_string(),
    };
    ErrorReport::failure(sentence)
        .with_why(vec![format!(
            "This one-shot reached the core at {addr} as an operator; that verb admits only an \
             in-process CLI, which has no running core to change. The app and the TUI are \
             refused by the same gate. {NOTHING_CHANGED}"
        )])
        .with_fix(fix)
}

/// **R10** — the connection was accepted but `budget` elapsed before the
/// answer. `verb` is `None` for the handshake budget, before any verb is
/// sent: `… did not answer within 2 s`. The outcome is unknown.
pub fn no_answer(addr: SocketAddr, verb: Option<&str>, budget: Duration) -> ErrorReport {
    let answer = match verb {
        Some(verb) => format!("answer {} within", verb_words(verb)),
        None => "answer within".to_string(),
    };
    ErrorReport::failure(format!(
        "the core at {addr} accepted the connection but did not {answer} {}",
        budget_words(budget)
    ))
    .with_why(vec![format!(
        "The call may still be running there. {OUTCOME_UNKNOWN}"
    )])
    .with_fix(CHECK_LOG_THEN_RETRY)
}

/// **R11** — two or more live cores at the same preference. One line per
/// core, then whether they were started from `config`; the command keeps
/// `argv` as typed behind a literal `<addr>` placeholder.
pub fn two_cores(
    verb: &str,
    cores: &[CoreRef],
    config: &Path,
    now: u64,
    argv: &[String],
) -> ErrorReport {
    let count = cores.len();
    let what = if count == 2 {
        "two running cores found".to_string()
    } else {
        format!("{count} running cores found")
    };
    let mut why: Vec<String> = cores
        .iter()
        .map(|core| {
            let mut parts = vec![core.addr.to_string()];
            if let Some(pid) = core.pid {
                parts.push(format!("pid {pid}"));
            }
            if let Some(started) = core.started_unix {
                parts.push(format!("started {}", age_words(started, now)));
            }
            if let Some(path) = &core.config {
                parts.push(path.display().to_string());
            }
            parts.join(" · ")
        })
        .collect();
    let all_match = !cores.is_empty()
        && cores
            .iter()
            .all(|core| core.config.as_deref() == Some(config));
    let subject = match (all_match, count) {
        (true, 2) => "Both were started from",
        (true, _) => "All of them were started from",
        (false, 2) => "Neither was started from",
        (false, _) => "None of them was started from",
    };
    why.push(format!(
        "{subject} {}, so aitm cannot tell which one {} means. {NOTHING_CHANGED}",
        config.display(),
        verb_words(verb)
    ));
    let mut command = String::from("aitm --bus <addr>");
    for arg in argv {
        command.push(' ');
        command.push_str(arg);
    }
    ErrorReport::failure(what)
        .with_why(why)
        .with_fix(
            "Pass --bus with the address of the one you mean, or --config with the config it was \
             started with.",
        )
        .with_command(command)
}

/// **R12** — the connection dropped while the verb ran. `detail` is the bus
/// error's text; the outcome is unknown.
pub fn lost(addr: SocketAddr, verb: &str, detail: &str) -> ErrorReport {
    let detail = detail.strip_suffix('.').unwrap_or(detail);
    ErrorReport::failure(format!(
        "lost the core at {addr} while running {}",
        verb_words(verb)
    ))
    .with_why(vec![format!("{detail}. {OUTCOME_UNKNOWN}")])
    .with_fix(CHECK_LOG_THEN_RETRY)
}

/// **R15** — the token-bearing config is not a regular file owned by this
/// user (spec D7 rule 6), so no token was read and nothing was dialed.
pub fn foreign_config(path: &Path) -> ErrorReport {
    ErrorReport::failure(format!(
        "the config {} is not a regular file owned by this user",
        path.display()
    ))
    .with_why(vec![format!(
        "aitm reads an operator token only from a regular file it owns. {NOTHING_CHANGED}"
    )])
    .with_fix("Fix the file's owner, or pass --bus with --token-file.")
}

/// The core's own `isError` text as the headline, verbatim and alone (spec
/// D8 step 9, T6): the core already said what and why.
pub fn tool_failure(text: &str) -> ErrorReport {
    ErrorReport::failure(text)
}

/// Whether `text` is one of the four `Frontend::Cli`-only gate sentences
/// (research F14): each says the action is refused `from an agent frontend`.
pub fn is_cli_only_gate(text: &str) -> bool {
    text.contains(GATE_MARK)
}

/// A relative age for the panels (plan C17): `just now` under a minute,
/// then minutes, hours up to 48 h, then days. A start in the future reads
/// `just now`.
pub fn age_words(started_unix: u64, now: u64) -> String {
    let secs = now.saturating_sub(started_unix);
    if secs < 60 {
        "just now".to_string()
    } else if secs < 3_600 {
        format!("{} min ago", secs / 60)
    } else if secs < 48 * 3_600 {
        format!("{} h ago", secs / 3_600)
    } else {
        format!("{} d ago", secs / 86_400)
    }
}

/// A call budget as the panels print it: whole minutes as `<n> min`, else
/// `<n> s` (`2 s`, `30 s`, `10 min`).
pub fn budget_words(d: Duration) -> String {
    let secs = d.as_secs();
    if secs >= 60 && secs.is_multiple_of(60) {
        format!("{} min", secs / 60)
    } else {
        format!("{secs} s")
    }
}

/// The space form of a dotted verb name: `tls.passthrough.add` →
/// `tls passthrough add`. Dotted names never appear in prose we compose (T6).
pub fn verb_words(dotted: &str) -> String {
    dotted.replace('.', " ")
}

/// The one true start command: `aitm`, or `aitm --config <path>` when
/// `--config`/`AITM_CONFIG` named the config (`explicit`).
pub fn start_command(config: &Path, explicit: bool) -> String {
    if explicit {
        format!("{START_COMMAND} --config {}", config.display())
    } else {
        START_COMMAND.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aitm_term::caps::Caps;
    use aitm_term::error::{ErrorKind, FixCommand};
    use aitm_term::glyphs::RICH;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    const NOW: u64 = 1_762_000_000;
    const CFG: &str = "/Users/matt/Library/Application Support/aitmproxy/config.yaml";
    const RUN: &str = "/Users/matt/Library/Application Support/aitmproxy/run/cores";
    const LOG: &str = "/Users/matt/Library/Application Support/aitmproxy/logs/aitm.log";

    fn lo(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
    }

    fn args(tokens: &[&str]) -> Vec<String> {
        tokens.iter().map(|t| t.to_string()).collect()
    }

    /// A width-100 TTY that allows no colour: the panel of spec D9 R1.
    fn tty_100() -> Caps {
        Caps {
            tty: true,
            color: false,
            unicode: true,
            animate: true,
            width: 100,
            ci: false,
        }
    }

    fn other_core() -> CoreRef {
        CoreRef {
            addr: lo(50512),
            pid: Some(4821),
            started_unix: Some(NOW - 720),
            config: Some(PathBuf::from("/x/c.yaml")),
        }
    }

    #[test]
    fn r1_nothing_found_rich_and_plain() {
        let report = nothing_found("scope.add", Path::new(CFG), Path::new(RUN), false)
            .with_log(Some(PathBuf::from(LOG)));
        assert_eq!(report.kind, ErrorKind::Failure);
        assert_eq!(report.exit_code(), 1);

        // Spec D9, R1 piped block, copied verbatim (never wrapped).
        let plain = "\
error: no running core found
  Looked for a core started from /Users/matt/Library/Application Support/aitmproxy/config.yaml and for any core published under /Users/matt/Library/Application Support/aitmproxy/run/cores; none is running, so scope add has nothing to change. Nothing was changed.
  Start aitm, or use the app's Scope page.
  fix: aitm
  log: /Users/matt/Library/Application Support/aitmproxy/logs/aitm.log
";
        assert_eq!(report.render_plain(&RICH), plain);
        assert_eq!(
            report.render(&Caps::plain(), Some(Path::new("/Users/matt"))),
            plain
        );

        // Spec D9, R1 TTY block, copied verbatim; rendered rich at width 100,
        // no colour, home `/Users/matt`.
        let rich = "\
✕ no running core found
  Looked for a core started from /Users/matt/Library/Application Support/aitmproxy/config.yaml and
  for any core published under /Users/matt/Library/Application Support/aitmproxy/run/cores; none is
  running, so scope add has nothing to change. Nothing was changed.
  Start aitm, or use the app's Scope page.

  ▸ aitm

  Log           ~/Library/Application Support/aitmproxy/logs/aitm.log
";
        assert_eq!(
            report.render(&tty_100(), Some(Path::new("/Users/matt"))),
            rich
        );

        // `--config <path>` named one: the start command carries it.
        let explicit = nothing_found(
            "scope.add",
            Path::new("/etc/aitm.yaml"),
            Path::new(RUN),
            true,
        );
        assert_eq!(
            explicit.command,
            Some(FixCommand("aitm --config /etc/aitm.yaml".to_string()))
        );
        assert_eq!(explicit.log, None);
    }

    #[test]
    fn r2_names_the_other_core() {
        let report = not_listening_config_port(
            "scope.add",
            lo(9090),
            Path::new(CFG),
            false,
            &[other_core()],
            NOW,
        );
        assert_eq!(report.kind, ErrorKind::Failure);
        assert_eq!(report.what, "no running core at 127.0.0.1:9090");
        assert_eq!(
            report.why,
            vec![
                format!("{CFG} sets mcp.transport.loopback_tcp.port 9090, but nothing is listening there, so scope add has nothing to change. Nothing was changed."),
                "A different core is running at 127.0.0.1:50512 (pid 4821, started 12 min ago, config /x/c.yaml); pass --bus 127.0.0.1:50512 to use it.".to_string(),
            ]
        );
        assert_eq!(
            report.fix.as_deref(),
            Some("Start aitm with that config, or use the app's Scope page.")
        );
        assert_eq!(report.command, Some(FixCommand("aitm".to_string())));
        assert_eq!(report.log, None);

        // No other core: one sentence; an explicit config names itself in the command.
        let alone = not_listening_config_port(
            "scope.add",
            lo(9090),
            Path::new("/x/c.yaml"),
            true,
            &[],
            NOW,
        );
        assert_eq!(alone.why.len(), 1);
        assert_eq!(
            alone.command,
            Some(FixCommand("aitm --config /x/c.yaml".to_string()))
        );
    }

    #[test]
    fn r2prime_r3_r4_fields() {
        // R2' — `--bus`/`AITM_BUS` refuses.
        let flag = not_listening_explicit("scope.add", lo(1), false);
        assert_eq!(flag.kind, ErrorKind::Failure);
        assert_eq!(flag.what, "no running core at 127.0.0.1:1");
        assert_eq!(
            flag.why,
            vec!["Nothing is listening at the address --bus named, so scope add has nothing to change. Nothing was changed.".to_string()]
        );
        assert_eq!(
            flag.fix.as_deref(),
            Some("Start aitm, or drop --bus to let aitm find the core.")
        );
        assert_eq!(flag.command, Some(FixCommand("aitm".to_string())));
        let env = not_listening_explicit("scope.add", lo(1), true);
        assert_eq!(
            env.why,
            vec!["Nothing is listening at the address AITM_BUS named, so scope add has nothing to change. Nothing was changed.".to_string()]
        );

        // R3 — the config's endpoint file names a dead address.
        let r3 = stale_endpoint_file(
            lo(60680),
            Path::new("/run/aitm/bus.addr"),
            Path::new("/x/c.yaml"),
            true,
        );
        assert_eq!(r3.kind, ErrorKind::Failure);
        assert_eq!(r3.what, "no running core at 127.0.0.1:60680");
        assert_eq!(
            r3.why,
            vec!["The endpoint file /run/aitm/bus.addr names an address nothing is listening on; the core that wrote it has exited. Nothing was changed.".to_string()]
        );
        assert_eq!(
            r3.fix.as_deref(),
            Some("Start aitm, or use the app's Scope page.")
        );
        assert_eq!(
            r3.command,
            Some(FixCommand("aitm --config /x/c.yaml".to_string()))
        );
        let r3_default = stale_endpoint_file(
            lo(60680),
            Path::new("/run/aitm/bus.addr"),
            Path::new(CFG),
            false,
        );
        assert_eq!(r3_default.command, Some(FixCommand("aitm".to_string())));

        // R4 — a pointer whose writer holds the lock, its address refuses.
        let r4 = pointer_not_listening(
            "scope.add",
            lo(50512),
            Path::new("/Users/matt/Library/Application Support/aitmproxy/run/cores/4821.json"),
            4821,
        );
        assert_eq!(r4.kind, ErrorKind::Failure);
        assert_eq!(r4.what, "no running core at 127.0.0.1:50512");
        assert_eq!(
            r4.why,
            vec!["The core pointer /Users/matt/Library/Application Support/aitmproxy/run/cores/4821.json names process 4821, which is running but not listening there, so scope add has nothing to change. If that core has exited, delete the file. Nothing was changed.".to_string()]
        );
        assert_eq!(
            r4.fix.as_deref(),
            Some("Start aitm, or use the app's Scope page.")
        );
        assert_eq!(r4.command, Some(FixCommand("aitm".to_string())));
    }

    #[test]
    fn r5_r6_r7_r8_r9_r10_r11_r12_r15_fields() {
        // R5 — nothing found, the loaded config opts out.
        let r5 = no_operator_bus_configured(Path::new(CFG), "stdio");
        assert_eq!(r5.kind, ErrorKind::Failure);
        assert_eq!(
            r5.what,
            "this config serves MCP over stdio and no operator bus, which a second client cannot reach"
        );
        assert_eq!(
            r5.why,
            vec![format!("{CFG} sets mcp.operator_bus.enabled: false, so a core started from it has no address a one-shot can dial. Nothing was changed.")]
        );
        assert_eq!(
            r5.fix,
            Some(format!("Remove mcp.operator_bus.enabled: false from {CFG} (or set mcp.transport.loopback_tcp and mcp.operator_token) and restart aitm, or use the app's Scope page."))
        );
        assert_eq!(r5.command, None);
        assert_eq!(
            no_operator_bus_configured(Path::new(CFG), "HTTP").what,
            "this config serves MCP over HTTP and no operator bus, which a second client cannot reach"
        );

        // R6 — the resolved core has no operator token.
        let r6 = no_operator_token(lo(9090), Path::new(CFG), true);
        assert_eq!(r6.kind, ErrorKind::Failure);
        assert_eq!(r6.what, "the core at 127.0.0.1:9090 has no operator token");
        assert_eq!(
            r6.why,
            vec![format!("{CFG} sets no mcp.operator_token, so a one-shot could only connect as an agent, and an agent may not change Scope. Nothing was changed.")]
        );
        assert_eq!(
            r6.fix.as_deref(),
            Some("Generate one and restart the core.")
        );
        assert_eq!(
            r6.command,
            Some(FixCommand("aitm operator-token generate".to_string()))
        );
        let r6_missing = no_operator_token(lo(9090), Path::new(CFG), false);
        assert_eq!(
            r6_missing.fix,
            Some(format!(
                "Generate one and restart the core. Create {CFG} first."
            ))
        );
        assert_eq!(r6_missing.command, None);

        // R7 — `-32001`.
        let r7 = token_refused(lo(9090), &TokenSource::Config(PathBuf::from(CFG)));
        assert_eq!(r7.kind, ErrorKind::Failure);
        assert_eq!(
            r7.what,
            format!("the core at 127.0.0.1:9090 refused the operator token in {CFG}")
        );
        assert_eq!(
            r7.why,
            vec!["The config changed after that core started; a rotated token only takes effect on restart. Nothing was changed.".to_string()]
        );
        assert_eq!(
            r7.fix.as_deref(),
            Some("Restart the core, or pass --config for the config it was started with.")
        );
        assert_eq!(r7.command, None);
        let r7_file = token_refused(lo(9090), &TokenSource::TokenFile(PathBuf::from("/t/tok")));
        assert_eq!(
            r7_file.what,
            "the core at 127.0.0.1:9090 refused the operator token in /t/tok"
        );
        assert_eq!(
            r7_file.why,
            vec!["It matched neither the agent nor the operator token of that core. Nothing was changed.".to_string()]
        );
        assert_eq!(
            r7_file.fix.as_deref(),
            Some("Check the token, or drop --bus to let aitm find the core.")
        );
        assert_eq!(r7_file.command, None);
        let r7_env = token_refused(lo(9090), &TokenSource::Env);
        assert_eq!(
            r7_env.what,
            "the core at 127.0.0.1:9090 refused the operator token in AITM_BUS_TOKEN"
        );
        assert_eq!(r7_env.why, r7_file.why);
        assert_eq!(r7_env.fix, r7_file.fix);

        // R8 — `initialize.role` is not `operator`; the token from a config.
        let r8 = connected_as_agent(lo(9090), &TokenSource::Config(PathBuf::from(CFG)));
        assert_eq!(r8.kind, ErrorKind::Failure);
        assert_eq!(
            r8.what,
            "the core at 127.0.0.1:9090 would treat this as an agent"
        );
        assert_eq!(
            r8.why,
            vec![format!("The token in {CFG} is that core's agent token, not its operator token, and an agent may not change Scope. Nothing was changed.")]
        );
        assert_eq!(
            r8.fix.as_deref(),
            Some("Set mcp.operator_token to a different value and restart the core.")
        );
        assert_eq!(
            r8.command,
            Some(FixCommand(
                "aitm operator-token generate --force".to_string()
            ))
        );
        // R8 from `--token-file` / `AITM_BUS_TOKEN` (an explicit core): the
        // locator is the token's own, the fix is prose, no command (the
        // config command would rotate a token that core never read).
        let r8_file =
            connected_as_agent(lo(9090), &TokenSource::TokenFile(PathBuf::from("/t/tok")));
        assert_eq!(r8_file.kind, ErrorKind::Failure);
        assert_eq!(r8_file.what, r8.what);
        assert_eq!(
            r8_file.why,
            vec!["The token in /t/tok is that core's agent token, not its operator token, and an agent may not change Scope. Nothing was changed.".to_string()]
        );
        assert_eq!(
            r8_file.fix.as_deref(),
            Some("Pass that core's operator token, or drop --bus to let aitm find the core.")
        );
        assert_eq!(r8_file.command, None);
        let r8_env = connected_as_agent(lo(9090), &TokenSource::Env);
        assert_eq!(r8_env.what, r8.what);
        assert_eq!(
            r8_env.why,
            vec!["The token in AITM_BUS_TOKEN is that core's agent token, not its operator token, and an agent may not change Scope. Nothing was changed.".to_string()]
        );
        assert_eq!(r8_env.fix, r8_file.fix);
        assert_eq!(r8_env.command, None);

        // R9 — a Cli-only gate sentence from the core; the config is known.
        let sentence = "tls.passthrough.add refused: changing the TLS passthrough list from an agent frontend is disabled. Set tls.allow_agent_passthrough = true in the aitmproxy config to allow it, or change the list from the human CLI.";
        let r9 = cli_only_gate(sentence, lo(50512), Some(Path::new(CFG)));
        assert_eq!(r9.kind, ErrorKind::Failure);
        assert_eq!(r9.what, sentence);
        assert_eq!(
            r9.why,
            vec!["This one-shot reached the core at 127.0.0.1:50512 as an operator; that verb admits only an in-process CLI, which has no running core to change. The app and the TUI are refused by the same gate. Nothing was changed.".to_string()]
        );
        assert_eq!(
            r9.fix,
            Some(format!(
                "Set the config key the sentence names in {CFG} and restart the core."
            ))
        );
        assert_eq!(r9.command, None);
        // R9 for an explicit `--bus`/`AITM_BUS` core: no file was read, so
        // the fix names none.
        let r9_explicit = cli_only_gate(sentence, lo(50512), None);
        assert_eq!(r9_explicit.what, sentence);
        assert_eq!(r9_explicit.why, r9.why);
        assert_eq!(
            r9_explicit.fix.as_deref(),
            Some("Set the config key the sentence names in the config that core was started with, and restart it.")
        );
        assert_eq!(r9_explicit.command, None);

        // R10 — the budget elapses.
        let r10 = no_answer(lo(50512), Some("scope.add"), Duration::from_secs(30));
        assert_eq!(r10.kind, ErrorKind::Failure);
        assert_eq!(
            r10.what,
            "the core at 127.0.0.1:50512 accepted the connection but did not answer scope add within 30 s"
        );
        assert!(r10.what.ends_with("did not answer scope add within 30 s"));
        assert_eq!(
            r10.why,
            vec![
                "The call may still be running there. Whether anything changed is unknown."
                    .to_string()
            ]
        );
        assert_eq!(
            r10.fix.as_deref(),
            Some("Check the core's log, then retry.")
        );
        assert_eq!(r10.command, None);
        // The handshake budget elapses before any verb is sent: no verb.
        assert_eq!(
            no_answer(lo(50512), None, Duration::from_secs(2)).what,
            "the core at 127.0.0.1:50512 accepted the connection but did not answer within 2 s"
        );
        assert!(
            no_answer(lo(50512), Some("poc.run"), Duration::from_secs(600))
                .what
                .ends_with("did not answer poc run within 10 min")
        );

        // R11 — two or more live cores at the same preference.
        let cores = [
            CoreRef {
                addr: lo(50512),
                pid: Some(4821),
                started_unix: Some(NOW - 720),
                config: Some(PathBuf::from("/a/config.yaml")),
            },
            CoreRef {
                addr: lo(50600),
                pid: Some(4900),
                started_unix: Some(NOW - 30),
                config: Some(PathBuf::from("/b/config.yaml")),
            },
        ];
        let r11 = two_cores(
            "scope.list",
            &cores,
            Path::new("/c/config.yaml"),
            NOW,
            &args(&["scope", "list"]),
        );
        assert_eq!(r11.kind, ErrorKind::Failure);
        assert_eq!(r11.what, "two running cores found");
        assert_eq!(
            r11.why,
            vec![
                "127.0.0.1:50512 · pid 4821 · started 12 min ago · /a/config.yaml".to_string(),
                "127.0.0.1:50600 · pid 4900 · started just now · /b/config.yaml".to_string(),
                "Neither was started from /c/config.yaml, so aitm cannot tell which one scope list means. Nothing was changed.".to_string(),
            ]
        );
        assert_eq!(
            r11.fix.as_deref(),
            Some("Pass --bus with the address of the one you mean, or --config with the config it was started with.")
        );
        assert_eq!(
            r11.command,
            Some(FixCommand("aitm --bus <addr> scope list".to_string()))
        );
        // The tie among matching pointers.
        let matching = [
            CoreRef {
                config: Some(PathBuf::from("/a/config.yaml")),
                ..cores[0].clone()
            },
            CoreRef {
                config: Some(PathBuf::from("/a/config.yaml")),
                ..cores[1].clone()
            },
        ];
        let both = two_cores(
            "scope.list",
            &matching,
            Path::new("/a/config.yaml"),
            NOW,
            &args(&["scope", "list"]),
        );
        assert_eq!(both.why[2], "Both were started from /a/config.yaml, so aitm cannot tell which one scope list means. Nothing was changed.");
        // Three or more.
        let three = [
            cores[0].clone(),
            cores[1].clone(),
            CoreRef {
                addr: lo(50700),
                pid: Some(5000),
                started_unix: Some(NOW - 3 * 86400),
                config: Some(PathBuf::from("/d/config.yaml")),
            },
        ];
        let r11_3 = two_cores(
            "scope.add",
            &three,
            Path::new("/c/config.yaml"),
            NOW,
            &args(&["scope", "add", "--host", "x"]),
        );
        assert_eq!(r11_3.what, "3 running cores found");
        assert_eq!(r11_3.why.len(), 4);
        assert_eq!(
            r11_3.why[2],
            "127.0.0.1:50700 · pid 5000 · started 3 d ago · /d/config.yaml"
        );
        assert_eq!(r11_3.why[3], "None of them was started from /c/config.yaml, so aitm cannot tell which one scope add means. Nothing was changed.");
        assert_eq!(
            r11_3.command,
            Some(FixCommand(
                "aitm --bus <addr> scope add --host x".to_string()
            ))
        );

        // R12 — the connection drops mid-call.
        let r12 = lost(lo(50512), "scope.add", "connection reset by peer");
        assert_eq!(r12.kind, ErrorKind::Failure);
        assert_eq!(
            r12.what,
            "lost the core at 127.0.0.1:50512 while running scope add"
        );
        assert_eq!(
            r12.why,
            vec!["connection reset by peer. Whether anything changed is unknown.".to_string()]
        );
        assert_eq!(
            r12.fix.as_deref(),
            Some("Check the core's log, then retry.")
        );
        assert_eq!(r12.command, None);
        // A detail that already ends in a period is not given a second one.
        assert_eq!(
            lost(lo(50512), "scope.add", "transport closed.").why,
            vec!["transport closed. Whether anything changed is unknown.".to_string()]
        );

        // R15 — the token-bearing config is not a regular file owned by this user.
        let r15 = foreign_config(Path::new(CFG));
        assert_eq!(r15.kind, ErrorKind::Failure);
        assert_eq!(
            r15.what,
            format!("the config {CFG} is not a regular file owned by this user")
        );
        assert_eq!(
            r15.why,
            vec!["aitm reads an operator token only from a regular file it owns. Nothing was changed.".to_string()]
        );
        assert_eq!(
            r15.fix.as_deref(),
            Some("Fix the file's owner, or pass --bus with --token-file.")
        );
        assert_eq!(r15.command, None);

        // The core's own `isError` text, verbatim and alone (spec D8 step 9, T6).
        let tool = tool_failure("scope.add: \"\" is not a host");
        assert_eq!(tool.kind, ErrorKind::Failure);
        assert_eq!(tool.what, "scope.add: \"\" is not a host");
        assert_eq!(tool.why, Vec::<String>::new());
        assert_eq!(tool.fix, None);
        assert_eq!(tool.command, None);
        assert_eq!(tool.log, None);
    }

    /// Every variant renders rich and plain with its headline first, carries
    /// no escape byte, has no log until the caller adds one, and every `why`
    /// with a known outcome closes on `Nothing was changed.`
    #[test]
    fn every_variant_renders_rich_and_plain_and_states_the_outcome() {
        let cfg = Path::new(CFG);
        let known: Vec<(&str, ErrorReport)> = vec![
            ("R1", nothing_found("scope.add", cfg, Path::new(RUN), false)),
            (
                "R2",
                not_listening_config_port("scope.add", lo(9090), cfg, false, &[other_core()], NOW),
            ),
            ("R2'", not_listening_explicit("scope.add", lo(1), false)),
            (
                "R3",
                stale_endpoint_file(lo(60680), Path::new("/e/bus.addr"), cfg, false),
            ),
            (
                "R4",
                pointer_not_listening("scope.add", lo(50512), Path::new("/r/4821.json"), 4821),
            ),
            ("R5", no_operator_bus_configured(cfg, "stdio")),
            ("R6", no_operator_token(lo(9090), cfg, true)),
            (
                "R7",
                token_refused(lo(9090), &TokenSource::Config(cfg.to_path_buf())),
            ),
            (
                "R8",
                connected_as_agent(lo(9090), &TokenSource::Config(cfg.to_path_buf())),
            ),
            (
                "R8 token file",
                connected_as_agent(lo(9090), &TokenSource::TokenFile(PathBuf::from("/t/tok"))),
            ),
            ("R8 env", connected_as_agent(lo(9090), &TokenSource::Env)),
            (
                "R9",
                cli_only_gate(
                    "x refused: y from an agent frontend is disabled.",
                    lo(50512),
                    Some(cfg),
                ),
            ),
            (
                "R9 explicit",
                cli_only_gate(
                    "x refused: y from an agent frontend is disabled.",
                    lo(50512),
                    None,
                ),
            ),
            (
                "R11",
                two_cores(
                    "scope.list",
                    &[other_core(), other_core()],
                    cfg,
                    NOW,
                    &args(&["scope", "list"]),
                ),
            ),
            ("R15", foreign_config(cfg)),
        ];
        let unknown: Vec<(&str, ErrorReport)> = vec![
            (
                "R10",
                no_answer(lo(50512), Some("scope.add"), Duration::from_secs(30)),
            ),
            (
                "R10 handshake",
                no_answer(lo(50512), None, Duration::from_secs(2)),
            ),
            ("R12", lost(lo(50512), "scope.add", "reset")),
        ];
        for (id, report) in known.iter().chain(unknown.iter()) {
            assert_eq!(report.kind, ErrorKind::Failure, "{id}");
            assert_eq!(report.log, None, "{id}: the caller adds the log");
            assert!(!report.what.is_empty(), "{id}");
            let rich = report.render(&tty_100(), Some(Path::new("/Users/matt")));
            assert!(
                rich.starts_with(&format!("✕ {}\n", report.what)),
                "{id}: {rich:?}"
            );
            assert!(!rich.as_bytes().contains(&0x1b), "{id}: {rich:?}");
            let plain = report.render_plain(&RICH);
            assert!(
                plain.starts_with(&format!("error: {}\n", report.what)),
                "{id}: {plain:?}"
            );
            assert!(!plain.as_bytes().contains(&0x1b), "{id}: {plain:?}");
            assert!(!plain.contains("log:"), "{id}: {plain:?}");
        }
        // R2 states the outcome and then names the other core (spec D9's
        // own order), so the outcome sentence is pinned as present, not last.
        for (id, report) in &known {
            assert!(
                report
                    .why
                    .iter()
                    .any(|w| w.ends_with(" Nothing was changed.")),
                "{id}: {:?}",
                report.why
            );
        }
        for (id, report) in &unknown {
            let last = report
                .why
                .last()
                .unwrap_or_else(|| panic!("{id} has no why"));
            assert!(
                last.ends_with(" Whether anything changed is unknown."),
                "{id}: {last:?}"
            );
        }
    }

    #[test]
    fn age_and_budget_words() {
        assert_eq!(age_words(NOW - 30, NOW), "just now");
        assert_eq!(age_words(NOW, NOW), "just now");
        assert_eq!(age_words(NOW + 5, NOW), "just now");
        assert_eq!(age_words(NOW - 59, NOW), "just now");
        assert_eq!(age_words(NOW - 60, NOW), "1 min ago");
        assert_eq!(age_words(NOW - 720, NOW), "12 min ago");
        assert_eq!(age_words(NOW - 3599, NOW), "59 min ago");
        assert_eq!(age_words(NOW - 3600, NOW), "1 h ago");
        assert_eq!(age_words(NOW - 7200, NOW), "2 h ago");
        assert_eq!(age_words(NOW - 47 * 3600, NOW), "47 h ago");
        assert_eq!(age_words(NOW - 48 * 3600, NOW), "2 d ago");
        assert_eq!(age_words(NOW - 3 * 86400, NOW), "3 d ago");

        assert_eq!(budget_words(Duration::from_secs(2)), "2 s");
        assert_eq!(budget_words(Duration::from_secs(30)), "30 s");
        assert_eq!(budget_words(Duration::from_secs(600)), "10 min");
        assert_eq!(budget_words(Duration::from_secs(90)), "90 s");
        assert_eq!(budget_words(super::super::verbs::HANDSHAKE_BUDGET), "2 s");
        assert_eq!(budget_words(super::super::verbs::CALL_BUDGET), "30 s");
        assert_eq!(
            budget_words(super::super::verbs::LONG_CALL_BUDGET),
            "10 min"
        );

        assert_eq!(verb_words("tls.passthrough.add"), "tls passthrough add");
        assert_eq!(verb_words("scope.add"), "scope add");
        assert_eq!(verb_words("ca.status"), "ca status");

        assert_eq!(start_command(Path::new(CFG), false), "aitm");
        assert_eq!(
            start_command(Path::new("/etc/aitm.yaml"), true),
            "aitm --config /etc/aitm.yaml"
        );
    }

    #[test]
    fn is_cli_only_gate_matches_the_four_sentences() {
        // crates/aitm-plugin-passthrough/src/lib.rs (`{cmd}` is the verb).
        assert!(is_cli_only_gate(
            "tls.passthrough.add refused: changing the TLS passthrough list from an agent frontend is \
             disabled. Set tls.allow_agent_passthrough = true in the aitmproxy config to allow \
             it, or change the list from the human CLI."
        ));
        // crates/aitm-plugin-maprules/src/lib.rs
        assert!(is_cli_only_gate(
            "map authoring refused: adding or removing maps from an agent frontend is disabled. \
             Set maps.allow_agent_authoring = true in the aitmproxy config to allow it, or author \
             the map from the human CLI."
        ));
        // crates/aitm-plugin-sessionio/src/lib.rs
        assert!(is_cli_only_gate(
            "file I/O refused: reading or writing a host path from an agent frontend is \
             disabled. Set session_io.allow_agent_file_io = true in the aitmproxy config to \
             allow it, run the command from the human CLI, or pass `bytes` instead of `path`."
        ));
        // crates/aitm-plugin-rhai/src/commands.rs (`confine_validate`)
        assert!(is_cli_only_gate(
            "script.validate from an agent frontend may read only a .rhai file inside the \
             configured scripts/PoC directory (poc.dir); run it from the human CLI for an \
             arbitrary path"
        ));

        assert!(!is_cli_only_gate("scope.add: \"\" is not a host"));
        // The Rhai authoring gate admits trusted control (operators), so it is
        // not a Cli-only gate and its sentence does not match.
        assert!(!is_cli_only_gate(
            "script authoring refused: an agent frontend may not author scripts. \
             Set rhai.allow_agent_authoring = true in the aitmproxy config to allow it, \
             or author from the human CLI / operator UI."
        ));
        assert!(!is_cli_only_gate(""));
    }

    // ---- tester additions (stage 5, R14 pass 1) ----

    /// Tester — D10: every panel that names a token's *locator* prints the
    /// path or the variable name, never the token. The real file beside the
    /// panel holds `optoken-test-r7`; R7 for a config, a token file and the
    /// env, R6/R8/R15 for the config, rendered plain, rich and `Debug`.
    #[test]
    fn tester_token_refused_names_the_locator_never_the_token() {
        let dir = std::env::temp_dir().join(format!(
            "aitm-oneshot-refuse-tester-{}-{}",
            std::process::id(),
            NOW
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let tok = dir.join("tok");
        std::fs::write(&tok, "optoken-test-r7\n").unwrap();
        let cfg = dir.join("config.yaml");
        std::fs::write(&cfg, "mcp:\n  operator_token: optoken-test-r7\n").unwrap();

        let reports = [
            token_refused(lo(9090), &TokenSource::Config(cfg.clone())),
            token_refused(lo(9090), &TokenSource::TokenFile(tok.clone())),
            token_refused(lo(9090), &TokenSource::Env),
            no_operator_token(lo(9090), &cfg, true),
            connected_as_agent(lo(9090), &TokenSource::Config(cfg.clone())),
            connected_as_agent(lo(9090), &TokenSource::TokenFile(tok.clone())),
            foreign_config(&cfg),
        ];
        for report in &reports {
            let report = report.clone().with_log(Some(PathBuf::from(LOG)));
            for text in [
                report.render_plain(&RICH),
                report.render(&tty_100(), Some(Path::new("/Users/matt"))),
                format!("{report:?}"),
            ] {
                assert!(!text.contains("optoken-test"), "{text}");
            }
        }
        let plain = reports[0].render_plain(&RICH);
        assert!(plain.contains(cfg.to_str().unwrap()), "{plain}");
        let plain = reports[1].render_plain(&RICH);
        assert!(plain.contains(tok.to_str().unwrap()), "{plain}");
        assert_eq!(
            reports[2].what,
            "the core at 127.0.0.1:9090 refused the operator token in AITM_BUS_TOKEN"
        );
        assert_eq!(
            format!("{:?}", TokenSource::TokenFile(tok.clone())),
            format!("TokenFile({tok:?})")
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Tester — R2 with a pointer that knows nothing but its address (a
    /// `CoreRef` with every option `None`) prints no empty parenthesis; R11
    /// with such a core prints the address alone on its line.
    #[test]
    fn tester_bare_core_refs_print_no_empty_details() {
        let bare = CoreRef {
            addr: lo(50512),
            pid: None,
            started_unix: None,
            config: None,
        };
        let r2 = not_listening_config_port(
            "scope.add",
            lo(9090),
            Path::new(CFG),
            false,
            std::slice::from_ref(&bare),
            NOW,
        );
        assert_eq!(
            r2.why[1],
            "A different core is running at 127.0.0.1:50512; pass --bus 127.0.0.1:50512 to use it."
        );
        let r11 = two_cores(
            "scope.list",
            &[bare.clone(), bare],
            Path::new(CFG),
            NOW,
            &args(&["scope", "list"]),
        );
        assert_eq!(r11.why[0], "127.0.0.1:50512");
        assert_eq!(r11.why[1], "127.0.0.1:50512");
        assert!(
            r11.why[2].starts_with("Neither was started from"),
            "{:?}",
            r11.why
        );
    }

    /// Tester — the R11 command keeps argv exactly as typed (a value with a
    /// space is not re-quoted; the renderer sanitizes control bytes later),
    /// and an empty argv leaves the bare placeholder.
    #[test]
    fn tester_two_cores_command_keeps_argv_verbatim() {
        let cores = [other_core(), other_core()];
        let with_space = two_cores(
            "scope.add",
            &cores,
            Path::new(CFG),
            NOW,
            &args(&["scope", "add", "--host", "a b"]),
        );
        assert_eq!(
            with_space.command,
            Some(FixCommand(
                "aitm --bus <addr> scope add --host a b".to_string()
            ))
        );
        let none = two_cores("scope.add", &cores, Path::new(CFG), NOW, &[]);
        assert_eq!(
            none.command,
            Some(FixCommand("aitm --bus <addr>".to_string()))
        );
    }
}
