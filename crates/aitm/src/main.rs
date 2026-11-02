//! The `aitm` binary: build the proxy from config, then run the accept loop plus
//! the selected MCP transport, or dispatch a one-shot CLI command.
//!
//! Config comes from `--config <path>` (a leading flag stripped before CLI
//! dispatch), else `AITM_CONFIG`, else the default path (spec §D10); the env
//! bridge (`aitm::env`) is applied on top. Invoked with a subcommand (`aitm flow
//! list`, `aitm scope add --host ex.test`) it hands the verb to
//! `aitm::oneshot::run` — a local verb runs in-process, a live one on the
//! running core (R14 spec D6/D8) — writes the rendered bytes to stdout, and
//! exits. Invoked bare it starts
//! the proxy accept loop and the MCP server (stdio or loopback-TCP per config),
//! with the configured browser engine attached when it launches, and closes
//! the browser on every orderly exit path including SIGINT/SIGTERM (spec §D6).
//! Invoked as `aitm tui` it does the same but with the terminal operator UI in
//! the process too, over an in-process bus channel (`aitm::tui`).
//! `aitm web [--listen ADDR] [--token TOKEN] [--no-open]` is the server path
//! plus the embedded web UI and its `/bus` bridge (`aitm::web`, F15).
//!
//! Every serving mode writes the durable audit file (`mcp.audit_log`, on by
//! default; `aitm::audit_log`): it starts before any port is bound, so an
//! explicit path that cannot be used fails the boot, and it is flushed on every
//! orderly exit. The bus and web tokens never reach it.

use std::future::Future;
use std::io::Write as _;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use aitm::config_file::Settings;
use aitm::macos_capture::feeder;
use aitm::macos_capture::peer_auth::CodeSignatureVerifier;
use aitm::oneshot::{self, args::BusArgs, run::OneShotError};
use aitm::operator_bus;
use aitm::operator_token::{self, Minted};
use aitm::scripts::LateHandles;
use aitm::startup::card::{ModeWord, ReadyInputs};
use aitm::startup::errors::{exit_with, report_for, StartupError};
use aitm::startup::log::{current_log_path, init_tracing, log_file_path, tui_log};
use aitm::startup::{self, TermOpts};
use aitm::tui::TuiLog;
use aitm::web::{self, WebArgs, WebCommand, WebState};
use aitm::wire::{
    assemble_with_scripts, build_capture_session, self_port_hook, Assembled, Features, ScriptWiring,
};
use aitm::{audit_log, config_file, env, tui};
use aitm_cli::{Confirmer, TtyConfirmer};
use aitm_core::{
    engine_may_reach_private, BrowserDriver, Chain, McpTransport, Plugin, NOTHING_DECRYPTED_ADVICE,
};
use aitm_findings::FindingsPlugin;
use aitm_mcp::pointer::{self, PointerContext};
use aitm_plugin_rhai::{MemoryFindingSink, ScriptEntry, ScriptServices};
use aitm_plugin_scanner::jobs::ScanServices;
use aitm_sysproxy::watchdog::{self, WatchdogArgs};
use aitm_sysproxy::{Recovery, SystemProxy};
use aitm_term::error::ErrorReport;
use aitm_term::reporter::Reporter;
use tokio::net::TcpListener;
use tracing::{info, warn};

/// The config file path when `--config` is not given.
const CONFIG_ENV: &str = "AITM_CONFIG";

/// What the command line asked for, after the `--config` and `--script` splits.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Mode {
    /// No arguments: the proxy plus the configured MCP transport.
    Server,
    /// A subcommand: one-shot dispatch over the CLI frontend.
    Cli(Vec<String>),
    /// `tui`: the proxy plus the terminal operator UI in one process.
    Tui,
    /// `web …`: the server path plus the embedded web UI and its `/bus`
    /// bridge; the options live beside in `WebArgs`.
    Web,
    /// `operator-token generate [--force]`: write a CSPRNG `mcp.operator_token`
    /// into the config file and exit, before any service is built (spec F2).
    /// CLI-only; never dispatched through the registry, so no agent can run it.
    OperatorToken { force: bool },
    /// `sysproxy-watchdog --pid <n> --state <path> [--no-pipe]`: the hidden
    /// system-proxy watchdog the core spawns on every successful set
    /// (system-proxy spec §D9 (b)). It waits for the core to die, then runs
    /// the restore rule over the state file. Never in usage text, never in
    /// the CLI registry; parsed here like `operator-token`.
    SysproxyWatchdog {
        pid: u32,
        state: PathBuf,
        no_pipe: bool,
    },
}

/// `operator-token`'s usage line (spec F2).
const OPERATOR_TOKEN_USAGE: &str =
    "usage: aitm [--config <path>] operator-token generate [--force]";

/// The hidden watchdog's usage line: printed only to a caller that spelled
/// the hidden subcommand itself and got its arguments wrong (exit 2).
const SYSPROXY_WATCHDOG_USAGE: &str =
    "usage: aitm sysproxy-watchdog --pid <pid> --state <file> [--no-pipe]";

/// Classify `argv`. `tui` takes no arguments; anything after it is a usage
/// error carrying the line to print. `web` is recognised here and its
/// options parsed by the caller (`web::parse_args`).
fn parse_mode(argv: Vec<String>) -> Result<Mode, String> {
    match argv.first().map(String::as_str) {
        None => Ok(Mode::Server),
        Some("tui") if argv.len() == 1 => Ok(Mode::Tui),
        Some("tui") => Err(tui::USAGE.to_string()),
        Some("web") => Ok(Mode::Web),
        Some("operator-token") => parse_operator_token(&argv[1..]),
        Some("sysproxy-watchdog") => parse_sysproxy_watchdog(&argv[1..]),
        Some(_) => Ok(Mode::Cli(argv)),
    }
}

/// Classify the arguments after `sysproxy-watchdog`: `--pid <n>` and
/// `--state <path>` are both required, `--no-pipe` is optional; anything else,
/// a missing value or a non-numeric pid is a usage error (the process exits
/// `watchdog::EXIT_BAD_ARGS`, 2, like every other usage error here).
fn parse_sysproxy_watchdog(rest: &[String]) -> Result<Mode, String> {
    let mut pid: Option<u32> = None;
    let mut state: Option<PathBuf> = None;
    let mut no_pipe = false;
    let mut args = rest.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--pid" => {
                let value = args
                    .next()
                    .ok_or_else(|| format!("--pid requires a value\n{SYSPROXY_WATCHDOG_USAGE}"))?;
                pid = Some(value.parse().map_err(|_| {
                    format!("--pid `{value}` is not a number\n{SYSPROXY_WATCHDOG_USAGE}")
                })?);
            }
            "--state" => {
                let value = args
                    .next()
                    .ok_or_else(|| format!("--state requires a path\n{SYSPROXY_WATCHDOG_USAGE}"))?;
                state = Some(PathBuf::from(value));
            }
            "--no-pipe" => no_pipe = true,
            other => {
                return Err(format!(
                    "unknown argument `{other}`\n{SYSPROXY_WATCHDOG_USAGE}"
                ))
            }
        }
    }
    match (pid, state) {
        (Some(pid), Some(state)) => Ok(Mode::SysproxyWatchdog {
            pid,
            state,
            no_pipe,
        }),
        _ => Err(SYSPROXY_WATCHDOG_USAGE.to_string()),
    }
}

/// Plan C5: the system-proxy engine's startup recovery and orderly-exit
/// restore run only for a process that serves (`Server`, `Tui`, `Web`). A
/// one-shot `Cli` dispatch, the token generator and the watchdog itself
/// never touch the system proxy from `main` (spec §D10).
fn manages_system_proxy(mode: &Mode) -> bool {
    matches!(mode, Mode::Server | Mode::Tui | Mode::Web)
}

/// What the pre-bind block of `run` hands back once every service port is
/// ours: the listeners and the addresses they actually bound.
struct Bound {
    proxy_listener: TcpListener,
    browser_listener: TcpListener,
    /// `aitm web`: the UI listener and its bound address.
    web_listener: Option<(TcpListener, std::net::SocketAddr)>,
    proxy_addr: std::net::SocketAddr,
    browser_addr: std::net::SocketAddr,
}

/// Pre-bind every service port, then — and only then — run the §D9 (c)
/// startup recovery (plan 2026-10-31-system-proxy-automation, fix F2). `bind`
/// is the whole pre-bind block of `run`; when it fails (the "already in use"
/// error) that error is returned and the system proxy is untouched: a core
/// that cannot serve must never point the OS at itself, so nothing is left
/// for the watchdog or the exit path to undo. Serving modes only (plan C5);
/// a one-shot process never reaches this. The recovery outcome comes back
/// beside the bound value (`Recovery::Nothing` when the mode does not manage
/// the system proxy) so `run` reports it only when it did something
/// (terminal-reporting plan C18).
async fn bind_then_recover_system_proxy<T, F>(
    mode: &Mode,
    sysproxy: &SystemProxy,
    auto: bool,
    bind: F,
) -> anyhow::Result<(T, Recovery)>
where
    F: Future<Output = anyhow::Result<T>>,
{
    let bound = bind.await?;
    let recovery = if manages_system_proxy(mode) {
        let recovery = sysproxy.recover_at_startup(auto);
        log_recovery("startup", &recovery);
        recovery
    } else {
        Recovery::Nothing
    };
    Ok((bound, recovery))
}

/// A recovery that failed is worth a `warn!` here; every other outcome the
/// engine already logs at `info` as it happens (plan Q1: one line per
/// event, not two). `phase` is `startup` (§D9 (c)) or `exit` (§D9 (a)).
fn log_recovery(phase: &str, recovery: &Recovery) {
    if let Recovery::Failed(msg) = recovery {
        warn!(phase, "system proxy: {msg}");
    }
}

/// Classify the arguments after `operator-token`. Only `generate [--force]` is
/// valid; an unknown sub-verb or flag is a usage error carrying the line to
/// print. This stays out of the CLI registry (spec F2) so no agent reaches it.
fn parse_operator_token(rest: &[String]) -> Result<Mode, String> {
    match rest.first().map(String::as_str) {
        Some("generate") => {
            let mut force = false;
            for arg in &rest[1..] {
                match arg.as_str() {
                    "--force" => force = true,
                    other => {
                        return Err(format!(
                            "unknown argument `{other}`\n{OPERATOR_TOKEN_USAGE}"
                        ))
                    }
                }
            }
            Ok(Mode::OperatorToken { force })
        }
        _ => Err(OPERATOR_TOKEN_USAGE.to_string()),
    }
}

/// What `main` settles from `argv` before any runtime, tracing sink or
/// service exists: the global flags split off, `aitm web`'s options parsed,
/// and the mode classified.
struct Invocation {
    config_arg: Option<PathBuf>,
    script_args: Vec<PathBuf>,
    bus_endpoint_file: Option<PathBuf>,
    /// The one-shot's own flags (R14 spec D7), split off before the mode.
    bus_args: BusArgs,
    web_args: Option<WebArgs>,
    mode: Mode,
    /// The global terminal flags (`-v`, `-vv`, `-q`, `--color`), split off
    /// before anything else (terminal-reporting spec D9).
    term: TermOpts,
}

/// The reporter a mode usage error renders through once the terminal flags
/// are known (spec D9, panel Q3): stderr with the caps `--color` and the
/// environment settle to, at the parsed verbosity. Only a `split_term_args`
/// failure, before any `TermOpts` exist, falls back to auto-detected caps.
fn usage_reporter(term: &TermOpts) -> Reporter {
    Reporter::stderr(term.detect_caps(), term.verbosity)
}

/// Classify `argv`. `None` when `aitm web --help` printed its usage and
/// there is nothing to run. A mode usage error renders its panel through
/// [`usage_reporter`] (so `--color`/`-q` hold) and exits 2; nothing has been
/// built yet, so nothing needs tearing down.
fn parse_invocation(argv: Vec<String>) -> anyhow::Result<Option<Invocation>> {
    let (term, argv) = match startup::split_term_args(argv) {
        Ok(split) => split,
        Err(text) => exit_with(&ErrorReport::usage(text), None),
    };
    let (config_arg, argv) = split_config_arg(argv)?;
    let (script_args, argv) = split_script_args(argv)?;
    let (bus_endpoint_file, argv) = split_bus_endpoint_file_arg(argv)?;
    let (bus_args, argv) = match oneshot::args::split_bus_args(argv) {
        Ok(split) => split,
        Err(text) => exit_with(&ErrorReport::usage(text), Some(&usage_reporter(&term))),
    };
    // `aitm web …` is the server path with the web UI attached; its options
    // are resolved before any config is loaded so `--help` and bad flags are
    // answered immediately.
    let web_args: Option<WebArgs> = match argv.first().map(String::as_str) {
        Some("web") => match web::parse_args(&argv[1..])? {
            WebCommand::Help => {
                startup::write_stdout(web::USAGE)?;
                return Ok(None);
            }
            WebCommand::Run(args) => Some(args),
        },
        _ => None,
    };
    let mode = match parse_mode(argv) {
        Ok(mode) => mode,
        Err(usage) => exit_with(
            &report_for(&anyhow::anyhow!(usage), None),
            Some(&usage_reporter(&term)),
        ),
    };
    Ok(Some(Invocation {
        config_arg,
        script_args,
        bus_endpoint_file,
        bus_args,
        web_args,
        mode,
        term,
    }))
}

/// The runtime is built by hand rather than with `#[tokio::main]` so its
/// workers get a stack sized for script evaluation: a hook runs on the worker
/// that dispatches it (`block_in_place`), and Rhai recurses once per nesting
/// level of a value — see `aitm_plugin_rhai::engine::WORKER_STACK_SIZE`.
fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    // `--version` / `--help` are answered before anything boots: no mode
    // parse, no runtime, no config read, no tracing sink (spec D8). A closed
    // stdout changes nothing: the text was all there was to say.
    if let Some(pre) = startup::pre_boot(&argv) {
        let _ = match pre {
            startup::PreBoot::Version => {
                startup::write_stdout(&format!("{}\n", startup::version_line()))
            }
            startup::PreBoot::Help => startup::write_stdout(startup::SYNOPSIS),
        };
        std::process::exit(0);
    }
    let invocation = match parse_invocation(argv) {
        Ok(Some(invocation)) => invocation,
        Ok(None) => return,
        Err(e) => exit_with(&report_for(&e, None), None),
    };
    // The one reporter for this process (spec D4): it draws the checklist in
    // the serving modes only (plan C4) and shortens paths to `~` on a TTY (C7).
    let caps = invocation.term.detect_caps();
    let reporter = Reporter::stderr(caps, invocation.term.verbosity)
        .checklist(matches!(
            invocation.mode,
            Mode::Server | Mode::Web | Mode::Tui
        ))
        .with_home(std::env::var_os("HOME").map(PathBuf::from));
    // The two modes that exit before anything is built — no config load, no
    // tracing sink, no service, no runtime — are dispatched here, in one
    // place, so `run` only ever sees a mode that serves something.
    match &invocation.mode {
        // The system-proxy watchdog (spec §D9 (b)) sleeps on stdin until the
        // core dies, then shells out to restore. Its parent nulled its
        // stdout/stderr, so it never prints; its exit code is the whole
        // report (0 done, 2 bad arguments, 3 restore failed).
        Mode::SysproxyWatchdog {
            pid,
            state,
            no_pipe,
        } => {
            std::process::exit(watchdog::run(&WatchdogArgs {
                pid: *pid,
                state: state.clone(),
                no_pipe: *no_pipe,
            }));
        }
        // `operator-token generate` edits the config file and exits; it must
        // run even if the current config would fail to assemble. The path is
        // resolved exactly as the rest of the binary does.
        Mode::OperatorToken { force } => {
            let config_path = invocation
                .config_arg
                .clone()
                .or_else(|| std::env::var_os(CONFIG_ENV).map(PathBuf::from))
                .unwrap_or_else(config_file::default_config_path);
            let written = match operator_token::generate_and_store(&config_path, *force) {
                Ok(written) => written,
                Err(e) => exit_with(&report_for(&e, None), Some(&reporter)),
            };
            let confirmation = format!("{}\n", operator_token::confirmation_message(&written));
            if let Err(e) = startup::write_stdout(&confirmation) {
                exit_with(&report_for(&anyhow::Error::new(e), None), Some(&reporter));
            }
            return;
        }
        Mode::Server | Mode::Cli(_) | Mode::Tui | Mode::Web => {}
    }
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_stack_size(aitm_plugin_rhai::engine::WORKER_STACK_SIZE)
        .build()
    {
        Ok(runtime) => runtime,
        Err(e) => exit_with(&report_for(&anyhow::Error::new(e), None), Some(&reporter)),
    };
    // On failure the panel is rendered through the same reporter the phases
    // used (`exit_with` ends the live region itself; a `finish()` first would
    // turn the TTY panel into its piped form), with the log file as footer.
    match runtime.block_on(run(invocation, reporter.clone())) {
        Ok(()) => reporter.finish(),
        Err(e) => exit_with(
            &report_for(&e, current_log_path().as_deref()),
            Some(&reporter),
        ),
    }
}

async fn run(invocation: Invocation, reporter: Reporter) -> anyhow::Result<()> {
    let Invocation {
        config_arg,
        script_args,
        bus_endpoint_file,
        bus_args,
        web_args,
        mode,
        term,
    } = invocation;
    // The header opens the checklist in the serving modes only (plan C4); a
    // one-shot verb prints nothing unless a phase runs long (spec D12).
    if manages_system_proxy(&mode) {
        reporter.header("aitmproxy", env!("CARGO_PKG_VERSION"));
    }
    let web_settings = match &web_args {
        Some(args) => Some(args.resolve(|k| std::env::var(k).ok())?),
        None => None,
    };
    // The log file and the three-layer tracing composition (spec D7, D11):
    // the file always; in tui mode nothing else, because ratatui owns the
    // terminal after the handover (plan C14). (`OperatorToken` and
    // `SysproxyWatchdog` never reach here: `main` dispatched both before the
    // runtime was built.)
    let tui = mode == Mode::Tui;
    let log_path = log_file_path(tui, &|k| std::env::var(k).ok());
    let sink = init_tracing(&term, &reporter, &log_path, tui);
    let tui_log = if tui {
        tui_log(&sink, &log_path)
    } else {
        TuiLog::Off
    };

    let config_path = config_arg.or_else(|| std::env::var_os(CONFIG_ENV).map(PathBuf::from));
    // The file `load_settings` reads, or the default it falls back to when
    // nothing names one: the phase line and the remedies name it.
    let effective_path = config_path
        .clone()
        .unwrap_or_else(config_file::default_config_path);
    let phase = reporter.phase("reading config");
    let Settings {
        core: mut cfg,
        rhai: mut rhai_cfg,
        mut l4,
        macos_capture,
        // The `system_proxy:` section: `wire.rs` builds the `SystemProxy`
        // engine from it, and `auto` drives the startup recovery below.
        system_proxy,
        // The `scanner:` section (spec D11): the scanner v2 engine's agent
        // gates, job limits, ceilings and profiles. It rides the binary-owned
        // feature set below, like the L4 config; assembly copies `findings.dir`
        // and `l4.allow_agent_inject` onto it.
        scanner,
    } = phase.finish_with(
        config_file::load_settings(config_path.as_deref()).map_err(|e| StartupError::ConfigFile {
            path: effective_path.clone(),
            source: e,
        }),
        |_| {
            if effective_path.exists() {
                format!("config {}", reporter.display_path(&effective_path))
            } else {
                format!(
                    "config defaults · {} not found",
                    reporter.display_path(&effective_path)
                )
            }
        },
    )?;
    env::apply(&mut cfg, |k| std::env::var(k).ok());
    env::apply_rhai(&mut rhai_cfg, |k| std::env::var(k).ok());
    // `--bus-endpoint-file` wins over the config's `endpoint_file`; it only means
    // anything for the loopback-TCP bus, so asking for it over stdio is an error.
    apply_bus_endpoint_file(&mut cfg.mcp.transport, bus_endpoint_file)?;
    // R14 spec D3/D4, serving modes only: a first run mints `mcp.operator_token`
    // into the config (a failure only turns the operator bus off); the pointer
    // context is published whatever the mint did, with the config path made
    // absolute (observation b).
    let mut mint_failure = None;
    if manages_system_proxy(&mode) {
        if cfg.mcp.operator_bus.enabled
            && cfg.mcp.operator_token.as_deref().is_none_or(str::is_empty)
        {
            match operator_token::mint_if_absent(&effective_path, config_path.is_none()) {
                Minted::Written { path, token } => {
                    let phase = reporter.phase("creating operator token");
                    cfg.mcp.operator_token = Some(token.expose().to_string());
                    phase.done(&format!(
                        "operator token written · {}",
                        reporter.display_path(&path)
                    ));
                }
                Minted::Present => {}
                Minted::Skipped { reason } => {
                    let what = format!(
                        "could not write mcp.operator_token to {}",
                        effective_path.display()
                    );
                    reporter.warn(&format!("operator access off: {what} · {reason}"));
                    mint_failure = Some(what);
                }
            }
        }
        // `run()` publishes once per process, so the first-publish answer is
        // not read. The path is absolute unless the cwd is unreadable, when the
        // pointer keeps it as typed and says so in the log.
        let _ = pointer::publish(PointerContext {
            config: std::path::absolute(&effective_path).unwrap_or_else(|err| {
                warn!(%err, "core pointer keeps the config path as typed");
                effective_path.clone()
            }),
            run_dir: pointer::run_dir(&|k| std::env::var(k).ok()),
        });
    }
    // The L4 module is opt-in (fail-closed) and carried outside `aitm-core`'s
    // `Config`; `AITM_L4_*` env overrides win over the file (M5-AC17). It rides the
    // binary-owned feature set below; `l4_privilege: None` runs the real startup probe.
    env::apply_l4(&mut l4, |k| std::env::var(k).ok());
    // A script's `browser.navigate` decides SSRF under the same policy as the
    // `browser.navigate` command.
    rhai_cfg.ssrf = cfg.browser.ssrf.clone();
    // `--script` entries come last, so they take the chain positions after the
    // config's (spec §8: config entries, then flags).
    rhai_cfg
        .scripts
        .extend(script_args.into_iter().map(ScriptEntry::new));

    // Ship-by-default detection catalogue (scripts/bundled → share/aitm/scripts):
    // passive OWASP/vuln detectors plus operator-invoked active/L4 command scripts.
    // Appended last and deduped by path, so a config `scripts:`, `AITM_SCRIPTS`,
    // or `--script` entry naming the same file wins (the bundled copy is skipped);
    // observe-only passives keep deny-by-default. `AITM_NO_BUNDLED_SCRIPTS` turns
    // the whole catalogue off, `AITM_BUNDLED_SCRIPTS` points it at another dir.
    aitm::bundled::apply(&mut rhai_cfg, |k| std::env::var(k).ok());

    // The tier is built before the proxy — a script compiles against the shared
    // engine, and the engine's host verbs close over these handles — so they are
    // bound to the proxy's real ones below, before anything is served.
    let handles = LateHandles::new();
    let findings = Arc::new(MemoryFindingSink::new());
    let script_services = ScriptServices {
        store: handles.clone(),
        client: handles.clone(),
        browser: Some(handles.clone()),
        guard: handles.clone(),
        findings,
        rt: tokio::runtime::Handle::current(),
    };
    let strict = rhai_cfg.strict;
    // L4 goes live on the ONE shared scripting engine (hooks, PoC `script:` steps,
    // `ScriptCommands`) when `l4.enabled`. The live `L4Language` shares the SAME
    // deny-by-default guard + flow store the `l4.*` command module will own (threaded
    // in via `Features::l4_shared` below), so a script's `l4.scope.add` and the bus
    // see one L4 engagement state. The agent gate is enforced per call on the live
    // caller trust — no build-time `agent_sourced` bool. Built before the tier because
    // the engine must install the language at build time; `None` when L4 is disabled
    // leaves the scripting engine without an `l4.*` namespace (deny-by-default).
    let l4_shared = l4.enabled.then(|| aitm::wire::L4Shared {
        guard: Arc::new(aitm_proto_l4::guard::L4Guard::new(&l4)),
        store: Arc::new(aitm_proto_l4::flow::InMemoryL4FlowStore::new()),
    });
    let l4_language = l4_shared.as_ref().map(|shared| {
        aitm_proto_l4::L4Language::new(
            shared.guard.clone(),
            Arc::new(aitm_proto_l4::backend::pcap::PcapBackend::new()),
            shared.store.clone(),
        )
    });
    // Scanner v2's `ws.*` script language slot (spec D1 and D8.3): the WS lane's
    // language from `aitm-scan-ws`, built with the SAME `LateHandles` the script
    // tier uses as its scope/rate guard, so every `ws.*` host fn is guarded: a
    // script cannot reach a host outside scope or past the rate limit. The slot is
    // `None` only when a build ships without the lane, and a `None` slot adds no
    // language — the engine then has no `ws.*` namespace (deny-by-default).
    // It dials under the SAME certificate policy as the WS *lane*
    // (`wire::collect_lanes_with`): `aitm::wire::ws_tls_policy(&cfg)` maps the
    // operator's `ssl_insecure` onto `TlsPolicy`, so a self-signed `wss://` lab
    // target behaves the same whether a script or a scan reached it. The default
    // (`ssl_insecure: false`) verifies the chain against the webpki roots.
    let ws_language =
        aitm_scan_ws::language::build_with(handles.clone(), aitm::wire::ws_tls_policy(&cfg));
    let mut languages: Vec<&dyn aitm_plugin::language::ProtocolLanguage> = Vec::new();
    if let Some(lang) = &l4_language {
        languages.push(lang);
    }
    if let Some(lang) = &ws_language {
        languages.push(lang.as_ref());
    }
    let phase = reporter.phase("loading detections");
    let tier = phase.finish_with(
        aitm_plugin_rhai::wire::build_with_languages(rhai_cfg, script_services, &languages),
        |tier| format!("{} detections ready", tier.host.set().names().len()),
    )?;
    // The language only had to live long enough to install its host fns on the engine
    // (which holds its own `Arc` clones of the shared state); drop the borrow so the
    // shared handle can move into `Features` below.
    drop(languages);
    // The l4 `l4:` PoC-step handler is built from the SAME live language instance, so
    // it shares the exact `Arc<L4Guard>` + `Arc<dyn L4FlowStore>` that go into
    // `Features::l4_shared` and the `L4Module`: one engagement state.
    let poc_step_handlers = {
        let mut r = aitm_poc::step_registry::PocStepRegistry::new();
        if let Some(lang) = &l4_language {
            if let Some(h) = aitm_plugin::language::ProtocolLanguage::poc_step(lang) {
                r.register(std::sync::Arc::from(h));
            }
        }
        // The same for the `ws.*` language's PoC step, from the same instance the
        // engine installed, so a `ws:` step and a script share one guarded surface.
        if let Some(lang) = &ws_language {
            if let Some(h) = aitm_plugin::language::ProtocolLanguage::poc_step(lang.as_ref()) {
                r.register(std::sync::Arc::from(h));
            }
        }
        r
    };
    drop(l4_language);
    drop(ws_language);
    for err in &tier.errors {
        warn!(target: "aitm::scripts", "{err}");
    }
    if strict && !tier.errors.is_empty() {
        return Err(StartupError::StrictScripts {
            failed: tier.errors.len(),
        }
        .into());
    }
    // The loader already logs one `loaded script` line per script (name, path,
    // hooks; target `aitm_plugin_rhai::loader`), so only the total is logged
    // here, and nothing at all when no script loaded (quiet default logs).
    let loaded = tier.host.set().names().len();
    if loaded > 0 {
        info!(
            target: "aitm::scripts",
            count = loaded,
            "scripts loaded into the host"
        );
    }
    // Scripts see bodies up to the proxy's configured cap; the engine's string
    // and blob limits default to the same figure, and must keep up with it.
    let max_body = cfg.limits.max_body_bytes;
    if max_body > tier.limits.max_string_size || max_body > tier.limits.max_array_size {
        warn!(
            target: "aitm::scripts",
            max_body_bytes = max_body,
            max_string_size = tier.limits.max_string_size,
            max_array_size = tier.limits.max_array_size,
            "limits.max_body_bytes exceeds the rhai string/blob limits; scripts reading a body \
             larger than those limits will fail (raise rhai.max_string_size / max_array_size)"
        );
    }

    // Built once, outside the call, so the same value both assembles the proxy and
    // tells `build_capture_session` below whether the macOS capture feeder is on.
    let features = Features {
        l4,
        l4_shared,
        macos_capture,
        // Self-exclusion (L4PAR-AC34, spec §2.1): the core's own listener ports the
        // config already names — the web UI port (`aitm web` only) and the agent
        // transport's port (loopback bus / MCP streamable HTTP). The proxy and
        // browser-proxy ports are added by assembly; the bound ports are unioned
        // in right after the listeners bind, below.
        l4_self_ports: web_settings
            .iter()
            .map(|settings| settings.listen.port())
            .chain(configured_agent_port(&cfg.mcp.transport))
            .collect(),
        system_proxy: system_proxy.clone(),
        scanner,
        ..Features::default()
    };
    // Whether assembly mints the CA or loads it is read off the key file's
    // existence before the call (`wire.rs` is frozen; spec D10).
    let had_key = cfg.ca.dir.join("ca.key").exists();
    let phase = reporter.phase("preparing CA");
    let assembled = assemble_with_scripts(
        &cfg,
        &features,
        ScriptWiring {
            // One host plugin dispatches every script from a single chain
            // position; it carries the proxy's body cap to each script's
            // snapshot, including any appended live by `script.save`.
            plugins: vec![Box::new(tier.host.with_max_body(max_body)) as Box<dyn Plugin>],
            executor: Some(tier.executor.clone()),
            poc_step_handlers,
            // Both command providers: the rhai tier (script.validate/reload,
            // script.findings) and the persistent findings store, whose
            // `findings.*` commands read the configured `findings.dir` from the
            // command host at invocation time (`FindingsPlugin::store_for`).
            commands: vec![Box::new(tier.commands), Box::new(FindingsPlugin::new())],
            // The checks every `reg.add_check` in a script declared (call B9).
            // The scanner is registered over this exact registry, so a scripted
            // check joins the catalogue and gets its `check.<id>` command.
            script_checks: Some(tier.checks.clone()),
        },
    );
    let assembled = phase.finish_with(assembled, |assembled| {
        format!(
            "CA {} · {}",
            if had_key { "loaded" } else { "created" },
            reporter.display_path(assembled.ca.cert_path())
        )
    })?;
    let governance = assembled.governance();
    let Assembled {
        proxy,
        ca,
        listening,
        agent_state,
        push_tx,
        audit_ring,
        // The protocol-general capture ingress and the live L4 guard feed the macOS
        // Network/System Extension capture session below (macOS builds with
        // `macos_capture.enabled` only). On every other build, or with it disabled
        // (the default), they are dropped unused: the pcap capture path is
        // `l4.capture.*`'s own and nothing calls `accept`.
        l4_ingress,
        l4_guard,
        // The write side of `capture.status`, consumed by the feeder below.
        capture_status,
        // The system-proxy engine: startup recovery before serving, restore on
        // the orderly exit path (system-proxy spec §D8, §D9 (a)/(c)).
        sysproxy,
        // The one job bus (spec D9.2): handed to every `McpServer` this binary
        // builds through the shared `tui::services`, so a job started on one
        // surface publishes where every surface's subscribers listen.
        job_bus,
        // The scanner's handle cell: bound below, beside `handles.bind_proxy`,
        // once the proxy's store, client and guard exist (call B3).
        scan_late,
        // The assembled scanner engine. Nothing on the run path reads it — the
        // verbs hold their own clone of it — so the binding is unused; it is
        // named rather than absorbed by `..` so a new `Assembled` field cannot
        // slip in unnoticed.
        scanner_engine: _scanner_engine,
        // `..` stands only for the private `governance` (taken above). Any new
        // `pub` field of `Assembled` must be named here, not absorbed by it.
        ..
    } = assembled;

    if let Mode::Cli(argv) = &mode {
        // One-shot CLI dispatch (no browser needed): the same service
        // handles the frontends share, without a browser or a log file.
        let s = tui::services(&proxy, &cfg, None, TuiLog::Off, job_bus.clone());
        handles.bind_proxy(s.store.clone(), s.client.clone(), s.guard.clone());
        // The scanner runs on the proxy's own handles too (spec D5, call B3):
        // a probe is scoped, rated and recorded exactly like any other request.
        // No browser on the one-shot CLI path — nothing launches one — so a
        // browser-crawl lane reports that rather than driving a dead handle.
        scan_late.bind(scan_services(
            &s,
            None,
            l4_guard.clone(),
            &agent_state,
            &cfg,
        ));
        tier.error_sink
            .bind(Arc::new(Chain::new(s.registry.clone(), s.store.clone())));
        // ONE confirmer for the local and the live path (R14 plan Q7); the
        // service `Arc`s are cloned so `s` stays whole for `Inputs.services`.
        let confirmer: Arc<dyn Confirmer> = Arc::new(TtyConfirmer::from_stdin());
        let cli = aitm_cli::Cli::new(s.registry.clone())
            .with_ssrf_policy(cfg.browser.ssrf.clone())
            .with_poc_dir(cfg.poc.dir.clone())
            .with_config(Arc::new(cfg.clone()))
            .with_finding_recorder(Arc::new(aitm_findings::DiskFindingRecorder))
            // The proxy's live egress posture, so `aitm browser confine` flips
            // the connector's real posture (Task 4b).
            .with_egress(s.egress.clone())
            .with_confirmer(confirmer.clone())
            .with_services(s.store.clone(), s.client.clone(), s.guard.clone(), None);
        // A local verb runs through `cli`; a live one reaches the running core (D8).
        match oneshot::run::run(oneshot::run::Inputs {
            argv,
            bus_args: &bus_args,
            cfg: &cfg,
            effective_path: &effective_path,
            explicit_config: config_path.is_some(),
            services: &s,
            cli,
            confirmer,
            reporter: &reporter,
            log: current_log_path().as_deref(),
            env: &|k| std::env::var(k).ok(),
        })
        .await
        {
            Ok(bytes) => {
                let mut stdout = std::io::stdout().lock();
                stdout.write_all(&bytes)?;
                stdout.flush()?;
                return Ok(());
            }
            Err(OneShotError::Report(report)) => exit_with(&report, Some(&reporter)),
            Err(OneShotError::Other(err)) => exit_with(
                &report_for(&err, current_log_path().as_deref()),
                Some(&reporter),
            ),
        }
    }

    // The durable audit log (spec Design 10): started once the one-shot CLI branch
    // has returned and before any port is pre-bound or the browser is spawned, so
    // an explicit `mcp.audit_log` that cannot be used fails the boot here with
    // nothing bound and nothing to undo. `audit_ring` is the ring every server
    // below shares, so the sink it carries audits all of them. The configured
    // tokens, the web agent bridge token (resolved above, before the config was
    // loaded) and the secret-looking environment are registered by `start` before
    // the sink is attached; a non-UTF-8 variable is skipped, never a panic.
    let env_pairs: Vec<(String, String)> = std::env::vars_os()
        .filter_map(|(k, v)| Some((k.into_string().ok()?, v.into_string().ok()?)))
        .collect();
    let audit = audit_log::start(
        &cfg,
        &audit_ring,
        web_settings.as_ref().map(|s| s.token.as_str()),
        &env_pairs,
    )?;

    // Pre-bind every service port up front, before obscura is spawned and before
    // any "listening" success line. A port conflict is then ONE clear, actionable
    // error here — which port, who likely holds it, how to change it — never a
    // cryptic os-error-48 printed after `aitm web` already announced the UI. This
    // covers bare `aitm`, `aitm tui` and `aitm web` alike: the proxy and the
    // browser's proxy port here, and the web UI port just below for `aitm web`.
    //
    // Only once every port is ours does §D9 (c) run (`bind_then_recover_system_proxy`,
    // fix F2): judge any leftover state file (reboot, power loss, a killed
    // watchdog) and, with `system_proxy.auto`, point the system proxy at this
    // core. A bind failure returns before that, so a core that cannot serve never
    // points the OS at itself. Serving modes only (plan C5); a one-shot process
    // returned above. Blocking shell-outs, but nothing is served yet.
    //
    // The bound addresses are read inside this block too: after the startup set,
    // the only fallible step before the `select!` is `operator_bus::start`, whose
    // error arm restores the system proxy itself (security S8), so the §D9 (a)
    // restore is reached on every path.
    let config_display = effective_path.display().to_string();
    let phase = reporter.phase("binding ports");
    let bound = bind_then_recover_system_proxy(&mode, &sysproxy, system_proxy.auto, async {
        let proxy_listener = bind_service_port(
            cfg.listen,
            "the proxy",
            &format!("Free it, or set `listen:` to another address in {config_display}."),
        )
        .await?;
        let browser_listener = bind_service_port(
            cfg.browser.proxy_addr,
            "the embedded browser's proxy",
            &format!(
                "Free it, or set `browser.proxy_addr:` to another address in {config_display}."
            ),
        )
        .await?;
        // `aitm web`: the UI port is pre-bound here too, so a web-port conflict is
        // caught before obscura spawns, not after. The collision against the proxy /
        // browser ports is named here because a shared address would otherwise
        // surface only as a bare "address in use".
        let web_listener = match &web_settings {
            Some(settings) => {
                for (what, addr) in [
                    ("proxy listen", cfg.listen),
                    ("browser.proxy_addr", cfg.browser.proxy_addr),
                ] {
                    anyhow::ensure!(
                        settings.listen != addr,
                        "web UI --listen {} collides with {what} ({addr}); pick another port",
                        settings.listen
                    );
                }
                let listener = bind_service_port(
                    settings.listen,
                    "the web UI",
                    "Free it, or pass `--listen 127.0.0.1:<port>` (env AITM_WEB_LISTEN).",
                )
                .await?;
                let bound = listener.local_addr()?;
                Some((listener, bound))
            }
            None => None,
        };
        let proxy_addr = proxy_listener.local_addr()?;
        let browser_addr = browser_listener.local_addr()?;
        Ok(Bound {
            proxy_listener,
            browser_listener,
            web_listener,
            proxy_addr,
            browser_addr,
        })
    })
    .await;
    let (
        Bound {
            proxy_listener,
            browser_listener,
            web_listener,
            proxy_addr,
            browser_addr,
        },
        recovery,
    ) = phase.finish_with(bound, |(bound, _)| {
        let mut summary = format!(
            "proxy listening {} · browser proxy {}",
            bound.proxy_addr, bound.browser_addr
        );
        if let Some((_, addr)) = &bound.web_listener {
            summary.push_str(&format!(" · web UI listening {addr}"));
        }
        summary
    })?;
    // Shown only when the recovery did something (plan C18); a failed one is
    // already a `warn!` that reaches the view through the tracing layer.
    if let Some(summary) = startup::card::recovery_summary(&recovery) {
        reporter.phase("restoring system proxy").done(&summary);
    }

    // Self-exclusion of the core's own listeners (L4PAR-AC34, spec §2.1): the
    // bound proxy, browser-proxy and (for `aitm web`) web UI ports top up the set
    // assembly seeded from the config, so a loopback capture never records the
    // bus's plaintext token line or any other frame to or from the core itself.
    // The agent transport's bound port (an ephemeral `0` included) is added by
    // `on_bound` below. Each step only adds; none can drop an earlier port.
    let l4_live_guard = features
        .l4_shared
        .as_ref()
        .map(|shared| shared.guard.clone());
    // Bound addresses from the pre-bind step: nothing fallible may run between
    // the system-proxy auto-set and the `select!` (its restore-on-exit depends on
    // it) except `operator_bus::start` below, which restores on its error arm.
    if let Some(guard) = &l4_live_guard {
        guard.add_self_ports(
            [proxy_addr.port(), browser_addr.port()]
                .into_iter()
                .chain(web_listener.as_ref().map(|(_, bound)| bound.port())),
        );
    }

    // Server path: launch the configured engine so the browser.* commands reach
    // a live driver. No fallback to the other engine.
    //
    // Derive obscura's `--allow-private-network` from the SSRF policy ∪ the seed
    // scope (audit I15): a scoped loopback/private target lifts the engine flag
    // under the strict default, while a pure-public scope keeps the engine as
    // narrow as the policy. The SSRF-filtering proxy connector stays the
    // authoritative per-host gate; this only narrows the engine below it. It is
    // frozen here at launch — a host added later (`scope.add`) is still gated by
    // the connector, but the engine reaches a newly private target only on
    // relaunch.
    let mut browser_cfg = cfg.browser.clone();
    browser_cfg.obscura.allow_private =
        engine_may_reach_private(&cfg.browser.ssrf, &cfg.scope.entries);
    let phase = reporter.phase("starting obscura");
    let launched = match aitm_browser::launch_owned(&browser_cfg, ca.cert_path()).await {
        Ok(l) => {
            phase.done(&startup::card::browser_summary(
                &cfg.browser.engine,
                l.version(),
            ));
            Some(l)
        }
        Err(e) => {
            // The WARN reaches the view through the tracing layer; the phase
            // itself ends done, not failed (spec D10).
            warn!(
                engine = ?cfg.browser.engine,
                error = %e,
                "embedded browser unavailable; browser.* commands will error"
            );
            phase.done("browser unavailable");
            None
        }
    };
    let browser: Option<Arc<dyn BrowserDriver>> = launched.as_ref().map(|l| l.driver.clone());
    // The trust read shells out to the OS store, so it exists only in the
    // serving modes (spec amendment A); a one-shot verb returned above.
    let ca_trust = if manages_system_proxy(&mode) {
        let phase = reporter.phase("checking CA trust");
        let word = startup::card::read_ca_trust(&cfg.ca.dir);
        phase.done(startup::card::ca_phase_summary(word));
        word
    } else {
        None
    };
    // Shared service handles for the frontends and the replay client.
    let services = tui::services(&proxy, &cfg, browser.clone(), tui_log, job_bus.clone());
    // The operator bus (R14 spec D2): before the ready card and the TUI handover
    // (a fixed-port conflict is the M2 panel through `report_for`), bound outside
    // both branches so its drop, which removes the core pointer (D4), is `run()`'s end.
    let mut operator_bus = match operator_bus::start(
        &cfg,
        &effective_path,
        &services,
        &agent_state,
        &audit_ring,
        push_tx.clone(),
        l4_live_guard.clone().map(self_port_hook),
        mint_failure,
    )
    .await
    {
        Ok(bus) => bus,
        Err(err) => {
            // The one fallible step after the system-proxy auto-set (security
            // S8): give the OS its proxy back before the M2 panel, as the §D9 (a)
            // restore below would have.
            if manages_system_proxy(&mode) {
                log_recovery("exit", &sysproxy.on_orderly_exit());
            }
            return Err(err);
        }
    };

    // The scripting tier now reaches exactly the proxy's store, client and
    // guard, and a failed hook's `Event::Error` reaches the chain rather than
    // only the log; `browser.*` in a script reaches the same engine the
    // commands do.
    handles.bind_proxy(
        services.store.clone(),
        services.client.clone(),
        services.guard.clone(),
    );
    tier.error_sink.bind(Arc::new(Chain::new(
        services.registry.clone(),
        services.store.clone(),
    )));
    if let Some(driver) = browser {
        handles.bind_browser(driver);
    }

    // The scanner's owned handles (spec D5, call B3), bound beside the script
    // tier's: the proxy's store, client and guard, the browser that launched
    // (so a crawl drives the same engine `browser.*` does), the live egress
    // posture a running job holds confined, the live L4 guard when L4 is on,
    // the one job bus, and a reader for the agent policy so an agent job
    // re-checks the policy `agent.set` writes at every step.
    scan_late.bind(scan_services(
        &services,
        services.browser.clone(),
        l4_guard.clone(),
        &agent_state,
        &cfg,
    ));

    // The macOS Network/System Extension live-capture feeder: `Some` only on a macOS
    // build with `macos_capture.enabled` (deny-by-default; the config file is the
    // sole on-switch — no bus, MCP, or script path builds it). It feeds the proxy's
    // own ingress and guards, and verifies the provider's code signature with the
    // production requirement. Everywhere else the ingress is dropped, as before.
    let capture_session = if cfg!(target_os = "macos") {
        l4_ingress.and_then(|ingress| {
            build_capture_session(
                &features,
                ingress,
                proxy.guard(),
                l4_guard,
                Arc::new(CodeSignatureVerifier::default()),
                PathBuf::from(feeder::DEFAULT_SOCKET_DIR),
                capture_status,
            )
        })
    } else {
        None
    };
    // The feeder runs as an arm beside the proxy accept loops. It is fail-open: one
    // that is off, cannot bind, or has stopped must never end the run, so this
    // future never completes (`Infallible`) — only the accept loops, the frontends,
    // or the shutdown signal end the `select!`. When another arm wins, dropping this
    // future tears the session down: its rendezvous guard and sockets remove their
    // files and its pumps see the stop.
    let capture_run = async move {
        if let Some(session) = capture_session {
            session.run(aitm::shutdown_signal()).await;
        }
        std::future::pending::<std::convert::Infallible>().await
    };

    // We are about to serve: `proxy.status.listening` now reports the truth.
    listening.store(true, std::sync::atomic::Ordering::Relaxed);
    // Spec D8: with an empty Scope nothing is decrypted, and that is said once at
    // launch — as the `Scope` line of `aitm web`'s stdout summary below, or, where
    // no summary is printed (bare `aitm`, `aitm tui`), as one `info` line on the
    // `aitm` target. Never `warn`, never repeated: the live read is
    // `proxy.status.decrypt`, which follows a later `scope.add`.
    let launch_advice = cfg
        .scope
        .entries
        .is_empty()
        .then_some(NOTHING_DECRYPTED_ADVICE);
    if mode != Mode::Web {
        if let Some(advice) = launch_advice {
            info!(target: "aitm", "{advice}");
        }
    }
    // The ready card (spec D10): M1 for bare `aitm`, M6 for `aitm web`, none
    // for `aitm tui`, whose status bar is the card (D11). On stderr, so stdout
    // stays free for stdio MCP; the URL rows carry the bridge tokens on purpose.
    let print_ready_card = |mode: ModeWord, web_url: Option<&str>, operator_url: Option<&str>| {
        reporter.card(&startup::card::ready_card(&ReadyInputs {
            mode,
            proxy: proxy_addr,
            browser: browser_addr,
            // The Web card's `Bus` row is always `ready` (M6); the transport
            // word is the Server card's.
            bus: startup::card::bus_word(&cfg.mcp.transport),
            operator_bus: operator_bus.word(),
            web_url,
            operator_url,
            ca: ca_trust,
            scope_hosts: cfg.scope.entries.len(),
            system_proxy: &sysproxy.summary(),
            intercept_armed: false,
            capture_paused: false,
            log: sink.path.as_deref(),
            home: reporter.display_home(),
        }));
        reporter.finish();
    };
    let result = if mode == Mode::Tui {
        // The handover (spec D11): the checklist is erased up to the header
        // before ratatui takes the alternate screen.
        reporter.finish_and_clear();
        // `aitm tui`: the loopback agent server is built by `tui::build_servers`
        // on the core's shared policy state and audit ring (the `governance`
        // passed here, from `assembled.governance()` above) through
        // `tui::with_shared_governance`, so a live `agent.set` governs it and
        // its calls land in `agent.activity`. `push_tx` is not fed to it
        // (follow-up "tui-mode push"): a loopback subscriber still gets the
        // `notifications/aitm/agent` lines but no `notifications/aitm/flow`.
        // Its bound port joins the L4 self-port set through `on_bound`, exactly
        // as the server path's does below (L4PAR-AC34).
        let on_agent_bound = l4_live_guard.clone().map(self_port_hook);
        tokio::select! {
            result = tui::run(
                &cfg,
                &proxy,
                services,
                governance,
                proxy_listener,
                browser_listener,
                on_agent_bound,
            ) => result,
            never = capture_run => match never {},
            result = operator_bus.finished() => result,
        }
    } else {
        // The bare-`aitm` server path is the dedicated agent entry point, so it
        // carries M4's operator/agent token classes, the shared agent policy
        // gate, the F4 push fan-out and the F2 audit ring. The web bridge is
        // not exempt: its agent bridge token resolves to `Frontend::Mcp`, so it
        // is gated like any agent and must read the policy `agent.set` writes
        // and record into the ring `agent.activity` reads, which is why both
        // servers go through `tui::with_shared_governance`. Only the operator
        // bridge token (present only when `mcp.operator_token` is configured)
        // is un-gated, by role. The TUI's own in-process server (in
        // `tui::build_servers`) is the operator and bypasses the gate by role.
        let mcp = tui::with_shared_governance(
            tui::server(&cfg, cfg.mcp.transport.clone(), &services),
            &agent_state,
            &audit_ring,
        )
        .with_mcp_roles(cfg.mcp.operator_token.clone(), cfg.mcp.stdio_role)
        .with_push(push_tx.clone());
        // The agent transport binds inside `serve`; once it has, the bound port
        // (the configured one, or the ephemeral port a `0` resolved to) joins the
        // L4 self-port set beside the listeners bound above (L4PAR-AC34).
        let mcp = match l4_live_guard.clone() {
            Some(guard) => mcp.on_bound(self_port_hook(guard)),
            None => mcp,
        };

        // `aitm web`: a second McpServer over the same registry and services
        // (`serve` consumes the first), driven by the bridge's `handle_on` calls.
        // It is fed the core event stream too, with its own dispatcher: each
        // server keeps its own subscription registry and only `serve` spawns a
        // dispatcher, so without this a `/bus` subscription would sit in a
        // registry nothing feeds.
        // Both pre-bound listen addresses were read in the pre-bind block above
        // (the listeners move into `proxy.run_on` / `proxy.run_browser_on`
        // below), so the startup summary has them without another fallible step.
        let web_server = match (web_settings, web_listener) {
            (Some(settings), Some((listener, bound))) => {
                let bus = Arc::new(
                    tui::with_shared_governance(
                        tui::server(&cfg, cfg.mcp.transport.clone(), &services),
                        &agent_state,
                        &audit_ring,
                    )
                    .with_push(push_tx),
                );
                bus.spawn_push_dispatcher();
                // Operator access on the web UI is tied to `mcp.operator_token`
                // being configured to a NON-EMPTY value (operator role exists at
                // all); there is no separate `aitm web` opt-in. An empty token is
                // treated as "not configured", mirroring the loopback transport,
                // so a hand-edited `operator_token: ""` never enables operator
                // access. The operator *bridge* token is a fresh per-run token —
                // never the secret mcp operator token, which stays out of every
                // URL and log.
                let operator_token = cfg
                    .mcp
                    .operator_token
                    .as_deref()
                    .is_some_and(|t| !t.is_empty())
                    .then(|| audit_log::bridge_token(audit.as_ref()));
                let state = Arc::new(WebState {
                    mcp: bus,
                    agent_token: settings.token.clone(),
                    operator_token: operator_token.clone(),
                    bad_token_throttle: Default::default(),
                });
                if settings.insecure_bind {
                    warn!(
                        listen = %settings.listen,
                        "binding the web UI off loopback WITHOUT TLS ({}=1); the bridge token \
                         is its only protection",
                        web::INSECURE_BIND_ENV
                    );
                }
                // The UI listener was pre-bound up front (collision checks and
                // all) and its address read there, so here we just serve on it.
                let url = web::ui_url(bound, &settings.token);
                // Log only the bound address; the token must never reach a
                // tracing sink. The ready card is the operator's link — its
                // URLs carry the token on purpose (stderr, not logs).
                web::log_listening(bound);
                let operator_url = operator_token
                    .as_ref()
                    .map(|op| web::operator_ui_url(bound, op));
                print_ready_card(ModeWord::Web, Some(&url), operator_url.as_deref());
                Some((listener, state))
            }
            _ => None,
        };
        let web_run = async move {
            match web_server {
                Some((listener, state)) => web::serve(listener, state).await,
                None => std::future::pending().await,
            }
        };

        if mode == Mode::Server {
            print_ready_card(ModeWord::Server, None, None);
        }

        // The main listener relays client traffic; the browser listener is
        // SSRF-filtered (the embedded browser dials `cfg.browser.proxy_addr`).
        // Both sockets were pre-bound above, so the accept loops just run on them.
        // The stdio MCP arm ending `Ok` is the stdin-EOF exit: it gets one
        // reporter line after the `select!` (spec Open question 3, AC-W1-32),
        // ahead of the §D9 (a) restore; it stays the session's last line
        // because `reporter.quiesce()` below drops the browser teardown noise —
        // only a failed restore's warning (by design, spec D4) or the
        // audit-flush integrity warning (S7) may follow it.
        let stdio_transport = matches!(cfg.mcp.transport, McpTransport::Stdio);
        let mut stdio_eof = None;
        let served = tokio::select! {
            result = proxy.run_on(proxy_listener) => result,
            result = proxy.run_browser_on(browser_listener) => result,
            result = mcp.serve() => {
                stdio_eof = stdio_eof_note(stdio_transport, &result);
                result
            }
            result = web_run => result,
            never = capture_run => match never {},
            result = operator_bus.finished() => result,
            () = aitm::shutdown_signal() => {
                info!("shutdown signal received");
                Ok(())
            }
        };
        if let Some(line) = stdio_eof {
            reporter.note(line);
        }
        served
    };

    // §D9 (a): whichever arm ended the run, and whether `result` is `Ok` or
    // `Err`, give the system proxy back before anything else — a dead port is
    // never acceptable — whether or not `auto` set it. Runs ahead of the browser
    // reap so the restore lands inside the mac app's stop grace even when the
    // browser is slow to close. (`result` is only returned after this; fix F2.)
    if manages_system_proxy(&mode) {
        let recovery = sysproxy.on_orderly_exit();
        log_recovery("exit", &recovery);
    }

    // Spec D4 (AC-W1-33): the loop has ended; quiesce the reporter after the
    // system-proxy restore (its warning must stay visible), before the browser
    // reap (its CDP-socket teardown noise must not). That noise stays in the
    // log instead of becoming the operator's last line.
    reporter.quiesce();

    // Whichever arm ended the run, reap the browser child before returning;
    // a signal would otherwise leave it orphaned (no destructor runs).
    if let Some(b) = launched {
        let budget = cfg.browser.obscura.stop_timeout + Duration::from_secs(1);
        match tokio::time::timeout(budget, b.close()).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => warn!(error = %e, "embedded browser did not close cleanly"),
            Err(_) => warn!(?budget, "embedded browser close timed out"),
        }
    }

    // Last: every call the servers audited is queued by now. This flushes it, and
    // is bounded (`SHUTDOWN_BUDGET`), so a stalled disk cannot hold the exit. It
    // sleeps while the stream threads drain, so it says so to the (multi-thread)
    // runtime rather than blocking inside the async fn unannounced.
    if let Some(handle) = &audit {
        let report = tokio::task::block_in_place(|| handle.shutdown(audit_log::SHUTDOWN_BUDGET));
        if !report.complete {
            warn!(
                target: "aitm::audit",
                estimated_left = report.estimated_left,
                "the audit log did not finish flushing before exit"
            );
            // S7: the reporter is quiesced, so that tracing WARN is log-only;
            // lost audit records are an integrity signal the operator must
            // see, so the reporter says it too (a plain `warning:` line after
            // `finish()`, C10).
            reporter.warn(&audit_flush_warning(report.estimated_left));
        }
    }
    result
}

/// The port the configured agent transport will bind, when it names one: the
/// loopback-TCP bus port or the streamable-HTTP bind port. `None` for stdio (no
/// listener) and for an ephemeral `0` (unknown until bound; `McpServer::on_bound`
/// then reports the real one). Feeds the L4 self-port set (L4PAR-AC34).
fn configured_agent_port(transport: &McpTransport) -> Option<u16> {
    let port = match transport {
        McpTransport::Stdio => return None,
        McpTransport::LoopbackTcp { port, .. } => *port,
        McpTransport::StreamableHttp { bind, .. } => bind.port(),
    };
    (port != 0).then_some(port)
}

/// The reporter's last line of a serving session when the stdio MCP arm ended
/// `Ok` — the stdio JSON-RPC channel saw EOF (spec Open question 3, AC-W1-32).
/// `None` for every other transport and for an `Err` end, which keep their own
/// reporting.
fn stdio_eof_note(transport_is_stdio: bool, result: &anyhow::Result<()>) -> Option<&'static str> {
    (transport_is_stdio && result.is_ok()).then_some("stdin closed · stdio MCP transport ended")
}

/// The reporter's S7 integrity warning when the audit log did not finish
/// flushing within `SHUTDOWN_BUDGET`: `estimated_left` is the estimate of
/// records left behind. One place for the words, so the `warning:` line after
/// `finish()` (C10) and the unit test that pins it cannot drift apart.
fn audit_flush_warning(estimated_left: usize) -> String {
    format!(
        "the audit log did not finish flushing before exit ({estimated_left} records estimated left)"
    )
}

/// Split a leading `--config <path>` / `--config=<path>` off `argv`, returning
/// the path (if given) and the remaining CLI arguments.
fn split_config_arg(argv: Vec<String>) -> anyhow::Result<(Option<PathBuf>, Vec<String>)> {
    let mut rest = argv.into_iter();
    let Some(first) = rest.next() else {
        return Ok((None, Vec::new()));
    };
    if first == "--config" {
        let path = rest
            .next()
            .ok_or_else(|| anyhow::anyhow!("--config requires a path"))?;
        return Ok((Some(PathBuf::from(path)), rest.collect()));
    }
    if let Some(path) = first.strip_prefix("--config=") {
        return Ok((Some(PathBuf::from(path)), rest.collect()));
    }
    Ok((None, std::iter::once(first).chain(rest).collect()))
}

/// Split every `--script <path>` / `--script=<path>` out of `argv`, keeping the
/// order they were written: that is the order they take in the chain (spec §8).
/// Repeatable, and recognised anywhere a subcommand is not, so
/// `aitm --script a.rhai --script b.rhai` starts the proxy with both.
fn split_script_args(argv: Vec<String>) -> anyhow::Result<(Vec<PathBuf>, Vec<String>)> {
    let mut scripts = Vec::new();
    let mut rest = Vec::new();
    let mut args = argv.into_iter();
    while let Some(arg) = args.next() {
        if arg == "--script" {
            let path = args
                .next()
                .ok_or_else(|| anyhow::anyhow!("--script requires a path"))?;
            scripts.push(PathBuf::from(path));
        } else if let Some(path) = arg.strip_prefix("--script=") {
            scripts.push(PathBuf::from(path));
        } else {
            rest.push(arg);
        }
    }
    Ok((scripts, rest))
}

/// Split a single `--bus-endpoint-file <path>` / `--bus-endpoint-file=<path>`
/// out of `argv`, returning the path (if given) and the remaining arguments.
/// Recognised anywhere a subcommand is not, like `--script`. Specifying it more
/// than once is an error; it applies only to the loopback-TCP bus (see `run`).
fn split_bus_endpoint_file_arg(
    argv: Vec<String>,
) -> anyhow::Result<(Option<PathBuf>, Vec<String>)> {
    const FLAG: &str = "--bus-endpoint-file";
    let mut path: Option<PathBuf> = None;
    let mut rest = Vec::new();
    let mut args = argv.into_iter();
    while let Some(arg) = args.next() {
        let value = if arg == FLAG {
            Some(
                args.next()
                    .ok_or_else(|| anyhow::anyhow!("{FLAG} requires a path"))?,
            )
        } else {
            arg.strip_prefix("--bus-endpoint-file=")
                .map(|v| v.to_string())
        };
        match value {
            Some(v) => {
                anyhow::ensure!(path.is_none(), "{FLAG} may be given at most once");
                path = Some(PathBuf::from(v));
            }
            None => rest.push(arg),
        }
    }
    Ok((path, rest))
}

/// Apply a `--bus-endpoint-file` value (if any) onto the configured transport:
/// it overrides the loopback transport's `endpoint_file`, and over stdio — which
/// has no bound bus to publish — it is a usage error naming the fix.
fn apply_bus_endpoint_file(
    transport: &mut McpTransport,
    path: Option<PathBuf>,
) -> anyhow::Result<()> {
    let Some(path) = path else {
        return Ok(());
    };
    match transport {
        McpTransport::LoopbackTcp { endpoint_file, .. } => {
            *endpoint_file = Some(path);
            Ok(())
        }
        // Neither stdio nor streamable-HTTP publishes a loopback-bus endpoint
        // file: stdio has no bound bus, and the HTTP transport serves at its own
        // configured `bind`, not an ephemeral rendezvous the parent must discover.
        McpTransport::Stdio | McpTransport::StreamableHttp { .. } => anyhow::bail!(
            "--bus-endpoint-file needs the loopback-TCP bus; set mcp.transport.loopback_tcp \
             in the config so the core has a bound address to publish"
        ),
    }
}

/// The scanner's owned handles (spec D5, call B3), built the one way both bind
/// sites — the one-shot CLI dispatch and the serving path — share: the proxy's
/// store, client, guard, live egress posture and job bus from `services`, the
/// `browser` the caller launched (`None` on the CLI path, where nothing does),
/// the live L4 guard when L4 is on, a reader for the agent policy so an agent
/// job re-checks what `agent.set` writes at every step, and the config for the
/// `CommandHost` the worker builds. Spawned on the current runtime.
fn scan_services(
    services: &tui::Services,
    browser: Option<Arc<dyn BrowserDriver>>,
    l4_guard: Option<Arc<aitm_proto_l4::guard::L4Guard>>,
    agent_state: &Arc<aitm_core::AgentState>,
    cfg: &aitm_core::Config,
) -> ScanServices {
    ScanServices {
        store: services.store.clone(),
        client: services.client.clone(),
        guard: services.guard.clone(),
        browser,
        egress: Some(services.egress.clone()),
        l4: l4_guard,
        jobs: services.jobs.clone(),
        agent_policy: Arc::new({
            let state = Arc::clone(agent_state);
            move || state.policy()
        }),
        rt: tokio::runtime::Handle::current(),
        config: Arc::new(cfg.clone()),
    }
}

/// Bind one service port up front, turning "address already in use" into a
/// single clear, actionable error — the port, who most likely holds it, and how
/// to change it — so a conflict surfaces here, before obscura is spawned and
/// before any "listening" success line, instead of as a cryptic os-error after
/// one. `role` names the port ("the proxy"); `remedy` is the one-line fix hint.
/// Any other bind error is returned with context.
async fn bind_service_port(
    addr: std::net::SocketAddr,
    role: &str,
    remedy: &str,
) -> anyhow::Result<TcpListener> {
    match TcpListener::bind(addr).await {
        Ok(listener) => Ok(listener),
        Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
            Err(addr_in_use_error(addr, role, remedy))
        }
        Err(e) => Err(anyhow::Error::new(e).context(format!("binding {role} on {addr}"))),
    }
}

/// The one "already in use" error [`bind_service_port`] returns: the port, who
/// most likely holds it, and how to change it. Typed, so the error panel can
/// be exact; its `Display` is 0.5.10's four lines verbatim (spec D6).
fn addr_in_use_error(addr: std::net::SocketAddr, role: &str, remedy: &str) -> anyhow::Error {
    anyhow::Error::new(StartupError::PortInUse {
        role: role.to_string(),
        addr,
        remedy: remedy.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use std::io::{self, Write};
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};

    use tracing_subscriber::fmt::MakeWriter;

    use aitm_core::McpTransport;

    use aitm::oneshot::args::BusArgs;
    use aitm::wire::{build_proxy_with, Features};

    use aitm_ca::exec::Executor;
    use aitm_ca::testing::ScriptedExecutor;
    use aitm_sysproxy::{Endpoint, Mechanism, SystemProxy, SystemProxyConfig, STATE_FILE_NAME};

    use super::{
        addr_in_use_error, apply_bus_endpoint_file, bind_then_recover_system_proxy,
        configured_agent_port, manages_system_proxy, parse_invocation, parse_mode, scan_services,
        split_bus_endpoint_file_arg, split_config_arg, split_script_args, usage_reporter,
        Invocation, Mode, StartupError, TermOpts, OPERATOR_TOKEN_USAGE,
    };
    use aitm_sysproxy::Recovery;
    use aitm_term::caps::{ColorChoice, Verbosity};

    fn args(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    /// L4PAR-AC34 (plan A10): the configured agent-transport port joins the L4
    /// self-port set when it names a real port — loopback-TCP bus or streamable
    /// HTTP — and not for stdio or an ephemeral `0` (that one arrives through
    /// `McpServer::on_bound` once bound).
    #[test]
    fn configured_agent_port_names_bound_listeners_only() {
        assert_eq!(
            configured_agent_port(&McpTransport::LoopbackTcp {
                port: 27431,
                token: "t".into(),
                endpoint_file: None,
            }),
            Some(27431)
        );
        assert_eq!(
            configured_agent_port(&McpTransport::LoopbackTcp {
                port: 0,
                token: "t".into(),
                endpoint_file: None,
            }),
            None
        );
        assert_eq!(
            configured_agent_port(&McpTransport::streamable_http_default("t".into())),
            Some(8084)
        );
        assert_eq!(configured_agent_port(&McpTransport::Stdio), None);
    }

    /// Spec Open question 3 / AC-W1-32: the `stdin closed · stdio MCP
    /// transport ended` note is produced only when the stdio MCP arm ended
    /// `Ok` — never for another transport's `Ok`, never on `Err`.
    #[test]
    fn stdio_eof_note_only_for_stdio_ok() {
        let ok: anyhow::Result<()> = Ok(());
        let err: anyhow::Result<()> = Err(anyhow::anyhow!("boom"));
        assert_eq!(
            super::stdio_eof_note(true, &ok),
            Some("stdin closed · stdio MCP transport ended")
        );
        assert_eq!(super::stdio_eof_note(false, &ok), None);
        assert_eq!(super::stdio_eof_note(true, &err), None);
        assert_eq!(super::stdio_eof_note(false, &err), None);
    }

    /// S7: the reporter's audit-flush integrity warning names the estimate of
    /// records left behind, in exactly these words for 0 and for 3.
    #[test]
    fn audit_flush_warning_names_the_count() {
        assert_eq!(
            super::audit_flush_warning(0),
            "the audit log did not finish flushing before exit (0 records estimated left)"
        );
        assert_eq!(
            super::audit_flush_warning(3),
            "the audit log did not finish flushing before exit (3 records estimated left)"
        );
    }

    /// A `MakeWriter` that appends every formatted log line to a shared buffer,
    /// so a test can read back exactly what the subscriber emitted.
    #[derive(Clone)]
    struct BufWriter(Arc<Mutex<Vec<u8>>>);

    impl Write for BufWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for BufWriter {
        type Writer = BufWriter;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    #[test]
    fn web_listening_log_has_no_token() {
        let buf = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer(BufWriter(buf.clone()))
            .finish();

        let addr = "127.0.0.1:8082".parse().unwrap();
        tracing::subscriber::with_default(subscriber, || crate::web::log_listening(addr));

        let out = String::from_utf8(buf.lock().unwrap().clone()).unwrap();
        // The lifecycle line records the bound address...
        assert!(out.contains("web UI listening"), "missing event: {out:?}");
        assert!(out.contains("127.0.0.1:8082"), "missing addr: {out:?}");
        // ...and never the token or the tokened URL that carries it.
        let token = crate::web::generate_token();
        let tokened_url = crate::web::ui_url(addr, &token);
        assert!(!out.contains(&token), "token leaked into log: {out:?}");
        assert!(
            !out.contains("#t="),
            "token fragment leaked into log: {out:?}"
        );
        assert!(
            !out.contains(&tokened_url),
            "tokened URL leaked into log: {out:?}"
        );
    }

    #[test]
    fn no_tracing_call_site_logs_a_tokened_url() {
        // AC2's second clause: no `tracing` macro in the server/web/tui paths may
        // carry a token-bearing URL. `web::ui_url` is the only tokened-URL builder
        // and `#t=` is the token fragment marker, so a log macro referencing
        // either would be leaking the token.
        const SOURCES: &[(&str, &str)] = &[
            ("main.rs", include_str!("main.rs")),
            ("tui.rs", include_str!("tui.rs")),
            ("web/mod.rs", include_str!("web/mod.rs")),
            ("web/bridge.rs", include_str!("web/bridge.rs")),
            ("web/http.rs", include_str!("web/http.rs")),
        ];
        const MACROS: &[&str] = &["info!", "warn!", "debug!", "trace!", "error!"];

        for (name, src) in SOURCES {
            for (lineno, line) in src.lines().enumerate() {
                let is_log_call = MACROS.iter().any(|m| line.contains(m));
                if is_log_call && (line.contains("ui_url") || line.contains("#t=")) {
                    panic!("{name}:{} logs a tokened URL: {line:?}", lineno + 1);
                }
            }
        }
    }

    #[test]
    fn main_logs_loaded_scripts_once_as_a_count() {
        // Stage-6 fix (scanner-v2 T1b, item 3): the Rhai loader already logs
        // one `loaded script` line per script (`aitm_plugin_rhai::loader`), so
        // the binary must not repeat it per script; it logs one summary count.
        // The literals are split so this test's own source does not match.
        let src = include_str!("main.rs");
        let per_script = concat!("script loaded ", "into the host");
        let summary = concat!("scripts loaded ", "into the host");
        assert!(
            !src.contains(per_script),
            "main.rs still logs a per-script `{per_script}` line"
        );
        assert_eq!(
            src.matches(summary).count(),
            1,
            "main.rs must log exactly one `{summary}` summary"
        );
    }

    /// Stage-6 fix (scanner-v2 T1b, item 5): the one `ScanServices` builder both
    /// bind sites call carries the proxy's own handles (store, client, guard,
    /// egress, job bus), the browser it is given, the L4 guard, a live reader of
    /// the agent policy, and the config.
    #[tokio::test]
    async fn scan_services_carries_the_proxy_handles() {
        use aitm::scripts::LateHandles;
        use aitm::tui::{self, TuiLog};
        use aitm_core::{AgentPolicy, AgentState, JobBus};

        let mut cfg = aitm_core::Config::default();
        cfg.ca.dir = std::env::temp_dir().join(format!(
            "aitm-main-scan-services-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let proxy = build_proxy_with(&cfg, &Features::default()).expect("assemble");
        let job_bus = Arc::new(JobBus::new(8));
        let s = tui::services(&proxy, &cfg, None, TuiLog::Off, job_bus.clone());
        let agent_state = Arc::new(AgentState::new(AgentPolicy::ReadOnly));

        let no_browser = scan_services(&s, None, None, &agent_state, &cfg);
        assert_eq!(
            format!("{no_browser:?}"),
            "ScanServices { browser: false, egress: true, l4: false, .. }"
        );
        assert!(Arc::ptr_eq(&no_browser.store, &s.store));
        assert!(Arc::ptr_eq(&no_browser.client, &s.client));
        assert!(Arc::ptr_eq(&no_browser.guard, &s.guard));
        assert!(Arc::ptr_eq(&no_browser.jobs, &job_bus));
        assert!(Arc::ptr_eq(
            no_browser
                .egress
                .as_ref()
                .expect("the proxy's egress posture"),
            &s.egress
        ));
        assert_eq!((no_browser.agent_policy)(), AgentPolicy::ReadOnly);
        // A live reader, not a snapshot: `agent.set` must be seen at the next step.
        agent_state.set_policy(AgentPolicy::Paused);
        assert_eq!((no_browser.agent_policy)(), AgentPolicy::Paused);
        assert_eq!(no_browser.config.ssl_insecure, cfg.ssl_insecure);

        let browser: Arc<dyn aitm_core::BrowserDriver> = LateHandles::new();
        let with_browser = scan_services(&s, Some(browser), None, &agent_state, &cfg);
        assert_eq!(
            format!("{with_browser:?}"),
            "ScanServices { browser: true, egress: true, l4: false, .. }"
        );
    }

    #[test]
    fn bus_endpoint_file_flag_separate_value_is_stripped() {
        let (path, rest) =
            split_bus_endpoint_file_arg(args(&["--bus-endpoint-file", "/run/bus.addr", "tui"]))
                .unwrap();
        assert_eq!(path, Some(PathBuf::from("/run/bus.addr")));
        assert_eq!(rest, args(&["tui"]));
    }

    #[test]
    fn bus_endpoint_file_flag_with_equals_is_stripped() {
        let (path, rest) =
            split_bus_endpoint_file_arg(args(&["--bus-endpoint-file=/run/bus.addr"])).unwrap();
        assert_eq!(path, Some(PathBuf::from("/run/bus.addr")));
        assert_eq!(rest, Vec::<String>::new());
    }

    #[test]
    fn no_bus_endpoint_file_flag_leaves_argv_alone() {
        let (path, rest) = split_bus_endpoint_file_arg(args(&["flow", "list"])).unwrap();
        assert_eq!(path, None);
        assert_eq!(rest, args(&["flow", "list"]));
    }

    #[test]
    fn bus_endpoint_file_flag_without_a_path_is_an_error() {
        let err = split_bus_endpoint_file_arg(args(&["--bus-endpoint-file"])).unwrap_err();
        assert_eq!(err.to_string(), "--bus-endpoint-file requires a path");
    }

    #[test]
    fn bus_endpoint_file_flag_twice_is_an_error() {
        let err = split_bus_endpoint_file_arg(args(&[
            "--bus-endpoint-file",
            "/a",
            "--bus-endpoint-file=/b",
        ]))
        .unwrap_err();
        assert_eq!(
            err.to_string(),
            "--bus-endpoint-file may be given at most once"
        );
    }

    #[test]
    fn bus_endpoint_file_sets_the_loopback_transport() {
        let mut transport = McpTransport::LoopbackTcp {
            port: 0,
            token: "tok".into(),
            endpoint_file: None,
        };
        apply_bus_endpoint_file(&mut transport, Some(PathBuf::from("/run/bus.addr"))).unwrap();
        assert!(matches!(
            transport,
            McpTransport::LoopbackTcp { endpoint_file: Some(p), .. } if p == std::path::Path::new("/run/bus.addr")
        ));
    }

    #[test]
    fn bus_endpoint_file_over_stdio_is_an_error() {
        let mut transport = McpTransport::Stdio;
        let err = apply_bus_endpoint_file(&mut transport, Some(PathBuf::from("/run/bus.addr")))
            .unwrap_err();
        assert!(
            err.to_string().contains("loopback-TCP bus"),
            "error should explain the loopback requirement: {err}"
        );
    }

    #[test]
    fn no_bus_endpoint_file_leaves_the_transport_unchanged() {
        let mut transport = McpTransport::Stdio;
        apply_bus_endpoint_file(&mut transport, None).unwrap();
        assert!(matches!(transport, McpTransport::Stdio));
    }

    #[test]
    fn config_flag_with_separate_value_is_stripped() {
        let (path, rest) =
            split_config_arg(args(&["--config", "/c.yaml", "flow", "list"])).unwrap();
        assert_eq!(path, Some(PathBuf::from("/c.yaml")));
        assert_eq!(rest, args(&["flow", "list"]));
    }

    #[test]
    fn config_flag_with_equals_is_stripped() {
        let (path, rest) = split_config_arg(args(&["--config=/c.yaml"])).unwrap();
        assert_eq!(path, Some(PathBuf::from("/c.yaml")));
        assert_eq!(rest, Vec::<String>::new());
    }

    #[test]
    fn no_config_flag_leaves_argv_alone() {
        let (path, rest) = split_config_arg(args(&["flow", "list"])).unwrap();
        assert_eq!(path, None);
        assert_eq!(rest, args(&["flow", "list"]));
    }

    #[test]
    fn bare_config_flag_without_a_path_is_an_error() {
        let err = split_config_arg(args(&["--config"])).unwrap_err();
        assert_eq!(err.to_string(), "--config requires a path");
    }

    #[test]
    fn empty_argv_is_the_server() {
        assert_eq!(parse_mode(args(&[])), Ok(Mode::Server));
    }

    #[test]
    fn a_subcommand_is_a_cli_dispatch() {
        assert_eq!(
            parse_mode(args(&["flow", "list"])),
            Ok(Mode::Cli(args(&["flow", "list"])))
        );
    }

    #[test]
    fn tui_alone_embeds_the_proxy() {
        assert_eq!(parse_mode(args(&["tui"])), Ok(Mode::Tui));
    }

    #[test]
    fn web_is_the_server_with_the_web_ui_attached() {
        assert_eq!(parse_mode(args(&["web"])), Ok(Mode::Web));
        assert_eq!(
            parse_mode(args(&["web", "--listen", "127.0.0.1:8082"])),
            Ok(Mode::Web),
            "web's own flags are parsed by web::parse_args, not here"
        );
    }

    #[test]
    fn operator_token_generate_is_its_own_mode() {
        assert_eq!(
            parse_mode(args(&["operator-token", "generate"])),
            Ok(Mode::OperatorToken { force: false })
        );
    }

    #[test]
    fn operator_token_generate_accepts_force() {
        assert_eq!(
            parse_mode(args(&["operator-token", "generate", "--force"])),
            Ok(Mode::OperatorToken { force: true })
        );
    }

    #[test]
    fn operator_token_rejects_unknown_subverb_and_flag() {
        let err = parse_mode(args(&["operator-token", "rotate"])).unwrap_err();
        assert!(err.contains("operator-token generate"), "{err}");
        let err = parse_mode(args(&["operator-token"])).unwrap_err();
        assert!(err.contains("operator-token generate"), "{err}");
        let err = parse_mode(args(&["operator-token", "generate", "--oops"])).unwrap_err();
        assert!(err.contains("--oops"), "{err}");
    }

    #[test]
    fn tui_with_extra_arguments_is_a_usage_error() {
        assert_eq!(
            parse_mode(args(&["tui", "extra"])),
            Err("usage: aitm [--config <path>] tui (takes no further arguments)".to_string())
        );
    }

    /// SP-AC13 (`parse_mode` half): the hidden watchdog mode parses exactly
    /// `--pid <n> --state <path> [--no-pipe]`; anything less is the usage line.
    #[test]
    fn parse_mode_sysproxy_watchdog() {
        assert_eq!(
            parse_mode(args(&["sysproxy-watchdog", "--pid", "1", "--state", "/x"])),
            Ok(Mode::SysproxyWatchdog {
                pid: 1,
                state: PathBuf::from("/x"),
                no_pipe: false,
            })
        );
        assert_eq!(
            parse_mode(args(&[
                "sysproxy-watchdog",
                "--pid",
                "1",
                "--state",
                "/x",
                "--no-pipe"
            ])),
            Ok(Mode::SysproxyWatchdog {
                pid: 1,
                state: PathBuf::from("/x"),
                no_pipe: true,
            })
        );
        let err = parse_mode(args(&["sysproxy-watchdog", "--pid", "1"])).unwrap_err();
        assert!(err.contains("usage: aitm sysproxy-watchdog"), "{err}");
        let err = parse_mode(args(&["sysproxy-watchdog", "--state", "/x"])).unwrap_err();
        assert!(err.contains("usage: aitm sysproxy-watchdog"), "{err}");
        let err =
            parse_mode(args(&["sysproxy-watchdog", "--pid", "x", "--state", "/x"])).unwrap_err();
        assert!(err.contains("usage: aitm sysproxy-watchdog"), "{err}");
        let err = parse_mode(args(&[
            "sysproxy-watchdog",
            "--pid",
            "1",
            "--state",
            "/x",
            "--bogus",
        ]))
        .unwrap_err();
        assert!(err.contains("usage: aitm sysproxy-watchdog"), "{err}");
        assert!(err.contains("--bogus"), "{err}");
    }

    /// §D9 (b): the watchdog subcommand is hidden — no usage text reachable
    /// from this binary names it, and it is never a registry command, so the
    /// CLI dispatcher's `usage()` over the assembled registry has no line for it.
    #[test]
    fn usage_does_not_mention_the_watchdog() {
        for (name, text) in [
            ("tui::USAGE", aitm::tui::USAGE),
            ("web::USAGE", aitm::web::USAGE),
            ("operator-token usage", OPERATOR_TOKEN_USAGE),
        ] {
            assert!(
                !text.contains("sysproxy-watchdog"),
                "{name} mentions the hidden watchdog:\n{text}"
            );
        }
        let mut cfg = aitm_core::Config::default();
        cfg.ca.dir = std::env::temp_dir().join(format!(
            "aitm-main-usage-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let proxy = build_proxy_with(&cfg, &Features::default()).expect("assemble");
        let usage = aitm_cli::Cli::new(proxy.registry_arc()).usage();
        assert!(
            usage.contains("proxy system status"),
            "the real registry is being listed:\n{usage}"
        );
        assert!(
            !usage.contains("sysproxy-watchdog"),
            "the CLI dispatcher lists the hidden watchdog:\n{usage}"
        );
        let _ = std::fs::remove_dir_all(&cfg.ca.dir);
    }

    /// Plan C5: `recover_at_startup` / `on_orderly_exit` run only in the
    /// serving modes; a one-shot `aitm proxy system status`, the token
    /// generator and the watchdog itself never touch the system proxy here.
    #[test]
    fn recovery_runs_only_in_serving_modes() {
        assert!(manages_system_proxy(&Mode::Server));
        assert!(manages_system_proxy(&Mode::Tui));
        assert!(manages_system_proxy(&Mode::Web));
        assert!(!manages_system_proxy(&Mode::Cli(args(&[
            "proxy", "system", "status"
        ]))));
        assert!(!manages_system_proxy(&Mode::OperatorToken { force: false }));
        assert!(!manages_system_proxy(&Mode::SysproxyWatchdog {
            pid: 1,
            state: PathBuf::from("/x"),
            no_pipe: false,
        }));
    }

    /// A scripted macOS engine for `127.0.0.1:18080` with one enabled service
    /// (`Wi-Fi`, proxy off) and its state file in a fresh temp dir. Every read a
    /// `set` makes is answered, so a `set` that runs renders the `-set*` lines.
    fn scripted_sysproxy(tag: &str) -> (Arc<ScriptedExecutor>, SystemProxy, PathBuf) {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!("aitm-main-sysproxy-{tag}-{nanos}"));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let off = "Enabled: No\nServer: \nPort: 0\nAuthenticated Proxy Enabled: 0\n";
        let exec = Arc::new(
            ScriptedExecutor::new()
                .respond(
                    "/usr/sbin/networksetup -listallnetworkservices",
                    0,
                    "An asterisk (*) denotes that a network service is disabled.\nWi-Fi\n",
                    "",
                )
                .respond("/usr/sbin/networksetup -getwebproxy Wi-Fi", 0, off, "")
                .respond(
                    "/usr/sbin/networksetup -getsecurewebproxy Wi-Fi",
                    0,
                    off,
                    "",
                )
                .respond(
                    "/usr/sbin/networksetup -getproxybypassdomains Wi-Fi",
                    0,
                    "*.local\n169.254/16\n",
                    "",
                )
                .with_real_fs(),
        );
        let cfg = SystemProxyConfig {
            auto: true,
            bypass: vec![],
            state_file: Some(dir.join(STATE_FILE_NAME)),
        };
        let as_exec: Arc<dyn Executor> = exec.clone();
        let ours = Endpoint {
            host: "127.0.0.1".into(),
            port: 18080,
        };
        let sp = SystemProxy::with_mechanism(as_exec, &cfg, ours, None, Mechanism::Networksetup);
        (exec, sp, dir)
    }

    fn mutating_lines(exec: &ScriptedExecutor) -> Vec<String> {
        exec.runs()
            .into_iter()
            .filter(|l| l.contains(" -set") || l.contains("gsettings set"))
            .collect()
    }

    /// Fix F2 (live proof, Task 14): with `system_proxy.auto` on and the proxy
    /// port already taken, the core must fail with the "already in use" error
    /// and leave the system proxy untouched — it never points the OS at a port
    /// it cannot serve. The bind future here fails exactly as
    /// `bind_service_port` does on `AddrInUse` (the sandbox cannot bind a real
    /// port, so the conflict is not staged with a second listener).
    #[tokio::test]
    async fn port_conflict_never_sets_the_system_proxy() {
        let (exec, sp, dir) = scripted_sysproxy("conflict");
        let addr: std::net::SocketAddr = "127.0.0.1:18080".parse().unwrap();
        let err = bind_then_recover_system_proxy(&Mode::Server, &sp, true, async {
            Err::<(), _>(addr_in_use_error(
                addr,
                "the proxy",
                "Free it, or set `listen:` to another address in aitm.yaml.",
            ))
        })
        .await
        .unwrap_err();
        assert!(
            err.to_string()
                .starts_with("cannot start: the proxy port 127.0.0.1:18080 is already in use."),
            "{err}"
        );
        assert!(
            err.downcast_ref::<StartupError>().is_some(),
            "the port conflict is typed so its panel can be exact (spec D6): {err:?}"
        );
        assert_eq!(
            mutating_lines(&exec),
            Vec::<String>::new(),
            "a core that cannot bind must not set the system proxy"
        );
        assert_eq!(
            exec.runs(),
            Vec::<String>::new(),
            "recovery never ran: not even a read"
        );
        assert!(
            !dir.join(STATE_FILE_NAME).exists(),
            "no state file: nothing for the watchdog or the exit path to undo"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The other half of the ordering: once the ports are bound, the §D9 (c)
    /// recovery runs and `auto` points the system proxy at this core — and in
    /// a serving mode only (plan C5).
    #[tokio::test]
    async fn startup_recovery_sets_the_system_proxy_once_the_ports_are_bound() {
        let (exec, sp, dir) = scripted_sysproxy("bound");
        let (bound, recovery) =
            bind_then_recover_system_proxy(&Mode::Cli(args(&["flow", "list"])), &sp, true, async {
                Ok(("proxy", "browser"))
            })
            .await
            .unwrap();
        assert_eq!(bound, ("proxy", "browser"));
        assert!(
            matches!(recovery, Recovery::Nothing),
            "a one-shot mode never recovers: {recovery:?}"
        );
        assert_eq!(
            exec.runs(),
            Vec::<String>::new(),
            "a one-shot mode never recovers"
        );

        let (bound, recovery) = bind_then_recover_system_proxy(&Mode::Server, &sp, true, async {
            Ok(("proxy", "browser"))
        })
        .await
        .unwrap();
        assert_eq!(
            bound,
            ("proxy", "browser"),
            "the bound listeners come back untouched"
        );
        assert!(
            matches!(recovery, Recovery::Set(_)),
            "`auto` set the system proxy: {recovery:?}"
        );
        assert_eq!(
            mutating_lines(&exec),
            [
                "/usr/sbin/networksetup -setwebproxy Wi-Fi 127.0.0.1 18080",
                "/usr/sbin/networksetup -setsecurewebproxy Wi-Fi 127.0.0.1 18080",
                "/usr/sbin/networksetup -setproxybypassdomains Wi-Fi *.local 169.254/16 localhost 127.0.0.1 ::1",
            ]
        );
        assert!(
            dir.join(STATE_FILE_NAME).is_file(),
            "the state file is on disk for the exit path to restore from"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn script_flags_are_collected_in_order_and_stripped() {
        let (scripts, rest) = split_script_args(args(&[
            "--script",
            "a.rhai",
            "flow",
            "--script=b.rhai",
            "list",
        ]))
        .unwrap();
        assert_eq!(scripts, [PathBuf::from("a.rhai"), PathBuf::from("b.rhai")]);
        assert_eq!(rest, args(&["flow", "list"]), "the subcommand is untouched");
    }

    #[test]
    fn bare_script_flag_without_a_path_is_an_error() {
        let err = split_script_args(args(&["--script"])).unwrap_err();
        assert_eq!(err.to_string(), "--script requires a path");
    }

    #[test]
    fn script_flags_before_tui_still_embed() {
        let (scripts, rest) = split_script_args(args(&["--script", "a.rhai", "tui"])).unwrap();
        assert_eq!(scripts, [PathBuf::from("a.rhai")]);
        assert_eq!(parse_mode(rest), Ok(Mode::Tui));
    }

    /// Q1 (tester): the engine logs every recovery outcome at `info` as it
    /// happens, so `log_recovery` must add nothing for them (one line per
    /// event, not two); only a `Failed` recovery earns a second line, a
    /// `warn!` carrying the phase and the engine's message verbatim.
    #[test]
    fn log_recovery_warns_only_for_a_failed_recovery() {
        let capture = |recovery: &aitm_sysproxy::Recovery| -> String {
            let buf = Arc::new(Mutex::new(Vec::new()));
            let subscriber = tracing_subscriber::fmt()
                .with_ansi(false)
                .with_max_level(tracing::Level::TRACE)
                .with_writer(BufWriter(buf.clone()))
                .finish();
            tracing::subscriber::with_default(subscriber, || {
                super::log_recovery("startup", recovery)
            });
            let out = String::from_utf8(buf.lock().unwrap().clone()).unwrap();
            out
        };
        for quiet in [
            aitm_sysproxy::Recovery::Nothing,
            aitm_sysproxy::Recovery::Adopted { pid: 7 },
            aitm_sysproxy::Recovery::Restored {
                restored: vec!["Wi-Fi".into()],
                left_alone: vec!["Display Ethernet".into()],
            },
            aitm_sysproxy::Recovery::Forgot,
        ] {
            assert_eq!(
                capture(&quiet),
                "",
                "{quiet:?} is already logged by the engine; main.rs must not log it again"
            );
        }
        let out = capture(&aitm_sysproxy::Recovery::Failed(
            "write failed: networksetup exit 1; the state file /x is kept".into(),
        ));
        assert!(out.contains("WARN"), "{out:?}");
        assert!(
            out.contains(
                "system proxy: write failed: networksetup exit 1; the state file /x is kept"
            ),
            "{out:?}"
        );
        assert!(out.contains("phase=\"startup\""), "{out:?}");
        assert_eq!(out.lines().count(), 1, "{out:?}");
    }

    /// F3 (tester): `main` dispatches the hidden watchdog on the mode
    /// `parse_invocation` classified, before any runtime is built; the
    /// classification must therefore survive the global flags that may
    /// precede the subcommand. `aitm --config <p> sysproxy-watchdog …` (a
    /// spelling the spawner never emits; a hand launch may) is the watchdog
    /// with that config path recorded, never a server start.
    #[test]
    fn parse_invocation_classifies_the_watchdog_behind_a_leading_config_flag() {
        for argv in [
            args(&[
                "--config",
                "/etc/aitm.yaml",
                "sysproxy-watchdog",
                "--pid",
                "1",
                "--state",
                "/x",
            ]),
            args(&[
                "--config=/etc/aitm.yaml",
                "sysproxy-watchdog",
                "--pid",
                "1",
                "--state",
                "/x",
                "--no-pipe",
            ]),
            args(&["sysproxy-watchdog", "--pid", "1", "--state", "/x"]),
        ] {
            let no_pipe = argv.last().map(String::as_str) == Some("--no-pipe");
            let with_config = argv[0].starts_with("--config");
            let Invocation {
                config_arg,
                script_args,
                bus_endpoint_file,
                bus_args,
                web_args,
                mode,
                term,
            } = parse_invocation(argv.clone())
                .expect("parses")
                .expect("something to run");
            assert_eq!(term, TermOpts::default(), "{argv:?}");
            assert_eq!(bus_args, BusArgs::default(), "{argv:?}");
            assert_eq!(
                mode,
                Mode::SysproxyWatchdog {
                    pid: 1,
                    state: PathBuf::from("/x"),
                    no_pipe,
                },
                "{argv:?}"
            );
            assert_eq!(
                config_arg,
                with_config.then(|| PathBuf::from("/etc/aitm.yaml")),
                "{argv:?}"
            );
            assert!(script_args.is_empty(), "{argv:?}");
            assert!(bus_endpoint_file.is_none(), "{argv:?}");
            assert!(web_args.is_none(), "{argv:?}");
        }
    }

    /// Spec D9: the global terminal flags are split off first and ride in the
    /// invocation; the mode is classified from what is left.
    #[test]
    fn invocation_carries_the_term_opts() {
        let invocation = parse_invocation(args(&["-q", "--color=never", "scope", "list"]))
            .expect("parses")
            .expect("something to run");
        assert_eq!(
            invocation.term,
            TermOpts {
                verbosity: Verbosity::Quiet,
                color: ColorChoice::Never,
            }
        );
        assert_eq!(invocation.mode, Mode::Cli(args(&["scope", "list"])));
    }

    /// R14 spec D7 (plan Task 13): the one-shot's own flags are split out of
    /// argv before the mode is classified and ride in the invocation.
    #[test]
    fn invocation_carries_bus_args() {
        let argv = args(&["--bus", "127.0.0.1:1", "--token-file", "t", "scope", "list"]);
        let invocation = parse_invocation(argv)
            .expect("parses")
            .expect("something to run");
        assert_eq!(
            invocation.bus_args,
            BusArgs {
                bus: Some("127.0.0.1:1".to_string()),
                token_file: Some(PathBuf::from("t")),
            }
        );
        assert_eq!(invocation.mode, Mode::Cli(args(&["scope", "list"])));
    }

    /// Spec D9 (panel Q3/Sp3): a mode usage error (`aitm tui extra`,
    /// `aitm operator-token`) renders through a reporter built from the
    /// already-parsed `--color`/`-q`, not a fresh auto-detected one, so
    /// `--color never` and `-q` hold on that path. `ColorChoice::Always` and
    /// `Never` decide colour outright in `Caps::from_parts`, so the check is
    /// hermetic; `-v` switches animation off (D2 rule 5). No message is sent,
    /// so the real stderr stays untouched.
    #[test]
    fn mode_usage_panels_use_the_parsed_term_opts() {
        let quiet_plain = usage_reporter(&TermOpts {
            verbosity: Verbosity::Quiet,
            color: ColorChoice::Never,
        });
        assert!(!quiet_plain.caps().color, "--color never holds");
        assert_eq!(quiet_plain.verbosity(), Verbosity::Quiet, "-q holds");

        let loud_forced = usage_reporter(&TermOpts {
            verbosity: Verbosity::Verbose,
            color: ColorChoice::Always,
        });
        assert!(loud_forced.caps().color, "--color always holds");
        assert!(!loud_forced.caps().animate, "-v turns the live region off");
        assert_eq!(loud_forced.verbosity(), Verbosity::Verbose);
    }

    // ---- tester, whole-branch pass (spec D6, D9; AC-W1-3, AC-W1-12) ----

    /// Plan C26 end to end through `parse_invocation`: the terminal flags are
    /// stripped around an equals-form `--config`, the mode is classified from
    /// what is left, and a flag-shaped `--config` value is a file name.
    #[test]
    fn parse_invocation_strips_term_flags_around_an_equals_config() {
        let invocation = parse_invocation(args(&[
            "--config=/etc/aitm.yaml",
            "-v",
            "--color",
            "never",
            "scope",
            "list",
            "-q",
        ]))
        .expect("parses")
        .expect("something to run");
        assert_eq!(
            invocation.term,
            TermOpts {
                verbosity: Verbosity::Verbose,
                color: ColorChoice::Never,
            }
        );
        assert_eq!(invocation.config_arg, Some(PathBuf::from("/etc/aitm.yaml")));
        assert_eq!(invocation.mode, Mode::Cli(args(&["scope", "list", "-q"])));

        let named_dash_v = parse_invocation(args(&["--config", "-v", "web"]))
            .expect("parses")
            .expect("something to run");
        assert_eq!(named_dash_v.term, TermOpts::default());
        assert_eq!(named_dash_v.config_arg, Some(PathBuf::from("-v")));
        assert_eq!(named_dash_v.mode, Mode::Web);
        assert!(named_dash_v.web_args.is_some());
    }

    /// AC-W1-3 through the real producer: the error `bind_service_port`
    /// returns maps to M2's fields and its plain panel carries every literal
    /// the live proof greps for, with no `os error` text.
    #[test]
    fn addr_in_use_error_maps_to_the_m2_panel() {
        use aitm::startup::errors::report_for;
        use aitm_term::error::{ErrorKind, ErrorReport, FixCommand};

        let addr: std::net::SocketAddr = "127.0.0.1:18080".parse().unwrap();
        let remedy = "Free it, or set `listen:` to another address in aitm.yaml.";
        let err = addr_in_use_error(addr, "the proxy", remedy);
        let report = report_for(&err, Some(std::path::Path::new("/x/aitm.log")));
        assert_eq!(
            report,
            ErrorReport {
                kind: ErrorKind::Failure,
                what: "cannot start: the proxy port 127.0.0.1:18080 is already in use".to_string(),
                why: vec![
                    "It is most likely held by another running `aitm`, the aitmproxy macOS app's embedded core, or another program.".to_string()
                ],
                fix: Some(remedy.to_string()),
                command: Some(FixCommand("lsof -nP -iTCP:18080 -sTCP:LISTEN".to_string())),
                log: Some(PathBuf::from("/x/aitm.log")),
            }
        );
        assert_eq!(report.exit_code(), 1);
        assert_eq!(
            report.render_plain(&aitm_term::glyphs::ASCII),
            "error: cannot start: the proxy port 127.0.0.1:18080 is already in use\n\
             \x20 It is most likely held by another running `aitm`, the aitmproxy macOS app's embedded core, or another program.\n\
             \x20 Free it, or set `listen:` to another address in aitm.yaml.\n\
             \x20 fix: lsof -nP -iTCP:18080 -sTCP:LISTEN\n\
             \x20 log: /x/aitm.log\n"
        );
    }
}
