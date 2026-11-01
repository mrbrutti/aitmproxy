//! The `aitm` binary: build the proxy from config, then run the accept loop plus
//! the selected MCP transport, or dispatch a one-shot CLI command.
//!
//! Config comes from `--config <path>` (a leading flag stripped before CLI
//! dispatch), else `AITM_CONFIG`, else the default path (spec §D10); the env
//! bridge (`aitm::env`) is applied on top. Invoked with a subcommand (`aitm flow
//! list`, `aitm scope add --host ex.test`) it dispatches once over the CLI
//! frontend, prints via `render_cli_value`, and exits. Invoked bare it starts
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
use aitm::render::render_cli_value;
use aitm::scripts::LateHandles;
use aitm::tui::TuiLog;
use aitm::web::{self, WebArgs, WebCommand, WebState};
use aitm::wire::{
    assemble_with_scripts, build_capture_session, self_port_hook, Assembled, Features, ScriptWiring,
};
use aitm::{audit_log, config_file, env, operator_token, tui};
use aitm_core::{engine_may_reach_private, BrowserDriver, Chain, McpTransport, Plugin};
use aitm_findings::FindingsPlugin;
use aitm_plugin_rhai::{MemoryFindingSink, ScriptEntry, ScriptServices};
use aitm_sysproxy::watchdog::{self, WatchdogArgs};
use aitm_sysproxy::{Recovery, SystemProxy};
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
/// a one-shot process never reaches this.
async fn bind_then_recover_system_proxy<T, F>(
    mode: &Mode,
    sysproxy: &SystemProxy,
    auto: bool,
    bind: F,
) -> anyhow::Result<T>
where
    F: Future<Output = anyhow::Result<T>>,
{
    let bound = bind.await?;
    if manages_system_proxy(mode) {
        let recovery = sysproxy.recover_at_startup(auto);
        log_recovery("startup", &recovery);
    }
    Ok(bound)
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
    web_args: Option<WebArgs>,
    mode: Mode,
}

/// Classify `argv`. `None` when `aitm web --help` printed its usage and
/// there is nothing to run. A mode usage error prints its line and exits 2
/// (nothing has been built yet, so nothing needs tearing down).
fn parse_invocation(argv: Vec<String>) -> anyhow::Result<Option<Invocation>> {
    let (config_arg, argv) = split_config_arg(argv)?;
    let (script_args, argv) = split_script_args(argv)?;
    let (bus_endpoint_file, argv) = split_bus_endpoint_file_arg(argv)?;
    // `aitm web …` is the server path with the web UI attached; its options
    // are resolved before any config is loaded so `--help` and bad flags are
    // answered immediately.
    let web_args: Option<WebArgs> = match argv.first().map(String::as_str) {
        Some("web") => match web::parse_args(&argv[1..])? {
            WebCommand::Help => {
                print!("{}", web::USAGE);
                return Ok(None);
            }
            WebCommand::Run(args) => Some(args),
        },
        _ => None,
    };
    let mode = match parse_mode(argv) {
        Ok(mode) => mode,
        Err(usage) => {
            eprintln!("{usage}");
            std::process::exit(2);
        }
    };
    Ok(Some(Invocation {
        config_arg,
        script_args,
        bus_endpoint_file,
        web_args,
        mode,
    }))
}

/// The runtime is built by hand rather than with `#[tokio::main]` so its
/// workers get a stack sized for script evaluation: a hook runs on the worker
/// that dispatches it (`block_in_place`), and Rhai recurses once per nesting
/// level of a value — see `aitm_plugin_rhai::engine::WORKER_STACK_SIZE`.
fn main() -> anyhow::Result<()> {
    let Some(invocation) = parse_invocation(std::env::args().skip(1).collect())? else {
        return Ok(());
    };
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
            let written = operator_token::generate_and_store(&config_path, *force)?;
            println!("{}", operator_token::confirmation_message(&written));
            return Ok(());
        }
        Mode::Server | Mode::Cli(_) | Mode::Tui | Mode::Web => {}
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_stack_size(aitm_plugin_rhai::engine::WORKER_STACK_SIZE)
        .build()?;
    runtime.block_on(run(invocation))
}

async fn run(invocation: Invocation) -> anyhow::Result<()> {
    let Invocation {
        config_arg,
        script_args,
        bus_endpoint_file,
        web_args,
        mode,
    } = invocation;
    let web_settings = match &web_args {
        Some(args) => Some(args.resolve(|k| std::env::var(k).ok())?),
        None => None,
    };
    // The TUI owns the terminal, so its subscriber must not write there.
    // (`OperatorToken` and `SysproxyWatchdog` never reach here: `main`
    // dispatched both before the runtime was built. Their arms stay so the
    // match is exhaustive over `Mode` rather than hiding behind `_`.)
    let tui_log = match mode {
        Mode::Tui => tui::init_tracing(),
        Mode::Server
        | Mode::Cli(_)
        | Mode::Web
        | Mode::OperatorToken { .. }
        | Mode::SysproxyWatchdog { .. } => {
            init_tracing();
            TuiLog::Off
        }
    };

    let config_path = config_arg.or_else(|| std::env::var_os(CONFIG_ENV).map(PathBuf::from));
    let Settings {
        core: mut cfg,
        rhai: mut rhai_cfg,
        mut l4,
        macos_capture,
        // The `system_proxy:` section: `wire.rs` builds the `SystemProxy`
        // engine from it, and `auto` drives the startup recovery below.
        system_proxy,
    } = config_file::load_settings(config_path.as_deref())?;
    env::apply(&mut cfg, |k| std::env::var(k).ok());
    env::apply_rhai(&mut rhai_cfg, |k| std::env::var(k).ok());
    // `--bus-endpoint-file` wins over the config's `endpoint_file`; it only means
    // anything for the loopback-TCP bus, so asking for it over stdio is an error.
    apply_bus_endpoint_file(&mut cfg.mcp.transport, bus_endpoint_file)?;
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
    let languages: Vec<&dyn aitm_plugin::language::ProtocolLanguage> = match &l4_language {
        Some(lang) => vec![lang],
        None => Vec::new(),
    };
    let tier = aitm_plugin_rhai::wire::build_with_languages(rhai_cfg, script_services, &languages)?;
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
        r
    };
    drop(l4_language);
    for err in &tier.errors {
        warn!(target: "aitm::scripts", "{err}");
    }
    if strict && !tier.errors.is_empty() {
        anyhow::bail!(
            "{} script(s) failed to load and `rhai.strict` is set",
            tier.errors.len()
        );
    }
    for name in tier.host.set().names() {
        info!(target: "aitm::scripts", script = %name, "script loaded into the host");
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
        ..Features::default()
    };
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
        },
    )?;
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
        // `..` stands only for the private `governance` (taken above). Any new
        // `pub` field of `Assembled` must be named here, not absorbed by it.
        ..
    } = assembled;

    if let Mode::Cli(argv) = &mode {
        // One-shot CLI dispatch (no browser needed): the same service
        // handles the frontends share, without a browser or a log file.
        let s = tui::services(&proxy, &cfg, None, TuiLog::Off);
        handles.bind_proxy(s.store.clone(), s.client.clone(), s.guard.clone());
        tier.error_sink
            .bind(Arc::new(Chain::new(s.registry.clone(), s.store.clone())));
        let cli = aitm_cli::Cli::new(s.registry.clone())
            .with_ssrf_policy(cfg.browser.ssrf.clone())
            .with_poc_dir(cfg.poc.dir.clone())
            .with_config(Arc::new(cfg.clone()))
            .with_finding_recorder(Arc::new(aitm_findings::DiskFindingRecorder))
            // The proxy's live egress posture, so `aitm browser confine` flips
            // the connector's real posture (Task 4b).
            .with_egress(s.egress.clone())
            .with_services(s.store, s.client, s.guard, None);
        match cli.dispatch(argv) {
            Ok(value) => {
                let mut stdout = std::io::stdout().lock();
                stdout.write_all(&render_cli_value(&value))?;
                stdout.flush()?;
                return Ok(());
            }
            Err(err) => {
                eprintln!("{err}");
                std::process::exit(1);
            }
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
    // no `?` remains before the `select!`, so the §D9 (a) restore below is reached
    // on every path.
    let config_display = config_path
        .unwrap_or_else(config_file::default_config_path)
        .display()
        .to_string();
    let Bound {
        proxy_listener,
        browser_listener,
        web_listener,
        proxy_addr,
        browser_addr,
    } = bind_then_recover_system_proxy(&mode, &sysproxy, system_proxy.auto, async {
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
    .await?;

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
    // the system-proxy auto-set and the `select!` (its restore-on-exit depends on it).
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
    let launched = match aitm_browser::launch_owned(&browser_cfg, ca.cert_path()).await {
        Ok(l) => Some(l),
        Err(e) => {
            warn!(
                engine = ?cfg.browser.engine,
                error = %e,
                "embedded browser unavailable; browser.* commands will error"
            );
            None
        }
    };
    let browser: Option<Arc<dyn BrowserDriver>> = launched.as_ref().map(|l| l.driver.clone());
    // Shared service handles for the frontends and the replay client.
    let services = tui::services(&proxy, &cfg, browser.clone(), tui_log);

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
    let result = if mode == Mode::Tui {
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
                // tracing sink. The one-time summary println is the operator's
                // link — its URLs carry the token on purpose (stdout, not logs).
                web::log_listening(bound);
                let operator_url = operator_token
                    .as_ref()
                    .map(|op| web::operator_ui_url(bound, op));
                println!(
                    "{}",
                    web::startup_summary(
                        &url,
                        operator_url.as_deref(),
                        proxy_addr,
                        browser_addr,
                        "ready"
                    )
                );
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

        // The main listener relays client traffic; the browser listener is
        // SSRF-filtered (the embedded browser dials `cfg.browser.proxy_addr`).
        // Both sockets were pre-bound above, so the accept loops just run on them.
        tokio::select! {
            result = proxy.run_on(proxy_listener) => result,
            result = proxy.run_browser_on(browser_listener) => result,
            result = mcp.serve() => result,
            result = web_run => result,
            never = capture_run => match never {},
            () = aitm::shutdown_signal() => {
                info!("shutdown signal received");
                Ok(())
            }
        }
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
    // is bounded (`SHUTDOWN_BUDGET`), so a stalled disk cannot hold the exit.
    if let Some(handle) = &audit {
        let report = handle.shutdown(audit_log::SHUTDOWN_BUDGET);
        if !report.complete {
            warn!(
                target: "aitm::audit",
                estimated_left = report.estimated_left,
                "the audit log did not finish flushing before exit"
            );
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

/// The curated default tracing directive used when `RUST_LOG` is unset (AC3).
///
/// Operator-relevant lifecycle on the `aitm*` targets ("proxy listening", the
/// obscura start/stop/attach lines) stays at `info`, while the noisy transport
/// and browser dependencies are pinned to `warn` so a normal browsing session
/// does not bury the useful lines under per-connection dependency chatter.
/// Benign per-connection disconnects are already emitted at `debug` (Task 1),
/// so the `info` baseline hides them without a per-target pin. `RUST_LOG`, when
/// set, overrides this wholesale (see [`build_env_filter`]).
const DEFAULT_LOG_DIRECTIVE: &str = "info,\
    chromiumoxide=warn,\
    tungstenite=warn,\
    tokio_tungstenite=warn,\
    hyper=warn,\
    hyper_util=warn,\
    rustls=warn,\
    tower=warn,\
    reqwest=warn";

/// Build the server path's `EnvFilter`: `rust_log` (the `RUST_LOG` value) when it
/// is set and non-empty overrides the default wholesale; otherwise the curated
/// [`DEFAULT_LOG_DIRECTIVE`] is used. Both parse lossily, so a malformed
/// directive drops the bad part rather than failing startup.
fn build_env_filter(rust_log: Option<String>) -> tracing_subscriber::EnvFilter {
    use tracing_subscriber::EnvFilter;
    match rust_log.filter(|v| !v.trim().is_empty()) {
        Some(directive) => EnvFilter::new(directive),
        None => EnvFilter::new(DEFAULT_LOG_DIRECTIVE),
    }
}

/// Install a tracing subscriber: `RUST_LOG`-driven, defaulting to the curated
/// quiet filter ([`DEFAULT_LOG_DIRECTIVE`]).
fn init_tracing() {
    use tracing_subscriber::fmt;
    let filter = build_env_filter(std::env::var("RUST_LOG").ok());
    let _ = fmt().with_env_filter(filter).try_init();
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
/// most likely holds it, and how to change it.
fn addr_in_use_error(addr: std::net::SocketAddr, role: &str, remedy: &str) -> anyhow::Error {
    anyhow::anyhow!(
        "cannot start: {role} port {addr} is already in use.\n\
         It is most likely held by another running `aitm`, the aitmproxy macOS app's \
         embedded core, or another program.\n\
         {remedy}\n\
         Find the holder with:  lsof -nP -iTCP:{port} -sTCP:LISTEN",
        port = addr.port(),
    )
}

#[cfg(test)]
mod tests {
    use std::io::{self, Write};
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};

    use tracing_subscriber::fmt::MakeWriter;

    use aitm_core::McpTransport;

    use aitm::wire::{build_proxy_with, Features};

    use aitm_ca::exec::Executor;
    use aitm_ca::testing::ScriptedExecutor;
    use aitm_sysproxy::{Endpoint, Mechanism, SystemProxy, SystemProxyConfig, STATE_FILE_NAME};

    use super::{
        addr_in_use_error, apply_bus_endpoint_file, bind_then_recover_system_proxy,
        build_env_filter, configured_agent_port, manages_system_proxy, parse_invocation,
        parse_mode, split_bus_endpoint_file_arg, split_config_arg, split_script_args, Invocation,
        Mode, OPERATOR_TOKEN_USAGE,
    };

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

    /// Install a subscriber with `filter` over a buffer, run `f`, and return
    /// everything it emitted — so a test can assert which targets/levels survive.
    fn capture_with_filter(filter: tracing_subscriber::EnvFilter, f: impl FnOnce()) -> String {
        let buf = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_env_filter(filter)
            .with_writer(BufWriter(buf.clone()))
            .finish();
        tracing::subscriber::with_default(subscriber, f);
        let bytes = buf.lock().unwrap().clone();
        String::from_utf8(bytes).unwrap()
    }

    #[test]
    fn default_filter_quiets_connection_noise() {
        // AC3: the curated default (no RUST_LOG) keeps operator lifecycle while
        // silencing per-connection dependency chatter and benign disconnects.
        let out = capture_with_filter(build_env_filter(None), || {
            tracing::info!(target: "aitm_core::proxy", "proxy listening");
            tracing::info!(target: "chromiumoxide", "cdp event spam");
            tracing::debug!(target: "aitm_core::proxy", "connection closed before completion");
        });
        assert!(
            out.contains("proxy listening"),
            "operator lifecycle must survive the default filter: {out:?}"
        );
        assert!(
            !out.contains("cdp event spam"),
            "noisy dependency target must be pinned below info: {out:?}"
        );
        assert!(
            !out.contains("connection closed before completion"),
            "benign per-connection debug must stay hidden at the info baseline: {out:?}"
        );
    }

    #[test]
    fn rust_log_overrides_the_curated_default() {
        // AC3: RUST_LOG overrides the curated default wholesale — a directive that
        // raises a pinned dependency to trace makes its trace events appear.
        let out = capture_with_filter(build_env_filter(Some("chromiumoxide=trace".into())), || {
            tracing::trace!(target: "chromiumoxide", "cdp trace restored");
        });
        assert!(
            out.contains("cdp trace restored"),
            "RUST_LOG must override the curated default wholesale: {out:?}"
        );
    }

    #[test]
    fn empty_rust_log_falls_back_to_the_curated_default() {
        // An empty RUST_LOG is treated as unset, not as "disable everything".
        let out = capture_with_filter(build_env_filter(Some("   ".into())), || {
            tracing::info!(target: "aitm_core::proxy", "proxy listening");
        });
        assert!(
            out.contains("proxy listening"),
            "an empty RUST_LOG must fall back to the curated default: {out:?}"
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
        let bound =
            bind_then_recover_system_proxy(&Mode::Cli(args(&["flow", "list"])), &sp, true, async {
                Ok(("proxy", "browser"))
            })
            .await
            .unwrap();
        assert_eq!(bound, ("proxy", "browser"));
        assert_eq!(
            exec.runs(),
            Vec::<String>::new(),
            "a one-shot mode never recovers"
        );

        let bound = bind_then_recover_system_proxy(&Mode::Server, &sp, true, async {
            Ok(("proxy", "browser"))
        })
        .await
        .unwrap();
        assert_eq!(
            bound,
            ("proxy", "browser"),
            "the bound listeners come back untouched"
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
                web_args,
                mode,
            } = parse_invocation(argv.clone())
                .expect("parses")
                .expect("something to run");
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
}
