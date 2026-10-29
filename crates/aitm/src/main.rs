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

use std::io::Write as _;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use aitm::config_file::Settings;
use aitm::render::render_cli_value;
use aitm::scripts::LateHandles;
use aitm::tui::TuiLog;
use aitm::web::{self, WebArgs, WebCommand, WebState};
use aitm::wire::{assemble_with_scripts, Assembled, Features, ScriptWiring};
use aitm::{config_file, env, tui};
use aitm_core::{BrowserDriver, Chain, Plugin};
use aitm_findings::FindingsPlugin;
use aitm_plugin_rhai::{MemoryFindingSink, ScriptEntry, ScriptServices};
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
}

/// Classify `argv`. `tui` takes no arguments; anything after it is a usage
/// error carrying the line to print. `web` is recognised here and its
/// options parsed by the caller (`web::parse_args`).
fn parse_mode(argv: Vec<String>) -> Result<Mode, String> {
    match argv.first().map(String::as_str) {
        None => Ok(Mode::Server),
        Some("tui") if argv.len() == 1 => Ok(Mode::Tui),
        Some("tui") => Err(tui::USAGE.to_string()),
        Some("web") => Ok(Mode::Web),
        Some(_) => Ok(Mode::Cli(argv)),
    }
}

/// The runtime is built by hand rather than with `#[tokio::main]` so its
/// workers get a stack sized for script evaluation: a hook runs on the worker
/// that dispatches it (`block_in_place`), and Rhai recurses once per nesting
/// level of a value — see `aitm_plugin_rhai::engine::WORKER_STACK_SIZE`.
fn main() -> anyhow::Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_stack_size(aitm_plugin_rhai::engine::WORKER_STACK_SIZE)
        .build()?;
    runtime.block_on(run())
}

async fn run() -> anyhow::Result<()> {
    let (config_arg, argv) = split_config_arg(std::env::args().skip(1).collect())?;
    let (script_args, argv) = split_script_args(argv)?;
    // `aitm web …` is the server path with the web UI attached; its options
    // are resolved before any config is loaded so `--help` and bad flags are
    // answered immediately.
    let web_args: Option<WebArgs> = match argv.first().map(String::as_str) {
        Some("web") => match web::parse_args(&argv[1..])? {
            WebCommand::Help => {
                print!("{}", web::USAGE);
                return Ok(());
            }
            WebCommand::Run(args) => Some(args),
        },
        _ => None,
    };
    let web_settings = match &web_args {
        Some(args) => Some(args.resolve(|k| std::env::var(k).ok())?),
        None => None,
    };
    let mode = match parse_mode(argv) {
        Ok(mode) => mode,
        Err(usage) => {
            eprintln!("{usage}");
            std::process::exit(2);
        }
    };
    // The TUI owns the terminal, so its subscriber must not write there.
    let tui_log = match mode {
        Mode::Tui => tui::init_tracing(),
        Mode::Server | Mode::Cli(_) | Mode::Web => {
            init_tracing();
            TuiLog::Off
        }
    };

    let config_path = config_arg.or_else(|| std::env::var_os(CONFIG_ENV).map(PathBuf::from));
    let Settings {
        core: mut cfg,
        rhai: mut rhai_cfg,
        mut l4,
    } = config_file::load_settings(config_path.as_deref())?;
    env::apply(&mut cfg, |k| std::env::var(k).ok());
    env::apply_rhai(&mut rhai_cfg, |k| std::env::var(k).ok());
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
    let tier = aitm_plugin_rhai::wire::build(rhai_cfg, script_services)?;
    for err in &tier.errors {
        warn!(target: "aitm::scripts", "{err}");
    }
    if strict && !tier.errors.is_empty() {
        anyhow::bail!(
            "{} script(s) failed to load and `rhai.strict` is set",
            tier.errors.len()
        );
    }
    for plugin in &tier.plugins {
        info!(target: "aitm::scripts", script = %plugin.name(), "script plugin registered");
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

    let Assembled {
        proxy,
        ca,
        listening,
        agent_state,
        push_tx,
        audit_ring,
        // The protocol-general capture ingress is bound to the live L4 module here but
        // not fed in Phase 1 (the pcap capture path is `l4.capture.*`'s own; a backend
        // that calls `accept` is Phase 2's macOS Network/System Extension).
        l4_ingress: _,
    } = assemble_with_scripts(
        &cfg,
        &Features {
            l4,
            ..Features::default()
        },
        ScriptWiring {
            plugins: tier
                .plugins
                .into_iter()
                .map(|p| Box::new(p.with_max_body(max_body)) as Box<dyn Plugin>)
                .collect(),
            executor: Some(tier.executor.clone()),
            // Both command providers: the rhai tier (script.validate/reload,
            // script.findings) and the persistent findings store, whose
            // `findings.*` commands read the configured `findings.dir` from the
            // command host at invocation time (`FindingsPlugin::store_for`).
            commands: vec![Box::new(tier.commands), Box::new(FindingsPlugin::new())],
        },
    )?;

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

    // Server path: launch the configured engine so the browser.* commands reach
    // a live driver. No fallback to the other engine.
    let launched = match aitm_browser::launch_owned(&cfg.browser, ca.cert_path()).await {
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

    // We are about to serve: `proxy.status.listening` now reports the truth.
    listening.store(true, std::sync::atomic::Ordering::Relaxed);
    let result = if mode == Mode::Tui {
        tui::run(&cfg, &proxy, services).await
    } else {
        // The bare-`aitm` server path is the dedicated agent entry point, so it
        // carries M4's operator/agent token classes, the shared agent policy
        // gate, the F4 push fan-out and the F2 audit ring. The web bridge and
        // the TUI are operator frontends, built by `tui::server` without the gate.
        let mcp = tui::server(&cfg, cfg.mcp.transport.clone(), &services)
            .with_mcp_roles(cfg.mcp.operator_token.clone(), cfg.mcp.stdio_role)
            .with_agent_state(agent_state)
            .with_push(push_tx)
            .with_audit_ring(audit_ring);

        // `aitm web`: a second McpServer over the same registry and services
        // (`serve` consumes the first), driven by the bridge's `handle` calls.
        let web_server = match web_settings {
            Some(settings) => {
                let bus = tui::server(&cfg, cfg.mcp.transport.clone(), &services);
                let state = Arc::new(WebState {
                    mcp: Arc::new(bus),
                    token: settings.token.clone(),
                });
                if settings.insecure_bind {
                    warn!(
                        listen = %settings.listen,
                        "binding the web UI off loopback WITHOUT TLS ({}=1); the bridge token \
                         is its only protection",
                        web::INSECURE_BIND_ENV
                    );
                }
                // The proxy and the browser's proxy port bind later in the select; a shared
                // address would surface as a bare "address in use" there, so name it here.
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
                let listener = TcpListener::bind(settings.listen).await?;
                let url = web::ui_url(listener.local_addr()?, &settings.token);
                info!(url = %url, "web UI listening");
                println!("web UI: {url}");
                Some((listener, state))
            }
            None => None,
        };
        let web_run = async move {
            match web_server {
                Some((listener, state)) => web::serve(listener, state).await,
                None => std::future::pending().await,
            }
        };

        // The main listener relays client traffic; the browser listener is
        // SSRF-filtered (the embedded browser dials `cfg.browser.proxy_addr`).
        let main_listen = cfg.listen;
        let browser_listen = cfg.browser.proxy_addr;
        tokio::select! {
            result = proxy.run(main_listen) => result,
            result = proxy.run_browser(browser_listen) => result,
            result = mcp.serve() => result,
            result = web_run => result,
            () = aitm::shutdown_signal() => {
                info!("shutdown signal received");
                Ok(())
            }
        }
    };

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
    result
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

/// Install a tracing subscriber (RUST_LOG-driven, defaulting to `info`).
fn init_tracing() {
    use tracing_subscriber::{fmt, EnvFilter};
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = fmt().with_env_filter(filter).try_init();
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{parse_mode, split_config_arg, split_script_args, Mode};

    fn args(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
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
    fn tui_with_extra_arguments_is_a_usage_error() {
        assert_eq!(
            parse_mode(args(&["tui", "extra"])),
            Err("usage: aitm [--config <path>] tui (takes no further arguments)".to_string())
        );
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
}
