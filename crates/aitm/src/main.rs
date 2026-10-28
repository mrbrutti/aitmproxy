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

use std::io::Write as _;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use aitm::config_file::Settings;
use aitm::render::render_cli_value;
use aitm::scripts::LateHandles;
use aitm::wire::{assemble_with_scripts, Assembled, Features, Http1Sender, ScriptWiring};
use aitm::{config_file, env};
use aitm_core::{BrowserDriver, Chain, PipelineClient, Plugin, ProxyClient};
use aitm_plugin_rhai::{MemoryFindingSink, ScriptEntry, ScriptServices};
use tracing::{info, warn};

/// The config file path when `--config` is not given.
const CONFIG_ENV: &str = "AITM_CONFIG";

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
    init_tracing();

    let (config_arg, argv) = split_config_arg(std::env::args().skip(1).collect())?;
    let (script_args, argv) = split_script_args(argv)?;
    let config_path = config_arg.or_else(|| std::env::var_os(CONFIG_ENV).map(PathBuf::from));
    let Settings {
        core: mut cfg,
        rhai: mut rhai_cfg,
    } = config_file::load_settings(config_path.as_deref())?;
    env::apply(&mut cfg, |k| std::env::var(k).ok());
    env::apply_rhai(&mut rhai_cfg, |k| std::env::var(k).ok());
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
    let services = ScriptServices {
        store: handles.clone(),
        client: handles.clone(),
        browser: Some(handles.clone()),
        guard: handles.clone(),
        findings,
        rt: tokio::runtime::Handle::current(),
    };
    let strict = rhai_cfg.strict;
    let tier = aitm_plugin_rhai::wire::build(rhai_cfg, services)?;
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
    } = assemble_with_scripts(
        &cfg,
        &Features::default(),
        ScriptWiring {
            plugins: tier
                .plugins
                .into_iter()
                .map(|p| Box::new(p.with_max_body(max_body)) as Box<dyn Plugin>)
                .collect(),
            executor: Some(tier.executor.clone()),
            commands: Some(Box::new(tier.commands)),
        },
    )?;

    // Shared service handles for the frontends and the replay client.
    let registry = proxy.registry_arc();
    let store = proxy.store();
    let guard = proxy.guard();
    let client: Arc<dyn ProxyClient> = Arc::new(PipelineClient::new(
        store.clone(),
        guard.clone(),
        Arc::new(Http1Sender::new().with_insecure(cfg.ssl_insecure)),
    ));

    // The scripting tier now reaches exactly the proxy's store, client and
    // guard, and a failed hook's `Event::Error` reaches the chain rather than
    // only the log.
    handles.bind_proxy(store.clone(), client.clone(), guard.clone());
    tier.error_sink
        .bind(Arc::new(Chain::new(registry.clone(), store.clone())));

    if !argv.is_empty() {
        // One-shot CLI dispatch (no browser needed).
        let cli = aitm_cli::Cli::new(registry.clone())
            .with_ssrf_policy(cfg.browser.ssrf.clone())
            .with_poc_dir(cfg.poc.dir.clone())
            .with_config(Arc::new(cfg.clone()))
            .with_services(store.clone(), client.clone(), guard.clone(), None);
        match cli.dispatch(&argv) {
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
    // `browser.*` in a script reaches the same engine the commands do.
    if let Some(driver) = browser.clone() {
        handles.bind_browser(driver);
    }

    let mcp = aitm_mcp::McpServer::new(registry, cfg.mcp.transport.clone())
        .with_ssrf_policy(cfg.browser.ssrf.clone())
        .with_poc_dir(cfg.poc.dir.clone())
        .with_config(Arc::new(cfg.clone()))
        .with_services(store, client, guard, browser);

    // The main listener relays client traffic; the browser listener is
    // SSRF-filtered (the embedded browser dials `cfg.browser.proxy_addr`).
    let main_listen = cfg.listen;
    let browser_listen = cfg.browser.proxy_addr;
    // We are about to serve: `proxy.status.listening` now reports the truth.
    listening.store(true, std::sync::atomic::Ordering::Relaxed);
    let result = tokio::select! {
        result = proxy.run(main_listen) => result,
        result = proxy.run_browser(browser_listen) => result,
        result = mcp.serve() => result,
        () = shutdown_signal() => {
            info!("shutdown signal received");
            Ok(())
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

/// Resolves on SIGINT (Ctrl-C) or, on Unix, SIGTERM. A handler that cannot be
/// installed is logged and never fires, so it cannot end the run by itself.
async fn shutdown_signal() {
    let interrupt = async {
        if let Err(e) = tokio::signal::ctrl_c().await {
            warn!(error = %e, "could not install the SIGINT handler");
            std::future::pending::<()>().await;
        }
    };
    #[cfg(unix)]
    let terminate = async {
        use tokio::signal::unix::{signal, SignalKind};
        match signal(SignalKind::terminate()) {
            Ok(mut term) => {
                term.recv().await;
            }
            Err(e) => {
                warn!(error = %e, "could not install the SIGTERM handler");
                std::future::pending::<()>().await;
            }
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        () = interrupt => {}
        () = terminate => {}
    }
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

    use super::{split_config_arg, split_script_args};

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
}
