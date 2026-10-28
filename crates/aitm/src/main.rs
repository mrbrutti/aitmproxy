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

use aitm::render::render_cli_value;
use aitm::wire::{assemble, Assembled, Http1Sender};
use aitm::{config_file, env};
use aitm_core::{BrowserDriver, PipelineClient, ProxyClient};
use tracing::{info, warn};

/// The config file path when `--config` is not given.
const CONFIG_ENV: &str = "AITM_CONFIG";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();

    let (config_arg, argv) = split_config_arg(std::env::args().skip(1).collect())?;
    let config_path = config_arg.or_else(|| std::env::var_os(CONFIG_ENV).map(PathBuf::from));
    let mut cfg = config_file::load(config_path.as_deref())?;
    env::apply(&mut cfg, |k| std::env::var(k).ok());
    let Assembled { proxy, ca } = assemble(&cfg)?;

    // Shared service handles for the frontends and the replay client.
    let registry = proxy.registry_arc();
    let store = proxy.store();
    let guard = proxy.guard();
    let client: Arc<dyn ProxyClient> = Arc::new(PipelineClient::new(
        store.clone(),
        guard.clone(),
        Arc::new(Http1Sender::new().with_insecure(cfg.ssl_insecure)),
    ));

    if !argv.is_empty() {
        // One-shot CLI dispatch (no browser needed).
        let cli = aitm_cli::Cli::new(registry.clone())
            .with_ssrf_policy(cfg.browser.ssrf.clone())
            .with_poc_dir(cfg.poc.dir.clone())
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

    let mcp = aitm_mcp::McpServer::new(registry, cfg.mcp.transport.clone())
        .with_ssrf_policy(cfg.browser.ssrf.clone())
        .with_poc_dir(cfg.poc.dir.clone())
        .with_services(store, client, guard, browser);

    // The main listener relays client traffic; the browser listener is
    // SSRF-filtered (the embedded browser dials `cfg.browser.proxy_addr`).
    let main_listen = cfg.listen;
    let browser_listen = cfg.browser.proxy_addr;
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

    use super::split_config_arg;

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
}
