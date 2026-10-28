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

use std::io::Write as _;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use aitm::render::render_cli_value;
use aitm::tui::TuiLog;
use aitm::wire::{assemble, Assembled};
use aitm::{config_file, env, tui};
use aitm_core::BrowserDriver;
use tracing::{info, warn};

/// The config file path when `--config` is not given.
const CONFIG_ENV: &str = "AITM_CONFIG";

/// What the command line asked for, after the `--config` split.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Mode {
    /// No arguments: the proxy plus the configured MCP transport.
    Server,
    /// A subcommand: one-shot dispatch over the CLI frontend.
    Cli(Vec<String>),
    /// `tui`: the proxy plus the terminal operator UI in one process.
    Tui,
}

/// Classify `argv`. `tui` takes no arguments; anything after it is a usage
/// error carrying the line to print.
fn parse_mode(argv: Vec<String>) -> Result<Mode, String> {
    match argv.first().map(String::as_str) {
        None => Ok(Mode::Server),
        Some("tui") if argv.len() == 1 => Ok(Mode::Tui),
        Some("tui") => Err(tui::USAGE.to_string()),
        Some(_) => Ok(Mode::Cli(argv)),
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let (config_arg, argv) = split_config_arg(std::env::args().skip(1).collect())?;
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
        Mode::Server | Mode::Cli(_) => {
            init_tracing();
            TuiLog::Off
        }
    };

    let config_path = config_arg.or_else(|| std::env::var_os(CONFIG_ENV).map(PathBuf::from));
    let mut cfg = config_file::load(config_path.as_deref())?;
    env::apply(&mut cfg, |k| std::env::var(k).ok());
    let Assembled { proxy, ca } = assemble(&cfg)?;

    if let Mode::Cli(argv) = &mode {
        // One-shot CLI dispatch (no browser needed): the same service
        // handles the frontends share, without a browser or a log file.
        let s = tui::services(&proxy, &cfg, None, TuiLog::Off);
        let cli = aitm_cli::Cli::new(s.registry.clone())
            .with_ssrf_policy(cfg.browser.ssrf.clone())
            .with_poc_dir(cfg.poc.dir.clone())
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
    let services = tui::services(&proxy, &cfg, browser, tui_log);

    let result = if mode == Mode::Tui {
        tui::run(&cfg, &proxy, services).await
    } else {
        let mcp = tui::server(&cfg, cfg.mcp.transport.clone(), &services);

        // The main listener relays client traffic; the browser listener is
        // SSRF-filtered (the embedded browser dials `cfg.browser.proxy_addr`).
        let main_listen = cfg.listen;
        let browser_listen = cfg.browser.proxy_addr;
        tokio::select! {
            result = proxy.run(main_listen) => result,
            result = proxy.run_browser(browser_listen) => result,
            result = mcp.serve() => result,
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

/// Install a tracing subscriber (RUST_LOG-driven, defaulting to `info`).
fn init_tracing() {
    use tracing_subscriber::{fmt, EnvFilter};
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = fmt().with_env_filter(filter).try_init();
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{parse_mode, split_config_arg, Mode};

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
    fn tui_with_extra_arguments_is_a_usage_error() {
        assert_eq!(
            parse_mode(args(&["tui", "extra"])),
            Err("usage: aitm [--config <path>] tui (takes no further arguments)".to_string())
        );
    }
}
