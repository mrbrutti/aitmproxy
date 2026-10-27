//! The `aitm` binary: build the proxy from config, then run the accept loop plus
//! the selected MCP transport, or dispatch a one-shot CLI command.
//!
//! Invoked with a subcommand (`aitm flow list`, `aitm scope add --host ex.test`)
//! it dispatches once over the CLI frontend and exits. Invoked bare it starts the
//! proxy accept loop and the MCP server (stdio or loopback-TCP per config), with
//! the embedded browser attached when Chromium is available. M1 uses
//! `Config::default()`; reading a config file is a later wave.

use std::sync::Arc;

use aitm::wire::{build_proxy, Http1Sender};
use aitm_core::{BrowserDriver, Config, PipelineClient, ProxyClient};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();

    let cfg = Config::default();
    let proxy = build_proxy(&cfg)?;

    // Shared service handles for the frontends and the replay client.
    let registry = proxy.registry_arc();
    let store = proxy.store();
    let guard = proxy.guard();
    let client: Arc<dyn ProxyClient> = Arc::new(PipelineClient::new(
        store.clone(),
        guard.clone(),
        Arc::new(Http1Sender::new().with_insecure(cfg.ssl_insecure)),
    ));

    let argv: Vec<String> = std::env::args().skip(1).collect();
    if !argv.is_empty() {
        // One-shot CLI dispatch (no browser needed).
        let cli = aitm_cli::Cli::new(registry.clone())
            .with_ssrf_policy(cfg.browser.ssrf.clone())
            .with_poc_dir(cfg.poc.dir.clone())
            .with_services(store.clone(), client.clone(), guard.clone(), None);
        match cli.dispatch(&argv) {
            Ok(value) => {
                println!("{value:?}");
                return Ok(());
            }
            Err(err) => {
                eprintln!("{err}");
                std::process::exit(1);
            }
        }
    }

    // Server path: attach the embedded browser if Chromium is available, so the
    // browser.* commands reach a live driver.
    let browser: Option<Arc<dyn BrowserDriver>> = match aitm_browser::ChromeDriver::launch(
        &cfg.browser,
    )
    .await
    {
        Ok(driver) => Some(Arc::new(driver)),
        Err(e) => {
            tracing::warn!(
                error = %e,
                "embedded browser unavailable; browser.* commands will error until Chromium is installed"
            );
            None
        }
    };

    let mcp = aitm_mcp::McpServer::new(registry, cfg.mcp.transport.clone())
        .with_ssrf_policy(cfg.browser.ssrf.clone())
        .with_poc_dir(cfg.poc.dir.clone())
        .with_services(store, client, guard, browser);

    // The main listener relays client traffic; the browser listener is
    // SSRF-filtered (the embedded browser dials `cfg.browser.proxy_addr`).
    let main_listen = cfg.listen;
    let browser_listen = cfg.browser.proxy_addr;
    tokio::select! {
        result = proxy.run(main_listen) => result,
        result = proxy.run_browser(browser_listen) => result,
        result = mcp.serve() => result,
    }
}

/// Install a tracing subscriber (RUST_LOG-driven, defaulting to `info`).
fn init_tracing() {
    use tracing_subscriber::{fmt, EnvFilter};
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = fmt().with_env_filter(filter).try_init();
}
