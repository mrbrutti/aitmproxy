//! `aitm tui`: the proxy and the terminal operator UI in one process
//! (operator-UI foundation §2.10(c), TUI plan Task 4).
//!
//! The proxy is built exactly as the server path builds it; this module then
//! constructs **two** `McpServer`s over the same `Arc<Registry>` and service
//! handles. One is served on the configured agent transport — only when that
//! is loopback TCP, because stdio would share the terminal with the UI. The
//! other is wrapped as `Arc<McpServer>` so its `handle` becomes the TUI's
//! in-process bus handler: the bus contract is unchanged, the TUI is a bus
//! client like the others, there is just no socket between them.
//!
//! Logging: a `tracing` subscriber writing to stdout or stderr would paint
//! over the UI, so [`init_tracing`] writes to `aitm-tui.log` under the
//! system temp directory when `RUST_LOG` is set and installs nothing when it
//! is not. The path is returned so the UI can show it in a startup toast once
//! `aitm-tui` grows that hook; until then it is only in this doc.

use std::fs::OpenOptions;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use aitm_bus_client::InProcessHandler;
use aitm_core::{
    BrowserDriver, Config, FlowStore, McpTransport, Proxy, ProxyClient, Registry, ScopeRateGuard,
};
use aitm_mcp::McpServer;
use aitm_tui::{RunOptions, TransportChoice};
use tracing::{info, warn};

/// The usage line printed (exit status 2) when `tui` is given arguments.
pub const USAGE: &str = "usage: aitm [--config <path>] tui (takes no further arguments)";

/// The log file name under [`std::env::temp_dir`] when `RUST_LOG` is set.
pub const LOG_FILE_NAME: &str = "aitm-tui.log";

/// How often the TUI polls `flow.list` (F4 push is not on the bus yet).
const POLL: Duration = Duration::from_millis(500);

/// The service handles `main` shares between the frontends.
pub struct Services {
    pub registry: Arc<Registry>,
    pub store: Arc<dyn FlowStore>,
    pub client: Arc<dyn ProxyClient>,
    pub guard: Arc<dyn ScopeRateGuard>,
    pub browser: Option<Arc<dyn BrowserDriver>>,
    /// Where tui-mode tracing goes (see [`init_tracing`]), for the startup toast.
    pub log_path: Option<PathBuf>,
}

/// Install the `tui`-mode tracing subscriber: file-backed when `RUST_LOG` is
/// set (returns the file's path), nothing otherwise. Never writes to the
/// terminal. A log file that cannot be opened disables logging rather than
/// failing the run.
pub fn init_tracing() -> Option<PathBuf> {
    use tracing_subscriber::{fmt, EnvFilter};
    let filter = EnvFilter::try_from_default_env().ok()?;
    let path = std::env::temp_dir().join(LOG_FILE_NAME);
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .ok()?;
    let _ = fmt()
        .with_env_filter(filter)
        .with_ansi(false)
        .with_writer(Mutex::new(file))
        .try_init();
    Some(path)
}

/// Build the two servers over the shared `services` and run the proxy, the
/// agent transport (loopback TCP only) and the TUI side by side until one of
/// them ends — the TUI returning on operator quit is the ordinary exit.
///
/// The caller launches and reaps the browser, as it does for the server path.
pub async fn run(cfg: &Config, proxy: &Proxy, services: Services) -> anyhow::Result<()> {
    let Services {
        registry,
        store,
        client,
        guard,
        browser,
        log_path,
    } = services;

    // The agent-facing server: the configured transport, exactly as the
    // server path serves it, unless it is stdio.
    let agent = match &cfg.mcp.transport {
        McpTransport::LoopbackTcp { .. } => Some(
            McpServer::new(registry.clone(), cfg.mcp.transport.clone())
                .with_ssrf_policy(cfg.browser.ssrf.clone())
                .with_poc_dir(cfg.poc.dir.clone())
                .with_services(
                    store.clone(),
                    client.clone(),
                    guard.clone(),
                    browser.clone(),
                ),
        ),
        McpTransport::Stdio => {
            warn!("mcp.transport is stdio, which would share the terminal with the TUI; the agent transport is not served");
            None
        }
    };
    let agent_serve = async move {
        match agent {
            Some(server) => server.serve().await,
            None => std::future::pending().await,
        }
    };

    // The TUI-facing server: never served on a transport, so the variant is
    // only a label; `handle` is called directly through the handler.
    let ui = Arc::new(
        McpServer::new(registry, McpTransport::Stdio)
            .with_ssrf_policy(cfg.browser.ssrf.clone())
            .with_poc_dir(cfg.poc.dir.clone())
            .with_services(store, client, guard, browser),
    );
    let handler: InProcessHandler = Arc::new(move |line: &str| ui.handle(line));
    let tui = aitm_tui::run(RunOptions {
        transport: TransportChoice::InProcess(handler),
        caps: None,
        poll: POLL,
        startup_note: Some(match &log_path {
            Some(p) => format!("embedded proxy · log: {}", p.display()),
            None => "embedded proxy · set RUST_LOG to write a log file".to_string(),
        }),
        listening: Some(cfg.listen.to_string()),
    });

    let main_listen = cfg.listen;
    let browser_listen = cfg.browser.proxy_addr;
    tokio::select! {
        result = proxy.run(main_listen) => result,
        result = proxy.run_browser(browser_listen) => result,
        result = agent_serve => result,
        result = tui => result,
        () = crate::shutdown_signal() => {
            info!("shutdown signal received");
            Ok(())
        }
    }
}
