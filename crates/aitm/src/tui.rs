//! `aitm tui`: the proxy and the terminal operator UI in one process
//! (operator-UI foundation §2.10(c), TUI plan Task 4).
//!
//! The proxy is built exactly as the server path builds it; [`build_servers`]
//! then constructs **two** `McpServer`s over the same `Arc<Registry>` and
//! service handles. One is served on the configured agent transport — only
//! when that is loopback TCP, because stdio would share the terminal with the
//! UI. The other is wrapped as `Arc<McpServer>` so its `handle` becomes the
//! TUI's in-process bus handler: the bus contract is unchanged, the TUI is a
//! bus client like the others, there is just no socket between them.
//!
//! Logging: a `tracing` subscriber writing to stdout or stderr would paint
//! over the UI, so [`init_tracing`] writes to a file when `RUST_LOG` is set
//! and installs nothing when it is not. The file is `$AITM_TUI_LOG` when that
//! is set, else `aitm-tui.log` under the system temp directory; it is opened
//! owner-read/write only (`0600`) on Unix because the temp directory is
//! shared. The path is shown in the UI's startup toast.

use std::ffi::OsStr;
use std::fs::{File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};
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

/// The log file name under [`std::env::temp_dir`] when `RUST_LOG` is set and
/// [`LOG_PATH_ENV`] is not.
pub const LOG_FILE_NAME: &str = "aitm-tui.log";

/// Environment variable naming an explicit log file for `aitm tui`.
pub const LOG_PATH_ENV: &str = "AITM_TUI_LOG";

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

/// Where the tui-mode log goes: `explicit` (the value of [`LOG_PATH_ENV`])
/// when set and non-empty, else [`LOG_FILE_NAME`] under the system temp dir.
pub fn log_path_from(explicit: Option<&OsStr>) -> PathBuf {
    match explicit {
        Some(p) if !p.is_empty() => PathBuf::from(p),
        _ => std::env::temp_dir().join(LOG_FILE_NAME),
    }
}

/// Create-or-append the log file, readable and writable by the owner only on
/// Unix (the default temp directory is world-readable).
pub fn open_log_file(path: &Path) -> io::Result<File> {
    let mut opts = OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    opts.open(path)
}

/// Install the `tui`-mode tracing subscriber: file-backed when `RUST_LOG` is
/// set (returns the file's path), nothing otherwise. Never writes to the
/// terminal. A log file that cannot be opened disables logging rather than
/// failing the run.
pub fn init_tracing() -> Option<PathBuf> {
    use tracing_subscriber::{fmt, EnvFilter};
    let filter = EnvFilter::try_from_default_env().ok()?;
    let path = log_path_from(std::env::var_os(LOG_PATH_ENV).as_deref());
    let file = open_log_file(&path).ok()?;
    let _ = fmt()
        .with_env_filter(filter)
        .with_ansi(false)
        .with_writer(Mutex::new(file))
        .try_init();
    Some(path)
}

/// The two servers `aitm tui` runs over one proxy: the agent-facing one on the
/// configured transport (`None` when that is stdio, which would share the
/// terminal with the UI) and the TUI-facing one behind an in-process handler.
/// Both carry the SSRF policy, PoC dir and services exactly as the server
/// path builds its one `McpServer`.
pub fn build_servers(cfg: &Config, services: Services) -> (Option<McpServer>, InProcessHandler) {
    let Services {
        registry,
        store,
        client,
        guard,
        browser,
        log_path: _,
    } = services;

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

    // The TUI-facing server is never served on a transport, so the variant is
    // only a label; `handle` is called directly through the handler.
    let ui = Arc::new(
        McpServer::new(registry, McpTransport::Stdio)
            .with_ssrf_policy(cfg.browser.ssrf.clone())
            .with_poc_dir(cfg.poc.dir.clone())
            .with_services(store, client, guard, browser),
    );
    let handler: InProcessHandler = Arc::new(move |line: &str| ui.handle(line));
    (agent, handler)
}

/// Build the two servers over the shared `services` and run the proxy, the
/// agent transport (loopback TCP only) and the TUI side by side until one of
/// them ends — the TUI returning on operator quit is the ordinary exit.
///
/// The caller launches and reaps the browser, as it does for the server path.
pub async fn run(cfg: &Config, proxy: &Proxy, services: Services) -> anyhow::Result<()> {
    let log_path = services.log_path.clone();
    let (agent, handler) = build_servers(cfg, services);
    let agent_serve = async move {
        match agent {
            Some(server) => server.serve().await,
            None => std::future::pending().await,
        }
    };

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_log_path_defaults_to_the_temp_dir_and_honours_the_override() {
        let default = std::env::temp_dir().join("aitm-tui.log");
        assert_eq!(log_path_from(None), default);
        assert_eq!(log_path_from(Some(OsStr::new(""))), default);
        assert_eq!(
            log_path_from(Some(OsStr::new("/var/log/aitm/tui.log"))),
            PathBuf::from("/var/log/aitm/tui.log")
        );
    }

    #[test]
    fn the_log_file_is_created_owner_only_and_appended_to() {
        use std::io::Write as _;
        let dir = std::env::temp_dir().join(format!("aitm-tui-log-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("aitm-tui.log");
        let _ = std::fs::remove_file(&path);

        let mut first = open_log_file(&path).expect("create the log file");
        writeln!(first, "one").expect("write");
        drop(first);
        let mut second = open_log_file(&path).expect("reopen the log file");
        writeln!(second, "two").expect("write");
        drop(second);

        assert_eq!(
            std::fs::read_to_string(&path).expect("read back"),
            "one\ntwo\n",
            "reopening appends"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&path)
                .expect("metadata")
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "mode {mode:o}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
