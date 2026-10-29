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
//! is set (created or appended to), else `aitm-tui-<pid>.log` under the
//! system temp directory, made fresh for this run; either way it is opened
//! owner-read/write only (`0600`) on Unix because the temp directory is
//! shared. The outcome — path, or why there is no log — is the UI's startup
//! toast ([`TuiLog::startup_note`]).

use std::ffi::OsStr;
use std::fs::{File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use aitm_bus_client::InProcessHandler;
use aitm_core::{
    AgentState, BrowserDriver, Config, FlowStore, Frontend, McpTransport, PipelineClient, Proxy,
    ProxyClient, Registry, ScopeRateGuard,
};
use aitm_mcp::{ConnCtx, McpServer};
use aitm_tui::{RunOptions, TransportChoice};
use tracing::{info, warn};

use crate::wire::Http1Sender;

/// The usage line printed (exit status 2) when `tui` is given arguments.
pub const USAGE: &str = "usage: aitm [--config <path>] tui (takes no further arguments)";

/// Environment variable naming an explicit log file for `aitm tui`.
pub const LOG_PATH_ENV: &str = "AITM_TUI_LOG";

/// How often the TUI polls `flow.list` (F4 push is not on the bus yet).
const POLL: Duration = Duration::from_millis(500);

/// The default log file name under [`std::env::temp_dir`] when `RUST_LOG` is
/// set and [`LOG_PATH_ENV`] is not: one per process, so no run writes through
/// a file another run — or another user, in the shared temp dir — left there.
pub fn default_log_file_name() -> String {
    format!("aitm-tui-{}.log", std::process::id())
}

/// Where tui-mode tracing went, for the startup toast.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TuiLog {
    /// `RUST_LOG` is unset: no subscriber, no file.
    Off,
    /// Logging to this file.
    File(PathBuf),
    /// `RUST_LOG` is set but the file could not be opened: logging is
    /// disabled for the run and the operator is told, not left guessing.
    Unavailable { path: PathBuf, why: String },
}

impl TuiLog {
    /// The status-bar note shown when the UI starts.
    pub fn startup_note(&self) -> String {
        match self {
            TuiLog::Off => "embedded proxy · set RUST_LOG to write a log file".to_string(),
            TuiLog::File(p) => format!("embedded proxy · log: {}", p.display()),
            TuiLog::Unavailable { path, why } => format!(
                "embedded proxy · logging disabled: could not open {}: {why}",
                path.display()
            ),
        }
    }
}

/// The service handles `main` shares between the frontends.
pub struct Services {
    pub registry: Arc<Registry>,
    pub store: Arc<dyn FlowStore>,
    pub client: Arc<dyn ProxyClient>,
    pub guard: Arc<dyn ScopeRateGuard>,
    pub browser: Option<Arc<dyn BrowserDriver>>,
    /// Where tui-mode tracing went (see [`init_tracing`]), for the startup toast.
    pub log: TuiLog,
}

/// The service handles exactly as `main` shares them between the frontends:
/// the registry, store and guard from the proxy, the replay client over
/// `Http1Sender` honouring `ssl_insecure`, plus the browser driver (when one
/// launched) and the logging outcome.
pub fn services(
    proxy: &Proxy,
    cfg: &Config,
    browser: Option<Arc<dyn BrowserDriver>>,
    log: TuiLog,
) -> Services {
    let registry = proxy.registry_arc();
    let store = proxy.store();
    let guard: Arc<dyn ScopeRateGuard> = proxy.guard();
    let client: Arc<dyn ProxyClient> = Arc::new(PipelineClient::new(
        store.clone(),
        guard.clone(),
        // SSRF-gate the reissue path with the same policy + scope the browser
        // connector uses, so flow.replay / request.send / http.send cannot reach a
        // private/loopback/metadata host or rebind a scoped name to one (C1).
        Arc::new(
            Http1Sender::new()
                .with_insecure(cfg.ssl_insecure)
                .with_ssrf(cfg.browser.ssrf.clone(), guard.clone()),
        ),
    ));
    Services {
        registry,
        store,
        client,
        guard,
        browser,
        log,
    }
}

/// An `McpServer` over `services` on `transport`, carrying the SSRF policy
/// and PoC dir — the one way every server in this binary is built (the
/// server path's, and both of [`build_servers`]).
///
/// The M4 agent policy gate (and F4 push / F2 audit) are wired by the caller,
/// not here, because they differ by surface: the bare-`aitm` server path and
/// the `aitm tui` loopback **agent** transport carry the gate (seeded from
/// `mcp.policy`); the TUI's own in-process server is the operator and bypasses
/// it (see [`build_servers`]).
pub fn server(cfg: &Config, transport: McpTransport, services: &Services) -> McpServer {
    McpServer::new(services.registry.clone(), transport)
        .with_ssrf_policy(cfg.browser.ssrf.clone())
        .with_poc_dir(cfg.poc.dir.clone())
        .with_config(Arc::new(cfg.clone()))
        .with_services(
            services.store.clone(),
            services.client.clone(),
            services.guard.clone(),
            services.browser.clone(),
        )
}

/// Where the tui-mode log goes: `explicit` (the value of [`LOG_PATH_ENV`])
/// when set and non-empty, else [`default_log_file_name`] under the system
/// temp dir.
pub fn log_path_from(explicit: Option<&OsStr>) -> PathBuf {
    match explicit {
        Some(p) if !p.is_empty() => PathBuf::from(p),
        _ => std::env::temp_dir().join(default_log_file_name()),
    }
}

/// Open the log file, readable and writable by the owner only on Unix (the
/// default temp directory is world-readable). An explicit path (`append`)
/// is created or appended to. The default path is made fresh: whatever sits
/// there is removed and the file created with `create_new`, so a file or
/// link planted at the predictable name is never written through; if
/// something lands in the window between the two steps, the open fails and
/// the caller leaves logging off.
pub fn open_log_file(path: &Path, append: bool) -> io::Result<File> {
    let mut opts = OpenOptions::new();
    if append {
        opts.create(true).append(true);
    } else {
        match std::fs::remove_file(path) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        opts.write(true).create_new(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    opts.open(path)
}

/// Install the `tui`-mode tracing subscriber: file-backed when `RUST_LOG` is
/// set, nothing otherwise. Never writes to the terminal. A log file that
/// cannot be opened disables logging rather than failing the run; the
/// returned [`TuiLog`] says which happened.
pub fn init_tracing() -> TuiLog {
    use tracing_subscriber::{fmt, EnvFilter};
    let Ok(filter) = EnvFilter::try_from_default_env() else {
        return TuiLog::Off;
    };
    let explicit = std::env::var_os(LOG_PATH_ENV).filter(|p| !p.is_empty());
    let path = log_path_from(explicit.as_deref());
    let file = match open_log_file(&path, explicit.is_some()) {
        Ok(f) => f,
        Err(e) => {
            return TuiLog::Unavailable {
                path,
                why: e.to_string(),
            }
        }
    };
    let _ = fmt()
        .with_env_filter(filter)
        .with_ansi(false)
        .with_writer(Mutex::new(file))
        .try_init();
    TuiLog::File(path)
}

/// The two servers `aitm tui` runs over one proxy: the agent-facing one on the
/// configured transport (`None` when that is stdio, which would share the
/// terminal with the UI) and the TUI-facing one behind an in-process handler.
/// Both are built by [`server`], exactly as the server path builds its one.
pub fn build_servers(cfg: &Config, services: Services) -> (Option<McpServer>, InProcessHandler) {
    let agent = match &cfg.mcp.transport {
        // The loopback transport is agent-facing, so it carries the M4 policy gate
        // seeded from `mcp.policy` (default `auto`) and the operator/agent token
        // classes — an external agent here is gated exactly as on the bare-`aitm`
        // server path, not left ungated.
        McpTransport::LoopbackTcp { .. } => Some(
            server(cfg, cfg.mcp.transport.clone(), &services)
                .with_agent_state(Arc::new(AgentState::new(cfg.mcp.policy)))
                .with_mcp_roles(cfg.mcp.operator_token.clone(), cfg.mcp.stdio_role),
        ),
        McpTransport::Stdio => {
            warn!("mcp.transport is stdio, which would share the terminal with the TUI; the agent transport is not served");
            None
        }
    };

    // The TUI-facing server is never served on a transport, so the variant is
    // only a label; `handle` is called directly through the handler. The TUI is
    // the operator's own control surface, so its calls run as
    // `Frontend::Operator`, which bypasses the agent policy gate (an operator is
    // the control) — otherwise the operator could not arm intercept, mutate or
    // kill from their own UI.
    let ui = Arc::new(server(cfg, McpTransport::Stdio, &services));
    let handler: InProcessHandler =
        Arc::new(move |line: &str| ui.handle_on(&ConnCtx::new(Frontend::Operator), line));
    (agent, handler)
}

/// Build the two servers over the shared `services` and run the proxy, the
/// agent transport (loopback TCP only) and the TUI side by side until one of
/// them ends — the TUI returning on operator quit is the ordinary exit.
///
/// The caller launches and reaps the browser, as it does for the server path.
pub async fn run(cfg: &Config, proxy: &Proxy, services: Services) -> anyhow::Result<()> {
    let startup_note = services.log.startup_note();
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
        startup_note: Some(startup_note),
        listening: Some(cfg.listen.to_string()),
        poc_dir: cfg.poc.dir.clone(),
        // The embedded TUI shares the proxy process; its role follows the token
        // it presents, and it sets no client-side expectation.
        expect_role: None,
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

    /// SEC-3: the default log is per process (`aitm-tui-<pid>.log`), so two
    /// `aitm tui` runs never share a file in the world-writable temp dir;
    /// `AITM_TUI_LOG` names an explicit path.
    #[test]
    fn the_log_path_defaults_to_a_per_process_file_and_honours_the_override() {
        let default = std::env::temp_dir().join(format!("aitm-tui-{}.log", std::process::id()));
        assert_eq!(log_path_from(None), default);
        assert_eq!(log_path_from(Some(OsStr::new(""))), default);
        assert_eq!(
            log_path_from(Some(OsStr::new("/var/log/aitm/tui.log"))),
            PathBuf::from("/var/log/aitm/tui.log")
        );
    }

    /// SEC-3: the default file is opened fresh — whatever sits at the path
    /// is removed and the file created anew (`create_new`), owner-only — so
    /// a file planted there before the run is never written through.
    #[test]
    fn the_default_log_file_is_created_fresh_owner_only_and_fails_closed() {
        use std::io::Write as _;
        let dir = std::env::temp_dir().join(format!("aitm-tui-log-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("aitm-tui-fresh.log");
        std::fs::write(&path, "planted before the run\n").expect("plant a file");

        let mut fresh = open_log_file(&path, false).expect("create the log file");
        writeln!(fresh, "one").expect("write");
        drop(fresh);
        assert_eq!(
            std::fs::read_to_string(&path).expect("read back"),
            "one\n",
            "the planted content is gone, not appended to"
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
        // Something that cannot be removed as a file (a directory) fails
        // closed: no file is opened, the caller disables logging.
        let planted_dir = dir.join("aitm-tui-dir.log");
        std::fs::create_dir_all(&planted_dir).expect("plant a directory");
        assert!(open_log_file(&planted_dir, false).is_err());
        assert!(planted_dir.is_dir(), "left alone");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// SEC-3: an explicit `AITM_TUI_LOG` keeps the create-or-append
    /// semantics, owner-only on Unix.
    #[test]
    fn an_explicit_log_file_is_appended_to() {
        use std::io::Write as _;
        let dir = std::env::temp_dir().join(format!("aitm-tui-log-append-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("tui.log");
        let _ = std::fs::remove_file(&path);

        let mut first = open_log_file(&path, true).expect("create the log file");
        writeln!(first, "one").expect("write");
        drop(first);
        let mut second = open_log_file(&path, true).expect("reopen the log file");
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

    /// SEC-3: what the startup toast says for each logging outcome — a
    /// failed open is a warning, never a silent no-log run.
    #[test]
    fn the_startup_note_names_the_log_file_or_why_there_is_none() {
        assert_eq!(
            TuiLog::Off.startup_note(),
            "embedded proxy · set RUST_LOG to write a log file"
        );
        assert_eq!(
            TuiLog::File(PathBuf::from("/tmp/aitm-tui-7.log")).startup_note(),
            "embedded proxy · log: /tmp/aitm-tui-7.log"
        );
        assert_eq!(
            TuiLog::Unavailable {
                path: PathBuf::from("/tmp/aitm-tui-7.log"),
                why: "Is a directory (os error 21)".into()
            }
            .startup_note(),
            "embedded proxy · logging disabled: could not open /tmp/aitm-tui-7.log: Is a directory (os error 21)"
        );
    }
}
