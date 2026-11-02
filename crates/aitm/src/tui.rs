//! `aitm tui`: the proxy and the terminal operator UI in one process
//! (operator-UI foundation §2.10(c), TUI plan Task 4).
//!
//! The proxy is built exactly as the server path builds it; [`build_servers`]
//! then constructs **two** `McpServer`s over the same `Arc<Registry>` and
//! service handles. One is served on the configured agent transport — only
//! when that is loopback TCP or streamable HTTP, because stdio would share
//! the terminal with the UI. It is agent-facing and gated, and it runs on the
//! core's own shared `AgentState` and `AuditRing`, which [`build_servers`]
//! receives as a sealed `wire::Governance` (`Assembled::governance` is its
//! only public source, so no outside code can hand it a substitute pair; see
//! [`build_servers`] for what that does not tie down): a live `agent.set`
//! governs that agent on its next call, and its calls, allowed or refused,
//! land in the trail `agent.activity` reads (not audited: a successful
//! `flow.subscribe`/`flow.unsubscribe`, a `needs_confirmation` handshake step,
//! and protocol-level JSON-RPC errors). The other is wrapped as
//! `Arc<McpServer>` so its `handle` becomes the TUI's in-process bus handler:
//! the bus contract is unchanged, the TUI is a bus client like the others,
//! there is just no socket between them. That server is the operator, ungated
//! by role, and deliberately **not** on the shared ring: the TUI's polling
//! (`flow.list` every 500 ms plus five panel reads every 3 s, about 220 calls
//! a minute at idle) would flood it.
//!
//! Logging: a `tracing` subscriber writing to stdout or stderr would paint
//! over the UI, so in tui mode the shared composition in
//! [`crate::startup::log`] installs the file layer only: the log is
//! `<aitm dir>/logs/aitm.log`, overridable with `AITM_LOG_FILE` and, for one
//! more release, [`LOG_PATH_ENV`]. The outcome — path, or why there is no
//! log — is the UI's startup toast ([`TuiLog::startup_note`]).

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use aitm_bus_client::InProcessHandler;
use aitm_core::{
    AgentState, AuditRing, BrowserDriver, Config, EgressConfinement, FlowStore, Frontend, JobBus,
    McpTransport, PipelineClient, Proxy, ProxyClient, Registry, ScopeRateGuard,
};
use aitm_mcp::{ConnCtx, McpServer};
use aitm_tui::{RunOptions, TransportChoice};
use tracing::{info, warn};

use crate::wire::{BoundHook, Governance, Http1Sender};

/// The `Usage:` line of `aitm tui` (plan C48): the cause line of the usage
/// error (exit 2) when `tui` is given arguments; the page is
/// `help::pages::tui`.
pub const USAGE: &str = crate::help::pages::TUI_USAGE_LINE;

/// Environment variable naming an explicit log file for `aitm tui`.
pub const LOG_PATH_ENV: &str = "AITM_TUI_LOG";

/// How often the TUI polls `flow.list` (F4 push is not on the bus yet).
const POLL: Duration = Duration::from_millis(500);

/// Where this run's log went, for the TUI's startup toast. Built by
/// [`crate::startup::log::tui_log`] from the [`crate::startup::log::LogSink`]
/// that `init_tracing` returned: since wave 1 the file layer is always
/// attempted (`<aitm dir>/logs/aitm.log`, `AITM_LOG_FILE`, or `AITM_TUI_LOG`
/// in tui mode; spec D7, D11), whatever `RUST_LOG` says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TuiLog {
    /// The non-tui placeholder: `main` passes it to [`services`] on the
    /// server and web paths, where no toast is shown. It says nothing about
    /// whether a log file opened (the file layer was still attempted via
    /// `crate::startup::log`).
    Off,
    /// Logging to this file.
    File(PathBuf),
    /// The log file could not be opened (`crate::startup::log::open_log_file`
    /// refused it; `why` is the open error's text): the run continues with
    /// no file and the operator is told, not left guessing.
    Unavailable { path: PathBuf, why: String },
}

impl TuiLog {
    /// The status-bar note shown when the UI starts.
    pub fn startup_note(&self) -> String {
        match self {
            TuiLog::Off => "embedded proxy · log location not reported".to_string(),
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
    /// The proxy's live browser-egress posture (`Proxy::egress()`), shared with
    /// every frontend so `browser.confine` flips the connector's real posture.
    pub egress: Arc<EgressConfinement>,
    /// Where tui-mode tracing went (see [`crate::startup::log::tui_log`]),
    /// for the startup toast.
    pub log: TuiLog,
    /// The one job bus from `wire::Assembled` (spec D9.2). Every server built
    /// over these services carries it, so a job started on any surface
    /// publishes where every surface's subscribers listen. The in-process TUI
    /// connection has no push sink and polls instead (D3, "poll is truth"); it
    /// still carries the bus, because the server it is built from is the same
    /// one an operator-token client can subscribe on.
    pub jobs: Arc<JobBus>,
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
    jobs: Arc<JobBus>,
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
        egress: proxy.egress(),
        log,
        jobs,
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
/// it (see [`build_servers`]). Both servers the bare-`aitm` server run builds
/// (the primary and the `aitm web` bridge server) take the shared gate and audit
/// ring from [`with_shared_governance`], the other half of "wired by the
/// caller". So does the `aitm tui` loopback agent server: [`build_servers`]
/// applies [`with_shared_governance`] to it from the `Governance` it requires.
pub fn server(cfg: &Config, transport: McpTransport, services: &Services) -> McpServer {
    McpServer::new(services.registry.clone(), transport)
        .with_ssrf_policy(cfg.browser.ssrf.clone())
        .with_poc_dir(cfg.poc.dir.clone())
        .with_config(Arc::new(cfg.clone()))
        // Wire the persistent finding recorder so a poc.run records on pass (T7);
        // persistence stays gated on findings.dir.
        .with_finding_recorder(Arc::new(aitm_findings::DiskFindingRecorder))
        // The proxy's live egress posture, so browser.confine over any server
        // built here (agent transport, TUI bus, web bridge) flips the real one.
        .with_egress(services.egress.clone())
        // The one job bus (spec D9.2), so every server built here — the agent
        // transport, the in-process TUI server and the `aitm web` bridge —
        // dispatches `notifications/aitm/job` from the same stream of events.
        .with_jobs(services.jobs.clone())
        .with_services(
            services.store.clone(),
            services.client.clone(),
            services.guard.clone(),
            services.browser.clone(),
        )
}

/// Apply the shared agent policy and audit ring to `server`: the one function
/// `main.rs`, [`build_servers`] and the tests all call, so the tests exercise
/// the wiring the binary applies.
///
/// It shares **exactly** two things, the policy state (`agent_state`, which the
/// `AgentPlugin`'s `agent.set` writes and the server's gate reads) and the audit
/// ring (`audit_ring`, which `call_tool` appends to and `agent.activity` /
/// `agent.status` read), by cloning the two `Arc`s from
/// `wire::Assembled`. It applies nothing else: no push, no roles, no timeouts.
///
/// It does **not** share the `Ask` machinery. The subscription registry, the
/// parked-request table, the confirm tokens and the connection ids stay per
/// server. So `agent.approve` resolves only a call parked on the same server,
/// and an `approval_requested` push reaches only the operators subscribed on
/// that server. An approve sent to the other server is the plain "no parked
/// request" error and approves nothing.
///
/// How a caller gets here differs by mode. In TUI mode it is compile-enforced:
/// [`build_servers`] cannot be called without a `wire::Governance`, whose only
/// public source is `Assembled::governance`, and its agent arm applies this
/// function to that pair. The bare-`aitm` path (the primary server and the `aitm web`
/// bridge server in `main.rs`) applies it by convention: nothing in the types
/// makes it do so.
///
/// Residual risk: this makes tests and production share a function, not a
/// guarantee. [`build_servers`] is exercised through its production path by
/// `tests/tui_mode_governance.rs` and `tests/tui_mode_governance_live.rs`, so
/// dropping the wrapper from its agent arm fails them. `main.rs`'s bare-path
/// calls still have no such test: deleting the wrapper there would leave every
/// test green, and the function cannot force a future third server to call it.
pub fn with_shared_governance(
    server: McpServer,
    agent_state: &Arc<AgentState>,
    audit_ring: &Arc<AuditRing>,
) -> McpServer {
    server
        .with_agent_state(Arc::clone(agent_state))
        .with_audit_ring(Arc::clone(audit_ring))
}

/// The two servers `aitm tui` runs over one proxy: the agent-facing one on the
/// configured transport (`None` when that is stdio, which would share the
/// terminal with the UI) and the TUI-facing one behind an in-process handler.
/// Both are built by [`server`], the one way every server in this binary is
/// built.
///
/// `governance` is the core's own policy state and audit ring as a sealed
/// `wire::Governance`, whose only public source is `Assembled::governance`, so
/// this function cannot be called without one, and no outside code can
/// substitute the pair an assembly made. It is not tied to the `Proxy` in
/// `services`: a `Governance` from a second `assemble()` would pass (in-process
/// code only; not reachable from the network, a plugin, or MCP). The agent arm
/// goes through [`with_shared_governance`]: a live
/// `agent.set`, from the TUI or from any operator-token client, governs the
/// agent on its next call, and the agent's calls are recorded in the shared
/// ring. The TUI-facing arm deliberately does not: it is the operator, and its
/// polling would flood the ring (see the module doc).
///
/// `push_tx` is not fed to the agent server (follow-up "tui-mode push"), so a
/// loopback subscriber receives the `notifications/aitm/agent` lines but no
/// `notifications/aitm/flow`.
///
/// Under `ask`, only an operator-token client connected to this same server
/// and subscribed via `flow.subscribe` can approve a parked Sensitive agent
/// call: the `Ask` machinery is per server, and the TUI's in-process server is
/// a different `McpServer` with no push sink to subscribe on. With only the
/// TUI attached, a Sensitive agent call is therefore refused at once ("no
/// operator is connected to approve it") and never parks.
pub fn build_servers(
    cfg: &Config,
    services: Services,
    governance: Governance,
) -> (Option<McpServer>, InProcessHandler) {
    let agent = match &cfg.mcp.transport {
        // Agent-facing, so gated: built on the core's shared policy state and
        // audit ring (`governance`, applied through `with_shared_governance`)
        // with the operator/agent token classes, exactly as on the bare-`aitm`
        // server path. Loopback TCP and streamable HTTP are both addressable
        // endpoints that do not share the terminal with the TUI.
        McpTransport::LoopbackTcp { .. } | McpTransport::StreamableHttp { .. } => Some(
            with_shared_governance(
                server(cfg, cfg.mcp.transport.clone(), &services),
                &governance.agent_state,
                &governance.audit_ring,
            )
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
    // kill from their own UI. It is built by `server` alone, so it keeps
    // `McpServer::new`'s private state and ring: ungoverned and unrecorded on
    // purpose, since its polling would flood the shared trail.
    let ui = Arc::new(server(cfg, McpTransport::Stdio, &services));
    let handler: InProcessHandler =
        Arc::new(move |line: &str| ui.handle_on(&ConnCtx::new(Frontend::Operator), line));
    (agent, handler)
}

/// Attach `hook` to the agent server's `on_bound`, so the caller learns the port
/// the transport actually bound — `main.rs` passes
/// [`self_port_hook`](crate::wire::self_port_hook) over the live L4 guard, as it
/// does on the server path (L4PAR-AC34, spec §2.1). With no agent server (stdio)
/// the hook is dropped unfired; with no hook the server is returned as it was.
pub(crate) fn attach_bound_hook(
    agent: Option<McpServer>,
    hook: Option<BoundHook>,
) -> Option<McpServer> {
    match (agent, hook) {
        (Some(server), Some(hook)) => Some(server.on_bound(hook)),
        (agent, _) => agent,
    }
}

/// Build the two servers over the shared `services` and run the proxy, the
/// agent transport (loopback TCP or streamable HTTP) and the TUI side by side
/// until one of them ends — the TUI returning on operator quit is the ordinary
/// exit. `governance` is the core's own policy state and audit ring, from
/// `Assembled::governance()` in `main.rs`, passed through to [`build_servers`]
/// for the agent server.
///
/// The caller launches and reaps the browser, as it does for the server path,
/// and pre-binds the proxy and browser listeners so a port conflict is reported
/// before the terminal UI takes over the screen.
///
/// `on_agent_bound` is attached to the agent server's `on_bound` through
/// [`attach_bound_hook`], so the caller learns the port the transport actually
/// bound; `main.rs` passes [`self_port_hook`](crate::wire::self_port_hook) over
/// the live L4 guard, as it does on the server path (L4PAR-AC34). With no agent
/// server (stdio) the hook is dropped unused.
pub async fn run(
    cfg: &Config,
    proxy: &Proxy,
    services: Services,
    governance: Governance,
    main_listener: tokio::net::TcpListener,
    browser_listener: tokio::net::TcpListener,
    on_agent_bound: Option<BoundHook>,
) -> anyhow::Result<()> {
    let startup_note = services.log.startup_note();
    let (agent, handler) = build_servers(cfg, services, governance);
    let agent = attach_bound_hook(agent, on_agent_bound);
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

    tokio::select! {
        result = proxy.run_on(main_listener) => result,
        result = proxy.run_browser_on(browser_listener) => result,
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
    use aitm_core::{AgentPolicy, AuditResult};
    use aitm_proto_l4::guard::L4Guard;
    use std::io;

    /// Spec D9.2: every `McpServer` this binary builds carries the one job bus
    /// assembly made, so a `scan.start` over any surface — the agent transport,
    /// the in-process TUI server, the `aitm web` bridge — publishes its progress
    /// where that surface's subscribers are listening. It is the bus the caller
    /// passed, not a second one.
    #[test]
    fn server_carries_the_job_bus() {
        let cfg = Config::default();
        let proxy = Proxy::builder()
            .with_config(cfg.clone())
            .build()
            .expect("a proxy builds without binding anything");
        let jobs = Arc::new(JobBus::default());
        let services = services(&proxy, &cfg, None, TuiLog::Off, Arc::clone(&jobs));

        let carried = server(&cfg, McpTransport::Stdio, &services)
            .jobs()
            .expect("the server carries a job bus");
        assert!(
            Arc::ptr_eq(&carried, &jobs),
            "it is the bus assembly made, not a second one"
        );
    }

    /// L4PAR-AC34 / spec §2.1 (security Critical, second half), live: an agent
    /// `McpServer` on loopback TCP port 0 with [`crate::wire::self_port_hook`]
    /// attached through `attach_bound_hook`, served, reports the ephemeral port it
    /// actually bound into the L4 guard's self ports — exactly one non-zero port
    /// — before anything else learns it. Binds a port: in a sandbox that refuses
    /// `bind` (`PermissionDenied`), `serve` ends with that error and the test
    /// skips with a note; any other early end fails it.
    #[tokio::test]
    async fn attach_bound_hook_feeds_the_bound_port_to_the_l4_guard() {
        let guard = Arc::new(L4Guard::new(&aitm_proto_l4::config::L4Config::default()));
        let server = McpServer::new(
            Arc::new(Registry::new()),
            McpTransport::LoopbackTcp {
                port: 0,
                token: "attach-bound-hook-test".into(),
                endpoint_file: None,
            },
        );
        let agent = attach_bound_hook(
            Some(server),
            Some(crate::wire::self_port_hook(guard.clone())),
        )
        .expect("the agent server is kept");
        let serving = tokio::spawn(agent.serve());

        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        let ports = loop {
            let ports = guard.self_ports();
            if !ports.is_empty() {
                break ports;
            }
            if serving.is_finished() {
                let ended = serving.await;
                // A sandbox that refuses `bind` ends `serve` with EPERM before any
                // port exists: not a bug, so skip with a note, the way
                // `tests/l4_cua_tui.rs` does. Any other early end is a failure.
                if let Ok(Err(e)) = &ended {
                    if e.chain().any(|c| {
                        c.downcast_ref::<io::Error>()
                            .is_some_and(|io| io.kind() == io::ErrorKind::PermissionDenied)
                    }) {
                        eprintln!(
                            "tui::attach_bound_hook_feeds_the_bound_port_to_the_l4_guard: \
                             skipped — this sandbox refuses to bind 127.0.0.1:0 \
                             (PermissionDenied). Run `cargo test -p aitm --lib \
                             attach_bound_hook_feeds_the_bound_port_to_the_l4_guard` in the \
                             Terminal panel."
                        );
                        return;
                    }
                }
                panic!("serve ended before reporting a bound port: {ended:?}");
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "the bound port never reached the L4 guard"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        };
        serving.abort();
        assert_eq!(ports.len(), 1, "exactly one port: the agent transport's");
        assert_ne!(
            ports[0], 0,
            "the ephemeral port a `port: 0` bind resolved to"
        );
    }

    /// Without an agent server (stdio) the hook is dropped unfired: nothing
    /// reaches the guard; without a hook the server is passed through.
    #[test]
    fn attach_bound_hook_without_an_agent_server_fires_nothing() {
        let guard = Arc::new(L4Guard::new(&aitm_proto_l4::config::L4Config::default()));
        assert!(
            attach_bound_hook(None, Some(crate::wire::self_port_hook(guard.clone()))).is_none()
        );
        assert_eq!(guard.self_ports(), Vec::<u16>::new());
        let server = McpServer::new(Arc::new(Registry::new()), McpTransport::Stdio);
        assert!(attach_bound_hook(Some(server), None).is_some());
    }

    /// Tripwire: `run` attaches the caller's hook through `attach_bound_hook`,
    /// the one place the agent server's `on_bound` is set under `aitm tui`.
    #[test]
    fn run_wires_the_bound_port_hook_into_the_agent_server() {
        let run_body = include_str!("tui.rs")
            .split("pub async fn run(")
            .nth(1)
            .expect("tui.rs defines `run`")
            .split("#[cfg(test)]")
            .next()
            .expect("the test module follows `run`");
        assert!(run_body.contains("attach_bound_hook(agent, on_agent_bound)"));
    }

    /// SEC-3: what the startup toast says for each logging outcome — a
    /// failed open is a warning, never a silent no-log run. `Off` is the
    /// non-tui placeholder (spec reviewer Sp9): the file layer was still
    /// attempted by `startup::log`, so the note no longer tells the operator
    /// to set `RUST_LOG`, which has not decided whether a log is written
    /// since wave 1.
    #[test]
    fn the_startup_note_names_the_log_file_or_why_there_is_none() {
        assert_eq!(
            TuiLog::Off.startup_note(),
            "embedded proxy · log location not reported"
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

    /// Task 4b / AC9 (end-to-end reachability): the service handles `main`
    /// shares carry the proxy's live egress posture (the same `Arc`, not a
    /// copy), and a `browser.confine` sent to a `tui::server`-built server —
    /// the one way every server in this binary is built — flips that very
    /// posture on and back off.
    #[test]
    fn frontend_servers_toggle_the_proxy_egress_posture() {
        let mut cfg = Config::default();
        cfg.ca.dir = std::env::temp_dir().join(format!("aitm-tui-egress-{}", std::process::id()));
        let proxy = crate::wire::build_proxy(&cfg).expect("build proxy");
        let services = services(&proxy, &cfg, None, TuiLog::Off, Arc::new(JobBus::default()));
        assert!(
            Arc::ptr_eq(&services.egress, &proxy.egress()),
            "the frontends share the proxy's own posture handle"
        );

        let srv = server(&cfg, McpTransport::Stdio, &services);
        let operator = ConnCtx::new(Frontend::Operator);
        let confine = |on: bool| -> serde_json::Value {
            let req = serde_json::json!({
                "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": {"name": "browser.confine", "arguments": {"on": on}}
            });
            let resp = srv
                .handle_on(&operator, &req.to_string())
                .expect("a response");
            serde_json::from_str(&resp).expect("response is JSON")
        };

        assert!(!proxy.egress().confined(), "fixture starts free");
        let resp = confine(true);
        assert_eq!(
            resp["result"]["structuredContent"],
            serde_json::json!({"confined": true}),
            "{resp}"
        );
        assert!(
            proxy.egress().confined(),
            "the proxy's live posture flipped on"
        );

        let resp = confine(false);
        assert_eq!(
            resp["result"]["structuredContent"],
            serde_json::json!({"confined": false}),
            "{resp}"
        );
        assert!(!proxy.egress().confined(), "and back off");
        let _ = std::fs::remove_dir_all(&cfg.ca.dir);
    }

    /// An assembled core plus its service handles, over a CA dir unique to this
    /// run and removed on drop (so a failing assertion leaves nothing behind).
    struct Governed {
        cfg: Config,
        assembled: crate::wire::Assembled,
        services: Services,
    }

    impl Governed {
        fn new(tag: &str) -> Self {
            let mut cfg = Config::default();
            cfg.ca.dir =
                std::env::temp_dir().join(format!("aitm-tui-gov-{tag}-{}", std::process::id()));
            let assembled = crate::wire::assemble(&cfg).expect("assemble");
            let services = services(
                &assembled.proxy,
                &cfg,
                None,
                TuiLog::Off,
                Arc::clone(&assembled.job_bus),
            );
            Self {
                cfg,
                assembled,
                services,
            }
        }

        /// One more `tui::server`, passed through the helper under test with
        /// this fixture's own shared policy state and audit ring.
        fn governed_server(&self) -> McpServer {
            with_shared_governance(
                server(&self.cfg, McpTransport::Stdio, &self.services),
                &self.assembled.agent_state,
                &self.assembled.audit_ring,
            )
        }
    }

    impl Drop for Governed {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.cfg.ca.dir);
        }
    }

    /// One `tools/call` with no arguments on `conn`; the whole JSON-RPC reply.
    fn call(srv: &McpServer, conn: &ConnCtx, name: &str) -> serde_json::Value {
        let req = serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": name, "arguments": {}}
        });
        let resp = srv.handle_on(conn, &req.to_string()).expect("a response");
        serde_json::from_str(&resp).expect("response is JSON")
    }

    /// AC8: a server passed through the helper is gated by the shared policy
    /// state (an agent is refused under `paused`, with the policy's own reason),
    /// records the refusal in the shared ring as one `Mcp`-origin entry, and
    /// leaves the operator ungated.
    #[test]
    fn with_shared_governance_gates_an_agent_and_audits_into_the_shared_ring() {
        let g = Governed::new("gate");
        let srv = g.governed_server();
        g.assembled.agent_state.set_policy(AgentPolicy::Paused);
        let ring = &g.assembled.audit_ring;

        let agent = ConnCtx::new(Frontend::Mcp);
        let refused = call(&srv, &agent, "flow.list");
        assert_eq!(
            refused["result"]["isError"],
            serde_json::json!(true),
            "an agent call under `paused` is refused: {refused}"
        );
        let text = refused["result"]["content"][0]["text"]
            .as_str()
            .unwrap_or_default();
        assert!(
            text.contains("the agent policy is `paused`"),
            "the refusal names the policy: {refused}"
        );

        assert_eq!(ring.len(), 1, "the refusal is one entry in the shared ring");
        let entries = ring.recent(None, None);
        assert_eq!(entries[0].origin, Frontend::Mcp);
        assert_eq!(entries[0].command, "flow.list");
        match &entries[0].result {
            AuditResult::Error(reason) => {
                assert!(reason.contains("paused"), "the recorded reason: {reason}");
            }
            other => panic!("expected an Error result, got {other:?}"),
        }

        let operator = ConnCtx::new(Frontend::Operator);
        let listed = call(&srv, &operator, "flow.list");
        assert_eq!(
            listed["result"]["isError"],
            serde_json::json!(false),
            "the operator is not gated: {listed}"
        );
        assert_eq!(
            listed["result"]["structuredContent"],
            serde_json::json!([]),
            "{listed}"
        );
        // The operator's own call is audited too, under its own origin: the ring
        // holds the agent's refusal, then the operator's call, and only the first
        // is an agent entry. Compared as a list rather than by `== Frontend::Mcp`,
        // the deny-list shape `aitm-core`'s `trust_gate_scan` rejects in any `src`.
        let origins: Vec<Frontend> = ring.recent(None, None).iter().map(|e| e.origin).collect();
        assert_eq!(
            origins,
            vec![Frontend::Mcp, Frontend::Operator],
            "the operator's call is its own entry, not an agent one"
        );
    }

    /// AC7: two servers built through the helper from one `Assembled` write one
    /// trail. One agent call on each lands in the shared ring in call order, and
    /// one `agent.activity` (served from that ring) lists both.
    #[test]
    fn with_shared_governance_gives_two_servers_one_audit_trail() {
        let g = Governed::new("trail");
        let first = g.governed_server();
        let second = g.governed_server();
        let agent = ConnCtx::new(Frontend::Mcp);

        let listed = call(&first, &agent, "flow.list");
        assert_eq!(listed["result"]["isError"], serde_json::json!(false));
        let status = call(&second, &agent, "agent.status");
        assert_eq!(status["result"]["isError"], serde_json::json!(false));

        let ring = &g.assembled.audit_ring;
        assert_eq!(ring.len(), 2, "both servers record into the one ring");
        let entries = ring.recent(None, None);
        assert_eq!(entries[0].command, "flow.list");
        assert_eq!(entries[1].command, "agent.status");
        assert_eq!(entries[0].origin, Frontend::Mcp);
        assert_eq!(entries[1].origin, Frontend::Mcp);

        let operator = ConnCtx::new(Frontend::Operator);
        let activity = call(&first, &operator, "agent.activity");
        let rows = &activity["result"]["structuredContent"];
        assert_eq!(rows.as_array().map(Vec::len), Some(2), "{activity}");
        assert_eq!(rows[0]["command"], serde_json::json!("flow.list"));
        assert_eq!(rows[1]["command"], serde_json::json!("agent.status"));
        assert_eq!(rows[0]["origin"], serde_json::json!("mcp"));
    }
}
