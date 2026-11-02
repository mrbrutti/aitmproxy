//! The default loopback operator bus every serving surface starts (spec D2;
//! plan Task 6): [`plan`] is the mode rule, [`start`] binds and serves the
//! dedicated listener, [`OperatorBus`] holds it for the run.
//!
//! `run()` calls [`start`] once, right after `tui::services(..)` is built and
//! before the ready card, in every serving mode (bare `aitm`, `aitm web`,
//! `aitm tui`); a one-shot never does. The returned [`OperatorBusWord`] is
//! the card's `Operator bus` row. Dropping the [`OperatorBus`] aborts the
//! serving task, which drops the `LoopbackTcp`, which removes the core
//! pointer (spec D4): Ctrl-C, SIGTERM, the stdin-EOF exit and the TUI's `q`
//! all end `run()` and so the bus. The other way round, `run()` learns that
//! a dedicated bus died through [`OperatorBus::finished`] (security S1): a
//! `select!` arm beside its other exit paths, pending for ever when there is
//! no dedicated task.
//!
//! Why not a new `McpTransport` variant: the operator bus is not a transport
//! the operator configures but a property every core has (spec D2).

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;

use aitm_core::{AgentState, AuditRing, Config, Event, McpConfig, McpTransport};
use aitm_mcp::transport::LoopbackTcp;
use tokio::sync::broadcast;
use tokio::task::JoinHandle;
use tracing::debug;

use crate::startup::card::OperatorBusWord;
use crate::startup::errors::StartupError;
use crate::tui::{self, Services};

/// The role word in the M2 panel: `cannot start: the operator bus port
/// 127.0.0.1:N is already in use` (AC-R14-9).
pub const ROLE: &str = "the operator bus";

/// The `Off` reason when `mcp.operator_bus.enabled` is `false` (spec D2 table).
const REASON_DISABLED: &str = "mcp.operator_bus.enabled: false";
/// The `Off` reason when no non-empty `mcp.operator_token` exists (spec D2 table).
const REASON_NO_TOKEN: &str = "no mcp.operator_token";

/// Spec D2's mode rule: what the operator bus is for this config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Plan {
    /// `mcp.transport` is loopback TCP and an operator token exists: that
    /// transport carries operator access (`with_operator_token`, as today);
    /// no second listener; `mcp.operator_bus.port` is ignored.
    Shared,
    /// A dedicated operator-only loopback listener on `127.0.0.1:<port>`
    /// (`0` is ephemeral).
    Dedicated(u16),
    /// No operator bus; the reason the card shows after `off · `.
    Off(String),
}

/// The configured operator token when it is non-empty; `Some("")` counts as
/// none, as `LoopbackTcp::with_operator_token` and the web bridge treat it.
fn operator_token(mcp: &McpConfig) -> Option<&str> {
    mcp.operator_token.as_deref().filter(|t| !t.is_empty())
}

/// Spec D2's mode-rule table, row by row.
///
/// `mint_failure` is the reason `operator_token::mint_if_absent` skipped,
/// already formatted by the caller as `could not write mcp.operator_token to
/// <path>` (spec D3 warned it); it is passed through verbatim for the
/// stdio/HTTP · enabled · no-token row. Should that row be reached with no
/// mint failure to quote (a token-less config whose mint never ran), the
/// reason falls back to [`REASON_NO_TOKEN`], the same word the loopback row
/// uses for a missing token.
pub fn plan(mcp: &McpConfig, mint_failure: Option<&str>) -> Plan {
    let token = operator_token(mcp);
    match (&mcp.transport, mcp.operator_bus.enabled, token) {
        (McpTransport::LoopbackTcp { .. }, _, Some(_)) => Plan::Shared,
        (McpTransport::LoopbackTcp { .. }, _, None) => Plan::Off(REASON_NO_TOKEN.to_string()),
        (McpTransport::Stdio | McpTransport::StreamableHttp { .. }, false, _) => {
            Plan::Off(REASON_DISABLED.to_string())
        }
        (McpTransport::Stdio | McpTransport::StreamableHttp { .. }, true, Some(_)) => {
            Plan::Dedicated(mcp.operator_bus.port)
        }
        (McpTransport::Stdio | McpTransport::StreamableHttp { .. }, true, None) => Plan::Off(
            mint_failure
                .map(str::to_string)
                .unwrap_or_else(|| REASON_NO_TOKEN.to_string()),
        ),
    }
}

/// The M2 remedy line for a held `mcp.operator_bus.port`.
pub fn port_remedy(config: &Path) -> String {
    format!(
        "Free it, or set mcp.operator_bus.port to another port in {}.",
        config.display()
    )
}

/// The operator bus for one run: the card's word and, for a dedicated bus,
/// the serving task. Dropping it aborts the task (plan C5), which drops the
/// listener, which removes the core pointer.
pub struct OperatorBus {
    word: OperatorBusWord,
    task: Option<JoinHandle<anyhow::Result<()>>>,
}

impl OperatorBus {
    /// What the ready card says (spec D5).
    pub fn word(&self) -> OperatorBusWord {
        self.word.clone()
    }

    /// Resolves when the dedicated serving task ends, with its outcome:
    /// `Err` is why the bus died (the listener's error, or a panicked or
    /// cancelled task as `the operator bus task ended abnormally: ..`);
    /// `Ok(())` is a listener that ended without an error, which a serving
    /// core never expects. For a `Shared` or `Off` bus (no task), and once an
    /// outcome was taken, this pends for ever, so `run()` (Task 13) can make
    /// it one `tokio::select!` arm beside Ctrl-C, SIGTERM, stdin EOF and the
    /// TUI's `q` without a case split, and report a died bus the moment it
    /// happens instead of serving on with a silently dead listener. Cancel
    /// safe: a dropped `finished()` future leaves the task where it was.
    pub async fn finished(&mut self) -> anyhow::Result<()> {
        let Some(task) = self.task.as_mut() else {
            return std::future::pending().await;
        };
        let outcome = task.await;
        // A joined handle must not be polled again; dropping the bus now
        // aborts nothing, which is right: the task is gone.
        self.task = None;
        match outcome {
            Ok(outcome) => outcome,
            Err(join) => {
                Err(anyhow::Error::new(join).context("the operator bus task ended abnormally"))
            }
        }
    }
}

impl Drop for OperatorBus {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

/// Start the operator bus per spec D2 "Start".
///
/// - `Shared` → no second listener (the agent transport binds inside
///   `mcp.serve()` as today); `mcp.operator_bus.port` is ignored with one
///   `debug!` when it names a port.
/// - `Dedicated(port)` → `LoopbackTcp::bind_operator_only` **now**, so a
///   fixed-port conflict is the M2 panel ([`StartupError::PortInUse`] with
///   [`ROLE`] and [`port_remedy`]) before the ready card; then `on_bound(addr)`
///   (the L4 self-port hook, L4PAR-AC34); then the server, built exactly as
///   the TUI's in-process server is (`tui::server` with `McpTransport::Stdio`
///   as a label only, plan C6, `with_shared_governance`, `with_mcp_roles`,
///   `with_push`), served on the listener in a spawned task.
/// - `Off(reason)` → no task; the mint-failure reason was already warned
///   by spec D3.
///
/// `mint_failure` is the reason `plan` quotes when the token could not be
/// minted (see [`plan`]). The eight parameters are the spec's own list.
#[expect(
    clippy::too_many_arguments,
    reason = "the plan pins the eight-parameter signature"
)]
pub async fn start(
    cfg: &Config,
    config_path: &Path,
    services: &Services,
    agent_state: &Arc<AgentState>,
    audit_ring: &Arc<AuditRing>,
    push_tx: broadcast::Sender<Event>,
    on_bound: Option<Box<dyn FnOnce(SocketAddr) + Send>>,
    mint_failure: Option<String>,
) -> anyhow::Result<OperatorBus> {
    match plan(&cfg.mcp, mint_failure.as_deref()) {
        Plan::Shared => {
            if cfg.mcp.operator_bus.port != 0 {
                debug!(
                    port = cfg.mcp.operator_bus.port,
                    "mcp.operator_bus.port is ignored: the loopback MCP transport carries operator access"
                );
            }
            Ok(OperatorBus {
                word: OperatorBusWord::Shared,
                task: None,
            })
        }
        Plan::Off(reason) => Ok(OperatorBus {
            word: OperatorBusWord::Off(reason),
            task: None,
        }),
        Plan::Dedicated(port) => {
            // `plan` returned `Dedicated` only with a non-empty token; this is
            // the typed guard against the two drifting apart, never an unwrap.
            let Some(token) = operator_token(&cfg.mcp) else {
                anyhow::bail!("the operator bus needs a non-empty mcp.operator_token");
            };
            let listener = match LoopbackTcp::bind_operator_only(port, token.to_string()).await {
                Ok(listener) => listener,
                Err(err) => {
                    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
                    if err
                        .downcast_ref::<std::io::Error>()
                        .is_some_and(|io| io.kind() == std::io::ErrorKind::AddrInUse)
                    {
                        return Err(StartupError::PortInUse {
                            role: ROLE.to_string(),
                            addr,
                            remedy: port_remedy(config_path),
                        }
                        .into());
                    }
                    return Err(err.context(format!("binding {ROLE} on {addr}")));
                }
            };
            let addr = listener.local_addr();
            if let Some(hook) = on_bound {
                hook(addr);
            }
            let server = tui::with_shared_governance(
                tui::server(cfg, McpTransport::Stdio, services),
                agent_state,
                audit_ring,
            )
            .with_mcp_roles(cfg.mcp.operator_token.clone(), cfg.mcp.stdio_role)
            .with_push(push_tx);
            let task = tokio::spawn(server.serve_on(listener));
            Ok(OperatorBus {
                word: OperatorBusWord::Dedicated(addr),
                task: Some(task),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::path::Path;
    use std::time::Duration;

    use aitm_core::{McpConfig, McpTransport};

    use super::{plan, port_remedy, OperatorBus, OperatorBusWord, Plan};

    /// A loopback MCP transport with an agent token; the operator token is
    /// set separately by each case.
    fn loopback() -> McpTransport {
        McpTransport::LoopbackTcp {
            port: 9090,
            token: "agent-test-token".into(),
            endpoint_file: None,
        }
    }

    fn mcp(transport: McpTransport, enabled: bool, port: u16, token: Option<&str>) -> McpConfig {
        let mut mcp = McpConfig {
            transport,
            ..McpConfig::default()
        };
        mcp.operator_bus.enabled = enabled;
        mcp.operator_bus.port = port;
        mcp.operator_token = token.map(str::to_string);
        mcp
    }

    /// Spec D2's mode-rule table, one row per case.
    #[test]
    fn plan_follows_the_spec_table() {
        // loopback TCP · any · non-empty → Shared (the port is ignored).
        assert_eq!(
            plan(&mcp(loopback(), true, 9091, Some("optoken-test-a")), None),
            Plan::Shared
        );
        // loopback TCP · any · none → Off("no mcp.operator_token").
        assert_eq!(
            plan(&mcp(loopback(), true, 0, None), None),
            Plan::Off("no mcp.operator_token".to_string())
        );
        // stdio · true · non-empty → Dedicated(0) (ephemeral).
        assert_eq!(
            plan(
                &mcp(McpTransport::Stdio, true, 0, Some("optoken-test-b")),
                None
            ),
            Plan::Dedicated(0)
        );
        // streamable HTTP · true · non-empty · port 9091 → Dedicated(9091).
        assert_eq!(
            plan(
                &mcp(
                    McpTransport::streamable_http_default("bearer-test-token".into()),
                    true,
                    9091,
                    Some("optoken-test-c")
                ),
                None
            ),
            Plan::Dedicated(9091)
        );
        // stdio · true · none (mint failed) → the mint failure, verbatim.
        assert_eq!(
            plan(
                &mcp(McpTransport::Stdio, true, 0, None),
                Some("could not write mcp.operator_token to /p")
            ),
            Plan::Off("could not write mcp.operator_token to /p".to_string())
        );
        // stdio · false · any → Off("mcp.operator_bus.enabled: false").
        assert_eq!(
            plan(
                &mcp(McpTransport::Stdio, false, 0, Some("optoken-test-d")),
                None
            ),
            Plan::Off("mcp.operator_bus.enabled: false".to_string())
        );
    }

    #[test]
    fn port_remedy_names_the_key_and_the_file() {
        assert_eq!(
            port_remedy(Path::new("/x/config.yaml")),
            "Free it, or set mcp.operator_bus.port to another port in /x/config.yaml."
        );
    }

    /// S1 (security pass 1): `run()` learns that a dedicated bus died.
    /// A task that ends with an error hands that error back and a panicked
    /// task is an error too; a task that ends `Ok(())` is `Ok(())`; a
    /// `Shared`/`Off` bus (no task) pends, so a `select!` arm on it never
    /// fires; once the outcome was taken the bus pends as well.
    #[tokio::test]
    async fn finished_reports_a_died_bus_and_pends_without_one() {
        let addr: SocketAddr = "127.0.0.1:50512".parse().expect("addr");

        let mut died = OperatorBus {
            word: OperatorBusWord::Dedicated(addr),
            task: Some(tokio::spawn(async {
                anyhow::bail!("accept loop ended: boom")
            })),
        };
        let err = died.finished().await.expect_err("a died bus is an error");
        assert_eq!(err.to_string(), "accept loop ended: boom");
        assert!(died.task.is_none(), "the outcome was taken");
        let again = tokio::time::timeout(Duration::from_millis(50), died.finished()).await;
        assert!(again.is_err(), "pends once the outcome was taken");

        let mut clean = OperatorBus {
            word: OperatorBusWord::Dedicated(addr),
            task: Some(tokio::spawn(async { Ok(()) })),
        };
        clean.finished().await.expect("a clean end is Ok");

        let mut panicked = OperatorBus {
            word: OperatorBusWord::Dedicated(addr),
            task: Some(tokio::spawn(async { panic!("bus task panicked") })),
        };
        let err = panicked
            .finished()
            .await
            .expect_err("a panicked task is an error");
        assert!(
            format!("{err:#}").starts_with("the operator bus task ended abnormally: "),
            "{err:#}"
        );

        let mut off = OperatorBus {
            word: OperatorBusWord::Off("mcp.operator_bus.enabled: false".to_string()),
            task: None,
        };
        let pending = tokio::time::timeout(Duration::from_millis(50), off.finished()).await;
        assert!(pending.is_err(), "a bus with no task pends forever");
    }

    // ---- tester additions (stage 5, R14 pass 1) ----

    /// Tester — spec D2 table rows 1–2 say `any` for the opt-out on a
    /// loopback transport: `enabled: false` with a token is still `Shared`
    /// (that transport carries operator access by itself, whatever
    /// `operator_bus.port` says), without a token `Off("no
    /// mcp.operator_token")`; an empty token is none; on stdio and HTTP the
    /// opt-out word wins over a mint failure (the mint never runs when the
    /// bus is disabled).
    #[test]
    fn tester_plan_opt_out_is_ignored_on_a_loopback_transport() {
        let mint_failed = Some("could not write mcp.operator_token to /p");
        assert_eq!(
            plan(&mcp(loopback(), false, 0, Some("optoken-test-a")), None),
            Plan::Shared
        );
        assert_eq!(
            plan(
                &mcp(loopback(), false, 9091, Some("optoken-test-a")),
                mint_failed
            ),
            Plan::Shared
        );
        assert_eq!(
            plan(&mcp(loopback(), false, 0, None), None),
            Plan::Off("no mcp.operator_token".to_string())
        );
        assert_eq!(
            plan(&mcp(loopback(), true, 0, Some("")), mint_failed),
            Plan::Off("no mcp.operator_token".to_string())
        );
        assert_eq!(
            plan(&mcp(McpTransport::Stdio, true, 0, Some("")), mint_failed),
            Plan::Off("could not write mcp.operator_token to /p".to_string())
        );
        assert_eq!(
            plan(&mcp(McpTransport::Stdio, false, 0, None), mint_failed),
            Plan::Off("mcp.operator_bus.enabled: false".to_string())
        );
        assert_eq!(
            plan(
                &mcp(
                    McpTransport::streamable_http_default("bearer-test-token".into()),
                    false,
                    9091,
                    Some("optoken-test-c")
                ),
                None
            ),
            Plan::Off("mcp.operator_bus.enabled: false".to_string())
        );
        assert_eq!(
            plan(
                &mcp(
                    McpTransport::streamable_http_default("bearer-test-token".into()),
                    true,
                    0,
                    None
                ),
                None
            ),
            Plan::Off("no mcp.operator_token".to_string())
        );
        // The plan's Debug names reasons and ports, never a token.
        let shared = plan(&mcp(loopback(), true, 0, Some("optoken-test-dbg")), None);
        assert!(!format!("{shared:?}").contains("optoken-test"));
    }
}
