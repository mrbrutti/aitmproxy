//! The MCP server: JSON-RPC 2.0 dispatch over the command registry.
//!
//! `handle` is transport-neutral — one JSON-RPC message in, at most one out — so
//! the stdio and loopback-TCP transports (and in-process test clients) all run
//! the identical path: `tools/list` enumerates every registered command,
//! `tools/call` coerces the arguments by the command's schema and runs
//! `Command::invoke` against a `CommandHost` built from the attached services.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use aitm_core::{
    AgentPolicy, AgentState, BrowserDriver, Command, CommandHost, FlowStore, Frontend,
    McpTransport, ProxyClient, Registry, ScopeRateGuard, Sensitivity, SsrfPolicy,
};
use serde_json::{json, Map, Value as JsonValue};

use crate::json::{params_from_json, to_json};
use crate::schema::{McpSchemaDerive, StdSchemaDerive};
use crate::transport::{self, LoopbackTcp};

/// The MCP protocol revision this server speaks when the client names none.
pub const PROTOCOL_VERSION: &str = "2025-06-18";

// JSON-RPC 2.0 error codes, plus the transport's own refusal.
pub const PARSE_ERROR: i64 = -32700;
pub const INVALID_REQUEST: i64 = -32600;
pub const METHOD_NOT_FOUND: i64 = -32601;
pub const INVALID_PARAMS: i64 = -32602;
pub const INTERNAL_ERROR: i64 = -32603;
/// A loopback-TCP connection whose first line was not the expected token.
pub const UNAUTHORIZED: i64 = -32001;

/// Per-connection context, built once by the transport after it has classified
/// the connection's auth token (or, for stdio, from `mcp.stdio_role`), and
/// threaded into every message on that connection through [`McpServer::handle_on`].
///
/// The `role` drives policy and confirmation decisions (Tasks 4/5/9); the
/// `client_label` is the connection's `initialize.clientInfo.name`, carried for
/// audit only. (Task 7 adds the bounded push sink here.)
#[derive(Debug, Clone)]
pub struct ConnCtx {
    /// The frontend this connection speaks as.
    pub role: Frontend,
    /// The human-readable client label from `initialize.clientInfo.name`.
    pub client_label: Option<String>,
}

impl ConnCtx {
    /// A context for `role` with no client label yet.
    pub fn new(role: Frontend) -> Self {
        Self {
            role,
            client_label: None,
        }
    }

    /// The default agent context (`Frontend::Mcp`, no label) the back-compat
    /// [`McpServer::handle`] wrapper uses.
    pub fn agent() -> Self {
        Self::new(Frontend::Mcp)
    }
}

/// The core services a `CommandHost` borrows; shared handles so one server can
/// answer many connections.
struct Services {
    store: Arc<dyn FlowStore>,
    client: Arc<dyn ProxyClient>,
    guard: Arc<dyn ScopeRateGuard>,
    browser: Option<Arc<dyn BrowserDriver>>,
}

type OnBound = Box<dyn FnOnce(SocketAddr) + Send>;

/// Registry handle + transport selection + the services commands run against.
pub struct McpServer {
    registry: Arc<Registry>,
    transport: McpTransport,
    services: Option<Services>,
    on_bound: Mutex<Option<OnBound>>,
    ssrf: SsrfPolicy,
    poc_dir: Option<std::path::PathBuf>,
    config: Option<Arc<aitm_core::Config>>,
    /// The second loopback-TCP token; a connection presenting it is an operator.
    operator_token: Option<Arc<str>>,
    /// The role a stdio connection speaks as (default [`Frontend::Mcp`]).
    stdio_role: Frontend,
    /// The agent policy in effect, enforced by [`McpServer::call_tool`] for the
    /// agent role. Shared with the `AgentPlugin`, so an operator `agent.set` is
    /// seen here at once.
    agent_state: Arc<AgentState>,
}

/// A JSON-RPC level failure (as opposed to a tool's own error result).
struct RpcError {
    code: i64,
    message: String,
}

impl RpcError {
    fn new(code: i64, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl McpServer {
    /// A server over `registry` that will listen on `transport`. Attach the core
    /// services with [`McpServer::with_services`] before serving `tools/call`.
    pub fn new(registry: Arc<Registry>, transport: McpTransport) -> Self {
        Self {
            registry,
            transport,
            services: None,
            on_bound: Mutex::new(None),
            ssrf: SsrfPolicy::default(),
            poc_dir: None,
            config: None,
            operator_token: None,
            stdio_role: Frontend::Mcp,
            // The milestone default; wiring overrides it from `McpConfig.policy`.
            agent_state: Arc::new(AgentState::new(AgentPolicy::Auto)),
        }
    }

    /// The shared agent-policy state the policy gate reads and `agent.set` writes.
    /// Wiring seeds it from `McpConfig.policy` and hands the same `Arc` to the
    /// `AgentPlugin`.
    pub fn with_agent_state(mut self, agent_state: Arc<AgentState>) -> Self {
        self.agent_state = agent_state;
        self
    }

    /// The operator token (loopback TCP) and the stdio connection's role. The
    /// agent token stays on [`McpTransport::LoopbackTcp`]; an operator token here
    /// lets a loopback connection present it to be treated as [`Frontend::Operator`].
    pub fn with_mcp_roles(mut self, operator_token: Option<String>, stdio_role: Frontend) -> Self {
        self.operator_token = operator_token.map(Into::into);
        self.stdio_role = stdio_role;
        self
    }

    /// The role a stdio connection is served as (default [`Frontend::Mcp`]).
    pub fn stdio_role(&self) -> Frontend {
        self.stdio_role
    }

    /// Attach the proxy configuration so `config.get`/`proxy.status` can read it.
    pub fn with_config(mut self, config: Arc<aitm_core::Config>) -> Self {
        self.config = Some(config);
        self
    }

    /// Use the configured SSRF policy for command-side pre-flights (the PoC
    /// runner's browser navigation), so it matches the connector instead of
    /// silently falling back to the default.
    pub fn with_ssrf_policy(mut self, policy: SsrfPolicy) -> Self {
        self.ssrf = policy;
        self
    }

    /// Confine `poc.run` to PoC files under `dir` (opt-in; `None` = unconfined).
    pub fn with_poc_dir(mut self, dir: Option<std::path::PathBuf>) -> Self {
        self.poc_dir = dir;
        self
    }

    /// The services every `Command::invoke` receives through its `CommandHost`.
    pub fn with_services(
        mut self,
        store: Arc<dyn FlowStore>,
        client: Arc<dyn ProxyClient>,
        guard: Arc<dyn ScopeRateGuard>,
        browser: Option<Arc<dyn BrowserDriver>>,
    ) -> Self {
        self.services = Some(Services {
            store,
            client,
            guard,
            browser,
        });
        self
    }

    /// Called once with the bound address when `serve` listens on loopback TCP
    /// (lets a caller that asked for port 0 learn the port).
    pub fn on_bound(self, f: impl FnOnce(SocketAddr) + Send + 'static) -> Self {
        if let Ok(mut slot) = self.on_bound.lock() {
            *slot = Some(Box::new(f));
        }
        self
    }

    /// Serve the configured transport until it ends (stdio EOF) or fails.
    /// `tools/list` enumerates every registered command; `tools/call` →
    /// `Command::invoke`.
    pub async fn serve(self) -> anyhow::Result<()> {
        let McpServer {
            registry,
            transport: selected,
            services,
            on_bound,
            ssrf,
            poc_dir,
            config,
            operator_token,
            stdio_role,
            agent_state,
        } = self;
        let on_bound = on_bound.into_inner().unwrap_or(None);
        let server = Arc::new(McpServer {
            registry,
            transport: selected.clone(),
            services,
            on_bound: Mutex::new(None),
            ssrf,
            poc_dir,
            config,
            operator_token: operator_token.clone(),
            stdio_role,
            agent_state,
        });
        match selected {
            McpTransport::Stdio => transport::serve_stdio(server).await,
            McpTransport::LoopbackTcp { port, token } => {
                let listener = LoopbackTcp::bind(port, token)
                    .await?
                    .with_operator_token(operator_token.map(|t| t.to_string()));
                if let Some(f) = on_bound {
                    f(listener.local_addr());
                }
                listener.serve(server).await
            }
        }
    }

    /// Handle one JSON-RPC message with a default agent connection
    /// ([`Frontend::Mcp`], no client label). Back-compat wrapper over
    /// [`McpServer::handle_on`] for in-process callers and existing tests.
    pub fn handle(&self, message: &str) -> Option<String> {
        self.handle_on(&ConnCtx::agent(), message)
    }

    /// Handle one JSON-RPC message on a specific connection; `None` when it was
    /// a notification (no reply). The `conn` carries the frontend role and the
    /// client label, so `tools/call` runs against the right [`Frontend`].
    pub fn handle_on(&self, conn: &ConnCtx, message: &str) -> Option<String> {
        let parsed: JsonValue = match serde_json::from_str(message) {
            Ok(v) => v,
            Err(e) => {
                return Some(
                    error_response(JsonValue::Null, PARSE_ERROR, format!("parse error: {e}"))
                        .to_string(),
                )
            }
        };
        let Some(req) = parsed.as_object() else {
            return Some(
                error_response(
                    JsonValue::Null,
                    INVALID_REQUEST,
                    "a request must be a JSON object",
                )
                .to_string(),
            );
        };
        // Absent id = notification; a present-but-null id still gets a reply.
        let id = req.get("id").cloned();
        let Some(method) = req.get("method").and_then(JsonValue::as_str) else {
            return Some(
                error_response(
                    id.unwrap_or(JsonValue::Null),
                    INVALID_REQUEST,
                    "missing `method`",
                )
                .to_string(),
            );
        };
        let params = req.get("params").cloned().unwrap_or_else(|| json!({}));
        let outcome = self.dispatch(conn, method, &params);
        let id = id?;
        Some(
            match outcome {
                Ok(result) => json!({"jsonrpc": "2.0", "id": id, "result": result}),
                Err(e) => error_response(id, e.code, e.message),
            }
            .to_string(),
        )
    }

    fn dispatch(
        &self,
        conn: &ConnCtx,
        method: &str,
        params: &JsonValue,
    ) -> Result<JsonValue, RpcError> {
        match method {
            "initialize" => {
                let version = params
                    .get("protocolVersion")
                    .and_then(JsonValue::as_str)
                    .unwrap_or(PROTOCOL_VERSION);
                Ok(json!({
                    "protocolVersion": version,
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "aitmproxy", "version": aitm_core::VERSION},
                }))
            }
            "ping" => Ok(json!({})),
            "tools/list" => {
                let tools: Vec<JsonValue> = self
                    .registry
                    .commands()
                    .map(|cmd| StdSchemaDerive.to_mcp_tool(cmd.as_ref()).to_json())
                    .collect();
                Ok(json!({"tools": tools}))
            }
            "tools/call" => self.call_tool(conn, params),
            m if m.starts_with("notifications/") => Ok(JsonValue::Null),
            other => Err(RpcError::new(
                METHOD_NOT_FOUND,
                format!("unknown method `{other}`"),
            )),
        }
    }

    fn call_tool(&self, conn: &ConnCtx, params: &JsonValue) -> Result<JsonValue, RpcError> {
        let name = params
            .get("name")
            .and_then(JsonValue::as_str)
            .ok_or_else(|| RpcError::new(INVALID_PARAMS, "missing tool `name`"))?;
        let empty = Map::new();
        let arguments = match params.get("arguments") {
            None | Some(JsonValue::Null) => &empty,
            Some(JsonValue::Object(args)) => args,
            Some(other) => {
                return Err(RpcError::new(
                    INVALID_PARAMS,
                    format!("`arguments` must be an object, got {other}"),
                ))
            }
        };
        let cmd = self
            .registry
            .command(name)
            .ok_or_else(|| RpcError::new(INVALID_PARAMS, format!("unknown tool `{name}`")))?;
        // The agent policy gate (D2), before anything runs. Only the agent role
        // is gated; an operator or the CLI is the control and bypasses it.
        if let Some(reason) = self.policy_refusal(conn, cmd.as_ref()) {
            return Ok(tool_error(reason));
        }
        let services = self.services.as_ref().ok_or_else(|| {
            RpcError::new(
                INTERNAL_ERROR,
                "no core services attached; call McpServer::with_services first",
            )
        })?;
        let args = match params_from_json(arguments, &cmd.schema(), name) {
            Ok(args) => args,
            Err(e) => return Ok(tool_error(e.to_string())),
        };
        let host = CommandHost::new(
            services.store.as_ref(),
            services.client.as_ref(),
            services.guard.as_ref(),
            services.browser.as_deref(),
        )
        .with_ssrf(self.ssrf.clone())
        .with_poc_dir(self.poc_dir.clone())
        // The role comes from the connection (token class, or stdio_role), not a
        // hard-coded agent: an operator UI is treated as a human, an agent as an
        // agent, so gated commands and policy decide by who is actually on the end.
        .with_frontend(conn.role);
        let host = match &conn.client_label {
            Some(label) => host.with_client_label(label.clone()),
            None => host,
        };
        let host = match &self.config {
            Some(cfg) => host.with_config(cfg.clone()),
            None => host,
        };
        Ok(match cmd.invoke(args, &host) {
            Ok(value) => {
                let structured = to_json(&value);
                json!({
                    "content": [{"type": "text", "text": structured.to_string()}],
                    "structuredContent": structured,
                    "isError": false,
                })
            }
            // A failing command is a tool result, not a protocol failure.
            Err(e) => tool_error(format!("{e:#}")),
        })
    }

    /// The D2 policy decision for one command on one connection: `Some(reason)`
    /// when the agent policy refuses it, `None` when it may proceed. Only the
    /// agent role (`Frontend::Mcp`) is gated — `Operator`/`Cli` are the control.
    fn policy_refusal(&self, conn: &ConnCtx, cmd: &dyn Command) -> Option<String> {
        if conn.role != Frontend::Mcp {
            return None;
        }
        let policy = self.agent_state.policy();
        let sens = cmd.sensitivity();
        let allowed = match (policy, sens) {
            (AgentPolicy::All, _) => true,
            (AgentPolicy::Auto, Sensitivity::Read | Sensitivity::Write) => true,
            // Autonomous: a Sensitive command is refused unless it carries its own
            // per-command agent config gate (ca.install/uninstall → ca.allow_agent_install,
            // scope.add → scope.allow_agent_widen). Those are deferred to the
            // command, which self-governs — honouring its config flag, dry-run
            // escape, and its own audit/refusal — so the policy gate never pre-empts
            // the command-level posture. A Sensitive command with no such gate is
            // refused here (deny-by-default).
            (AgentPolicy::Auto, Sensitivity::Sensitive) => defers_to_command_gate(cmd.name()),
            (AgentPolicy::Ask, Sensitivity::Read | Sensitivity::Write) => true,
            // `Ask` parks a Sensitive call for operator approval (Task 9); until
            // that lands it is refused rather than run.
            (AgentPolicy::Ask, Sensitivity::Sensitive) => false,
            (AgentPolicy::ReadOnly, Sensitivity::Read) => true,
            (AgentPolicy::ReadOnly, _) => false,
            (AgentPolicy::Paused, _) => false,
            // `AgentPolicy` is `#[non_exhaustive]`: a future posture fails closed.
            _ => false,
        };
        if allowed {
            None
        } else {
            Some(policy_refusal_reason(policy, sens, cmd.name()))
        }
    }
}

/// Whether a Sensitive command carries its own per-command agent config gate, so
/// the `Auto` policy defers the agent's call to the command (which enforces the
/// flag, dry-run, and audit) instead of pre-empting it (spec D2, "unless its
/// config gate allows"). Any other Sensitive command is refused by the policy gate.
fn defers_to_command_gate(name: &str) -> bool {
    matches!(name, "ca.install" | "ca.uninstall" | "scope.add")
}

/// The refusal text for a command the agent policy blocked, tuned to why.
fn policy_refusal_reason(policy: AgentPolicy, sens: Sensitivity, name: &str) -> String {
    match policy {
        AgentPolicy::Paused => format!(
            "`{name}` refused: the agent policy is `paused`; no agent command runs. An operator can \
             change it with agent.set."
        ),
        AgentPolicy::ReadOnly => format!(
            "`{name}` refused: the agent policy is `readonly`; only read-only commands run. An \
             operator can change it with agent.set."
        ),
        _ if sens == Sensitivity::Sensitive => format!(
            "`{name}` refused: a sensitive command is not allowed to the agent under the `{}` \
             policy without its config gate (e.g. ca.allow_agent_install, scope.allow_agent_widen). \
             An operator can run or approve it, or open that gate.",
            policy.label()
        ),
        _ => format!(
            "`{name}` refused by the agent policy `{}`.",
            policy.label()
        ),
    }
}

/// A JSON-RPC error response.
pub(crate) fn error_response(id: JsonValue, code: i64, message: impl Into<String>) -> JsonValue {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {"code": code, "message": message.into()},
    })
}

fn tool_error(text: String) -> JsonValue {
    json!({
        "content": [{"type": "text", "text": text}],
        "isError": true,
    })
}
