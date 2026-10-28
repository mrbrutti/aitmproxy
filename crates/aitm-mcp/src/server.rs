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
    BrowserDriver, CommandHost, FlowStore, Frontend, McpTransport, ProxyClient, Registry,
    ScopeRateGuard, SsrfPolicy,
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
        }
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
        } = self;
        let on_bound = on_bound.into_inner().unwrap_or(None);
        let server = Arc::new(McpServer {
            registry,
            transport: selected.clone(),
            services,
            on_bound: Mutex::new(None),
            ssrf,
            poc_dir,
        });
        match selected {
            McpTransport::Stdio => transport::serve_stdio(server).await,
            McpTransport::LoopbackTcp { port, token } => {
                let listener = LoopbackTcp::bind(port, token).await?;
                if let Some(f) = on_bound {
                    f(listener.local_addr());
                }
                listener.serve(server).await
            }
        }
    }

    /// Handle one JSON-RPC message; `None` when it was a notification (no reply).
    pub fn handle(&self, message: &str) -> Option<String> {
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
        let outcome = self.dispatch(method, &params);
        let id = id?;
        Some(
            match outcome {
                Ok(result) => json!({"jsonrpc": "2.0", "id": id, "result": result}),
                Err(e) => error_response(id, e.code, e.message),
            }
            .to_string(),
        )
    }

    fn dispatch(&self, method: &str, params: &JsonValue) -> Result<JsonValue, RpcError> {
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
            "tools/call" => self.call_tool(params),
            m if m.starts_with("notifications/") => Ok(JsonValue::Null),
            other => Err(RpcError::new(
                METHOD_NOT_FOUND,
                format!("unknown method `{other}`"),
            )),
        }
    }

    fn call_tool(&self, params: &JsonValue) -> Result<JsonValue, RpcError> {
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
        // Said explicitly, though it is the default: an agent is on this end,
        // so a gated command relies on its config flag, never on a prompt.
        .with_frontend(Frontend::Mcp);
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
