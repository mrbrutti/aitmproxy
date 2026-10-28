//! The control plugin (F7): proxy and session control over the bus.
//!
//! `proxy.status` reports the proxy's live state (listening address, whether
//! interception is armed, how many flows are paused, whether capture is on, and
//! the stored-flow count) so a surface has a read-only way to learn it.
//! `proxy.pause`/`proxy.resume` toggle capture (the record button); `flow.clear`
//! empties the store; `config.get` returns a redacted view of the configuration
//! (never the MCP token or any key material).

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use aitm_core::{
    BrowserEngine, Command, CommandHost, Config, Flow, InterceptState, McpTransport, ParamSchema,
    Params, Plugin, Registry, TypeDesc, Value,
};

/// Registers `proxy.status`, `proxy.pause`, `proxy.resume`, `flow.clear`, and
/// `config.get`. Shares the intercept plugin's armed flag for read-only status.
pub struct ControlPlugin {
    armed: Arc<AtomicBool>,
}

impl ControlPlugin {
    /// `armed` is the intercept plugin's shared flag (see
    /// `InterceptPlugin::armed_flag`), so `proxy.status` reports the real state.
    pub fn new(armed: Arc<AtomicBool>) -> Self {
        Self { armed }
    }
}

impl Plugin for ControlPlugin {
    fn name(&self) -> &str {
        "control"
    }

    fn load(&mut self, reg: &mut Registry) {
        reg.add_command(Arc::new(ProxyStatus {
            armed: self.armed.clone(),
        }));
        reg.add_command(Arc::new(ProxyPause));
        reg.add_command(Arc::new(ProxyResume));
        reg.add_command(Arc::new(FlowClear));
        reg.add_command(Arc::new(ConfigGet));
    }
}

/// The count of flows currently parked (intercepted) in the store.
fn paused_count(host: &CommandHost) -> i64 {
    host.store()
        .list()
        .into_iter()
        .filter_map(|id| host.store().get(id))
        .filter(is_intercepted)
        .count() as i64
}

fn is_intercepted(flow: &Flow) -> bool {
    let state = match flow {
        Flow::Http(f) => &f.intercept,
        Flow::WebSocket(f) => &f.intercept,
    };
    matches!(state, InterceptState::Intercepted { .. })
}

/// `proxy.status` → the proxy's live state.
struct ProxyStatus {
    armed: Arc<AtomicBool>,
}

impl Command for ProxyStatus {
    fn name(&self) -> &str {
        "proxy.status"
    }

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "The proxy's live state: listening address, whether intercept is armed, \
                          paused-flow count, whether capture is on, and stored-flow count."
                .into(),
            params: vec![],
            result: TypeDesc::Object(Vec::new()),
        }
    }

    fn invoke(&self, _args: Params, host: &CommandHost) -> anyhow::Result<Value> {
        let mut obj = BTreeMap::new();
        obj.insert(
            "listening".into(),
            host.config()
                .map_or(Value::Null, |c| Value::Str(c.listen.to_string())),
        );
        obj.insert(
            "intercept_armed".into(),
            Value::Bool(self.armed.load(Ordering::Relaxed)),
        );
        obj.insert("capturing".into(), Value::Bool(host.store().is_capturing()));
        obj.insert("paused".into(), Value::Int(paused_count(host)));
        obj.insert("flows".into(), Value::Int(host.store().list().len() as i64));
        Ok(Value::Object(obj))
    }
}

fn set_capturing(host: &CommandHost, on: bool) -> Value {
    host.store().set_capturing(on);
    let mut obj = BTreeMap::new();
    obj.insert("capturing".into(), Value::Bool(host.store().is_capturing()));
    Value::Object(obj)
}

/// `proxy.pause` → stop retaining new flows (the record toggle, off).
struct ProxyPause;

impl Command for ProxyPause {
    fn name(&self) -> &str {
        "proxy.pause"
    }

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "Pause capture: new flows are not retained (traffic still flows). \
                          Returns the capture state."
                .into(),
            params: vec![],
            result: TypeDesc::Object(Vec::new()),
        }
    }

    fn invoke(&self, _args: Params, host: &CommandHost) -> anyhow::Result<Value> {
        Ok(set_capturing(host, false))
    }
}

/// `proxy.resume` → resume retaining new flows (the record toggle, on).
struct ProxyResume;

impl Command for ProxyResume {
    fn name(&self) -> &str {
        "proxy.resume"
    }

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "Resume capture: new flows are retained again. Returns the capture state."
                .into(),
            params: vec![],
            result: TypeDesc::Object(Vec::new()),
        }
    }

    fn invoke(&self, _args: Params, host: &CommandHost) -> anyhow::Result<Value> {
        Ok(set_capturing(host, true))
    }
}

/// `flow.clear` → empty the flow store; returns how many were removed.
struct FlowClear;

impl Command for FlowClear {
    fn name(&self) -> &str {
        "flow.clear"
    }

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "Remove every captured flow from the store; returns the count cleared."
                .into(),
            params: vec![],
            result: TypeDesc::Object(Vec::new()),
        }
    }

    fn invoke(&self, _args: Params, host: &CommandHost) -> anyhow::Result<Value> {
        let cleared = host.store().clear();
        let mut obj = BTreeMap::new();
        obj.insert("cleared".into(), Value::Int(cleared as i64));
        Ok(Value::Object(obj))
    }
}

/// `config.get` → a redacted view of the proxy configuration.
struct ConfigGet;

impl Command for ConfigGet {
    fn name(&self) -> &str {
        "config.get"
    }

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description:
                "A redacted view of the proxy configuration (no MCP token or key material).".into(),
            params: vec![],
            result: TypeDesc::Object(Vec::new()),
        }
    }

    fn invoke(&self, _args: Params, host: &CommandHost) -> anyhow::Result<Value> {
        let cfg = host
            .config()
            .ok_or_else(|| anyhow::anyhow!("configuration is not available to this frontend"))?;
        Ok(redacted(cfg))
    }
}

/// The configuration a surface may safely see: addresses, scope, limits and
/// feature flags — never the MCP token or any key/cert path's contents.
fn redacted(cfg: &Config) -> Value {
    let mut obj = BTreeMap::new();
    obj.insert("listen".into(), Value::Str(cfg.listen.to_string()));
    obj.insert("ssl_insecure".into(), Value::Bool(cfg.ssl_insecure));
    obj.insert("max_flows".into(), Value::Int(cfg.max_flows as i64));
    obj.insert(
        "max_flow_bytes".into(),
        Value::Int(cfg.max_flow_bytes as i64),
    );

    let mut scope = BTreeMap::new();
    scope.insert(
        "entries".into(),
        Value::Array(
            cfg.scope
                .entries
                .iter()
                .map(|e| Value::Str(e.host.clone()))
                .collect(),
        ),
    );
    scope.insert(
        "allow_agent_widen".into(),
        Value::Bool(cfg.scope.allow_agent_widen),
    );
    obj.insert("scope".into(), Value::Object(scope));

    let mut limits = BTreeMap::new();
    limits.insert(
        "global_rps".into(),
        Value::Int(i64::from(cfg.limits.global_rps)),
    );
    limits.insert(
        "per_host_rps".into(),
        Value::Int(i64::from(cfg.limits.per_host_rps)),
    );
    limits.insert(
        "max_concurrency".into(),
        Value::Int(i64::from(cfg.limits.max_concurrency)),
    );
    limits.insert(
        "host_error_budget".into(),
        Value::Int(i64::from(cfg.limits.host_error_budget)),
    );
    limits.insert(
        "max_body_bytes".into(),
        Value::Int(cfg.limits.max_body_bytes as i64),
    );
    obj.insert("limits".into(), Value::Object(limits));

    let mut ca = BTreeMap::new();
    ca.insert("dir".into(), Value::Str(cfg.ca.dir.display().to_string()));
    ca.insert(
        "allow_agent_install".into(),
        Value::Bool(cfg.ca.allow_agent_install),
    );
    obj.insert("ca".into(), Value::Object(ca));

    // The transport kind and (for loopback) its port, but never the token.
    let mut mcp = BTreeMap::new();
    match &cfg.mcp.transport {
        McpTransport::Stdio => {
            mcp.insert("transport".into(), Value::Str("stdio".into()));
        }
        McpTransport::LoopbackTcp { port, .. } => {
            mcp.insert("transport".into(), Value::Str("loopback_tcp".into()));
            mcp.insert("port".into(), Value::Int(i64::from(*port)));
        }
    }
    obj.insert("mcp".into(), Value::Object(mcp));

    let mut browser = BTreeMap::new();
    browser.insert(
        "engine".into(),
        Value::Str(
            match cfg.browser.engine {
                BrowserEngine::Obscura => "obscura",
                BrowserEngine::Chrome => "chrome",
            }
            .into(),
        ),
    );
    obj.insert("browser".into(), Value::Object(browser));

    obj.insert(
        "poc_dir".into(),
        cfg.poc
            .dir
            .as_ref()
            .map_or(Value::Null, |d| Value::Str(d.display().to_string())),
    );

    Value::Object(obj)
}
