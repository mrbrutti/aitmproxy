//! The handler/command contexts and the service seams they reach through.
//!
//! `FlowCtx` is the read/mutate handle a plugin gets while handling an event.
//! `CommandHost` is what a command sees: the store, the proxy client, the guard,
//! and an optional browser. The `ProxyClient` and `BrowserDriver` traits live here
//! (not in their feature crates) because `CommandHost` references them and
//! `aitm-core` is the bottom of the dependency graph — a feature crate implements
//! them. The concrete `FlowCtx`/`CommandHost` wiring is completed in Task 8.

use futures::future::BoxFuture;
use tokio::sync::oneshot;

use crate::flow::{Flow, HttpFlow, HttpRequest, HttpResponse, InterceptState, ResumeHandle};
use crate::guard::ScopeRateGuard;
use crate::store::FlowStore;
use crate::value::Value;

/// Reissue a request through the proxy's own pipeline (scope/rate-guarded,
/// captured). Implemented in Task 8; the trait is here so `CommandHost` can name it.
pub trait ProxyClient: Send + Sync {
    /// Send `req` and return the resulting captured flow (marked `is_replay`).
    fn send(&self, req: HttpRequest) -> BoxFuture<'_, anyhow::Result<HttpFlow>>;
}

/// Where to click in the browser.
#[derive(Debug, Clone)]
pub enum ClickTarget {
    Selector(String),
    Point { x: f64, y: f64 },
}

/// The outcome of a navigation.
#[derive(Debug, Clone)]
pub struct NavOutcome {
    pub final_url: String,
    pub status: Option<u16>,
}

/// The embedded browser's CUA-style primitives. Declared in core because
/// `CommandHost::browser` returns `&dyn BrowserDriver`; `aitm-browser` implements it.
pub trait BrowserDriver: Send + Sync {
    fn navigate(&self, url: &str) -> BoxFuture<'_, anyhow::Result<NavOutcome>>;
    fn click(&self, target: ClickTarget) -> BoxFuture<'_, anyhow::Result<()>>;
    fn type_text(&self, selector: &str, text: &str) -> BoxFuture<'_, anyhow::Result<()>>;
    /// PNG bytes.
    fn screenshot(&self) -> BoxFuture<'_, anyhow::Result<Vec<u8>>>;
    fn eval(&self, expr: &str) -> BoxFuture<'_, anyhow::Result<Value>>;
    fn get_dom(&self) -> BoxFuture<'_, anyhow::Result<String>>;
}

/// Which frontend is invoking a command. A command that gates an active
/// capability on a human being present (the `ca.*` trust-store changes) reads
/// this from the host; the frontends never learn command names.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Frontend {
    /// The human-driven `aitm` CLI.
    Cli,
    /// An agent over MCP.
    Mcp,
    /// A human operator over MCP (an operator-token connection, e.g. the
    /// `aitm-mac`/`aitm-web`/`aitm-tui` surfaces). Distinct from [`Frontend::Mcp`]
    /// so policy and confirmation decisions can treat a present human differently
    /// from an autonomous agent. The role stays `Copy`; the human-readable client
    /// label rides [`CommandHost`] separately.
    Operator,
}

/// Core services a command may use, without depending on any protocol crate.
pub struct CommandHost<'a> {
    store: &'a dyn FlowStore,
    client: &'a dyn ProxyClient,
    guard: &'a dyn ScopeRateGuard,
    browser: Option<&'a dyn BrowserDriver>,
    ssrf: crate::config::SsrfPolicy,
    poc_dir: Option<std::path::PathBuf>,
    frontend: Frontend,
    client_label: Option<String>,
    config: Option<std::sync::Arc<crate::config::Config>>,
}

impl<'a> CommandHost<'a> {
    /// Assemble a host from borrowed core services. The SSRF policy defaults to
    /// the deny-by-default posture; wiring that has the configured policy sets it
    /// with [`CommandHost::with_ssrf`] so command-side pre-flights (e.g. the PoC
    /// runner's browser navigation) match the connector.
    pub fn new(
        store: &'a dyn FlowStore,
        client: &'a dyn ProxyClient,
        guard: &'a dyn ScopeRateGuard,
        browser: Option<&'a dyn BrowserDriver>,
    ) -> Self {
        Self {
            store,
            client,
            guard,
            browser,
            ssrf: crate::config::SsrfPolicy::default(),
            poc_dir: None,
            // The gated posture: a host that did not declare itself the human
            // CLI is treated as agent-driven.
            frontend: Frontend::Mcp,
            client_label: None,
            config: None,
        }
    }

    /// Attach the proxy configuration, so commands that report or read it
    /// (`config.get`, `proxy.status`, `poc.*` output confinement) can reach it.
    pub fn with_config(mut self, config: std::sync::Arc<crate::config::Config>) -> Self {
        self.config = Some(config);
        self
    }

    /// The attached proxy configuration, if the frontend provided it.
    pub fn config(&self) -> Option<&crate::config::Config> {
        self.config.as_deref()
    }

    /// Use the configured SSRF policy instead of the default.
    pub fn with_ssrf(mut self, policy: crate::config::SsrfPolicy) -> Self {
        self.ssrf = policy;
        self
    }

    /// Declare which frontend built this host (defaults to [`Frontend::Mcp`]).
    pub fn with_frontend(mut self, frontend: Frontend) -> Self {
        self.frontend = frontend;
        self
    }

    /// The frontend invoking the command; [`Frontend::Mcp`] when never set.
    pub fn frontend(&self) -> Frontend {
        self.frontend
    }

    /// Attach the connection's human-readable client label (from
    /// `initialize.clientInfo.name`, e.g. `aitm-mac`). Carried for audit only;
    /// policy and confirmation decisions key off [`CommandHost::frontend`], not
    /// this label.
    pub fn with_client_label(mut self, label: impl Into<String>) -> Self {
        self.client_label = Some(label.into());
        self
    }

    /// The connection's client label, if one was declared (`None` otherwise).
    pub fn client_label(&self) -> Option<&str> {
        self.client_label.as_deref()
    }

    /// Confine `poc.run` to loading PoC files under `dir` (opt-in). `None` leaves
    /// loading unconfined (the default).
    pub fn with_poc_dir(mut self, dir: Option<std::path::PathBuf>) -> Self {
        self.poc_dir = dir;
        self
    }

    pub fn store(&self) -> &dyn FlowStore {
        self.store
    }
    pub fn client(&self) -> &dyn ProxyClient {
        self.client
    }
    pub fn browser(&self) -> Option<&dyn BrowserDriver> {
        self.browser
    }
    pub fn guard(&self) -> &dyn ScopeRateGuard {
        self.guard
    }
    /// The configured SSRF policy (defaults to deny-by-default).
    pub fn ssrf_policy(&self) -> &crate::config::SsrfPolicy {
        &self.ssrf
    }
    /// The configured PoC directory confinement, if any (`None` = unconfined).
    pub fn poc_dir(&self) -> Option<&std::path::Path> {
        self.poc_dir.as_deref()
    }
}

/// Read/mutate handle a plugin gets while handling an event for one flow.
///
/// Holds a mutable borrow of the flow plus an optional backup. `intercept()` parks
/// the flow (arming a [`ResumeHandle`]); Task 8's chain awaits the paired receiver
/// to drive the pausable future, and resumes/kills the flow in the store.
pub struct FlowCtx<'a> {
    flow: &'a mut Flow,
    backup: Option<Box<Flow>>,
    parked: Option<oneshot::Receiver<()>>,
}

impl<'a> FlowCtx<'a> {
    /// Wrap a borrowed flow for the duration of one event.
    pub fn new(flow: &'a mut Flow) -> Self {
        Self {
            flow,
            backup: None,
            parked: None,
        }
    }

    /// The flow this event is about.
    pub fn flow(&self) -> &Flow {
        self.flow
    }

    /// Mutate the flow in place before it is forwarded.
    pub fn flow_mut(&mut self) -> &mut Flow {
        self.flow
    }

    /// Short-circuit: answer the client with this response (HTTP flows only).
    pub fn set_response(&mut self, resp: HttpResponse) {
        if let Flow::Http(f) = self.flow {
            f.response = Some(resp);
        }
    }

    /// Park this flow as a pausable future; a command later resumes it. Returns
    /// the handle a command fires to resume.
    pub fn intercept(&mut self) -> ResumeHandle {
        let (handle, rx) = ResumeHandle::new();
        let backup = self
            .backup
            .take()
            .unwrap_or_else(|| Box::new(self.flow.clone()));
        set_intercept(
            self.flow,
            InterceptState::Intercepted {
                backup,
                resume: handle.clone(),
            },
        );
        self.parked = Some(rx);
        handle
    }

    /// Mark the flow resumed (edits applied, ready to forward).
    pub fn resume(&mut self) {
        set_intercept(self.flow, InterceptState::Resumed);
    }

    /// Drop the flow; the client sees a reset/closed connection.
    pub fn kill(&mut self) {
        set_intercept(self.flow, InterceptState::Killed);
    }

    /// Snapshot the flow before edits (enables `revert`).
    pub fn backup(&mut self) {
        self.backup = Some(Box::new(self.flow.clone()));
    }

    /// Restore the last backup, discarding edits.
    pub fn revert(&mut self) {
        if let Some(backup) = self.backup.take() {
            *self.flow = *backup;
        }
    }

    /// Take the parked receiver, if `intercept()` armed one. The chain (Task 8)
    /// awaits it to implement the pausable future.
    pub fn take_parked(&mut self) -> Option<oneshot::Receiver<()>> {
        self.parked.take()
    }
}

/// Set a flow's interception state regardless of protocol.
fn set_intercept(flow: &mut Flow, state: InterceptState) {
    match flow {
        Flow::Http(f) => f.intercept = state,
        Flow::WebSocket(f) => f.intercept = state,
    }
}
