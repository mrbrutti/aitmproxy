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

use crate::flow::{
    Flow, FlowId, HttpFlow, HttpRequest, HttpResponse, InterceptState, ResumeHandle,
};
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
///
/// # Adding a variant
///
/// A new variant must be classified in each place that decides what a frontend may
/// do: `CallerTrust::from` (this file), `origin_label` (`audit.rs`), and the MCP
/// trust gate `is_trusted_control` (`aitm-mcp`, `server.rs`). The first two are
/// wildcard-free matches, so `aitm-core` fails to build until you classify it. The
/// enum is `#[non_exhaustive]`, so the compiler cannot check the MCP gate from
/// another crate: left unclassified there, the variant is treated as an agent and
/// gated (it fails closed).
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

/// A finding a `poc.run` produces, in the shape the persistence layer records.
/// Declared in `aitm-core` (the bottom of the dependency graph) so the PoC runner
/// can build one without depending on `aitm-findings`; `aitm-findings` provides the
/// [`FindingRecorder`] that turns it into a durable record. `severity` is a
/// lowercase string (`info|low|medium|high|critical`) because core cannot name
/// `aitm_poc::Severity`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingDraft {
    pub title: String,
    pub class: String,
    pub severity: String,
    pub target: String,
    pub poc_ref: String,
    pub passed: bool,
    pub finding_capture: FlowId,
    pub flows: Vec<FlowId>,
    pub poc_path: String,
    pub screenshot_path: String,
    pub origin: Frontend,
    pub client_label: Option<String>,
}

/// Persists a [`FindingDraft`] into the configured findings store, returning the
/// recorded finding's id. Implemented by `aitm-findings` (`DiskFindingRecorder`)
/// and wired onto [`CommandHost`] by the binary — the same seam shape as
/// `FindingSink` / `ScriptStepExecutor`: `aitm-core` stays the bottom of the graph
/// and the PoC runner records through the trait with no findings-crate dependency.
pub trait FindingRecorder: Send + Sync {
    /// Record `draft` under `dir` (the configured `findings.dir`); returns the
    /// recorded finding's id.
    fn record(&self, draft: &FindingDraft, dir: &std::path::Path) -> anyhow::Result<String>;
}

/// Whether the caller behind a scripting/PoC invocation is a present human
/// operator or an autonomous agent. Distinct from [`Frontend`] because the
/// per-invocation seam only needs the trust distinction (human-present vs.
/// agent) to gate a verb (`l4.allow_agent_*`, and later `log.option`/`finding`),
/// not which exact surface issued the call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallerTrust {
    /// A present human operator — the human-driven `aitm` CLI ([`Frontend::Cli`])
    /// or an operator-token MCP connection ([`Frontend::Operator`]).
    Operator,
    /// An autonomous agent over MCP ([`Frontend::Mcp`]).
    Agent,
}

impl From<Frontend> for CallerTrust {
    /// The caller is an [`Agent`](CallerTrust::Agent) **iff** the frontend is
    /// [`Frontend::Mcp`]; the human-driven CLI ([`Frontend::Cli`]) and an
    /// operator-token MCP connection ([`Frontend::Operator`]) both map to
    /// [`CallerTrust::Operator`], since a present human is behind each.
    fn from(frontend: Frontend) -> Self {
        match frontend {
            Frontend::Mcp => CallerTrust::Agent,
            Frontend::Cli | Frontend::Operator => CallerTrust::Operator,
        }
    }
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
    finding_recorder: Option<&'a dyn FindingRecorder>,
    egress: Option<std::sync::Arc<crate::egress::EgressConfinement>>,
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
            finding_recorder: None,
            egress: None,
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

    /// Wire the finding recorder (the binary's `DiskFindingRecorder`), so
    /// `poc.run` can persist a [`FindingDraft`]. `None` (the default) means no
    /// persistence — the deny-by-default posture; recording is additionally gated
    /// on a configured `findings.dir`.
    pub fn with_finding_recorder(mut self, recorder: &'a dyn FindingRecorder) -> Self {
        self.finding_recorder = Some(recorder);
        self
    }

    /// The wired finding recorder, if any (`None` = no persistence).
    pub fn finding_recorder(&self) -> Option<&dyn FindingRecorder> {
        self.finding_recorder
    }

    /// Use the configured SSRF policy instead of the default.
    pub fn with_ssrf(mut self, policy: crate::config::SsrfPolicy) -> Self {
        self.ssrf = policy;
        self
    }

    /// Attach the proxy's live browser-egress posture (`Proxy::egress()`), so
    /// `browser.confine` can toggle its base and a campaign command (the
    /// scanner's crawl) can take an RAII hold on it. Shared by `Arc` because
    /// [`EgressConfinement::confine`](crate::egress::EgressConfinement::confine)
    /// needs an owned handle to hand the token. `None` (the default) means the
    /// posture is unavailable on this host — a frontend that never invokes
    /// `browser.confine` or a campaign need not wire it.
    pub fn with_egress(mut self, egress: std::sync::Arc<crate::egress::EgressConfinement>) -> Self {
        self.egress = Some(egress);
        self
    }

    /// The attached browser-egress posture, if the frontend wired one.
    pub fn egress(&self) -> Option<&crate::egress::EgressConfinement> {
        self.egress.as_deref()
    }

    /// An owned handle to the attached posture, for a command that must hold
    /// a campaign-scoped confinement across its run (`EgressConfinement::confine`
    /// takes `&Arc<Self>`). `None` when no posture is wired.
    pub fn egress_handle(&self) -> Option<std::sync::Arc<crate::egress::EgressConfinement>> {
        self.egress.clone()
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

#[cfg(test)]
mod finding_recorder_tests {
    use super::*;
    use crate::guard::StdGuard;
    use crate::store::MemFlowStore;

    /// A `ProxyClient` that is never called in these tests.
    struct NoopClient;
    impl ProxyClient for NoopClient {
        fn send(&self, _req: HttpRequest) -> BoxFuture<'_, anyhow::Result<HttpFlow>> {
            Box::pin(async { anyhow::bail!("NoopClient: send not supported in this test") })
        }
    }

    /// A recorder that asserts on the draft it is given and returns a fixed id.
    struct StubRecorder;
    impl FindingRecorder for StubRecorder {
        fn record(&self, draft: &FindingDraft, _dir: &std::path::Path) -> anyhow::Result<String> {
            assert_eq!(draft.title, "SQLi");
            assert_eq!(draft.severity, "critical");
            assert!(draft.passed);
            Ok("rec-1".to_string())
        }
    }

    fn sample_draft() -> FindingDraft {
        FindingDraft {
            title: "SQLi".to_string(),
            class: "cwe-89".to_string(),
            severity: "critical".to_string(),
            target: "http://127.0.0.1".to_string(),
            poc_ref: "dvwa-01-sqli".to_string(),
            passed: true,
            finding_capture: FlowId::new(),
            flows: vec![FlowId::new()],
            poc_path: "/tmp/x.poc.yaml".to_string(),
            screenshot_path: String::new(),
            origin: Frontend::Operator,
            client_label: Some("aitm-mac".to_string()),
        }
    }

    #[test]
    fn finding_recorder_opt_in() {
        let store = MemFlowStore::new();
        let client = NoopClient;
        let guard = StdGuard::default();
        let host = CommandHost::new(&store, &client, &guard, None);
        // Deny-by-default: no recorder unless one is wired.
        assert!(host.finding_recorder().is_none());

        // Once wired, it is reachable and records through the trait.
        let rec = StubRecorder;
        let host = host.with_finding_recorder(&rec);
        let recorder = host.finding_recorder().expect("recorder wired");
        let id = recorder
            .record(&sample_draft(), std::path::Path::new("/tmp"))
            .expect("record ok");
        assert_eq!(id, "rec-1");
    }
}
