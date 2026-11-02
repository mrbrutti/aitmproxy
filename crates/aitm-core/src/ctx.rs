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

use crate::client::SendOptions;
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

    /// Send `req` under [`SendOptions`] (record policy, marks, version policy).
    /// The default ignores `opts` and calls [`ProxyClient::send`], which records;
    /// an impl that cannot honour the options falls back to it. `PipelineClient`
    /// overrides this to apply every option.
    fn send_opts(
        &self,
        req: HttpRequest,
        opts: SendOptions,
    ) -> BoxFuture<'_, anyhow::Result<HttpFlow>> {
        let _ = opts;
        self.send(req)
    }

    /// Send `req` as a **scanner probe** (spec amendment 80). A probe exists to
    /// provoke the target, so a 5xx *answer* is a completed exchange and must
    /// not count toward the host's error budget; a transport failure or a
    /// timeout still does, and still disables the host. Proxied and reissued
    /// traffic keeps [`ProxyClient::send_opts`]'s semantics. The default cannot
    /// tell the two apart and falls back to `send_opts`; `PipelineClient`
    /// overrides it.
    fn send_probe(
        &self,
        req: HttpRequest,
        opts: SendOptions,
    ) -> BoxFuture<'_, anyhow::Result<HttpFlow>> {
        self.send_opts(req, opts)
    }
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
/// Classify the new variant in exactly two places, both in `aitm-core`:
/// `CallerTrust::from` (this file, its trust class) and `origin_label`
/// (`audit.rs`, its wire label). Both are wildcard-free matches, so `aitm-core`
/// does not build until you do. That covers classification only; for a variant
/// that is a human surface, see the `Operator` routing note below.
///
/// Every trust gate in the workspace derives from the one predicate
/// [`CallerTrust::is_trusted_control`], reached through
/// [`Frontend::is_trusted_control`] or [`CommandHost::caller_is_trusted_control`],
/// so classifying the variant once is enough: no trust gate needs an edit. If
/// `CallerTrust` itself grows a variant, `is_trusted_control` is the single place
/// to classify it. Never compare a `Frontend` against the agent role
/// (`Frontend::Mcp`, `CallerTrust::Agent`) with `==` or `!=` to decide trust: that
/// is a deny-list that fails open for a variant added later, and the compiler
/// cannot exhaustiveness-check it. The source scan
/// `crates/aitm-core/tests/trust_gate_scan.rs` rejects an `==`, `!=`, `matches!` or
/// `if let` comparison against the agent role in any `crates/*/src` file. It does
/// not flag a Cli-only `!= Frontend::Cli` gate: that one is legitimate, because it
/// fails closed for every variant added later.
///
/// Classification is not routing. `aitm-mcp` also keys on [`Frontend::Operator`]
/// itself: the D4 confirm handshake (`conn.role == Frontend::Operator`),
/// `any_role(Frontend::Operator)` in `park_for_approval` and
/// `fanout_role(Frontend::Operator, ..)` (all in `crates/aitm-mcp/src/server.rs`;
/// find them by symbol, line numbers move). A new variant classified as
/// [`CallerTrust::Operator`] passes every trust gate but does not get the confirm
/// handshake or approval routing unless those sites are updated too.
///
/// Label-only sites (`role_str` in `aitm-mcp`, `frontend_label` in `aitm-ca`,
/// `origin_str` in `aitm-findings`) map an unclassified variant to the agent label
/// with `_ =>`; they only name a role and are not gates. The Cli-only gates
/// (`!= Frontend::Cli`) gate any non-Cli variant automatically (they fail closed)
/// and need touching only if the new variant should be treated like `Cli`.
///
/// **Default a new variant to [`CallerTrust::Agent`].** Classify it as
/// [`CallerTrust::Operator`] only when a present human is behind every connection
/// of that kind; that is one explicit, reviewable line in `CallerTrust::from`.
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

impl Frontend {
    /// Whether this frontend is a present human control surface (it bypasses the
    /// agent gates) rather than an autonomous agent (it is gated).
    ///
    /// This is the entry point for code that holds a `Frontend` but no
    /// [`CommandHost`] (for example a connection's role). It is not a second
    /// definition: it delegates to [`CallerTrust::is_trusted_control`] through the
    /// wildcard-free [`CallerTrust::from`], so the answer for every variant is
    /// decided in one place.
    #[must_use]
    pub fn is_trusted_control(self) -> bool {
        CallerTrust::from(self).is_trusted_control()
    }
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
///
/// [`CallerTrust::is_trusted_control`] is the one predicate every agent gate asks
/// ("does this caller bypass the agent gates?"); a gate never compares a
/// `CallerTrust` with `==` to decide that.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallerTrust {
    /// A present human operator — the human-driven `aitm` CLI ([`Frontend::Cli`])
    /// or an operator-token MCP connection ([`Frontend::Operator`]).
    Operator,
    /// An autonomous agent over MCP ([`Frontend::Mcp`]).
    Agent,
}

impl CallerTrust {
    /// Whether this caller is a present human control surface that bypasses the
    /// agent gates (`true`), or an autonomous agent that is gated (`false`).
    ///
    /// The one definition of "trusted" in the workspace; [`Frontend::is_trusted_control`]
    /// and [`CommandHost::caller_is_trusted_control`] delegate here. It is an
    /// allow-list: a wildcard-free `match`, so adding a `CallerTrust` variant does
    /// not compile until it is classified here, and nothing is trusted by default.
    #[must_use]
    #[deny(
        clippy::wildcard_enum_match_arm,
        clippy::match_wildcard_for_single_variants
    )]
    pub fn is_trusted_control(self) -> bool {
        match self {
            CallerTrust::Operator => true,
            CallerTrust::Agent => false,
        }
    }
}

impl From<Frontend> for CallerTrust {
    /// The one classification of every [`Frontend`] into a trust class:
    ///
    /// | `Frontend` | `CallerTrust` | Who is behind it |
    /// |---|---|---|
    /// | [`Frontend::Cli`] | [`CallerTrust::Operator`] | the human at the `aitm` CLI |
    /// | [`Frontend::Operator`] | [`CallerTrust::Operator`] | a present human on an operator-token connection |
    /// | [`Frontend::Mcp`] | [`CallerTrust::Agent`] | an autonomous agent |
    ///
    /// The match is wildcard-free, so a new `Frontend` variant does not compile
    /// until it is placed in this table. Default a new variant to
    /// [`CallerTrust::Agent`]; map it to [`CallerTrust::Operator`] only when a
    /// present human is behind every connection of that kind.
    #[deny(
        clippy::wildcard_enum_match_arm,
        clippy::match_wildcard_for_single_variants
    )]
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
    connection_id: Option<String>,
    config: Option<std::sync::Arc<crate::config::Config>>,
    finding_recorder: Option<&'a dyn FindingRecorder>,
    egress: Option<std::sync::Arc<crate::egress::EgressConfinement>>,
    jobs: Option<std::sync::Arc<crate::jobs::JobBus>>,
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
            connection_id: None,
            config: None,
            finding_recorder: None,
            egress: None,
            jobs: None,
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

    /// Attach the process-wide job bus, so a command that runs work in the
    /// background can publish progress to whatever frontends are listening.
    /// Shared by `Arc` because the publisher outlives this borrowed host.
    pub fn with_jobs(mut self, jobs: std::sync::Arc<crate::jobs::JobBus>) -> Self {
        self.jobs = Some(jobs);
        self
    }

    /// An owned handle to the attached job bus, or `None` when the frontend
    /// wired none. A command must work without it: no bus means no listener,
    /// never a refusal.
    pub fn jobs(&self) -> Option<std::sync::Arc<crate::jobs::JobBus>> {
        self.jobs.clone()
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

    /// Whether the invoking frontend is a present human control surface that
    /// bypasses the agent gates, per [`Frontend::is_trusted_control`]. A host never
    /// given a frontend defaults to [`Frontend::Mcp`], so this is `false` for it:
    /// the gated posture. A command gate reads
    /// `!host.caller_is_trusted_control() && !flag`, never a comparison against a
    /// `Frontend` variant.
    #[must_use]
    pub fn caller_is_trusted_control(&self) -> bool {
        self.frontend.is_trusted_control()
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

    /// Attach the server-assigned, opaque id of the calling connection (see
    /// `McpServer::connection_id` in `aitm-mcp`). Policy and confirmation
    /// decisions key off [`CommandHost::frontend`], not this id.
    pub fn with_connection_id(mut self, id: impl Into<String>) -> Self {
        self.connection_id = Some(id.into());
        self
    }

    /// The server-assigned id of the calling connection. `None` for an
    /// in-process caller (a host never given one).
    pub fn connection_id(&self) -> Option<&str> {
        self.connection_id.as_deref()
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

/// A `ProxyClient` that is never called: the one shared stub for this file's
/// test modules, which only need a `CommandHost` to exist.
#[cfg(test)]
struct NoopClient;
#[cfg(test)]
impl ProxyClient for NoopClient {
    fn send(&self, _req: HttpRequest) -> BoxFuture<'_, anyhow::Result<HttpFlow>> {
        Box::pin(async { anyhow::bail!("NoopClient: send not supported in this test") })
    }
}

#[cfg(test)]
mod finding_recorder_tests {
    use super::*;
    use crate::guard::StdGuard;
    use crate::store::MemFlowStore;

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

/// Pins the one trust predicate for every `Frontend` and `CallerTrust` variant.
///
/// These live in `aitm-core/src` (not `tests/`) on purpose: `Frontend` is
/// `#[non_exhaustive]`, so a wildcard-free `match` over it compiles only inside
/// this crate. Adding a `Frontend` variant therefore breaks this module's build
/// until its expected trust is stated in `expected_trusted`; a new `CallerTrust`
/// variant already breaks the wildcard-free match in
/// [`CallerTrust::is_trusted_control`] itself.
#[cfg(test)]
mod trust_tests {
    use super::*;
    use crate::guard::StdGuard;
    use crate::store::MemFlowStore;

    /// The expected trust of each `Frontend`, wildcard-free on purpose.
    fn expected_trusted(f: Frontend) -> bool {
        match f {
            Frontend::Cli | Frontend::Operator => true,
            Frontend::Mcp => false,
        }
    }

    #[test]
    fn caller_trust_predicate_pins_both_variants() {
        assert!(CallerTrust::Operator.is_trusted_control());
        assert!(!CallerTrust::Agent.is_trusted_control());
    }

    #[test]
    fn caller_trust_from_frontend_pins_all_three() {
        assert_eq!(CallerTrust::from(Frontend::Cli), CallerTrust::Operator);
        assert_eq!(CallerTrust::from(Frontend::Operator), CallerTrust::Operator);
        assert_eq!(CallerTrust::from(Frontend::Mcp), CallerTrust::Agent);
    }

    #[test]
    fn frontend_predicate_pins_all_three_and_matches_caller_trust() {
        // The literals, stated outright so a flipped helper cannot hide behind
        // the loop below.
        assert!(Frontend::Cli.is_trusted_control());
        assert!(Frontend::Operator.is_trusted_control());
        assert!(!Frontend::Mcp.is_trusted_control());

        for f in [Frontend::Cli, Frontend::Mcp, Frontend::Operator] {
            assert_eq!(
                f.is_trusted_control(),
                expected_trusted(f),
                "Frontend::is_trusted_control disagrees with the pinned table for {f:?}"
            );
            assert_eq!(
                f.is_trusted_control(),
                CallerTrust::from(f).is_trusted_control(),
                "Frontend::is_trusted_control must delegate to CallerTrust for {f:?}"
            );
        }
    }

    #[test]
    fn command_host_caller_is_trusted_control_follows_frontend() {
        let store = MemFlowStore::new();
        let client = NoopClient;
        let guard = StdGuard::default();

        // A host never given a frontend defaults to Frontend::Mcp: untrusted.
        let never_set = CommandHost::new(&store, &client, &guard, None);
        assert!(!never_set.caller_is_trusted_control());

        let cli = CommandHost::new(&store, &client, &guard, None).with_frontend(Frontend::Cli);
        assert!(cli.caller_is_trusted_control());

        let operator =
            CommandHost::new(&store, &client, &guard, None).with_frontend(Frontend::Operator);
        assert!(operator.caller_is_trusted_control());

        let mcp = CommandHost::new(&store, &client, &guard, None).with_frontend(Frontend::Mcp);
        assert!(!mcp.caller_is_trusted_control());
    }
}

/// Pins the server-assigned connection id carried on a [`CommandHost`].
#[cfg(test)]
mod host_identity_tests {
    use super::*;
    use crate::guard::StdGuard;
    use crate::store::MemFlowStore;

    #[test]
    fn connection_id_defaults_to_none_and_follows_with_connection_id() {
        let store = MemFlowStore::new();
        let client = NoopClient;
        let guard = StdGuard::default();

        // A fresh host has no connection id: an in-process caller.
        let fresh = CommandHost::new(&store, &client, &guard, None);
        assert_eq!(fresh.connection_id(), None);

        // The id is whatever the server attached, verbatim.
        let attached =
            CommandHost::new(&store, &client, &guard, None).with_connection_id("conn_ab-1");
        assert_eq!(attached.connection_id(), Some("conn_ab-1"));

        // A label is never promoted into an id.
        let labelled = CommandHost::new(&store, &client, &guard, None).with_client_label("x");
        assert_eq!(labelled.client_label(), Some("x"));
        assert_eq!(labelled.connection_id(), None);
    }
}

/// Pins the optional job bus a frontend may attach to a [`CommandHost`].
#[cfg(test)]
mod job_bus_tests {
    use super::*;
    use crate::guard::StdGuard;
    use crate::jobs::JobBus;
    use crate::store::MemFlowStore;
    use std::sync::Arc;

    #[test]
    fn command_host_jobs_defaults_to_none_and_with_jobs_sets_it() {
        let store = MemFlowStore::new();
        let client = NoopClient;
        let guard = StdGuard::default();

        // No bus unless a frontend wires one: a command must cope without it.
        let fresh = CommandHost::new(&store, &client, &guard, None);
        assert!(fresh.jobs().is_none());

        // The very bus that was attached comes back, not a clone of its contents.
        let bus = Arc::new(JobBus::default());
        let wired = CommandHost::new(&store, &client, &guard, None).with_jobs(bus.clone());
        let got = wired.jobs().expect("the bus is wired");
        assert!(Arc::ptr_eq(&got, &bus));
    }
}
