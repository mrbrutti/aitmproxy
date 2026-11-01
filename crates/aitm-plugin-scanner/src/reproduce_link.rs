//! PoC-hint reproduction: an issue becomes a `FindingRecord` only when its PoC
//! ran and passed (spec D6).
//!
//! A check does not ask for a finding; it supplies a [`PocHint`] — the
//! assertions its verdict rests on, and optionally a benign control payload —
//! and the engine does the rest (Architect's call 23: the hint is the contract,
//! the engine holds no class list). For an issue the caller judged reproducible
//! (`vulnerable`, `confidence >= firm`, a hint present), this module:
//!
//! 1. builds a PoC from the **probe** request with [`StdPocBuilder`], so the
//!    PoC sends exactly what the check sent;
//! 2. scrubs it through [`crate::reproduce::scrub_poc`], so no credential of
//!    the captured session is written to a shareable file;
//! 3. runs it **exactly once** through [`StdPocRunner`] against the job's
//!    `host.client()`, so the run is paced, scoped and counted against the
//!    job's probe budget like every other probe;
//! 4. runs the control once more when the hint gave one;
//! 5. records a [`FindingRecord`] **only** when the run passed, and hands back
//!    the `poc_ref`/`finding_id` the caller links onto the issue
//!    ([`crate::issues::IssueStore::set_links`]).
//!
//! Nothing here is fatal to a scan: a reproduction that fails, a run that
//! errors, or a missing `findings.dir` yields `finding_id: None` and a `note`
//! saying why, never an `Err` that would sink the job.

use std::path::Path;
use std::time::SystemTime;

use aitm_core::{Body, CommandHost, Frontend, HttpFlow, HttpRequest, Value};
use aitm_findings::{FindingArtifacts, FindingRecord, Reproduction};
use aitm_poc::{
    Assertion, Poc, PocBuilder, PocInfo, PocRunResult, PocRunner, PocSpec, StdPocBuilder,
    StdPocRunner, VarBindings, Variable,
};
use aitm_scan_model::{CheckMeta, Confidence, Issue, PocHint, StartedBy};

use crate::reproduce::{record_finding, scrub_poc, secret_var_name};

/// Characters of the issue name kept in the PoC name. `aitm_poc` slugs the name
/// into the PoC id and rejects an id longer than 64 characters, so the name is
/// bounded here rather than letting a long (network-derived) parameter name make
/// the whole reproduction fail at `precheck`.
const MAX_POC_NAME_CHARS: usize = 64;

/// Everything the reproducer needs about one issue to rebuild its probe.
#[derive(Debug)]
pub struct ReproductionInput<'a> {
    /// The issue the reproduction would be recorded against.
    pub issue: &'a Issue,
    /// The hint the reporting check supplied with its verdict.
    pub hint: &'a PocHint,
    /// The flow whose **request** the probe was sent with.
    pub probe_flow: &'a HttpFlow,
    /// The payload that request carries, so the control can replace it.
    pub payload: &'a str,
    /// The reporting check's metadata (CWE and description for the PoC).
    pub meta: &'a CheckMeta,
    /// Who started the job: the finding's origin and client label.
    pub started_by: &'a StartedBy,
}

/// What the reproduction did, in the shape the caller links onto the issue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reproduced {
    /// The written PoC file, empty when no PoC ran.
    pub poc_ref: String,
    /// The recorded finding, when the run passed and the store accepted it.
    pub finding_id: Option<String>,
    /// Whether the PoC reproduced the issue.
    pub passed: bool,
    /// Whether the benign control behaved as the hint expected; `None` when the
    /// hint gave no control or the payload was not in the probe request.
    pub control_passed: Option<bool>,
    /// Why no finding was recorded, when none was. The crate carries no
    /// `tracing` dependency, so the reason is returned rather than logged (the
    /// caller logs it with the job's context).
    pub note: Option<String>,
}

impl Reproduced {
    /// Nothing ran: `why` says what stopped it.
    fn skipped(why: impl Into<String>) -> Self {
        Self {
            poc_ref: String::new(),
            finding_id: None,
            passed: false,
            control_passed: None,
            note: Some(why.into()),
        }
    }
}

/// Reproduce `input`'s issue through its PoC hint and, when the PoC passes,
/// record the finding (spec D6).
///
/// `out_dir` is where the PoC artifacts are written (the system temp directory
/// when `None`); the finding record itself goes to the configured
/// `findings.dir`, as `record_finding` decides.
///
/// Only an issue at `confidence >= firm` is reproduced — spec D6's floor — and
/// only a hint that actually asserts something: an empty assertion list would
/// make an `all: []` that matches vacuously, which would report a false
/// positive. Either case spends no probe and returns a `note`.
///
/// Errors only when the PoC cannot be built at all. A run that fails or errors,
/// and a findings store that refuses the record, are reported in the returned
/// value: a scan keeps its issue either way.
pub async fn reproduce_and_record(
    input: ReproductionInput<'_>,
    host: &CommandHost<'_>,
    out_dir: Option<&Path>,
) -> anyhow::Result<Reproduced> {
    if input.issue.confidence < Confidence::Firm {
        return Ok(Reproduced::skipped(format!(
            "issue {} is {:?}, below the firm floor for a PoC reproduction",
            input.issue.id, input.issue.confidence
        )));
    }
    if input.hint.assertions.is_empty() {
        return Ok(Reproduced::skipped(format!(
            "check {} supplied a PoC hint with no assertion",
            input.issue.check_id
        )));
    }

    let runner =
        StdPocRunner::with_output_dir(out_dir.map_or_else(std::env::temp_dir, |d| d.to_path_buf()));

    let poc = build(
        &input,
        input.probe_flow,
        Assertion::All(input.hint.assertions.clone()),
    )?;
    let bindings = bindings_for(&poc, &input.probe_flow.request);
    let run = match runner.run(&poc, bindings, host).await {
        Ok(run) => run,
        Err(e) => {
            return Ok(Reproduced::skipped(format!(
                "PoC {} did not run: {e}",
                poc.id
            )))
        }
    };

    // The control runs only when the reproduction itself did something worth
    // controlling for: a benign payload against a PoC that did not reproduce
    // would spend a probe to learn nothing.
    let control_passed = match input.hint.control.as_ref().filter(|_| run.passed) {
        Some(control) => run_control(&input, control, &runner, host).await,
        None => None,
    };

    let poc_ref = run.poc_path.display().to_string();
    if !run.passed {
        return Ok(Reproduced {
            poc_ref,
            finding_id: None,
            passed: false,
            control_passed,
            note: Some(format!(
                "PoC {} did not reproduce issue {}",
                poc.id, input.issue.id
            )),
        });
    }

    let record = record_for(&input, &run, &poc_ref, control_passed);
    match record_finding(host, record) {
        Ok(id) => Ok(Reproduced {
            poc_ref,
            finding_id: Some(id),
            passed: true,
            control_passed,
            note: None,
        }),
        Err(e) => Ok(Reproduced {
            poc_ref,
            finding_id: None,
            passed: true,
            control_passed,
            // Typically "no findings directory is configured": the issue stands
            // on its own and the scan goes on.
            note: Some(format!("the finding was not recorded: {e}")),
        }),
    }
}

/// Build and scrub the PoC for `flow`'s request with `success` as its verdict.
fn build(
    input: &ReproductionInput<'_>,
    flow: &HttpFlow,
    success: Assertion,
) -> anyhow::Result<Poc> {
    let spec = PocSpec {
        info: PocInfo {
            name: cap_chars(&input.issue.name, MAX_POC_NAME_CHARS),
            severity: input.issue.severity,
            references: Vec::new(),
            tags: vec![
                input.issue.class.clone(),
                "scan".to_string(),
                input.issue.job.clone(),
            ],
            cwe: input.meta.cwe.map(|c| format!("CWE-{c}")),
            description: Some(input.meta.description.clone()),
            author: None,
            metadata: None,
        },
        variables: vec![Variable {
            name: "target".to_string(),
            default: None,
            description: "Base URL of the target".to_string(),
            required: true,
        }],
        success,
    };
    let mut poc = StdPocBuilder.build(flow, spec)?;
    scrub_poc(&mut poc, &flow.request, input.payload);
    Ok(poc)
}

/// Run the benign control once: the probe request with `payload` textually
/// replaced by the control's, asserted against the control's expectations.
///
/// `None` when the control cannot be built from this request (the payload text
/// is not in the path or body), when it asserts nothing, or when the run
/// errored — a control that did not run says nothing about the issue.
async fn run_control(
    input: &ReproductionInput<'_>,
    control: &aitm_scan_model::ControlHint,
    runner: &StdPocRunner,
    host: &CommandHost<'_>,
) -> Option<bool> {
    if control.expect.is_empty() {
        return None;
    }
    let flow = control_flow(input.probe_flow, input.payload, &control.payload)?;
    let poc = build(input, &flow, Assertion::All(control.expect.clone())).ok()?;
    let bindings = bindings_for(&poc, &flow.request);
    runner
        .run(&poc, bindings, host)
        .await
        .ok()
        .map(|r| r.passed)
}

/// A copy of `flow` whose request path and body carry `control` where they
/// carried `payload`; `None` when the payload text is in neither, so no control
/// request can be derived from this probe.
fn control_flow(flow: &HttpFlow, payload: &str, control: &str) -> Option<HttpFlow> {
    if payload.is_empty() {
        return None;
    }
    let mut out = flow.clone();
    let in_path = out.request.path.contains(payload);
    if in_path {
        out.request.path = out.request.path.replace(payload, control);
    }
    let in_body = match &out.request.body {
        Body::Bytes(bytes) => {
            let text = String::from_utf8_lossy(bytes);
            match text.contains(payload) {
                true => {
                    let replaced = text.replace(payload, control).into_bytes();
                    out.request.body = Body::Bytes(replaced);
                    true
                }
                false => false,
            }
        }
        _ => false,
    };
    (in_path || in_body).then_some(out)
}

/// The run-time bindings for `poc`: the real target, and the credentials the
/// builder and the scrubber turned into required `{{var}}` placeholders.
///
/// The placeholders exist so the credential is not written to the PoC file; the
/// reproduction still has to send it or an authenticated issue could never be
/// reproduced, so each one is bound here from the live probe request and stays
/// in memory. A placeholder whose value cannot be recovered from the request is
/// bound empty rather than left unbound: an unbound `{{var}}` is a hard render
/// error, and a blank credential merely fails to reproduce.
fn bindings_for(poc: &Poc, request: &HttpRequest) -> VarBindings {
    let mut bindings = VarBindings::new();
    bindings.insert(
        "target",
        Value::Str(format!("{}://{}", request.scheme, request.authority)),
    );
    for var in &poc.variables {
        if var.name == "target" || var.default.is_some() {
            continue;
        }
        let value = request
            .headers
            .iter()
            .find(|(name, _)| secret_var_name(name) == var.name)
            .map(|(_, value)| value.to_string())
            .unwrap_or_default();
        bindings.insert(var.name.clone(), Value::Str(value));
    }
    bindings
}

/// The finding a passing reproduction records (spec D6).
fn record_for(
    input: &ReproductionInput<'_>,
    run: &PocRunResult,
    poc_ref: &str,
    control_passed: Option<bool>,
) -> FindingRecord {
    let issue = input.issue;
    let now = SystemTime::now();
    FindingRecord {
        // The store mints the id.
        id: String::new(),
        title: issue.name.clone(),
        class: issue.class.clone(),
        severity: issue.severity,
        target: format!(
            "{}://{}:{}{}",
            issue.target.scheme, issue.target.host, issue.target.port, issue.location.path
        ),
        discovered_at: now,
        origin: frontend_of(&input.started_by.frontend),
        client_label: input.started_by.client_label.clone(),
        poc_ref: poc_ref.to_string(),
        reproduction: Reproduction {
            passed: true,
            control_passed,
            run_at: now,
        },
        artifacts: FindingArtifacts {
            finding_capture: run.finding_capture,
            poc_path: poc_ref.to_string(),
            screenshot_path: run.screenshot_path.display().to_string(),
        },
        flows: issue.evidence.probe_flows.iter().map(|f| f.0).collect(),
        notes: Some(issue.description.clone()),
    }
}

/// The [`Frontend`] behind `StartedBy.frontend` (its lowercase name). An
/// unknown name reads as [`Frontend::Mcp`], the least-trusted caller class, so
/// a malformed job record can never upgrade a finding's recorded origin.
fn frontend_of(name: &str) -> Frontend {
    match name {
        "cli" => Frontend::Cli,
        "operator" => Frontend::Operator,
        _ => Frontend::Mcp,
    }
}

/// The first `max` characters of `s`.
fn cap_chars(s: &str, max: usize) -> String {
    s.chars().take(max).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::SystemTime;

    use aitm_core::{
        Body, Config, ConnInfo, FindingsConfig, FlowId, FlowMeta, HeaderMap, HttpFlow, HttpRequest,
        HttpResponse, HttpVersion, InterceptState, MemFlowStore, ProxyClient, ScopeEntry,
        ScopeRateGuard, StdGuard,
    };
    use aitm_poc::{Assertion, Severity};
    use aitm_scan_model::{
        CheckCost, CheckMeta, CheckOrigin, CheckScope, Confidence, ControlHint, Evidence,
        InsertionKind, Intensity, Issue, IssueLocation, IssueStatus, IssueTarget, LaneKind,
        PocHint, StartedBy, Technique,
    };
    use futures::future::BoxFuture;

    const TARGET_HOST: &str = "target.test";
    /// The marker the probe payload carries and the hint asserts on.
    const MARK: &str = "AITMMARK";

    /// A scratch directory, removed when dropped.
    struct ScratchDir(std::path::PathBuf);

    impl ScratchDir {
        fn new() -> Self {
            let dir =
                std::env::temp_dir().join(format!("aitm-scanner-repro-link-{}", FlowId::new()));
            std::fs::create_dir_all(&dir).expect("create scratch dir");
            Self(dir)
        }

        fn path(&self) -> &std::path::Path {
            &self.0
        }

        /// The `*.yaml` files directly under this directory (the finding records
        /// `DiskFindingStore` writes; the PoC artifacts live elsewhere).
        fn yaml_files(&self) -> Vec<std::path::PathBuf> {
            let mut out: Vec<_> = std::fs::read_dir(&self.0)
                .expect("read scratch dir")
                .filter_map(|e| e.ok().map(|e| e.path()))
                .filter(|p| p.extension().is_some_and(|e| e == "yaml"))
                .collect();
            out.sort();
            out
        }
    }

    impl Drop for ScratchDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn conn() -> ConnInfo {
        ConnInfo {
            peer: std::net::SocketAddr::from(([127, 0, 0, 1], 0)),
            sni: None,
            alpn: None,
            tls: false,
            established: SystemTime::now(),
        }
    }

    /// The probe request that produced the verdict: `payload` sits in the
    /// query parameter `param`.
    fn probe_flow(headers: &[(&str, &str)], param: &str, payload: &str) -> HttpFlow {
        let mut map = HeaderMap::new();
        for (name, value) in headers {
            map.set(name, value);
        }
        HttpFlow {
            id: FlowId::new(),
            request: HttpRequest {
                method: "GET".into(),
                scheme: "http".into(),
                authority: TARGET_HOST.into(),
                path: format!("/search?{param}={payload}"),
                version: HttpVersion::Http11,
                headers: map,
                body: Body::Empty,
                timestamp: SystemTime::now(),
            },
            response: None,
            client_conn: conn(),
            server_conn: None,
            metadata: FlowMeta::default(),
            intercept: InterceptState::Observed,
        }
    }

    /// A `ProxyClient` that answers every probe with `status` and a body built
    /// from the request, counting the sends and keeping each path.
    struct StubClient {
        status: u16,
        /// `true`: echo the request's `q` value into the body (a reflection);
        /// `false`: always answer `clean`.
        reflect: bool,
        sends: AtomicUsize,
        paths: std::sync::Mutex<Vec<String>>,
    }

    impl StubClient {
        fn new(status: u16, reflect: bool) -> Arc<Self> {
            Arc::new(Self {
                status,
                reflect,
                sends: AtomicUsize::new(0),
                paths: std::sync::Mutex::new(Vec::new()),
            })
        }

        fn sends(&self) -> usize {
            self.sends.load(Ordering::SeqCst)
        }

        fn paths(&self) -> Vec<String> {
            self.paths.lock().expect("paths lock").clone()
        }
    }

    impl ProxyClient for StubClient {
        fn send(&self, req: HttpRequest) -> BoxFuture<'_, anyhow::Result<HttpFlow>> {
            self.sends.fetch_add(1, Ordering::SeqCst);
            self.paths
                .lock()
                .expect("paths lock")
                .push(req.path.clone());
            let reflected = req
                .path
                .rsplit_once('=')
                .map(|(_, v)| v.to_string())
                .unwrap_or_default();
            let body = if self.reflect {
                format!("<html>results for {reflected}</html>")
            } else {
                "clean".to_string()
            };
            let status = self.status;
            Box::pin(async move {
                Ok(HttpFlow {
                    id: FlowId::new(),
                    request: req,
                    response: Some(HttpResponse {
                        status,
                        version: HttpVersion::Http11,
                        headers: HeaderMap::new(),
                        trailers: HeaderMap::new(),
                        body: Body::Bytes(body.into_bytes()),
                        timestamp: SystemTime::now(),
                    }),
                    client_conn: conn(),
                    server_conn: None,
                    metadata: FlowMeta::default(),
                    intercept: InterceptState::Observed,
                })
            })
        }
    }

    fn config_with_dir(dir: Option<&std::path::Path>) -> Config {
        Config {
            findings: FindingsConfig {
                dir: dir.map(|d| d.to_path_buf()),
            },
            ..Config::default()
        }
    }

    fn issue(confidence: Confidence, probe: &HttpFlow) -> Issue {
        Issue {
            id: "issue-abcd1234".to_string(),
            job: "scan-12345678".to_string(),
            check_id: "xss-reflected".to_string(),
            class: "reflected-xss".to_string(),
            name: "Reflected XSS in q".to_string(),
            severity: Severity::High,
            confidence,
            status: IssueStatus::Open,
            lane: LaneKind::Http,
            target: IssueTarget {
                scheme: "http".to_string(),
                host: TARGET_HOST.to_string(),
                port: 80,
            },
            location: IssueLocation {
                method: Some("GET".to_string()),
                path: "/search".to_string(),
                path_template: "/search".to_string(),
                kind: InsertionKind::Query,
                name: "q".to_string(),
                field_path: None,
                ws_path: None,
                l4: None,
            },
            evidence: Evidence {
                payload: Some(MARK.to_string()),
                matched: Some(MARK.to_string()),
                probe_flows: vec![probe.id.into()],
                ..Evidence::default()
            },
            first_seen: 1,
            last_seen: 1,
            occurrences: 1,
            poc_ref: None,
            finding_id: None,
            description: "A payload reflected unescaped.".to_string(),
            remediation: Some("Escape it.".to_string()),
            note: None,
        }
    }

    fn meta() -> CheckMeta {
        CheckMeta {
            id: "xss-reflected".to_string(),
            name: "Reflected XSS".to_string(),
            class: "reflected-xss".to_string(),
            lanes: vec![LaneKind::Http],
            kinds: vec![InsertionKind::Query],
            intensity: Intensity::Light,
            cost: CheckCost::Light,
            technique: Technique::Reflected,
            severity: Severity::High,
            confidence_max: Confidence::Certain,
            needs_baseline: false,
            wants_traits: None,
            targets_session: false,
            scope: CheckScope::Point,
            cwe: Some(79),
            description: "Reflects a marker into the response unescaped.".to_string(),
            remediation: Some("Escape it.".to_string()),
            origin: CheckOrigin::Native,
        }
    }

    fn started_by() -> StartedBy {
        StartedBy {
            frontend: "mcp".to_string(),
            client_label: Some("agent-1".to_string()),
        }
    }

    /// Everything a `CommandHost` borrows: the flow store, the scope guard with
    /// the target host in it, the stub client and the config.
    struct Harness {
        store: MemFlowStore,
        guard: StdGuard,
        client: Arc<StubClient>,
        config: Config,
    }

    impl Harness {
        fn new(client: Arc<StubClient>, findings_dir: Option<&std::path::Path>) -> Self {
            let guard = StdGuard::default();
            guard.add_scope(ScopeEntry {
                host: TARGET_HOST.to_string(),
            });
            Self {
                store: MemFlowStore::new(),
                guard,
                client,
                config: config_with_dir(findings_dir),
            }
        }

        fn host(&self) -> CommandHost<'_> {
            let client: &dyn ProxyClient = self.client.as_ref();
            CommandHost::new(&self.store, client, &self.guard, None)
                .with_config(Arc::new(self.config.clone()))
        }
    }

    /// Spec D6: a `vulnerable` verdict whose check supplied a hint, whose PoC
    /// reproduces, becomes a `FindingRecord` the issue links to.
    #[tokio::test]
    async fn vulnerable_with_hint_records_a_finding_when_reproduction_passes() {
        let findings = ScratchDir::new();
        let artifacts = ScratchDir::new();
        let probe = probe_flow(&[], "q", MARK);
        let issue = issue(Confidence::Firm, &probe);
        let meta = meta();
        let started = started_by();
        let hint = PocHint {
            assertions: vec![Assertion::word(MARK)],
            control: None,
        };
        let client = StubClient::new(200, true);

        let harness = Harness::new(Arc::clone(&client), Some(findings.path()));
        let out = reproduce_and_record(
            ReproductionInput {
                issue: &issue,
                hint: &hint,
                probe_flow: &probe,
                payload: MARK,
                meta: &meta,
                started_by: &started,
            },
            &harness.host(),
            Some(artifacts.path()),
        )
        .await
        .expect("reproduction runs");

        assert!(out.passed, "the reproduction passed: {out:?}");
        assert_eq!(out.control_passed, None, "no control was given");
        assert!(out.poc_ref.ends_with(".yaml"), "poc_ref: {}", out.poc_ref);
        let id = out.finding_id.expect("a finding was recorded");
        assert!(id.starts_with("reflected-xss"), "finding id: {id}");
        assert_eq!(client.sends(), 1, "the PoC runs exactly once");

        let records = findings.yaml_files();
        assert_eq!(records.len(), 1, "one finding record: {records:?}");
        let text = std::fs::read_to_string(&records[0]).expect("read the record");
        assert!(text.contains("reflected-xss"), "record: {text}");
        assert!(
            text.contains("passed: true"),
            "the record carries the reproduction: {text}"
        );
    }

    /// Spec D6: a reproduction that does not pass records nothing.
    #[tokio::test]
    async fn failed_reproduction_records_nothing() {
        let findings = ScratchDir::new();
        let artifacts = ScratchDir::new();
        let probe = probe_flow(&[], "q", MARK);
        let issue = issue(Confidence::Firm, &probe);
        let meta = meta();
        let started = started_by();
        let hint = PocHint {
            assertions: vec![Assertion::word(MARK)],
            control: None,
        };
        // Answers `clean`: the marker is not in the body.
        let client = StubClient::new(200, false);

        let harness = Harness::new(Arc::clone(&client), Some(findings.path()));
        let out = reproduce_and_record(
            ReproductionInput {
                issue: &issue,
                hint: &hint,
                probe_flow: &probe,
                payload: MARK,
                meta: &meta,
                started_by: &started,
            },
            &harness.host(),
            Some(artifacts.path()),
        )
        .await
        .expect("a failed reproduction is not an error");

        assert!(!out.passed, "the reproduction failed: {out:?}");
        assert_eq!(out.finding_id, None, "nothing was recorded");
        assert_eq!(client.sends(), 1, "the PoC still ran exactly once");
        assert!(
            findings.yaml_files().is_empty(),
            "no finding file: {:?}",
            findings.yaml_files()
        );
    }

    /// Spec D2/D6: a hint with a control runs the control exactly once, with the
    /// benign payload in place of the probe's.
    #[tokio::test]
    async fn control_runs_once_when_given() {
        let findings = ScratchDir::new();
        let artifacts = ScratchDir::new();
        let probe = probe_flow(&[], "q", MARK);
        let issue = issue(Confidence::Firm, &probe);
        let meta = meta();
        let started = started_by();
        let hint = PocHint {
            assertions: vec![Assertion::word(MARK)],
            control: Some(ControlHint {
                payload: "benign".to_string(),
                expect: vec![Assertion::Status(200)],
            }),
        };
        let client = StubClient::new(200, true);

        let harness = Harness::new(Arc::clone(&client), Some(findings.path()));
        let out = reproduce_and_record(
            ReproductionInput {
                issue: &issue,
                hint: &hint,
                probe_flow: &probe,
                payload: MARK,
                meta: &meta,
                started_by: &started,
            },
            &harness.host(),
            Some(artifacts.path()),
        )
        .await
        .expect("reproduction runs");

        assert!(out.passed, "the reproduction passed: {out:?}");
        assert_eq!(out.control_passed, Some(true), "the control ran: {out:?}");
        assert_eq!(client.sends(), 2, "one probe PoC and one control PoC");
        let paths = client.paths();
        assert_eq!(
            paths,
            vec![format!("/search?q={MARK}"), "/search?q=benign".to_string()],
            "the control sends the benign payload in place of the probe's"
        );
        assert!(out.finding_id.is_some(), "the finding was recorded");
    }

    /// Spec D6: the written PoC carries no credential from the probe request,
    /// is parameterized on `{{target}}`, and still carries the payload.
    ///
    /// The payload sits at a *secret-named* point (`?token=`), which is where
    /// `aitm_poc`'s own text scrub and the scanner's structural one differ: the
    /// builder alone redacts `token=<payload>` and leaves a PoC that cannot
    /// reproduce anything.
    #[tokio::test]
    async fn poc_text_is_scrubbed() {
        let findings = ScratchDir::new();
        let artifacts = ScratchDir::new();
        let probe = probe_flow(&[("Cookie", "sid=s3cr3t")], "token", MARK);
        let issue = issue(Confidence::Firm, &probe);
        let meta = meta();
        let started = started_by();
        let hint = PocHint {
            assertions: vec![Assertion::word(MARK)],
            control: None,
        };
        let client = StubClient::new(200, true);

        let harness = Harness::new(Arc::clone(&client), Some(findings.path()));
        let out = reproduce_and_record(
            ReproductionInput {
                issue: &issue,
                hint: &hint,
                probe_flow: &probe,
                payload: MARK,
                meta: &meta,
                started_by: &started,
            },
            &harness.host(),
            Some(artifacts.path()),
        )
        .await
        .expect("reproduction runs");

        let text = std::fs::read_to_string(&out.poc_ref).expect("read the written PoC");
        assert!(
            !text.contains("s3cr3t"),
            "the cookie survived into the PoC: {text}"
        );
        assert!(
            text.contains("{{target}}"),
            "the PoC is not parameterized: {text}"
        );
        assert!(
            text.contains(&format!("token={MARK}")),
            "the payload at a secret-named point must stay or the PoC cannot \
             reproduce: {text}"
        );
        assert!(out.passed, "the scrubbed PoC still reproduces: {out:?}");
    }

    /// With no `findings.dir` the issue stands alone: the reproduction still
    /// runs and passes, and the missing store is reported, not an error.
    #[tokio::test]
    async fn no_findings_dir_yields_an_issue_only() {
        let artifacts = ScratchDir::new();
        let probe = probe_flow(&[], "q", MARK);
        let issue = issue(Confidence::Firm, &probe);
        let meta = meta();
        let started = started_by();
        let hint = PocHint {
            assertions: vec![Assertion::word(MARK)],
            control: None,
        };
        let client = StubClient::new(200, true);

        let harness = Harness::new(Arc::clone(&client), None);
        let out = reproduce_and_record(
            ReproductionInput {
                issue: &issue,
                hint: &hint,
                probe_flow: &probe,
                payload: MARK,
                meta: &meta,
                started_by: &started,
            },
            &harness.host(),
            Some(artifacts.path()),
        )
        .await
        .expect("no findings dir is not an error");

        assert!(out.passed, "the reproduction still ran: {out:?}");
        assert_eq!(out.finding_id, None, "nothing could be recorded");
        assert!(
            out.note.is_some_and(|n| n.contains("findings")),
            "the reason is reported"
        );
    }

    /// Spec D6: only `confidence >= firm` is reproduced — a tentative issue
    /// spends no probe and records nothing.
    #[tokio::test]
    async fn tentative_issue_is_not_reproduced() {
        let findings = ScratchDir::new();
        let artifacts = ScratchDir::new();
        let probe = probe_flow(&[], "q", MARK);
        let issue = issue(Confidence::Tentative, &probe);
        let meta = meta();
        let started = started_by();
        let hint = PocHint {
            assertions: vec![Assertion::word(MARK)],
            control: None,
        };
        let client = StubClient::new(200, true);

        let harness = Harness::new(Arc::clone(&client), Some(findings.path()));
        let out = reproduce_and_record(
            ReproductionInput {
                issue: &issue,
                hint: &hint,
                probe_flow: &probe,
                payload: MARK,
                meta: &meta,
                started_by: &started,
            },
            &harness.host(),
            Some(artifacts.path()),
        )
        .await
        .expect("a tentative issue is not an error");

        assert!(!out.passed, "nothing was reproduced: {out:?}");
        assert_eq!(out.finding_id, None);
        assert_eq!(client.sends(), 0, "no probe was spent");
        assert!(findings.yaml_files().is_empty(), "no finding file");
    }

    /// A hint with no assertion asserts nothing, so it reproduces nothing: the
    /// engine spends no probe rather than running an empty `all`.
    #[tokio::test]
    async fn empty_hint_reproduces_nothing() {
        let findings = ScratchDir::new();
        let probe = probe_flow(&[], "q", MARK);
        let issue = issue(Confidence::Certain, &probe);
        let meta = meta();
        let started = started_by();
        let hint = PocHint {
            assertions: Vec::new(),
            control: None,
        };
        let client = StubClient::new(200, true);

        let harness = Harness::new(Arc::clone(&client), Some(findings.path()));
        let out = reproduce_and_record(
            ReproductionInput {
                issue: &issue,
                hint: &hint,
                probe_flow: &probe,
                payload: MARK,
                meta: &meta,
                started_by: &started,
            },
            &harness.host(),
            None,
        )
        .await
        .expect("an empty hint is not an error");

        assert!(!out.passed);
        assert_eq!(out.finding_id, None);
        assert_eq!(client.sends(), 0, "no probe was spent");
        assert!(out.poc_ref.is_empty(), "no PoC was written");
    }
}
