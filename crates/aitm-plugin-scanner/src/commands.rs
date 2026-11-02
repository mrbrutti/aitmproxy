//! The scanner's three shipped verbs, now driven by the v2 job engine:
//! `scan.discover` (deprecated), `scan.passive` and `scan.report`.
//!
//! Their **result shapes are frozen** (spec D3, "the shipped UIs keep working
//! while the UI tracks migrate"): the TUI's Scan surface, the web UI and
//! `crates/aitm/tests/frontends.rs` parse exactly these keys, so this module
//! shapes every value the three verbs return and the engine modules build no
//! [`Value`] of their own (bar the one JSON-to-[`Value`] bridge,
//! [`crate::util::json_to_value`]).
//!
//! `scan.discover` is **deprecated**: it is now [`crate::jobs::start`] with
//! `force_map`, i.e. exactly the `scan.map` job — one HTTP lane, `passive`
//! intensity, no probe — followed by a bounded wait for that job's terminal
//! state. The caller still gets one synchronous answer with the reached
//! `endpoints`, the `injection_points` behind them, the `endpoint_flows`
//! links, `pages_crawled` and `stopped_reason`; what changed underneath is
//! that the work is a job, visible to `scan.status`, `scan.list` and the
//! progress push while it runs, and cancellable. A UI should move to
//! `scan.map` + `scan.status`; `scan.discover` is removed in a later release.
//!
//! The wait is bounded by the shipped `ScannerConfig.time_budget` (call B11):
//! when it runs out the job is **cancelled** and the result says
//! `stopped_reason: "time_budget"`, so a lane that never finishes cannot pin
//! the calling connection open for ever. Only that one connection ever blocks,
//! exactly as the shipped verb did.
//!
//! Single flight is no longer a flag on the command: the job model refuses a
//! second job against an origin one is already running on (`scan: busy: ..`),
//! and that refusal is rephrased here into the sentence the shipped verb used,
//! so a frontend that matches on it is unaffected.
//!
//! Deny-by-default throughout, now in the engine: the job's origin is gated
//! through [`aitm_core::ScopeRateGuard`] before anything is spawned, the job
//! holds the proxy's browser-egress posture confined for its whole life, and
//! the agent gates of spec D3 apply. The result carries no credential: the
//! lane scrubs every example it reports and every free-text string that
//! reaches the caller is run through [`scrub_text`] again here.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use aitm_core::redact::scrub_text;
use aitm_core::{
    Command, CommandHost, ParamDef, ParamSchema, Params, Registry, Sensitivity, TypeDesc, Value,
};
use aitm_findings::{render_index, render_report, FindingRecord};
use aitm_poc::Severity;
use aitm_scan_model::{
    builtin, Discovery, InsertionKind, InsertionPoint, JobState, JobStatus, PointTrait,
    ProfileTarget, ScanErrorCode, ScanProfile, ScanRefusal, SiteNode,
};

use crate::config::ScannerConfig;
use crate::crawl::normalize_url;
use crate::inject::target_flows;
use crate::jobs::{self, Engine};
use crate::passive::{passive_checks, PassiveFinding};
use crate::report;
use crate::util::{default_port, origin_key, wire_token};

/// Upper bound on each array in the result, so a long crawl cannot return an
/// unbounded object to the caller.
const MAX_RESULT_ITEMS: usize = 1024;

/// The built-in profile a `scan.discover` runs as: crawl plus passive checks,
/// no probe (spec D3's `scan.map`).
const MAP_PROFILE: &str = "map-only";

/// How long a job cancelled by the wait is given to wind down before the
/// verb answers with the last status it saw.
const CANCEL_GRACE: Duration = Duration::from_secs(5);

/// A bound on the configured budget: a deadline further out than this would
/// overflow the clock on some platforms, and no scan waits a week.
const MAX_WAIT: Duration = Duration::from_secs(60 * 60 * 24 * 7);

/// The sentence a second concurrent discovery is refused with. Unchanged from
/// the shipped verb (the job model's `scan: busy: ..` is rephrased into it),
/// because a frontend may be showing it to an operator verbatim.
const BUSY_SENTENCE: &str = "scan.discover is already running; wait for it to finish before \
                             starting another (concurrent crawls share one browser page and \
                             would corrupt each other)";

/// Put the three legacy verbs on the registry, bound to the engine that runs
/// their jobs. Called by `ScannerPlugin::load`.
pub(crate) fn register(engine: &Arc<Engine>, reg: &mut Registry) {
    reg.add_command(Arc::new(ScanDiscover {
        engine: Arc::clone(engine),
    }));
    reg.add_command(Arc::new(ScanPassive));
    reg.add_command(Arc::new(ScanReport {
        engine: Arc::clone(engine),
    }));
}

/// `scan.discover` — the deprecated synchronous one-shot: a `scan.map` job and
/// a bounded wait for it.
pub(crate) struct ScanDiscover {
    /// The one engine every `scan.*` verb shares, so the job this verb starts
    /// is the same job `scan.status`, `scan.list` and `scan.cancel` see.
    engine: Arc<Engine>,
}

impl Command for ScanDiscover {
    fn name(&self) -> &str {
        "scan.discover"
    }

    fn sensitivity(&self) -> Sensitivity {
        // A scope/rate-bounded testing verb: it drives the browser against an
        // authorized target. Read-only in intent, but it issues navigations, so
        // it is `Write`, not `Sensitive` and not `Read` — the tier `scan.map`
        // carries, and unchanged from the shipped verb.
        Sensitivity::Write
    }

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "Discover reachable in-scope URLs under `target` (same-origin, \
                          scope-bound, budget-capped) and enumerate the injection points \
                          visible in captured requests. No injection or fuzzing is performed. \
                          `max_depth`/`max_pages` may lower the configured caps, never raise them. \
                          Runs as a `map` scan job and waits for it: the wait is bounded by the \
                          configured scan time budget, after which the job is cancelled and the \
                          result reports `stopped_reason = \"time_budget\"`. Only one scan runs \
                          against an origin at a time; a second call while one is running is \
                          refused immediately \u{2014} wait for it to finish. \
                          Deprecated: use `scan.map` and poll `scan.status`."
                .into(),
            params: vec![
                ParamDef {
                    name: "target".into(),
                    ty: TypeDesc::Str,
                    required: true,
                    description: "The in-scope seed URL, e.g. `https://app.example/`.".into(),
                },
                ParamDef {
                    name: "max_depth".into(),
                    ty: TypeDesc::Int,
                    required: false,
                    description: "Link depth to follow (clamped to the configured cap).".into(),
                },
                ParamDef {
                    name: "max_pages".into(),
                    ty: TypeDesc::Int,
                    required: false,
                    description: "Pages to visit (clamped to the configured cap).".into(),
                },
            ],
            result: TypeDesc::Object(Vec::new()),
        }
    }

    fn invoke(&self, args: Params, host: &CommandHost) -> anyhow::Result<Value> {
        let target = args.get_str("target")?;
        let cfg = &self.engine.cfg;

        // Optional budget overrides may only *lower* the configured caps, never
        // raise them — the operator's config is the ceiling.
        let mut max_depth = cfg.max_depth;
        if args.get("max_depth").is_some() {
            let requested = usize::try_from(args.get_int("max_depth")?)
                .map_err(|_| anyhow::anyhow!("`max_depth` must be non-negative"))?;
            max_depth = max_depth.min(requested);
        }
        let mut max_pages = cfg.max_pages;
        if args.get("max_pages").is_some() {
            let requested = usize::try_from(args.get_int("max_pages")?)
                .map_err(|_| anyhow::anyhow!("`max_pages` must be non-negative"))?;
            max_pages = max_pages.min(requested);
        }

        let profile = map_profile(cfg, target, max_depth, max_pages)?;
        let caller = crate::verbs::caller_of(host);
        // `force_map`: one HTTP lane, `passive` intensity, no probe. Every
        // refusal (scope, agent policy, concurrency) is the engine's, in spec
        // D3's order; only `busy` is rephrased, because the shipped verb's
        // sentence may be on an operator's screen.
        let started = jobs::start(&self.engine, profile, caller, true).map_err(rephrase_busy)?;

        let (status, timed_out) = self.await_terminal(&started.job, &started.status);
        if status.state == JobState::Failed {
            // A lane that refused the profile reports `scan: invalid_profile: ..`;
            // the synchronous verb hands that back as its own error rather than
            // returning an empty result the caller would read as "nothing here".
            let message = status
                .error
                .clone()
                .unwrap_or_else(|| format!("the scan job {} failed", status.job));
            return Err(anyhow::anyhow!(message));
        }

        let discovery = self
            .engine
            .registry
            .entry_handles(&started.job)
            .map(|handles| {
                handles
                    .discovery
                    .read()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .clone()
            })
            .unwrap_or_default();
        Ok(discover_value_from(&discovery, &status, timed_out))
    }
}

impl ScanDiscover {
    /// Wait for `job` to reach a terminal state, at most `cfg.time_budget`
    /// (call B11). Answers `(status, timed_out)`; on a timeout the job is
    /// cancelled and given [`CANCEL_GRACE`] to wind down.
    ///
    /// `start` is the snapshot [`jobs::start`] returned, so a job that is
    /// pruned from the registry mid-wait (a zero-length history) still has a
    /// status to report.
    fn await_terminal(&self, job: &str, start: &JobStatus) -> (JobStatus, bool) {
        let budget = self.engine.cfg.time_budget.min(MAX_WAIT);
        blocking(|| {
            let mut last = start.clone();
            if let Some(status) = self.wait_until(job, budget, &mut last) {
                return (status, false);
            }
            if let Some(status) = self.engine.registry.cancel(job) {
                last = status;
            }
            let status = self
                .wait_until(job, CANCEL_GRACE, &mut last)
                .unwrap_or_else(|| last.clone());
            (status, true)
        })
    }

    /// Wait until `job` is over or `within` has passed, on the registry's
    /// terminal wait ([`jobs::JobRegistry::wait_terminal`]): the wait ends
    /// when the worker's `finish` has run, not on the first read of a terminal
    /// `state`, so the job's handles (its egress hold) are released by the
    /// time the verb answers. No polling: the deadline is a `tokio::time::timeout`
    /// on the engine's runtime, bridged to this synchronous verb over a channel.
    ///
    /// `Some(status)` when the job settled or is gone from the registry (a
    /// history of zero, or pruned under load: nothing left to wait for),
    /// `None` when the deadline passed first. `last` always holds the newest
    /// status seen, whether or not the job settled in time.
    fn wait_until(&self, job: &str, within: Duration, last: &mut JobStatus) -> Option<JobStatus> {
        let settled = match self.engine.late.get() {
            Ok(services) => {
                let (tx, rx) = std::sync::mpsc::channel();
                let engine = Arc::clone(&self.engine);
                let job = job.to_string();
                services.rt.spawn(async move {
                    let settled = tokio::time::timeout(within, engine.registry.wait_terminal(&job))
                        .await
                        .is_ok();
                    // The verb may have stopped listening (its connection
                    // closed); nobody else cares about the answer.
                    let _ = tx.send(settled);
                });
                // The receive is bounded a second past the task's own
                // deadline: this thread blocks here, and if the caller's
                // runtime *is* `services.rt` on a single thread (never the
                // shipped core, which is multi-threaded; `blocking` only
                // yields the worker there), nothing could drive the task and
                // an unbounded `recv` would hang the verb for ever. Bounded,
                // a starved task degrades to "not settled": the deadline,
                // cancel and grace run as before and the last status answers.
                match rx.recv_timeout(within.saturating_add(Duration::from_secs(1))) {
                    Ok(settled) => settled,
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => false,
                    // The runtime dropped the task on shutdown; there is
                    // nothing left to wait for.
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => true,
                }
            }
            // Unreachable once `jobs::start` has succeeded: the services are
            // not bound, so nothing can be running.
            Err(_) => true,
        };
        if let Some(status) = self.engine.registry.status(job) {
            *last = status;
        }
        settled.then(|| last.clone())
    }
}

/// Run a blocking wait without starving the runtime it may be called from: a
/// bus connection handled on a multi-threaded runtime hands its worker thread
/// back for the duration, exactly as the shipped crawl did.
fn blocking<T>(f: impl FnOnce() -> T) -> T {
    use tokio::runtime::{Handle, RuntimeFlavor};
    match Handle::try_current() {
        Ok(handle) if matches!(handle.runtime_flavor(), RuntimeFlavor::MultiThread) => {
            tokio::task::block_in_place(f)
        }
        _ => f(),
    }
}

/// The `map-only` profile for one seed URL, with the shipped crawl budgets
/// applied (spec D3; the caller's `max_depth`/`max_pages` have already been
/// lowered against the configured caps).
fn map_profile(
    cfg: &ScannerConfig,
    target: &str,
    max_depth: usize,
    max_pages: usize,
) -> anyhow::Result<ScanProfile> {
    let mut profile = builtin(MAP_PROFILE).unwrap_or_default();
    profile.name = MAP_PROFILE.to_string();
    profile.target = ProfileTarget {
        origins: vec![origin_of(target)?],
        l4: Vec::new(),
    };
    profile.crawl.max_depth = u32::try_from(max_depth).unwrap_or(u32::MAX);
    profile.crawl.max_pages = u32::try_from(max_pages).unwrap_or(u32::MAX);
    // The shipped verb's wall-clock budget is the job's too, and the wait's.
    // A sub-second budget still makes a valid profile (`time_s >= 1`); it is
    // the *wait* that honours it to the millisecond.
    profile.budget.time_s = profile.budget.time_s.min(cfg.time_budget.as_secs()).max(1);
    Ok(profile)
}

/// The origin of a seed URL. `scan.discover` takes a seed with a path
/// (`https://app.example/login`); a job takes origins, so the path is dropped
/// here rather than refused — the crawl starts from the origin and the seed's
/// own page is reached through it.
fn origin_of(target: &str) -> anyhow::Result<String> {
    let raw = target.trim();
    let parsed = url::Url::parse(raw).map_err(|e| anyhow::anyhow!("`{raw}` is not a URL: {e}"))?;
    let host = parsed
        .host_str()
        .filter(|host| !host.is_empty())
        .ok_or_else(|| anyhow::anyhow!("`{raw}` is not a URL: it has no host"))?;
    let authority = match parsed.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    };
    Ok(origin_key(parsed.scheme(), &authority))
}

/// The job model's `scan: busy: ..` in the sentence the shipped verb used.
/// Every other refusal keeps the engine's typed `scan: <code>: <message>`.
fn rephrase_busy(err: anyhow::Error) -> anyhow::Error {
    match err.downcast_ref::<ScanRefusal>() {
        Some(refusal) if refusal.code == ScanErrorCode::Busy => anyhow::anyhow!(BUSY_SENTENCE),
        _ => err,
    }
}

/// The `scan.discover` result for a finished map job: the reached `endpoints`
/// (the job's site-map nodes), the `injection_points` the lane found behind
/// them, the `endpoint_flows` links, `pages_crawled` and `stopped_reason`.
///
/// The shape is the shipped one, key for key. What fills it is the job's
/// [`Discovery`] and [`JobStatus`] rather than a crawl outcome, so any lane —
/// the interim HTTP lane today, T2's lane tomorrow — feeds the same object.
/// Every free-text string is run through [`scrub_text`].
pub(crate) fn discover_value_from(
    discovery: &Discovery,
    status: &JobStatus,
    timed_out: bool,
) -> Value {
    // Endpoint URLs, in discovery order, deduplicated: two nodes (a GET and a
    // POST) on one path are one endpoint to this result's shape.
    let mut endpoints: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut node_urls: HashMap<&str, String> = HashMap::new();
    // endpoint URL (scrubbed, matching an entry in `endpoints`) -> flow id.
    // The node's newest flow, so an endpoint re-captured by a later scan links
    // to the fresh capture.
    let mut endpoint_flows: BTreeMap<String, Value> = BTreeMap::new();
    for node in &discovery.nodes {
        let url = scrub_text(&node_url(node));
        node_urls.insert(node.id.as_str(), url.clone());
        if !seen.contains(&url) {
            if endpoints.len() >= MAX_RESULT_ITEMS {
                continue;
            }
            seen.insert(url.clone());
            endpoints.push(url.clone());
        }
        if let Some(flow) = node.flows.last() {
            endpoint_flows.insert(url, Value::Str(flow.0.to_string()));
        }
    }

    // One entry per (endpoint, location, name), at the position of its first
    // appearance and carrying the newest capture's flow and example: the store
    // keeps every earlier scan's captures, so the same point turns up once per
    // capture and must be reported once.
    let mut injection_points: Vec<Value> = Vec::new();
    let mut point_index: HashMap<(String, String, String), usize> = HashMap::new();
    for point in &discovery.points {
        let endpoint = point
            .site_node
            .as_deref()
            .and_then(|id| node_urls.get(id).cloned())
            .or_else(|| {
                // A lane that reports no site node is keyed by the point's own
                // URL, in the crawl's one normal form, so two spellings of one
                // URL cannot become two endpoints.
                point
                    .url
                    .as_deref()
                    .map(|url| scrub_text(&normalize_url(url).unwrap_or_else(|| url.to_string())))
            })
            .unwrap_or_default();
        let location = location_token(point);
        let key = (endpoint, location.clone(), point.name.clone());
        // The cap bounds distinct keys; overwriting an existing one is always
        // allowed. Decide before building anything.
        let slot = point_index.get(&key).copied();
        if slot.is_none() && injection_points.len() >= MAX_RESULT_ITEMS {
            continue;
        }
        let mut obj = BTreeMap::new();
        obj.insert(
            "flow".into(),
            Value::Str(
                point
                    .flow
                    .map(|flow| flow.0.to_string())
                    .unwrap_or_default(),
            ),
        );
        obj.insert("location".into(), Value::Str(location));
        obj.insert("name".into(), Value::Str(point.name.clone()));
        // The lane has already replaced a secret-named example; this catches a
        // credential embedded inside an otherwise innocent value
        // (`next=…?access_token=…`).
        obj.insert(
            "example".into(),
            Value::Str(scrub_text(point.example.as_deref().unwrap_or_default())),
        );
        match slot {
            Some(idx) => {
                if let Some(existing) = injection_points.get_mut(idx) {
                    *existing = Value::Object(obj);
                }
            }
            None => {
                point_index.insert(key, injection_points.len());
                injection_points.push(Value::Object(obj));
            }
        }
    }

    let mut result = BTreeMap::new();
    result.insert(
        "endpoints".into(),
        Value::Array(endpoints.into_iter().map(Value::Str).collect()),
    );
    result.insert("injection_points".into(), Value::Array(injection_points));
    result.insert("endpoint_flows".into(), Value::Object(endpoint_flows));
    result.insert(
        "pages_crawled".into(),
        Value::Int(i64::try_from(status.crawl.pages).unwrap_or(i64::MAX)),
    );
    result.insert("stopped_reason".into(), stopped_reason(status, timed_out));
    Value::Object(result)
}

/// A site-map node as the URL the shipped result exposed: `scheme://host[:port]`
/// and the node's path template, the scheme's default port elided.
fn node_url(node: &SiteNode) -> String {
    let authority = match default_port(&node.scheme) {
        Some(default) if default == node.port => node.host.clone(),
        _ => format!("{}:{}", node.host, node.port),
    };
    format!("{}://{}{}", node.scheme, authority, node.path_template)
}

/// The legacy wire token for an insertion point's location. The v1 vocabulary
/// had one location the v2 `InsertionKind` folds into `query`: a query (or
/// body) parameter whose value is a URL was `redirect`, and the v2 point says
/// the same thing with the `url` trait.
fn location_token(point: &InsertionPoint) -> String {
    if point.kind == InsertionKind::Query && point.traits.contains(&PointTrait::Url) {
        return "redirect".to_string();
    }
    wire_token(&point.kind)
}

/// `stopped_reason`: absent for a job that simply finished, the job's own
/// reason when it stopped early, and `time_budget` when the verb's own wait
/// ran out and cancelled it (call B11).
fn stopped_reason(status: &JobStatus, timed_out: bool) -> Value {
    if timed_out {
        return Value::Str("time_budget".to_string());
    }
    status
        .stopped_reason
        .as_ref()
        .map_or(Value::Null, |reason| Value::Str(wire_token(reason)))
}

/// An optional `target` argument: absent or `Null` is `None`, a string is
/// `Some`, and anything else is an error rather than a silently ignored filter.
fn optional_target(args: &Params) -> anyhow::Result<Option<&str>> {
    match args.get("target") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Str(s)) => Ok(Some(s)),
        Some(other) => anyhow::bail!("param `target` must be a string, got {other:?}"),
    }
}

/// `scan.passive` — evaluate the passive checks over already-captured flows.
/// Registered by [`register`].
///
/// A unit struct: `invoke` reads no configuration and starts no job. It is
/// `Read` and issues no traffic — it reads the stored flows and nothing else,
/// with no proxy client send and no browser — so it runs under a read-only
/// agent policy. Unchanged by the v2 engine (spec D3).
pub(crate) struct ScanPassive;

impl Command for ScanPassive {
    fn name(&self) -> &str {
        "scan.passive"
    }

    fn sensitivity(&self) -> Sensitivity {
        Sensitivity::Read
    }

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "Run the passive checks (reflected request parameters, missing \
                          security headers, cookie flags) over the flows already captured \
                          for `target`, or over every captured flow when `target` is absent. \
                          Issues no traffic. Findings carry the parameter, header or cookie \
                          NAME, never its value."
                .into(),
            params: vec![ParamDef {
                name: "target".into(),
                ty: TypeDesc::Str,
                required: false,
                description: "Only flows of this origin (scheme, host and port), e.g. \
                              `https://app.example`. Absent: every captured flow."
                    .into(),
            }],
            result: TypeDesc::Object(Vec::new()),
        }
    }

    fn invoke(&self, args: Params, host: &CommandHost) -> anyhow::Result<Value> {
        let target = optional_target(&args)?;
        let findings: Vec<PassiveFinding> = target_flows(host, target)
            .iter()
            .flat_map(passive_checks)
            .collect();
        Ok(passive_value(&findings))
    }
}

/// The `scan.passive` result: `{ "findings": [ {class, flow, location, name,
/// evidence, severity} ] }`, capped at [`MAX_RESULT_ITEMS`].
///
/// Every string goes through [`scrub_text`], whatever the engine put in it: the
/// passive checks never carry a request value, and this is the second line of
/// defence if one ever did. A finding with no location or name (a missing-header
/// finding) reports them as `Null`.
pub(crate) fn passive_value(findings: &[PassiveFinding]) -> Value {
    let text = |s: &str| Value::Str(scrub_text(s));
    let items = findings
        .iter()
        .take(MAX_RESULT_ITEMS)
        .map(|f| {
            let mut obj = BTreeMap::new();
            obj.insert("class".into(), text(&f.class));
            obj.insert("flow".into(), text(&f.flow.to_string()));
            obj.insert(
                "location".into(),
                f.location
                    .as_ref()
                    .map_or(Value::Null, |l| text(l.as_str())),
            );
            obj.insert("name".into(), f.name.as_deref().map_or(Value::Null, text));
            obj.insert("evidence".into(), text(&f.evidence));
            obj.insert("severity".into(), text(severity_str(f.severity)));
            Value::Object(obj)
        })
        .collect();
    let mut result = BTreeMap::new();
    result.insert("findings".into(), Value::Array(items));
    Value::Object(result)
}

/// The lowercase nuclei-vocabulary word for a severity, as `aitm-poc` serializes
/// it. An exhaustive match: a new severity is a compile error here, not a
/// silently misreported finding.
fn severity_str(severity: Severity) -> &'static str {
    match severity {
        Severity::Info => "info",
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}

/// `scan.report` — fold the recorded findings into a markdown report and a
/// machine-readable index, plus the scan issue store's own markdown section.
/// Registered by [`register`].
///
/// It is `Read`: it lists and reads stored findings and issues and writes
/// nothing, issues no traffic and needs no browser.
pub(crate) struct ScanReport {
    /// The engine whose issue store `issues_md` is rendered from.
    engine: Arc<Engine>,
}

impl Command for ScanReport {
    fn name(&self) -> &str {
        "scan.report"
    }

    fn sensitivity(&self) -> Sensitivity {
        Sensitivity::Read
    }

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "Fold the recorded findings into `report_md` (one markdown section per \
                          finding) and `index` (one {poc_path, target_path, class, passed, \
                          control_passed, finding_capture, screenshot_path} entry per finding), \
                          and the scan jobs' issues into `issues_md` (one section per issue). \
                          `target` selects the findings recorded against that origin, or against \
                          a path under it, and the issues of that origin. Empty when no findings \
                          directory is configured and no scan has run. Credentials are masked."
                .into(),
            params: vec![ParamDef {
                name: "target".into(),
                ty: TypeDesc::Str,
                required: false,
                description: "Only findings whose recorded target has this scheme, host and \
                              port and a path equal to or under this URL's, e.g. \
                              `https://app.example`. Absent: every recorded finding."
                    .into(),
            }],
            result: TypeDesc::Object(Vec::new()),
        }
    }

    fn invoke(&self, args: Params, host: &CommandHost) -> anyhow::Result<Value> {
        let target = optional_target(&args)?;
        Ok(report_value(
            &report::load_records(host, target),
            &self.engine.issues.render_issues_md(target),
        ))
    }
}

/// The `scan.report` result: `{ "report_md": Str, "index": Array, "issues_md":
/// Str }`, where `report_md` is [`render_report`] and `index` is
/// [`render_index`] converted to the transport-neutral [`Value`], both over the
/// same leading [`MAX_RESULT_ITEMS`] records, so the two halves describe the
/// same findings, and `issues_md` is the issue store's own rendering.
///
/// A shareable report carries no credential (AC11/AC24): the markdown and every
/// string of the index are run through [`scrub_text`]. The store masks a
/// finding's `title`, `notes` and `target` when it writes them, but not
/// `poc_ref` or the artifact paths, and a record may predate the masking or be
/// edited by hand, so the output is scrubbed here whatever the record holds.
pub(crate) fn report_value(recs: &[FindingRecord], issues_md: &str) -> Value {
    let capped = &recs[..recs.len().min(MAX_RESULT_ITEMS)];
    let mut result = BTreeMap::new();
    result.insert(
        "report_md".into(),
        Value::Str(scrub_text(&render_report(capped))),
    );
    result.insert(
        "index".into(),
        scrub_value(report::index_to_value(render_index(capped))),
    );
    // The issue store scrubs with the scanner's own helper on the way in; this
    // is the same second line of defence the other two halves get.
    result.insert("issues_md".into(), Value::Str(scrub_text(issues_md)));
    Value::Object(result)
}

/// `value` with every string, at any depth, run through [`scrub_text`]. Object
/// keys are the renderer's fixed field names and are left alone.
fn scrub_value(value: Value) -> Value {
    match value {
        Value::Str(s) => Value::Str(scrub_text(&s)),
        Value::Array(items) => Value::Array(items.into_iter().map(scrub_value).collect()),
        Value::Object(map) => {
            Value::Object(map.into_iter().map(|(k, v)| (k, scrub_value(v))).collect())
        }
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aitm_core::{
        Body, BrowserDriver, ClickTarget, Config, ConnInfo, EgressConfinement, FindingsConfig,
        Flow, FlowId, FlowMeta, FlowStore, Frontend, HeaderMap, HttpFlow, HttpRequest,
        HttpResponse, HttpVersion, InterceptState, MemFlowStore, NavOutcome, ProxyClient,
        ScopeEntry, ScopeRateGuard, StdGuard,
    };
    use aitm_findings::{DiskFindingStore, FindingArtifacts, FindingStore, Reproduction};
    use futures::future::BoxFuture;
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{mpsc, Arc, Mutex};
    use std::time::{Duration, SystemTime};

    use crate::discover::Location;

    /// A browser that serves one fixed page and, at every `navigate()`, records
    /// whether the shared egress posture was confined at that instant — the
    /// moment the real browser would be issuing the request.
    struct PostureProbeBrowser {
        store: Arc<MemFlowStore>,
        posture: Arc<EgressConfinement>,
        observed: Mutex<Vec<bool>>,
    }

    impl PostureProbeBrowser {
        fn new(store: Arc<MemFlowStore>, posture: Arc<EgressConfinement>) -> Self {
            Self {
                store,
                posture,
                observed: Mutex::new(Vec::new()),
            }
        }

        /// `confined()` as seen at each navigation, in order.
        fn observed(&self) -> Vec<bool> {
            self.observed.lock().expect("observed lock").clone()
        }
    }

    impl BrowserDriver for PostureProbeBrowser {
        fn navigate(&self, url: &str) -> BoxFuture<'_, anyhow::Result<NavOutcome>> {
            let url = url.to_string();
            Box::pin(async move {
                self.observed
                    .lock()
                    .expect("observed lock")
                    .push(self.posture.confined());
                // A browser behind the proxy leaves a capture behind; the
                // engine builds its site map from those captures.
                self.store.insert(captured(path_of(&url), HeaderMap::new()));
                Ok(NavOutcome {
                    final_url: url,
                    status: Some(200),
                })
            })
        }

        fn click(&self, _target: ClickTarget) -> BoxFuture<'_, anyhow::Result<()>> {
            Box::pin(async { unimplemented!("the crawler never clicks") })
        }

        fn type_text(&self, _selector: &str, _text: &str) -> BoxFuture<'_, anyhow::Result<()>> {
            Box::pin(async { unimplemented!("the crawler never types") })
        }

        fn screenshot(&self) -> BoxFuture<'_, anyhow::Result<Vec<u8>>> {
            Box::pin(async { unimplemented!("the crawler never screenshots") })
        }

        fn eval(&self, _expr: &str) -> BoxFuture<'_, anyhow::Result<Value>> {
            Box::pin(async { unimplemented!("the crawler never evals") })
        }

        fn get_dom(&self) -> BoxFuture<'_, anyhow::Result<String>> {
            Box::pin(async { Ok(r#"<a href="/one">one</a>"#.to_string()) })
        }
    }

    /// The test's end of a gated [`GatedBrowser`].
    struct Gate {
        /// Receives one message every time the browser is navigated, so the test
        /// can wait until a crawl is genuinely parked inside the browser.
        entered: mpsc::Receiver<()>,
        /// Dropping this releases every held navigation, and every later one.
        release: mpsc::Sender<()>,
    }

    /// The browser's end of a [`Gate`]: it announces each navigation on `entered`,
    /// then parks on `release`. Only the `Receiver` needs a `Mutex` to be `Sync`.
    struct BrowserGate {
        entered: mpsc::Sender<()>,
        release: Mutex<mpsc::Receiver<()>>,
    }

    /// What a [`GatedBrowser`] does when it is navigated.
    enum Behaviour {
        /// Every navigation succeeds at once.
        Open,
        /// Every navigation announces itself, then parks until the test releases it.
        Gated(BrowserGate),
    }

    /// A browser for the single-flight tests: it serves one fixed page
    /// (`<a href="/one">`, so a crawl of the seed reaches the seed and `/one`),
    /// counts the navigations it is asked for, and behaves as its [`Behaviour`]
    /// says. Unrelated to `crawl.rs`'s `StubBrowser`, which serves crafted pages
    /// per URL.
    struct GatedBrowser {
        store: Arc<MemFlowStore>,
        navigations: AtomicUsize,
        behaviour: Behaviour,
    }

    impl GatedBrowser {
        fn new(store: Arc<MemFlowStore>, behaviour: Behaviour) -> Self {
            Self {
                store,
                navigations: AtomicUsize::new(0),
                behaviour,
            }
        }

        fn open(store: Arc<MemFlowStore>) -> Self {
            Self::new(store, Behaviour::Open)
        }

        fn gated(store: Arc<MemFlowStore>) -> (Self, Gate) {
            let (entered_tx, entered_rx) = mpsc::channel();
            let (release_tx, release_rx) = mpsc::channel();
            let browser = Self::new(
                store,
                Behaviour::Gated(BrowserGate {
                    entered: entered_tx,
                    release: Mutex::new(release_rx),
                }),
            );
            let gate = Gate {
                entered: entered_rx,
                release: release_tx,
            };
            (browser, gate)
        }

        fn navigations(&self) -> usize {
            self.navigations.load(Ordering::SeqCst)
        }
    }

    impl BrowserDriver for GatedBrowser {
        fn navigate(&self, url: &str) -> BoxFuture<'_, anyhow::Result<NavOutcome>> {
            let url = url.to_string();
            Box::pin(async move {
                self.navigations.fetch_add(1, Ordering::SeqCst);
                match &self.behaviour {
                    Behaviour::Open => {}
                    Behaviour::Gated(gate) => {
                        let _ = gate.entered.send(());
                        // Parks this thread, deliberately: the crawl is "in flight"
                        // until the test drops `Gate::release` (recv then errors).
                        let _ = gate.release.lock().expect("release lock").recv();
                    }
                }
                self.store.insert(captured(path_of(&url), HeaderMap::new()));
                Ok(NavOutcome {
                    final_url: url,
                    status: Some(200),
                })
            })
        }

        fn click(&self, _target: ClickTarget) -> BoxFuture<'_, anyhow::Result<()>> {
            Box::pin(async { unimplemented!("the crawler never clicks") })
        }

        fn type_text(&self, _selector: &str, _text: &str) -> BoxFuture<'_, anyhow::Result<()>> {
            Box::pin(async { unimplemented!("the crawler never types") })
        }

        fn screenshot(&self) -> BoxFuture<'_, anyhow::Result<Vec<u8>>> {
            Box::pin(async { unimplemented!("the crawler never screenshots") })
        }

        fn eval(&self, _expr: &str) -> BoxFuture<'_, anyhow::Result<Value>> {
            Box::pin(async { unimplemented!("the crawler never evals") })
        }

        fn get_dom(&self) -> BoxFuture<'_, anyhow::Result<String>> {
            Box::pin(async { Ok(r#"<a href="/one">one</a>"#.to_string()) })
        }
    }

    /// A browser that behaves like the real one sitting behind the proxy: every
    /// `navigate()` leaves a freshly captured flow for the navigated URL in the
    /// store shared with the host (as the proxy would), and `get_dom()` serves
    /// that URL's page. Each captured flow carries one header, so every
    /// endpoint yields a header injection point as well.
    struct CapturingBrowser {
        store: Arc<MemFlowStore>,
        /// path+query -> HTML served for it; unknown pages serve an empty body.
        pages: HashMap<String, String>,
        current: Mutex<Option<String>>,
        navigations: AtomicUsize,
    }

    impl CapturingBrowser {
        fn new(store: Arc<MemFlowStore>, pages: &[(&str, &str)]) -> Self {
            Self {
                store,
                pages: pages
                    .iter()
                    .map(|(path, html)| (path.to_string(), html.to_string()))
                    .collect(),
                current: Mutex::new(None),
                navigations: AtomicUsize::new(0),
            }
        }

        /// How many pages the crawl fetched, so a budget test can prove the cap
        /// bounded the crawl itself and not just the result.
        fn navigations(&self) -> usize {
            self.navigations.load(Ordering::SeqCst)
        }
    }

    impl BrowserDriver for CapturingBrowser {
        fn navigate(&self, url: &str) -> BoxFuture<'_, anyhow::Result<NavOutcome>> {
            let url = url.to_string();
            Box::pin(async move {
                let path = url
                    .strip_prefix("http://target.test")
                    .unwrap_or_else(|| panic!("the crawl stays on the target origin: {url}"))
                    .to_string();
                let mut headers = HeaderMap::new();
                headers.set("X-Trace", "trace-1");
                self.navigations.fetch_add(1, Ordering::SeqCst);
                self.store.insert(captured(&path, headers));
                *self.current.lock().expect("current lock") = Some(path);
                Ok(NavOutcome {
                    final_url: url,
                    status: Some(200),
                })
            })
        }

        fn click(&self, _target: ClickTarget) -> BoxFuture<'_, anyhow::Result<()>> {
            Box::pin(async { unimplemented!("the crawler never clicks") })
        }

        fn type_text(&self, _selector: &str, _text: &str) -> BoxFuture<'_, anyhow::Result<()>> {
            Box::pin(async { unimplemented!("the crawler never types") })
        }

        fn screenshot(&self) -> BoxFuture<'_, anyhow::Result<Vec<u8>>> {
            Box::pin(async { unimplemented!("the crawler never screenshots") })
        }

        fn eval(&self, _expr: &str) -> BoxFuture<'_, anyhow::Result<Value>> {
            Box::pin(async { unimplemented!("the crawler never evals") })
        }

        fn get_dom(&self) -> BoxFuture<'_, anyhow::Result<String>> {
            Box::pin(async {
                let current = self.current.lock().expect("current lock").clone();
                Ok(current
                    .and_then(|path| self.pages.get(&path).cloned())
                    .unwrap_or_default())
            })
        }
    }

    /// A `ProxyClient` the command must never reach: `scan.passive` reads what
    /// the proxy already captured and sends nothing at all.
    struct NoSendClient;

    impl ProxyClient for NoSendClient {
        fn send(&self, req: HttpRequest) -> BoxFuture<'_, anyhow::Result<HttpFlow>> {
            panic!("scan.passive must not send through the proxy client: {req:?}");
        }
    }

    /// The client a `scan.discover` harness sends through, holding the one
    /// invariant that verb has left: a `map` job is "crawl + passive +
    /// insertion points, **no probes**" (spec D3), and since the interim lane
    /// crawls through the proxy client when no browser is bound (spec D5,
    /// "client-crawler GETs go through `send_opts` like probes, recorded under
    /// the same policy with the crawl mark"), every send it sees must be a
    /// crawl capture of the target's own origin — recorded, `crawl`-marked,
    /// and a `GET` or a form `POST`. A probe, or a request off the origin,
    /// panics the job instead of being answered.
    ///
    /// It answers a plain `text/plain` 200 (a page with no links, so the crawl
    /// ends on the seed) and does **not** insert into the store: the harness
    /// seeds the store by hand with the captures a test wants mapped, the way
    /// the proxy would have.
    #[derive(Default)]
    struct CrawlOnlyClient {
        seen: Mutex<Vec<HttpRequest>>,
    }

    impl CrawlOnlyClient {
        fn new() -> Arc<Self> {
            Arc::new(Self::default())
        }

        fn requests(&self) -> Vec<HttpRequest> {
            self.seen.lock().unwrap_or_else(|e| e.into_inner()).clone()
        }
    }

    impl ProxyClient for CrawlOnlyClient {
        fn send(&self, req: HttpRequest) -> BoxFuture<'_, anyhow::Result<HttpFlow>> {
            self.send_opts(req, aitm_core::SendOptions::default())
        }

        fn send_opts(
            &self,
            req: HttpRequest,
            opts: aitm_core::SendOptions,
        ) -> BoxFuture<'_, anyhow::Result<HttpFlow>> {
            assert_eq!(
                opts.record,
                aitm_core::RecordPolicy::Always,
                "a map job sends nothing but crawl captures, and a crawl capture is recorded: \
                 {req:?}"
            );
            assert!(
                opts.marks.iter().any(|mark| mark == "crawl"),
                "a map job's only sends are its crawl, which carries the crawl mark: {:?}",
                opts.marks
            );
            assert_eq!(
                req.authority, "target.test",
                "the crawl never leaves the origin: {req:?}"
            );
            assert!(
                matches!(req.method.as_str(), "GET" | "POST"),
                "the crawl navigates and submits forms, nothing else: {req:?}"
            );
            self.seen
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(req.clone());
            Box::pin(async move {
                Ok(HttpFlow {
                    id: FlowId::new(),
                    request: req,
                    response: Some(HttpResponse {
                        status: 200,
                        version: HttpVersion::Http11,
                        headers: {
                            let mut headers = HeaderMap::new();
                            headers.set("content-type", "text/plain");
                            headers
                        },
                        trailers: HeaderMap::new(),
                        body: Body::Bytes(b"ok".to_vec()),
                        timestamp: SystemTime::now(),
                        peer: None,
                    }),
                    client_conn: conn(),
                    server_conn: None,
                    metadata: FlowMeta {
                        is_replay: true,
                        marks: opts.marks,
                        ..FlowMeta::default()
                    },
                    intercept: InterceptState::Observed,
                })
            })
        }
    }

    fn params(pairs: &[(&str, Value)]) -> Params {
        Params::new(
            pairs
                .iter()
                .map(|(k, v)| (k.to_string(), v.clone()))
                .collect(),
        )
    }

    fn conn() -> ConnInfo {
        ConnInfo {
            peer: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
            sni: None,
            alpn: None,
            tls: false,
            established: SystemTime::now(),
        }
    }

    /// The request path (and query) of a navigated target URL.
    fn path_of(url: &str) -> &str {
        let rest = url
            .strip_prefix("http://target.test")
            .unwrap_or_else(|| panic!("the crawl stays on the target origin: {url}"));
        if rest.is_empty() {
            "/"
        } else {
            rest
        }
    }

    fn captured(path: &str, headers: HeaderMap) -> Flow {
        Flow::Http(HttpFlow {
            id: FlowId::new(),
            request: HttpRequest {
                method: "GET".into(),
                scheme: "http".into(),
                authority: "target.test".into(),
                path: path.into(),
                version: HttpVersion::Http11,
                headers,
                body: Body::Empty,
                timestamp: SystemTime::now(),
            },
            response: None,
            client_conn: conn(),
            server_conn: None,
            metadata: FlowMeta::default(),
            intercept: InterceptState::Observed,
        })
    }

    fn scoped_guard() -> StdGuard {
        let guard = StdGuard::default();
        guard.add_scope(ScopeEntry {
            host: "target.test".into(),
        });
        guard
    }

    /// Every string anywhere in a result value.
    fn strings(value: &Value, out: &mut Vec<String>) {
        match value {
            Value::Str(s) => out.push(s.clone()),
            Value::Array(items) => items.iter().for_each(|v| strings(v, out)),
            Value::Object(map) => map.iter().for_each(|(k, v)| {
                out.push(k.clone());
                strings(v, out);
            }),
            _ => {}
        }
    }

    fn endpoints_of(result: &Value) -> Vec<String> {
        let Value::Object(map) = result else {
            panic!("the result is an object: {result:?}");
        };
        let Some(Value::Array(items)) = map.get("endpoints") else {
            panic!("the result carries an endpoints array: {result:?}");
        };
        items
            .iter()
            .filter_map(|v| match v {
                Value::Str(s) => Some(s.clone()),
                _ => None,
            })
            .collect()
    }

    /// One `injection_points` entry, as the caller sees it.
    #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
    struct Point {
        flow: String,
        location: String,
        name: String,
        example: String,
    }

    fn points_of(result: &Value) -> Vec<Point> {
        let Value::Object(map) = result else {
            panic!("the result is an object: {result:?}");
        };
        let Some(Value::Array(items)) = map.get("injection_points") else {
            panic!("the result carries an injection_points array: {result:?}");
        };
        items
            .iter()
            .map(|item| {
                let Value::Object(o) = item else {
                    panic!("each injection point is an object: {item:?}");
                };
                let field = |key: &str| match o.get(key) {
                    Some(Value::Str(s)) => s.clone(),
                    other => panic!("injection point `{key}` is a string: {other:?}"),
                };
                Point {
                    flow: field("flow"),
                    location: field("location"),
                    name: field("name"),
                    example: field("example"),
                }
            })
            .collect()
    }

    /// `endpoint_flows` as endpoint URL -> flow id.
    fn endpoint_flows_of(result: &Value) -> BTreeMap<String, String> {
        let Value::Object(map) = result else {
            panic!("the result is an object: {result:?}");
        };
        let Some(Value::Object(ef)) = map.get("endpoint_flows") else {
            panic!("the result carries an endpoint_flows map: {result:?}");
        };
        ef.iter()
            .map(|(endpoint, id)| match id {
                Value::Str(s) => (endpoint.clone(), s.clone()),
                other => panic!("endpoint_flows values are flow ids: {other:?}"),
            })
            .collect()
    }

    /// Every stored flow's id -> the request URL it captured.
    fn flow_urls(store: &MemFlowStore) -> BTreeMap<String, String> {
        store
            .list()
            .into_iter()
            .filter_map(|id| match store.get(id) {
                Some(Flow::Http(flow)) => {
                    let req = &flow.request;
                    Some((
                        id.to_string(),
                        format!("{}://{}{}", req.scheme, req.authority, req.path),
                    ))
                }
                _ => None,
            })
            .collect()
    }

    /// `(location, name, example)` of each point, sorted: the shape of a scan's
    /// output independent of which capture each point was read from.
    fn shape(points: &[Point]) -> Vec<(String, String, String)> {
        let mut shape: Vec<_> = points
            .iter()
            .map(|p| (p.location.clone(), p.name.clone(), p.example.clone()))
            .collect();
        shape.sort();
        shape
    }

    const SITE_ROOT: &str =
        r#"<a href="/search?q=hello">search</a> <a href="/account/1">account</a>"#;

    /// The seed every discover test scans.
    fn seed() -> Params {
        params(&[("target", Value::Str("http://target.test/".into()))])
    }

    /// A site served by a [`CapturingBrowser`] over one shared store, scanned
    /// as many times as a test likes: every `scan()` is a full `scan.discover`
    /// of `http://target.test/` — a `map` job, crawled and waited for — and the
    /// store keeps each earlier scan's captures, exactly as the proxy's would.
    struct Site {
        store: Arc<MemFlowStore>,
        browser: Arc<CapturingBrowser>,
        harness: Harness,
    }

    impl Site {
        fn new(pages: &[(&str, &str)]) -> Self {
            Self::with_cfg(pages, ScannerConfig::default())
        }

        fn with_cfg(pages: &[(&str, &str)], cfg: ScannerConfig) -> Self {
            let store = Arc::new(MemFlowStore::new());
            let browser = Arc::new(CapturingBrowser::new(Arc::clone(&store), pages));
            let harness = Harness::builder()
                .cfg(cfg)
                .store(Arc::clone(&store))
                .browser(Arc::clone(&browser) as Arc<dyn BrowserDriver>)
                .build();
            Self {
                store,
                browser,
                harness,
            }
        }

        fn scan(&self) -> Value {
            self.scan_with(seed())
        }

        fn scan_with(&self, args: Params) -> Value {
            self.harness
                .discover(args)
                .expect("an in-scope seed crawls")
        }
    }

    /// A node URL as the result reports it: the shipped `endpoints` were the
    /// reached URLs, the job model's are its site-map nodes, so a captured
    /// `/account/1` is the `/account/{id}` endpoint and a query string is a
    /// property of the flow, not of the endpoint.
    fn endpoint(path: &str) -> String {
        format!("http://target.test{path}")
    }

    #[test]
    fn scan_discover_is_write() {
        let h = Harness::builder().build();
        let cmd = h
            .reg
            .command("scan.discover")
            .expect("scan.discover is registered");
        assert_eq!(cmd.name(), "scan.discover");
        assert_eq!(cmd.sensitivity(), Sensitivity::Write);
    }

    /// The description MCP clients read says a second concurrent scan is
    /// refused, so an agent knows to wait rather than retry. Single flight is
    /// the job model's now, so the sentence is per origin rather than per
    /// command, and the refusal is unchanged.
    #[test]
    fn schema_description_says_only_one_discovery_runs_at_a_time() {
        let h = Harness::builder().build();
        let description = h
            .reg
            .command("scan.discover")
            .expect("scan.discover is registered")
            .schema()
            .description;
        assert!(
            description.contains("Only one scan runs against an origin at a time"),
            "the single-flight rule is in the description: {description}"
        );
        assert!(
            description.contains("refused immediately"),
            "the description says a second call is refused: {description}"
        );
    }

    /// Deny-by-default: an out-of-scope seed is refused before the job is
    /// admitted. The refusal is now the engine's typed `scan: out_of_scope: ..`
    /// (spec D3's error vocabulary) rather than the crawler's `GuardError`, and
    /// it still names the host that was refused.
    #[test]
    fn scan_discover_out_of_scope_refused() {
        // Empty scope: deny-by-default.
        let h = Harness::builder().scope(&[]).build();

        let err = h
            .discover(params(&[(
                "target",
                Value::Str("http://unscoped.example/".into()),
            )]))
            .expect_err("an out-of-scope target is refused before any crawl");

        let refusal = err
            .downcast_ref::<ScanRefusal>()
            .unwrap_or_else(|| panic!("a typed scan refusal: {err}"));
        assert_eq!(refusal.code, ScanErrorCode::OutOfScope);
        assert!(
            refusal.message.contains("unscoped.example"),
            "the refusal names the host: {refusal}"
        );
        assert_eq!(
            h.engine.registry.list(false, 16).len(),
            0,
            "a refused seed starts no job"
        );
    }

    /// The anti-goal, at the command boundary: no secret the operator's captured
    /// traffic carried may appear anywhere in the structured result.
    #[test]
    fn discover_result_has_no_secret() {
        let mut headers = HeaderMap::new();
        headers.set("Authorization", "Bearer s3cr3t-value");
        // `PHPSESSID` carries no secret keyword in its name: it is caught only
        // because every cookie value is redacted.
        headers.set(
            "Cookie",
            "session_token=s3cr3t-value; PHPSESSID=s3cr3t-value; theme=dark",
        );
        let store = Arc::new(MemFlowStore::new());
        store.insert(captured("/x?access_token=s3cr3t-value&q=1", headers));
        let h = Harness::builder().store(Arc::clone(&store)).build();

        let result = h
            .discover(seed())
            .expect("an in-scope target with no browser maps the captured flows");

        let mut found = Vec::new();
        strings(&result, &mut found);
        assert!(
            !found.iter().any(|s| s.contains("s3cr3t-value")),
            "a captured secret reached the result: {found:?}"
        );
        // The shape is still useful: the names survive, only the values go.
        assert!(
            found.iter().any(|s| s == "access_token"),
            "the injection point name must survive redaction: {found:?}"
        );
        assert!(
            found.iter().any(|s| s == "Authorization"),
            "the header point name must survive redaction: {found:?}"
        );
    }

    /// AC3: every reached endpoint is mapped to the flow that served it, so a UI
    /// can link an endpoint row to its capture. The mapping points at the same flow
    /// the endpoint's injection points were enumerated from.
    #[test]
    fn discover_links_each_endpoint_to_its_flow() {
        let store = Arc::new(MemFlowStore::new());
        store.insert(captured("/one?q=1", HeaderMap::new()));
        let h = Harness::builder().store(Arc::clone(&store)).build();

        let result = h
            .discover(seed())
            .expect("an in-scope target with no browser maps the captured flows");

        let Value::Object(map) = &result else {
            panic!("object result: {result:?}");
        };
        let reached = endpoints_of(&result)
            .into_iter()
            .next()
            .expect("one reached endpoint");
        assert_eq!(reached, endpoint("/one"));

        // endpoint_flows links that endpoint to a flow id...
        let Some(Value::Object(ef)) = map.get("endpoint_flows") else {
            panic!("the result carries an endpoint_flows map: {result:?}");
        };
        let Some(Value::Str(flow_id)) = ef.get(&reached) else {
            panic!("the endpoint links to its flow: {result:?}");
        };

        // ...and it is the same flow the `q` injection point was found in.
        let Some(Value::Array(points)) = map.get("injection_points") else {
            panic!("injection_points array: {result:?}");
        };
        let q_point = points
            .iter()
            .find(
                |p| matches!(p, Value::Object(o) if o.get("name") == Some(&Value::Str("q".into()))),
            )
            .expect("a q injection point");
        let Value::Object(o) = q_point else {
            unreachable!()
        };
        assert_eq!(
            o.get("flow"),
            Some(&Value::Str(flow_id.clone())),
            "endpoint_flows points at the same flow as its injection point",
        );
    }

    /// The crawl takes one permit per page, and the job itself takes none: a
    /// guard that allows a single concurrent request still crawls the whole
    /// target, rather than refusing the crawl's own first navigation.
    #[test]
    fn scan_discover_runs_under_max_concurrency_one() {
        let guard = Arc::new(StdGuard::new(aitm_core::LimitConfig {
            max_concurrency: 1,
            ..aitm_core::LimitConfig::default()
        }));
        guard.add_scope(ScopeEntry {
            host: "target.test".into(),
        });
        let store = Arc::new(MemFlowStore::new());
        let browser = Arc::new(CapturingBrowser::new(
            Arc::clone(&store),
            &[("/", r#"<a href="/one">one</a>"#)],
        ));
        let h = Harness::builder()
            .store(Arc::clone(&store))
            .guard(guard)
            .browser(browser as Arc<dyn BrowserDriver>)
            .build();

        let result = h
            .discover(seed())
            .expect("one permit at a time still crawls");

        assert_eq!(endpoints_of(&result), vec![endpoint("/"), endpoint("/one")]);
    }

    /// `max_pages` may lower the configured cap: the crawl stops at the seed.
    #[test]
    fn scan_discover_max_pages_lowers_the_cap() {
        let site = Site::new(&[("/", SITE_ROOT)]);

        let result = site.scan_with(params(&[
            ("target", Value::Str("http://target.test/".into())),
            ("max_pages", Value::Int(1)),
        ]));

        assert_eq!(endpoints_of(&result), vec![endpoint("/")]);
        assert_eq!(site.browser.navigations(), 1, "one page was fetched");
    }

    /// `max_pages` may never raise it.
    #[test]
    fn scan_discover_max_pages_cannot_raise_the_cap() {
        let site = Site::with_cfg(
            &[("/", SITE_ROOT)],
            ScannerConfig {
                max_pages: 2,
                ..ScannerConfig::default()
            },
        );

        let result = site.scan_with(params(&[
            ("target", Value::Str("http://target.test/".into())),
            ("max_pages", Value::Int(500)),
        ]));

        assert_eq!(
            endpoints_of(&result),
            vec![endpoint("/"), endpoint("/search")],
            "the configured cap of 2 holds against a request for 500"
        );
        assert_eq!(site.browser.navigations(), 2);
    }

    #[test]
    fn scan_discover_rejects_a_negative_budget() {
        let h = Harness::builder().build();

        let err = h
            .discover(params(&[
                ("target", Value::Str("http://target.test/".into())),
                ("max_depth", Value::Int(-1)),
            ]))
            .expect_err("a negative budget is an error, not a wrap-around");

        assert!(
            err.to_string().contains("non-negative"),
            "explains the refusal: {err}"
        );
        assert_eq!(
            h.engine.registry.list(false, 16).len(),
            0,
            "a malformed argument starts no job"
        );
    }

    /// S2, the real fix: the crawl runs under a campaign hold on the proxy's
    /// browser-egress posture, so every navigation the browser issues happens
    /// while the `SsrfConnector` refuses out-of-scope public hosts — and the
    /// hold is released when the job ends, leaving the standing (off) base
    /// untouched. The hold is the job's now (the engine takes it in
    /// `jobs::start` and drops it in `JobRegistry::finish`), and the verb's
    /// wait answers on the terminal signal `finish` flips last, so the hold is
    /// gone by the time `invoke` returns: no wait, no clock.
    #[test]
    fn scan_discover_crawls_under_egress_confinement() {
        let posture = Arc::new(EgressConfinement::new(false));
        let store = Arc::new(MemFlowStore::new());
        let browser = Arc::new(PostureProbeBrowser::new(
            Arc::clone(&store),
            Arc::clone(&posture),
        ));
        let h = Harness::builder()
            .store(Arc::clone(&store))
            .browser(Arc::clone(&browser) as Arc<dyn BrowserDriver>)
            .egress(Arc::clone(&posture))
            .build();
        assert!(!posture.confined(), "fixture starts with the free posture");

        let result = h.discover(seed()).expect("an in-scope seed crawls");

        // The crawl really navigated (seed + the one harvested link).
        assert_eq!(endpoints_of(&result), vec![endpoint("/"), endpoint("/one")]);
        // (a) every navigation saw the posture confined.
        assert_eq!(
            browser.observed(),
            vec![true, true],
            "each navigation must run while egress is confined"
        );
        // (b) the hold is released with the finished job: the base was off and
        // stays off, so a finished scan never leaves the browser confined.
        assert!(
            !posture.confined(),
            "the campaign hold must be released when the job ends"
        );
    }

    /// Without a wired posture (a frontend that never attached one) the crawl
    /// runs exactly as before: there is nothing to hold, and nothing errors.
    #[test]
    fn scan_discover_without_egress_handle_still_crawls() {
        let store = Arc::new(MemFlowStore::new());
        store.insert(captured("/one", HeaderMap::new()));
        let client = CrawlOnlyClient::new();
        let h = Harness::builder()
            .store(Arc::clone(&store))
            .client(Arc::clone(&client) as Arc<dyn ProxyClient>)
            .build();
        assert!(
            h.engine
                .late
                .get()
                .expect("the services are bound")
                .egress
                .is_none(),
            "no posture is wired"
        );

        let result = h
            .discover(seed())
            .expect("no posture wired is not an error");

        assert_eq!(endpoints_of(&result), vec![endpoint("/one")]);
        // Spec D3/D5: with no browser the crawl is the client's, and a map job
        // makes no other request — the seed, and nothing else.
        let trail: Vec<String> = client
            .requests()
            .iter()
            .map(|req| format!("{} {}", req.method, req.path))
            .collect();
        assert_eq!(
            trail,
            vec!["GET /".to_string()],
            "the seed was crawled once"
        );
    }

    /// The target gate and the crawl use one parser, so a URL whose real host is
    /// `evil.com` is refused even under a `*.target.test` scope entry.
    #[test]
    fn scan_discover_refuses_a_backslash_host_bypass() {
        let guard = Arc::new(StdGuard::default());
        guard.add_scope(ScopeEntry {
            host: "*.target.test".into(),
        });
        let h = Harness::builder().guard(guard).build();

        let err = h
            .discover(params(&[(
                "target",
                Value::Str("http://evil.com\\.target.test/".into()),
            )]))
            .expect_err("the real host is out of scope");

        let refusal = err
            .downcast_ref::<ScanRefusal>()
            .unwrap_or_else(|| panic!("a typed scan refusal: {err}"));
        assert_eq!(refusal.code, ScanErrorCode::OutOfScope);
        assert!(
            refusal.message.contains("evil.com"),
            "the refusal names the real host: {refusal}"
        );
    }

    /// Two scans of one origin at once would interleave their navigations on
    /// the one browser page, so the job model refuses the second — and the
    /// refusal keeps the sentence the shipped verb used, because a frontend may
    /// be showing it verbatim. The scan already running is unharmed.
    #[test]
    fn overlapping_scan_is_refused_without_touching_the_browser() {
        let store = Arc::new(MemFlowStore::new());
        let (browser, gate) = GatedBrowser::gated(Arc::clone(&store));
        let browser = Arc::new(browser);
        let h = Harness::builder()
            .store(Arc::clone(&store))
            .browser(Arc::clone(&browser) as Arc<dyn BrowserDriver>)
            .build();

        let with_budget = |name: &str| {
            params(&[
                ("target", Value::Str("http://target.test/".into())),
                (name, Value::Int(-1)),
            ])
        };

        let (entered, missing, negative_depth, negative_pages, second, first) =
            std::thread::scope(|s| {
                let first = s.spawn(|| h.discover(seed()));
                // Scan #1 is now parked inside the browser, mid-crawl. The
                // gate itself is the notification; `TERMINAL_NET` is only the
                // safety net that names a scan that never got there instead
                // of hanging the suite (never a measured bound).
                let entered = gate.entered.recv_timeout(TERMINAL_NET);

                // A malformed call is still told what is wrong with it, not that
                // another scan is running: every argument is validated before the
                // job is started, whether it is missing or out of range.
                let missing = h.discover(params(&[]));
                let negative_depth = h.discover(with_budget("max_depth"));
                let negative_pages = h.discover(with_budget("max_pages"));
                let second = h.discover(seed());

                // Release #1 *before* any assertion: a failing assertion must not
                // leave it parked, or the scope's join would hang the test run.
                drop(gate.release);
                let first = first.join().expect("scan #1's thread did not panic");
                (
                    entered,
                    missing,
                    negative_depth,
                    negative_pages,
                    second,
                    first,
                )
            });

        entered.expect("scan #1 reached the browser");
        let err = missing.expect_err("a call with no target is an error");
        assert_eq!(err.to_string(), "missing required param `target`");
        let err = negative_depth.expect_err("a negative max_depth is an error");
        assert_eq!(err.to_string(), "`max_depth` must be non-negative");
        let err = negative_pages.expect_err("a negative max_pages is an error");
        assert_eq!(err.to_string(), "`max_pages` must be non-negative");
        let err = second.expect_err("an overlapping scan is refused, not run");
        assert_eq!(
            err.to_string(),
            "scan.discover is already running; wait for it to finish before starting \
             another (concurrent crawls share one browser page and would corrupt each other)"
        );

        let first = first.expect("scan #1 is unharmed by the refused overlap");
        assert_eq!(endpoints_of(&first), vec![endpoint("/"), endpoint("/one")]);
        assert_eq!(
            browser.navigations(),
            2,
            "the refused scans must not touch the browser"
        );
    }

    /// The browser needs no reset between crawls: scans run one after another on
    /// the same engine each see the whole target, so the per-origin single
    /// flight must hold only while a scan is running.
    #[test]
    fn scan_runs_again_after_the_previous_one_finished() {
        let store = Arc::new(MemFlowStore::new());
        let browser = Arc::new(GatedBrowser::open(Arc::clone(&store)));
        let h = Harness::builder()
            .store(Arc::clone(&store))
            .browser(Arc::clone(&browser) as Arc<dyn BrowserDriver>)
            .build();

        for round in 1..=3 {
            let result = h
                .discover(seed())
                .unwrap_or_else(|err| panic!("scan #{round} must run: {err}"));
            assert_eq!(
                endpoints_of(&result),
                vec![endpoint("/"), endpoint("/one")],
                "scan #{round} crawls the whole target"
            );
        }
        assert_eq!(browser.navigations(), 6, "three scans, two pages each");
    }

    /// A scan that ends in a refusal must leave nothing behind: the next scan
    /// of the same origin is not refused as "already running".
    #[test]
    fn a_refused_scan_leaves_the_origin_free() {
        let store = Arc::new(MemFlowStore::new());
        let browser = Arc::new(GatedBrowser::open(Arc::clone(&store)));
        let h = Harness::builder()
            .store(Arc::clone(&store))
            .browser(Arc::clone(&browser) as Arc<dyn BrowserDriver>)
            .build();

        // An out-of-scope seed is refused by the engine before a job exists.
        let err = h
            .discover(params(&[(
                "target",
                Value::Str("http://unscoped.example/".into()),
            )]))
            .expect_err("an out-of-scope target is refused");
        assert_eq!(
            err.downcast_ref::<ScanRefusal>().map(|r| r.code),
            Some(ScanErrorCode::OutOfScope)
        );

        let result = h
            .discover(seed())
            .expect("the refused scan left the origin free");
        assert_eq!(endpoints_of(&result), vec![endpoint("/"), endpoint("/one")]);
    }

    /// Scanning the same site again must report the same thing, not the sum of
    /// every scan so far: the store still holds the earlier scans' captures, and
    /// each of them serves the same endpoints.
    #[test]
    fn repeated_identical_scans_equal_one_scan() {
        let site = Site::new(&[("/", SITE_ROOT)]);

        let first = site.scan();
        let _second = site.scan();
        let third = site.scan();
        assert_eq!(
            site.store.count(),
            9,
            "three scans captured three pages each"
        );

        assert_eq!(
            endpoints_of(&first),
            vec![
                endpoint("/"),
                endpoint("/search"),
                endpoint("/account/{id}"),
            ]
        );
        assert_eq!(endpoints_of(&third), endpoints_of(&first));

        let first_points = points_of(&first);
        let third_points = points_of(&third);
        // One `X-Trace` header point per page, `q` on /search, the `1` segment
        // on /account/1.
        assert_eq!(first_points.len(), 5, "{first_points:?}");
        assert_eq!(
            third_points.len(),
            first_points.len(),
            "a rescan must not accumulate the earlier scans' points: {third_points:?}"
        );
        assert_eq!(shape(&third_points), shape(&first_points));

        // No (url, location, name) key appears twice.
        let urls = flow_urls(&site.store);
        let mut keys = HashSet::new();
        for p in &third_points {
            let key = (urls[&p.flow].clone(), p.location.clone(), p.name.clone());
            assert!(
                keys.insert(key.clone()),
                "injection point repeated across rescans: {key:?} in {third_points:?}"
            );
        }
    }

    /// With several captures of one endpoint in the store, the result links to
    /// the newest (the one this scan just made), not the oldest.
    #[test]
    fn endpoint_flows_prefers_the_newest_flow() {
        let site = Site::new(&[("/", SITE_ROOT)]);

        // `list()` is in insertion order, so the ids past scan 1's are scan 2's.
        let _first = site.scan();
        let after_first = site.store.list();
        assert_eq!(after_first.len(), 3, "scan 1 captured three pages");
        let second = site.scan();
        let all = site.store.list();
        assert_eq!(all.len(), 6, "scan 2 captured the same three pages again");

        let urls = flow_urls(&site.store);
        // Scan 2's flow for each endpoint: the flow URL carries the query and
        // the id, the endpoint is its node.
        let newest: BTreeMap<String, String> = all[3..]
            .iter()
            .map(|id| (node_of(&urls[&id.to_string()]), id.to_string()))
            .collect();
        assert_eq!(newest.len(), 3);
        let oldest: HashSet<String> = after_first.iter().map(ToString::to_string).collect();

        // Every endpoint links to the flow scan 2 inserted for it...
        let ef = endpoint_flows_of(&second);
        assert_eq!(
            ef, newest,
            "endpoint_flows must point at the latest capture of each endpoint"
        );

        // ...and every injection point was read from scan 2's flow for its URL.
        let points = points_of(&second);
        assert_eq!(points.len(), 5, "{points:?}");
        for p in &points {
            assert!(
                !oldest.contains(&p.flow),
                "injection point still reads from scan 1's flow: {p:?}"
            );
            assert_eq!(
                newest.get(&node_of(&urls[&p.flow])),
                Some(&p.flow),
                "injection point must carry scan 2's flow for its endpoint: {p:?}"
            );
        }
    }

    /// The endpoint a captured URL belongs to, the way the site map groups
    /// them: the query string dropped and a numeric segment collapsed.
    fn node_of(url: &str) -> String {
        let path = url
            .strip_prefix("http://target.test")
            .unwrap_or_else(|| panic!("a target.test URL: {url}"));
        let path = path.split('?').next().unwrap_or(path);
        let template: Vec<String> = path
            .split('/')
            .map(|segment| {
                if !segment.is_empty() && segment.bytes().all(|b| b.is_ascii_digit()) {
                    "{id}".to_string()
                } else {
                    segment.to_string()
                }
            })
            .collect();
        endpoint(&template.join("/"))
    }

    /// Output order is stable across rescans: a point sits where it first
    /// appeared (store order, then `enumerate`'s query, path, header order), and
    /// a repeat key overwrites it there rather than moving it. Compared as the
    /// ordered sequence against a literal, not sorted.
    #[test]
    fn rescan_keeps_each_injection_point_in_its_place() {
        let site = Site::new(&[("/", SITE_ROOT)]);

        let first = points_of(&site.scan());
        let second = points_of(&site.scan());

        let urls = flow_urls(&site.store);
        let order = |points: &[Point]| -> Vec<(String, String, String)> {
            points
                .iter()
                .map(|p| (urls[&p.flow].clone(), p.location.clone(), p.name.clone()))
                .collect()
        };
        let expected: Vec<(String, String, String)> = [
            ("http://target.test/", "header", "X-Trace"),
            ("http://target.test/search?q=hello", "query", "q"),
            ("http://target.test/search?q=hello", "header", "X-Trace"),
            ("http://target.test/account/1", "path_segment", "1"),
            ("http://target.test/account/1", "header", "X-Trace"),
        ]
        .into_iter()
        .map(|(url, location, name)| (url.to_string(), location.to_string(), name.to_string()))
        .collect();
        assert_eq!(order(&first), expected, "scan 1 order");
        assert_eq!(
            order(&second),
            expected,
            "scan 2 must list the same points in the same positions as scan 1"
        );
        // ...and each position really was overwritten: it now carries scan 2's
        // flow, not scan 1's.
        for (idx, (a, b)) in first.iter().zip(&second).enumerate() {
            assert_ne!(
                a.flow, b.flow,
                "position {idx} must carry the newer capture's flow: {a:?} vs {b:?}"
            );
        }
    }

    /// `MAX_RESULT_ITEMS` bounds the number of DISTINCT keys, not the number of
    /// writes: once the cap is full a new key is dropped, but a capture of a key
    /// already in the list still overwrites it with the newer flow.
    ///
    /// Store-only (no browser), so the store's shape is the whole input: 600
    /// endpoints x 2 query points = 1200 distinct keys, so the cap fills at the
    /// 512th endpoint; the newest capture of the FIRST endpoint is stored last,
    /// when the cap is already full.
    #[test]
    fn cap_bounds_distinct_keys_but_an_existing_key_is_still_overwritten() {
        const ENDPOINTS: usize = 600;
        const _: () = assert!(
            ENDPOINTS * 2 > MAX_RESULT_ITEMS,
            "the fixture must exceed the cap"
        );
        let store = Arc::new(MemFlowStore::new());
        for i in 0..ENDPOINTS {
            store.insert(captured(&format!("/p{i}?a=1&b=2"), HeaderMap::new()));
        }
        let newest = store
            .insert(captured("/p0?a=1&b=2", HeaderMap::new()))
            .to_string();
        let h = Harness::builder().store(Arc::clone(&store)).build();

        let result = h
            .discover(seed())
            .expect("an in-scope target with no browser maps the captured flows");

        assert_eq!(
            endpoints_of(&result).len(),
            ENDPOINTS,
            "every endpoint is reached"
        );
        let points = points_of(&result);
        assert_eq!(
            points.len(),
            MAX_RESULT_ITEMS,
            "the cap bounds the number of distinct keys, never exceeded"
        );
        let urls = flow_urls(&store);
        let keys: HashSet<(String, String, String)> = points
            .iter()
            .map(|p| (urls[&p.flow].clone(), p.location.clone(), p.name.clone()))
            .collect();
        assert_eq!(
            keys.len(),
            MAX_RESULT_ITEMS,
            "every listed point is distinct"
        );
        // The keys past the cap were dropped, not swapped in for earlier ones.
        assert!(
            !points
                .iter()
                .any(|p| urls[&p.flow] == "http://target.test/p599?a=1&b=2"),
            "a new key past the cap is dropped"
        );

        // The first endpoint's `a` point was reached again after the cap filled
        // and still took the newest flow, in its original (first) position.
        let p0_a = points
            .iter()
            .find(|p| urls[&p.flow] == "http://target.test/p0?a=1&b=2" && p.name == "a")
            .expect("the first endpoint's `a` point is listed");
        assert_eq!(
            p0_a.flow, newest,
            "an existing key is overwritten with the newest flow even when the cap is full"
        );
        assert_eq!(points[0], *p0_a, "and it kept its place");
    }

    // ---- scan.passive ----------------------------------------------------

    /// A captured flow with a response, so the passive checks have a body and
    /// headers to read. Returns the flow plus its id as the result shows it.
    fn captured_response(
        authority: &str,
        path: &str,
        req_headers: HeaderMap,
        resp_headers: HeaderMap,
        body: &str,
    ) -> (Flow, String) {
        let id = FlowId::new();
        let flow = Flow::Http(HttpFlow {
            id,
            request: HttpRequest {
                method: "GET".into(),
                scheme: "http".into(),
                authority: authority.into(),
                path: path.into(),
                version: HttpVersion::Http11,
                headers: req_headers,
                body: Body::Empty,
                timestamp: SystemTime::now(),
            },
            response: Some(HttpResponse {
                status: 200,
                version: HttpVersion::Http11,
                headers: resp_headers,
                trailers: HeaderMap::new(),
                body: Body::Bytes(body.as_bytes().to_vec()),
                timestamp: SystemTime::now(),
                peer: None,
            }),
            client_conn: conn(),
            server_conn: None,
            metadata: FlowMeta::default(),
            intercept: InterceptState::Observed,
        });
        (flow, id.to_string())
    }

    /// The `findings` array of a `scan.passive` result.
    fn passive_findings_of(result: &Value) -> Vec<BTreeMap<String, Value>> {
        let Value::Object(map) = result else {
            panic!("the result is an object: {result:?}");
        };
        assert_eq!(
            map.keys().map(String::as_str).collect::<Vec<_>>(),
            vec!["findings"],
            "the result carries exactly `findings`: {result:?}"
        );
        let Some(Value::Array(items)) = map.get("findings") else {
            panic!("the result carries a findings array: {result:?}");
        };
        items
            .iter()
            .map(|item| match item {
                Value::Object(o) => o.clone(),
                other => panic!("each finding is an object: {other:?}"),
            })
            .collect()
    }

    fn passive_invoke(store: &MemFlowStore, args: Params) -> anyhow::Result<Value> {
        let guard = scoped_guard();
        let client = NoSendClient;
        let host = CommandHost::new(store, &client, &guard, None);
        ScanPassive.invoke(args, &host)
    }

    #[test]
    fn scan_passive_is_read() {
        let cmd = ScanPassive;
        assert_eq!(cmd.name(), "scan.passive");
        assert_eq!(cmd.sensitivity(), Sensitivity::Read);
        assert!(!cmd.mutates(), "a Read command does not mutate");
        assert!(
            cmd.confirm_prompt(&params(&[])).is_none(),
            "a read-only verb never asks the operator"
        );
        let schema = cmd.schema();
        assert_eq!(schema.params.len(), 1);
        assert_eq!(schema.params[0].name, "target");
        assert!(matches!(schema.params[0].ty, TypeDesc::Str));
        assert!(!schema.params[0].required, "`target` is optional");
    }

    /// No traffic: the command has no `ProxyClient` to send through (`NoSendClient`
    /// panics if it is touched) and no browser, and the store is unchanged.
    #[test]
    fn scan_passive_issues_no_traffic() {
        let store = MemFlowStore::new();
        let (flow, _) = captured_response(
            "target.test",
            "/search?q=hello1",
            HeaderMap::new(),
            HeaderMap::new(),
            "you searched hello1",
        );
        store.insert(flow);
        let before = store.count();

        let result = passive_invoke(&store, params(&[])).expect("scan.passive runs");

        assert_eq!(store.count(), before, "scan.passive must add no flow");
        assert_eq!(before, 1);
        assert!(
            !passive_findings_of(&result).is_empty(),
            "the seeded flow produced findings, so the call did real work: {result:?}"
        );
    }

    #[test]
    fn scan_passive_finds_reflection() {
        let store = MemFlowStore::new();
        let (flow, id) = captured_response(
            "target.test",
            "/search?q=hello1",
            HeaderMap::new(),
            HeaderMap::new(),
            "you searched hello1",
        );
        store.insert(flow);

        let result = passive_invoke(&store, params(&[])).expect("scan.passive runs");

        let expected: BTreeMap<String, Value> = [
            ("class", Value::Str("reflection".into())),
            ("flow", Value::Str(id)),
            ("location", Value::Str("query".into())),
            ("name", Value::Str("q".into())),
            (
                "evidence",
                Value::Str("request parameter value reflected in response body".into()),
            ),
            ("severity", Value::Str("low".into())),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect();
        assert_eq!(
            passive_findings_of(&result),
            vec![expected],
            "one reflection finding naming `q`, nothing else for a plain-http, \
             non-HTML, cookie-less response"
        );
    }

    /// AC3: AC3's literal fixture. No `abc123` reaches any key or value of the
    /// result, while the result still names what was found.
    #[test]
    fn scan_passive_redacts() {
        let store = MemFlowStore::new();
        let mut req_headers = HeaderMap::new();
        req_headers.set("Cookie", "PHPSESSID=abc123");
        req_headers.set("Authorization", "Bearer abc123");
        let mut resp_headers = HeaderMap::new();
        resp_headers.set("Content-Type", "text/html");
        resp_headers.set("Set-Cookie", "PHPSESSID=abc123");
        let (flow, _) = captured_response(
            "target.test",
            "/search?access_token=abc123&q=abc123",
            req_headers,
            resp_headers,
            "echo abc123 token abc123",
        );
        store.insert(flow);

        let result = passive_invoke(&store, params(&[])).expect("scan.passive runs");

        // Not vacuous: the reflected `q`, both missing HTML security headers
        // and the bare session cookie are all reported by name.
        let findings = passive_findings_of(&result);
        let pairs: Vec<(String, Option<String>)> = findings
            .iter()
            .map(|f| {
                let get = |k: &str| match f.get(k) {
                    Some(Value::Str(s)) => Some(s.clone()),
                    _ => None,
                };
                (get("class").expect("class"), get("name"))
            })
            .collect();
        assert!(
            pairs.contains(&("reflection".into(), Some("q".into()))),
            "{pairs:?}"
        );
        assert!(
            pairs.contains(&("cookie-flag".into(), Some("PHPSESSID".into()))),
            "{pairs:?}"
        );
        assert_eq!(
            pairs.iter().filter(|(c, _)| c == "security-header").count(),
            2,
            "CSP and X-Content-Type-Options are missing on this HTML page: {pairs:?}"
        );

        let mut found = Vec::new();
        strings(&result, &mut found);
        assert!(
            !found.iter().any(|s| s.contains("abc123")),
            "a request secret reached the result: {found:?}"
        );
    }

    /// The command-level scrub is its own defence, not a restatement of the
    /// engine's: a finding that DID carry a credential in any string field has it
    /// masked on the way out.
    #[test]
    fn passive_value_scrubs_every_string() {
        let finding = crate::passive::PassiveFinding {
            class: "x?token=abc123".into(),
            flow: FlowId::new(),
            location: Some(Location::Query),
            name: Some("Authorization: Bearer abc123".into()),
            evidence: "seen password=abc123 in the body".into(),
            severity: aitm_poc::Severity::High,
        };

        let result = passive_value(std::slice::from_ref(&finding));

        let findings = passive_findings_of(&result);
        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert_eq!(f["class"], Value::Str("x?token=[redacted]".into()));
        assert_eq!(f["name"], Value::Str("Authorization: [redacted]".into()));
        assert_eq!(
            f["evidence"],
            Value::Str("seen password=[redacted] in the body".into())
        );
        assert_eq!(f["flow"], Value::Str(finding.flow.to_string()));
        assert_eq!(f["location"], Value::Str("query".into()));
        assert_eq!(f["severity"], Value::Str("high".into()));
    }

    /// A finding with no location/name (a missing-header finding) reports them as
    /// `Null`, and the array is capped at `MAX_RESULT_ITEMS`.
    #[test]
    fn passive_value_nulls_missing_fields_and_caps_the_array() {
        let finding = crate::passive::PassiveFinding {
            class: "security-header".into(),
            flow: FlowId::new(),
            location: None,
            name: None,
            evidence: "missing".into(),
            severity: aitm_poc::Severity::Info,
        };
        let many = vec![finding; MAX_RESULT_ITEMS + 10];

        let result = passive_value(&many);

        let findings = passive_findings_of(&result);
        assert_eq!(findings.len(), MAX_RESULT_ITEMS);
        assert_eq!(findings[0]["location"], Value::Null);
        assert_eq!(findings[0]["name"], Value::Null);
        assert_eq!(findings[0]["severity"], Value::Str("info".into()));
    }

    /// `target` narrows the stored flows read; an absent one reads them all.
    #[test]
    fn scan_passive_target_selects_one_origin() {
        let store = MemFlowStore::new();
        let (mine, mine_id) = captured_response(
            "target.test",
            "/search?q=hello1",
            HeaderMap::new(),
            HeaderMap::new(),
            "hello1",
        );
        let (theirs, _) = captured_response(
            "other.test",
            "/search?q=hello1",
            HeaderMap::new(),
            HeaderMap::new(),
            "hello1",
        );
        store.insert(mine);
        store.insert(theirs);

        let scoped = passive_invoke(
            &store,
            params(&[("target", Value::Str("http://target.test".into()))]),
        )
        .expect("scan.passive runs");
        let flows: Vec<Value> = passive_findings_of(&scoped)
            .into_iter()
            .map(|f| f["flow"].clone())
            .collect();
        assert_eq!(flows, vec![Value::Str(mine_id)]);

        let all = passive_invoke(&store, params(&[])).expect("scan.passive runs");
        assert_eq!(passive_findings_of(&all).len(), 2);

        let err = passive_invoke(&store, params(&[("target", Value::Int(7))]))
            .expect_err("a non-string target is refused");
        assert!(
            err.to_string().contains("`target` must be a string"),
            "{err}"
        );
    }

    // ---- scan.report -----------------------------------------------------

    /// A scratch findings directory, removed when dropped.
    struct FindingsDir(std::path::PathBuf);

    impl FindingsDir {
        fn new() -> Self {
            let dir = std::env::temp_dir().join(format!("aitm-scanner-cmd-{}", FlowId::new()));
            std::fs::create_dir_all(&dir).expect("create findings dir");
            Self(dir)
        }

        fn store(&self) -> DiskFindingStore {
            DiskFindingStore::new(&self.0)
        }
    }

    impl Drop for FindingsDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// A recorded finding whose every identifying string derives from `id`.
    fn finding(id: &str, title: &str, target: &str) -> FindingRecord {
        FindingRecord {
            id: id.into(),
            title: title.into(),
            class: "reflected-xss".into(),
            severity: aitm_poc::Severity::High,
            target: target.into(),
            discovered_at: SystemTime::now(),
            origin: Frontend::Cli,
            client_label: None,
            poc_ref: format!("{id}-poc"),
            reproduction: Reproduction {
                passed: true,
                control_passed: Some(false),
                run_at: SystemTime::now(),
            },
            artifacts: FindingArtifacts {
                finding_capture: FlowId::new(),
                poc_path: format!("{id}.poc.yaml"),
                screenshot_path: format!("{id}.png"),
            },
            flows: Vec::new(),
            notes: None,
        }
    }

    /// Invoke `scan.report` against a host whose findings dir is `dir` (none at
    /// all when `None`).
    fn report_invoke(dir: Option<&FindingsDir>, args: Params) -> anyhow::Result<Value> {
        let mut builder = Harness::builder();
        if let Some(dir) = dir {
            builder = builder.findings_dir(dir.0.clone());
        }
        builder.build().call("scan.report", args)
    }

    /// A `scan.report` result split into `report_md` and its `index` objects.
    fn report_parts(result: &Value) -> (String, Vec<BTreeMap<String, Value>>) {
        let Value::Object(map) = result else {
            panic!("the result is an object: {result:?}");
        };
        assert_eq!(
            map.keys().map(String::as_str).collect::<Vec<_>>(),
            vec!["index", "issues_md", "report_md"],
            "the result carries exactly `report_md`, `index` and `issues_md`: {result:?}"
        );
        let Some(Value::Str(md)) = map.get("report_md") else {
            panic!("report_md is a string: {result:?}");
        };
        let Some(Value::Array(items)) = map.get("index") else {
            panic!("index is an array: {result:?}");
        };
        let index = items
            .iter()
            .map(|item| match item {
                Value::Object(o) => o.clone(),
                other => panic!("each index entry is an object: {other:?}"),
            })
            .collect();
        (md.clone(), index)
    }

    /// The `## ` finding sections of a rendered report (the title is `# `).
    fn section_count(md: &str) -> usize {
        md.lines().filter(|l| l.starts_with("## ")).count()
    }

    #[test]
    fn scan_report_is_read() {
        let h = Harness::builder().build();
        let cmd = h
            .reg
            .command("scan.report")
            .expect("scan.report is registered");
        assert_eq!(cmd.name(), "scan.report");
        assert_eq!(cmd.sensitivity(), Sensitivity::Read);
        assert!(!cmd.mutates(), "a Read command does not mutate");
        assert!(
            cmd.confirm_prompt(&params(&[])).is_none(),
            "a read-only verb never asks the operator"
        );
        let schema = cmd.schema();
        assert_eq!(schema.params.len(), 1);
        assert_eq!(schema.params[0].name, "target");
        assert!(matches!(schema.params[0].ty, TypeDesc::Str));
        assert!(!schema.params[0].required, "`target` is optional");
    }

    /// AC4: one `## ` section per recorded finding, and an `index` array with one
    /// entry per finding carrying `poc_path`, `class` and `passed`.
    #[test]
    fn scan_report_one_section_per_finding() {
        let dir = FindingsDir::new();
        let store = dir.store();
        for (id, title) in [
            ("f-one", "Reflected XSS in q"),
            ("f-two", "Open redirect in next"),
            ("f-three", "Reflected XSS in name"),
        ] {
            store
                .record(finding(id, title, "http://t.test:8080/search"))
                .expect("record finding");
        }

        let result = report_invoke(Some(&dir), params(&[])).expect("scan.report runs");

        let (md, index) = report_parts(&result);
        assert_eq!(section_count(&md), 3, "{md}");
        for title in [
            "Reflected XSS in q",
            "Open redirect in next",
            "Reflected XSS in name",
        ] {
            assert!(md.contains(&format!("## {title}\n")), "{title} in {md}");
        }
        assert!(
            md.contains("3 findings, 3 reproduced against a patched control."),
            "{md}"
        );
        assert_eq!(index.len(), 3);
        let mut poc_paths: Vec<Value> = index.iter().map(|e| e["poc_path"].clone()).collect();
        poc_paths.sort_by_key(|v| format!("{v:?}"));
        assert_eq!(
            poc_paths,
            vec![
                Value::Str("f-one.poc.yaml".into()),
                Value::Str("f-three.poc.yaml".into()),
                Value::Str("f-two.poc.yaml".into()),
            ]
        );
        for entry in &index {
            assert_eq!(entry["class"], Value::Str("reflected-xss".into()));
            assert_eq!(entry["passed"], Value::Bool(true));
            assert_eq!(entry["control_passed"], Value::Bool(false));
            assert_eq!(
                entry["target_path"],
                Value::Str("http://t.test:8080/search".into())
            );
        }
    }

    /// No findings directory configured: an empty report, not an error.
    #[test]
    fn scan_report_without_a_findings_dir_is_empty() {
        let result = report_invoke(None, params(&[])).expect("scan.report runs");

        let (md, index) = report_parts(&result);
        assert_eq!(section_count(&md), 0, "{md}");
        assert!(md.contains("0 findings, 0 reproduced"), "{md}");
        assert!(index.is_empty());
    }

    /// The origin-and-path rule (spec "`scan.report`"): a campaign base URL
    /// selects the record stored against one of its endpoints.
    #[test]
    fn scan_report_target_selects_endpoint_records() {
        let dir = FindingsDir::new();
        dir.store()
            .record(finding(
                "f-one",
                "Reflected XSS",
                "http://t.test:8080/search",
            ))
            .expect("record finding");

        let base = report_invoke(
            Some(&dir),
            params(&[("target", Value::Str("http://t.test:8080".into()))]),
        )
        .expect("scan.report runs");
        let other = report_invoke(
            Some(&dir),
            params(&[("target", Value::Str("http://other.test:8080".into()))]),
        )
        .expect("scan.report runs");

        let (base_md, base_index) = report_parts(&base);
        assert_eq!(base_index.len(), 1);
        assert_eq!(section_count(&base_md), 1, "{base_md}");
        let (other_md, other_index) = report_parts(&other);
        assert_eq!(other_index.len(), 0);
        assert_eq!(section_count(&other_md), 0, "{other_md}");

        let err = report_invoke(Some(&dir), params(&[("target", Value::Int(7))]))
            .expect_err("a non-string target is refused");
        assert!(
            err.to_string().contains("`target` must be a string"),
            "{err}"
        );
    }

    /// AC11/AC24, through the command: the store scrubs `title`/`notes`/`target`
    /// when it writes, but not `poc_ref` or the artifact paths, so a credential
    /// an agent put there reaches `scan.report` unless the command masks it.
    #[test]
    fn scan_report_leaks_no_secret() {
        let dir = FindingsDir::new();
        let mut rec = finding("f-secret", "Reflected XSS", "http://t.test:8080/search?q=1");
        rec.poc_ref = "poc?access_token=abc123".into();
        rec.artifacts.poc_path = "poc.yaml?api_key=abc123".into();
        rec.artifacts.screenshot_path = "shot.png?password=abc123".into();
        dir.store().record(rec).expect("record finding");

        let result = report_invoke(Some(&dir), params(&[])).expect("scan.report runs");

        let (md, index) = report_parts(&result);
        // Not vacuous: the finding is reported, and what is not secret survives.
        assert_eq!(section_count(&md), 1, "{md}");
        assert_eq!(index.len(), 1);
        assert!(md.contains("access_token=[redacted]"), "{md}");
        assert_eq!(
            index[0]["poc_path"],
            Value::Str("poc.yaml?api_key=[redacted]".into())
        );
        let mut found = Vec::new();
        strings(&result, &mut found);
        assert!(
            !found.iter().any(|s| s.contains("abc123")),
            "a credential reached the scan.report result: {found:?}"
        );
    }

    /// The shaping helper is its own defence: a record that carries a credential
    /// in ANY field (as a hand-edited or older on-disk record could) is masked in
    /// `report_md` and in every `index` string.
    #[test]
    fn report_value_scrubs_every_field() {
        let mut rec = finding(
            "f-secret",
            "Leak at token=abc123",
            "http://t.test/x?token=abc123",
        );
        rec.class = "x?secret=abc123".into();
        rec.poc_ref = "poc?password=abc123".into();
        rec.artifacts.poc_path = "p.yaml?api_key=abc123".into();
        rec.artifacts.screenshot_path = "s.png?access_token=abc123".into();
        rec.notes = Some("Authorization: Bearer abc123".into());

        let result = report_value(std::slice::from_ref(&rec), "");

        let (md, index) = report_parts(&result);
        assert_eq!(section_count(&md), 1, "{md}");
        assert_eq!(index.len(), 1);
        let mut found = Vec::new();
        strings(&result, &mut found);
        assert!(
            !found.iter().any(|s| s.contains("abc123")),
            "a credential reached the report: {found:?}"
        );
        // Names and structure survive; only the values go.
        assert!(md.contains("token=[redacted]"), "{md}");
        assert_eq!(
            index[0]["target_path"],
            Value::Str("http://t.test/x?token=[redacted]".into())
        );
        assert_eq!(index[0]["class"], Value::Str("x?secret=[redacted]".into()));
        assert_eq!(index[0]["passed"], Value::Bool(true));
    }

    /// `report_md` and `index` are both capped at `MAX_RESULT_ITEMS`, over the
    /// SAME leading slice of records, so the two halves of one result agree on
    /// which findings they describe.
    #[test]
    fn report_value_caps_the_report_and_the_index_to_the_same_slice() {
        let recs: Vec<FindingRecord> = (0..MAX_RESULT_ITEMS + 6)
            .map(|i| {
                finding(
                    &format!("f-{i}"),
                    &format!("Finding {i}"),
                    "http://t.test/x",
                )
            })
            .collect();

        let result = report_value(&recs, "");

        let (md, index) = report_parts(&result);
        assert_eq!(index.len(), MAX_RESULT_ITEMS);
        assert_eq!(
            section_count(&md),
            MAX_RESULT_ITEMS,
            "report_md is capped too"
        );
        assert!(
            md.contains(&format!("{MAX_RESULT_ITEMS} findings,")),
            "the summary line counts the capped slice: {}",
            md.lines().nth(2).unwrap_or_default()
        );

        // The last finding inside the cap is in both halves; the first one past
        // it is in neither.
        let last = MAX_RESULT_ITEMS - 1;
        assert!(md.contains(&format!("## Finding {last}\n")));
        assert_eq!(
            index[last]["poc_path"],
            Value::Str(format!("f-{last}.poc.yaml"))
        );
        assert!(!md.contains(&format!("## Finding {MAX_RESULT_ITEMS}\n")));
    }

    /// The dedupe key includes the URL: the same `(location, name)` on two
    /// different endpoints stays two points, each read from its own flow.
    #[test]
    fn rescan_dedupe_does_not_merge_distinct_urls() {
        let site = Site::new(&[("/", r#"<a href="/a?q=1">a</a> <a href="/b?q=2">b</a>"#)]);

        let _first = site.scan();
        let second = site.scan();

        let points = points_of(&second);
        let urls = flow_urls(&site.store);
        let q: Vec<&Point> = points
            .iter()
            .filter(|p| p.location == "query" && p.name == "q")
            .collect();
        assert_eq!(
            q.len(),
            2,
            "`q` on /a and on /b are two distinct points: {points:?}"
        );
        let q_urls: Vec<(&str, &str)> = {
            let mut v: Vec<_> = q
                .iter()
                .map(|p| (urls[&p.flow].as_str(), p.example.as_str()))
                .collect();
            v.sort();
            v
        };
        assert_eq!(
            q_urls,
            vec![
                ("http://target.test/a?q=1", "1"),
                ("http://target.test/b?q=2", "2"),
            ]
        );
        // The shared header stays one point per endpoint: three endpoints,
        // three `X-Trace` points.
        assert_eq!(
            points
                .iter()
                .filter(|p| p.location == "header" && p.name == "X-Trace")
                .count(),
            3,
            "{points:?}"
        );
        assert_eq!(points.len(), 5, "{points:?}");
    }

    // ---- the job model behind the legacy verbs ---------------------------

    use crate::interim_lane::InterimHttpLane;
    use crate::issues::IssueStore;
    use crate::jobs::test_support::{
        fake_point, FakeCheck, FakeLane, FakeRun, StubClient, TERMINAL_NET,
    };
    use crate::jobs::{self, Caller, Engine, JobRegistry, ScanLate, ScanServices};
    use crate::profiles::Profiles;
    use aitm_core::{AgentPolicy, JobBus, Registry};
    use aitm_scan_model::{
        CheckRegistry, Discovery, InsertionPoint, Intensity, JobCtx, JobState, Lane, LaneKind,
        PointTrait, ProfileTarget, ScanProfile,
    };
    use std::path::PathBuf;

    /// A lane whose `discover` never ends until the job is cancelled, so the
    /// verb's wait is the only thing that can stop it.
    struct BlockingLane;

    impl Lane for BlockingLane {
        fn lane(&self) -> LaneKind {
            LaneKind::Http
        }

        fn discover<'a>(
            &'a self,
            _target: &'a ProfileTarget,
            job: &'a dyn JobCtx,
        ) -> BoxFuture<'a, anyhow::Result<Discovery>> {
            Box::pin(async move {
                while !job.cancelled() {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                Ok(Discovery::default())
            })
        }

        fn probe_host_for(
            &self,
            _point: &InsertionPoint,
            _job: Arc<dyn JobCtx>,
        ) -> anyhow::Result<Box<dyn aitm_scan_model::ProbeHost>> {
            Err(anyhow::anyhow!("the blocking lane hosts no probe"))
        }

        fn checks(&self) -> Vec<Arc<dyn aitm_scan_model::Check>> {
            Vec::new()
        }
    }

    /// An [`Engine`] over in-memory services, the runtime its workers run on,
    /// and the commands [`register`] put on a registry.
    ///
    /// `scan.discover` is synchronous, so `discover()` blocks the calling
    /// thread until the map job it started is terminal — exactly as it blocks
    /// one bus connection in production. The runtime therefore lives on its
    /// own threads and the test thread is never inside it.
    struct Harness {
        reg: Registry,
        engine: Arc<Engine>,
        store: Arc<MemFlowStore>,
        guard: Arc<StdGuard>,
        client: Arc<dyn ProxyClient>,
        browser: Option<Arc<dyn BrowserDriver>>,
        frontend: Frontend,
        /// What the binary puts on the `CommandHost` as `findings.dir`, which
        /// is where `scan.report` reads the recorded findings from.
        findings_dir: Option<PathBuf>,
        /// Declared last so it is dropped last: the engine holds its handle.
        _rt: tokio::runtime::Runtime,
    }

    /// What a test turns before the engine is assembled.
    struct HarnessBuilder {
        cfg: ScannerConfig,
        scope: Vec<String>,
        store: Arc<MemFlowStore>,
        guard: Option<Arc<StdGuard>>,
        client: Option<Arc<dyn ProxyClient>>,
        browser: Option<Arc<dyn BrowserDriver>>,
        egress: Option<Arc<EgressConfinement>>,
        lanes: Vec<Arc<dyn Lane>>,
        frontend: Frontend,
    }

    impl Harness {
        fn builder() -> HarnessBuilder {
            HarnessBuilder {
                cfg: ScannerConfig::default(),
                scope: vec!["target.test".to_string()],
                store: Arc::new(MemFlowStore::new()),
                guard: None,
                client: None,
                browser: None,
                egress: None,
                lanes: Vec::new(),
                frontend: Frontend::Cli,
            }
        }

        /// Invoke a registered verb the way a frontend does.
        fn call(&self, name: &str, args: Params) -> anyhow::Result<Value> {
            let mut host = CommandHost::new(
                &*self.store,
                &*self.client,
                &*self.guard,
                self.browser.as_deref(),
            )
            .with_frontend(self.frontend);
            if self.findings_dir.is_some() {
                host = host.with_config(Arc::new(Config {
                    findings: FindingsConfig {
                        dir: self.findings_dir.clone(),
                    },
                    ..Config::default()
                }));
            }
            self.reg
                .command(name)
                .unwrap_or_else(|| panic!("{name} is registered"))
                .invoke(args, &host)
        }

        fn discover(&self, args: Params) -> anyhow::Result<Value> {
            self.call("scan.discover", args)
        }

        /// The one job the registry holds, newest first.
        fn newest_job(&self) -> String {
            self.engine
                .registry
                .list(false, 16)
                .first()
                .expect("the verb started a job")
                .job
                .clone()
        }

        /// Wait for a job's terminal state from outside the runtime, on the
        /// registry's terminal signal (`test_support::wait_terminal_blocking`;
        /// this `#[test]` thread is never inside the harness runtime).
        fn wait_terminal(&self, job: &str) -> aitm_scan_model::JobStatus {
            crate::jobs::test_support::wait_terminal_blocking(&self.engine.registry, job)
        }
    }

    impl HarnessBuilder {
        fn cfg(mut self, cfg: ScannerConfig) -> Self {
            self.cfg = cfg;
            self
        }

        fn scope(mut self, hosts: &[&str]) -> Self {
            self.scope = hosts.iter().map(|h| (*h).to_string()).collect();
            self
        }

        fn store(mut self, store: Arc<MemFlowStore>) -> Self {
            self.store = store;
            self
        }

        fn guard(mut self, guard: Arc<StdGuard>) -> Self {
            self.guard = Some(guard);
            self
        }

        fn client(mut self, client: Arc<dyn ProxyClient>) -> Self {
            self.client = Some(client);
            self
        }

        fn browser(mut self, browser: Arc<dyn BrowserDriver>) -> Self {
            self.browser = Some(browser);
            self
        }

        fn egress(mut self, egress: Arc<EgressConfinement>) -> Self {
            self.egress = Some(egress);
            self
        }

        fn lane(mut self, lane: Arc<dyn Lane>) -> Self {
            self.lanes.push(lane);
            self
        }

        fn findings_dir(mut self, dir: PathBuf) -> Self {
            self.cfg.findings_dir = Some(dir);
            self
        }

        fn build(self) -> Harness {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .expect("a test runtime");
            let guard = self.guard.unwrap_or_else(|| {
                let guard = Arc::new(StdGuard::default());
                for host in &self.scope {
                    guard.add_scope(ScopeEntry { host: host.clone() });
                }
                guard
            });
            // A harness job may crawl through the client (spec D5), and
            // nothing else: `CrawlOnlyClient` panics on any other send.
            let client: Arc<dyn ProxyClient> =
                self.client.unwrap_or_else(|| CrawlOnlyClient::new());
            let engine = Arc::new(Engine {
                cfg: self.cfg.clone(),
                late: ScanLate::new(),
                lanes: self.lanes,
                native_checks: Vec::new(),
                passive_checks: crate::interim_lane::shipped_passive_checks(),
                script_checks: Arc::new(CheckRegistry::new()),
                interim: InterimHttpLane::new(self.cfg.clone()),
                registry: JobRegistry::new(self.cfg.history),
                issues: Arc::new(IssueStore::new(self.cfg.findings_dir.as_deref())),
                profiles: Profiles::new(&self.cfg),
            });
            assert!(
                engine.late.bind(ScanServices {
                    store: self.store.clone(),
                    client: Arc::clone(&client),
                    guard: Arc::clone(&guard) as Arc<dyn ScopeRateGuard>,
                    browser: self.browser.clone(),
                    egress: self.egress.clone(),
                    l4: None,
                    jobs: Arc::new(JobBus::default()),
                    // The operator's posture: the agent gate is Task 15's, and
                    // these tests are about the legacy verbs' own behaviour.
                    agent_policy: Arc::new(|| AgentPolicy::All),
                    rt: rt.handle().clone(),
                    config: Arc::new(Config {
                        findings: FindingsConfig {
                            dir: self.cfg.findings_dir.clone(),
                        },
                        ..Config::default()
                    }),
                }),
                "the harness binds the services once"
            );
            let mut reg = Registry::new();
            register(&engine, &mut reg);
            Harness {
                reg,
                engine,
                store: self.store,
                guard,
                client,
                browser: self.browser,
                frontend: self.frontend,
                findings_dir: self.cfg.findings_dir.clone(),
                _rt: rt,
            }
        }
    }

    /// Task 16: `scan.discover` is `scan.map` plus a wait. The caller sees the
    /// shipped object — the same five keys, the same per-point shape — built
    /// from the job's discovery, and the job it ran is in the registry
    /// afterwards (what `scan.list` reads).
    #[test]
    fn discover_waits_for_the_map_job_and_keeps_its_shape() {
        let mut redirect = fake_point("p2", "next", "http://target.test/search");
        redirect.traits = vec![PointTrait::Url];
        let lane = FakeLane::http().with_points(vec![
            fake_point("p1", "q", "http://target.test/search"),
            redirect,
        ]);
        let h = Harness::builder().lane(Arc::new(lane)).build();

        let result = h
            .discover(params(&[(
                "target",
                Value::Str("http://target.test/".into()),
            )]))
            .expect("the map job runs to completion");

        let Value::Object(map) = &result else {
            panic!("the result is an object: {result:?}");
        };
        assert_eq!(
            map.keys().map(String::as_str).collect::<Vec<_>>(),
            vec![
                "endpoint_flows",
                "endpoints",
                "injection_points",
                "pages_crawled",
                "stopped_reason"
            ],
            "the shipped result shape is unchanged"
        );
        assert_eq!(map.get("stopped_reason"), Some(&Value::Null));
        let points = points_of(&result);
        assert_eq!(points.len(), 2, "{points:?}");
        assert_eq!(
            points
                .iter()
                .map(|p| (p.location.as_str(), p.name.as_str()))
                .collect::<Vec<_>>(),
            vec![("query", "q"), ("redirect", "next")],
            "a query point carrying a URL is the legacy `redirect` location",
        );

        let jobs = h.engine.registry.list(false, 16);
        assert_eq!(jobs.len(), 1, "one job ran: {jobs:?}");
        assert_eq!(jobs[0].state, JobState::Done);
    }

    /// Call B11: the wait is bounded by the shipped `ScannerConfig.time_budget`.
    /// When it runs out the job is cancelled and the caller is told so, rather
    /// than the connection blocking forever on a lane that never finishes.
    ///
    /// The lane cannot end on its own, so the verb answering at all with
    /// `stopped_reason: time_budget` and a cancelled job *is* the proof that
    /// the budget ended the wait; nothing is measured. `TERMINAL_NET` is the
    /// safety net around the call: on expiry the job is cancelled so the
    /// scope can join, and the test fails naming the hang.
    #[test]
    fn discover_time_budget_cancels_and_reports() {
        let h = Harness::builder()
            .cfg(ScannerConfig {
                time_budget: Duration::from_millis(300),
                ..ScannerConfig::default()
            })
            .lane(Arc::new(BlockingLane))
            .build();

        let h = &h;
        let result = std::thread::scope(|s| {
            let (tx, rx) = mpsc::channel();
            s.spawn(move || {
                let _ = tx.send(h.discover(params(&[(
                    "target",
                    Value::Str("http://target.test/".into()),
                )])));
            });
            match rx.recv_timeout(TERMINAL_NET) {
                Ok(result) => result,
                Err(_) => {
                    for job in h.engine.registry.list(true, 16) {
                        h.engine.registry.cancel(&job.job);
                    }
                    panic!("scan.discover did not answer within the {TERMINAL_NET:?} safety net");
                }
            }
        })
        .expect("a cancelled map job still answers");

        let Value::Object(map) = &result else {
            panic!("the result is an object: {result:?}");
        };
        assert_eq!(
            map.get("stopped_reason"),
            Some(&Value::Str("time_budget".into()))
        );
        let job = h.newest_job();
        assert_eq!(
            h.wait_terminal(&job).state,
            JobState::Cancelled,
            "the verb cancelled the job it could not wait for"
        );
    }

    /// The wait behind `scan.discover` answers when the job's `finish` has run
    /// (the registry's terminal signal), not on the first read of a terminal
    /// `state`. Between the two the worker persists the record and the job
    /// still holds its egress hold, so a verb answering on the status alone
    /// could hand back a "finished" map while the browser was still confined.
    /// A zero deadline makes the distinction without a clock: the wait either
    /// answers on its first look or it does not.
    #[test]
    fn discover_wait_answers_on_finish_not_on_a_terminal_status() {
        let posture = Arc::new(EgressConfinement::new(false));
        let h = Harness::builder().build();
        let verb = ScanDiscover {
            engine: Arc::clone(&h.engine),
        };

        // A job as the worker leaves it for a moment on its terminal path:
        // the status says `done`, `finish` has not run, the hold is held.
        let job = "scan-0000d15c".to_string();
        let start = aitm_scan_model::JobStatus {
            job: job.clone(),
            state: JobState::Done,
            started_at: 1,
            finished_at: Some(2),
            targets: vec!["http://target.test".to_string()],
            ..Default::default()
        };
        assert!(h.engine.registry.try_insert(jobs::JobEntry {
            status: Arc::new(std::sync::RwLock::new(start.clone())),
            cancel: tokio_util::sync::CancellationToken::new(),
            confine: Some(posture.confine()),
            started_by: Default::default(),
            discovery: Arc::new(std::sync::RwLock::new(Default::default())),
            origins: vec!["http://target.test".to_string()],
            is_agent: false,
            terminal: tokio::sync::watch::channel(false).0,
        }));
        assert!(posture.confined(), "the job still holds its egress hold");

        let mut last = start.clone();
        assert!(
            verb.wait_until(&job, Duration::ZERO, &mut last).is_none(),
            "a terminal state alone is not the end of the job: the wait runs out its deadline"
        );
        assert_eq!(
            last, start,
            "the deadline leaves the newest status in `last`"
        );

        h.engine.registry.finish(&job);
        let settled = verb
            .wait_until(&job, Duration::ZERO, &mut last)
            .expect("a finished job answers on the first look");
        assert_eq!(settled.state, JobState::Done);
        assert!(
            !posture.confined(),
            "by the time the wait answers, `finish` has released the hold"
        );

        // A job the registry no longer holds (pruned under load, or a history
        // of zero) leaves nothing to wait for: the last status seen answers.
        let gone = verb
            .wait_until("scan-00000000", Duration::ZERO, &mut last)
            .expect("an unknown job answers at once");
        assert_eq!(gone.job, job);
    }

    /// Spec D3: the verb stays, marked deprecated, so a UI reading `tools/list`
    /// learns to move to `scan.map`.
    #[test]
    fn discover_description_says_deprecated() {
        let h = Harness::builder().build();
        let description = h
            .reg
            .command("scan.discover")
            .expect("scan.discover is registered")
            .schema()
            .description;

        assert!(
            description.contains("Deprecated: use `scan.map` and poll `scan.status`."),
            "the description marks the verb deprecated: {description}"
        );
    }

    /// Coordinator decision 1: a lane that refuses the profile fails the job,
    /// and the synchronous verb hands that failure back as its own error.
    #[test]
    fn discover_surfaces_a_failed_jobs_error() {
        let lane = FakeLane::http().with_discover_error("invalid_profile: bad seed");
        let h = Harness::builder().lane(Arc::new(lane)).build();

        let err = h
            .discover(params(&[(
                "target",
                Value::Str("http://target.test/".into()),
            )]))
            .expect_err("a failed job is the verb's error");

        assert_eq!(err.to_string(), "scan: invalid_profile: bad seed");
    }

    /// Task 16: `scan.report` keeps `report_md` and `index` and gains the
    /// issue store's `issues_md`, so the report covers what the v2 engine found.
    #[test]
    fn report_gains_issues_md() {
        let lane = FakeLane::http().with_check(FakeCheck::new(
            "demo.check",
            "demo",
            FakeRun::vulnerable(),
        ));
        let h = Harness::builder()
            .client(StubClient::new())
            .lane(Arc::new(lane))
            .build();

        let profile = ScanProfile {
            name: "audit".to_string(),
            target: ProfileTarget {
                origins: vec!["http://target.test".to_string()],
                l4: Vec::new(),
            },
            intensity: Intensity::Light,
            ..ScanProfile::default()
        };
        let started = jobs::start(
            &h.engine,
            profile,
            Caller {
                frontend: Frontend::Cli,
                client_label: None,
            },
            false,
        )
        .expect("the audit job starts");
        let status = h.wait_terminal(&started.job);
        assert_eq!(status.state, JobState::Done, "{status:?}");
        let issues = h.engine.issues.for_job(&started.job);
        let name = issues
            .first()
            .map(|issue| issue.name.clone())
            .expect("the vulnerable verdict raised an issue");

        let result = h
            .call("scan.report", params(&[]))
            .expect("scan.report runs");

        let Value::Object(map) = &result else {
            panic!("the result is an object: {result:?}");
        };
        assert!(map.contains_key("report_md"), "{result:?}");
        assert!(map.contains_key("index"), "{result:?}");
        let Some(Value::Str(issues_md)) = map.get("issues_md") else {
            panic!("the report carries an issues_md section: {result:?}");
        };
        assert!(
            issues_md.contains(&name),
            "the issue `{name}` is rendered: {issues_md}"
        );
    }
}
