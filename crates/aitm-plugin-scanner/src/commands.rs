//! The scanner's MCP commands: `scan.discover` (endpoint discovery, below), and
//! the two read-only verbs `scan.passive` (passive checks over captured flows)
//! and `scan.report` (the findings report and index). All result shaping lives
//! here; the engine modules build no [`Value`] (bar the one JSON-to-[`Value`]
//! bridge, [`report::index_to_value`]).
//!
//! `scan.discover` crawls one operator-authorized, in-scope target (same-origin, scope-bound,
//! budget-capped — see [`crate::crawl`]) and enumerates the parameter names
//! present in the requests already captured for the reached endpoints (see
//! [`crate::discover`]). It performs **no** injection and **no** fuzzing: it only
//! lists reachable URLs and the injection points visible in observed traffic.
//! Repeated scans of one target do not accumulate: each endpoint links to the
//! newest captured flow that served it, and injection points are de-duplicated
//! on (URL, location, name) across captures.
//!
//! Deny-by-default throughout: the crawl gates the target host through
//! [`aitm_core::ScopeRateGuard::check_active`] before its first navigation, so
//! an out-of-scope target is refused before anything is fetched, and every page
//! the crawl then visits takes its own permit. The crawl also runs under a
//! campaign hold on the proxy's browser-egress posture
//! ([`aitm_core::EgressConfinement::confine`]), so the browser-facing connector
//! refuses an out-of-scope public host before dialing it; the hold is an RAII
//! token released when the command returns.
//!
//! Single-flight: there is exactly one browser page, so two crawls running at
//! once would interleave their navigations on it (each harvesting the other's
//! pages, or losing its seed navigation to the other). `scan.discover` is
//! therefore refused **immediately** while another discovery is running on the
//! same command, before it takes an egress hold or touches the browser, and the
//! next one runs normally as soon as the running one ends — on success, error,
//! or unwind (the claim is an RAII token). Sequential scans need no browser
//! reset between them.
//!
//! The result carries no credentials: [`crate::discover::enumerate`] replaces a
//! secret-named point's example with a placeholder, and every free-text string
//! that reaches the caller is additionally run through
//! [`aitm_core::redact::scrub_text`], so a token embedded in a URL's query is
//! masked as well.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};

use aitm_core::redact::scrub_text;
use aitm_core::{
    Command, CommandHost, Flow, ParamDef, ParamSchema, Params, Sensitivity, TypeDesc, Value,
};
use aitm_findings::{render_index, render_report, FindingRecord};
use aitm_poc::Severity;

use crate::crawl::{block_on, crawl, normalize_url};
use crate::discover::{enumerate, Location};
use crate::inject::target_flows;
use crate::passive::{passive_checks, PassiveFinding};
use crate::report;
use crate::ScannerConfig;

/// Upper bound on each array in the result, so a long crawl cannot return an
/// unbounded object to the caller.
const MAX_RESULT_ITEMS: usize = 1024;

/// `scan.discover` — list reachable in-scope URLs and the parameter names
/// present in captured requests. Registered by [`crate::ScannerPlugin`].
pub(crate) struct ScanDiscover {
    cfg: ScannerConfig,
    /// Set while a discovery is running. The command is created once per
    /// registry and shared (behind an `Arc`) by every frontend built over it, so
    /// this one flag serializes every `scan.discover` that can reach the one
    /// shared browser page.
    in_flight: AtomicBool,
}

impl ScanDiscover {
    pub(crate) fn new(cfg: ScannerConfig) -> Self {
        Self {
            cfg,
            in_flight: AtomicBool::new(false),
        }
    }
}

/// The claim on [`ScanDiscover::in_flight`], held for the whole discovery. It
/// releases the flag when dropped, so the slot is given back on success, on
/// error, and on unwind alike.
struct InFlightSlot<'a>(&'a AtomicBool);

impl<'a> InFlightSlot<'a> {
    /// Claim the slot, or `None` if a discovery already holds it. The slot is
    /// built only on success (`map`, not an eagerly evaluated `then_some`): a
    /// slot built on failure would clear the running scan's flag when dropped.
    fn claim(flag: &'a AtomicBool) -> Option<Self> {
        // A plain try-lock pairing (`Acquire` on a successful claim, `Release` in
        // `Drop`); the flag guards no data, it only keeps a second crawl out.
        flag.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .ok()
            .map(|_| Self(flag))
    }
}

impl Drop for InFlightSlot<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

impl Command for ScanDiscover {
    fn name(&self) -> &str {
        "scan.discover"
    }

    fn sensitivity(&self) -> Sensitivity {
        // A scope/rate-bounded testing verb: it drives the browser against an
        // authorized target. Read-only in intent, but it issues navigations, so
        // it is `Write`, not `Read`.
        Sensitivity::Write
    }

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "Discover reachable in-scope URLs under `target` (same-origin, \
                          scope-bound, budget-capped) and enumerate the injection points \
                          visible in captured requests. No injection or fuzzing is performed. \
                          `max_depth`/`max_pages` may lower the configured caps, never raise them. \
                          A navigation that lands off-origin or out of scope (a redirect) aborts \
                          the crawl with `stopped_reason = \"left_scope\"`. While the crawl runs \
                          the proxy's browser-egress posture is held confined, so the embedded \
                          browser cannot fetch an out-of-scope public host (sub-resource or \
                          redirect target); the hold is released when the command returns. \
                          Only one discovery runs at a time (crawls share one browser page); a second \
                          call while one is running is refused immediately \u{2014} wait for it to finish."
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

        // Optional budget overrides may only *lower* the configured caps, never
        // raise them — the operator's config is the ceiling.
        let mut cfg = self.cfg.clone();
        if args.get("max_depth").is_some() {
            let requested = usize::try_from(args.get_int("max_depth")?)
                .map_err(|_| anyhow::anyhow!("`max_depth` must be non-negative"))?;
            cfg.max_depth = cfg.max_depth.min(requested);
        }
        if args.get("max_pages").is_some() {
            let requested = usize::try_from(args.get_int("max_pages")?)
                .map_err(|_| anyhow::anyhow!("`max_pages` must be non-negative"))?;
            cfg.max_pages = cfg.max_pages.min(requested);
        }

        // Single-flight: one browser page is shared by every crawl, so a second
        // discovery running now would interleave its navigations with the running
        // one. Refuse it here, after argument validation (a bad argument is still
        // reported as such). `_slot` is claimed before `_confine` is taken, so a
        // refused call returns before it does anything: no egress hold, no
        // browser. Locals drop in reverse order, so on the way out the hold is
        // released first and the slot last.
        let Some(_slot) = InFlightSlot::claim(&self.in_flight) else {
            anyhow::bail!(
                "scan.discover is already running; wait for it to finish before starting \
                 another (concurrent crawls share one browser page and would corrupt each other)"
            );
        };

        // S2: run the whole crawl under a campaign hold on the proxy's
        // browser-egress posture, so the `SsrfConnector` refuses any
        // out-of-scope public host the browser is sent to (a redirect, a
        // sub-resource) *before* dialing it. The RAII token is dropped when
        // `invoke` returns — on success, error, or unwind — so a finished scan
        // never leaves the posture confined (`set_base` would). A host with no
        // posture wired crawls unconfined, as before; the `left_scope` abort in
        // the crawl stays as defense-in-depth.
        let _confine = host.egress_handle().map(|e| e.confine());

        // Deny-by-default: the crawl gates the seed through the scope/rate
        // guard before its first navigation (and the no-browser fallback takes
        // one permit of its own), so an out-of-scope target returns
        // `GuardError::OutOfScope` before anything is fetched. The gate lives in
        // one place on purpose: a second `check_active` here for the same seed
        // would spend a second rate token and a second concurrency slot, and
        // with `max_concurrency == 1` would refuse the crawl's own permit.
        let outcome = block_on(crawl(host, target, &cfg))?;

        Ok(discover_value(host, &outcome))
    }
}

/// The `scan.discover` result for a finished crawl: the reached `endpoints`, the
/// `injection_points` enumerated from the captured requests that served them,
/// the `endpoint_flows` links, `pages_crawled` and `stopped_reason`.
///
/// Shared by [`ScanDiscover`] and, later, the `scan.run` driver, so the two
/// shape the discovery half of their results identically. Reads only the host's store;
/// every free-text string is run through [`scrub_text`].
pub(crate) fn discover_value(
    host: &CommandHost<'_>,
    outcome: &crate::crawl::CrawlOutcome,
) -> Value {
    // Enumerate injection points from the captured requests whose normalized
    // URL is one of the reached endpoints — observed traffic only.
    // Capped at MAX_RESULT_ITEMS to match the exposed `endpoints` array (which is
    // `.take(MAX_RESULT_ITEMS)` below), so `endpoint_flows` and `endpoints` stay in
    // lockstep and neither grows unbounded on a long crawl.
    let endpoint_set: HashSet<&str> = outcome
        .endpoints
        .iter()
        .take(MAX_RESULT_ITEMS)
        .map(String::as_str)
        .collect();
    let mut injection_points: Vec<Value> = Vec::new();
    // (endpoint URL, location, name) -> index into `injection_points`. The
    // store keeps every earlier scan's captures of the same site, so the
    // same point turns up once per capture; it is reported once, at the
    // position of its first appearance, carrying the newest capture's flow
    // and example.
    let mut point_index: HashMap<(&str, Location, String), usize> = HashMap::new();
    // Map each reached endpoint (keyed by the same scrubbed URL the result
    // exposes in `endpoints`) to the newest captured flow that served it, so
    // a UI can link an endpoint row to its flow (AC3). `list()` is in
    // insertion order, so overwriting on every hit leaves the latest capture
    // without consulting clocks. Deliberately not limited to flows newer
    // than the crawl: the `no_browser` store-only fallback has only older
    // flows, and an endpoint whose fresh capture was missed should still
    // link the older real one. Bounded by `endpoint_set` (<=
    // MAX_RESULT_ITEMS), i.e. capped like the arrays; an endpoint with no
    // captured flow is simply absent from the map.
    let mut endpoint_flows: BTreeMap<String, Value> = BTreeMap::new();
    for id in host.store().list() {
        let Some(Flow::Http(flow)) = host.store().get(id) else {
            continue;
        };
        let req = &flow.request;
        let raw = format!("{}://{}{}", req.scheme, req.authority, req.path);
        let Some(normalized) = normalize_url(&raw) else {
            continue;
        };
        let Some(&url) = endpoint_set.get(normalized.as_str()) else {
            continue;
        };
        endpoint_flows.insert(scrub_text(url), Value::Str(id.to_string()));
        for point in enumerate(&flow) {
            let key = (url, point.location.clone(), point.name.clone());
            // The cap bounds distinct keys; overwriting an existing one is
            // always allowed. Decide before building anything, so a new key
            // past the cap is dropped unbuilt rather than assembled and
            // scrubbed only to be thrown away.
            let slot = point_index.get(&key).copied();
            if slot.is_none() && injection_points.len() >= MAX_RESULT_ITEMS {
                continue;
            }
            let mut obj = BTreeMap::new();
            obj.insert("flow".into(), Value::Str(point.flow.to_string()));
            obj.insert(
                "location".into(),
                Value::Str(point.location.as_str().to_string()),
            );
            obj.insert("name".into(), Value::Str(point.name));
            // `enumerate` has already replaced a secret-named example; this
            // catches a credential embedded inside an otherwise innocent
            // value (`next=…?access_token=…`).
            obj.insert("example".into(), Value::Str(scrub_text(&point.example)));
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
    }

    let mut result = BTreeMap::new();
    result.insert(
        "endpoints".into(),
        Value::Array(
            outcome
                .endpoints
                .iter()
                .take(MAX_RESULT_ITEMS)
                // A reached URL can carry a token in its query string.
                .map(|url| Value::Str(scrub_text(url)))
                .collect(),
        ),
    );
    result.insert("injection_points".into(), Value::Array(injection_points));
    // endpoint URL (scrubbed, matching an entry in `endpoints`) -> flow id.
    result.insert("endpoint_flows".into(), Value::Object(endpoint_flows));
    result.insert(
        "pages_crawled".into(),
        Value::Int(i64::try_from(outcome.pages_crawled).unwrap_or(i64::MAX)),
    );
    result.insert(
        "stopped_reason".into(),
        outcome
            .stopped_reason
            .clone()
            .map_or(Value::Null, Value::Str),
    );
    Value::Object(result)
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
/// Registered by [`crate::ScannerPlugin`].
///
/// A unit struct: `invoke` reads no configuration. It is `Read` and issues no
/// traffic — it reads the stored flows and nothing else, with no proxy client
/// send and no browser — so it runs under a read-only agent policy.
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
/// finding) reports them as `Null`. Shared by [`ScanPassive`] and, later, the
/// `scan.run` driver.
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
/// machine-readable index. Registered by [`crate::ScannerPlugin`].
///
/// A unit struct: `invoke` reads no configuration beyond the host's findings
/// directory. It is `Read`: it lists and reads stored findings and writes
/// nothing, issues no traffic and needs no browser.
pub(crate) struct ScanReport;

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
                          control_passed, finding_capture, screenshot_path} entry per finding). \
                          `target` selects the findings recorded against that origin, or against \
                          a path under it. Empty when no findings directory is configured. \
                          Credentials are masked."
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
        Ok(report_value(&report::load_records(host, target)))
    }
}

/// The `scan.report` result: `{ "report_md": Str, "index": Array }`, where
/// `report_md` is [`render_report`] and `index` is [`render_index`] converted
/// to the transport-neutral [`Value`], both over the same leading
/// [`MAX_RESULT_ITEMS`] records, so the two halves describe the same findings.
///
/// A shareable report carries no credential (AC11/AC24): the markdown and every
/// string of the index are run through [`scrub_text`]. The store masks a
/// finding's `title`, `notes` and `target` when it writes them, but not
/// `poc_ref` or the artifact paths, and a record may predate the masking or be
/// edited by hand, so the output is scrubbed here whatever the record holds.
/// Shared by [`ScanReport`] and, later, the `scan.run` driver.
pub(crate) fn report_value(recs: &[FindingRecord]) -> Value {
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
        FlowId, FlowMeta, FlowStore, Frontend, GuardError, HeaderMap, HttpFlow, HttpRequest,
        HttpResponse, HttpVersion, InterceptState, MemFlowStore, NavOutcome, ProxyClient,
        ScopeEntry, ScopeRateGuard, StdGuard,
    };
    use aitm_findings::{DiskFindingStore, FindingArtifacts, FindingStore, Reproduction};
    use futures::future::BoxFuture;
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::panic::AssertUnwindSafe;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{mpsc, Arc, Mutex};
    use std::time::{Duration, SystemTime};

    /// A browser that serves one fixed page and, at every `navigate()`, records
    /// whether the shared egress posture was confined at that instant — the
    /// moment the real browser would be issuing the request.
    struct PostureProbeBrowser {
        posture: Arc<EgressConfinement>,
        observed: Mutex<Vec<bool>>,
    }

    impl PostureProbeBrowser {
        fn new(posture: Arc<EgressConfinement>) -> Self {
            Self {
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

    /// What a [`GatedBrowser`] does when it is navigated. A browser has exactly
    /// one behaviour, so it cannot be both gated and panicking.
    enum Behaviour {
        /// Every navigation succeeds at once.
        Open,
        /// Every navigation panics, as a crashing driver would.
        Panic,
        /// Every navigation announces itself, then parks until the test releases it.
        Gated(BrowserGate),
    }

    /// A browser for the single-flight tests: it serves one fixed page
    /// (`<a href="/one">`, so a crawl of the seed reaches the seed and `/one`),
    /// counts the navigations it is asked for, and behaves as its [`Behaviour`]
    /// says. Unrelated to `crawl.rs`'s `StubBrowser`, which serves crafted pages
    /// per URL.
    struct GatedBrowser {
        navigations: AtomicUsize,
        behaviour: Behaviour,
    }

    impl GatedBrowser {
        fn new(behaviour: Behaviour) -> Self {
            Self {
                navigations: AtomicUsize::new(0),
                behaviour,
            }
        }

        fn open() -> Self {
            Self::new(Behaviour::Open)
        }

        fn panicking() -> Self {
            Self::new(Behaviour::Panic)
        }

        fn gated() -> (Self, Gate) {
            let (entered_tx, entered_rx) = mpsc::channel();
            let (release_tx, release_rx) = mpsc::channel();
            let browser = Self::new(Behaviour::Gated(BrowserGate {
                entered: entered_tx,
                release: Mutex::new(release_rx),
            }));
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
                    Behaviour::Panic => panic!("the browser was told to panic mid-crawl"),
                    Behaviour::Gated(gate) => {
                        let _ = gate.entered.send(());
                        // Parks this thread, deliberately: the crawl is "in flight"
                        // until the test drops `Gate::release` (recv then errors).
                        let _ = gate.release.lock().expect("release lock").recv();
                    }
                }
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
            }
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

    /// A `ProxyClient` the command must never reach: discovery is read-only and
    /// crawls through the browser, never the proxy client.
    struct NoSendClient;

    impl ProxyClient for NoSendClient {
        fn send(&self, req: HttpRequest) -> BoxFuture<'_, anyhow::Result<HttpFlow>> {
            panic!("scan.discover must not send through the proxy client: {req:?}");
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

    /// A site served by a [`CapturingBrowser`] over one shared store, scanned
    /// as many times as a test likes: every `scan()` is a full `scan.discover`
    /// of `http://target.test/`, and the store keeps each earlier scan's
    /// captures, exactly as the proxy's would.
    struct Site {
        store: Arc<MemFlowStore>,
        browser: CapturingBrowser,
        guard: StdGuard,
        client: NoSendClient,
        cmd: ScanDiscover,
    }

    impl Site {
        fn new(pages: &[(&str, &str)]) -> Self {
            let store = Arc::new(MemFlowStore::new());
            Self {
                browser: CapturingBrowser::new(store.clone(), pages),
                store,
                guard: scoped_guard(),
                client: NoSendClient,
                cmd: ScanDiscover::new(ScannerConfig::default()),
            }
        }

        fn scan(&self) -> Value {
            let host =
                CommandHost::new(&*self.store, &self.client, &self.guard, Some(&self.browser));
            self.cmd
                .invoke(
                    params(&[("target", Value::Str("http://target.test/".into()))]),
                    &host,
                )
                .expect("an in-scope seed crawls")
        }
    }

    #[test]
    fn scan_discover_is_write() {
        let cmd = ScanDiscover::new(ScannerConfig::default());
        assert_eq!(cmd.sensitivity(), Sensitivity::Write);
    }

    /// The description MCP clients read says a second concurrent scan is refused,
    /// so an agent knows to wait rather than retry.
    #[test]
    fn schema_description_says_only_one_discovery_runs_at_a_time() {
        let description = ScanDiscover::new(ScannerConfig::default())
            .schema()
            .description;
        assert!(
            description.contains("Only one discovery runs at a time"),
            "the single-flight rule is in the description: {description}"
        );
        assert!(
            description.contains("refused immediately"),
            "the description says a second call is refused: {description}"
        );
    }

    #[test]
    fn scan_discover_out_of_scope_refused() {
        let store = MemFlowStore::new();
        let guard = StdGuard::default(); // empty scope: deny-by-default
        let client = NoSendClient;
        let host = CommandHost::new(&store, &client, &guard, None);
        let cmd = ScanDiscover::new(ScannerConfig::default());

        let err = cmd
            .invoke(
                params(&[("target", Value::Str("http://unscoped.example/".into()))]),
                &host,
            )
            .expect_err("an out-of-scope target is refused before any crawl");
        assert_eq!(
            err.downcast_ref::<GuardError>(),
            Some(&GuardError::OutOfScope("unscoped.example:80".into()))
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
        let store = MemFlowStore::new();
        store.insert(captured("/x?access_token=s3cr3t-value&q=1", headers));
        let guard = scoped_guard();
        let client = NoSendClient;
        let host = CommandHost::new(&store, &client, &guard, None);
        let cmd = ScanDiscover::new(ScannerConfig::default());

        let result = cmd
            .invoke(
                params(&[("target", Value::Str("http://target.test/".into()))]),
                &host,
            )
            .expect("an in-scope target with no browser falls back to the store");

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
        let store = MemFlowStore::new();
        store.insert(captured("/one?q=1", HeaderMap::new()));
        let guard = scoped_guard();
        let client = NoSendClient;
        let host = CommandHost::new(&store, &client, &guard, None);
        let cmd = ScanDiscover::new(ScannerConfig::default());

        let result = cmd
            .invoke(
                params(&[("target", Value::Str("http://target.test/".into()))]),
                &host,
            )
            .expect("an in-scope target with no browser falls back to the store");

        let Value::Object(map) = &result else {
            panic!("object result: {result:?}");
        };
        let endpoint = endpoints_of(&result)
            .into_iter()
            .next()
            .expect("one reached endpoint");
        assert_eq!(endpoint, "http://target.test/one?q=1");

        // endpoint_flows links that endpoint to a flow id...
        let Some(Value::Object(ef)) = map.get("endpoint_flows") else {
            panic!("the result carries an endpoint_flows map: {result:?}");
        };
        let Some(Value::Str(flow_id)) = ef.get(&endpoint) else {
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

    /// The seed is gated exactly once: with a concurrency cap of one, a second
    /// `check_active` for the same seed would refuse the command's own crawl.
    #[test]
    fn scan_discover_runs_under_max_concurrency_one() {
        let store = MemFlowStore::new();
        store.insert(captured("/one", HeaderMap::new()));
        let guard = StdGuard::new(aitm_core::LimitConfig {
            max_concurrency: 1,
            ..aitm_core::LimitConfig::default()
        });
        guard.add_scope(ScopeEntry {
            host: "target.test".into(),
        });
        let client = NoSendClient;
        let host = CommandHost::new(&store, &client, &guard, None);
        let cmd = ScanDiscover::new(ScannerConfig::default());

        let result = cmd
            .invoke(
                params(&[("target", Value::Str("http://target.test/".into()))]),
                &host,
            )
            .expect("one permit for the seed, not two");

        assert_eq!(endpoints_of(&result), vec!["http://target.test/one"]);
    }

    /// `max_pages` may lower the configured cap.
    #[test]
    fn scan_discover_max_pages_lowers_the_cap() {
        let store = MemFlowStore::new();
        store.insert(captured("/one", HeaderMap::new()));
        store.insert(captured("/two", HeaderMap::new()));
        store.insert(captured("/three", HeaderMap::new()));
        let guard = scoped_guard();
        let client = NoSendClient;
        let host = CommandHost::new(&store, &client, &guard, None);
        let cmd = ScanDiscover::new(ScannerConfig::default());

        let result = cmd
            .invoke(
                params(&[
                    ("target", Value::Str("http://target.test/".into())),
                    ("max_pages", Value::Int(1)),
                ]),
                &host,
            )
            .expect("scan.discover succeeds");

        assert_eq!(endpoints_of(&result), vec!["http://target.test/one"]);
    }

    /// `max_pages` may never raise it.
    #[test]
    fn scan_discover_max_pages_cannot_raise_the_cap() {
        let store = MemFlowStore::new();
        store.insert(captured("/one", HeaderMap::new()));
        store.insert(captured("/two", HeaderMap::new()));
        store.insert(captured("/three", HeaderMap::new()));
        let guard = scoped_guard();
        let client = NoSendClient;
        let host = CommandHost::new(&store, &client, &guard, None);
        let cmd = ScanDiscover::new(ScannerConfig {
            max_pages: 2,
            ..ScannerConfig::default()
        });

        let result = cmd
            .invoke(
                params(&[
                    ("target", Value::Str("http://target.test/".into())),
                    ("max_pages", Value::Int(500)),
                ]),
                &host,
            )
            .expect("scan.discover succeeds");

        assert_eq!(
            endpoints_of(&result),
            vec!["http://target.test/one", "http://target.test/two"],
            "the configured cap of 2 holds against a request for 500"
        );
    }

    #[test]
    fn scan_discover_rejects_a_negative_budget() {
        let store = MemFlowStore::new();
        let guard = scoped_guard();
        let client = NoSendClient;
        let host = CommandHost::new(&store, &client, &guard, None);
        let cmd = ScanDiscover::new(ScannerConfig::default());

        let err = cmd
            .invoke(
                params(&[
                    ("target", Value::Str("http://target.test/".into())),
                    ("max_depth", Value::Int(-1)),
                ]),
                &host,
            )
            .expect_err("a negative budget is an error, not a wrap-around");
        assert!(
            err.to_string().contains("non-negative"),
            "explains the refusal: {err}"
        );
    }

    /// S2, the real fix: the crawl runs under a campaign hold on the proxy's
    /// browser-egress posture, so every navigation the browser issues happens
    /// while the `SsrfConnector` refuses out-of-scope public hosts — and the
    /// hold is released the moment `invoke` returns, leaving the standing (off)
    /// base untouched.
    #[test]
    fn scan_discover_crawls_under_egress_confinement() {
        let posture = Arc::new(EgressConfinement::new(false));
        let browser = PostureProbeBrowser::new(posture.clone());
        let store = MemFlowStore::new();
        let guard = scoped_guard();
        let client = NoSendClient;
        let host =
            CommandHost::new(&store, &client, &guard, Some(&browser)).with_egress(posture.clone());
        let cmd = ScanDiscover::new(ScannerConfig::default());
        assert!(!posture.confined(), "fixture starts with the free posture");

        let result = cmd
            .invoke(
                params(&[("target", Value::Str("http://target.test/".into()))]),
                &host,
            )
            .expect("an in-scope seed crawls");

        // The crawl really navigated (seed + the one harvested link).
        assert_eq!(
            endpoints_of(&result),
            vec!["http://target.test/", "http://target.test/one"]
        );
        // (a) every navigation saw the posture confined.
        assert_eq!(
            browser.observed(),
            vec![true, true],
            "each navigation must run while egress is confined"
        );
        // (b) the hold is released when the command returns: the base was off
        // and stays off, so a finished scan never leaves the browser confined.
        assert!(
            !posture.confined(),
            "the campaign hold must be released after invoke returns"
        );
    }

    /// Without a wired posture (a frontend that never attached one) the crawl
    /// runs exactly as before: there is nothing to hold, and nothing errors.
    #[test]
    fn scan_discover_without_egress_handle_still_crawls() {
        let store = MemFlowStore::new();
        store.insert(captured("/one", HeaderMap::new()));
        let guard = scoped_guard();
        let client = NoSendClient;
        let host = CommandHost::new(&store, &client, &guard, None);
        assert!(host.egress_handle().is_none());
        let cmd = ScanDiscover::new(ScannerConfig::default());

        let result = cmd
            .invoke(
                params(&[("target", Value::Str("http://target.test/".into()))]),
                &host,
            )
            .expect("no posture wired is not an error");
        assert_eq!(endpoints_of(&result), vec!["http://target.test/one"]);
    }

    /// The target gate and the crawl use one parser, so a URL whose real host is
    /// `evil.com` is refused even under a `*.target.test` scope entry.
    #[test]
    fn scan_discover_refuses_a_backslash_host_bypass() {
        let store = MemFlowStore::new();
        let guard = StdGuard::default();
        guard.add_scope(ScopeEntry {
            host: "*.target.test".into(),
        });
        let client = NoSendClient;
        let host = CommandHost::new(&store, &client, &guard, None);
        let cmd = ScanDiscover::new(ScannerConfig::default());

        let err = cmd
            .invoke(
                params(&[(
                    "target",
                    Value::Str("http://evil.com\\.target.test/".into()),
                )]),
                &host,
            )
            .expect_err("the real host is out of scope");
        assert_eq!(
            err.downcast_ref::<GuardError>(),
            Some(&GuardError::OutOfScope("evil.com:80".into()))
        );
    }

    /// The seed every single-flight test scans.
    fn seed() -> Params {
        params(&[("target", Value::Str("http://target.test/".into()))])
    }

    /// There is one browser page, shared by every crawl. Two scans at once would
    /// interleave their navigations on it (one scan harvests the other's pages),
    /// so a second `scan.discover` is refused up front — before it touches the
    /// browser — and the one already running is unharmed.
    #[test]
    fn overlapping_scan_is_refused_without_touching_the_browser() {
        let cmd = ScanDiscover::new(ScannerConfig::default());
        let (first_browser, gate) = GatedBrowser::gated();
        let second_browser = GatedBrowser::open();
        let client = NoSendClient;
        let first_store = MemFlowStore::new();
        let first_guard = scoped_guard();
        let second_store = MemFlowStore::new();
        let second_guard = scoped_guard();

        let with_budget = |name: &str| {
            params(&[
                ("target", Value::Str("http://target.test/".into())),
                (name, Value::Int(-1)),
            ])
        };

        let (entered, missing, negative_depth, negative_pages, second, first) =
            std::thread::scope(|s| {
                let first = s.spawn(|| {
                    let host =
                        CommandHost::new(&first_store, &client, &first_guard, Some(&first_browser));
                    cmd.invoke(seed(), &host)
                });
                // Scan #1 is now parked inside the browser, mid-crawl.
                let entered = gate.entered.recv_timeout(Duration::from_secs(10));

                let host =
                    CommandHost::new(&second_store, &client, &second_guard, Some(&second_browser));
                // A malformed call is still told what is wrong with it, not that
                // another scan is running: every argument is validated before the
                // claim, whether it is missing or out of range.
                let missing = cmd.invoke(params(&[]), &host);
                let negative_depth = cmd.invoke(with_budget("max_depth"), &host);
                let negative_pages = cmd.invoke(with_budget("max_pages"), &host);
                let second = cmd.invoke(seed(), &host);

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
        assert_eq!(
            second_browser.navigations(),
            0,
            "the refused scan must not touch the browser"
        );

        let first = first.expect("scan #1 is unharmed by the refused overlap");
        assert_eq!(
            endpoints_of(&first),
            vec!["http://target.test/", "http://target.test/one"]
        );
        assert_eq!(first_browser.navigations(), 2);
    }

    /// The browser needs no reset between crawls: scans run one after another on
    /// the same command each see the whole target, so single-flight must hold the
    /// slot only while a scan is running.
    #[test]
    fn scan_runs_again_after_the_previous_one_finished() {
        let cmd = ScanDiscover::new(ScannerConfig::default());
        let browser = GatedBrowser::open();
        let store = MemFlowStore::new();
        let guard = scoped_guard();
        let client = NoSendClient;
        let host = CommandHost::new(&store, &client, &guard, Some(&browser));

        for round in 1..=3 {
            let result = cmd
                .invoke(seed(), &host)
                .unwrap_or_else(|err| panic!("scan #{round} must run: {err}"));
            assert_eq!(
                endpoints_of(&result),
                vec!["http://target.test/", "http://target.test/one"],
                "scan #{round} crawls the whole target"
            );
        }
        assert_eq!(browser.navigations(), 6, "three scans, two pages each");
    }

    /// A scan that ends in an error must give the slot back: the next scan is
    /// not refused as "already running".
    #[test]
    fn slot_is_released_when_a_scan_errors() {
        let cmd = ScanDiscover::new(ScannerConfig::default());
        let browser = GatedBrowser::open();
        let store = MemFlowStore::new();
        let guard = scoped_guard();
        let client = NoSendClient;
        let host = CommandHost::new(&store, &client, &guard, Some(&browser));

        // An out-of-scope seed fails the crawl itself, after the slot is taken.
        let err = cmd
            .invoke(
                params(&[("target", Value::Str("http://unscoped.example/".into()))]),
                &host,
            )
            .expect_err("an out-of-scope target is refused");
        assert_eq!(
            err.downcast_ref::<GuardError>(),
            Some(&GuardError::OutOfScope("unscoped.example:80".into()))
        );

        let result = cmd
            .invoke(seed(), &host)
            .expect("the failed scan released the slot");
        assert_eq!(
            endpoints_of(&result),
            vec!["http://target.test/", "http://target.test/one"]
        );
    }

    /// Nor may a scan that panics wedge the command: unwinding releases the slot.
    #[test]
    fn slot_is_released_when_a_scan_panics() {
        let cmd = ScanDiscover::new(ScannerConfig::default());
        let client = NoSendClient;

        let panicking = GatedBrowser::panicking();
        let store = MemFlowStore::new();
        let guard = scoped_guard();
        let host = CommandHost::new(&store, &client, &guard, Some(&panicking));
        let outcome = std::panic::catch_unwind(AssertUnwindSafe(|| cmd.invoke(seed(), &host)));
        assert!(outcome.is_err(), "the browser panicked mid-crawl");
        assert_eq!(panicking.navigations(), 1);

        let browser = GatedBrowser::open();
        let store = MemFlowStore::new();
        let guard = scoped_guard();
        let host = CommandHost::new(&store, &client, &guard, Some(&browser));
        let result = cmd
            .invoke(seed(), &host)
            .expect("the unwound scan released the slot");
        assert_eq!(
            endpoints_of(&result),
            vec!["http://target.test/", "http://target.test/one"]
        );
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
                "http://target.test/",
                "http://target.test/search?q=hello",
                "http://target.test/account/1",
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
        // Scan 2's flow for each URL.
        let newest: BTreeMap<String, String> = all[3..]
            .iter()
            .map(|id| (urls[&id.to_string()].clone(), id.to_string()))
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
                newest.get(&urls[&p.flow]),
                Some(&p.flow),
                "injection point must carry scan 2's flow for its URL: {p:?}"
            );
        }
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
        let store = MemFlowStore::new();
        for i in 0..ENDPOINTS {
            store.insert(captured(&format!("/p{i}?a=1&b=2"), HeaderMap::new()));
        }
        let newest = store
            .insert(captured("/p0?a=1&b=2", HeaderMap::new()))
            .to_string();
        let guard = scoped_guard();
        let client = NoSendClient;
        let host = CommandHost::new(&store, &client, &guard, None);
        let cmd = ScanDiscover::new(ScannerConfig {
            // The no-browser fallback lists at most `max_pages` endpoints;
            // raise it so all 600 are reached and the point cap is the
            // only bound in play.
            max_pages: 2048,
            ..ScannerConfig::default()
        });

        let result = cmd
            .invoke(
                params(&[("target", Value::Str("http://target.test/".into()))]),
                &host,
            )
            .expect("an in-scope target with no browser falls back to the store");

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
        let store = MemFlowStore::new();
        let guard = scoped_guard();
        let client = NoSendClient;
        let mut host = CommandHost::new(&store, &client, &guard, None);
        if let Some(dir) = dir {
            host = host.with_config(Arc::new(Config {
                findings: FindingsConfig {
                    dir: Some(dir.0.clone()),
                },
                ..Config::default()
            }));
        }
        ScanReport.invoke(args, &host)
    }

    /// A `scan.report` result split into `report_md` and its `index` objects.
    fn report_parts(result: &Value) -> (String, Vec<BTreeMap<String, Value>>) {
        let Value::Object(map) = result else {
            panic!("the result is an object: {result:?}");
        };
        assert_eq!(
            map.keys().map(String::as_str).collect::<Vec<_>>(),
            vec!["index", "report_md"],
            "the result carries exactly `report_md` and `index`: {result:?}"
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
        let cmd = ScanReport;
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

        let result = report_value(std::slice::from_ref(&rec));

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

        let result = report_value(&recs);

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
}
