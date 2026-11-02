//! The uniform manual `check.<id>` command every catalogue entry gets
//! (spec D4, plan call B8).
//!
//! A check is written once — as a Rust [`aitm_scan_model::Check`] or as a Rhai
//! `reg.add_check` closure — and is then reachable two ways: scheduled inside a
//! job by `scan.start`, and by hand on one query parameter through
//! `check.<id>`. The manual path exists because the shipped scanner's hand-run
//! verbs were the operator's fastest loop, and because a native check that
//! could only run inside a job would be untestable by hand.
//!
//! What a manual run is **not** is a way around the job model's budget and
//! gates. It builds a one-shot [`ManualJob`] over the same
//! [`crate::client::JobClient`] a job uses, so every probe is scope-checked,
//! rate-paced, budgeted (64 probes), bounded by `scanner.check_timeout_s`, and
//! recorded under the same policy. The verb is `Sensitive` for the same reason
//! `scan.start` is (spec D4, "Tier laundering guard").
//!
//! The synthetic point never enters the proxy's flow store. The command mints a
//! captured-looking `HttpFlow` for `url` with `param` set, puts it in a
//! **private** [`aitm_core::MemFlowStore`] that lives for the call, and lets the
//! interim HTTP lane discover and host the point out of that store. The
//! operator's capture list is untouched.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Instant, SystemTime};

use aitm_core::{
    Body, Command, CommandHost, ConnInfo, Flow, FlowId, FlowMeta, FlowStore, HeaderMap, HttpFlow,
    HttpRequest, HttpVersion, InterceptState, MemFlowStore, ParamDef, ParamSchema, Params,
    ProxyClient, Registry, Sensitivity, TypeDesc, Value,
};
use aitm_scan_model::{
    scan_error, Check, InsertionKind, JobCtx, LaneKind, ProfileTarget, ScanErrorCode, ScanProfile,
    SessionMaterial,
};
use tokio_util::sync::CancellationToken;

use crate::client::{bounded_await, JobBudget, JobClient, ProbeMeter};
use crate::jobs::Engine;
use crate::util;
use crate::verbs::result_of;

/// Probes one manual run may spend. Generous enough for the heaviest shipped
/// check's payload list, small enough that a mistyped `url` cannot turn into a
/// scan.
const MANUAL_PROBE_BUDGET: u32 = 64;

/// The default value placed at the point when the caller names none.
const DEFAULT_VALUE: &str = "1";

/// One catalogue entry's manual command (spec D4).
pub struct ManualCheck {
    engine: Arc<Engine>,
    check: Arc<dyn Check>,
    /// `check.<id>`, held because [`Command::name`] returns a borrow.
    name: String,
}

impl ManualCheck {
    /// The manual command for `check`.
    pub fn new(engine: &Arc<Engine>, check: Arc<dyn Check>) -> Self {
        let name = format!("check.{}", check.meta().id);
        Self {
            engine: Arc::clone(engine),
            check,
            name,
        }
    }
}

/// Register one [`ManualCheck`] per catalogue entry (spec D4, call B8).
///
/// A command of that name already on the registry **wins**: a track-3 script
/// that declares a check *and* still calls `add_command("check.sqli")` keeps
/// its own command, and the scanner says so rather than silently shadowing it.
pub fn register_all(engine: &Arc<Engine>, reg: &mut Registry) {
    for check in engine.catalogue().all() {
        let command = ManualCheck::new(engine, Arc::clone(check));
        if reg.command(&command.name).is_some() {
            tracing::info!(
                target: "aitm::scanner",
                command = %command.name,
                "a command of that name is already registered; the scanner does not add its own"
            );
            continue;
        }
        reg.add_command(Arc::new(command));
    }
}

impl Command for ManualCheck {
    fn name(&self) -> &str {
        &self.name
    }

    fn sensitivity(&self) -> Sensitivity {
        // Spec D4: a manual check run sends real payloads at a real target.
        // Its tier does not depend on what the check does — a script could not
        // otherwise be trusted to classify itself.
        Sensitivity::Sensitive
    }

    fn schema(&self) -> ParamSchema {
        let meta = self.check.meta();
        ParamSchema {
            description: format!(
                "{} Manual run of catalogue check `{}` on one query parameter. The URL's \
                 origin must be in the HTTP scope; the request is synthesized in memory and \
                 never enters the flow store. Probes are budgeted ({MANUAL_PROBE_BUDGET}) \
                 and bounded by `scanner.check_timeout_s`.",
                meta.description, meta.id
            ),
            params: vec![
                ParamDef {
                    name: "url".into(),
                    ty: TypeDesc::Str,
                    required: true,
                    description: "The in-scope request URL, e.g. \
                                  `https://app.example/search?q=1`."
                        .into(),
                },
                ParamDef {
                    name: "param".into(),
                    ty: TypeDesc::Str,
                    required: true,
                    description: "The query parameter to place payloads in.".into(),
                },
                ParamDef {
                    name: "value".into(),
                    ty: TypeDesc::Str,
                    required: false,
                    description: "The parameter's benign baseline value. Default `1`.".into(),
                },
            ],
            result: TypeDesc::Object(Vec::new()),
        }
    }

    fn invoke(&self, args: Params, _host: &CommandHost) -> anyhow::Result<Value> {
        let services = self.engine.late.get()?;
        let raw_url = args.get_str("url")?;
        let param = args.get_str("param")?.to_string();
        if param.is_empty() {
            return Err(scan_error(
                ScanErrorCode::InvalidProfile,
                "`param` must name a query parameter",
            ));
        }
        let value = match args.get("value") {
            None | Some(Value::Null) => DEFAULT_VALUE.to_string(),
            Some(_) => args.get_str("value")?.to_string(),
        };

        let request = synthetic_request(raw_url, &param, &value)?;
        let origin = util::origin_key(&request.scheme, &request.authority);
        // Deny-by-default, before anything is synthesized or sent. The guard is
        // asked about the same `host:port` it will see at request time (the
        // explicit port, else the scheme default): a ported scope entry matches
        // only on port equality, so a bare host would never be admitted by it.
        if !services
            .guard
            .in_scope(&util::guard_authority(&request.scheme, &request.authority))
        {
            return Err(scan_error(
                ScanErrorCode::OutOfScope,
                format!("{origin} is not in the HTTP scope"),
            ));
        }

        // The synthetic capture lives in a store of its own, for this call
        // only: the lane needs a flow to derive and host the point from, and
        // the operator's capture list must not grow a request nobody made.
        let scratch: Arc<dyn FlowStore> = Arc::new(MemFlowStore::new());
        scratch.insert(Flow::Http(synthetic_flow(request)));

        let job_id = util::job_id();
        let profile = manual_profile(&origin, self.engine.cfg.check_timeout_s);
        let cancel = CancellationToken::new();
        let deadline = crate::jobs::deadline_in(profile.budget.time_s);
        let budget = Arc::new(JobBudget::new(
            u64::from(MANUAL_PROBE_BUDGET),
            deadline,
            cancel.clone(),
        ));
        let client: Arc<dyn ProxyClient> = Arc::new(JobClient::new(
            Arc::clone(&services.client),
            &job_id,
            Arc::clone(&budget),
            Arc::new(ProbeMeter::default()),
            profile.http.record_probes,
            profile.http.version,
            profile.budget.per_host_errors.clone(),
        ));

        let job: Arc<dyn JobCtx> = Arc::new(ManualJob {
            job: job_id,
            profile: profile.clone(),
            client,
            store: Arc::clone(&scratch),
            guard: Arc::clone(&services.guard),
            budget,
            markers: AtomicU32::new(0),
            marker_seed: util::marker_seed(),
        });

        // The interim HTTP lane owns the only shape a manual run has: a query
        // point on a captured request. Letting it *discover* the point rather
        // than hand-building one keeps the point id, traits and example in one
        // place, so `probe_host_for` can always match the point back.
        let lane = Arc::clone(&self.engine.interim);
        let target = ProfileTarget {
            origins: vec![origin.clone()],
            l4: Vec::new(),
        };
        let check = Arc::clone(&self.check);
        let timeout_s = profile.budget.check_timeout_s;

        let verdict = crate::crawl::block_on(async move {
            let discovery = lane.discover(&target, job.as_ref()).await?;
            let point = discovery
                .points
                .into_iter()
                .find(|p| p.kind == InsertionKind::Query && p.name == param)
                .ok_or_else(|| {
                    scan_error(
                        ScanErrorCode::InvalidProfile,
                        format!("`{param}` is not a query parameter of that url"),
                    )
                })?;
            // Behind an `Arc`, as the worker hands it (amendment 62): a
            // script check borrows the host through `shared()` for the
            // length of its run and errors out before sending a byte when
            // there is none to borrow.
            let host =
                crate::worker::ArcHost(Arc::from(lane.probe_host_for(&point, Arc::clone(&job))?));
            bounded_await(job.deadline(), &cancel, check.run(&point, &host))
                .await
                .map_err(|_| {
                    anyhow::anyhow!(
                        "check `{}` did not finish within {timeout_s}s",
                        check.meta().id
                    )
                })
        })?;

        // The verdict goes straight back to the bus caller, so it gets the
        // scrub the job path's worker applies when it files an issue (spec
        // D8.1, amendment 56); a native check that echoes a credential from a
        // response leaks nothing through `check.<id>`. `Verdict::scrubbed` is
        // the model's one shared rule (amendment 67): `detail` and evidence,
        // root and every sibling, scrub then bound; idempotent, so a Rhai
        // verdict the bridge already scrubbed comes through unchanged.
        result_of(&verdict.scrubbed())
    }
}

/// The request a manual run probes: `url` with `param` set to `value`.
///
/// Refused with `invalid_profile` for anything that is not an absolute
/// `http`/`https` URL, because the point's lane is the HTTP one.
fn synthetic_request(raw: &str, param: &str, value: &str) -> anyhow::Result<HttpRequest> {
    let mut url = url::Url::parse(raw.trim()).map_err(|e| {
        scan_error(
            ScanErrorCode::InvalidProfile,
            format!("`url`: `{raw}` is not a url: {e}"),
        )
    })?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(scan_error(
            ScanErrorCode::InvalidProfile,
            format!("`url`: `{raw}` is not an http or https url"),
        ));
    }
    if url.host_str().is_none() {
        return Err(scan_error(
            ScanErrorCode::InvalidProfile,
            format!("`url`: `{raw}` has no host"),
        ));
    }
    // The named parameter is set, replacing any the caller's url already had,
    // so the point the lane derives is exactly the one asked for.
    let kept: Vec<(String, String)> = url
        .query_pairs()
        .filter(|(name, _)| name != param)
        .map(|(name, value)| (name.into_owned(), value.into_owned()))
        .collect();
    {
        let mut pairs = url.query_pairs_mut();
        pairs.clear();
        for (name, existing) in &kept {
            pairs.append_pair(name, existing);
        }
        pairs.append_pair(param, value);
    }

    let scheme = url.scheme().to_string();
    let authority = match url.port() {
        Some(port) => format!("{}:{port}", url.host_str().unwrap_or_default()),
        None => url.host_str().unwrap_or_default().to_string(),
    };
    let path = match url.query() {
        Some(query) => format!("{}?{query}", url.path()),
        None => url.path().to_string(),
    };
    let mut headers = HeaderMap::new();
    headers.set("Host", &authority);
    Ok(HttpRequest {
        method: "GET".into(),
        scheme,
        authority,
        path,
        version: HttpVersion::Http11,
        headers,
        body: Body::Empty,
        timestamp: SystemTime::now(),
    })
}

/// The captured-looking flow the lane derives the point from. It has no
/// response: the host fetches its own baseline through the job's client.
fn synthetic_flow(request: HttpRequest) -> HttpFlow {
    HttpFlow {
        id: FlowId::new(),
        request,
        response: None,
        client_conn: ConnInfo {
            peer: "127.0.0.1:0".parse().unwrap_or_else(|_| {
                std::net::SocketAddr::new(std::net::IpAddr::from([127, 0, 0, 1]), 0)
            }),
            sni: None,
            alpn: None,
            tls: false,
            established: SystemTime::now(),
        },
        server_conn: None,
        metadata: FlowMeta::default(),
        intercept: InterceptState::Observed,
    }
}

/// The profile a manual run reads its knobs from: one origin, HTTP only, no
/// crawl, the configured per-check timeout.
fn manual_profile(origin: &str, check_timeout_s: u64) -> ScanProfile {
    let mut profile = ScanProfile {
        name: "manual-check".to_string(),
        target: ProfileTarget {
            origins: vec![origin.to_string()],
            l4: Vec::new(),
        },
        lanes: vec![LaneKind::Http],
        ..ScanProfile::default()
    };
    profile.budget.probes = MANUAL_PROBE_BUDGET;
    // One check's wall budget is the whole run's: there is only one check.
    profile.budget.time_s = check_timeout_s.max(1);
    profile.budget.check_timeout_s = check_timeout_s.max(1);
    // A manual run never crawls; the point is the one the caller named.
    profile.crawl.max_pages = 0;
    profile
}

/// The one-shot [`JobCtx`] a manual run hands the lane.
///
/// It reports no L4 counters, loses no session and holds no browser: a manual
/// run is one check against one point, and the default bodies of those hooks
/// are exactly right.
struct ManualJob {
    job: String,
    profile: ScanProfile,
    client: Arc<dyn ProxyClient>,
    store: Arc<dyn FlowStore>,
    guard: Arc<dyn aitm_core::ScopeRateGuard>,
    budget: Arc<JobBudget>,
    /// The per-call marker counter, as wide as [`util::marker`]'s.
    markers: AtomicU32,
    /// Minted per invocation (amendment 55): a manual run's markers are as
    /// unguessable up front as a job's.
    marker_seed: u32,
}

impl JobCtx for ManualJob {
    fn job_id(&self) -> &str {
        &self.job
    }

    fn profile(&self) -> &ScanProfile {
        &self.profile
    }

    fn client(&self) -> Arc<dyn ProxyClient> {
        Arc::clone(&self.client)
    }

    fn store(&self) -> Arc<dyn FlowStore> {
        Arc::clone(&self.store)
    }

    fn guard(&self) -> Arc<dyn aitm_core::ScopeRateGuard> {
        Arc::clone(&self.guard)
    }

    fn browser(&self) -> Option<Arc<dyn aitm_core::BrowserDriver>> {
        None
    }

    fn session(&self) -> Option<Arc<SessionMaterial>> {
        None
    }

    fn charge(&self, units: u32) -> bool {
        self.budget.charge(units)
    }

    fn budget_left(&self) -> u32 {
        self.budget.left()
    }

    fn deadline(&self) -> Instant {
        self.budget.deadline
    }

    fn cancelled(&self) -> bool {
        self.budget.cancel.is_cancelled()
    }

    /// Fresh per call (amendment 57), seeded per invocation (amendment 55).
    fn marker(&self) -> String {
        let counter = self.markers.fetch_add(1, Ordering::SeqCst);
        util::marker(self.marker_seed, counter)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use std::time::SystemTime;

    use aitm_core::{
        AgentPolicy, Body, Command, CommandHost, ConnInfo, FlowStore, HeaderMap, HttpFlow,
        HttpRequest, HttpResponse, HttpVersion, JobBus, MemFlowStore, Params, ProxyClient,
        Registry, ScopeEntry, ScopeRateGuard, SendOptions, Sensitivity, StdGuard, Value,
    };
    use aitm_scan_model::check::{CheckMeta, Evidence, Verdict};
    use aitm_scan_model::point::InsertionPoint;
    use aitm_scan_model::testing::null_meta;
    use aitm_scan_model::traits::{Check, ProbeHost};
    use aitm_scan_model::vocab::{Confidence, Outcome};
    use aitm_scan_model::{ScanErrorCode, ScanRefusal};
    use futures::future::BoxFuture;

    use crate::config::ScannerConfig;
    use crate::jobs::ScanServices;
    use crate::plugin::ScannerPlugin;

    /// A native check whose evidence echoes what a target's response carried —
    /// a session cookie and a bearer token — the way a real check's `matched`
    /// excerpt and `payload` would. It sends nothing; the leak is in the verdict.
    struct LeakyCheck {
        meta: CheckMeta,
    }

    impl LeakyCheck {
        fn new() -> Self {
            Self {
                meta: null_meta("leaky-echo"),
            }
        }
    }

    impl Check for LeakyCheck {
        fn meta(&self) -> &CheckMeta {
            &self.meta
        }

        fn run<'a>(
            &'a self,
            _point: &'a InsertionPoint,
            _host: &'a dyn ProbeHost,
        ) -> BoxFuture<'a, Verdict> {
            Box::pin(async {
                Verdict {
                    outcome: Outcome::Vulnerable,
                    confidence: Confidence::Firm,
                    evidence: Evidence {
                        payload: Some("q=1&access_token=tok-123".to_string()),
                        matched: Some(
                            "Cookie: sid=s3cr3t-cookie; Authorization: Bearer abc.def.ghi"
                                .to_string(),
                        ),
                        ..Evidence::default()
                    },
                    detail: "echo: Authorization: Bearer abc.def.ghi".to_string(),
                    poc_hint: None,
                    location: None,
                    more: Vec::new(),
                }
            })
        }
    }

    /// A native check whose `matched` is long enough that the excerpt bound
    /// bites, with the secrets at the end, and which also returns a sibling
    /// verdict carrying its own leak. Both are what a real check produces when
    /// it quotes a whole response header block.
    struct LoudLeakyCheck {
        meta: CheckMeta,
    }

    impl LoudLeakyCheck {
        /// The same shape the Rhai bridge's order test uses: 230 bytes of
        /// padding, then a cookie and an `Authorization` line.
        fn matched() -> String {
            format!(
                "{} Cookie: sid=s3cr3t-cookie; Authorization: Bearer abc.def.ghi",
                "a".repeat(230)
            )
        }

        fn new() -> Self {
            Self {
                meta: null_meta("loud-echo"),
            }
        }
    }

    impl Check for LoudLeakyCheck {
        fn meta(&self) -> &CheckMeta {
            &self.meta
        }

        fn run<'a>(
            &'a self,
            _point: &'a InsertionPoint,
            _host: &'a dyn ProbeHost,
        ) -> BoxFuture<'a, Verdict> {
            Box::pin(async {
                Verdict {
                    outcome: Outcome::Vulnerable,
                    confidence: Confidence::Firm,
                    evidence: Evidence {
                        matched: Some(Self::matched()),
                        ..Evidence::default()
                    },
                    detail: "loud".to_string(),
                    poc_hint: None,
                    location: None,
                    more: vec![Verdict {
                        outcome: Outcome::Vulnerable,
                        confidence: Confidence::Firm,
                        evidence: Evidence {
                            payload: Some("sid=s3cr3t-cookie".to_string()),
                            matched: Some("Cookie: sid=s3cr3t-cookie".to_string()),
                            ..Evidence::default()
                        },
                        detail: "sibling: Authorization: Bearer abc.def.ghi".to_string(),
                        poc_hint: None,
                        location: None,
                        more: Vec::new(),
                    }],
                }
            })
        }
    }

    /// A native check that needs the host behind an `Arc` the way every Rhai
    /// script check does (the bridge errors with "ProbeHost::shared returned
    /// none" otherwise): `Vulnerable` when `shared()` gives one, `Error`
    /// naming the gap when it does not.
    struct SharingCheck {
        meta: CheckMeta,
    }

    impl SharingCheck {
        fn new() -> Self {
            Self {
                meta: null_meta("needs-shared"),
            }
        }
    }

    impl Check for SharingCheck {
        fn meta(&self) -> &CheckMeta {
            &self.meta
        }

        fn run<'a>(
            &'a self,
            _point: &'a InsertionPoint,
            host: &'a dyn ProbeHost,
        ) -> BoxFuture<'a, Verdict> {
            Box::pin(async move {
                let (outcome, detail) = match host.shared() {
                    Some(_) => (Outcome::Vulnerable, "shared host received"),
                    None => (Outcome::Error, "ProbeHost::shared returned none"),
                };
                Verdict {
                    outcome,
                    confidence: Confidence::Firm,
                    evidence: Evidence::default(),
                    detail: detail.to_string(),
                    poc_hint: None,
                    location: None,
                    more: Vec::new(),
                }
            })
        }
    }

    /// A client that answers every request with an HTML page echoing the
    /// decoded query values, so the interim `xss-reflected` check sees its
    /// marker come back unencoded.
    struct EchoClient {
        seen: std::sync::Mutex<Vec<String>>,
    }

    impl EchoClient {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                seen: std::sync::Mutex::new(Vec::new()),
            })
        }

        fn payloads(&self) -> Vec<String> {
            self.seen.lock().expect("seen lock").clone()
        }
    }

    impl ProxyClient for EchoClient {
        fn send(&self, req: HttpRequest) -> BoxFuture<'_, anyhow::Result<HttpFlow>> {
            self.send_opts(req, SendOptions::default())
        }

        fn send_opts(
            &self,
            req: HttpRequest,
            _opts: SendOptions,
        ) -> BoxFuture<'_, anyhow::Result<HttpFlow>> {
            Box::pin(async move {
                let query = req.path.split_once('?').map(|(_, q)| q).unwrap_or("");
                let echoed: Vec<String> = url::form_urlencoded::parse(query.as_bytes())
                    .map(|(_, value)| value.into_owned())
                    .collect();
                self.seen
                    .lock()
                    .expect("seen lock")
                    .extend(echoed.iter().cloned());
                let mut headers = HeaderMap::new();
                headers.set("Content-Type", "text/html; charset=utf-8");
                Ok(HttpFlow {
                    id: aitm_core::FlowId::new(),
                    request: req,
                    response: Some(HttpResponse {
                        status: 200,
                        version: HttpVersion::Http11,
                        headers,
                        trailers: HeaderMap::new(),
                        body: Body::Bytes(
                            format!("<html><body>{}</body></html>", echoed.join(" ")).into_bytes(),
                        ),
                        timestamp: SystemTime::now(),
                        peer: None,
                    }),
                    client_conn: ConnInfo {
                        peer: "127.0.0.1:0".parse().expect("loopback"),
                        sni: None,
                        alpn: None,
                        tls: false,
                        established: SystemTime::now(),
                    },
                    server_conn: None,
                    metadata: aitm_core::FlowMeta::default(),
                    intercept: aitm_core::InterceptState::Observed,
                })
            })
        }
    }

    struct Harness {
        reg: Registry,
        store: Arc<MemFlowStore>,
        guard: Arc<StdGuard>,
        client: Arc<EchoClient>,
    }

    impl Harness {
        fn new() -> Self {
            Self::with_checks(Vec::new())
        }

        /// A harness whose catalogue also holds `extra`, for a test that needs a
        /// check with a particular verdict beside the legacy natives.
        fn with_checks(extra: Vec<Arc<dyn Check>>) -> Self {
            let cfg = ScannerConfig::default();
            // The native slot holds the lane's two legacy active checks, standing
            // in for the T3 natives the binary puts there (PR 2a), so
            // `check.xss-reflected` exists to drive these tests with.
            let mut natives = crate::interim_lane::legacy_active_checks();
            natives.extend(extra);
            let plugin = ScannerPlugin::new(cfg.clone()).with_native_checks(natives);
            let late = plugin.late();
            let mut reg = Registry::new();
            reg.add_plugin(Box::new(plugin));

            let guard = Arc::new(StdGuard::default());
            guard.add_scope(ScopeEntry {
                host: "ex.test".into(),
            });
            let store = Arc::new(MemFlowStore::new());
            let client = EchoClient::new();
            assert!(late.bind(ScanServices {
                store: Arc::clone(&store) as Arc<dyn FlowStore>,
                client: Arc::clone(&client) as Arc<dyn ProxyClient>,
                guard: Arc::clone(&guard) as Arc<dyn aitm_core::ScopeRateGuard>,
                browser: None,
                egress: None,
                l4: None,
                jobs: Arc::new(JobBus::default()),
                agent_policy: Arc::new(|| AgentPolicy::Ask),
                rt: tokio::runtime::Handle::current(),
                config: Arc::new(aitm_core::Config::default()),
            }));
            Self {
                reg,
                store,
                guard,
                client,
            }
        }

        fn call(&self, name: &str, args: &[(&str, Value)]) -> anyhow::Result<Value> {
            let cmd = Arc::clone(
                self.reg
                    .command(name)
                    .unwrap_or_else(|| panic!("`{name}` is registered")),
            );
            let host = CommandHost::new(&*self.store, &*self.client, &*self.guard, None);
            cmd.invoke(
                Params::new(
                    args.iter()
                        .map(|(k, v)| ((*k).to_string(), v.clone()))
                        .collect(),
                ),
                &host,
            )
        }
    }

    fn s(v: &str) -> Value {
        Value::Str(v.to_string())
    }

    fn obj<'a>(value: &'a Value, key: &str) -> &'a Value {
        match value {
            Value::Object(map) => map
                .get(key)
                .unwrap_or_else(|| panic!("the result has a `{key}` key")),
            other => panic!("expected an object, got {other:?}"),
        }
    }

    fn code(err: &anyhow::Error) -> ScanErrorCode {
        err.downcast_ref::<ScanRefusal>()
            .unwrap_or_else(|| panic!("`{err}` is not a typed scan refusal"))
            .code
    }

    /// Spec D4: a catalogue check is invocable by hand on one query parameter,
    /// through a synthetic point that never enters the proxy's store.
    #[tokio::test(flavor = "multi_thread")]
    async fn manual_check_runs_one_check_on_a_query_point() {
        let h = Harness::new();
        let before = h.store.count();

        let result = h
            .call(
                "check.xss-reflected",
                &[("url", s("http://ex.test/search")), ("param", s("q"))],
            )
            .expect("the manual check runs");

        assert_eq!(obj(&result, "outcome"), &s("vulnerable"));
        let sent = h.client.payloads();
        assert!(
            sent.iter().any(|p| p.contains("aitm-canary")),
            "the check sent its marker: {sent:?}"
        );
        assert_eq!(
            h.store.count(),
            before,
            "the synthetic flow never entered the store"
        );
    }

    /// Amendment 62: the manual path hands the check a host whose `shared()`
    /// is `Some`, exactly as the worker does with `ArcHost`; otherwise every
    /// `check.<rhai-id>` verb errors before it sends a byte (T3's 2b live run).
    #[tokio::test(flavor = "multi_thread")]
    async fn manual_check_hands_a_shared_host_to_the_check() {
        let h = Harness::with_checks(vec![Arc::new(SharingCheck::new())]);

        let result = h
            .call(
                "check.needs-shared",
                &[("url", s("http://ex.test/search")), ("param", s("q"))],
            )
            .expect("the manual check runs");

        assert_eq!(
            obj(&result, "detail"),
            &s("shared host received"),
            "the host handed to a manual check has `shared()`: {result:?}"
        );
        assert_eq!(obj(&result, "outcome"), &s("vulnerable"));
    }

    /// Amendment 56 (D8.1): the manual path returns a verdict straight to the bus
    /// caller, so it scrubs `evidence.matched` and `evidence.payload` the way the
    /// job path's worker does — a native check that echoes a session cookie or a
    /// bearer token from a response hands neither to the caller. The literals
    /// are `scrub_text_wide`'s own form: a secret pair's value and the whole of
    /// an `Authorization` line become `[redacted]`.
    #[tokio::test(flavor = "multi_thread")]
    async fn manual_verdict_evidence_is_scrubbed() {
        let h = Harness::with_checks(vec![Arc::new(LeakyCheck::new()) as Arc<dyn Check>]);

        let result = h
            .call(
                "check.leaky-echo",
                &[("url", s("http://ex.test/search")), ("param", s("q"))],
            )
            .expect("the manual check runs");

        assert_eq!(obj(&result, "outcome"), &s("vulnerable"));
        let evidence = obj(&result, "evidence");
        assert_eq!(
            obj(evidence, "matched"),
            &s("Cookie: [redacted]; Authorization: [redacted]")
        );
        assert_eq!(obj(evidence, "payload"), &s("q=1&access_token=[redacted]"));
        assert_eq!(
            obj(&result, "detail"),
            &Value::Str("echo: Authorization: [redacted]".into()),
            "detail is scrubbed on the manual path too"
        );
    }

    /// Amendment 56 with amendment 16's order: the manual path scrubs **then**
    /// bounds, exactly as the Rhai bridge does, and it reaches the sibling
    /// verdicts too. Bounded first, the cut would land inside the cookie value
    /// and the scrub would then leave 249 bytes; the exact 256-byte literal
    /// pins the order rather than merely "something was redacted".
    #[tokio::test(flavor = "multi_thread")]
    async fn manual_evidence_is_scrubbed_before_it_is_bounded() {
        let h = Harness::with_checks(vec![Arc::new(LoudLeakyCheck::new()) as Arc<dyn Check>]);

        let result = h
            .call(
                "check.loud-echo",
                &[("url", s("http://ex.test/search")), ("param", s("q"))],
            )
            .expect("the manual check runs");

        let matched = match obj(obj(&result, "evidence"), "matched") {
            Value::Str(text) => text.clone(),
            other => panic!("matched is not a string: {other:?}"),
        };
        assert_eq!(
            matched.len(),
            aitm_scan_model::check::MAX_EXCERPT_BYTES,
            "scrubbed first, then cut: {matched:?}"
        );
        assert_eq!(
            matched,
            format!("{} Cookie: [redacted]; Autho", "a".repeat(230))
        );
        assert!(!matched.contains("s3cr3t"), "{matched:?}");

        let more = match obj(&result, "more") {
            Value::Array(items) => items.clone(),
            other => panic!("more is not an array: {other:?}"),
        };
        assert_eq!(more.len(), 1);
        let sibling = obj(&more[0], "evidence");
        assert_eq!(obj(sibling, "matched"), &s("Cookie: [redacted]"));
        assert_eq!(obj(sibling, "payload"), &s("sid=[redacted]"));
        assert_eq!(
            obj(&more[0], "detail"),
            &Value::Str("sibling: Authorization: [redacted]".into()),
            "a sibling's detail is scrubbed like the root's"
        );
    }

    /// Deny-by-default: a URL outside the HTTP scope is refused before anything
    /// is sent.
    #[tokio::test(flavor = "multi_thread")]
    async fn manual_check_out_of_scope() {
        let h = Harness::new();
        let err = h
            .call(
                "check.xss-reflected",
                &[("url", s("http://other.test/search")), ("param", s("q"))],
            )
            .expect_err("an unscoped url is refused");
        assert_eq!(code(&err), ScanErrorCode::OutOfScope);
        assert!(err.to_string().starts_with("scan: out_of_scope: "));
        assert!(h.client.payloads().is_empty());
    }

    /// Spec D4: every manual check is `Sensitive`, and its schema names the
    /// three parameters with `url` and `param` required.
    #[tokio::test(flavor = "multi_thread")]
    async fn manual_check_schema_and_tier() {
        let h = Harness::new();
        let cmd = Arc::clone(
            h.reg
                .command("check.cookie-flag")
                .expect("check.cookie-flag is registered"),
        );
        assert_eq!(cmd.sensitivity(), Sensitivity::Sensitive);
        let schema = cmd.schema();
        let names: Vec<(&str, bool)> = schema
            .params
            .iter()
            .map(|p| (p.name.as_str(), p.required))
            .collect();
        assert_eq!(
            names,
            vec![("url", true), ("param", true), ("value", false)]
        );
        assert!(
            schema.description.contains("`cookie-flag`"),
            "description was {:?}",
            schema.description
        );
    }

    /// Call B8: a command of that name already on the registry wins; the
    /// scanner does not overwrite a script's own `check.<id>`.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_existing_command_of_that_name_is_kept() {
        struct Squatter;

        impl Command for Squatter {
            fn name(&self) -> &str {
                "check.xss-reflected"
            }

            fn schema(&self) -> aitm_core::ParamSchema {
                aitm_core::ParamSchema {
                    description: "the script's own command".into(),
                    params: Vec::new(),
                    result: aitm_core::TypeDesc::Any,
                }
            }

            fn invoke(&self, _args: Params, _host: &CommandHost) -> anyhow::Result<Value> {
                Ok(Value::Object(BTreeMap::new()))
            }
        }

        let mut reg = Registry::new();
        reg.add_command(Arc::new(Squatter));
        reg.add_plugin(Box::new(
            ScannerPlugin::new(ScannerConfig::default())
                .with_native_checks(crate::interim_lane::legacy_active_checks()),
        ));

        assert_eq!(
            reg.command("check.xss-reflected")
                .expect("still registered")
                .schema()
                .description,
            "the script's own command"
        );
        // The other four are still the scanner's.
        assert!(reg.command("check.open-redirect").is_some());
    }

    /// Panel fix (2026-11-01): the manual check asks the guard about the same
    /// `host:port` the request-time guard sees. A ported entry admits the url
    /// on that port and refuses another port; an explicit `:443` entry admits
    /// a default-port https url.
    #[tokio::test(flavor = "multi_thread")]
    async fn manual_check_ported_scope_entry_matches_on_port() {
        let h = Harness::new();
        h.guard.add_scope(ScopeEntry {
            host: "127.0.0.1:8080".into(),
        });
        h.guard.add_scope(ScopeEntry {
            host: "secure.test:443".into(),
        });

        let err = h
            .call(
                "check.xss-reflected",
                &[
                    ("url", s("http://127.0.0.1:8081/search")),
                    ("param", s("q")),
                ],
            )
            .expect_err("another port is not the scoped one");
        assert_eq!(code(&err), ScanErrorCode::OutOfScope);
        assert!(h.client.payloads().is_empty());

        h.call(
            "check.xss-reflected",
            &[
                ("url", s("http://127.0.0.1:8080/search")),
                ("param", s("q")),
            ],
        )
        .expect("the ported entry admits the url on that port");
        h.call(
            "check.xss-reflected",
            &[("url", s("https://secure.test/search")), ("param", s("q"))],
        )
        .expect("the 443 entry admits the default-port https url");
        assert!(
            !h.client.payloads().is_empty(),
            "the admitted checks were sent"
        );
    }
}
