//! `HttpProbeHost`, the lane's `ProbeHost` (task 19), and `SessionMonitors`.
//!
//! One [`HttpProbeHost`] serves one insertion point for the life of one check
//! run (spec **D2**). It owns the captured source request with the job's
//! session already applied, places a payload at its one point through
//! [`mutate::build_request`], sends through the job's own guarded, budgeted
//! client and hands the check a bounded [`ProbeResponse`]. A check reaches the
//! network through nothing else.
//!
//! What this module guarantees:
//!
//! - **The source is the capture, not a reconstruction.** The request comes
//!   from the store by the point's `flow` id; a point whose flow is gone is an
//!   error rather than a probe against a guessed URL.
//! - **The session is applied once.** [`session::apply_session`] runs in
//!   [`HttpProbeHost::new`], so every probe, the baseline and every raw probe
//!   carry the job's session (spec **D7**, AC T2-4) and a `cookie`-kind probe
//!   that deliberately mutates a session cookie is not overwritten later.
//! - **Every send is bounded.** `min(deadline - now, MAX_AWAIT)`, where the
//!   host's deadline is itself `min(job deadline, now + check_timeout_s)`, so a
//!   check cannot outlive its slice of the job (AC T2-6).
//! - **The lane never charges the budget for an HTTP send.** The engine's
//!   client charges every `send_opts` (spec **D5**); charging here would double
//!   count.
//! - **The record policy is the profile's.** `issues_only` sends with
//!   `RecordPolicy::Never` and keeps at most [`MAX_HELD_FLOWS`] flows in memory
//!   for the engine to re-record on a `vulnerable` verdict (D5, seam S6); `all`
//!   sends with `RecordPolicy::Always`.
//! - **No value in a line.** Nothing here logs a header value, a cookie value
//!   or a body: the one URL in an error goes through [`redact::safe_url`], a
//!   rejected header is named and never quoted (`HeaderError`'s `Display`
//!   prints the value it rejected), and a sender's error text is scrubbed
//!   before it becomes this crate's error (AC T2-6, call A17).
//!
//! **The session-lost token.** The job's [`SessionMonitor`] is replayed every
//! [`CANARY_EVERY`] sends; once it reports a loss under `OnLost::Stop`, every
//! later `baseline`/`probe`/`probe_raw` of every host of that job returns an
//! error starting with [`session::SESSION_LOST_PREFIX`] and sends nothing
//! (cross-track seam S1, AC T2-5).

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use aitm_core::{Body, Flow, HeaderMap, HttpRequest, RecordPolicy, SendOptions};
use aitm_scan_model::{
    FlowRef, InsertionPoint, JobCtx, Payload, ProbeHost, ProbeResponse, RawProbe, RecordProbes,
    ScanProfile, SessionMode, MAX_MATCH_BODY,
};
use anyhow::{anyhow, Result};
use futures::future::BoxFuture;
use tokio::sync::OnceCell;
use url::Url;

use crate::limits::{CANARY_EVERY, MAX_AWAIT, MAX_HELD_FLOWS, MAX_SESSION_MONITORS};
use crate::session::{CanaryOutcome, SessionMonitor};
use crate::{mutate, redact, session, url_norm};

/// The point-bound surface a check sends through (spec D2, D8.1).
///
/// No `Debug`: it holds the captured request, whose `Debug` prints every header
/// value.
pub(crate) struct HttpProbeHost {
    /// The captured request, session already applied, every probe starts from.
    source: HttpRequest,
    /// The one point this host mutates.
    point: InsertionPoint,
    /// The source's origin; a raw probe may not leave it.
    origin: Url,
    /// The job: client, store, budget, deadline, cancellation, marker.
    job: Arc<dyn JobCtx>,
    /// The job's profile, cloned so `ProbeHost::profile` can hand out a
    /// reference that outlives a `job.profile()` borrow.
    profile: ScanProfile,
    /// The job's session canary, shared by every host of the job.
    monitor: Arc<SessionMonitor>,
    /// The unmutated response, taken once per host.
    baseline: OnceCell<ProbeResponse>,
    /// The last [`MAX_HELD_FLOWS`] flows this host produced, for the engine's
    /// issue re-recording under `issues_only` (D5).
    held: Mutex<VecDeque<Flow>>,
}

impl HttpProbeHost {
    /// A host for `point`, reading its source request out of the job's store.
    ///
    /// # Errors
    ///
    /// When the point names no source flow, when that flow is absent from the
    /// store or is not an HTTP flow, or when its request does not address an
    /// absolute `http(s)` origin.
    pub fn new(
        point: &InsertionPoint,
        job: Arc<dyn JobCtx>,
        monitor: Arc<SessionMonitor>,
    ) -> Result<Self> {
        let Some(flow_ref) = point.flow else {
            return Err(anyhow!("scan: point {} has no source flow", point.id));
        };
        let Some(Flow::Http(flow)) = job.store().get(flow_ref.0) else {
            return Err(anyhow!("scan: source flow {flow_ref} is gone"));
        };

        let mut source = flow.request;
        if let Some(material) = job.session() {
            session::apply_session(&mut source, &material);
        }
        let Some(origin) = url_norm::request_url(&source) else {
            return Err(anyhow!(
                "scan: source flow {flow_ref} does not address an absolute origin"
            ));
        };

        let profile = job.profile().clone();
        Ok(Self {
            source,
            point: point.clone(),
            origin,
            job,
            profile,
            monitor,
            baseline: OnceCell::new(),
            held: Mutex::new(VecDeque::new()),
        })
    }

    /// The options every send of this host goes out with (D5, D9.1).
    fn send_options(&self) -> SendOptions {
        SendOptions {
            record: match self.profile.http.record_probes {
                RecordProbes::IssuesOnly => RecordPolicy::Never,
                RecordProbes::All => RecordPolicy::Always,
            },
            marks: vec![format!("scan:{}", self.job.job_id())],
            version: self.profile.http.version.into(),
        }
    }

    /// The ceiling on one await: what is left of the deadline, at most
    /// [`MAX_AWAIT`].
    fn bound(&self) -> Duration {
        self.deadline()
            .saturating_duration_since(Instant::now())
            .min(MAX_AWAIT)
    }

    /// Send `req` under the session monitor, the deadline and the record
    /// policy, and bound what comes back.
    ///
    /// `what` names the stage (`baseline`, `probe`, `probe_raw`) and is the
    /// only thing that reaches the error text besides a scrubbed sender
    /// message.
    async fn send_bounded(&self, req: HttpRequest, what: &str) -> Result<ProbeResponse> {
        if self.monitor.should_stop() {
            return Err(self.monitor.lost_error(what));
        }

        let client = self.job.client();
        if self.monitor.tick() {
            let outcome = self
                .monitor
                .check(client.as_ref(), self.send_options(), self.bound())
                .await;
            if matches!(outcome, CanaryOutcome::Lost { .. }) && self.monitor.should_stop() {
                return Err(self.monitor.lost_error(what));
            }
        }

        let options = self.send_options();
        let record = options.record;
        let started = Instant::now();
        let flow = match tokio::time::timeout(self.bound(), client.send_opts(req, options)).await {
            Ok(Ok(flow)) => flow,
            // A sender error can carry whatever the transport put in it, so it
            // is scrubbed rather than propagated as it came.
            Ok(Err(err)) => {
                return Err(anyhow!(
                    "scan: {what} failed: {}",
                    redact::scrub(&format!("{err:#}"))
                ))
            }
            Err(_) => return Err(anyhow!("scan: {what} ran past its time bound")),
        };
        let elapsed_ms = u32::try_from(started.elapsed().as_millis()).unwrap_or(u32::MAX);

        let (status, headers, body) = match flow.response.as_ref() {
            Some(response) => (
                Some(response.status),
                response
                    .headers
                    .iter()
                    .map(|(name, value)| (name.to_string(), value.to_string()))
                    .collect(),
                match &response.body {
                    Body::Bytes(bytes) => bytes[..bytes.len().min(MAX_MATCH_BODY)].to_vec(),
                    Body::Empty | Body::Streamed(_) => Vec::new(),
                },
            ),
            None => (None, Vec::new(), Vec::new()),
        };

        let id = flow.id;
        let stored = record == RecordPolicy::Always || self.job.store().get(id).is_some();
        self.hold(Flow::Http(flow));

        Ok(ProbeResponse {
            status,
            headers,
            body,
            elapsed_ms,
            flow: stored.then_some(FlowRef(id)),
            ws_frames: None,
            l4: None,
        })
    }

    /// Keep `flow` for the engine's issue re-recording, dropping the oldest
    /// past [`MAX_HELD_FLOWS`].
    ///
    /// A poisoned lock is recovered rather than propagated: the buffer is
    /// evidence, and losing a probe to another thread's panic must not turn a
    /// working probe into an error.
    fn hold(&self, flow: Flow) {
        let mut held = self
            .held
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        held.push_back(flow);
        while held.len() > MAX_HELD_FLOWS {
            held.pop_front();
        }
    }

    /// The request a [`RawProbe`] describes, refused when it leaves the point's
    /// origin.
    ///
    /// The method is taken verbatim (a check probing a malformed method is the
    /// reason `probe_raw` exists) and the authority is the capture's, so a
    /// same-origin raw probe addresses exactly the host the capture did.
    fn raw_request(&self, raw: &RawProbe) -> Result<HttpRequest> {
        let target = url_norm::parse_absolute(&raw.url)
            .filter(|url| url_norm::same_origin(url, &self.origin))
            .ok_or_else(|| {
                anyhow!(
                    "scan: probe_raw: {} is not on the point's origin",
                    redact::safe_url(&raw.url)
                )
            })?;

        let path = match target.query() {
            Some(query) => format!("{}?{query}", target.path()),
            None => target.path().to_string(),
        };

        let mut headers = HeaderMap::new();
        headers.set("host", &self.source.authority);
        for (name, value) in &raw.headers {
            if name.eq_ignore_ascii_case("host") {
                continue;
            }
            // `HeaderError`'s `Display` prints the value it rejected, so it is
            // dropped and the name alone names the problem.
            headers
                .try_set(name, value)
                .map_err(|_| anyhow!("scan: probe_raw: header {name} cannot go on the wire"))?;
        }

        let body = if raw.body.is_empty() {
            Body::Empty
        } else {
            if !headers.has("content-length") {
                headers.set("content-length", &raw.body.len().to_string());
            }
            Body::Bytes(raw.body.clone())
        };

        let mut req = HttpRequest {
            method: raw.method.clone(),
            scheme: target.scheme().to_string(),
            authority: self.source.authority.clone(),
            path,
            version: self.source.version,
            headers,
            body,
            timestamp: SystemTime::now(),
        };
        if let Some(material) = self.job.session() {
            session::apply_session(&mut req, &material);
        }
        Ok(req)
    }
}

impl ProbeHost for HttpProbeHost {
    fn baseline(&self) -> BoxFuture<'_, Result<ProbeResponse>> {
        Box::pin(async move {
            let answer = self
                .baseline
                .get_or_try_init(|| self.send_bounded(self.source.clone(), "baseline"))
                .await?;
            Ok(answer.clone())
        })
    }

    fn probe<'a>(&'a self, payload: &'a Payload) -> BoxFuture<'a, Result<ProbeResponse>> {
        Box::pin(async move {
            let req = mutate::build_request(&self.source, &self.point, payload)?;
            self.send_bounded(req, "probe").await
        })
    }

    fn probe_raw(&self, req: RawProbe) -> BoxFuture<'_, Result<ProbeResponse>> {
        Box::pin(async move {
            let built = self.raw_request(&req)?;
            self.send_bounded(built, "probe_raw").await
        })
    }

    fn marker(&self) -> String {
        self.job.marker()
    }

    fn budget_left(&self) -> u32 {
        self.job.budget_left()
    }

    fn deadline(&self) -> Instant {
        let check_timeout = Duration::from_secs(self.profile.budget.check_timeout_s);
        match Instant::now().checked_add(check_timeout) {
            Some(check) => self.job.deadline().min(check),
            // An absurd `check_timeout_s` cannot be added to `now`; the job's
            // own deadline is then the only bound, which is the stricter one.
            None => self.job.deadline(),
        }
    }

    fn profile(&self) -> &ScanProfile {
        &self.profile
    }

    fn cancelled(&self) -> bool {
        self.job.cancelled()
    }

    fn held_flows(&self) -> Vec<Flow> {
        self.held
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .iter()
            .cloned()
            .collect()
    }
}

/// The registry's contents: job ids in insertion order, so the oldest can be
/// evicted, and the monitors themselves.
type MonitorTable = (VecDeque<String>, HashMap<String, Arc<SessionMonitor>>);

/// One [`SessionMonitor`] per job, bounded at [`MAX_SESSION_MONITORS`].
///
/// Every host of a job shares its monitor, so a loss seen by one probe stops
/// all of them (AC T2-5). The canary is picked from the origin of the first
/// point the job asks for (call A5); a job with `session.mode: none` or no
/// observed material gets an unarmed monitor, so the probe path needs no
/// `Option`.
#[derive(Default)]
pub(crate) struct SessionMonitors {
    /// Insertion order and the monitors themselves, behind one lock so the
    /// eviction cannot see them disagree.
    inner: Mutex<MonitorTable>,
}

impl SessionMonitors {
    /// An empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// The monitor for `job`, building it against `origin` the first time.
    pub fn for_job(&self, job: &dyn JobCtx, origin: &Url) -> Arc<SessionMonitor> {
        let key = job.job_id().to_string();
        let mut guard = self
            .inner
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let (order, monitors) = &mut *guard;
        if let Some(found) = monitors.get(&key) {
            return Arc::clone(found);
        }

        let profile = job.profile();
        let on_lost = profile.session.on_lost;
        let monitor = match (profile.session.mode, job.session()) {
            (SessionMode::Observed, Some(material)) => {
                let store = job.store();
                let canary = session::pick_canary(
                    store.as_ref(),
                    origin,
                    &material,
                    profile.session.from_flow.map(|flow| flow.0),
                );
                SessionMonitor::new(canary, on_lost, CANARY_EVERY)
            }
            _ => SessionMonitor::unarmed(on_lost),
        };

        let monitor = Arc::new(monitor);
        monitors.insert(key.clone(), Arc::clone(&monitor));
        order.push_back(key);
        while monitors.len() > MAX_SESSION_MONITORS {
            match order.pop_front() {
                Some(oldest) => {
                    monitors.remove(&oldest);
                }
                None => break,
            }
        }
        monitor
    }

    /// How many monitors are held. Read by the lane's tests to pin call A5
    /// (one monitor per job, built on the first point).
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .1
            .len()
    }

    /// Whether no monitor is held. The conventional partner of
    /// [`SessionMonitors::len`] (`clippy::len_without_is_empty`); no caller
    /// needs it yet.
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use aitm_core::{
        Flow, FlowStore, HttpRequest, MemFlowStore, ProxyClient, RecordPolicy, ScopeRateGuard,
    };
    use aitm_scan_model::{
        CanaryMethod, FlowRef, InsertionKind, InsertionPoint, JobCtx, LaneKind, OnLost, Payload,
        PayloadMode, ProbeHost, RawProbe, RecordProbes, ScanProfile, SessionMaterial, SessionMode,
        MAX_MATCH_BODY,
    };

    use crate::host::{HttpProbeHost, SessionMonitors};
    use crate::limits::{MAX_HELD_FLOWS, MAX_SESSION_MONITORS};
    use crate::session::{CanaryRequest, SessionMonitor, SESSION_LOST_PREFIX};
    use crate::testutil::{captured_flow, request, response, FakeJob, ScriptedClient, JOB_ID};

    /// The URL of the captured flow every fixture probes.
    const SOURCE_URL: &str = "http://t:8080/search?q=hello&x=1";

    /// A client that answers every request `200 text/html`.
    fn ok_200() -> ScriptedClient {
        ScriptedClient::new(|_: &HttpRequest| {
            Ok(response(
                200,
                &[("content-type", "text/html")],
                b"<html>ok</html>",
            ))
        })
    }

    /// The job's session material: one cookie the capture does not carry.
    fn material() -> SessionMaterial {
        SessionMaterial {
            cookies: vec![("sid".to_string(), "S3".to_string())],
            headers: Vec::new(),
        }
    }

    /// The `query` point on `q` of the fixture's captured flow.
    fn query_point(flow: FlowRef) -> InsertionPoint {
        InsertionPoint {
            id: format!("{flow}:query:0"),
            lane: LaneKind::Http,
            kind: InsertionKind::Query,
            name: "q".to_string(),
            path: None,
            example: None,
            flow: Some(flow),
            site_node: None,
            traits: Vec::new(),
            frequency: 1,
            method: None,
            url: None,
        }
    }

    fn replace(value: &str) -> Payload {
        Payload {
            value: value.to_string(),
            mode: PayloadMode::Replace,
            bytes: None,
        }
    }

    /// A monitor with no canary: `tick()` is never true.
    fn unarmed() -> Arc<SessionMonitor> {
        Arc::new(SessionMonitor::unarmed(OnLost::Stop))
    }

    /// A monitor whose canary is `GET /me`, observed answering 200.
    fn canary_monitor(every: u32, on_lost: OnLost) -> Arc<SessionMonitor> {
        Arc::new(SessionMonitor::new(
            Some(CanaryRequest {
                request: request("GET", "http://t:8080/me", &[("cookie", "sid=S3")], None),
                method: CanaryMethod::Get,
                path: "/me".to_string(),
                expected_status: 200,
            }),
            on_lost,
            every,
        ))
    }

    /// A job over the doubles with the captured source flow in its store.
    struct Fixture {
        job: Arc<FakeJob>,
        client: Arc<ScriptedClient>,
        store: Arc<MemFlowStore>,
        point: InsertionPoint,
    }

    impl Fixture {
        fn ctx(&self) -> Arc<dyn JobCtx> {
            Arc::clone(&self.job) as Arc<dyn JobCtx>
        }

        /// The `(request, options)` pairs the lane sent so far.
        fn sent(&self) -> Vec<(HttpRequest, aitm_core::SendOptions)> {
            self.client.sent.lock().unwrap().clone()
        }
    }

    fn fixture(client: ScriptedClient) -> Fixture {
        fixture_full(ScanProfile::default(), client, 60)
    }

    fn fixture_full(profile: ScanProfile, client: ScriptedClient, deadline_s: u64) -> Fixture {
        let store = Arc::new(MemFlowStore::new());
        let client = Arc::new(client.recording_into(Arc::clone(&store) as Arc<dyn FlowStore>));
        let flow = captured_flow(
            request("GET", SOURCE_URL, &[("cookie", "theme=dark")], None),
            200,
            &[("content-type", "text/html")],
            b"hi",
        );
        let flow_id = flow.id;
        store.insert(Flow::Http(flow));

        let mut job = FakeJob::new(profile, Arc::clone(&client))
            .with_store(Arc::clone(&store))
            .with_session(material());
        job.deadline = Instant::now() + Duration::from_secs(deadline_s);

        Fixture {
            job: Arc::new(job),
            client,
            store,
            point: query_point(FlowRef(flow_id)),
        }
    }

    /// A profile whose HTTP options record every probe.
    fn record_all() -> ScanProfile {
        let mut profile = ScanProfile::default();
        profile.http.record_probes = RecordProbes::All;
        profile
    }

    #[tokio::test]
    async fn baseline_is_cached() {
        let fx = fixture(ok_200());
        let host = HttpProbeHost::new(&fx.point, fx.ctx(), unarmed()).unwrap();

        let first = host.baseline().await.unwrap();
        let second = host.baseline().await.unwrap();

        assert_eq!(first.status, Some(200));
        assert_eq!(second.status, Some(200));
        let sent = fx.sent();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].0.path, "/search?q=hello&x=1");
        assert_eq!(sent[0].0.headers.get("cookie"), Some("theme=dark; sid=S3"));
        assert_eq!(sent[0].1.marks, vec![format!("scan:{JOB_ID}")]);
        assert_eq!(sent[0].1.record, RecordPolicy::Never);
    }

    #[tokio::test]
    async fn probe_mutates_only_the_point() {
        let fx = fixture(ok_200());
        let host = HttpProbeHost::new(&fx.point, fx.ctx(), unarmed()).unwrap();

        let answer = host.probe(&replace("<s>")).await.unwrap();

        assert_eq!(answer.status, Some(200));
        assert_eq!(answer.flow, None);
        let sent = fx.sent();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].0.path, "/search?q=%3Cs%3E&x=1");
        assert_eq!(sent[0].0.headers.get("cookie"), Some("theme=dark; sid=S3"));
        assert_eq!(sent[0].0.method, "GET");
    }

    #[tokio::test]
    async fn record_all_stores_the_probe_flow() {
        let fx = fixture_full(record_all(), ok_200(), 60);
        let host = HttpProbeHost::new(&fx.point, fx.ctx(), unarmed()).unwrap();

        let answer = host.probe(&replace("<s>")).await.unwrap();

        assert_eq!(fx.sent()[0].1.record, RecordPolicy::Always);
        let flow = answer.flow.expect("a recorded probe carries its flow ref");
        assert!(fx.store.get(flow.0).is_some());
    }

    #[tokio::test]
    async fn held_flows_bounded() {
        let fx = fixture(ok_200());
        let host = HttpProbeHost::new(&fx.point, fx.ctx(), unarmed()).unwrap();

        for index in 0..20 {
            host.probe(&replace(&format!("p{index}"))).await.unwrap();
        }

        let held = host.held_flows();
        assert_eq!(held.len(), MAX_HELD_FLOWS);
        assert_eq!(held.len(), 16);
        let Flow::Http(last) = held.last().unwrap() else {
            panic!("an HTTP probe holds an HTTP flow");
        };
        assert_eq!(last.request.path, "/search?q=p19&x=1");
    }

    #[tokio::test]
    async fn probe_raw_same_origin_only() {
        let fx = fixture(ok_200());
        let host = HttpProbeHost::new(&fx.point, fx.ctx(), unarmed()).unwrap();

        let refused = host
            .probe_raw(RawProbe {
                method: "GET".to_string(),
                url: "http://evil.test/?token=abc".to_string(),
                headers: Vec::new(),
                body: Vec::new(),
            })
            .await
            .expect_err("another origin is refused");
        let message = format!("{refused:#}");
        assert!(
            message.contains("not on the point's origin"),
            "unexpected message: {message}"
        );
        assert!(
            !message.contains("abc"),
            "the error leaked a value: {message}"
        );
        assert_eq!(fx.sent().len(), 0);

        host.probe_raw(RawProbe {
            method: "HEAD".to_string(),
            url: "http://t:8080/raw".to_string(),
            headers: Vec::new(),
            body: Vec::new(),
        })
        .await
        .unwrap();

        let sent = fx.sent();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].0.method, "HEAD");
        assert_eq!(sent[0].0.path, "/raw");
        assert!(sent[0].0.headers.get("cookie").unwrap().contains("sid=S3"));
    }

    #[tokio::test]
    async fn elapsed_is_measured() {
        let fx = fixture(ok_200().with_delay(Duration::from_millis(50)));
        let host = HttpProbeHost::new(&fx.point, fx.ctx(), unarmed()).unwrap();

        let answer = host.probe(&replace("x")).await.unwrap();

        assert!(
            answer.elapsed_ms >= 50,
            "elapsed_ms was {}",
            answer.elapsed_ms
        );
    }

    #[tokio::test]
    async fn body_is_bounded() {
        let big = vec![b'a'; 2 * 1024 * 1024];
        let client = ScriptedClient::new(move |_: &HttpRequest| {
            Ok(response(200, &[("content-type", "text/html")], &big))
        });
        let fx = fixture(client);
        let host = HttpProbeHost::new(&fx.point, fx.ctx(), unarmed()).unwrap();

        let answer = host.probe(&replace("x")).await.unwrap();

        assert_eq!(answer.body.len(), MAX_MATCH_BODY);
    }

    /// A client answering `/me` (the canary) `302` and everything else `200`.
    fn canary_lost_client() -> ScriptedClient {
        ScriptedClient::new(|req: &HttpRequest| {
            if req.path == "/me" {
                Ok(response(302, &[("location", "/login")], b""))
            } else {
                Ok(response(200, &[("content-type", "text/html")], b"ok"))
            }
        })
    }

    #[tokio::test]
    async fn session_lost_stops_every_probe() {
        let fx = fixture(canary_lost_client());
        let host =
            HttpProbeHost::new(&fx.point, fx.ctx(), canary_monitor(2, OnLost::Stop)).unwrap();

        host.probe(&replace("one")).await.unwrap();
        let stopped = host
            .probe(&replace("two"))
            .await
            .expect_err("the second probe runs the canary and finds the session lost");
        assert!(
            format!("{stopped:#}").starts_with(SESSION_LOST_PREFIX),
            "unexpected message: {stopped:#}"
        );

        let after_baseline = host.baseline().await.expect_err("the job is stopped");
        assert!(format!("{after_baseline:#}").starts_with(SESSION_LOST_PREFIX));
        let after_raw = host
            .probe_raw(RawProbe {
                method: "GET".to_string(),
                url: "http://t:8080/raw".to_string(),
                headers: Vec::new(),
                body: Vec::new(),
            })
            .await
            .expect_err("the job is stopped");
        assert!(format!("{after_raw:#}").starts_with(SESSION_LOST_PREFIX));

        // One probe and one canary: nothing was sent after the loss.
        assert_eq!(fx.sent().len(), 2);
    }

    #[tokio::test]
    async fn session_lost_continue_keeps_probing() {
        let fx = fixture(canary_lost_client());
        let host =
            HttpProbeHost::new(&fx.point, fx.ctx(), canary_monitor(2, OnLost::Continue)).unwrap();

        for index in 0..3 {
            host.probe(&replace(&format!("p{index}")))
                .await
                .unwrap_or_else(|e| panic!("probe {index} must still run: {e:#}"));
        }

        // Three probes and the one canary the second probe triggered.
        assert_eq!(fx.sent().len(), 4);
    }

    /// The message of a refused [`HttpProbeHost::new`]. The host has no
    /// `Debug` (it holds header values), so `expect_err` cannot be used.
    fn refusal(result: anyhow::Result<HttpProbeHost>, what: &str) -> String {
        match result {
            Ok(_) => panic!("{what}"),
            Err(err) => format!("{err:#}"),
        }
    }

    #[tokio::test]
    async fn source_gone_errors() {
        let fx = fixture(ok_200());

        let mut orphan = fx.point.clone();
        orphan.flow = Some(FlowRef(aitm_core::FlowId::new()));
        let gone = refusal(
            HttpProbeHost::new(&orphan, fx.ctx(), unarmed()),
            "a source flow that is not in the store is an error",
        );
        assert!(gone.contains("gone"), "unexpected message: {gone}");

        let mut unlinked = fx.point.clone();
        unlinked.flow = None;
        let missing = refusal(
            HttpProbeHost::new(&unlinked, fx.ctx(), unarmed()),
            "a point with no source flow is an error",
        );
        assert!(
            missing.contains("no source flow"),
            "unexpected message: {missing}"
        );
    }

    #[tokio::test]
    async fn deadline_is_the_min() {
        let fx = fixture_full(ScanProfile::default(), ok_200(), 10);
        let host = HttpProbeHost::new(&fx.point, fx.ctx(), unarmed()).unwrap();
        assert!(host.deadline() <= Instant::now() + Duration::from_secs(10));

        let fx = fixture_full(ScanProfile::default(), ok_200(), 120);
        let host = HttpProbeHost::new(&fx.point, fx.ctx(), unarmed()).unwrap();
        assert!(host.deadline() <= Instant::now() + Duration::from_secs(60));
        assert!(host.deadline() > Instant::now() + Duration::from_secs(50));
    }

    /// A [`FakeJob`] reporting a job id of its own, so one test can hold many.
    struct IdJob {
        inner: FakeJob,
        id: String,
    }

    impl JobCtx for IdJob {
        fn job_id(&self) -> &str {
            &self.id
        }
        fn profile(&self) -> &ScanProfile {
            self.inner.profile()
        }
        fn client(&self) -> Arc<dyn ProxyClient> {
            self.inner.client()
        }
        fn store(&self) -> Arc<dyn FlowStore> {
            self.inner.store()
        }
        fn guard(&self) -> Arc<dyn ScopeRateGuard> {
            self.inner.guard()
        }
        fn browser(&self) -> Option<Arc<dyn aitm_core::BrowserDriver>> {
            self.inner.browser()
        }
        fn session(&self) -> Option<Arc<SessionMaterial>> {
            self.inner.session()
        }
        fn charge(&self, units: u32) -> bool {
            self.inner.charge(units)
        }
        fn budget_left(&self) -> u32 {
            self.inner.budget_left()
        }
        fn deadline(&self) -> Instant {
            self.inner.deadline()
        }
        fn cancelled(&self) -> bool {
            self.inner.cancelled()
        }
        fn marker(&self) -> String {
            self.inner.marker()
        }
    }

    fn id_job(id: &str, session: bool) -> IdJob {
        let job = FakeJob::new(ScanProfile::default(), Arc::new(ok_200()));
        let job = if session {
            job.with_session(material())
        } else {
            job
        };
        IdJob {
            inner: job,
            id: id.to_string(),
        }
    }

    #[test]
    fn monitors_bounded_and_shared() {
        let monitors = SessionMonitors::new();
        let origin = url::Url::parse("http://t:8080/").unwrap();

        for index in 0..17 {
            let job = id_job(&format!("scan-{index:08x}"), true);
            monitors.for_job(&job, &origin);
        }
        assert_eq!(monitors.len(), MAX_SESSION_MONITORS);
        assert_eq!(monitors.len(), 16);

        let job = id_job("scan-shared1", true);
        let first = monitors.for_job(&job, &origin);
        let second = monitors.for_job(&job, &origin);
        assert!(Arc::ptr_eq(&first, &second));

        let sessionless = id_job("scan-nosess1", false);
        let monitor = monitors.for_job(&sessionless, &origin);
        for _ in 0..50 {
            assert!(!monitor.tick(), "a sessionless job gets an unarmed monitor");
        }
    }

    #[test]
    fn session_mode_none_is_unarmed() {
        let monitors = SessionMonitors::new();
        let origin = url::Url::parse("http://t:8080/").unwrap();
        let mut job = id_job("scan-modenone", true);
        job.inner.profile.session.mode = SessionMode::None;

        let monitor = monitors.for_job(&job, &origin);

        for _ in 0..50 {
            assert!(!monitor.tick(), "session.mode none gets an unarmed monitor");
        }
    }

    #[tokio::test]
    async fn no_probe_is_charged_to_the_job_budget() {
        let fx = fixture(ok_200());
        let host = HttpProbeHost::new(&fx.point, fx.ctx(), unarmed()).unwrap();

        host.baseline().await.unwrap();
        host.probe(&replace("x")).await.unwrap();

        // The engine's client charges HTTP sends; the lane never does (D5).
        assert_eq!(
            fx.job.charges.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "the lane charged the budget for an HTTP send"
        );
        assert_eq!(host.budget_left(), 1000);
    }

    // --- tester additions (stage 5, whole branch) ----------------------------

    /// A loss seen through one host stops every other host of the job that
    /// shares the monitor, including a host built after the loss, and nothing
    /// more is sent (AC T2-5: "every probe/baseline/probe_raw of every host").
    #[tokio::test]
    async fn session_lost_stops_sibling_and_later_hosts() {
        let fx = fixture(canary_lost_client());
        let monitor = canary_monitor(2, OnLost::Stop);
        let first = HttpProbeHost::new(&fx.point, fx.ctx(), Arc::clone(&monitor)).unwrap();
        let sibling = HttpProbeHost::new(&fx.point, fx.ctx(), Arc::clone(&monitor)).unwrap();

        first.probe(&replace("one")).await.unwrap();
        let lost = first
            .probe(&replace("two"))
            .await
            .expect_err("the second probe runs the canary and finds the loss");
        assert!(format!("{lost:#}").starts_with(SESSION_LOST_PREFIX));
        assert_eq!(fx.sent().len(), 2);

        let raw = || RawProbe {
            method: "GET".to_string(),
            url: "http://t:8080/raw".to_string(),
            headers: Vec::new(),
            body: Vec::new(),
        };
        for (what, result) in [
            ("sibling baseline", sibling.baseline().await),
            ("sibling probe", sibling.probe(&replace("x")).await),
            ("sibling probe_raw", sibling.probe_raw(raw()).await),
        ] {
            let err = result.expect_err(what);
            assert!(
                format!("{err:#}").starts_with(SESSION_LOST_PREFIX),
                "{what}: {err:#}"
            );
        }

        let later = HttpProbeHost::new(&fx.point, fx.ctx(), Arc::clone(&monitor)).unwrap();
        let err = later
            .baseline()
            .await
            .expect_err("a host built after the loss is stopped too");
        assert!(format!("{err:#}").starts_with(SESSION_LOST_PREFIX));
        assert_eq!(fx.sent().len(), 2, "nothing is sent after the loss");
    }

    /// A sender's error is named by stage and scrubbed before it becomes the
    /// lane's error: whatever the transport put in it, no credential survives
    /// (AC T2-6), while the structural part of the message does.
    #[tokio::test]
    async fn sender_errors_are_scrubbed_and_name_the_stage() {
        let client = ScriptedClient::new(|_: &HttpRequest| {
            Err(anyhow::anyhow!(
                "connect reset while sending sid=S3; password=hunter2 Authorization: Bearer tok"
            ))
        });
        let fx = fixture(client);
        let host = HttpProbeHost::new(&fx.point, fx.ctx(), unarmed()).unwrap();

        let probe = host
            .probe(&replace("x"))
            .await
            .expect_err("the sender failed");
        let text = format!("{probe:#}");
        assert!(text.starts_with("scan: probe failed: "), "{text}");
        for secret in ["S3", "hunter2", "tok"] {
            assert!(!text.contains(secret), "{secret} leaked: {text}");
        }
        assert!(
            text.contains("connect reset"),
            "the structural part survives: {text}"
        );

        let baseline = host.baseline().await.expect_err("the sender failed");
        assert!(format!("{baseline:#}").starts_with("scan: baseline failed: "));
        let raw = host
            .probe_raw(RawProbe {
                method: "GET".to_string(),
                url: "http://t:8080/raw".to_string(),
                headers: Vec::new(),
                body: Vec::new(),
            })
            .await
            .expect_err("the sender failed");
        assert!(format!("{raw:#}").starts_with("scan: probe_raw failed: "));

        // Every attempt reached the client; none produced a flow to hold.
        assert_eq!(fx.sent().len(), 3);
        assert!(host.held_flows().is_empty());
    }

    /// A send that outlives `min(deadline - now, MAX_AWAIT)` is cut off with
    /// an error, not awaited to completion: the host's deadline bounds it.
    #[tokio::test]
    async fn a_send_past_the_deadline_is_cut_off() {
        let fx = fixture_full(
            ScanProfile::default(),
            ok_200().with_delay(Duration::from_secs(5)),
            1,
        );
        let host = HttpProbeHost::new(&fx.point, fx.ctx(), unarmed()).unwrap();

        let started = Instant::now();
        let err = host
            .probe(&replace("x"))
            .await
            .expect_err("the send outlives the deadline");

        assert!(
            format!("{err:#}").contains("ran past its time bound"),
            "{err:#}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(4),
            "the await was not bounded: {:?}",
            started.elapsed()
        );
        assert!(host.held_flows().is_empty());
    }

    /// A raw probe's header that cannot go on the wire is refused by name with
    /// its value never quoted; `Host` is the capture's whatever the raw probe
    /// says; a raw body is framed with its length and the session still rides.
    #[tokio::test]
    async fn probe_raw_headers_and_body_are_framed_safely() {
        let fx = fixture(ok_200());
        let host = HttpProbeHost::new(&fx.point, fx.ctx(), unarmed()).unwrap();

        let refused = host
            .probe_raw(RawProbe {
                method: "GET".to_string(),
                url: "http://t:8080/raw".to_string(),
                headers: vec![("X-Bad".to_string(), "a\r\nhunter2".to_string())],
                body: Vec::new(),
            })
            .await
            .expect_err("a header with a line break cannot go on the wire");
        let text = format!("{refused:#}");
        assert!(text.contains("X-Bad"), "{text}");
        assert!(
            !text.contains("hunter2"),
            "the error quoted the value: {text}"
        );
        assert_eq!(fx.sent().len(), 0);

        host.probe_raw(RawProbe {
            method: "POST".to_string(),
            url: "http://t:8080/raw?x=1".to_string(),
            headers: vec![
                ("Host".to_string(), "evil.test".to_string()),
                ("X-Extra".to_string(), "yes".to_string()),
            ],
            body: b"abc".to_vec(),
        })
        .await
        .unwrap();

        let sent = fx.sent();
        assert_eq!(sent.len(), 1);
        let req = &sent[0].0;
        assert_eq!(req.method, "POST");
        assert_eq!(req.path, "/raw?x=1");
        assert_eq!(req.authority, "t:8080");
        assert_eq!(req.headers.get("host"), Some("t:8080"));
        assert_eq!(req.headers.get("x-extra"), Some("yes"));
        assert_eq!(req.headers.get("content-length"), Some("3"));
        assert!(matches!(&req.body, aitm_core::Body::Bytes(bytes) if bytes == b"abc"));
        assert!(req.headers.get("cookie").unwrap().contains("sid=S3"));
    }
}
