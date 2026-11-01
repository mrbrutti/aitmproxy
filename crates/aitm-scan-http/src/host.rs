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
//! - **The session is settled once.** Under `session.mode: observed`
//!   [`session::apply_session`] runs in [`HttpProbeHost::new`], so every probe,
//!   the baseline and every raw probe carry the job's session (spec **D7**,
//!   AC T2-4) and a `cookie`-kind probe that deliberately mutates a session
//!   cookie is not overwritten later.
//! - **`session.mode: none` means unauthenticated.** A capture taken while the
//!   operator was logged in carries the operator's own session, so under that
//!   mode [`strip_session_headers`] takes `Cookie`, `Authorization` and every
//!   header [`redact::is_secret_name`] knows off the source request at
//!   construction, no material is merged, and a raw probe's own copies of those
//!   headers are dropped too: a job that must scan unauthenticated cannot
//!   re-authenticate itself through any path (AC T2-4).
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
//! (cross-track seam S1, AC T2-5). The check that flips the monitor's lost
//! flag also reports the loss to the job once, and building a job's monitor
//! reports the canary it armed, so `JobStatus.session` shows both (spec D5).

use std::collections::{HashMap, HashSet, VecDeque};
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

use crate::limits::{
    job_mark, CANARY_EVERY, MAX_AWAIT, MAX_HELD_FLOWS, MAX_LOST_MONITOR_IDS, MAX_SESSION_MONITORS,
};
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
    /// The job: client, store, budget, deadline, cancellation, marker, and the
    /// profile every `profile()` hands out.
    job: Arc<dyn JobCtx>,
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
    pub(crate) fn new(
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
        match job.profile().session.mode {
            // The capture may itself be authenticated; an unauthenticated job
            // sheds that here, before the baseline exists, so no later path
            // can put it back (AC T2-4).
            SessionMode::None => strip_session_headers(&mut source),
            SessionMode::Observed => {
                if let Some(material) = job.session() {
                    session::apply_session(&mut source, &material);
                }
            }
        }
        let Some(origin) = url_norm::request_url(&source) else {
            return Err(anyhow!(
                "scan: source flow {flow_ref} does not address an absolute origin"
            ));
        };

        Ok(Self {
            source,
            point: point.clone(),
            origin,
            job,
            monitor,
            baseline: OnceCell::new(),
            held: Mutex::new(VecDeque::new()),
        })
    }

    /// The options every send of this host goes out with (D5, D9.1).
    fn send_options(&self) -> SendOptions {
        SendOptions {
            record: match self.job.profile().http.record_probes {
                RecordProbes::IssuesOnly => RecordPolicy::Never,
                RecordProbes::All => RecordPolicy::Always,
            },
            marks: vec![job_mark(self.job.job_id())],
            version: self.job.profile().http.version.into(),
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
            if let CanaryOutcome::Lost { first, .. } = outcome {
                // The monitor is shared by every host of the job, so the one
                // check that flipped its lost flag is the one that tells the
                // job: `JobStatus.session.lost` is set once, not once per
                // probe (spec D7).
                if first {
                    self.job.report_session_lost();
                }
                if self.monitor.should_stop() {
                    return Err(self.monitor.lost_error(what));
                }
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
                    redact::scrub_error(&err)
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
        // The method is taken verbatim onto the request line, so a malformed one
        // is refused here; the value is left out of the error (S-M1).
        // A method is an RFC 9110 `token`, the same production as a header
        // name, so the core's one tchar rule decides (S-M1, R-M5).
        if !aitm_core::header::is_valid_name(&raw.method) {
            return Err(anyhow!(
                "scan: probe_raw: method is not a valid RFC 9110 token"
            ));
        }
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
            // A check that hands `probe_raw` a session header does not get to
            // authenticate a job whose profile says `session.mode: none`.
            if self.unauthenticated() && is_session_header(name) {
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
        if !self.unauthenticated() {
            if let Some(material) = self.job.session() {
                session::apply_session(&mut req, &material);
            }
        }
        Ok(req)
    }

    /// Whether the job's profile says scan unauthenticated
    /// (`session.mode: none`).
    fn unauthenticated(&self) -> bool {
        self.job.profile().session.mode == SessionMode::None
    }
}

/// Whether `name` is a header a session rides in: `Cookie`, `Authorization`,
/// or any name the shared secret vocabulary recognises (`X-Api-Key`,
/// `X-CSRF-Token`, …).
///
/// The first two are named outright rather than left to the vocabulary: they
/// are the two headers the spec calls out (D7), and naming them keeps this
/// decision readable without reading another crate.
fn is_session_header(name: &str) -> bool {
    name.eq_ignore_ascii_case("cookie")
        || name.eq_ignore_ascii_case("authorization")
        || redact::is_secret_name(name)
}

/// Take every [`is_session_header`] header off `req`.
///
/// Names are collected before anything is removed: `HeaderMap::remove` takes
/// a name, so mutating while iterating is not possible, and a request may
/// legally carry the same header twice (`remove` drops both).
fn strip_session_headers(req: &mut HttpRequest) {
    let doomed: Vec<String> = req
        .headers
        .iter()
        .map(|(name, _)| name.to_string())
        .filter(|name| is_session_header(name))
        .collect();
    for name in doomed {
        req.headers.remove(&name);
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
        let check_timeout = Duration::from_secs(self.job.profile().budget.check_timeout_s);
        match Instant::now().checked_add(check_timeout) {
            Some(check) => self.job.deadline().min(check),
            // An absurd `check_timeout_s` cannot be added to `now`; the job's
            // own deadline is then the only bound, which is the stricter one.
            None => self.job.deadline(),
        }
    }

    fn profile(&self) -> &ScanProfile {
        self.job.profile()
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

/// The registry's contents, behind one lock: the per-job monitors in insertion
/// order (so the oldest can be evicted) and a bounded record of the jobs whose
/// monitor was lost when it was evicted, so a rebuilt monitor starts lost and
/// probing does not resume after a `session_lost` stop (S-M5).
#[derive(Default)]
struct MonitorTable {
    /// Job ids in insertion order, oldest first.
    order: VecDeque<String>,
    /// The live monitors, one per job id.
    monitors: HashMap<String, Arc<SessionMonitor>>,
    /// Evicted-lost job ids in insertion order, oldest first (for the bound).
    lost_order: VecDeque<String>,
    /// Membership test for [`MonitorTable::lost_order`].
    lost_ids: HashSet<String>,
}

impl MonitorTable {
    /// The monitor held for `key`, if any.
    fn get(&self, key: &str) -> Option<Arc<SessionMonitor>> {
        self.monitors.get(key).map(Arc::clone)
    }

    /// Whether `key`'s last monitor was evicted while lost (S-M5), so a
    /// rebuilt one must start lost.
    fn was_lost(&self, key: &str) -> bool {
        self.lost_ids.contains(key)
    }

    /// Hold `monitor` for `key`, newest in the eviction order, evicting the
    /// oldest monitors until no more than [`MAX_SESSION_MONITORS`] are held:
    /// the table owns its bound.
    fn insert(&mut self, key: String, monitor: Arc<SessionMonitor>) {
        self.monitors.insert(key.clone(), monitor);
        self.order.push_back(key);
        while self.over_capacity() {
            if !self.evict_oldest() {
                break;
            }
        }
    }

    /// Whether more monitors are held than [`MAX_SESSION_MONITORS`].
    fn over_capacity(&self) -> bool {
        self.monitors.len() > MAX_SESSION_MONITORS
    }

    /// Evict the oldest monitor, remembering its job when the monitor was
    /// lost; `false` when there was nothing to evict.
    fn evict_oldest(&mut self) -> bool {
        let Some(oldest) = self.order.pop_front() else {
            return false;
        };
        let was_lost = self
            .monitors
            .remove(&oldest)
            .is_some_and(|evicted| evicted.is_lost());
        if was_lost {
            tracing::debug!(job = %oldest, "scan: evicting a lost session monitor");
            self.remember_lost(oldest);
        }
        true
    }

    /// Remember that `key`'s monitor was evicted lost, keeping at most
    /// [`MAX_LOST_MONITOR_IDS`] such jobs, the oldest forgotten first.
    fn remember_lost(&mut self, key: String) {
        if !self.lost_ids.insert(key.clone()) {
            return;
        }
        self.lost_order.push_back(key);
        while self.lost_ids.len() > MAX_LOST_MONITOR_IDS {
            match self.lost_order.pop_front() {
                Some(stale) => {
                    self.lost_ids.remove(&stale);
                }
                None => break,
            }
        }
    }
}

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
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// The monitor for `job`, building it against `origin` the first time.
    pub(crate) fn for_job(&self, job: &dyn JobCtx, origin: &Url) -> Arc<SessionMonitor> {
        let key = job.job_id().to_string();
        let mut table = self
            .inner
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if let Some(found) = table.get(&key) {
            return found;
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
        // A rebuilt monitor for a job whose monitor was evicted while lost starts
        // lost, so probing does not resume after a `session_lost` stop (S-M5).
        if table.was_lost(&key) {
            monitor.force_lost();
        }
        table.insert(key, Arc::clone(&monitor));
        // The build is the one moment the canary is decided, so the job hears
        // it once — a later host of the same job finds the monitor above and
        // reports nothing (spec D5). Reported with the table lock dropped: the
        // job's own lock is not this registry's business.
        drop(table);
        job.report_session_canary(monitor.canary());
        monitor
    }

    /// How many monitors are held. Read only by this crate's tests to pin call
    /// A5 (one monitor per job, built on the first point), so it is test-only.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .monitors
            .len()
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
        Canary, CanaryMethod, FlowRef, InsertionKind, InsertionPoint, JobCtx, LaneKind, OnLost,
        Payload, PayloadMode, ProbeHost, RawProbe, RecordProbes, ScanProfile, SessionMaterial,
        SessionMode, MAX_MATCH_BODY,
    };

    use crate::host::{HttpProbeHost, SessionMonitors};
    use crate::limits::{MAX_HELD_FLOWS, MAX_LOST_MONITOR_IDS, MAX_SESSION_MONITORS};
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

    /// A method that is not an RFC 9110 token is refused with a value-free error
    /// (it never reaches the request line), and the method text does not leak
    /// into the message (S-M1).
    #[tokio::test]
    async fn probe_raw_rejects_a_non_token_method() {
        let fx = fixture(ok_200());
        let host = HttpProbeHost::new(&fx.point, fx.ctx(), unarmed()).unwrap();

        let refused = host
            .probe_raw(RawProbe {
                method: "GE T".to_string(),
                url: "http://t:8080/raw".to_string(),
                headers: Vec::new(),
                body: Vec::new(),
            })
            .await
            .expect_err("a non-token method is refused");
        let message = format!("{refused:#}");
        assert!(message.contains("method"), "unexpected message: {message}");
        assert!(
            !message.contains("GE T"),
            "the error leaked the method: {message}"
        );
        assert_eq!(fx.sent().len(), 0);
    }

    /// S-M1 (tester): every non-token shape is refused with the one literal,
    /// value-free message and nothing is sent; an unusual but legal token is
    /// put on the request line as given.
    #[tokio::test]
    async fn probe_raw_method_token_rule_pins() {
        let fx = fixture(ok_200());
        let host = HttpProbeHost::new(&fx.point, fx.ctx(), unarmed()).unwrap();
        let raw = |method: &str| RawProbe {
            method: method.to_string(),
            url: "http://t:8080/raw".to_string(),
            headers: Vec::new(),
            body: Vec::new(),
        };

        for bad in [
            "",
            "GE T",
            "GET\r\nX-Injected: 1",
            "GET\n",
            "G\tET",
            "GET/",
            "GET;",
            "G\u{c9}T",
            "GET\u{0}",
        ] {
            let Err(refused) = host.probe_raw(raw(bad)).await else {
                panic!("{bad:?} must be refused");
            };
            let message = format!("{refused:#}");
            assert_eq!(
                message, "scan: probe_raw: method is not a valid RFC 9110 token",
                "{bad:?}"
            );
        }
        assert_eq!(fx.sent().len(), 0, "a refused method sends nothing");

        for good in ["M-SEARCH", "PROPFIND", "get", "X!#$%&'*+.^_`|~1"] {
            host.probe_raw(raw(good))
                .await
                .unwrap_or_else(|err| panic!("{good:?} is a token: {err:#}"));
        }
        let methods: Vec<String> = fx
            .sent()
            .into_iter()
            .filter(|(req, _)| req.path == "/raw")
            .map(|(req, _)| req.method)
            .collect();
        assert_eq!(methods, ["M-SEARCH", "PROPFIND", "get", "X!#$%&'*+.^_`|~1"]);
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

    /// Task 22: the canary the lane armed is reported to the job once, when
    /// that job's monitor is **built**, so the engine can mirror it into
    /// `JobStatus.session.canary` (spec D5). A second host of the same job
    /// looks the monitor up and reports nothing.
    #[test]
    fn a_built_monitor_reports_its_canary_once() {
        let fx = fixture(ok_200());
        fx.store.insert(Flow::Http(captured_flow(
            request(
                "GET",
                "http://t:8080/account",
                &[("cookie", "sid=S3")],
                None,
            ),
            200,
            &[],
            b"account",
        )));

        let monitors = SessionMonitors::new();
        let first_origin = url::Url::parse("http://t:8080/").unwrap();
        let second_origin = url::Url::parse("http://t:8080/other").unwrap();

        let first = monitors.for_job(&*fx.job, &first_origin);
        let second = monitors.for_job(&*fx.job, &second_origin);
        assert!(Arc::ptr_eq(&first, &second), "one monitor per job");

        assert_eq!(
            fx.job.reported_canaries(),
            vec![Canary::Flow {
                method: CanaryMethod::Get,
                path: "/account".to_string(),
                expected_status: Some(200),
            }],
            "the picked canary is reported exactly once, on the build"
        );
    }

    /// Task 22: a job with `session.mode: none` arms no canary, and reports
    /// that — `Canary::None`, once — rather than nothing at all.
    #[test]
    fn an_unarmed_monitor_reports_canary_none_once() {
        let mut profile = ScanProfile::default();
        profile.session.mode = SessionMode::None;
        let fx = fixture_full(profile, ok_200(), 60);

        let monitors = SessionMonitors::new();
        let origin = url::Url::parse("http://t:8080/").unwrap();
        monitors.for_job(&*fx.job, &origin);
        monitors.for_job(&*fx.job, &origin);

        assert_eq!(fx.job.reported_canaries(), vec![Canary::None]);
    }

    /// Task 22: the first probe that sees the canary lose the session reports
    /// it once; no later probe reports it again, under either `on_lost`
    /// (spec D7).
    #[tokio::test]
    async fn a_lost_session_is_reported_once_per_job() {
        let fx = fixture(canary_lost_client());
        let host =
            HttpProbeHost::new(&fx.point, fx.ctx(), canary_monitor(2, OnLost::Stop)).unwrap();

        host.probe(&replace("one")).await.unwrap();
        assert_eq!(fx.job.session_lost_reports(), 0, "no loss yet");

        host.probe(&replace("two"))
            .await
            .expect_err("the second probe runs the canary and finds the session lost");
        assert_eq!(fx.job.session_lost_reports(), 1);

        host.probe(&replace("three"))
            .await
            .expect_err("a stopped job refuses every later probe");
        assert_eq!(
            fx.job.session_lost_reports(),
            1,
            "a refused probe is not a second loss"
        );

        // `continue`: probing goes on, the second check loses again, and the
        // job still hears about the loss exactly once.
        let fx = fixture(canary_lost_client());
        let host =
            HttpProbeHost::new(&fx.point, fx.ctx(), canary_monitor(2, OnLost::Continue)).unwrap();
        for index in 0..4 {
            host.probe(&replace(&format!("p{index}")))
                .await
                .unwrap_or_else(|e| panic!("probe {index} must still run: {e:#}"));
        }
        assert_eq!(fx.sent().len(), 6, "four probes and two canary checks");
        assert_eq!(fx.job.session_lost_reports(), 1);
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

    /// A lost monitor evicted from the bounded registry is rebuilt lost, so
    /// probing does not resume for a job after a `session_lost` stop (S-M5).
    #[tokio::test]
    async fn an_evicted_lost_monitor_is_rebuilt_lost() {
        let monitors = SessionMonitors::new();
        let origin = url::Url::parse("http://t:8080/").unwrap();

        let fx = fixture(ok_200());
        let first = monitors.for_job(&*fx.job, &origin);
        first.force_lost();
        assert!(first.should_stop());

        // Sixteen more jobs push job 1's monitor out of the registry.
        for index in 0..MAX_SESSION_MONITORS {
            let job = id_job(&format!("scan-fill-{index:08x}"), true);
            monitors.for_job(&job, &origin);
        }
        assert_eq!(monitors.len(), MAX_SESSION_MONITORS);

        let rebuilt = monitors.for_job(&*fx.job, &origin);
        assert!(
            rebuilt.should_stop(),
            "the rebuilt monitor must start lost, not fresh"
        );

        let host = HttpProbeHost::new(&fx.point, fx.ctx(), rebuilt).unwrap();
        let err = host.probe(&replace("x")).await.unwrap_err().to_string();
        assert!(err.starts_with(SESSION_LOST_PREFIX), "{err}");
    }

    /// S-M5 (tester): only a *lost* monitor's eviction is remembered. A live
    /// monitor evicted and rebuilt starts fresh, and the remembered set is
    /// bounded at `MAX_LOST_MONITOR_IDS`: once that many later lost evictions
    /// have happened, the oldest lost job is rebuilt fresh while the newer ones
    /// still start lost.
    #[test]
    fn lost_eviction_memory_is_lost_only_and_bounded() {
        let monitors = SessionMonitors::new();
        let origin = url::Url::parse("http://t:8080/").unwrap();
        let fill = |tag: &str, count: usize| {
            for index in 0..count {
                monitors.for_job(&id_job(&format!("scan-{tag}-{index:04x}"), true), &origin);
            }
        };

        // A live monitor evicted is rebuilt fresh.
        let live = id_job("scan-live0001", true);
        let first = monitors.for_job(&live, &origin);
        assert!(!first.is_lost());
        fill("fill-a", MAX_SESSION_MONITORS);
        let rebuilt = monitors.for_job(&live, &origin);
        assert!(!Arc::ptr_eq(&first, &rebuilt), "the monitor was evicted");
        assert!(
            !rebuilt.is_lost(),
            "a live eviction is not remembered as lost"
        );
        assert!(!rebuilt.should_stop());

        // The oldest lost eviction.
        let oldest = id_job("scan-lost0000", true);
        monitors.for_job(&oldest, &origin).force_lost();
        fill("fill-b", MAX_SESSION_MONITORS);
        assert!(monitors.for_job(&oldest, &origin).should_stop());
        // Rebuilding it put it back in the table; evict it again (it is still
        // lost, and the set does not grow for a repeat).
        fill("fill-c", MAX_SESSION_MONITORS);

        // `MAX_LOST_MONITOR_IDS` further lost evictions, each pushed out by
        // the next, then the last sixteen pushed out by fillers.
        let later: Vec<IdJob> = (0..MAX_LOST_MONITOR_IDS)
            .map(|index| id_job(&format!("scan-later-{index:04x}"), true))
            .collect();
        for job in &later {
            monitors.for_job(job, &origin).force_lost();
        }
        fill("fill-d", MAX_SESSION_MONITORS);
        assert_eq!(monitors.len(), MAX_SESSION_MONITORS);

        assert!(
            !monitors.for_job(&oldest, &origin).should_stop(),
            "the oldest lost job fell out of the bounded set and is rebuilt fresh"
        );
        assert!(monitors.for_job(&later[0], &origin).should_stop());
        assert!(monitors
            .for_job(&later[MAX_LOST_MONITOR_IDS - 1], &origin)
            .should_stop());
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

    // --- N1: `session.mode: none` means unauthenticated (AC T2-4) ----------

    /// A capture taken while the operator was logged in: its own session rides
    /// in a `Cookie`, an `Authorization` and a secret-named header, and the
    /// job's observed material repeats the session cookie.
    fn authed_capture() -> HttpRequest {
        request(
            "GET",
            "http://t:8080/account?tab=overview",
            &[
                ("cookie", "session=abc; theme=dark"),
                ("authorization", "Bearer tok"),
                ("x-api-key", "tok"),
            ],
            None,
        )
    }

    /// A fixture over a caller-supplied capture, pointed at its `tab` query
    /// parameter, with the capture's own session cookie as the job's material.
    fn fixture_capture(profile: ScanProfile, source: HttpRequest) -> Fixture {
        let store = Arc::new(MemFlowStore::new());
        let client = Arc::new(ok_200().recording_into(Arc::clone(&store) as Arc<dyn FlowStore>));
        let flow = captured_flow(source, 200, &[("content-type", "text/html")], b"hi");
        let flow_id = flow.id;
        store.insert(Flow::Http(flow));

        let mut job = FakeJob::new(profile, Arc::clone(&client))
            .with_store(Arc::clone(&store))
            .with_session(SessionMaterial {
                cookies: vec![("session".to_string(), "abc".to_string())],
                headers: Vec::new(),
            });
        job.deadline = Instant::now() + Duration::from_secs(60);

        let mut point = query_point(FlowRef(flow_id));
        point.name = "tab".to_string();
        Fixture {
            job: Arc::new(job),
            client,
            store,
            point,
        }
    }

    /// A profile that scans unauthenticated.
    fn mode_none() -> ScanProfile {
        let mut profile = ScanProfile::default();
        profile.session.mode = SessionMode::None;
        profile
    }

    /// Under `session.mode: none` the capture's own session goes once, at
    /// construction, so the baseline, every probe and every raw probe leave
    /// unauthenticated — including the session headers a check handed to
    /// `probe_raw` itself (AC T2-4).
    #[tokio::test]
    async fn session_mode_none_strips_the_captures_own_session() {
        let fx = fixture_capture(mode_none(), authed_capture());
        let host = HttpProbeHost::new(&fx.point, fx.ctx(), unarmed()).unwrap();

        host.baseline().await.unwrap();
        host.probe(&replace("x")).await.unwrap();
        host.probe_raw(RawProbe {
            method: "GET".to_string(),
            url: "http://t:8080/account".to_string(),
            headers: vec![
                ("Cookie".to_string(), "session=abc".to_string()),
                ("Authorization".to_string(), "Bearer tok".to_string()),
                ("X-Api-Key".to_string(), "tok".to_string()),
                ("X-Extra".to_string(), "yes".to_string()),
            ],
            body: Vec::new(),
        })
        .await
        .unwrap();

        let sent = fx.sent();
        assert_eq!(sent.len(), 3);
        for (what, (req, _)) in ["baseline", "probe", "probe_raw"].iter().zip(sent.iter()) {
            assert_eq!(req.headers.get("cookie"), None, "{what} sent a cookie");
            assert_eq!(
                req.headers.get("authorization"),
                None,
                "{what} sent an authorization header"
            );
            assert_eq!(
                req.headers.get("x-api-key"),
                None,
                "{what} sent a secret-named header"
            );
        }

        // Only the session goes: the capture and the raw probe keep the rest.
        assert_eq!(sent[0].0.path, "/account?tab=overview");
        assert_eq!(sent[0].0.headers.get("host"), Some("t:8080"));
        assert_eq!(sent[1].0.path, "/account?tab=x");
        assert_eq!(sent[2].0.headers.get("x-extra"), Some("yes"));

        // And no value of the stripped session reaches an error (AC T2-6).
        let refused = host
            .probe_raw(RawProbe {
                method: "GET".to_string(),
                url: "http://evil.test/in?session=abc&auth=tok".to_string(),
                headers: Vec::new(),
                body: Vec::new(),
            })
            .await
            .expect_err("another origin is refused");
        let text = format!("{refused:#}");
        for secret in ["abc", "tok"] {
            assert!(!text.contains(secret), "{secret} leaked: {text}");
        }
    }

    /// `mode: observed` is unchanged: the capture's own session rides and the
    /// job's material only fills the gaps (spec D7).
    #[tokio::test]
    async fn session_mode_observed_keeps_the_captures_own_session() {
        let fx = fixture_capture(ScanProfile::default(), authed_capture());
        assert_eq!(fx.job.profile().session.mode, SessionMode::Observed);
        let host = HttpProbeHost::new(&fx.point, fx.ctx(), unarmed()).unwrap();

        host.baseline().await.unwrap();

        let sent = fx.sent();
        assert_eq!(sent.len(), 1);
        assert_eq!(
            sent[0].0.headers.get("cookie"),
            Some("session=abc; theme=dark")
        );
        assert_eq!(sent[0].0.headers.get("authorization"), Some("Bearer tok"));
        assert_eq!(sent[0].0.headers.get("x-api-key"), Some("tok"));
    }
}
