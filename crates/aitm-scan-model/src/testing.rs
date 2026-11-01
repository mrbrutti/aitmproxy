//! Test stubs for this crate's traits (T1a Quality follow-up). Task 1 of the
//! T1b plan owns this file.
//!
//! Compiled under `cfg(test)` or the `testing` feature, never in a release
//! build. Every stub here answers the smallest thing its trait allows and
//! performs no I/O: the null client, job, host, check and lane exist so a test
//! can hold a `dyn Check` or a `dyn Lane` without inventing one, and
//! [`RecordingHost`] exists so a test can see what a check *sent*.
//!
//! Before T1b each test module defined its own copies; they are here once so a
//! trait gaining a method is one edit, and so the lane and scripting tracks can
//! test a `Check` implementation against the same stubs the model tests use.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use futures::future::BoxFuture;

use aitm_core::{
    BrowserDriver, FlowStore, HttpFlow, HttpRequest, MemFlowStore, ProxyClient, ScopeRateGuard,
    StdGuard,
};

use crate::check::{CheckMeta, Evidence, Verdict};
use crate::point::{InsertionPoint, Payload, ProbeResponse, RawProbe};
use crate::profile::{ProfileTarget, ScanProfile};
use crate::session::SessionMaterial;
use crate::traits::{Check, Discovery, JobCtx, Lane, ProbeHost};
use crate::vocab::{
    CheckCost, CheckOrigin, CheckScope, Confidence, InsertionKind, Intensity, LaneKind, Outcome,
    Technique,
};

/// How long a stub's deadline is from the moment it is asked.
const STUB_DEADLINE: Duration = Duration::from_secs(60);

/// The budget [`RecordingHost`] starts with, in probes.
const RECORDING_BUDGET: u32 = 16;

/// A [`ProxyClient`] that performs no I/O; every send is an error.
pub struct NullClient;

impl ProxyClient for NullClient {
    fn send(&self, _req: HttpRequest) -> BoxFuture<'_, anyhow::Result<HttpFlow>> {
        Box::pin(async { Err(anyhow::anyhow!("no client in the test context")) })
    }
}

/// A [`JobCtx`] whose handles are all inert: a null client, an in-memory flow
/// store and a default guard. Job id `scan-1a2b3c4d`, budget 7, marker
/// `aitm7f3a`.
pub struct NullJob {
    profile: ScanProfile,
    client: Arc<dyn ProxyClient>,
    store: Arc<dyn FlowStore>,
    guard: Arc<dyn ScopeRateGuard>,
}

impl NullJob {
    /// A job context over the default profile.
    pub fn new() -> Self {
        Self {
            profile: ScanProfile::default(),
            client: Arc::new(NullClient),
            store: Arc::new(MemFlowStore::new()),
            guard: Arc::new(StdGuard::default()),
        }
    }
}

impl Default for NullJob {
    fn default() -> Self {
        Self::new()
    }
}

impl JobCtx for NullJob {
    fn job_id(&self) -> &str {
        "scan-1a2b3c4d"
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
    fn guard(&self) -> Arc<dyn ScopeRateGuard> {
        Arc::clone(&self.guard)
    }
    fn browser(&self) -> Option<Arc<dyn BrowserDriver>> {
        None
    }
    fn session(&self) -> Option<Arc<SessionMaterial>> {
        None
    }
    fn charge(&self, _units: u32) -> bool {
        true
    }
    fn budget_left(&self) -> u32 {
        7
    }
    fn deadline(&self) -> Instant {
        Instant::now() + STUB_DEADLINE
    }
    fn cancelled(&self) -> bool {
        false
    }
    fn marker(&self) -> String {
        "aitm7f3a".to_string()
    }
}

/// A [`ProbeHost`] whose every I/O method errors. Budget 3, marker `aitm7f3a`.
///
/// It inherits the default bodies of [`ProbeHost::client`],
/// [`ProbeHost::shared`] and [`ProbeHost::captured`], which is what makes it the
/// stub those defaults are tested through.
pub struct NullHost {
    profile: ScanProfile,
}

impl NullHost {
    /// A probe host over the default profile.
    pub fn new() -> Self {
        Self {
            profile: ScanProfile::default(),
        }
    }
}

impl Default for NullHost {
    fn default() -> Self {
        Self::new()
    }
}

impl ProbeHost for NullHost {
    fn baseline(&self) -> BoxFuture<'_, anyhow::Result<ProbeResponse>> {
        Box::pin(async { Err(anyhow::anyhow!("no baseline in the test context")) })
    }
    fn probe<'a>(&'a self, _payload: &'a Payload) -> BoxFuture<'a, anyhow::Result<ProbeResponse>> {
        Box::pin(async { Err(anyhow::anyhow!("no probe in the test context")) })
    }
    fn probe_raw(&self, _req: RawProbe) -> BoxFuture<'_, anyhow::Result<ProbeResponse>> {
        Box::pin(async { Err(anyhow::anyhow!("no probe in the test context")) })
    }
    fn marker(&self) -> String {
        "aitm7f3a".to_string()
    }
    fn budget_left(&self) -> u32 {
        3
    }
    fn deadline(&self) -> Instant {
        Instant::now() + STUB_DEADLINE
    }
    fn profile(&self) -> &ScanProfile {
        &self.profile
    }
    fn cancelled(&self) -> bool {
        false
    }
    fn held_flows(&self) -> Vec<aitm_core::Flow> {
        Vec::new()
    }
}

/// A [`CheckMeta`] for `id`: class `none`, HTTP lane, query points, passive,
/// light, observing, info, tentative, native, scoped per point.
pub fn null_meta(id: &str) -> CheckMeta {
    CheckMeta {
        id: id.to_string(),
        name: id.to_string(),
        class: "none".to_string(),
        lanes: vec![LaneKind::Http],
        kinds: vec![InsertionKind::Query],
        intensity: Intensity::Passive,
        cost: CheckCost::Light,
        technique: Technique::Observe,
        severity: aitm_poc::Severity::Info,
        confidence_max: Confidence::Tentative,
        needs_baseline: false,
        wants_traits: None,
        targets_session: false,
        scope: CheckScope::Point,
        cwe: None,
        description: "Concludes nothing.".to_string(),
        remediation: None,
        origin: CheckOrigin::Native,
    }
}

/// A [`Check`] that sends nothing and always returns a clean, tentative verdict
/// with the detail `nothing to report`.
pub struct NullCheck {
    meta: CheckMeta,
}

impl NullCheck {
    /// A check carrying `meta` (usually from [`null_meta`]).
    pub fn new(meta: CheckMeta) -> Self {
        Self { meta }
    }
}

impl Check for NullCheck {
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
                outcome: Outcome::Clean,
                confidence: Confidence::Tentative,
                evidence: Evidence::default(),
                detail: "nothing to report".to_string(),
                poc_hint: None,
                location: None,
                more: Vec::new(),
            }
        })
    }
}

/// An HTTP [`Lane`] that discovers nothing, ships no check and hosts no probe.
pub struct NullLane;

impl Lane for NullLane {
    fn lane(&self) -> LaneKind {
        LaneKind::Http
    }
    fn discover<'a>(
        &'a self,
        _target: &'a ProfileTarget,
        _job: &'a dyn JobCtx,
    ) -> BoxFuture<'a, anyhow::Result<Discovery>> {
        Box::pin(async { Ok(Discovery::default()) })
    }
    fn probe_host_for(
        &self,
        _point: &InsertionPoint,
        _job: Arc<dyn JobCtx>,
    ) -> anyhow::Result<Box<dyn ProbeHost>> {
        Err(anyhow::anyhow!("the null lane hosts no probes"))
    }
    fn checks(&self) -> Vec<Arc<dyn Check>> {
        Vec::new()
    }
}

/// A `GET` query-parameter [`InsertionPoint`] named `name` on `url`, id `p1`.
pub fn query_point(url: &str, name: &str) -> InsertionPoint {
    InsertionPoint {
        id: "p1".to_string(),
        lane: LaneKind::Http,
        kind: InsertionKind::Query,
        name: name.to_string(),
        path: None,
        example: None,
        flow: None,
        site_node: None,
        traits: Vec::new(),
        frequency: 1,
        method: Some("GET".to_string()),
        url: Some(url.to_string()),
    }
}

/// A [`ProbeHost`] that records what a check sent and answers one canned
/// response, so a test can assert on the payloads rather than on the network.
///
/// Every probe appends its payload's `value` to the list [`RecordingHost::payloads`]
/// returns, every raw probe appends its URL to the list [`RecordingHost::raw_urls`]
/// returns, and each spends one of the sixteen probes the host starts with; the
/// budget saturates at zero and the host keeps answering, because it is a
/// recorder, not an enforcer. A baseline costs nothing and is recorded nowhere.
///
/// A `probe` may be answered from a payload-keyed table instead of the canned
/// reply ([`RecordingHost::with_reply_for`]), so a multi-path check can be
/// driven to distinct answers per path; `baseline` and `probe_raw` always give
/// the canned reply.
pub struct RecordingHost {
    /// An owning handle to this host, when it was built by
    /// [`RecordingHost::shared_new`]; otherwise dangling, so `shared()` is `None`.
    me: Weak<RecordingHost>,
    status: u16,
    body: Vec<u8>,
    /// Payload values from `probe`, in order.
    sent: Mutex<Vec<String>>,
    /// URLs from `probe_raw`, in order.
    raw: Mutex<Vec<String>>,
    budget: AtomicU32,
    profile: ScanProfile,
    /// The address the canned baseline is pretended to have come from, when a
    /// test pinned one with [`RecordingHost::with_peer`]. `None` otherwise.
    peer: Option<SocketAddr>,
    /// `(needle, status, body)` in registration order; the first needle that is
    /// a substring of a probe's payload value answers that probe.
    replies: Vec<(String, u16, Vec<u8>)>,
}

impl RecordingHost {
    /// A host answering `status` and `body`, owning no handle to itself.
    pub fn new(status: u16, body: &str) -> Self {
        Self {
            me: Weak::new(),
            status,
            body: body.as_bytes().to_vec(),
            sent: Mutex::new(Vec::new()),
            raw: Mutex::new(Vec::new()),
            budget: AtomicU32::new(RECORDING_BUDGET),
            profile: ScanProfile::default(),
            peer: None,
            replies: Vec::new(),
        }
    }

    /// The same host, answering `status`/`body` to any `probe` whose payload
    /// value contains `needle`. Entries are consulted in the order they were
    /// added and the first match wins; a payload no needle matches gets the
    /// canned reply. `baseline` and `probe_raw` never consult the table.
    #[must_use]
    pub fn with_reply_for(mut self, needle: &str, status: u16, body: &str) -> Self {
        self.replies
            .push((needle.to_string(), status, body.as_bytes().to_vec()));
        self
    }

    /// The same host, pinned to the peer address its baseline came from, so a
    /// test can assert a raw probe dialled exactly that address rather than
    /// re-resolving the name (spec D7's DNS-rebinding window).
    #[must_use]
    pub fn with_peer(mut self, addr: SocketAddr) -> Self {
        self.peer = Some(addr);
        self
    }

    /// The same host behind an `Arc`, so [`ProbeHost::shared`] hands an owning
    /// handle back — what a scripting bridge holding the host in a thread-local
    /// needs (spec D9.3, plan call B5).
    pub fn shared_new(status: u16, body: &str) -> Arc<RecordingHost> {
        Arc::new_cyclic(|me| RecordingHost {
            me: me.clone(),
            ..RecordingHost::new(status, body)
        })
    }

    /// The payload values this host was sent through `probe`, in order. A raw
    /// probe is not here; see [`RecordingHost::raw_urls`].
    pub fn payloads(&self) -> Vec<String> {
        self.sent().clone()
    }

    /// The URLs this host was sent through `probe_raw`, in order.
    pub fn raw_urls(&self) -> Vec<String> {
        self.raw.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// The canned response.
    fn response(&self) -> ProbeResponse {
        self.response_with(self.status, self.body.clone())
    }

    /// The table's reply for `payload` when a needle matches, else the canned one.
    fn response_for(&self, payload: &str) -> ProbeResponse {
        match self
            .replies
            .iter()
            .find(|(needle, _, _)| payload.contains(needle.as_str()))
        {
            Some((_, status, body)) => self.response_with(*status, body.clone()),
            None => self.response(),
        }
    }

    fn response_with(&self, status: u16, body: Vec<u8>) -> ProbeResponse {
        ProbeResponse {
            status: Some(status),
            headers: Vec::new(),
            body,
            elapsed_ms: 1,
            flow: None,
            ws_frames: None,
            l4: None,
        }
    }

    /// The recorded payloads, recovering the list if a writer panicked.
    fn sent(&self) -> std::sync::MutexGuard<'_, Vec<String>> {
        self.sent.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Charge one probe, saturating at zero.
    fn charge_one(&self) {
        let _ = self
            .budget
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |left| {
                Some(left.saturating_sub(1))
            });
    }
}

impl ProbeHost for RecordingHost {
    fn baseline(&self) -> BoxFuture<'_, anyhow::Result<ProbeResponse>> {
        Box::pin(async { Ok(self.response()) })
    }

    fn probe<'a>(&'a self, payload: &'a Payload) -> BoxFuture<'a, anyhow::Result<ProbeResponse>> {
        Box::pin(async {
            self.sent().push(payload.value.clone());
            self.charge_one();
            Ok(self.response_for(&payload.value))
        })
    }

    fn probe_raw(&self, req: RawProbe) -> BoxFuture<'_, anyhow::Result<ProbeResponse>> {
        Box::pin(async move {
            self.raw
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(req.url.clone());
            self.charge_one();
            Ok(self.response())
        })
    }

    fn marker(&self) -> String {
        "aitm7f3a".to_string()
    }

    fn budget_left(&self) -> u32 {
        self.budget.load(Ordering::SeqCst)
    }

    fn deadline(&self) -> Instant {
        Instant::now() + STUB_DEADLINE
    }

    fn profile(&self) -> &ScanProfile {
        &self.profile
    }

    fn cancelled(&self) -> bool {
        false
    }

    fn held_flows(&self) -> Vec<aitm_core::Flow> {
        Vec::new()
    }

    fn shared(&self) -> Option<Arc<dyn ProbeHost>> {
        self.me.upgrade().map(|host| host as Arc<dyn ProbeHost>)
    }

    /// An inert client, so a script check driven by the recorder runs on the
    /// bridge's budgeted path and a closure's `http.send` is refused rather
    /// than reaching any network (spec D9.3).
    fn client(&self) -> Option<Arc<dyn ProxyClient>> {
        Some(Arc::new(NullClient))
    }

    fn baseline_peer_addr(&self) -> Option<SocketAddr> {
        self.peer
    }

    /// The recorder charges for real, so a test can see a bypassing stimulus
    /// spend budget. A charge the budget cannot cover is refused and spends
    /// nothing, so the count never wraps.
    fn charge(&self, units: u32) -> bool {
        self.budget
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |left| {
                left.checked_sub(units)
            })
            .is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::{Check, JobCtx, Lane, ProbeHost};
    use crate::vocab::PayloadMode;
    use futures::executor::block_on;

    fn payload(value: &str) -> Payload {
        Payload {
            value: value.to_string(),
            mode: PayloadMode::Replace,
            bytes: None,
        }
    }

    #[test]
    fn recording_host_records_payloads() {
        let host = RecordingHost::new(200, "hello");

        for value in ["x", "y"] {
            let response = block_on(host.probe(&payload(value))).expect("the stub answers");
            assert_eq!(response.status, Some(200));
            assert_eq!(response.body, b"hello".to_vec());
            assert_eq!(response.elapsed_ms, 1);
        }

        assert_eq!(host.payloads(), vec!["x".to_string(), "y".to_string()]);
        assert_eq!(host.budget_left(), 14);
    }

    #[test]
    fn recording_host_baseline_is_the_canned_response() {
        let host = RecordingHost::new(404, "gone");
        let baseline = block_on(host.baseline()).expect("the stub answers");

        assert_eq!(baseline.status, Some(404));
        assert_eq!(baseline.body, b"gone".to_vec());
        assert_eq!(host.budget_left(), 16, "a baseline costs the stub nothing");
        assert!(host.payloads().is_empty(), "a baseline is not a payload");
    }

    #[test]
    fn shared_new_hands_back_an_owning_handle() {
        let host = RecordingHost::shared_new(204, "");
        let shared = host.shared().expect("shared_new owns a handle");
        assert_eq!(shared.budget_left(), 16);

        assert!(
            RecordingHost::new(204, "").shared().is_none(),
            "a stack-built host owns no handle"
        );
    }

    #[test]
    fn the_null_stubs_conclude_nothing() {
        let job = NullJob::new();
        assert_eq!(job.job_id(), "scan-1a2b3c4d");
        assert_eq!(job.budget_left(), 7);
        assert_eq!(job.marker(), "aitm7f3a");

        let host = NullHost::new();
        assert_eq!(host.budget_left(), 3);
        assert!(block_on(host.baseline()).is_err());

        let meta = null_meta("null-check");
        assert_eq!(meta.id, "null-check");
        assert_eq!(meta.class, "none");

        let check = NullCheck::new(meta);
        let verdict = block_on(check.run(&query_point("http://127.0.0.1:8080/s", "q"), &host));
        assert_eq!(verdict.detail, "nothing to report");

        assert_eq!(NullLane.lane(), crate::vocab::LaneKind::Http);
        assert!(NullLane.checks().is_empty());
    }

    /// Coordinator decision (2026-11-01): the recorder can be pinned to a peer
    /// address, so an engine test can prove a raw probe dialled the address the
    /// baseline came from rather than re-resolving the name.
    #[test]
    fn recording_host_reports_its_peer() {
        let addr: std::net::SocketAddr = "127.0.0.1:8080".parse().expect("a literal address");

        let host = RecordingHost::new(200, "ok").with_peer(addr);
        let dynamic: &dyn ProbeHost = &host;

        assert_eq!(dynamic.baseline_peer_addr(), Some(addr));
        assert_eq!(
            dynamic.baseline_peer_addr().map(|a| a.to_string()),
            Some("127.0.0.1:8080".to_string())
        );
        assert_eq!(
            RecordingHost::new(200, "ok").baseline_peer_addr(),
            None,
            "a recorder nobody pinned knows no peer"
        );
    }

    /// T3 security panel (2026-11-01): the recorder charges for real, so an
    /// engine test can prove a raw-h2 stream spent a unit. A charge it cannot
    /// cover is refused *and* spends nothing.
    #[test]
    fn recording_host_charge_spends_the_budget_and_refuses_what_it_cannot_cover() {
        let host = RecordingHost::new(200, "ok");
        let dynamic: &dyn ProbeHost = &host;
        assert_eq!(dynamic.budget_left(), 16);

        assert!(dynamic.charge(10), "ten of sixteen is affordable");
        assert_eq!(dynamic.budget_left(), 6);

        assert!(!dynamic.charge(7), "seven of six is not");
        assert_eq!(dynamic.budget_left(), 6, "a refused charge spends nothing");
    }

    /// Tester: the recorder's budget saturates at zero and it keeps answering —
    /// it is a recorder, not an enforcer, so a check that overspends is visible
    /// in `payloads()` rather than hidden behind an error.
    #[test]
    fn recording_host_budget_saturates_at_zero_and_keeps_answering() {
        let host = RecordingHost::new(200, "ok");
        for i in 0..20 {
            block_on(host.probe(&payload(&i.to_string()))).expect("the recorder keeps answering");
        }
        assert_eq!(host.budget_left(), 0);
        assert_eq!(host.payloads().len(), 20);
    }

    /// Tester: `probe_raw` is recorded (by URL, in its own list) and charged
    /// like a probe, so a handshake-style check's sends are visible to a test
    /// too — without a URL ever posing as a payload value in `payloads()`.
    #[test]
    fn recording_host_probe_raw_records_the_url_and_charges() {
        let host = RecordingHost::new(200, "ok");
        block_on(host.probe(&payload("x"))).expect("the stub answers");
        let response = block_on(host.probe_raw(RawProbe {
            method: "OPTIONS".to_string(),
            url: "http://127.0.0.1:8080/raw".to_string(),
            headers: vec![("X-Test".to_string(), "1".to_string())],
            body: Vec::new(),
        }))
        .expect("the stub answers");

        assert_eq!(response.status, Some(200));
        assert_eq!(
            host.raw_urls(),
            vec!["http://127.0.0.1:8080/raw".to_string()]
        );
        assert_eq!(
            host.payloads(),
            vec!["x".to_string()],
            "a raw probe's URL is not a payload value"
        );
        assert_eq!(host.budget_left(), 14, "one probe and one raw probe");
    }

    /// Tester: an empty payload is a payload — recorded as `""`, charged once.
    #[test]
    fn recording_host_records_an_empty_payload() {
        let host = RecordingHost::new(200, "");
        let response = block_on(host.probe(&payload(""))).expect("the stub answers");
        assert!(response.body.is_empty());
        assert_eq!(host.payloads(), vec![String::new()]);
        assert_eq!(host.budget_left(), 15);
    }

    /// Coordinator item (2026-11-01): a payload-keyed reply table, so a test
    /// can drive a multi-path check — `/.git/` answers one body, `/.env`
    /// another — and a payload nothing matches still gets the canned default.
    /// Only `probe` consults the table.
    #[test]
    fn recording_host_answers_by_payload_needle() {
        let host = RecordingHost::new(200, "default")
            .with_reply_for(".git", 200, "ref: refs/heads/main")
            .with_reply_for(".env", 403, "forbidden");

        let git = block_on(host.probe(&payload("/.git/HEAD"))).expect("the stub answers");
        assert_eq!(git.status, Some(200));
        assert_eq!(git.body, b"ref: refs/heads/main".to_vec());

        let env = block_on(host.probe(&payload("/.env"))).expect("the stub answers");
        assert_eq!(env.status, Some(403));
        assert_eq!(env.body, b"forbidden".to_vec());

        let other = block_on(host.probe(&payload("/robots.txt"))).expect("the stub answers");
        assert_eq!(other.status, Some(200));
        assert_eq!(other.body, b"default".to_vec());

        let baseline = block_on(host.baseline()).expect("the stub answers");
        assert_eq!(
            baseline.body,
            b"default".to_vec(),
            "baseline ignores the table"
        );
        let raw = block_on(host.probe_raw(RawProbe {
            method: "GET".to_string(),
            url: "http://127.0.0.1:8080/.git/".to_string(),
            headers: Vec::new(),
            body: Vec::new(),
        }))
        .expect("the stub answers");
        assert_eq!(raw.body, b"default".to_vec(), "probe_raw ignores the table");

        assert_eq!(
            host.payloads(),
            vec![
                "/.git/HEAD".to_string(),
                "/.env".to_string(),
                "/robots.txt".to_string()
            ]
        );
    }

    /// Wave-2/3 security review: a script check must only ever send through
    /// the host's budgeted client. The recorder therefore lends one — inert, so
    /// a closure's `http.send` is refused rather than reaching the network —
    /// instead of the trait default `None`, which the bridge is to treat as a
    /// wiring error.
    #[test]
    fn recording_host_lends_an_inert_client() {
        let host = RecordingHost::new(200, "ok");
        let dynamic: &dyn ProbeHost = &host;
        let client = dynamic.client().expect("the recorder lends a client");
        let err = block_on(client.send(HttpRequest {
            method: "GET".to_string(),
            scheme: "http".to_string(),
            authority: "127.0.0.1:8080".to_string(),
            path: "/".to_string(),
            version: aitm_core::HttpVersion::Http11,
            headers: aitm_core::HeaderMap::new(),
            body: aitm_core::Body::Empty,
            timestamp: std::time::SystemTime::now(),
        }))
        .expect_err("the lent client sends nothing");
        assert!(err.to_string().contains("no client"), "{err}");
    }
}
