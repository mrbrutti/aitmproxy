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
/// returns and spends one of the sixteen probes the host starts with; the budget
/// saturates at zero and the host keeps answering, because it is a recorder, not
/// an enforcer. A baseline costs nothing and is not recorded as a payload.
pub struct RecordingHost {
    /// An owning handle to this host, when it was built by
    /// [`RecordingHost::shared_new`]; otherwise dangling, so `shared()` is `None`.
    me: Weak<RecordingHost>,
    status: u16,
    body: Vec<u8>,
    sent: Mutex<Vec<String>>,
    budget: AtomicU32,
    profile: ScanProfile,
}

impl RecordingHost {
    /// A host answering `status` and `body`, owning no handle to itself.
    pub fn new(status: u16, body: &str) -> Self {
        Self {
            me: Weak::new(),
            status,
            body: body.as_bytes().to_vec(),
            sent: Mutex::new(Vec::new()),
            budget: AtomicU32::new(RECORDING_BUDGET),
            profile: ScanProfile::default(),
        }
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

    /// The payload values this host was sent, in order.
    pub fn payloads(&self) -> Vec<String> {
        self.sent().clone()
    }

    /// The canned response.
    fn response(&self) -> ProbeResponse {
        ProbeResponse {
            status: Some(self.status),
            headers: Vec::new(),
            body: self.body.clone(),
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
            Ok(self.response())
        })
    }

    fn probe_raw(&self, req: RawProbe) -> BoxFuture<'_, anyhow::Result<ProbeResponse>> {
        Box::pin(async move {
            self.sent().push(req.url.clone());
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
}
