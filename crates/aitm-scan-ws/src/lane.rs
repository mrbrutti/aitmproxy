//! The `WsLane` — scanner v2's WebSocket half of the `Lane` seam.
//!
//! Everything protocol-specific about WebSockets reaches the engine through
//! this one object (spec D1, D2): discovery reads the *already captured*
//! conversations in the job's flow store, `probe_host_for` re-drives one of
//! their insertion points as a real conversation, and `checks()` hands over the
//! eight native WS checks. The engine owns scheduling, budget and results; the
//! binary registers the lane by calling [`build`], so adding this lane edits no
//! shared file.
//!
//! Three rules here are load-bearing:
//!
//! - **The lane is the registry.** An `InsertionPoint` on the wire carries no
//!   way back to the capture it came from, so `discover` keeps the
//!   [`PointSpec`] of every point it minted, under the id of the job it minted
//!   it for, and `probe_host_for` looks the point up by `(job id, point id)`
//!   and re-reads the two flows the spec names out of that job's store (plan
//!   call 4). An id this lane never issued for this job is an error, never a
//!   quietly empty probe; so is a point whose conversation the store has since
//!   dropped. Only the specs are held, and only for the last
//!   [`REGISTERED_JOBS`] jobs, so a lane that lives as long as the process does
//!   not grow with every job it serves.
//! - **One dialer per lane.** The 4-permit semaphore lives in the
//!   [`WsDialer`], and every probe host the lane builds shares this one dialer,
//!   so a job holds at most 4 WebSocket connections open — and two concurrent
//!   jobs share those 4, which errs toward fewer connections than the spec's
//!   "4 per job" (plan calls 2 and 23).
//! - **Only captured, non-replay, in-target conversations.** A conversation the
//!   scanner itself drove (`is_replay`) is never a source of points, and a
//!   conversation whose handshake origin is outside `target.origins` is skipped
//!   before anything is read out of it (plan call 4).

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use aitm_core::{Flow, FlowKind, FlowQuery};
use aitm_scan_model::{
    Check, Discovery, InsertionPoint, JobCtx, Lane, LaneKind, ProbeHost, ProfileTarget, SiteNode,
};
use anyhow::anyhow;
use futures::future::BoxFuture;

use crate::checks;
use crate::dialer::WsDialer;
use crate::discover::{discover_flow, origin_matches, IdGen};
use crate::host::WsProbeHost;
use crate::transport::TcpTransport;
use crate::types::{PointSpec, TlsPolicy};

/// How long the production transport waits for a TCP connect or TLS handshake.
const DIAL_TIMEOUT: Duration = Duration::from_secs(10);

/// How many jobs' point specs the lane keeps before it drops the oldest.
///
/// A lane is built once and lives as long as the process, so the registry is
/// bounded: the seventeenth job to discover evicts the first, whose points then
/// read as unknown (quality finding Q2).
pub const REGISTERED_JOBS: usize = 16;

/// The point specs of the jobs the lane has discovered for.
///
/// Specs only — a few hundred bytes a point. The flows a spec names are read
/// back out of the job's own store when a probe is built, so a conversation is
/// never cloned per point and the lane never pins a flow the store has dropped.
#[derive(Debug, Default)]
struct Registry {
    /// Job id -> point id -> where in the conversation that point sits.
    jobs: HashMap<String, HashMap<String, PointSpec>>,
    /// The registered job ids in first-registration order; the front is the
    /// oldest and is what eviction drops.
    order: VecDeque<String>,
}

/// The WebSocket lane: discovery, probe hosting and the eight native checks.
pub struct WsLane {
    /// Shared by every probe host this lane builds, so its 4 permits bound the
    /// whole lane (plan calls 2 and 23).
    dialer: Arc<WsDialer>,
    /// What each job's points were, bounded at [`REGISTERED_JOBS`] jobs.
    registry: Mutex<Registry>,
}

impl WsLane {
    /// A lane that dials through `dialer`.
    #[must_use]
    pub fn new(dialer: Arc<WsDialer>) -> Self {
        Self {
            dialer,
            registry: Mutex::new(Registry::default()),
        }
    }

    /// Remember `specs` (the points just minted) under `job_id`, so
    /// `probe_host_for` can find them again by `(job id, point id)`.
    ///
    /// Registering a job the lane has not seen before may evict the oldest one.
    fn register(&self, job_id: &str, specs: Vec<(String, PointSpec)>) {
        let mut guard = self.registry.lock().unwrap_or_else(PoisonError::into_inner);
        let registry = &mut *guard;
        let points = match registry.jobs.get_mut(job_id) {
            Some(points) => points,
            None => {
                registry.order.push_back(job_id.to_string());
                registry.jobs.entry(job_id.to_string()).or_default()
            }
        };
        for (id, spec) in specs {
            points.insert(id, spec);
        }
        while registry.order.len() > REGISTERED_JOBS {
            match registry.order.pop_front() {
                Some(oldest) => {
                    registry.jobs.remove(&oldest);
                }
                // Unreachable while `len() > 16`, but a `break` is cheaper than
                // an `expect` in a path that holds a lock.
                None => break,
            }
        }
    }

    /// The spec registered for `point` under `job_id`, if this lane minted it.
    fn spec_for(&self, job_id: &str, point_id: &str) -> Option<PointSpec> {
        let registry = self.registry.lock().unwrap_or_else(PoisonError::into_inner);
        registry
            .jobs
            .get(job_id)
            .and_then(|points| points.get(point_id))
            .cloned()
    }
}

/// Fold `from` into the node `into`, which addresses the same endpoint.
///
/// Two captured conversations to the same `(scheme, host, port, path)` are one
/// site-map node: their flows and `(kind, name)` pairs are unioned and their
/// point counts added. Every other field is the first conversation's, which is
/// the one that created the node.
fn merge_node(into: &mut SiteNode, from: SiteNode) {
    for flow in from.flows {
        if !into.flows.contains(&flow) {
            into.flows.push(flow);
        }
    }
    for param in from.params {
        if !into.params.contains(&param) {
            into.params.push(param);
        }
    }
    into.points = into.points.saturating_add(from.points);
}

impl Lane for WsLane {
    fn lane(&self) -> LaneKind {
        LaneKind::Ws
    }

    fn discover<'a>(
        &'a self,
        target: &'a ProfileTarget,
        job: &'a dyn JobCtx,
    ) -> BoxFuture<'a, anyhow::Result<Discovery>> {
        Box::pin(async move {
            let store = job.store();
            // One generator for the whole pass: its collision suffix is what
            // keeps ids unique across the conversations of one job.
            let mut ids = IdGen::new(job.job_id());
            let mut points: Vec<InsertionPoint> = Vec::new();
            let mut nodes: Vec<SiteNode> = Vec::new();

            let captured = store.query(&FlowQuery {
                kind: Some(FlowKind::WebSocket),
                is_replay: Some(false),
                ..FlowQuery::default()
            });

            for id in captured {
                // A flow that vanished between the query and the read (the
                // store evicts) is skipped: discovery is best-effort, and a
                // partial result is a successful discovery.
                let Some(Flow::WebSocket(ws)) = store.get(id) else {
                    continue;
                };
                let Some(Flow::Http(handshake)) = store.get(ws.handshake) else {
                    continue;
                };
                if !origin_matches(&handshake, &target.origins) {
                    continue;
                }

                let found = discover_flow(&ws, &handshake, &mut ids);
                self.register(job.job_id(), found.specs);

                match nodes.iter_mut().find(|node| {
                    node.scheme == found.node.scheme
                        && node.host == found.node.host
                        && node.port == found.node.port
                        && node.path_template == found.node.path_template
                }) {
                    Some(existing) => merge_node(existing, found.node),
                    None => nodes.push(found.node),
                }
                points.extend(found.points);
            }

            tracing::debug!(
                points = points.len(),
                nodes = nodes.len(),
                "ws lane discovery finished"
            );
            Ok(Discovery { points, nodes })
        })
    }

    fn probe_host_for(
        &self,
        point: &InsertionPoint,
        job: Arc<dyn JobCtx>,
    ) -> anyhow::Result<Box<dyn ProbeHost>> {
        let spec = self
            .spec_for(job.job_id(), &point.id)
            .ok_or_else(|| anyhow!("unknown ws point {}", point.id))?;

        // The registry holds no flows: the conversation and its handshake are
        // read back out of the job's store, which may have dropped either of
        // them since discovery ran.
        let store = job.store();
        let Some(Flow::WebSocket(ws)) = store.get(spec.ws_flow) else {
            return Err(anyhow!(
                "the point's flow is no longer in the store: {}",
                point.id
            ));
        };
        let Some(Flow::Http(handshake)) = store.get(spec.handshake) else {
            return Err(anyhow!(
                "the point's flow is no longer in the store: {} (handshake)",
                point.id
            ));
        };

        let host = WsProbeHost::new(
            point.clone(),
            spec,
            handshake,
            ws,
            Arc::clone(&self.dialer),
            job,
        )?;
        Ok(Box::new(host))
    }

    fn checks(&self) -> Vec<Arc<dyn Check>> {
        checks::all()
    }
}

/// The WebSocket lane, registered by `crates/aitm/src/wire.rs` through
/// [`crate::lane`].
///
/// **Security review, named item (plan call 3; finding S2).** The production
/// dialer **verifies** upstream certificates against the webpki roots
/// ([`TlsPolicy::Verify`]), the same default `aitm-proto-http`'s `Http1Sender`
/// has (`Config.ssl_insecure = false`). A lab of self-signed targets is served
/// by [`build_with`]`(TlsPolicy::AcceptAny)`, which is what the operator's
/// `ssl_insecure` setting should select; wiring that setting through
/// `wire.rs` is a coordinator hand-off. Every dial still passes the scope guard
/// and the SSRF check before a socket is opened, under either policy.
#[must_use]
pub fn build() -> Option<Arc<dyn Lane>> {
    build_with(TlsPolicy::Verify)
}

/// The WebSocket lane with an explicit certificate policy.
///
/// `TlsPolicy::AcceptAny` skips chain validation (the handshake signature is
/// still verified) and is for `Config.ssl_insecure`; see [`build`].
#[must_use]
pub fn build_with(tls: TlsPolicy) -> Option<Arc<dyn Lane>> {
    let transport = Arc::new(TcpTransport::new(tls, DIAL_TIMEOUT));
    Some(Arc::new(WsLane::new(Arc::new(WsDialer::new(transport)))))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use aitm_core::{Flow, FlowId, InterceptState};
    use aitm_scan_model::{CheckOrigin, InsertionKind, InsertionPoint, JobCtx, Lane, LaneKind};

    use super::WsLane;
    use crate::dialer::WsDialer;
    use crate::testing::{captured_conversation, point, DuplexTransport, TestJob};
    use crate::types::{Locator, PointSpec};

    /// A lane whose transport is never dialled: these tests read the flow store
    /// and build hosts, they never open a conversation.
    fn lane() -> WsLane {
        WsLane::new(Arc::new(WsDialer::new(DuplexTransport::new(|_| {}))))
    }

    /// A job whose store holds the three conversations the task names: the
    /// fixture pair, a replayed copy of it, and a copy against another
    /// authority. Returns the job and the id of the one conversation discovery
    /// is allowed to read.
    fn job_with_three_conversations() -> (Arc<TestJob>, FlowId) {
        let job = TestJob::new(64);
        let store = job.store();

        // (a) The capture discovery must find.
        let (handshake, ws) = captured_conversation();
        let wanted = ws.id;
        store.insert(Flow::Http(handshake));
        store.insert(Flow::WebSocket(ws));

        // (b) The same conversation re-driven by a previous scan: a replay is
        // the scanner's own traffic and is never a source of points.
        let (mut handshake, mut ws) = captured_conversation();
        handshake.metadata.is_replay = true;
        ws.metadata.is_replay = true;
        store.insert(Flow::Http(handshake));
        store.insert(Flow::WebSocket(ws));

        // (c) The same conversation against a host the job never targeted.
        let (mut handshake, ws) = captured_conversation();
        handshake.request.authority = "other.test:8080".to_string();
        store.insert(Flow::Http(handshake));
        store.insert(Flow::WebSocket(ws));

        (job, wanted)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn discover_reads_only_captured_in_target_ws_flows() {
        let (job, wanted) = job_with_three_conversations();
        let lane = lane();

        let found = lane
            .discover(&job.profile().target, &*job)
            .await
            .expect("discovery over a store it can read");

        assert_eq!(found.points.len(), 6);
        assert_eq!(found.nodes.len(), 1);
        assert_eq!(found.nodes[0].path_template, "/ws");
        for found_point in &found.points {
            assert_eq!(found_point.flow.map(|flow| flow.0), Some(wanted));
            assert_eq!(found_point.lane, LaneKind::Ws);
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn probe_host_for_registered_point_builds_a_host() {
        let (job, _) = job_with_three_conversations();
        let lane = lane();
        let found = lane
            .discover(&job.profile().target, &*job)
            .await
            .expect("discovery over a store it can read");

        let msg = &found.points[4];
        assert_eq!(msg.name, "msg");

        let host = lane
            .probe_host_for(msg, job.clone())
            .expect("a point the lane itself registered is hostable");
        assert_eq!(host.profile().ws.reply_window_ms, 300);
    }

    #[test]
    fn probe_host_for_unknown_id_is_err() {
        let lane = lane();
        let job = TestJob::new(8);
        let (handshake, ws) = captured_conversation();
        let mut stranger = point(
            InsertionKind::WsJsonValue,
            "msg",
            Some("msg"),
            PointSpec {
                ws_flow: ws.id,
                handshake: handshake.id,
                frame_index: Some(1),
                locator: Locator::JsonPath("msg".to_string()),
            },
        );
        stranger.id = "ws-deadbeef".to_string();

        // `Box<dyn ProbeHost>` is not `Debug`, so the `Ok` arm is spelled out
        // rather than taken through `expect_err`.
        let err = match lane.probe_host_for(&stranger, job) {
            Ok(_) => panic!("an id this lane never issued must not host a probe"),
            Err(err) => err,
        };
        assert!(
            err.to_string().contains("unknown ws point"),
            "unexpected error text: {err}"
        );
    }

    /// A job named `job_id` whose store holds one fixture conversation.
    fn job_with_one_conversation(job_id: &str) -> Arc<TestJob> {
        let job = TestJob::named(job_id, 64);
        let (handshake, ws) = captured_conversation();
        job.store().insert(Flow::Http(handshake));
        job.store().insert(Flow::WebSocket(ws));
        job
    }

    /// `probe_host_for`'s error, or a panic naming `why` when it built a host
    /// (`Box<dyn ProbeHost>` is not `Debug`, so `expect_err` is unavailable).
    fn host_err(lane: &WsLane, point: &InsertionPoint, job: Arc<TestJob>, why: &str) -> String {
        match lane.probe_host_for(point, job) {
            Ok(_) => panic!("{why}"),
            Err(err) => err.to_string(),
        }
    }

    /// Assert `probe_host_for` builds a host for `point` under `job`.
    fn hosts(lane: &WsLane, point: &InsertionPoint, job: Arc<TestJob>) {
        assert!(
            lane.probe_host_for(point, job).is_ok(),
            "a point the lane registered for this job must still host a probe"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_second_job_does_not_see_the_first_jobs_points() {
        let lane = lane();
        let first = job_with_one_conversation("job-a");
        let second = job_with_one_conversation("job-b");

        let found = lane
            .discover(&first.profile().target, &*first)
            .await
            .expect("discovery for the first job");
        lane.discover(&second.profile().target, &*second)
            .await
            .expect("discovery for the second job");

        let point = &found.points[0];
        let err = host_err(
            &lane,
            point,
            Arc::clone(&second),
            "a job must not host another job's point",
        );
        assert!(
            err.contains("unknown ws point"),
            "unexpected error text: {err}"
        );
        hosts(&lane, point, first);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn registry_evicts_the_oldest_job_past_sixteen() {
        let lane = lane();
        let mut jobs = Vec::new();
        let mut points = Vec::new();
        for nth in 0..17 {
            let job = job_with_one_conversation(&format!("job-{nth}"));
            let found = lane
                .discover(&job.profile().target, &*job)
                .await
                .unwrap_or_else(|err| panic!("discovery for job {nth}: {err}"));
            points.push(found.points[0].clone());
            jobs.push(job);
        }

        let err = host_err(
            &lane,
            &points[0],
            Arc::clone(&jobs[0]),
            "the seventeenth job must have evicted the first",
        );
        assert!(
            err.contains("unknown ws point"),
            "unexpected error text: {err}"
        );
        hosts(&lane, &points[16], Arc::clone(&jobs[16]));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_point_whose_flow_left_the_store_is_err() {
        let lane = lane();
        let job = TestJob::new(64);
        let (handshake, mut ws) = captured_conversation();
        // A killed conversation is terminal, so `clear` removes it — this is
        // the store dropping a flow the registry still names.
        ws.intercept = InterceptState::Killed;
        job.store().insert(Flow::Http(handshake));
        job.store().insert(Flow::WebSocket(ws));

        let found = lane
            .discover(&job.profile().target, &*job)
            .await
            .expect("discovery over the fixture");
        job.store().clear();

        let err = host_err(
            &lane,
            &found.points[0],
            Arc::clone(&job),
            "a point whose conversation left the store must not host a probe",
        );
        assert!(
            err.contains("the point's flow is no longer in the store"),
            "unexpected error text: {err}"
        );
    }

    #[test]
    fn checks_are_the_eight() {
        let checks = lane().checks();

        assert_eq!(
            checks
                .iter()
                .map(|check| check.meta().id.clone())
                .collect::<Vec<_>>(),
            vec![
                "cswsh",
                "ws-auth-bypass-handshake",
                "ws-input-reflection",
                "ws-sql-error",
                "ws-ssti",
                "ws-cmdi-echo",
                "ws-oversize-frame",
                "ws-subprotocol-observe",
            ]
        );
        for check in &checks {
            assert_eq!(check.meta().lanes, vec![LaneKind::Ws]);
            assert_eq!(check.meta().origin, CheckOrigin::Native);
        }
    }

    #[test]
    fn slot_is_some() {
        let lane = crate::lane().expect("the lane slot is filled");
        assert_eq!(lane.lane(), LaneKind::Ws);
    }

    // --- The redaction rule, swept over the whole catalogue (tester) -----
    //
    // Each check file asserts its own vulnerable case is scrubbed. This runs
    // *every* check against *every* discovered point of the fixture — whose
    // handshake carries `Cookie: sid=s3cr3t-cookie` — against a server that
    // echoes whatever it is given, and greps the `Debug` of every verdict and
    // every insertion point. A ninth check added without its own assertion is
    // caught here.

    #[tokio::test(flavor = "multi_thread")]
    async fn no_verdict_or_point_of_any_check_carries_the_captured_cookie() {
        use crate::testing::{echo_handler, ws_server};

        let (transport, _log) = ws_server(None, echo_handler);
        // A short reply window: this test greps text, it does not time anything.
        let job = TestJob::with(4096, |profile| {
            profile.ws.reply_window_ms = 40;
        });
        let store = job.store();
        let (handshake, ws) = captured_conversation();
        store.insert(Flow::Http(handshake));
        store.insert(Flow::WebSocket(ws));
        let lane = WsLane::new(Arc::new(WsDialer::new(transport)));

        let found = lane
            .discover(&job.profile().target, &*job)
            .await
            .expect("discovery over the fixture");
        assert_eq!(found.points.len(), 6, "the fixture's six points");

        let mut verdicts = 0usize;
        for found_point in &found.points {
            let shown = format!("{found_point:?}");
            assert!(
                !shown.contains("s3cr3t-cookie"),
                "a discovered point leaked the cookie: {shown}"
            );
            for check in lane.checks() {
                let host = lane
                    .probe_host_for(found_point, job.clone())
                    .expect("every discovered point is hostable");
                let verdict = check.run(found_point, host.as_ref()).await;
                let shown = format!("{verdict:?}");
                assert!(
                    !shown.contains("s3cr3t-cookie"),
                    "{} @ {} leaked the cookie: {shown}",
                    check.meta().id,
                    found_point.name
                );
                assert!(
                    !shown.contains("aitm-pad"),
                    "{} @ {} leaked the pad sentinel: {shown}",
                    check.meta().id,
                    found_point.name
                );
                verdicts += 1;
            }
        }
        assert_eq!(verdicts, 48, "eight checks over six points");
    }
}
