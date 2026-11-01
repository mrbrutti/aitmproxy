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
//!   [`PointSpec`] and the two flows behind every point it minted and
//!   `probe_host_for` looks the point up by id (plan call 4). An id this lane
//!   never issued is an error, never a quietly empty probe.
//! - **One dialer per lane.** The 4-permit semaphore lives in the
//!   [`WsDialer`], and every probe host the lane builds shares this one dialer,
//!   so a job holds at most 4 WebSocket connections open — and two concurrent
//!   jobs share those 4, which errs toward fewer connections than the spec's
//!   "4 per job" (plan calls 2 and 23).
//! - **Only captured, non-replay, in-target conversations.** A conversation the
//!   scanner itself drove (`is_replay`) is never a source of points, and a
//!   conversation whose handshake origin is outside `target.origins` is skipped
//!   before anything is read out of it (plan call 4).

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use aitm_core::{Flow, FlowKind, FlowQuery, HttpFlow, WsFlow};
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

/// What the lane remembers about one point so it can re-drive it later.
#[derive(Debug, Clone)]
struct Registered {
    /// Where in the conversation the payload goes.
    spec: PointSpec,
    /// The captured upgrade request the probe replays.
    handshake: HttpFlow,
    /// The captured conversation whose frames the probe replays.
    ws: WsFlow,
}

/// The WebSocket lane: discovery, probe hosting and the eight native checks.
pub struct WsLane {
    /// Shared by every probe host this lane builds, so its 4 permits bound the
    /// whole lane (plan calls 2 and 23).
    dialer: Arc<WsDialer>,
    /// Point id -> everything needed to re-drive that point.
    registry: Mutex<HashMap<String, Registered>>,
}

impl WsLane {
    /// A lane that dials through `dialer`.
    #[must_use]
    pub fn new(dialer: Arc<WsDialer>) -> Self {
        Self {
            dialer,
            registry: Mutex::new(HashMap::new()),
        }
    }

    /// Remember `specs` (parallel to the points just minted) for `handshake`
    /// and `ws`, so `probe_host_for` can find them by point id.
    fn register(&self, specs: Vec<(String, PointSpec)>, handshake: &HttpFlow, ws: &WsFlow) {
        let mut registry = self.registry.lock().unwrap_or_else(PoisonError::into_inner);
        for (id, spec) in specs {
            registry.insert(
                id,
                Registered {
                    spec,
                    handshake: handshake.clone(),
                    ws: ws.clone(),
                },
            );
        }
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
                self.register(found.specs, &handshake, &ws);

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
        let registered = {
            let registry = self.registry.lock().unwrap_or_else(PoisonError::into_inner);
            registry.get(&point.id).cloned()
        };
        let registered = registered.ok_or_else(|| anyhow!("unknown ws point {}", point.id))?;

        let host = WsProbeHost::new(
            point.clone(),
            registered.spec,
            registered.handshake,
            registered.ws,
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
/// **Security review, named item (plan call 3).** The production dialer accepts
/// *any* upstream certificate ([`TlsPolicy::AcceptAny`]). The scanner only ever
/// dials an authority the operator put in scope, and the lab targets this tool
/// exists for routinely present self-signed certificates, so verifying would
/// turn every such target into a connect error rather than a finding. It is the
/// same posture `aitm-proto-http`'s `Http1Sender` takes for upstream probes.
#[must_use]
pub fn build() -> Option<Arc<dyn Lane>> {
    let transport = Arc::new(TcpTransport::new(TlsPolicy::AcceptAny, DIAL_TIMEOUT));
    Some(Arc::new(WsLane::new(Arc::new(WsDialer::new(transport)))))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use aitm_core::{Flow, FlowId};
    use aitm_scan_model::{CheckOrigin, InsertionKind, JobCtx, Lane, LaneKind};

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
