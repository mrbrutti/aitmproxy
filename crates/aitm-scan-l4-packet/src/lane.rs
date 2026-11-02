//! The `Lane` implementation and the slot body behind `crate::lane` — owned by
//! scanner v2 track T5, plan task 11.
//!
//! [`PacketLane`] is the assembly point: it owns the one [`Shared`] context
//! (guard, backend, lane-private case store, seed store, timings and the
//! per-job [`LaneState`]), the [`RunnerRegistry`] that maps
//! `(job id, point id)` to the single [`PointRunner`] that owns a point's
//! fuzz run, and the two native checks that read that run. Discovery mints the
//! points; `probe_host_for` builds and registers the runner; whichever check
//! reaches the point first drives the cases and the other sends nothing.
//!
//! The lane is `Some` even when both handles are `None`, so `scan.start`
//! refuses with `refused_l4` rather than `lane_unavailable` (spec D1 call A18,
//! D3's refusal order). Every refusal this module raises carries its D3 code as
//! the first token of the message, and the codes [`discover_all`] raises travel
//! out verbatim.

use std::fmt;
use std::net::IpAddr;
use std::sync::Arc;

use aitm_proto_l4::backend::pcap::PcapBackend;
use aitm_proto_l4::backend::CaptureInjectBackend;
use aitm_proto_l4::flow::{InMemoryL4FlowStore, L4FlowStore};
use aitm_proto_l4::guard::L4Guard;
use aitm_scan_model::{
    Check, Discovery, InsertionPoint, JobCtx, L4Counters, Lane, LaneKind, ProbeHost, ProfileTarget,
    ScanProfile,
};
use anyhow::anyhow;
use futures::future::BoxFuture;

use crate::checks::checks;
use crate::discover::{discover_all, ip_version};
use crate::fields::validate_fields;
use crate::host::{PacketHost, PointRunner, RunnerRegistry, Shared, Timing};
use crate::plan::{parse_point_id, requested_fields, target_key};
use crate::state::{JobKey, JobStats, LaneState};

/// How many case flows the lane's own store holds before it evicts the oldest.
///
/// The lane never writes a case into the operator's store (call C8), so a fuzz
/// run can never evict a real capture.
pub const CASE_STORE_FLOWS: usize = 1024;

/// How many packets one case flow keeps in the lane's own store.
pub const CASE_STORE_PACKETS: usize = 16;

/// The refusal a lane with no L4 handles returns, D3 code first (call A18).
const REFUSED_L4: &str =
    "refused_l4: the L4 layer is disabled (l4.enabled: false), so the packet lane has no guard or store";

/// A lane kind as the wire vocabulary spells it, for a refusal message.
const fn lane_name(lane: LaneKind) -> &'static str {
    match lane {
        LaneKind::Http => "http",
        LaneKind::Ws => "ws",
        LaneKind::L4Packet => "l4_packet",
        LaneKind::L4Stream => "l4_stream",
    }
}

/// The scanner v2 L4 packet lane (spec D8.4).
///
/// `inner` is `None` when the core started with L4 disabled: the lane still
/// exists and still lists its checks, and every call that would touch the wire
/// refuses with [`REFUSED_L4`].
pub struct PacketLane {
    inner: Option<Arc<Shared>>,
    registry: Arc<RunnerRegistry>,
    checks: Vec<Arc<dyn Check>>,
    default_fields: Vec<String>,
}

impl fmt::Debug for PacketLane {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PacketLane")
            .field("inner", &self.inner)
            .field("registry", &self.registry)
            .field("checks", &self.checks.len())
            .field("default_fields", &self.default_fields)
            .finish()
    }
}

impl PacketLane {
    /// The lane `wire.rs` builds from `Features::l4_shared`, over the real
    /// [`PcapBackend`]. A `None` guard yields a lane that refuses every call
    /// with [`REFUSED_L4`]; `store` is then dropped, because without a guard
    /// the lane may read nothing and send nothing.
    #[must_use]
    pub fn new(guard: Option<Arc<L4Guard>>, store: Option<Arc<dyn L4FlowStore>>) -> Self {
        let Some(guard) = guard else {
            return Self::assemble(None);
        };
        let backend: Arc<dyn CaptureInjectBackend> = Arc::new(PcapBackend::new());
        Self::assemble(Some(Self::shared(
            guard,
            store,
            backend,
            Timing::default(),
            Arc::new(LaneState::new()),
        )))
    }

    /// The same lane over a caller-supplied backend: the mock in the inner
    /// loop, a real [`PcapBackend`] in `tests/live_loopback.rs`.
    #[must_use]
    pub fn with_backend(
        guard: Arc<L4Guard>,
        seed_store: Option<Arc<dyn L4FlowStore>>,
        backend: Arc<dyn CaptureInjectBackend>,
    ) -> Self {
        Self::assemble(Some(Self::shared(
            guard,
            seed_store,
            backend,
            Timing::default(),
            Arc::new(LaneState::new()),
        )))
    }

    /// Replace the lane's waits and ceilings (plan call C3: set here, never by
    /// a profile). A handle-less lane keeps its `None` context.
    #[must_use]
    pub fn with_timing(mut self, timing: Timing) -> Self {
        if let Some(shared) = self.inner.take() {
            self.inner = Some(Arc::new(Shared {
                timing,
                ..(*shared).clone()
            }));
        }
        self
    }

    /// The field list a job fuzzes when its profile requests none. The
    /// profile's own `L4Options.fields` always wins ([`requested_fields`] reads
    /// it since task 4a of the live-proof plan); an empty list here is the
    /// target's default field table.
    #[must_use]
    pub fn with_default_fields(mut self, fields: Vec<String>) -> Self {
        self.default_fields = fields;
        self
    }

    /// Spec D5's counters for one job, or `None` for a job this lane never
    /// began (including every job on a handle-less lane).
    #[must_use]
    pub fn counters(&self, job_id: &str) -> Option<L4Counters> {
        self.inner.as_ref()?.state.counters(job_id)
    }

    /// Everything the lane counted for one job, D5's counters included.
    #[must_use]
    pub fn stats(&self, job_id: &str) -> Option<JobStats> {
        self.inner.as_ref()?.state.stats(job_id)
    }

    /// The per-job bookkeeping, or `None` when L4 is disabled.
    #[must_use]
    pub fn state(&self) -> Option<&Arc<LaneState>> {
        self.inner.as_ref().map(|shared| &shared.state)
    }

    /// The context every runner of this lane reads. The case store is the
    /// lane's own, bounded at [`CASE_STORE_FLOWS`] × [`CASE_STORE_PACKETS`].
    fn shared(
        guard: Arc<L4Guard>,
        seed_store: Option<Arc<dyn L4FlowStore>>,
        backend: Arc<dyn CaptureInjectBackend>,
        timing: Timing,
        state: Arc<LaneState>,
    ) -> Arc<Shared> {
        let case_store: Arc<dyn L4FlowStore> = Arc::new(InMemoryL4FlowStore::with_limits(
            CASE_STORE_FLOWS,
            CASE_STORE_PACKETS,
        ));
        Arc::new(Shared {
            guard,
            backend,
            case_store,
            seed_store,
            timing,
            state,
        })
    }

    /// A lane around an already-built context, with a fresh registry and the
    /// two checks reading it. The checks exist even when `inner` is `None`, so
    /// `scan.checks` lists the lane's catalogue on a core with L4 disabled.
    fn assemble(inner: Option<Arc<Shared>>) -> Self {
        let registry = Arc::new(RunnerRegistry::new());
        Self {
            inner,
            checks: checks(Arc::clone(&registry)),
            registry,
            default_fields: Vec::new(),
        }
    }

    /// The live context, or the D3 `refused_l4` error.
    fn context(&self) -> anyhow::Result<&Arc<Shared>> {
        self.inner.as_ref().ok_or_else(|| anyhow!(REFUSED_L4))
    }
}

impl Lane for PacketLane {
    fn lane(&self) -> LaneKind {
        LaneKind::L4Packet
    }

    fn discover<'a>(
        &'a self,
        target: &'a ProfileTarget,
        job: &'a dyn JobCtx,
    ) -> BoxFuture<'a, anyhow::Result<Discovery>> {
        Box::pin(async move {
            let shared = self.context()?;
            // A profile that declares no L4 target is not an error: the engine
            // runs the other lanes and this one contributes nothing (call C17).
            if target.l4.is_empty() {
                return Ok(Discovery::default());
            }
            let profile = job.profile();
            let mut requested = requested_fields(profile);
            if requested.is_empty() {
                requested.clone_from(&self.default_fields);
            }
            // `discover_all` opens a pcap handle for its privilege probe, which
            // blocks the thread, so it runs on the blocking pool rather than a
            // tokio worker (review findings M7/SEC5). Its inputs are cloned in:
            // the handles are `Arc`s, and `ProfileTarget`/`ScanProfile` are
            // `Clone`.
            let guard = Arc::clone(&shared.guard);
            let backend = Arc::clone(&shared.backend);
            let seed_store = shared.seed_store.clone();
            let target_owned = target.clone();
            let profile_owned = profile.clone();
            let marker = job.marker();
            // The engine's stable job id (not `marker`, which is minted fresh
            // per call) seeds each target's source port, so two concurrent jobs
            // against one target never share a reply five-tuple (amendment 73 b).
            let job_id = job.job_id().to_string();
            let planned = tokio::task::spawn_blocking(move || {
                discover_all(
                    guard.as_ref(),
                    backend.as_ref(),
                    seed_store.as_deref(),
                    &target_owned,
                    &profile_owned,
                    &requested,
                    &marker,
                    &job_id,
                )
            })
            .await;
            // `discover_all`'s own errors already read `invalid_profile: `,
            // `out_of_scope: ` or `lane_unavailable: `, so the D3 code the
            // engine matches on survives the conversion to `anyhow`; a task that
            // panicked or was cancelled is itself a `lane_unavailable:`.
            let (plans, discovery) = match planned {
                Ok(result) => result.map_err(|err| anyhow!("{err}"))?,
                Err(join) => {
                    return Err(anyhow!("lane_unavailable: discovery task failed: {join}"))
                }
            };
            let forgotten = shared.state.begin_job(
                JobKey::new(job.job_id(), &job.marker()),
                plans,
                discovery.points.iter().map(|p| p.id.clone()).collect(),
                profile.l4.cases,
                profile.l4.consecutive_timeouts,
                profile.l4.dry_run,
            );
            // A job whose state is gone has no run left to drive, so its
            // runners go with it: the registry is bounded by the same window
            // (review findings SEC2/Q4). `begin_job` hands back the job ids it
            // dropped, which are the registry's keys (T5 live proof, 4b).
            for job_id in forgotten {
                self.registry.forget_job(&job_id);
            }
            Ok(discovery)
        })
    }

    fn probe_host_for(
        &self,
        point: &InsertionPoint,
        job: Arc<dyn JobCtx>,
    ) -> anyhow::Result<Box<dyn ProbeHost>> {
        let shared = self.context()?;
        if point.lane != LaneKind::L4Packet {
            return Err(anyhow!(
                "the packet lane hosts only l4_packet points, got {}",
                lane_name(point.lane)
            ));
        }
        let job_id = job.job_id().to_string();
        // Only a point this job minted is this lane's to fuzz: a forged id
        // never reaches a target plan, let alone the wire.
        if !shared.state.point_known(&job_id, &point.id) {
            return Err(anyhow!(
                "point {} was not minted by the packet lane for job {job_id}",
                point.id
            ));
        }
        // The point id round-trips through `parse_point_id` to the target it
        // names, and the plan is found by that target's key — no string surgery
        // on the id itself (review finding M3).
        let (ip, port, proto, field) = parse_point_id(&point.id)
            .ok_or_else(|| anyhow!("point {} is not a packet-lane point id", point.id))?;
        let key = target_key(ip, port, proto);
        let plan = shared
            .state
            .plans(&job_id)
            .unwrap_or_default()
            .into_iter()
            .find(|plan| plan.key() == key)
            .ok_or_else(|| anyhow!("no target plan for point {} in job {job_id}", point.id))?;

        // Seed 0 is built here, once, so a seed that does not craft is refused
        // with its D3 code rather than at send time (review finding M8); it was
        // already validated at discovery, so this is unreachable short of a
        // guard ceiling change mid-job.
        let runner = PointRunner::new(Arc::clone(shared), job, point.clone(), plan, field)
            .map_err(|err| anyhow!("{err}"))?;
        // The registry owns the point's runner, keyed by the engine's stable
        // job id — never `JobCtx::marker`, which mints a fresh token on every
        // call, so the crash and reaction checks (which look the runner up by
        // the host's `marker()`, itself the job id) would read `missing_runner`
        // and the job would send nothing (T5 live proof, 4b). A second host for
        // the same point wraps the runner already registered, so both hosts
        // drive one idempotent run (review finding Q3).
        let runner = self.registry.register(&job_id, &point.id, Arc::new(runner));
        Ok(Box::new(PacketHost::new(runner)))
    }

    fn checks(&self) -> Vec<Arc<dyn Check>> {
        self.checks.clone()
    }

    /// Refuse, before the job is spawned, a profile whose `L4Options.fields`
    /// names a field this lane cannot fuzz (AC T5-3, spec D8.4).
    ///
    /// Every declared target is checked with the same [`validate_fields`] the
    /// run itself uses, so a pinned path (`ipv4.src`, `dst`, `interface`,
    /// `ether.src` ...), an unknown path, or a path that does not apply to the
    /// target's IP version and transport is named by `scan.start` rather than
    /// by a job the caller already believes started. `discover` keeps its own
    /// identical check as the second line of defence: a lane can be driven
    /// without the engine in front of it.
    ///
    /// Only the field list is decided here. Scope, privilege and seeds all need
    /// the guard and the wire, so they stay with discovery — and a handle-less
    /// lane validates rather than refusing, so `scan.start` still reports
    /// `refused_l4` (call A18) instead of `invalid_profile`.
    ///
    /// # Errors
    ///
    /// The first offending path's message, *bare*: the engine renders it as
    /// `scan: invalid_profile: <message>` (`aitm_scan_model::scan_error`), so
    /// the code [`validate_fields`] prefixes is stripped once here, exactly as
    /// `discover` strips it before `DiscoverError`'s `Display` re-adds it. The
    /// sentence after the code is the same on both paths.
    fn validate(&self, target: &ProfileTarget, profile: &ScanProfile) -> Result<(), String> {
        // The same substitution discovery makes: the profile's own list wins,
        // and an empty one falls back to this lane's default list (empty in
        // production, which `validate_fields` reads as the target's default
        // table and always accepts).
        let mut requested = requested_fields(profile);
        if requested.is_empty() {
            requested.clone_from(&self.default_fields);
        }
        for spec in &target.l4 {
            // A target whose address does not parse has no IP version to check
            // a path against; `resolve_target` refuses it at discovery with its
            // own `invalid_profile` message naming the address.
            let Ok(ip) = spec.ip.parse::<IpAddr>() else {
                continue;
            };
            validate_fields(ip_version(ip), spec.proto, &requested).map_err(|message| {
                message
                    .strip_prefix("invalid_profile: ")
                    .unwrap_or(&message)
                    .to_string()
            })?;
        }
        Ok(())
    }
}

/// Build the packet lane. Always `Some`: a landed lane with no handles refuses
/// `scan.start` with `refused_l4` rather than letting the engine report
/// `lane_unavailable` (spec D1, call A18).
#[must_use]
pub fn build(
    guard: Option<Arc<L4Guard>>,
    store: Option<Arc<dyn L4FlowStore>>,
) -> Option<Arc<dyn Lane>> {
    Some(Arc::new(PacketLane::new(guard, store)))
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;
    use std::sync::Arc;

    use aitm_proto_l4::backend::CaptureInjectBackend;
    use aitm_proto_l4::config::L4Config;
    use aitm_proto_l4::guard::L4Guard;
    use aitm_proto_l4::types::{
        IpCidr, L4Capability, L4Direction, L4ScopeEntry, L4ScopeId, L4ScopeSource, PortRange,
        RateCap,
    };
    use aitm_scan_model::{
        InsertionKind, InsertionPoint, JobCtx, L4Counters, Lane, LaneKind, Outcome, ProfileTarget,
    };

    use super::PacketLane;
    use crate::host::Timing;
    use crate::testing::{
        fields, l4_profile, loopback_guard, tcp_target, udp_target, with_hex_seed, MockBackend,
        MockReply, TestJob,
    };

    /// The job id and marker every [`TestJob`] runs under.
    const JOB_ID: &str = "scan-1a2b3c4d";

    /// Millisecond timings, so a hundred cases cost milliseconds; task 9's
    /// recovery ladder keeps its ten polls so inject counts stay exact. The one
    /// copy lives in the shared harness (review finding M3).
    fn fast() -> Timing {
        crate::testing::harness::fast_timing()
    }

    /// A lane over the mock backend, the loopback guard and [`fast`] timings.
    /// An empty `paths` leaves the target's default field table in force.
    fn lane_with(mock: Arc<MockBackend>, paths: &[&str]) -> PacketLane {
        let backend: Arc<dyn CaptureInjectBackend> = mock;
        PacketLane::with_backend(loopback_guard("*", 1000), None, backend)
            .with_timing(fast())
            .with_default_fields(fields(paths))
    }

    /// A guard that admits `10.0.0.0/8` and nothing else, so the loopback
    /// target the profile declares is out of scope.
    fn far_guard() -> Arc<L4Guard> {
        let entry = |direction, capability| L4ScopeEntry {
            id: L4ScopeId::new(),
            cidr: IpCidr {
                addr: IpAddr::from([10, 0, 0, 0]),
                prefix: 8,
            },
            ports: PortRange {
                lo: 0,
                hi: u16::MAX,
            },
            interface: "*".to_string(),
            direction,
            capability,
            inject_rate: RateCap {
                pps: 100,
                burst: 100,
            },
            source: L4ScopeSource::Config,
        };
        Arc::new(L4Guard::new(&L4Config {
            enabled: true,
            scope: vec![
                entry(L4Direction::Outbound, L4Capability::Inject),
                entry(L4Direction::Inbound, L4Capability::Capture),
            ],
            ..L4Config::default()
        }))
    }

    /// A point id the lane never minted, shaped exactly like one it would.
    fn forged_point(id: &str) -> InsertionPoint {
        InsertionPoint {
            id: id.to_string(),
            lane: LaneKind::L4Packet,
            kind: InsertionKind::L4Field,
            name: "ipv4.ttl".to_string(),
            path: Some("ipv4.ttl".to_string()),
            example: None,
            flow: None,
            site_node: None,
            traits: Vec::new(),
            frequency: 1,
            method: None,
            url: None,
        }
    }

    #[test]
    fn build_is_some_even_without_handles() {
        let lane = crate::lane(None, None).expect("a landed lane is Some with no handles (A18)");
        assert_eq!(lane.lane(), LaneKind::L4Packet);
        let checks = lane.checks();
        assert_eq!(checks.len(), 2);
        assert_eq!(checks[0].meta().id, "l4-packet-crash");
        assert_eq!(checks[1].meta().id, "l4-packet-reaction");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn discover_without_handles_is_refused_l4() {
        let lane = PacketLane::new(None, None);
        let profile = l4_profile(vec![udp_target(9)], 10);
        let job = TestJob::new(profile.clone());

        let err = lane
            .discover(&profile.target, job.as_ref())
            .await
            .expect_err("a lane with no guard plans nothing");
        assert!(
            err.to_string().starts_with("refused_l4:"),
            "D3 code first: {err}"
        );

        let Err(err) = lane.probe_host_for(
            &forged_point("l4:127.0.0.1:9/udp/ipv4.ttl"),
            Arc::clone(&job) as Arc<dyn JobCtx>,
        ) else {
            panic!("a lane with no guard hosts nothing");
        };
        assert!(
            err.to_string().starts_with("refused_l4:"),
            "D3 code first: {err}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn discover_mints_points_and_rejects_foreign() {
        let mock = MockBackend::new(MockReply::Echo);
        let lane = lane_with(Arc::clone(&mock), &[]);
        let profile = l4_profile(vec![udp_target(9)], 10);
        let job = TestJob::new(profile.clone());

        let discovery = lane
            .discover(&profile.target, job.as_ref())
            .await
            .expect("the loopback target plans");
        assert_eq!(discovery.points.len(), 14);
        // One node for the one declared target, named by all 14 points, so the
        // engine can place an issue on it (`l4_location`).
        assert_eq!(discovery.nodes.len(), 1);
        assert_eq!(discovery.nodes[0].id, "l4:127.0.0.1:9/udp");
        assert_eq!(discovery.nodes[0].points, 14);
        for point in &discovery.points {
            assert_eq!(point.site_node.as_deref(), Some("l4:127.0.0.1:9/udp"));
        }

        let mut foreign = discovery.points[0].clone();
        foreign.lane = LaneKind::Http;
        let Err(err) = lane.probe_host_for(&foreign, Arc::clone(&job) as Arc<dyn JobCtx>) else {
            panic!("a foreign point is not this lane's");
        };
        assert!(err.to_string().contains("l4_packet"), "{err}");

        let stranger = TestJob::new(profile).with_job_id("scan-never-discovered");
        let Err(err) = lane.probe_host_for(
            &forged_point("l4:127.0.0.1:9/udp/ipv4.ttl"),
            stranger as Arc<dyn JobCtx>,
        ) else {
            panic!("a forged point was never minted");
        };
        assert!(err.to_string().contains("not minted"), "{err}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pinned_field_is_invalid_profile() {
        for path in ["ipv4.src", "dst"] {
            let mock = MockBackend::new(MockReply::Echo);
            let lane = lane_with(Arc::clone(&mock), &[path]);
            let profile = l4_profile(vec![udp_target(9)], 10);
            let job = TestJob::new(profile.clone());

            let err = lane
                .discover(&profile.target, job.as_ref())
                .await
                .expect_err("a pinned field is refused before any case");
            let text = err.to_string();
            assert!(text.starts_with("invalid_profile:"), "{text}");
            assert!(text.contains(path), "the path is named: {text}");
            assert_eq!(mock.inject_count(), 0);
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn out_of_scope_and_unavailable() {
        let profile = l4_profile(vec![udp_target(9)], 10);

        let mock = MockBackend::new(MockReply::Echo);
        let backend: Arc<dyn CaptureInjectBackend> = mock;
        let lane = PacketLane::with_backend(far_guard(), None, backend);
        let job = TestJob::new(profile.clone());
        let err = lane
            .discover(&profile.target, job.as_ref())
            .await
            .expect_err("127.0.0.1 is outside 10.0.0.0/8");
        assert!(err.to_string().starts_with("out_of_scope:"), "{err}");

        let dead: Arc<dyn CaptureInjectBackend> = MockBackend::unavailable();
        let lane = PacketLane::with_backend(loopback_guard("*", 1000), None, dead);
        let job = TestJob::new(profile.clone());
        let err = lane
            .discover(&profile.target, job.as_ref())
            .await
            .expect_err("no capture handle, no lane");
        assert!(err.to_string().starts_with("lane_unavailable:"), "{err}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn end_to_end_hundred_clean() {
        let mock = MockBackend::new(MockReply::Echo);
        let lane = lane_with(Arc::clone(&mock), &["raw"]);
        let profile = l4_profile(vec![udp_target(9)], 100);
        let job = TestJob::new(profile.clone());

        let discovery = lane
            .discover(&profile.target, job.as_ref())
            .await
            .expect("one raw point");
        assert_eq!(discovery.points.len(), 1);
        let point = discovery.points[0].clone();
        let host = lane
            .probe_host_for(&point, Arc::clone(&job) as Arc<dyn JobCtx>)
            .expect("the lane hosts the point it minted");

        let checks = lane.checks();
        let crash = checks[0].run(&point, host.as_ref()).await;
        assert_eq!(crash.outcome, Outcome::Clean);
        let reaction = checks[1].run(&point, host.as_ref()).await;
        assert_eq!(reaction.outcome, Outcome::Clean);

        assert_eq!(
            lane.counters(JOB_ID),
            Some(L4Counters {
                cases: 100,
                crashes: 0,
                liveness_failures: 0,
                retired_elements: 0,
            })
        );
        assert_eq!(mock.inject_count(), 105);
    }

    /// Task 4b (T5 live proof): the engine's `JobCtx::marker()` is a reflection
    /// canary that mints a *fresh* token on every call (its trait doc and
    /// `aitm_plugin_scanner::worker`), so the lane must key a point's runner by
    /// the stable, unique job id instead. Driven by an engine-shaped job — one
    /// whose marker changes every call — the whole lane path still works:
    /// `probe_host_for` registers the runner and the crash check finds it, so
    /// the verdict is a real reading and not the `missing_runner` error, and
    /// the mock answers every one of the profile's cases. Keyed by the marker
    /// instead, this is exactly what every real-bus packet job did: the check
    /// looked the runner up under a different token, read `missing_runner`, and
    /// the job finished `done` with zero cases and nothing on the wire.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn checks_find_the_runner_when_the_job_marker_is_fresh_per_call() {
        let mock = MockBackend::new(MockReply::Echo);
        let lane = lane_with(Arc::clone(&mock), &["raw"]);
        let profile = l4_profile(vec![udp_target(9)], 100);
        let job = TestJob::new(profile.clone()).fresh_markers();

        // The double really is the engine's canary: no two asks agree.
        assert_ne!(
            job.marker(),
            job.marker(),
            "fresh-markers mode mints a new token every call"
        );

        let discovery = lane
            .discover(&profile.target, job.as_ref())
            .await
            .expect("one raw point");
        assert_eq!(discovery.points.len(), 1);
        let point = discovery.points[0].clone();
        let host = lane
            .probe_host_for(&point, Arc::clone(&job) as Arc<dyn JobCtx>)
            .expect("the lane hosts the point it minted");

        let crash = lane.checks()[0].run(&point, host.as_ref()).await;
        assert_ne!(
            crash.outcome,
            Outcome::Error,
            "the runner must be found, not reported missing: {}",
            crash.detail
        );
        assert!(
            !crash.detail.contains("no packet-lane runner"),
            "the registry key must not depend on the marker: {}",
            crash.detail
        );
        assert_eq!(
            lane.counters(JOB_ID).map(|counters| counters.cases),
            Some(u64::from(profile.l4.cases)),
            "the mock answers every case through the full lane path"
        );
        assert!(
            job.markers_asked() >= 1,
            "the engine was asked for a fresh marker at least once"
        );
    }

    /// Review findings SEC2/Q4: the runner registry is bounded by the same
    /// eight-job window `LaneState` keeps. Each runner holds its target plan
    /// and its cached run (up to the case ceiling of records), so a long-lived
    /// core must not accumulate them: beginning a ninth job drops the first
    /// job's runners with the first job's state.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_registry_is_bounded_by_the_job_window() {
        let mock = MockBackend::new(MockReply::Echo);
        let lane = lane_with(Arc::clone(&mock), &["raw"]);
        let profile = l4_profile(vec![udp_target(9)], 1);
        // The registry keys by job id (T5 live proof, 4b): each job gets a
        // distinct one, as the engine mints them.
        let mut first: Option<(String, String)> = None;

        for n in 0..9u32 {
            let job = TestJob::new(profile.clone()).with_job_id(&format!("scan-{n:08x}"));
            let discovery = lane
                .discover(&profile.target, job.as_ref())
                .await
                .expect("one raw point");
            let point = discovery.points[0].clone();
            lane.probe_host_for(&point, Arc::clone(&job) as Arc<dyn JobCtx>)
                .expect("the lane hosts the point it minted");
            if first.is_none() {
                first = Some((job.job_id().to_string(), point.id.clone()));
            }
            assert!(
                lane.registry.len() <= 8,
                "job {n} left {} runners registered",
                lane.registry.len()
            );
        }

        let (job_id, point_id) = first.expect("the first job ran");
        assert!(
            lane.registry.get(&job_id, &point_id).is_none(),
            "the first job's runner outlived its state"
        );
        assert_eq!(lane.registry.len(), 8);
    }

    /// Review finding Q3: two hosts for the same point are two views of one
    /// run, not two runs. The engine may hand a point to the crash check and
    /// the reaction check through hosts it asked for separately, so
    /// `probe_host_for` must hand back the registered runner, whose
    /// `run_point` is idempotent — concurrently, the point still sends exactly
    /// what one host sends.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn two_hosts_for_one_point_share_one_run() {
        let mock = MockBackend::new(MockReply::Echo);
        let lane = lane_with(Arc::clone(&mock), &["raw"]);
        let profile = l4_profile(vec![udp_target(9)], 100);
        let job = TestJob::new(profile.clone());

        let discovery = lane
            .discover(&profile.target, job.as_ref())
            .await
            .expect("one raw point");
        let point = discovery.points[0].clone();
        let first = lane
            .probe_host_for(&point, Arc::clone(&job) as Arc<dyn JobCtx>)
            .expect("the lane hosts the point it minted");
        let runner = lane
            .registry
            .get(job.job_id(), &point.id)
            .expect("the first host registered the point's runner");
        let second = lane
            .probe_host_for(&point, Arc::clone(&job) as Arc<dyn JobCtx>)
            .expect("a second host for the same point");
        let again = lane
            .registry
            .get(job.job_id(), &point.id)
            .expect("the second host finds a runner too");
        assert!(
            Arc::ptr_eq(&runner, &again),
            "one point, one runner: the second host must not orphan the first's"
        );

        let checks = lane.checks();
        let (crash, reaction) = tokio::join!(
            checks[0].run(&point, first.as_ref()),
            checks[1].run(&point, second.as_ref())
        );

        assert_eq!(crash.outcome, Outcome::Clean);
        assert_eq!(reaction.outcome, Outcome::Clean);
        // Exactly the single-host figures of `end_to_end_hundred_clean`:
        // 1 baseline + 100 cases + 4 scheduled liveness probes.
        assert_eq!(mock.inject_count(), 105);
        assert_eq!(
            lane.counters(JOB_ID),
            Some(L4Counters {
                cases: 100,
                crashes: 0,
                liveness_failures: 0,
                retired_elements: 0,
            })
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn end_to_end_crash() {
        let mock = MockBackend::new(MockReply::Echo);
        mock.dies_on_pattern(vec![0xde, 0xad, 0xbe, 0xef], 8, 2, true);
        let lane = lane_with(Arc::clone(&mock), &["raw"]);
        let profile = with_hex_seed(l4_profile(vec![udp_target(9)], 50), "deadbeef0000");
        let job = TestJob::new(profile.clone());

        let discovery = lane
            .discover(&profile.target, job.as_ref())
            .await
            .expect("one raw point");
        let point = discovery.points[0].clone();
        let host = lane
            .probe_host_for(&point, Arc::clone(&job) as Arc<dyn JobCtx>)
            .expect("the lane hosts the point it minted");

        let checks = lane.checks();
        let crash = checks[0].run(&point, host.as_ref()).await;
        assert_eq!(crash.outcome, Outcome::Vulnerable);
        assert_eq!(
            lane.counters(JOB_ID),
            Some(L4Counters {
                cases: 5,
                crashes: 1,
                liveness_failures: 8,
                retired_elements: 1,
            })
        );
        assert_eq!(mock.inject_count(), 17);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn two_targets_share_the_case_budget() {
        let mock = MockBackend::new(MockReply::Echo);
        let lane = lane_with(Arc::clone(&mock), &["raw"]);
        let profile = l4_profile(vec![udp_target(9), udp_target(10)], 10);
        let job = TestJob::new(profile.clone());

        let discovery = lane
            .discover(&profile.target, job.as_ref())
            .await
            .expect("one raw point per target");
        assert_eq!(discovery.points.len(), 2);

        let checks = lane.checks();
        for point in &discovery.points {
            let host = lane
                .probe_host_for(point, Arc::clone(&job) as Arc<dyn JobCtx>)
                .expect("the lane hosts the point it minted");
            let verdict = checks[0].run(point, host.as_ref()).await;
            assert_eq!(verdict.outcome, Outcome::Clean);
        }

        let counters = lane.counters(JOB_ID).expect("the job counted");
        assert_eq!(counters.cases, 10);
        assert_eq!(mock.inject_count(), 2 + 10);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn empty_targets_discover_nothing() {
        let mock = MockBackend::new(MockReply::Echo);
        let lane = lane_with(Arc::clone(&mock), &["raw"]);
        let job = TestJob::new(l4_profile(Vec::new(), 10));

        let discovery = lane
            .discover(&ProfileTarget::default(), job.as_ref())
            .await
            .expect("a profile with no l4 target is not an error");
        assert!(discovery.points.is_empty());
        assert!(discovery.nodes.is_empty());
        assert_eq!(mock.inject_count(), 0);
    }

    /// Tester (stage 5): a point one job minted is not hosted for another job
    /// of the same lane, even one that discovered a target of its own; each
    /// job's points stay its own, and the refusal names the job.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_point_is_hosted_only_for_the_job_that_minted_it() {
        let mock = MockBackend::new(MockReply::Echo);
        let lane = lane_with(Arc::clone(&mock), &["raw"]);
        let profile_a = l4_profile(vec![udp_target(9)], 10);
        let job_a = TestJob::new(profile_a.clone());
        let profile_b = l4_profile(vec![udp_target(10)], 10);
        let job_b = TestJob::new(profile_b.clone()).with_job_id("scan-b");

        let a = lane
            .discover(&profile_a.target, job_a.as_ref())
            .await
            .expect("job a plans");
        let b = lane
            .discover(&profile_b.target, job_b.as_ref())
            .await
            .expect("job b plans");
        assert_eq!(a.points[0].id, "l4:127.0.0.1:9/udp/raw");
        assert_eq!(b.points[0].id, "l4:127.0.0.1:10/udp/raw");

        let Err(err) = lane.probe_host_for(&a.points[0], Arc::clone(&job_b) as Arc<dyn JobCtx>)
        else {
            panic!("job b never minted job a's point");
        };
        assert_eq!(
            err.to_string(),
            "point l4:127.0.0.1:9/udp/raw was not minted by the packet lane for job scan-b"
        );
        let Err(err) = lane.probe_host_for(&b.points[0], Arc::clone(&job_a) as Arc<dyn JobCtx>)
        else {
            panic!("job a never minted job b's point");
        };
        assert!(err.to_string().contains("for job scan-1a2b3c4d"), "{err}");

        // Each job's own point is hosted, and the two jobs count apart.
        let host_b = lane
            .probe_host_for(&b.points[0], Arc::clone(&job_b) as Arc<dyn JobCtx>)
            .expect("job b hosts its own point");
        let verdict = lane.checks()[0].run(&b.points[0], host_b.as_ref()).await;
        assert_eq!(verdict.outcome, Outcome::Clean);
        assert_eq!(lane.counters("scan-b").map(|c| c.cases), Some(10));
        assert_eq!(lane.counters(JOB_ID).map(|c| c.cases), Some(0));
        assert_eq!(mock.inject_count(), 11);
        assert_eq!(lane.counters("scan-never"), None);
    }

    /// Tester (stage 5): an IPv6 loopback target runs end to end through the
    /// mock — the bracketed plan key is matched by `probe_host_for`, the v6
    /// seed is echoed and correlated, and the counters are exact.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ipv6_loopback_end_to_end() {
        let entry = |direction, capability| L4ScopeEntry {
            id: L4ScopeId::new(),
            cidr: IpCidr {
                addr: IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
                prefix: 128,
            },
            ports: PortRange {
                lo: 0,
                hi: u16::MAX,
            },
            interface: "*".to_string(),
            direction,
            capability,
            inject_rate: RateCap {
                pps: 1000,
                burst: 1000,
            },
            source: L4ScopeSource::Config,
        };
        let guard = Arc::new(L4Guard::new(&L4Config {
            enabled: true,
            scope: vec![
                entry(L4Direction::Outbound, L4Capability::Inject),
                entry(L4Direction::Inbound, L4Capability::Capture),
            ],
            global_inject_pps: 1000,
            ..L4Config::default()
        }));
        let mock = MockBackend::new(MockReply::Echo);
        let backend: Arc<dyn CaptureInjectBackend> =
            Arc::clone(&mock) as Arc<dyn CaptureInjectBackend>;
        let lane = PacketLane::with_backend(guard, None, backend)
            .with_timing(fast())
            .with_default_fields(fields(&["raw"]));
        let profile = l4_profile(
            vec![aitm_scan_model::L4TargetSpec {
                ip: "::1".to_string(),
                port: 53,
                proto: aitm_scan_model::L4Transport::Udp,
                grammar: None,
            }],
            10,
        );
        let job = TestJob::new(profile.clone());

        let discovery = lane
            .discover(&profile.target, job.as_ref())
            .await
            .expect("::1 plans under a ::1/128 entry");
        assert_eq!(discovery.points.len(), 1);
        let point = discovery.points[0].clone();
        assert_eq!(point.id, "l4:[::1]:53/udp/raw");
        assert_eq!(point.url.as_deref(), Some("udp://[::1]:53"));
        let host = lane
            .probe_host_for(&point, Arc::clone(&job) as Arc<dyn JobCtx>)
            .expect("the bracketed key matches its plan");

        let checks = lane.checks();
        let crash = checks[0].run(&point, host.as_ref()).await;
        let reaction = checks[1].run(&point, host.as_ref()).await;
        assert_eq!(crash.outcome, Outcome::Clean, "{}", crash.detail);
        assert_eq!(reaction.outcome, Outcome::Clean, "{}", reaction.detail);
        assert_eq!(
            lane.counters(JOB_ID),
            Some(L4Counters {
                cases: 10,
                crashes: 0,
                liveness_failures: 0,
                retired_elements: 0,
            })
        );
        assert_eq!(mock.inject_count(), 11);
        for frame in mock.injected() {
            let ends = aitm_proto_l4::craft::PacketSpec::endpoints(&frame);
            assert_eq!(ends.dst, Some(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)));
            assert_eq!(ends.dst_port, Some(53));
        }
    }

    /// A UDP target on `[::1]:port`, for the IPv6 half of the field checks.
    fn v6_target(port: u16) -> aitm_scan_model::L4TargetSpec {
        aitm_scan_model::L4TargetSpec {
            ip: "::1".to_string(),
            port,
            proto: aitm_scan_model::L4Transport::Udp,
            grammar: None,
        }
    }

    /// AC T5-3 / spec D8.4: a profile naming a pinned field is refused by
    /// `Lane::validate`, synchronously, before the engine spawns the job
    /// (`crates/aitm-plugin-scanner/src/jobs.rs` wraps the `Err` into
    /// `scan: invalid_profile: <message>`), so the message carries no code of
    /// its own.
    #[test]
    fn validate_refuses_a_pinned_field_synchronously() {
        let lane = lane_with(MockBackend::new(MockReply::Echo), &[]);

        let mut profile = l4_profile(vec![udp_target(9)], 10);
        profile.l4.fields = fields(&["ipv4.src"]);
        assert_eq!(
            lane.validate(&profile.target, &profile),
            Err(r#"field path "ipv4.src" is pinned and cannot be fuzzed"#.to_string())
        );

        let mut profile = l4_profile(vec![udp_target(9)], 10);
        profile.l4.fields = fields(&["dst"]);
        assert_eq!(
            lane.validate(&profile.target, &profile),
            Err(r#"field path "dst" is pinned and cannot be fuzzed"#.to_string())
        );

        let mut profile = l4_profile(vec![v6_target(53)], 10);
        profile.l4.fields = fields(&["ipv6.src"]);
        assert_eq!(
            lane.validate(&profile.target, &profile),
            Err(r#"field path "ipv6.src" is pinned and cannot be fuzzed"#.to_string())
        );
    }

    /// A path the lane does not know is refused the same way, and named.
    #[test]
    fn validate_refuses_an_unknown_path() {
        let lane = lane_with(MockBackend::new(MockReply::Echo), &[]);
        let mut profile = l4_profile(vec![udp_target(9)], 10);
        profile.l4.fields = fields(&["udp.nope"]);
        assert_eq!(
            lane.validate(&profile.target, &profile),
            Err(r#"unknown field path "udp.nope""#.to_string())
        );
    }

    /// A fuzzable path and the empty list (the target's default table) both
    /// pass, so `validate` refuses nothing a run would accept.
    #[test]
    fn validate_accepts_raw_and_the_empty_default() {
        let lane = lane_with(MockBackend::new(MockReply::Echo), &[]);

        let mut profile = l4_profile(vec![udp_target(9)], 10);
        profile.l4.fields = fields(&["raw"]);
        assert_eq!(lane.validate(&profile.target, &profile), Ok(()));

        let profile = l4_profile(vec![udp_target(9)], 10);
        assert!(profile.l4.fields.is_empty());
        assert_eq!(lane.validate(&profile.target, &profile), Ok(()));

        // A profile with no L4 target at all is this lane's `Ok` too: the
        // engine's own rule refuses that case (jobs.rs), not the lane.
        let mut empty = l4_profile(vec![], 10);
        empty.l4.fields = fields(&["ipv4.src"]);
        assert_eq!(lane.validate(&empty.target, &empty), Ok(()));
    }

    /// Every declared target is checked, not just the first: `tcp.flags` is a
    /// field on the TCP target and absent from the UDP one.
    #[test]
    fn validate_checks_every_l4_target() {
        let lane = lane_with(MockBackend::new(MockReply::Echo), &[]);
        let mut profile = l4_profile(vec![tcp_target(9), udp_target(53)], 10);
        profile.l4.fields = fields(&["tcp.flags"]);
        assert_eq!(
            lane.validate(&profile.target, &profile),
            Err(r#"field path "tcp.flags" does not apply to a ipv4/udp target"#.to_string())
        );
    }

    /// Tester (stage 5), AC T5-3: `validate` checks both dimensions of a
    /// field's applicability — the transport *and* the IP version — against
    /// **every** declared target, in profile order. A mixed-family profile is
    /// the case the engine cannot catch for us: `ipv4.ttl` is a real, fuzzable
    /// field of the v4 target and nonsense for the `[::1]` one, and
    /// `ipv6.hop_limit` is the mirror image. Either way `scan.start` must
    /// refuse, naming the family and transport that rejected the path, rather
    /// than letting discovery raise `invalid_profile` later with a job
    /// already begun.
    ///
    /// Mutation: `break` out of `validate`'s loop after the first target (or
    /// check `spec.proto` without `ip_version(ip)`) and both halves pass
    /// `Ok(())`.
    #[test]
    fn validate_checks_the_ip_version_of_every_target() {
        let lane = lane_with(MockBackend::new(MockReply::Echo), &[]);

        // Valid for the first (v4) target, nonsense for the second (v6) one.
        let mut profile = l4_profile(vec![udp_target(9), v6_target(53)], 10);
        profile.l4.fields = fields(&["ipv4.ttl"]);
        assert_eq!(
            lane.validate(&profile.target, &profile),
            Err(r#"field path "ipv4.ttl" does not apply to a ipv6/udp target"#.to_string())
        );

        // The mirror image, with the families the other way round.
        let mut profile = l4_profile(vec![v6_target(53), udp_target(9)], 10);
        profile.l4.fields = fields(&["ipv6.hop_limit"]);
        assert_eq!(
            lane.validate(&profile.target, &profile),
            Err(r#"field path "ipv6.hop_limit" does not apply to a ipv4/udp target"#.to_string())
        );

        // `raw` and `udp.*` apply to both families, so a mixed profile that
        // names only portable paths is accepted: validate refuses nothing a
        // run would accept.
        let mut profile = l4_profile(vec![udp_target(9), v6_target(53)], 10);
        profile.l4.fields = fields(&["raw", "udp.length"]);
        assert_eq!(lane.validate(&profile.target, &profile), Ok(()));
    }

    /// Tester (stage 5): `with_timing` on a handle-less lane keeps refusing,
    /// and its counters/stats/state are all `None`.
    #[test]
    fn handle_less_lane_has_no_state() {
        let lane = PacketLane::new(None, None).with_timing(fast());
        assert!(lane.state().is_none());
        assert_eq!(lane.counters(JOB_ID), None);
        assert!(lane.stats(JOB_ID).is_none());
        assert_eq!(lane.checks().len(), 2);
        let printed = format!("{lane:?}");
        assert!(printed.contains("inner: None"), "{printed}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dry_run_end_to_end() {
        let mock = MockBackend::new(MockReply::Echo);
        let lane = lane_with(Arc::clone(&mock), &["raw"]);
        let mut profile = l4_profile(vec![udp_target(9)], 100);
        profile.l4.dry_run = true;
        let job = TestJob::new(profile.clone());

        let discovery = lane
            .discover(&profile.target, job.as_ref())
            .await
            .expect("a dry run still plans");
        let point = discovery.points[0].clone();
        let host = lane
            .probe_host_for(&point, Arc::clone(&job) as Arc<dyn JobCtx>)
            .expect("the lane hosts the point it minted");

        let checks = lane.checks();
        let crash = checks[0].run(&point, host.as_ref()).await;
        assert_eq!(crash.outcome, Outcome::Clean);
        let reaction = checks[1].run(&point, host.as_ref()).await;
        assert_eq!(reaction.outcome, Outcome::Clean);

        assert_eq!(mock.inject_count(), 0);
        assert_eq!(lane.counters(JOB_ID).expect("the job counted").cases, 0);
    }

    /// Tester (fix rounds, review findings SEC2/Q4; keyed by job id, T5 live
    /// proof 4b): the eviction window and the registry move together through a
    /// *re-begun* job too. The engine never reuses a job id in production, but
    /// re-discovering one forgets its previous runner at once — before the new
    /// host registers, so a fresh runner takes the slot — and the ninth job
    /// then evicts the oldest slot, its runner going with it, so the registry
    /// never exceeds eight and never keeps a runner whose job state is gone.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn re_discovering_a_job_forgets_its_previous_runners_and_keeps_its_slot() {
        let mock = MockBackend::new(MockReply::Echo);
        let lane = lane_with(Arc::clone(&mock), &["raw"]);
        let profile = l4_profile(vec![udp_target(9)], 1);
        let host_job = |job_id: &str| {
            let lane = &lane;
            let profile = profile.clone();
            let job_id = job_id.to_string();
            async move {
                let job = TestJob::new(profile.clone()).with_job_id(&job_id);
                let discovery = lane
                    .discover(&profile.target, job.as_ref())
                    .await
                    .expect("one raw point");
                let point = discovery.points[0].clone();
                lane.probe_host_for(&point, Arc::clone(&job) as Arc<dyn JobCtx>)
                    .expect("the lane hosts the point it minted");
                point.id
            }
        };

        let mut point_id = String::new();
        for n in 0..8u32 {
            point_id = host_job(&format!("scan-{n:08x}")).await;
        }
        assert_eq!(lane.registry.len(), 8);
        let first_runner = lane
            .registry
            .get("scan-00000000", &point_id)
            .expect("job 0's runner");

        // Job 0's id again: its old runner is forgotten the moment the job is
        // re-begun, before the new host registers, so a fresh runner takes the
        // slot. The engine never reuses a job id — this only drives the window.
        host_job("scan-00000000").await;
        assert_eq!(lane.registry.len(), 8, "one runner per live job");
        let re_runner = lane
            .registry
            .get("scan-00000000", &point_id)
            .expect("the re-begun job's new runner");
        assert!(
            !Arc::ptr_eq(&first_runner, &re_runner),
            "the re-begun job's previous runner is gone, replaced by a fresh one"
        );
        for n in 1..8u32 {
            assert!(
                lane.registry
                    .get(&format!("scan-{n:08x}"), &point_id)
                    .is_some(),
                "job {n} kept its runner"
            );
        }

        // The ninth job evicts the oldest slot, which is still job 0's.
        host_job("scan-00000008").await;
        assert_eq!(lane.registry.len(), 8);
        assert!(
            lane.registry.get("scan-00000000", &point_id).is_none(),
            "the evicted job's runner went with its state"
        );
        assert!(lane.registry.get("scan-00000001", &point_id).is_some());
        assert!(lane.registry.get("scan-00000008", &point_id).is_some());
        assert_eq!(lane.counters("scan-00000000"), None);
        assert!(lane.counters("scan-00000001").is_some());
    }

    /// A backend whose capture open panics, standing in for a pcap handle that
    /// takes the blocking thread down with it.
    #[derive(Debug)]
    struct PanickingBackend;

    impl CaptureInjectBackend for PanickingBackend {
        fn open_capture(
            &self,
            _iface: &str,
            _filter: Option<&str>,
            _read_timeout: std::time::Duration,
        ) -> Result<Box<dyn aitm_proto_l4::backend::CaptureSource>, aitm_proto_l4::backend::L4Error>
        {
            panic!("the mock pcap handle blew up")
        }

        fn inject(
            &self,
            _iface: &str,
            _bytes: &[u8],
        ) -> Result<(), aitm_proto_l4::backend::L4Error> {
            Ok(())
        }
    }

    /// Tester (fix rounds, review findings SEC5/M7): discovery runs on the
    /// blocking pool, so a panic inside it — here the privilege probe's capture
    /// open — is a `JoinError` the lane turns into a `lane_unavailable:`
    /// refusal, not a panic on the engine's task and not a hung worker. The job
    /// was never begun, so it has no counters.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_discovery_panic_is_a_lane_unavailable_refusal() {
        let backend: Arc<dyn CaptureInjectBackend> = Arc::new(PanickingBackend);
        let lane = PacketLane::with_backend(loopback_guard("*", 1000), None, backend)
            .with_timing(fast())
            .with_default_fields(fields(&["raw"]));
        let profile = l4_profile(vec![udp_target(9)], 10);
        let job = TestJob::new(profile.clone());

        let err = lane
            .discover(&profile.target, job.as_ref())
            .await
            .expect_err("a panicking privilege probe plans nothing");
        let text = err.to_string();
        assert!(
            text.starts_with("lane_unavailable: discovery task failed: "),
            "D3 code first, then the task failure: {text}"
        );
        assert!(
            text.contains("panicked"),
            "the join error names the panic: {text}"
        );
        assert_eq!(lane.counters(JOB_ID), None, "the job was never begun");
        assert!(lane.registry.is_empty());
    }
}
