//! `aitm-scan-l4-stream` — the scanner v2 L4 stream lane.
//!
//! Owned by track **T6** of the scanner v2 design
//! (`docs/superpowers/specs/2026-10-31-aitmproxy-scanner-v2-design.md`, section
//! **D8.5**). `crates/aitm/src/wire.rs` calls [`lane`] with the handles from
//! `Features::l4_shared`; both are `None` when L4 is disabled. The lane returns
//! `Some` even then, so that `scan.start` refuses with `refused_l4` rather than
//! `lane_unavailable` (D3's refusal order, call A18) — and [`L4StreamLane`]
//! refuses the same way itself, in both entry points, rather than trusting the
//! engine to have refused first.
//!
//! [`L4StreamLane`] is the lane's three halves joined up: [`L4StreamLane::discover`]
//! turns each profile endpoint into seeds, a grammar, insertion points and one
//! site node without opening a socket (spec S5.2); [`L4StreamLane::probe_host_for`]
//! hands a check the [`host::StreamHost`] for one of those points (S5.5); and
//! [`L4StreamLane::checks`] is the three checks of S6.3. Nothing here sends a
//! byte: every destination is previewed against the deny-by-default
//! [`L4Guard`] first (S5.2 step 1, S5.4), and the first byte leaves only when a
//! check drives a host.

#![forbid(unsafe_code)]

pub mod checks;
pub mod client;
pub mod codec;
pub mod corpus;
pub mod denylist;
pub mod frame;
pub mod grammar;
pub mod grammars;
pub mod host;
pub mod infer;
pub mod mutate;
pub mod oracle;
pub mod spec;
pub mod state;
pub mod tree;

use std::net::IpAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use aitm_proto_l4::flow::L4FlowStore;
use aitm_proto_l4::guard::{interface_covers, L4Guard, ANY_INTERFACE};
use aitm_proto_l4::types::{IpCidr, L4Action, L4Capability, L4Direction, L4ScopeEntry, L4Target};
use aitm_scan_model::{
    Discovery, InsertionPoint, JobCtx, L4Counters, L4Transport, Lane, LaneKind, ProbeHost,
    ProfileTarget,
};
use anyhow::anyhow;
use futures::future::BoxFuture;

use crate::client::{StreamClient, TokioStreamClient};
use crate::codec::fnv1a64;
use crate::corpus::Seed;
use crate::host::StreamHost;
use crate::state::{
    lock, not_this_lanes_point, proto_of, DiscoveredPoint, EndpointAddr, LaneState,
    MAX_SEEDS_PER_ENDPOINT,
};

/// What the lane says when L4 is disabled (spec S5.1).
///
/// The engine has already refused at `scan.start`; this is the same D3 token
/// from the lane itself, so a misordered caller still gets `refused_l4` rather
/// than a surprise.
pub(crate) const L4_DISABLED: &str =
    "scan: refused_l4: L4 is disabled (l4.enabled: false); the stream lane sends nothing";

/// What [`L4StreamLane::scope_entry_for`] says when no entry renders — a race
/// with `l4.scope.remove` between the check and the description (spec S5.4).
const ENTRY_GONE: &str = "<entry removed after check>";

/// The L4 stream lane (spec S5).
///
/// Holds the two handles `wire.rs` passes (both `None` when L4 is disabled),
/// the per-job [`LaneState`] the three checks read through a host's marker, and
/// the [`StreamClient`] every host sends through — [`TokioStreamClient`] in a
/// shipped build, a double in a test.
pub struct L4StreamLane {
    /// The deny-by-default guard every destination is previewed against, or
    /// `None` when L4 is disabled.
    guard: Option<Arc<L4Guard>>,
    /// Captured L4 flows, the first corpus source (spec S5.2 (a)).
    store: Option<Arc<dyn L4FlowStore>>,
    /// Per-job discovery and counters (spec S5.1).
    state: Arc<LaneState>,
    /// How a host reaches the wire.
    client: Arc<dyn StreamClient>,
}

// Hand-written: none of the four fields is `Debug`, and a lane is described by
// which handles it holds and how many jobs it is tracking.
impl std::fmt::Debug for L4StreamLane {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("L4StreamLane")
            .field("guard", &self.guard.is_some())
            .field("store", &self.store.is_some())
            .field("jobs", &self.state.len())
            .finish()
    }
}

impl L4StreamLane {
    /// The lane over `guard`, `store` and `client`.
    #[must_use]
    pub fn new(
        guard: Option<Arc<L4Guard>>,
        store: Option<Arc<dyn L4FlowStore>>,
        client: Arc<dyn StreamClient>,
    ) -> Self {
        Self {
            guard,
            store,
            state: Arc::new(LaneState::new()),
            client,
        }
    }

    /// The lane's per-job state, which a test reads to see what discovery left
    /// behind.
    #[must_use]
    pub fn state(&self) -> &Arc<LaneState> {
        &self.state
    }

    /// The L4 counters a job has accumulated, or `None` when the lane holds no
    /// state for it (it never ran, or it was evicted).
    #[must_use]
    pub fn job_counters(&self, job_id: &str) -> Option<L4Counters> {
        self.state.get(job_id).map(|state| state.counters())
    }

    /// The scope entry that authorised `ip:port`, as [`L4Evidence::scope_entry`]
    /// reports it (spec S5.4).
    ///
    /// The first entry granting `Inject` outbound on any interface whose CIDR
    /// holds `ip` and whose port range holds `port` — exactly the guard's own
    /// match, read back for the operator. [`ENTRY_GONE`] when none renders,
    /// which is a scope removal racing the check rather than an unauthorised
    /// send.
    ///
    /// [`L4Evidence::scope_entry`]: aitm_scan_model::L4Evidence::scope_entry
    pub(crate) fn scope_entry_for(guard: &L4Guard, ip: IpAddr, port: u16) -> String {
        guard
            .list_scope()
            .iter()
            .find(|entry| {
                entry.capability == L4Capability::Inject
                    && entry.direction == L4Direction::Outbound
                    && interface_covers(entry, ANY_INTERFACE)
                    && cidr_contains(&entry.cidr, ip)
                    && entry.ports.lo <= port
                    && port <= entry.ports.hi
            })
            .map_or_else(|| ENTRY_GONE.to_string(), render_entry)
    }

    /// The per-endpoint authorisation preview of S5.2 step 1, returning the
    /// scope entry that allowed it.
    ///
    /// Opens nothing: the minted permit is dropped unused. The self-port check
    /// runs **before** the guard (amendment A1, C18), so a loopback listener of
    /// the core's own is refused even when the operator scoped `127.0.0.0/8`.
    ///
    /// # Errors
    ///
    /// `scan: refused_l4: ...` when L4 is disabled; `scan: out_of_scope: ...`
    /// for one of the core's own listener ports or any guard refusal.
    pub(crate) fn authorise_preview(
        &self,
        ip: IpAddr,
        port: u16,
        proto: L4Transport,
    ) -> anyhow::Result<String> {
        let Some(guard) = self.guard.as_deref() else {
            return Err(anyhow!(L4_DISABLED));
        };
        if ip.is_loopback() && guard.self_ports().contains(&port) {
            return Err(anyhow!(
                "scan: out_of_scope: {ip}:{port} is one of the core's own listener ports"
            ));
        }
        let permit = guard
            .check(
                L4Action::Inject,
                &L4Target {
                    interface: ANY_INTERFACE.to_string(),
                    direction: L4Direction::Outbound,
                    dst: Some(ip),
                    dst_port: Some(port),
                    proto: proto_of(proto),
                },
            )
            .map_err(|error| anyhow!("scan: out_of_scope: {error}"))?;
        drop(permit);
        Ok(Self::scope_entry_for(guard, ip, port))
    }

    /// [`Lane::discover`] without the future: discovery is pure computation
    /// over the profile, the captured flows and the grammars (spec S5.2).
    fn discover_now(&self, target: &ProfileTarget, job: &dyn JobCtx) -> anyhow::Result<Discovery> {
        if self.guard.is_none() {
            return Err(anyhow!(L4_DISABLED));
        }
        let job_state = self.state.job_for(job);
        let mut discovery = Discovery {
            points: Vec::new(),
            nodes: Vec::new(),
        };

        for spec in &target.l4 {
            let ip: IpAddr = spec.ip.parse().map_err(|_| {
                anyhow!(
                    "scan: invalid_profile: l4 target ip '{ip}' is not an IP address",
                    ip = spec.ip
                )
            })?;
            let scope_entry = self.authorise_preview(ip, spec.port, spec.proto)?;
            let endpoint = EndpointAddr {
                ip,
                port: spec.port,
                proto: spec.proto,
            };
            let node_id = corpus::node_id(ip, spec.port, spec.proto);

            // (a) captured flows, then (b) the profile's own seeds.
            let mut seeds: Vec<Seed> = Vec::new();
            if let Some(store) = self.store.as_deref() {
                seeds.extend(corpus::seeds_from_store(store, ip, spec.port, spec.proto));
            }
            let (profile_seeds, seed_notes) = corpus::seeds_from_profile(&job.profile().l4.seeds)?;
            seeds.extend(profile_seeds);
            dedupe_seeds(&mut seeds);

            let selected =
                corpus::select_for(spec.grammar.as_deref(), spec.proto, spec.port, &seeds)?;
            let grammar = selected.grammar;
            let (mut seeds, dropped_credential) =
                corpus::filter_credentials(grammar.as_ref(), seeds);
            if seeds.is_empty() {
                // (c) the grammar's own messages. `tlv` and `raw` generate
                // nothing, so such an endpoint yields a node and no points.
                let rng_seed =
                    fnv1a64(format!("{marker}{node_id}", marker = job.marker()).as_bytes());
                seeds = corpus::seeds_generated(grammar.as_ref(), rng_seed);
            }

            let (points, points_dropped) = corpus::build_points(
                &node_id,
                endpoint,
                grammar.as_ref(),
                &seeds,
                &scope_entry,
                &selected.reason,
            );
            let node = corpus::build_node(&node_id, endpoint, grammar.name(), &points);
            let selection = corpus::selection_text(&selected.reason);

            // Counts only, never a byte of a seed or a reply (spec S9, C11).
            tracing::info!(
                node = %node_id,
                grammar = grammar.name(),
                reason = %selection,
                seeds = seeds.len(),
                seeds_dropped_credential = dropped_credential,
                seeds_skipped = seed_notes.len(),
                points = points.len(),
                points_dropped,
                "l4_stream discover"
            );

            // The selected grammar is the one a check must speak: an inferred
            // TLV grammar is not reachable from `grammar::by_kind`, which hands
            // back the pending stub (spec S5.5).
            lock(&job_state.grammars).insert(node_id.clone(), Arc::clone(&grammar));
            lock(&job_state.selection).insert(node_id.clone(), selection);
            if !seed_notes.is_empty() {
                lock(&job_state.seed_notes).insert(node_id.clone(), seed_notes);
            }
            {
                let mut held = lock(&job_state.points);
                for point in &points {
                    held.insert(point.point.id.clone(), point.clone());
                }
            }

            discovery
                .points
                .extend(points.into_iter().map(|point| point.point));
            discovery.nodes.push(node);
        }

        // The share divisor is every point this job has discovered, across
        // every endpoint and every target (spec S5.2, S6.2).
        let total = u32::try_from(lock(&job_state.points).len()).unwrap_or(u32::MAX);
        job_state.points_total.store(total, Ordering::SeqCst);

        Ok(discovery)
    }
}

impl Lane for L4StreamLane {
    fn lane(&self) -> LaneKind {
        LaneKind::L4Stream
    }

    fn discover<'a>(
        &'a self,
        target: &'a ProfileTarget,
        job: &'a dyn JobCtx,
    ) -> BoxFuture<'a, anyhow::Result<Discovery>> {
        Box::pin(async move { self.discover_now(target, job) })
    }

    fn probe_host_for(
        &self,
        point: &InsertionPoint,
        job: Arc<dyn JobCtx>,
    ) -> anyhow::Result<Box<dyn ProbeHost>> {
        // Records `by_marker[marker] = job_id`, which is how a check reaches
        // this job's state from a host (spec S5.1, A2).
        let job_state = self.state.job_for(job.as_ref());
        if self.guard.is_none() {
            return Err(anyhow!(L4_DISABLED));
        }

        let found: Option<DiscoveredPoint> = lock(&job_state.points).get(&point.id).cloned();
        let Some(discovered) = found else {
            return Err(anyhow!(not_this_lanes_point(&point.id, job.job_id())));
        };

        // The seed is not parsed here: the host sends bytes, and the campaign
        // is the one parser (spec S5.5, S6.2). A seed that no longer parses
        // is the campaign's error, raised once rather than in two places.
        let grammar = lock(&job_state.grammars)
            .get(&discovered.node_id)
            .map(Arc::clone)
            .unwrap_or_else(|| grammar::by_kind(discovered.grammar));

        Ok(Box::new(StreamHost::new(
            discovered,
            grammar,
            job,
            job_state,
            self.guard.clone(),
            Arc::clone(&self.client),
        )))
    }

    fn checks(&self) -> Vec<Arc<dyn aitm_scan_model::Check>> {
        checks::checks(Arc::clone(&self.state))
    }
}

/// The L4 stream lane. Always `Some`, L4 enabled or not.
///
/// `crates/aitm/src/wire.rs` calls this once at startup with the handles from
/// `Features::l4_shared`; both are `None` when L4 is disabled, and the lane is
/// still `Some` then so `scan.start` refuses with `refused_l4` rather than
/// `lane_unavailable` (D3's refusal order, call A18). The signature is final.
#[must_use]
pub fn lane(
    guard: Option<Arc<L4Guard>>,
    store: Option<Arc<dyn L4FlowStore>>,
) -> Option<Arc<dyn Lane>> {
    Some(Arc::new(L4StreamLane::new(
        guard,
        store,
        Arc::new(TokioStreamClient),
    )))
}

/// [`lane`] over a caller-supplied [`StreamClient`], as the concrete type.
///
/// The seam the crate's own tests and `tests/` use to drive the lane against an
/// in-process speaker, or against a client that opens nothing at all.
#[must_use]
pub fn lane_with_client(
    guard: Option<Arc<L4Guard>>,
    store: Option<Arc<dyn L4FlowStore>>,
    client: Arc<dyn StreamClient>,
) -> Arc<L4StreamLane> {
    Arc::new(L4StreamLane::new(guard, store, client))
}

/// The scope entry as S5.4 renders it: `"<addr>/<prefix>:<lo>-<hi> <interface> <direction>"`.
fn render_entry(entry: &L4ScopeEntry) -> String {
    format!(
        "{addr}/{prefix}:{lo}-{hi} {interface} {direction}",
        addr = entry.cidr.addr,
        prefix = entry.cidr.prefix,
        lo = entry.ports.lo,
        hi = entry.ports.hi,
        interface = entry.interface,
        direction = direction_name(entry.direction),
    )
}

/// `inbound` or `outbound`, matching the wire spelling of [`L4Direction`].
fn direction_name(direction: L4Direction) -> &'static str {
    match direction {
        L4Direction::Inbound => "inbound",
        L4Direction::Outbound => "outbound",
    }
}

/// Whether `ip` falls inside `cidr` (same family required).
///
/// The guard's own containment test is private to `aitm-proto-l4`; this one
/// only describes an entry the guard has **already** accepted, and never
/// authorises anything.
fn cidr_contains(cidr: &IpCidr, ip: IpAddr) -> bool {
    match (cidr.addr, ip) {
        (IpAddr::V4(net), IpAddr::V4(host)) => {
            let prefix = cidr.prefix.min(32);
            let mask: u32 = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - u32::from(prefix))
            };
            u32::from(net) & mask == u32::from(host) & mask
        }
        (IpAddr::V6(net), IpAddr::V6(host)) => {
            let prefix = cidr.prefix.min(128);
            let mask: u128 = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - u32::from(prefix))
            };
            u128::from(net) & mask == u128::from(host) & mask
        }
        _ => false,
    }
}

/// Drop seeds whose bytes another source already contributed, and cut the list
/// to [`MAX_SEEDS_PER_ENDPOINT`] (spec S5.2 step 2).
fn dedupe_seeds(seeds: &mut Vec<Seed>) {
    let mut seen: std::collections::HashSet<Vec<u8>> = std::collections::HashSet::new();
    seeds.retain(|seed| seen.insert(seed.bytes.clone()));
    seeds.truncate(MAX_SEEDS_PER_ENDPOINT);
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::atomic::Ordering;
    use std::time::{Duration, Instant};

    use aitm_core::{
        BrowserDriver, FlowStore, HttpFlow, HttpRequest, MemFlowStore, ProxyClient, ScopeRateGuard,
        StdGuard,
    };
    use aitm_proto_l4::config::L4Config;
    use aitm_proto_l4::guard::ANY_INTERFACE;
    use aitm_proto_l4::types::{
        IpCidr, L4Capability, L4Direction, L4ScopeEntry, L4ScopeId, L4ScopeSource, PortRange,
        RateCap,
    };
    use aitm_scan_model::{
        InsertionKind, InsertionPoint, JobCtx, L4Seed, L4TargetSpec, L4Transport, LaneKind,
        ProfileTarget, ScanProfile, SessionMaterial,
    };
    use futures::future::BoxFuture;

    use crate::client::testing::CountingClient;
    use crate::state::lock;

    /// A `ProxyClient` that performs no I/O; a job context needs one to exist.
    struct NullClient;

    impl ProxyClient for NullClient {
        fn send(&self, _req: HttpRequest) -> BoxFuture<'_, anyhow::Result<HttpFlow>> {
            Box::pin(async { Err(anyhow::anyhow!("no client in the test context")) })
        }
    }

    /// A `JobCtx` with a fixed marker, job id and profile.
    struct TestJob {
        profile: ScanProfile,
        client: Arc<dyn ProxyClient>,
        store: Arc<dyn FlowStore>,
        guard: Arc<dyn ScopeRateGuard>,
    }

    impl TestJob {
        fn new() -> Self {
            Self {
                profile: ScanProfile::default(),
                client: Arc::new(NullClient),
                store: Arc::new(MemFlowStore::new()),
                guard: Arc::new(StdGuard::default()),
            }
        }

        fn with_seeds(hex_seeds: &[&str]) -> Self {
            let mut job = Self::new();
            job.profile.l4.seeds = hex_seeds
                .iter()
                .map(|text| L4Seed::Hex {
                    hex: (*text).to_string(),
                })
                .collect();
            job
        }
    }

    impl JobCtx for TestJob {
        fn job_id(&self) -> &str {
            "scan-20"
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
            1000
        }
        fn deadline(&self) -> Instant {
            Instant::now() + Duration::from_secs(600)
        }
        fn cancelled(&self) -> bool {
            false
        }
        fn marker(&self) -> String {
            "aitm20".to_string()
        }
    }

    /// One scope entry, written the way an operator's config does.
    fn entry(
        addr: Ipv4Addr,
        prefix: u8,
        interface: &str,
        capability: L4Capability,
    ) -> L4ScopeEntry {
        L4ScopeEntry {
            id: L4ScopeId::new(),
            cidr: IpCidr {
                addr: IpAddr::V4(addr),
                prefix,
            },
            ports: PortRange { lo: 0, hi: 65535 },
            interface: interface.to_string(),
            direction: L4Direction::Outbound,
            capability,
            inject_rate: RateCap {
                pps: 1000,
                burst: 1000,
            },
            source: L4ScopeSource::Config,
        }
    }

    /// A guard over `scope`, L4 enabled.
    fn guard_over(scope: Vec<L4ScopeEntry>) -> Arc<L4Guard> {
        Arc::new(L4Guard::new(&L4Config {
            enabled: true,
            scope,
            ..Default::default()
        }))
    }

    /// The config-declared loopback wildcard inject entry: what an operator
    /// writes to let the lane reach a local speaker.
    fn loopback_guard() -> Arc<L4Guard> {
        guard_over(vec![entry(
            Ipv4Addr::new(127, 0, 0, 0),
            8,
            ANY_INTERFACE,
            L4Capability::Inject,
        )])
    }

    /// A lane that opens no socket: every exchange is `ClientError::DryRun`.
    fn dry_lane(guard: Option<Arc<L4Guard>>) -> Arc<L4StreamLane> {
        lane_with_client(
            guard,
            None,
            Arc::new(CountingClient {
                exchanges: std::sync::atomic::AtomicU32::new(0),
                inner: None,
            }),
        )
    }

    fn one_target(ip: &str, port: u16) -> ProfileTarget {
        ProfileTarget {
            origins: Vec::new(),
            l4: vec![L4TargetSpec {
                ip: ip.to_string(),
                port,
                proto: L4Transport::Tcp,
                grammar: None,
            }],
        }
    }

    /// A point this lane never produced.
    fn foreign_point() -> InsertionPoint {
        InsertionPoint {
            id: "l4s-0000000000000000".to_string(),
            lane: LaneKind::L4Stream,
            kind: InsertionKind::L4Field,
            name: "payload".to_string(),
            path: Some("payload".to_string()),
            example: None,
            flow: None,
            site_node: None,
            traits: Vec::new(),
            frequency: 1,
            method: Some("L4".to_string()),
            url: None,
        }
    }

    // -----------------------------------------------------------------
    // S5.1: the slot, the lane kind and the three checks
    // -----------------------------------------------------------------

    #[test]
    fn lane_is_some_and_l4_stream() {
        let lane = crate::lane(None, None).expect("the lane is Some even with L4 disabled");
        assert_eq!(lane.lane(), LaneKind::L4Stream);

        let ids: Vec<String> = lane
            .checks()
            .iter()
            .map(|check| check.meta().id.clone())
            .collect();
        assert_eq!(
            ids,
            vec![
                "l4-crash".to_string(),
                "l4-parser-fault".to_string(),
                "l4-latency-outlier".to_string(),
            ]
        );
    }

    // -----------------------------------------------------------------
    // S5.1: guard `None` is `refused_l4`, in both entry points
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn discover_refuses_when_l4_disabled() {
        let lane = dry_lane(None);
        let job = TestJob::new();

        let error = lane
            .discover(&one_target("127.0.0.1", 9000), &job)
            .await
            .expect_err("a disabled L4 subsystem sends nothing");
        assert_eq!(
            error.to_string(),
            "scan: refused_l4: L4 is disabled (l4.enabled: false); the stream lane sends nothing"
        );

        let error = lane
            .probe_host_for(&foreign_point(), Arc::new(TestJob::new()))
            .map(|_| ())
            .expect_err("a disabled L4 subsystem hosts no probe");
        assert_eq!(
            error.to_string(),
            "scan: refused_l4: L4 is disabled (l4.enabled: false); the stream lane sends nothing"
        );
    }

    // -----------------------------------------------------------------
    // S5.2 step 1: the authorisation preview
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn discover_out_of_scope_and_capability() {
        // An entry somewhere else entirely: no entry matches the location.
        let elsewhere = dry_lane(Some(guard_over(vec![entry(
            Ipv4Addr::new(10, 0, 0, 0),
            8,
            ANY_INTERFACE,
            L4Capability::Inject,
        )])));
        let error = elsewhere
            .discover(&one_target("127.0.0.1", 9000), &TestJob::new())
            .await
            .expect_err("an unscoped destination is refused");
        assert!(
            error.to_string().starts_with("scan: out_of_scope: "),
            "{error}"
        );

        // The location matches, but the entry only grants Capture.
        let capture_only = dry_lane(Some(guard_over(vec![entry(
            Ipv4Addr::new(127, 0, 0, 0),
            8,
            ANY_INTERFACE,
            L4Capability::Capture,
        )])));
        let error = capture_only
            .discover(&one_target("127.0.0.1", 9000), &TestJob::new())
            .await
            .expect_err("Capture does not grant Inject");
        let text = error.to_string();
        assert!(text.starts_with("scan: out_of_scope: "), "{text}");
        assert!(text.contains("capability"), "{text}");
    }

    // -----------------------------------------------------------------
    // S5.2 step 1 / A1 / C18: the core's own listener ports
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn discover_self_port() {
        let guard = loopback_guard();
        guard.set_self_ports([9000]);
        let lane = dry_lane(Some(guard));

        let error = lane
            .discover(&one_target("127.0.0.1", 9000), &TestJob::new())
            .await
            .expect_err("the lane never addresses the core's own listener");
        assert_eq!(
            error.to_string(),
            "scan: out_of_scope: 127.0.0.1:9000 is one of the core's own listener ports"
        );

        // The same port on a routable address the operator scoped is fine: the
        // self-port rule is about the core's own loopback listeners.
        let elsewhere = guard_over(vec![entry(
            Ipv4Addr::new(10, 0, 0, 0),
            8,
            ANY_INTERFACE,
            L4Capability::Inject,
        )]);
        elsewhere.set_self_ports([9000]);
        let lane = dry_lane(Some(elsewhere));
        lane.discover(&one_target("10.0.0.9", 9000), &TestJob::new())
            .await
            .expect("a scoped routable destination on the same port number");
    }

    // -----------------------------------------------------------------
    // S5.2: profile mistakes are `invalid_profile`
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn discover_bad_ip_and_grammar() {
        let lane = dry_lane(Some(loopback_guard()));

        let error = lane
            .discover(&one_target("nope", 9000), &TestJob::new())
            .await
            .expect_err("'nope' is not an address");
        assert_eq!(
            error.to_string(),
            "scan: invalid_profile: l4 target ip 'nope' is not an IP address"
        );

        let mut target = one_target("127.0.0.1", 9000);
        target.l4[0].grammar = Some("zzz".to_string());
        let error = lane
            .discover(&target, &TestJob::new())
            .await
            .expect_err("'zzz' is not a grammar");
        assert!(
            error
                .to_string()
                .starts_with("scan: invalid_profile: unknown grammar 'zzz'"),
            "{error}"
        );
    }

    // -----------------------------------------------------------------
    // S5.2 steps 2-5 and S5.5: points, the node, and hosting a probe
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn discover_builds_points_from_hex_seeds() {
        let lane = dry_lane(Some(loopback_guard()));
        let job = TestJob::with_seeds(&["0003616263", "0001ff"]);

        let found = lane
            .discover(&one_target("127.0.0.1", 9000), &job)
            .await
            .expect("two TLV seeds infer a grammar");

        assert_eq!(found.nodes.len(), 1);
        let node = &found.nodes[0];
        assert_eq!(node.id, "l4s-tcp-127.0.0.1-9000");
        assert_eq!(node.path_template, "/tlv");
        assert_eq!(node.scheme, "tcp");
        assert_eq!(node.method, "L4");
        assert_eq!(node.host, "127.0.0.1");
        assert_eq!(node.port, 9000);

        assert!(!found.points.is_empty());
        let paths: Vec<String> = found
            .points
            .iter()
            .map(|point| point.path.clone().unwrap_or_default())
            .collect();
        assert!(paths.contains(&"length".to_string()), "{paths:?}");
        assert!(paths.contains(&"payload".to_string()), "{paths:?}");
        for point in &found.points {
            assert_eq!(point.kind, InsertionKind::L4Field);
            assert_eq!(point.lane, LaneKind::L4Stream);
            assert_eq!(point.site_node.as_deref(), Some(node.id.as_str()));
            assert_eq!(point.url.as_deref(), Some("tcp://127.0.0.1:9000/tlv"));
        }

        // The job state carries the discovery the checks read.
        let state = lane.state().get("scan-20").expect("the job's state");
        assert_eq!(
            state.points_total.load(Ordering::SeqCst),
            u32::try_from(found.points.len()).expect("a small count")
        );
        assert!(lock(&state.grammars).contains_key(&node.id));
        assert_eq!(
            lock(&state.selection).get(&node.id).cloned(),
            Some("inferred 2-byte be length at offset 0 counting body only".to_string())
        );

        // S5.5: a point this lane produced is hosted; a foreign one is not.
        lane.probe_host_for(&found.points[0], Arc::new(TestJob::new()))
            .expect("a discovered point is hosted");
        let error = lane
            .probe_host_for(&foreign_point(), Arc::new(TestJob::new()))
            .map(|_| ())
            .expect_err("a foreign point is not");
        assert_eq!(
            error.to_string(),
            "l4_stream: point l4s-0000000000000000 was not produced by this lane for job scan-20"
        );

        assert_eq!(lane.job_counters("scan-20").map(|c| c.cases), Some(0));
        assert!(lane.job_counters("no-such-job").is_none());
    }

    // -----------------------------------------------------------------
    // C10: a literal interface does not cover the wildcard the lane asks for
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn wildcard_vs_literal_interface() {
        let literal = dry_lane(Some(guard_over(vec![entry(
            Ipv4Addr::new(127, 0, 0, 0),
            8,
            "lo0",
            L4Capability::Inject,
        )])));
        let error = literal
            .discover(&one_target("127.0.0.1", 9000), &TestJob::new())
            .await
            .expect_err("a socket client cannot promise an egress interface");
        assert!(
            error.to_string().starts_with("scan: out_of_scope: "),
            "{error}"
        );

        let wildcard = dry_lane(Some(loopback_guard()));
        wildcard
            .discover(&one_target("127.0.0.1", 9000), &TestJob::new())
            .await
            .expect("the wildcard entry authorises the preview");
    }
}
